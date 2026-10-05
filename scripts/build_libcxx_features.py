#!/usr/bin/env python3
"""Materialize the bounded libc++ accessor rules from checked compiler evidence.

Layout extraction reads the compiler's record-layout dump, not a guessed SDK
version. This authoring tool has no matcher. Every resulting rule requires
independent receiver identity at use time; the structural expression alone
never identifies a C++ library or a template specialization.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import tarfile
from pathlib import Path

from build_library_feature_probes import describe, write_json
from validate_library_features import FeatureError, require, validate_pack


class Expression:
    def __init__(self):
        self.nodes = [{"id": "receiver", "op": "input", "bits": 64, "role": "receiver"}]

    def node(self, name, op, bits, *args, **fields):
        value = {"id": name, "op": op, "bits": bits, **fields}
        if args:
            value["args"] = list(args)
        self.nodes.append(value)
        return name

    def const(self, name, bits, value):
        return self.node(name, "constant", bits, value=hex(value))

    def load(self, name, bits, offset):
        return self.node(name, "load", bits, "receiver", offset=offset)

    def finish(self, result):
        # A size/empty expression can reuse a partial graph while publishing
        # only nodes that actually contribute to this operation's result.
        by_name = {node["id"]: node for node in self.nodes}
        used = set()
        def visit(name):
            if name in used:
                return
            used.add(name)
            for arg in by_name[name].get("args", []):
                visit(arg)
        visit(result)
        return {"nodes": [n for n in self.nodes if n["id"] in used], "result": result}


def record_layout(text: str, name: str) -> str:
    candidates = [part for part in text.split("*** Dumping AST Record Layout")
                  if re.search(r"^\s*0 \| (?:struct|class) " + re.escape(name) + r"\s*$", part, re.M)]
    require(len(candidates) == 1, f"missing or ambiguous compiler layout for {name}")
    return candidates[0]


def field(layout: str, name: str) -> int:
    matches = re.findall(r"^\s*(\d+) \|\s+[^\n]*\b" + re.escape(name) + r"\s*$", layout, re.M)
    require(len(matches) == 1, f"missing or ambiguous field {name}")
    return int(matches[0])


def layouts_from_dump(text: str) -> dict:
    layouts = {}
    for char, width in (("char", 8), ("wchar_t", 32)):
        long = record_layout(text, f"std::basic_string<{char}>::__long")
        short = record_layout(text, f"std::basic_string<{char}>::__short")
        cap = re.findall(r"^\s*(\d+):0-(\d+) \|\s+size_type __cap_\s*$", long, re.M)
        tag = re.findall(r"^\s*(\d+):7-7 \|\s+unsigned char __is_long_\s*$", short, re.M)
        extent = re.findall(r"value_type\[(\d+)\] __data_", short)
        require(len(cap) == len(tag) == len(extent) == 1 and int(cap[0][1]) == 62,
                "unsupported libc++ SSO bitfield layout")
        sizes = re.findall(r"\[sizeof=(\d+),", long)
        require(len(sizes) == 1, "missing string object size")
        layouts["string-" + char.replace("_t", "")] = {
            "object_bytes": int(sizes[0]), "element_bits": width,
            "long_data_offset": field(long, "__data_"), "long_size_offset": field(long, "__size_"),
            "long_capacity_offset": int(cap[0][0]), "long_capacity_mask": "0x7fffffffffffffff",
            "tag_offset": int(tag[0]), "long_mask": "0x80", "short_data_offset": field(short, "__data_"),
            "short_capacity": int(extent[0]) - 1,
            "receiver_type": f"std::__1::basic_string<{char}, std::__1::char_traits<{char}>, std::__1::allocator<{char}>>"}
    for suffix, element, width in (("u32", "unsigned int", 32), ("u64", "unsigned long long", 64)):
        layout = record_layout(text, f"std::vector<{element}>")
        sizes = re.findall(r"\[sizeof=(\d+),", layout)
        require(len(sizes) == 1, "missing vector object size")
        layouts["vector-" + suffix] = {
            "object_bytes": int(sizes[0]), "element_bits": width,
            "begin_offset": field(layout, "__begin_"), "end_offset": field(layout, "__end_"),
            "capacity_offset": field(layout, "__cap_"),
            "receiver_type": f"std::__1::vector<{element}, std::__1::allocator<{element}>>"}
    return layouts


def accessor(layout: dict, operation: str) -> dict:
    e = Expression()
    if "tag_offset" in layout:
        tag = e.load("tag", 8, layout["tag_offset"])
        flag = e.node("flag", "and", 8, tag, e.const("long-mask", 8, 128))
        condition = e.node("is-long", "ne", 8, flag, e.const("zero-tag", 8, 0))
        if operation in ("size", "empty"):
            large = e.load("long-size", 64, layout["long_size_offset"])
            small = e.node("short-size", "zext", 64, tag)
        elif operation == "data":
            require(layout["short_data_offset"] == 0, "unsupported short string base")
            large, small = e.load("long-data", 64, layout["long_data_offset"]), "receiver"
        else:
            capacity = e.load("long-capacity", 64, layout["long_capacity_offset"])
            raw = e.node("allocation", "and", 64, capacity, e.const("capacity-mask", 64, (1 << 63) - 1))
            large = e.node("usable", "sub", 64, raw, e.const("terminator", 64, 1))
            small = e.const("short-capacity", 64, layout["short_capacity"])
        result = e.node("value", "select", 64, condition, large, small)
        if operation == "empty":
            result = e.node("empty", "eq", 8, result, e.const("zero-size", 64, 0))
    else:
        begin = e.load("begin", 64, layout["begin_offset"])
        if operation == "data":
            result = begin
        else:
            end = e.load("end", 64, layout["end_offset"] if operation != "capacity" else layout["capacity_offset"])
            if operation == "empty":
                result = e.node("empty", "eq", 8, begin, end)
            else:
                distance = e.node("distance", "sub", 64, end, begin)
                stride = layout["element_bits"] // 8
                require(stride in (4, 8), "unsupported vector element width")
                result = e.node("elements", "ashr", 64, distance, e.const("scale", 64, stride.bit_length() - 1))
    return e.finish(result)


def archive_evidence(evidence: Path, manifest: dict, output: Path) -> None:
    with output.open("wb") as file:
        with gzip.GzipFile(fileobj=file, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for item in sorted(manifest["artifacts"], key=lambda item: item["path"]):
                    path = evidence / item["path"]
                    require(path.parent == evidence and path.is_file(), "invalid producer artifact")
                    content = path.read_bytes()
                    require(hashlib.sha256(content).hexdigest() == item["sha256"], "producer artifact changed")
                    info = tarfile.TarInfo(path.name)
                    info.size = len(content)
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(content))


def build(root: Path, evidence: Path, repeated: Path) -> Path:
    manifest = json.loads((evidence / "manifest.json").read_text())
    other = json.loads((repeated / "manifest.json").read_text())
    require(manifest["status"] == other["status"] == "produced", "incomplete compiler run")
    require(manifest["source"] == other["source"] and manifest["compiler"] == other["compiler"],
            "repeated run used different inputs")
    a = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
    b = {item["path"]: item["sha256"] for item in other["artifacts"]}
    stable = sorted(name for name in a if name.endswith((".o", ".s", ".ll")))
    require(len(stable) == 9 and all(a[name] == b.get(name) for name in stable),
            "object/assembly/IR reconstruction is not reproducible")
    build = next(b for b in manifest["builds"] if b["id"] == "accessors-inline")
    config = build["configuration"]
    require(re.search(r"clang version 22\.1\.6\b", manifest["compiler_version"]) is not None and
            manifest["target"] == "aarch64-macho" and config.get("_LIBCPP_VERSION") == "230000" and
            config.get("_LIBCPP_ABI_VERSION") == "1" and "_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT" in config and
            config.get("_LIBCPP_HARDENING_MODE") == "2" and config.get("__SIZEOF_WCHAR_T__") == "4",
            "evidence does not describe the supported libc++ profile")
    layouts = layouts_from_dump((evidence / "accessors-inline.stdout.txt").read_text())
    identity = "libcxx-23git-arm64-macos-abi1-alternate-clang22"
    for directory in ("profiles", "rules", "evidence"):
        (root / "features" / directory).mkdir(parents=True, exist_ok=True)
    manifest_path = root / "features/evidence" / (identity + ".json")
    shutil.copyfile(evidence / "manifest.json", manifest_path)
    archive = manifest_path.with_suffix(".tar.gz")
    archive_evidence(evidence, manifest, archive)
    def file_ref(path):
        return describe(path, path.relative_to(root).as_posix())
    profile = {"schema_version": 1, "kind": "library-feature-profile", "id": identity,
               "implementation": "libc++", "target": {"architecture": "aarch64", "format": "macho",
               "abi": "darwin-aapcs64", "pointer_bits": 64, "endianness": "little"},
               "configuration": {"build": "accessors-inline", "language": "c++17", "optimization": "O2", "lto": False,
                                 "macros": config, "arguments": build["arguments"],
                                 "sdk": manifest["source"]["sdk"]},
               "source": {"origin": manifest["source"]["origin"], "revision": manifest["source"]["revision"],
                          "license": manifest["source"]["license"], "files": build["headers"]},
               "compiler": {**manifest["compiler"], "version": manifest["compiler_version"]},
               "layouts": layouts, "evidence": file_ref(manifest_path), "artifact_archive": file_ref(archive)}
    profile_path = root / "features/profiles" / (identity + ".json")
    write_json(profile_path, profile)
    symbols = [line.split()[-1] for line in (evidence / "accessors-inline-symbols.stdout.txt").read_text().splitlines()
               if len(line.split()) >= 3]
    rules = []
    for name, layout in layouts.items():
        string = name.startswith("string-")
        if string:
            prefix = "nd_string_char" if name == "string-char" else "nd_string_wide"
            fragment = "basic_stringIc" if name == "string-char" else "basic_stringIw"
        else:
            prefix = "nd_vector_" + name.split("-", 1)[1]
            fragment = "vectorIj" if name.endswith("u32") else "vectorIy"
        for operation in ("size", "empty", "data", "capacity"):
            original = [s for s in symbols if fragment in s and f"{len(operation)}{operation}B" in s]
            require(len(original) == 1, f"missing standalone library symbol: {name} {operation}")
            rules.append({"id": f"libcxx.{name}.{operation}", "revision": 1, "family": "stl",
                          "operation": operation, "receiver_type": layout["receiver_type"], "layout": name,
                          "identity_evidence": "authoritative-receiver", "scope": ["whole-function", "inline-expression"],
                          "pattern": accessor(layout, operation),
                          "positive": [
                              {"build": "accessors-inline", "symbol": original[0], "expectation": "whole-function"},
                              {"build": "accessors-inline", "symbol": "_" + prefix + "_" + operation + "_inline",
                               "expectation": "inline-expression"}],
                          "negative": [
                              {"build": "accessors-inline", "symbol": "_nd_user_range_data" if operation == "data" else
                               "_nd_user_range_empty" if operation == "empty" else "_nd_user_range_size",
                               "expectation": "unproven-receiver"},
                              {"build": "accessors-negative-configuration", "symbol": "_" + prefix + "_" + operation,
                               "expectation": "configuration-mismatch"}]})
    pack = {"schema_version": 1, "kind": "library-feature-pack", "id": identity,
            "profile": file_ref(profile_path), "rules": rules,
            "verification": {"data_verified": True, "consumer_verified": False}}
    pack_path = root / "features/rules" / (identity + ".json")
    write_json(pack_path, pack)
    validate_pack(root, pack_path)
    return pack_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--repeat", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        print(build(args.root.resolve(), args.evidence.resolve(), args.repeat.resolve()))
    except (FeatureError, OSError, KeyError, ValueError) as error:
        parser.exit(1, f"libc++ feature generation: {error}\n")
