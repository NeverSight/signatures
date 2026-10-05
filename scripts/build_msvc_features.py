#!/usr/bin/env python3
"""Author the selected STL/ATL rules from an actual MSVC compiler capture."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from build_library_feature_probes import describe, write_json
from build_libcxx_features import Expression, accessor as vector_accessor, archive_evidence
from validate_library_features import COM_POLICIES, FeatureError, require, validate_pack


def record(text: str, name: str) -> tuple[int, str]:
    found = re.findall(r"^class " + re.escape(name) +
                       r"\s+size\((\d+)\):\n\t\+---\n(.*?)^\t\+---\s*$",
                       text, re.M | re.S)
    require(len(found) == 1, f"missing or ambiguous MSVC layout: {name}")
    return int(found[0][0]), found[0][1]


def offset(body: str, field: str) -> int:
    found = re.findall(r"^\s*(\d+)\t\|[^\n]*\b" + re.escape(field) + r"\s*$", body, re.M)
    require(len(found) == 1, f"missing or ambiguous MSVC field: {field}")
    return int(found[0])


def stl_layouts(text: str) -> dict:
    result = {}
    for name, char, bits in (("string-char", "char", 8), ("string-wchar", "wchar_t", 16)):
        stem = f"std::_String_val<struct std::_Simple_types<{char}> >"
        size, body = record(text, stem)
        union_size, union = record(text, stem + "::_Bxty")
        result[name] = {"object_bytes": size, "element_bits": bits,
                        "size_offset": offset(body, "_Mysize"), "capacity_offset": offset(body, "_Myres"),
                        "data_offset": offset(body, "_Bx") + offset(union, "_Ptr"),
                        "short_data_offset": offset(body, "_Bx") + offset(union, "_Buf"),
                        "short_capacity": union_size // (bits // 8) - 1,
                        "receiver_type": f"std::basic_string<{char}, std::char_traits<{char}>, std::allocator<{char}>>"}
    for name, element, bits in (("vector-u32", "unsigned int", 32), ("vector-u64", "unsigned __int64", 64)):
        size, body = record(text, f"std::_Vector_val<struct std::_Simple_types<{element}> >")
        result[name] = {"object_bytes": size, "element_bits": bits,
                        "begin_offset": offset(body, "_Myfirst"), "end_offset": offset(body, "_Mylast"),
                        "capacity_offset": offset(body, "_Myend"),
                        "receiver_type": f"std::vector<{element}, std::allocator<{element}>>"}
    return result


def string_layouts(text: str) -> dict:
    header_bytes, header = record(text, "ATL::CStringData")
    result = {}
    for name, char, bits in (("cstring-char", "char", 8), ("cstring-wchar", "wchar_t", 16)):
        size, body = record(text, f"ATL::CSimpleStringT<{char},0>")
        receiver = f"ATL::CStringT<{char}, ATL::StrTraitATL<{char}, ATL::ChTraitsCRT<{char}>>>"
        result[name] = {"object_bytes": size, "element_bits": bits,
                        "data_offset": offset(body, "m_pszData"), "header_bytes": header_bytes,
                        "length_offset": offset(header, "nDataLength") - header_bytes,
                        "capacity_offset": offset(header, "nAllocLength") - header_bytes,
                        "references_offset": offset(header, "nRefs") - header_bytes,
                        "receiver_type": receiver}
        result[name.replace("cstring", "simplestring")] = {
            **result[name], "receiver_type": f"ATL::CSimpleStringT<{char}, false>",
            "known_derived_receivers": [{"type": receiver, "base_offset": 0}]}
    return result


def string_accessor(layout: dict, operation: str, atl: bool = False) -> dict:
    e = Expression()
    if atl:
        data = e.load("data", 64, layout["data_offset"])
        result = data if operation == "GetString" else e.node(
            "length", "load", 32, data, offset=layout["length_offset"])
        if operation == "IsEmpty":
            result = e.node("empty", "eq", 8, result, e.const("zero", 32, 0))
    elif operation in ("size", "empty"):
        result = e.load("size", 64, layout["size_offset"])
        if operation == "empty":
            result = e.node("empty", "eq", 8, result, e.const("zero", 64, 0))
    else:
        capacity = e.load("capacity", 64, layout["capacity_offset"])
        result = capacity
        if operation == "data":
            require(layout["short_data_offset"] == 0, "unsupported MSVC short buffer base")
            is_short = e.node("is-short", "ule", 8, capacity,
                              e.const("short-capacity", 64, layout["short_capacity"]))
            result = e.node("data", "select", 64, is_short, "receiver",
                            e.load("long-data", 64, layout["data_offset"]))
    return e.finish(result)


def symbol_set(evidence: Path, build: str) -> set[str]:
    return {line.split()[-1] for line in (evidence / (build + "-symbols.stdout.txt")).read_text().splitlines()
            if " T " in line}


def one_symbol(symbols: set[str], prefix: str, suffix: str = "") -> str:
    found = [s for s in symbols if s.startswith(prefix) and s.endswith(suffix)]
    require(len(found) == 1, f"missing or ambiguous library symbol: {prefix} {suffix}")
    return found[0]


def witness(build: str, symbol: str, expectation: str) -> dict:
    return {"build": build, "symbol": symbol, "expectation": expectation}


def base_rule(name: str, family: str, operation: str, layout: str, layouts: dict) -> dict:
    return {"id": name, "revision": 1, "family": family, "operation": operation,
            "receiver_type": layouts[layout]["receiver_type"], "layout": layout,
            "identity_evidence": "authoritative-receiver"}


def build(root: Path, evidence: Path, neverd_source: Path, sigmaker: Path) -> list[Path]:
    manifest = json.loads((evidence / "manifest.json").read_text())
    require(manifest["status"] == "produced" and manifest["target"] == "x86_64-coff",
            "incomplete or wrong-target MSVC evidence")
    require(manifest["source"]["revision"] == "14.44.35207" and
            "Version 19.44.35229 for x64" in manifest["compiler_version"], "unsupported MSVC version")
    builds = {b["id"]: b for b in manifest["builds"]}
    require(builds["accessors-inline"]["configuration"]["_ITERATOR_DEBUG_LEVEL"] == "0",
            "unsupported iterator debug layout")
    for name in ("evidence", "profiles", "rules", "patterns"):
        (root / "features" / name).mkdir(parents=True, exist_ok=True)
    def ref(path):
        return describe(path, path.relative_to(root).as_posix())
    evidence_id = "msvc-14.44.35207-x64-release"
    manifest_path = root / "features/evidence" / (evidence_id + ".json")
    shutil.copyfile(evidence / "manifest.json", manifest_path)
    archive_path = manifest_path.with_suffix(".tar.gz")
    archive_evidence(evidence, manifest, archive_path)
    layouts = {
        "stl": stl_layouts((evidence / "accessors-inline.stdout.txt").read_text()),
        "atl-mfc-string": string_layouts((evidence / "atl_string-inline.stdout.txt").read_text()),
    }
    size, com_body = record((evidence / "atl_com-inline.stdout.txt").read_text(), "ATL::CComPtr<struct IUnknown>")
    layouts["atl-com"] = {"ccomptr-iunknown": {"object_bytes": size, "pointer_offset": offset(com_body, "p"),
                                              "receiver_type": "ATL::CComPtr<IUnknown>"}}
    layouts["atl-com"]["ccomptrbase-iunknown"] = {
        "object_bytes": size, "pointer_offset": offset(com_body, "p"),
        "receiver_type": "ATL::CComPtrBase<IUnknown>",
        "known_derived_receivers": [{"type": "ATL::CComPtr<IUnknown>", "base_offset": 0}]}
    # Reuse NeverD's existing .pat producer and parser. Rules retain one
    # genuine library entry each; probe wrappers never become library names.
    module_path = neverd_source / "scripts/signatures/build_eh_signatures.py"
    spec = importlib.util.spec_from_file_location("neverd_pattern_authoring", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    generated = evidence / "atl-generated.pat"
    command = [str(sigmaker), "--machine=x64", "--tail=65536", "--references", "--name=" + evidence_id,
               "-o", str(generated), str(evidence / "atl_string-inline.obj")]
    subprocess.run(command, check=True)
    subprocess.run([str(sigmaker), "--verify", str(generated)], check=True)
    patterns = {}
    for line in generated.read_text().splitlines():
        parsed = module.parse_pattern_line(line)
        if parsed:
            for symbol in parsed.names:
                patterns[symbol] = parsed
    receipt = {"kind": "byte-feature-generation", "generator": describe(sigmaker),
               "neverd_revision": subprocess.check_output(["git", "-C", str(neverd_source), "rev-parse", "HEAD"], text=True).strip(),
               "parser": describe(module_path), "input": describe(evidence / "atl_string-inline.obj"),
               "options": ["--machine=x64", "--tail=65536", "--references", "--name=" + evidence_id],
               "patterns": []}
    packs = []
    for family, build_id in (("stl", "accessors-inline"), ("atl-mfc-string", "atl_string-inline"),
                             ("atl-com", "atl_com-inline")):
        identity = evidence_id + "-" + family
        selected = builds[build_id]
        profile = {"schema_version": 1, "kind": "library-feature-profile", "id": identity,
                   "implementation": "MSVC STL" if family == "stl" else "ATL",
                   "target": {"architecture": "x86_64", "format": "pe", "abi": "win64", "pointer_bits": 64, "endianness": "little"},
                   "configuration": {"build": build_id, "language": "c++17", "optimization": "O2", "lto": False,
                                     "macros": selected["configuration"], "arguments": selected["arguments"],
                                     "sdk": {"version": manifest["source"]["sdk_version"]}},
                   "source": {**{k: manifest["source"][k] for k in ("origin", "revision", "license")},
                              "files": selected["headers"]},
                   "compiler": {**manifest["compiler"], "version": manifest["compiler_version"]},
                   "layouts": layouts[family], "evidence": ref(manifest_path), "artifact_archive": ref(archive_path)}
        profile_path = root / "features/profiles" / (identity + ".json")
        write_json(profile_path, profile)
        symbols = symbol_set(evidence, build_id)
        rules = []
        for layout_name, layout in layouts[family].items():
            if family == "stl":
                fragment, prefix = {"string-char": ("basic_string@D", "nd_string_char"),
                                    "string-wchar": ("basic_string@_W", "nd_string_wide"),
                                    "vector-u32": ("vector@I", "nd_vector_u32"),
                                    "vector-u64": ("vector@_K", "nd_vector_u64")}[layout_name]
                for operation in ("size", "empty", "data", "capacity"):
                    symbol = one_symbol(symbols, "?" + operation + "@?$" + fragment)
                    rule = base_rule(f"msvc.{layout_name}.{operation}", family, operation, layout_name, layouts[family])
                    rule.update({"scope": ["whole-function", "inline-expression"],
                                 "pattern": string_accessor(layout, operation) if layout_name.startswith("string") else vector_accessor(layout, operation),
                                 "positive": [witness(build_id, symbol, "whole-function"),
                                              witness(build_id, prefix + "_" + operation + "_inline", "inline-expression")],
                                 "negative": [witness(build_id, "nd_user_range_" + (operation if operation in ("data", "empty") else "size"), "unproven-receiver"),
                                              witness("accessors-negative-configuration", prefix + "_" + operation, "configuration-mismatch")]})
                    if layout_name.startswith("vector") and operation == "size":
                        rule["negative"].append(witness(build_id, "nd_vector_bool_size", "wrong-layout"))
                    rules.append(rule)
            elif family == "atl-mfc-string":
                char = "D" if layout["element_bits"] == 8 else "_W"
                prefix = "nd_cstring_char" if char == "D" else "nd_cstring_wide"
                operations = (("construct", "construct"), ("copy", "copy"), ("assign", "assign")) if layout_name.startswith("cstring") else (
                    ("GetLength", "length"), ("IsEmpty", "empty"), ("GetString", "data"),
                    ("GetBuffer", "get_buffer"), ("ReleaseBuffer", "release_buffer"))
                for operation, probe in operations:
                    rule = base_rule(f"msvc.{layout_name}.{operation.lower()}", family, operation, layout_name, layouts[family])
                    if operation in ("construct", "copy", "assign"):
                        symbol = one_symbol(symbols, ("??4" if operation == "assign" else "??0") + "?$CStringT@" + char,
                                            "@XZ" if operation == "construct" else "@AEBV01@@Z")
                    else:
                        symbol = one_symbol(symbols, "?" + operation + "@?$CSimpleStringT@" + char + "$0A@")
                    rule["positive"] = [witness(build_id, symbol, "whole-function")]
                    rule["negative"] = [witness(build_id, "nd_user_IsEmpty" if operation == "IsEmpty" else "nd_user_GetLength", "unproven-receiver")]
                    if operation in ("GetLength", "IsEmpty", "GetString"):
                        rule["scope"] = ["whole-function", "inline-expression"]
                        rule["pattern"] = string_accessor(layout, operation, atl=True)
                        rule["positive"].append(witness(build_id, prefix + "_" + probe + "_inline", "inline-expression"))
                    else:
                        require(symbol in patterns, f"library function has no usable byte pattern: {symbol}")
                        parsed = patterns[symbol]
                        require(parsed.names == (symbol,), "gated byte pattern has unexpected entry aliases")
                        path = root / "features/patterns" / (rule["id"] + ".pat.txt")
                        path.write_text(parsed.text + "\n---\n")
                        subprocess.run([str(sigmaker), "--verify", str(path)], check=True, capture_output=True)
                        rule["scope"] = ["whole-function"]
                        rule["pattern"] = {"kind": "byte-pattern", "file": ref(path), "symbol": symbol,
                                           "generator": "neverd-sigmaker", "fixed_bytes_min": 16}
                        receipt["patterns"].append(ref(path))
                    rules.append(rule)
            else:
                for operation, policy in COM_POLICIES.items():
                    base = layout_name == "ccomptrbase-iunknown"
                    if base and operation != "Release":
                        continue
                    stem, suffix = {
                        "construct": ("??0?$CComPtr@", "@XZ"), "copy": ("??0?$CComPtr@", "@AEBV01@@Z"),
                        "assign": ("??4?$CComPtr@", ""), "Release": ("?Release@?$CComPtrBase@", ""),
                        "destroy": ("??1?$CComPtr@", "")}[operation]
                    symbol = one_symbol(symbols, stem, suffix)
                    rule = base_rule("msvc." + layout_name + "." + operation.lower(), family, operation, layout_name, layouts[family])
                    inline = "nd_com_" + operation.lower()
                    if operation in ("Release", "assign"):
                        inline += "_inline"
                    rule.update({"scope": ["whole-function", "inline-region"],
                                 "pattern": {"kind": "com-lifetime", "pointer_offset": layout["pointer_offset"],
                                             "interface_type": "IUnknown", "addref_slot": 1, "release_slot": 2,
                                             "policy": policy, "self_assignment": "skip-equal-pointer" if operation == "assign" else "not-applicable"},
                                 "positive": [witness(build_id, symbol, "whole-function"), witness(build_id, inline, "inline-region")],
                                 "negative": [witness(build_id, "nd_user_com_release", "unproven-receiver"),
                                              witness(build_id, "nd_unknown_release", "unproven-receiver")]})
                    if operation == "Release":
                        rule["scope"] = ["whole-function"] if base else ["inline-region"]
                        rule["positive"] = [rule["positive"][0 if base else 1]]
                    for name, expectation in (("nd_user_release_then_clear", "wrong-call-order"),
                                              ("nd_user_release_without_guard", "missing-null-guard"),
                                              ("nd_user_clear_then_addref", "wrong-interface-slot")):
                        if operation == "Release" and name in symbols:
                            rule["negative"].append(witness(build_id, name, expectation))
                    if operation == "assign" and "nd_user_assign_release_first" in symbols:
                        rule["negative"].append(witness(build_id, "nd_user_assign_release_first", "wrong-call-order"))
                    rules.append(rule)
        pack = {"schema_version": 1, "kind": "library-feature-pack", "id": identity,
                "profile": ref(profile_path), "rules": rules,
                "verification": {"data_verified": True, "consumer_verified": False}}
        pack_path = root / "features/rules" / (identity + ".json")
        write_json(pack_path, pack)
        validate_pack(root, pack_path)
        packs.append(pack_path)
    write_json(root / "features/evidence" / (evidence_id + "-byte-generation.json"), receipt)
    return packs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--neverd-source", type=Path, required=True)
    parser.add_argument("--sigmaker", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        for path in build(args.root.resolve(), args.evidence.resolve(), args.neverd_source.resolve(), args.sigmaker.resolve()):
            print(path)
    except (FeatureError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"MSVC feature generation: {error}\n")
