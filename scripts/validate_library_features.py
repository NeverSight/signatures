#!/usr/bin/env python3
"""Validate feature contracts and their exact on-disk evidence, without matching IR."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

MAX_BYTES = 8 * 1024 * 1024
ID = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
WIDTHS = (8, 16, 32, 64)
ARITY = {"input": 0, "constant": 0, "load": 1, "zext": 1, "sext": 1,
         "select": 3, **{op: 2 for op in (
             "add", "sub", "mul", "udiv", "and", "or", "xor", "shl", "lshr", "ashr",
             "eq", "ne", "ult", "ule", "slt")}}
COMPARE = {"eq", "ne", "ult", "ule", "slt"}
FAMILIES = {"stl", "atl-mfc-string", "atl-com", "libc"}
OPERATIONS = {"stl": {"size", "empty", "data", "capacity"},
              "atl-mfc-string": {"construct", "copy", "assign", "GetLength", "IsEmpty", "GetString", "GetBuffer", "ReleaseBuffer"},
              "atl-com": {"construct", "copy", "assign", "Release", "destroy"},
              "libc": {"memcpy", "memmove", "memset", "memcmp", "strlen"}}


class FeatureError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FeatureError(message)


def keys(value: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    require(isinstance(value, dict), "expected an object")
    require(set(value) >= required and set(value) <= required | optional,
            f"missing/unknown fields: expected {sorted(required)}, got {sorted(value)}")
    return value


def identifier(value: object) -> None:
    require(isinstance(value, str) and ID.fullmatch(value) is not None, "invalid identifier")


def read_json(path: Path) -> dict:
    require(path.stat().st_size <= MAX_BYTES, f"JSON exceeds {MAX_BYTES} bytes")
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def finite(value: str) -> None:
        raise FeatureError(f"non-finite JSON number: {value}")
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique,
                      parse_constant=finite)
    require(isinstance(data, dict), "document must be an object")
    return data


def checked_path(root: Path, value: object) -> Path:
    require(isinstance(value, str) and 0 < len(value) < 1024, "invalid artifact path")
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in value,
            "artifact path must stay inside the repository")
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()), "artifact symlink escapes repository")
    require(path.is_file(), f"missing evidence: {value}")
    return path


def verify_file(root: Path, record: dict) -> Path:
    keys(record, {"path", "sha256"}, {"size"})
    require(isinstance(record["sha256"], str) and HEX.fullmatch(record["sha256"]) is not None,
            "invalid SHA-256")
    path = checked_path(root, record["path"])
    if "size" in record:
        require(type(record["size"]) is int and record["size"] == path.stat().st_size,
                f"wrong size: {record['path']}")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"],
            f"hash mismatch: {record['path']}")
    return path


def expression(pattern: dict) -> None:
    keys(pattern, {"nodes", "result"})
    nodes = pattern["nodes"]
    require(isinstance(nodes, list) and 1 <= len(nodes) <= 128, "expression node budget exceeded")
    seen = {}
    for node in nodes:
        keys(node, {"id", "op", "bits"}, {"args", "role", "value", "offset"})
        identifier(node["id"])
        require(node["id"] not in seen, "duplicate expression node")
        op, bits = node["op"], node["bits"]
        require(isinstance(op, str) and op in ARITY, "unsupported expression operator")
        require(type(bits) is int and bits in WIDTHS, "unsupported integer width")
        args = node.get("args", [])
        require(isinstance(args, list) and len(args) == ARITY[op], "wrong operator arity")
        require(all(isinstance(arg, str) and arg in seen for arg in args),
                "expression is cyclic or refers to a missing/forward node")
        widths = [seen[arg]["bits"] for arg in args]
        require(("role" in node) == (op == "input"), "role belongs only to an input")
        require(("value" in node) == (op == "constant"), "value belongs only to a constant")
        require(("offset" in node) == (op == "load"), "offset belongs only to a load")
        if op == "input":
            require(node["role"] in ("receiver", "argument"), "invalid input role")
        elif op == "constant":
            require(isinstance(node["value"], str) and
                    re.fullmatch(r"0x[0-9a-f]+", node["value"]) is not None, "constant must be hex")
            require(int(node["value"], 16) < (1 << bits), "constant does not fit its width")
        elif op == "load":
            require(widths == [64] and type(node["offset"]) is int and
                    -(1 << 20) <= node["offset"] <= (1 << 20), "invalid 64-bit load address/offset")
        elif op in ("zext", "sext"):
            require(widths[0] < bits, "extension must widen")
        elif op in COMPARE:
            require(bits == 8 and widths[0] == widths[1], "invalid comparison widths")
        elif op == "select":
            require(widths == [8, bits, bits], "invalid select widths")
        else:
            require(widths == [bits, bits], "binary operands must have the result width")
        seen[node["id"]] = node
    require(isinstance(pattern["result"], str) and pattern["result"] in seen, "missing expression result")
    reachable = set()
    def visit(name: str) -> None:
        if name not in reachable:
            reachable.add(name)
            for arg in seen[name].get("args", []):
                visit(arg)
    visit(pattern["result"])
    require(reachable == set(seen), "unused expression nodes cannot supply evidence")
    require(any(seen[name].get("role") == "receiver" for name in reachable),
            "library expression must bind its receiver")


def evidence_symbols(root: Path, profile: dict, manifest: dict) -> dict[str, set[str]]:
    archive = verify_file(root, profile["artifact_archive"])
    files = {entry["path"]: entry for entry in manifest["artifacts"]}
    require(len(files) == len(manifest["artifacts"]), "duplicate evidence artifact")
    symbols = {}
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(len(members) <= 512 and sum(m.size for m in members) <= 128 * 1024 * 1024,
                "evidence archive exceeds its budget")
        seen = set()
        for member in members:
            name = member.name
            require(member.isfile() and "/" not in name and "\\" not in name and
                    name not in (".", "..") and name not in seen, "invalid or duplicate archive member")
            seen.add(name)
            require(name in files, "archive contains an unrecorded artifact")
            content = source.extractfile(member).read()
            record = files[name]
            require(len(content) == record["size"] and
                    hashlib.sha256(content).hexdigest() == record["sha256"], "artifact digest mismatch")
            suffix = "-symbols.stdout.txt"
            if name.endswith(suffix):
                symbols[name[:-len(suffix)]] = {line.split()[-1] for line in content.decode("utf-8").splitlines()
                                               if len(line.split()) >= 3}
        require(seen == set(files), "evidence archive is incomplete")
    return symbols


COM_POLICIES = {
    "construct": "zero-initialize", "copy": "store-before-addref",
    "assign": "addref-publish-release", "Release": "clear-before-release",
    "destroy": "release-without-clear",
}


def pattern_contract(root: Path, rule: dict) -> None:
    pattern = rule["pattern"]
    if "kind" not in pattern:
        expression(pattern)
        require(set(rule["scope"]) <= {"whole-function", "inline-expression"},
                "expression rule has an effect-region scope")
        return
    if pattern["kind"] == "com-lifetime":
        keys(pattern, {"kind", "pointer_offset", "interface_type", "addref_slot", "release_slot",
                       "policy", "self_assignment"})
        require(rule["family"] == "atl-com" and rule["receiver_type"] in (
                    "ATL::CComPtr<IUnknown>", "ATL::CComPtrBase<IUnknown>"),
                "COM pattern requires the exact supported receiver")
        require(rule["receiver_type"] != "ATL::CComPtrBase<IUnknown>" or rule["operation"] == "Release",
                "unsupported CComPtrBase operation")
        require(pattern["interface_type"] == "IUnknown" and
                type(pattern["pointer_offset"]) is int and pattern["pointer_offset"] == 0 and
                type(pattern["addref_slot"]) is int and pattern["addref_slot"] == 1 and
                type(pattern["release_slot"]) is int and pattern["release_slot"] == 2,
                "unsupported COM interface or layout")
        require(pattern["policy"] == COM_POLICIES.get(rule["operation"]), "wrong COM effect policy")
        require(pattern["self_assignment"] == (
            "skip-equal-pointer" if rule["operation"] == "assign" else "not-applicable"),
            "wrong COM self-assignment policy")
        require(set(rule["scope"]) <= {"whole-function", "inline-region"}, "wrong COM scope")
        return
    if pattern["kind"] == "byte-pattern":
        keys(pattern, {"kind", "file", "symbol", "generator", "fixed_bytes_min"})
        path = verify_file(root, pattern["file"])
        require(path.suffix == ".txt", "gated byte patterns must not be auto-loaded as .pat files")
        require(pattern["fixed_bytes_min"] == 16 and type(pattern["fixed_bytes_min"]) is int,
                "byte feature cannot lower the existing matcher threshold")
        require(pattern["generator"] == "neverd-sigmaker", "unknown byte pattern producer")
        require(rule["scope"] == ["whole-function"], "byte patterns do not prove an inline region")
        require(isinstance(pattern["symbol"], str) and pattern["symbol"], "missing byte pattern symbol")
        rows = [line.split() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith((";", "#", "---"))]
        require(len(rows) == 1 and len(rows[0]) >= 6, "expected one generated byte pattern")
        row = rows[0]
        require(row[4:6] == [":0000", pattern["symbol"]], "wrong byte pattern entry symbol")
        # This is an admission check, not another .pat parser or matcher.
        # The producer must run neverd-sigmaker --verify as well.
        require(re.fullmatch(r"(?:[0-9A-Fa-f]{2}|\.\.)+", row[0]) is not None and
                sum(row[0][i:i+2] != ".." for i in range(0, len(row[0]), 2)) >= 16,
                "insufficient fixed leading bytes")
        return
    raise FeatureError("unsupported library pattern kind")


def validate_pack(root: Path, path: Path) -> dict:
    pack = read_json(path)
    keys(pack, {"schema_version", "kind", "id", "profile", "rules", "verification"})
    require(pack["schema_version"] == 1 and type(pack["schema_version"]) is int,
            "unsupported schema version")
    require(pack["kind"] == "library-feature-pack", "wrong document kind")
    identifier(pack["id"])
    profile_path = verify_file(root, pack["profile"])
    profile = read_json(profile_path)
    keys(profile, {"schema_version", "kind", "id", "implementation", "target", "configuration",
                   "source", "compiler", "layouts", "evidence", "artifact_archive"})
    require(profile["schema_version"] == 1 and profile["kind"] == "library-feature-profile",
            "unsupported profile schema")
    identifier(profile["id"])
    target = keys(profile["target"], {"architecture", "format", "abi", "pointer_bits", "endianness"})
    require(target["pointer_bits"] == 64 and target["endianness"] == "little", "unsupported target")
    require((target["architecture"], target["format"], target["abi"]) in (
        ("aarch64", "macho", "darwin-aapcs64"), ("x86_64", "pe", "win64"),
        ("x86_64", "elf", "sysv-amd64")), "inconsistent architecture/format/ABI")
    source = keys(profile["source"], {"origin", "revision", "license", "files"})
    require(all(isinstance(source[k], str) and source[k] for k in ("origin", "revision", "license")),
            "source provenance is incomplete")
    require(isinstance(source["files"], list) and source["files"], "source hashes are missing")
    for item in source["files"]:
        keys(item, {"path", "size", "sha256"})
        require(isinstance(item["sha256"], str) and HEX.fullmatch(item["sha256"]) is not None,
                "invalid source hash")
    evidence = read_json(verify_file(root, profile["evidence"]))
    require(evidence.get("kind") == "library-feature-evidence" and evidence.get("status") == "produced",
            "producer evidence is incomplete")
    builds = {b["id"]: b for b in evidence["builds"]}
    require(len(builds) == len(evidence["builds"]), "duplicate producer builds")
    configuration = keys(profile["configuration"], {"build", "language", "optimization", "lto",
                                                    "macros", "arguments", "sdk"})
    require(configuration["build"] in builds, "profile references a missing producer build")
    build = builds[configuration["build"]]
    require(configuration["macros"] == build["configuration"] and
            configuration["arguments"] == build["arguments"], "profile configuration contradicts the producer")
    require(source["files"] == build["headers"], "profile header hashes contradict the producer")
    require(all(source[k] == evidence["source"][k] for k in ("origin", "revision", "license")),
            "profile source identity contradicts the producer")
    compiler = keys(profile["compiler"], {"path", "size", "sha256", "version"})
    require({k: compiler[k] for k in ("path", "size", "sha256")} == evidence["compiler"] and
            compiler["version"] == evidence["compiler_version"], "profile compiler contradicts the producer")
    symbols = evidence_symbols(root, profile, evidence)
    require(isinstance(profile["layouts"], dict) and profile["layouts"], "layouts are missing")
    verification = keys(pack["verification"], {"data_verified", "consumer_verified"})
    require(verification["data_verified"] is True, "data gate has not passed")
    require(verification["consumer_verified"] is False,
            "consumer success requires a separately reviewed NeverD test receipt")
    require(isinstance(pack["rules"], list) and 0 < len(pack["rules"]) <= 256, "invalid rule count")
    ids = set()
    for rule in pack["rules"]:
        keys(rule, {"id", "revision", "family", "operation", "receiver_type", "layout",
                    "identity_evidence", "scope", "pattern", "positive", "negative"})
        identifier(rule["id"])
        require(rule["id"] not in ids, "duplicate rule ID")
        ids.add(rule["id"])
        require(type(rule["revision"]) is int and rule["revision"] >= 1, "invalid rule revision")
        require(rule["family"] in FAMILIES, "unknown library family")
        require(isinstance(rule["operation"], str) and rule["operation"] in OPERATIONS[rule["family"]],
                "unsupported library operation")
        require(rule["layout"] in profile["layouts"], "missing layout")
        require((isinstance(rule["receiver_type"], str) and rule["receiver_type"]) or
                (rule["family"] == "libc" and rule["receiver_type"] is None), "missing receiver type")
        require(rule["receiver_type"] == profile["layouts"][rule["layout"]]["receiver_type"],
                "receiver type contradicts its layout")
        require(rule["identity_evidence"] in ("authoritative-receiver", "authenticated-call-relationship") or
                (rule["family"] == "libc" and rule["identity_evidence"] == "byte-signature" and
                 rule["pattern"].get("kind") == "byte-pattern"),
                "layout alone cannot establish a library identity")
        require(isinstance(rule["scope"], list) and rule["scope"] and
                len(set(rule["scope"])) == len(rule["scope"]) and
                set(rule["scope"]) <= {"whole-function", "inline-expression", "inline-region"}, "unsupported scope")
        pattern_contract(root, rule)
        for category in ("positive", "negative"):
            require(isinstance(rule[category], list) and rule[category], f"missing {category} witnesses")
            for witness in rule[category]:
                keys(witness, {"build", "symbol", "expectation"})
                require(witness["build"] in builds, "witness references an unknown build")
                require(isinstance(witness["symbol"], str) and witness["symbol"], "missing witness symbol")
                require(witness["symbol"] in symbols.get(witness["build"], set()),
                        "witness symbol is absent from the compiled evidence")
                require(witness["expectation"] in (
                    "inline-expression", "inline-region", "whole-function") if category == "positive" else
                    witness["expectation"] in (
                        "unproven-receiver", "configuration-mismatch", "wrong-layout",
                        "wrong-stride", "ordered-memory", "extra-effects",
                        "wrong-call-order", "missing-null-guard", "wrong-interface-slot"), "invalid witness expectation")
        require({w["expectation"] for w in rule["positive"]} == set(rule["scope"]),
                "every supported scope needs a compiled positive witness")
        if rule["pattern"].get("kind") == "byte-pattern":
            require(all(w["symbol"] == rule["pattern"]["symbol"] for w in rule["positive"]),
                    "byte rule and positive callee disagree")
    return pack


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        paths = sorted((args.root / "features/rules").glob("*.json"))
        require(bool(paths), "no feature packs")
        ids = set()
        count = 0
        for path in paths:
            pack = validate_pack(args.root, path)
            require(pack["id"] not in ids, "duplicate pack ID")
            ids.add(pack["id"])
            count += len(pack["rules"])
        print(f"validated {len(paths)} packs / {count} rules; consumer matching is a separate gate")
    except (FeatureError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"library features: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
