#!/usr/bin/env python3
"""Compare real rebuilt compiler artifacts, not just their recorded hashes."""
from __future__ import annotations

import argparse
from pathlib import Path

from build_library_feature_probes import describe, write_json
from validate_library_features import FeatureError, read_json, require


def verify(first: Path, second: Path) -> dict:
    a, b = (read_json(p / "manifest.json") for p in (first, second))
    require(a["status"] == b["status"] == "produced", "incomplete compiler run")
    for key in ("target", "source", "compiler", "compiler_version", "generator", "builds"):
        require(a[key] == b[key], f"rebuild used different {key}")
    stable = []
    artifacts = [{entry["path"]: entry for entry in m["artifacts"]} for m in (a, b)]
    for name in sorted(artifacts[0]):
        if not name.endswith((".o", ".obj", ".s", ".asm", ".ll")):
            continue
        require("/" not in name and "\\" not in name and name in artifacts[1], "missing rebuilt artifact")
        records = [describe(p / name) for p in (first, second)]
        require(all(record == entries[name] for record, entries in zip(records, artifacts)),
                f"recorded rebuild digest is stale: {name}")
        require(records[0] == records[1], f"rebuild differs: {name}")
        stable.append(records[0])
    require(len(stable) >= 2, "no compiled artifacts to compare")
    return {"kind": "library-feature-reproduction", "artifacts": stable,
            "first_manifest": describe(first / "manifest.json"),
            "second_manifest": describe(second / "manifest.json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.first, args.second)
        if args.report:
            write_json(args.report, result)
        print(f"reproduced {len(result['artifacts'])} object/assembly/IR artifacts")
    except (FeatureError, OSError, KeyError, ValueError) as error:
        parser.exit(1, f"library feature rebuild: {error}\n")
