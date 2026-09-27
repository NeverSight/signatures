#!/usr/bin/env python3
"""Turn .github/msvc-matrix.json into the collection workflow's job matrix.

Each row is one Windows runner: a Visual Studio toolset with every
architecture it targets, or one Windows SDK. A row lists what has to be
installed first -- Visual Studio installer components, or Chocolatey packages
for Windows SDKs the image's installer no longer offers -- the collector
arguments, and how to build the validation probes with the same toolset.

`--rows` keeps only the named rows, so a run can supply what an earlier one
missed without repeating every row. Naming a row that does not exist is an
error, not an empty run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_MATRIX = Path(__file__).resolve().parents[1] / ".github" / "msvc-matrix.json"

FIELDS = {
    "name": str,
    "runner": str,
    "vswhere_version": str,
    "components": list,
    "choco": list,
    "collect": str,
    "probe_arches": list,
    "probe_vcvars": str,
    "probe_winsdk": str,
    "probe_mfc": bool,
}


def load(path: Path) -> list[dict]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    names = set()
    for row in rows:
        missing = set(FIELDS) - set(row)
        extra = set(row) - set(FIELDS)
        if missing or extra:
            raise SystemExit(f"{row.get('name', '?')}: missing {sorted(missing)}, "
                             f"unexpected {sorted(extra)}")
        for key, kind in FIELDS.items():
            if not isinstance(row[key], kind):
                raise SystemExit(f"{row['name']}: {key} must be {kind.__name__}")
        if row["name"] in names:
            raise SystemExit(f"{row['name']}: duplicate row")
        names.add(row["name"])
    return rows


def select(rows: list[dict], wanted: str) -> list[dict]:
    names = [name for name in wanted.replace(",", " ").split() if name]
    if not names:
        return rows
    known = {row["name"] for row in rows}
    unknown = [name for name in names if name not in known]
    if unknown:
        raise SystemExit(f"unknown rows: {', '.join(unknown)}; known: {', '.join(sorted(known))}")
    return [row for row in rows if row["name"] in names]


def for_workflow(row: dict) -> dict:
    """The row with lists joined, as the workflow's steps take them."""

    entry = dict(row)
    entry["components"] = " ".join(row["components"])
    entry["choco"] = " ".join(row["choco"])
    entry["probe_arches"] = " ".join(row["probe_arches"])
    entry["probe_flags"] = "" if row["probe_mfc"] else "-NoMfc"
    del entry["probe_mfc"]
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--rows", default="", help="row names to keep, comma or space separated")
    parser.add_argument("--github-output", type=Path, help="append matrix=<json> to this file")
    args = parser.parse_args(argv)

    rows = select(load(args.matrix), args.rows)
    matrix = json.dumps({"include": [for_workflow(row) for row in rows]}, separators=(",", ":"))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as out:
            out.write(f"matrix={matrix}\n")
    print("\n".join(row["name"] for row in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
