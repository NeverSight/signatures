#!/usr/bin/env python3
"""Turn .github/msvc-matrix.json into the collection workflow's job matrix.

Each row is one Windows runner: a Visual Studio toolset with every
architecture it targets, or one Windows SDK. A row lists what has to be
installed first (Visual Studio installer components, Chocolatey packages, or a
Windows SDK's standalone installer, for SDKs the image's installer no longer
offers), the collector arguments, and how to build the validation probes with
the same toolset.

`--rows` keeps only the named rows, so a run can supply what an earlier one
missed without repeating every row. Naming a row that does not exist is an
error, not an empty run.

.github/msvc-legacy-matrix.json lists the toolsets no current image can
install, Visual Studio 2005 to 2013: each row names Microsoft's installation
media and what to unpack from it (see collect_legacy_media.py).  Its rows run
on Linux and are selected by the same `--rows`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_MATRIX = Path(__file__).resolve().parents[1] / ".github" / "msvc-matrix.json"
DEFAULT_LEGACY_MATRIX = (
    Path(__file__).resolve().parents[1] / ".github" / "msvc-legacy-matrix.json"
)

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
    "sdk_installer": str,
}


LEGACY_FIELDS = {
    "name": str,
    "vs_year": int,
    "media": str,
    "sha256": str,
    "members": list,
    "bundle": str,
    "vc_directory": str,
    "version_package": str,
    "atlmfc": bool,
    "arches": list,
    "extra_directories": list,
}


def load(path: Path, fields: dict = FIELDS) -> list[dict]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    names = set()
    for row in rows:
        missing = set(fields) - set(row)
        extra = set(row) - set(fields)
        if missing or extra:
            raise SystemExit(f"{row.get('name', '?')}: missing {sorted(missing)}, "
                             f"unexpected {sorted(extra)}")
        for key, kind in fields.items():
            if not isinstance(row[key], kind):
                raise SystemExit(f"{row['name']}: {key} must be {kind.__name__}")
        if row["name"] in names:
            raise SystemExit(f"{row['name']}: duplicate row")
        names.add(row["name"])
    return rows


def select(rows: list[dict], wanted: str, others: list[dict] = ()) -> list[dict]:
    """The rows named in `wanted`, or every row when it names none.

    `others` are the rows of the other matrix: a name must be in one of them.
    """

    names = [name for name in wanted.replace(",", " ").split() if name]
    if not names:
        return rows
    known = {row["name"] for row in rows} | {row["name"] for row in others}
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
    parser.add_argument("--legacy-matrix", type=Path, default=DEFAULT_LEGACY_MATRIX)
    parser.add_argument("--rows", default="", help="row names to keep, comma or space separated")
    parser.add_argument("--github-output", type=Path, help="append matrix=<json> to this file")
    args = parser.parse_args(argv)

    windows = load(args.matrix)
    legacy = load(args.legacy_matrix, LEGACY_FIELDS)
    rows = select(windows, args.rows, legacy)
    legacy_rows = select(legacy, args.rows, windows)
    matrix = json.dumps({"include": [for_workflow(row) for row in rows]}, separators=(",", ":"))
    legacy_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in legacy_rows]}, separators=(",", ":")
    )
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as out:
            out.write(f"matrix={matrix}\n")
            out.write(f"rows={len(rows)}\n")
            out.write(f"legacy_matrix={legacy_matrix}\n")
            out.write(f"legacy_rows={len(legacy_rows)}\n")
    print("\n".join(row["name"] for row in rows + legacy_rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
