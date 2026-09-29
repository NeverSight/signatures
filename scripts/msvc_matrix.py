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
on Linux and are selected by the same `--rows`, as are the rows of
.github/masm32-matrix.json (MASM32 SDK releases, built under Wine; see
collect_masm32.py), .github/mingw-matrix.json (C libraries built with the
MinGW-w64 cross compilers; see collect_mingw_library.py),
.github/fedora-matrix.json (C libraries built with a Fedora release's own
compilers; see collect_fedora_library.py), .github/elf-matrix.json (the
packages rizin's ELF files came from; see collect_elf_packages.py) and
.github/homebrew-matrix.json (the Homebrew bottles the macho/ files are built
from; see collect_homebrew_bottles.py).
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
DEFAULT_MASM32_MATRIX = (
    Path(__file__).resolve().parents[1] / ".github" / "masm32-matrix.json"
)
DEFAULT_MINGW_MATRIX = (
    Path(__file__).resolve().parents[1] / ".github" / "mingw-matrix.json"
)
DEFAULT_FEDORA_MATRIX = (
    Path(__file__).resolve().parents[1] / ".github" / "fedora-matrix.json"
)
DEFAULT_ELF_MATRIX = (
    Path(__file__).resolve().parents[1] / ".github" / "elf-matrix.json"
)
DEFAULT_HOMEBREW_MATRIX = (
    Path(__file__).resolve().parents[1] / ".github" / "homebrew-matrix.json"
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


MASM32_FIELDS = {
    "name": str,
    "version": str,
    "media": str,
    "sha256": str,
    "build": list,
}


ELF_FIELDS = {
    "name": str,
    "library": str,
    "directories": list,
    "archives": list,
}

# Where in its packages a row's archives lie, when their names alone would
# also take other archives: an NDK carries its toolchains' host libraries.
ELF_OPTIONAL = {"paths": list}


MINGW_FIELDS = {
    "name": str,
    "library": str,
    "version": str,
    "source": str,
    "sha256": str,
    "sources": list,
    "archive": str,
    "cflags": list,
    "arches": list,
}


HOMEBREW_FIELDS = {
    "name": str,
    "library": str,
    "formula": str,
    "version": str,
    "archives": list,
    "bottles": list,
}


FEDORA_FIELDS = {
    "name": str,
    "library": str,
    "version": str,
    "source": str,
    "sha256": str,
    "target": str,
    "archive": str,
    "builds": list,
    "packages": list,
}


def load(path: Path, fields: dict = FIELDS, optional: dict | None = None) -> list[dict]:
    optional = optional or {}
    rows = json.loads(path.read_text(encoding="utf-8"))
    names = set()
    for row in rows:
        missing = set(fields) - set(row)
        extra = set(row) - set(fields) - set(optional)
        if missing or extra:
            raise SystemExit(f"{row.get('name', '?')}: missing {sorted(missing)}, "
                             f"unexpected {sorted(extra)}")
        for key, kind in (fields | optional).items():
            if key in row and not isinstance(row[key], kind):
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
    parser.add_argument("--masm32-matrix", type=Path, default=DEFAULT_MASM32_MATRIX)
    parser.add_argument("--mingw-matrix", type=Path, default=DEFAULT_MINGW_MATRIX)
    parser.add_argument("--fedora-matrix", type=Path, default=DEFAULT_FEDORA_MATRIX)
    parser.add_argument("--elf-matrix", type=Path, default=DEFAULT_ELF_MATRIX)
    parser.add_argument("--homebrew-matrix", type=Path, default=DEFAULT_HOMEBREW_MATRIX)
    parser.add_argument("--rows", default="", help="row names to keep, comma or space separated")
    parser.add_argument("--github-output", type=Path, help="append matrix=<json> to this file")
    args = parser.parse_args(argv)

    windows = load(args.matrix)
    legacy = load(args.legacy_matrix, LEGACY_FIELDS)
    masm32 = load(args.masm32_matrix, MASM32_FIELDS)
    mingw = load(args.mingw_matrix, MINGW_FIELDS)
    fedora = load(args.fedora_matrix, FEDORA_FIELDS)
    elf = load(args.elf_matrix, ELF_FIELDS, ELF_OPTIONAL)
    homebrew = load(args.homebrew_matrix, HOMEBREW_FIELDS)
    rows = select(windows, args.rows, legacy + masm32 + mingw + fedora + elf + homebrew)
    legacy_rows = select(legacy, args.rows, windows + masm32 + mingw + fedora + elf + homebrew)
    masm32_rows = select(masm32, args.rows, windows + legacy + mingw + fedora + elf + homebrew)
    mingw_rows = select(mingw, args.rows, windows + legacy + masm32 + fedora + elf + homebrew)
    fedora_rows = select(fedora, args.rows, windows + legacy + masm32 + mingw + elf + homebrew)
    elf_rows = select(elf, args.rows, windows + legacy + masm32 + mingw + fedora + homebrew)
    homebrew_rows = select(homebrew, args.rows, windows + legacy + masm32 + mingw + fedora + elf)
    matrix = json.dumps({"include": [for_workflow(row) for row in rows]}, separators=(",", ":"))
    legacy_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in legacy_rows]}, separators=(",", ":")
    )
    masm32_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in masm32_rows]}, separators=(",", ":")
    )
    mingw_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in mingw_rows]}, separators=(",", ":")
    )
    fedora_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in fedora_rows]}, separators=(",", ":")
    )
    elf_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in elf_rows]}, separators=(",", ":")
    )
    homebrew_matrix = json.dumps(
        {"include": [{"name": row["name"]} for row in homebrew_rows]}, separators=(",", ":")
    )
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as out:
            out.write(f"matrix={matrix}\n")
            out.write(f"rows={len(rows)}\n")
            out.write(f"legacy_matrix={legacy_matrix}\n")
            out.write(f"legacy_rows={len(legacy_rows)}\n")
            out.write(f"masm32_matrix={masm32_matrix}\n")
            out.write(f"masm32_rows={len(masm32_rows)}\n")
            out.write(f"mingw_matrix={mingw_matrix}\n")
            out.write(f"mingw_rows={len(mingw_rows)}\n")
            out.write(f"fedora_matrix={fedora_matrix}\n")
            out.write(f"fedora_rows={len(fedora_rows)}\n")
            out.write(f"elf_matrix={elf_matrix}\n")
            out.write(f"elf_rows={len(elf_rows)}\n")
            out.write(f"homebrew_matrix={homebrew_matrix}\n")
            out.write(f"homebrew_rows={len(homebrew_rows)}\n")
    print("\n".join(row["name"] for row in rows + legacy_rows + masm32_rows + mingw_rows
                    + fedora_rows + elf_rows + homebrew_rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
