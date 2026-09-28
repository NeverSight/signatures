#!/usr/bin/env python3
"""Collect one row of .github/msvc-legacy-matrix.json from its downloaded media.

A row names Microsoft's installation media of an old Visual C++ toolset, the
SHA-256 it must have, the Windows Installer packages that carry the
libraries, and the directories to collect.  This unpacks the packages with
extract_legacy_toolset.py and collects them with collect_msvc_libraries.py's
toolset-legacy command, naming each asset after the toolset version the
library package states.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_MATRIX = HERE.parent / ".github" / "msvc-legacy-matrix.json"


def row_named(matrix: Path, name: str) -> dict:
    rows = [row for row in json.loads(matrix.read_text(encoding="utf-8")) if row["name"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{matrix.name} has no row {name!r}")
    return rows[0]


def extraction_command(row: dict, iso: Path, work: Path) -> list[str]:
    command = [sys.executable, str(HERE / "extract_legacy_toolset.py"),
               "--iso", str(iso), "--sha256", row["sha256"],
               "--vc-directory", row["vc_directory"],
               "--version-package", row["version_package"],
               "--work", str(work)]
    for member in row["members"]:
        command += ["--member", member]
    if row["bundle"]:
        command += ["--bundle", row["bundle"]]
    return command


def collection_command(row: dict, extracted: dict, output: Path, level: int) -> list[str]:
    command = [sys.executable, str(HERE / "collect_msvc_libraries.py"), "toolset-legacy",
               "--vc-directory", extracted["vc_directory"],
               "--vs-year", str(row["vs_year"]),
               "--toolset-version", extracted["product_version"],
               "--media", row["media"], "--media-sha256", row["sha256"],
               "--install-root", extracted["root"],
               "--atlmfc" if row["atlmfc"] else "--no-atlmfc",
               "--zstd-level", str(level), "--output", str(output)]
    for arch in row["arches"]:
        command += ["--arch", arch]
    for extra in row["extra_directories"]:
        command += ["--extra-directory", extra]
    return command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--name", required=True, help="the matrix row to collect")
    parser.add_argument("--iso", type=Path, required=True, help="the row's downloaded media")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zstd-level", type=int, default=15)
    args = parser.parse_args(argv)

    row = row_named(args.matrix, args.name)
    extracted = json.loads(subprocess.run(extraction_command(row, args.iso, args.work),
                                          check=True, stdout=subprocess.PIPE, text=True).stdout)
    subprocess.run(collection_command(row, extracted, args.output, args.zstd_level), check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
