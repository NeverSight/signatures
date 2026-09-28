#!/usr/bin/env python3
"""Build and collect a C library with the MinGW-w64 cross compilers.

rizin's sigdb-source holds pattern files for a library it built with MinGW
itself: mingw32-zlib, zlib 1.3 compiled without optimization, whose source
archive's SHA-1 it records. Each row of .github/mingw-matrix.json names such a
library: where its source archive is published, the SHA-256 that archive must
have, the files that make up the library, the compiler flags, and the
architectures to build.

Each architecture's objects come from Ubuntu's MinGW-w64 GCC and are archived
with its ar in deterministic mode. GCC writes no time stamp into a COFF
object, so two builds give the same archive. Which compiler rizin used is not
recorded, so the asset does not claim to be rizin's build: the migration
leaves out only the imported lines whose bytes this build reproduces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_msvc_libraries as collector  # noqa: E402

DEFAULT_MATRIX = HERE.parent / ".github" / "mingw-matrix.json"

# The MinGW-w64 target triple of each architecture this builds for.
TARGETS = {"x86": "i686-w64-mingw32", "x64": "x86_64-w64-mingw32"}


class BuildError(RuntimeError):
    """The source archive or its build is not what the matrix row says."""


def row_named(matrix: Path, name: str) -> dict:
    rows = [row for row in json.loads(matrix.read_text(encoding="utf-8")) if row["name"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{matrix.name} has no row {name!r}")
    return rows[0]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(archive: Path, work: Path) -> Path:
    """Unpack a source archive into work/source and return its one top directory."""

    destination = work / "source"
    destination.mkdir(parents=True)
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter="data")
    tops = list(destination.iterdir())
    if len(tops) != 1 or not tops[0].is_dir():
        raise BuildError(f"{archive.name} does not unpack into one directory")
    return tops[0]


def build(root: Path, row: dict, prefix: str, output: Path) -> Path:
    """Compile the row's sources with <prefix>-gcc and archive them with <prefix>-ar."""

    output.mkdir(parents=True)
    objects = []
    for source in row["sources"]:
        path = root / source
        if not path.is_file():
            raise BuildError(f"{root.name} holds no {source}")
        target = output / (PurePosixPath(source).stem + ".o")
        # Named relative to the source tree, so no object records where the
        # tree was unpacked.
        subprocess.run([f"{prefix}-gcc", *row["cflags"], "-c", source, "-o", str(target)],
                       check=True, cwd=root)
        objects.append(target)
    library = output / row["archive"]
    # D: zero dates, owners and modes, so the archive is the same every run.
    subprocess.run([f"{prefix}-ar", "rcsD", str(library), *map(str, objects)], check=True)
    return library


def compiler_version(prefix: str) -> str:
    result = subprocess.run([f"{prefix}-gcc", "--version"], capture_output=True, text=True,
                            check=True)
    return result.stdout.splitlines()[0].strip()


def packages(prefix: str) -> dict[str, str]:
    """The Debian packages of the compiler and of the MinGW-w64 headers, by version.

    Ubuntu's MinGW-w64 GCC names no release in its version ("13-win32"), and
    the code it makes depends on both.
    """

    compiler = shutil.which(f"{prefix}-gcc")
    if compiler is None or shutil.which("dpkg-query") is None:
        return {}
    owner = subprocess.run(["dpkg-query", "-S", str(Path(compiler).resolve())],
                           capture_output=True, text=True)
    names = [owner.stdout.split(":", 1)[0].strip()] if owner.returncode == 0 else []
    names.append(f"mingw-w64-{prefix.split('-', 1)[0].replace('_', '-')}-dev")
    found = {}
    for name in names:
        version = subprocess.run(["dpkg-query", "-W", "-f=${Version}", name],
                                 capture_output=True, text=True)
        if version.returncode == 0 and version.stdout.strip():
            found[name] = version.stdout.strip()
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--name", required=True, help="the matrix row to build")
    parser.add_argument("--source", type=Path, required=True,
                        help="the row's downloaded source archive")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zstd-level", type=int, default=15)
    args = parser.parse_args(argv)

    row = row_named(args.matrix, args.name)
    if sha256(args.source) != row["sha256"]:
        print(f"error: {args.source.name} does not have the expected SHA-256", file=sys.stderr)
        return 1
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        root = unpack(args.source, work)
        for arch in row["arches"]:
            prefix = TARGETS[arch]
            library = build(root, row, prefix, work / arch)
            collector.emit_asset(
                output=args.output,
                asset=f"{row['library']}-{row['version']}-{arch}",
                kind="library",
                arch=arch,
                files=[collector.CollectedFile(
                    library, PurePosixPath(row["library"], arch, row["archive"]))],
                extra={
                    "library": row["library"],
                    "library_version": row["version"],
                    "source": {"url": row["source"], "sha256": row["sha256"]},
                    "cflags": row["cflags"],
                    # Not rizin's build: only what its bytes reproduce
                    # supersedes an imported line.
                    "reproduces_import": False,
                    "built_with": compiler_version(prefix),
                    "packages": packages(prefix),
                },
                level=args.zstd_level,
            )
    except (BuildError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
