#!/usr/bin/env python3
"""Build and collect a C library with a Fedora release's own compilers.

rizin's sigdb-source holds pattern files for a library built on Fedora:
fedora-zlib, which signature-builds-zlib
(https://github.com/feliwir/signature-builds-zlib) made by configuring zlib
1.3 with CMake and no build type -- so without optimization -- and compiling
it with the machine's `gcc` and `clang`, for x86 and x64. Each row of
.github/fedora-matrix.json names such a library: its source archive and the
SHA-256 that archive must have, the CMake target and the archive it makes,
each build's compiler and flags, and the Fedora packages of those compilers
and of the headers they compile against, as Koji keeps them, with the SHA-256
each must have: the builds the release had when the lines were made.

This downloads and checks the packages, unpacks them into a root of their
own, configures and builds the library with CMake and Ninja once per build,
running each compiler from that root with the root as its system root, and
archives each architecture's builds as one ELF library asset. The compilers,
the source and the recipe are the ones the lines were made with, so the asset
claims to be rizin's build (`reproduces_import`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_msvc_libraries as collector  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402

DEFAULT_MATRIX = HERE.parent / ".github" / "fedora-matrix.json"

# The RPM payload compressors, by magic.
DECOMPRESSORS = {b"\x28\xb5\x2f\xfd": ["zstd", "-dc"], b"\xfd7zXZ\x00": ["xz", "-dc"],
                 b"\x1f\x8b": ["gzip", "-dc"]}


class BuildError(RuntimeError):
    """A package, the source archive or the build is not what the row says."""


def row_named(matrix: Path, name: str) -> dict:
    rows = [row for row in json.loads(matrix.read_text(encoding="utf-8")) if row["name"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{matrix.name} has no row {name!r}")
    return rows[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def obtain(package: dict, downloads: Path) -> Path:
    """The package, downloaded once and checked against its SHA-256."""

    path = downloads / PurePosixPath(package["url"]).name
    if path.is_file() and sha256(path) == package["sha256"]:
        return path
    fetcher.fetch(package["url"], path)
    if sha256(path) != package["sha256"]:
        path.unlink()
        raise BuildError(f"{path.name} does not have the expected SHA-256")
    return path


def rpm_payload(data: bytes) -> bytes:
    """An RPM's compressed cpio payload: what follows its lead and two headers."""

    offset = 96
    for index in range(2):
        if data[offset:offset + 3] != b"\x8e\xad\xe8":
            raise BuildError("not an RPM package")
        entries, size = struct.unpack(">II", data[offset + 8:offset + 16])
        offset += 16 + entries * 16 + size
        if index == 0:
            # The signature header is padded to eight bytes.
            offset = (offset + 7) & ~7
    return data[offset:]


def unpack_rpm(package: Path, root: Path) -> None:
    payload = rpm_payload(package.read_bytes())
    command = next((tool for magic, tool in DECOMPRESSORS.items()
                    if payload.startswith(magic)), None)
    if command is None:
        raise BuildError(f"{package.name}: unknown payload compression")
    archive = subprocess.run(command, input=payload, capture_output=True, check=True).stdout
    subprocess.run(["cpio", "-idm", "--quiet", "--no-absolute-filenames"], input=archive,
                   cwd=root, check=True)


def unpack_source(archive: Path, work: Path) -> Path:
    """Unpack a source archive into work/source and return its one top directory."""

    destination = work / "source"
    destination.mkdir(parents=True)
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter="data")
    tops = list(destination.iterdir())
    if len(tops) != 1 or not tops[0].is_dir():
        raise BuildError(f"{archive.name} does not unpack into one directory")
    return tops[0]


def toolchain_file(root: Path, build: dict) -> str:
    """The CMake toolchain file of a build, as signature-builds-zlib wrote it,
    with the compiler taken from the unpacked root."""

    lines = ["set(CMAKE_SYSTEM_NAME Linux)", "",
             f"set(CMAKE_C_COMPILER {root / 'usr/bin' / build['compiler']})"]
    if build["cflags"]:
        lines.append(f"set(CMAKE_C_FLAGS {shlex.join(build['cflags'])})")
    return "\n".join(lines) + "\n"


def environment(root: Path) -> dict[str, str]:
    """clang's LLVM libraries come with it; GCC's cc1 needs only the host's GMP,
    MPFR and MPC, which fold floating-point constants."""

    env = dict(os.environ)
    libraries = str(root / "usr/lib64")
    env["LD_LIBRARY_PATH"] = libraries + (os.pathsep + env["LD_LIBRARY_PATH"]
                                          if env.get("LD_LIBRARY_PATH") else "")
    return env


def build(source: Path, root: Path, row: dict, build: dict, work: Path) -> Path:
    """Configure and build the row's target once, and return the archive it made."""

    directory = work / f"build-{build['arch']}-{build['compiler']}"
    toolchain = work / f"{build['arch']}-{build['compiler']}.cmake"
    toolchain.write_text(toolchain_file(root, build), encoding="utf-8")
    subprocess.run(
        ["cmake", "-S", str(source), "-B", str(directory), "-G", "Ninja",
         f"-DCMAKE_TOOLCHAIN_FILE={toolchain}", f"-DCMAKE_SYSROOT={root}",
         # The root holds headers, not a C runtime to link against: the
         # configuration checks compile and do not link.
         "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
         # D: zero dates, owners and modes, so the archive is the same every run.
         "-DCMAKE_C_ARCHIVE_CREATE=<CMAKE_AR> qcD <TARGET> <LINK_FLAGS> <OBJECTS>",
         "-DCMAKE_C_ARCHIVE_FINISH=<CMAKE_RANLIB> -D <TARGET>"],
        check=True, env=environment(root), stdout=subprocess.DEVNULL)
    subprocess.run(["ninja", "-C", str(directory), row["target"]], check=True,
                   env=environment(root), stdout=subprocess.DEVNULL)
    library = directory / row["archive"]
    if not library.is_file():
        raise BuildError(f"{row['target']} made no {row['archive']}")
    return library


def compiler_version(root: Path, compiler: str) -> str:
    result = subprocess.run([str(root / "usr/bin" / compiler), "--version"],
                            capture_output=True, text=True, check=True, env=environment(root))
    return result.stdout.splitlines()[0].strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--name", required=True, help="the matrix row to build")
    parser.add_argument("--source", type=Path, required=True,
                        help="the row's downloaded source archive")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep-downloads", type=Path,
                        help="keep the downloaded packages here and reuse them")
    parser.add_argument("--zstd-level", type=int, default=15)
    args = parser.parse_args(argv)

    row = row_named(args.matrix, args.name)
    if sha256(args.source) != row["sha256"]:
        print(f"error: {args.source.name} does not have the expected SHA-256", file=sys.stderr)
        return 1
    work = args.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    downloads = (args.keep_downloads or work / "downloads").resolve()
    downloads.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        root = work / "root"
        root.mkdir()
        for package in row["packages"]:
            unpack_rpm(obtain(package, downloads), root)
        source = unpack_source(args.source, work)
        arches = sorted({entry["arch"] for entry in row["builds"]})
        for arch in arches:
            builds = [entry for entry in row["builds"] if entry["arch"] == arch]
            files = []
            for entry in builds:
                library = build(source, root, row, entry, work)
                files.append(collector.CollectedFile(
                    library, PurePosixPath(row["library"], arch, entry["compiler"],
                                           row["archive"])))
            collector.emit_asset(
                output=args.output,
                asset=f"{row['library']}-{row['version']}-{arch}",
                kind="library",
                arch=arch,
                files=files,
                extra={
                    "format": "elf",
                    "library": row["library"],
                    "library_version": row["version"],
                    "source": {"url": row["source"], "sha256": row["sha256"]},
                    "builds": [{"compiler": entry["compiler"], "cflags": entry["cflags"],
                                "built_with": compiler_version(root, entry["compiler"])}
                               for entry in builds],
                    "packages": row["packages"],
                    # The source, the recipe and the compilers rizin's
                    # lines were made with.
                    "reproduces_import": True,
                },
                level=args.zstd_level,
            )
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
