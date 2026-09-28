#!/usr/bin/env python3
"""Collect the static libraries of the packages rizin's ELF files came from.

rizin's sigdb-source keeps, next to each ELF pattern file, a `<name>.src.sha1`
listing the exact packages the patterns were generated from: Ubuntu `.deb`
files and Android NDK archives. Each row of .github/elf-matrix.json names one
such library, the directories of the tree it has files in, and the archives
of the packages its lines came from, as file name patterns (glibc's libc.a,
not the libm.a beside it; libgcc's libgcc.a, not the sanitizer runtimes; an
NDK's archives and its crtbegin/crtend start files),
and where needed as path patterns too (every Android library of an NDK, none
of the libraries its toolchains run on the host). This downloads every
package the library's lists name, once, checks it against the SHA-1 rizin
recorded, and files each static library it holds under the directory its
objects' ELF class and machine belong to -- an NDK archive holds every
Android ABI -- as one `library` asset per directory, for NeverD's builder:

    elf/x86/64  ->  <library>-x64.tar.zst and its manifest

A package that can no longer be downloaded, or no longer matches its SHA-1,
is listed in the manifest as unavailable; the asset then does not claim to
be the build rizin's lines were made from, and only the lines its bytes
reproduce leave the imported file.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import shutil
import sys
import threading
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_msvc_libraries as collector  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402

DEFAULT_MATRIX = HERE.parent / ".github" / "elf-matrix.json"

# The sigdb-source commit the repository's ELF files were imported from.
SIGDB_COMMIT = "5f068bbe82a2b283f8eaa6b49d3ed4820e1deee0"

# The architecture each ELF directory holds, as asset manifests name it.
DIRECTORIES = {"elf/x86/32": "x86", "elf/x86/64": "x64", "elf/arm/32": "arm",
               "elf/arm/64": "arm64"}


def row_named(matrix: Path, name: str) -> dict:
    rows = [row for row in json.loads(matrix.read_text(encoding="utf-8")) if row["name"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{matrix.name} has no row {name!r}")
    return rows[0]


def package_sources(row: dict, cache: Path) -> list[tuple[str, str]]:
    """Every package the library's source lists name, once, in list order.

    A list names a package once per distribution series that carried it,
    and an NDK archive once per directory: one file, one SHA-1.
    """

    seen: dict[tuple[str, str], str] = {}
    for directory in row["directories"]:
        (cache / directory).mkdir(parents=True, exist_ok=True)
        for digest, path in fetcher.source_list(f"{directory}/{row['library']}",
                                                SIGDB_COMMIT, cache / directory):
            seen.setdefault((PurePosixPath(path).name, digest), path)
    return [(digest, path) for (_, digest), path in seen.items()]


def obtain(digest: str, path: str, downloads: Path,
           attempts: int = 3) -> tuple[Path | None, str | None]:
    """The package, downloaded and checked, or None and why not."""

    filename = PurePosixPath(path).name
    package = downloads / filename
    if package.is_file() and fetcher.sha1(package) == digest:
        return package, None
    url = fetcher.source_url(path)
    if url is None:
        return None, "no known download location"
    # The download goes to a file of its own and takes the package's name
    # only once it checks out, so a collection sharing --keep-downloads never
    # reads or overwrites another's half-written package. Launchpad serves
    # the files rizin recorded; one that differs was damaged in transfer.
    partial = package.with_name(f"{filename}.{os.getpid()}.{threading.get_ident()}.part")
    try:
        for _ in range(attempts):
            try:
                fetcher.fetch(url, partial)
            except OSError as error:
                return None, str(error)
            if fetcher.sha1(partial) == digest:
                os.replace(partial, package)
                return package, None
        return None, "SHA-1 does not match rizin's record"
    finally:
        partial.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--name", required=True, help="the matrix row to collect")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep-downloads", type=Path,
                        help="keep the downloaded packages here and reuse them")
    parser.add_argument("--zstd-level", type=int, default=15)
    parser.add_argument("--jobs", type=int, default=4, help="downloads at once")
    args = parser.parse_args(argv)

    row = row_named(args.matrix, args.name)
    unknown = [d for d in row["directories"] if d not in DIRECTORIES]
    if unknown:
        raise SystemExit(f"{row['name']}: no architecture for {unknown}")
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    downloads = (args.keep_downloads or work / "downloads").resolve()
    downloads.mkdir(parents=True, exist_ok=True)
    staging = work / "staging"
    shutil.rmtree(staging, ignore_errors=True)

    sources = package_sources(row, work / "lists")
    files: dict[str, list[collector.CollectedFile]] = {d: [] for d in row["directories"]}
    used: dict[str, list[dict]] = {d: [] for d in row["directories"]}
    # An archive byte for byte like one already placed in a directory -- an
    # NDK's libraries repeat across API levels -- is stored once.
    placed_digests: dict[str, set[str]] = {d: set() for d in row["directories"]}
    unavailable: list[dict] = []
    # Packages with no library the row takes: a -dev package that shipped
    # only the shared library. rizin's lines cannot have come from them.
    without_libraries: list[dict] = []
    pool = concurrent.futures.ThreadPoolExecutor(args.jobs)
    # At most --jobs packages are fetched ahead of the one being unpacked, so
    # a runner never holds more of them than that (an NDK archive is 1 GB).
    pending: collections.deque = collections.deque()
    remaining = iter(sources)

    def refill() -> None:
        for source in remaining:
            pending.append((source, pool.submit(obtain, *source, downloads)))
            if len(pending) >= args.jobs:
                return

    refill()
    while pending:
        (digest, path), future = pending.popleft()
        package, problem = future.result()
        refill()
        filename = PurePosixPath(path).name
        if package is None:
            print(f"{filename}: {problem}", file=sys.stderr, flush=True)
            unavailable.append({"package": path, "sha1": digest, "problem": problem})
            continue
        stem = filename.removesuffix(".tar.bz2").removesuffix(".zip").removesuffix(".deb")
        unpacked = work / "unpacked" / stem
        shutil.rmtree(unpacked, ignore_errors=True)
        held = {d: 0 for d in row["directories"]}
        placed = {d: 0 for d in row["directories"]}
        for library in fetcher.unpack(package, unpacked):
            # A package links some archives to where LLVM keeps them
            # (libc++.a -> ../llvm-10/lib/libc++.a); the file itself is
            # listed too.
            if library.is_symlink():
                continue
            # The archives rizin's lines were made from, and an NDK's start
            # files; a package also carries others, such as libgcc's
            # sanitizer runtimes.
            if not any(fnmatch.fnmatchcase(library.name, pattern)
                       for pattern in row["archives"]):
                continue
            # An NDK also carries libraries its toolchains run on the host
            # (Python, libiberty, Linux sanitizer runtimes); a row's paths,
            # when it has them, keep the Android ones.
            inside = library.relative_to(unpacked).as_posix()
            if "paths" in row and not any(fnmatch.fnmatchcase(inside, pattern)
                                          for pattern in row["paths"]):
                continue
            directory = fetcher.archive_machine(library)
            if directory not in files:
                continue
            held[directory] += 1
            content = hashlib.sha256(library.read_bytes()).hexdigest()
            if content in placed_digests[directory]:
                continue
            placed_digests[directory].add(content)
            member = PurePosixPath(row["library"], stem,
                                   library.relative_to(unpacked).as_posix())
            target = staging / directory / member
            target.parent.mkdir(parents=True, exist_ok=True)
            library.rename(target)
            files[directory].append(collector.CollectedFile(target, member))
            placed[directory] += 1
        # Every package with libraries for a directory is listed, also one
        # whose libraries all repeat bytes the asset already stores.
        for directory, count in held.items():
            if count:
                used[directory].append({"package": path, "sha1": digest,
                                        "url": fetcher.source_url(path), "libraries": count,
                                        "stored": placed[directory]})
        if not any(held.values()):
            without_libraries.append({"package": path, "sha1": digest,
                                      "url": fetcher.source_url(path)})
        shutil.rmtree(unpacked, ignore_errors=True)
        if args.keep_downloads is None:
            package.unlink()
        print(f"{filename}: " + ", ".join(f"{d} {placed[d]} of {n}" for d, n in held.items() if n),
              flush=True)

    pool.shutdown()
    args.output.mkdir(parents=True, exist_ok=True)
    for directory, collected in files.items():
        if not collected:
            print(f"{row['name']}: no library for {directory}", file=sys.stderr)
            continue
        arch = DIRECTORIES[directory]
        collector.emit_asset(
            output=args.output,
            asset=f"{row['library']}-{arch}",
            kind="library",
            arch=arch,
            files=collected,
            extra={
                "format": "elf",
                "library": row["library"],
                "sigdb_source": SIGDB_COMMIT,
                "sources": used[directory],
                "without_libraries": without_libraries,
                "unavailable": unavailable,
                # Every package rizin's lines were made from, or not.
                "reproduces_import": not unavailable,
            },
            level=args.zstd_level,
        )
    print(f"{row['name']}: {len(sources) - len(unavailable)} of {len(sources)} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
