#!/usr/bin/env python3
"""Collect the static libraries of Homebrew bottles.

Each row of .github/homebrew-matrix.json names one library of the macho/
tree, the Homebrew formula whose bottles carry it, the formula's version, the
archives to take from each bottle's keg (`lib/libz.a`), and the bottles
themselves: one per macOS release and processor Homebrew builds the formula
for (`arm64_sequoia`, or `sonoma` for Intel), by bottle tag and the SHA-256
Homebrew publishes for it. This downloads every bottle from Homebrew's
package registry on ghcr.io, anonymously, by the SHA-256 that names the blob,
checks it, and files each archive under the directory its objects' Mach-O
CPU type belongs to, as one `library` asset per directory, for NeverD's
builder:

    macho/arm/64  ->  <library>-arm64.tar.zst and its manifest
    macho/x86/64  ->  <library>-x64.tar.zst and its manifest

An archive byte for byte like one another bottle already supplied is stored
once; the manifest still lists the bottle. A bottle that cannot be
downloaded, does not match its SHA-256, or lacks an archive the row names is
an error: the asset would not be the libraries the row states.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_msvc_libraries as collector  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402

DEFAULT_MATRIX = HERE.parent / ".github" / "homebrew-matrix.json"

# Where Homebrew publishes homebrew/core's bottles, and where ghcr.io hands out
# the anonymous token that reads them.
REGISTRY = "https://ghcr.io/v2/homebrew/core"
TOKEN_URL = "https://ghcr.io/token"
TOKEN_SERVICE = "ghcr.io"

# The directory of the tree, and the architecture asset manifests name, that
# the objects of each Mach-O CPU type (<mach/machine.h>) belong to.
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
DIRECTORIES = {CPU_TYPE_ARM64: ("macho/arm/64", "arm64"),
               CPU_TYPE_X86_64: ("macho/x86/64", "x64")}

MH_MAGIC_64 = 0xFEEDFACF
AR_MAGIC = b"!<arch>\n"
AR_HEADER = 60
# A BSD archive writes a member name longer than 16 bytes, or one with a
# space, after the header: `#1/<length>` counts it into the member's size.
AR_LONG_NAME = b"#1/"
# The symbol table ranlib writes, in its 32- and 64-bit and sorted forms.
AR_SYMBOL_TABLES = ("__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64",
                    "__.SYMDEF_64 SORTED")


class CollectionError(RuntimeError):
    """A bottle or an archive is not what the row states."""


def row_named(matrix: Path, name: str) -> dict:
    rows = [row for row in json.loads(matrix.read_text(encoding="utf-8")) if row["name"] == name]
    if len(rows) != 1:
        raise SystemExit(f"{matrix.name} has no row {name!r}")
    return rows[0]


def repository(formula: str) -> str:
    """The registry repository of a formula's bottles, as Homebrew names it:
    `openssl@3` is `openssl/3`, and `+` becomes `x`."""

    return formula.replace("@", "/").replace("+", "x")


def bottle_url(formula: str, digest: str) -> str:
    return f"{REGISTRY}/{repository(formula)}/blobs/sha256:{digest}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def blob_location(formula: str, digest: str) -> str:
    """Where the registry serves a bottle: it answers the blob's URL, with an
    anonymous token, by redirecting to a signed download that must not
    receive the token."""

    query = urllib.parse.urlencode({
        "service": TOKEN_SERVICE,
        "scope": f"repository:homebrew/core/{repository(formula)}:pull",
    })
    request = urllib.request.Request(f"{TOKEN_URL}?{query}",
                                     headers={"User-Agent": "neverd-signatures"})
    with urllib.request.urlopen(request, timeout=60) as response:
        token = json.load(response)["token"]
    request = urllib.request.Request(bottle_url(formula, digest), headers={
        "User-Agent": "neverd-signatures",
        "Authorization": f"Bearer {token}",
    })
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=60):
            pass
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location")
        if error.code in (301, 302, 303, 307, 308) and location:
            return urllib.parse.urljoin(bottle_url(formula, digest), location)
        raise
    raise OSError(f"{bottle_url(formula, digest)} did not redirect to a download")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def obtain(formula: str, bottle: dict, downloads: Path, attempts: int = 6) -> Path:
    """The bottle, downloaded and checked against its SHA-256."""

    digest = bottle["sha256"]
    package = downloads / f"{formula}--{bottle['tag']}--{digest}.tar.gz"
    if package.is_file() and sha256(package) == digest:
        return package
    # The download takes the bottle's name only once it checks out, so a
    # collection sharing --keep-downloads never reads a half-written one.
    partial = package.with_name(f"{package.name}.{os.getpid()}.{threading.get_ident()}.part")
    try:
        for attempt in range(1, attempts + 1):
            try:
                fetcher.fetch(blob_location(formula, digest), partial)
            except OSError as error:
                if attempt == attempts:
                    raise CollectionError(f"{formula} {bottle['tag']}: {error}") from error
                time.sleep(min(60, 5 * attempt))
                continue
            if sha256(partial) == digest:
                os.replace(partial, package)
                return package
        raise CollectionError(f"{formula} {bottle['tag']}: SHA-256 does not match {digest}")
    finally:
        partial.unlink(missing_ok=True)


def archive_cpu_type(path: Path) -> int:
    """The Mach-O CPU type of every object of an ar archive.

    An archive of objects of several CPU types, a universal archive, or one
    with a member that is no 64-bit Mach-O object has none, and is an error.
    """

    data = path.read_bytes()
    if not data.startswith(AR_MAGIC):
        raise CollectionError(f"{path.name} is not an ar archive")
    types: set[int] = set()
    offset = len(AR_MAGIC)
    while offset < len(data):
        header = data[offset:offset + AR_HEADER]
        if len(header) < AR_HEADER or header[58:60] != b"`\n":
            raise CollectionError(f"{path.name}: malformed member header at {offset}")
        name = header[:16].rstrip(b" ")
        size = int(header[48:58])
        body = data[offset + AR_HEADER:offset + AR_HEADER + size]
        if len(body) != size:
            raise CollectionError(f"{path.name}: member at {offset} runs past the end")
        if name.startswith(AR_LONG_NAME):
            length = int(name[len(AR_LONG_NAME):])
            name, body = body[:length].rstrip(b"\0"), body[length:]
        offset += AR_HEADER + size + (size & 1)
        text = name.decode("utf-8", "replace")
        if text in AR_SYMBOL_TABLES:
            continue
        if len(body) < 8 or struct.unpack_from("<I", body)[0] != MH_MAGIC_64:
            raise CollectionError(f"{path.name}({text}) is not a 64-bit Mach-O object")
        types.add(struct.unpack_from("<I", body, 4)[0])
    if len(types) != 1:
        raise CollectionError(f"{path.name}: objects of CPU types "
                              f"{sorted(hex(t) for t in types)}, not one")
    return types.pop()


def unpack(package: Path, formula: str, version: str, archives: list[str],
           destination: Path) -> dict[str, Path]:
    """Each archive the row names, read from the bottle's keg,
    `<formula>/<version>/<archive>`, to a file under `destination`."""

    wanted = {str(PurePosixPath(formula, version, archive)): archive for archive in archives}
    found: dict[str, Path] = {}
    with tarfile.open(package, "r:gz") as bottle:
        for member in bottle:
            archive = wanted.get(member.name)
            if archive is None:
                continue
            if not member.isfile():
                raise CollectionError(f"{package.name}: {member.name} is not a regular file")
            target = destination / archive
            target.parent.mkdir(parents=True, exist_ok=True)
            with bottle.extractfile(member) as stream, target.open("wb") as out:
                shutil.copyfileobj(stream, out, 1 << 20)
            found[archive] = target
    missing = sorted(set(archives) - set(found))
    if missing:
        raise CollectionError(f"{package.name} has no {', '.join(missing)}")
    return found


def collect(row: dict, work: Path, downloads: Path
            ) -> tuple[dict[str, list[collector.CollectedFile]], dict[str, list[dict]]]:
    """The archives of every bottle of a row, by directory, and the bottles
    each directory's archives came from."""

    staging = work / "staging"
    shutil.rmtree(staging, ignore_errors=True)
    files: dict[str, list[collector.CollectedFile]] = {}
    used: dict[str, list[dict]] = {}
    placed_digests: dict[str, set[str]] = {}
    for bottle in row["bottles"]:
        package = obtain(row["formula"], bottle, downloads)
        keg = f"{row['formula']}-{row['version']}-{bottle['tag']}"
        unpacked = work / "unpacked" / keg
        shutil.rmtree(unpacked, ignore_errors=True)
        held: dict[str, int] = {}
        placed: dict[str, int] = {}
        for archive, path in sorted(unpack(package, row["formula"], row["version"],
                                           row["archives"], unpacked).items()):
            cpu_type = archive_cpu_type(path)
            if cpu_type not in DIRECTORIES:
                raise CollectionError(f"{keg}: {archive} holds objects of CPU type "
                                      f"{cpu_type:#x}, which no directory takes")
            directory = DIRECTORIES[cpu_type][0]
            held[directory] = held.get(directory, 0) + 1
            content = sha256(path)
            if content in placed_digests.setdefault(directory, set()):
                continue
            placed_digests[directory].add(content)
            member = PurePosixPath(row["library"], keg, archive)
            target = staging / directory / member
            target.parent.mkdir(parents=True, exist_ok=True)
            path.rename(target)
            files.setdefault(directory, []).append(collector.CollectedFile(target, member))
            placed[directory] = placed.get(directory, 0) + 1
        for directory, count in held.items():
            used.setdefault(directory, []).append({
                "tag": bottle["tag"], "sha256": bottle["sha256"],
                "url": bottle_url(row["formula"], bottle["sha256"]),
                "libraries": count, "stored": placed.get(directory, 0),
            })
        shutil.rmtree(unpacked, ignore_errors=True)
        print(f"{keg}: " + ", ".join(f"{d} {placed.get(d, 0)} of {n}"
                                     for d, n in sorted(held.items())), flush=True)
    return files, used


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--name", required=True, help="the matrix row to collect")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep-downloads", type=Path,
                        help="keep the downloaded bottles here and reuse them")
    parser.add_argument("--zstd-level", type=int, default=15)
    args = parser.parse_args(argv)

    row = row_named(args.matrix, args.name)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    downloads = (args.keep_downloads or work / "downloads").resolve()
    downloads.mkdir(parents=True, exist_ok=True)
    try:
        files, used = collect(row, work, downloads)
    except CollectionError as error:
        raise SystemExit(f"{row['name']}: {error}") from error

    args.output.mkdir(parents=True, exist_ok=True)
    architectures = dict(DIRECTORIES.values())
    for directory, collected in sorted(files.items()):
        arch = architectures[directory]
        collector.emit_asset(
            output=args.output,
            asset=f"{row['library']}-{arch}",
            kind="library",
            arch=arch,
            files=collected,
            extra={
                "format": "macho",
                "library": row["library"],
                "library_version": row["version"],
                "formula": row["formula"],
                "bottles": used[directory],
            },
            level=args.zstd_level,
        )
    print(f"{row['name']}: {len(row['bottles'])} bottles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
