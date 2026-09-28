#!/usr/bin/env python3
"""Fetch the libraries an imported signature file was made from.

rizin's sigdb-source keeps, next to each pattern file, a `<name>.src.sha1`
listing the exact packages the patterns were generated from: Ubuntu `.deb`
files and Android NDK archives. This downloads each of them, checks it
against the recorded SHA-1, and runs neverd-sigmaker over the static
libraries inside with a leading pattern long enough to state every byte of
every function. The result is the reference migrate_imported_signatures.py
renames imported lines by:

    <output>/<format>/<arch>/<bits>/<library>--<package>.pat

A package that cannot be fetched or does not match its recorded digest is
reported and skipped; the rest still count. The run fails only when nothing
could be fetched at all.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

SIGDB_RAW = "https://raw.githubusercontent.com/rizinorg/sigdb-source"
LAUNCHPAD = "https://launchpad.net/ubuntu/+archive/primary/+files/"
NDK = "https://dl.google.com/android/repository/"
LEGACY_NDK = "https://dl.google.com/android/ndk/"

# Long enough that the leading pattern states the whole function.
WHOLE_FUNCTION = 65535

# ELF (e_machine, EI_CLASS) -> the directory an image of that machine is
# filed under. x86-64 code of 32-bit class (x32) has none.
ELF_MACHINES = {(3, 1): "elf/x86/32", (62, 2): "elf/x86/64", (40, 1): "elf/arm/32",
                (183, 2): "elf/arm/64"}


def fetch(url: str, destination: Path, attempts: int = 6) -> None:
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "neverd-signatures"})
            with urllib.request.urlopen(request, timeout=300) as response, \
                    destination.open("wb") as out:
                shutil.copyfileobj(response, out, 1 << 20)
                expected = response.headers.get("Content-Length")
            # A connection that closes early raises nothing; the length shows it.
            received = destination.stat().st_size
            if expected is not None and received != int(expected):
                raise OSError(f"received {received} of {expected} bytes")
            return
        except OSError as error:
            if attempt == attempts:
                raise
            print(f"  retrying {url}: {error}", file=sys.stderr, flush=True)
            time.sleep(min(60, 5 * attempt))


def sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_list(library: str, commit: str, cache: Path) -> list[tuple[str, str]]:
    name = library.rsplit("/", 1)[1]
    target = cache / f"{name}.src.sha1"
    if not target.is_file():
        fetch(f"{SIGDB_RAW}/{commit}/{library}/{name}.src.sha1", target)
    entries = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, path = line.split(None, 1)
            entries.append((digest.strip(), path.strip()))
    return entries


def source_url(path: str) -> str | None:
    filename = path.rsplit("/", 1)[-1]
    if path.startswith("ubuntu/") and filename.endswith(".deb"):
        return LAUNCHPAD + urllib.parse.quote(filename)
    if filename.startswith("android-ndk-") and filename.endswith(".zip"):
        return NDK + filename
    if filename.startswith("android-ndk-") and filename.endswith(".tar.bz2"):
        return LEGACY_NDK + filename
    return None


def unpack(package: Path, destination: Path) -> list[Path]:
    """The static libraries and object files inside a package."""

    destination.mkdir(parents=True, exist_ok=True)
    if package.suffix == ".deb":
        subprocess.run(["dpkg-deb", "-x", str(package), str(destination)], check=True)
    elif package.suffix == ".zip":
        subprocess.run(["unzip", "-q", "-o", str(package), "*.a", "*.o", "-d",
                        str(destination)], check=False)
    elif package.name.endswith(".tar.bz2"):
        subprocess.run(["tar", "-xjf", str(package), "-C", str(destination),
                        "--wildcards", "*.a", "*.o"], check=False)
    return sorted(path for path in destination.rglob("*")
                  if path.suffix in (".a", ".o") and path.is_file())


def elf_directory(head: bytes) -> str | None:
    """The directory an ELF file of this header is filed under."""

    if head[:4] != b"\x7fELF" or len(head) < 20:
        return None
    (machine,) = struct.unpack("<H" if head[5] == 1 else ">H", head[18:20])
    return ELF_MACHINES.get((machine, head[4]))


def archive_machine(path: Path) -> str | None:
    """The directory an ELF object, or the first one in an ar archive, is filed
    under."""

    with path.open("rb") as stream:
        magic = stream.read(8)
        if magic[:4] == b"\x7fELF":
            return elf_directory(magic + stream.read(12))
        if magic != b"!<arch>\n":
            return None
        while True:
            header = stream.read(60)
            if len(header) < 60:
                return None
            name = header[:16].strip()
            size = int(header[48:58].strip() or 0)
            body_start = stream.tell()
            if name.startswith(b"#1/"):
                stream.read(int(name[3:]))
            if name not in (b"/", b"//", b"/SYM64/", b"__.SYMDEF", b"__.SYMDEF SORTED"):
                head = stream.read(20)
                if head[:4] == b"\x7fELF":
                    return elf_directory(head)
            stream.seek(body_start + size + (size & 1))


def reference_lines(sigmaker: Path, libraries: list[Path], output: Path) -> int:
    subprocess.run(
        [str(sigmaker), *map(str, libraries), "-o", str(output),
         "--leading", str(WHOLE_FUNCTION), "--tail", "0", "--min-size", "1"],
        check=True, stdout=subprocess.DEVNULL,
    )
    return sum(1 for line in output.read_text(encoding="utf-8").splitlines() if line.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--library", required=True,
                        help="sigdb-source library path, e.g. elf/x86/64/ubuntu-libstdc++-12")
    parser.add_argument("--sigdb-commit", required=True)
    parser.add_argument("--sigmaker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--only", action="append", default=[],
                        help="only sources whose file name contains this text (repeatable)")
    parser.add_argument("--work", type=Path, default=None)
    args = parser.parse_args(argv)

    name = args.library.rsplit("/", 1)[1]
    fetched = failed = 0
    with tempfile.TemporaryDirectory(dir=args.work) as scratch_name:
        scratch = Path(scratch_name)
        for digest, path in source_list(args.library, args.sigdb_commit, scratch):
            filename = path.rsplit("/", 1)[-1]
            if args.only and not any(text in filename for text in args.only):
                continue
            url = source_url(path)
            if url is None:
                print(f"{filename}: no known download location", file=sys.stderr)
                failed += 1
                continue
            package = scratch / filename
            try:
                fetch(url, package)
            except OSError as error:
                print(f"{filename}: {error}", file=sys.stderr)
                failed += 1
                continue
            if sha1(package) != digest:
                print(f"{filename}: SHA-1 does not match rizin's record", file=sys.stderr)
                package.unlink()
                failed += 1
                continue
            unpacked = scratch / (filename + ".d")
            by_target: dict[str, list[Path]] = {}
            for library in unpack(package, unpacked):
                target = archive_machine(library)
                if target is not None:
                    by_target.setdefault(target, []).append(library)
            stem = filename.removesuffix(".tar.bz2").removesuffix(".zip").removesuffix(".deb")
            for target, libraries in sorted(by_target.items()):
                directory = args.output / target
                directory.mkdir(parents=True, exist_ok=True)
                count = reference_lines(args.sigmaker, libraries,
                                        directory / f"{name}--{stem}.pat")
                print(f"{filename}: {target}: {len(libraries)} libraries, {count} functions",
                      flush=True)
            fetched += 1
            package.unlink()
            shutil.rmtree(unpacked)
    print(f"{name}: {fetched} sources fetched, {failed} failed")
    return 0 if fetched else 1


if __name__ == "__main__":
    sys.exit(main())
