#!/usr/bin/env python3
"""Build the Mach-O validation probes, and what each one's functions are.

A Mach-O probe is a program that links every object of the Homebrew bottles
one bottle tag names, so each function their archives define is in it. Each
row of validation/macho/probes.json names the tag and its processor (`arm64`
or `x86_64`), the rows of .github/homebrew-matrix.json whose bottles it
takes, and how the program binds its imports: `chained` fixups or classic
`dyld` information. This downloads
and checks the bottles as collect_homebrew_bottles.py does, compiles the
program with clang, links it with LLVM's ld64.lld against a text stub of
libSystem that exports what the objects import, and writes, next to the
stripped program `<name>.macho`:

    <name>.truth.json   every function of the linker's map: its address, its
                        names, and whether a member of the bottles' archives
                        defines it

which evaluate_probes.py reads in place of an MSVC map. The unstripped
program is kept as `<name>.debug`, and the map as `<name>.map`.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_homebrew_bottles as bottles  # noqa: E402

DEFAULT_PROBES = HERE.parent / "validation" / "macho" / "probes.json"

# The link each probe is: a macOS program for one of these processors, as
# clang and ld64.lld name them, whose imports bind through libSystem.
ARCHES = ("arm64", "x86_64")
MACOS_VERSION = "15.0"
LIBSYSTEM = "/usr/lib/libSystem.B.dylib"
# What ld64.lld binds classic dyld information's lazy imports through.
STUB_BINDER = "dyld_stub_binder"
FIXUPS = {"chained": "-fixup_chains", "dyld": "-no_fixup_chains"}

# A map line of ld64.lld's `# Symbols:` table: address, size, the index of
# the file that defines the symbol, and its name.
MAP_FILE = re.compile(r"^\[\s*(\d+)\] (.+)$")
MAP_SYMBOL = re.compile(r"^0x([0-9A-F]+)\s+0x[0-9A-F]+\s+\[\s*(\d+)\] (.+)$")
MAP_SECTION = re.compile(r"^0x([0-9A-F]+)\s+0x([0-9A-F]+)\s+(\S+)\s+(\S+)$")
# An archive member, as the map names its file: `lib.a(member.o)`.
ARCHIVE_MEMBER = re.compile(r"\.a\([^)]+\)$")


def bottle_archives(row: dict, matrix: Path, work: Path, downloads: Path) -> list[Path]:
    """The archives of each library's bottle for the probe's tag, unpacked."""

    archives = []
    for name in row["libraries"]:
        library = bottles.row_named(matrix, name)
        entry = next((b for b in library["bottles"] if b["tag"] == row["tag"]), None)
        if entry is None:
            raise SystemExit(f"{row['name']}: {name} has no {row['tag']} bottle")
        package = bottles.obtain(library["formula"], entry, downloads)
        keg = work / row["name"] / f"{library['formula']}-{row['tag']}"
        shutil.rmtree(keg, ignore_errors=True)
        found = bottles.unpack(package, library["formula"], library["version"],
                               library["archives"], keg)
        archives += [found[archive] for archive in library["archives"]]
    return archives


def imports(nm: str, archives: list[Path]) -> list[str]:
    """The symbols the archives' objects use and none of them defines."""

    defined: set[str] = set()
    undefined: set[str] = set()
    for archive in archives:
        listing = subprocess.run([nm, "--defined-only", "--format=just-symbols", str(archive)],
                                 capture_output=True, text=True, check=True).stdout
        defined |= {line for line in listing.splitlines() if line and not line.endswith(":")}
        listing = subprocess.run([nm, "--undefined-only", "--format=just-symbols",
                                  str(archive)], capture_output=True, text=True,
                                 check=True).stdout
        undefined |= {line for line in listing.splitlines() if line and not line.endswith(":")}
    return sorted(undefined - defined)


def libsystem_stub(symbols: list[str], arch: str, path: Path) -> None:
    """A text-based stub of libSystem for `arch` that exports `symbols`."""

    exported = ", ".join([*symbols, STUB_BINDER])
    path.write_text("--- !tapi-tbd\n"
                    "tbd-version: 4\n"
                    f"targets: [ {arch}-macos ]\n"
                    f"install-name: '{LIBSYSTEM}'\n"
                    "exports:\n"
                    f"  - targets: [ {arch}-macos ]\n"
                    f"    symbols: [ {exported} ]\n"
                    "...\n", encoding="utf-8")


def write_truth(map_path: Path, stripped: Path) -> None:
    """Every symbol the map places in `__TEXT,__text`, by address: an
    assembler's local label (`ltmp0`, `lCPI0_0`) names no function."""

    files: dict[int, str] = {}
    functions: dict[int, set[str]] = {}
    from_library: dict[int, bool] = {}
    text = None
    part = None
    for line in map_path.read_text(encoding="utf-8").splitlines():
        # `# Symbols:` starts a part, and `# Address  Size ...` heads its
        # columns.
        if line.startswith("#"):
            if line.endswith(":"):
                part = line[2:-1]
            continue
        if part == "Object files" and (match := MAP_FILE.match(line)):
            files[int(match.group(1))] = match.group(2)
        elif part == "Sections" and (match := MAP_SECTION.match(line)):
            if (match.group(3), match.group(4)) == ("__TEXT", "__text"):
                start = int(match.group(1), 16)
                text = (start, start + int(match.group(2), 16))
        elif part == "Symbols" and (match := MAP_SYMBOL.match(line)) and text:
            address, name = int(match.group(1), 16), match.group(3)
            if not text[0] <= address < text[1] or name.startswith(("l", "L")):
                continue
            functions.setdefault(address, set()).add(name)
            member = bool(ARCHIVE_MEMBER.search(files.get(int(match.group(2)), "")))
            from_library[address] = from_library.get(address, False) or member
    if text is None:
        raise SystemExit(f"{map_path.name} places no __TEXT,__text section")
    truth = [{"address": hex(address), "names": sorted(names),
              "from_library": from_library[address]}
             for address, names in sorted(functions.items())]
    stripped.with_suffix(".truth.json").write_text(json.dumps(truth, indent=1) + "\n",
                                                   encoding="utf-8")


def build(row: dict, args: argparse.Namespace, work: Path, downloads: Path) -> Path:
    if row["fixups"] not in FIXUPS:
        raise SystemExit(f"{row['name']}: fixups must be one of {sorted(FIXUPS)}")
    arch = row["arch"]
    if arch not in ARCHES:
        raise SystemExit(f"{row['name']}: arch must be one of {list(ARCHES)}")
    archives = bottle_archives(row, args.matrix, work, downloads)
    scratch = work / row["name"]
    obj = scratch / "probe.o"
    subprocess.run([args.clang, f"--target={arch}-apple-macos{MACOS_VERSION}", "-O2", "-c",
                    str(args.probes.parent / row["program"]), "-o", str(obj)], check=True)
    stub = scratch / "libSystem.tbd"
    libsystem_stub(imports(args.nm, archives), arch, stub)
    output = args.output.resolve()
    program = output / f"{row['name']}.debug"
    map_path = output / f"{row['name']}.map"
    linked = subprocess.run(
        [args.lld, "-arch", arch, "-platform_version", "macos", MACOS_VERSION, MACOS_VERSION,
         FIXUPS[row["fixups"]], "-o", str(program), "-map", str(map_path), str(obj),
         *[argument for archive in archives for argument in ("-force_load", str(archive))],
         str(stub)],
        capture_output=True, text=True)
    if linked.returncode != 0:
        raise SystemExit(f"{row['name']}: {args.lld} failed:\n{linked.stderr}")
    stripped = output / f"{row['name']}.macho"
    subprocess.run([args.strip, "-o", str(stripped), str(program)], check=True)
    write_truth(map_path, stripped)
    return stripped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    parser.add_argument("--matrix", type=Path, default=bottles.DEFAULT_MATRIX)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--keep-downloads", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--lld", default="ld64.lld")
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--strip", default="llvm-strip")
    parser.add_argument("names", nargs="*", help="only these probes")
    args = parser.parse_args(argv)

    rows = json.loads(args.probes.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)
    work = args.work.resolve()
    downloads = (args.keep_downloads or work / "downloads").resolve()
    downloads.mkdir(parents=True, exist_ok=True)
    for row in rows:
        if args.names and row["name"] not in args.names:
            continue
        try:
            probe = build(row, args, work, downloads)
        except bottles.CollectionError as error:
            raise SystemExit(f"{row['name']}: {error}") from error
        print(f"{probe.name}: built", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
