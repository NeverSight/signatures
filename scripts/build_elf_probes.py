#!/usr/bin/env python3
"""Build the ELF validation probes, and what each one's functions are.

A PE probe is checked against the linker map MSVC writes beside it. An ELF
probe is a small program linked statically against the very packages rizin's
ELF files were made from; each row of validation/elf/probes.json names the
packages, by the SHA-1 sigdb-source records, the program and the archives to
link. This downloads and checks the packages, compiles the program with the
packages' own headers where they ship them, links it with the host's linker,
and writes, next to the stripped program:

    <name>.truth.json   every function of the unstripped program: its
                        address, its names, and whether one of the linked
                        archives defines it

which evaluate_probes.py reads in place of a map, beside the stripped
program `<name>.elf`. The unstripped program is kept as `<name>.debug`.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_elf_packages as packages  # noqa: E402
import fetch_imported_sources as fetcher  # noqa: E402
from coff_symbols import code_symbols  # noqa: E402

DEFAULT_PROBES = HERE.parent / "validation" / "elf" / "probes.json"


def extract(row: dict, work: Path, downloads: Path) -> Path:
    """Every package of a probe, unpacked into one tree."""

    root = work / row["name"] / "root"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    for source in row["packages"]:
        package, problem = packages.obtain(source["sha1"], source["package"], downloads)
        if package is None:
            raise SystemExit(f"{row['name']}: {PurePosixPath(source['package']).name}: {problem}")
        subprocess.run(["dpkg-deb", "-x", str(package), str(root)], check=True)
    return root


def find(root: Path, name: str) -> Path:
    found = sorted(path for path in root.rglob(name) if path.is_file() and not path.is_symlink())
    if not found:
        raise SystemExit(f"no {name} in the probe's packages")
    return found[0]


def host_file(compiler: str, name: str) -> str:
    return subprocess.run([compiler, f"-print-file-name={name}"], capture_output=True,
                          text=True, check=True).stdout.strip()


def build(row: dict, sources: Path, output: Path, work: Path, downloads: Path) -> Path:
    root = extract(row, work, downloads)
    compiler = row["compiler"]
    # The package's own headers, as its build saw them: a newer glibc's
    # redirect strtol to __isoc23_strtol, which an older libc.a lacks. Only
    # the compiler's own headers, and the kernel's, which libc6-dev does not
    # ship, come from the host.
    includes = ["-nostdinc"]
    includes += [f"-isystem{root / directory}" for directory in row.get("includes", [])]
    includes += [f"-isystem{host_file(compiler, 'include')}",
                 f"-isystem{root / 'usr/include/x86_64-linux-gnu'}",
                 f"-isystem{root / 'usr/include'}",
                 "-idirafter/usr/include/x86_64-linux-gnu", "-idirafter/usr/include"]
    obj = work / row["name"] / "probe.o"
    subprocess.run([compiler, *row["flags"], *includes,
                    "-c", str(sources / row["program"]), "-o", str(obj)], check=True)
    archives = [find(root, name) for name in row["archives"]]
    crt = [find(root, name) for name in ("crt1.o", "crti.o")]
    program = output / f"{row['name']}.debug"
    # The C runtime's start files come with glibc, the compiler runtime's
    # (crtbeginT.o, crtend.o) with the series' libgcc package, as the libgcc.a
    # and libgcc_eh.a the probe lists: a newer libgcc_eh needs a newer glibc.
    subprocess.run(
        [compiler, "-static", "-nostdlib", *map(str, crt), str(find(root, "crtbeginT.o")),
         str(obj), "-Wl,--start-group", *map(str, archives), "-Wl,--end-group",
         str(find(root, "crtend.o")), str(find(root, "crtn.o")), "-o", str(program)],
        check=True)
    stripped = output / f"{row['name']}.elf"
    subprocess.run(["strip", "-o", str(stripped), str(program)], check=True)

    library_names: set[str] = set()
    for archive in archives:
        library_names |= code_symbols(archive)
    functions: dict[int, set[str]] = {}
    listing = subprocess.run(["nm", "--defined-only", str(program)], capture_output=True,
                             text=True, check=True).stdout
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in "TtWwi":
            functions.setdefault(int(fields[0], 16), set()).add(fields[2])
    truth = [{"address": hex(address), "names": sorted(names),
              "from_library": bool(names & library_names)}
             for address, names in sorted(functions.items())]
    stripped.with_suffix(".truth.json").write_text(json.dumps(truth, indent=1) + "\n",
                                                   encoding="utf-8")
    return stripped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--keep-downloads", type=Path)
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
        probe = build(row, args.probes.parent, args.output.resolve(), work, downloads)
        print(f"{probe.name}: built", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
