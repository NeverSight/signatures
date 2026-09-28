#!/usr/bin/env python3
"""Write a program's .truth.json from its public PDB, for evaluate_probes.py.

The Visual Studio 2005 to 2013 files have no validation programs, but the
setup programs of their installation discs are linked statically with their
release's runtime, and Microsoft's symbol server keeps some of their public
PDBs. This reads a program's CodeView record, downloads the PDB it names
(unless given one), and lists the functions NeverD finds with the PDB loaded:
each one's address and name, and whether the libraries of the release the
program was linked with (an msvc-libs-* asset) define that name.

A public PDB names only public symbols: a static function of the runtime has
no name in it, so a signature name there cannot be checked either way.
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from coff_symbols import code_symbols  # noqa: E402

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def codeview(data: bytes) -> tuple[str, str] | None:
    """The PDB file name and the symbol server key an RSDS record names."""

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    directory = pe + 24 + (96 if magic == 0x10B else 112) + 6 * 8
    rva, size = struct.unpack_from("<II", data, directory)
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]

    def file_offset(address: int) -> int | None:
        for index in range(sections):
            header = pe + 24 + optional + 40 * index
            virtual_size, virtual, raw_size, raw = struct.unpack_from("<IIII", data, header + 8)
            if virtual <= address < virtual + max(virtual_size, raw_size):
                return raw + address - virtual
        return None

    start = file_offset(rva) if rva else None
    if start is None:
        return None
    for entry in range(size // 28):
        kind, _, _, pointer = struct.unpack_from("<IIII", data, start + entry * 28 + 12)
        if kind != 2 or data[pointer : pointer + 4] != b"RSDS":
            continue
        first, second, third, rest = struct.unpack_from("<IHH8s", data, pointer + 4)
        age = struct.unpack_from("<I", data, pointer + 20)[0]
        end = data.index(b"\0", pointer + 24)
        name = data[pointer + 24 : end].decode("utf-8", errors="replace").split("\\")[-1]
        return name, f"{first:08X}{second:04X}{third:04X}{rest.hex().upper()}{age:X}"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--neverd", type=Path, required=True)
    parser.add_argument("--asset", type=Path, required=True,
                        help="the msvc-libs-* archive of the program's release")
    parser.add_argument("--pdb", type=Path, help="the program's PDB (default: download it)")
    parser.add_argument("program", type=Path)
    args = parser.parse_args(argv)

    pdb = args.pdb
    if pdb is None:
        record = codeview(args.program.read_bytes())
        if record is None:
            raise SystemExit(f"{args.program.name} names no PDB")
        name, key = record
        pdb = args.program.with_suffix(".pdb")
        request = urllib.request.Request(f"{SYMBOL_SERVER}/{name}/{key}/{name}",
                                         headers={"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"})
        with urllib.request.urlopen(request, timeout=300) as response:
            pdb.write_bytes(response.read())
    functions = json.loads(subprocess.run(
        [str(args.neverd), "funcs", "--json", f"--pdb={pdb}", str(args.program)],
        check=True, capture_output=True, text=True).stdout)
    with tempfile.TemporaryDirectory(dir=args.program.parent) as scratch:
        subprocess.run(["tar", "--zstd", "-xf", str(args.asset), "-C", scratch], check=True)
        library: set[str] = set()
        for path in Path(scratch).rglob("*"):
            if path.is_file() and path.suffix.lower() in (".lib", ".obj"):
                try:
                    library |= code_symbols(path)
                except ValueError:
                    continue
    truth = [{"address": entry["addr"].lower(), "names": [entry["name"]],
              "from_library": entry["name"] in library}
             for entry in functions if not entry["name"].startswith("sub_")]
    args.program.with_suffix(".truth.json").write_text(json.dumps(truth, indent=1) + "\n",
                                                      encoding="utf-8")
    print(f"{args.program.name}: {len(truth)} named functions, "
          f"{sum(entry['from_library'] for entry in truth)} of them the release's")
    return 0


if __name__ == "__main__":
    sys.exit(main())
