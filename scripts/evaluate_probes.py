#!/usr/bin/env python3
"""Check a signature set against the linker maps of the validation probes.

Each probe was linked with /MAP, so the map names every function the linker
placed and says which library object it came from. This runs
`neverd sigs --json --no-debug` over the probe, so the image's own debug
information cannot supply a name, and compares every address NeverD would
rename against the map:

    correct    the name NeverD settles on is one the map gives that address
    wrong      the name is not one the map gives that address
    disputed   signatures offered different names, so NeverD renames nothing

Coverage is the share of the map's library functions that end up correctly
named. A wrong name is a failure; low coverage is a finding.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# " 0001:00000010       ?foo@@YAXXZ   0000000140001010 f   libcmt:foo.obj"
_MAP_LINE = re.compile(
    r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(?P<name>\S+)\s+(?P<va>[0-9A-Fa-f]{8,16})"
    r"\s+(?P<flags>(?:[fi] )*)\s*(?P<object>\S+)\s*$"
)


# The first bytes of an image, and the signature tree that holds its format's
# files; any other image is PE.
TREES = {b"\x7fELF": "elf", b"\xcf\xfa\xed\xfe": "macho"}


@dataclass
class MapFunction:
    names: set[str] = field(default_factory=set)
    from_library: bool = False


def parse_map(path: Path) -> dict[int, MapFunction]:
    functions: dict[int, MapFunction] = defaultdict(MapFunction)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _MAP_LINE.match(line)
        if not match or "f" not in match.group("flags").split():
            continue
        address = int(match.group("va"), 16)
        entry = functions[address]
        entry.names.add(match.group("name"))
        if ":" in match.group("object"):
            entry.from_library = True
    return dict(functions)


def parse_truth(path: Path) -> dict[int, MapFunction]:
    """A probe's <name>.truth.json: each function's address, names, and
    whether a library it was linked from defines it.

    An ELF probe has no MSVC linker map; build_elf_probes.py writes this from
    the unstripped program's symbol table and the libraries' own, and
    build_macho_probes.py from a Mach-O probe's ld64.lld map.
    """

    functions = {}
    for entry in json.loads(path.read_text(encoding="utf-8")):
        functions[int(entry["address"], 16)] = MapFunction(
            set(entry["names"]), bool(entry["from_library"]))
    return functions


def has_truth(probe: Path) -> bool:
    """Whether a probe has a linker map or truth file to compare with."""

    return probe.with_suffix(".truth.json").is_file() or probe.with_suffix(".map").is_file()


def probe_functions(probe: Path) -> dict[int, MapFunction]:
    truth = probe.with_suffix(".truth.json")
    if truth.is_file():
        return parse_truth(truth)
    return parse_map(probe.with_suffix(".map"))


def alias_order(name: str) -> tuple:
    """Where a name sorts among one routine's names: the fewest leading
    underscores first, then the shorter, then the smaller.

    The same rule as preferredAliasOrder in NeverD's
    include/neverd/sigs/Signature.h and alias_order in its builder,
    scripts/signatures/build_msvc_signatures.py.
    """

    return (len(name) - len(name.lstrip("_")), len(name), name)


def settled_names(matches: list[dict]) -> tuple[dict[int, str], set[int]]:
    """The name NeverD renames each address to, as SignatureDB::buildNameMap does.

    Each match gives its address a set of names: its name and its `aliases`,
    the other symbols its library gives the same routine. Matches agree when
    a name is in every one of those sets, and the address takes the preferred
    such name. Otherwise it is disputed, unless the matches whose branch
    references the image confirmed (`confirmed`, which NeverD before those
    references omits) agree on one in the same way.
    """

    proposed: dict[int, list[tuple[frozenset[str], bool]]] = {}
    for match in matches:
        names = frozenset([match["name"], *match.get("aliases", [])])
        proposed.setdefault(int(match["addr"], 16), []).append(
            (names, bool(match.get("confirmed", False))))

    def agree(name_sets: list[frozenset[str]]) -> str | None:
        if not name_sets:
            return None
        shared = frozenset.intersection(*name_sets)
        return min(shared, key=alias_order) if shared else None

    names: dict[int, str] = {}
    disputed: set[int] = set()
    for address, proposals in proposed.items():
        name = (agree([names_ for names_, _ in proposals])
                or agree([names_ for names_, confirmed in proposals if confirmed]))
        if name is None:
            disputed.add(address)
        else:
            names[address] = name
    return names, disputed


@dataclass
class Result:
    probe: str
    library_functions: int = 0
    correct: int = 0
    wrong: list[tuple[str, str, list[str]]] = field(default_factory=list)
    disputed: int = 0
    unmapped: int = 0
    # Why NeverD could not read the program, when it could not.
    failure: str | None = None

    @property
    def coverage(self) -> float:
        return self.correct / self.library_functions if self.library_functions else 0.0


def evaluate(neverd: Path, source: str, probe: Path) -> Result:
    completed = subprocess.run(
        [str(neverd), "sigs", "--json", "--no-debug", source, str(probe)],
        capture_output=True, text=True,
    )
    functions = probe_functions(probe)
    result = Result(probe.name)
    result.library_functions = sum(1 for f in functions.values() if f.from_library)
    if completed.returncode != 0:
        # A program NeverD refuses to load names nothing; say why.
        lines = [line.strip() for line in completed.stderr.splitlines() if line.strip()]
        result.failure = lines[-1] if lines else f"exit status {completed.returncode}"
        return result
    matches = json.loads(completed.stdout or "[]")
    names, disputed = settled_names(matches)
    result.disputed = len(disputed)
    for address, name in sorted(names.items()):
        expected = functions.get(address)
        if expected is None:
            result.unmapped += 1
            result.wrong.append((hex(address), name, []))
        elif name in expected.names:
            if expected.from_library:
                result.correct += 1
        else:
            result.wrong.append((hex(address), name, sorted(expected.names)))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--neverd", type=Path, required=True)
    parser.add_argument("--signatures", type=Path, required=True,
                        help="signature tree root (holding pe/)")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--auto", action="store_true",
                        help="let NeverD choose the files, as `sigs --auto` does, "
                             "instead of loading the whole directory")
    parser.add_argument("probes", nargs="+", type=Path, help="probe executables")
    args = parser.parse_args(argv)

    directories = {"x86": "x86/32", "x64": "x86/64", "arm": "arm/32", "arm64": "arm/64"}
    results = []
    failed = False
    for probe in args.probes:
        arch = next((a for a in ("arm64", "arm", "x64", "x86") if f"-{a}-" in probe.name), None)
        if arch is None:
            print(f"{probe.name}: cannot tell the architecture from the name", file=sys.stderr)
            return 1
        # The VS 2012 and 2013 setup programs have no public PDB to turn into
        # one; the programs after them are still measured.
        if not has_truth(probe):
            print(f"{probe.name}: no linker map or truth file to compare with; skipped")
            continue
        tree = TREES.get(probe.read_bytes()[:4], "pe")
        source = (f"--sig-base={args.signatures}" if args.auto
                  else f"--sig-dir={args.signatures / tree / directories[arch]}")
        result = evaluate(args.neverd, source, probe)
        results.append(result)
        failed |= bool(result.wrong) or result.failure is not None
        if result.failure is not None:
            print(f"{probe.name}: NeverD could not read it: {result.failure}")
            continue
        print(
            f"{probe.name}: {result.correct}/{result.library_functions} library functions "
            f"named ({result.coverage:.0%}), {len(result.wrong)} wrong, "
            f"{result.disputed} disputed"
        )
        for address, name, expected in result.wrong[:10]:
            print(f"  WRONG {address}: {name} (map: {', '.join(expected) or 'no function'})")
    if args.report:
        args.report.write_text(
            json.dumps([r.__dict__ | {"coverage": r.coverage} for r in results], indent=2) + "\n",
            encoding="utf-8",
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
