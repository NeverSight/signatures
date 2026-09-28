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


def settled_names(matches: list[dict]) -> tuple[dict[int, str], set[int]]:
    """The name NeverD renames each address to, as SignatureDB::buildNameMap does.

    An address the matches name differently is disputed, unless exactly one
    of the names comes from a match whose branch references the image
    confirmed (`confirmed`, which NeverD before those references omits).
    """

    proposed: dict[int, dict[str, bool]] = {}
    for match in matches:
        by_name = proposed.setdefault(int(match["addr"], 16), {})
        name = match["name"]
        by_name[name] = by_name.get(name, False) or bool(match.get("confirmed", False))
    names: dict[int, str] = {}
    disputed: set[int] = set()
    for address, by_name in proposed.items():
        if len(by_name) == 1:
            names[address] = next(iter(by_name))
            continue
        confirmed = [name for name, settled in by_name.items() if settled]
        if len(confirmed) == 1:
            names[address] = confirmed[0]
        else:
            disputed.add(address)
    return names, disputed


@dataclass
class Result:
    probe: str
    library_functions: int = 0
    correct: int = 0
    wrong: list[tuple[str, str, list[str]]] = field(default_factory=list)
    disputed: int = 0
    unmapped: int = 0

    @property
    def coverage(self) -> float:
        return self.correct / self.library_functions if self.library_functions else 0.0


def evaluate(neverd: Path, source: str, probe: Path) -> Result:
    completed = subprocess.run(
        [str(neverd), "sigs", "--json", "--no-debug", source, str(probe)],
        check=True, capture_output=True, text=True,
    )
    matches = json.loads(completed.stdout or "[]")
    functions = parse_map(probe.with_suffix(".map"))
    names, disputed = settled_names(matches)
    result = Result(probe.name)
    result.library_functions = sum(1 for f in functions.values() if f.from_library)
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

    directories = {"x86": "pe/x86/32", "x64": "pe/x86/64", "arm": "pe/arm/32", "arm64": "pe/arm/64"}
    results = []
    failed = False
    for probe in args.probes:
        arch = next((a for a in ("arm64", "arm", "x64", "x86") if f"-{a}-" in probe.name), None)
        if arch is None:
            print(f"{probe.name}: cannot tell the architecture from the name", file=sys.stderr)
            return 1
        source = (f"--sig-base={args.signatures}" if args.auto
                  else f"--sig-dir={args.signatures / directories[arch]}")
        result = evaluate(args.neverd, source, probe)
        results.append(result)
        failed |= bool(result.wrong)
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
