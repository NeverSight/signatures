#!/usr/bin/env python3
"""Check supplemental patterns against independent PE linker-map truth.

Only the supplied supplement tree is loaded, so every wrong proposal is
attributable to the import. Check every proposal, including disputed ones,
instead of allowing an existing signature to hide a bad imported name.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import hashlib
import struct
import subprocess
from pathlib import Path

from evaluate_probes import probe_functions
from import_ida_signatures import digest, load_builder
from migrate_imported_signatures import crc16, parse_hex


MACHINES = {0x14C: "pe/x86/32", 0x8664: "pe/x86/64", 0x1C4: "pe/arm/32", 0xAA64: "pe/arm/64"}


def function_bytes(data: bytes, address: int, size: int) -> bytes:
    """Read a default-image-base PE function, without applying relocations."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header")
    image_base = struct.unpack_from("<I" if magic == 0x10B else "<Q", data,
                                    optional + (28 if magic == 0x10B else 24))[0]
    rva = address - image_base
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    table = optional + struct.unpack_from("<H", data, pe + 20)[0]
    for index in range(sections):
        header = table + 40 * index
        virtual_size, virtual, raw_size, raw = struct.unpack_from("<IIII", data, header + 8)
        if virtual <= rva and rva + size <= virtual + raw_size:
            start = raw + rva - virtual
            if start + size <= len(data):
                return data[start:start + size]
    raise ValueError(f"function at {address:#x} is outside raw PE sections")


def matches_bytes(shape, data: bytes) -> bool:
    def matches(pattern, actual):
        values, mask = parse_hex(pattern)
        return len(actual) >= len(values) and all(not fixed or byte == actual[index]
                                                 for index, (byte, fixed) in enumerate(zip(values, mask)))

    leading = len(shape.lead) // 2
    if not matches(shape.lead[:shape.total * 2], data):
        return False
    if shape.crc_len and crc16(data[leading:leading + shape.crc_len]) != int(shape.crc, 16):
        return False
    tail_start = leading + shape.crc_len
    return matches(shape.tail[:max(0, shape.total - tail_start) * 2], data[tail_start:])


def counterexamples(report: dict, signatures: Path, probes: Path, source: Path, destination: Path) -> None:
    """Locate every wrong native proposal's exact byte claim before rejecting it."""
    builder = load_builder(source)
    wanted = {}
    for probe in report["probes"]:
        for index, match in enumerate(probe.get("wrong", [])):
            key = (probe["target"], match["library"], match["name"], match["func_len"])
            wanted.setdefault(key, []).append((probe, index, match))
    policy = json.loads(destination.read_text()) if destination.exists() else {"schema": 1, "claims": []}
    claims = {(item["target"], item["sha256"]): item for item in policy["claims"]}
    binary_cache = {}
    covered = set()
    for target, library in sorted({key[:2] for key in wanted}):
        files = [path for path in (signatures / target).glob("*.pat") if path.stem == library]
        if not files:
            raise ValueError(f"no source pattern file for {target}/{library}")
        for path in files:
            for raw in path.open():
                line = builder.parse_line(raw)
                if line is None:
                    continue
                shape = builder.Shape.of(line.key)
                for name in line.names:
                    bare = name.split(" ", 1)[1]
                    for probe, index, match in wanted.get((target, library, bare, shape.total), []):
                        if probe["probe"] not in binary_cache:
                            binary_cache[probe["probe"]] = (probes / probe["probe"]).read_bytes()
                        data = function_bytes(binary_cache[probe["probe"]], int(match["addr"], 16), shape.total)
                        if not matches_bytes(shape, data):
                            continue
                        covered.add((probe["probe"], index))
                        identity = hashlib.sha256(line.key.encode()).hexdigest()
                        claims.setdefault((target, identity), {
                            "target": target, "sha256": identity, "byte_claim": line.key,
                            "reason": "native_proposal_contradicts_linker_truth",
                            "example": {"probe": probe["probe"], "probe_sha256": probe["sha256"],
                                        "truth_sha256": probe["truth_sha256"], "addr": match["addr"],
                                        "proposed": match["name"], "expected": match["expected"],
                                        "confirmed": match.get("confirmed", False)}})
    expected = sum(len(probe.get("wrong", [])) for probe in report["probes"])
    if len(covered) != expected:
        raise ValueError(f"mapped {len(covered)} of {expected} wrong proposals; no policy was written")
    policy["claims"] = [claims[key] for key in sorted(claims)]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(policy, indent=2) + "\n")
    print(f"Mapped {expected} proposals to {len(claims)} unique byte claims", flush=True)


def check(neverd: Path, signatures: Path, probe: Path) -> dict:
    data = probe.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{probe}: expected PE probe")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError(f"{probe}: invalid PE header")
    target = MACHINES[struct.unpack_from("<H", data, pe + 4)[0]]
    truth = probe_functions(probe)
    if not truth:
        raise ValueError(f"{probe}: no function truth")
    result = {"probe": probe.name, "sha256": digest(probe), "target": target,
              "truth_sha256": digest(probe.with_suffix(".truth.json") if probe.with_suffix(".truth.json").exists()
                                     else probe.with_suffix(".map"))}
    if not list((signatures / target).glob("*.pat")):
        return result | {"skipped": "no supplement for this target"}
    process = subprocess.run([str(neverd), "sigs", "--json", "--no-debug",
                              "--sig-dir=" + str(signatures / target), str(probe)],
                             check=True, capture_output=True, text=True)
    matches = json.loads(process.stdout)
    wrong = []
    correct = 0
    for match in matches:
        expected = truth.get(int(match["addr"], 16))
        proposed = {match["name"], *match.get("aliases", [])}
        if expected and proposed & expected.names:
            correct += 1
        else:
            wrong.append(match | {"expected": sorted(expected.names) if expected else []})
    return result | {"proposals": len(matches), "correct": correct, "wrong": wrong}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--neverd", type=Path, required=True)
    parser.add_argument("--signatures", type=Path, required=True)
    parser.add_argument("--probes", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--counterexamples", type=Path,
                        help="write exact byte-claim exclusions for wrong proposals")
    parser.add_argument("--neverd-source", type=Path)
    args = parser.parse_args()
    probes = sorted(path for path in args.probes.glob("*.exe")
                    if path.with_suffix(".map").exists() or path.with_suffix(".truth.json").exists())
    if not probes:
        parser.error("no PE probes with linker truth")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = {pool.submit(check, args.neverd, args.signatures, path): path for path in probes}
        for future in concurrent.futures.as_completed(pending):
            path = pending[future]
            try:
                result = future.result()
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                result = {"probe": path.name, "failure": str(error)}
            results.append(result)
            print(f"{path.name}: {len(result.get('wrong', []))} wrong; "
                  f"{result.get('correct', 0)} correct; {result.get('skipped', result.get('failure', 'checked'))}", flush=True)
    report = {"neverd_sha256": digest(args.neverd), "probes": sorted(results, key=lambda item: item["probe"])}
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    if args.counterexamples:
        if not args.neverd_source:
            parser.error("--counterexamples requires --neverd-source")
        counterexamples(report, args.signatures, args.probes, args.neverd_source, args.counterexamples)
    return int(any(result.get("failure") or result.get("wrong") for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
