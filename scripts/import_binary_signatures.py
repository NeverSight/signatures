#!/usr/bin/env python3
"""Audit binary library signatures and import missing, expressible records.

Supply a compatible FLAIR dumpsig -F tool and a local input tree.
NeverD's existing pattern builder
owns alias folding and cross-library byte-claim admission. Existing files
are read as evidence and are never rewritten.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib.util
import inspect
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterator


OUTPUT_PREFIX = "supplemental-"
PART_BYTES = 45_000_000
PAIR = re.compile(r"(?:[0-9A-F]{2}|\.\.)*\Z")
NAME = re.compile(r"(-?[0-9A-F]+):([^\s]+)((?: \[[^\]]+\])*)", re.ASCII)
PUBLIC = re.compile(r" :[0-9A-Fa-f]+\s+(\S+)")


class DumpError(ValueError):
    """The dumper output does not satisfy the understood format."""


class Unsupported(ValueError):
    """A record cannot be stated without discarding evidence."""


@dataclass
class Record:
    pattern: str
    length: int
    names: list[tuple[int, str, str]] = field(default_factory=list)
    crc_length: int | None = None
    crc: int = 0
    rule_bytes: list[tuple[int, str]] = field(default_factory=list)
    references: list[tuple[int, str]] = field(default_factory=list)
    unsupported: set[str] = field(default_factory=set)
    saw_bytes: bool = False
    saw_references: bool = False


def read_dump(path: Path) -> Iterator[Record]:
    """Read full records, including multiple leaves sharing one pattern path."""
    pattern: str | None = None
    record: Record | None = None
    in_fixups = False

    def complete() -> Record:
        assert record is not None
        if record.crc_length is None or not record.saw_bytes or not record.saw_references:
            raise DumpError(f"{path}: incomplete record; dumpsig -F is required")
        return record

    # Structural fields are ASCII. Non-ASCII names are rejected explicitly;
    # decoding arbitrary symbol bytes as UTF-8 would change their identity.
    with path.open(encoding="latin1") as source:
        for number, raw in enumerate(source, 1):
            text = raw.strip(" \t\r\n")
            if not text:
                continue
            if raw.startswith("Pattern: "):
                if record is not None:
                    yield complete()
                    record = None
                pattern = text.removeprefix("Pattern: ")
                if not pattern or not PAIR.fullmatch(pattern):
                    raise DumpError(f"{path}:{number}: invalid pattern path")
                in_fixups = False
                continue
            length = re.fullmatch(r"\[len=([0-9A-F]+)\]", text)
            if length:
                if record is not None:
                    yield complete()
                if pattern is None:
                    raise DumpError(f"{path}:{number}: record before its pattern")
                record = Record(pattern, int(length[1], 16))
                in_fixups = False
                continue
            if record is None:
                raise DumpError(f"{path}:{number}: unexpected field {text[:100]!r}")
            additional = re.fullmatch(r"Additional: length=([0-9A-F]+) checksum=([0-9A-F]+)", text)
            if additional:
                if record.crc_length is not None:
                    raise DumpError(f"{path}:{number}: repeated checksum")
                record.crc_length, record.crc = (int(part, 16) for part in additional.groups())
            elif text.startswith(("Fixups (", "Alt fixups #")):
                # v11 fixups also encode data references, masks and alternative
                # tables. NeverD's ^offset branch references are insufficient.
                record.unsupported.add("fixup_tables")
                in_fixups = True
            elif text.startswith("Rulebytes:"):
                if record.saw_bytes:
                    raise DumpError(f"{path}:{number}: repeated rule bytes")
                record.saw_bytes = True
                in_fixups = False
                for token in text.removeprefix("Rulebytes:").split():
                    match = re.fullmatch(r"([0-9A-F]{2})@(-?[0-9A-F]+)", token)
                    if not match:
                        raise DumpError(f"{path}:{number}: invalid rule byte {token!r}")
                    record.rule_bytes.append((int(match[2], 16), match[1]))
            elif text.startswith("Rulefuncs:"):
                if record.saw_references:
                    raise DumpError(f"{path}:{number}: repeated rule functions")
                record.saw_references = True
                in_fixups = False
                if any(ord(char) > 126 or ord(char) < 32 for char in text):
                    record.unsupported.add("non_ascii_reference")
                    continue
                for token in text.removeprefix("Rulefuncs:").split():
                    match = re.fullmatch(r"(-?[0-9A-F]+):(.+)", token)
                    if not match:
                        raise DumpError(f"{path}:{number}: invalid rule function {token!r}")
                    record.references.append((int(match[1], 16), match[2]))
            elif in_fixups:
                # Keep the unsupported table as a refusal, never silently
                # reinterpret its entries as public names or rule functions.
                continue
            elif raw.startswith("\t") and not raw.startswith("\t\t"):
                if any(ord(char) > 126 or ord(char) < 32 for char in text):
                    record.unsupported.add("non_ascii_names")
                    continue
                matches = list(NAME.finditer(text))
                if not matches or " ".join(match[0] for match in matches) != text:
                    raise DumpError(f"{path}:{number}: invalid public-name list")
                record.names.extend((int(match[1], 16), match[2], match[3]) for match in matches)
            else:
                raise DumpError(f"{path}:{number}: unknown field {text[:100]!r}")
    if record is not None:
        yield complete()


def ascii_name(name: str) -> bool:
    return name != "?" and all(33 <= ord(char) <= 126 for char in name) and not name.startswith((":", "^", ".."))


def pattern_line(record: Record, arch: str, leading: int, minimum: int) -> str:
    """Preserve every understood constraint, or refuse the complete record."""
    if record.unsupported:
        raise Unsupported("unsupported_" + "_".join(sorted(record.unsupported)))
    if not record.length or record.length > 0xFFFFFFFF:
        raise Unsupported("invalid_module_extent")
    if not record.names or any(not ascii_name(name) for _, name, _ in record.names):
        raise Unsupported("unnamed_or_non_ascii")
    if any(flags for _, _, flags in record.names):
        raise Unsupported("local_or_collision_flags")
    if any(offset != 0 for offset, _, _ in record.names):
        raise Unsupported("multi_function_or_negative_offset")
    assert record.crc_length is not None
    if record.crc_length > 0xFF or record.crc > 0xFFFF:
        raise Unsupported("unsupported_checksum_width")
    head_length = min(leading, record.length)
    pairs = [record.pattern[i:i + 2] for i in range(0, len(record.pattern), 2)]
    if any(pair != ".." for pair in pairs[head_length:]):
        raise Unsupported("pattern_checks_beyond_extent")
    head = pairs[:head_length] + [".."] * max(0, head_length - len(pairs))
    tail_start = head_length + record.crc_length
    if tail_start > record.length:
        raise Unsupported("checksum_outside_extent")
    tail: dict[int, str] = {}
    for offset, value in record.rule_bytes:
        if offset < 0 or tail_start + offset >= record.length:
            raise Unsupported("rule_byte_outside_extent")
        if offset in tail and tail[offset] != value:
            raise DumpError("contradictory rule bytes")
        tail[offset] = value

    def stated(offset: int) -> str:
        if 0 <= offset < len(head):
            return head[offset]
        return tail.get(offset - tail_start, "..")

    for offset, name in record.references:
        # A FLIRT rule function may refer to a data address or indirect call.
        # ^offset names only a direct branch in NeverD. Require its opcode
        # in the stated bytes; bytes hidden inside a CRC are not evidence.
        if arch != "x86" or offset <= 0 or offset + 4 > record.length \
                or stated(offset - 1) not in ("E8", "E9") or not ascii_name(name):
            raise Unsupported("non_direct_or_unproved_reference")
        if any(stated(i) != ".." or head_length <= i < tail_start for i in range(offset, offset + 4)):
            raise Unsupported("reference_overlaps_fixed_bytes")
    fixed = sum(pair != ".." for pair in head) + len(tail)
    if fixed < minimum:
        raise Unsupported("too_few_stated_bytes")
    names = sorted({name for _, name, _ in record.names},
                   key=lambda name: (len(name) - len(name.lstrip("_")), len(name), name))
    fields = ["".join(head), f"{record.crc_length:02X}", f"{record.crc:04X}", f"{record.length:04X}"]
    fields.extend(f":0000 {name}" for name in names)
    fields.extend(f"^{offset:04X} {name}" for offset, name in sorted(set(record.references)))
    if tail:
        fields.append("".join(tail.get(offset, "..") for offset in range(max(tail) + 1)))
    return " ".join(fields)


def destination(relative: str, header: dict[str, str]) -> tuple[str | None, str]:
    """Admit only an evidenced format and width; protect rebuilt library families."""
    path = Path(relative)
    if path.parts[0] not in ("pc", "arm"):
        return None, "signature_tree_architecture_unsupported"
    if path.stem.startswith("vc") and path.stem != "vc32mfce" \
            or path.stem.startswith("mssdk") \
            or "glibc" in path.stem or path.stem.startswith("android_"):
        return None, "rebuilt_family_preserved"
    if int(header.get("Flags", "0"), 16) & 1:
        return None, "startup_rules_unsupported"
    if "ctype" in header.get("Features", ""):
        return None, "ctype_constraints_unsupported"
    if not header.get("Features", "32-bytes patterns").endswith(" 32-bytes patterns") \
            and header.get("Features", "32-bytes patterns") != "32-bytes patterns":
        return None, "pattern_width_unsupported"
    file_types = header.get("File types", "").split()
    app_types = set(header.get("App types", "").split()[1:])
    widths = app_types & {"32BIT", "64BIT"}
    if len(widths) != 1 or not file_types or file_types[0] == "FFFFFFFF":
        return None, "missing_or_mixed_target_metadata"
    if "PE" not in file_types:
        return None, "binary_format_or_16bit_unsupported"
    width = next(iter(widths)).removesuffix("BIT")
    title_widths = set(re.findall(r"\b(32|64)\s*bit\b", header.get("Signature", ""), re.I))
    if title_widths and title_widths != {width}:
        return None, "contradictory_bitness_metadata"
    arch = "x86" if path.parts[0] == "pc" else "arm"
    return f"pe/{arch}/{width}", "candidate"


def load_builder(root: Path):
    path = root / "scripts/signatures/build_msvc_signatures.py"
    spec = importlib.util.spec_from_file_location("neverd_pattern_builder", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load NeverD pattern authority: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def signature_limits(root: Path) -> tuple[int, int]:
    text = (root / "include/neverd/sigs/SignatureLimits.def").read_text()
    values = []
    for name in ("DefaultLeadingBytes", "MinStatedBytes"):
        match = re.search(rf"NEVERD_SIGS_LIMIT\({name}, (\d+)\)", text)
        if not match:
            raise ValueError(f"cannot read NeverD's {name} authority")
        values.append(int(match[1]))
    return values[0], values[1]


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def settle_missing(builder, results: dict, evidence: list) -> None:
    """Apply the shared admission rules while protecting existing claims both ways.

    If a new, longer claim causes an old shorter claim to be removed by the
    builder, the old file will still exist. Refuse that new claim as well.
    A supplement must not require rewriting the baseline to remain sound.
    """
    if not any(result.lines for result in results.values()):
        return
    # Every baseline name was excluded before folding. Equal byte keys
    # therefore cannot add a new identity without disputing an old one.
    # Baseline records belong in the builder's evidence index, not its
    # output lists: rechecking baseline-vs-baseline claims is unnecessary.
    imported_keys = {line.key for result in results.values() for line in result.lines}
    ambiguous = {key for result in results.values() for key in result.ambiguous_keys}
    ambiguous.update(line.key for line in evidence if line.key in imported_keys)
    indexed = {}
    for line in [*evidence, *(line for result in results.values() for line in result.evidence)]:
        indexed.setdefault((line.key, line.names), line)
    all_evidence = sorted(indexed.values(), key=lambda line: line.key[:line.key.index(" ")])
    evidence_leads = [line.key[:line.key.index(" ")] for line in all_evidence]
    groups = {}
    for path, result in results.items():
        for line in result.lines:
            shape = builder.Shape.of(line.key)
            prefix = shape.stated_prefix()[:2 * shape.total]
            groups.setdefault(prefix, {}).setdefault(path, []).append(line)
    retained = {path: [] for path in results}
    # A covering routine must state every byte before a claim's first
    # wildcard. Partition output claims by that prefix and give the shared
    # builder all evidence in its matching prefix range. This preserves the
    # same-key/reference decisions while avoiding unrelated CRC buckets.
    for prefix, owners in groups.items():
        start = bisect.bisect_left(evidence_leads, prefix)
        end = bisect.bisect_right(evidence_leads, prefix + "~")
        chunks = {path: builder.FoldResult(lines=lines) for path, lines in owners.items()}
        first = next(iter(chunks.values()))
        first.evidence = all_evidence[start:end]
        first.ambiguous_keys = ambiguous.intersection(line.key for lines in owners.values() for line in lines)
        builder.settle_directory(chunks)
        for path, chunk in chunks.items():
            retained[path].extend(chunk.lines)
            results[path].dropped_across_files += chunk.dropped_across_files
            results[path].dropped_covered += chunk.dropped_covered
    for path, result in results.items():
        result.lines = sorted(retained[path], key=lambda line: line.text)
    claimed = sorted((builder.Shape.of(line.key).lead, line.text,
                      builder.Shape.of(line.key), line.names)
                     for result in results.values() for line in result.lines)
    leads = [claim[0] for claim in claimed]
    by_crc: dict[tuple[int, str], list[tuple]] = {}
    for claim in claimed:
        shape = claim[2]
        by_crc.setdefault((shape.crc_len, shape.crc), []).append(claim)
    crc_leads = {key: [claim[0] for claim in claims] for key, claims in by_crc.items()}
    rejected: set[str] = set()
    for old in evidence:
        shape = builder.Shape.of(old.key)
        prefix = shape.stated_prefix()[:2 * shape.total]
        if shape.crc_len and len(shape.lead) < shape.total * 2:
            crc_key = (shape.crc_len, shape.crc)
            candidates = by_crc.get(crc_key, [])
            prefix_index = crc_leads.get(crc_key, [])
            first = bisect.bisect_left(prefix_index, prefix)
            last = bisect.bisect_right(prefix_index, prefix + "~")
            possible = candidates[first:last]
        else:
            first = bisect.bisect_left(leads, prefix)
            last = bisect.bisect_right(leads, prefix + "~")
            possible = claimed[first:last]
        for _, text, other, names in possible:
            if builder.another_routine(old.names, names) and shape.covered_by(other):
                rejected.add(text)
    for result in results.values():
        kept = [line for line in result.lines if line.text not in rejected]
        result.dropped_across_files += len(result.lines) - len(kept)
        result.lines = kept


def decode(sig_root: Path, dumper: Path, work: Path) -> list[dict]:
    """Cache full dumps with source and tool identities; capture headers from stdout."""
    tool_hash = digest(dumper)
    inventory = []
    for path in sorted(sig_root.rglob("*.sig")):
        relative = path.relative_to(sig_root)
        output = work / "dumps" / relative.with_suffix(".dump")
        meta = output.with_suffix(".json")
        source_hash = digest(path)
        cached = json.loads(meta.read_text()) if meta.exists() else {}
        if not output.exists() or cached.get("sha256") != source_hash \
                or cached.get("dumper_sha256") != tool_hash \
                or cached.get("dump_sha256") != digest(output):
            output.parent.mkdir(parents=True, exist_ok=True)
            run = subprocess.run([str(dumper), "-F", str(path), str(output)],
                                 capture_output=True, text=True, errors="replace")
            if run.returncode or "Error:" in run.stdout or not output.exists():
                raise DumpError(f"{relative}: dumpsig failed: {run.stdout}\n{run.stderr}")
            header = {line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
                      for line in run.stdout.splitlines() if ":" in line}
            if not re.search(r"\b\d+-bytes patterns$", header.get("Features", "")):
                raise DumpError(f"{relative}: unsupported pattern width: {header}")
            cached = {"file": relative.as_posix(), "sha256": source_hash,
                      "dumper_sha256": tool_hash, "dump_sha256": digest(output),
                      "header": header}
            meta.write_text(json.dumps(cached, indent=2) + "\n")
        inventory.append(cached)
    if not inventory:
        raise ValueError("the source tree contains no .sig files")
    return inventory


def baseline_files(root: Path, target: str) -> list[Path]:
    return sorted(path for path in (root / target).glob("*.pat") if not path.name.startswith(OUTPUT_PREFIX))


def read_names(paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for path in paths:
        with path.open() as source:
            for raw in source:
                if not raw.startswith((";", "#")):
                    names.update(PUBLIC.findall(raw))
    return names


def write_patterns(root: Path, relative: Path, texts: list[str], provenance: dict) -> None:
    parts: list[list[str]] = [[]]
    size = 0
    for text in texts:
        if size and size + len(text) + 1 > PART_BYTES:
            parts.append([])
            size = 0
        parts[-1].append(text)
        size += len(text) + 1
    artifacts = []
    for number, lines in enumerate(parts, 1):
        path = root / relative
        if number > 1:
            path = path.with_name(f"{path.stem}.part{number}.pat")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("; Converted missing records; see the adjacent .sources.json\n"
                        + "\n".join(lines) + "\n---\n")
        artifacts.append({"file": path.relative_to(root).as_posix(), "sha256": digest(path)})
    metadata = root / relative.with_suffix(".sources.json")
    metadata.write_text(json.dumps(provenance | {"file": relative.as_posix(), "lines": len(texts),
                                                 "parts": len(parts), "artifacts": artifacts}, indent=2) + "\n")


def run(args: argparse.Namespace) -> dict:
    builder = load_builder(args.neverd_source)
    leading, minimum = signature_limits(args.neverd_source)
    inventory = decode(args.sig_root, args.dumpsig, args.work)
    targets = sorted({target for item in inventory
                      if (target := destination(item["file"], item["header"])[0])})
    existing = {target: read_names(baseline_files(args.baseline, target)) for target in targets}
    baseline_hashes = {}
    for target in targets:
        hashes = [(path.name, digest(path)) for path in baseline_files(args.baseline, target)]
        baseline_hashes[target] = hashlib.sha256(json.dumps(hashes).encode()).hexdigest()
    policy = "\n".join(inspect.getsource(function) for function in
                       (run, read_dump, pattern_line, destination, read_names, ascii_name))
    policy += repr((OUTPUT_PREFIX, PAIR.pattern, NAME.pattern, NAME.flags, PUBLIC.pattern))
    policy += digest(args.neverd_source / "scripts/signatures/build_msvc_signatures.py")
    policy += digest(args.neverd_source / "include/neverd/sigs/SignatureLimits.def")
    policy_hash = hashlib.sha256(policy.encode()).hexdigest()
    reports: list[dict] = []
    candidates: dict[str, dict[Path, object]] = {target: {} for target in targets}
    for item in inventory:
        target, decision = destination(item["file"], item["header"])
        fingerprint = hashlib.sha256(json.dumps(
            [item, policy_hash, baseline_hashes.get(target)], sort_keys=True).encode()).hexdigest()
        checkpoint = args.work / "selection" / Path(item["file"]).with_suffix(".json")
        cached = json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
        if cached.get("fingerprint") == fingerprint:
            report = cached["report"]
            if target:
                candidates[target][Path(report["output"])] = builder.FoldResult(
                    lines=[builder.parse_line(text) for text in cached["lines"]],
                    evidence=[builder.parse_line(text) for text in cached["evidence"]],
                    ambiguous_keys=set(cached["ambiguous_keys"]))
            reports.append(report)
            print(f"{item['file']}: cached selection", flush=True)
            continue
        report = item | {"target": target, "decision": decision}
        counts: Counter[str] = Counter()
        names: set[str] = set()
        lines: list[str] = []
        blocked: set[str] = set()
        dump_path = args.work / "dumps" / Path(item["file"]).with_suffix(".dump")
        if target is None:
            # These files cannot contribute records. Inventory their names
            # without pretending to understand unsupported startup/fixup rules.
            with dump_path.open(encoding="latin1") as source:
                for raw in source:
                    if raw.startswith("\t[len="):
                        counts["records"] += 1
                    elif raw.startswith("\t") and not raw.startswith("\t\t"):
                        names.update(match[2] for match in NAME.finditer(raw)
                                     if int(match[1], 16) == 0 and not match[3] and ascii_name(match[2]))
        for record in read_dump(dump_path) if target else ():
            counts["records"] += 1
            names.update(name for offset, name, flags in record.names
                         if offset == 0 and not flags and ascii_name(name))
            if any("[COLL]" in flags for _, _, flags in record.names):
                counts["local_or_collision_flags"] += 1
                try:
                    collision = replace(record, names=[(0, "collision", "")])
                    line = pattern_line(collision, target.split("/")[1], leading, minimum)
                    blocked.add(builder.parse_line(line).key)
                except Unsupported:
                    pass
                continue
            if any(name in existing[target] for _, name, _ in record.names):
                counts["already_named"] += 1
                continue
            try:
                lines.append(pattern_line(record, target.split("/")[1], leading, minimum))
            except Unsupported as refusal:
                counts[str(refusal)] += 1
        report["counts"] = dict(sorted(counts.items()))
        report["symbols"] = len(names)
        if target:
            report["missing_symbols"] = len(names - existing[target])
            report["missing_examples"] = sorted(names - existing[target])[:12]
            relative = Path(target) / f"{OUTPUT_PREFIX}{Path(item['file']).stem}.pat"
            folded = builder.fold(lines)
            folded.ambiguous_keys.update(blocked)
            candidates[target][relative] = folded
            report["output"] = relative.as_posix()
            report["expressible_records"] = len(lines)
            report["after_folding"] = len(folded.lines)
        reports.append(report)
        snapshot = {"fingerprint": fingerprint, "report": report}
        if target:
            snapshot.update(lines=[line.text for line in folded.lines],
                            evidence=[line.text for line in folded.evidence],
                            ambiguous_keys=sorted(folded.ambiguous_keys))
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        temporary = checkpoint.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(snapshot) + "\n")
        temporary.replace(checkpoint)
        print(f"{item['file']}: {decision}, {counts['records']} records, {len(lines)} candidates", flush=True)

    for target, results in candidates.items():
        evidence = []
        for path in baseline_files(args.baseline, target):
            with path.open() as source:
                evidence.extend(line for raw in source if (line := builder.parse_line(raw)) is not None)
        # The normal builder evaluates all files together. Only imported lines
        # are subsequently written; existing files remain byte-for-byte intact.
        print(f"{target}: settle {sum(len(result.lines) for result in results.values())} "
              f"imported claims against {len(evidence)} baseline records", flush=True)
        settle_missing(builder, results, evidence)
        print(f"{target}: admission complete", flush=True)
        seen: set[str] = set()
        for relative, folded in sorted(results.items()):
            texts = [line.text for line in folded.lines if line.text not in seen]
            seen.update(texts)
            report = next(item for item in reports if item.get("output") == relative.as_posix())
            report["imported_records"] = len(texts)
            report["imported_symbols"] = len({name for text in texts for name in PUBLIC.findall(" " + text)})
            report["dropped_conflicts_or_covered"] = folded.dropped_across_files + folded.dropped_covered
            report["duplicate_records_across_sources"] = len(folded.lines) - len(texts)
            if texts:
                write_patterns(args.output, relative, texts, {
                    "origin": "Converted third-party binary library signatures",
                    "source": report["file"], "sha256": report["sha256"],
                    "dumper_sha256": report["dumper_sha256"],
                    "header": report["header"],
                    "baseline_ref": args.baseline_ref,
                    "generator": "scripts/import_binary_signatures.py",
                })
    summary = {"source_files": len(inventory), "baseline_ref": args.baseline_ref,
               "neverd_leading_bytes": leading, "neverd_minimum_stated_bytes": minimum,
               "imported_records": sum(item.get("imported_records", 0) for item in reports),
               "files": reports}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "supplemental-audit.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for name in ("sig-root", "dumpsig", "neverd-source", "baseline", "work", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--baseline-ref", required=True)
    parser.add_argument("--counterexamples", type=Path,
                        default=Path(__file__).resolve().parents[1] / "validation/supplemental-counterexamples.json")
    args = parser.parse_args()
    if args.output.resolve() == args.baseline.resolve():
        parser.error("stage output separately before reviewing and installing it")
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("the staging directory must be empty; preserve earlier results in another directory")
    try:
        report = run(args)
        if args.counterexamples.exists():
            report = apply_counterexamples(args.output, args.counterexamples, load_builder(args.neverd_source))
        report = publication_metadata(args.output, args.work / "input-records", {
            "signature_root": str(args.sig_root.resolve()), "dumper": str(args.dumpsig.resolve())})
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Imported {report['imported_records']} supplemental records")
    return 0


def apply_counterexamples(output: Path, policy_path: Path, builder) -> dict:
    """Remove byte claims proven unsafe by native proposals and linker truth."""
    policy = json.loads(policy_path.read_text())
    if policy.get("schema") != 1:
        raise ValueError("unsupported counterexample policy schema")
    excluded = set()
    for item in policy["claims"]:
        if hashlib.sha256(item["byte_claim"].encode()).hexdigest() != item["sha256"]:
            raise ValueError("counterexample byte-claim hash mismatch")
        excluded.add((item["target"], item["sha256"]))
    report_path = output / "supplemental-audit.json"
    report = json.loads(report_path.read_text())
    policy_hash = digest(policy_path)
    for item in report["files"]:
        if not item.get("imported_records"):
            continue
        relative = Path(item["output"])
        metadata_path = output / relative.with_suffix(".sources.json")
        metadata = json.loads(metadata_path.read_text())
        paths = [output / relative]
        paths.extend((output / relative).with_name(f"{relative.stem}.part{number}.pat")
                     for number in range(2, metadata["parts"] + 1))
        kept = []
        removed = 0
        for path in paths:
            for raw in path.open():
                line = builder.parse_line(raw)
                if line is None:
                    continue
                fingerprint = hashlib.sha256(line.key.encode()).hexdigest()
                if (item["target"], fingerprint) in excluded:
                    removed += 1
                else:
                    kept.append(line.text)
        if removed:
            for path in paths:
                path.unlink()
            metadata_path.unlink()
            item["rejected_by_probe_counterexamples"] = item.get("rejected_by_probe_counterexamples", 0) + removed
            item["imported_records"] = len(kept)
            item["imported_symbols"] = len({name for text in kept for name in PUBLIC.findall(" " + text)})
        metadata["validation"] = {"counterexample_policy_sha256": policy_hash,
                                  "rejected_records": item.get("rejected_by_probe_counterexamples", 0)}
        if kept:
            write_patterns(output, relative, kept, metadata)
    report["counterexample_policy_sha256"] = policy_hash
    report["imported_records"] = sum(item.get("imported_records", 0) for item in report["files"])
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


def publication_metadata(output: Path, private: Path, context: dict | None = None,
                         report_path: Path | None = None) -> dict:
    """Keep input records locally and publish coverage plus artifact identities."""
    if private.resolve().is_relative_to(output.resolve()):
        raise ValueError("input records must be kept outside the publication tree")
    report_path = report_path or output / "legacy-library-audit.json"
    report = json.loads(report_path.read_text())
    raw_input = report.get("publication_schema") != 1
    if raw_input:
        snapshot = private / digest(report_path)
        snapshot.mkdir(parents=True, exist_ok=True)
        private.chmod(0o700)
        snapshot.chmod(0o700)
        (snapshot / "input-records.json").write_text(json.dumps(report, indent=2) + "\n")
        (snapshot / "context.json").write_text(json.dumps(context or {}, indent=2) + "\n")
    fields = {"target", "decision", "counts", "symbols", "missing_symbols", "missing_examples",
              "output", "expressible_records", "after_folding", "imported_records",
              "imported_symbols", "dropped_conflicts_or_covered", "duplicate_records_across_sources",
              "rejected_by_probe_counterexamples"}
    records = []
    for index, item in enumerate(report["files"], 1):
        title = item.get("library_family") or item.get("header", {}).get("Signature", "")
        title = re.sub(r", \d+ modules$", "", title)
        row = {key: value for key, value in item.items() if key in fields}
        row.update(profile=index, library_family=title)
        records.append(row)
        if not item.get("imported_records"):
            continue
        relative = Path(item["output"])
        path = output / relative.with_suffix(".sources.json")
        original = json.loads(path.read_text())
        if raw_input:
            saved = snapshot / relative.with_suffix(".sources.json")
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_text(json.dumps(original, indent=2) + "\n")
        parts = [output / relative]
        parts.extend((output / relative).with_name(f"{relative.stem}.part{number}.pat")
                     for number in range(2, original["parts"] + 1))
        public = {"schema": 1, "file": relative.as_posix(), "library_family": title,
                  "source_kind": "converted_binary_library_signatures",
                  "generator": "scripts/import_binary_signatures.py",
                  "baseline_ref": report.get("baseline_ref", original.get("baseline_ref")),
                  "lines": original["lines"], "parts": original["parts"],
                  "artifacts": [{"file": part.relative_to(output).as_posix(), "sha256": digest(part)}
                                for part in parts], "validation": original.get("validation", {})}
        for notice in ("copyright", "license", "licenses", "notice", "notices", "attribution"):
            if notice in original:
                public[notice] = original[notice]
        path.write_text(json.dumps(public, indent=2) + "\n")
    published = {key: report[key] for key in ("baseline_ref", "neverd_leading_bytes",
                 "neverd_minimum_stated_bytes", "imported_records", "counterexample_policy_sha256")
                 if key in report}
    published.update(publication_schema=1, files=records)
    report_path.write_text(json.dumps(published, indent=2) + "\n")
    return published


if __name__ == "__main__":
    raise SystemExit(main())
