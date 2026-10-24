"""Synthetic, vendor-data-free checks for the FLIRT import boundary."""

from __future__ import annotations

import sys
import os
import json
import subprocess
import random
import argparse
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import import_binary_signatures as importer


HEAD = bytes(range(32)).hex().upper()


def record(**changes) -> importer.Record:
    values = dict(pattern=HEAD, length=80, names=[(0, "missing_function", "")],
                  crc_length=3, crc=0x1234, saw_bytes=True, saw_references=True)
    values.update(changes)
    return importer.Record(**values)


class DumpTests(unittest.TestCase):
    def parse(self, text: str) -> list[importer.Record]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.dump"
            path.write_text(text)
            return list(importer.read_dump(path))

    def test_shared_tree_path_retains_separate_crc_and_rule_variants(self):
        records = self.parse(
            f"Pattern: {HEAD}\n"
            "\t[len=0050]\n\t0000:first 0000:first_alias \n"
            "\t\tAdditional: length=03 checksum=1234\n"
            "\t\tRulebytes: AA@0004 BB@0006\n\t\tRulefuncs: \n"
            "\t[len=0060]\n\t0000:second \n"
            "\t\tAdditional: length=04 checksum=ABCD\n"
            "\t\tRulebytes: \n\t\tRulefuncs: 000B:callee\n")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].names, [(0, "first", ""), (0, "first_alias", "")])
        self.assertEqual(records[0].rule_bytes, [(4, "AA"), (6, "BB")])
        self.assertEqual(records[1].pattern, HEAD)
        self.assertEqual(records[1].references, [(11, "callee")])

    def test_fixups_are_not_reinterpreted_as_names(self):
        records = self.parse(
            f"Pattern: {HEAD}\n\t[len=0050]\n\t0000:entry \n"
            "\t\tAdditional: length=03 checksum=1234\n"
            "\t\tFixups (1):\n\t\t  0024:external_data\n"
            "\t\tAlt fixups #1 (1):\n\t\t  0024:other_data\n"
            "\t\tRulebytes: \n\t\tRulefuncs: \n")
        self.assertEqual(records[0].names, [(0, "entry", "")])
        with self.assertRaisesRegex(importer.Unsupported, "fixup_tables"):
            importer.pattern_line(records[0], "x86", 32, 16)

    def test_truncated_and_unknown_fields_fail_loudly(self):
        with self.assertRaisesRegex(importer.DumpError, "incomplete"):
            self.parse(f"Pattern: {HEAD}\n\t[len=0050]\n\t0000:entry\n")
        with self.assertRaisesRegex(importer.DumpError, "unknown field"):
            self.parse(f"Pattern: {HEAD}\n\t[len=0050]\n\t\tNew constraint: 7\n")

    def test_negative_offsets_and_local_flags_are_retained_for_refusal(self):
        records = self.parse(
            f"Pattern: {HEAD}\n\t[len=0050]\n"
            "\t-0004:data 0000:entry 0008:label [LOCAL] \n"
            "\t\tAdditional: length=00 checksum=0000\n"
            "\t\tRulebytes: \n\t\tRulefuncs: \n")
        self.assertEqual(records[0].names[-1], (8, "label", " [LOCAL]"))
        with self.assertRaises(importer.Unsupported):
            importer.pattern_line(records[0], "x86", 32, 16)

    def test_compressed_non_ascii_names_are_refused_without_corrupting_structure(self):
        records = self.parse(
            f"Pattern: {HEAD}\n\t[len=0050]\n\t0000:compressed_\u0085_name \n"
            "\t\tAdditional: length=00 checksum=0000\n"
            "\t\tRulebytes: \n\t\tRulefuncs: \n")
        with self.assertRaisesRegex(importer.Unsupported, "non_ascii"):
            importer.pattern_line(records[0], "x86", 32, 16)


class ConversionTests(unittest.TestCase):
    def line(self, item: importer.Record) -> str:
        return importer.pattern_line(item, "x86", 32, 16)

    def test_crc_starts_after_padded_head_and_tail_after_crc(self):
        item = record(pattern=HEAD[:56], rule_bytes=[(4, "AA"), (6, "BB")])
        line = self.line(item)
        self.assertEqual(line.split()[0], HEAD[:56] + "........")
        self.assertEqual(line.split()[-1], "........AA..BB")
        self.assertIn(" 03 1234 0050 ", line)

    def test_short_head_is_not_padded_past_its_module(self):
        item = record(pattern=HEAD[:40], length=20, crc_length=0, crc=0)
        self.assertEqual(self.line(item).split()[0], HEAD[:40])

    def test_preserves_linkage_spelling_and_aliases(self):
        names = [(0, "?Close@Class@@UEAAXXZ", ""), (0, "_plain@12", "")]
        line = self.line(record(names=names))
        self.assertIn(":0000 ?Close@Class@@UEAAXXZ", line)
        self.assertIn(":0000 _plain@12", line)

    def test_only_evidenced_direct_branch_references_are_emitted(self):
        head = HEAD[:20] + "E8........" + HEAD[30:]
        line = self.line(record(pattern=head, references=[(11, "_callee@4")]))
        self.assertIn("^000B _callee@4", line)
        for item in [record(references=[(11, "data")]),
                     record(references=[(35, "hidden_by_crc")]),
                     record(pattern=head, references=[(11, "?anything")], rule_bytes=[(-1, "FF")])]:
            with self.assertRaises(importer.Unsupported):
                self.line(item)
        with self.assertRaisesRegex(importer.Unsupported, "reference"):
            importer.pattern_line(record(pattern=head, references=[(11, "callee")]), "arm", 32, 16)

    def test_does_not_drop_constraints_outside_neverd_extent(self):
        for item in [record(pattern=HEAD, length=20, crc_length=0),
                     record(length=34, crc_length=3),
                     record(rule_bytes=[(45, "AA")]),
                     record(names=[(4, "non_entry", "")]),
                     record(names=[(0, "entry", " [LOCAL]")]),
                     record(names=[(0, "?", " [COLL]")])]:
            with self.assertRaises(importer.Unsupported):
                self.line(item)

    def test_crc_bytes_do_not_count_as_stated_bytes(self):
        with self.assertRaisesRegex(importer.Unsupported, "too_few_stated"):
            self.line(record(pattern="AABBCCDD", length=64, crc_length=32))

    def test_fixed_relocated_operand_is_refused(self):
        head = HEAD[:20] + "E800000000" + HEAD[30:]
        with self.assertRaisesRegex(importer.Unsupported, "overlaps_fixed"):
            self.line(record(pattern=head, references=[(11, "callee")]))


class RoutingTests(unittest.TestCase):
    def header(self, width="32BIT", title="A runtime"):
        return {"File types": "00000800 PE", "App types": "017F CONSOLE " + width,
                "Signature": title, "Flags": "0010"}

    def test_supported_targets(self):
        self.assertEqual(importer.destination("pc/runtime.sig", self.header()), ("pe/x86/32", "candidate"))
        self.assertEqual(importer.destination("arm/mfc.sig", self.header()), ("pe/arm/32", "candidate"))
        self.assertEqual(importer.destination("pc/runtime.sig", self.header("64BIT"))[0], "pe/x86/64")

    def test_preserves_rebuilt_families_even_if_a_name_would_be_new(self):
        for source in ("pc/vc64seh.sig", "pc/vc32rtf.sig", "arm/vc64mfc.sig",
                       "pc/glibc_i386.sig", "arm/android_arm.sig", "pc/mssdk32.sig"):
            self.assertEqual(importer.destination(source, self.header())[1], "rebuilt_family_preserved")

    def test_mislabeled_ddk_and_mixed_go_cannot_choose_a_width(self):
        self.assertEqual(importer.destination("pc/msddk32.sig", self.header("64BIT", "DDK Windows 32bit"))[1],
                         "contradictory_bitness_metadata")
        self.assertIsNone(importer.destination("pc/go_std.sig", self.header("32BIT 64BIT"))[0])

    def test_startup_and_unsupported_isa_are_not_library_patterns(self):
        header = self.header() | {"Flags": "0011"}
        self.assertEqual(importer.destination("pc/pe.sig", header)[1], "startup_rules_unsupported")
        self.assertIsNone(importer.destination("mips/runtime.sig", self.header())[0])

    def test_ctype_header_constraints_are_not_lost(self):
        header = self.header() | {"Features": "(ctype=table,crc=1234) compressed(zlib) 32-bytes patterns"}
        self.assertEqual(importer.destination("pc/runtime.sig", header)[1], "ctype_constraints_unsupported")


class BaselineProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get("NEVERD_SOURCE_DIR")
        if not source:
            raise unittest.SkipTest("NEVERD_SOURCE_DIR supplies the authoritative NeverD builder")
        cls.builder = importer.load_builder(Path(source))

    def settle(self, baseline, supplement):
        evidence = [self.builder.parse_line(raw) for raw in baseline]
        original = [line.text for line in evidence]
        result = self.builder.fold(supplement)
        importer.settle_missing(self.builder, {Path("new.pat"): result}, evidence)
        self.assertEqual([line.text for line in evidence], original)
        return [line.text for line in result.lines]

    def test_identical_bytes_under_new_name_do_not_dispute_existing_name(self):
        self.assertEqual(self.settle(["AABBCCDD 00 0000 0004 :0000 original"],
                                     ["AABBCCDD 00 0000 0004 :0000 missing"]), [])

    def test_new_shorter_claim_cannot_name_a_longer_existing_routine(self):
        self.assertEqual(self.settle(["AABBCCDDEE 00 0000 0005 :0000 original"],
                                     ["AABBCCDD 00 0000 0004 :0000 missing"]), [])

    def test_longer_new_claim_must_not_require_removing_the_existing_claim(self):
        self.assertEqual(self.settle(["AABBCCDD 00 0000 0004 :0000 original"],
                                     ["AABBCCDDEE 00 0000 0005 :0000 missing"]), [])

    def test_unrelated_new_code_is_retained(self):
        candidate = "AABBCCDD 00 0000 0004 :0000 missing"
        self.assertEqual(self.settle(["AABBCCEE 00 0000 0004 :0000 original"], [candidate]), [candidate])

    def test_inverse_prefix_index_ignores_baseline_bytes_past_its_declared_extent(self):
        old = "AA" * 20 + "BB" * 4 + " 00 0000 0014 :0000 original"
        new = "AA" * 20 + "CC" * 4 + " 00 0000 0018 :0000 missing"
        self.assertEqual(self.settle([old], [new]), [])

    def test_indexed_admission_agrees_with_full_cross_library_and_inverse_checks(self):
        from migrate_imported_signatures import crc16

        random_source = random.Random(95)

        def line(name):
            size = random_source.choice((16, 20, 32, 40, 48))
            data = bytes([random_source.randrange(3)]) * size
            lead = data[:32].hex().upper()
            if random_source.randrange(2):
                lead = lead[:20] + ".." * 4 + lead[28:]
            crc_length = min(random_source.choice((0, 4)), max(0, size - 32))
            checksum = crc16(data[32:32 + crc_length])
            tail = data[32 + crc_length:].hex().upper()
            return f"{lead} {crc_length:02X} {checksum:04X} {size:04X} :0000 {name} {tail}".rstrip()

        for iteration in range(150):
            baseline = [line(f"existing_{i}") for i in range(4)]
            imported = [line(f"missing_{i}") for i in range(4)]
            old = self.builder.fold(baseline)
            slow = self.builder.fold(imported)
            self.builder.settle_directory({Path("baseline"): old, Path("new"): slow})
            expected = []
            for candidate in slow.lines:
                shape = self.builder.Shape.of(candidate.key)
                if not any(self.builder.Shape.of(item.key).covered_by(shape)
                           for item in old.evidence):
                    expected.append(candidate.text)
            with self.subTest(iteration=iteration):
                self.assertEqual(self.settle(baseline, imported), expected)

    def test_selection_cache_invalidates_when_baseline_or_source_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            dump = work / "dumps/pc/runtime.dump"
            dump.parent.mkdir(parents=True)
            baseline = root / "baseline/pe/x86/32"
            baseline.mkdir(parents=True)
            source = Path(os.environ["NEVERD_SOURCE_DIR"])
            item = {"file": "pc/runtime.sig", "sha256": "0" * 64,
                    "dumper_sha256": "1" * 64, "dump_sha256": "2" * 64,
                    "header": {"Signature": "A runtime", "Flags": "0010",
                               "Features": "32-bytes patterns", "File types": "00000800 PE",
                               "App types": "017F CONSOLE 32BIT"}}

            def write(name, head=HEAD):
                dump.write_text(f"Pattern: {head}\n\t[len=0020]\n\t0000:{name} \n"
                                "\t\tAdditional: length=00 checksum=0000\n"
                                "\t\tRulebytes: \n\t\tRulefuncs: \n")

            def run(label):
                args = argparse.Namespace(neverd_source=source, sig_root=root / "sig",
                                          dumpsig=root / "dumpsig", work=work,
                                          baseline=root / "baseline", baseline_ref="synthetic",
                                          output=root / label)
                with patch.object(importer, "decode", return_value=[item]):
                    return importer.run(args)["imported_records"]

            write("missing_function")
            self.assertEqual(run("first"), 1)
            dump.write_text("not a dump; an unchanged selection does not reparse it")
            self.assertEqual(run("cached"), 1)
            write("missing_function")
            (baseline / "existing.pat").write_text(f"{HEAD} 00 0000 0020 :0000 missing_function\n")
            self.assertEqual(run("new_baseline"), 0)
            write("another_missing_function", bytes(range(32, 64)).hex().upper())
            item["sha256"] = "3" * 64
            self.assertEqual(run("new_source"), 1)

    def test_counterexamples_remove_only_the_proven_byte_claim_and_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = Path("pe/x86/32/supplemental-synthetic.pat")
            first = f"{HEAD} 00 0000 0020 :0000 missing"
            second = f"{bytes(range(32, 64)).hex().upper()} 00 0000 0020 :0000 missing"
            importer.write_patterns(root, relative, [first, second], {"origin": "synthetic"})
            report = {"files": [{"target": "pe/x86/32", "output": str(relative),
                                 "imported_records": 2, "imported_symbols": 1}]}
            (root / "supplemental-audit.json").write_text(json.dumps(report))
            claim = self.builder.parse_line(first).key
            policy = {"schema": 1, "claims": [{"target": "pe/x86/32", "byte_claim": claim,
                                                "sha256": hashlib.sha256(claim.encode()).hexdigest()}]}
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy))
            result = importer.apply_counterexamples(root, policy_path, self.builder)
            self.assertEqual(result["imported_records"], 1)
            self.assertIn(second, (root / relative).read_text())
            self.assertNotIn(first, (root / relative).read_text())
            result = importer.apply_counterexamples(root, policy_path, self.builder)
            self.assertEqual(result["files"][0]["rejected_by_probe_counterexamples"], 1)
            before = (root / relative).read_bytes()
            policy["claims"][0]["byte_claim"] += "00"
            policy_path.write_text(json.dumps(policy))
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                importer.apply_counterexamples(root, policy_path, self.builder)
            self.assertEqual((root / relative).read_bytes(), before)


class PublicationMetadataTests(unittest.TestCase):
    def test_input_details_are_archived_without_changing_patterns_or_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, private = root / "stage", root / "input-records"
            relative = Path("pe/x86/32/supplemental-synthetic.pat")
            importer.write_patterns(output, relative, [f"{HEAD} 00 0000 0020 :0000 missing"], {
                "source": "private-input-file.sig", "origin": "private-source-product",
                "copyright": "Example library owner", "baseline_ref": "synthetic"})
            report_path = output / "legacy-library-audit.json"
            report_path.write_text(json.dumps({"baseline_ref": "synthetic", "imported_records": 1,
                "files": [{"file": "private-input-file.sig", "header": {"Signature": "Example runtime, 3 modules"},
                           "target": "pe/x86/32", "output": relative.as_posix(), "imported_records": 1}]}))
            original = (output / relative).read_bytes()
            published = importer.publication_metadata(output, private, {"note": "private context"})
            self.assertEqual((output / relative).read_bytes(), original)
            self.assertEqual(published["files"][0]["library_family"], "Example runtime")
            metadata_path = output / relative.with_suffix(".sources.json")
            metadata = json.loads(metadata_path.read_text())
            self.assertEqual(metadata["copyright"], "Example library owner")
            self.assertEqual(metadata["artifacts"][0]["sha256"], importer.digest(output / relative))
            self.assertNotIn("private-input-file", report_path.read_text() + metadata_path.read_text())
            self.assertNotIn("private-source-product", metadata_path.read_text())
            self.assertTrue(any("private-input-file" in path.read_text() for path in private.rglob("*.json")))
            before = metadata_path.read_bytes()
            importer.publication_metadata(output, private)
            self.assertEqual(metadata_path.read_bytes(), before)
            with self.assertRaisesRegex(ValueError, "outside"):
                importer.publication_metadata(output, output / "input-records")


class NativeRoundtripTests(unittest.TestCase):
    def test_vendor_roundtrip_and_neverd_positive_and_negative_matching(self):
        flair, neverd = os.environ.get("FLAIR_TOOL_DIR"), os.environ.get("NEVERD_BIN")
        if not flair or not neverd:
            self.skipTest("FLAIR_TOOL_DIR and NEVERD_BIN enable the local tool roundtrip")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            code = bytearray(bytes.fromhex("554889E5") + b"\x90" * 74 + bytes.fromhex("5DC3"))
            lead = code[:28].hex().upper() + ".." * 4
            source = work / "source.pat"
            source.write_text(
                f"{lead} 03 61C2 0050 :0000 synthetic_a ........90\n"
                f"{lead} 03 61C2 0050 :0000 synthetic_b ........91\n---\n")
            for command in ([str(Path(flair) / "sigmake"), str(source), str(work / "out.sig")],
                            [str(Path(flair) / "dumpsig"), "-F", str(work / "out.sig"), str(work / "out.dump")]):
                subprocess.run(command, check=True, capture_output=True, text=True)
            converted = work / "converted.pat"
            converted.write_text("\n".join(importer.pattern_line(item, "x86", 32, 16)
                                           for item in importer.read_dump(work / "out.dump")) + "\n---\n")
            cases = [("original", {}, "synthetic_a"),
                     ("tail_variant", {39: 0x91}, "synthetic_b"),
                     ("wildcard", {28: 0x91}, "synthetic_a"),
                     ("crc_mutation", {32: 0x91}, None),
                     ("prefix_mutation", {1: 0x49}, None)]
            for label, changes, expected in cases:
                with self.subTest(label=label):
                    data = bytearray(code)
                    for offset, value in changes.items():
                        data[offset] = value
                    binary = work / (label + ".bin")
                    binary.write_bytes(data)
                    run = subprocess.run([neverd, "sigs", "--json", "--no-debug", "--loader=binary",
                                          "--processor=x86_64", "--load-base=0x1000",
                                          "--sig-file=" + str(converted), str(binary)],
                                         check=True, capture_output=True, text=True)
                    self.assertEqual({item["name"] for item in json.loads(run.stdout)},
                                     {expected} if expected else set())


if __name__ == "__main__":
    unittest.main()
