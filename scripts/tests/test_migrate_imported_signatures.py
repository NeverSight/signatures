"""Tests for migrate_imported_signatures.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import migrate_imported_signatures as migrate  # noqa: E402


def reference_line(name: str, data: str) -> str:
    """A whole-function reference line as neverd-sigmaker writes it."""

    return f"{data} 00 0000 {len(data) // 2:04X} :0000 {name}"


class SpellingTests(unittest.TestCase):
    def test_rizin_spelling_of_decorated_names(self) -> None:
        cases = {
            "??1CMFCButton@@UEAA@XZ": "__1CMFCButton__UEAA_XZ",
            "?dtor$0@?0???1CWinApp@@UEAA@XZ@4HA": "_dtor_0__0___1CWinApp__UEAA_XZ_4HA",
            "??R<lambda_c24b6d9e>@@QEBAHXZ": "__R_lambda_c24b6d9e___QEBAHXZ",
            "?.cctor@ModuleUninitializer@<CrtImplementationDetails>@@$$FCMXXZ":
                "_.cctor_ModuleUninitializer__CrtImplementationDetails_____FCMXXZ",
            "_memcpy": "_memcpy",
            "___std_stacktrace_address_to_string@12": "___std_stacktrace_address_to_string_12",
        }
        for linkage, imported in cases.items():
            self.assertEqual(migrate.rizin_spelling(linkage), imported)

    def test_long_names_are_cut_at_125(self) -> None:
        self.assertEqual(len(migrate.rizin_spelling("?" + "a" * 300)), 125)

    def test_section_and_label_names_are_not_functions(self) -> None:
        for name in (".text_tii_131", ".lf_1", ".lf", "_LN116"):
            self.assertTrue(migrate.is_artifact(name), name)
        for name in ("_memcpy", "__1CMFCButton__UEAA_XZ", "_LN", "_LNfoo"):
            self.assertFalse(migrate.is_artifact(name), name)


class CRCTests(unittest.TestCase):
    def test_matches_neverd_check_vector(self) -> None:
        self.assertEqual(migrate.crc16(b"123456789"), 0x6E90)
        self.assertEqual(migrate.crc16(b""), 0x0000)


class ResolveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reference = migrate.Reference()
        body = "".join(f"{i:02X}" for i in range(48))
        self.body = body
        self.reference.add_line(reference_line("?Close@CFile@@UEAAXXZ", body))
        # Same length, different bytes after the prologue.
        other = body[:64] + "FF" * 16
        self.reference.add_line(reference_line("?Abort@CFile@@UEAAXXZ", other))
        # A relocation in the CRC span of the imported line below.
        relocated = body[:70] + "........" + body[78:]
        self.reference.add_line(reference_line("?Flush@CFile@@UEAAXXZ", relocated))

    def imported(self, name: str, crc_from: str | None = None, lead: str | None = None) -> migrate.Line:
        data = bytes.fromhex(crc_from or self.body)
        lead = lead or self.body[:64]
        crc = migrate.crc16(data[32:48])
        return migrate.Line.parse(f"{lead} 10 {crc:04X} 0030 :0000 {name}")

    def test_bytes_settle_the_name(self) -> None:
        line = self.imported("_Close_CFile__UEAAXXZ")
        self.assertEqual(
            migrate.resolve(line, self.reference), ("?Close@CFile@@UEAAXXZ", "bytes")
        )

    def test_wildcards_in_the_import_are_not_disagreement(self) -> None:
        line = self.imported("_Close_CFile__UEAAXXZ", lead="...." + self.body[4:64])
        self.assertEqual(migrate.resolve(line, self.reference)[0], "?Close@CFile@@UEAAXXZ")

    def test_spelling_settles_bytes_no_library_has(self) -> None:
        # Bytes nothing in the reference states; the spelling is unique.
        line = migrate.Line.parse("AABBCCDD 00 0000 0004 :0000 _Abort_CFile__UEAAXXZ")
        self.assertEqual(
            migrate.resolve(line, self.reference), ("?Abort@CFile@@UEAAXXZ", "spelling")
        )

    def test_unknown_bytes_and_spelling_stay_unresolved(self) -> None:
        line = migrate.Line.parse("AABBCCDD 00 0000 0004 :0000 _Gone_CFile__UEAAXXZ")
        self.assertEqual(migrate.resolve(line, self.reference), (None, "unresolved"))

    def test_uncheckable_crc_still_settles_when_nothing_else_does(self) -> None:
        reference = migrate.Reference()
        relocated = self.body[:70] + "........" + self.body[78:]
        reference.add_line(reference_line("?Flush@CFile@@UEAAXXZ", relocated))
        line = self.imported("_Flush_CFile__UEAAXXZ")
        self.assertEqual(migrate.resolve(line, reference), ("?Flush@CFile@@UEAAXXZ", "bytes"))


class MigrateFileTests(unittest.TestCase):
    def test_file_keeps_order_renames_and_reports(self) -> None:
        reference = migrate.Reference()
        reference.add_line(reference_line("?Run@@YAXXZ", "4883EC28C3"))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vs2013.pat"
            path.write_text(
                "AABBCCDD 00 0000 0004 :0000 _unknown_thing__YAXXZ\n"
                "4883EC28C3 00 0000 0005 :0000 _Run__YAXXZ\n"
                "90909090 00 0000 0004 :0000 .text_tii_131\n"
                "---\n"
            )
            report = migrate.FileReport()
            lines = migrate.migrate_file(path, reference, report)
        self.assertEqual(
            lines,
            [
                "AABBCCDD 00 0000 0004 :0000 _unknown_thing__YAXXZ",
                "4883EC28C3 00 0000 0005 :0000 ?Run@@YAXXZ",
                "---",
            ],
        )
        self.assertEqual(report.by_bytes, 1)
        self.assertEqual(report.removed_artifacts, 1)
        self.assertEqual(report.unresolved, 1)
        self.assertEqual(report.unresolved_names, ["_unknown_thing__YAXXZ"])


if __name__ == "__main__":
    unittest.main()
