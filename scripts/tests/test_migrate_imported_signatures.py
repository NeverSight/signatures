"""Tests for migrate_imported_signatures.py."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import migrate_imported_signatures as migrate  # noqa: E402


def reference_line(name: str, data: str) -> str:
    """A whole-function reference line as neverd-sigmaker writes it."""

    return f"{data} 00 0000 {len(data) // 2:04X} :0000 {name}"


def pe_reference(*lines: str) -> migrate.Reference:
    reference = migrate.Reference("pe")
    for line in lines:
        reference.add_line(line)
    reference.index_spellings()
    return reference


class PESpellingTests(unittest.TestCase):
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
            self.assertEqual(migrate.pe_spelling(linkage), imported)

    def test_a_cut_name_that_ends_in_underscores_loses_them(self) -> None:
        name = ("?Pop@?$WorkStealingQueue@V_UnrealizedChore@details@Concurrency@@"
                "V_CriticalNonReentrantLock@23@@details@Concurrency@@QEAAPEAV_UnrealizedChore@23@XZ")
        reference = pe_reference(reference_line(name, "4883EC28" * 5 + "C3"))
        imported = migrate.pe_spelling(name).rstrip("_")
        self.assertEqual(len(imported), 124)
        self.assertEqual(reference.spelled(imported), {name})

    def test_long_names_are_cut_at_125(self) -> None:
        self.assertEqual(len(migrate.pe_spelling("?" + "a" * 300)), 125)

    def test_section_and_label_names_are_not_functions(self) -> None:
        for name in (".text_tii_131", ".lf_1", ".lf", "_LN116"):
            self.assertTrue(migrate.is_artifact(name, "pe"), name)
        for name in ("_memcpy", "__1CMFCButton__UEAA_XZ", "_LN", "_LNfoo"):
            self.assertFalse(migrate.is_artifact(name, "pe"), name)


class ELFSpellingTests(unittest.TestCase):
    def test_plain_and_method_forms(self) -> None:
        cases = {
            "std::__cxx11::basic_stringbuf<char, std::char_traits<char>, "
            "std::allocator<char> >::setbuf(char*, long)":
                "std::__cxx11::basic_stringbuf_char__std::char_traits_char___"
                "std::allocator_char___::setbuf_char___long",
            "std::filesystem::temp_directory_path[abi:cxx11](std::error_code&)":
                "std::filesystem::temp_directory_path_abi:cxx11__std::error_code",
            "(anonymous namespace)::_M_destroy_thread_key(void*)":
                "_anonymous_namespace_::_M_destroy_thread_key_void",
        }
        for demangled, imported in cases.items():
            self.assertIn(imported, migrate.elf_spellings(demangled))

    def test_method_form_splits_before_the_first_parenthesis(self) -> None:
        forms = migrate.elf_spellings("std::basic_ios<char, std::char_traits<char> >::fill() const")
        self.assertIn("method.std::basic_ios_char__std::char_traits_char___.fill___const", forms)
        forms = migrate.elf_spellings(
            "std::filesystem::__cxx11::path::_M_split_cmpts() [clone .cold]")
        self.assertIn("method.std::filesystem::__cxx11::path._M_split_cmpts____clone_.cold", forms)
        # The first '(' can be the one in "(anonymous namespace)".
        forms = migrate.elf_spellings(
            "char const* std::(anonymous namespace)::ucs4_span<char>(char const*)")
        self.assertIn(
            "method.char_const__std._anonymous_namespace_::ucs4_span_char__char_const", forms)

    def test_data_objects_are_not_functions(self) -> None:
        for name in ("obj.once.9977", "obj.atexit_mutex", ".text.unlikely"):
            self.assertTrue(migrate.is_artifact(name, "elf"), name)
        for name in ("psiginfo", "method.std::thread.join", "std::thread::join"):
            self.assertFalse(migrate.is_artifact(name, "elf"), name)


class VerbatimTests(unittest.TestCase):
    def test_only_names_the_import_cannot_have_changed(self) -> None:
        self.assertTrue(migrate.is_verbatim("psiginfo", "elf"))
        self.assertTrue(migrate.is_verbatim("__libc_start_main", "elf"))
        self.assertFalse(migrate.is_verbatim("std::thread::join", "elf"))
        self.assertFalse(migrate.is_verbatim("method.std::thread.join", "elf"))
        self.assertTrue(migrate.is_verbatim("memcpy", "pe"))
        # A decorated PE name's leading '?' became '_', so these could be either.
        self.assertFalse(migrate.is_verbatim("_memcpy", "pe"))
        self.assertFalse(migrate.is_verbatim("_Close_CFile__UEAAXXZ", "pe"))


class SectionSymbolTests(unittest.TestCase):
    def test_function_sections_name_their_function(self) -> None:
        self.assertEqual(migrate.section_symbol(".text._ZNSt6__ndk19strstreamD1Ev", "elf"),
                         "_ZNSt6__ndk19strstreamD1Ev")
        self.assertEqual(migrate.section_symbol(".text.unlikely.crc32_combine", "elf"),
                         "crc32_combine")
        self.assertIsNone(migrate.section_symbol(".LTHUNK3", "elf"))
        self.assertIsNone(migrate.section_symbol(".text_tii_131", "pe"))

    def test_a_section_name_is_renamed_not_removed(self) -> None:
        reference = migrate.Reference("elf")
        reference.index_spellings()
        line = migrate.Line.parse("AABBCCDD 00 0000 0004 :0000 .text.crc32_combine")
        self.assertEqual(migrate.resolve(line, reference), ("crc32_combine", "section"))


class CRCTests(unittest.TestCase):
    def test_matches_neverd_check_vector(self) -> None:
        self.assertEqual(migrate.crc16(b"123456789"), 0x6E90)
        self.assertEqual(migrate.crc16(b""), 0x0000)


class ResolveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.body = "".join(f"{i:02X}" for i in range(48))
        other = self.body[:64] + "FF" * 16
        relocated = self.body[:70] + "........" + self.body[78:]
        self.reference = pe_reference(
            reference_line("?Close@CFile@@UEAAXXZ", self.body),
            reference_line("?Abort@CFile@@UEAAXXZ", other),
            reference_line("?Flush@CFile@@UEAAXXZ", relocated),
        )

    def imported(self, name: str, lead: str | None = None) -> migrate.Line:
        data = bytes.fromhex(self.body)
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
        line = migrate.Line.parse("AABBCCDD 00 0000 0004 :0000 _Abort_CFile__UEAAXXZ")
        self.assertEqual(
            migrate.resolve(line, self.reference), ("?Abort@CFile@@UEAAXXZ", "spelling")
        )

    def test_unknown_bytes_and_spelling_stay_unresolved(self) -> None:
        line = migrate.Line.parse("AABBCCDD 00 0000 0004 :0000 _Gone_CFile__UEAAXXZ")
        self.assertEqual(migrate.resolve(line, self.reference), (None, "unresolved"))

    def test_bytes_rename_an_artifact_before_it_is_removed(self) -> None:
        named = self.imported(".text_tii_131")
        self.assertEqual(migrate.resolve(named, self.reference)[0], "?Close@CFile@@UEAAXXZ")
        unnamed = migrate.Line.parse("AABBCCDD 00 0000 0004 :0000 .text_tii_131")
        self.assertEqual(migrate.resolve(unnamed, self.reference), (None, "artifact"))

    def test_bytes_several_routines_share_remove_the_line(self) -> None:
        # MSVC compiles many constructors to the same bytes; the imported
        # spelling must not pick one of them.
        reference = pe_reference(
            reference_line("??0CSpinButtonCtrl@@QEAA@XZ", self.body),
            reference_line("??0CMFCBaseToolBar@@QEAA@XZ", self.body),
        )
        line = self.imported("__0CSpinButtonCtrl__QEAA_XZ")
        self.assertEqual(migrate.resolve(line, reference), (None, "ambiguous"))

    def test_a_routine_shorter_than_the_lead_is_compared_by_its_bytes(self) -> None:
        # rizin pads the leading pattern of a 26-byte routine to 32 bytes.
        code = "4883EC28488B4940FF1500000000488BC84883C428E900000000"
        relocated = code[:20] + "........" + code[28:44] + "........"
        reference = pe_reference(reference_line("?GetParent@CWnd@@QEBAPEAV1@XZ", relocated))
        padded = relocated + ".." * 6
        line = migrate.Line.parse(f"{padded} 00 0000 001A :0000 _GetParent_CWnd__QEBAPEAV1_XZ")
        self.assertEqual(
            migrate.resolve(line, reference), ("?GetParent@CWnd@@QEBAPEAV1@XZ", "bytes")
        )
        # Its modern twin differs only in what the call reaches.
        twin = pe_reference(
            reference_line("?GetParent@CWnd@@QEBAPEAV1@XZ", relocated),
            reference_line("?GetMenu@CWnd@@UEBAPEAVCMenu@@XZ", relocated),
        )
        self.assertEqual(migrate.resolve(line, twin), (None, "ambiguous"))

    def test_bytes_of_a_routine_the_import_does_not_name_remove_the_line(self) -> None:
        # OpenSSL's SSL_peek_ex compiles to the same bytes as libstdc++'s
        # std::thread::hardware_concurrency; only the call target differs.
        code = "4883EC08E8........BA0000000085C00F48C24883C408C3"
        reference = migrate.Reference("elf")
        reference.add_line(reference_line("_ZNSt6thread20hardware_concurrencyEv", code))
        line = migrate.Line.parse(f"{code}{'..' * 8} 00 0000 0018 :0000 SSL_peek_ex")
        self.assertEqual(migrate.settle(line, reference), (None, "ambiguous"))

    def test_bytes_that_open_a_longer_routine_remove_the_line(self) -> None:
        # The imported routine is the first 48 bytes of a longer one that
        # the libraries name differently.
        reference = pe_reference(
            reference_line("?Close@CFile@@UEAAXXZ", self.body),
            reference_line("?Close@CStdioFile@@UEAAXXZ", self.body + "C3CCCCCC"),
        )
        line = self.imported("_Close_CFile__UEAAXXZ")
        self.assertEqual(migrate.resolve(line, reference), (None, "opening"))

    def test_a_longer_build_of_the_same_routine_keeps_the_line(self) -> None:
        reference = pe_reference(
            reference_line("?Close@CFile@@UEAAXXZ", self.body),
            reference_line("?Close@CFile@@UEAAXXZ", self.body + "C3CCCCCC"),
        )
        line = self.imported("_Close_CFile__UEAAXXZ")
        self.assertEqual(migrate.resolve(line, reference), ("?Close@CFile@@UEAAXXZ", "bytes"))

    def test_uncheckable_crc_still_settles_when_nothing_else_does(self) -> None:
        relocated = self.body[:70] + "........" + self.body[78:]
        reference = pe_reference(reference_line("?Flush@CFile@@UEAAXXZ", relocated))
        line = self.imported("_Flush_CFile__UEAAXXZ")
        self.assertEqual(migrate.resolve(line, reference), ("?Flush@CFile@@UEAAXXZ", "bytes"))


@unittest.skipUnless(shutil.which("c++filt"), "needs c++filt")
class ELFReferenceTests(unittest.TestCase):
    def test_spelling_index_maps_imports_back_to_mangled_names(self) -> None:
        reference = migrate.Reference("elf")
        reference.add_line(reference_line("_ZNSt6thread4joinEv", "4883EC08C3"))
        reference.add_line(reference_line("psiginfo", "C3C3C3C3"))
        reference.index_spellings()
        self.assertEqual(reference.spelled("std::thread::join"), {"_ZNSt6thread4joinEv"})
        self.assertEqual(reference.spelled("method.std::thread.join"), {"_ZNSt6thread4joinEv"})
        self.assertEqual(reference.spelled("psiginfo"), {"psiginfo"})


class TailAlignmentTests(unittest.TestCase):
    LEAD = "".join(f"{i:02X}" for i in range(32))

    def line(self, crc_len: int, total: int, tail: str) -> migrate.Line:
        return migrate.Line.parse(
            f"{self.LEAD} {crc_len:02X} 0000 {total:04X} :0000 f {tail}")

    def test_tail_with_fixed_bytes_inside_the_crc_width_starts_after_the_crc(self) -> None:
        self.assertEqual(self.line(4, 48, "..AABBCC").tail_style(), "after-crc")

    def test_tail_longer_than_the_room_after_the_crc_starts_after_the_lead(self) -> None:
        # 44 bytes: 32 leading, 4 in the CRC span, 8 after it; the tail is 12.
        line = self.line(4, 44, "........1122334455667788")
        self.assertEqual(line.tail_style(), "after-lead")
        self.assertEqual(line.realigned().tail, "1122334455667788")

    def test_realigned_tail_is_clipped_to_the_function(self) -> None:
        line = self.line(2, 38, "....11223344556677")
        self.assertEqual(line.realigned().tail, "11223344")

    def test_undecided_tails_follow_a_file_that_is_settled_one_way(self) -> None:
        settled = [self.line(4, 44, "........1122334455667788")] * 19 + [
            self.line(4, 48, "..AABBCC")]
        self.assertEqual(migrate.file_tail_style(settled), "after-lead")
        mixed = settled + [self.line(4, 48, "..AABBCC")] * 5
        self.assertIsNone(migrate.file_tail_style(mixed))

    def test_reference_bytes_decide_an_undecided_tail(self) -> None:
        body = bytes(range(48))
        reference = pe_reference(reference_line("?f@@YAXXZ", body.hex().upper()))
        crc = migrate.crc16(body[32:36])
        # Stated from the end of the lead: four CRC wildcards, then bytes 36..
        tail = "........" + body[36:40].hex().upper()
        line = migrate.Line.parse(
            f"{body[:32].hex().upper()} 04 {crc:04X} 0030 :0000 _f__YAXXZ {tail}")
        self.assertEqual(line.tail_style(), "either")
        aligned, how = migrate.align(line, reference, None)
        self.assertEqual(how, "realigned")
        self.assertEqual(aligned.tail, body[36:40].hex().upper())
        self.assertEqual(migrate.resolve(aligned, reference), ("?f@@YAXXZ", "bytes"))


class MoveTests(unittest.TestCase):
    THUMB = "10B50446BDE81040" * 3
    OTHER = "70B5054670BD" * 3

    def test_only_bytes_of_the_other_width_move_a_line(self) -> None:
        own = pe_reference(reference_line("?Run@@YAXXZ", "4883EC28" * 5 + "C3"))
        other = pe_reference(
            reference_line("?Thumb@@YAXXZ", self.THUMB),
            reference_line("?Spelled@@YAXXZ", self.OTHER),
        )
        unknown = "AABBCCDDEEFF" * 3
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "android-ndk.pat"
            path.write_text(
                f"{self.THUMB} 00 0000 0018 :0000 _Thumb__YAXXZ\n"
                f"{unknown} 00 0000 0012 :0000 _Spelled__YAXXZ\n"
            )
            report = migrate.FileReport()
            moved: list[str] = []
            lines = migrate.migrate_file(path, own, report, other, moved)
        self.assertEqual(moved, [f"{self.THUMB} 00 0000 0018 :0000 ?Thumb@@YAXXZ"])
        self.assertEqual(lines, [f"; unresolved: {unknown} 00 0000 0012 :0000 _Spelled__YAXXZ"])
        self.assertEqual(report.moved, 1)
        self.assertEqual(report.unresolved, 1)

    def test_code_several_routines_of_the_other_width_share_is_removed(self) -> None:
        # zlib's crc32_combine and crc32_combine64 compile to the same 32-bit
        # code; a copy of it filed under 64 bits names neither.
        own = pe_reference(reference_line("?Run@@YAXXZ", "4883EC28" * 5 + "C3"))
        other = pe_reference(
            reference_line("crc32_combine", self.THUMB),
            reference_line("crc32_combine64", self.THUMB),
        )
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "android-ndk.pat"
            path.write_text(f"{self.THUMB} 00 0000 0018 :0000 _Spelled__YAXXZ\n")
            report = migrate.FileReport()
            moved: list[str] = []
            lines = migrate.migrate_file(path, own, report, other, moved)
        self.assertEqual((lines, moved), ([], []))
        self.assertEqual(report.removed_ambiguous, 1)


class WeakLineTests(unittest.TestCase):
    def test_stated_bytes_follow_the_matcher(self) -> None:
        lead = "".join(f"{i:02X}" for i in range(32))
        line = migrate.Line.parse(f"{lead} 04 0000 0030 :0000 f ....AABB")
        # 32 leading + 4 in the CRC span + 2 fixed tail bytes.
        self.assertEqual(line.stated_bytes(), 38)
        short = migrate.Line.parse("55......C3 00 0000 0005 :0000 g")
        self.assertEqual(short.stated_bytes(), 2)
        # Bytes past the function's end state nothing.
        past = migrate.Line.parse("AABBCCDD 00 0000 0002 :0000 h")
        self.assertEqual(past.stated_bytes(), 2)

    def test_weak_lines_are_removed_and_listed(self) -> None:
        reference = pe_reference(reference_line("?Run@@YAXXZ", "4883EC28" * 5 + "C3"))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vs2008.pat"
            path.write_text(
                "55......C3 00 0000 0005 :0000 _tiny\n"
                + "4883EC28" * 5 + "C3 00 0000 0015 :0000 _Run__YAXXZ\n"
            )
            report = migrate.FileReport()
            lines = migrate.migrate_file(path, reference, report)
        self.assertEqual(lines, ["4883EC28" * 5 + "C3 00 0000 0015 :0000 ?Run@@YAXXZ"])
        self.assertEqual(report.removed_weak, 1)
        self.assertEqual(report.weak_names, ["_tiny"])


class MigrateFileTests(unittest.TestCase):
    def test_file_keeps_order_renames_and_reports(self) -> None:
        run = "4883EC28" * 5 + "C3"
        shared = "4883EC38" * 5 + "C3"
        reference = pe_reference(
            reference_line("?Run@@YAXXZ", run),
            reference_line("??1CListCtrl@@UEAA@XZ", shared),
            reference_line("??1CTreeCtrl@@UEAA@XZ", shared),
        )
        unknown = "AABBCCDD" * 5
        section = "90909090" * 5
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vs2013.pat"
            path.write_text(
                f"{unknown} 00 0000 0014 :0000 _unknown_thing__YAXXZ\n"
                f"{run} 00 0000 0015 :0000 _Run__YAXXZ\n"
                f"{section} 00 0000 0014 :0000 .text_tii_131\n"
                f"{shared} 00 0000 0015 :0000 __1CListCtrl__UEAA_XZ\n"
                "---\n"
            )
            report = migrate.FileReport()
            lines = migrate.migrate_file(path, reference, report)
        self.assertEqual(
            lines,
            [
                f"; unresolved: {unknown} 00 0000 0014 :0000 _unknown_thing__YAXXZ",
                f"{run} 00 0000 0015 :0000 ?Run@@YAXXZ",
                "---",
            ],
        )
        self.assertEqual(report.by_bytes, 1)
        self.assertEqual(report.removed_artifacts, 1)
        self.assertEqual(report.removed_ambiguous, 1)
        self.assertEqual(report.ambiguous_names, ["__1CListCtrl__UEAA_XZ"])
        self.assertEqual(report.unresolved, 1)
        self.assertEqual(report.unresolved_names, ["_unknown_thing__YAXXZ"])


class CNameTests(unittest.TestCase):
    @staticmethod
    def line(name: str, data: str) -> migrate.Line:
        return migrate.Line.parse(reference_line(name, data))

    def test_names_no_cxx_decoration_can_spell_are_kept(self) -> None:
        x86 = pe_reference()
        x86.callee_cleanup = True
        body = "558BEC" + "90" * 16 + "5DC3"
        self.assertEqual(migrate.c_linkage_name(self.line("_gzclose", body), x86), "_gzclose")
        self.assertEqual(migrate.c_linkage_name(self.line("_adler32_z", body), x86), "_adler32_z")
        self.assertEqual(migrate.c_linkage_name(self.line("___crtFlsAlloc", body), x86),
                         "___crtFlsAlloc")
        # "@@" became "__": this may be ?Close@CFile@@UAEXXZ.
        self.assertIsNone(migrate.c_linkage_name(self.line("_Close_CFile__UAEXXZ", body), x86))

    def test_stdcall_spelling_needs_the_routines_ret(self) -> None:
        x86 = pe_reference()
        x86.callee_cleanup = True
        stdcall = "558BEC" + "90" * 16 + "5DC21800"
        cdecl = "558BEC" + "90" * 16 + "5DC3"
        self.assertEqual(migrate.c_linkage_name(self.line("_TimeSpan_24", stdcall), x86),
                         "_TimeSpan@24")
        self.assertIsNone(migrate.c_linkage_name(self.line("_TimeSpan_24", cdecl), x86))
        # No stdcall routine pops six bytes.
        self.assertEqual(migrate.c_linkage_name(self.line("_crc32_6", cdecl), x86), "_crc32_6")

    def test_other_architectures_do_not_decorate_c_names(self) -> None:
        x64 = pe_reference()
        body = "4883EC28" + "90" * 16 + "4883C428C3"
        self.assertEqual(migrate.c_linkage_name(self.line("_tr_init", body), x64), "_tr_init")
        self.assertEqual(migrate.c_linkage_name(self.line("_foo_24", body), x64), "_foo_24")


class CollectedReleaseTests(unittest.TestCase):
    def test_lines_the_collected_libraries_reproduce_are_left_out(self) -> None:
        run = "4883EC28" * 5 + "C3"
        reference = pe_reference(reference_line("?Run@@YAXXZ", run))
        other = "AABBCCDD" * 5
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vs2013.pat"
            path.write_text(
                f"{run} 00 0000 0015 :0000 _Run__YAXXZ\n"
                f"{other} 00 0000 0014 :0000 ?Only@CInImportedLibs@@QAEXXZ\n"
            )
            report = migrate.FileReport()
            lines = migrate.migrate_file(path, reference, report, defined=set())
        self.assertEqual(lines, [f"{other} 00 0000 0014 :0000 ?Only@CInImportedLibs@@QAEXXZ"])
        self.assertEqual(report.reproduced, 1)

    def test_lines_for_routines_the_collected_libraries_define_are_superseded(self) -> None:
        # The collected libraries define ?Skip@@YAXXZ, but neverd-sigmaker
        # wrote no line for it: its rules reject that code, and the imported
        # line does not bring it back.
        reference = pe_reference(reference_line("?Run@@YAXXZ", "4883EC28" * 5 + "C3"))
        reference.names.add("?Skip@@YAXXZ")
        reference.index_spellings()
        skipped = "90CC" * 10
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vs2013.pat"
            path.write_text(f"{skipped} 00 0000 0014 :0000 _Skip__YAXXZ\n")
            report = migrate.FileReport()
            lines = migrate.migrate_file(path, reference, report, defined={"?Skip@@YAXXZ"})
        self.assertEqual(lines, [])
        self.assertEqual(report.superseded, 1)

    def test_unresolved_lines_of_a_collected_release_are_kept_as_comments(self) -> None:
        reference = pe_reference(reference_line("?Run@@YAXXZ", "4883EC28" * 5 + "C3"))
        unknown = "AABBCCDD" * 5
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "vs2013.pat"
            path.write_text(f"{unknown} 00 0000 0014 :0000 _unknown_thing__YAXXZ\n")
            report = migrate.FileReport()
            lines = migrate.migrate_file(path, reference, report, defined=set())
        self.assertEqual(lines, [f"; unresolved: {unknown} 00 0000 0014 :0000 _unknown_thing__YAXXZ"])
        self.assertEqual(report.unresolved, 1)

    def test_releases_come_from_toolset_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            assets = Path(scratch)
            (assets / "vs2013-12.0.21005-x86.json").write_text(
                '{"kind": "toolset", "visual_studio": {"year": 2013}}')
            (assets / "winsdk-10.0.26100.0-x86.json").write_text('{"kind": "winsdk"}')
            self.assertEqual(migrate.collected_releases(assets, "x86"), {2013})
        self.assertEqual(migrate.release_of(Path("pe/x86/32/vs2013.pat")), 2013)
        self.assertIsNone(migrate.release_of(Path("pe/x86/32/masm32.pat")))


class ImportedFilesTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_files_rebuilt_from_libraries_are_not_imported_any_more(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch)
            directory = tree / "pe/x86/64"
            directory.mkdir(parents=True)
            for name in ("vs2013.pat", "vs2022.pat"):
                (directory / name).write_text("AABBCCDD 00 0000 0004 :0000 f\n")
            git = ["git", "-C", str(tree), "-c", "user.name=t", "-c", "user.email=t@t"]
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "import"], check=True)
            (directory / "vs2022.sources.json").write_text("{}\n")
            files = migrate.imported_files(tree, "HEAD", "pe/x86/64")
        self.assertEqual([path.name for path in files], ["vs2013.pat"])

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_a_run_starts_from_the_imported_text(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch)
            path = tree / "pe/x86/64/vs2013.pat"
            path.parent.mkdir(parents=True)
            imported = "4883EC28" * 5 + "C3 00 0000 0015 :0000 _Run__YAXXZ\n"
            path.write_text(imported)
            git = ["git", "-C", str(tree), "-c", "user.name=t", "-c", "user.email=t@t"]
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "import"], check=True)
            path.write_text("an earlier run's output\n")
            migrate.restore(tree, "HEAD", path)
            self.assertEqual(path.read_text(), imported)


if __name__ == "__main__":
    unittest.main()
