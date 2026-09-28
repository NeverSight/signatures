"""Tests for collect_mingw_library.py; the build itself needs MinGW-w64."""

from __future__ import annotations

import io
import os
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect_mingw_library as mingw  # noqa: E402
import msvc_matrix  # noqa: E402

# Records its arguments; "gcc" writes the object it is asked for.
FAKE_TOOL = textwrap.dedent(
    """\
    #!{python}
    import sys
    from pathlib import Path

    args = sys.argv[1:]
    with open({log!r}, "a") as log:
        log.write(Path(sys.argv[0]).name + " " + " ".join(args) + "\\n")
    if "-o" in args:
        Path(args[args.index("-o") + 1]).write_bytes(b"object")
    """
)


def source_archive(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as bundle:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))


class UnpackTests(unittest.TestCase):
    def test_the_archive_unpacks_into_its_one_directory(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "zlib-1.3.tar.gz"
            source_archive(archive, {"zlib-1.3/adler32.c": b"int a;"})
            root = mingw.unpack(archive, Path(scratch) / "work")
            self.assertEqual(root.name, "zlib-1.3")
            self.assertTrue((root / "adler32.c").is_file())

    def test_an_archive_of_several_directories_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "mixed.tar.gz"
            source_archive(archive, {"a/x.c": b"", "b/y.c": b""})
            with self.assertRaises(mingw.BuildError):
                mingw.unpack(archive, Path(scratch) / "work")


@unittest.skipUnless(os.name == "posix", "needs POSIX")
class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.log = self.root / "commands.log"
        for tool in ("fake-gcc", "fake-ar"):
            path = self.root / tool
            path.write_text(FAKE_TOOL.format(python=sys.executable, log=str(self.log)))
            path.chmod(0o755)
        self.tree = self.root / "zlib-1.3"
        self.tree.mkdir()
        for name in ("adler32.c", "crc32.c"):
            (self.tree / name).write_text("int x;\n")
        self.row = {"sources": ["adler32.c", "crc32.c"], "cflags": ["-O0"],
                    "archive": "libz.a"}

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_every_source_is_compiled_by_its_name_and_archived_in_order(self) -> None:
        library = mingw.build(self.tree, self.row, str(self.root / "fake"), self.root / "x86")
        self.assertEqual(library, self.root / "x86" / "libz.a")
        out = self.root / "x86"
        self.assertEqual(self.log.read_text().splitlines(), [
            f"fake-gcc -O0 -c adler32.c -o {out / 'adler32.o'}",
            f"fake-gcc -O0 -c crc32.c -o {out / 'crc32.o'}",
            f"fake-ar rcsD {library} {out / 'adler32.o'} {out / 'crc32.o'}",
        ])

    def test_a_source_the_archive_lacks_is_an_error(self) -> None:
        row = dict(self.row, sources=["adler32.c", "gzlib.c"])
        with self.assertRaises(mingw.BuildError):
            mingw.build(self.tree, row, str(self.root / "fake"), self.root / "x86")


class MatrixTests(unittest.TestCase):
    def test_rows_name_known_architectures_and_a_library_file(self) -> None:
        rows = msvc_matrix.load(mingw.DEFAULT_MATRIX, msvc_matrix.MINGW_FIELDS)
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(set(row["arches"]) <= set(mingw.TARGETS), row["name"])
            self.assertRegex(row["library"], r"^[a-z0-9][a-z0-9._+-]*$")
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(row["source"].startswith("https://"), row["name"])


if __name__ == "__main__":
    unittest.main()
