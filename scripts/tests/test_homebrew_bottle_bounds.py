"""Offline Homebrew guards: synthetic archives and mocked HTTP only."""
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_homebrew_bottles as c


class BottleGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.package = self.root / 'bottle.tar.gz'
        self.destination = self.root / 'out'

    def bottle(self, entries):
        with tarfile.open(self.package, 'w:gz') as archive:
            for name, data, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = 'libz.a'
                archive.addfile(member, io.BytesIO(data))

    def unpack(self, archives=None):
        return c.unpack(self.package, 'zlib', '1.4', archives or ['lib/libz.a'],
                        self.destination)

    def normal(self, extras=()):
        self.bottle([('zlib/1.4/lib/libz.a', b'fixture', tarfile.REGTYPE), *extras])

    def test_selected_bytes_and_ignored_symlink_preserved(self):
        self.normal([('zlib/1.4/lib/link', b'', tarfile.SYMTYPE)])
        self.assertEqual(self.unpack()['lib/libz.a'].read_bytes(), b'fixture')
        self.assertFalse((self.destination / 'lib/link').exists())

    def test_duplicate_selected_and_unselected_and_aliases(self):
        for name in ['zlib/1.4/lib/libz.a', './zlib/1.4/lib/libz.a', 'ignored']:
            with self.subTest(name=name):
                extras = [(name, b'bad', tarfile.REGTYPE)]
                if name == 'ignored':
                    extras *= 2
                self.normal(extras)
                with self.assertRaisesRegex(c.CollectionError, 'duplicate'):
                    self.unpack()
                self.assertFalse(self.destination.exists())

    def test_unsafe_unselected_paths(self):
        for name in ['../bad', '/bad', 'a/../../bad', 'a\\bad', 'C:/bad', '.', './', '././']:
            with self.subTest(name=name):
                self.normal([(name, b'x', tarfile.REGTYPE)])
                with self.assertRaisesRegex(c.CollectionError, 'unsafe'):
                    self.unpack()
                self.assertFalse(self.destination.exists())

    def test_member_count_includes_ignored(self):
        self.normal([('ignored', b'', tarfile.REGTYPE)])
        with patch.object(c, 'MAX_MEMBERS', 1):
            with self.assertRaisesRegex(c.CollectionError, 'count'):
                self.unpack()
        self.assertFalse(self.destination.exists())

    def test_member_size_includes_ignored(self):
        self.normal([('ignored', b'x' * 20, tarfile.REGTYPE)])
        with patch.object(c, 'MAX_MEMBER_BYTES', 10):
            with self.assertRaisesRegex(c.CollectionError, 'size'):
                self.unpack()
        self.assertFalse(self.destination.exists())

    def test_full_decompression_bound_before_tar_parser(self):
        self.package.write_bytes(gzip.compress(b'\0' * 10000))
        with patch.object(c, 'MAX_TAR_BYTES', 100), patch.object(c.tarfile, 'open') as op:
            with self.assertRaisesRegex(c.CollectionError, 'byte limit'):
                self.unpack()
            op.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_extension_headers_count_toward_decompression_bound(self):
        with tarfile.open(self.package, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo('zlib/1.4/lib/libz.a')
            member.pax_headers = {'comment': 'x' * 20000}
            archive.addfile(member, io.BytesIO())
        with patch.object(c, 'MAX_TAR_BYTES', 10000):
            with self.assertRaises(c.CollectionError):
                self.unpack()

    def test_extension_chain_rejected_before_recursive_parser(self):
        header = tarfile.TarInfo('pax')
        header.type = tarfile.XHDTYPE
        raw = header.tobuf() * 1100 + b'\0' * 1024
        self.package.write_bytes(gzip.compress(raw))
        with patch.object(c.tarfile, 'open') as op:
            with self.assertRaisesRegex(c.CollectionError, 'extension'):
                self.unpack()
            op.assert_not_called()

    def test_large_extension_rejected_before_parser(self):
        header = tarfile.TarInfo('pax')
        header.type = tarfile.XHDTYPE
        header.size = 512
        self.package.write_bytes(gzip.compress(header.tobuf() + b'x' * 512 + b'\0' * 1024))
        with patch.object(c, 'MAX_EXTENSION_BYTES', 128):
            with self.assertRaisesRegex(c.CollectionError, 'extension'):
                self.unpack()

    def test_pax_size_override_rejected_before_parser(self):
        with tarfile.open(self.package, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo('zlib/1.4/lib/libz.a')
            member.pax_headers = {'size': '0'}
            archive.addfile(member, io.BytesIO())
        with patch.object(c.tarfile, 'open') as op:
            with self.assertRaisesRegex(c.CollectionError, 'overrides'):
                self.unpack()
            op.assert_not_called()

    def test_nondata_size_cannot_hide_extension_chain(self):
        for kind in [tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE]:
            with self.subTest(kind=kind):
                carrier = tarfile.TarInfo('carrier')
                carrier.type = kind
                carrier.size = 1100 * 512
                header = tarfile.TarInfo('pax')
                header.type = tarfile.XHDTYPE
                self.package.write_bytes(gzip.compress(
                    carrier.tobuf() + header.tobuf() * 1100 + b'\0' * 1024))
                with patch.object(c.tarfile, 'open') as op:
                    with self.assertRaisesRegex(c.CollectionError, 'non-data'):
                        self.unpack()
                    op.assert_not_called()

    def test_global_pax_size_override_rejected(self):
        with tarfile.open(self.package, 'w:gz', format=tarfile.PAX_FORMAT,
                          pax_headers={'size': '0'}) as archive:
            archive.addfile(tarfile.TarInfo('zlib/1.4/lib/libz.a'), io.BytesIO())
        with self.assertRaisesRegex(c.CollectionError, 'overrides'):
            self.unpack()

    def test_special_and_selected_links_rejected(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE]:
            with self.subTest(kind=kind):
                self.bottle([('zlib/1.4/lib/libz.a', b'', kind)])
                with self.assertRaises(c.CollectionError):
                    self.unpack()
                self.assertFalse(self.destination.exists())

    def test_missing_selected_rejects_before_output(self):
        self.normal()
        with self.assertRaisesRegex(c.CollectionError, 'has no'):
            self.unpack(['lib/libz.a', 'missing.a'])
        self.assertFalse(self.destination.exists())

    def test_truncated_gzip_rejected_before_output(self):
        self.normal()
        self.package.write_bytes(self.package.read_bytes()[:-4])
        with self.assertRaises(c.CollectionError):
            self.unpack()
        self.assertFalse(self.destination.exists())

    def test_preexisting_output_not_overwritten(self):
        self.normal()
        target = self.destination / 'lib/libz.a'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'keep')
        with self.assertRaises(c.CollectionError):
            self.unpack()
        self.assertEqual(target.read_bytes(), b'keep')

    def test_output_parent_symlink_escape(self):
        self.normal()
        self.destination.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (self.destination / 'lib').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(c.CollectionError):
            self.unpack()
        self.assertEqual(list(outside.iterdir()), [])

    def test_requested_traversal_rejected(self):
        self.normal()
        with self.assertRaises(c.CollectionError):
            self.unpack(['../escape'])

    def response(self, data, length=None):
        response = io.BytesIO(data)
        response.headers = {} if length is None else {'Content-Length': length}
        return response

    def test_download_bounds_with_absent_false_and_large_lengths(self):
        for length in [None, '1', '11', '-1', 'bad']:
            with self.subTest(length=length):
                target = self.root / 'partial'
                target.unlink(missing_ok=True)
                with patch.object(c, 'MAX_DOWNLOAD_BYTES', 10), patch.object(
                        c.urllib.request, 'urlopen', return_value=self.response(b'x' * 11, length)):
                    with self.assertRaises(c.CollectionError):
                        c.fetch_bottle('https://example.invalid/bottle', target)
                self.assertLessEqual(target.stat().st_size if target.exists() else 0, 10)

    def test_download_exact_limit_and_early_eof(self):
        target = self.root / 'partial'
        with patch.object(c, 'MAX_DOWNLOAD_BYTES', 10), patch.object(
                c.urllib.request, 'urlopen', return_value=self.response(b'x' * 10, '10')):
            c.fetch_bottle('https://example.invalid/bottle', target)
        self.assertEqual(target.read_bytes(), b'x' * 10)
        with patch.object(c.urllib.request, 'urlopen', return_value=self.response(b'x', '10')):
            with self.assertRaises(OSError):
                c.fetch_bottle('https://example.invalid/bottle', target)

    def test_cache_size_rejected_before_hash_or_network(self):
        digest = 'a' * 64
        cached = self.root / f'zlib--tag--{digest}.tar.gz'
        cached.write_bytes(b'x' * 11)
        with patch.object(c, 'MAX_DOWNLOAD_BYTES', 10), patch.object(c, 'sha256') as sha, \
                patch.object(c, 'blob_location') as location:
            with self.assertRaises(c.CollectionError):
                c.obtain('zlib', {'tag': 'tag', 'sha256': digest}, self.root)
            sha.assert_not_called()
            location.assert_not_called()

    def test_cache_rehashed_and_download_promotion(self):
        data = b'bottle'
        digest = hashlib.sha256(data).hexdigest()
        bottle = {'tag': 'tag', 'sha256': digest}
        with patch.object(c, 'blob_location', return_value='https://example.invalid/bottle'), \
                patch.object(c.urllib.request, 'urlopen', return_value=self.response(data)):
            result = c.obtain('zlib', bottle, self.root)
        self.assertEqual(result.read_bytes(), data)
        with patch.object(c, 'sha256', wraps=c.sha256) as sha, patch.object(c, 'blob_location') as loc:
            self.assertEqual(c.obtain('zlib', bottle, self.root), result)
            sha.assert_called_once_with(result)
            loc.assert_not_called()

    def test_access_denials_not_retried(self):
        for code in [401, 403, 404]:
            with self.subTest(code=code), patch.object(c, 'blob_location', side_effect=
                    c.urllib.error.HTTPError('https://example.invalid', code, 'denied', {}, None)) as loc:
                with self.assertRaises(c.CollectionError):
                    c.obtain('zlib', {'tag': 'tag', 'sha256': 'a' * 64}, self.root)
                loc.assert_called_once()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_ar_negative_size_and_invalid_bsd_name_length(self):
        for name, size, payload in [(b'x.o', -60, b''), (b'#1/-1', 8, b'x' * 8),
                                     (b'#1/9', 8, b'x' * 8), (b'#1/bad', 8, b'x' * 8)]:
            with self.subTest(name=name, size=size):
                header = name.ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) * 2 + b'644'.ljust(8)
                header += str(size).encode().ljust(10) + b'`\n'
                path = self.root / 'bad.a'
                path.write_bytes(c.AR_MAGIC + header + payload)
                with self.assertRaises(c.CollectionError):
                    c.archive_cpu_type(path)

    def test_oversized_download_not_retried_or_promoted(self):
        with patch.object(c, 'blob_location', return_value='https://example.invalid/bottle') as loc, \
                patch.object(c, 'MAX_DOWNLOAD_BYTES', 10), patch.object(
                    c.urllib.request, 'urlopen', return_value=self.response(b'x' * 11)):
            with self.assertRaises(c.CollectionError):
                c.obtain('zlib', {'tag': 'tag', 'sha256': 'a' * 64}, self.root)
            loc.assert_called_once()
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
