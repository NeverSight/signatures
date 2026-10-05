"""Feature admission tests, including tampered real compiler evidence."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import validate_library_features as validate
import build_libcxx_features as libcxx
import build_msvc_features as msvc
import verify_library_feature_repeat as repeat
from build_library_feature_probes import describe

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / 'features/rules/libcxx-23git-arm64-macos-abi1-alternate-clang22.json'


class ExpressionTests(unittest.TestCase):
    def setUp(self):
        self.pattern = {"nodes": [
            {"id": "receiver", "op": "input", "bits": 64, "role": "receiver"},
            {"id": "data", "op": "load", "bits": 64, "args": ["receiver"], "offset": 0}], "result": "data"}

    def test_valid_typed_load(self):
        validate.expression(self.pattern)

    def test_cycles_missing_inputs_and_unreachable_evidence_fail(self):
        for change in ('self', 'missing', 'unused'):
            pattern = copy.deepcopy(self.pattern)
            if change == 'self':
                pattern['nodes'][1]['args'] = ['data']
            elif change == 'missing':
                pattern['nodes'][1]['args'] = ['undefined']
            else:
                pattern['nodes'].append({'id': 'spare', 'op': 'constant', 'bits': 8, 'value': '0x1'})
            with self.subTest(change=change), self.assertRaises(validate.FeatureError):
                validate.expression(pattern)

    def test_unsupported_memory_operator_cannot_be_silently_treated_as_load(self):
        self.pattern['nodes'][1]['op'] = 'atomic-load'
        with self.assertRaises(validate.FeatureError):
            validate.expression(self.pattern)

    def test_address_width_and_constant_overflow_are_rejected(self):
        self.pattern['nodes'][0]['bits'] = 32
        with self.assertRaises(validate.FeatureError):
            validate.expression(self.pattern)
        self.pattern['nodes'][0]['bits'] = 64
        self.pattern['nodes'][1] = {'id': 'data', 'op': 'constant', 'bits': 8, 'value': '0x100'}
        with self.assertRaises(validate.FeatureError):
            validate.expression(self.pattern)

    def test_duplicate_json_members_are_not_last_writer_wins(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pack.json'
            path.write_text('{"schema_version": 1, "schema_version": 2}')
            with self.assertRaises(validate.FeatureError):
                validate.read_json(path)

    def test_nonfinite_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pack.json'
            for value in ('NaN', 'Infinity', '-Infinity'):
                path.write_text('{"value": ' + value + '}')
                with self.subTest(value=value), self.assertRaises(validate.FeatureError):
                    validate.read_json(path)

    def test_evidence_paths_cannot_escape_the_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('../outside', '/etc/passwd', '..\\outside'):
                with self.subTest(name=name), self.assertRaises(validate.FeatureError):
                    validate.checked_path(root, name)


@unittest.skipUnless(PACK.is_file(), 'libc++ evidence pack is not checked out')
class ProducedPackTests(unittest.TestCase):
    def setUp(self):
        self.pack = json.loads(PACK.read_text())

    def validate_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'modified.json'
            path.write_text(json.dumps(self.pack))
            return validate.validate_pack(ROOT, path)

    def test_real_compiler_evidence_validates(self):
        result = validate.validate_pack(ROOT, PACK)
        self.assertEqual(len(result['rules']), 16)
        self.assertFalse(result['verification']['consumer_verified'])

    def test_a_renamed_or_nonexistent_probe_is_not_a_positive_witness(self):
        self.pack['rules'][0]['positive'][0]['symbol'] = 'not_produced_by_the_compiler'
        with self.assertRaises(validate.FeatureError):
            self.validate_modified()

    def test_profile_tampering_fails_the_digest_check(self):
        self.pack['profile']['sha256'] = '0' * 64
        with self.assertRaises(validate.FeatureError):
            self.validate_modified()

    def test_layout_similarity_cannot_replace_receiver_evidence(self):
        self.pack['rules'][0]['identity_evidence'] = 'layout-only'
        with self.assertRaises(validate.FeatureError):
            self.validate_modified()

    def test_data_validation_cannot_claim_runtime_matcher_success(self):
        self.pack['verification']['consumer_verified'] = True
        with self.assertRaises(validate.FeatureError):
            self.validate_modified()

    def test_positive_and_negative_witnesses_are_both_required(self):
        self.pack['rules'][0]['negative'] = []
        with self.assertRaises(validate.FeatureError):
            self.validate_modified()

    def test_unwitnessed_scope_is_not_coverage(self):
        self.pack['rules'][0]['positive'] = self.pack['rules'][0]['positive'][:1]
        with self.assertRaises(validate.FeatureError):
            self.validate_modified()


class LayoutTests(unittest.TestCase):
    def test_ambiguous_layout_is_rejected(self):
        dump = '*** Dumping AST Record Layout\n0 | struct Example\n0 | int member\n'
        with self.assertRaises(validate.FeatureError):
            libcxx.record_layout(dump + dump, 'Example')

    def test_msvc_nested_layout_retains_offsets_and_rejects_ambiguity(self):
        text = 'class Owner\tsize(8):\n\t+---\n 0\t| +--- (base class Base)\n 0\t| | pointer\n\t| +---\n\t+---\n'
        size, body = msvc.record(text, 'Owner')
        self.assertEqual(size, 8)
        self.assertEqual(msvc.offset(body, 'pointer'), 0)
        with self.assertRaises(validate.FeatureError):
            msvc.record(text + text, 'Owner')


class ReproductionTests(unittest.TestCase):
    def test_recorded_digest_cannot_hide_a_changed_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = (Path(temporary) / p for p in ('one', 'two'))
            for directory in (first, second):
                directory.mkdir()
                records = []
                for name in ('test.o', 'test.s'):
                    path = directory / name
                    path.write_bytes(b'original artifact')
                    records.append(describe(path))
                manifest = dict.fromkeys(('target', 'source', 'compiler', 'compiler_version', 'generator', 'builds'), [])
                manifest.update(status='produced', artifacts=records)
                (directory / 'manifest.json').write_text(json.dumps(manifest))
            self.assertEqual(len(repeat.verify(first, second)['artifacts']), 2)
            (second / 'test.o').write_bytes(b'changed after the build')
            with self.assertRaises(validate.FeatureError):
                repeat.verify(first, second)


MSVC = ROOT / 'features/rules/msvc-14.44.35207-x64-release-atl-com.json'


@unittest.skipUnless(MSVC.is_file(), 'MSVC evidence pack is not checked out')
class ComContractTests(unittest.TestCase):
    def setUp(self):
        self.rule = next(r for r in json.loads(MSVC.read_text())['rules'] if r['operation'] == 'Release')

    def test_release_order_slot_and_null_policy_are_not_interchangeable(self):
        for field, value in (('release_slot', 1), ('pointer_offset', 8), ('policy', 'release-without-clear'),
                             ('self_assignment', 'skip-equal-pointer')):
            rule = copy.deepcopy(self.rule)
            rule['pattern'][field] = value
            with self.subTest(field=field), self.assertRaises(validate.FeatureError):
                validate.pattern_contract(ROOT, rule)

    def test_com_shape_does_not_accept_an_arbitrary_user_receiver(self):
        self.rule['receiver_type'] = 'UserComOwner'
        with self.assertRaises(validate.FeatureError):
            validate.pattern_contract(ROOT, self.rule)

    def test_msvc_packs_and_inherited_method_identities(self):
        total = 0
        for path in (ROOT / 'features/rules').glob('msvc-*.json'):
            pack = validate.validate_pack(ROOT, path)
            total += len(pack['rules'])
            for rule in pack['rules']:
                if rule['operation'] in ('GetLength', 'GetString', 'IsEmpty', 'GetBuffer', 'ReleaseBuffer'):
                    self.assertTrue(rule['receiver_type'].startswith('ATL::CSimpleStringT<'))
                if rule['operation'] == 'Release' and 'whole-function' in rule['scope']:
                    self.assertEqual(rule['receiver_type'], 'ATL::CComPtrBase<IUnknown>')
        self.assertEqual(total, 38)


MUSL = ROOT / 'features/rules/musl-1.2.5-x64-clang22-memory.json'


@unittest.skipUnless(MUSL.is_file(), 'musl evidence pack is not checked out')
class ByteContractTests(unittest.TestCase):
    def test_real_libc_pack_uses_no_invented_receiver_type(self):
        pack = validate.validate_pack(ROOT, MUSL)
        self.assertEqual({rule['operation'] for rule in pack['rules']},
                         {'memcpy', 'memmove', 'memset', 'memcmp', 'strlen'})
        self.assertTrue(all(rule['receiver_type'] is None for rule in pack['rules']))

    def test_byte_patterns_cannot_claim_inline_or_lower_the_threshold(self):
        for field, value in (('fixed_bytes_min', 8), ('symbol', 'user_wrapper')):
            rule = copy.deepcopy(json.loads(MUSL.read_text())['rules'][0])
            rule['pattern'][field] = value
            with self.subTest(field=field), self.assertRaises(validate.FeatureError):
                validate.pattern_contract(ROOT, rule)
        rule = json.loads(MUSL.read_text())['rules'][0]
        rule['scope'].append('inline-region')
        with self.assertRaises(validate.FeatureError):
            validate.pattern_contract(ROOT, rule)


if __name__ == '__main__':
    unittest.main()
