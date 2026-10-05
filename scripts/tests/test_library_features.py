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


class LayoutTests(unittest.TestCase):
    def test_ambiguous_layout_is_rejected(self):
        dump = '*** Dumping AST Record Layout\n0 | struct Example\n0 | int member\n'
        with self.assertRaises(validate.FeatureError):
            libcxx.record_layout(dump + dump, 'Example')


if __name__ == '__main__':
    unittest.main()
