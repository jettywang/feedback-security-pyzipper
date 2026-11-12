"""Regression tests for the structured AES/ZIP64 metadata fuzzing findings.

These tests pin the behaviour discovered by fuzz/run_fuzz.py with a fixed
seed. They use only small in-memory archives (no large files) and assert the
contract the parser should provide:

* benign extra-field reordering / unknown fields stay readable;
* contradictory lengths are rejected with the documented BadZipFile;
* genuinely unexpected failures (raw struct.error, KeyError, EOFError,
  zlib.error) and out-of-bounds data reads are recorded as findings;
* relaxing the length guard turns clean rejections into raw struct.error.

The "unexpected" tests document current library behaviour. If a future pyzipper
release hardens these paths, update the expected exception to BadZipFile here;
the fuzzer itself (run_fuzz.py) will simply report fewer findings.
"""

import struct
import unittest

from fuzz.classify import classify, is_oob
from fuzz.engine import (DEFAULT_SEED, evaluate, minimize,
                         run_named_mutations, run_random)
from fuzz.layout_dump import describe
from fuzz.mini_zip import (EXTRA_WZ_AES, EXTRA_ZIP64, aes_field, field,
                           parse_layout, rebuild, unknown_field,
                           valid_aes_archive, zip64_field)
from fuzz.relax_guard import RelaxedLengthGuard
from fuzz.tracer import drive_parse


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob, cls.password = valid_aes_archive()
        cls.payload_len = (parse_layout(cls.blob).payload_end
                           - parse_layout(cls.blob).data_off)

    def evaluate(self, mutated):
        return evaluate(self.blob, mutated, self.password)


class TestBenignMetadata(Base):
    """Legal reordering and skippable unknown fields must not be rejected."""

    def test_unknown_field_before_and_after_aes(self):
        unk = unknown_field()
        for chain in (aes_field() + unk, unk + aes_field(),
                      unk + aes_field() + unknown_field(0x4242, b'')):
            mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=chain)
            outcome, kind, _ = self.evaluate(mutated)
            self.assertEqual(kind, 'ok', describe(mutated))
            self.assertEqual(outcome.zinfo.wz_aes_strength, 3)

    def test_zip64_and_aes_field_order_interchangeable(self):
        # A ZIP64 field with no active 0xffffffff sentinel is informational and
        # must be ignored regardless of its position relative to the AES field.
        z64 = zip64_field(12345)
        aes = aes_field()
        original_usize = 19
        for chain in (z64 + aes, aes + z64):
            mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=chain)
            outcome, kind, _ = self.evaluate(mutated)
            self.assertEqual(kind, 'ok', describe(mutated))
            self.assertEqual(outcome.zinfo.file_size, original_usize)

    def test_duplicate_unknown_fields_skipped(self):
        chain = (unknown_field(0x5151, b'') + aes_field()
                 + unknown_field(0x5252, b'zz'))
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=chain)
        _, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'ok')


class TestCleanRejections(Base):
    """Length/header contradictions are refused via documented exceptions."""

    def test_truncated_aes_extra_body_rejected(self):
        chain = struct.pack('<HH', EXTRA_WZ_AES, 7) + b'\x00' * 3
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=aes_field())
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'clean-rejection')
        self.assertEqual(outcome.exc_type, 'BadZipFile')

    def test_zip64_declared_length_overrun_rejected(self):
        chain = (struct.pack('<HH', EXTRA_ZIP64, 8) + b'\x00' * 4
                 + aes_field())
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=aes_field())
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'clean-rejection')
        self.assertEqual(outcome.exc_type, 'BadZipFile')

    def test_unknown_field_declared_long_rejected(self):
        chain = (struct.pack('<HH', 0x7777, 30) + b'xy' + aes_field())
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=aes_field())
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'clean-rejection')
        self.assertEqual(outcome.exc_type, 'BadZipFile')


class TestRecordedFindings(Base):
    """Current-library findings: wrong algorithm, OOB reads, raw exceptions."""

    def test_duplicate_aes_last_block_selects_wrong_algorithm(self):
        # Two WZ_AES fields; the last one's actual method (deflate) wins even
        # though the payload is AES-STORED -> zlib.error instead of clean data.
        chain = aes_field(actual_method=0) + aes_field(actual_method=8)
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=chain)
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(outcome.zinfo.compress_type, 8)
        self.assertEqual(kind, 'unexpected')
        self.assertEqual(outcome.exc_type, 'error')  # zlib.error __name__

    def test_invalid_aes_strength_leaks_keyerror(self):
        chain = field(EXTRA_WZ_AES,
                      struct.pack('<H2sBH', 2, b'AE', 9, 0))
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=chain)
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'unexpected')
        self.assertEqual(outcome.exc_type, 'KeyError')

    def test_csize_contradiction_reads_past_payload_boundary(self):
        mutated = rebuild(self.blob,
                          cd_patch={'csize': ('<I', 5000)})
        outcome, kind, _ = self.evaluate(mutated)
        self.assertTrue(is_oob(outcome), describe(mutated))
        self.assertGreater(outcome.max_end, outcome.payload_region[1])
        # The over-read reaches the EOCD bytes at the end of the archive.
        self.assertEqual(outcome.max_end, outcome.archive_len)

    def test_zip64_sentinel_csize_drives_oob_read(self):
        chain = zip64_field(19, 5000) + aes_field()
        mutated = rebuild(
            self.blob, cd_extra=chain, lfh_extra=aes_field(),
            cd_patch={'csize': ('<I', 0xFFFFFFFF),
                      'usize': ('<I', 0xFFFFFFFF)})
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(outcome.zinfo.compress_size, 5000)
        self.assertTrue(is_oob(outcome))

    def test_placeholder_sizes_without_zip64_extra_eoferror(self):
        mutated = rebuild(
            self.blob, cd_extra=aes_field(), lfh_extra=aes_field(),
            cd_patch={'usize': ('<I', 0xFFFFFFFF),
                      'csize': ('<I', 0xFFFFFFFF)})
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'unexpected')
        self.assertEqual(outcome.exc_type, 'EOFError')

    def test_lfh_extra_length_overrun_raw_struct_error(self):
        mutated = rebuild(self.blob, lfh_patch={'xlen': ('<H', 200)})
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'unexpected')
        self.assertEqual(outcome.exc_type, 'error')

    def test_aes_extra_without_encrypted_flag_attribute_error(self):
        # AES extra sets wz_aes_version, but clearing the encrypted bit means
        # no decrypter is built; the integrity path then dereferences None.
        mutated = rebuild(
            self.blob, cd_extra=aes_field(), lfh_extra=aes_field(),
            cd_patch={'flags': ('<H', 0)},
            lfh_patch={'flags': ('<H', 0)})
        outcome, kind, _ = self.evaluate(mutated)
        self.assertEqual(kind, 'unexpected')
        self.assertEqual(outcome.exc_type, 'AttributeError')


class TestMinimizer(Base):
    """Minimal counterexamples keep the two-field triggering relationship."""

    def test_minimal_duplicate_aes_layout(self):
        result = minimize(self.blob, self.password,
                          'dup_aes_last_deflate')
        self.assertEqual(result['chain'], ['dup_aes_last_deflate'])
        self.assertEqual(result['signature'],
                         ('unexpected', 'error', 'read'))
        layout = parse_layout(result['blob'])
        chain = result['blob'][layout.cd_extra_off:
                               layout.cd_extra_off + layout.cd_extra_len]
        # Exactly two AES fields survive minimization; their ordering is the
        # relationship that makes the last (deflate) block win.
        self.assertEqual(chain.count(struct.pack('<H', EXTRA_WZ_AES)), 2)
        self.assertIn('WZ_AES', describe(result['blob']))

    def test_minimal_strength_layout_holds_strength_value(self):
        result = minimize(self.blob, self.password,
                          'aes_strength_invalid_9')
        self.assertEqual(result['signature'],
                         ('unexpected', 'KeyError', 'open'))
        layout = parse_layout(result['blob'])
        # AES extra layout: id(H) len(H) version(H) vendor(2s) strength(B).
        strength_off = layout.cd_extra_off + 8
        self.assertEqual(result['blob'][strength_off:strength_off + 1],
                         b'\x09')


class TestRelaxedLengthGuard(Base):
    """Removing the length guard must make the suite fail (raw struct.error)."""

    def test_truncated_chain_becomes_struct_error_without_guard(self):
        chain = struct.pack('<HH', EXTRA_WZ_AES, 7) + b'\x00' * 3
        mutated = rebuild(self.blob, cd_extra=chain, lfh_extra=aes_field())

        # Strict production parser: documented BadZipFile.
        strict_outcome, strict_kind, _ = self.evaluate(mutated)
        self.assertEqual(strict_kind, 'clean-rejection')
        self.assertEqual(strict_outcome.exc_type, 'BadZipFile')

        # Relaxed parser: the contradiction reaches struct.unpack and escapes
        # as a raw struct.error, proving the guard is the active defense.
        with RelaxedLengthGuard():
            relaxed_outcome, relaxed_kind, _ = self.evaluate(mutated)
        self.assertEqual(relaxed_kind, 'unexpected')
        self.assertEqual(relaxed_outcome.exc_type, 'error')
        self.assertIn('buffer', relaxed_outcome.exc_message)

    def test_relaxed_guard_is_reverted(self):
        from pyzipper.zipfile import ZipInfo
        original = ZipInfo._decodeExtra
        with RelaxedLengthGuard():
            self.assertIsNot(ZipInfo._decodeExtra, original)
        self.assertIs(ZipInfo._decodeExtra, original)


class TestFixedSeedRegression(Base):
    """The whole fuzzing campaign is deterministic for a fixed seed."""

    def test_named_mutation_classification_stable(self):
        first = [(r['name'], r['kind'], r['outcome'].exc_type,
                  r['outcome'].stage)
                 for r in run_named_mutations(self.blob, self.password)]
        second = [(r['name'], r['kind'], r['outcome'].exc_type,
                   r['outcome'].stage)
                  for r in run_named_mutations(self.blob, self.password)]
        self.assertEqual(first, second)

    def test_random_campaign_reproducible_for_seed(self):
        run_a = run_random(self.blob, self.password, seed=DEFAULT_SEED,
                           iterations=60)
        run_b = run_random(self.blob, self.password, seed=DEFAULT_SEED,
                           iterations=60)
        sig_a = [(r['kind'], r['outcome'].exc_type, r['outcome'].stage,
                  is_oob(r['outcome'])) for r in run_a]
        sig_b = [(r['kind'], r['outcome'].exc_type, r['outcome'].stage,
                  is_oob(r['outcome'])) for r in run_b]
        self.assertEqual(sig_a, sig_b)
        # And the fixed seed does surface the unexpected families.
        self.assertIn('unexpected', {r['kind'] for r in run_a})


if __name__ == '__main__':
    unittest.main()
