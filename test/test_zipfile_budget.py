import io
import unittest
from unittest import mock

from test.support import unlink

from .test_zipfile import TESTFN, requires_zlib

from pyzipper import zipfile
from pyzipper import zipfile_aes

try:
    import Cryptodome
except ImportError:
    Cryptodome = None

requires_pycrypto = unittest.skipUnless(Cryptodome, 'requires pycryptodomex')

PASSWORD = b'topsecret'


def make_aes_archive(members):
    """Write a WZ_AES encrypted, deflated archive of {name: data}."""
    with zipfile_aes.AESZipFile(
            TESTFN, 'w',
            compression=zipfile.ZIP_DEFLATED,
            encryption=zipfile_aes.WZ_AES) as zf:
        zf.setpassword(PASSWORD)
        for name, data in members.items():
            zf.writestr(name, data)


@requires_pycrypto
@requires_zlib
class ExtractionBudgetTests(unittest.TestCase):

    def setUp(self):
        self.addCleanup(self.remove_testfile)

    def remove_testfile(self):
        try:
            unlink(TESTFN)
        except FileNotFoundError:
            pass

    def open_budgeted(self, budget):
        return zipfile_aes.AESZipFile(
            TESTFN, 'r', extraction_budget=budget)

    def test_budget_exceeded_is_not_badzipfile(self):
        self.assertFalse(
            issubclass(zipfile.ExtractionBudgetExceeded, zipfile.BadZipFile))
        self.assertTrue(
            issubclass(zipfile.ExtractionBudgetExceeded, Exception))

    def test_small_highly_compressed_member_trips_decompressed_budget(self):
        # A tiny archive that expands to a large output: the central
        # directory file_size is not what guards us, the budget is.
        payload = b'\x00' * (1024 * 1024)
        make_aes_archive({'bomb.bin': payload})

        budget = zipfile.ExtractionBudget(max_decompressed_bytes=100_000)
        with self.open_budgeted(budget) as zf:
            with mock.patch.object(
                    zipfile_aes.AESZipDecrypter, 'check_hmac',
                    autospec=True) as hmac_spy:
                with self.assertRaises(zipfile.ExtractionBudgetExceeded):
                    zf.read('bomb.bin', pwd=PASSWORD)
                # The aborted member must not be marked fully verified:
                # the HMAC check never ran for it.
                hmac_spy.assert_not_called()
        self.assertGreater(budget.decompressed_bytes, 100_000)
        # Peak is recorded at the decompressor output.
        self.assertGreater(budget.peak_decompressed_chunk, 0)
        self.assertLessEqual(
            budget.peak_decompressed_chunk, budget.decompressed_bytes)

    def test_compressed_read_budget(self):
        payload = b'\x00' * (1024 * 1024)
        make_aes_archive({'bomb.bin': payload})

        budget = zipfile.ExtractionBudget(max_compressed_bytes=100)
        with self.open_budgeted(budget) as zf:
            with self.assertRaises(zipfile.ExtractionBudgetExceeded):
                zf.read('bomb.bin', pwd=PASSWORD)
        self.assertGreater(budget.compressed_bytes_read, 100)

    def test_member_count_budget(self):
        make_aes_archive({'a.txt': b'aaa', 'b.txt': b'bbb'})

        budget = zipfile.ExtractionBudget(max_members=1)
        with self.open_budgeted(budget) as zf:
            self.assertEqual(zf.read('a.txt', pwd=PASSWORD), b'aaa')
            with self.assertRaises(zipfile.ExtractionBudgetExceeded):
                zf.open('b.txt', pwd=PASSWORD)
        self.assertEqual(budget.members_opened, 2)

    def test_two_members_individually_fine_collectively_over(self):
        # Each member is under the limit on its own; together they exceed
        # the per-archive decompressed budget.
        member_data = b'abcd' * 25_000  # 100_000 bytes each
        make_aes_archive({'one.bin': member_data, 'two.bin': member_data})

        budget = zipfile.ExtractionBudget(max_decompressed_bytes=150_000)
        with self.open_budgeted(budget) as zf:
            # First member reads to completion and passes its HMAC check.
            self.assertEqual(zf.read('one.bin', pwd=PASSWORD), member_data)
            # Second member is aborted by the shared budget mid-read.
            with self.assertRaises(zipfile.ExtractionBudgetExceeded):
                zf.read('two.bin', pwd=PASSWORD)
        self.assertGreater(budget.decompressed_bytes, 150_000)

    def test_interleaved_reads_and_small_chunks_accumulate(self):
        member_data = b'wxyz' * 25_000  # 100_000 bytes each
        make_aes_archive({'one.bin': member_data, 'two.bin': member_data})

        budget = zipfile.ExtractionBudget(max_decompressed_bytes=150_000)
        with self.open_budgeted(budget) as zf:
            f1 = zf.open('one.bin', pwd=PASSWORD)
            f2 = zf.open('two.bin', pwd=PASSWORD)
            buf = bytearray(97)
            total = 0
            with self.assertRaises(zipfile.ExtractionBudgetExceeded):
                while True:
                    # Interleave read1 and readinto with small chunks;
                    # small reads must not reset the allowance.
                    chunk = f1.read1(113)
                    if chunk:
                        total += len(chunk)
                    n = f2.readinto(buf)
                    if n:
                        total += n
                    if not chunk and not n:
                        break
            # The budget tripped before both members were fully read.
            self.assertLess(total, 2 * len(member_data))
        self.assertGreater(budget.decompressed_bytes, 150_000)

    def test_archive_exactly_at_budget_completes_and_verifies(self):
        member_data = b'exactly-at-the-limit' * 5_000  # 100_000 bytes
        make_aes_archive({'one.bin': member_data, 'two.bin': member_data})

        budget = zipfile.ExtractionBudget(
            max_decompressed_bytes=2 * len(member_data),
            max_members=2)
        with self.open_budgeted(budget) as zf:
            with mock.patch.object(
                    zipfile_aes.AESZipDecrypter, 'check_hmac',
                    autospec=True,
                    side_effect=zipfile_aes.AESZipDecrypter.check_hmac,
            ) as hmac_spy:
                self.assertEqual(zf.read('one.bin', pwd=PASSWORD), member_data)
                self.assertEqual(zf.read('two.bin', pwd=PASSWORD), member_data)
            # Both members reached EOF and were HMAC verified.
            self.assertEqual(hmac_spy.call_count, 2)
        self.assertEqual(budget.decompressed_bytes, 2 * len(member_data))
        self.assertGreater(budget.peak_decompressed_chunk, 0)
        self.assertLessEqual(
            budget.peak_decompressed_chunk, budget.decompressed_bytes)
        self.assertGreater(budget.compressed_bytes_read, 0)
        self.assertEqual(budget.members_opened, 2)

    def test_readinto_counts_towards_budget(self):
        member_data = b'readinto-target' * 1_000  # 15_000 bytes
        make_aes_archive({'data.bin': member_data})

        budget = zipfile.ExtractionBudget()
        with self.open_budgeted(budget) as zf:
            with zf.open('data.bin', pwd=PASSWORD) as f:
                buf = bytearray(4096)
                out = io.BytesIO()
                while True:
                    n = f.readinto(buf)
                    if not n:
                        break
                    out.write(buf[:n])
        self.assertEqual(out.getvalue(), member_data)
        self.assertEqual(budget.decompressed_bytes, len(member_data))

    def test_budget_is_per_archive_processing(self):
        # A fresh budget on a new ZipFile starts from zero; a ZipFile
        # without a budget is unlimited.
        make_aes_archive({'a.txt': b'hello world'})

        budget = zipfile.ExtractionBudget(max_members=1)
        with self.open_budgeted(budget) as zf:
            zf.read('a.txt', pwd=PASSWORD)
            with self.assertRaises(zipfile.ExtractionBudgetExceeded):
                zf.open('a.txt', pwd=PASSWORD)

        fresh_budget = zipfile.ExtractionBudget(max_members=1)
        with self.open_budgeted(fresh_budget) as zf:
            self.assertEqual(zf.read('a.txt', pwd=PASSWORD), b'hello world')

        with zipfile_aes.AESZipFile(TESTFN, 'r') as zf:
            self.assertEqual(zf.read('a.txt', pwd=PASSWORD), b'hello world')
            self.assertEqual(zf.read('a.txt', pwd=PASSWORD), b'hello world')

    def test_invalid_budget_limits_rejected(self):
        with self.assertRaises(ValueError):
            zipfile.ExtractionBudget(max_decompressed_bytes=-1)
        with self.assertRaises(ValueError):
            zipfile.ExtractionBudget(max_members=-1)
        with self.assertRaises(TypeError):
            zipfile_aes.AESZipFile(TESTFN, 'r', extraction_budget=object())


if __name__ == '__main__':
    unittest.main()
