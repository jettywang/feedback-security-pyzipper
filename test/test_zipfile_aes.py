import io
import os
import struct
import time
import unittest
from random import randint, random

from test.support import unlink
from .test_zipfile import (
    TESTFN, TESTFN2, Unseekable, get_files, requires_bz2, requires_zlib, requires_lzma,
)

from pyzipper import zipfile
from pyzipper import zipfile_aes


FIXEDTEST_SIZE = 1000


try:
    import Cryptodome
except ImportError:
    Cryptodome = None

requires_pycrypto = unittest.skipUnless(Cryptodome, 'requires pycryptodomex')


@requires_pycrypto
class WZAESKnownFileTests(unittest.TestCase):
    """Test decryption against invariant files for behaviour.

    Once we know that we can decrypt a file known for a particular behaviour,
    we have confidence that files encrypted with the library, which are also
    able to be decrypted, are also good. In essence, this is a sanity check to
    make sure that we don't have a bug in both the encryption and decryption
    routines which allows the library to encrypt / decrypt files it has
    written but which are not compatible with other implementations.
    """

    def tearDown(self):
        try:
            unlink(TESTFN)
        except FileNotFoundError:
            pass

    def test_decrypt_known_good(self):
        """Decrypting a known good file works."""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<ZC\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            content = zipfp.read('test.txt', pwd=b'test')
        self.assertEqual(content, b'This is a test file for AES encryption.')

    def test_decrypt_bad_password_fails(self):
        """Decrypting a file with a bad password raises an error."""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\x00\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<ZC\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad password for file %r" % fname
            with self.assertRaises(RuntimeError, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_bad_hmac_ae1(self):
        """Decrypting an encrypted AE-1 file with a bad HMAC raises BadZipFile"""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb0\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<ZC\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad HMAC check for file %r" % 'test.txt'
            with self.assertRaises(zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_bad_hmac_ae2(self):
        """Decrypting an encrypted AE-2 file with a bad HMAC raises BadZipFile"""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00\x00\x00\x00\x00C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb0\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'\x00\x00\x00\x00C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad HMAC check for file %r" % 'test.txt'
            with self.assertRaises(zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_bad_crc_ae1(self):
        """Decrypting an encrypted AE-1 with a bad CRC raises BadZipFile"""
        bad_crc_ae_1_data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<0C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<0C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(bad_crc_ae_1_data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad CRC-32 for file %r" % 'test.txt'
            with self.assertRaises(
                    zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_zero_crc_ae2(self):
        """Decrypting an encrypted AE-2 file with 0 CRC.

        CRC is not supposed to be used for AE-2 encryption and should be set
        to 0.
        """
        bad_crc_ae_2_data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00\x00\x00\x00\x00C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'\x00\x00\x00\x00C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(bad_crc_ae_2_data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            content = zipfp.read('test.txt', pwd=b'test')
        self.assertEqual(content, b'This is a test file for AES encryption.')

    def test_decrypt_bad_crc_ae2(self):
        """Decrypting an encrypted AE-2 with an incorrect non-zero CRC raises
        BadZipFile.

        CRC is not supposed to be used for AE-2 encryption and should be set
        to 0 but in the case where it is provided, let's make sure it matches.
        """
        bad_crc_ae_2_data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<0C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<0C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(bad_crc_ae_2_data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad CRC-32 for file %r" % 'test.txt'
            with self.assertRaises(
                    zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')


@requires_pycrypto
class WZAESTests(unittest.TestCase):

    def tearDown(self):
        try:
            unlink(TESTFN)
        except FileNotFoundError:
            pass

    def test_write_password_required(self):
        """Not supplying a password when encrypting raises a RuntimeError"""
        fname = TESTFN
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setencryption(zipfile_aes.WZ_AES)
            with self.assertRaises(
                    RuntimeError,
                    msg='%s encryption requires a password.' % zipfile_aes.WZ_AES
            ):
                zipfp.open('test', 'w')

    def test_read_password_required(self):
        """Not supplying a password when decrypting raises a RuntimeError"""
        fname = TESTFN
        pwd = b'passwd'
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(zipfile_aes.WZ_AES)
            zipfp.writestr('test.txt', 'content')

        with zipfile_aes.AESZipFile(fname) as zipfp:
            self.assertRaises(RuntimeError, zipfp.read, 'test.txt')

    def test_crc_options(self):
        fname = TESTFN
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(b"passwd")
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=1,
            )
            with self.assertRaises(
                ValueError,
                msg="`conditionally_include_crc` must be True or False or None"
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=True,
            )
            with self.assertRaises(
                ValueError,
                msg="`min_bytes_to_include_crc` must be set if `conditionally_include_crc` is True"
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=True,
                min_bytes_to_include_crc=10,
            )
            with self.assertRaises(
                ValueError,
                msg="`min_bytes_to_include_crc` must be 20 or greater"
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                min_bytes_to_include_crc=10,
            )
            with self.assertRaises(
                ValueError,
                msg="`conditionally_include_crc` must be True if `min_bytes_to_include_crc` is set"
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=False,
                min_bytes_to_include_crc=10,
            )
            with self.assertRaises(
                ValueError,
                msg="`conditionally_include_crc` must be True if `min_bytes_to_include_crc` is set"
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                force_wz_aes_version=3,
            )
            with self.assertRaises(
                ValueError,
                msg="`force_wz_aes_version` must be WZ_AES_V1 (1) or WZ_AES_V2 (2)"
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                force_wz_aes_version=zipfile_aes.WZ_AES_V1,
                conditionally_include_crc=True,
                min_bytes_to_include_crc=20,
            )
            with self.assertRaises(
                ValueError,
                msg="`force_wz_aes_version` and `conditionally_include_crc` must not be specified at the same time."
            ):
                zipfp.writestr("test_fname", b"test")

            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                force_wz_aes_version=zipfile_aes.WZ_AES_V1,
                min_bytes_to_include_crc=20,
            )
            with self.assertRaises(
                ValueError,
                msg="`min_bytes_to_include_crc` must be set if `conditionally_include_crc` is True"
            ):
                zipfp.writestr("test_fname", b"test")

    def do_test_force_wz_aes_version(self, force_wz_aes_version):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                force_wz_aes_version=force_wz_aes_version
            )
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zinfo = zipfp.NameToInfo[content_fname]
            zipfp.setpassword(pwd)
            self.assertEqual(zinfo.wz_aes_version, force_wz_aes_version)
            read_content = zipfp.read(content_fname)
            self.assertEqual(content, read_content)
            if force_wz_aes_version == zipfile_aes.WZ_AES_V2:
                self.assertEqual(zinfo.CRC, 0)
            else:
                self.assertEqual(zinfo.CRC, zipfile.crc32(content))

    def test_force_wz_aes_version(self):
        """Supplying force_wz_aes_version overrides the calculated version."""
        # One of these will fail if not overridden based on identical content.
        self.do_test_force_wz_aes_version(force_wz_aes_version=1)
        self.do_test_force_wz_aes_version(force_wz_aes_version=2)

    def test_no_crc_by_default(self):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        for compress_method in [
            zipfile.ZIP_STORED,
            zipfile.ZIP_DEFLATED,
            zipfile.ZIP_BZIP2,
            zipfile.ZIP_LZMA,
        ]:
            for i in [1, 10, 19, 20, 200, 1000]:
                with self.subTest(f"{compress_method}: content length: {i}"):
                    content = b"a" * i
                    with zipfile_aes.AESZipFile(fname, "w") as zipfp:
                        zipfp.setpassword(pwd)
                        zipfp.setencryption(zipfile_aes.WZ_AES)
                        zipfp.writestr(content_fname, content)

                    with zipfile_aes.AESZipFile(fname) as zipfp:
                        zinfo = zipfp.NameToInfo[content_fname]
                        zipfp.setpassword(pwd)
                        self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
                        read_content = zipfp.read(content_fname)
                        self.assertEqual(content, read_content)
                        self.assertEqual(zinfo.CRC, 0)

    def test_conditional_crc_small_files(self):
        """Entries of size less than min_bytes_to_include_crc bytes have no CRC"""
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        for min_bytes_to_include_crc in [20, 30]:
            for i in range(1, min_bytes_to_include_crc):
                with self.subTest(f"min_bytes_to_include_crc: {min_bytes_to_include_crc}; content length: {i}"):
                    content = b"a" * i
                    with zipfile_aes.AESZipFile(fname, "w") as zipfp:
                        zipfp.setpassword(pwd)
                        zipfp.setencryption(
                            zipfile_aes.WZ_AES,
                            conditionally_include_crc=True,
                            min_bytes_to_include_crc=min_bytes_to_include_crc,
                        )
                        zipfp.writestr(content_fname, content)

                    with zipfile_aes.AESZipFile(fname) as zipfp:
                        zinfo = zipfp.NameToInfo[content_fname]
                        zipfp.setpassword(pwd)
                        self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
                        read_content = zipfp.read(content_fname)
                        self.assertEqual(content, read_content)
                        self.assertEqual(zinfo.CRC, 0)

    def test_conditional_crc_larger_files(self):
        """Entries of size min_bytes_to_include_crc bytes or more include CRC"""
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        for i in [20, 200, 1000]:
            with self.subTest(f"content length: {i}"):
                content = b"a" * i
                with zipfile_aes.AESZipFile(fname, "w") as zipfp:
                    zipfp.setpassword(pwd)
                    zipfp.setencryption(
                        zipfile_aes.WZ_AES,
                        conditionally_include_crc=True,
                        min_bytes_to_include_crc=20,
                    )
                    zipfp.writestr(content_fname, content)

                with zipfile_aes.AESZipFile(fname) as zipfp:
                    zinfo = zipfp.NameToInfo[content_fname]
                    zipfp.setpassword(pwd)
                    self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V1)
                    read_content = zipfp.read(content_fname)
                    self.assertEqual(content, read_content)
                    self.assertEqual(zinfo.CRC, zipfile.crc32(content))

    def test_bzip2_conditional_crc(self):
        """bzip2 streams have an internal integrity check and don't have CRC32"""
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        for i in [1, 10, 19, 20, 200, 1000]:
            with self.subTest(f"content length: {i}"):
                content = b"a" * i
                with zipfile_aes.AESZipFile(fname, "w", compression=zipfile.ZIP_BZIP2) as zipfp:
                    zipfp.setpassword(pwd)
                    zipfp.setencryption(
                        zipfile_aes.WZ_AES,
                        conditionally_include_crc=True,
                        min_bytes_to_include_crc=20,
                    )
                    zipfp.writestr(content_fname, content)

                with zipfile_aes.AESZipFile(fname) as zipfp:
                    zinfo = zipfp.NameToInfo[content_fname]
                    zipfp.setpassword(pwd)
                    self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
                    read_content = zipfp.read(content_fname)
                    self.assertEqual(content, read_content)
                    self.assertEqual(zinfo.CRC, 0)

    def read_datadescripter(self, fid, zinfo, is_zip64=False):
        if not zinfo.use_datadescripter:
            raise ValueError("datadescriptor not set")

        fid.seek(zinfo.header_offset)
        fheader_bytes = fid.read(zipfile.sizeFileHeader)
        if len(fheader_bytes) != zipfile.sizeFileHeader:
            raise zipfile.BadZipFile("Truncated file header")
        fheader = struct.unpack(zipfile.structFileHeader, fheader_bytes)
        if fheader[zipfile._FH_SIGNATURE] != zipfile.stringFileHeader:
            raise zipfile.BadZipFile("Bad magic number for file header")

        fname = fid.read(fheader[zipfile._FH_FILENAME_LENGTH])
        if fheader[zipfile._FH_EXTRA_FIELD_LENGTH]:
            fid.read(fheader[zipfile._FH_EXTRA_FIELD_LENGTH])
        fid.seek(zinfo.compress_size, os.SEEK_CUR)
        if is_zip64:
            size = 24
            fmt = '<LLQQ'
        else:
            size = 16
            fmt = '<LLLL'
        dd_sig, crc, compress_size, file_size = struct.unpack(fmt, fid.read(size))
        self.assertEqual(dd_sig, zipfile._DD_SIGNATURE)
        return crc, compress_size, file_size

    def test_datadescriptor_no_crc(self):
        fid = io.BytesIO()
        unseek_fid = Unseekable(fid)
        pwd = b'passwd'
        content_fname = 'test.txt'
        for i in [1, 10, 19, 20, 200, 1000]:
            with self.subTest(f"content length: {i}"):
                content = b"a" * i
                with zipfile_aes.AESZipFile(unseek_fid, "w") as zipfp:
                    zipfp.setpassword(pwd)
                    zipfp.setencryption(
                        zipfile_aes.WZ_AES,
                    )
                    zipfp.writestr(content_fname, content)

                with zipfile_aes.AESZipFile(fid) as zipfp:
                    zinfo = zipfp.NameToInfo[content_fname]
                    zipfp.setpassword(pwd)
                    self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
                    self.assertEqual(zinfo.CRC, 0)
                    read_content = zipfp.read(content_fname)
                    self.assertEqual(content, read_content)

                dd_crc, dd_compress_size, dd_filesize = self.read_datadescripter(fid, zinfo)
                self.assertEqual(dd_crc, 0)

    def test_datadescriptor_unknown_size(self):
        """Files of initially unknown sizes written to unseekable archives use ae-2"""
        fid = io.BytesIO()
        unseek_fid = Unseekable(fid)
        pwd = b'passwd'
        content_fname = 'test.txt'
        # content length of 40 should use ae-1 when using conditionally written
        # CRC but because we initially don't know the size, we default to ae-2
        # and can't change that later due to the file being unseekable.
        content = b"a" * 40
        with zipfile_aes.AESZipFile(unseek_fid, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=True,
                min_bytes_to_include_crc=20,
            )
            with zipfp.open(content_fname, "w") as zfout:
                zfout.write(content)

        with zipfile_aes.AESZipFile(fid) as zipfp:
            zinfo = zipfp.NameToInfo[content_fname]
            zipfp.setpassword(pwd)
            self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
            self.assertEqual(zinfo.CRC, 0)
            read_content = zipfp.read(content_fname)
            self.assertEqual(content, read_content)

        dd_crc, dd_compress_size, dd_filesize = self.read_datadescripter(fid, zinfo)
        self.assertEqual(dd_crc, 0)

    def test_datadescriptor_conditional_crc(self):
        fid = io.BytesIO()
        unseek_fid = Unseekable(fid)
        pwd = b'passwd'
        content_fname = 'test.txt'
        for i in [1, 10, 19, 20, 200, 1000]:
            with self.subTest(f"content length: {i}"):
                content = b"a" * i
                with zipfile_aes.AESZipFile(unseek_fid, "w") as zipfp:
                    zipfp.setpassword(pwd)
                    zipfp.setencryption(
                        zipfile_aes.WZ_AES,
                        conditionally_include_crc=True,
                        min_bytes_to_include_crc=20,
                    )
                    zipfp.writestr(content_fname, content)

                with zipfile_aes.AESZipFile(fid) as zipfp:
                    zinfo = zipfp.NameToInfo[content_fname]
                    zipfp.setpassword(pwd)
                    if i < 20:
                        self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
                        self.assertEqual(zinfo.CRC, 0)
                    else:
                        self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V1)
                        self.assertEqual(zinfo.CRC, zipfile.crc32(content))
                    read_content = zipfp.read(content_fname)
                    self.assertEqual(content, read_content)

                dd_crc, dd_compress_size, dd_filesize = self.read_datadescripter(fid, zinfo)
                if i < 20:
                    self.assertEqual(dd_crc, 0)
                else:
                    self.assertEqual(dd_crc, zipfile.crc32(content))

    def do_test_aes_strength(self, nbits):
        """Providing an `nbits` encryption kwarg changes the encryption strength.

        Checks that we can encrypt then decrypt and that the compressed size is
        as expected for the varying salt length.
        """
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                nbits=nbits
            )
            with zipfp.open(content_fname, 'w') as zopen:
                zopen.write(content)

        salt_lengths = {
            128: 8,
            192: 12,
            256: 16,
        }

        def expected_compress_size(content, nbits):
            """Computes the expected compress_size for a STORED file for nbits
            encryption."""
            return (
                len(content)
                + salt_lengths[nbits]
                + 2   # pwd_verify_length
                + 10  # mac_length
            )

        expected_strength = {
            128: 1,
            192: 2,
            256: 3,
        }

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zinfo = zipfp.NameToInfo[content_fname]
            zipfp.setpassword(pwd)
            read_content = zipfp.read(content_fname)
            self.assertEqual(content, read_content)
            self.assertEqual(zinfo.wz_aes_strength, expected_strength[nbits])
            self.assertEqual(
                zinfo.compress_size,
                expected_compress_size(content, nbits)
            )

    def test_aes_strengths(self):
        self.do_test_aes_strength(nbits=128)
        self.do_test_aes_strength(nbits=192)
        self.do_test_aes_strength(nbits=256)

    def test_aes_invalid_strength(self):
        with self.assertRaises(RuntimeError):
            self.do_test_aes_strength(nbits='not correct')

    def test_aes_encryption_via_init(self):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(
                fname,
                mode='w',
                encryption=zipfile_aes.WZ_AES) as zipfp:
            zipfp.setpassword(pwd)
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zipfp.setpassword(pwd)
            read_content = zipfp.read(content_fname)

        self.assertEqual(content, read_content)

    def test_aes_encryption_via_init_with_kwargs(self):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(
                fname,
                'w',
                encryption=zipfile_aes.WZ_AES,
                encryption_kwargs={'nbits': 128}
        ) as zipfp:
            zipfp.setpassword(pwd)
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zipfp.setpassword(pwd)
            zinfo = zipfp.NameToInfo[content_fname]
            wz_aes_strength = zinfo.wz_aes_strength
            read_content = zipfp.read(content_fname)

        self.assertEqual(wz_aes_strength, 1)
        self.assertEqual(content, read_content)

    def test_local_header(self):
        """Local file header contains correct WZ AES information."""
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(
                fname,
                'w',
                encryption=zipfile_aes.WZ_AES
        ) as zipfp:
            zipfp.setpassword(pwd)
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zipfp.setpassword(pwd)
            with zipfp.open(zipfp.NameToInfo[content_fname]) as zf:
                zf._fileobj.seek(0)
                fheader = zf._fileobj.read(zipfile.sizeFileHeader)
                fheader = struct.unpack(zipfile.structFileHeader, fheader)

                # local header record
                self.assertEqual(fheader[4], zipfile_aes.WZ_AES_COMPRESS_TYPE)

                # extra info record
                fname_len = fheader[-2]
                extra_len = fheader[-1]
                zf._fileobj.read(fname_len)
                extra = zf._fileobj.read(extra_len)
                records = []
                # Iterate through any extra records which may be present.
                while len(extra) >= 4:
                    tp, ln = struct.unpack('<HH', extra[:4])
                    if tp == zipfile_aes.EXTRA_WZ_AES:
                        records.append(extra[4:ln+4])
                    extra = extra[ln+4:]
                # The WZ extra record only appears once.
                self.assertEqual(len(records), 1)
                counts = struct.unpack("<H2sBH", records[0])
                # The local header and central directory extra are the same.
                self.assertEqual(zf._zinfo.wz_aes_version, counts[0])
                self.assertEqual(zf._zinfo.wz_aes_vendor_id, counts[1])
                self.assertEqual(zf._zinfo.wz_aes_strength, counts[2])
                self.assertEqual(zf._zinfo.compress_type, counts[3])

    def test_seek_tell(self):
        # Test seek functionality
        txt = b"Where's Bruce?"
        bloc = txt.find(b"Bruce")
        pwd = b'passwd'
        # Check seek on a file
        with zipfile_aes.AESZipFile(TESTFN, "w") as zipf:
            zipf.pwd = pwd
            zipf.setencryption(zipfile_aes.WZ_AES, nbits=128)
            zipf.writestr("foo.txt", txt)
        with zipfile_aes.AESZipFile(TESTFN, "r") as zipf:
            zipf.pwd = pwd
            with zipf.open("foo.txt", "r") as fp:
                fp.seek(bloc, os.SEEK_SET)
                self.assertEqual(fp.tell(), bloc)
                fp.seek(-bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), 0)
                fp.seek(bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), bloc)
                self.assertEqual(fp.read(5), txt[bloc:bloc+5])
                fp.seek(0, os.SEEK_END)
                self.assertEqual(fp.tell(), len(txt))
                fp.seek(0, os.SEEK_SET)
                self.assertEqual(fp.tell(), 0)

        # Check seek on memory file
        data = io.BytesIO()
        with zipfile_aes.AESZipFile(data, mode="w") as zipf:
            zipf.pwd = pwd
            zipf.setencryption(zipfile_aes.WZ_AES, nbits=128)
            zipf.writestr("foo.txt", txt)
        with zipfile_aes.AESZipFile(data, mode="r") as zipf:
            zipf.pwd = pwd
            with zipf.open("foo.txt", "r") as fp:
                fp.seek(bloc, os.SEEK_SET)
                self.assertEqual(fp.tell(), bloc)
                fp.seek(-bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), 0)
                fp.seek(bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), bloc)
                self.assertEqual(fp.read(5), txt[bloc:bloc+5])

                # Make sure that the second read after seeking back beyond
                # _readbuffer returns the same content (ie. rewind to the start of
                # the file to read forward to the required position).
                old_read_size = fp.MIN_READ_SIZE
                fp.MIN_READ_SIZE = 1
                fp._readbuffer = b''
                fp._offset = 0
                fp.seek(0, os.SEEK_SET)
                self.assertEqual(fp.tell(), 0)
                fp.seek(bloc, os.SEEK_CUR)
                self.assertEqual(fp.read(5), txt[bloc:bloc+5])
                fp.MIN_READ_SIZE = old_read_size

                fp.seek(0, os.SEEK_END)
                self.assertEqual(fp.tell(), len(txt))
                fp.seek(0, os.SEEK_SET)
                self.assertEqual(fp.tell(), 0)

                # Read the file completely to definitely call any eof integrity
                # checks (hmac/crc) and make sure they still pass.
                fp.read()


class _NonSeekableShortWrite:
    """Write-only sink that rejects seeking and performs short writes.

    Each ``write`` pushes data to the underlying sink in bounded chunks (at
    most ``max_write`` bytes per sink write), like a socket or pipe that
    accepts fewer bytes than requested. The full payload is still transferred
    before the call returns, so the reported byte count is always the complete
    input length as a well-behaved writer loop requires.
    """

    def __init__(self, sink, max_write=7):
        self._sink = sink
        self._max_write = max_write
        self._offset = 0

    def write(self, data):
        view = memoryview(data)
        total = len(view)
        while view:
            chunk = bytes(view[:self._max_write])
            written = self._sink.write(chunk)
            if not written:
                raise BlockingIOError('underlying sink accepted no bytes')
            view = view[written:]
            self._offset += written
        return total

    def flush(self):
        self._sink.flush()

    def tell(self):
        return self._offset

    def seek(self, *args):
        raise io.UnsupportedOperation('stream is not seekable')

    def seekable(self):
        return False


def _parse_aes_extra(extra):
    while len(extra) >= 4:
        tp, ln = struct.unpack('<HH', extra[:4])
        if tp == zipfile_aes.EXTRA_WZ_AES:
            version, vendor, strength, method = struct.unpack(
                '<H2sBH', extra[4:4 + ln])
            return {
                'version': version,
                'vendor': vendor,
                'strength': strength,
                'method': method,
            }
        extra = extra[4 + ln:]
    return None


def _find_eocd(raw):
    # The EOCD is the final record. A signature inside member data can only be
    # a false match if its declared comment does not reach EOF, so validate
    # the comment length while scanning backwards.
    scan_start = max(
        0, len(raw) - (zipfile.ZIP_MAX_COMMENT + zipfile.sizeEndCentDir))
    pos = raw.rfind(zipfile.stringEndArchive, scan_start)
    while pos != -1 and pos + zipfile.sizeEndCentDir <= len(raw):
        comment_len = struct.unpack(
            '<H',
            raw[pos + zipfile.sizeEndCentDir - 2:
                pos + zipfile.sizeEndCentDir],
        )[0]
        if pos + zipfile.sizeEndCentDir + comment_len == len(raw):
            return pos
        pos = raw.rfind(zipfile.stringEndArchive, scan_start, pos)
    raise zipfile.BadZipFile('end of central directory record not found')


def _parse_archive(raw):
    """Independently split local headers, member data, data descriptors and
    central directory records.

    Central directory offsets and sizes drive navigation, so random bytes
    inside the encrypted member data cannot be mistaken for record
    signatures.
    """
    eocd_pos = _find_eocd(raw)
    eocd = struct.unpack(
        zipfile.structEndArchive,
        raw[eocd_pos:eocd_pos + zipfile.sizeEndCentDir],
    )
    cd_count = eocd[zipfile._ECD_ENTRIES_TOTAL]
    pos = eocd[zipfile._ECD_OFFSET]

    entries = {}
    for _ in range(cd_count):
        if raw[pos:pos + 4] != zipfile.stringCentralDir:
            raise zipfile.BadZipFile('Bad magic number for central directory')
        rec = struct.unpack(
            zipfile.structCentralDir,
            raw[pos:pos + zipfile.sizeCentralDir],
        )
        name_len = rec[zipfile._CD_FILENAME_LENGTH]
        extra_len = rec[zipfile._CD_EXTRA_FIELD_LENGTH]
        comment_len = rec[zipfile._CD_COMMENT_LENGTH]
        name = raw[pos + zipfile.sizeCentralDir:
                   pos + zipfile.sizeCentralDir + name_len].decode('utf-8')
        extra = raw[pos + zipfile.sizeCentralDir + name_len:
                    pos + zipfile.sizeCentralDir + name_len + extra_len]
        entries[name] = {
            'central': {
                'flags': rec[zipfile._CD_FLAG_BITS],
                'method': rec[zipfile._CD_COMPRESS_TYPE],
                'crc': rec[zipfile._CD_CRC],
                'csize': rec[zipfile._CD_COMPRESSED_SIZE],
                'fsize': rec[zipfile._CD_UNCOMPRESSED_SIZE],
                'aes': _parse_aes_extra(extra),
                'header_offset': rec[zipfile._CD_LOCAL_HEADER_OFFSET],
            },
        }
        pos += (zipfile.sizeCentralDir + name_len + extra_len + comment_len)

    for name, entry in entries.items():
        start = entry['central']['header_offset']
        hdr = struct.unpack(
            zipfile.structFileHeader,
            raw[start:start + zipfile.sizeFileHeader],
        )
        if hdr[zipfile._FH_SIGNATURE] != zipfile.stringFileHeader:
            raise zipfile.BadZipFile('Bad magic number for file header')
        name_len = hdr[zipfile._FH_FILENAME_LENGTH]
        extra_len = hdr[zipfile._FH_EXTRA_FIELD_LENGTH]
        extra = raw[start + zipfile.sizeFileHeader + name_len:
                    start + zipfile.sizeFileHeader + name_len + extra_len]
        data_start = start + zipfile.sizeFileHeader + name_len + extra_len
        data_end = data_start + entry['central']['csize']
        dd_sig, dd_crc, dd_csize, dd_fsize = struct.unpack(
            '<LLLL', raw[data_end:data_end + 16])
        if dd_sig != zipfile._DD_SIGNATURE:
            raise zipfile.BadZipFile('Missing data descriptor for %r' % name)
        entry['local'] = {
            'offset': start,
            'flags': hdr[zipfile._FH_GENERAL_PURPOSE_FLAG_BITS],
            'method': hdr[zipfile._FH_COMPRESSION_METHOD],
            'crc': hdr[zipfile._FH_CRC],
            'aes': _parse_aes_extra(extra),
        }
        entry['data_start'] = data_start
        entry['data_end'] = data_end
        entry['dd'] = {
            'crc': dd_crc,
            'csize': dd_csize,
            'fsize': dd_fsize,
            'offset': data_end,
        }
    return entries


@requires_pycrypto
class WZAESUnseekableVersionTests(unittest.TestCase):
    """AES version selection for archives written to non-seekable streams.

    The local file header, central directory, CRC handling, HMAC auth tail and
    data descriptor must always describe the same AES format, even though the
    member size is unknown when the local header is emitted.
    """

    pwd = b'fixed-vector-password'
    min_bytes_to_include_crc = 20

    def setUp(self):
        # Fixed vectors spanning the empty member, below-boundary, exact
        # boundary and above-boundary cases.
        boundary = self.min_bytes_to_include_crc
        self.vectors = {
            'empty.bin': b'',
            'small.bin': b'z' * (boundary - 1),
            'boundary.bin': b'q' * boundary,
            'large.bin': b'k' * (boundary * 5),
        }
        self.expected_crc = {
            name: zipfile.crc32(data) & 0xffffffff
            for name, data in self.vectors.items()
        }

    def build_archive(self, encryption_kwargs, *, use_open,
                      compression=zipfile.ZIP_STORED, members=None):
        sink = io.BytesIO()
        members = self.vectors.items() if members is None else members
        with zipfile_aes.AESZipFile(
                _NonSeekableShortWrite(sink), 'w',
                compression=compression) as zipfp:
            zipfp.setpassword(self.pwd)
            zipfp.setencryption(zipfile_aes.WZ_AES, **encryption_kwargs)
            for name, data in members:
                if use_open:
                    # Stream the member in chunks; its final size is unknown
                    # when the local header is written.
                    with zipfp.open(name, 'w') as zfout:
                        for index in range(0, len(data), 11):
                            zfout.write(data[index:index + 11])
                else:
                    # writestr declares the size up front.
                    zipfp.writestr(name, data)
        return sink.getvalue()

    def assertHeadersDescribeOneFormat(self, raw, expected_versions):
        entries = _parse_archive(raw)
        self.assertEqual(set(entries), set(expected_versions))
        for name, expected_version in expected_versions.items():
            entry = entries[name]
            local = entry['local']
            central = entry['central']
            descriptor = entry['dd']

            # Both headers must carry an identical 0x9901 AES extra field.
            self.assertIsNotNone(local['aes'])
            self.assertIsNotNone(central['aes'])
            self.assertEqual(local['aes'], central['aes'])
            self.assertEqual(local['aes']['version'], expected_version)

            # Compression method 99 and the data descriptor flag must agree.
            self.assertEqual(local['method'],
                             zipfile_aes.WZ_AES_COMPRESS_TYPE)
            self.assertEqual(central['method'],
                             zipfile_aes.WZ_AES_COMPRESS_TYPE)
            self.assertTrue(
                local['flags'] & zipfile._MASK_USE_DATA_DESCRIPTOR)
            self.assertTrue(
                central['flags'] & zipfile._MASK_USE_DATA_DESCRIPTOR)
            self.assertEqual(central['header_offset'], local['offset'])

            # Sizes in the data descriptor and central directory must match
            # the actual encrypted member footprint on disk.
            self.assertEqual(descriptor['csize'], central['csize'])
            self.assertEqual(descriptor['fsize'], central['fsize'])
            self.assertEqual(
                entry['data_end'] - entry['data_start'],
                descriptor['csize'],
            )

            if expected_version == zipfile_aes.WZ_AES_V2:
                # AE-2: CRC is unused and must be zero everywhere.
                self.assertEqual(local['crc'], 0)
                self.assertEqual(central['crc'], 0)
                self.assertEqual(descriptor['crc'], 0)
            else:
                # AE-1: the real fixed-vector CRC must be stored and agree.
                self.assertEqual(central['crc'], self.expected_crc[name])
                self.assertEqual(descriptor['crc'], self.expected_crc[name])
        return entries

    def assertRoundtrips(self, raw, members):
        with zipfile_aes.AESZipFile(io.BytesIO(raw)) as zipfp:
            zipfp.setpassword(self.pwd)
            for name, data in members:
                self.assertEqual(zipfp.read(name), data)
        # testzip exercises the HMAC auth tail (and any AE-1 CRC) per member.
        with zipfile_aes.AESZipFile(io.BytesIO(raw)) as zipfp:
            zipfp.setpassword(self.pwd)
            self.assertIsNone(zipfp.testzip())

    def test_default_selection_is_ae2_for_all_member_sizes(self):
        raw = self.build_archive({}, use_open=True)
        self.assertHeadersDescribeOneFormat(
            raw,
            {name: zipfile_aes.WZ_AES_V2 for name in self.vectors},
        )
        self.assertRoundtrips(raw, list(self.vectors.items()))

    def test_conditional_crc_unknown_size_freezes_ae2(self):
        # Even members which would qualify for AE-1 must stay AE-2: the size
        # is only known after the local header has already been emitted.
        raw = self.build_archive(
            {
                'conditionally_include_crc': True,
                'min_bytes_to_include_crc': self.min_bytes_to_include_crc,
            },
            use_open=True,
        )
        self.assertHeadersDescribeOneFormat(
            raw,
            {name: zipfile_aes.WZ_AES_V2 for name in self.vectors},
        )
        self.assertRoundtrips(raw, list(self.vectors.items()))

    def test_conditional_crc_known_size_honours_boundary(self):
        raw = self.build_archive(
            {
                'conditionally_include_crc': True,
                'min_bytes_to_include_crc': self.min_bytes_to_include_crc,
            },
            use_open=False,
        )
        self.assertHeadersDescribeOneFormat(raw, {
            'empty.bin': zipfile_aes.WZ_AES_V2,
            'small.bin': zipfile_aes.WZ_AES_V2,
            'boundary.bin': zipfile_aes.WZ_AES_V1,
            'large.bin': zipfile_aes.WZ_AES_V1,
        })
        self.assertRoundtrips(raw, list(self.vectors.items()))

    def test_forced_ae1_unknown_size_including_empty_member(self):
        raw = self.build_archive(
            {'force_wz_aes_version': zipfile_aes.WZ_AES_V1},
            use_open=True,
        )
        self.assertHeadersDescribeOneFormat(
            raw,
            {name: zipfile_aes.WZ_AES_V1 for name in self.vectors},
        )
        self.assertRoundtrips(raw, list(self.vectors.items()))

    def test_forced_ae2(self):
        raw = self.build_archive(
            {'force_wz_aes_version': zipfile_aes.WZ_AES_V2},
            use_open=True,
        )
        self.assertHeadersDescribeOneFormat(
            raw,
            {name: zipfile_aes.WZ_AES_V2 for name in self.vectors},
        )
        self.assertRoundtrips(raw, list(self.vectors.items()))

    def test_bzip2_stays_ae2_even_above_crc_threshold(self):
        data = self.vectors['large.bin']
        raw = self.build_archive(
            {
                'conditionally_include_crc': True,
                'min_bytes_to_include_crc': self.min_bytes_to_include_crc,
            },
            use_open=False,
            compression=zipfile.ZIP_BZIP2,
            members=[('bz.bin', data)],
        )
        self.assertHeadersDescribeOneFormat(
            raw, {'bz.bin': zipfile_aes.WZ_AES_V2})
        self.assertRoundtrips(raw, [('bz.bin', data)])

    def test_local_header_version_is_final_while_member_still_streams(self):
        # Intercept the bytes while a large, unknown-size member is still being
        # written. The version committed in the first local header must
        # already be final and must not change in the completed archive.
        captured = {}

        class ProbeStream(_NonSeekableShortWrite):
            def write(self, data):
                count = super().write(data)
                if self._offset >= 40 and 'version' not in captured:
                    raw = self._sink.getvalue()
                    header = struct.unpack(
                        zipfile.structFileHeader,
                        raw[:zipfile.sizeFileHeader],
                    )
                    name_len = header[zipfile._FH_FILENAME_LENGTH]
                    extra_len = header[zipfile._FH_EXTRA_FIELD_LENGTH]
                    extra = raw[zipfile.sizeFileHeader + name_len:
                                zipfile.sizeFileHeader + name_len + extra_len]
                    captured['version'] = _parse_aes_extra(extra)['version']
                return count

        sink = io.BytesIO()
        data = b'x' * 5000
        with zipfile_aes.AESZipFile(ProbeStream(sink), 'w') as zipfp:
            zipfp.setpassword(self.pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=True,
                min_bytes_to_include_crc=self.min_bytes_to_include_crc,
            )
            with zipfp.open('streamed.bin', 'w') as zfout:
                for index in range(0, len(data), 37):
                    zfout.write(data[index:index + 37])

        self.assertEqual(captured['version'], zipfile_aes.WZ_AES_V2)
        entries = _parse_archive(sink.getvalue())
        entry = entries['streamed.bin']
        self.assertEqual(entry['local']['aes']['version'],
                         captured['version'])
        self.assertEqual(entry['central']['aes']['version'],
                         captured['version'])
        self.assertEqual(entry['central']['crc'], 0)
        self.assertEqual(entry['dd']['crc'], 0)
        self.assertRoundtrips(sink.getvalue(), [('streamed.bin', data)])

    def test_forced_version_visible_while_member_still_streams(self):
        captured = {}

        class ProbeStream(_NonSeekableShortWrite):
            def write(self, data):
                count = super().write(data)
                if self._offset >= 40 and 'version' not in captured:
                    raw = self._sink.getvalue()
                    header = struct.unpack(
                        zipfile.structFileHeader,
                        raw[:zipfile.sizeFileHeader],
                    )
                    name_len = header[zipfile._FH_FILENAME_LENGTH]
                    extra_len = header[zipfile._FH_EXTRA_FIELD_LENGTH]
                    extra = raw[zipfile.sizeFileHeader + name_len:
                                zipfile.sizeFileHeader + name_len + extra_len]
                    captured['version'] = _parse_aes_extra(extra)['version']
                return count

        sink = io.BytesIO()
        with zipfile_aes.AESZipFile(ProbeStream(sink), 'w') as zipfp:
            zipfp.setpassword(self.pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                force_wz_aes_version=zipfile_aes.WZ_AES_V1,
            )
            with zipfp.open('forced.bin', 'w') as zfout:
                zfout.write(b'y' * 300)

        self.assertEqual(captured['version'], zipfile_aes.WZ_AES_V1)
        entries = _parse_archive(sink.getvalue())
        self.assertEqual(entries['forced.bin']['local']['aes']['version'], 1)
        self.assertEqual(entries['forced.bin']['central']['aes']['version'], 1)

    def test_large_member_is_streamed_not_buffered(self):
        # The largest single sink write stays bounded regardless of member
        # size, proving the member is not accumulated before being emitted.
        max_write_seen = 0

        class TrackingSink:
            def write(self, data):
                nonlocal max_write_seen
                max_write_seen = max(max_write_seen, len(data))
                self.buffer = getattr(self, 'buffer', bytearray())
                self.buffer.extend(data)
                return len(data)

            def flush(self):
                pass

        tracking_sink = TrackingSink()
        data = b'abcdefgh' * (1 << 18)  # 2 MiB
        with zipfile_aes.AESZipFile(
                _NonSeekableShortWrite(tracking_sink, max_write=1024),
                'w') as zipfp:
            zipfp.setpassword(self.pwd)
            zipfp.setencryption(zipfile_aes.WZ_AES)
            with zipfp.open('huge.bin', 'w') as zfout:
                for index in range(0, len(data), 4096):
                    zfout.write(data[index:index + 4096])

        self.assertLessEqual(max_write_seen, 1024)
        with zipfile_aes.AESZipFile(
                io.BytesIO(bytes(tracking_sink.buffer))) as zipfp:
            zipfp.setpassword(self.pwd)
            self.assertEqual(zipfp.read('huge.bin'), data)

    def test_finalize_rejects_version_drift_on_unseekable_stream(self):
        encrypter = zipfile_aes.AESZipEncrypter(self.pwd)
        zinfo = zipfile_aes.AESZipInfo('drift.bin')
        zinfo.compress_type = zipfile.ZIP_STORED
        zinfo.file_size = 0
        encrypter.update_zipinfo(zinfo, seekable=False)
        frozen = zinfo.wz_aes_version
        zinfo.wz_aes_version = (
            zipfile_aes.WZ_AES_V1
            if frozen == zipfile_aes.WZ_AES_V2
            else zipfile_aes.WZ_AES_V2
        )
        with self.assertRaises(RuntimeError):
            encrypter.finalize_zipinfo(zinfo, seekable=False)

    def test_seekable_output_keeps_existing_recompute_behaviour(self):
        # On seekable output the local header is rewritten at close, so an
        # unknown-size member may still become AE-1 once its size is known.
        sink = io.BytesIO()
        with zipfile_aes.AESZipFile(sink, 'w') as zipfp:
            zipfp.setpassword(self.pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=True,
                min_bytes_to_include_crc=self.min_bytes_to_include_crc,
            )
            with zipfp.open('member.bin', 'w') as zfout:
                zfout.write(b'a' * 100)

        with zipfile_aes.AESZipFile(io.BytesIO(sink.getvalue())) as zipfp:
            zipfp.setpassword(self.pwd)
            zinfo = zipfp.getinfo('member.bin')
            self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V1)
            self.assertEqual(zinfo.CRC, zipfile.crc32(b'a' * 100))
            self.assertEqual(zipfp.read('member.bin'), b'a' * 100)

    def test_seekable_small_member_remains_ae2(self):
        sink = io.BytesIO()
        with zipfile_aes.AESZipFile(sink, 'w') as zipfp:
            zipfp.setpassword(self.pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                conditionally_include_crc=True,
                min_bytes_to_include_crc=self.min_bytes_to_include_crc,
            )
            zipfp.writestr('small.bin', b'a' * 5)

        with zipfile_aes.AESZipFile(io.BytesIO(sink.getvalue())) as zipfp:
            zipfp.setpassword(self.pwd)
            zinfo = zipfp.getinfo('small.bin')
            self.assertEqual(zinfo.wz_aes_version, zipfile_aes.WZ_AES_V2)
            self.assertEqual(zinfo.CRC, 0)


@requires_pycrypto
@requires_lzma
class WZAESLZMATests(unittest.TestCase):
    def tearDown(self):
        try:
            unlink(TESTFN)
        except FileNotFoundError:
            pass

    def test_lzma_files(self):
        """End of stream marker is used in HMAC.

        This is a test for the end of stream marker. We read one byte at a time
        so that we've consumed all 'file_size' bytes but the end of stream
        marker remains unread (_compress_left != 0).
        """
        expected_content = b"Test"
        fname = "test.txt"

        with zipfile_aes.AESZipFile(
            TESTFN,
            "w",
            compression=zipfile.ZIP_LZMA,
            encryption=zipfile_aes.WZ_AES,
        ) as zipfp:
            zipfp.setpassword(b"super secret")
            zipfp.writestr(fname, expected_content)

        with zipfile_aes.AESZipFile(
            TESTFN,
            compression=zipfile.ZIP_LZMA,
            encryption=zipfile_aes.WZ_AES,
        ) as zipfp:
            zipfp.setpassword(b"super secret")
            with zipfp.open(fname) as zf:
                # read 1 byte at a time from the zipped stream
                zf.MIN_READ_SIZE = 1
                content_out = b""
                char = zf.read(1)
                while char:
                    content_out += char
                    char = zf.read(1)
                self.assertEqual(content_out, expected_content)


class AbstractTestsWithRandomBinaryFiles:
    compression = None
    encryption = None
    pwd = None
    encryption_kwargs = None

    @classmethod
    def setUpClass(cls):
        datacount = randint(16, 64)*1024 + randint(1, 1024)
        cls.data = b''.join(struct.pack('<f', random()*randint(-1000, 1000))
                            for i in range(datacount))

    def setUp(self):
        # Make a source file with some lines
        with open(TESTFN, "wb") as fp:
            fp.write(self.data)

    def tearDown(self):
        unlink(TESTFN)
        unlink(TESTFN2)

    def set_pwd_if_needed(self, zipfp):
        if self.encryption and self.pwd:
            zipfp.setpassword(self.pwd)

    def make_test_archive(self, f, compression):
        # Create the ZIP archive
        with zipfile_aes.AESZipFile(f, "w", compression) as zipfp:
            if self.encryption:
                if self.pwd:
                    zipfp.setpassword(self.pwd)
                if self.encryption_kwargs:
                    encryption_kwargs = self.encryption_kwargs
                else:
                    encryption_kwargs = {}
                zipfp.setencryption(
                    self.encryption,
                    **encryption_kwargs
                )
            zipfp.write(TESTFN, "another.name")
            zipfp.write(TESTFN, TESTFN)

    def zip_test(self, f, compression):
        self.make_test_archive(f, compression)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            testdata = zipfp.read(TESTFN)
            self.assertEqual(len(testdata), len(self.data))
            self.assertEqual(testdata, self.data)
            self.assertEqual(zipfp.read("another.name"), self.data)

    def test_read(self):
        for f in get_files(self):
            self.zip_test(f, self.compression)

    def zip_open_test(self, f, compression):
        self.make_test_archive(f, compression)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zipdata1 = []
            with zipfp.open(TESTFN) as zipopen1:
                while True:
                    read_data = zipopen1.read(256)
                    if not read_data:
                        break
                    zipdata1.append(read_data)

            zipdata2 = []
            with zipfp.open("another.name") as zipopen2:
                while True:
                    read_data = zipopen2.read(256)
                    if not read_data:
                        break
                    zipdata2.append(read_data)

            testdata1 = b''.join(zipdata1)
            self.assertEqual(len(testdata1), len(self.data))
            self.assertEqual(testdata1, self.data)

            testdata2 = b''.join(zipdata2)
            self.assertEqual(len(testdata2), len(self.data))
            self.assertEqual(testdata2, self.data)

    def test_open(self):
        for f in get_files(self):
            self.zip_open_test(f, self.compression)

    def zip_random_open_test(self, f, compression):
        self.make_test_archive(f, compression)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zipdata1 = []
            with zipfp.open(TESTFN) as zipopen1:
                while True:
                    read_data = zipopen1.read(randint(1, 1024))
                    if not read_data:
                        break
                    zipdata1.append(read_data)

            testdata = b''.join(zipdata1)
            self.assertEqual(len(testdata), len(self.data))
            self.assertEqual(testdata, self.data)

    def test_random_open(self):
        for f in get_files(self):
            self.zip_random_open_test(f, self.compression)


@requires_pycrypto
class WZAESStoredTestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                            unittest.TestCase):
    compression = zipfile.ZIP_STORED
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


@requires_pycrypto
@requires_zlib
class WZAESDeflateTestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                             unittest.TestCase):
    compression = zipfile.ZIP_DEFLATED
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


@requires_pycrypto
@requires_bz2
class WZAESBzip2TestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                           unittest.TestCase):
    compression = zipfile.ZIP_BZIP2
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


@requires_pycrypto
@requires_lzma
class WZAESLzmaTestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                          unittest.TestCase):
    compression = zipfile.ZIP_LZMA
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


class AbstractTestZip64InSmallFiles:
    # These tests test the ZIP64 functionality without using large files,
    # see test_zipfile64 for proper tests.

    @classmethod
    def setUpClass(cls):
        line_gen = (bytes("Test of zipfile line %d." % i, "ascii")
                    for i in range(0, FIXEDTEST_SIZE))
        cls.data = b'\n'.join(line_gen)

    def setUp(self):
        self._limit = zipfile.ZIP64_LIMIT
        self._filecount_limit = zipfile.ZIP_FILECOUNT_LIMIT
        zipfile.ZIP64_LIMIT = 1000
        zipfile.ZIP_FILECOUNT_LIMIT = 9

        # Make a source file with some lines
        with open(TESTFN, "wb") as fp:
            fp.write(self.data)

    def set_pwd_if_needed(self, zipfp):
        if self.encryption and self.pwd:
            zipfp.setpassword(self.pwd)

    def start_encryption(self, zipfp):
        if self.encryption:
            if self.pwd:
                zipfp.setpassword(self.pwd)
                if self.encryption_kwargs:
                    encryption_kwargs = self.encryption_kwargs
                else:
                    encryption_kwargs = {}
                zipfp.setencryption(
                    self.encryption,
                    **encryption_kwargs
                )

    def zip_test(self, f, compression):
        # Create the ZIP archive
        with zipfile_aes.AESZipFile(f, "w", compression, allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.write(TESTFN, "another.name")
            zipfp.write(TESTFN, TESTFN)
            zipfp.writestr("strfile", self.data)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            self.assertEqual(zipfp.read(TESTFN), self.data)
            self.assertEqual(zipfp.read("another.name"), self.data)
            self.assertEqual(zipfp.read("strfile"), self.data)

            # Print the ZIP directory
            fp = io.StringIO()
            zipfp.printdir(fp)

            directory = fp.getvalue()
            lines = directory.splitlines()
            self.assertEqual(len(lines), 4) # Number of files + header

            self.assertIn('File Name', lines[0])
            self.assertIn('Modified', lines[0])
            self.assertIn('Size', lines[0])

            fn, date, time_, size = lines[1].split()
            self.assertEqual(fn, 'another.name')
            self.assertTrue(time.strptime(date, '%Y-%m-%d'))
            self.assertTrue(time.strptime(time_, '%H:%M:%S'))
            self.assertEqual(size, str(len(self.data)))

            # Check the namelist
            names = zipfp.namelist()
            self.assertEqual(len(names), 3)
            self.assertIn(TESTFN, names)
            self.assertIn("another.name", names)
            self.assertIn("strfile", names)

            # Check infolist
            infos = zipfp.infolist()
            names = [i.filename for i in infos]
            self.assertEqual(len(names), 3)
            self.assertIn(TESTFN, names)
            self.assertIn("another.name", names)
            self.assertIn("strfile", names)
            for i in infos:
                self.assertEqual(i.file_size, len(self.data))

            # check getinfo
            for nm in (TESTFN, "another.name", "strfile"):
                info = zipfp.getinfo(nm)
                self.assertEqual(info.filename, nm)
                self.assertEqual(info.file_size, len(self.data))

            # Check that testzip doesn't raise an exception
            zipfp.testzip()

    def test_basic(self):
        for f in get_files(self):
            self.zip_test(f, self.compression)

    def test_too_many_files(self):
        # This test checks that more than 64k files can be added to an archive,
        # and that the resulting archive can be read properly by ZipFile
        zipf = zipfile_aes.AESZipFile(TESTFN, "w", self.compression,
                                      allowZip64=True)
        zipf.debug = 100
        numfiles = 15
        for i in range(numfiles):
            zipf.writestr("foo%08d" % i, "%d" % (i**3 % 57))
        self.assertEqual(len(zipf.namelist()), numfiles)
        zipf.close()

        zipf2 = zipfile_aes.AESZipFile(TESTFN, "r", self.compression)
        self.assertEqual(len(zipf2.namelist()), numfiles)
        for i in range(numfiles):
            content = zipf2.read("foo%08d" % i).decode('ascii')
            self.assertEqual(content, "%d" % (i**3 % 57))
        zipf2.close()

    def test_too_many_files_append(self):
        zipf = zipfile_aes.AESZipFile(TESTFN, "w", self.compression,
                                      allowZip64=False)
        zipf.debug = 100
        numfiles = 9
        for i in range(numfiles):
            zipf.writestr("foo%08d" % i, "%d" % (i**3 % 57))
        self.assertEqual(len(zipf.namelist()), numfiles)
        with self.assertRaises(zipfile.LargeZipFile):
            zipf.writestr("foo%08d" % numfiles, b'')
        self.assertEqual(len(zipf.namelist()), numfiles)
        zipf.close()

        zipf = zipfile_aes.AESZipFile(TESTFN, "a", self.compression,
                                      allowZip64=False)
        zipf.debug = 100
        self.assertEqual(len(zipf.namelist()), numfiles)
        with self.assertRaises(zipfile.LargeZipFile):
            zipf.writestr("foo%08d" % numfiles, b'')
        self.assertEqual(len(zipf.namelist()), numfiles)
        zipf.close()

        zipf = zipfile_aes.AESZipFile(TESTFN, "a", self.compression,
                                      allowZip64=True)
        zipf.debug = 100
        self.assertEqual(len(zipf.namelist()), numfiles)
        numfiles2 = 15
        for i in range(numfiles, numfiles2):
            zipf.writestr("foo%08d" % i, "%d" % (i**3 % 57))
        self.assertEqual(len(zipf.namelist()), numfiles2)
        zipf.close()

        zipf2 = zipfile_aes.AESZipFile(TESTFN, "r", self.compression)
        self.assertEqual(len(zipf2.namelist()), numfiles2)
        for i in range(numfiles2):
            content = zipf2.read("foo%08d" % i).decode('ascii')
            self.assertEqual(content, "%d" % (i**3 % 57))
        zipf2.close()

    def tearDown(self):
        zipfile.ZIP64_LIMIT = self._limit
        zipfile.ZIP_FILECOUNT_LIMIT = self._filecount_limit
        unlink(TESTFN)
        unlink(TESTFN2)


class StoredTestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                  unittest.TestCase):
    compression = zipfile.ZIP_STORED
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'

    def large_file_exception_test(self, f, compression):
        with zipfile_aes.AESZipFile(f, "w", compression, allowZip64=False) as zipfp:
            self.start_encryption(zipfp)
            self.assertRaises(zipfile.LargeZipFile,
                              zipfp.write, TESTFN, "another.name")

    def large_file_exception_test2(self, f, compression):
        with zipfile_aes.AESZipFile(f, "w", compression, allowZip64=False) as zipfp:
            self.start_encryption(zipfp)
            self.assertRaises(zipfile.LargeZipFile,
                              zipfp.writestr, "another.name", self.data)

    def test_large_file_exception(self):
        for f in get_files(self):
            self.large_file_exception_test(f, zipfile.ZIP_STORED)
            self.large_file_exception_test2(f, zipfile.ZIP_STORED)

    def test_absolute_arcnames(self):
        with zipfile_aes.AESZipFile(TESTFN2, "w", zipfile.ZIP_STORED,
                                    allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.write(TESTFN, "/absolute")

        with zipfile_aes.AESZipFile(TESTFN2, "r", zipfile.ZIP_STORED) as zipfp:
            self.set_pwd_if_needed(zipfp)
            self.assertEqual(zipfp.namelist(), ["absolute"])

    def test_append(self):
        # Test that appending to the Zip64 archive doesn't change
        # extra fields of existing entries.
        with zipfile_aes.AESZipFile(TESTFN2, "w", allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.writestr("strfile", self.data)
        with zipfile_aes.AESZipFile(TESTFN2, "r", allowZip64=True) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zinfo = zipfp.getinfo("strfile")
            extra = zinfo.extra
        with zipfile_aes.AESZipFile(TESTFN2, "a", allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.writestr("strfile2", self.data)
        with zipfile_aes.AESZipFile(TESTFN2, "r", allowZip64=True) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zinfo = zipfp.getinfo("strfile")
            self.assertEqual(zinfo.extra, extra)


@requires_zlib
class DeflateTestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                   unittest.TestCase):
    compression = zipfile.ZIP_DEFLATED
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'


@requires_bz2
class Bzip2TestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                 unittest.TestCase):
    compression = zipfile.ZIP_BZIP2
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'


@requires_lzma
class LzmaTestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                unittest.TestCase):
    compression = zipfile.ZIP_LZMA
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'


if __name__ == "__main__":
    unittest.main()
