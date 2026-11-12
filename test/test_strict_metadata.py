"""Tests for the strict local-header / central-directory metadata policy.

A ZIP entry stores its security-relevant metadata twice: in the central
directory and again in the local file header. Most readers (including
pyzipper) follow the central directory, but some decompressors follow the
local header. An archive whose two headers disagree can therefore be
interpreted two different ways (different encryption, AES strength or
compression algorithm depending on which tool opens it).

``strict_metadata=True`` rejects those disagreements before any decrypter or
decompressor is selected, while still accepting legitimate data descriptors
and ZIP64 placeholder sizes.
"""
import io
import struct
import unittest
from unittest import mock

from .test_zipfile import Unseekable

from pyzipper import zipfile
from pyzipper import zipfile_aes


PASSWORD = b'this is a test password'
MEMBER = 'test.txt'
CONTENT = b'The quick brown fox jumps over the lazy dog. ' * 8

# Offsets of fields inside the 30-byte local file header.
LOCAL_FLAG_BITS_OFFSET = 6
LOCAL_COMPRESSION_METHOD_OFFSET = 8
LOCAL_CRC_OFFSET = 14
LOCAL_COMPRESSED_SIZE_OFFSET = 18
LOCAL_UNCOMPRESSED_SIZE_OFFSET = 22
LOCAL_FILENAME_LENGTH_OFFSET = 26
LOCAL_EXTRA_LENGTH_OFFSET = 28


try:
    import Cryptodome
except ImportError:
    Cryptodome = None

requires_pycrypto = unittest.skipUnless(Cryptodome, 'requires pycryptodomex')


def parse_local_header(blob):
    """Return (header tuple, extra field bytes, extra field start offset)."""
    if blob[:4] != zipfile.stringFileHeader:
        raise AssertionError('archive does not start with a local header')
    header = struct.unpack(
        zipfile.structFileHeader, blob[:zipfile.sizeFileHeader])
    data_start = (
        zipfile.sizeFileHeader + header[zipfile._FH_FILENAME_LENGTH])
    extra = blob[
        data_start:data_start + header[zipfile._FH_EXTRA_FIELD_LENGTH]]
    return header, extra, data_start


def iter_extra_fields(extra, base_offset):
    offset = 0
    while offset + 4 <= len(extra):
        xid, xlen = struct.unpack('<HH', extra[offset:offset + 4])
        yield xid, base_offset + offset, xlen
        offset += 4 + xlen


def find_aes_extra_offset(blob):
    _, extra, base = parse_local_header(blob)
    for xid, absolute_offset, _ in iter_extra_fields(extra, base):
        if xid == zipfile_aes.EXTRA_WZ_AES:
            return absolute_offset
    raise AssertionError('no WZ-AES extra field in local header')


def build_aes_archive(*, force_wz_aes_version,
                      compression=zipfile.ZIP_DEFLATED,
                      descriptor=False):
    buf = io.BytesIO()
    target = Unseekable(buf) if descriptor else buf
    with zipfile_aes.AESZipFile(target, 'w', compression=compression) as zf:
        zf.setpassword(PASSWORD)
        zf.setencryption(
            zipfile_aes.WZ_AES,
            force_wz_aes_version=force_wz_aes_version,
        )
        zf.writestr(MEMBER, CONTENT)
    return buf.getvalue()


def build_zip64_aes_archive():
    """An AES archive whose local header carries ZIP64 placeholder sizes."""
    previous_limit = zipfile.ZIP64_LIMIT
    zipfile.ZIP64_LIMIT = 100
    try:
        return build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
    finally:
        zipfile.ZIP64_LIMIT = previous_limit


def build_plain_archive(*, descriptor=False):
    buf = io.BytesIO()
    target = Unseekable(buf) if descriptor else buf
    with zipfile.ZipFile(target, 'w',
                         compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MEMBER, CONTENT)
    return buf.getvalue()


class StrictMetadataBase:

    reader_cls = None

    def open_reader(self, blob, *, strict):
        kwargs = {'strict_metadata': True} if strict else {}
        return self.reader_cls(io.BytesIO(blob), 'r', **kwargs)

    def assert_rejected_strict(self, blob, *message_parts):
        with self.assertRaises(zipfile.BadZipFile) as context:
            with self.open_reader(blob, strict=True) as zf:
                zf.read(MEMBER, pwd=PASSWORD)
        message = str(context.exception)
        for part in message_parts:
            self.assertIn(part, message)
        # The error must point at both declaration locations.
        self.assertIn('central directory', message)
        self.assertIn('local file header', message)


@requires_pycrypto
class StrictMetadataAcceptanceTests(StrictMetadataBase, unittest.TestCase):
    """Well-formed archives must keep reading correctly in strict mode."""

    reader_cls = zipfile_aes.AESZipFile

    def test_ae1_and_ae2_roundtrip(self):
        for version in (zipfile_aes.WZ_AES_V1, zipfile_aes.WZ_AES_V2):
            with self.subTest(version=version):
                blob = build_aes_archive(force_wz_aes_version=version)
                with self.open_reader(blob, strict=True) as zf:
                    self.assertEqual(
                        zf.read(MEMBER, pwd=PASSWORD), CONTENT)

    def test_data_descriptor_accepted(self):
        # Flag bit 3 makes the local CRC and sizes legitimate zero
        # placeholders; strict mode must not treat that as a conflict.
        blob = build_aes_archive(
            force_wz_aes_version=zipfile_aes.WZ_AES_V2, descriptor=True)
        header, _, _ = parse_local_header(blob)
        self.assertTrue(
            header[zipfile._FH_GENERAL_PURPOSE_FLAG_BITS]
            & zipfile._MASK_USE_DATA_DESCRIPTOR)
        self.assertEqual(header[zipfile._FH_CRC], 0)
        self.assertEqual(header[zipfile._FH_COMPRESSED_SIZE], 0)
        self.assertEqual(header[zipfile._FH_UNCOMPRESSED_SIZE], 0)
        with self.open_reader(blob, strict=True) as zf:
            self.assertEqual(
                zf.read(MEMBER, pwd=PASSWORD), CONTENT)

    def test_zip64_placeholder_sizes_accepted(self):
        blob = build_zip64_aes_archive()
        header, _, _ = parse_local_header(blob)
        self.assertEqual(header[zipfile._FH_COMPRESSED_SIZE], 0xFFFFFFFF)
        self.assertEqual(header[zipfile._FH_UNCOMPRESSED_SIZE], 0xFFFFFFFF)
        with self.open_reader(blob, strict=True) as zf:
            self.assertEqual(
                zf.read(MEMBER, pwd=PASSWORD), CONTENT)

    def test_default_interface_is_not_strict(self):
        # The default compatible interface keeps its historical behaviour:
        # the central directory is the sole source of truth and the strict
        # cross-check is not performed.
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        aes_offset = find_aes_extra_offset(blob)
        mutated = bytearray(blob)
        mutated[aes_offset + 4:aes_offset + 6] = struct.pack(
            '<H', zipfile_aes.WZ_AES_V2)
        with zipfile_aes.AESZipFile(io.BytesIO(bytes(mutated))) as zf:
            self.assertEqual(
                zf.read(MEMBER, pwd=PASSWORD), CONTENT)


@requires_pycrypto
class StrictMetadataRejectionTests(StrictMetadataBase, unittest.TestCase):
    """Each variant mutates exactly one local-header field of one archive."""

    reader_cls = zipfile_aes.AESZipFile

    def assert_no_algorithm_selected(self, blob):
        # The conflict must be raised before a decrypter or decompressor is
        # instantiated, so the wrong algorithm can never be started.
        with mock.patch.object(
                zipfile_aes.AESZipExtFile,
                'setup_aeszipdecrypter',
                side_effect=AssertionError('AES decrypter must not start')
        ) as setup_decrypter, mock.patch.object(
                zipfile.ZipExtFile,
                'get_decompressor',
                side_effect=AssertionError('decompressor must not start')
        ) as get_decompressor:
            with self.assertRaises(zipfile.BadZipFile):
                with self.open_reader(blob, strict=True) as zf:
                    zf.read(MEMBER, pwd=PASSWORD)
        setup_decrypter.assert_not_called()
        get_decompressor.assert_not_called()

    def test_local_aes_version_conflict(self):
        # Central directory says AE-1, local header says AE-2 (or vice versa).
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        aes_offset = find_aes_extra_offset(blob)
        mutated = bytearray(blob)
        mutated[aes_offset + 4:aes_offset + 6] = struct.pack(
            '<H', zipfile_aes.WZ_AES_V2)
        self.assert_rejected_strict(
            bytes(mutated), 'WZ-AES version')
        self.assert_no_algorithm_selected(bytes(mutated))

    def test_local_aes_strength_conflict(self):
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        aes_offset = find_aes_extra_offset(blob)
        strength_offset = aes_offset + 4 + 4  # H version + 2s vendor
        mutated = bytearray(blob)
        original = mutated[strength_offset]
        mutated[strength_offset] = 1 if original == 3 else 3
        self.assert_rejected_strict(
            bytes(mutated), 'WZ-AES encryption strength')
        self.assert_no_algorithm_selected(bytes(mutated))

    def test_local_aes_actual_compression_conflict(self):
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        aes_offset = find_aes_extra_offset(blob)
        method_offset = aes_offset + 4 + 5  # H version + 2s vendor + B strength
        mutated = bytearray(blob)
        mutated[method_offset:method_offset + 2] = struct.pack(
            '<H', zipfile.ZIP_STORED)
        self.assert_rejected_strict(
            bytes(mutated), 'actual compression method')
        self.assert_no_algorithm_selected(bytes(mutated))

    def test_local_header_compression_marker_conflict(self):
        # Local header drops the 99 WZ-AES marker, central keeps it.
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        mutated = bytearray(blob)
        mutated[LOCAL_COMPRESSION_METHOD_OFFSET:
                LOCAL_COMPRESSION_METHOD_OFFSET + 2] = struct.pack(
            '<H', zipfile.ZIP_DEFLATED)
        self.assert_rejected_strict(
            bytes(mutated), 'compression method', '99')
        self.assert_no_algorithm_selected(bytes(mutated))

    def test_local_encryption_flag_conflict(self):
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        mutated = bytearray(blob)
        mutated[LOCAL_FLAG_BITS_OFFSET] &= ~zipfile._MASK_ENCRYPTED
        self.assert_rejected_strict(
            bytes(mutated), 'encryption flag')
        self.assert_no_algorithm_selected(bytes(mutated))

    def test_local_filename_conflict(self):
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        mutated = bytearray(blob)
        mutated[zipfile.sizeFileHeader] = ord('X')
        # Filename mismatch is rejected regardless of the strict policy.
        with self.assertRaises(zipfile.BadZipFile) as context:
            with self.open_reader(bytes(mutated), strict=True) as zf:
                zf.read(MEMBER, pwd=PASSWORD)
        self.assertIn('File name in directory', str(context.exception))
        self.assert_no_algorithm_selected(bytes(mutated))

    def test_local_crc_conflict(self):
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        header, _, _ = parse_local_header(blob)
        mutated = bytearray(blob)
        bad_crc = (header[zipfile._FH_CRC] + 1) & 0xFFFFFFFF
        mutated[LOCAL_CRC_OFFSET:LOCAL_CRC_OFFSET + 4] = struct.pack(
            '<I', bad_crc)
        self.assert_rejected_strict(bytes(mutated), 'CRC-32')

    def test_local_uncompressed_size_conflict(self):
        blob = build_aes_archive(force_wz_aes_version=zipfile_aes.WZ_AES_V1)
        header, _, _ = parse_local_header(blob)
        mutated = bytearray(blob)
        mutated[LOCAL_UNCOMPRESSED_SIZE_OFFSET:
                LOCAL_UNCOMPRESSED_SIZE_OFFSET + 4] = struct.pack(
            '<I', header[zipfile._FH_UNCOMPRESSED_SIZE] + 1)
        self.assert_rejected_strict(
            bytes(mutated), 'uncompressed size')

    def test_zip64_placeholder_without_local_zip64_extra(self):
        blob = build_zip64_aes_archive()
        _, extra, base = parse_local_header(blob)
        zip64_offset = None
        for xid, absolute_offset, _ in iter_extra_fields(extra, base):
            if xid == zipfile.EXTRA_ZIP64:
                zip64_offset = absolute_offset
        self.assertIsNotNone(zip64_offset)
        mutated = bytearray(blob)
        # Relabel the local ZIP64 extra field as unknown while keeping the
        # header layout intact, so the 0xFFFFFFFF placeholders cannot be
        # resolved.
        mutated[zip64_offset:zip64_offset + 2] = struct.pack('<H', 0x7777)
        with self.assertRaises(zipfile.BadZipFile) as context:
            with self.open_reader(bytes(mutated), strict=True) as zf:
                zf.read(MEMBER, pwd=PASSWORD)
        self.assertIn('ZIP64 size placeholder', str(context.exception))

    def test_zip64_extra_size_conflict(self):
        blob = build_zip64_aes_archive()
        _, extra, base = parse_local_header(blob)
        zip64_offset = None
        for xid, absolute_offset, _ in iter_extra_fields(extra, base):
            if xid == zipfile.EXTRA_ZIP64:
                zip64_offset = absolute_offset
        mutated = bytearray(blob)
        # Local ZIP64 extra: tag(H) length(H) file_size(Q) compress_size(Q).
        file_size_offset = zip64_offset + 4
        mutated[file_size_offset:file_size_offset + 8] = struct.pack(
            '<Q', len(CONTENT) + 7)
        self.assert_rejected_strict(
            bytes(mutated), 'uncompressed size')


class StrictPlainZipTests(StrictMetadataBase, unittest.TestCase):
    """Strict checks also apply to non-AES archives."""

    reader_cls = zipfile.ZipFile

    def test_plain_archive_accepted(self):
        blob = build_plain_archive()
        with self.open_reader(blob, strict=True) as zf:
            self.assertEqual(zf.read(MEMBER), CONTENT)

    def test_plain_data_descriptor_accepted(self):
        blob = build_plain_archive(descriptor=True)
        header, _, _ = parse_local_header(blob)
        self.assertEqual(header[zipfile._FH_UNCOMPRESSED_SIZE], 0)
        with self.open_reader(blob, strict=True) as zf:
            self.assertEqual(zf.read(MEMBER), CONTENT)

    def test_plain_compression_method_conflict(self):
        blob = build_plain_archive()
        mutated = bytearray(blob)
        mutated[LOCAL_COMPRESSION_METHOD_OFFSET:
                LOCAL_COMPRESSION_METHOD_OFFSET + 2] = struct.pack(
            '<H', zipfile.ZIP_STORED)
        self.assert_rejected_strict(
            bytes(mutated), 'compression method')

    def test_plain_encryption_flag_conflict(self):
        blob = build_plain_archive()
        mutated = bytearray(blob)
        mutated[LOCAL_FLAG_BITS_OFFSET] |= zipfile._MASK_ENCRYPTED
        self.assert_rejected_strict(
            bytes(mutated), 'encryption flag')


if __name__ == '__main__':
    unittest.main()
