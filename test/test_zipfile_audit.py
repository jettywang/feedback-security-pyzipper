import io
import struct
import unittest

import pyzipper
from pyzipper import zipfile as pyzipzipfile

try:
    import Cryptodome
except ImportError:
    Cryptodome = None

requires_pycrypto = unittest.skipUnless(Cryptodome, 'requires pycryptodomex')

PASSWORD = b'topsecret'

CENTRAL_STRUCT = '<4s4B4HL2L5H2L'
EOCD_STRUCT = '<4s4H2LH'
LOCAL_STRUCT = '<4s2B4HL2L2H'
SIZE_CENTRAL = struct.calcsize(CENTRAL_STRUCT)
SIZE_LOCAL = struct.calcsize(LOCAL_STRUCT)

CD_FLAG_BITS = 5
CD_COMPRESS_SIZE = 10
CD_FILENAME_LENGTH = 12
CD_EXTRA_LENGTH = 13
CD_COMMENT_LENGTH = 14
CD_HEADER_OFFSET = 18

FH_FILENAME_LENGTH = 10
FH_EXTRA_LENGTH = 11


class Unseekable:
    def __init__(self, fp):
        self.fp = fp

    def write(self, data):
        return self.fp.write(data)

    def flush(self):
        self.fp.flush()


def build_mixed_archive(seekable=True):
    """AES-encrypted, deflated-plain and stored members, tightly packed."""
    raw = io.BytesIO()
    fp = raw if seekable else Unseekable(raw)
    with pyzipper.AESZipFile(fp, 'w', compression=pyzipper.ZIP_DEFLATED) as zf:
        zf.setpassword(PASSWORD)
        zf.setencryption(pyzipper.WZ_AES, nbits=128)
        zf.writestr('aes.txt', b'aes-secret-' * 12)
        zf.setencryption(None)
        zf.setpassword(None)
        zf.writestr('plain.txt', b'plain-data-' * 12)
        zf.writestr('stored.txt', b'stored-data-' * 12,
                    compress_type=pyzipper.ZIP_STORED)
    return raw.getvalue()


def parse_entries(data):
    eocd_at = data.rfind(b'PK\x05\x06')
    eocd = struct.unpack_from(EOCD_STRUCT, data, eocd_at)
    cd_size, cd_offset, count = eocd[5], eocd[6], eocd[4]
    entries = []
    pos = cd_offset
    for _ in range(count):
        fields = list(struct.unpack_from(CENTRAL_STRUCT, data, pos))
        name_len = fields[CD_FILENAME_LENGTH]
        extra_len = fields[CD_EXTRA_LENGTH]
        comment_len = fields[CD_COMMENT_LENGTH]
        entries.append({
            'fields': fields,
            'name': data[pos + SIZE_CENTRAL:pos + SIZE_CENTRAL + name_len],
            'extra': data[pos + SIZE_CENTRAL + name_len:
                          pos + SIZE_CENTRAL + name_len + extra_len],
            'comment': data[pos + SIZE_CENTRAL + name_len + extra_len:
                            pos + SIZE_CENTRAL + name_len + extra_len
                            + comment_len],
        })
        pos += SIZE_CENTRAL + name_len + extra_len + comment_len
    assert pos == cd_offset + cd_size
    return cd_offset, entries


def rebuild_zip(data, transform):
    """Rewrite the central directory of ``data`` after ``transform`` edits
    the parsed entries. Member payloads are left untouched."""
    cd_offset, entries = parse_entries(data)
    entries = transform(entries)
    central = bytearray()
    for entry in entries:
        entry['fields'][CD_FILENAME_LENGTH] = len(entry['name'])
        entry['fields'][CD_EXTRA_LENGTH] = len(entry['extra'])
        entry['fields'][CD_COMMENT_LENGTH] = len(entry['comment'])
        central += struct.pack(CENTRAL_STRUCT, *entry['fields'])
        central += entry['name'] + entry['extra'] + entry['comment']
    prefix = data[:cd_offset]
    eocd = struct.pack(EOCD_STRUCT, b'PK\x05\x06', 0, 0,
                       len(entries), len(entries),
                       len(central), len(prefix), 0)
    return prefix + bytes(central) + eocd


def copy_entry(entry):
    return {'fields': list(entry['fields']), 'name': entry['name'],
            'extra': entry['extra'], 'comment': entry['comment']}


def local_data_start(data, header_offset):
    fields = struct.unpack_from(LOCAL_STRUCT, data, header_offset)
    return (header_offset + SIZE_LOCAL
            + fields[FH_FILENAME_LENGTH] + fields[FH_EXTRA_LENGTH])


def make_alias_archive(data):
    """Two central directory entries sharing one local header offset."""
    def transform(entries):
        alias = copy_entry(entries[0])
        alias['name'] = b'alias.txt'
        return [entries[0], alias] + entries[1:]
    return rebuild_zip(data, transform)


def make_payload_overlap_archive(data):
    """First member's declared payload extends into the second member."""
    cd_offset, entries = parse_entries(data)
    first = entries[0]['fields']
    second_offset = entries[1]['fields'][CD_HEADER_OFFSET]
    data_start = local_data_start(data, first[CD_HEADER_OFFSET])
    # Extend the first member's compressed size so its payload swallows
    # the second member's local header and part of its payload.
    first[CD_COMPRESS_SIZE] = second_offset + 40 - data_start

    def transform(entries):
        entries[0]['fields'][CD_COMPRESS_SIZE] = first[CD_COMPRESS_SIZE]
        return entries
    return rebuild_zip(data, transform)


def make_header_pointing_archive(data):
    """Second member's header offset points inside the first member's
    local header."""
    def transform(entries):
        entries[1]['fields'][CD_HEADER_OFFSET] = (
            entries[0]['fields'][CD_HEADER_OFFSET] + 5)
        return entries
    return rebuild_zip(data, transform)


def make_negative_length_archive(data):
    """AES member whose declared size is smaller than its encryption
    framing (salt + password verifier + HMAC)."""
    def transform(entries):
        entries[0]['fields'][CD_COMPRESS_SIZE] = 5
        return entries
    return rebuild_zip(data, transform)


def make_out_of_bounds_archive(data):
    def transform(entries):
        entries[0]['fields'][CD_COMPRESS_SIZE] = len(data) * 4
        return entries
    return rebuild_zip(data, transform)


class TrackingIO:
    """File-like wrapper recording the offset/length of every read."""

    def __init__(self, raw):
        self.raw = raw
        self.reads = []

    def seek(self, *args):
        return self.raw.seek(*args)

    def tell(self):
        return self.raw.tell()

    def seekable(self):
        return True

    def read(self, n=-1):
        pos = self.raw.tell()
        data = self.raw.read(n)
        self.reads.append((pos, len(data)))
        return data


@requires_pycrypto
class MemberSpanLayoutTests(unittest.TestCase):

    def test_segments_distinguish_member_boundaries(self):
        data = build_mixed_archive()
        with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
            audit = zf.audit_member_spans()
            self.assertTrue(audit.ok, audit.problem_summary())
            spans = {span.zinfo.filename: span for span in audit.spans}

            aes = spans['aes.txt']
            # 128-bit AES: 8 byte salt + 2 byte verifier, 10 byte HMAC.
            self.assertEqual(
                aes.encryption_header[1] - aes.encryption_header[0], 10)
            self.assertEqual(
                aes.auth_trailer[1] - aes.auth_trailer[0], 10)
            self.assertEqual(aes.encryption_header[0], aes.name_extra[1])
            self.assertEqual(aes.payload[0], aes.encryption_header[1])
            self.assertEqual(aes.auth_trailer[0], aes.payload[1])
            self.assertEqual(aes.end, aes.auth_trailer[1])
            self.assertIsNone(aes.descriptor)

            stored = spans['stored.txt']
            self.assertIsNone(stored.encryption_header)
            self.assertIsNone(stored.auth_trailer)
            self.assertEqual(stored.payload[0], stored.name_extra[1])
            self.assertEqual(
                stored.payload[1] - stored.payload[0],
                len(b'stored-data-' * 12))

            # Every segment boundary is contiguous within a member.
            for span in spans.values():
                self.assertEqual(span.header[0], span.start)
                self.assertEqual(span.header[1], span.name_extra[0])
                segments = [getattr(span, name)
                            for name in span._SEGMENT_NAMES]
                segments = [s for s in segments if s is not None]
                for left, right in zip(segments, segments[1:]):
                    self.assertEqual(left[1], right[0])
                self.assertEqual(segments[-1][1], span.end)

            # Members are tightly packed and cover everything up to the
            # central directory.
            ordered = sorted(audit.spans, key=lambda span: span.start)
            for left, right in zip(ordered, ordered[1:]):
                self.assertEqual(left.end, right.start)
            self.assertEqual(ordered[-1].end, zf.start_dir)

    def test_data_descriptor_boundaries(self):
        data = build_mixed_archive(seekable=False)
        with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
            audit = zf.audit_member_spans()
            self.assertTrue(audit.ok, audit.problem_summary())
            for span in audit.spans:
                self.assertTrue(span.zinfo.use_datadescripter)
                self.assertIsNotNone(span.descriptor)
                # pyzipper writes a signed 16-byte data descriptor.
                self.assertEqual(
                    span.descriptor[1] - span.descriptor[0], 16)
                self.assertEqual(span.descriptor[1], span.end)
            ordered = sorted(audit.spans, key=lambda span: span.start)
            for left, right in zip(ordered, ordered[1:]):
                self.assertEqual(left.end, right.start)
            self.assertEqual(ordered[-1].end, zf.start_dir)

    def test_precheck_does_not_read_payloads(self):
        data = build_mixed_archive()
        tracker = TrackingIO(io.BytesIO(data))
        with pyzipper.AESZipFile(tracker) as zf:
            tracker.reads.clear()
            audit = zf.audit_member_spans()
            self.assertTrue(audit.ok, audit.problem_summary())
            payloads = [span.payload for span in audit.spans]
            for offset, length in tracker.reads:
                for start, end in payloads:
                    self.assertFalse(
                        offset < end and offset + length > start,
                        'precheck read payload bytes [%d, %d)' % (
                            max(offset, start), min(offset + length, end)))


@requires_pycrypto
class MemberSpanConflictTests(unittest.TestCase):

    def open_audit(self, data):
        zf = pyzipper.AESZipFile(io.BytesIO(data))
        return zf, zf.audit_member_spans()

    def test_legal_adjacent_members_pass(self):
        data = build_mixed_archive()
        with pyzipper.AESZipFile(
                io.BytesIO(data), strict_member_spans=True) as zf:
            audit = zf.check_member_spans(strict=True)
            self.assertTrue(audit.ok)
            self.assertEqual(audit.conflicts, [])
            self.assertEqual(audit.indeterminate, [])
            zf.setpassword(PASSWORD)
            self.assertEqual(zf.read('aes.txt'), b'aes-secret-' * 12)
            self.assertEqual(zf.read('plain.txt'), b'plain-data-' * 12)
            self.assertEqual(zf.read('stored.txt'), b'stored-data-' * 12)

    def test_duplicate_header_offset(self):
        data = make_alias_archive(build_mixed_archive())
        zf, audit = self.open_audit(data)
        with zf:
            self.assertFalse(audit.ok)
            self.assertEqual(len(audit.conflicts), 1)
            conflict = audit.conflicts[0]
            self.assertEqual(
                {m.filename for m in conflict.members},
                {'aes.txt', 'alias.txt'})
            self.assertEqual(conflict.kind, 'header-overlaps-header')
            span = next(s for s in audit.spans
                        if s.zinfo.filename == 'aes.txt')
            self.assertEqual((conflict.start, conflict.end),
                             (span.start, span.end))

            with self.assertRaises(pyzipper.BadZipFile) as cm:
                zf.check_member_spans(strict=True)
            message = str(cm.exception)
            self.assertIn('alias.txt', message)
            self.assertIn('aes.txt', message)
            self.assertIn('[%d, %d)' % (span.start, span.end), message)

    def test_partial_payload_overlap(self):
        data = make_payload_overlap_archive(build_mixed_archive())
        zf, audit = self.open_audit(data)
        with zf:
            self.assertFalse(audit.ok)
            self.assertEqual(len(audit.conflicts), 1)
            conflict = audit.conflicts[0]
            self.assertEqual(
                {m.filename for m in conflict.members},
                {'aes.txt', 'plain.txt'})
            self.assertEqual(conflict.kind, 'payload-overlaps-header')
            plain = next(s for s in audit.spans
                         if s.zinfo.filename == 'plain.txt')
            self.assertEqual(conflict.start, plain.start)
            self.assertGreater(conflict.end, plain.start)

    def test_member_pointing_into_another_header(self):
        data = make_header_pointing_archive(build_mixed_archive())
        zf, audit = self.open_audit(data)
        with zf:
            self.assertFalse(audit.ok)
            self.assertEqual(len(audit.conflicts), 1)
            conflict = audit.conflicts[0]
            self.assertEqual(
                {m.filename for m in conflict.members},
                {'aes.txt', 'plain.txt'})
            self.assertEqual(conflict.kind, 'header-overlaps-indeterminate')
            # The misdirected member cannot be sized and is reported as
            # indeterminate rather than clamped.
            self.assertEqual(
                [s.zinfo.filename for s in audit.indeterminate],
                ['plain.txt'])

    def test_negative_payload_length_is_indeterminate(self):
        data = make_negative_length_archive(build_mixed_archive())
        zf, audit = self.open_audit(data)
        with zf:
            self.assertFalse(audit.ok)
            self.assertEqual(audit.conflicts, [])
            self.assertEqual(
                [s.zinfo.filename for s in audit.indeterminate], ['aes.txt'])
            span = audit.indeterminate[0]
            # The negative payload length must not be clamped to a
            # valid-looking empty range.
            self.assertIsNone(span.payload)
            self.assertIn('encryption framing', span.error)
            with self.assertRaises(pyzipper.BadZipFile):
                zf.check_member_spans(strict=True)

    def test_out_of_bounds_length_is_indeterminate(self):
        data = make_out_of_bounds_archive(build_mixed_archive())
        zf, audit = self.open_audit(data)
        with zf:
            self.assertFalse(audit.ok)
            self.assertEqual(
                [s.zinfo.filename for s in audit.indeterminate], ['aes.txt'])
            self.assertIn('past end of file', audit.indeterminate[0].error)
            with self.assertRaises(pyzipper.BadZipFile):
                zf.check_member_spans(strict=True)


@requires_pycrypto
class StrictModeConsistencyTests(unittest.TestCase):

    def assert_consistent(self, data):
        """Per-member strict opens and the whole-archive precheck must
        flag exactly the same members."""
        zf = pyzipper.AESZipFile(io.BytesIO(data), strict_member_spans=True)
        with zf:
            zf.setpassword(PASSWORD)
            audit = zf.audit_member_spans()
            flagged = {s.zinfo.filename for s in audit.indeterminate}
            for conflict in audit.conflicts:
                flagged.update(m.filename for m in conflict.members)

            rejected = set()
            for name in zf.namelist():
                try:
                    zf.read(name)
                except pyzipper.BadZipFile:
                    rejected.add(name)
            self.assertEqual(rejected, flagged)

            if flagged:
                with self.assertRaises(pyzipper.BadZipFile):
                    zf.check_member_spans(strict=True)
            else:
                self.assertTrue(zf.check_member_spans(strict=True).ok)
            return flagged

    def test_mixed_archive_has_no_false_positives(self):
        flagged = self.assert_consistent(build_mixed_archive())
        self.assertEqual(flagged, set())

    def test_mixed_archive_with_descriptors_has_no_false_positives(self):
        flagged = self.assert_consistent(build_mixed_archive(seekable=False))
        self.assertEqual(flagged, set())

    def test_alias_members_rejected_consistently(self):
        flagged = self.assert_consistent(
            make_alias_archive(build_mixed_archive()))
        self.assertEqual(flagged, {'aes.txt', 'alias.txt'})

    def test_payload_overlap_rejected_consistently(self):
        flagged = self.assert_consistent(
            make_payload_overlap_archive(build_mixed_archive()))
        self.assertEqual(flagged, {'aes.txt', 'plain.txt'})

    def test_header_pointing_member_rejected_consistently(self):
        flagged = self.assert_consistent(
            make_header_pointing_archive(build_mixed_archive()))
        self.assertEqual(flagged, {'aes.txt', 'plain.txt'})

    def test_unconfirmable_length_rejected_consistently(self):
        flagged = self.assert_consistent(
            make_negative_length_archive(build_mixed_archive()))
        self.assertEqual(flagged, {'aes.txt'})

    def test_strict_open_reports_member_and_range(self):
        data = make_alias_archive(build_mixed_archive())
        with pyzipper.AESZipFile(
                io.BytesIO(data), strict_member_spans=True) as zf:
            zf.setpassword(PASSWORD)
            span = next(s for s in zf.audit_member_spans().spans
                        if s.zinfo.filename == 'aes.txt')
            with self.assertRaises(pyzipper.BadZipFile) as cm:
                zf.open('alias.txt')
            message = str(cm.exception)
            self.assertIn('alias.txt', message)
            self.assertIn('aes.txt', message)
            self.assertIn('[%d, %d)' % (span.start, span.end), message)
            # A non-conflicting member is still readable in strict mode.
            self.assertEqual(zf.read('stored.txt'), b'stored-data-' * 12)


if __name__ == '__main__':
    unittest.main()
