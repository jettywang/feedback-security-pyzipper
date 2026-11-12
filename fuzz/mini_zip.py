"""Small, deterministic, hand-controlled ZIP archive builder.

Every layout number (extra-field chains in both the local file header and the
central-directory entry, 32-bit size placeholders, EOCD offsets) is computed
from the rebuilt bytes so a mutated archive still has a reachable central
directory. That keeps malformed *metadata* from being rejected up front by the
EOCD / central-directory signature checks.
"""

import struct

LFH_SIZE = 30
CDH_SIZE = 46
EOCD_SIZE = 22

SIG_LFH = b'PK\x03\x04'
SIG_CD = b'PK\x01\x02'
SIG_EOCD = b'PK\x05\x06'

EXTRA_ZIP64 = 0x0001
EXTRA_WZ_AES = 0x9901

MASK_ENCRYPTED = 0x1

# Central-directory header field offsets (after the 4-byte signature).
_CD_OFFSETS = {
    'creator': 4, 'needver': 6, 'flags': 8, 'method': 10, 'dostime': 12,
    'dosdate': 14, 'crc': 16, 'csize': 20, 'usize': 24, 'nlen': 28,
    'xlen': 30, 'clen': 32, 'disk': 34, 'iattr': 36, 'eattr': 38,
    'offset': 42,
}
_LFH_OFFSETS = {
    'needver': 4, 'flags': 6, 'method': 8, 'dostime': 10, 'dosdate': 12,
    'crc': 14, 'csize': 18, 'usize': 22, 'nlen': 26, 'xlen': 28,
}


def field(tag, body):
    """Wrap a raw extra-field body with its (id, length) header."""
    return struct.pack('<HH', tag, len(body)) + body


def aes_field(strength=3, version=2, actual_method=0, vendor=b'AE'):
    """WZ-AES extra field (0x9901); the 7-byte body is H + 2s + B + H."""
    body = struct.pack('<H2sBH', version, vendor, strength, actual_method)
    return field(EXTRA_WZ_AES, body)


def zip64_field(*qwords, trailing_disk=None):
    """ZIP64 extended-information field (0x0001).

    `qwords` are the optional 8-byte values in spec order (uncompressed size,
    compressed size, local-header offset). `trailing_disk` adds the optional
    4-byte disk number. Raw bodies may also be supplied directly to exercise
    length contradictions.
    """
    body = b''.join(struct.pack('<Q', q) for q in qwords)
    if trailing_disk is not None:
        body += struct.pack('<I', trailing_disk)
    return field(EXTRA_ZIP64, body)


def unknown_field(xid=0x7777, payload=b'abc'):
    """A skippable, unknown extra field."""
    return field(xid, payload)


class Layout:
    """Byte offsets of the structural pieces of a built archive."""

    def __init__(self, blob):
        lfh = struct.unpack('<4sHHHHHIIIHH', blob[:LFH_SIZE])
        self.name = lfh[9]
        self.lfh_extra_off = LFH_SIZE + lfh[9]
        self.lfh_extra_len = lfh[10]
        self.data_off = self.lfh_extra_off + self.lfh_extra_len
        self.cd_off = blob.index(SIG_CD)
        cdh = struct.unpack('<4sHHHHHHIIIHHHHHII',
                            blob[self.cd_off:self.cd_off + CDH_SIZE])
        self.cd_extra_off = self.cd_off + CDH_SIZE + cdh[10]
        self.cd_extra_len = cdh[11]
        self.eocd_off = blob.index(SIG_EOCD)
        self.payload_end = self.cd_off


def parse_layout(blob):
    return Layout(blob)


def build_archive(*, name=b't.txt', flags=MASK_ENCRYPTED, method=99,
                  crc=0, payload=b'', cd_extra=b'', lfh_extra=b'',
                  csize=None, usize=None, lfh_csize=0, lfh_usize=0,
                  need_version=45):
    """Assemble a one-entry archive from explicit pieces.

    The 32-bit central-directory sizes default to the actual payload / a
    caller-supplied uncompressed size so the archive is internally coherent;
    callers mutate them afterwards to create contradictions.
    """
    if csize is None:
        csize = len(payload)
    if usize is None:
        usize = 0
    local = struct.pack(
        '<4sHHHHHIIIHH', SIG_LFH, need_version, flags, method, 0, 0, crc,
        lfh_csize, lfh_usize, len(name), len(lfh_extra)) + name + lfh_extra
    central = struct.pack(
        '<4sHHHHHHIIIHHHHHII', SIG_CD, 0x033E, need_version, flags, method,
        0, 0, crc, csize, usize, len(name), len(cd_extra), 0, 0, 0, 0,
        0) + name + cd_extra
    cd_offset = len(local) + len(payload)
    eocd = struct.pack('<4sHHHHIIH', SIG_EOCD, 0, 0, 1, 1,
                       len(central), cd_offset, 0)
    return local + payload + central + eocd


def rebuild(blob, *, cd_extra=None, lfh_extra=None, cd_patch=None,
            lfh_patch=None):
    """Rebuild an archive, replacing extra chains and/or header numbers.

    All offsets and the EOCD central-directory size are recomputed, so the
    central directory stays reachable regardless of how the extra-field chains
    change length. `cd_patch` / `lfh_patch` map a field name to a (fmt, value)
    tuple.
    """
    layout = Layout(blob)
    old_lfh = blob[layout.lfh_extra_off:
                   layout.lfh_extra_off + layout.lfh_extra_len]
    old_cd = blob[layout.cd_extra_off:
                  layout.cd_extra_off + layout.cd_extra_len]
    if lfh_extra is None:
        lfh_extra = old_lfh
    if cd_extra is None:
        cd_extra = old_cd
    cd_patch = cd_patch or {}
    lfh_patch = lfh_patch or {}

    name = blob[LFH_SIZE:layout.lfh_extra_off]
    payload = blob[layout.data_off:layout.cd_off]

    lfh = bytearray(blob[:LFH_SIZE])
    lfh[_LFH_OFFSETS['xlen']:_LFH_OFFSETS['xlen'] + 2] = struct.pack(
        '<H', len(lfh_extra))
    for key, (fmt, value) in lfh_patch.items():
        off = _LFH_OFFSETS[key]
        lfh[off:off + struct.calcsize(fmt)] = struct.pack(fmt, value)
    new_local = bytes(lfh) + name + lfh_extra

    cdh = bytearray(blob[layout.cd_off:layout.cd_off + CDH_SIZE])
    cdh[_CD_OFFSETS['xlen']:_CD_OFFSETS['xlen'] + 2] = struct.pack(
        '<H', len(cd_extra))
    for key, (fmt, value) in cd_patch.items():
        off = _CD_OFFSETS[key]
        cdh[off:off + struct.calcsize(fmt)] = struct.pack(fmt, value)
    cd_name = blob[layout.cd_off + CDH_SIZE:layout.cd_extra_off]
    comment = blob[layout.cd_extra_off + layout.cd_extra_len:
                   layout.eocd_off]
    new_central = bytes(cdh) + cd_name + cd_extra + comment

    cd_offset = len(new_local) + len(payload)
    eocd_old = struct.unpack('<4sHHHHIIH',
                             blob[layout.eocd_off:
                                  layout.eocd_off + EOCD_SIZE])
    new_eocd = struct.pack('<4sHHHHIIH', eocd_old[0], eocd_old[1],
                           eocd_old[2], eocd_old[3], eocd_old[4],
                           len(new_central), cd_offset, eocd_old[7])
    return new_local + payload + new_central + new_eocd


def valid_aes_archive(content=b'hello world payload',
                      method=0, password=b'secret'):
    """Return (blob, password) for a genuinely readable WZ-AES archive."""
    import io
    from pyzipper import zipfile_aes, ZIP_STORED
    buf = io.BytesIO()
    with zipfile_aes.AESZipFile(buf, 'w', encryption='WZ_AES') as zf:
        zf.setpassword(password)
        zf.writestr('t.txt', content,
                    compress_type=method if method else ZIP_STORED)
    return buf.getvalue(), password
