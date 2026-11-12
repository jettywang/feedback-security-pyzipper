"""Human-readable field-layout dump of a (minimal) counterexample archive."""

import struct

from pyzipper.zipfile import structFileHeader, structCentralDir
from .mini_zip import LFH_SIZE, CDH_SIZE, parse_layout

_EXTRA_NAMES = {0x0001: 'ZIP64', 0x9901: 'WZ_AES'}

# Indices into pyzipper's native header tuples.
_LFH = dict(flags=3, method=4, crc=7, csize=8, usize=9, nlen=10, xlen=11)
_CD = dict(flags=5, method=6, crc=9, csize=10, usize=11, nlen=12, xlen=13)


def _walk_extra(data):
    items = []
    i = 0
    while i + 4 <= len(data):
        xid, xlen = struct.unpack('<HH', data[i:i + 4])
        body = data[i + 4:i + 4 + xlen]
        overflow = i + 4 + xlen > len(data)
        items.append(dict(off=i, id=xid, name=_EXTRA_NAMES.get(xid, 'UNKNOWN'),
                          declared_len=xlen, body=body, overflow=overflow))
        i += 4 + xlen
    return items


def describe(blob):
    """Return a multi-line description of headers, sizes and extra chains."""
    layout = parse_layout(blob)
    lfh = struct.unpack(structFileHeader, blob[:LFH_SIZE])
    cd_off = layout.cd_off
    cdh = struct.unpack(structCentralDir, blob[cd_off:cd_off + CDH_SIZE])
    lines = []
    lines.append('archive bytes: %d' % len(blob))
    lines.append(
        'local file header @0: method=0x%04x flags=0x%04x csize=%s '
        'usize=%s xlen=%s' % (
            lfh[_LFH['method']], lfh[_LFH['flags']], lfh[_LFH['csize']],
            lfh[_LFH['usize']], lfh[_LFH['xlen']]))
    lfh_extra = blob[layout.lfh_extra_off:
                     layout.lfh_extra_off + layout.lfh_extra_len]
    lines.append('  LFH extra chain (%d bytes):' % len(lfh_extra))
    for item in _walk_extra(lfh_extra):
        lines.append('    +%2d id=0x%04x %-7s len=%-2d body=%s%s' % (
            item['off'], item['id'], item['name'], item['declared_len'],
            item['body'].hex(), ' OVERFLOW' if item['overflow'] else ''))
    if layout.data_off <= layout.payload_end:
        lines.append('payload region: [%d, %d) (%d bytes)' % (
            layout.data_off, layout.payload_end,
            layout.payload_end - layout.data_off))
    else:
        lines.append(
            'payload region: declared LFH xlen overruns the header; '
            'data_off=%d is past cd_off=%d' % (
                layout.data_off, layout.payload_end))
    lines.append(
        'central directory @%d: method=0x%04x flags=0x%04x csize=%s '
        'usize=%s xlen=%s' % (
            cd_off, cdh[_CD['method']], cdh[_CD['flags']],
            cdh[_CD['csize']], cdh[_CD['usize']], cdh[_CD['xlen']]))
    cd_extra = blob[layout.cd_extra_off:
                    layout.cd_extra_off + layout.cd_extra_len]
    lines.append('  CD extra chain (%d bytes):' % len(cd_extra))
    for item in _walk_extra(cd_extra):
        lines.append('    +%2d id=0x%04x %-7s len=%-2d body=%s%s' % (
            item['off'], item['id'], item['name'], item['declared_len'],
            item['body'].hex(), ' OVERFLOW' if item['overflow'] else ''))
    lines.append('EOCD @%d' % layout.eocd_off)
    return '\n'.join(lines)
