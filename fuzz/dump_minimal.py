"""Dump the field layouts of the minimized counterexamples and the
relaxed-guard evidence into a plain-text report."""

import struct

from .engine import minimize
from .layout_dump import describe
from .mini_zip import (EXTRA_WZ_AES, aes_field, parse_layout, rebuild,
                       valid_aes_archive)
from .relax_guard import RelaxedLengthGuard
from .tracer import drive_parse
from .engine import payload_region_for

TARGETS = (
    'dup_aes_last_deflate',
    'aes_strength_invalid_9',
    'cd_csize_crosses_central_dir',
    'zip64_placeholder_no_extra',
    'lfh_xlen_overruns',
)


def main():
    blob, password = valid_aes_archive()
    out = []
    out.append('Minimal counterexample field layouts')
    out.append('=' * 40)
    for target in TARGETS:
        result = minimize(blob, password, target)
        out.append('')
        out.append('### %s' % target)
        out.append('failure signature: kind=%s exc=%s stage=%s' %
                   result['signature'])
        out.append('minimal mutation chain: %s' % result['chain'])
        out.append(describe(result['blob']))

    out.append('')
    out.append('Relaxed length-guard evidence')
    out.append('=' * 40)
    truncated = struct.pack('<HH', EXTRA_WZ_AES, 7) + b'\x00' * 3
    mutated = rebuild(blob, cd_extra=truncated, lfh_extra=aes_field())
    region = payload_region_for(blob, mutated)
    strict = drive_parse(mutated, 'strict', password=password,
                         payload_region=region)
    out.append('strict parser  -> %s @%s: %s' % (
        strict.exc_type, strict.stage, strict.exc_message))
    with RelaxedLengthGuard():
        relaxed = drive_parse(mutated, 'relaxed', password=password,
                              payload_region=region)
    out.append('relaxed parser -> %s @%s: %s' % (
        relaxed.exc_type, relaxed.stage, relaxed.exc_message))
    out.append('')
    out.append('Conclusion: with the ln+4 guard present the contradiction is a '
               'clean BadZipFile;')
    out.append('with the guard removed the same bytes reach struct.unpack and '
               'escape as a raw')
    out.append('struct.error, so the guard is the defense preventing an '
               'unvalidated over-read.')
    text = '\n'.join(out)
    print(text)
    return text


if __name__ == '__main__':
    main()
