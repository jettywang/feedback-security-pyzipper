"""Controlled experiment: relax the extra-field length validation.

The production parser (ZipInfo._decodeExtra) rejects a field whose declared
body length overruns the chain before the field decoder runs:

    if ln + 4 > len(extra):
        raise BadZipFile(...)

This module monkeypatches that single guard away and re-runs the same
mutations. With the guard removed, contradictory lengths reach struct.unpack
and raise a raw struct.error instead of a documented BadZipFile, demonstrating
that the guard is what keeps a length-contradiction from becoming an
out-of-bounds-style unpack. The patch is reverted in a finally block so no
other test observes it.
"""

import struct

from pyzipper.zipfile import ZipInfo


def relaxed_decode_extra(self):
    """Copy of ZipInfo._decodeExtra with the ln+4 bounds guard removed."""
    extra = self.extra
    extra_decoders = self.get_extra_decoders()
    while len(extra) >= 4:
        tp, ln = struct.unpack('<HH', extra[:4])
        # Intentionally no `if ln + 4 > len(extra): raise BadZipFile(...)`.
        try:
            extra_decoders[tp](ln, extra)
        except KeyError:
            pass
        extra = extra[ln + 4:]


class RelaxedLengthGuard:
    """Context manager that swaps in the guard-free extra decoder."""

    def __enter__(self):
        self._original = ZipInfo._decodeExtra
        ZipInfo._decodeExtra = relaxed_decode_extra
        return self

    def __exit__(self, *exc):
        ZipInfo._decodeExtra = self._original
        return False
