"""Structured, seed-driven mutations of AES / ZIP64 metadata.

Mutations operate on the parsed structure (extra-field chains, 32-bit size
placeholders, AES actual-compression-method field) rather than flipping random
bytes, and every rebuild keeps the central directory reachable.
"""

import random
import struct

from .mini_zip import (
    EXTRA_WZ_AES, EXTRA_ZIP64, aes_field, zip64_field, unknown_field,
    field, rebuild,
)

UINT32_MAX = 0xFFFFFFFF


def _chain(*blocks):
    return b''.join(blocks)


# Each mutator returns a dict of kwargs suitable for mini_zip.rebuild().
def mutators(blob):
    layout_blob = blob
    aes_good = aes_field(strength=3, actual_method=0)
    aes_deflate = aes_field(strength=3, actual_method=8)
    aes_bz2 = aes_field(strength=3, actual_method=12)
    aes_lzma = aes_field(strength=3, actual_method=14)
    unk = unknown_field()

    def both(**kw):
        # Mirror a chain change into local + central unless the mutation is
        # specifically about LFH/CD divergence.
        if 'cd_extra' in kw and 'lfh_extra' not in kw:
            kw['lfh_extra'] = kw['cd_extra']
        if 'lfh_extra' in kw and 'cd_extra' not in kw:
            kw['cd_extra'] = kw['lfh_extra']
        return kw

    return [
        # ---- extra-field ordering ------------------------------------------------
        ('aes_then_unknown', lambda: both(cd_extra=_chain(aes_good, unk))),
        ('unknown_then_aes', lambda: both(cd_extra=_chain(unk, aes_good))),
        ('unknown_both_sides', lambda: both(
            cd_extra=_chain(unk, aes_good, unknown_field(0x4242, b'')))),
        ('zip64_then_aes', lambda: both(
            cd_extra=_chain(zip64_field(12345), aes_good))),
        ('aes_then_zip64', lambda: both(
            cd_extra=_chain(aes_good, zip64_field(12345)))),

        # ---- duplicate field types ----------------------------------------------
        ('dup_aes_last_deflate', lambda: both(
            cd_extra=_chain(aes_good, aes_deflate))),
        ('dup_aes_first_deflate', lambda: both(
            cd_extra=_chain(aes_deflate, aes_good))),
        ('dup_aes_bz2_lzma', lambda: both(
            cd_extra=_chain(aes_bz2, aes_lzma))),
        ('triple_aes', lambda: both(
            cd_extra=_chain(aes_good, aes_deflate, aes_good))),
        ('dup_zip64', lambda: both(cd_extra=_chain(
            zip64_field(1), zip64_field(2)) + b'')),
        ('dup_aes_divergent_lfh_cd', lambda: {
            'cd_extra': _chain(aes_good, aes_deflate),
            'lfh_extra': aes_good}),

        # ---- length contradictions within an extra chain ------------------------
        ('aes_len6_short', lambda: both(cd_extra=_chain(
            field(EXTRA_WZ_AES, struct.pack('<H2sB', 2, b'AE', 3))))),
        ('aes_len8_long', lambda: both(cd_extra=_chain(
            field(EXTRA_WZ_AES,
                  struct.pack('<H2sBHH', 2, b'AE', 3, 0, 0xCCCC))))),
        ('aes_header_truncated_body', lambda: both(cd_extra=_chain(
            struct.pack('<HH', EXTRA_WZ_AES, 7) + b'\x00' * 3))),
        ('zip64_declared8_body4', lambda: both(cd_extra=_chain(
            struct.pack('<HH', EXTRA_ZIP64, 8) + b'\x00' * 4, aes_good))),
        ('zip64_declared24_body8', lambda: both(cd_extra=_chain(
            struct.pack('<HH', EXTRA_ZIP64, 24) + b'\x00' * 8, aes_good))),
        ('unknown_declared_long', lambda: both(cd_extra=_chain(
            struct.pack('<HH', 0x7777, 30) + b'xy', aes_good))),

        # ---- ZIP64 placeholder / size contradictions ----------------------------
        ('zip64_usize_sentinel_huge', lambda: {
            'cd_extra': _chain(zip64_field(10 ** 15), aes_good),
            'lfh_extra': aes_good,
            'cd_patch': {'usize': ('<I', UINT32_MAX)}}),
        ('zip64_csize_sentinel_huge', lambda: {
            'cd_extra': _chain(
                zip64_field(19, 5000), aes_good),
            'lfh_extra': aes_good,
            'cd_patch': {'csize': ('<I', UINT32_MAX),
                         'usize': ('<I', UINT32_MAX)}}),
        ('zip64_csize_sentinel_tiny', lambda: {
            'cd_extra': _chain(zip64_field(19, 3), aes_good),
            'lfh_extra': aes_good,
            'cd_patch': {'csize': ('<I', UINT32_MAX),
                         'usize': ('<I', UINT32_MAX)}}),
        ('zip64_ln4_missing_q', lambda: {
            'cd_extra': _chain(
                field(EXTRA_ZIP64, struct.pack('<I', 7)), aes_good),
            'lfh_extra': aes_good,
            'cd_patch': {'usize': ('<I', UINT32_MAX)}}),
        ('zip64_len0_with_sentinel', lambda: {
            'cd_extra': _chain(field(EXTRA_ZIP64, b''), aes_good),
            'lfh_extra': aes_good,
            'cd_patch': {'usize': ('<I', UINT32_MAX)}}),
        ('zip64_placeholder_no_extra', lambda: {
            'cd_extra': aes_good, 'lfh_extra': aes_good,
            'cd_patch': {'usize': ('<I', UINT32_MAX),
                         'csize': ('<I', UINT32_MAX)}}),

        # ---- raw 32-bit size contradictions (no ZIP64 extra) --------------------
        ('cd_csize_zero', lambda: {'cd_patch': {'csize': ('<I', 0)}}),
        ('cd_csize_below_aes_overhead', lambda: {
            'cd_patch': {'csize': ('<I', 5)}}),
        ('cd_csize_crosses_central_dir', lambda: {
            'cd_patch': {'csize': ('<I', 5000)}}),
        ('cd_usize_truncates_output', lambda: {
            'cd_patch': {'usize': ('<I', 7)}}),
        ('lfh_xlen_overruns', lambda: {
            'lfh_patch': {'xlen': ('<H', 200)}}),

        # ---- AES metadata semantics ---------------------------------------------
        ('aes_strength_invalid_9', lambda: both(cd_extra=_chain(
            aes_field(strength=9, actual_method=0)))),
        ('aes_strength_invalid_0', lambda: both(cd_extra=_chain(
            aes_field(strength=0, actual_method=0)))),
        ('aes_actual_method_unknown_97', lambda: both(cd_extra=_chain(
            aes_field(strength=3, actual_method=97)))),
        ('aes_actual_method_99_self', lambda: both(cd_extra=_chain(
            aes_field(strength=3, actual_method=99)))),
        ('aes_version_3', lambda: both(cd_extra=_chain(
            aes_field(strength=3, version=3, actual_method=0)))),
        ('aes_bad_vendor', lambda: both(cd_extra=_chain(
            aes_field(strength=3, actual_method=0, vendor=b'XX')))),
        ('aes_extra_without_encrypted_flag', lambda: {
            'cd_extra': aes_good, 'lfh_extra': aes_good,
            'cd_patch': {'flags': ('<H', 0)},
            'lfh_patch': {'flags': ('<H', 0)}}),
    ]


def random_mutation(blob, rng):
    """Pick a mutator deterministically and apply it."""
    choices = mutators(blob)
    name, factory = choices[rng.randrange(len(choices))]
    return name, rebuild(blob, **factory())


def all_named_mutations(blob):
    """Deterministic list of (name, mutated_blob) for regression tests."""
    return [(name, rebuild(blob, **factory()))
            for name, factory in mutators(blob)]


def random_chain(blob, rng, depth=3):
    """Compose several chain mutations to reach order/dup combinations."""
    cur = blob
    applied = []
    for _ in range(depth):
        name, cur = random_mutation(cur, rng)
        applied.append(name)
    return '+'.join(applied), cur
