"""Pre-publish audit of per-member encryption attributes in a ZIP archive.

Appending encrypted members to an existing archive does not change the
protection of members already stored in it.  This module inspects every
central directory entry individually -- encryption method, AES strength
and available integrity protection -- and reports whether the whole
archive conforms to a caller declared :class:`EncryptionPolicy`.

The audit is read-only: it never modifies the audited archive.
"""

from .zipfile_aes import (
    AESZipFile,
    WZ_AES_COMPRESS_TYPE,
    WZ_KEY_LENGTHS,
)

ENCRYPTION_NONE = 'none'
ENCRYPTION_ZIPCRYPTO = 'zipcrypto'
ENCRYPTION_WZ_AES = 'wz_aes'
ENCRYPTION_STRONG = 'strong'

#: Encryption methods this audit is able to verify.  PKWARE strong
#: encryption (general purpose flag bit 6) cannot be verified and any
#: member using it is always reported as non-compliant.
SUPPORTED_METHODS = frozenset({
    ENCRYPTION_NONE,
    ENCRYPTION_ZIPCRYPTO,
    ENCRYPTION_WZ_AES,
})

#: AES key strengths (in bits) that may be required by a policy.
AES_STRENGTHS = tuple(8 * key_length for key_length in WZ_KEY_LENGTHS.values())

_WZ_AES_STRENGTH_BITS = {
    strength: 8 * key_length
    for strength, key_length in WZ_KEY_LENGTHS.items()
}

#: Methods that provide an authentication code over the member data.
_METHODS_WITH_INTEGRITY = frozenset({ENCRYPTION_WZ_AES})


class EncryptionPolicy:
    """Caller declared policy an archive must satisfy before publishing.

    :param require_encryption: every member must be encrypted.
    :param allowed_methods: encryption methods members may use.
    :param min_aes_strength: minimum AES key strength in bits
        (128, 192 or 256) required of WZ_AES members.
    :param require_integrity: every member must offer integrity
        protection (an authentication code over its data).

    Claims that are unsupported or contradictory are rejected with
    :class:`ValueError` so that a misconfigured policy can never be
    used to approve a release.
    """

    def __init__(self, *, require_encryption=True,
                 allowed_methods=(ENCRYPTION_WZ_AES,),
                 min_aes_strength=256, require_integrity=True):
        allowed_methods = frozenset(allowed_methods)

        unknown = allowed_methods - SUPPORTED_METHODS
        if unknown:
            raise ValueError(
                "Unsupported encryption method(s) in policy: %s"
                % ', '.join(sorted(unknown)))

        if min_aes_strength not in AES_STRENGTHS:
            raise ValueError(
                "min_aes_strength must be one of %r, got %r"
                % (AES_STRENGTHS, min_aes_strength))

        if require_encryption and ENCRYPTION_NONE in allowed_methods:
            raise ValueError(
                "Conflicting policy: require_encryption=True but "
                "'none' is an allowed method")

        if require_encryption and not (allowed_methods - {ENCRYPTION_NONE}):
            raise ValueError(
                "Conflicting policy: require_encryption=True but no "
                "encryption method is allowed")

        if require_integrity and ENCRYPTION_NONE in allowed_methods:
            raise ValueError(
                "Conflicting policy: require_integrity=True but "
                "unencrypted members, which cannot provide integrity "
                "protection, are allowed")

        self.require_encryption = require_encryption
        self.allowed_methods = allowed_methods
        self.min_aes_strength = min_aes_strength
        self.require_integrity = require_integrity

    def __repr__(self):
        return (
            '%s(require_encryption=%r, allowed_methods=%r, '
            'min_aes_strength=%r, require_integrity=%r)' % (
                self.__class__.__name__,
                self.require_encryption,
                sorted(self.allowed_methods),
                self.min_aes_strength,
                self.require_integrity,
            )
        )


class MemberAudit:
    """Audit result for a single central directory entry."""

    __slots__ = (
        'filename',
        'header_offset',
        'encryption',
        'aes_strength',
        'has_integrity',
        'reasons',
    )

    def __init__(self, *, filename, header_offset, encryption,
                 aes_strength, has_integrity, reasons):
        self.filename = filename
        self.header_offset = header_offset
        self.encryption = encryption
        self.aes_strength = aes_strength
        self.has_integrity = has_integrity
        self.reasons = tuple(reasons)

    @property
    def compliant(self):
        return not self.reasons

    def __repr__(self):
        return (
            '<%s filename=%r header_offset=%r encryption=%r '
            'aes_strength=%r compliant=%r>' % (
                self.__class__.__name__,
                self.filename,
                self.header_offset,
                self.encryption,
                self.aes_strength,
                self.compliant,
            )
        )


class ArchiveAuditReport:
    """Result of auditing every central directory entry of an archive."""

    def __init__(self, entries):
        self.entries = tuple(entries)

    @property
    def failures(self):
        """Non-compliant central directory entries with their reasons."""
        return tuple(entry for entry in self.entries if not entry.compliant)

    @property
    def conforms(self):
        """True when every central directory entry satisfies the policy."""
        return not self.failures

    def __bool__(self):
        return self.conforms

    def __repr__(self):
        return '<%s conforms=%r entries=%d failures=%d>' % (
            self.__class__.__name__,
            self.conforms,
            len(self.entries),
            len(self.failures),
        )


def _detect_encryption(zinfo):
    """Return (encryption method, AES strength in bits) for one entry."""
    if not zinfo.is_encrypted:
        return ENCRYPTION_NONE, None
    if zinfo.is_strong_encryption:
        return ENCRYPTION_STRONG, None
    wz_aes_version = getattr(zinfo, 'wz_aes_version', None)
    if wz_aes_version is not None:
        return ENCRYPTION_WZ_AES, _WZ_AES_STRENGTH_BITS.get(
            zinfo.wz_aes_strength)
    if zinfo.compress_type == WZ_AES_COMPRESS_TYPE:
        # Compression method 99 announces WZ_AES but the AES extra
        # field is missing or corrupt, so the strength cannot be
        # established.
        return ENCRYPTION_WZ_AES, None
    return ENCRYPTION_ZIPCRYPTO, None


def audit_member(zinfo, policy):
    """Audit a single central directory entry against *policy*."""
    encryption, aes_strength = _detect_encryption(zinfo)
    has_integrity = encryption in _METHODS_WITH_INTEGRITY

    reasons = []
    if encryption == ENCRYPTION_STRONG:
        reasons.append(
            'strong encryption (general purpose flag bit 6) is not '
            'supported and cannot be verified')
    if encryption not in policy.allowed_methods:
        reasons.append(
            "encryption method '%s' is not allowed by the policy"
            % encryption)
    if policy.require_encryption and encryption == ENCRYPTION_NONE:
        reasons.append('member is not encrypted')
    if encryption == ENCRYPTION_WZ_AES:
        if aes_strength is None:
            reasons.append(
                'WZ_AES member with missing or unknown AES strength')
        elif aes_strength < policy.min_aes_strength:
            reasons.append(
                'AES-%d is below the required minimum of AES-%d'
                % (aes_strength, policy.min_aes_strength))
    if policy.require_integrity and not has_integrity:
        reasons.append(
            'member has no integrity protection (authentication code)')

    return MemberAudit(
        filename=zinfo.filename,
        header_offset=zinfo.header_offset,
        encryption=encryption,
        aes_strength=aes_strength,
        has_integrity=has_integrity,
        reasons=reasons,
    )


def audit_zipfile(zipfp, policy):
    """Audit every central directory entry of an open archive.

    All entries are inspected, including duplicate names left behind
    when members were appended to the archive; the lookup-by-name index
    (which only keeps the last entry for a name) is deliberately not
    used.  Only per-member metadata is considered -- the ``ZipFile``
    object's own default encryption configuration is ignored.
    """
    return ArchiveAuditReport(
        [audit_member(zinfo, policy) for zinfo in zipfp.infolist()])


def audit_archive(file, policy):
    """Audit the archive at *file* against *policy* before publishing.

    *file* is a path or a file-like object positioned for reading.
    Returns an :class:`ArchiveAuditReport`; the archive itself is never
    modified.
    """
    if isinstance(policy, type) or not isinstance(policy, EncryptionPolicy):
        raise TypeError(
            'policy: expected EncryptionPolicy, got %s'
            % type(policy).__name__)
    with AESZipFile(file, 'r') as zipfp:
        return audit_zipfile(zipfp, policy)
