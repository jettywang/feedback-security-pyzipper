#!/usr/bin/env python3
"""Reference receiver contract for pyzipper AES archives.

pyzipper's HMAC authenticates each member's *ciphertext*, not the archive.
This module demonstrates the checks a backend must add before treating
"password accepted and read succeeded" as a trustworthy upload.

It is a reference, not a drop-in security boundary: the cryptographic root of
trust still has to come from outside the ZIP (e.g. an HMAC/signature over a
canonical manifest, or an out-of-band digest supplied by the business system).

Run:  .venv/bin/python experiments/verify_trusted_upload.py
"""

from __future__ import annotations

import hashlib
import hmac
import io
import struct
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import pyzipper
from pyzipper import AESZipFile, BadZipFile, WZ_AES
from pyzipper.zipfile import structCentralDir, structEndArchive, structFileHeader

AE_STRENGTH_BITS = {1: 128, 2: 192, 3: 256}
AE_VERSION_NAMES = {1: "AE-1", 2: "AE-2"}


class UntrustedArchive(Exception):
    """Raised when the archive is structurally usable but not trustworthy."""


@dataclass
class MemberDigest:
    name: str
    size: int
    sha256: str
    ordinal: int = 0
    mode: int = 0
    entry_comment_sha256: str = ""
    # Business identity bound outside the archive. pyzipper cannot supply this.
    role: str = ""
    business_id: str = ""


@dataclass
class VerifiedArchive:
    members: list[MemberDigest] = field(default_factory=list)
    manifest_sha256: str = ""
    archive_comment: bytes = b""

    def manifest(self) -> bytes:
        """Canonical identity+content manifest to sign outside the ZIP."""
        lines = ["pyzipper-trusted-v1"]
        for m in sorted(self.members, key=lambda x: x.ordinal):
            lines.append("%d\t%s\t%d\t%s\t0o%o\t%s\t%s\t%s"
                         % (m.ordinal, m.name, m.size, m.sha256, m.mode,
                            m.entry_comment_sha256, m.role, m.business_id))
        lines.append("comment\t" + hashlib.sha256(self.archive_comment).hexdigest())
        return ("\n".join(lines) + "\n").encode("utf-8")


def _parse_raw(data: bytes):
    eocd_pos = data.rfind(b"PK\x05\x06")
    if eocd_pos < 0:
        raise UntrustedArchive("missing EOCD")
    if eocd_pos + 22 > len(data):
        raise UntrustedArchive("truncated EOCD")
    eocd = struct.unpack_from(structEndArchive, data, eocd_pos)
    count, cd_size, cd_offset, comment_len = eocd[4], eocd[5], eocd[6], eocd[7]
    if eocd_pos + 22 + comment_len != len(data):
        raise UntrustedArchive("bytes after EOCD comment")
    if eocd_pos >= 20 and struct.unpack_from("<4s", data, eocd_pos - 20)[0] == b"PK\x06\x07":
        raise UntrustedArchive("ZIP64 archives are not handled by this reference parser")
    records = []
    p = cd_offset
    for _ in range(count):
        if p + 46 > len(data):
            raise UntrustedArchive("truncated central directory record")
        f = struct.unpack_from(structCentralDir, data, p)
        name_len, extra_len, entry_comment_len = f[12], f[13], f[14]
        rec_len = 46 + name_len + extra_len + entry_comment_len
        if p + rec_len > len(data):
            raise UntrustedArchive("central directory record runs past EOF")
        name_raw = bytes(data[p + 46:p + 46 + name_len])
        if 0xFFFFFFFF in (f[10], f[11], f[18]):
            raise UntrustedArchive("ZIP64 sentinel present in record %d" % len(records))
        if b"\x00" in name_raw:
            raise UntrustedArchive("NUL byte in raw member name")
        try:
            name = name_raw.decode("utf-8" if f[5] & 0x0800 else "cp437")
        except UnicodeDecodeError as exc:
            raise UntrustedArchive("undecodable member name") from exc
        records.append({
            "pos": p, "len": rec_len, "name_raw": name_raw, "name": name,
            "extract_version": f[3], "create_system": f[2],
            "flag_bits": f[5], "compress_type": f[6], "CRC": f[9],
            "compress_size": f[10], "file_size": f[11],
            "external_attr": f[17], "header_offset": f[18],
            "extra": bytes(data[p + 46 + name_len:p + 46 + name_len + extra_len]),
            "entry_comment": bytes(data[p + 46 + name_len + extra_len:p + rec_len]),
        })
        p += rec_len
    if p != cd_offset + cd_size:
        raise UntrustedArchive("central directory size mismatch")
    if len(records) != count:
        raise UntrustedArchive("EOCD declares %d entries, found %d"
                               % (count, len(records)))
    if eocd[3] != eocd[4] or eocd[1] != eocd[2]:
        raise UntrustedArchive("multi-disk archive is not supported")
    return records, bytes(data[eocd_pos + 22:eocd_pos + 22 + comment_len])


MAX_COMPRESS_RATIO = 200


def _ae_meta(rec):
    extra = rec["extra"]
    p = 0
    found = None
    while p + 4 <= len(extra):
        tag, ln = struct.unpack_from("<HH", extra, p)
        if p + 4 + ln > len(extra):
            raise UntrustedArchive("truncated extra field for %r" % rec["name"])
        if tag == 0x9901:
            if found is not None:
                raise UntrustedArchive("duplicate WZ_AES extra for %r" % rec["name"])
            if ln != 7:
                raise UntrustedArchive("malformed WZ_AES extra for %r" % rec["name"])
            found = struct.unpack_from("<H2sBH", extra, p + 4)
        p += 4 + ln
    return found


def verify(path: str | Path, password: bytes, *, require_ae2: bool = True,
           require_exact_members: Iterable[str] | None = None,
           require_min_members: int = 1,
           expected_modes: dict[str, int] | None = None,
           member_identity: dict[str, tuple[str, str]] | None = None,
           expected_manifest_hmac: tuple[bytes, bytes] | None = None
           ) -> VerifiedArchive:
    """Verify an uploaded archive under the stated trust contract.

    Checks performed here:
      1. exactly one password; no unencrypted member falls back to success;
      2. every member is WinZip-AES, AE-2 by default, vendor "AE";
      3. member count > 0; no duplicate raw names;
      4. local and central filenames agree (pyzipper checks only this pair);
      5. each member is read to EOF in the production API, which triggers HMAC;
      6. the returned bytes are compared to declared size and (for AE-1) CRC;
      7. optional exact member-set allowlist;
      8. optional exact Unix modes, because external_attr is unauthenticated;
      9. optional external (role, business id) binding, because member names
         are not authenticated either;
     10. optional external HMAC over the canonical manifest (name, size,
         SHA-256, mode, role, business id, and archive-comment digest).
    """
    data = Path(path).read_bytes()
    records, archive_comment = _parse_raw(data)

    if len(records) < require_min_members:
        raise UntrustedArchive("only %d member(s); contract requires at least %d "
                               "(an empty archive performs no HMAC check)"
                               % (len(records), require_min_members))
    if require_exact_members is not None:
        want = sorted(require_exact_members)
        got = sorted(r["name"] for r in records)
        if got != want:
            raise UntrustedArchive("member set mismatch: %r != %r" % (got, want))

    if member_identity is not None:
        extra_names = set(member_identity) - {r["name"] for r in records}
        if extra_names:
            raise UntrustedArchive("external identity names not present in archive: %r"
                                   % sorted(extra_names))
    if expected_modes is not None:
        for rec in records:
            if rec["create_system"] != 3:
                raise UntrustedArchive("member %r was not created on Unix; "
                                       "external_attr mode is not meaningful"
                                       % rec["name"])
            want = expected_modes.get(rec["name"])
            if want is None:
                raise UntrustedArchive("unexpected member %r in mode allowlist"
                                       % rec["name"])
            got = rec["external_attr"] >> 16
            if got != want:
                raise UntrustedArchive(
                    "member %r mode 0o%o != expected 0o%o (external_attr is not "
                    "covered by the AES HMAC)" % (rec["name"], got, want))

    seen = set()
    for rec in records:
        if rec["name"] in seen:
            raise UntrustedArchive("duplicate member name %r" % rec["name"])
        seen.add(rec["name"])
        if not rec["flag_bits"] & 1:
            raise UntrustedArchive("member %r is not encrypted" % rec["name"])
        if rec["flag_bits"] & 0x2000:
            raise UntrustedArchive("member %r claims encrypted central directory"
                                   % rec["name"])
        if rec["flag_bits"] & 0x0040:
            raise UntrustedArchive("member %r claims strong encryption; pyzipper "
                                   "does not implement it" % rec["name"])
        ae = _ae_meta(rec)
        if ae is None:
            raise UntrustedArchive("member %r lacks WZ_AES extra" % rec["name"])
        version, vendor, strength, actual_comp = ae
        if vendor != b"AE":
            raise UntrustedArchive("member %r has vendor %r, not AE"
                                   % (rec["name"], vendor))
        if strength not in AE_STRENGTH_BITS:
            raise UntrustedArchive("member %r has unknown strength %d"
                                   % (rec["name"], strength))
        if require_ae2 and version != 2:
            raise UntrustedArchive("member %r is %s, contract requires AE-2"
                                   % (rec["name"], AE_VERSION_NAMES.get(version, version)))
        # The on-disk CD compression method is 99 (AES marker); the real
        # compression code lives in the WZ_AES extra's actual_comp field.
        # Directory entries are legal but must not be used as file records.
        if rec["name"].endswith("/"):
            raise UntrustedArchive("member %r is a directory entry" % rec["name"])
        if rec["extract_version"] > 63:
            raise UntrustedArchive("member %r requires version %d (unsupported)"
                                   % (rec["name"], rec["extract_version"]))
        # The local header must repeat the same encryption / AES metadata.
        lh = rec["header_offset"]
        fh = struct.unpack_from(structFileHeader, data, lh)
        if fh[0] != b"PK\x03\x04":
            raise UntrustedArchive("bad local header for %r" % rec["name"])
        if fh[3] & 1 != rec["flag_bits"] & 1:
            raise UntrustedArchive("local/central encryption flag mismatch for %r"
                                   % rec["name"])
        if fh[4] != rec["compress_type"]:
            raise UntrustedArchive("local/central compression method mismatch for %r"
                                   % rec["name"])
        local_name = bytes(data[lh + 30:lh + 30 + fh[10]])
        if local_name != rec["name_raw"]:
            raise UntrustedArchive("local/central name mismatch for %r" % rec["name"])
        local_extra = bytes(data[lh + 30 + fh[10]:lh + 30 + fh[10] + fh[11]])
        local_ae = _ae_meta({"extra": local_extra, "name": rec["name"]})
        if local_ae != ae:
            raise UntrustedArchive("local/central WZ_AES metadata mismatch for %r"
                                   % rec["name"])
        if rec["compress_type"] != 99:
            raise UntrustedArchive("member %r CD compression method is %d, not 99"
                                   % (rec["name"], rec["compress_type"]))
        # AE-2 must not carry a plaintext CRC.
        if version == 2 and rec["CRC"] != 0:
            raise UntrustedArchive("AE-2 member %r has nonzero CRC 0x%08x"
                                   % (rec["name"], rec["CRC"]))

    digests = []
    with AESZipFile(io.BytesIO(data), "r") as zf:
        zf.setpassword(password)
        infos = zf.infolist()
        if [i.filename for i in infos] != [r["name"] for r in records]:
            raise UntrustedArchive("raw parser and pyzipper disagree on member "
                                   "names/order")
        record_by_name = {r["name"]: r for r in records}
        for ordinal, (info, rec) in enumerate(zip(infos, records)):
            if (info.file_size != rec["file_size"]
                    or info.compress_size != rec["compress_size"]
                    or info.header_offset != rec["header_offset"]):
                raise UntrustedArchive("raw parser and pyzipper disagree on size/"
                                       "offset for %r" % info.filename)
        for info in infos:
            if not info.is_encrypted or getattr(info, "wz_aes_version", None) is None:
                raise UntrustedArchive("member %r did not enter the AES path"
                                       % info.filename)
            # Read to EOF through the normal API: only EOF triggers check_hmac.
            try:
                payload = zf.read(info, pwd=password)
            except (BadZipFile, RuntimeError, EOFError, zlib.error) as exc:
                raise UntrustedArchive("authentication failed for %r: %s"
                                       % (info.filename, exc)) from exc
            if len(payload) != info.file_size:
                raise UntrustedArchive("size mismatch for %r: got %d, declared %d"
                                       % (info.filename, len(payload), info.file_size))
            if info.compress_size > info.file_size * MAX_COMPRESS_RATIO + 4096:
                raise UntrustedArchive("suspicious expansion for %r: %d compressed "
                                       "-> %d uncompressed" % (info.filename,
                                                               info.compress_size,
                                                               info.file_size))
            # AE-2 has no CRC. Cross-check the declared size and optionally an
            # externally supplied digest; an attacker can rewrite both size and
            # CRC, so these are consistency checks, not authenticity.
            role, business_id = ("", "")
            if member_identity is not None:
                if info.filename not in member_identity:
                    raise UntrustedArchive("member %r has no external identity"
                                           % info.filename)
                role, business_id = member_identity[info.filename]
            raw = record_by_name[info.filename]
            digests.append(MemberDigest(
                info.filename, len(payload), hashlib.sha256(payload).hexdigest(),
                ordinal, raw["external_attr"] >> 16,
                hashlib.sha256(raw["entry_comment"]).hexdigest(),
                role, business_id))

    archive = VerifiedArchive(digests, "", archive_comment)
    archive.manifest_sha256 = hashlib.sha256(archive.manifest()).hexdigest()

    if expected_manifest_hmac is not None:
        key, expected = expected_manifest_hmac
        got = hmac.new(key, archive.manifest(), hashlib.sha256).digest()
        if not hmac.compare_digest(got, expected):
            raise UntrustedArchive("external manifest HMAC mismatch")

    return archive


# ----------------------------------------------------------------- demo / tests


def build_archive(path, password=b"pw", *, ae2=True, members=None):
    from pyzipper import zipfile_aes as za
    if members is None:
        members = {"a.txt": b"alpha", "b.txt": b"bravo"}
    with AESZipFile(path, "w", compression=pyzipper.ZIP_STORED,
                    encryption=WZ_AES,
                    encryption_kwargs=(dict(nbits=256) if ae2 else
                                       dict(nbits=256, force_wz_aes_version=1)
                                       )) as zf:
        zf.setpassword(password)
        for name, payload in members.items():
            zi = za.AESZipInfo(name)
            zi.compress_type = pyzipper.ZIP_STORED
            zi.comment = b"comment-" + name.encode()
            zi.external_attr = 0o600 << 16
            zf.writestr(zi, payload)
        zf.comment = b"demo-archive-comment"


def _expect_reject(label, fn):
    try:
        fn()
    except UntrustedArchive as exc:
        print("REJECT %-38s %s" % (label, exc))
        return True
    print("ACCEPT %-38s <-- CONTRACT FAILURE" % label)
    return False


IDENTITY = {"a.txt": ("invoice", "INV-1"), "b.txt": ("invoice", "INV-2")}


def main():
    import hmac as hmaclib
    tmp = Path(tempfile.mkdtemp(prefix="pyzipper-contract-"))
    ok = True

    good = tmp / "good.zip"
    build_archive(good)
    verified = verify(good, b"pw", require_exact_members={"a.txt", "b.txt"},
                      member_identity=IDENTITY)
    print("ACCEPT good archive: %d members, manifest %s"
          % (len(verified.members), verified.manifest_sha256[:16]))

    # 1. same-length rename of both local and central names
    renamed = tmp / "renamed.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    for rec in recs:
        new = {"a.txt": "x.txt", "b.txt": "y.txt"}[rec["name"]]
        data[rec["pos"] + 46:rec["pos"] + 51] = new.encode()
        lh = rec["header_offset"]
        data[lh + 30:lh + 35] = new.encode()
    renamed.write_bytes(data)
    ok &= _expect_reject("renamed both headers (allowlist)",
                         lambda: verify(renamed, b"pw",
                                        require_exact_members={"a.txt", "b.txt"}))

    # 2. permissions changed in external_attr
    chmodded = tmp / "chmod.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    struct.pack_into("<L", data, recs[0]["pos"] + 38, 0o777 << 16)
    chmodded.write_bytes(data)
    ok &= _expect_reject("external_attr rewritten (mode allowlist)",
                         lambda: verify(chmodded, b"pw",
                                        expected_modes={"a.txt": 0o600, "b.txt": 0o600}))

    key = b"business-signing-key"
    good_sig = hmac.new(key, verify(good, b"pw", member_identity=IDENTITY).manifest(),
                        hashlib.sha256).digest()

    # 3. whole encrypted blob transplant
    swapped = tmp / "swapped.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    assert recs[0]["compress_size"] == recs[1]["compress_size"]
    span = recs[0]["compress_size"]
    for a, b in ((recs[0], recs[1]),):
        def start(rec):
            lh = rec["header_offset"]
            fh = struct.unpack_from("<4s2B4HL2L2H", data, lh)
            return lh + 30 + fh[10] + fh[11]
        sa, sb = start(a), start(b)
        da = bytes(data[sa:sa + span])
        db = bytes(data[sb:sb + span])
        data[sa:sa + span] = db
        data[sb:sb + span] = da
    swapped.write_bytes(data)
    # The blob swap keeps each member's HMAC valid, so no local check can reject
    # it. Only an external binding of (name -> content digest) catches it.
    swapped_verified = verify(swapped, b"pw", require_exact_members={"a.txt", "b.txt"},
                              member_identity=IDENTITY)
    print("ACCEPT blobs swapped locally (HMAC always passes); manifest digest now %s"
          % swapped_verified.manifest_sha256[:16])
    ok &= _expect_reject("swapped blobs with external manifest",
                         lambda: verify(swapped, b"pw",
                                        require_exact_members={"a.txt", "b.txt"},
                                        expected_manifest_hmac=(key, good_sig)))

    # 3b. declared uncompressed size lowered (central only): pyzipper returns a
    # truncated prefix and still reports HMAC success; external manifest catches.
    truncated = tmp / "truncated.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    struct.pack_into("<L", data, recs[0]["pos"] + 24, 2)
    truncated.write_bytes(data)
    truncated_verified = verify(truncated, b"pw", require_exact_members={"a.txt", "b.txt"},
                                member_identity=IDENTITY)
    print("ACCEPT size field lowered locally: a.txt returned %d byte(s), HMAC passed"
          % truncated_verified.members[0].size)
    ok &= _expect_reject("size field lowered with external manifest",
                         lambda: verify(truncated, b"pw",
                                        require_exact_members={"a.txt", "b.txt"},
                                        member_identity=IDENTITY,
                                        expected_manifest_hmac=(key, good_sig)))

    # 3c. local header AES metadata disagrees with the central directory
    local_only = tmp / "local_meta.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    lh = recs[0]["header_offset"]
    fh = struct.unpack_from(structFileHeader, data, lh)
    local_extra = lh + 30 + fh[10]
    p = local_extra
    while p < local_extra + fh[11]:
        tag, ln = struct.unpack_from("<HH", data, p)
        if tag == 0x9901:
            data[p + 8] = 1          # local strength 256 -> 128
            break
        p += 4 + ln
    local_only.write_bytes(data)
    ok &= _expect_reject("local-only AES strength change",
                         lambda: verify(local_only, b"pw",
                                        require_exact_members={"a.txt", "b.txt"}))

    # 3d. central-directory order swapped: local HMAC passes, order binding fails
    reordered = tmp / "reordered.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    start = min(r["pos"] for r in recs)
    cd = bytes(data[start:start + (recs[-1]["pos"] + recs[-1]["len"] - start)])
    first, second = recs[0], recs[1]
    a0, a1 = first["pos"] - start, first["pos"] - start + first["len"]
    b0, b1 = second["pos"] - start, second["pos"] - start + second["len"]
    new_cd = cd[:a0] + cd[b0:b1] + cd[a1:b0] + cd[a0:a1] + cd[b1:]
    data[start:start + len(cd)] = new_cd
    reordered.write_bytes(data)
    reordered_verified = verify(reordered, b"pw",
                                require_exact_members={"a.txt", "b.txt"},
                                member_identity=IDENTITY)
    print("ACCEPT reordered CD locally: member order is now %r"
          % [m.name for m in reordered_verified.members])
    ok &= _expect_reject("reordered CD with external manifest",
                         lambda: verify(reordered, b"pw",
                                        require_exact_members={"a.txt", "b.txt"},
                                        member_identity=IDENTITY,
                                        expected_manifest_hmac=(key, good_sig)))

    # 3d2. archive comment rewritten: HMAC passes, manifest binding fails
    archive_comment_bad = tmp / "archive_comment_bad.zip"
    data = bytearray(good.read_bytes())
    recs, comment = _parse_raw(bytes(data))
    if comment:
        start = len(data) - len(comment)
        data[start:start + len(comment)] = b"C" * len(comment)
    else:
        data[-1:] = b"X"
    archive_comment_bad.write_bytes(data)
    ac_verified = verify(archive_comment_bad, b"pw",
                         require_exact_members={"a.txt", "b.txt"},
                         member_identity=IDENTITY)
    print("ACCEPT archive-comment rewrite locally: HMAC passed, archive comment %r"
          % ac_verified.archive_comment)
    ok &= _expect_reject("archive comment with external manifest",
                         lambda: verify(archive_comment_bad, b"pw",
                                        require_exact_members={"a.txt", "b.txt"},
                                        member_identity=IDENTITY,
                                        expected_manifest_hmac=(key, good_sig)))

    # 3e. per-entry comment rewritten: HMAC passes, manifest binding fails
    comment_bad = tmp / "comment_bad.zip"
    data = bytearray(good.read_bytes())
    recs, _ = _parse_raw(bytes(data))
    if recs[0]["entry_comment"]:
        start = recs[0]["pos"] + recs[0]["len"] - len(recs[0]["entry_comment"])
        data[start:start + len(recs[0]["entry_comment"])] = b"C" * len(recs[0]["entry_comment"])
    comment_bad.write_bytes(data)
    comment_verified = verify(comment_bad, b"pw",
                              require_exact_members={"a.txt", "b.txt"},
                              member_identity=IDENTITY)
    print("ACCEPT entry-comment rewrite locally: HMAC passed, comment digest %s"
          % comment_verified.members[0].entry_comment_sha256[:16])
    ok &= _expect_reject("entry comment with external manifest",
                         lambda: verify(comment_bad, b"pw",
                                        require_exact_members={"a.txt", "b.txt"},
                                        member_identity=IDENTITY,
                                        expected_manifest_hmac=(key, good_sig)))

    # 4. unencrypted archive
    plain = tmp / "plain.zip"
    with zipfile.ZipFile(plain, "w") as zf:
        zf.writestr("a.txt", b"alpha")
    ok &= _expect_reject("plaintext archive",
                         lambda: verify(plain, b"pw"))

    # 5. empty archive
    empty = tmp / "empty.zip"
    build_archive(empty, members={})
    ok &= _expect_reject("empty archive",
                         lambda: verify(empty, b"pw", require_min_members=1))

    # 6. AE-1 when AE-2 required
    ae1 = tmp / "ae1.zip"
    build_archive(ae1, ae2=False)
    ok &= _expect_reject("AE-1 archive under AE-2 contract",
                         lambda: verify(ae1, b"pw"))

    # 7. external manifest signature is what binds identity
    v = verify(good, b"pw", require_exact_members={"a.txt", "b.txt"},
               member_identity=IDENTITY)
    sig = hmaclib.new(key, v.manifest(), hashlib.sha256).digest()
    print("external manifest HMAC accepted:",
          verify(good, b"pw", require_exact_members={"a.txt", "b.txt"},
                 member_identity=IDENTITY,
                 expected_manifest_hmac=(key, sig)).manifest_sha256[:16])
    ok &= _expect_reject("manifest signature over different identity",
                         lambda: verify(renamed, b"pw", require_exact_members={"x.txt", "y.txt"},
                                        member_identity={"x.txt": ("invoice", "INV-1"),
                                                         "y.txt": ("invoice", "INV-2")},
                                        expected_manifest_hmac=(key, sig)))

    # 8. wrong password and truncated archive are rejected
    ok &= _expect_reject("wrong password",
                         lambda: verify(good, b"wrong", require_exact_members={"a.txt", "b.txt"}))
    truncated_file = tmp / "cut.zip"
    truncated_file.write_bytes(good.read_bytes()[:300])
    ok &= _expect_reject("truncated archive",
                         lambda: verify(truncated_file, b"pw"))

    print("\ncontract demo:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
