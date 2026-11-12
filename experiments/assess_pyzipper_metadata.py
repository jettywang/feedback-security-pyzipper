#!/usr/bin/env python3
"""Byte-level assessment of what pyzipper/WinZip-AES actually authenticates.

Builds a small AES-256 archive with ZIP_STORED members (so offsets are stable),
then mutates exactly one metadata class / ciphertext region at a time and
reports:
  * whether the member still decrypts,
  * whether the AES HMAC was checked and whether it passed,
  * whether returned plaintext still matches the expected bytes,
  * which metadata fields changed.

Run:  .venv/bin/python experiments/assess_pyzipper_metadata.py
"""

from __future__ import annotations

import os
import stat
import struct
import sys
import tempfile
import zlib
from pathlib import Path

import pyzipper
from Cryptodome.Hash import HMAC
from Cryptodome.Hash.SHA1 import SHA1Hash
from Cryptodome.Protocol.KDF import PBKDF2
from pyzipper import AESZipFile, WZ_AES, ZIP_STORED, BadZipFile
from pyzipper import zipfile_aes
from pyzipper.zipfile import structCentralDir, structEndArchive, structFileHeader

PASSWORD = b"correct horse battery staple"
ARCHIVE_COMMENT = b"archive-comment-original"
ARCHIVE_COMMENT_TAMPER = b"archive-comment-tampered"
MEMBERS = [
    ("alpha.txt", b"alpha secret payload", 0o600, b"alpha-comment-original"),
    ("beta.txt", b"beta secret payload!", 0o640, b"beta-comment-original!"),
    ("gamma.txt", b"gamma secret payload", 0o644, b"gamma-comment-original"),
]
# Same-length replacements keep every later byte offset stable.
RENAME = {"alpha.txt": "omega.txt", "beta.txt": "zeta.txt", "gamma.txt": "kappa.txt"}
EXPECTED = {name: payload for name, payload, _, _ in MEMBERS}

# ---------------------------------------------------------------- instrumentation

HMAC_STATS = {"calls": 0, "pass": 0, "fail": 0}
_ORIG_CHECK_HMAC = zipfile_aes.AESZipDecrypter.check_hmac


def _counting_check_hmac(self, hmac_check):
    HMAC_STATS["calls"] += 1
    try:
        _ORIG_CHECK_HMAC(self, hmac_check)
    except BadZipFile:
        HMAC_STATS["fail"] += 1
        raise
    else:
        HMAC_STATS["pass"] += 1


zipfile_aes.AESZipDecrypter.check_hmac = _counting_check_hmac


def reset_hmac_stats():
    HMAC_STATS["calls"] = 0
    HMAC_STATS["pass"] = 0
    HMAC_STATS["fail"] = 0


# ------------------------------------------------------------------ byte helpers


def read_bytes(path):
    return bytearray(Path(path).read_bytes())


def write_bytes(path, data):
    Path(path).write_bytes(bytes(data))


def parse_archive(data: bytes):
    eocd_pos = data.rfind(b"PK\x05\x06")
    if eocd_pos < 0:
        raise RuntimeError("no EOCD")
    eocd = struct.unpack_from(structEndArchive, data, eocd_pos)
    cd_size, cd_offset, comment_len = eocd[5], eocd[6], eocd[7]
    if eocd_pos + 22 + comment_len != len(data):
        raise RuntimeError("trailing bytes after EOCD comment")
    records = []
    p = cd_offset
    end = cd_offset + cd_size
    while p < end:
        f = struct.unpack_from(structCentralDir, data, p)
        name_len, extra_len, entry_comment_len = f[12], f[13], f[14]
        rec_len = 46 + name_len + extra_len + entry_comment_len
        records.append({
            "cd_pos": p,
            "cd_len": rec_len,
            "name": bytes(data[p + 46:p + 46 + name_len]).decode("cp437"),
            "name_len": name_len,
            "extra_len": extra_len,
            "entry_comment_len": entry_comment_len,
            "extra": bytes(data[p + 46 + name_len:p + 46 + name_len + extra_len]),
            "entry_comment": bytes(data[p + 46 + name_len + extra_len:
                                     p + 46 + name_len + extra_len + entry_comment_len]),
            "header_offset": f[18],
            "flag_bits": f[5],
            "compress_type": f[6],
            "CRC": f[9],
            "compress_size": f[10],
            "file_size": f[11],
            "internal_attr": f[16],
            "external_attr": f[17],
        })
        p += rec_len
    return {
        "eocd_pos": eocd_pos,
        "cd_offset": cd_offset,
        "cd_size": cd_size,
        "comment": bytes(data[eocd_pos + 22:eocd_pos + 22 + comment_len]),
        "records": records,
    }


def aes_extra(rec):
    extra = rec["extra"]
    p = 0
    while p + 4 <= len(extra):
        tag, ln = struct.unpack_from("<HH", extra, p)
        if tag == 0x9901:
            version, vendor, strength, actual_comp = struct.unpack_from(
                "<H2sBH", extra, p + 4)
            return {
                "cd_pos": rec["cd_pos"] + 46 + rec["name_len"] + p,
                "version": version,
                "vendor": vendor,
                "strength": strength,
                "actual_comp": actual_comp,
            }
        p += 4 + ln
    raise RuntimeError("no WZ_AES extra for %r" % rec["name"])


def member_regions(data: bytes, rec):
    ex = aes_extra(rec)
    lh = rec["header_offset"]
    fh = struct.unpack_from(structFileHeader, data, lh)
    local_name_len, local_extra_len = fh[10], fh[11]
    data_start = lh + 30 + local_name_len + local_extra_len
    salt_len = {1: 8, 2: 12, 3: 16}[ex["strength"]]
    ct_start = data_start + salt_len + 2
    ct_len = rec["compress_size"] - salt_len - 2 - 10
    hmac_start = ct_start + ct_len
    return {
        "local_header": lh,
        "local_name": lh + 30,
        "local_extra": lh + 30 + local_name_len,
        "salt": data_start,
        "salt_len": salt_len,
        "pwd_verify": data_start + salt_len,
        "ciphertext": ct_start,
        "ct_len": ct_len,
        "hmac": hmac_start,
        "hmac_len": 10,
        "cd_record": rec["cd_pos"],
        "cd_name": rec["cd_pos"] + 46,
        "cd_extra": rec["cd_pos"] + 46 + rec["name_len"],
        "cd_comment": rec["cd_pos"] + 46 + rec["name_len"] + rec["extra_len"],
    }


def print_layout(data: bytes):
    parsed = parse_archive(data)
    print("EOCD @ %d, CD @ %d..%d (%d records), archive comment %d bytes @ EOCD+22"
          % (parsed["eocd_pos"], parsed["cd_offset"],
             parsed["cd_offset"] + parsed["cd_size"], len(parsed["records"]),
             len(parsed["comment"])))
    for i, rec in enumerate(parsed["records"]):
        r = member_regions(data, rec)
        ex = aes_extra(rec)
        print("  [%d] %-9s LFH@%-4d local-name@%-4d local-extra@%-4d "
              "salt@%-4d+%d pwd-verify@%-4d+2 ciphertext@%-4d+%d hmac@%-4d+10"
              % (i, rec["name"], r["local_header"], r["local_name"],
                 r["local_extra"], r["salt"], r["salt_len"], r["pwd_verify"],
                 r["ciphertext"], r["ct_len"], r["hmac"]))
        print("      CD@%-4d name@%-4d extra@%-4d comment@%-4d ext-attr@%-4d "
              "AE-extra@%-4d ver=%d vendor=%r strength=%d actual-comp=%d"
              % (r["cd_record"], r["cd_name"], r["cd_extra"], r["cd_comment"],
                 r["cd_record"] + 38, ex["cd_pos"], ex["version"], ex["vendor"],
                 ex["strength"], ex["actual_comp"]))


# --------------------------------------------------------------------- patching


def patch_local_name(data, rec, new_name, old_name):
    assert len(new_name.encode("cp437")) == len(old_name.encode("cp437"))
    p = member_regions(data, rec)["local_name"]
    data[p:p + len(old_name)] = new_name.encode("cp437")


def patch_cd_name(data, rec, new_name):
    assert len(new_name.encode("cp437")) == rec["name_len"]
    p = member_regions(data, rec)["cd_name"]
    data[p:p + rec["name_len"]] = new_name.encode("cp437")


def patch_cd_u32(data, rec, offset, value):
    struct.pack_into("<L", data, rec["cd_pos"] + offset, value)


def swap_records(data, parsed, rec_a, rec_b):
    start = parsed["cd_offset"]
    cd = data[start:start + parsed["cd_size"]]
    a0 = rec_a["cd_pos"] - start
    a1 = a0 + rec_a["cd_len"]
    b0 = rec_b["cd_pos"] - start
    b1 = b0 + rec_b["cd_len"]
    assert a1 <= b0
    data[start:start + parsed["cd_size"]] = (
        cd[:a0] + cd[b0:b1] + cd[a1:b0] + cd[a0:a1] + cd[b1:]
    )


def swap_member_data(data, rec_a, rec_b):
    """Swap complete encrypted payloads (salt + pwd-verify + ciphertext + HMAC).

    No HMAC key or password is needed. Both members must have equal
    compress_size for this byte-for-byte transplant to stay self-consistent.
    """
    assert rec_a["compress_size"] == rec_b["compress_size"]
    span = rec_a["compress_size"]
    ra = member_regions(bytes(data), rec_a)
    rb = member_regions(bytes(data), rec_b)
    da = data[ra["salt"]:ra["salt"] + span]
    db = data[rb["salt"]:rb["salt"] + span]
    data[ra["salt"]:ra["salt"] + span] = db
    data[rb["salt"]:rb["salt"] + span] = da


# ---------------------------------------------------------------------- archive


def build_baseline(path):
    with AESZipFile(path, "w", compression=ZIP_STORED, encryption=WZ_AES,
                    encryption_kwargs={"nbits": 256}) as zf:
        zf.setpassword(PASSWORD)
        for name, payload, mode, comment in MEMBERS:
            zinfo = zipfile_aes.AESZipInfo(name, date_time=(2020, 1, 2, 3, 4, 6))
            zinfo.compress_type = ZIP_STORED
            zinfo.external_attr = mode << 16
            zinfo.comment = comment
            zf.writestr(zinfo, payload)
        zf.comment = ARCHIVE_COMMENT


def read_archive(path, expected, password=PASSWORD, partial_bytes=None):
    """Read all members in central-directory order via the production API."""
    reset_hmac_stats()
    out = {"open_ok": False, "open_error": None, "names": [], "archive_comment": None,
           "members": []}
    try:
        with AESZipFile(path, "r") as zf:
            out["open_ok"] = True
            out["names"] = zf.namelist()
            out["archive_comment"] = zf.comment
            for z in zf.infolist():
                m = {
                    "name": z.filename, "declared_size": z.file_size,
                    "compress_size": z.compress_size, "CRC": z.CRC,
                    "external_attr": z.external_attr,
                    "mode": stat.filemode(z.external_attr >> 16),
                    "entry_comment": z.comment,
                }
                try:
                    if partial_bytes is not None:
                        with zf.open(z.filename, "r", pwd=password) as f:
                            got = f.read(partial_bytes)
                        m["data_len"] = len(got)
                        m["data_prefix"] = got
                        m["content_ok"] = expected[z.filename].startswith(got)
                        m["status"] = "partial-read-returned"
                    else:
                        got = zf.read(z.filename, pwd=password)
                        m["data_len"] = len(got)
                        m["data"] = got
                        m["content_ok"] = got == expected[z.filename]
                        m["status"] = "ok"
                except Exception as exc:  # noqa: BLE001 - exact exception is evidence
                    m["status"] = "%s: %s" % (type(exc).__name__, exc)
                    m["content_ok"] = False
                out["members"].append(m)
    except Exception as exc:  # noqa: BLE001
        out["open_error"] = "%s: %s" % (type(exc).__name__, exc)
    out["hmac"] = dict(HMAC_STATS)
    return out


def summarize(case, result, fields):
    errors = []
    if result["open_error"]:
        errors.append("open: " + result["open_error"])
    errors.extend(m["status"] for m in result["members"] if m["status"] != "ok")
    h = result["hmac"]
    if h["calls"] == 0:
        hmac = "not checked"
    elif h["fail"]:
        hmac = "FAILED %d/%d" % (h["fail"], h["calls"])
    else:
        hmac = "PASSED %d/%d" % (h["pass"], h["calls"])
    read_ok = result["open_ok"] and not errors
    content_ok = result["open_ok"] and all(m["content_ok"] for m in result["members"])
    return {
        "case": case,
        "decrypt": "YES" if read_ok else "NO",
        "hmac": hmac,
        "content": "MATCH" if content_ok else "MISMATCH",
        "fields": fields,
        "error": "; ".join(errors) if errors else "-",
        "result": result,
    }


def mutate_and_run(base, tmp, case, mutate, expected=None, partial_bytes=None):
    data = read_bytes(base)
    parsed = parse_archive(bytes(data))
    fields = mutate(data, parsed)
    path = tmp / (case.replace(" ", "_").replace("/", "-") + ".zip")
    write_bytes(path, data)
    result = read_archive(path, expected or EXPECTED, partial_bytes=partial_bytes)
    return summarize(case, result, fields)


# ------------------------------------------------------------------------- main


def main():
    tmp = Path(tempfile.mkdtemp(prefix="pyzipper-assessment-"))
    base = tmp / "baseline.zip"
    build_baseline(base)
    baseline = read_bytes(base)
    print("== environment ==")
    print("python=%s pyzipper=%s" % (sys.version.split()[0], pyzipper.__version__))
    print("baseline=%s bytes=%d" % (base, len(baseline)))
    print("\n== baseline byte layout ==")
    print_layout(bytes(baseline))

    rows = [summarize("baseline", read_archive(base, EXPECTED), "none")]

    def add(case, mutate, expected=None, partial_bytes=None, show=False):
        s = mutate_and_run(base, tmp, case, mutate, expected, partial_bytes)
        rows.append(s)
        if show:
            print("\n-- %s --" % case)
            print("fields: %s" % s["fields"])
            print("names seen: %r" % s["result"]["names"])
            for m in s["result"]["members"]:
                print("  %-9s mode=%-10s entry-comment=%-26r declared_size=%-3d "
                      "crc=0x%08x status=%s content_ok=%s data=%r"
                      % (m["name"], m["mode"], m["entry_comment"],
                         m["declared_size"], m["CRC"], m["status"],
                         m["content_ok"],
                         m.get("data", m.get("data_prefix", ""))))
            print("HMAC stats: %r" % s["result"]["hmac"])
            if s["result"]["archive_comment"] is not None:
                print("archive comment: %r" % s["result"]["archive_comment"])
        return s

    def rename_both(data, parsed):
        for rec in parsed["records"]:
            patch_local_name(data, rec, RENAME[rec["name"]], rec["name"])
            patch_cd_name(data, rec, RENAME[rec["name"]])
        return "local name + CD name renamed (same lengths): " + ", ".join(
            "%s->%s" % (k, v) for k, v in RENAME.items())

    add("rename both headers", rename_both,
        {RENAME[k]: v for k, v in EXPECTED.items()}, show=True)

    def rename_cd_only(data, parsed):
        rec = parsed["records"][0]
        patch_cd_name(data, rec, "omega.txt")
        return "CD name only: alpha.txt->omega.txt (local header untouched)"

    add("rename CD only", rename_cd_only,
        {"omega.txt": EXPECTED["alpha.txt"], "beta.txt": EXPECTED["beta.txt"],
         "gamma.txt": EXPECTED["gamma.txt"]}, show=True)

    def reorder(data, parsed):
        swap_records(data, parsed, parsed["records"][0], parsed["records"][1])
        return "swap complete CD records: alpha.txt <-> beta.txt"

    add("central directory order", reorder, show=True)

    def chmod(data, parsed):
        rec = parsed["records"][0]
        old = rec["external_attr"]
        patch_cd_u32(data, rec, 38, 0o777 << 16)
        return "CD external_attr: 0o%o (%s) -> 0o777 (%s)" % (
            old >> 16, stat.filemode(old >> 16), stat.filemode(0o777))

    add("permissions external_attr", chmod, show=True)

    def entry_comment(data, parsed):
        rec = parsed["records"][0]
        start = member_regions(bytes(data), rec)["cd_comment"]
        old = bytes(data[start:start + rec["entry_comment_len"]])
        new = b"E" * rec["entry_comment_len"]
        data[start:start + rec["entry_comment_len"]] = new
        return "per-entry comment: %r -> %r (same length)" % (old, new)

    add("entry comment", entry_comment, show=True)

    def archive_comment(data, parsed):
        start = parsed["eocd_pos"] + 22
        assert len(parsed["comment"]) == len(ARCHIVE_COMMENT)
        data[start:start + len(ARCHIVE_COMMENT)] = ARCHIVE_COMMENT_TAMPER
        return "archive comment: %r -> %r" % (ARCHIVE_COMMENT, ARCHIVE_COMMENT_TAMPER)

    add("archive comment", archive_comment, show=True)

    def flip_ciphertext(data, parsed):
        rec = parsed["records"][0]
        p = member_regions(bytes(data), rec)["hmac"] - 8
        data[p] ^= 0x01
        return "ciphertext byte @%d ^= 0x01 (first member)" % p

    add("flip ciphertext", flip_ciphertext, show=True)

    add("flip ciphertext then partial read", flip_ciphertext, partial_bytes=1, show=True)

    def flip_hmac(data, parsed):
        rec = parsed["records"][0]
        p = member_regions(bytes(data), rec)["hmac"] + 9
        data[p] ^= 0x01
        return "stored HMAC tag byte @%d ^= 0x01 (first member)" % p

    add("flip hmac", flip_hmac, show=True)

    def size_up(data, parsed):
        rec = parsed["records"][0]
        old = rec["file_size"]
        patch_cd_u32(data, rec, 24, old + 100)
        return "declared uncompressed size: %d -> %d" % (old, old + 100)

    add("declared file_size upward", size_up, show=True)

    def size_down(data, parsed):
        rec = parsed["records"][0]
        old = rec["file_size"]
        patch_cd_u32(data, rec, 24, old - 5)
        return "declared uncompressed size: %d -> %d" % (old, old - 5)

    add("declared file_size downward", size_down, show=True)

    def csize_down(data, parsed):
        rec = parsed["records"][0]
        old = rec["compress_size"]
        patch_cd_u32(data, rec, 20, old - 1)
        return "declared compressed size: %d -> %d" % (old, old - 1)

    add("declared compress_size downward", csize_down, show=True)

    def crc_forge(data, parsed):
        rec = parsed["records"][0]
        real = zlib.crc32(EXPECTED["alpha.txt"]) & 0xFFFFFFFF
        old = rec["CRC"]
        patch_cd_u32(data, rec, 16, real)
        return "CD CRC: 0x%08x -> real plaintext CRC 0x%08x" % (old, real)

    add("CRC forged (known plaintext)", crc_forge, show=True)

    def vendor(data, parsed):
        rec = parsed["records"][0]
        p = aes_extra(rec)["cd_pos"] + 6
        data[p:p + 2] = b"XX"
        return "WZ_AES vendor ID: AE -> XX"

    add("aes vendor id", vendor, show=True)

    def version_and_crc(data, parsed):
        rec = parsed["records"][0]
        struct.pack_into("<H", data, aes_extra(rec)["cd_pos"] + 4, 1)
        real = zlib.crc32(EXPECTED["alpha.txt"]) & 0xFFFFFFFF
        patch_cd_u32(data, rec, 16, real)
        return "WZ_AES version 2 -> 1 plus CD CRC = real plaintext CRC"

    add("aes version + forged crc", version_and_crc, show=True)

    def strength(data, parsed):
        rec = parsed["records"][0]
        data[aes_extra(rec)["cd_pos"] + 8] = 1
        return "WZ_AES strength 3 -> 1 (256-bit -> 128-bit metainfo)"

    add("aes strength", strength, show=True)

    def combined(data, parsed):
        rename_both(data, parsed)
        chmod(data, parsed)
        entry_comment(data, parsed)
        archive_comment(data, parsed)
        swap_records(data, parsed, parsed["records"][0], parsed["records"][1])
        return ("names in both headers, external_attr 0o600->0o777, entry comment, "
                "archive comment, and CD order all changed; ciphertext untouched")

    add("COMBINED business metadata", combined,
        {RENAME[k]: v for k, v in EXPECTED.items()}, show=True)


    # --- local header fields are not compared except the filename -----------
    def local_header_metadata(data, parsed):
        rec = parsed["records"][0]
        lh = rec["header_offset"]
        fh = struct.unpack_from(structFileHeader, data, lh)
        # local CRC, compressed size and uncompressed size live at 14, 18, 22
        struct.pack_into("<L", data, lh + 14, fh[7] ^ 0xFFFFFFFF)
        struct.pack_into("<L", data, lh + 18, 7)
        struct.pack_into("<L", data, lh + 22, 999)
        return "local header CRC/sizes changed; only local filename is compared"

    add("local header CRC+sizes", local_header_metadata, show=True)

    def local_extra_strength(data, parsed):
        rec = parsed["records"][0]
        lh = rec["header_offset"]
        fh = struct.unpack_from(structFileHeader, data, lh)
        local_extra = lh + 30 + fh[10]
        p = local_extra
        while p + 4 <= local_extra + fh[11]:
            tag, ln = struct.unpack_from("<HH", data, p)
            if tag == 0x9901:
                data[p + 8] = 1
                return "local WZ_AES extra strength 3 -> 1 (central still 3)"
            p += 4 + ln
        raise RuntimeError("no local AE extra")

    add("local AES strength only", local_extra_strength, show=True)

    # --- remove a member record; remaining members still authenticate ------
    def remove_last_record(data, parsed):
        rec = parsed["records"][-1]
        start = rec["cd_pos"]
        del data[start:start + rec["cd_len"]]
        eocd = parsed["eocd_pos"] - rec["cd_len"]
        struct.pack_into("<HH", data, eocd + 8, 2, 2)   # entries this disk / total
        struct.pack_into("<L", data, eocd + 12, parsed["cd_size"] - rec["cd_len"])
        return "removed last CD record (gamma.txt); EOCD count 3 -> 2"

    add("remove one member", remove_last_record,
        {"alpha.txt": EXPECTED["alpha.txt"], "beta.txt": EXPECTED["beta.txt"]},
        show=True)

    # --- strongest identity-binding counterexample -------------------------
    def swap_encrypted_blobs(data, parsed):
        # alpha and beta must be the same compressed size for the transplant.
        swap_member_data(data, parsed["records"][0], parsed["records"][1])
        return ("whole AE-2 payloads (salt+pwd-verify+ciphertext+HMAC) swapped "
                "between alpha.txt and beta.txt; no key used")

    add("swap encrypted member blobs", swap_encrypted_blobs, EXPECTED, show=True)

    # --- prove HMAC input is ciphertext only -------------------------------
    print("\n== HMAC input reconstruction ==")
    rec0 = parse_archive(bytes(baseline))["records"][0]
    r0 = member_regions(bytes(baseline), rec0)
    salt = bytes(baseline[r0["salt"]:r0["salt"] + r0["salt_len"]])
    ct = bytes(baseline[r0["ciphertext"]:r0["ciphertext"] + r0["ct_len"]])
    stored = bytes(baseline[r0["hmac"]:r0["hmac"] + 10])
    keylen = {1: 16, 2: 24, 3: 32}[aes_extra(rec0)["strength"]]
    km = PBKDF2(PASSWORD, salt, count=1000, dkLen=2 * keylen + 2)
    h = HMAC.new(km[keylen:2 * keylen], digestmod=SHA1Hash())
    h.update(ct)
    recomputed = h.digest()[:10]
    print("salt=%r ciphertext=%d bytes stored-tag=%s" % (salt.hex(), len(ct), stored.hex()))
    print("HMAC-SHA1(mac-key, ciphertext)[:10]=%s equal-stored=%r"
          % (recomputed.hex(), recomputed == stored))
    print("=> name, local/central extra fields, comments, external_attr and "
          "the central-directory position are outside the MAC input.")

    # --- salt / password-verifier tampering: rejected before HMAC -------------
    print("\n== salt and password-verifier tampering ==")
    salt_bad = tmp / "salt_bad.zip"
    sv_bad = tmp / "pwd_verify_bad.zip"
    rec0 = parse_archive(bytes(baseline))["records"][0]
    r0 = member_regions(bytes(baseline), rec0)
    d = read_bytes(base)
    d[r0["salt"] + 3] ^= 0x01
    write_bytes(salt_bad, d)
    d = read_bytes(base)
    d[r0["pwd_verify"]] ^= 0x01
    write_bytes(sv_bad, d)
    for label, path in (("salt byte", salt_bad), ("password-verifier byte", sv_bad)):
        res = read_archive(path, EXPECTED)
        print("%s: %s" % (label, res["members"][0]["status"]))
    print("=> these fail the PBKDF2/password check before the AES path, so the "
          "member is rejected; this is password correctness, not identity.")

    print("\n== empty archive: no member means no password/HMAC check ==")
    empty = tmp / "empty.zip"
    with AESZipFile(empty, "w", compression=ZIP_STORED, encryption=WZ_AES,
                    encryption_kwargs={"nbits": 256}) as zf:
        zf.setpassword(PASSWORD)
        zf.comment = b"empty-archive-comment"
    empty_result = read_archive(empty, {})
    print("empty archive read without password: open_ok=%r names=%r hmac=%r"
          % (empty_result["open_ok"], empty_result["names"], empty_result["hmac"]))
    print("=> a loop over infolist() has zero iterations; 'read success' is vacuous.")

    print("\n== plaintext archive: pyzipper reads it with a supplied password and no HMAC ==")
    plain = tmp / "plaintext.zip"
    with pyzipper.ZipFile(plain, "w", compression=ZIP_STORED) as zf:
        for name, payload, _, _ in MEMBERS:
            zf.writestr(name, payload)
    plain_result = read_archive(plain, EXPECTED)
    print("plaintext decrypt=%s hmac=%r content=%s"
          % ("YES" if plain_result["open_ok"] else "NO", plain_result["hmac"],
             all(m["content_ok"] for m in plain_result["members"])))
    print("=> if the receiver does not require AE per member, an unencrypted "
          "archive is accepted and no HMAC exists at all.")

    print("\n== streaming read: HMAC is checked only at EOF ==")
    large = tmp / "large.zip"
    with AESZipFile(large, "w", compression=ZIP_STORED, encryption=WZ_AES,
                    encryption_kwargs={"nbits": 256}) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("large.bin", b"A" * 8192)
    large_data = read_bytes(large)
    large_parsed = parse_archive(bytes(large_data))
    large_rec = large_parsed["records"][0]
    ct = member_regions(bytes(large_data), large_rec)["ciphertext"]
    large_data[ct + 100] ^= 0x01
    large_bad = tmp / "large_bad.zip"
    write_bytes(large_bad, large_data)
    reset_hmac_stats()
    with AESZipFile(large_bad, "r") as zf:
        with zf.open("large.bin", "r", pwd=PASSWORD) as f:
            prefix = f.read(200)
            prefix_stats = dict(HMAC_STATS)
            try:
                tail = f.read()
                tail_status = "ok"
            except Exception as exc:  # noqa: BLE001
                tail_status = "%s: %s" % (type(exc).__name__, exc)
    print("prefix read(200) returned %d bytes, differs from original at offset 100: %r"
          % (len(prefix), prefix[100] != ord("A")))
    print("HMAC stats after prefix read: %r (0 calls means no authentication yet)"
          % prefix_stats)
    print("reading to EOF then: %s" % tail_status)
    print("=> do not release any plaintext to business logic before full-member HMAC.")

    print("\n== mutation matrix ==")
    print("case | decrypt | HMAC | content | changed fields | error")
    print("--- | --- | --- | --- | --- | ---")
    for s in rows:
        print("%s | %s | %s | %s | %s | %s"
              % (s["case"], s["decrypt"], s["hmac"], s["content"], s["fields"],
                 s["error"]))

    print("\n== extraction: does pyzipper apply external_attr? ==")
    perm = tmp / "permissions_extract.zip"
    data = read_bytes(base)
    chmod(data, parse_archive(bytes(data)))
    write_bytes(perm, data)
    outdir = Path(tempfile.mkdtemp(prefix="pyzipper-extract-"))
    with AESZipFile(perm, "r") as zf:
        zf.extractall(path=outdir, pwd=PASSWORD)
    extracted_mode = stat.filemode(os.stat(outdir / "alpha.txt").st_mode)
    print("archive metadata claims mode=%s; extracted file mode=%s"
          % (stat.filemode(0o777), extracted_mode))
    print("=> pyzipper._extract_member never applies external_attr (it only reads "
          "member.filename); consumers that map archive permissions themselves "
          "would apply the tampered 0777.")

    print("\n== same password, attacker-built valid archive ==")
    repl = tmp / "replacement.zip"
    with AESZipFile(repl, "w", compression=ZIP_STORED, encryption=WZ_AES,
                    encryption_kwargs={"nbits": 256}) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("alpha.txt", b"attacker chosen content")
        zf.comment = ARCHIVE_COMMENT_TAMPER
    r = read_archive(repl, {"alpha.txt": b"attacker chosen content"})
    s = summarize("valid replacement archive", r,
                  "fresh AE-2 archive, arbitrary content, same password")
    print("decrypt=%s hmac=%s content=%s error=%s"
          % (s["decrypt"], s["hmac"], s["content"], s["error"]))
    print("member names: %r, archive comment: %r"
          % (r["names"], r["archive_comment"]))
    print("HMAC stats: %r" % r["hmac"])

    # ---------------------------------------------------------------- assertions
    # The point of the experiment is to pin the exact security boundary. These
    # assertions fail loudly if a future pyzipper version changes the contract.
    by_case = {s["case"]: s for s in rows}

    def assert_row(case, decrypt, hmac, content):
        s = by_case[case]
        assert s["decrypt"] == decrypt, (case, s["decrypt"], decrypt)
        assert s["hmac"] == hmac, (case, s["hmac"], hmac)
        assert s["content"] == content, (case, s["content"], content)

    assert_row("baseline", "YES", "PASSED 3/3", "MATCH")
    # metadata mutations that pyzipper accepts without any HMAC failure
    assert_row("rename both headers", "YES", "PASSED 3/3", "MATCH")
    assert_row("central directory order", "YES", "PASSED 3/3", "MATCH")
    assert_row("permissions external_attr", "YES", "PASSED 3/3", "MATCH")
    assert_row("entry comment", "YES", "PASSED 3/3", "MATCH")
    assert_row("archive comment", "YES", "PASSED 3/3", "MATCH")
    assert_row("COMBINED business metadata", "YES", "PASSED 3/3", "MATCH")
    assert_row("swap encrypted member blobs", "YES", "PASSED 3/3", "MISMATCH")
    assert_row("declared file_size upward", "YES", "PASSED 3/3", "MATCH")
    assert_row("declared file_size downward", "YES", "PASSED 3/3", "MISMATCH")
    assert_row("CRC forged (known plaintext)", "YES", "PASSED 3/3", "MATCH")
    assert_row("aes vendor id", "YES", "PASSED 3/3", "MATCH")
    assert_row("aes version + forged crc", "YES", "PASSED 3/3", "MATCH")
    assert_row("local header CRC+sizes", "YES", "PASSED 3/3", "MATCH")
    assert_row("local AES strength only", "YES", "PASSED 3/3", "MATCH")
    assert_row("remove one member", "YES", "PASSED 2/2", "MATCH")
    # mutations that do break authentication or parsing
    assert_row("flip ciphertext", "NO", "FAILED 1/3", "MISMATCH")
    assert_row("flip hmac", "NO", "FAILED 1/3", "MISMATCH")
    assert_row("rename CD only", "NO", "PASSED 2/2", "MISMATCH")
    assert_row("declared compress_size downward", "NO", "FAILED 1/3", "MISMATCH")
    assert_row("aes strength", "NO", "PASSED 2/2", "MISMATCH")
    assert empty_result["hmac"]["calls"] == 0
    assert plain_result["hmac"]["calls"] == 0
    assert prefix_stats["calls"] == 0

    print("\nassertions: all %d expected results confirmed" % len(rows))
    print("temp dir: %s" % tmp)


if __name__ == "__main__":
    main()
