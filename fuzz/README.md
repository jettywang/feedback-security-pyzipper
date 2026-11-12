# Structured fuzzing for pyzipper AES / ZIP64 metadata

Target: the WZ-AES (`0x9901`) and ZIP64 (`0x0001`) extra-field chains in both
the local file header and the central-directory entry. The campaign looks for
three failure classes when extra-field order, duplicate field types and
declared/actual lengths contradict each other:

1. wrong algorithm selection (e.g. a duplicate AES field's last block wins and
   points a STORED payload at the deflate decompressor);
2. out-of-bounds reads (a declared/ZIP64 compressed size that makes the data
   reader cross the entry's payload boundary into the central directory/EOCD);
3. non-domain exceptions escaping the structured parser (`KeyError`,
   `struct.error`, `EOFError`, `zlib.error`, ...) instead of `BadZipFile`.

## Why the archives stay small and reach the parser

`mini_zip.py` rebuilds every mutated archive from explicit pieces and
recomputes the EOCD central-directory offset/size after each change. The
central directory is therefore always reachable: a malformed *metadata* chain
is never rejected up front by the EOCD or central-directory signature checks.
No real large file is needed -- ZIP64 placeholder sizes are just 32-bit
`0xffffffff` values plus a small extra block, and OOB reads are proven by the
tracer's byte ranges rather than by allocating gigabytes.

## Modules

- `mini_zip.py`     -- hand-controlled one-entry archive builder + consistent
  rebuild helper; `valid_aes_archive()` produces a genuinely readable seed.
- `mutator.py`      -- 34 named structural mutations (ordering, duplicates,
  length contradictions, ZIP64 placeholders, AES actual method/strength) plus
  fixed-seed chain composition.
- `tracer.py`       -- records every underlying read range, attributes reads to
  the entry-data stage, and reports the furthest parse stage reached
  (`init` -> `central-dir` -> `open` -> `read`).
- `classify.py`     -- separates clean rejections (`BadZipFile`,
  `NotImplementedError`, `RuntimeError`, `ValueError`) from unexpected
  non-domain exceptions.
- `engine.py`       -- deterministic named pass + fixed-seed random pass and a
  relation-preserving delta-debug minimizer.
- `relax_guard.py`  -- context manager that removes the `_decodeExtra`
  `ln + 4 > len(extra)` length guard for the controlled experiment.
- `layout_dump.py`  -- field-level layout of a counterexample.
- `run_fuzz.py`     -- CLI campaign driver.
- `dump_minimal.py` -- emits the minimized layouts + relaxed-guard evidence.
- `test_metadata_fuzzing.py` -- pytest regression suite (19 tests).

## Running

```sh
# full campaign, fixed seed (hex or decimal), optional JSON artifact
python -m fuzz.run_fuzz --seed 0x5EED1234 --iterations 300 \
    --json fuzz/reports/fuzz_report.json

# minimized counterexample layouts + relaxed-guard evidence
python -m fuzz.dump_minimal

# regression tests
python -m pytest fuzz/test_metadata_fuzzing.py -q
```

## Minimization invariant

Minimization operates on the *sequence of structural mutations*, never on raw
bytes. A shorter chain is accepted only while it still triggers the same
`(classification, exception type, stage)` signature. That keeps the
relationship between the two fields that jointly cause a failure -- e.g. a
duplicated AES field plus the ordering that lets its last block's actual
compression method win.

## Recorded findings (seed `0x5EED1234`)

These document current pyzipper 0.4.0 behaviour; the library source is
intentionally left unchanged. See `reports/` for full artifacts.

- duplicate `0x9901` blocks: the last block's "actual compression method"
  overwrites the first, so a STORED payload can be fed to deflate/bzip2/lzma
  (`zlib.error` / ...) -- wrong algorithm selection.
- invalid AES strength byte (not in 1/2/3) reaches the key/salt map and leaks
  `KeyError` instead of a `BadZipFile`.
- compressed-size contradictions (`csize` larger than the payload, or a ZIP64
  sentinel resolved to a large value) make the data reader cross the payload
  boundary; reads run into central-directory/EOCD bytes (OOB, recorded by the
  tracer). Reads still inside the archive buffer are short reads that end in a
  `BadZipFile` HMAC failure; sentinel sizes without a ZIP64 extra raise a raw
  `EOFError`.
- an LFH extra-field length that overruns the header reaches `struct.unpack`
  as a raw `struct.error`.
- an AES extra field present with the encrypted general-purpose flag bit
  cleared: `wz_aes_version` is set but no decrypter is built, so the
  integrity path dereferences `None` and raises `AttributeError`
  (`hmac_size` on `NoneType`).

## Relaxed length-guard experiment

With the production guard in place, a truncated extra body is a clean
`BadZipFile`; with `RelaxedLengthGuard` removing just that check, the same
bytes reach `struct.unpack` and escape as a raw `struct.error`
("unpack requires a buffer of N bytes"). This is the concrete evidence that
the guard is the active defense against a length-contradiction over-read. The
patch is reverted in a `finally`/context-exit so no other test observes it.

## Benign metadata stays accepted

Legal reordering and skippable unknown fields are asserted readable in
`TestBenignMetadata`: AES before/after an unknown field, unknown fields on
both sides, and a ZIP64 field (with no active sentinel) on either side of the
AES field all still decrypt correctly and are not blanket-rejected.
