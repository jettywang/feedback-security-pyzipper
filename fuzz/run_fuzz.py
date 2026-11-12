"""CLI entry point for the structured AES/ZIP64 metadata fuzzer.

Usage:
    python -m fuzz.run_fuzz [--seed N] [--iterations N] [--json OUT]

Writes a human-readable report and (optionally) a JSON artifact. Exits 0 even
when unexpected findings are present; this is a discovery harness, not a
pass/fail unit test. The pytest regression module pins the findings.
"""

import argparse
import json

from .engine import (DEFAULT_SEED, run_named_mutations, run_random,
                     minimize, summarize)
from .mini_zip import valid_aes_archive
from .classify import is_oob


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=lambda s: int(s, 0),
                        default=DEFAULT_SEED)
    parser.add_argument('--iterations', type=int, default=200)
    parser.add_argument('--json', dest='json_path', default=None)
    args = parser.parse_args(argv)

    blob, password = valid_aes_archive()
    named = run_named_mutations(blob, password)
    randoms = run_random(blob, password, seed=args.seed,
                         iterations=args.iterations)
    all_results = named + randoms
    summary = summarize(all_results)

    report = []
    report.append('pyzipper AES/ZIP64 structured fuzzing')
    report.append('seed=%d iterations=%d archive_bytes=%d' % (
        args.seed, args.iterations, len(blob)))
    report.append('')
    report.append('counts: ok=%d clean_rejections=%d unexpected=%d oob=%d' % (
        len(summary['ok']), len(summary['clean-rejection']),
        len(summary['unexpected']), len(summary['oob'])))
    report.append('')
    report.append('unexpected failures (non-domain exceptions):')
    seen = set()
    for row in all_results:
        if row['kind'] != 'unexpected':
            continue
        out = row['outcome']
        key = (out.exc_type, out.stage, row['name'].split(':', 1)[0])
        if key in seen:
            continue
        seen.add(key)
        report.append('  - %-28s %-12s @%s %s' % (
            row['name'].split(':', 1)[0], out.exc_type, out.stage,
            out.exc_message))
    report.append('')
    report.append('out-of-bounds data reads (crossed entry payload boundary):')
    seen_oob = set()
    for row in all_results:
        if not is_oob(row['outcome']):
            continue
        base = row['name'].split(':', 1)[0]
        if base in seen_oob:
            continue
        seen_oob.add(base)
        out = row['outcome']
        report.append('  - %-28s read_end=%s payload_end=%s ranges=%s' % (
            base, out.max_end, out.payload_region[1], out.crossing[:2]))
    report.append('')
    report.append('benign order/unknown-field mutations accepted:')
    for name in ('aes_then_unknown', 'unknown_then_aes',
                 'unknown_both_sides', 'zip64_then_aes', 'aes_then_zip64'):
        report.append('  - %s -> %s' % (
            name, 'accepted' if name in summary['ok'] else 'NOT accepted'))

    text = '\n'.join(report)
    print(text)

    if args.json_path:
        def stable_message(row):
            # zlib's exact phrasing varies with buffer state; keep the stable
            # exception family instead of the volatile sentence.
            if row['outcome'].exc_type == 'error':
                return 'zlib/bz2/lzma decompressor error (message varies)'
            return row['outcome'].exc_message

        artifact = {
            'seed': args.seed,
            'iterations': args.iterations,
            'archive_bytes': len(blob),
            'summary_counts': {k: len(v) for k, v in summary.items()},
            'unexpected': [
                {'name': r['name'], 'exc_type': r['outcome'].exc_type,
                 'stage': r['outcome'].stage,
                 'message': stable_message(r)}
                for r in all_results if r['kind'] == 'unexpected'],
            'oob': [
                {'name': r['name'], 'crossing': r['outcome'].crossing,
                 'payload_region': r['outcome'].payload_region,
                 'max_end': r['outcome'].max_end}
                for r in all_results if is_oob(r['outcome'])],
        }
        with open(args.json_path, 'w', encoding='utf-8') as fh:
            json.dump(artifact, fh, indent=2)
        print('\nwrote', args.json_path)


if __name__ == '__main__':
    main()
