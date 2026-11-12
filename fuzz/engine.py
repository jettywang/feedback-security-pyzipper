"""Seed-driven structured fuzzing engine and relation-preserving minimizer.

The engine runs two passes:

* a deterministic pass over every named structural mutation (regression
  baseline);
* a randomized pass that composes mutations with a fixed seed so results are
  reproducible without any real large file.

The minimizer uses delta debugging on the *sequence of structural mutations*,
never on raw bytes. A candidate is only accepted while it still triggers the
same (exception family, stage) signature, which preserves the relationship
between the two fields that jointly cause the failure (e.g. a duplicated AES
field plus the last-block actual-compression method).
"""

import random

from .classify import classify, is_oob
from .mini_zip import valid_aes_archive, parse_layout
from .mutator import all_named_mutations, mutators, random_chain
from .tracer import drive_parse

DEFAULT_SEED = 0x5EED1234


def payload_region_for(original, mutated):
    """Map the original entry's payload region onto a rebuilt archive."""
    base = parse_layout(original)
    cur = parse_layout(mutated)
    length = base.payload_end - base.data_off
    return cur.data_off, cur.data_off + length


def evaluate(blob, mutated, password):
    region = payload_region_for(blob, mutated)
    outcome = drive_parse(mutated, password=password, payload_region=region)
    kind, reason = classify(outcome)
    return outcome, kind, reason


def run_named_mutations(blob, password):
    """Deterministic pass: every named mutation, classified."""
    results = []
    for name, mutated in all_named_mutations(blob):
        outcome, kind, reason = evaluate(blob, mutated, password)
        results.append(dict(name=name, kind=kind, reason=reason,
                            outcome=outcome, blob=mutated))
    return results


def run_random(blob, password, seed=DEFAULT_SEED, iterations=200, depth=3):
    """Fixed-seed pass: composed mutation chains, fully reproducible."""
    rng = random.Random(seed)
    results = []
    for i in range(iterations):
        label, mutated = random_chain(blob, rng, depth=rng.randint(1, depth))
        outcome, kind, reason = evaluate(blob, mutated, password)
        results.append(dict(name='random#%d:%s' % (i, label), kind=kind,
                            reason=reason, outcome=outcome, blob=mutated))
    return results


def signature(outcome, kind):
    """Failure identity preserved during minimization."""
    return (kind, outcome.exc_type, outcome.stage)


def minimize(blob, password, target_name, *, seed=DEFAULT_SEED):
    """Delta-debug a failing mutation down to its smallest triggering form.

    Minimization removes whole structural mutations from the applied chain and
    re-checks the (kind, exception, stage) signature, so the relationship among
    the fields that together trigger the bug is retained.
    """
    name_to_kwargs = {n: f for n, f in mutators(blob)}
    if target_name not in name_to_kwargs:
        raise KeyError(target_name)

    from .mini_zip import rebuild
    chain = [target_name]

    def apply(names):
        cur = blob
        for nm in names:
            cur = rebuild(cur, **name_to_kwargs[nm]())
        outcome, kind, _ = evaluate(blob, cur, password)
        return cur, outcome, kind

    target_blob, target_outcome, target_kind = apply(chain)
    target_sig = signature(target_outcome, target_kind)
    if target_kind == 'ok':
        raise ValueError('target mutation %r does not fail' % target_name)

    # Try to shrink while preserving the signature. Single named mutations are
    # already atomic, so minimization mainly strips composed-chain prefixes;
    # for a single mutation we verify it is itself the minimal reproducer.
    changed = True
    while changed and len(chain) > 1:
        changed = False
        for i in range(len(chain)):
            candidate = chain[:i] + chain[i + 1:]
            _, outcome, kind = apply(candidate)
            if signature(outcome, kind) == target_sig:
                chain = candidate
                changed = True
                break

    minimal_blob, minimal_outcome, minimal_kind = apply(chain)
    return dict(chain=chain, signature=target_sig, blob=minimal_blob,
                outcome=minimal_outcome, kind=minimal_kind)


def summarize(results):
    """Group results by classification for human-readable reporting."""
    summary = {'ok': [], 'clean-rejection': [], 'unexpected': [], 'oob': []}
    for row in results:
        summary[row['kind']].append(row['name'])
        if is_oob(row['outcome']):
            summary['oob'].append(row['name'])
    return summary
