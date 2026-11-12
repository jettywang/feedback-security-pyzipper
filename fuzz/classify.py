"""Separate clean rejections from unexpected parser failures.

A well-behaved parser rejects contradictory metadata with its documented
domain exceptions (BadZipFile / NotImplementedError / RuntimeError for a bad
password). Anything else leaking out of the structured parser -- KeyError,
struct.error, EOFError, zlib.error, OverflowError, ... -- is an *unexpected*
failure and worth a report, even when it does not escape the process.
"""

# Exceptions the library is allowed to use to refuse malformed input.
CLEAN_REJECTIONS = {
    'BadZipFile',        # documented corrupt-archive error
    'NotImplementedError',  # documented "unsupported compression/flags"
    'RuntimeError',      # bad password / password required
    'ValueError',        # documented argument validation
}

# Signatures of failures that should never escape a metadata parser.
UNEXPECTED_FAMILIES = {
    'KeyError': 'unvalidated lookup (e.g. AES strength map)',
    'error': 'raw struct.error: length/header contradiction reached unpack',
    'struct.error': 'raw struct.error: length/header contradiction',
    'EOFError': 'read ran past the archive without a clean rejection',
    'OverflowError': 'integer overflow while applying metadata',
    'UnicodeDecodeError': 'metadata bytes decoded as text without validation',
    'IndexError': 'short/shifted encryption header indexed out of range',
    'zlib.error': 'wrong decompressor selected for the payload',
    'LZMAError': 'wrong decompressor selected for the payload',
    'AttributeError': 'inconsistent encryption state left a None decrypter',
    'OSError': 'low-level IO error instead of a domain rejection',
}


def classify(outcome):
    """Return ('ok'|'clean-rejection'|'unexpected', reason)."""
    if outcome.ok:
        return 'ok', 'full lifecycle completed'
    if outcome.exc_type in CLEAN_REJECTIONS:
        return 'clean-rejection', outcome.exc_type
    reason = UNEXPECTED_FAMILIES.get(
        outcome.exc_type, 'non-domain exception escaped the parser')
    return 'unexpected', reason


def is_oob(outcome):
    """True if underlying reads crossed the entry payload boundary."""
    return bool(outcome.crossing)
