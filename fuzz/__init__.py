"""Structured fuzzing for pyzipper AES / ZIP64 extra-field metadata.

This package builds small, fully hand-controlled ZIP archives (the central
directory is always reachable) and mutates the local-header and
central-directory extra-field chains, ZIP64 placeholder sizes and the WZ-AES
"actual compression method" to look for wrong algorithm selection,
out-of-bounds reads and unexpected (non-BadZipFile) exceptions.
"""
