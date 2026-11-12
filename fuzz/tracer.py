"""Instrumentation: parse-stage tracking and underlying read-range capture.

A TracingFile records every (start, end) range the parser reads so an
out-of-bounds read (a read that leaves the entry's payload region) can be
proved without relying on a real multi-gigabyte file. `drive_parse` runs the
full lifecycle and reports the furthest stage reached.
"""

import io

# Stages, in the order a parse can reach them.
STAGE_INIT = 'init'                       # ZipFile construction / EOCD
STAGE_CENTRAL_DIRECTORY = 'central-dir'   # _RealGetContents + _decodeExtra
STAGE_OPEN = 'open'                       # local-header processing / decrypter
STAGE_READ = 'read'                       # payload decompression / integrity


class TracingFile(io.BytesIO):
    """BytesIO that logs absolute byte ranges served via read().

    `mark()` snapshots how many ranges belong to an earlier parse phase; reads
    recorded afterwards can be attributed to the entry-data stage.
    """

    def __init__(self, data):
        super().__init__(data)
        self.ranges = []

    def read(self, n=-1):
        start = self.tell()
        data = super().read(n)
        if data:
            self.ranges.append((start, start + len(data)))
        return data

    def mark(self):
        return len(self.ranges)

    def ranges_since(self, mark):
        return self.ranges[mark:]

    def max_end(self):
        return max((end for _, end in self.ranges), default=0)

    def reads_crossing(self, boundary, ranges=None):
        """Ranges that extend past `boundary` (the entry's payload end)."""
        if ranges is None:
            ranges = self.ranges
        return [(s, e) for s, e in ranges if e > boundary]


class ParseOutcome:
    def __init__(self, label, stage, exc_type, exc_message, max_end,
                 archive_len, crossing, zinfo=None, payload_region=None):
        self.label = label
        self.stage = stage
        self.exc_type = exc_type
        self.exc_message = exc_message
        self.max_end = max_end
        self.archive_len = archive_len
        self.crossing = crossing
        self.zinfo = zinfo
        self.payload_region = payload_region

    @property
    def ok(self):
        return self.exc_type is None

    def __repr__(self):
        if self.ok:
            head = 'OK'
        else:
            head = '%s@%s: %s' % (self.exc_type, self.stage, self.exc_message)
        return '<ParseOutcome %s max_end=%s/%s crossing=%d region=%s>' % (
            head, self.max_end, self.archive_len, len(self.crossing),
            self.payload_region)


def drive_parse(blob, label='', password=b'secret', payload_region=None):
    """Run the full read lifecycle on `blob` and capture a ParseOutcome.

    `payload_region` is the (start, end) of the entry's encrypted payload in
    the *mutated* archive, supplied by the caller so an OOB read is measured
    against the real entry boundary rather than the shifted central directory.
    """
    from pyzipper import zipfile_aes
    from .mini_zip import parse_layout

    tf = TracingFile(blob)
    stage = STAGE_INIT
    exc_type = exc_message = None
    zinfo = None
    data_mark = None
    try:
        zf = zipfile_aes.AESZipFile(tf)
        stage = STAGE_CENTRAL_DIRECTORY
        zinfo = zf.infolist()[0]
        stage = STAGE_OPEN
        data_mark = tf.mark()  # everything after this is entry-data reading
        with zf.open(zinfo, pwd=password) as ext:
            stage = STAGE_READ
            ext.read()
    except Exception as exc:  # classification happens in the classifier
        exc_type = type(exc).__name__
        exc_message = str(exc)

    if payload_region is None:
        layout = parse_layout(blob)
        payload_region = (layout.data_off, layout.payload_end)
    boundary = payload_region[1]
    payload_start = payload_region[0]
    if data_mark is None:
        # Never reached entry-data reading, so no data-stage OOB is observable.
        data_ranges = []
    else:
        data_ranges = tf.ranges_since(data_mark)
    crossing = [(s, e) for s, e in data_ranges
                if e > boundary and s >= payload_start]
    data_max_end = max((e for _, e in data_ranges), default=0)
    return ParseOutcome(label, stage, exc_type, exc_message,
                        data_max_end, len(blob), crossing, zinfo,
                        payload_region)
