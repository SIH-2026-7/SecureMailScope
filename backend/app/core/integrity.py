import hashlib
import struct
from pathlib import Path

MAGICS = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'}
MAX_BYTES = 50 * 1024 * 1024


def validate(path: Path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('Capture exceeds the 50 MB limit.')
    with path.open('rb') as handle:
        magic = handle.read(4)
        if magic not in MAGICS:
            raise ValueError('Invalid PCAP/PCAPNG magic bytes.')
        handle.seek(0)
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
        handle.seek(0)
        data = handle.read()
    validate_structure(data)
    return {'sha256': digest, 'size_bytes': path.stat().st_size, 'format': 'pcapng' if magic == b'\x0a\x0d\x0d\x0a' else 'pcap'}


def validate_structure(data):
    if data[:4] != b'\x0a\x0d\x0d\x0a':
        if len(data) < 24:
            raise ValueError('Truncated PCAP header.')
        endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        offset = 24
        while offset < len(data):
            if offset + 16 > len(data):
                raise ValueError('Truncated PCAP packet header.')
            size = struct.unpack_from(endian + 'I', data, offset + 8)[0]
            offset += 16 + size
            if offset > len(data):
                raise ValueError('Truncated PCAP packet data.')
    else:
        offset, endian = 0, None
        while offset < len(data):
            if offset + 12 > len(data):
                raise ValueError('Truncated PCAPNG block.')
            if data[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
                bom = data[offset + 8:offset + 12]
                if bom not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                    raise ValueError('Invalid PCAPNG byte order marker.')
                endian = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            if endian is None:
                raise ValueError('Missing PCAPNG section header.')
            size = struct.unpack_from(endian + 'I', data, offset + 4)[0]
            if size < 12 or size % 4 or offset + size > len(data):
                raise ValueError('Invalid or truncated PCAPNG block length.')
            if struct.unpack_from(endian + 'I', data, offset + size - 4)[0] != size:
                raise ValueError('PCAPNG block lengths do not match.')
            offset += size
