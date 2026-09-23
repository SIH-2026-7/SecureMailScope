import struct
from scapy.layers.tls.crypto.suites import _tls_cipher_suites

VERSIONS = {0x0300: 'SSLv3', 0x0301: 'TLS1.0', 0x0302: 'TLS1.1', 0x0303: 'TLS1.2', 0x0304: 'TLS1.3'}
CIPHERS = {0x0000: 'TLS_NULL_WITH_NULL_NULL', 0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
           0x0004: 'TLS_RSA_WITH_RC4_128_MD5', 0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
           0x0009: 'TLS_RSA_WITH_DES_CBC_SHA', 0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
           0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
           0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
           0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
           0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 0x1301: 'TLS_AES_128_GCM_SHA256',
           0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256'}


CIPHERS.update(_tls_cipher_suites)


def u16(data, offset=0):
    return struct.unpack_from('!H', data, offset)[0]


def extensions(body, offset):
    result = {}
    if offset + 2 > len(body):
        return result
    end = offset + 2 + u16(body, offset)
    offset += 2
    while offset + 4 <= min(end, len(body)):
        kind, size = u16(body, offset), u16(body, offset + 2)
        offset += 4
        result[kind] = body[offset:offset + size]
        offset += size
    return result


def parse_handshake(kind, body, tls):
    if kind not in (1, 2):
        return
    version = u16(body)
    offset = 35 + body[34]
    if kind == 1:
        size = u16(body, offset)
        offset += 2 + size
        offset += 1 + body[offset]
        ext = extensions(body, offset)
        offered = [version]
        if 43 in ext:
            offered = [u16(ext[43], i) for i in range(1, len(ext[43]) - 1, 2)]
        tls['offered_versions'] = [VERSIONS[v] for v in offered if v in VERSIONS]
        if 0 in ext and len(ext[0]) >= 5:
            tls['sni'] = ext[0][5:5 + u16(ext[0], 3)].decode('ascii', errors='replace')
    else:
        cipher = u16(body, offset)
        ext = extensions(body, offset + 3)
        if 43 in ext and len(ext[43]) == 2:
            version = u16(ext[43])
        tls.update(version=VERSIONS.get(version, f'Unknown 0x{version:04x}'),
                   cipher_suite=CIPHERS.get(cipher, f'Unknown 0x{cipher:04x}'), server_hello=True,
                   ocsp_stapling_acknowledged=5 in ext)


def records(chunks):
    """Yield plaintext lines and TLS records, retaining the originating packet."""
    buffer, origins = b'', []
    for p in chunks:
        if p.get('gap'):
            buffer, origins = b'', []
        buffer += p['payload']
        origins.extend([p] * len(p['payload']))
        while buffer:
            is_tls = buffer[0] in (20, 21, 22, 23) and (len(buffer) < 2 or buffer[1] == 3)
            if is_tls:
                if len(buffer) < 5:
                    break
                size = 5 + u16(buffer, 3)
                if size > 18437:
                    yield 'invalid', b'', origins[0]
                    buffer, origins = b'', []
                    break
                if len(buffer) < size:
                    break
                yield buffer[0], buffer[5:size], origins[0]
            else:
                end = buffer.find(b'\n')
                if end < 0:
                    if len(buffer) > 65536:
                        buffer, origins = b'', []
                    break
                size = end + 1
                yield 'line', buffer[:size], origins[0]
            buffer, origins = buffer[size:], origins[size:]
    if buffer:
        yield 'incomplete', b'', origins[0]
