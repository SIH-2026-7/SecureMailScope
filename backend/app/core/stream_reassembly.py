from collections import defaultdict
from .pcap_extractor import PORTS


def reassemble(packets):
    groups, generations, active = {}, defaultdict(int), {}
    for p in packets:
        key = tuple(sorted(((p['src'], p['sport']), (p['dst'], p['dport']))))
        # A new SYN (excluding retransmitted SYN) starts a new connection on a reused tuple.
        if p['flags'] & 2 and not p['flags'] & 16:
            if key in active and active[key] != p['seq']:
                generations[key] += 1
            active[key] = p['seq']
        groups.setdefault((key, generations[key]), []).append(p)
    result = []
    for (key, generation), rows in groups.items():
        known = next((endpoint for endpoint in key if endpoint[1] in PORTS), None)
        hello = next((p for p in rows if p['payload'][:1] == b'\x16' and p['payload'][5:6] == b'\x01'), None)
        if known is None and hello is None:
            # A ClientHello can itself span several TCP segments on a nonstandard port.
            for endpoint in key:
                direction = sorted((p for p in rows if (p['src'], p['sport']) == endpoint and p['payload']), key=lambda p: p['seq'])
                prefix, end = b'', None
                for p in direction:
                    if end is not None and p['seq'] > end:
                        break
                    overlap = max(0, (end if end is not None else p['seq']) - p['seq'])
                    prefix += p['payload'][overlap:64]
                    end = max(end or p['seq'], p['seq'] + len(p['payload']))
                    if len(prefix) >= 6:
                        break
                if prefix[:1] == b'\x16' and prefix[1:2] == b'\x03' and prefix[5:6] == b'\x01':
                    hello = direction[0]
                    break
        if known is None and hello is None:
            continue
        server = known or (hello['dst'], hello['dport'])
        client = key[0] if key[1] == server else key[1]
        stream = dict(id=f'{PORTS.get(server[1], "TLS").lower()}-stream-{len(result)}',
                      server=server, client=client, protocol=PORTS.get(server[1], 'TLS'), rows=rows,
                      directions={}, warnings=[], has_syn=any(p['flags'] & 2 for p in rows))
        for direction, endpoint in [('client', client), ('server', server)]:
            parts = [p for p in rows if (p['src'], p['sport']) == endpoint and p['payload']]
            if not parts:
                stream['directions'][direction] = []
                continue
            base = next((p['seq'] + 1 for p in rows if (p['src'], p['sport']) == endpoint and p['flags'] & 2), parts[0]['seq'])
            def relative(p):
                return ((p['seq'] - base + 2**31) % 2**32) - 2**31
            parts.sort(key=lambda p: (relative(p), p['frame']))
            end, chunks = None, []
            for p in parts:
                seq, data = relative(p), p['payload']
                if end is not None and seq > end:
                    stream['warnings'].append(f'TCP gap before frame {p["frame"]}; evidence is partial.')
                overlap = max(0, (end if end is not None else seq) - seq)
                if overlap:
                    stream['warnings'].append(f'Retransmission/overlap at frame {p["frame"]}; first observed bytes retained.')
                if overlap < len(data):
                    chunks.append({**p, 'payload': data[overlap:], 'gap': end is not None and seq > end})
                end = max(end if end is not None else seq, seq + len(data))
            stream['directions'][direction] = chunks
        result.append(stream)
    return result
