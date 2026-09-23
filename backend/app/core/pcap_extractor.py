"""Scapy fallback works offline without an OS TShark installation."""
from scapy.all import PcapReader, TCP, IP, IPv6
import os
import shutil
import subprocess

PORTS = {25: 'SMTP', 587: 'SMTP', 465: 'SMTP', 143: 'IMAP', 993: 'IMAP', 110: 'POP3', 995: 'POP3'}


def extract(path):
    if os.environ.get('PACKET_EXTRACTOR', 'auto') != 'scapy' and shutil.which('tshark'):
        return extract_tshark(path)
    packets, times, warnings, count, linktype = [], [], [], 0, None
    try:
        with PcapReader(str(path)) as reader:
            linktype = getattr(reader, 'linktype', None)
            for frame, packet in enumerate(reader, 1):
                count = frame
                if frame > 500_000:
                    raise ValueError('Capture exceeds the 500,000 packet processing limit.')
                ts = float(packet.time)
                times.append(ts)
                if TCP not in packet or (IP not in packet and IPv6 not in packet):
                    continue
                ip = packet[IP] if IP in packet else packet[IPv6]
                tcp = packet[TCP]
                packets.append(dict(frame=frame, ts=ts, src=ip.src, dst=ip.dst,
                                    sport=int(tcp.sport), dport=int(tcp.dport), seq=int(tcp.seq),
                                    flags=int(tcp.flags), payload=bytes(tcp.payload)))
    except (EOFError, ValueError):
        raise
    except Exception as exc:
        raise ValueError('Capture could not be decoded; it may be truncated or unsupported.') from exc
    if not count:
        raise ValueError('Capture contains no decodable packets.')
    return packets, dict(packet_count=count, start_time=min(times), end_time=max(times), link_type=linktype,
                        extractor='Scapy', warnings=warnings)


def extract_tshark(path):
    fields = ['frame.number', 'frame.time_epoch', 'frame.encap_type', 'ip.src', 'ipv6.src',
              'ip.dst', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.seq_raw', 'tcp.flags', 'tcp.payload']
    command = ['tshark', '-n', '-r', str(path), '-T', 'fields', '-E', 'occurrence=f']
    for field in fields:
        command.extend(['-e', field])
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=120, check=True).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        raise ValueError('TShark could not decode this capture.') from exc
    packets, times, count, linktype = [], [], 0, None
    for line in output.splitlines():
        values = (line.split('\t') + [''] * len(fields))[:len(fields)]
        frame, ts, link, ip4src, ip6src, ip4dst, ip6dst, sport, dport, seq, flags, payload = values
        count += 1
        if count > 500_000:
            raise ValueError('Capture exceeds the 500,000 packet processing limit.')
        times.append(float(ts))
        linktype = linktype or link
        if sport and dport and (ip4src or ip6src):
            packets.append(dict(frame=int(frame), ts=float(ts), src=ip4src or ip6src, dst=ip4dst or ip6dst,
                                sport=int(sport), dport=int(dport), seq=int(seq), flags=int(flags, 16),
                                payload=bytes.fromhex(payload.replace(':', ''))))
    if not count:
        raise ValueError('Capture contains no decodable packets.')
    return packets, dict(packet_count=count, start_time=min(times), end_time=max(times), link_type=linktype,
                        extractor='TShark', warnings=[])
