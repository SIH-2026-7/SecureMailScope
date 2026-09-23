"""TCP flow simulator and packet builder for Scapy."""

import random
from typing import List, Dict, Optional, Tuple
from scapy.all import Ether, IP, TCP, Raw, Packet
from .crypto import BASE_TIMESTAMP


class TCPFlow:
    """Manages an individual bidirectional TCP stream with accurate sequence/ack tracking."""

    def __init__(
        self,
        client_ip: str = "10.24.1.10",
        server_ip: str = "10.24.1.25",
        client_port: int = 45100,
        server_port: int = 587,
        client_mac: str = "00:50:56:c0:00:01",
        server_mac: str = "00:50:56:c0:00:02",
        start_time: float = BASE_TIMESTAMP,
        client_isn: int = 1000,
        server_isn: int = 5000,
        rng: Optional[random.Random] = None,
    ):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.current_time = start_time
        self.rng = rng or random.Random(42)

        self.client_seq = client_isn
        self.server_seq = server_isn
        self.client_ack = 0
        self.server_ack = 0

        self.ip_id_counter = 1000
        self.packets: List[Packet] = []
        self.markers: Dict[str, int] = {}

    def _next_time(self, min_ms: float = 1.0, max_ms: float = 15.0) -> float:
        delta = self.rng.uniform(min_ms, max_ms) / 1000.0
        self.current_time += delta
        return self.current_time

    def _build_packet(
        self,
        direction: str,
        flags: str,
        seq: int,
        ack: int,
        payload: bytes = b"",
    ) -> Packet:
        is_client = direction == "client"
        src_ip = self.client_ip if is_client else self.server_ip
        dst_ip = self.server_ip if is_client else self.client_ip
        src_port = self.client_port if is_client else self.server_port
        dst_port = self.server_port if is_client else self.client_port
        src_mac = self.client_mac if is_client else self.server_mac
        dst_mac = self.server_mac if is_client else self.client_mac

        self.ip_id_counter = (self.ip_id_counter + 1) % 65535

        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, id=self.ip_id_counter, ttl=64)
            / TCP(
                sport=src_port,
                dport=dst_port,
                seq=seq,
                ack=ack,
                flags=flags,
                window=64240,
            )
        )
        if payload:
            pkt = pkt / Raw(payload)

        pkt.time = self._next_time()
        return pkt

    def mark(self, name: str) -> None:
        """Associate a marker name with the most recently emitted packet's frame index."""
        if self.packets:
            self.markers[name] = len(self.packets)

    def handshake(self) -> None:
        """Execute a clean TCP 3-way handshake (SYN, SYN-ACK, ACK)."""
        # 1. Client SYN
        syn_pkt = self._build_packet("client", "S", self.client_seq, 0)
        self.packets.append(syn_pkt)
        self.client_seq += 1
        self.server_ack = self.client_seq

        # 2. Server SYN-ACK
        sa_pkt = self._build_packet("server", "SA", self.server_seq, self.server_ack)
        self.packets.append(sa_pkt)
        self.server_seq += 1
        self.client_ack = self.server_seq

        # 3. Client ACK
        ack_pkt = self._build_packet("client", "A", self.client_seq, self.client_ack)
        self.packets.append(ack_pkt)

    def send(
        self,
        direction: str,
        payload: bytes,
        flags: str = "PA",
        auto_ack: bool = True,
        marker: Optional[str] = None,
    ) -> None:
        """Send data in the specified direction and optionally auto-acknowledge from peer."""
        if direction == "client":
            seq = self.client_seq
            ack = self.client_ack
            pkt = self._build_packet("client", flags, seq, ack, payload)
            self.packets.append(pkt)
            self.client_seq += len(payload)
            self.server_ack = self.client_seq
            if marker:
                self.markers[marker] = len(self.packets)

            if auto_ack:
                ack_pkt = self._build_packet("server", "A", self.server_seq, self.server_ack)
                self.packets.append(ack_pkt)
        else:
            seq = self.server_seq
            ack = self.server_ack
            pkt = self._build_packet("server", flags, seq, ack, payload)
            self.packets.append(pkt)
            self.server_seq += len(payload)
            self.client_ack = self.server_seq
            if marker:
                self.markers[marker] = len(self.packets)

            if auto_ack:
                ack_pkt = self._build_packet("client", "A", self.client_seq, self.client_ack)
                self.packets.append(ack_pkt)

    def close(self) -> None:
        """Gracefully close the TCP connection (FIN-ACK / ACK sequence)."""
        # Client sends FIN-ACK
        fin_c = self._build_packet("client", "FA", self.client_seq, self.client_ack)
        self.packets.append(fin_c)
        self.client_seq += 1
        self.server_ack = self.client_seq

        # Server ACKs client FIN and sends own FIN-ACK
        fin_s = self._build_packet("server", "FA", self.server_seq, self.server_ack)
        self.packets.append(fin_s)
        self.server_seq += 1
        self.client_ack = self.server_seq

        # Client ACKs server FIN
        ack_c = self._build_packet("client", "A", self.client_seq, self.client_ack)
        self.packets.append(ack_c)
