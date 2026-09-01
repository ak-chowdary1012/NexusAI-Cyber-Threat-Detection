# Author: Avinash Krishna — Team AVV Elites (SIH26153)
"""
src/features/packet_features.py
Architecture ref: docs/architecture.md § Dual-Level Feature Extraction (packet-level)

Parses raw PCAP via Scapy and computes the timing/sequencing features that
flow-level aggregates miss: TTL variance, TCP window size, IP fragmentation,
payload size distribution, port-scan signatures, and retransmissions. This is
what lets the system catch a slow, evasive reconnaissance scan that never
crosses a flood-style volumetric threshold.

Scapy is used (not PyShark) because it has no dependency on a system tshark
binary, which keeps the "fully offline, no external service" property of the
spec intact on a bare machine. Swap in PyShark by replacing _iter_packets()
if your team already has tshark installed and prefers its dissectors.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterator

import numpy as np
import pandas as pd

from src.utils import get_logger

logger = get_logger(__name__)

PACKET_FEATURE_NAMES = [
    "ttl_mean", "ttl_var",
    "tcp_window_mean", "tcp_window_var",
    "frag_ratio",
    "payload_size_mean", "payload_size_var",
    "port_scan_score",
    "retransmission_ratio",
    "unique_dst_ports_per_src",
]


def _iter_packets(pcap_path: str) -> Iterator[object]:
    """Yields Scapy packets one at a time (PcapReader streams — it does not
    load the whole capture into memory, which matters on large PCAPs)."""
    from scapy.all import PcapReader  # imported lazily: scapy is a heavy
    # optional dependency and callers that only touch flow-level CSVs
    # (e.g. the CIC-IDS-only path) shouldn't be forced to have it installed.

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            yield pkt


def extract_packet_features(pcap_path: str, window_seconds: float = 30.0) -> pd.DataFrame:
    """Parse a PCAP and compute PACKET_FEATURE_NAMES per (src_ip, time-window).

    Returns a DataFrame indexed by (src_ip, window_start) so windowing.py can
    join it against the flow-level table on the same key.
    """
    from scapy.layers.inet import IP, TCP, UDP

    buckets: dict[tuple[str, int], dict] = defaultdict(lambda: {
        "ttls": [], "tcp_windows": [], "frag_count": 0, "payload_sizes": [],
        "syn_count": 0, "synack_count": 0, "retrans_seen": set(), "retrans_count": 0,
        "dst_ports": set(), "packet_count": 0,
    })

    n_parsed, n_skipped = 0, 0
    for pkt in _iter_packets(pcap_path):
        try:
            if IP not in pkt:
                n_skipped += 1
                continue
            ip = pkt[IP]
            window_start = int(float(pkt.time) // window_seconds) * window_seconds
            key = (ip.src, window_start)
            b = buckets[key]
            b["packet_count"] += 1
            b["ttls"].append(ip.ttl)
            b["frag_count"] += 1 if (ip.flags == 1 or ip.frag > 0) else 0
            payload_len = len(bytes(ip.payload))
            b["payload_sizes"].append(payload_len)

            if TCP in pkt:
                tcp = pkt[TCP]
                b["tcp_windows"].append(tcp.window)
                b["dst_ports"].add(tcp.dport)
                flags = tcp.flags
                is_syn = flags & 0x02 and not flags & 0x10
                is_synack = flags & 0x02 and flags & 0x10
                if is_syn:
                    b["syn_count"] += 1
                if is_synack:
                    b["synack_count"] += 1
                seq_key = (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq)
                if seq_key in b["retrans_seen"]:
                    b["retrans_count"] += 1
                b["retrans_seen"].add(seq_key)
            elif UDP in pkt:
                b["dst_ports"].add(pkt[UDP].dport)

            n_parsed += 1
        except Exception:  # a single malformed packet must not abort the whole capture
            n_skipped += 1
            continue

    logger.info(f"packet_features: parsed={n_parsed} skipped={n_skipped} pcap={pcap_path}")

    rows = []
    for (src_ip, window_start), b in buckets.items():
        ttls = np.array(b["ttls"], dtype=float) if b["ttls"] else np.array([0.0])
        windows = np.array(b["tcp_windows"], dtype=float) if b["tcp_windows"] else np.array([0.0])
        payloads = np.array(b["payload_sizes"], dtype=float) if b["payload_sizes"] else np.array([0.0])
        pkt_count = max(b["packet_count"], 1)

        # port_scan_score: many distinct destination ports contacted with very
        # few packets each (SYN-heavy, low SYN-ACK reply rate) is the classic
        # signature of a scan — sequential or randomized — as opposed to a
        # normal session which talks to one or a handful of ports repeatedly.
        unique_ports = len(b["dst_ports"])
        syn_no_ack_rate = b["syn_count"] / max(b["syn_count"] + b["synack_count"], 1)
        port_scan_score = min(1.0, (unique_ports / pkt_count) * (0.5 + 0.5 * syn_no_ack_rate))

        rows.append({
            "src_ip": src_ip,
            "window_start": window_start,
            "ttl_mean": ttls.mean(),
            "ttl_var": ttls.var(),
            "tcp_window_mean": windows.mean(),
            "tcp_window_var": windows.var(),
            "frag_ratio": b["frag_count"] / pkt_count,
            "payload_size_mean": payloads.mean(),
            "payload_size_var": payloads.var(),
            "port_scan_score": port_scan_score,
            "retransmission_ratio": b["retrans_count"] / pkt_count,
            "unique_dst_ports_per_src": float(unique_ports),
        })

    if not rows:
        return pd.DataFrame(columns=["src_ip", "window_start"] + PACKET_FEATURE_NAMES)

    return pd.DataFrame(rows).replace([np.inf, -np.inf], 0.0).fillna(0.0)
