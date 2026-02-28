# Copyright (c) 2026 Antonio Telesca / IRST Institute. All Rights Reserved.
# PROPRIETARY SOFTWARE - Unauthorized use strictly prohibited. See LICENSE.

"""
SENTINEL BUSINESS - Core Engine
Motore principale di analisi rete per PMI
"""
import time
import json
import hashlib
import random
from datetime import datetime, timezone


class Packet:
    def __init__(self, src, dst, port, protocol, size, dns_query=None, tls_sni=None):
        self.timestamp = datetime.now(timezone.utc)
        self.src = src
        self.dst = dst
        self.port = port
        self.protocol = protocol
        self.size = size
        self.dns_query = dns_query
        self.tls_sni = tls_sni

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "src": self.src,
            "dst": self.dst,
            "port": self.port,
            "protocol": self.protocol,
            "size": self.size,
            "dns_query": self.dns_query,
            "tls_sni": self.tls_sni
        }


class NetworkFlow:
    def __init__(self, src, dst, port):
        self.src = src
        self.dst = dst
        self.port = port
        self.packets = []
        self.total_bytes = 0
        self.dns_queries = []
        self.tls_snis = []

    def add_packet(self, pkt):
        self.packets.append(pkt)
        self.total_bytes += pkt.size
        if pkt.dns_query:
            self.dns_queries.append(pkt.dns_query)
        if pkt.tls_sni:
            self.tls_snis.append(pkt.tls_sni)

    def get_features(self):
        if len(self.packets) < 2:
            intervals = []
        else:
            times = [p.timestamp.timestamp() for p in self.packets]
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        std_interval = 0
        if len(intervals) > 1:
            mean = avg_interval
            std_interval = (sum((x - mean) ** 2 for x in intervals) / len(intervals)) ** 0.5

        regularity = std_interval / avg_interval if avg_interval > 0 else 999

        dns_lengths = [len(q) for q in self.dns_queries]
        avg_dns_len = sum(dns_lengths) / len(dns_lengths) if dns_lengths else 0

        entropy = 0
        if self.dns_queries:
            all_chars = "".join(self.dns_queries)
            if all_chars:
                freq = {}
                for c in all_chars:
                    freq[c] = freq.get(c, 0) + 1
                import math
                length = len(all_chars)
                entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())

        return {
            "src": self.src,
            "dst": self.dst,
            "port": self.port,
            "packet_count": len(self.packets),
            "total_bytes": self.total_bytes,
            "avg_interval": avg_interval,
            "interval_std": std_interval,
            "interval_regularity": regularity,
            "dns_query_count": len(self.dns_queries),
            "avg_dns_length": avg_dns_len,
            "dns_entropy": entropy,
            "dns_queries": self.dns_queries,
            "tls_snis": self.tls_snis,
            "first_seen": self.packets[0].timestamp.isoformat() if self.packets else None,
            "last_seen": self.packets[-1].timestamp.isoformat() if self.packets else None
        }


class FlowTable:
    def __init__(self):
        self.flows = {}
        self.devices = set()

    def process_packet(self, pkt):
        self.devices.add(pkt.src)
        self.devices.add(pkt.dst)
        key = (pkt.src, pkt.dst, pkt.port)
        if key not in self.flows:
            self.flows[key] = NetworkFlow(pkt.src, pkt.dst, pkt.port)
        self.flows[key].add_packet(pkt)

    def get_all_flows(self):
        return [f.get_features() for f in self.flows.values() if len(f.packets) >= 2]

    def device_count(self):
        return len(self.devices)

    def flow_count(self):
        return len(self.flows)
