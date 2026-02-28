# Copyright (c) 2026 Antonio Telesca / IRST Institute. All Rights Reserved.
# PROPRIETARY SOFTWARE - Unauthorized use strictly prohibited. See LICENSE.

"""
SENTINEL BUSINESS - Threat Analyzer
Motore di analisi minacce con 8 detection engines
"""
import json
import os
import math

SAFE_IP_PREFIXES = ("142.250.", "172.217.", "216.58.", "74.125.", "173.194.",
                    "157.240.", "52.96.", "34.107.", "93.62.", "151.1.")

MALICIOUS_DOMAINS = [
    "evil-command-server.ru", "malware-cnc.top", "darknet-c2.xyz",
    "bancaintesa-verifica.com", "postepay-sicura.net",
    "faceb00k-login.com", "g00gle-verify.net", "paypa1-secure.com",
    "update-service.xyz"
]

MALICIOUS_IP_RANGES = ["185.234.72.", "91.215.85.", "45.155.205."]

SUSPICIOUS_PORTS = [3333, 4444, 5555, 6666, 8545, 9090, 1337, 31337, 14444, 45700]

SIGNATURES = {
    "emotet": {"beacon_interval": 30, "ports": [443, 8080, 7080]},
    "cobalt_strike": {"beacon_interval": 60, "ports": [443, 8443, 50050]},
    "trickbot": {"beacon_interval": 120, "ports": [443, 449]},
    "lockbit": {"ports": [445, 139], "lateral": True},
}


def _is_private_ip(ip):
    if not ip:
        return False
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3")


class ThreatAnalyzer:
    def __init__(self):
        self.alerts = []

    def analyze_flow(self, features):
        threats = []
        checks = [
            self._check_beaconing,
            self._check_dns_exfil,
            self._check_malicious_domain,
            self._check_suspicious_port,
            self._check_lateral_movement,
            self._check_phishing,
            self._check_brute_force,
            self._check_data_volume,
        ]
        for check in checks:
            try:
                result = check(features)
                if result:
                    threats.append(result)
            except Exception:
                pass
        return threats

    def _is_safe_ip(self, ip):
        if not ip:
            return False
        return any(ip.startswith(p) for p in SAFE_IP_PREFIXES)

    def _check_beaconing(self, f):
        if f.get("packet_count", 0) < 5:
            return None
        if self._is_safe_ip(f.get("dst")):
            return None
        dst = f.get("dst", "")
        if _is_private_ip(dst):
            return None
        regularity = f.get("interval_regularity", 999)
        avg = f.get("avg_interval", 0)
        std = f.get("interval_std", 0)
        if regularity < 0.3 and avg > 5:
            matched = None
            for name, sig in SIGNATURES.items():
                sig_int = sig.get("beacon_interval", 0)
                if sig_int > 0 and abs(avg - sig_int) < sig_int * 0.3:
                    matched = name.upper()
                    break
            severity = "CRITICO" if matched else "ALTO"
            confidence = max(60, min(99, int(100 - regularity * 100)))
            return {
                "type": "beaconing",
                "severity": severity,
                "confidence": confidence,
                "src": f.get("src"),
                "dst": f.get("dst"),
                "port": f.get("port"),
                "detail": f"Intervallo regolare: {avg:.1f}s (+-{std:.1f}s) su {f['packet_count']} pacchetti",
                "matched_malware": matched,
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
        return None

    def _check_dns_exfil(self, f):
        if f.get("dns_query_count", 0) < 5:
            return None
        avg_len = f.get("avg_dns_length", 0)
        entropy = f.get("dns_entropy", 0)
        if avg_len > 40 and entropy > 3.0:
            matched = None
            for q in f.get("dns_queries", []):
                for d in MALICIOUS_DOMAINS:
                    if d in q:
                        matched = d.upper()
                        break
                if matched:
                    break
            confidence = min(99, int(60 + avg_len * 0.3 + entropy * 5))
            return {
                "type": "dns_exfiltration",
                "severity": "CRITICO",
                "confidence": confidence,
                "src": f.get("src"),
                "dst": f.get("dst"),
                "port": 53,
                "detail": f"{f['dns_query_count']} query DNS sospette, lunghezza media {avg_len:.0f}, entropia {entropy:.2f}",
                "matched_malware": matched,
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
        return None

    def _check_malicious_domain(self, f):
        for q in f.get("dns_queries", []) + f.get("tls_snis", []):
            for d in MALICIOUS_DOMAINS:
                if d in str(q).lower():
                    return {
                        "type": "malicious_domain",
                        "severity": "CRITICO",
                        "confidence": 95,
                        "src": f.get("src"),
                        "dst": f.get("dst"),
                        "port": f.get("port"),
                        "detail": f"Connessione a dominio malevolo: {q}",
                        "matched_malware": d.upper(),
                        "first_seen": f.get("first_seen"),
                        "last_seen": f.get("last_seen"),
                    }
        return None

    def _check_suspicious_port(self, f):
        port = f.get("port", 0)
        if port in SUSPICIOUS_PORTS and not self._is_safe_ip(f.get("dst")) and not _is_private_ip(f.get("dst", "")):
            return {
                "type": "suspicious_port",
                "severity": "MEDIO",
                "confidence": 70,
                "src": f.get("src"),
                "dst": f.get("dst"),
                "port": port,
                "detail": f"Traffico su porta sospetta {port} ({f.get('packet_count',0)} pacchetti, {f.get('total_bytes',0)} bytes)",
                "matched_malware": None,
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
        return None

    def _check_lateral_movement(self, f):
        src = f.get("src", "")
        dst = f.get("dst", "")
        port = f.get("port", 0)
        if _is_private_ip(src) and _is_private_ip(dst) and port in [445, 139, 3389]:
            pkts = f.get("packet_count", 0)
            total = f.get("total_bytes", 0)
            if total > 10000 or pkts > 5:
                return {
                    "type": "lateral_movement",
                    "severity": "CRITICO",
                    "confidence": 88,
                    "src": src,
                    "dst": dst,
                    "port": port,
                    "detail": f"Movimento laterale via porta {port}: {total} bytes trasferiti a {dst}",
                    "matched_malware": "RANSOMWARE",
                    "first_seen": f.get("first_seen"),
                    "last_seen": f.get("last_seen"),
                }
        return None

    def _check_phishing(self, f):
        for q in f.get("dns_queries", []) + f.get("tls_snis", []):
            q_lower = str(q).lower()
            banks = ["intesa", "unicredit", "postepay", "paypal", "poste"]
            phishing_signs = ["verifica", "sicura", "secure", "login", "update", "alert"]
            for bank in banks:
                if bank in q_lower:
                    for sign in phishing_signs:
                        if sign in q_lower:
                            return {
                                "type": "phishing",
                                "severity": "CRITICO",
                                "confidence": 93,
                                "src": f.get("src"),
                                "dst": f.get("dst"),
                                "port": f.get("port"),
                                "detail": f"Sito phishing bancario rilevato: {q}",
                                "matched_malware": q.upper(),
                                "first_seen": f.get("first_seen"),
                                "last_seen": f.get("last_seen"),
                            }
        return None

    def _check_brute_force(self, f):
        port = f.get("port", 0)
        pkts = f.get("packet_count", 0)
        avg_interval = f.get("avg_interval", 999)
        if port in [22, 3389, 21] and pkts > 10 and avg_interval < 3:
            return {
                "type": "brute_force",
                "severity": "ALTO",
                "confidence": 85,
                "src": f.get("src"),
                "dst": f.get("dst"),
                "port": port,
                "detail": f"Possibile brute force su porta {port}: {pkts} tentativi in rapida successione",
                "matched_malware": None,
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
        return None

    def _check_data_volume(self, f):
        total = f.get("total_bytes", 0)
        src = f.get("src", "")
        dst = f.get("dst", "")
        if _is_private_ip(dst):
            return None
        if total > 100000 and _is_private_ip(src) and not self._is_safe_ip(dst):
            return {
                "type": "data_exfiltration",
                "severity": "ALTO",
                "confidence": 75,
                "src": src,
                "dst": dst,
                "port": f.get("port"),
                "detail": f"Volume dati anomalo: {total} bytes verso IP esterno {dst}",
                "matched_malware": None,
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
        return None
