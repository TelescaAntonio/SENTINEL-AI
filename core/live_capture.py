"""
SENTINEL BUSINESS - Live Network Capture
Cattura traffico reale dalla rete via Scapy
"""
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime, timezone
import threading, time


class LiveCapture:
    def __init__(self, iface="Wi-Fi", callback=None):
        self.iface = iface
        self.callback = callback
        self.running = False
        self.packets = []
        self.packet_count = 0
        self.start_time = None

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src": ip.src,
            "dst": ip.dst,
            "size": len(pkt),
            "proto": ip.proto,
            "port": 0,
            "dns_query": None
        }

        if pkt.haslayer(TCP):
            info["port"] = pkt[TCP].dport
            info["proto_name"] = "TCP"
        elif pkt.haslayer(UDP):
            info["port"] = pkt[UDP].dport
            info["proto_name"] = "UDP"

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
                info["dns_query"] = query
            except:
                pass

        self.packets.append(info)
        self.packet_count += 1

        if self.callback:
            self.callback(info)

    def start(self):
        self.running = True
        self.start_time = datetime.now(timezone.utc)
        print(f"[LIVE] Cattura avviata su {self.iface}")
        print(f"[LIVE] Premi Ctrl+C per fermare")

        def _sniff():
            try:
                sniff(
                    iface=self.iface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self.running
                )
            except Exception as e:
                print(f"[LIVE] Errore: {e}")

        self.thread = threading.Thread(target=_sniff, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        print(f"[LIVE] Cattura fermata. Totale: {self.packet_count} pacchetti")

    def get_stats(self):
        devices = set()
        for p in self.packets:
            devices.add(p["src"])
            devices.add(p["dst"])
        return {
            "packets": self.packet_count,
            "devices": len(devices),
            "capture_time": str(datetime.now(timezone.utc) - self.start_time) if self.start_time else "0"
        }
