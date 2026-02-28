# Copyright (c) 2026 Antonio Telesca / IRST Institute. All Rights Reserved.
# PROPRIETARY SOFTWARE - Unauthorized use strictly prohibited. See LICENSE.

"""
SENTINEL BUSINESS v2.0 - Live Mode
"""
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from core.engine import FlowTable, Packet
from core.analyzer import ThreatAnalyzer
from dashboard.app import DATA
import threading
import time

IFACE = "Wi-Fi"
ANALYSIS_INTERVAL = 30

flow_table = FlowTable()
analyzer = ThreatAnalyzer()
seen_threats = set()
packet_count = 0


def process_packet(raw_pkt):
    global packet_count
    if not raw_pkt.haslayer(IP):
        return
    ip = raw_pkt[IP]

    port = 0
    protocol = "OTHER"
    if raw_pkt.haslayer(TCP):
        port = raw_pkt[TCP].dport
        protocol = "TCP"
    elif raw_pkt.haslayer(UDP):
        port = raw_pkt[UDP].dport
        protocol = "UDP"

    dns_query = None
    if raw_pkt.haslayer(DNS) and raw_pkt.haslayer(DNSQR):
        try:
            dns_query = raw_pkt[DNSQR].qname.decode().rstrip(".")
        except:
            pass

    pkt = Packet(
        src=ip.src,
        dst=ip.dst,
        port=port,
        protocol=protocol,
        size=len(raw_pkt),
        dns_query=dns_query
    )

    packet_count += 1
    flow_table.process_packet(pkt)

    if packet_count % 50 == 0:
        update_dashboard()


def update_dashboard():
    devs = {}
    for key, flow in flow_table.flows.items():
        src, dst, p = key
        npkts = len(flow.packets)
        nbytes = flow.total_bytes
        for addr in [src, dst]:
            devs.setdefault(addr, {"packets": 0, "bytes": 0})
        devs[src]["packets"] += npkts
        devs[src]["bytes"] += nbytes
        devs[dst]["packets"] += npkts
        devs[dst]["bytes"] += nbytes
    DATA["devices"] = devs
    DATA["stats"]["packets"] = packet_count
    DATA["stats"]["devices"] = len(devs)
    DATA["stats"]["flows"] = len(flow_table.flows)


def analyze_loop():
    while True:
        time.sleep(ANALYSIS_INTERVAL)
        try:
            update_dashboard()
            flows = flow_table.get_all_flows()
            count_new = 0
            for f in flows:
                for t in analyzer.analyze_flow(f):
                    key = f"{t.get('type')}_{t.get('src')}_{t.get('dst')}"
                    if key not in seen_threats:
                        seen_threats.add(key)
                        DATA["alerts"].append(t)
                        count_new += 1
            DATA["stats"]["threats"] = len(DATA["alerts"])
            p = DATA["stats"]["packets"]
            d = DATA["stats"]["devices"]
            fl = DATA["stats"]["flows"]
            th = DATA["stats"]["threats"]
            if count_new:
                print(f"[!] {count_new} NUOVE MINACCE | PKT:{p} DEV:{d} FLOW:{fl} THR:{th}")
            else:
                print(f"[OK] Rete sicura | PKT:{p} DEV:{d} FLOW:{fl} THR:{th}")
        except Exception as e:
            print(f"[ERR] {e}")


def start_dashboard():
    from dashboard.app import app
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)


if __name__ == "__main__":
    print("=" * 55)
    print("  SENTINEL BUSINESS v2.0 | LIVE MODE")
    print(f"  Interfaccia: {IFACE}")
    print("  Dashboard: http://localhost:8080")
    print("=" * 55)

    t1 = threading.Thread(target=start_dashboard, daemon=True)
    t1.start()
    time.sleep(2)

    t2 = threading.Thread(target=analyze_loop, daemon=True)
    t2.start()

    print(f"[LIVE] Cattura su {IFACE}...")
    try:
        sniff(iface=IFACE, prn=process_packet, store=False)
    except KeyboardInterrupt:
        update_dashboard()
        p = DATA["stats"]["packets"]
        d = DATA["stats"]["devices"]
        th = DATA["stats"]["threats"]
        print(f"\n  FINE: {p} PKT, {d} DEV, {th} minacce")
