# Copyright (c) 2026 Antonio Telesca / IRST Institute. All Rights Reserved.
# PROPRIETARY SOFTWARE - Unauthorized use strictly prohibited. See LICENSE.

"""
SENTINEL-AI v2.0 - Universal Launcher
Funziona su: Windows PC, Raspberry Pi Zero 2 W
Connessione: Wi-Fi, Bluetooth PAN, USB Ethernet
"""
import sys
import os
import platform
import subprocess
import socket
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def get_all_interfaces():
    """Trova tutte le interfacce di rete disponibili"""
    interfaces = []
    try:
        from scapy.all import IFACES
        for iface in IFACES.values():
            if hasattr(iface, 'ip') and iface.ip and iface.ip != '':
                interfaces.append({
                    'name': iface.name,
                    'description': getattr(iface, 'description', ''),
                    'ip': iface.ip,
                    'index': iface.index
                })
    except:
        pass
    return interfaces


def get_local_ips():
    """Ottieni tutti gli IP locali"""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if not ip.startswith('127.') and ':' not in ip:
                ips.append(ip)
    except:
        pass
    return list(set(ips))


def detect_platform():
    """Rileva la piattaforma"""
    sys_name = platform.system()
    machine = platform.machine()
    is_pi = os.path.exists('/proc/device-tree/model')
    pi_model = ''
    if is_pi:
        try:
            with open('/proc/device-tree/model', 'r') as f:
                pi_model = f.read().strip()
        except:
            pass
    return {
        'system': sys_name,
        'machine': machine,
        'is_pi': is_pi,
        'pi_model': pi_model,
        'hostname': socket.gethostname()
    }


def print_banner(plat, interfaces, mode):
    print("=" * 60)
    print("  SENTINEL-AI v2.0 | AI Cybersecurity Guardian")
    print("  Copyright (c) 2026 Antonio Telesca / IRST Institute")
    print("=" * 60)
    print(f"  Sistema:     {plat['system']} ({plat['machine']})")
    print(f"  Hostname:    {plat['hostname']}")
    if plat['is_pi']:
        print(f"  Hardware:    {plat['pi_model']}")
    print(f"  Modalita:    {mode.upper()}")
    print(f"  Dashboard:   http://localhost:8080")
    print("-" * 60)
    print("  INTERFACCE DI RETE DISPONIBILI:")
    for i, iface in enumerate(interfaces):
        print(f"    [{i}] {iface['name']} - {iface['ip']}")
        if iface['description']:
            print(f"        {iface['description']}")
    print("-" * 60)
    ips = get_local_ips()
    print("  ACCESSO DASHBOARD DA ALTRI DISPOSITIVI:")
    for ip in ips:
        print(f"    http://{ip}:8080")
    print("=" * 60)


def run_live(iface_name):
    """Avvia cattura live"""
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    from core.engine import FlowTable, Packet
    from core.analyzer import ThreatAnalyzer
    from dashboard.app import DATA

    flow_table = FlowTable()
    analyzer = ThreatAnalyzer()
    seen_threats = set()
    packet_count = [0]

    def process_packet(raw_pkt):
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
            src=ip.src, dst=ip.dst, port=port,
            protocol=protocol, size=len(raw_pkt),
            dns_query=dns_query
        )
        packet_count[0] += 1
        flow_table.process_packet(pkt)
        if packet_count[0] % 50 == 0:
            update_dash(flow_table, packet_count[0], DATA)

    def update_dash(ft, pcount, data):
        devs = {}
        for key, flow in ft.flows.items():
            src, dst, p = key
            npkts = len(flow.packets)
            nbytes = flow.total_bytes
            for addr in [src, dst]:
                devs.setdefault(addr, {"packets": 0, "bytes": 0})
            devs[src]["packets"] += npkts
            devs[src]["bytes"] += nbytes
            devs[dst]["packets"] += npkts
            devs[dst]["bytes"] += nbytes
        data["devices"] = devs
        data["stats"]["packets"] = pcount
        data["stats"]["devices"] = len(devs)
        data["stats"]["flows"] = len(ft.flows)

    def analyze_loop():
        while True:
            time.sleep(30)
            try:
                update_dash(flow_table, packet_count[0], DATA)
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
                    print(f"  [!] {count_new} NUOVE MINACCE | PKT:{p} DEV:{d} FLOW:{fl} THR:{th}")
                else:
                    print(f"  [OK] Rete sicura | PKT:{p} DEV:{d} FLOW:{fl} THR:{th}")
            except Exception as e:
                print(f"  [ERR] {e}")

    t = threading.Thread(target=analyze_loop, daemon=True)
    t.start()
    print(f"  [LIVE] Cattura su {iface_name}...")
    sniff(iface=iface_name, prn=process_packet, store=False)


def run_simulation():
    """Avvia simulazione"""
    from core.simulator import BusinessSimulator
    from core.engine import FlowTable
    from core.analyzer import ThreatAnalyzer
    from dashboard.app import DATA

    print("  [SIM] Avvio simulazione...")
    sim = BusinessSimulator()
    packets = sim.run_all_scenarios()
    ft = FlowTable()
    for pkt in packets:
        ft.process_packet(pkt)
    flows = ft.get_all_flows()
    analyzer = ThreatAnalyzer()
    threats = []
    for f in flows:
        for t in analyzer.analyze_flow(f):
            threats.append(t)
    devs = {}
    for pkt in packets:
        for ip in [pkt.src, pkt.dst]:
            devs.setdefault(ip, {"packets": 0, "bytes": 0})
            devs[ip]["packets"] += 1
            devs[ip]["bytes"] += pkt.size
    DATA["stats"] = {
        "packets": len(packets), "devices": len(devs),
        "flows": len(flows), "threats": len(threats)
    }
    DATA["devices"] = devs
    DATA["alerts"] = threats
    if hasattr(sim, 'office_devices'):
        DATA["office_devices"] = sim.office_devices
    crit = sum(1 for t in threats if t.get("severity") == "CRITICO")
    alto = sum(1 for t in threats if t.get("severity") == "ALTO")
    print(f"  [SIM] {len(packets)} PKT, {len(flows)} FLOW, {len(threats)} MINACCE (C:{crit} A:{alto})")


def main():
    plat = detect_platform()
    interfaces = get_all_interfaces()

    # Menu
    print("\n  SENTINEL-AI v2.0 - Seleziona modalita:\n")
    print("  [1] LIVE     - Cattura traffico reale dalla rete")
    print("  [2] SIMULAZIONE - Demo con attacchi simulati")
    print("  [3] ENTRAMBI - Simulazione + cattura live\n")

    choice = input("  Scegli (1/2/3): ").strip()

    if choice == "1":
        mode = "live"
    elif choice == "3":
        mode = "both"
    else:
        mode = "simulation"

    # Selezione interfaccia per modalita live
    iface_name = None
    if mode in ["live", "both"]:
        if not interfaces:
            print("  [ERRORE] Nessuna interfaccia di rete trovata!")
            return
        print("\n  Seleziona interfaccia di rete:\n")
        for i, iface in enumerate(interfaces):
            print(f"    [{i}] {iface['name']} ({iface['ip']}) - {iface['description']}")
        try:
            idx = int(input(f"\n  Scegli (0-{len(interfaces)-1}): ").strip())
            iface_name = interfaces[idx]['name']
        except:
            iface_name = interfaces[0]['name']

    print_banner(plat, interfaces, mode)

    # Avvia dashboard
    from dashboard.app import app
    dash_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False),
        daemon=True
    )
    dash_thread.start()
    time.sleep(2)

    # Avvia in base alla modalita
    if mode == "simulation":
        sim_thread = threading.Thread(target=run_simulation, daemon=True)
        sim_thread.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  [STOP] Sentinel-AI arrestato.")

    elif mode == "live":
        try:
            run_live(iface_name)
        except KeyboardInterrupt:
            print("\n  [STOP] Sentinel-AI arrestato.")

    elif mode == "both":
        sim_thread = threading.Thread(target=run_simulation, daemon=True)
        sim_thread.start()
        time.sleep(5)
        try:
            run_live(iface_name)
        except KeyboardInterrupt:
            print("\n  [STOP] Sentinel-AI arrestato.")


if __name__ == "__main__":
    main()