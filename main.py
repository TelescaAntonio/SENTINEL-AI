"""
SENTINEL BUSINESS v1.0
Sicurezza di rete AI per PMI - Conforme NIS2/GDPR
"""
import sys
import os
import threading
import time
import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import FlowTable
from core.simulator import BusinessSimulator
from core.analyzer import ThreatAnalyzer

DASH_URL = "http://127.0.0.1:8080"


def post_to_dashboard(data):
    try:
        requests.post(f"{DASH_URL}/api/update", json=data, timeout=2)
    except:
        pass


def run_simulation():
    time.sleep(2)
    try:
        post_to_dashboard({"status": "running"})

        sim = BusinessSimulator()
        packets = sim.run_all_scenarios()

        ft = FlowTable()
        for pkt in packets:
            ft.process_packet(pkt)
        flows = ft.get_all_flows()

        analyzer = ThreatAnalyzer()
        all_threats = []
        for f in flows:
            threats = analyzer.analyze_flow(f)
            all_threats.extend(threats)

        # Costruisci mappa dispositivi
        devs = {}
        for pkt in packets:
            for ip in [pkt.src, pkt.dst]:
                if ip:
                    devs.setdefault(ip, {"packets": 0, "bytes": 0, "threats": 0})
                    devs[ip]["packets"] += 1
                    devs[ip]["bytes"] += pkt.size

        # Conta minacce per dispositivo
        for t in all_threats:
            src = t.get("src", "")
            if src in devs:
                devs[src]["threats"] = devs[src].get("threats", 0) + 1

        crit = sum(1 for t in all_threats if t["severity"] == "CRITICO")
        alto = sum(1 for t in all_threats if t["severity"] == "ALTO")
        medio = sum(1 for t in all_threats if t["severity"] == "MEDIO")

        # Invia tutto alla dashboard
        post_to_dashboard({
            "status": "done",
            "stats": {
                "packets": len(packets),
                "devices": len(devs),
                "flows": len(flows),
                "threats": len(all_threats),
                "critical": crit,
                "high": alto,
                "medium": medio,
            },
            "alerts": all_threats,
            "devices": devs,
            "office_devices": sim.office_devices,
        })

        # Stampa riepilogo nel terminale
        print(f"\n[ANALISI] {len(packets)} pacchetti -> {len(flows)} flussi -> {len(devs)} dispositivi")
        print(f"[RISULTATO] {len(all_threats)} minacce (Critiche: {crit}, Alte: {alto}, Medie: {medio})")
        print(f"[DASHBOARD] Dati inviati a {DASH_URL}")

    except Exception as e:
        print(f"[ERRORE] Simulazione: {e}")
        import traceback
        traceback.print_exc()


def main():
    print("=" * 55)
    print("  SENTINEL BUSINESS v1.0")
    print("  Sicurezza AI per PMI - NIS2/GDPR")
    print("  http://localhost:8080")
    print("=" * 55)

    # Avvia dashboard
    from dashboard.app import run_dashboard
    dash_thread = threading.Thread(target=run_dashboard, daemon=True)
    dash_thread.start()

    # Avvia simulazione
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()

    # Tieni vivo il processo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[STOP] Sentinel Business arrestato.")


if __name__ == "__main__":
    main()
