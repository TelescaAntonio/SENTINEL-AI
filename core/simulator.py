"""
SENTINEL BUSINESS - Network Simulator
Simula traffico realistico di una piccola impresa
"""
import random
import time
from datetime import datetime, timezone, timedelta
from core.engine import Packet


class BusinessSimulator:
    def __init__(self):
        self.base_time = datetime.now(timezone.utc)
        self.packets = []

        # Rete tipica PMI
        self.office_devices = {
            "192.168.1.1": {"name": "Router/Gateway", "type": "router"},
            "192.168.1.10": {"name": "PC Titolare", "type": "workstation"},
            "192.168.1.11": {"name": "PC Segretaria", "type": "workstation"},
            "192.168.1.12": {"name": "PC Contabilita", "type": "workstation"},
            "192.168.1.20": {"name": "Server NAS", "type": "server"},
            "192.168.1.30": {"name": "Stampante di rete", "type": "printer"},
            "192.168.1.40": {"name": "Telefono IP", "type": "voip"},
            "192.168.1.50": {"name": "Tablet reception", "type": "tablet"},
            "192.168.1.100": {"name": "WiFi Ospiti - Tel1", "type": "mobile"},
            "192.168.1.101": {"name": "WiFi Ospiti - Tel2", "type": "mobile"},
        }

        # Server esterni legittimi
        self.legitimate_servers = {
            "142.250.180.14": "Google",
            "157.240.1.35": "Facebook",
            "52.96.166.130": "Microsoft 365",
            "34.107.243.93": "Aruba PEC",
            "185.26.156.39": "Banca Intesa",
            "93.62.226.21": "Agenzia Entrate",
            "151.1.1.1": "Vodafone DNS",
        }

    def _make_packet(self, src, dst, port, proto, size, offset_sec, dns=None, tls=None):
        pkt = Packet(src, dst, port, proto, size, dns_query=dns, tls_sni=tls)
        pkt.timestamp = self.base_time + timedelta(seconds=offset_sec)
        return pkt

    def generate_normal_traffic(self):
        """Traffico normale di ufficio"""
        print("  [SIM] Traffico normale ufficio...")
        t = 0
        for _ in range(40):
            src = random.choice(["192.168.1.10", "192.168.1.11", "192.168.1.12"])
            dst = random.choice(list(self.legitimate_servers.keys()))
            port = random.choice([80, 443])
            self.packets.append(self._make_packet(src, dst, port, "TCP", random.randint(64, 1500), t))
            t += random.uniform(1, 10)

        # DNS normali
        for _ in range(15):
            src = random.choice(["192.168.1.10", "192.168.1.11", "192.168.1.12"])
            domain = random.choice(["google.com", "microsoft.com", "aruba.it", "agenziaentrate.gov.it"])
            self.packets.append(self._make_packet(src, "151.1.1.1", 53, "UDP", random.randint(40, 120), t, dns=domain))
            t += random.uniform(0.5, 3)

        # Stampa
        for _ in range(5):
            self.packets.append(self._make_packet("192.168.1.10", "192.168.1.30", 9100, "TCP", random.randint(500, 5000), t))
            t += random.uniform(2, 8)

    def simulate_emotet_infection(self):
        """PC Segretaria infettato da Emotet via email"""
        print("  [SIM] ATTACCO: Emotet su PC Segretaria (email phishing)")
        t = 60
        # Beacon C2 ogni ~30 secondi
        for i in range(25):
            self.packets.append(self._make_packet(
                "192.168.1.11", "185.234.72.100", 443, "TCP",
                random.randint(200, 800), t + i * 30 + random.uniform(-2, 2),
                tls="update-service.xyz"
            ))

    def simulate_ransomware_lateral(self):
        """Ransomware si muove lateralmente nella rete"""
        print("  [SIM] ATTACCO: Movimento laterale ransomware")
        t = 300
        targets = ["192.168.1.10", "192.168.1.12", "192.168.1.20", "192.168.1.30"]
        for target in targets:
            # SMB scan
            for port in [445, 139, 3389]:
                self.packets.append(self._make_packet("192.168.1.11", target, port, "TCP", 64, t))
                t += 0.3
            # Se trova SMB aperto, trasferisce payload
            self.packets.append(self._make_packet("192.168.1.11", target, 445, "TCP", random.randint(50000, 200000), t))
            t += 2

    def simulate_data_exfiltration(self):
        """Esfiltrazione dati contabili via DNS tunneling"""
        print("  [SIM] ATTACCO: Esfiltrazione dati contabili via DNS")
        t = 500
        for i in range(12):
            encoded = "".join(random.choices("0123456789abcdef", k=48))
            domain = f"{encoded}.data.evil-command-server.ru"
            self.packets.append(self._make_packet(
                "192.168.1.12", "8.8.8.8", 53, "UDP",
                random.randint(80, 250), t + i * 5 + random.uniform(-1, 1),
                dns=domain
            ))

    def simulate_phishing_site(self):
        """Titolare apre sito phishing bancario"""
        print("  [SIM] ATTACCO: Phishing bancario su PC Titolare")
        t = 200
        # DNS richiesta sito phishing
        self.packets.append(self._make_packet(
            "192.168.1.10", "151.1.1.1", 53, "UDP", 80, t,
            dns="bancaintesa-verifica.com"
        ))
        # Connessione al sito falso
        for i in range(8):
            self.packets.append(self._make_packet(
                "192.168.1.10", "45.155.205.10", 443, "TCP",
                random.randint(200, 3000), t + 2 + i * 3,
                tls="bancaintesa-verifica.com"
            ))

    def simulate_cryptominer_nas(self):
        """NAS compromesso con crypto miner"""
        print("  [SIM] ATTACCO: Crypto miner su Server NAS")
        t = 100
        for i in range(20):
            self.packets.append(self._make_packet(
                "192.168.1.20", "104.20.45.78", 3333, "TCP",
                random.randint(100, 500), t + i * 20 + random.uniform(-3, 3)
            ))

    def simulate_unauthorized_access(self):
        """Accesso non autorizzato da rete ospiti"""
        print("  [SIM] ATTACCO: Accesso non autorizzato da WiFi ospiti")
        t = 400
        # Dispositivo ospite tenta di accedere al NAS
        for port in [445, 22, 80, 8080, 21, 3389]:
            self.packets.append(self._make_packet("192.168.1.100", "192.168.1.20", port, "TCP", 64, t))
            t += 0.5
        # Tenta brute force SSH
        for i in range(15):
            self.packets.append(self._make_packet("192.168.1.100", "192.168.1.20", 22, "TCP", random.randint(100, 300), t))
            t += 1

    def run_all_scenarios(self):
        print("[SIM] Simulazione rete PMI...")
        self.generate_normal_traffic()
        self.simulate_emotet_infection()
        self.simulate_ransomware_lateral()
        self.simulate_data_exfiltration()
        self.simulate_phishing_site()
        self.simulate_cryptominer_nas()
        self.simulate_unauthorized_access()
        self.packets.sort(key=lambda p: p.timestamp)
        print(f"[SIM] Totale pacchetti: {len(self.packets)}")
        return self.packets
