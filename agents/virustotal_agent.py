import requests
import json
import os


class VirusTotalAgent:
    def __init__(self, api_key=None):
        self.api_key = api_key or self._load_key()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
        self.cache = {}

    def _load_key(self):
        try:
            path = os.path.join(os.path.dirname(__file__), "..", "config", "keys.json")
            with open(path, "r", encoding="utf-8") as f:
                keys = json.load(f)
                return keys.get("virustotal", "")
        except:
            return ""

    def is_available(self):
        return bool(self.api_key) and len(self.api_key) > 20

    def _request(self, endpoint):
        if not self.is_available():
            return {"error": "API key non configurata"}
        if endpoint in self.cache:
            return self.cache[endpoint]
        try:
            url = self.base_url + "/" + endpoint
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                self.cache[endpoint] = data
                return data
            elif response.status_code == 404:
                return {"error": "Non trovato su VirusTotal"}
            elif response.status_code == 429:
                return {"error": "Troppe richieste. Riprova tra 60s."}
            else:
                return {"error": "Errore HTTP " + str(response.status_code)}
        except requests.exceptions.Timeout:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    def check_ip(self, ip):
        data = self._request("ip_addresses/" + ip)
        if "error" in data:
            return {"ip": ip, "status": "error", "message": data["error"]}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        country = attrs.get("country", "??")
        owner = attrs.get("as_owner", "Sconosciuto")
        reputation = attrs.get("reputation", 0)
        if malicious > 5:
            verdict = "MALEVOLO"
        elif malicious > 0 or suspicious > 0:
            verdict = "SOSPETTO"
        else:
            verdict = "PULITO"
        return {
            "ip": ip, "status": "ok", "verdict": verdict,
            "malicious_detections": malicious, "suspicious_detections": suspicious,
            "total_engines": total, "reputation": reputation,
            "country": country, "owner": owner
        }

    def check_domain(self, domain):
        data = self._request("domains/" + domain)
        if "error" in data:
            return {"domain": domain, "status": "error", "message": data["error"]}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0)
        reputation = attrs.get("reputation", 0)
        registrar = attrs.get("registrar", "Sconosciuto")
        if malicious > 5:
            verdict = "MALEVOLO"
        elif malicious > 0 or suspicious > 0:
            verdict = "SOSPETTO"
        else:
            verdict = "PULITO"
        return {
            "domain": domain, "status": "ok", "verdict": verdict,
            "malicious_detections": malicious, "suspicious_detections": suspicious,
            "total_engines": total, "reputation": reputation, "registrar": registrar
        }

    def format_ip_report(self, result):
        if result.get("status") == "error":
            return "VirusTotal: " + result.get("message", "Errore")
        v = result["verdict"]
        r = "VIRUSTOTAL - ANALISI IP: " + result["ip"] + "\n"
        r += "  Verdetto: " + v + "\n"
        r += "  Rilevamenti malevoli: " + str(result["malicious_detections"]) + "/" + str(result["total_engines"]) + "\n"
        r += "  Sospetti: " + str(result["suspicious_detections"]) + "\n"
        r += "  Reputazione: " + str(result["reputation"]) + "\n"
        r += "  Paese: " + result["country"] + "\n"
        r += "  Proprietario: " + result["owner"]
        return r

    def format_domain_report(self, result):
        if result.get("status") == "error":
            return "VirusTotal: " + result.get("message", "Errore")
        v = result["verdict"]
        r = "VIRUSTOTAL - ANALISI DOMINIO: " + result["domain"] + "\n"
        r += "  Verdetto: " + v + "\n"
        r += "  Rilevamenti malevoli: " + str(result["malicious_detections"]) + "/" + str(result["total_engines"]) + "\n"
        r += "  Sospetti: " + str(result["suspicious_detections"]) + "\n"
        r += "  Reputazione: " + str(result["reputation"]) + "\n"
        r += "  Registrar: " + result.get("registrar", "?")
        return r
