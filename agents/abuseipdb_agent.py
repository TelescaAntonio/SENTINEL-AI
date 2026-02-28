# Copyright (c) 2026 Antonio Telesca / IRST Institute. All Rights Reserved.
# PROPRIETARY SOFTWARE - Unauthorized use strictly prohibited. See LICENSE.

import requests
import json
import os


class AbuseIPDBAgent:
    def __init__(self, api_key=None):
        self.api_key = api_key or self._load_key()
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}

    def _load_key(self):
        try:
            path = os.path.join(os.path.dirname(__file__), "..", "config", "keys.json")
            with open(path, "r", encoding="utf-8") as f:
                keys = json.load(f)
                return keys.get("abuseipdb", "")
        except:
            return ""

    def is_available(self):
        return bool(self.api_key) and len(self.api_key) > 20

    def check_ip(self, ip):
        if not self.is_available():
            return {"ip": ip, "status": "error", "message": "API key non configurata"}
        if ip in self.cache:
            return self.cache[ip]
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            return {"ip": ip, "status": "skip", "message": "IP privato"}
        try:
            response = requests.get(
                self.base_url + "/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=15
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                if score > 80:
                    verdict = "MALEVOLO"
                elif score > 30:
                    verdict = "SOSPETTO"
                else:
                    verdict = "PULITO"
                result = {
                    "ip": ip, "status": "ok", "verdict": verdict,
                    "abuse_score": score,
                    "country": data.get("countryCode", "??"),
                    "isp": data.get("isp", "Sconosciuto"),
                    "total_reports": data.get("totalReports", 0),
                    "num_users": data.get("numDistinctUsers", 0),
                    "last_reported": data.get("lastReportedAt", "Mai"),
                    "usage_type": data.get("usageType", "Sconosciuto"),
                }
                self.cache[ip] = result
                return result
            elif response.status_code == 429:
                return {"ip": ip, "status": "error", "message": "Limite richieste raggiunto"}
            else:
                return {"ip": ip, "status": "error", "message": "Errore HTTP " + str(response.status_code)}
        except Exception as e:
            return {"ip": ip, "status": "error", "message": str(e)}

    def format_report(self, result):
        if result.get("status") == "error":
            return "AbuseIPDB: " + result.get("message", "Errore")
        if result.get("status") == "skip":
            return "AbuseIPDB: " + result.get("message", "Skip")
        v = result.get("verdict", "?")
        r = "ABUSEIPDB - REPUTAZIONE IP: " + result["ip"] + "\n"
        r += "  Verdetto: " + v + "\n"
        r += "  Punteggio abuso: " + str(result.get("abuse_score", 0)) + "%\n"
        r += "  Segnalazioni: " + str(result.get("total_reports", 0))
        r += " da " + str(result.get("num_users", 0)) + " utenti\n"
        r += "  Ultima segnalazione: " + str(result.get("last_reported", "Mai")) + "\n"
        r += "  Paese: " + result.get("country", "??") + "\n"
        r += "  ISP: " + result.get("isp", "?") + "\n"
        r += "  Uso: " + result.get("usage_type", "?")
        return r
