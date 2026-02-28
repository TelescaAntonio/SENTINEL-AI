import requests
import json
import os


class ClaudeAgent:
    def __init__(self, api_key=None):
        self.api_key = api_key or self._load_key()
        self.model = "claude-sonnet-4-20250514"
        self.base_url = "https://api.anthropic.com/v1/messages"

    def _load_key(self):
        try:
            path = os.path.join(os.path.dirname(__file__), "..", "config", "keys.json")
            with open(path, "r", encoding="utf-8") as f:
                keys = json.load(f)
                return keys.get("anthropic", "")
        except:
            return ""

    def is_available(self):
        return bool(self.api_key) and self.api_key.startswith("sk-ant-")

    def _call_claude(self, prompt, max_tokens=500):
        try:
            response = requests.post(
                self.base_url,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("content", [{}])[0].get("text", "Nessuna risposta")
            else:
                return None
        except:
            return None

    def analyze_threat(self, threat_data):
        ttype = threat_data.get("type", "?")
        severity = threat_data.get("severity", "?")
        src = threat_data.get("src", "?")
        dst = threat_data.get("dst", "?")
        port = str(threat_data.get("port", "?"))
        detail = threat_data.get("detail", "?")
        malware = threat_data.get("matched_malware", "non identificato")
        confidence = str(threat_data.get("confidence", "?"))

        prompt = "Sei un esperto di cybersecurity per una piccola impresa italiana. "
        prompt += "Analizza questa minaccia e fornisci: "
        prompt += "1) Spiegazione semplice 2) Rischio per i dati 3) Azioni immediate (max 5) "
        prompt += "4) Se serve notifica al Garante Privacy.\n\n"
        prompt += "Tipo: " + ttype + "\n"
        prompt += "Severita: " + severity + "\n"
        prompt += "Sorgente: " + src + "\n"
        prompt += "Destinazione: " + dst + ":" + port + "\n"
        prompt += "Dettaglio: " + detail + "\n"
        prompt += "Malware: " + str(malware) + "\n"
        prompt += "Confidenza: " + confidence + "%\n\n"
        prompt += "Rispondi in italiano, max 300 parole."

        if self.is_available():
            result = self._call_claude(prompt)
            if result:
                return "ANALISI AI (Claude):\n\n" + result

        return self._offline_analysis(threat_data)

    def analyze_network_status(self, stats, threats, devices):
        crit = sum(1 for t in threats if t.get("severity") == "CRITICO")
        alto = sum(1 for t in threats if t.get("severity") == "ALTO")

        threat_lines = ""
        for t in threats[:10]:
            sev = t.get("severity", "?")
            ttype = t.get("type", "?")
            src = t.get("src", "?")
            dst = t.get("dst", "?")
            mal = t.get("matched_malware", "?")
            threat_lines += "- [" + sev + "] " + ttype + ": " + src + " -> " + dst + " (" + str(mal) + ")\n"

        prompt = "Sei un consulente cybersecurity per PMI italiane. "
        prompt += "Fornisci un briefing esecutivo per il titolare.\n\n"
        prompt += "Pacchetti: " + str(stats.get("packets", 0)) + "\n"
        prompt += "Dispositivi: " + str(stats.get("devices", 0)) + "\n"
        prompt += "Minacce: " + str(stats.get("threats", 0)) + "\n\n"
        prompt += "Minacce:\n" + threat_lines + "\n"
        prompt += "Fornisci: 1) Rischio 1-10 2) 3 azioni urgenti 3) Impatto economico 4) Stato NIS2\n"
        prompt += "Italiano, max 250 parole."

        if self.is_available():
            result = self._call_claude(prompt)
            if result:
                return "BRIEFING AI:\n\n" + result

        return self._offline_status(stats, threats)

    def _offline_analysis(self, t):
        tipo = t.get("type", "sconosciuto")
        severity = t.get("severity", "MEDIO")
        explanations = {
            "beaconing": "Il dispositivo comunica regolarmente con un server sospetto. Tipico di malware controllato da remoto.",
            "dns_exfiltration": "Dati aziendali rubati tramite richieste DNS. Documenti e dati clienti potrebbero essere stati copiati.",
            "malicious_domain": "Collegamento a sito malevolo. Possibile phishing o distribuzione malware.",
            "lateral_movement": "Malware si muove tra computer della rete. Comportamento tipico di ransomware.",
            "phishing": "Sito che imita una banca. Le credenziali inserite potrebbero essere state rubate.",
            "brute_force": "Tentativi di indovinare password. Se debole, potrebbe riuscirci.",
            "suspicious_port": "Comunicazione su porta insolita, spesso usata da malware o crypto miner.",
            "data_exfiltration": "Volume anomalo di dati in uscita. Possibile furto dati in corso.",
        }
        explanation = explanations.get(tipo, "Attivita di rete sospetta.")
        r = "ANALISI MINACCIA (offline):\n\n" + explanation + "\n\n"
        r += "AZIONI CONSIGLIATE:\n"
        if severity == "CRITICO":
            r += "  1. Scollegare SUBITO il dispositivo dalla rete\n"
            r += "  2. NON spegnere il computer\n"
            r += "  3. Cambiare tutte le password da altro dispositivo\n"
            r += "  4. Contattare tecnico sicurezza\n"
            r += "  5. Verificare obbligo notifica Garante (72h)"
        elif severity == "ALTO":
            r += "  1. Isolare il dispositivo\n"
            r += "  2. Scansione antivirus completa\n"
            r += "  3. Cambiare password utente\n"
            r += "  4. Monitorare 24h"
        else:
            r += "  1. Verificare se legittima\n"
            r += "  2. Aggiornare antivirus\n"
            r += "  3. Monitorare"
        return r

    def _offline_status(self, stats, threats):
        crit = sum(1 for t in threats if t.get("severity") == "CRITICO")
        if crit > 3:
            risk = "9/10 - EMERGENZA"
        elif crit > 0:
            risk = "7/10 - ALTO"
        else:
            risk = "3/10 - BASSO"
        r = "VALUTAZIONE RISCHIO: " + risk + "\n"
        r += "Minacce critiche: " + str(crit) + "\n"
        r += "Dispositivi: " + str(stats.get("devices", 0))
        return r
