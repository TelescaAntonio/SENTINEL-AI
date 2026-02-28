from datetime import datetime, timezone


class Investigator:
    def __init__(self):
        self.threats = []
        self.devices = {}
        self.office_map = {}
        self.stats = {}
        self.blocked = []
        self.notes = []
        self.vt = None
        self.abuse = None
        self.claude = None
        self._init_agents()

    def _init_agents(self):
        try:
            from agents.virustotal_agent import VirusTotalAgent
            self.vt = VirusTotalAgent()
        except:
            pass
        try:
            from agents.abuseipdb_agent import AbuseIPDBAgent
            self.abuse = AbuseIPDBAgent()
        except:
            pass
        try:
            from agents.claude_agent import ClaudeAgent
            self.claude = ClaudeAgent()
        except:
            pass

    def process_command(self, cmd):
        raw = cmd.strip()
        c = raw.lower()
        if c == "aiuto":
            return self._help()
        if c == "stato":
            return self._status()
        if c == "minacce":
            return self._threats()
        if c == "dispositivi":
            return self._devices()
        if c == "report":
            return self._report()
        if c == "scan":
            return self._scan()
        if c == "bloccati":
            return self._blocked_list()
        if c == "agenti":
            return self._agents_status()
        if c == "briefing":
            return self._briefing()
        if c.startswith("analizza "):
            return self._analyze(c[9:].strip())
        if c.startswith("chi e "):
            return self._who_is(c[6:].strip())
        if c.startswith("cosa fa "):
            return self._what_does(c[8:].strip())
        if c.startswith("blocca "):
            return self._block(c[7:].strip())
        if c.startswith("sblocca "):
            return self._unblock(c[8:].strip())
        if c.startswith("nota "):
            return self._add_note(raw[5:].strip())
        if c.startswith("vt "):
            return self._vt_check(c[3:].strip())
        if c.startswith("abuse "):
            return self._abuse_check(c[6:].strip())
        if c.startswith("spiega "):
            return self._explain_threat(c[7:].strip())
        return "Comando non riconosciuto. Scrivi 'aiuto' per la lista."

    def _help(self):
        h = "COMANDI SENTINEL BUSINESS\n\n"
        h += "MONITORAGGIO:\n"
        h += "  stato          - Stato rete\n"
        h += "  minacce        - Lista minacce\n"
        h += "  dispositivi    - Mappa dispositivi\n"
        h += "  scan           - Scansione rete\n"
        h += "  briefing       - Briefing AI\n\n"
        h += "INVESTIGAZIONE:\n"
        h += "  analizza <IP>  - Analisi IP\n"
        h += "  chi e <IP>     - Identifica dispositivo\n"
        h += "  cosa fa <IP>   - Attivita dispositivo\n"
        h += "  spiega <N>     - Spiega minaccia #N con AI\n\n"
        h += "INTELLIGENCE:\n"
        h += "  vt <IP/dominio>  - VirusTotal\n"
        h += "  abuse <IP>       - AbuseIPDB\n"
        h += "  agenti           - Stato agenti\n\n"
        h += "AZIONI:\n"
        h += "  blocca <IP>    - Blocca IP\n"
        h += "  sblocca <IP>   - Sblocca IP\n"
        h += "  bloccati       - Lista bloccati\n\n"
        h += "COMPLIANCE:\n"
        h += "  report         - Report NIS2/GDPR\n"
        h += "  nota <testo>   - Nota indagine"
        return h

    def _agents_status(self):
        vt_ok = self.vt and self.vt.is_available()
        ab_ok = self.abuse and self.abuse.is_available()
        cl_ok = self.claude and self.claude.is_available()
        s = "STATO AGENTI AI:\n"
        if vt_ok:
            s += "  VirusTotal:  ATTIVO\n"
        else:
            s += "  VirusTotal:  NON CONFIGURATO\n"
        if ab_ok:
            s += "  AbuseIPDB:   ATTIVO\n"
        else:
            s += "  AbuseIPDB:   NON CONFIGURATO\n"
        if cl_ok:
            s += "  Claude AI:   ATTIVO"
        else:
            s += "  Claude AI:   OFFLINE (analisi locale)"
        return s

    def _vt_check(self, target):
        if not self.vt or not self.vt.is_available():
            return "VirusTotal non configurato. Aggiungi API key in config/keys.json"
        if "." in target and not target.replace(".", "").isdigit():
            result = self.vt.check_domain(target)
            return self.vt.format_domain_report(result)
        else:
            result = self.vt.check_ip(target)
            return self.vt.format_ip_report(result)

    def _abuse_check(self, ip):
        if not self.abuse or not self.abuse.is_available():
            return "AbuseIPDB non configurato. Aggiungi API key in config/keys.json"
        result = self.abuse.check_ip(ip)
        return self.abuse.format_report(result)

    def _explain_threat(self, num_str):
        try:
            idx = int(num_str) - 1
        except ValueError:
            return "Usa: spiega <numero> (es: spiega 1)"
        if idx < 0 or idx >= len(self.threats):
            return "Minaccia #" + num_str + " non trovata."
        threat = self.threats[idx]
        if self.claude:
            return self.claude.analyze_threat(threat)
        return "Claude AI non disponibile."

    def _briefing(self):
        if self.claude:
            return self.claude.analyze_network_status(self.stats, self.threats, self.devices)
        crit = sum(1 for t in self.threats if t.get("severity") == "CRITICO")
        return "Briefing locale: " + str(len(self.threats)) + " minacce, " + str(crit) + " critiche."

    def _status(self):
        s = self.stats
        if not s or s.get("packets", 0) == 0:
            return "Sistema in attesa."
        crit = sum(1 for t in self.threats if t.get("severity") == "CRITICO")
        alto = sum(1 for t in self.threats if t.get("severity") == "ALTO")
        medio = sum(1 for t in self.threats if t.get("severity") == "MEDIO")
        if crit > 0:
            level = "CRITICO"
        elif alto > 0:
            level = "ATTENZIONE"
        else:
            level = "SICURO"
        vt_ok = self.vt and self.vt.is_available()
        ab_ok = self.abuse and self.abuse.is_available()
        cl_ok = self.claude and self.claude.is_available()
        r = "STATO RETE - SENTINEL BUSINESS\n"
        r += "  Livello: " + level + "\n"
        r += "  Pacchetti: " + str(s.get("packets", 0)) + "\n"
        r += "  Dispositivi: " + str(s.get("devices", 0)) + "\n"
        r += "  Flussi: " + str(s.get("flows", 0)) + "\n"
        r += "  Minacce: " + str(s.get("threats", 0))
        r += " (Critiche: " + str(crit) + ", Alte: " + str(alto) + ", Medie: " + str(medio) + ")\n"
        r += "  Bloccati: " + str(len(self.blocked)) + "\n"
        vt_s = "ON" if vt_ok else "OFF"
        ab_s = "ON" if ab_ok else "OFF"
        cl_s = "ON" if cl_ok else "LOCAL"
        r += "  Agenti: VT=" + vt_s + " Abuse=" + ab_s + " AI=" + cl_s
        return r

    def _threats(self):
        if not self.threats:
            return "Nessuna minaccia rilevata."
        lines = ["MINACCE RILEVATE: " + str(len(self.threats)), ""]
        for i, t in enumerate(self.threats, 1):
            sev = t.get("severity", "?")
            ttype = t.get("type", "?")
            src = t.get("src", "?")
            dst = t.get("dst", "?")
            port = str(t.get("port", "?"))
            detail = t.get("detail", "")
            malware = t.get("matched_malware", "")
            lines.append("  #" + str(i) + " [" + sev + "] " + ttype)
            lines.append("     " + src + " -> " + dst + ":" + port)
            lines.append("     " + detail)
            if malware:
                lines.append("     Malware: " + malware)
            lines.append("")
        lines.append("Usa 'spiega <N>' per analisi AI.")
        return "\n".join(lines)

    def _devices(self):
        if not self.devices:
            return "Nessun dispositivo."
        lines = ["DISPOSITIVI IN RETE:", ""]
        for ip in sorted(self.devices.keys()):
            info = self.devices[ip]
            name = self.office_map.get(ip, {}).get("name", "Sconosciuto")
            threats = info.get("threats", 0)
            pkts = str(info.get("packets", 0))
            if threats > 0:
                status = "!!! " + str(threats) + " MINACCE"
            else:
                status = "OK"
            lines.append("  " + ip.ljust(18) + " " + name.ljust(22) + " " + pkts.rjust(5) + " pkt  [" + status + "]")
        return "\n".join(lines)

    def _analyze(self, ip):
        dev = self.devices.get(ip)
        if not dev:
            return "IP " + ip + " non trovato."
        name = self.office_map.get(ip, {}).get("name", "Sconosciuto")
        dtype = self.office_map.get(ip, {}).get("type", "sconosciuto")
        ip_threats = [t for t in self.threats if t.get("src") == ip or t.get("dst") == ip]
        lines = []
        lines.append("ANALISI: " + ip)
        lines.append("  Nome: " + name)
        lines.append("  Tipo: " + dtype)
        lines.append("  Pacchetti: " + str(dev.get("packets", 0)))
        lines.append("  Bytes: " + str(dev.get("bytes", 0)))
        lines.append("  Minacce: " + str(len(ip_threats)))
        lines.append("")
        is_external = not ip.startswith("192.168.") and not ip.startswith("10.")
        if is_external:
            if self.vt and self.vt.is_available():
                vt = self.vt.check_ip(ip)
                v = str(vt.get("verdict", "?"))
                m = str(vt.get("malicious_detections", 0))
                tot = str(vt.get("total_engines", 0))
                lines.append("  VIRUSTOTAL: " + v + " (" + m + "/" + tot + ")")
            if self.abuse and self.abuse.is_available():
                ab = self.abuse.check_ip(ip)
                if ab.get("status") == "ok":
                    v = str(ab.get("verdict", "?"))
                    sc = str(ab.get("abuse_score", 0))
                    lines.append("  ABUSEIPDB: " + v + " (score: " + sc + "%)")
            lines.append("")
        if ip_threats:
            lines.append("  MINACCE:")
            for t in ip_threats:
                sev = t.get("severity", "?")
                ttype = t.get("type", "?")
                detail = t.get("detail", "")
                malware = t.get("matched_malware", "")
                lines.append("    [" + sev + "] " + ttype + ": " + detail)
                if malware:
                    lines.append("    Malware: " + malware)
            lines.append("")
            lines.append("  AZIONI:")
            lines.append("    1. Isolare il dispositivo")
            lines.append("    2. Scansione antivirus")
            lines.append("    3. Cambiare password")
            lines.append("    4. Verificare backup")
            lines.append("    5. Contattare IT")
        else:
            lines.append("  Dispositivo pulito.")
        return "\n".join(lines)

    def _who_is(self, ip):
        name = self.office_map.get(ip, {}).get("name", None)
        dtype = self.office_map.get(ip, {}).get("type", None)
        dev = self.devices.get(ip)
        if name:
            pkts = dev.get("packets", 0) if dev else 0
            threats = dev.get("threats", 0) if dev else 0
            if threats > 0:
                status = "ATTENZIONE: " + str(threats) + " minacce!"
            else:
                status = "Nessuna minaccia."
            r = ip + " e' '" + name + "' (tipo: " + str(dtype) + ")\n"
            r += "  Pacchetti: " + str(pkts) + "\n"
            r += "  " + status
            return r
        elif dev:
            return ip + " presente ma non identificato. Possibile dispositivo non autorizzato."
        return ip + " non trovato nella rete."

    def _what_does(self, ip):
        dev = self.devices.get(ip, {})
        if not dev:
            return ip + " non trovato."
        name = self.office_map.get(ip, {}).get("name", ip)
        ip_threats = [t for t in self.threats if t.get("src") == ip]
        pkts = str(dev.get("packets", 0))
        bts = str(dev.get("bytes", 0))
        lines = [name + " (" + ip + "): " + pkts + " pacchetti, " + bts + " bytes."]
        if ip_threats:
            lines.append("ATTENZIONE: " + str(len(ip_threats)) + " attivita sospette:")
            for t in ip_threats:
                sev = t.get("severity", "?")
                ttype = t.get("type", "?")
                detail = t.get("detail", "")
                lines.append("  - [" + sev + "] " + ttype + ": " + detail)
        else:
            lines.append("Nessuna attivita sospetta.")
        return "\n".join(lines)

    def _block(self, ip):
        if ip not in self.blocked:
            self.blocked.append(ip)
        return "[BLOCCATO] " + ip + "\nTotale bloccati: " + str(len(self.blocked))

    def _unblock(self, ip):
        if ip in self.blocked:
            self.blocked.remove(ip)
            return "[SBLOCCATO] " + ip
        return ip + " non era bloccato."

    def _blocked_list(self):
        if not self.blocked:
            return "Nessun IP bloccato."
        lines = ["IP BLOCCATI (" + str(len(self.blocked)) + "):"]
        for ip in self.blocked:
            lines.append("  - " + ip)
        return "\n".join(lines)

    def _scan(self):
        if not self.devices:
            return "Nessun dato."
        internal = sum(1 for ip in self.devices if ip.startswith("192.168."))
        external = len(self.devices) - internal
        compromised = sum(1 for d in self.devices.values() if d.get("threats", 0) > 0)
        r = "SCANSIONE RETE:\n"
        r += "  Interni: " + str(internal) + "\n"
        r += "  Esterni: " + str(external) + "\n"
        r += "  Compromessi: " + str(compromised) + "\n\n"
        r += "Usa 'vt <IP>' o 'abuse <IP>' per intelligence."
        return r

    def _report(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        s = self.stats
        crit = sum(1 for t in self.threats if t.get("severity") == "CRITICO")
        alto = sum(1 for t in self.threats if t.get("severity") == "ALTO")
        medio = sum(1 for t in self.threats if t.get("severity") == "MEDIO")
        types = {}
        for t in self.threats:
            tp = t.get("type", "altro")
            types[tp] = types.get(tp, 0) + 1
        sep = "=" * 55
        lines = [sep]
        lines.append("  REPORT SICUREZZA - SENTINEL BUSINESS")
        lines.append("  Generato: " + now)
        lines.append("  Conforme a: NIS2 Art.21, GDPR Art.32")
        lines.append(sep)
        lines.append("")
        lines.append("1. RIEPILOGO")
        lines.append("   Pacchetti: " + str(s.get("packets", 0)))
        lines.append("   Dispositivi: " + str(s.get("devices", 0)))
        lines.append("   Flussi: " + str(s.get("flows", 0)))
        lines.append("   Minacce: " + str(len(self.threats)))
        lines.append("     Critiche: " + str(crit) + " | Alte: " + str(alto) + " | Medie: " + str(medio))
        lines.append("")
        lines.append("2. MINACCE PER TIPO")
        for tp, count in sorted(types.items(), key=lambda x: -x[1]):
            lines.append("   - " + tp + ": " + str(count))
        lines.append("")
        lines.append("3. DISPOSITIVI A RISCHIO")
        for ip in sorted(self.devices.keys()):
            dev = self.devices[ip]
            if dev.get("threats", 0) > 0:
                name = self.office_map.get(ip, {}).get("name", "?")
                lines.append("   - " + ip + " (" + name + "): " + str(dev["threats"]) + " minacce")
        lines.append("")
        lines.append("4. COMPLIANCE")
        if crit > 0:
            lines.append("   NIS2: NON CONFORME")
            lines.append("   GDPR: A RISCHIO")
        else:
            lines.append("   NIS2: CONFORME")
            lines.append("   GDPR: CONFORME")
        if crit > 0:
            lines.append("")
            lines.append("5. AZIONI URGENTI")
            lines.append("   - Isolare dispositivi compromessi")
            lines.append("   - Scansione antivirus completa")
            lines.append("   - Cambiare tutte le credenziali")
            lines.append("   - Verificare backup")
            lines.append("   - Notifica Garante entro 72h se dati personali compromessi")
        if self.notes:
            lines.append("")
            lines.append("6. NOTE")
            for n in self.notes:
                ts = n.get("time", "")[:16]
                tx = n.get("text", "")
                lines.append("   [" + ts + "] " + tx)
        vt_ok = self.vt and self.vt.is_available()
        ab_ok = self.abuse and self.abuse.is_available()
        cl_ok = self.claude and self.claude.is_available()
        vt_s = "ON" if vt_ok else "OFF"
        ab_s = "ON" if ab_ok else "OFF"
        cl_s = "ON" if cl_ok else "OFF"
        lines.append("")
        lines.append("7. AGENTI")
        lines.append("   VT: " + vt_s + " | Abuse: " + ab_s + " | AI: " + cl_s)
        lines.append("")
        lines.append(sep)
        fname = "report_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + ".txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            lines.append("Salvato in: " + fname)
        except:
            pass
        return "\n".join(lines)

    def _add_note(self, text):
        self.notes.append({"time": datetime.now(timezone.utc).isoformat(), "text": text})
        return "Nota aggiunta. Totale: " + str(len(self.notes))
