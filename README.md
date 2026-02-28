# SENTINEL-AI Business v2.0

### AI-Powered Cybersecurity Guardian for SMEs

Real-time network threat detection with multi-agent AI analysis.
Designed for European SMEs with NIS2 and GDPR compliance built-in.
Runs on Raspberry Pi Zero 2 W with ZeroClaw runtime.

## Threat Detection (8 Engines)

- Beaconing (Emotet, Cobalt Strike, Trickbot)
- DNS Exfiltration via tunneling
- Malicious Domains and typosquatting
- Lateral Movement via SMB/445 (ransomware)
- Phishing (fake banking pages)
- Brute Force (SSH/RDP)
- Suspicious Ports (crypto-mining)
- Data Exfiltration (anomalous volumes)

## Multi-Agent AI System

- VirusTotal Agent: real-time IP/domain reputation
- AbuseIPDB Agent: IP abuse scoring and geolocation
- Claude AI Agent: natural language threat analysis

## Dashboard

Web-based real-time UI at http://localhost:8080
- Live counters (packets, devices, flows, threats)
- NIS2 compliance status
- Color-coded alerts
- Device map
- AI investigative console (14+ commands)

## Quick Start

```
git clone https://github.com/TelescaAntonio/SENTINEL-AI.git
cd SENTINEL-AI
pip install flask requests scapy
python main.py
```

Open http://localhost:8080

## License

PROPRIETARY - All Rights Reserved. See LICENSE for full terms.

## Author

Antonio Telesca - IRST Institute
Email: antonio.telesca@irst-institute.eu
GitHub: https://github.com/TelescaAntonio

Copyright (c) 2026 Antonio Telesca. All Rights Reserved.
Unauthorized use, reproduction or distribution is strictly prohibited.
