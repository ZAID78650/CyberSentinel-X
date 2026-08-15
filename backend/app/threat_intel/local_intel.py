"""Local threat intelligence dataset.

Provides a STIX-shaped synthetic indicator feed so the platform works
fully offline. An adapter layer (see adapter.py) allows swapping in live
STIX/TAXII or vendor APIs later without changing consumers.
"""

LOCAL_INDICATORS = [
    # --- IPs (synthetic but representative of real-world malicious ranges) ---
    {"indicator_type": "IP", "value": "45.155.205.233", "confidence": 0.92, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["c2", "brute-force", "tor-exit"], "description": "Known C2 infrastructure; observed in credential stuffing campaigns."},
    {"indicator_type": "IP", "value": "185.220.101.34", "confidence": 0.88, "severity": "HIGH", "source": "local-feed",
     "tags": ["scanning", "tor-exit"], "description": "TOR exit node used for network reconnaissance and login spraying."},
    {"indicator_type": "IP", "value": "103.75.190.12", "confidence": 0.84, "severity": "HIGH", "source": "local-feed",
     "tags": ["brute-force", "rdp"], "description": "Source of repeated RDP brute-force attempts against multiple tenants."},
    {"indicator_type": "IP", "value": "91.240.118.17", "confidence": 0.90, "severity": "HIGH", "source": "local-feed",
     "tags": ["phishing", "infrastructure"], "description": "Hosting infrastructure for phishing kit delivery."},
    {"indicator_type": "IP", "value": "192.99.14.201", "confidence": 0.75, "severity": "MEDIUM", "source": "local-feed",
     "tags": ["scanning"], "description": "Observed performing mass port scans against internet-facing assets."},
    {"indicator_type": "IP", "value": "5.188.206.44", "confidence": 0.86, "severity": "HIGH", "source": "local-feed",
     "tags": ["c2", "exfiltration"], "description": "Command-and-control node; exfiltration staging observed."},
    {"indicator_type": "IP", "value": "194.26.135.90", "confidence": 0.82, "severity": "HIGH", "source": "local-feed",
     "tags": ["botnet"], "description": "Member of a known proxy/botnet network."},

    # --- Domains ---
    {"indicator_type": "DOMAIN", "value": "update-secure-check.xyz", "confidence": 0.94, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["malware", "c2", "phishing"], "description": "Lookalike security-update domain delivering malware payloads."},
    {"indicator_type": "DOMAIN", "value": "cdn-verify-service.net", "confidence": 0.89, "severity": "HIGH", "source": "local-feed",
     "tags": ["c2"], "description": "Observed as C2 callback domain for info-stealer family."},
    {"indicator_type": "DOMAIN", "value": "invoice-attachment.link", "confidence": 0.90, "severity": "HIGH", "source": "local-feed",
     "tags": ["phishing"], "description": "Used in invoice-themed phishing campaigns."},
    {"indicator_type": "DOMAIN", "value": "support-microsoft-365.top", "confidence": 0.93, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["phishing", "credential-harvesting"], "description": "Credential harvesting page mimicking Microsoft 365 login."},

    # --- URLs ---
    {"indicator_type": "URL", "value": "http://45.155.205.233/gate.php", "confidence": 0.91, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["c2"], "description": "C2 beacon endpoint."},
    {"indicator_type": "URL", "value": "https://update-secure-check.xyz/dl/setup.exe", "confidence": 0.95, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["malware-download"], "description": "Distribution URL for a malicious installer."},

    # --- Hashes ---
    {"indicator_type": "HASH", "value": "44d88612fea8a8f36de82e1278abb02f", "confidence": 0.97, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["malware", "eicar"], "description": "EICAR test signature — used to validate detection pipelines."},
    {"indicator_type": "HASH", "value": "b1946ac92492d2347c6235b4d2611184", "confidence": 0.93, "severity": "HIGH", "source": "local-feed",
     "tags": ["malware", "info-stealer"], "description": "SHA-1 of a known info-stealer dropper sample."},
    {"indicator_type": "HASH", "value": "8d41b32e4b1c2b2e0c2a4c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c", "confidence": 0.90, "severity": "HIGH", "source": "local-feed",
     "tags": ["ransomware"], "description": "SHA-256 of a ransomware encryptor sample."},

    # --- CVEs ---
    {"indicator_type": "CVE", "value": "CVE-2021-44228", "confidence": 0.99, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["rce", "log4j"], "description": "Log4Shell — remote code execution in Apache Log4j 2.x."},
    {"indicator_type": "CVE", "value": "CVE-2023-23397", "confidence": 0.95, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["ntlm", "exchange"], "description": "Microsoft Outlook elevation of privilege via NTLM hashes."},
    {"indicator_type": "CVE", "value": "CVE-2021-34527", "confidence": 0.98, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["rce", "printnightmare"], "description": "Windows Print Spooler remote code execution (PrintNightmare)."},
    {"indicator_type": "CVE", "value": "CVE-2023-34362", "confidence": 0.92, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["zero-day", "mft"], "description": "MOVEit Transfer SQL injection leading to data theft."},

    # --- Malware families ---
    {"indicator_type": "MALWARE", "value": "Emotet", "confidence": 0.95, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["banking-trojan", "botnet", "loader"], "description": "Modular banking trojan / loader that drops additional malware."},
    {"indicator_type": "MALWARE", "value": "Cobalt Strike", "confidence": 0.96, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["c2", "framework"], "description": "Commercial C2 framework abused by threat actors for post-exploitation."},
    {"indicator_type": "MALWARE", "value": "Mimikatz", "confidence": 0.98, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["credential-dumping"], "description": "Credential dumping tool frequently used post-compromise."},
    {"indicator_type": "MALWARE", "value": "RedLine Stealer", "confidence": 0.93, "severity": "HIGH", "source": "local-feed",
     "tags": ["info-stealer"], "description": "Info-stealer that harvests credentials, cookies and crypto wallets."},
    {"indicator_type": "MALWARE", "value": "LockBit", "confidence": 0.94, "severity": "CRITICAL", "source": "local-feed",
     "tags": ["ransomware"], "description": "Ransomware-as-a-service family with double-extortion model."},
    {"indicator_type": "MALWARE", "value": "TrickBot", "confidence": 0.92, "severity": "HIGH", "source": "local-feed",
     "tags": ["banking-trojan", "loader"], "description": "Modular banking trojan and credential stealer."},

    # --- Techniques (alias to MITRE for convenience) ---
    {"indicator_type": "TECHNIQUE", "value": "T1110", "confidence": 0.90, "severity": "HIGH", "source": "local-feed",
     "tags": ["brute-force"], "description": "Brute Force — repeated credential guessing."},
    {"indicator_type": "TECHNIQUE", "value": "T1078", "confidence": 0.88, "severity": "HIGH", "source": "local-feed",
     "tags": ["valid-accounts"], "description": "Valid Accounts — use of compromised credentials."},
]

# Sources the local feed pretends to aggregate.
LOCAL_SOURCES = [
    {"name": "Local Indicator Feed", "source_type": "local", "status": "ACTIVE",
     "description": "Synthetic STIX-shaped indicators for offline demo mode."},
    {"name": "MITRE ATT&CK Dataset", "source_type": "local", "status": "ACTIVE",
     "description": "Embedded ATT&CK technique knowledge base."},
    {"name": "TAXII Server (stub)", "source_type": "taxii", "status": "DISABLED",
     "description": "Reserved adapter point for a live TAXII collection."},
    {"name": "VirusTotal (stub)", "source_type": "api", "status": "DISABLED",
     "description": "Reserved adapter point for vendor reputation APIs."},
]
