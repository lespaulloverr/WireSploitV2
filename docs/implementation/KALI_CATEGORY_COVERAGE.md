# WireSploit v4.0.1 — Kali Linux Category Coverage Analysis

**Date:** 2026-10-25  
**Version:** 4.0.1  
**Purpose:** Map official Kali Linux tool categories to WireSploit integration classifications (Executable / Restricted / Educational)

---

## Executive Summary

This document analyzes the **official Kali Linux tool categories** from two authoritative sources and classifies each for WireSploit integration:

| Source | Category Count | Classification Approach |
|--------|----------------|------------------------|
| **kali.org/tools/** (MITRE ATT&CK) | 14 top-level + 50+ subcategories | Maps to execution risk profile |
| **Traditional Kali Menu** (GeeksforGeeks) | 13 categories | Maps to WireSploit's OSINT-first philosophy |

---

## Source 1: kali.org/tools/ — MITRE ATT&CK Framework Categories

### Top-Level Categories (14 + Forensics + Services)

| MITRE ATT&CK Category | Subcategories | WireSploit Classification | Rationale |
|-----------------------|---------------|---------------------------|-----------|
| **Reconnaissance** | Host Info, Identity Info, Network Info, DNS, Web Scanning, Vuln Scanning, Web Vuln Scanning, Bluetooth, WiFi, Radio Frequency | **EXECUTABLE** | Core OSINT mission; passive/active info gathering aligns with WireSploit's purpose |
| **Resource Development** | (Various) | **EDUCATIONAL** | Infrastructure setup, not direct targeting |
| **Initial Access** | (Various) | **RESTRICTED** | Active exploitation entry points; requires explicit authorization gating |
| **Execution** | (Various) | **RESTRICTED** | Code execution on targets; high risk |
| **Persistence** | (Various) | **RESTRICTED** | Maintaining access post-compromise; out of scope for OSINT |
| **Privilege Escalation** | (Various) | **RESTRICTED** | Post-exploitation; requires compromise first |
| **Defense Evasion** | Pass-the-Hash | **RESTRICTED** | Evasion techniques; dual-use but primarily offensive |
| **Credential Access** | OS Credential Dumping, Hash ID, Password Profiling, Brute Force, Password Cracking, Unsecured Credentials, WiFi Creds, Keylogger, VoIP, NFC, Kerberoasting | **RESTRICTED** | Direct credential theft; `authorized_only: true` + `deep_only: true` required |
| **Discovery** | Network Service, SSL/TLS, SNMP, Sniffing, Remote System, Account, Network Share, Process, Config, Security Appliances, Databases, SMTP, Cisco, AD, VoIP | **EXECUTABLE** (partial) | Network/service discovery aligns with OSINT; host-based discovery needs restriction |
| **Lateral Movement** | Pass-the-Hash | **RESTRICTED** | Post-exploitation movement |
| **Collection** | (Various) | **EDUCATIONAL** | Data staging/exfiltration prep; educational value |
| **Command and Control** | App Layer Protocol, Non-App Layer, Protocol Tunneling | **RESTRICTED** | C2 frameworks; high misuse potential |
| **Exfiltration** | (Various) | **RESTRICTED** | Data theft; out of scope |
| **Impact** | (Various) | **RESTRICTED** | Destructive actions; prohibited |
| **Forensics** | Digital Forensics, Forensic Carving, Forensic Imaging, PDF Forensics, Sleuth Kit | **EXECUTABLE** | Evidence analysis aligns with WireSploit's evidence management |
| **Services and Other Tools** | Reporting Tools, Laboratories, System Services | **EXECUTABLE** | Reporting tools enhance WireSploit exports; labs/services are infrastructure |

---

## Source 2: Traditional Kali Menu Categories (13 Categories)

*From [GeeksforGeeks Kali Linux Tools](https://www.geeksforgeeks.org/linux-unix/kali-linux-tools/) — reflects the classic Kali desktop menu structure*

| Traditional Category | Description | Kali Tools Examples | WireSploit Classification | Integration Notes |
|----------------------|-------------|---------------------|---------------------------|-------------------|
| **Information Gathering** | Collecting and formatting data | `nmap`, `masscan`, `dnsrecon`, `fierce`, `theharvester`, `recon-ng`, `maltego`, `sherlock`, `subfinder`, `amass`, `assetfinder`, `gobuster`, `dirb`, `dirsearch` | **EXECUTABLE** | **Primary alignment** — 11 of 23 WireSploit CLI tools already here; extend catalog |
| **Vulnerability Analysis** | Check system for flaws/vulnerabilities | `openvas`, `nikto`, `wpscan`, `lynis`, `nessus`, `sparta`, `arjun`, `dalfox`, `xsser`, `sqlmap` | **EXECUTABLE** (scanners) / **RESTRICTED** (exploit modules) | Passive scanners OK; active exploit modules need `authorized_only` |
| **Web Application Analysis** | Identify/access websites to check bugs | `burpsuite`, `owasp-zap`, `wpscan`, `nikto`, `sqlmap`, `commix`, `xsser`, `dalfox`, `ffuf`, `feroxbuster` | **EXECUTABLE** (scanners) / **RESTRICTED** (active exploitation) | Map to `web_providers` for passive APIs; CLI scanners need scope gating |
| **Database Assessment** | Access/analyze databases for attacks | `sqlmap`, `sqlitebrowser`, `dbeaver`, `mysql`, `postgresql`, `mongo` | **RESTRICTED** | Direct DB access requires explicit credentials/authorization |
| **Password Attacks** | Wordlist/password list handling | `hydra`, `medusa`, `john`, `hashcat`, `crunch`, `cewl`, `cupp`, `wordlists`, `brutespray`, `bruteforce-luks` | **RESTRICTED** | **All require `authorized_only: true` + `deep_only: true`** — credential testing is high-risk |
| **Wireless Attacks** | Wireless security cracking | `aircrack-ng`, `airgeddon`, `wifite`, `kismet`, `wash`, `reaver`, `bully`, `fern-wifi-cracker`, `fluxion`, `bettercap` | **RESTRICTED** | Requires physical proximity + authorization; hardware-dependent |
| **Reverse Engineering** | Break down software layers | `ghidra`, `radare2`, `cutter`, `dex2jar`, `apktool`, `jadx`, `binwalk`, `exiftool`, `strings`, `ltrace`, `strace` | **EXECUTABLE** | Static analysis tools safe; dynamic debuggers need `authorized_only` |
| **Exploitation Tools** | Exploit systems | `metasploit`, `searchsploit`, `exploitdb`, `crackmapexec`, `evil-winrm`, `coercer`, `nopayload`, `donut` | **RESTRICTED** | **All require `authorized_only: true`** — exploitation frameworks |
| **Sniffing and Spoofing** | Secretly access unauthorized network data | `wireshark`, `tcpdump`, `ettercap`, `bettercap`, `mitmproxy`, `dsniff`, `ferret-sidejack`, `sslstrip`, `arp-scan` | **RESTRICTED** | Network interception; requires controlled environment authorization |
| **Post Exploitation** | Backdoors to return to vulnerable systems | `metasploit` (post modules), `crackmapexec`, `evil-winrm`, `bloodhound`, `sharphound`, `lazagne`, `mimikatz` | **RESTRICTED** | Post-compromise only; requires prior authorized access |
| **Forensics** | Recover information for forensics | `autopsy`, `sleuthkit`, `volatility`, `bulk-extractor`, `foremost`, `scalpel`, `dd`, `dc3dd`, `ewf-tools`, `pdf-parser` | **EXECUTABLE** | Strong alignment with WireSploit evidence system; integrate via `analyze_file` |
| **Reporting Tools** | Statistics/information for analysis | `dradis`, `faraday`, `magneto`, `pipal`, `magictree`, `keepnote`, `cherrytree` | **EXECUTABLE** | Enhance WireSploit's export (JSON/CSV/HTML/PDF) with Kali report formats |
| **Social Engineering** | Generate similar services to extract personal info | `setoolkit`, `gophish`, `king-phisher`, `evilginx2`, `credential-harvester`, `social-analyzer` | **RESTRICTED** | Phishing frameworks; `authorized_only: true` + explicit opt-in |

---

## WireSploit Classification Definitions

### EXECUTABLE
- **Definition**: Tools that can be safely executed within WireSploit's automated investigation pipeline
- **Requirements**: Passive or authorized-active only; no credential testing; no exploitation
- **Scope Gate**: `authorized_only: false` (or true for active checks), `deep_only: false`
- **Examples**: `subfinder`, `amass`, `nmap` (passive), `theharvester`, `sherlock`, `ghidra` (static), `autopsy`

### RESTRICTED
- **Definition**: Tools that require explicit authorization, controlled environment, and/or manual operator oversight
- **Requirements**: 
  - `authorized_only: true` — Only runs if target in authorized scope
  - `deep_only: true` — Only runs in deep investigation mode
  - Operator confirmation dialog before execution
  - Audit log entry with timestamp, operator, target, tool
- **Examples**: `hydra`, `hashcat`, `sqlmap` (exploit mode), `metasploit`, `aircrack-ng`, `ettercap`, `setoolkit`

### EDUCATIONAL
- **Definition**: Tools referenced in catalog for awareness/learning but not executed by WireSploit
- **Requirements**: Listed in `catalog.py` or `awesome_catalog.py` with `integration: "external"`
- **No execution path**: WireSploit never claims their output as findings
- **Examples**: `burpsuite` (GUI), `metasploit` (framework), `wireshark` (GUI), lab environments

---

## Current WireSploit Coverage vs. Kali Categories

| Kali Category | WireSploit v4.0.1 Coverage | Gap |
|---------------|---------------------------|-----|
| Information Gathering | ✅ 11 CLI tools + 30+ web providers + 13 native providers | Minor: more DNS/SSL tools |
| Vulnerability Analysis | ⚠️ Partial (nikto via web, no OpenVAS/Nessus) | Add scanner CLIs as RESTRICTED |
| Web Application Analysis | ⚠️ Partial (no Burp/ZAP integration) | Add scanner CLIs; Burp as EDUCATIONAL |
| Database Assessment | ❌ None | Add `sqlmap` as RESTRICTED |
| Password Attacks | ❌ None (by design) | Add `hydra`/`hashcat`/`john` as RESTRICTED |
| Wireless Attacks | ❌ None | Hardware-dependent; low priority |
| Reverse Engineering | ❌ None | Add `ghidra`/`radare2` as EXECUTABLE (static) |
| Exploitation Tools | ❌ None (by design) | Add `metasploit`/`searchsploit` as RESTRICTED |
| Sniffing & Spoofing | ❌ None | Add `tcpdump`/`tshark` as EXECUTABLE (passive capture) |
| Post Exploitation | ❌ None | Add `bloodhound`/`crackmapexec` as RESTRICTED |
| Forensics | ✅ `analyze_file` (PDF, Office, EXIF) | Add `volatility`/`bulk-extractor` as EXECUTABLE |
| Reporting Tools | ⚠️ Basic exports only | Add Dradis/Faraday export formats |
| Social Engineering | ❌ None (by design) | Add `gophish`/`setoolkit` as RESTRICTED |

---

## Classification Decision Matrix

For each Kali tool considered for integration, apply this matrix:

| Question | Yes → | No → |
|----------|-------|------|
| Is the tool purely passive (no packets sent to target)? | EXECUTABLE | Next question |
| Does it send packets but only to authorized scopes? | EXECUTABLE (if `authorized_only`) | Next question |
| Does it test credentials (brute force, spray, crack)? | RESTRICTED | Next question |
| Does it exploit vulnerabilities (RCE, SQLi, etc.)? | RESTRICTED | Next question |
| Does it require physical/hardware access (WiFi, RFID, USB)? | RESTRICTED | Next question |
| Is it a GUI/framework not automatable via CLI? | EDUCATIONAL | Next question |
| Does it perform post-exploitation actions? | RESTRICTED | EDUCATIONAL |

---

## Recommended Integration Priority

### Phase 2A — EXECUTABLE (High Value, Low Risk)
1. **Reverse Engineering (static)**: `ghidra` (headless), `radare2`, `binwalk`, `strings`
2. **Forensics Enhancement**: `volatility3`, `bulk-extractor`, `foremost`, `scalpel`
3. **Information Gathering Additions**: `masscan`, `dnsx`, `dnsgen`, `dnsrecon`, `fierce`, `altdns`
4. **Passive Network**: `tshark` (CLI Wireshark), `p0f`
5. **Reporting**: `dradis` API, `faraday` CLI

### Phase 2B — RESTRICTED (High Value, Requires Auth Gating)
1. **Vulnerability Scanners**: `nikto`, `wpscan`, `nuclei`, `dalfox` (XSS), `arjun` (param discovery)
2. **Password Attacks**: `hydra`, `hashcat`, `john`, `crunch`, `cewl` (wordlist gen)
3. **Web Exploitation**: `sqlmap`, `commix`, `xsser` (with `--batch`/safe flags)
4. **Post-Exploitation**: `bloodhound` (SharpHound ingest), `crackmapexec`, `ldapdomaindump`
5. **Wireless** (if hardware present): `aircrack-ng`, `kismet` (passive)

### Phase 2C — EDUCATIONAL (Catalog Only)
1. **Frameworks**: `metasploit`, `burpsuite`, `owasp-zap`, `setoolkit`, `gophish`
2. **GUI Tools**: `wireshark`, `autopsy` (GUI), `ghidra` (GUI), `maltego`
3. **Labs**: `dvwa`, `bwapp`, `mutillidae`, `juice-shop`

---

## References

- [kali.org/tools/](https://www.kali.org/tools/) — Official MITRE ATT&CK categorized tool index
- [kali.org/tools/all-tools/](https://www.kali.org/tools/all-tools/) — Complete alphabetical tool listing
- [GeeksforGeeks Kali Linux Tools](https://www.geeksforgeeks.org/linux-unix/kali-linux-tools/) — Traditional 13-category menu reference
- [en.kali.tools/](https://en.kali.tools/) — Community tool reference with categories
- `KALI_PROJECT_AUDIT.md` — WireSploit architecture audit
- `engine/tooling.py` — Current tool registry (23 tools)
- `engine/catalog.py` — Current web resource catalog (130+ entries)
- `engine/awesome_catalog.py` — Awesome OSINT derived catalog (130 entries)

---

*End of KALI_CATEGORY_COVERAGE.md*