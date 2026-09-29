from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


@dataclass
class ToolSpec:
    id: str
    name: str
    categories: list[str]
    kind: str
    repo: str | None = None
    deep_only: bool = False
    notes: str = ""
    install_hint: str = ""
    raw_command: str | None = None
    automated: bool = True
    server_only: bool = False
    requires_auth: bool = False
    authorized_only: bool = False
    group: str = "OSINT"


# WireSploit 0.3 deliberately separates providers into:
# - native: implemented directly in WireSploit
# - web: public endpoints that need no paid key
# - external: open-source command-line providers that run on the backend/server
# A mobile iOS client never spawns these command-line tools itself.
SPECS = [
    ToolSpec("native", "WireSploit Native", ["username", "phone", "email", "ip", "domain", "geolocation", "archives", "social", "search", "public_records", "technical", "files", "images"], "native", notes="Built-in public-source modules."),

    # Public web/API providers with no paid key required.
    ToolSpec("github_public", "GitHub Public API", ["username", "social"], "web"),
    ToolSpec("gitlab_public", "GitLab Public API", ["username", "social"], "web"),
    ToolSpec("reddit_public", "Reddit Public Profile", ["username", "social"], "web"),
    ToolSpec("hackernews_public", "Hacker News API", ["username", "social"], "web"),
    ToolSpec("bluesky_public", "Bluesky Public API", ["username", "social"], "web", notes="Exact Bluesky handles only; WireSploit does not guess suffixes."),
    ToolSpec("whatsmyname_public", "WhatsMyName Dataset", ["username", "social"], "web", deep_only=True, repo="https://github.com/WebBreacher/WhatsMyName", notes="Community-maintained public username checks across hundreds of sites."),
    ToolSpec("gravatar_public", "Gravatar Public Profile", ["email"], "web"),
    ToolSpec("rdap_domain", "RDAP.org Domain", ["domain", "technical"], "web"),
    ToolSpec("rdap_ip", "RDAP.org IP", ["ip", "technical"], "web"),
    ToolSpec("ipquery_public", "IPQuery", ["ip"], "web"),
    ToolSpec("crtsh_public", "crt.sh", ["domain", "technical"], "web", deep_only=True),
    ToolSpec("google_doh", "Google DNS over HTTPS", ["domain", "technical"], "web"),
    ToolSpec("cloudflare_doh", "Cloudflare DNS over HTTPS", ["domain", "technical"], "web"),
    ToolSpec("wayback_public", "Wayback Machine CDX", ["archives", "domain"], "web"),
    ToolSpec("commoncrawl_public", "Common Crawl Index", ["archives", "domain"], "web", deep_only=True),
    ToolSpec("openmeteo_public", "Open-Meteo", ["geolocation"], "web", deep_only=True),
    ToolSpec("overpass_public", "OpenStreetMap Overpass", ["geolocation"], "web", deep_only=True),
    ToolSpec("wikipedia_geo_public", "Wikipedia GeoSearch", ["geolocation"], "web", deep_only=True),
    ToolSpec("wikidata_public", "Wikidata Search", ["public_records"], "web"),
    ToolSpec("openalex_public", "OpenAlex", ["public_records"], "web", deep_only=True, notes="Open scholarly author/work metadata."),
    ToolSpec("hackingtool_catalog", "HackingTool Safe Catalog Bridge", ["security", "technical"], "web", repo="https://github.com/Z4nzu/hackingtool", automated=False, notes="Windows-safe catalogue router. Maps filtered defensive/OSINT entries to separately managed WireSploit integrations or narrower built-in workflows; upstream attack-oriented runners are not exposed.", group="Security Frameworks"),

    # Core external open-source providers.
    ToolSpec("sherlock", "Sherlock Project", ["username", "social"], "pip", repo="https://github.com/sherlock-project/sherlock", install_hint="pip install sherlock-project", raw_command="sherlock --help", server_only=True),
    ToolSpec("gosherlock", "Go Sherlock", ["username", "social"], "repo", repo="https://github.com/Longwater1234/go-sherlock", deep_only=True, install_hint="Clone/build with Go.", raw_command="go-sherlock --help", server_only=True),
    ToolSpec("ghosttrack", "GhostTrack", ["username", "phone", "ip", "social"], "repo", repo="https://github.com/HunxByts/GhostTrack", install_hint="Cloned into tools/ghosttrack with isolated venv.", raw_command="python GhostTR.py", server_only=True),
    ToolSpec("maigret", "Maigret", ["username", "social"], "pip", repo="https://github.com/soxoj/maigret", install_hint="pip install maigret", raw_command="maigret --help", server_only=True),
    ToolSpec("blackbird", "BlackBird", ["username", "email", "social"], "repo", repo="https://github.com/p1ngul1n0/blackbird", deep_only=True, install_hint="Cloned into tools/blackbird with isolated venv.", raw_command="python blackbird.py --help", server_only=True),
    ToolSpec("phunter", "Phunter", ["phone"], "repo", repo="https://github.com/N0rz3/Phunter", install_hint="Cloned into tools/phunter with isolated venv.", raw_command="python phunter.py -h", server_only=True),
    ToolSpec("phoneinfoga", "PhoneInfoga", ["phone"], "go", repo="https://github.com/sundowndev/phoneinfoga", deep_only=True, install_hint="Install/build PhoneInfoga on the server.", raw_command="phoneinfoga --help", server_only=True),
    ToolSpec("ghunt", "GHunt", ["email"], "pip", repo="https://github.com/mxrch/GHunt", deep_only=True, automated=False, install_hint="pip install ghunt; requires its own Google authentication before use.", raw_command="ghunt --help", server_only=True, requires_auth=True, notes="Manual until GHunt authentication has been configured; this prevents normal email searches from showing a permanently unavailable provider."),
    ToolSpec("amass", "OWASP Amass", ["domain", "technical"], "binary", repo="https://github.com/owasp-amass/amass", deep_only=True, install_hint="Install Amass on the backend. WireSploit uses passive enumeration only by default.", raw_command="amass -h", server_only=True),

    # Additional public-source / passive discovery providers.
    ToolSpec("socialanalyzer", "Social Analyzer", ["username", "social"], "pip", repo="https://github.com/qeeqbox/social-analyzer", deep_only=True, install_hint="pip install social-analyzer", raw_command="social-analyzer --help", server_only=True),
    ToolSpec("theharvester", "theHarvester", ["domain", "email", "technical"], "binary", repo="https://github.com/laramies/theHarvester", deep_only=True, automated=False, install_hint="Install from the upstream project/Docker. Current upstream builds require a newer Python toolchain than WireSploit itself on some Windows systems. WireSploit limits it to public/passive sources.", raw_command="theHarvester -h", server_only=True, notes="Manual until a compatible upstream installation is detected; avoids false 'unavailable' cards during ordinary searches."),
    ToolSpec("subfinder", "Subfinder", ["domain", "technical"], "go", repo="https://github.com/projectdiscovery/subfinder", deep_only=True, install_hint="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", raw_command="subfinder -h", server_only=True),
    ToolSpec("assetfinder", "Assetfinder", ["domain", "technical"], "go", repo="https://github.com/tomnomnom/assetfinder", deep_only=True, install_hint="go install github.com/tomnomnom/assetfinder@latest", raw_command="assetfinder --help", server_only=True),
    ToolSpec("waymore", "Waymore", ["archives", "domain"], "pip", repo="https://github.com/xnl-h4ck3r/waymore", deep_only=True, install_hint="pip install waymore", raw_command="waymore -h", server_only=True),
    ToolSpec("gau", "gau", ["archives", "domain"], "go", repo="https://github.com/lc/gau", deep_only=True, install_hint="Install gau from the upstream Go module/release.", raw_command="gau --help", server_only=True),
    ToolSpec("ytdlp", "yt-dlp Metadata", ["social"], "pip", repo="https://github.com/yt-dlp/yt-dlp", deep_only=True, install_hint="pip install yt-dlp", raw_command="yt-dlp --help", server_only=True, notes="Only used for metadata on a public URL; WireSploit does not download media."),
    ToolSpec("gallerydl", "gallery-dl Metadata", ["social", "images"], "pip", repo="https://github.com/mikf/gallery-dl", deep_only=True, install_hint="pip install gallery-dl", raw_command="gallery-dl --help", server_only=True, notes="Only used for metadata on public URLs."),
    ToolSpec("spiderfoot", "SpiderFoot", ["username", "email", "ip", "domain", "social"], "repo", repo="https://github.com/smicallef/spiderfoot", deep_only=True, automated=False, install_hint="Optional advanced framework. Exposed in Tool Manager rather than auto-run until configured for passive modules.", server_only=True),

    # Additional public-source / passive OSINT utilities. These are either passive
    # automated adapters or Tool Manager integrations. Active HTTP/DNS crawlers are
    # never auto-run from a normal lookup.
    ToolSpec("waybackurls", "waybackurls", ["archives", "domain"], "go", repo="https://github.com/tomnomnom/waybackurls", deep_only=True, install_hint="go install github.com/tomnomnom/waybackurls@latest", raw_command="waybackurls", server_only=True),
    ToolSpec("findomain", "Findomain", ["domain", "technical"], "binary", repo="https://github.com/Findomain/Findomain", deep_only=True, install_hint="Install the official Findomain release on the Engine.", raw_command="findomain --help", server_only=True, notes="WireSploit automation uses API/CT discovery only; intrusive/resolution options are not enabled."),
    ToolSpec("instaloader", "Instaloader", ["social", "username"], "pip", repo="https://github.com/instaloader/instaloader", deep_only=True, automated=False, install_hint="pip install instaloader", raw_command="instaloader --help", server_only=True, notes="Optional public-profile research utility; not auto-run because platform access rules and login requirements change frequently."),
    ToolSpec("photon", "Photon", ["domain", "technical"], "repo", repo="https://github.com/s0md3v/Photon", deep_only=True, automated=False, install_hint="Clone the upstream project on the Engine.", raw_command="python photon.py -h", server_only=True, notes="Web crawler. Tool Manager only; use only on public sites or authorized scope."),
    ToolSpec("gowitness", "gowitness", ["domain", "technical"], "go", repo="https://github.com/sensepost/gowitness", deep_only=True, automated=False, install_hint="Install the official Go/release build.", raw_command="gowitness --help", server_only=True, notes="Public-page screenshot utility; Tool Manager only."),
    ToolSpec("httpx", "ProjectDiscovery httpx", ["domain", "technical"], "go", repo="https://github.com/projectdiscovery/httpx", deep_only=True, automated=False, install_hint="go install github.com/projectdiscovery/httpx/cmd/httpx@latest", raw_command="httpx -h", server_only=True, notes="HTTP probing utility. Available only as an explicitly selected authorized technical tool."),
    ToolSpec("dnsrecon", "DNSRecon", ["domain", "technical"], "pip", repo="https://github.com/darkoperator/dnsrecon", deep_only=True, automated=False, install_hint="Install DNSRecon from upstream.", raw_command="dnsrecon -h", server_only=True, notes="DNS enumeration can generate active queries; not auto-run."),
    ToolSpec("dnsenum", "dnsenum", ["domain", "technical"], "binary", repo="https://github.com/fwaeytens/dnsenum", deep_only=True, automated=False, install_hint="Install dnsenum on the Engine if desired.", raw_command="dnsenum --help", server_only=True, notes="Tool Manager only; active DNS enumeration is not part of normal searches."),
    ToolSpec("reconng", "Recon-ng", ["domain", "social", "technical"], "repo", repo="https://github.com/lanmaster53/recon-ng", deep_only=True, automated=False, install_hint="Clone/install Recon-ng on the Engine.", raw_command="recon-ng", server_only=True, notes="Modular framework; WireSploit does not auto-run third-party modules."),
    ToolSpec("sn0int", "sn0int", ["domain", "social", "technical"], "binary", repo="https://github.com/kpcyrd/sn0int", deep_only=True, automated=False, install_hint="Install sn0int from its official release/package.", raw_command="sn0int --help", server_only=True, notes="OSINT framework exposed through Tool Manager; modules are not auto-run."),
    ToolSpec("metagoofil", "Metagoofil", ["domain", "files"], "repo", repo="https://github.com/opsdisk/metagoofil", deep_only=True, automated=False, install_hint="Clone/install Metagoofil on the Engine.", raw_command="metagoofil -h", server_only=True, notes="Public-document metadata research; manual because search-engine behavior changes frequently."),

    # Authorized cybersecurity / defensive assessment tools. These are deliberately
    # Tool Manager integrations rather than automatic OSINT providers. The web UI
    # keeps them under Security Testing and requires the user to maintain scope.
    ToolSpec("metasploit", "Metasploit Framework", ["security", "technical"], "binary", repo="https://github.com/rapid7/metasploit-framework", automated=False, install_hint="Install Metasploit Framework from Rapid7/upstream. WireSploit only detects and launches msfconsole; it never auto-runs exploit modules.", raw_command="msfconsole", server_only=True, authorized_only=True, group="Security Frameworks"),
    ToolSpec("nmap", "Nmap", ["security", "technical"], "binary", repo="https://github.com/nmap/nmap", automated=False, install_hint="Install Nmap for authorized network discovery/service assessment.", raw_command="nmap --help", server_only=True, authorized_only=True, group="Network Assessment"),
    ToolSpec("rustscan", "RustScan", ["security", "technical"], "binary", repo="https://github.com/bee-san/RustScan", automated=False, install_hint="Install RustScan for authorized network-port discovery.", raw_command="rustscan --help", server_only=True, authorized_only=True, group="Network Assessment"),
    ToolSpec("naabu", "ProjectDiscovery Naabu", ["security", "technical"], "go", repo="https://github.com/projectdiscovery/naabu", automated=False, install_hint="Install Naabu for authorized network discovery.", raw_command="naabu -h", server_only=True, authorized_only=True, group="Network Assessment"),
    ToolSpec("nuclei", "ProjectDiscovery Nuclei", ["security", "technical"], "go", repo="https://github.com/projectdiscovery/nuclei", automated=False, install_hint="Install Nuclei. Template-based scanning remains manual and restricted to your authorized scope.", raw_command="nuclei -h", server_only=True, authorized_only=True, group="Vulnerability Assessment"),
    ToolSpec("nikto", "Nikto", ["security", "technical"], "binary", repo="https://github.com/sullo/nikto", automated=False, install_hint="Install Nikto for authorized web-server assessment.", raw_command="nikto -Help", server_only=True, authorized_only=True, group="Web Assessment"),
    ToolSpec("zap", "OWASP ZAP", ["security", "technical"], "binary", repo="https://github.com/zaproxy/zaproxy", automated=False, install_hint="Install OWASP ZAP. WireSploit can detect/launch it but does not automatically attack targets.", raw_command="zap.bat", server_only=True, authorized_only=True, group="Web Assessment"),
    ToolSpec("testssl", "testssl.sh", ["security", "technical"], "binary", repo="https://github.com/testssl/testssl.sh", automated=False, install_hint="Install testssl.sh (normally via WSL/Git Bash/Docker on Windows) for authorized TLS assessment.", raw_command="testssl.sh --help", server_only=True, authorized_only=True, group="TLS / Web"),
    ToolSpec("sslscan", "SSLScan", ["security", "technical"], "binary", repo="https://github.com/rbsec/sslscan", automated=False, install_hint="Install SSLScan for authorized TLS configuration checks.", raw_command="sslscan --help", server_only=True, authorized_only=True, group="TLS / Web"),
    ToolSpec("sslyze", "SSLyze", ["security", "technical"], "pip", repo="https://github.com/nabla-c0d3/sslyze", automated=False, install_hint="pip install sslyze", raw_command="sslyze --help", server_only=True, authorized_only=True, group="TLS / Web"),
    ToolSpec("wafw00f", "WAFW00F", ["security", "technical"], "pip", repo="https://github.com/EnableSecurity/wafw00f", automated=False, install_hint="pip install wafw00f", raw_command="wafw00f --help", server_only=True, authorized_only=True, group="Web Assessment"),
    ToolSpec("whatweb", "WhatWeb", ["security", "technical", "domain"], "binary", repo="https://github.com/urbanadventurer/WhatWeb", automated=False, install_hint="Install WhatWeb (WSL/Ruby environment recommended on Windows) for technology fingerprinting.", raw_command="whatweb --help", server_only=True, authorized_only=True, group="Web Assessment"),
    ToolSpec("feroxbuster", "Feroxbuster", ["security", "technical"], "binary", repo="https://github.com/epi052/feroxbuster", automated=False, install_hint="Install Feroxbuster. Content discovery is manual and authorized-scope only.", raw_command="feroxbuster --help", server_only=True, authorized_only=True, group="Web Content Discovery"),
    ToolSpec("gobuster", "Gobuster", ["security", "technical"], "go", repo="https://github.com/OJ/gobuster", automated=False, install_hint="Install Gobuster. Directory/DNS discovery remains manual and authorized-scope only.", raw_command="gobuster help", server_only=True, authorized_only=True, group="Web Content Discovery"),
    ToolSpec("ffuf", "ffuf", ["security", "technical"], "go", repo="https://github.com/ffuf/ffuf", automated=False, install_hint="Install ffuf. Fuzzing remains manual and authorized-scope only.", raw_command="ffuf -h", server_only=True, authorized_only=True, group="Web Content Discovery"),
    ToolSpec("dirsearch", "dirsearch", ["security", "technical"], "pip", repo="https://github.com/maurosoria/dirsearch", automated=False, install_hint="Install dirsearch. Content discovery remains manual and authorized-scope only.", raw_command="dirsearch --help", server_only=True, authorized_only=True, group="Web Content Discovery"),
    ToolSpec("sqlmap", "sqlmap", ["security", "technical"], "binary", repo="https://github.com/sqlmapproject/sqlmap", automated=False, install_hint="Install sqlmap for authorized application testing. WireSploit does not automate injection attempts.", raw_command="sqlmap -h", server_only=True, authorized_only=True, group="Web Assessment"),
    ToolSpec("dalfox", "Dalfox", ["security", "technical"], "go", repo="https://github.com/hahwul/dalfox", automated=False, install_hint="Install Dalfox for authorized XSS assessment. Manual use only.", raw_command="dalfox --help", server_only=True, authorized_only=True, group="Web Assessment"),
    ToolSpec("semgrep", "Semgrep", ["security", "files"], "pip", repo="https://github.com/semgrep/semgrep", automated=False, install_hint="Install Semgrep for local source-code security analysis.", raw_command="semgrep --help", server_only=True, group="Code Security"),
    ToolSpec("bandit", "Bandit", ["security", "files"], "pip", repo="https://github.com/PyCQA/bandit", automated=False, install_hint="pip install bandit", raw_command="bandit --help", server_only=True, group="Code Security"),
    ToolSpec("pipaudit", "pip-audit", ["security", "files"], "pip", repo="https://github.com/pypa/pip-audit", automated=False, install_hint="pip install pip-audit", raw_command="pip-audit --help", server_only=True, group="Dependency Security"),
    ToolSpec("osvscanner", "OSV-Scanner", ["security", "files"], "binary", repo="https://github.com/google/osv-scanner", automated=False, install_hint="Install OSV-Scanner for dependency vulnerability checks.", raw_command="osv-scanner --help", server_only=True, group="Dependency Security"),
    ToolSpec("trivy", "Trivy", ["security", "files"], "binary", repo="https://github.com/aquasecurity/trivy", automated=False, install_hint="Install Trivy for filesystem, dependency, config and container security assessment.", raw_command="trivy --help", server_only=True, group="Dependency / Container Security"),
    ToolSpec("grype", "Grype", ["security", "files"], "binary", repo="https://github.com/anchore/grype", automated=False, install_hint="Install Grype for local software/container vulnerability assessment.", raw_command="grype --help", server_only=True, group="Dependency / Container Security"),
    ToolSpec("syft", "Syft", ["security", "files"], "binary", repo="https://github.com/anchore/syft", automated=False, install_hint="Install Syft for software bill-of-materials generation.", raw_command="syft --help", server_only=True, group="Dependency / Container Security"),
    ToolSpec("gitleaks", "Gitleaks", ["security", "files"], "binary", repo="https://github.com/gitleaks/gitleaks", automated=False, install_hint="Install Gitleaks for secrets scanning in code you control.", raw_command="gitleaks --help", server_only=True, group="Secrets / Code Security"),
    ToolSpec("trufflehog", "TruffleHog", ["security", "files"], "binary", repo="https://github.com/trufflesecurity/trufflehog", automated=False, install_hint="Install TruffleHog for secrets scanning in repositories/data you are authorized to inspect.", raw_command="trufflehog --help", server_only=True, group="Secrets / Code Security"),
    ToolSpec("detectsecrets", "detect-secrets", ["security", "files"], "pip", repo="https://github.com/Yelp/detect-secrets", automated=False, install_hint="pip install detect-secrets", raw_command="detect-secrets --help", server_only=True, group="Secrets / Code Security"),
    ToolSpec("checkov", "Checkov", ["security", "files"], "pip", repo="https://github.com/bridgecrewio/checkov", automated=False, install_hint="pip install checkov", raw_command="checkov --help", server_only=True, group="IaC / Cloud Security"),
    ToolSpec("yara", "YARA", ["security", "files"], "binary", repo="https://github.com/VirusTotal/yara", automated=False, install_hint="Install YARA for local file classification/rule matching.", raw_command="yara --help", server_only=True, group="Malware / Forensics"),
    ToolSpec("capa", "FLARE capa", ["security", "files"], "binary", repo="https://github.com/mandiant/capa", automated=False, install_hint="Install capa for local executable capability analysis.", raw_command="capa --help", server_only=True, group="Malware / Forensics"),
    ToolSpec("volatility3", "Volatility 3", ["security", "files"], "pip", repo="https://github.com/volatilityfoundation/volatility3", automated=False, install_hint="pip install volatility3", raw_command="vol -h", server_only=True, group="Memory Forensics"),
    ToolSpec("wireshark", "Wireshark", ["security"], "binary", repo="https://gitlab.com/wireshark/wireshark", automated=False, install_hint="Install Wireshark for packet capture/analysis on networks you are authorized to inspect.", raw_command="wireshark", server_only=True, authorized_only=True, group="Network Analysis"),
    ToolSpec("zeek", "Zeek", ["security"], "binary", repo="https://github.com/zeek/zeek", automated=False, install_hint="Install Zeek (often easiest through WSL/Linux) for network-security monitoring and analysis.", raw_command="zeek --help", server_only=True, authorized_only=True, group="Network Analysis"),
    ToolSpec("mitmproxy", "mitmproxy", ["security"], "pip", repo="https://github.com/mitmproxy/mitmproxy", automated=False, install_hint="pip install mitmproxy; use only with traffic/devices you are authorized to intercept.", raw_command="mitmproxy --help", server_only=True, authorized_only=True, group="Network / Web Analysis"),

    # Local file/image analysis providers.
    ToolSpec("exiftool", "ExifTool", ["files", "images"], "binary", deep_only=False, install_hint="Install ExifTool on the backend for extended metadata.", raw_command="exiftool -ver", server_only=True),
    ToolSpec("tesseract", "Tesseract OCR", ["files", "images"], "binary", deep_only=True, install_hint="Install Tesseract on the backend for OCR.", raw_command="tesseract --version", server_only=True),
    ToolSpec("mediainfo", "MediaInfo", ["files", "images"], "binary", deep_only=True, install_hint="Install MediaInfo on the backend for audio/video/container metadata.", raw_command="mediainfo --Version", server_only=True),
    ToolSpec("oletools", "oletools", ["files"], "pip", deep_only=True, install_hint="pip install oletools", raw_command="olemeta -h", server_only=True),
    ToolSpec("hachoir", "Hachoir Metadata", ["files", "images"], "pip", deep_only=True, automated=False, repo="https://github.com/vstinner/hachoir", install_hint="pip install hachoir", raw_command="hachoir-metadata --help", server_only=True),
    ToolSpec("ffprobe", "FFprobe", ["files", "images"], "binary", deep_only=True, automated=False, install_hint="Install FFmpeg/ffprobe on the Engine.", raw_command="ffprobe -version", server_only=True),
    ToolSpec("imagemagick", "ImageMagick identify", ["files", "images"], "binary", deep_only=True, automated=False, install_hint="Install ImageMagick on the Engine.", raw_command="identify -version", server_only=True),
    ToolSpec("pdftotext", "Poppler pdftotext", ["files"], "binary", deep_only=True, automated=False, install_hint="Install Poppler utilities on the Engine.", raw_command="pdftotext -v", server_only=True),
]

SPEC_BY_ID = {s.id: s for s in SPECS}


def _which(name: str):
    scripts = Path(sys.executable).parent
    candidates = [scripts / name, scripts / (name + ".exe"), scripts / (name + ".cmd")]
    for p in candidates:
        if p.exists():
            return str(p)
    return shutil.which(name)


def _tool_dir(tid: str):
    return TOOLS / tid


def _venv_python(tid: str):
    p = _tool_dir(tid) / ".venv" / "Scripts" / "python.exe"
    if p.exists():
        return str(p)
    p2 = _tool_dir(tid) / ".venv" / "bin" / "python"
    return str(p2) if p2.exists() else None


def diagnose(tid: str):
    spec = SPEC_BY_ID.get(tid)
    if not spec:
        return {"id": tid, "status": "unknown", "checks": []}
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": ok if ok is None else bool(ok), "detail": detail})

    add("WireSploit registry", True, spec.name)
    if spec.kind in ("native", "web"):
        add("Provider implementation", True, "Built into the WireSploit engine." if spec.kind == "native" else "Uses a public web endpoint at search time.")
        return {"id": tid, "name": spec.name, "status": "ready", "checks": checks, "repairable": False}

    cli_names = {
        "sherlock": "sherlock", "maigret": "maigret", "ghunt": "ghunt",
        "socialanalyzer": "social-analyzer", "theharvester": "theHarvester",
        "subfinder": "subfinder", "assetfinder": "assetfinder", "waymore": "waymore",
        "gau": "gau", "ytdlp": "yt-dlp", "gallerydl": "gallery-dl",
        "amass": "amass", "exiftool": "exiftool", "tesseract": "tesseract",
        "mediainfo": "mediainfo", "oletools": "olemeta", "phoneinfoga": "phoneinfoga",
        "waybackurls": "waybackurls", "findomain": "findomain", "instaloader": "instaloader",
            "hachoir": "hachoir",
        "gowitness": "gowitness", "httpx": "httpx", "dnsrecon": "dnsrecon", "dnsenum": "dnsenum",
        "reconng": "recon-ng", "sn0int": "sn0int", "metagoofil": "metagoofil",
        "hachoir": "hachoir-metadata", "ffprobe": "ffprobe", "imagemagick": "identify", "pdftotext": "pdftotext",
        "metasploit": "msfconsole", "nmap": "nmap", "rustscan": "rustscan", "naabu": "naabu",
        "nuclei": "nuclei", "nikto": "nikto", "zap": "zap.bat", "testssl": "testssl.sh",
        "sslscan": "sslscan", "sslyze": "sslyze", "wafw00f": "wafw00f", "whatweb": "whatweb",
        "feroxbuster": "feroxbuster", "gobuster": "gobuster", "ffuf": "ffuf", "dirsearch": "dirsearch",
        "sqlmap": "sqlmap", "dalfox": "dalfox", "semgrep": "semgrep", "bandit": "bandit",
        "pipaudit": "pip-audit", "osvscanner": "osv-scanner", "trivy": "trivy", "grype": "grype",
        "syft": "syft", "gitleaks": "gitleaks", "trufflehog": "trufflehog", "detectsecrets": "detect-secrets",
        "checkov": "checkov", "yara": "yara", "capa": "capa", "volatility3": "vol",
        "wireshark": "wireshark", "zeek": "zeek", "mitmproxy": "mitmproxy",
    }
    if tid in cli_names:
        exe = _which(cli_names[tid])
        # Legacy Windows builds may keep Go binaries inside tools/<id>.
        if not exe:
            local_names = {
                "phoneinfoga": "phoneinfoga.exe", "amass": "amass.exe",
                "subfinder": "subfinder.exe", "assetfinder": "assetfinder.exe", "gau": "gau.exe",
                "waybackurls": "waybackurls.exe", "findomain": "findomain.exe",
            }
            ln = local_names.get(tid)
            if ln and (_tool_dir(tid) / ln).exists():
                exe = str(_tool_dir(tid) / ln)
        add("CLI detected", bool(exe), exe or f"{cli_names[tid]} not found")
        if tid == "ghunt":
            add("Authentication", None, "GHunt requires its own login/authentication before email queries can run.")
    elif tid == "gosherlock":
        d = _tool_dir(tid)
        exe = d / ("go-sherlock.exe" if os.name == "nt" else "go-sherlock")
        add("Repository present", d.exists(), str(d))
        add("Binary built", exe.exists(), str(exe))
        add("Go available", _which("go") is not None, _which("go") or "go not found")
    elif tid in ("ghosttrack", "blackbird", "phunter"):
        d = _tool_dir(tid)
        entries = {"ghosttrack": "GhostTR.py", "blackbird": "blackbird.py", "phunter": "phunter.py"}
        add("Repository present", d.exists(), str(d))
        add("Tool virtualenv", _venv_python(tid) is not None, _venv_python(tid) or "missing")
        add("Entry script", (d / entries[tid]).exists(), str(d / entries[tid]))
    elif tid == "spiderfoot":
        d = _tool_dir(tid)
        add("Repository present", d.exists(), str(d))
        add("Manual configuration", None, "Advanced framework; passive modules must be configured explicitly before use.")
    else:
        add("Installation", False, spec.install_hint)

    # The registry check is informational; readiness is based on the actual executable/repo checks.
    readiness = [x["ok"] for x in checks if x["ok"] is not None and x["name"] != "WireSploit registry"]
    status = "ready" if readiness and all(readiness) else ("partial" if any(readiness) else "missing")
    repairable = tid in {
        "sherlock", "maigret", "socialanalyzer", "waymore", "ytdlp", "gallerydl", "oletools", "instaloader", "hachoir",
        "ghosttrack", "blackbird", "phunter", "gosherlock",
        "phoneinfoga", "subfinder", "assetfinder", "gau", "waybackurls", "findomain", "amass",
        "sslyze", "wafw00f", "semgrep", "bandit", "pipaudit", "detectsecrets", "checkov", "volatility3", "mitmproxy",
    }
    return {"id": tid, "name": spec.name, "status": status, "checks": checks, "repairable": repairable}


def list_tools():
    return [{**asdict(s), "diagnostic": diagnose(s.id)} for s in SPECS]


def _run(cmd: list[str], cwd: Path | None = None, timeout=300, env: dict | None = None):
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, timeout=timeout, env=env)
    return {"code": p.returncode, "stdout": p.stdout[-12000:], "stderr": p.stderr[-12000:]}


def _install_go_tool(tid: str, module: str, binary_name: str):
    """Install a fixed, known passive provider into tools/<id> without relying on PATH."""
    go = _which("go")
    if not go:
        return {"ok": False, "message": "Go is required for this provider. Re-run SETUP_WINDOWS.ps1 so WireSploit can install/detect Go.", "diagnostic": diagnose(tid)}
    d = _tool_dir(tid)
    d.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GOBIN"] = str(d)
    r = _run([go, "install", module], timeout=1200, env=env)
    # Go produces .exe automatically on Windows.
    expected = d / (binary_name + ".exe" if os.name == "nt" else binary_name)
    ok = r["code"] == 0 and expected.exists()
    return {"ok": ok, "message": f"go install {module}", "result": r, "diagnostic": diagnose(tid)}


def _download_release_asset(tid: str, api_repo: str, asset_pattern: str, binary_name: str):
    """Download a fixed upstream GitHub release asset into tools/<id>.

    The repository and regex are hard-coded by WireSploit; browser input can never select a URL.
    """
    import io, tarfile, urllib.request, zipfile
    d = _tool_dir(tid)
    d.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(
        f"https://api.github.com/repos/{api_repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "WireSploit/0.3.3"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        release = json.load(resp)
    rx = re.compile(asset_pattern, re.I)
    asset = next((a for a in release.get("assets", []) if rx.search(a.get("name", ""))), None)
    if not asset:
        return {"ok": False, "message": f"No matching Windows release asset was published by {api_repo}.", "diagnostic": diagnose(tid)}
    areq = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "WireSploit/0.3.3"})
    with urllib.request.urlopen(areq, timeout=120) as resp:
        payload = resp.read()
    name = asset.get("name", "").lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            z.extractall(d)
    elif name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as t:
            # Avoid archive path traversal; only regular files under their basenames are extracted.
            for m in t.getmembers():
                if not m.isfile():
                    continue
                src = t.extractfile(m)
                if src:
                    (d / Path(m.name).name).write_bytes(src.read())
    else:
        (d / Path(asset["name"]).name).write_bytes(payload)
    expected = d / (binary_name + ".exe" if os.name == "nt" else binary_name)
    if not expected.exists():
        # Some upstream archives use a different case/name; locate the binary by basename.
        candidates = list(d.rglob(binary_name + ".exe")) if os.name == "nt" else list(d.rglob(binary_name))
        if candidates:
            expected.write_bytes(candidates[0].read_bytes())
    return {"ok": expected.exists(), "message": f"Installed latest release from {api_repo}", "diagnostic": diagnose(tid)}


def repair(tid: str):
    """Install only known upstream providers using fixed commands; never execute UI-supplied shell text."""
    TOOLS.mkdir(exist_ok=True)
    spec = SPEC_BY_ID.get(tid)
    if not spec:
        return {"ok": False, "message": "Unknown tool"}
    try:
        pip_packages = {
            "sherlock": "sherlock-project",
            "maigret": "maigret",
            "socialanalyzer": "social-analyzer",
            "waymore": "waymore",
            "ytdlp": "yt-dlp",
            "gallerydl": "gallery-dl",
            "oletools": "oletools",
            "instaloader": "instaloader",
            "hachoir": "hachoir",
            "sslyze": "sslyze",
            "wafw00f": "wafw00f",
            "semgrep": "semgrep",
            "bandit": "bandit",
            "pipaudit": "pip-audit",
            "detectsecrets": "detect-secrets",
            "checkov": "checkov",
            "volatility3": "volatility3",
            "mitmproxy": "mitmproxy",
        }
        if tid in pip_packages:
            pkg = pip_packages[tid]
            r = _run([sys.executable, "-m", "pip", "install", "--upgrade", pkg], timeout=900)
            return {"ok": r["code"] == 0, "message": f"pip install {pkg}", "result": r, "diagnostic": diagnose(tid)}

        if tid in ("ghosttrack", "blackbird", "phunter"):
            d = _tool_dir(tid)
            if not d.exists():
                r = _run(["git", "clone", spec.repo + ".git", str(d)], timeout=600)
                if r["code"] != 0:
                    return {"ok": False, "message": "git clone failed", "result": r}
            elif (d / ".git").exists():
                _run(["git", "pull", "--ff-only"], cwd=d, timeout=300)
            vp = _venv_python(tid)
            if not vp:
                _run([sys.executable, "-m", "venv", str(d / ".venv")], timeout=300)
                vp = _venv_python(tid)
            req = d / "requirements.txt"
            r = _run([vp, "-m", "pip", "install", "-r", str(req)], cwd=d, timeout=900) if req.exists() else {"code": 0, "stdout": "No requirements.txt", "stderr": ""}
            return {"ok": r["code"] == 0, "message": "Repository and dependencies refreshed", "result": r, "diagnostic": diagnose(tid)}

        if tid == "gosherlock":
            if not _which("go"):
                return {"ok": False, "message": "Go is required before Go Sherlock can be built.", "diagnostic": diagnose(tid)}
            d = _tool_dir(tid)
            if not d.exists():
                r = _run(["git", "clone", spec.repo + ".git", str(d)], timeout=600)
                if r["code"] != 0:
                    return {"ok": False, "message": "git clone failed", "result": r}
            out = d / ("go-sherlock.exe" if os.name == "nt" else "go-sherlock")
            r = _run(["go", "build", "-o", str(out), "."], cwd=d, timeout=900)
            return {"ok": r["code"] == 0, "message": "Go Sherlock built", "result": r, "diagnostic": diagnose(tid)}

        go_tools = {
            "subfinder": ("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder"),
            "assetfinder": ("github.com/tomnomnom/assetfinder@latest", "assetfinder"),
            "gau": ("github.com/lc/gau/v2/cmd/gau@latest", "gau"),
            "waybackurls": ("github.com/tomnomnom/waybackurls@latest", "waybackurls"),
            # Amass remains constrained to passive enumeration by tool_command().
            "amass": ("github.com/owasp-amass/amass/v4/...@master", "amass"),
        }
        if tid in go_tools:
            module, binary = go_tools[tid]
            return _install_go_tool(tid, module, binary)

        if tid == "findomain":
            if os.name != "nt":
                return {"ok": False, "message": "Automatic Findomain release repair is currently configured for Windows only.", "diagnostic": diagnose(tid)}
            return _download_release_asset(tid, "Findomain/Findomain", r"findomain-windows\.exe\.zip$", "findomain")

        if tid == "phoneinfoga":
            if os.name != "nt":
                return {"ok": False, "message": "Automatic PhoneInfoga release repair is currently configured for Windows only.", "diagnostic": diagnose(tid)}
            return _download_release_asset(tid, "sundowndev/phoneinfoga", r"phoneinfoga_Windows_x86_64\.tar\.gz$", "phoneinfoga")

        return {"ok": False, "message": "Automatic repair is not configured for this provider. See its install hint.", "diagnostic": diagnose(tid)}
    except Exception as e:
        return {"ok": False, "message": str(e), "diagnostic": diagnose(tid)}


def check_update(tid: str):
    spec = SPEC_BY_ID.get(tid)
    if not spec:
        return {"ok": False, "message": "Unknown tool"}
    if spec.kind in ("native", "web"):
        return {"ok": True, "update_available": False, "message": "This provider is updated with WireSploit itself."}
    try:
        d = _tool_dir(tid)
        if d.exists() and (d / ".git").exists():
            fetch = _run(["git", "fetch", "--quiet", "origin"], cwd=d, timeout=120)
            if fetch["code"] != 0:
                return {"ok": False, "message": "Could not contact upstream.", "result": fetch}
            head = _run(["git", "rev-parse", "HEAD"], cwd=d, timeout=30)
            upstream = _run(["git", "rev-parse", "@{u}"], cwd=d, timeout=30)
            if head["code"] == 0 and upstream["code"] == 0:
                local, remote = head["stdout"].strip(), upstream["stdout"].strip()
                return {"ok": True, "update_available": local != remote, "local": local[:12], "upstream": remote[:12]}
        pip_packages = {
            "sherlock": "sherlock-project", "maigret": "maigret", "socialanalyzer": "social-analyzer",
            "waymore": "waymore", "ytdlp": "yt-dlp", "gallerydl": "gallery-dl", "oletools": "oletools", "instaloader": "instaloader", "hachoir": "hachoir",
            "sslyze": "sslyze", "wafw00f": "wafw00f", "semgrep": "semgrep", "bandit": "bandit",
            "pipaudit": "pip-audit", "detectsecrets": "detect-secrets", "checkov": "checkov",
            "volatility3": "volatility3", "mitmproxy": "mitmproxy",
        }
        if tid in pip_packages:
            pkg = pip_packages[tid]
            r = _run([sys.executable, "-m", "pip", "index", "versions", pkg], timeout=120)
            installed = _run([sys.executable, "-m", "pip", "show", pkg], timeout=30)
            m_inst = re.search(r"^Version:\s*(.+)$", installed["stdout"], re.M)
            m_latest = re.search(r"^Available versions:\s*([^,\s]+)", r["stdout"], re.M)
            iv = m_inst.group(1).strip() if m_inst else None
            lv = m_latest.group(1).strip() if m_latest else None
            return {"ok": r["code"] == 0, "installed": iv, "latest": lv, "update_available": bool(iv and lv and iv != lv)}
        return {"ok": False, "message": "Automatic update check is not configured for this provider."}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def analyze_file_with_external(path: Path):
    """Run installed read-only metadata utilities against a user-supplied file.

    Commands are fixed by WireSploit and receive only the generated upload path.
    Missing utilities are skipped so file analysis always remains usable.
    """
    evidence = {}
    sources = []
    suffix = path.suffix.lower()
    jobs = []
    exif = _which("exiftool")
    if exif: jobs.append(("exiftool", [exif, "-j", str(path)], "json"))
    media = _which("mediainfo")
    if media: jobs.append(("mediainfo", [media, "--Output=JSON", str(path)], "json"))
    ffprobe = _which("ffprobe")
    if ffprobe: jobs.append(("ffprobe", [ffprobe, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(path)], "json"))
    hachoir = _which("hachoir-metadata")
    if hachoir: jobs.append(("hachoir", [hachoir, "--level=1", str(path)], "text"))
    if suffix in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"}:
        olemeta = _which("olemeta")
        if olemeta: jobs.append(("oletools", [olemeta, str(path)], "text"))
    if suffix == ".pdf":
        pdftotext = _which("pdftotext")
        if pdftotext: jobs.append(("pdftotext", [pdftotext, "-f", "1", "-l", "3", str(path), "-"], "text"))
    identify = _which("identify")
    if identify and suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".tif", ".tiff", ".bmp"}:
        jobs.append(("imagemagick", [identify, "-verbose", str(path)], "text"))
    for tid, cmd, kind in jobs:
        try:
            r = _run(cmd, timeout=30)
            if r["code"] != 0: continue
            out = r["stdout"].strip()
            if not out: continue
            if kind == "json":
                try: value = json.loads(out)
                except Exception: value = out[:20000]
            else:
                value = out[:20000]
            evidence[tid] = value
            sources.append(tid)
        except Exception:
            continue
    return evidence, sources


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s):
    return ANSI.sub("", s or "")


async def run_subprocess(cmd: list[str], cwd: Path | None = None, timeout=90, stdin_text=None):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        stdin=asyncio.subprocess.PIPE if stdin_text else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin_text.encode() if stdin_text else None), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"timed out after {timeout}s")
    return proc.returncode, strip_ansi(out.decode(errors="replace")), strip_ansi(err.decode(errors="replace"))


def _external_exe(tid: str, name: str):
    exe = _which(name)
    if exe:
        return exe
    local = _tool_dir(tid) / (name + ".exe" if os.name == "nt" else name)
    return str(local) if local.exists() else None


def tool_command(tid, query, category):
    """Return a safe, fixed command/cwd for an installed provider, or None."""
    if tid == "sherlock" and _which("sherlock"):
        return ([_which("sherlock"), query, "--print-found", "--no-color"], ROOT)
    if tid == "maigret" and _which("maigret"):
        return ([_which("maigret"), query, "--json", "simple"], ROOT)
    if tid == "gosherlock":
        exe = _tool_dir(tid) / ("go-sherlock.exe" if os.name == "nt" else "go-sherlock")
        if exe.exists():
            return ([str(exe), query], _tool_dir(tid))
    if tid == "blackbird":
        vp, d = _venv_python(tid), _tool_dir(tid)
        if vp and (d / "blackbird.py").exists():
            return ([vp, "blackbird.py", "--email" if category == "email" else "--username", query], d)
    if tid == "phunter":
        vp, d = _venv_python(tid), _tool_dir(tid)
        if vp and (d / "phunter.py").exists():
            return ([vp, "phunter.py", "-t", query], d)
    if tid == "phoneinfoga":
        exe = _external_exe(tid, "phoneinfoga")
        if exe:
            return ([exe, "scan", "-n", query], _tool_dir(tid) if _tool_dir(tid).exists() else ROOT)
    if tid == "ghunt" and _which("ghunt"):
        output = ROOT / "data" / "ghunt_last.json"
        return ([_which("ghunt"), "email", query, "--json", str(output)], ROOT)
    if tid == "socialanalyzer" and _which("social-analyzer"):
        return ([_which("social-analyzer"), "--username", query, "--output", "json", "--filter", "good", "--profiles", "detected", "--metadata"], ROOT)
    if tid == "subfinder":
        exe = _external_exe(tid, "subfinder")
        if exe:
            return ([exe, "-silent", "-d", query], ROOT)
    if tid == "assetfinder":
        exe = _external_exe(tid, "assetfinder")
        if exe:
            return ([exe, "--subs-only", query], ROOT)
    if tid == "waymore" and _which("waymore"):
        # URL-only mode, stdout output, public archive sources. No archived content downloads.
        return ([_which("waymore"), "-i", query, "-mode", "U", "-oU", "-"], ROOT)
    if tid == "gau":
        exe = _external_exe(tid, "gau")
        if exe:
            return ([exe, "--subs", query], ROOT)
    if tid == "waybackurls":
        exe = _external_exe(tid, "waybackurls")
        if exe:
            return ([exe], ROOT, query.strip() + "\n")
    if tid == "findomain":
        exe = _external_exe(tid, "findomain")
        if exe:
            return ([exe, "-t", query], ROOT)
    if tid == "ytdlp" and _which("yt-dlp") and re.match(r"^https?://", query.strip()):
        return ([_which("yt-dlp"), "--skip-download", "--dump-single-json", "--no-playlist", query], ROOT)
    if tid == "gallerydl" and _which("gallery-dl") and re.match(r"^https?://", query.strip()):
        return ([_which("gallery-dl"), "--dump-json", query], ROOT)
    if tid == "theharvester" and _which("theHarvester") and category in ("domain", "technical"):
        return ([_which("theHarvester"), "-d", query, "-b", "crtsh,duckduckgo,rapiddns"], ROOT)
    if tid == "amass":
        exe = _external_exe(tid, "amass")
        if exe:
            return ([exe, "enum", "-passive", "-d", query], ROOT)
    return None


def parse_username_output(tid, query, stdout, category="username"):
    findings = []
    seen = set()
    # Social Analyzer may emit one JSON object; extract profile URLs conservatively.
    for line in stdout.splitlines():
        urls = re.findall(r"https?://[^\s\]\)>,\"']+", line)
        for url in urls:
            url = url.rstrip(".,;:")
            if query.lower() not in url.lower() and tid not in ("maigret", "socialanalyzer"):
                continue
            if url in seen:
                continue
            seen.add(url)
            host = re.sub(r"^www\.", "", re.sub(r"^https?://", "", url)).split("/")[0]
            prefix = "username" if category in ("username", "social") else category
            findings.append({
                "entity_key": f"{prefix}:{host}:{query.lower()}",
                "platform": host,
                "value": query,
                "url": url,
                "source_tools": [tid],
                "evidence": {"exact_match": True, "raw_line": line[:1000]},
            })
    return findings


def parse_domain_lines(tid, query, stdout, category):
    findings = []
    seen = set()
    for raw in stdout.splitlines():
        value = raw.strip().strip("[] ,\t")
        if not value:
            continue
        urls = re.findall(r"https?://[^\s\]\)>,\"']+", value)
        candidates = urls or re.findall(r"(?:[A-Za-z0-9-]+\.)+" + re.escape(query.strip().lower()) + r"(?:/[^\s]*)?", value, flags=re.I)
        for c in candidates:
            c = c.rstrip(".,;:")
            key = c.lower()
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "entity_key": f"{category}:{tid}:{key}",
                "platform": SPEC_BY_ID.get(tid).name if SPEC_BY_ID.get(tid) else tid,
                "value": c,
                "url": c if c.startswith("http") else None,
                "source_tools": [tid],
                "evidence": {"exact_match": True, "source_domain": query, "raw_line": raw[:1000]},
            })
    return findings


def parse_json_metadata(tid, query, stdout, category):
    try:
        d = json.loads(stdout)
    except Exception:
        return parse_kv_output(tid, query, stdout, category)
    return [{
        "entity_key": f"{category}:{tid}:{query}",
        "platform": SPEC_BY_ID.get(tid).name if SPEC_BY_ID.get(tid) else tid,
        "value": query,
        "url": query if query.startswith("http") else None,
        "source_tools": [tid],
        "evidence": {"exact_match": True, "metadata": d},
    }]


def parse_kv_output(tid, query, stdout, category):
    fields = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(" []+-\t").strip(), v.strip()
            if k and v and len(k) < 80:
                fields[k] = v
    if not fields and stdout.strip():
        fields["output"] = stdout[-4000:]
    if not fields:
        return []
    return [{
        "entity_key": f"{category}:{tid}:{query}",
        "platform": SPEC_BY_ID.get(tid).name if SPEC_BY_ID.get(tid) else tid,
        "value": query,
        "url": None,
        "source_tools": [tid],
        "evidence": {"exact_match": True, "fields": fields, "raw": stdout[-4000:]},
    }]
