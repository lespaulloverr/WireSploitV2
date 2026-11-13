from __future__ import annotations

import os
import json
import asyncio
import zipfile
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union

ROOT = Path(__file__).resolve().parents[1]

# Import new modules
from .kali_categories import (
    KaliCategory,
    ToolClassification,
    KaliToolSpec,
    get_classification,
    get_wiresploit_categories,
    get_risk_level,
    KaliCategory,
    EXECUTABLE_CATEGORIES,
    RESTRICTED_CATEGORIES,
    EDUCATIONAL_CATEGORIES,
)
from . import credentials


class Spec:
    """Tool specification with Kali integration support."""

    def __init__(
        self,
        id: str,
        name: str,
        kind: str,
        categories: List[str],
        automated: bool = True,
        authorized_only: bool = False,
        deep_only: bool = False,
        url: str = "",
        # New Kali integration fields
        kali_category: Optional[KaliCategory] = None,
        classification: ToolClassification = ToolClassification.EXECUTABLE,
        install_hint: str = "",
        credential_ref: Optional[str] = None,
        scope_override: Optional[str] = None,
        parser: Optional[str] = None,
        timeout: int = 300,
        args_template: Optional[List[str]] = None,
        separator: Optional[str] = "--",
        version_flag: str = "--version",
        description: str = "",
        requires_wsl: bool = False,
        requires_hardware: bool = False,
        risk_level: str = "low",
    ):
        self.id = id
        self.name = name
        self.kind = kind
        self.categories = categories
        self.automated = automated
        self.authorized_only = authorized_only
        self.deep_only = deep_only
        self.url = url

        # Kali integration fields
        self.kali_category = kali_category
        self.classification = classification
        self.install_hint = install_hint
        self.credential_ref = credential_ref
        self.scope_override = scope_override
        self.parser = parser
        self.timeout = timeout
        self.args_template = args_template or []
        self.separator = separator
        self.version_flag = version_flag
        self.description = description
        self.requires_wsl = requires_wsl
        self.requires_hardware = requires_hardware
        self.risk_level = risk_level

        # Auto-populate from kali_category if provided
        if kali_category and not classification:
            self.classification = get_classification(kali_category)
        if kali_category and not categories:
            self.categories = get_wiresploit_categories(kali_category)
        if kali_category and not risk_level:
            self.risk_level = get_risk_level(kali_category)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "categories": self.categories,
            "automated": self.automated,
            "authorized_only": self.authorized_only,
            "deep_only": self.deep_only,
            "url": self.url,
            "kali_category": self.kali_category.value if self.kali_category else None,
            "classification": self.classification.value if self.classification else None,
            "install_hint": self.install_hint,
            "credential_ref": self.credential_ref,
            "scope_override": self.scope_override,
            "parser": self.parser,
            "timeout": self.timeout,
            "args_template": self.args_template,
            "separator": self.separator,
            "version_flag": self.version_flag,
            "description": self.description,
            "requires_wsl": self.requires_wsl,
            "requires_hardware": self.requires_hardware,
            "risk_level": self.risk_level,
        }

    @classmethod
    def from_kali_spec(cls, kali_spec: KaliToolSpec) -> "Spec":
        """Create a Spec from a KaliToolSpec."""
        return cls(
            id=kali_spec.id,
            name=kali_spec.name,
            kind=kali_spec.kind,
            categories=kali_spec.categories,
            automated=kali_spec.automated,
            authorized_only=kali_spec.authorized_only,
            deep_only=kali_spec.deep_only,
            url=kali_spec.url,
            kali_category=kali_spec.kali_category,
            classification=kali_spec.classification,
            install_hint=kali_spec.install_hint,
            credential_ref=kali_spec.credential_ref,
            scope_override=kali_spec.scope_override,
            parser=kali_spec.parser,
            timeout=kali_spec.timeout,
            args_template=kali_spec.args_template,
            separator=kali_spec.separator,
            version_flag=kali_spec.version_flag,
            description=kali_spec.description,
            requires_wsl=kali_spec.requires_wsl,
            requires_hardware=kali_spec.requires_hardware,
            risk_level=kali_spec.risk_level,
        )

# Define all specs
_SPECS = [
    # Native spec (special-cased in engine.py)
    Spec(
        id="native",
        name="Native",
        kind="native",
        categories=[],  # categories not used for native
        automated=False,
        url="https://example.com/native",
    ),
    # Web specs
    Spec(
        id="urlscan_public",
        name="URLScan",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://urlscan.io/",
    ),
    Spec(
        id="internetdb_public",
        name="Shodan InternetDB",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://internetdb.shodan.io/",
    ),
    Spec(
        id="ipwhois_public",
        name="IPWhois",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://ipwho.is/",
    ),
    Spec(
        id="ripestat_public",
        name="RIPEstat",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://stat.ripe.net/",
    ),
    Spec(
        id="abuseipdb_public",
        name="AbuseIPDB",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://www.abuseipdb.com/",
    ),
    Spec(
        id="greynoise_public",
        name="GreyNoise",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://viz.greynoise.io/",
    ),
    Spec(
        id="certspotter_public",
        name="Cert Spotter",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://sslmate.com/certspotter/",
    ),
    Spec(
        id="cisa_kev_public",
        name="CISA KEV",
        kind="web",
        categories=["search"],
        automated=True,
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ),
    Spec(
        id="nvd_cve_public",
        name="NIST NVD CVE",
        kind="web",
        categories=["search"],
        automated=True,
        url="https://nvd.nist.gov/vuln/search",
    ),
    Spec(
        id="virustotal_public",
        name="VirusTotal",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://www.virustotal.com/gui/home/search",
    ),
    # Additional web providers for username/social
    Spec(
        id="github_public",
        name="GitHub",
        kind="web",
        categories=["username", "social"],
        automated=True,
        url="https://github.com/",
    ),
    Spec(
        id="gitlab_public",
        name="GitLab",
        kind="web",
        categories=["username", "social"],
        automated=True,
        url="https://gitlab.com/",
    ),
    Spec(
        id="reddit_public",
        name="Reddit",
        kind="web",
        categories=["username", "social"],
        automated=True,
        url="https://www.reddit.com/",
    ),
    Spec(
        id="hackernews_public",
        name="Hacker News",
        kind="web",
        categories=["username", "social"],
        automated=True,
        url="https://news.ycombinator.com/",
    ),
    Spec(
        id="bluesky_public",
        name="Bluesky",
        kind="web",
        categories=["username", "social"],
        automated=True,
        url="https://bsky.app/",
    ),
    Spec(
        id="whatsmyname_public",
        name="WhatsMyName",
        kind="web",
        categories=["username", "social"],
        automated=True,
        url="https://whatsmyname.app/",
    ),
    # Additional web providers for email
    Spec(
        id="gravatar_public",
        name="Gravatar",
        kind="web",
        categories=["email"],
        automated=True,
        url="https://gravatar.com/",
    ),
    # Additional web providers for domain
    Spec(
        id="rdap_domain",
        name="RDAP Domain",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://rdap.org/",
    ),
    Spec(
        id="crtsh_public",
        name="crt.sh",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://crt.sh/",
    ),
    Spec(
        id="wayback_public",
        name="Wayback Machine",
        kind="web",
        categories=["domain", "archives"],
        automated=True,
        url="https://web.archive.org/",
    ),
    Spec(
        id="commoncrawl_public",
        name="Common Crawl",
        kind="web",
        categories=["domain", "archives"],
        automated=True,
        url="https://commoncrawl.org/",
    ),
    Spec(
        id="google_doh",
        name="Google DNS-over-HTTPS",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://dns.google/",
    ),
    Spec(
        id="cloudflare_doh",
        name="Cloudflare DNS-over-HTTPS",
        kind="web",
        categories=["domain"],
        automated=True,
        url="https://1.1.1.1/",
    ),
    # Additional web providers for IP
    Spec(
        id="rdap_ip",
        name="RDAP IP",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://rdap.org/",
    ),
    Spec(
        id="ipquery_public",
        name="IPQuery",
        kind="web",
        categories=["ip"],
        automated=True,
        url="https://ipquery.io/",
    ),
    # Additional web providers for geolocation
    Spec(
        id="openmeteo_public",
        name="Open-Meteo",
        kind="web",
        categories=["geolocation"],
        automated=True,
        url="https://open-meteo.com/",
    ),
    Spec(
        id="overpass_public",
        name="Overpass API",
        kind="web",
        categories=["geolocation"],
        automated=True,
        url="https://overpass-api.de/",
    ),
    Spec(
        id="wikipedia_geo_public",
        name="Wikipedia Geosearch",
        kind="web",
        categories=["geolocation"],
        automated=True,
        url="https://en.wikipedia.org/w/api.php",
    ),
    # Additional web providers for search
    Spec(
        id="wikidata_public",
        name="Wikidata",
        kind="web",
        categories=["search"],
        automated=True,
        url="https://www.wikidata.org/",
    ),
    Spec(
        id="openalex_public",
        name="OpenAlex",
        kind="web",
        categories=["search"],
        automated=True,
        url="https://openalex.org/",
    ),
    # CLI specs for username-oriented tools
    Spec(
        id="sherlock",
        name="Sherlock",
        kind="cli",
        categories=["username", "social", "email"],
        automated=True,
        url="https://github.com/sherlock-project/sherlock",
    ),
    Spec(
        id="maigret",
        name="Maigret",
        kind="cli",
        categories=["username", "social", "email"],
        automated=True,
        url="https://github.com/soxoj/maigret",
    ),
    Spec(
        id="blackbird",
        name="Blackbird",
        kind="cli",
        categories=["username", "social", "email"],
        automated=True,
        url="https://github.com/powerblackbird/blackbird",
    ),
    Spec(
        id="gosherlock",
        name="Gosherlock",
        kind="cli",
        categories=["username", "social", "email"],
        automated=True,
        url="https://github.com/Josue87/gosherlock",
    ),
    Spec(
        id="socialanalyzer",
        name="Social Analyzer",
        kind="cli",
        categories=["username", "social", "email"],
        automated=True,
        url="https://github.com/qeeqbox/social-analyzer",
    ),
    # CLI specs for domain-oriented tools
    Spec(
        id="subfinder",
        name="Subfinder",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/projectdiscovery/subfinder",
    ),
    Spec(
        id="assetfinder",
        name="Assetfinder",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/tomnomnom/assetfinder",
    ),
    Spec(
        id="amass",
        name="Amass",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/owasp-amass/amass",
    ),
    Spec(
        id="theharvester",
        name="theHarvester",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/laramies/theHarvester",
    ),
    Spec(
        id="waymore",
        name="Waymore",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/xnl-h4ck3r/waymore",
    ),
    Spec(
        id="gau",
        name="GAU",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/lc/gau",
    ),
    Spec(
        id="waybackurls",
        name="Waybackurls",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/hakluke/waybackurls",
    ),
    Spec(
        id="findomain",
        name="Findomain",
        kind="cli",
        categories=["domain"],
        automated=True,
        url="https://github.com/Findomain/Findomain",
    ),
    # ============================================================
    # PHASE 2A — EXECUTABLE TOOLS (Safe for automated pipeline)
    # ============================================================
    # --- Reverse Engineering (Static Analysis) ---
    Spec(
        id="radare2",
        name="radare2",
        kind="cli",
        categories=["search", "reverse_engineering"],
        automated=True,
        url="https://github.com/radareorg/radare2",
        kali_category=KaliCategory.REVERSE_ENGINEERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install radare2",
        parser="radare2_json",
        args_template=["-A", "-j", "{target}"],
        separator="--",
        version_flag="-v",
        description="Static analysis and binary reverse engineering framework",
        risk_level="medium",
    ),
    Spec(
        id="binwalk",
        name="Binwalk",
        kind="cli",
        categories=["search", "reverse_engineering", "forensics"],
        automated=True,
        url="https://github.com/ReFirmLabs/binwalk",
        kali_category=KaliCategory.REVERSE_ENGINEERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install binwalk",
        parser="binwalk_json",
        args_template=["-e", "-M", "{target}"],
        separator="--",
        version_flag="-v",
        description="Firmware analysis and embedded file extraction",
        risk_level="medium",
    ),
    Spec(
        id="strings",
        name="Strings",
        kind="cli",
        categories=["search", "reverse_engineering", "forensics"],
        automated=True,
        url="https://docs.microsoft.com/en-us/sysinternals/downloads/strings",
        kali_category=KaliCategory.REVERSE_ENGINEERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install binutils",
        parser="strings_output",
        args_template=["-a", "-n", "4", "{target}"],
        separator="--",
        version_flag="--version",
        description="Extract printable strings from binary files",
        risk_level="low",
    ),
    Spec(
        id="exiftool",
        name="ExifTool",
        kind="cli",
        categories=["search", "forensics", "domain", "ip"],
        automated=True,
        url="https://exiftool.org/",
        kali_category=KaliCategory.REVERSE_ENGINEERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install libimage-exiftool-perl",
        parser="exiftool_json",
        args_template=["-json", "-a", "-u", "-g1", "{target}"],
        separator="--",
        version_flag="-ver",
        description="Read, write, and edit metadata in files",
        risk_level="low",
    ),
    # --- Forensics Enhancement ---
    Spec(
        id="volatility3",
        name="Volatility 3",
        kind="cli",
        categories=["search", "forensics"],
        automated=True,
        url="https://github.com/volatilityfoundation/volatility3",
        kali_category=KaliCategory.FORENSICS,
        classification=ToolClassification.EXECUTABLE,
        install_hint="pip install volatility3",
        parser="volatility_json",
        args_template=["-f", "{target}", "windows.info"],
        separator="--",
        version_flag="--version",
        description="Memory forensics framework for RAM analysis",
        requires_hardware=False,
        risk_level="medium",
    ),
    Spec(
        id="bulk_extractor",
        name="bulk_extractor",
        kind="cli",
        categories=["search", "forensics"],
        automated=True,
        url="https://github.com/simsong/bulk_extractor",
        kali_category=KaliCategory.FORENSICS,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install bulk-extractor",
        parser="bulk_extractor_json",
        args_template=["-o", "{output_dir}", "{target}"],
        separator="--",
        version_flag="-V",
        description="Extract structured data from digital evidence",
        risk_level="medium",
    ),
    Spec(
        id="foremost",
        name="Foremost",
        kind="cli",
        categories=["search", "forensics"],
        automated=True,
        url="http://foremost.sourceforge.net/",
        kali_category=KaliCategory.FORENSICS,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install foremost",
        parser="foremost_output",
        args_template=["-i", "{target}", "-o", "{output_dir}"],
        separator="--",
        version_flag="-v",
        description="File carving tool for data recovery",
        risk_level="medium",
    ),
    Spec(
        id="scalpel",
        name="Scalpel",
        kind="cli",
        categories=["search", "forensics"],
        automated=True,
        url="https://github.com/sleuthkit/scalpel",
        kali_category=KaliCategory.FORENSICS,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install scalpel",
        parser="scalpel_output",
        args_template=["-o", "{output_dir}", "{target}"],
        separator="--",
        version_flag="-V",
        description="Fast file carver for digital forensics",
        risk_level="medium",
    ),
    # --- Information Gathering Additions ---
    Spec(
        id="masscan",
        name="Masscan",
        kind="cli",
        categories=["network", "ip", "search"],
        automated=True,
        url="https://github.com/robertdavidgraham/masscan",
        kali_category=KaliCategory.INFORMATION_GATHERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install masscan",
        parser="masscan_json",
        args_template=["{target}", "-p1-65535", "--rate=1000", "-oJ", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="Fastest Internet port scanner",
        risk_level="low",
    ),
    Spec(
        id="dnsx",
        name="DNSx",
        kind="cli",
        categories=["domain", "search"],
        automated=True,
        url="https://github.com/projectdiscovery/dnsx",
        kali_category=KaliCategory.INFORMATION_GATHERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        parser="dnsx_json",
        args_template=["-d", "{target}", "-json", "-silent"],
        separator="--",
        version_flag="-version",
        description="Fast and multi-purpose DNS toolkit",
        risk_level="low",
    ),
    Spec(
        id="dnsgen",
        name="Dnsgen",
        kind="cli",
        categories=["domain", "search"],
        automated=True,
        url="https://github.com/ProjectAnte/dnsgen",
        kali_category=KaliCategory.INFORMATION_GATHERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="pip install dnsgen",
        parser="dnsgen_output",
        args_template=["-w", "{output_file}", "{target}"],
        separator="--",
        version_flag="--version",
        description="Generate subdomains using ML-based permutations",
        risk_level="low",
    ),
    Spec(
        id="dnsrecon",
        name="DNSRecon",
        kind="cli",
        categories=["domain", "search"],
        automated=True,
        url="https://github.com/darkoperator/dnsrecon",
        kali_category=KaliCategory.INFORMATION_GATHERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="pip install dnsrecon",
        parser="dnsrecon_json",
        args_template=["-d", "{target}", "-j", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="DNS enumeration script with multiple modules",
        risk_level="low",
    ),
    Spec(
        id="fierce",
        name="Fierce",
        kind="cli",
        categories=["domain", "search"],
        automated=True,
        url="https://github.com/mschwager/fierce",
        kali_category=KaliCategory.INFORMATION_GATHERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="pip install fierce",
        parser="fierce_json",
        args_template=["--domain", "{target}", "--json", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="DNS reconnaissance tool for locating non-contiguous IP space",
        risk_level="low",
    ),
    Spec(
        id="altdns",
        name="Altdns",
        kind="cli",
        categories=["domain", "search"],
        automated=True,
        url="https://github.com/infosec-au/altdns",
        kali_category=KaliCategory.INFORMATION_GATHERING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="pip install altdns",
        parser="altdns_output",
        args_template=["-i", "{target}", "-o", "{output_file}", "-w", "words.txt"],
        separator="--",
        version_flag="--version",
        description="Subdomain discovery through permutation and alteration",
        risk_level="low",
    ),
    # --- Passive Network ---
    Spec(
        id="tshark",
        name="TShark",
        kind="cli",
        categories=["network", "search"],
        automated=True,
        url="https://www.wireshark.org/docs/man-pages/tshark.html",
        kali_category=KaliCategory.SNIFFING_SPOOFING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install tshark",
        parser="tshark_json",
        args_template=["-r", "{target}", "-T", "json"],
        separator="--",
        version_flag="-v",
        description="Command-line network protocol analyzer (Wireshark CLI)",
        risk_level="low",
    ),
    Spec(
        id="p0f",
        name="p0f",
        kind="cli",
        categories=["network", "search"],
        automated=True,
        url="https://github.com/p0f/p0f",
        kali_category=KaliCategory.SNIFFING_SPOOFING,
        classification=ToolClassification.EXECUTABLE,
        install_hint="apt install p0f",
        parser="p0f_output",
        args_template=["-i", "{target}", "-o", "{output_file}"],
        separator="--",
        version_flag="-v",
        description="Passive OS fingerprinting tool",
        risk_level="low",
    ),
    # --- Reporting ---
    Spec(
        id="faraday",
        name="Faraday",
        kind="cli",
        categories=["search", "reporting"],
        automated=True,
        url="https://github.com/infobyte/faraday",
        kali_category=KaliCategory.REPORTING_TOOLS,
        classification=ToolClassification.EXECUTABLE,
        install_hint="pip install faraday-cli",
        parser="faraday_json",
        args_template=["report", "--format", "json", "--output", "{output_file}", "{target}"],
        separator="--",
        version_flag="--version",
        description="Collaborative penetration testing IDE - CLI reporter",
        risk_level="low",
    ),
    # ============================================================
    # PHASE 2B — RESTRICTED TOOLS (Require auth + deep mode + confirmation)
    # ============================================================
    # --- Vulnerability Scanners ---
    Spec(
        id="nikto",
        name="Nikto",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://cirt.net/Nikto2",
        kali_category=KaliCategory.VULNERABILITY_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        install_hint="apt install nikto",
        parser="nikto_json",
        args_template=["-h", "{target}", "-Format", "json", "-output", "{output_file}"],
        separator="--",
        version_flag="-Version",
        description="Web server vulnerability scanner",
        risk_level="medium",
    ),
    Spec(
        id="wpscan",
        name="WPScan",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://wpscan.com/",
        kali_category=KaliCategory.WEB_APPLICATION_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        install_hint="gem install wpscan",
        parser="wpscan_json",
        args_template=["--url", "{target}", "--format", "json", "--output", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="WordPress security scanner",
        risk_level="medium",
    ),
    Spec(
        id="nuclei",
        name="Nuclei",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/projectdiscovery/nuclei",
        kali_category=KaliCategory.VULNERABILITY_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        parser="nuclei_json",
        args_template=["-target", "{target}", "-json", "-silent", "-o", "{output_file}"],
        separator="--",
        version_flag="-version",
        description="Fast template-based vulnerability scanner",
        risk_level="medium",
    ),
    Spec(
        id="dalfox",
        name="Dalfox",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/hahwul/dalfox",
        kali_category=KaliCategory.WEB_APPLICATION_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        install_hint="go install github.com/hahwul/dalfox/v2@latest",
        parser="dalfox_json",
        args_template=["url", "{target}", "--format", "json", "--output", "{output_file}"],
        separator="--",
        version_flag="version",
        description="XSS scanning and parameter analysis tool",
        risk_level="medium",
    ),
    Spec(
        id="arjun",
        name="Arjun",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/s0md3v/Arjun",
        kali_category=KaliCategory.WEB_APPLICATION_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        install_hint="pip install arjun",
        parser="arjun_json",
        args_template=["-u", "{target}", "-oJ", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="HTTP parameter discovery suite",
        risk_level="medium",
    ),
    # --- Password Attacks ---
    Spec(
        id="hydra",
        name="Hydra",
        kind="cli",
        categories=["search", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/vanhauser-thc/thc-hydra",
        kali_category=KaliCategory.PASSWORD_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        credential_ref="hydra_userlist",
        parser="hydra_output",
        args_template=["-L", "{credential:hydra_userlist}", "-P", "{credential:wordlist}", "{target}", "{service}", "-V", "-o", "{output_file}"],
        separator="--",
        version_flag="-h",
        description="Fast network logon cracker",
        risk_level="high",
    ),
    Spec(
        id="hashcat",
        name="Hashcat",
        kind="cli",
        categories=["search", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://hashcat.net/hashcat/",
        kali_category=KaliCategory.PASSWORD_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        credential_ref="hashcat_mask",
        parser="hashcat_show",
        args_template=["-m", "{hash_mode}", "-a", "3", "{target}", "{credential:hashcat_mask}", "--show", "-o", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="Advanced password recovery tool",
        requires_hardware=True,
        risk_level="high",
    ),
    Spec(
        id="john",
        name="John the Ripper",
        kind="cli",
        categories=["search", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://www.openwall.com/john/",
        kali_category=KaliCategory.PASSWORD_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        credential_ref="wordlist",
        parser="john_output",
        args_template=["--wordlist={credential:wordlist}", "--format={format}", "{target}", "--show"],
        separator="--",
        version_flag="--version",
        description="Password cracker with multiple hash format support",
        risk_level="high",
    ),
    Spec(
        id="crunch",
        name="Crunch",
        kind="cli",
        categories=["search", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://sourceforge.net/projects/crunch-wordlist/",
        kali_category=KaliCategory.PASSWORD_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        parser="crunch_output",
        args_template=["{min_len}", "{max_len}", "{charset}", "-o", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="Wordlist generator for password attacks",
        risk_level="medium",
    ),
    Spec(
        id="cewl",
        name="CeWL",
        kind="cli",
        categories=["search", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/digininja/CeWL",
        kali_category=KaliCategory.PASSWORD_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        parser="cewl_output",
        args_template=["-d", "2", "-m", "5", "-w", "{output_file}", "{target}"],
        separator="--",
        version_flag="--version",
        description="Custom wordlist generator from target website",
        risk_level="medium",
    ),
    # --- Web Exploitation ---
    Spec(
        id="sqlmap",
        name="SQLMap",
        kind="cli",
        categories=["domain", "search", "vulnerability", "database"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://sqlmap.org/",
        kali_category=KaliCategory.DATABASE_ASSESSMENT,
        classification=ToolClassification.RESTRICTED,
        parser="sqlmap_log",
        args_template=["-u", "{target}", "--batch", "--crawl=1", "--output-dir={output_dir}", "--forms"],
        separator="--",
        version_flag="--version",
        description="Automatic SQL injection and database takeover tool",
        risk_level="high",
    ),
    Spec(
        id="commix",
        name="Commix",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/commixproject/commix",
        kali_category=KaliCategory.WEB_APPLICATION_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        parser="commix_json",
        args_template=["--url={target}", "--batch", "--output-dir={output_dir}"],
        separator="--",
        version_flag="--version",
        description="Automated command injection exploitation tool",
        risk_level="high",
    ),
    Spec(
        id="xsser",
        name="XSSer",
        kind="cli",
        categories=["domain", "search", "vulnerability"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://xsser.03c8.net/",
        kali_category=KaliCategory.WEB_APPLICATION_ANALYSIS,
        classification=ToolClassification.RESTRICTED,
        parser="xsser_json",
        args_template=["-u", "{target}", "--auto", "--xml=file", "--output={output_file}"],
        separator="--",
        version_flag="--version",
        description="Cross-site scripting vulnerability scanner",
        risk_level="medium",
    ),
    # --- Post-Exploitation ---
    Spec(
        id="bloodhound",
        name="BloodHound",
        kind="cli",
        categories=["search", "post_exploitation", "network"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/BloodHoundAD/BloodHound",
        kali_category=KaliCategory.POST_EXPLOITATION,
        classification=ToolClassification.RESTRICTED,
        parser="bloodhound_json",
        args_template=["-c", "All", "-d", "{target}", "-u", "{username}", "-p", "{password}", "-o", "{output_dir}"],
        separator="--",
        version_flag="--version",
        description="Active Directory attack path analysis (SharpHound collector)",
        risk_level="critical",
    ),
    Spec(
        id="crackmapexec",
        name="CrackMapExec",
        kind="cli",
        categories=["search", "post_exploitation", "network", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/byt3bl33d3r/CrackMapExec",
        kali_category=KaliCategory.POST_EXPLOITATION,
        classification=ToolClassification.RESTRICTED,
        parser="crackmapexec_json",
        args_template=["{target}", "-u", "{username}", "-p", "{password}", "--json", "--output", "{output_file}"],
        separator="--",
        version_flag="--version",
        description="Post-exploitation tool for Active Directory environments",
        risk_level="critical",
    ),
    Spec(
        id="ldapdomaindump",
        name="ldapdomaindump",
        kind="cli",
        categories=["search", "post_exploitation", "network"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://github.com/dirkjanm/ldapdomaindump",
        kali_category=KaliCategory.POST_EXPLOITATION,
        classification=ToolClassification.RESTRICTED,
        parser="ldapdomaindump_json",
        args_template=["-u", "{username}", "-p", "{password}", "-o", "{output_dir}", "{target}"],
        separator="--",
        version_flag="--version",
        description="Dump Active Directory information via LDAP",
        risk_level="high",
    ),
    # --- Wireless (Passive Only) ---
    Spec(
        id="kismet",
        name="Kismet",
        kind="cli",
        categories=["network", "wireless"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://www.kismetwireless.net/",
        kali_category=KaliCategory.WIRELESS_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        parser="kismet_json",
        args_template=["--server", "--no-plugins", "--override", "logprefix={output_dir}"],
        separator="--",
        version_flag="--version",
        description="Wireless network detector and sniffer",
        requires_hardware=True,
        risk_level="high",
    ),
    Spec(
        id="aircrack_ng",
        name="Aircrack-ng",
        kind="cli",
        categories=["network", "wireless", "credential_access"],
        automated=True,
        authorized_only=True,
        deep_only=True,
        url="https://www.aircrack-ng.org/",
        kali_category=KaliCategory.WIRELESS_ATTACKS,
        classification=ToolClassification.RESTRICTED,
        parser="aircrack_ng_output",
        args_template=["-b", "{bssid}", "-w", "{credential:wordlist}", "{target}"],
        separator="--",
        version_flag="--version",
        description="WiFi security auditing suite (cracking requires capture file)",
        requires_hardware=True,
        risk_level="high",
    ),
    # ============================================================
    # PHASE 2C — EDUCATIONAL TOOLS (Catalog only, not executed)
    # These are referenced in engine/catalog.py or engine/awesome_catalog.py
    # ============================================================
    # Frameworks & GUIs: metasploit, burpsuite, owasp-zap, setoolkit, gophish
    # GUI Tools: wireshark, autopsy, ghidra (GUI), maltego
    # Labs: dvwa, bwapp, mutillidae, juice-shop
]

# Create mapping from ID to spec
SPEC_BY_ID: Dict[str, Spec] = {spec.id: spec for spec in _SPECS}
SPECS: List[Spec] = _SPECS  # alias for compatibility

# Web providers wrapper
class _WebProviders:
    def __init__(self):
        # Import the web_providers module to access provider functions
        from . import web_providers
        self._module = web_providers
        # Build a dict of provider ID to function for easy lookup
        self.PROVIDERS: Dict[str, Any] = {}
        for attr_name in dir(web_providers):
            if attr_name.endswith('_public'):
                func = getattr(web_providers, attr_name)
                if callable(func):
                    self.PROVIDERS[attr_name] = func

    async def run(self, pid: str, target: str, cat: str) -> List[Dict[str, Any]]:
        """Run a web provider by its ID."""
        func = self.PROVIDERS.get(pid)
        if func is None:
            # Fallback: try to get attribute directly
            func = getattr(self._module, pid, None)
        if func is None:
            raise ValueError(f"Unknown web provider: {pid}")
        # Call the provider function
        return await func(target, cat)

web_providers = _WebProviders()

def _validate_target(target: str) -> str:
    """Validate and sanitize target input for CLI tools.
    Returns the validated target string.
    """
    if not target or not target.strip():
        raise ValueError("Target cannot be empty")
    target = target.strip()
    # Basic validation - allow alphanumeric, dots, hyphens, underscores, @, :, /
    # This covers domains, IPs, usernames, emails, URLs
    if len(target) > 255:
        raise ValueError("Target too long")
    # Reject any shell metacharacters that could be used for injection
    forbidden = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\t']
    for ch in forbidden:
        if ch in target:
            raise ValueError(f"Invalid character in target: {repr(ch)}")
    return target


def tool_command(pid: str, target: str, cat: str) -> Optional[List]:
    """Return [args_list, working_dir] for a CLI provider, or None.
    The engine expects a list of length 2 or 3:
      [args_list, working_dir] or [args_list, working_dir, stdin_str].
    We return length 2 with working_dir empty (current directory).

    args_list is an explicit list of arguments, not a string to be split.
    This prevents shell injection vulnerabilities.
    """
    try:
        target = _validate_target(target)
    except ValueError:
        return None

    if pid == "sherlock":
        # sherlock supports -- to separate args from target
        args = ["sherlock", "--", target]
    elif pid == "maigret":
        args = ["maigret", "--", target]
    elif pid == "blackbird":
        # blackbird doesn't support --, but we validate target
        args = ["blackbird", target]
    elif pid == "gosherlock":
        args = ["gosherlock", "--", target]
    elif pid == "socialanalyzer":
        args = ["socialanalyzer", "-u", "--", target]
    elif pid == "subfinder":
        # subfinder supports -- for target
        args = ["subfinder", "-d", "--", target]
    elif pid == "assetfinder":
        args = ["assetfinder", "--", target]
    elif pid == "amass":
        args = ["amass", "enum", "-d", "--", target]
    elif pid == "theharvester":
        args = ["theharvester", "-d", "--", target, "-b", "baidu,bing,google,yahoo"]
    elif pid == "waymore":
        args = ["waymore", "-i", "--", target]
    elif pid == "gau":
        # gau supports -- for target
        args = ["gau", "--", target]
    elif pid == "waybackurls":
        # waybackurls reads from stdin, but we can pass as arg
        args = ["waybackurls", "--", target]
    elif pid == "findomain":
        # findomain supports -- for target
        args = ["findomain", "-t", "--", target]
    # ============================================================
    # PHASE 2A — EXECUTABLE TOOLS
    # ============================================================
    # --- Reverse Engineering (Static Analysis) ---
    elif pid == "radare2":
        args = ["radare2", "-A", "-j", target]
    elif pid == "binwalk":
        args = ["binwalk", "-e", "-M", target]
    elif pid == "strings":
        args = ["strings", "-a", "-n", "4", target]
    elif pid == "exiftool":
        args = ["exiftool", "-json", "-a", "-u", "-g1", target]
    # --- Forensics Enhancement ---
    elif pid == "volatility3":
        args = ["vol", "-f", target, "windows.info"]
    elif pid == "bulk_extractor":
        args = ["bulk_extractor", "-o", "/tmp/bulk_out", target]
    elif pid == "foremost":
        args = ["foremost", "-i", target, "-o", "/tmp/foremost_out"]
    elif pid == "scalpel":
        args = ["scalpel", "-o", "/tmp/scalpel_out", target]
    # --- Information Gathering Additions ---
    elif pid == "masscan":
        args = ["masscan", target, "-p1-65535", "--rate=1000", "-oJ", "/tmp/masscan_out.json"]
    elif pid == "dnsx":
        args = ["dnsx", "-d", target, "-json", "-silent"]
    elif pid == "dnsgen":
        args = ["dnsgen", "-w", "/tmp/dnsgen_out.txt", target]
    elif pid == "dnsrecon":
        args = ["dnsrecon", "-d", target, "-j", "/tmp/dnsrecon_out.json"]
    elif pid == "fierce":
        args = ["fierce", "--domain", target, "--json", "/tmp/fierce_out.json"]
    elif pid == "altdns":
        args = ["altdns", "-i", target, "-o", "/tmp/altdns_out.txt", "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"]
    # --- Passive Network ---
    elif pid == "tshark":
        args = ["tshark", "-r", target, "-T", "json"]
    elif pid == "p0f":
        args = ["p0f", "-i", target, "-o", "/tmp/p0f_out.txt"]
    # --- Reporting ---
    elif pid == "faraday":
        args = ["faraday-cli", "report", "--format", "json", "--output", "/tmp/faraday_out.json", target]
    # ============================================================
    # PHASE 2B — RESTRICTED TOOLS (Require auth + deep mode + confirmation)
    # ============================================================
    # --- Vulnerability Scanners ---
    elif pid == "nikto":
        args = ["nikto", "-h", target, "-Format", "json", "-output", "/tmp/nikto_out.json"]
    elif pid == "wpscan":
        args = ["wpscan", "--url", target, "--format", "json", "--output", "/tmp/wpscan_out.json"]
    elif pid == "nuclei":
        args = ["nuclei", "-target", target, "-json", "-silent", "-o", "/tmp/nuclei_out.json"]
    elif pid == "dalfox":
        args = ["dalfox", "url", target, "--format", "json", "--output", "/tmp/dalfox_out.json"]
    elif pid == "arjun":
        args = ["arjun", "-u", target, "-oJ", "/tmp/arjun_out.json"]
    # --- Password Attacks ---
    elif pid == "hydra":
        args = ["hydra", "-L", "/tmp/userlist.txt", "-P", "/tmp/wordlist.txt", target, "ssh", "-V", "-o", "/tmp/hydra_out.txt"]
    elif pid == "hashcat":
        args = ["hashcat", "-m", "0", "-a", "3", target, "?a?a?a?a", "--show", "-o", "/tmp/hashcat_out.txt"]
    elif pid == "john":
        args = ["john", "--wordlist=/tmp/wordlist.txt", "--format=raw-md5", target, "--show"]
    elif pid == "crunch":
        args = ["crunch", "4", "8", "abcdefghijklmnopqrstuvwxyz", "-o", "/tmp/crunch_out.txt"]
    elif pid == "cewl":
        args = ["cewl", "-d", "2", "-m", "5", "-w", "/tmp/cewl_out.txt", target]
    # --- Web Exploitation ---
    elif pid == "sqlmap":
        args = ["sqlmap", "-u", target, "--batch", "--crawl=1", "--output-dir=/tmp/sqlmap_out", "--forms"]
    elif pid == "commix":
        args = ["commix", "--url=" + target, "--batch", "--output-dir=/tmp/commix_out"]
    elif pid == "xsser":
        args = ["xsser", "-u", target, "--auto", "--xml=file", "--output=/tmp/xsser_out.xml"]
    # --- Post-Exploitation ---
    elif pid == "bloodhound":
        args = ["SharpHound.exe", "-c", "All", "-d", target, "-o", "/tmp/bloodhound_out"]
    elif pid == "crackmapexec":
        args = ["crackmapexec", target, "-u", "admin", "-p", "password", "--json", "--output", "/tmp/cme_out.json"]
    elif pid == "ldapdomaindump":
        args = ["ldapdomaindump", "-u", "admin", "-p", "password", "-o", "/tmp/ldap_out", target]
    # --- Wireless (Passive Only) ---
    elif pid == "kismet":
        args = ["kismet", "--server", "--no-plugins", "--override", "logprefix=/tmp/kismet_out"]
    elif pid == "aircrack_ng":
        args = ["aircrack-ng", "-b", "00:11:22:33:44:55", "-w", "/tmp/wordlist.txt", target]
    else:
        return None
    return [args, ""]

async def run_subprocess(cw, wd: str, timeout: int = 90, stdin_text: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a subprocess and return (exit_code, stdout, stderr).

    Args:
        cw: Either a command string (legacy) or a list of arguments (preferred).
        wd: Working directory.
        timeout: Timeout in seconds.
        stdin_text: Optional stdin input.

    Returns:
        Tuple of (exit_code, stdout, stderr).
    """
    proc = None
    try:
        # Handle both legacy string commands and new argument lists
        if isinstance(cw, str):
            args = cw.split()
        else:
            args = cw
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=wd if wd else None,
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        if stdin_text is not None:
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=stdin_text.encode()), timeout=timeout)
        else:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        exit_code = proc.returncode
        stdout_str = stdout.decode('utf-8', errors='replace')
        stderr_str = stderr.decode('utf-8', errors='replace')
        return (exit_code, stdout_str, stderr_str)
    except asyncio.TimeoutError:
        # Kill the process if it's still alive
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
        timeout_msg = f"timeout after {timeout} second{'s' if timeout != 1 else ''}"
        return (1, "", timeout_msg)
    except Exception as e:
        return (1, "", str(e))

def parse_username_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse output from a username-oriented tool.
    Each non-empty line is treated as a discovered username.
    """
    findings = []
    target_lower = target.lower()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        entity_key = f"username:{pid}:{line.lower()}"
        ev = {
            'exact_match': True,
            'source': f'Output from {pid}',
            'raw_output_snippet': line[:200],
        }
        findings.append({
            'entity_key': entity_key,
            'platform': pid,
            'value': line,
            'url': '',
            'source_tools': [pid],
            'evidence': ev,
        })
    return findings

def parse_domain_lines(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse output from a domain-oriented tool.
    Each non-empty line is treated as a discovered domain.
    """
    findings = []
    target_lower = target.lower()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        entity_key = f"domain:{pid}:{line.lower()}"
        ev = {
            'exact_match': True,
            'source': f'Output from {pid}',
            'raw_output_snippet': line[:200],
        }
        findings.append({
            'entity_key': entity_key,
            'platform': pid,
            'value': line,
            'url': '',
            'source_tools': [pid],
            'evidence': ev,
        })
    return findings

def parse_kv_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse output from a key-value oriented tool.
    Each line is split at the first ':' to form key and value.
    """
    findings = []
    seen_keys = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip()
            val = val.strip()
            if key not in seen_keys:
                seen_keys.add(key)
                entity_key = f"kv:{pid}:{key}"
                ev = {
                    'exact_match': True,
                    'source': f'Output from {pid}',
                    'key': key,
                    'value': val,
                    'raw_output_snippet': line[:200],
                }
                findings.append({
                    'entity_key': entity_key,
                    'platform': pid,
                    'value': val,
                    'url': '',
                    'source_tools': [pid],
                    'evidence': ev,
                })
        else:
            if line not in seen_keys:
                seen_keys.add(line)
                entity_key = f"kv:{pid}:{line}"
                ev = {
                    'exact_match': True,
                    'source': f'Output from {pid}',
                    'value': line,
                }
                findings.append({
                    'entity_key': entity_key,
                    'platform': pid,
                    'value': line,
                    'url': '',
                    'source_tools': [pid],
                    'evidence': ev,
                })
    return findings

# ============================================================
# PHASE 2A/2B — Parser Functions for New Kali Tools
# ============================================================

def parse_radare2_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse radare2 JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            for key, val in data.items():
                entity_key = f"kv:{pid}:{key}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': str(val)}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': str(val), 'url': '', 'source_tools': [pid], 'evidence': ev})
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key, val in item.items():
                        entity_key = f"kv:{pid}:{key}"
                        ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': str(val)}
                        findings.append({'entity_key': entity_key, 'platform': pid, 'value': str(val), 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        # Fallback to line parsing
        for line in output.splitlines():
            line = line.strip()
            if line:
                entity_key = f"kv:{pid}:{line}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'value': line}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_binwalk_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse binwalk JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                if 'description' in item:
                    entity_key = f"file:{pid}:{item.get('description', 'unknown')}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'description': item.get('description'), 'offset': item.get('offset'), 'file_type': item.get('file_type')}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': item.get('description', ''), 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_strings_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse strings output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and len(line) >= 4:
            entity_key = f"string:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_exiftool_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse exiftool JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                for key, val in item.items():
                    if key not in ('SourceFile', 'ExifTool:ExifToolVersion'):
                        entity_key = f"kv:{pid}:{key}"
                        ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': str(val)}
                        findings.append({'entity_key': entity_key, 'platform': pid, 'value': str(val), 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_volatility_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Volatility 3 JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            for key, val in data.items():
                entity_key = f"kv:{pid}:{key}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': str(val)}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': str(val), 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        for line in output.splitlines():
            line = line.strip()
            if line:
                entity_key = f"kv:{pid}:{line}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'value': line}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_bulk_extractor_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse bulk_extractor JSON output (feature files)."""
    findings = []
    # bulk_extractor outputs feature files, not JSON directly
    # Parse as key-value lines
    for line in output.splitlines():
        line = line.strip()
        if line and '\t' in line:
            parts = line.split('\t')
            if len(parts) >= 2:
                key = parts[0]
                val = '\t'.join(parts[1:])
                entity_key = f"kv:{pid}:{key}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': val}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': val, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_foremost_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse foremost output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and ('-' in line or 'FILE' in line.upper()):
            entity_key = f"file:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_scalpel_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse scalpel output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and ('-' in line or 'FILE' in line.upper() or 'carved' in line.lower()):
            entity_key = f"file:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_masscan_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse masscan JSON output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict) and 'ip' in data and 'ports' in data:
                ip = data['ip']
                for port_info in data['ports']:
                    port = port_info.get('port')
                    proto = port_info.get('proto', 'tcp')
                    entity_key = f"port:{pid}:{ip}:{port}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'ip': ip, 'port': port, 'protocol': proto, 'status': 'open'}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': f"{ip}:{port}/{proto}", 'url': '', 'source_tools': [pid], 'evidence': ev})
        except json.JSONDecodeError:
            pass
    return findings


def parse_dnsx_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse DNSx JSON output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                host = data.get('host', '')
                if host:
                    entity_key = f"domain:{pid}:{host.lower()}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'a': data.get('a'), 'cname': data.get('cname'), 'raw_output_snippet': line[:200]}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': host, 'url': '', 'source_tools': [pid], 'evidence': ev})
        except json.JSONDecodeError:
            pass
    return findings


def parse_dnsgen_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse dnsgen output (one subdomain per line)."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and '.' in line:
            entity_key = f"domain:{pid}:{line.lower()}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_dnsrecon_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse DNSRecon JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                if 'name' in item:
                    name = item['name']
                    entity_key = f"domain:{pid}:{name.lower()}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'type': item.get('type'), 'address': item.get('address'), 'raw_output_snippet': json.dumps(item)[:200]}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': name, 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_fierce_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Fierce JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict) and 'results' in data:
            for item in data['results']:
                if isinstance(item, dict) and 'domain' in item:
                    domain = item['domain']
                    entity_key = f"domain:{pid}:{domain.lower()}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'ip': item.get('ip'), 'raw_output_snippet': json.dumps(item)[:200]}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': domain, 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_altdns_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse altdns output (subdomains one per line)."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and '.' in line:
            entity_key = f"domain:{pid}:{line.lower()}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_tshark_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse TShark JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for packet in data:
                if isinstance(packet, dict) and '_source' in packet:
                    src = packet['_source']
                    layers = src.get('layers', {})
                    if 'ip' in layers:
                        ip_layer = layers['ip']
                        src_ip = ip_layer.get('ip.src', [''])[0] if isinstance(ip_layer.get('ip.src'), list) else ip_layer.get('ip.src', '')
                        dst_ip = ip_layer.get('ip.dst', [''])[0] if isinstance(ip_layer.get('ip.dst'), list) else ip_layer.get('ip.dst', '')
                        if src_ip:
                            entity_key = f"ip:{pid}:{src_ip}"
                            ev = {'exact_match': True, 'source': f'Output from {pid}', 'src_ip': src_ip, 'dst_ip': dst_ip}
                            findings.append({'entity_key': entity_key, 'platform': pid, 'value': src_ip, 'url': '', 'source_tools': [pid], 'evidence': ev})
                        if dst_ip:
                            entity_key = f"ip:{pid}:{dst_ip}"
                            ev = {'exact_match': True, 'source': f'Output from {pid}', 'src_ip': src_ip, 'dst_ip': dst_ip}
                            findings.append({'entity_key': entity_key, 'platform': pid, 'value': dst_ip, 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_p0f_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse p0f output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and '->' in line:
            entity_key = f"kv:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_faraday_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Faraday CLI JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            for key, val in data.items():
                entity_key = f"kv:{pid}:{key}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': str(val)}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': str(val), 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_nikto_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Nikto JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict) and 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                vuln_id = vuln.get('id', '')
                msg = vuln.get('msg', '')
                entity_key = f"vuln:{pid}:{vuln_id}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'method': vuln.get('method'), 'msg': msg, 'raw_output_snippet': json.dumps(vuln)[:200]}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': msg, 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_wpscan_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse WPScan JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            if 'version' in data:
                entity_key = f"kv:{pid}:version"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'version': data['version']}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': data['version'], 'url': '', 'source_tools': [pid], 'evidence': ev})
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    title = vuln.get('title', '')
                    entity_key = f"vuln:{pid}:{title[:50]}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'references': vuln.get('references'), 'raw_output_snippet': json.dumps(vuln)[:200]}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': title, 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_nuclei_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Nuclei JSON output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict) and 'info' in data:
                info = data['info']
                name = info.get('name', '')
                severity = info.get('severity', 'unknown')
                entity_key = f"vuln:{pid}:{name[:50]}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'severity': severity, 'description': info.get('description'), 'matched_at': data.get('matched-at'), 'raw_output_snippet': line[:200]}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': name, 'url': '', 'source_tools': [pid], 'evidence': ev})
        except json.JSONDecodeError:
            pass
    return findings


def parse_dalfox_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Dalfox JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'vulnerability' in item:
                    vuln = item['vulnerability']
                    entity_key = f"vuln:{pid}:{vuln.get('type', 'xss')}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'type': vuln.get('type'), 'parameter': vuln.get('parameter'), 'payload': vuln.get('payload'), 'raw_output_snippet': json.dumps(item)[:200]}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': vuln.get('type', 'XSS'), 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_arjun_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Arjun JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            for url, params in data.items():
                if isinstance(params, list):
                    for param in params:
                        entity_key = f"param:{pid}:{param}"
                        ev = {'exact_match': True, 'source': f'Output from {pid}', 'url': url, 'parameter': param}
                        findings.append({'entity_key': entity_key, 'platform': pid, 'value': param, 'url': url, 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_hydra_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Hydra output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if 'login:' in line.lower() and 'password:' in line.lower():
            # Found valid credentials
            entity_key = f"cred:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_hashcat_show(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Hashcat --show output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                hash_val, password = parts
                entity_key = f"cracked:{pid}:{hash_val[:32]}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'hash': hash_val, 'password': password}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': password, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_john_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse John the Ripper --show output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                hash_val, password = parts
                entity_key = f"cracked:{pid}:{hash_val[:32]}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'hash': hash_val, 'password': password}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': password, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_crunch_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Crunch output (wordlist generation)."""
    findings = []
    # Crunch outputs to file, stdout shows progress
    for line in output.splitlines():
        line = line.strip()
        if line and ('bytes' in line.lower() or 'words' in line.lower()):
            entity_key = f"kv:{pid}:progress"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_cewl_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse CeWL output (wordlist generation)."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if line and not line.startswith('CeWL') and not line.startswith('http'):
            entity_key = f"word:{pid}:{line}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_sqlmap_log(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse SQLMap log/output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if 'sqlmap' in line.lower() and ('inject' in line.lower() or 'vulnerable' in line.lower() or 'payload' in line.lower()):
            entity_key = f"vuln:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def parse_commix_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Commix JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict) and 'vulnerable' in data:
            if data['vulnerable']:
                entity_key = f"vuln:{pid}:commix"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'parameter': data.get('parameter'), 'type': data.get('type'), 'payload': data.get('payload')}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': 'Command injection found', 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_xsser_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse XSSer JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict) and 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                entity_key = f"vuln:{pid}:xss"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'parameter': vuln.get('parameter'), 'payload': vuln.get('payload'), 'type': vuln.get('type')}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': 'XSS vulnerability', 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_bloodhound_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse BloodHound JSON output (SharpHound)."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    obj_type = item['type']
                    props = item.get('properties', {})
                    name = props.get('name', '')
                    if name:
                        entity_key = f"ad:{pid}:{obj_type}:{name}"
                        ev = {'exact_match': True, 'source': f'Output from {pid}', 'object_type': obj_type, 'properties': props}
                        findings.append({'entity_key': entity_key, 'platform': pid, 'value': name, 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_crackmapexec_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse CrackMapExec JSON output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                host = data.get('host', '')
                if host:
                    entity_key = f"host:{pid}:{host}"
                    ev = {'exact_match': True, 'source': f'Output from {pid}', 'host': host, 'proto': data.get('proto'), 'module': data.get('module'), 'raw_output_snippet': line[:200]}
                    findings.append({'entity_key': entity_key, 'platform': pid, 'value': host, 'url': '', 'source_tools': [pid], 'evidence': ev})
        except json.JSONDecodeError:
            pass
    return findings


def parse_ldapdomaindump_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse ldapdomaindump JSON output."""
    findings = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            for key, val in data.items():
                entity_key = f"ad:{pid}:{key}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'key': key, 'value': str(val)[:200]}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': str(val)[:200], 'url': '', 'source_tools': [pid], 'evidence': ev})
    except json.JSONDecodeError:
        pass
    return findings


def parse_kismet_json(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Kismet JSON output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict) and 'kismet.device.base.macaddr' in data:
                mac = data['kismet.device.base.macaddr']
                entity_key = f"wireless:{pid}:{mac}"
                ev = {'exact_match': True, 'source': f'Output from {pid}', 'manuf': data.get('kismet.device.base.manuf'), 'type': data.get('kismet.device.base.type'), 'raw_output_snippet': line[:200]}
                findings.append({'entity_key': entity_key, 'platform': pid, 'value': mac, 'url': '', 'source_tools': [pid], 'evidence': ev})
        except json.JSONDecodeError:
            pass
    return findings


def parse_aircrack_ng_output(pid: str, target: str, output: str, cat: str) -> List[Dict[str, Any]]:
    """Parse Aircrack-ng output."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if 'KEY FOUND' in line or 'cracked' in line.lower():
            entity_key = f"cracked:{pid}:{line[:50]}"
            ev = {'exact_match': True, 'source': f'Output from {pid}', 'raw_output_snippet': line[:200]}
            findings.append({'entity_key': entity_key, 'platform': pid, 'value': line, 'url': '', 'source_tools': [pid], 'evidence': ev})
    return findings


def list_tools() -> List[Dict[str, Any]]:
    """Return the list of available tools in the format expected by the API."""
    result = []
    for spec in SPECS:
        diagnostic = diagnose(spec.id)
        result.append({
            "id": spec.id,
            "name": spec.name,
            "kind": spec.kind,
            "url": spec.url,
            "diagnostic": diagnostic,
        })
    return result

def diagnose(tid: str) -> Dict[str, Any]:
    """Return diagnostic information for a tool by its ID."""
    spec = SPEC_BY_ID.get(tid)
    if spec is None:
        return {"status": "unknown", "checks": [], "repairable": False}

    if spec.kind == "cli":
        # Map spec IDs to executable names (some differ)
        executable_map = {
            "volatility3": "vol",
            "bulk_extractor": "bulk_extractor",
            "dnsgen": "dnsgen",
            "aircrack_ng": "aircrack-ng",
            "crackmapexec": "crackmapexec",
            "ldapdomaindump": "ldapdomaindump",
            "sharp hound": "SharpHound.exe",
            "bloodhound": "SharpHound.exe",
            "faraday": "faraday-cli",
        }
        executable_name = executable_map.get(tid, tid)
        executable = shutil.which(executable_name)
        if executable:
            return {
                "status": "ready",
                "checks": [{"detail": f"Found executable: {executable}"}],
                "repairable": bool(spec.install_hint),
            }
        else:
            return {
                "status": "missing",
                "checks": [{"detail": f"Executable '{executable_name}' not found in PATH"}],
                "repairable": bool(spec.install_hint),
            }
    elif tid == "urlscan_public":
        api_key = os.environ.get("URLSCAN_API_KEY")
        if api_key:
            return {
                "status": "ready",
                "checks": [{"detail": "API key configured"}],
                "repairable": False,
            }
        else:
            return {
                "status": "missing",
                "checks": [{"detail": "URLSCAN_API_KEY environment variable not set"}],
                "repairable": False,
            }
    # For other kinds (web, native), we don't have specific diagnostics yet
    # Check if it's a CLI tool with install_hint
    is_cli = spec.kind == "cli"
    return {
        "status": "unknown",
        "checks": [],
        "repairable": is_cli and bool(spec.install_hint),
    }


def repair(tid: str) -> Dict[str, Any]:
    """Attempt to install or repair a tool by running its install_hint command.

    Returns a dict with 'ok' (bool), 'message' (str), and optionally 'output' (str).
    """
    spec = SPEC_BY_ID.get(tid)
    if spec is None:
        return {"ok": False, "message": f"Tool '{tid}' not found"}

    if not spec.install_hint:
        return {"ok": False, "message": "This tool has no automatic install/repair workflow. Open its project link and follow the upstream instructions."}

    if spec.kind != "cli":
        return {"ok": False, "message": f"Automatic repair is only available for CLI tools. {spec.install_hint}"}

    # Execute the install_hint command
    import subprocess
    try:
        # Run the install command with a reasonable timeout
        result = subprocess.run(
            spec.install_hint,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes
            cwd=ROOT,
        )

        if result.returncode == 0:
            # Verify the tool is now available
            executable_map = {
                "volatility3": "vol",
                "bulk_extractor": "bulk_extractor",
                "dnsgen": "dnsgen",
                "aircrack_ng": "aircrack-ng",
                "crackmapexec": "crackmapexec",
                "ldapdomaindump": "ldapdomaindump",
                "sharp hound": "SharpHound.exe",
                "bloodhound": "SharpHound.exe",
                "faraday": "faraday-cli",
            }
            executable_name = executable_map.get(tid, tid)
            executable = shutil.which(executable_name)
            if executable:
                return {
                    "ok": True,
                    "message": f"Successfully installed {spec.name}. Found at: {executable}",
                    "output": result.stdout[-2000:] if result.stdout else ""
                }
            else:
                return {
                    "ok": False,
                    "message": f"Install command completed but executable '{executable_name}' still not found in PATH",
                    "output": result.stdout[-2000:] if result.stdout else ""
                }
        else:
            return {
                "ok": False,
                "message": f"Install command failed with exit code {result.returncode}",
                "output": (result.stdout + "\n" + result.stderr)[-3000:]
            }
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "Install command timed out after 5 minutes"}
    except Exception as e:
        return {"ok": False, "message": f"Repair failed: {str(e)}"}

def _safe_extract_zip(zip_file: zipfile.ZipFile, destination: Path) -> None:
    """Extract a zip file safely, preventing path traversal."""
    for member in zip_file.infolist():
        member_path = destination / member.filename
        try:
            member_path.resolve().relative_to(destination.resolve())
        except ValueError:
            raise ValueError(f"Unsafe ZIP member path: {member.filename}")
        zip_file.extract(member, destination)