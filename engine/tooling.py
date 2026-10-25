from __future__ import annotations

import os
import asyncio
import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

class Spec:
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
    ):
        self.id = id
        self.name = name
        self.kind = kind
        self.categories = categories
        self.automated = automated
        self.authorized_only = authorized_only
        self.deep_only = deep_only
        self.url = url

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
    # Add more specs as needed...
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

def list_tools() -> List[Dict[str, Any]]:
    """Return the list of available tools in the format expected by the API."""
    result = []
    for spec in SPECS:
        diagnostic = diagnose(spec.id)
        result.append({
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
        return {"status": "unknown", "checks": []}

    if spec.kind == "cli":
        # Check if the tool executable is available in PATH
        executable = shutil.which(tid)
        if executable:
            return {
                "status": "ready",
                "checks": [{"detail": f"Found executable: {executable}"}],
            }
        else:
            return {
                "status": "missing",
                "checks": [{"detail": f"Executable '{tid}' not found in PATH"}],
            }
    elif tid == "urlscan_public":
        api_key = os.environ.get("URLSCAN_API_KEY")
        if api_key:
            return {
                "status": "ready",
                "checks": [{"detail": "API key configured"}],
            }
        else:
            return {
                "status": "missing",
                "checks": [{"detail": "URLSCAN_API_KEY environment variable not set"}],
            }
    # For other kinds (web, native), we don't have specific diagnostics yet
    return {
        "status": "unknown",
        "checks": [],
    }

def _safe_extract_zip(zip_file: zipfile.ZipFile, destination: Path) -> None:
    """Extract a zip file safely, preventing path traversal."""
    for member in zip_file.infolist():
        member_path = destination / member.filename
        try:
            member_path.resolve().relative_to(destination.resolve())
        except ValueError:
            raise ValueError(f"Unsafe ZIP member path: {member.filename}")
        zip_file.extract(member, destination)