from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import httpx

ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "data" / "authorized_scopes.json"
UA = {"User-Agent": "WireSploit/0.3 security-assessment client"}
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "MIME sniffing protection",
    "x-frame-options": "Frame embedding protection",
    "referrer-policy": "Referrer policy",
    "permissions-policy": "Permissions policy",
    "cross-origin-opener-policy": "Cross-Origin Opener Policy",
    "cross-origin-resource-policy": "Cross-Origin Resource Policy",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _load_scopes():
    try:
        data = json.loads(SCOPE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_scopes(items):
    SCOPE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCOPE_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _normalize_idn(host: str) -> str:
    """
    Normalize Internationalized Domain Names (IDN) to ASCII (A-label) form.
    This prevents IDN homograph attacks by converting Unicode domains to Punycode.
    """
    try:
        # Encode to IDNA (Punycode) and decode back to ASCII
        return host.encode('idna').decode('ascii')
    except Exception:
        # If IDNA encoding fails, return original (will be validated later)
        return host


def normalize_target(value: str):
    q = value.strip()
    if not q or len(q) > 500:
        raise ValueError("Enter a target domain, URL, IP address or CIDR range.")
    try:
        net = ipaddress.ip_network(q, strict=False)
        return {"type": "cidr" if "/" in q else "ip", "value": str(net) if "/" in q else str(net.network_address)}
    except Exception:
        pass
    if re.match(r"^https?://", q, re.I):
        u = urlparse(q)
        if not u.hostname:
            raise ValueError("Invalid URL.")
        # Normalize hostname for IDN
        normalized_host = _normalize_idn(u.hostname.lower())
        return {"type": "url", "value": q, "host": normalized_host}
    # Handle explicit wildcard syntax: *.example.com -> example.com (domain type)
    if q.startswith("*."):
        host = q[2:].lower().split("/")[0].split(":")[0].rstrip(".")
        # Normalize IDN in wildcard domain
        host = _normalize_idn(host)
        if re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
            return {"type": "domain", "value": host, "host": host, "wildcard": True}
        raise ValueError("Invalid wildcard domain format. Use *.example.com")
    host = q.lower().split("/")[0].split(":")[0].rstrip(".")
    # Normalize IDN in domain
    host = _normalize_idn(host)
    if re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
        return {"type": "domain", "value": host, "host": host, "wildcard": False}
    try:
        ip = str(ipaddress.ip_address(host))
        return {"type": "ip", "value": ip, "host": ip}
    except Exception:
        raise ValueError("Target must be a valid domain, URL, IP address or CIDR range.")


def list_scopes():
    return _load_scopes()


def add_scope(value: str, label: str = ""):
    n = normalize_target(value)
    items = _load_scopes()
    key = (n["type"], n["value"])
    for x in items:
        if (x.get("type"), x.get("value")) == key:
            return x
    entry = {"id": f"scope-{len(items)+1}-{abs(hash(key)) & 0xfffffff:x}", **n, "label": label.strip()[:120], "created_at": _now()}
    items.append(entry)
    _save_scopes(items)
    return entry


def delete_scope(scope_id: str):
    items = _load_scopes()
    new = [x for x in items if x.get("id") != scope_id]
    _save_scopes(new)
    return len(new) != len(items)


def is_authorized(value: str):
    try:
        n = normalize_target(value)
    except Exception:
        return False
    host = n.get("host") or n["value"]
    try:
        host_ip = ipaddress.ip_address(host)
    except Exception:
        host_ip = None
    for s in _load_scopes():
        if s.get("type") == n["type"] and s.get("value") == n["value"]:
            return True
        if s.get("type") == "domain" and n.get("host"):
            d = s.get("value", "")
            if host == d or host.endswith("." + d):
                return True
        if s.get("type") == "url" and n.get("host") and n.get("host") == s.get("host"):
            return True
        if s.get("type") == "cidr" and host_ip:
            try:
                if host_ip in ipaddress.ip_network(s.get("value"), strict=False):
                    return True
            except Exception:
                pass
    return False


def _dns(domain: str):
    out = {}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    for typ in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            out[typ] = [str(x).strip('"') for x in resolver.resolve(domain, typ)]
        except Exception:
            out[typ] = []
    # DMARC is separate from root TXT.
    try:
        out["DMARC"] = [str(x).strip('"') for x in resolver.resolve("_dmarc." + domain, "TXT")]
    except Exception:
        out["DMARC"] = []
    return out


def _tls(host: str, port: int = 443):
    result = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=7) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                result.update({
                    "protocol": sock.version(),
                    "cipher": sock.cipher(),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": cert.get("subjectAltName", [])[:100],
                })
    except Exception as e:
        result["error"] = str(e)
    return result


def _is_public_addr(ip_str: str):
    ip = ipaddress.ip_address(ip_str)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


async def _safe_get_public_host(url: str, timeout=12, max_redirects=3):
    current = httpx.URL(url)
    for _ in range(max_redirects + 1):
        if current.scheme not in ('http', 'https') or not current.host:
            raise ValueError('Only absolute HTTP(S) URLs are permitted')
        infos = await asyncio.to_thread(socket.getaddrinfo, current.host, current.port or (443 if current.scheme == 'https' else 80), 0, socket.SOCK_STREAM)
        addresses = {entry[4][0] for entry in infos}
        if not addresses or not all(_is_public_addr(addr) for addr in addresses):
            raise ValueError(f'Refusing to connect to non-public address for host {current.host}')
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=UA, verify=True) as client:
            response = await client.get(str(current))
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get('location'):
            current = current.join(response.headers['location'])
            continue
        return response
    raise ValueError('Too many redirects')


async def web_security_snapshot(target: str):
    if not is_authorized(target):
        raise PermissionError('Target is not in a saved authorized scope.')
    n = normalize_target(target)
    host = n.get("host") or n["value"]
    if n["type"] == "cidr":
        raise ValueError("Web security snapshot requires a single host/domain/URL, not a CIDR range.")
    try:
        ipaddress.ip_address(host)
        domain_for_dns = None
    except Exception:
        domain_for_dns = host
    url = n["value"] if n["type"] == "url" else f"https://{host}"
    # Validate every resolved address before the raw TLS helper opens a socket.
    try:
        resolved = await asyncio.to_thread(socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM)
        addresses = {item[4][0] for item in resolved}
        if not addresses or not all(_is_public_addr(addr) for addr in addresses):
            raise ValueError(f"Refusing to connect to non-public address for host {host}")
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve {host}: {e}") from e
    dns_task = asyncio.to_thread(_dns, domain_for_dns) if domain_for_dns else None
    tls_task = asyncio.to_thread(_tls, host)
    if dns_task:
        dns_value, tls_value = await asyncio.gather(dns_task, tls_task)
    else:
        dns_value, tls_value = {}, await tls_task
    result = {
        "target": target,
        "normalized": n,
        "dns": dns_value,
        "tls": tls_value,
        "http": {},
        "security_headers": {},
        "cookies": [],
        "well_known": {},
        "observations": [],
    }
    try:
        r = await _safe_get_public_host(url, timeout=12)
        result["http"] = {
            "status": r.status_code,
            "final_url": str(r.url),
            "redirects": [{"status": x.status_code, "url": str(x.url)} for x in r.history],
            "server": r.headers.get("server"),
            "content_type": r.headers.get("content-type"),
            "content_length": r.headers.get("content-length"),
        }
        lower = {k.lower(): v for k, v in r.headers.items()}
        for h, description in SECURITY_HEADERS.items():
            result["security_headers"][h] = {"present": h in lower, "value": lower.get(h), "description": description}
        if str(r.url).startswith("https://") and not lower.get("strict-transport-security"):
            result["observations"].append("HTTPS is in use but HSTS was not observed in this response.")
        if not lower.get("content-security-policy"):
            result["observations"].append("No Content-Security-Policy header was observed in this response.")
        for cookie in r.headers.get_list("set-cookie")[:50]:
            lc = cookie.lower()
            result["cookies"].append({"raw": cookie[:1200], "secure": "; secure" in lc, "httponly": "; httponly" in lc, "samesite": "samesite=" in lc})
        base = f"{r.url.scheme}://{r.url.host}"
        for path, key in (("/.well-known/security.txt", "security_txt"), ("/robots.txt", "robots_txt")):
            try:
                rr = await _safe_get_public_host(base + path, timeout=8)
                result["well_known"][key] = {"status": rr.status_code, "url": str(rr.url), "preview": rr.text[:6000] if rr.status_code == 200 else ""}
            except Exception as e:
                result["well_known"][key] = {"error": str(e)}
    except ssl.SSLError as e:
        result["http"]["tls_error"] = str(e)
    except Exception as e:
        result["http"]["error"] = str(e)
    return result


async def limited_authorized_probe(target: str):
    """Low-impact active checks. Requires a saved scope before the route calls this.

    This intentionally avoids exploitation, credential attacks, brute-force content discovery,
    high-rate scanning, evasion, or persistence. Heavy security frameworks are exposed as
    manual Tool Manager integrations instead.
    """
    if not is_authorized(target):
        raise PermissionError("Target is not in a saved authorized scope.")
    n = normalize_target(target)
    if n["type"] == "cidr":
        raise ValueError("The built-in active probe accepts one host at a time. Use an external authorized scanner for a saved CIDR scope.")
    host = n.get("host") or n["value"]
    common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]
    sem = asyncio.Semaphore(8)

    async def probe(port):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return {"port": port, "open": True}
            except Exception:
                return {"port": port, "open": False}

    ports = await asyncio.gather(*(probe(p) for p in common_ports))
    open_ports = [x["port"] for x in ports if x["open"]]
    return {
        "target": target,
        "host": host,
        "checked_ports": common_ports,
        "open_ports": open_ports,
        "notice": "Built-in active probe checks only a small fixed set of common TCP ports for an explicitly saved authorized target. Use dedicated scanners for a fuller assessment.",
    }


async def validate_screenshot_url(url: str, timeout=12, max_redirects=3):
    """
    Validate a URL for screenshot capture to prevent SSRF.
    Checks:
    - URL is authorized scope
    - All resolved IPs are public (no private, loopback, link-local, reserved, multicast, unspecified)
    - Validates each redirect destination
    Returns a tuple of (final_validated_url, resolved_ips) for DNS pinning.
    """
    # First check authorization
    if not is_authorized(url):
        raise PermissionError('URL is not in an authorized scope for screenshot capture')

    current = httpx.URL(url)
    resolved_ips = None

    for _ in range(max_redirects + 1):
        if current.scheme not in ('http', 'https') or not current.host:
            raise ValueError('Only absolute HTTP(S) URLs are permitted')

        # Resolve and validate all IPs for the current host
        infos = await asyncio.to_thread(socket.getaddrinfo, current.host, current.port or (443 if current.scheme == 'https' else 80), 0, socket.SOCK_STREAM)
        addresses = {entry[4][0] for entry in infos}
        if not addresses or not all(_is_public_addr(addr) for addr in addresses):
            raise ValueError(f'Refusing to connect to non-public address for host {current.host}')

        # Store the resolved IPs for the final destination (DNS pinning)
        resolved_ips = addresses

        # Check for redirects without following them
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=UA, verify=True) as client:
            response = await client.get(str(current))

        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get('location'):
            current = current.join(response.headers['location'])
            # Validate the redirect destination's IPs too
            redirect_infos = await asyncio.to_thread(socket.getaddrinfo, current.host, current.port or (443 if current.scheme == 'https' else 80), 0, socket.SOCK_STREAM)
            redirect_addresses = {entry[4][0] for entry in redirect_infos}
            if not redirect_addresses or not all(_is_public_addr(addr) for addr in redirect_addresses):
                raise ValueError(f'Refusing to follow redirect to non-public address for host {current.host}')
            continue

        # No redirect or not a redirect status - return the final URL and pinned IPs
        return str(current), resolved_ips

    raise ValueError('Too many redirects')
