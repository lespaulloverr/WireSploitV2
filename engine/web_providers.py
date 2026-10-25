from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import quote

import httpx

UA = {"User-Agent": "WireSploit/0.3 (+public-source OSINT and authorized security research)"}


async def _get(url: str, *, params=None, timeout=15, headers=None):
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={**UA, **(headers or {})},
    ) as client:
        return await client.get(url, params=params)


def _finding(key, platform, value, url, tool, evidence):
    return {
        "entity_key": key,
        "platform": platform,
        "value": value,
        "url": url,
        "source_tools": [tool],
        "evidence": {"exact_match": True, **evidence},
    }


def _username(q: str):
    q = q.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", q):
        raise ValueError("Username must be an exact username containing letters, numbers, dot, underscore or hyphen.")
    return q


def _email(q: str):
    q = q.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", q):
        raise ValueError("Invalid email address format.")
    return q


def _domain(q: str):
    q = q.strip().lower().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", q):
        raise ValueError("Invalid domain name.")
    return q


async def github_public(query: str, category: str):
    q = _username(query)
    r = await _get(f"https://api.github.com/users/{quote(q)}", headers={"Accept": "application/vnd.github+json"})
    if r.status_code != 200:
        return []
    d = r.json()
    if str(d.get("login", "")).lower() != q.lower():
        return []
    ev = {
        "login": d.get("login"), "id": d.get("id"), "name": d.get("name"),
        "company": d.get("company"), "blog": d.get("blog"), "location": d.get("location"),
        "bio": d.get("bio"), "public_repos": d.get("public_repos"), "followers": d.get("followers"),
        "following": d.get("following"), "created_at": d.get("created_at"), "updated_at": d.get("updated_at"),
        "avatar_url": d.get("avatar_url"),
    }
    # Enrich the profile with a bounded sample of public GitHub activity. All endpoints are
    # unauthenticated/public and failures are isolated so rate limiting never kills the profile hit.
    import asyncio
    async def optional(path, params=None):
        try:
            rr=await _get("https://api.github.com"+path, params=params, headers={"Accept":"application/vnd.github+json"}, timeout=12)
            return rr.json() if rr.status_code==200 else []
        except Exception:
            return []
    repos,orgs,events=await asyncio.gather(
        optional(f"/users/{quote(q)}/repos",{"per_page":30,"sort":"updated"}),
        optional(f"/users/{quote(q)}/orgs",{"per_page":30}),
        optional(f"/users/{quote(q)}/events/public",{"per_page":30}),
    )
    if isinstance(repos,list):
        ev["recent_public_repositories"]=[{k:x.get(k) for k in ("name","html_url","description","language","fork","archived","updated_at")} for x in repos[:30]]
    if isinstance(orgs,list):
        ev["public_organizations"]=[{k:x.get(k) for k in ("login","avatar_url","description")} for x in orgs[:30]]
    if isinstance(events,list):
        ev["recent_public_events"]=[{"type":x.get("type"),"repo":(x.get("repo") or {}).get("name"),"created_at":x.get("created_at")} for x in events[:30]]
    return [_finding(f"username:github.com:{q.lower()}", "GitHub", q, d.get("html_url"), "github_public", ev)]


async def gitlab_public(query: str, category: str):
    q = _username(query)
    r = await _get("https://gitlab.com/api/v4/users", params={"username": q})
    if r.status_code != 200:
        return []
    rows = r.json() if isinstance(r.json(), list) else []
    d = next((x for x in rows if str(x.get("username", "")).lower() == q.lower()), None)
    if not d:
        return []
    ev = {k: d.get(k) for k in ("id", "username", "name", "state", "avatar_url", "web_url")}
    try:
        pr=await _get(f"https://gitlab.com/api/v4/users/{d.get('id')}/projects",params={"per_page":30,"simple":True},timeout=12)
        projects=pr.json() if pr.status_code==200 and isinstance(pr.json(),list) else []
        ev["public_projects"]=[{k:x.get(k) for k in ("name","web_url","description","last_activity_at","star_count","forks_count")} for x in projects[:30]]
    except Exception:
        pass
    return [_finding(f"username:gitlab.com:{q.lower()}", "GitLab", q, d.get("web_url"), "gitlab_public", ev)]


async def reddit_public(query: str, category: str):
    q = _username(query)
    r = await _get(f"https://www.reddit.com/user/{quote(q)}/about.json", headers={"User-Agent": "WireSploit/0.3 public profile checker"})
    if r.status_code != 200:
        return []
    try:
        d = r.json().get("data", {})
    except Exception:
        return []
    if str(d.get("name", "")).lower() != q.lower():
        return []
    ev = {
        "name": d.get("name"), "created_utc": d.get("created_utc"), "link_karma": d.get("link_karma"),
        "comment_karma": d.get("comment_karma"), "is_employee": d.get("is_employee"),
        "is_gold": d.get("is_gold"), "verified": d.get("verified"),
    }
    import asyncio
    async def listing(kind):
        try:
            rr=await _get(f"https://www.reddit.com/user/{quote(q)}/{kind}.json",params={"limit":20,"raw_json":1},headers={"User-Agent":"WireSploit/0.3 public profile checker"},timeout=12)
            if rr.status_code!=200:return []
            return (((rr.json() or {}).get("data") or {}).get("children") or [])[:20]
        except Exception:return []
    submitted,comments=await asyncio.gather(listing("submitted"),listing("comments"))
    ev["recent_public_submissions"]=[{"title":(x.get("data") or {}).get("title"),"subreddit":(x.get("data") or {}).get("subreddit"),"created_utc":(x.get("data") or {}).get("created_utc"),"url":"https://www.reddit.com"+str((x.get("data") or {}).get("permalink") or "")} for x in submitted]
    ev["recent_public_comments"]=[{"body":str((x.get("data") or {}).get("body") or "")[:500],"subreddit":(x.get("data") or {}).get("subreddit"),"created_utc":(x.get("data") or {}).get("created_utc"),"url":"https://www.reddit.com"+str((x.get("data") or {}).get("permalink") or "")} for x in comments]
    return [_finding(f"username:reddit.com:{q.lower()}", "Reddit", q, f"https://www.reddit.com/user/{q}/", "reddit_public", ev)]


async def hackernews_public(query: str, category: str):
    q = _username(query)
    r = await _get(f"https://hacker-news.firebaseio.com/v0/user/{quote(q)}.json")
    if r.status_code != 200:
        return []
    d = r.json()
    if not isinstance(d, dict) or str(d.get("id", "")).lower() != q.lower():
        return []
    ev = {"id": d.get("id"), "created": d.get("created"), "karma": d.get("karma"), "about": d.get("about")}
    return [_finding(f"username:news.ycombinator.com:{q.lower()}", "Hacker News", q, f"https://news.ycombinator.com/user?id={quote(q)}", "hackernews_public", ev)]


async def bluesky_public(query: str, category: str):
    q = query.strip().lstrip("@")
    # Bluesky handles are DNS-like handles; we deliberately do not guess suffixes.
    if not re.fullmatch(r"[A-Za-z0-9.-]{3,253}", q) or "." not in q:
        return []
    r = await _get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile", params={"actor": q})
    if r.status_code != 200:
        return []
    d = r.json()
    if str(d.get("handle", "")).lower() != q.lower():
        return []
    ev = {k: d.get(k) for k in ("did", "handle", "displayName", "description", "avatar", "followersCount", "followsCount", "postsCount")}
    try:
        fr=await _get("https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed",params={"actor":q,"limit":20,"filter":"posts_no_replies"},timeout=12)
        feed=fr.json().get("feed",[]) if fr.status_code==200 else []
        ev["recent_public_posts"]=[{"text":str((((x.get("post") or {}).get("record") or {}).get("text") or ""))[:700],"created_at":(((x.get("post") or {}).get("record") or {}).get("createdAt")),"uri":((x.get("post") or {}).get("uri"))} for x in feed[:20]]
    except Exception:
        pass
    return [_finding(f"username:bsky.app:{q.lower()}", "Bluesky", q, f"https://bsky.app/profile/{quote(q)}", "bluesky_public", ev)]


async def gravatar_public(query: str, category: str):
    q = _email(query)
    h = hashlib.md5(q.encode()).hexdigest()
    r = await _get(f"https://en.gravatar.com/{h}.json")
    if r.status_code != 200:
        return []
    try:
        entries = r.json().get("entry", [])
    except Exception:
        return []
    if not entries:
        return []
    d = entries[0]
    ev = {k: d.get(k) for k in ("displayName", "preferredUsername", "profileUrl", "thumbnailUrl", "aboutMe", "currentLocation")}
    return [_finding(f"email:{q}", "Gravatar", q, d.get("profileUrl") or f"https://gravatar.com/{h}", "gravatar_public", ev)]


async def rdap_domain(query: str, category: str):
    dmn = _domain(query)
    r = await _get(f"https://rdap.org/domain/{quote(dmn)}", timeout=20)
    if r.status_code != 200:
        return []
    d = r.json()
    ev = {
        "ldhName": d.get("ldhName"), "unicodeName": d.get("unicodeName"), "status": d.get("status"),
        "events": d.get("events"), "nameservers": d.get("nameservers"), "secureDNS": d.get("secureDNS"),
        "port43": d.get("port43"),
    }
    return [_finding(f"domain:{dmn}", "RDAP.org", dmn, f"https://rdap.org/domain/{quote(dmn)}", "rdap_domain", ev)]


async def rdap_ip(query: str, category: str):
    ip = str(ipaddress.ip_address(query.strip()))
    r = await _get(f"https://rdap.org/ip/{quote(ip)}", timeout=20)
    if r.status_code != 200:
        return []
    d = r.json()
    ev = {k: d.get(k) for k in ("name", "handle", "startAddress", "endAddress", "ipVersion", "country", "type", "status", "events", "remarks")}
    return [_finding(f"ip:{ip}", "RDAP.org", ip, f"https://rdap.org/ip/{quote(ip)}", "rdap_ip", ev)]


async def ipquery_public(query: str, category: str):
    ip = str(ipaddress.ip_address(query.strip()))
    r = await _get(f"https://api.ipquery.io/{quote(ip)}", params={"format": "json"}, timeout=15)
    if r.status_code != 200:
        return []
    d = r.json()
    if not isinstance(d, dict):
        return []
    ev = {"isp": d.get("isp"), "location": d.get("location"), "risk": d.get("risk")}
    return [_finding(f"ip:{ip}", "IPQuery", ip, None, "ipquery_public", ev)]


async def crtsh_public(query: str, category: str):
    dmn = _domain(query)
    r = await _get("https://crt.sh/", params={"q": f"%.{dmn}", "output": "json"}, timeout=25)
    if r.status_code != 200:
        return []
    try:
        rows = r.json()
    except Exception:
        return []
    names = set()
    issuers = set()
    for row in rows[:1000]:
        names.update(n.strip().lower() for n in str(row.get("name_value", "")).splitlines() if n.strip())
        if row.get("issuer_name"):
            issuers.add(str(row["issuer_name"]))
    ev = {"certificate_names": sorted(names)[:1000], "issuers": sorted(issuers)[:100], "records_returned": len(rows)}
    return [_finding(f"domain:{dmn}", "crt.sh", dmn, f"https://crt.sh/?q={quote(dmn)}", "crtsh_public", ev)]


async def google_doh(query: str, category: str):
    dmn = _domain(query)
    records = {}
    for typ in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            r = await _get("https://dns.google/resolve", params={"name": dmn, "type": typ}, timeout=12)
            if r.status_code == 200:
                records[typ] = [a.get("data") for a in r.json().get("Answer", []) if a.get("data")]
        except Exception:
            pass
    if not any(records.values()):
        return []
    return [_finding(f"domain:{dmn}", "Google DNS", dmn, f"https://dns.google/resolve?name={quote(dmn)}", "google_doh", {"records": records})]


async def cloudflare_doh(query: str, category: str):
    dmn = _domain(query)
    records = {}
    for typ in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            r = await _get("https://cloudflare-dns.com/dns-query", params={"name": dmn, "type": typ}, headers={"Accept": "application/dns-json"}, timeout=12)
            if r.status_code == 200:
                records[typ] = [a.get("data") for a in r.json().get("Answer", []) if a.get("data")]
        except Exception:
            pass
    if not any(records.values()):
        return []
    return [_finding(f"domain:{dmn}", "Cloudflare DNS", dmn, "https://1.1.1.1/", "cloudflare_doh", {"records": records})]


async def wayback_public(query: str, category: str):
    target = query.strip()
    if category == "domain":
        target = _domain(target)
    params = {"url": f"{target}/*", "output": "json", "fl": "timestamp,original,statuscode,mimetype,digest", "filter": "statuscode:200", "collapse": "urlkey", "limit": "100"}
    r = await _get("https://web.archive.org/cdx/search/cdx", params=params, timeout=25)
    if r.status_code != 200:
        return []
    try:
        rows = r.json()
    except Exception:
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    header = rows[0]
    items = [dict(zip(header, row)) for row in rows[1:101]]
    key = f"archive:{hashlib.sha1(target.encode()).hexdigest()}"
    return [_finding(key, "Wayback Machine", target, f"https://web.archive.org/web/*/{target}", "wayback_public", {"snapshots": items, "count": len(items)})]


async def commoncrawl_public(query: str, category: str):
    target = query.strip()
    if category == "domain":
        target = _domain(target)
    indexes = await _get("https://index.commoncrawl.org/collinfo.json", timeout=15)
    if indexes.status_code != 200:
        return []
    rows = indexes.json()
    if not rows:
        return []
    idx = rows[0].get("id")
    if not idx:
        return []
    r = await _get(f"https://index.commoncrawl.org/{idx}-index", params={"url": f"{target}/*", "output": "json", "filter": "status:200", "limit": "100"}, timeout=25)
    if r.status_code != 200:
        return []
    items = []
    for line in r.text.splitlines()[:100]:
        try:
            d = json.loads(line)
            items.append({k: d.get(k) for k in ("url", "timestamp", "status", "mime", "digest")})
        except Exception:
            pass
    if not items:
        return []
    key = f"archive:{hashlib.sha1(target.encode()).hexdigest()}"
    return [_finding(key, "Common Crawl", target, None, "commoncrawl_public", {"index": idx, "records": items, "count": len(items)})]


# ---- Additional passive OSINT / defensive intelligence providers ----------------
_CISA_KEV_CACHE = {"loaded_at": 0.0, "by_cve": {}}
_CISA_KEV_TTL = 6 * 60 * 60
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _public_ip(query: str) -> str:
    ip = str(ipaddress.ip_address(query.strip()))
    parsed = ipaddress.ip_address(ip)
    if not parsed.is_global:
        raise ValueError("This provider only accepts globally routable IP addresses.")
    return ip


async def internetdb_public(query: str, category: str):
    """Look up already-collected Shodan InternetDB context; never performs a scan."""
    try:
        ip = _public_ip(query)
    except ValueError:
        return []
    r = await _get(f"https://internetdb.shodan.io/{quote(ip)}", timeout=15)
    if r.status_code in (404, 400):
        return []
    if r.status_code != 200:
        return []
    d = r.json()
    if not isinstance(d, dict) or d.get("ip") != ip:
        return []
    ev = {k: d.get(k) for k in ("ports", "hostnames", "cpes", "tags", "vulns")}
    ev["source_updated"] = "Shodan InternetDB snapshot; data can be stale and CVE references require verification."
    ev["passive"] = True
    return [_finding(f"ip:{ip}", "Shodan InternetDB", ip, f"https://internetdb.shodan.io/{quote(ip)}", "internetdb_public", ev)]


async def ipwhois_public(query: str, category: str):
    try:
        ip = _public_ip(query)
    except ValueError:
        return []
    r = await _get(f"https://ipwho.is/{quote(ip)}", timeout=15)
    if r.status_code != 200:
        return []
    d = r.json()
    if not isinstance(d, dict) or d.get("success") is False:
        return []
    conn = d.get("connection") or {}
    tz = d.get("timezone") or {}
    ev = {
        "ip": d.get("ip"), "type": d.get("type"), "continent": d.get("continent"),
        "country": d.get("country"), "region": d.get("region"), "city": d.get("city"),
        "latitude": d.get("latitude"), "longitude": d.get("longitude"),
        "postal": d.get("postal"), "timezone": tz.get("id"),
        "asn": conn.get("asn"), "org": conn.get("org"), "isp": conn.get("isp"), "domain": conn.get("domain"),
    }
    return [_finding(f"ip:{ip}", "IPWho.is", ip, f"https://ipwho.is/{quote(ip)}", "ipwhois_public", ev)]


async def ripestat_public(query: str, category: str):
    try:
        ip = _public_ip(query)
    except ValueError:
        return []
    r = await _get("https://stat.ripe.net/data/network-info/data.json", params={"resource": ip, "sourceapp": "wiresploit"}, timeout=20)
    if r.status_code != 200:
        return []
    body = r.json()
    d = body.get("data") or {}
    if not d:
        return []
    ev = {
        "resource": d.get("resource"), "prefix": d.get("prefix"), "asns": d.get("asns"),
        "query_time": body.get("time"), "status": body.get("status"), "passive": True,
    }
    return [_finding(f"ip:{ip}", "RIPEstat", ip, f"https://stat.ripe.net/{quote(ip)}", "ripestat_public", ev)]


async def certspotter_public(query: str, category: str):
    dmn = _domain(query)
    r = await _get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": dmn, "include_subdomains": "true", "expand": ["dns_names", "issuer"], "match_wildcards": "true"},
        timeout=25,
    )
    if r.status_code != 200:
        return []
    rows = r.json()
    if not isinstance(rows, list):
        return []
    certificates = []
    names = set()
    for row in rows[:100]:
        dns_names = row.get("dns_names") or []
        names.update(str(n).strip().lower() for n in dns_names if isinstance(n, str) and n.strip())
        issuer = row.get("issuer") or {}
        certificates.append({
            "id": row.get("id"), "not_before": row.get("not_before"), "not_after": row.get("not_after"),
            "dns_names": dns_names[:100], "issuer": issuer.get("name") if isinstance(issuer, dict) else issuer,
        })
    return [_finding(
        f"domain:{dmn}", "Cert Spotter", dmn,
        f"https://api.certspotter.com/v1/issuances?domain={quote(dmn)}&include_subdomains=true",
        "certspotter_public", {"certificates": certificates, "certificate_count": len(rows), "certificate_names": sorted(names)[:500], "passive": True},
    )] if certificates else []


async def urlscan_public(query: str, category: str):
    q = query.strip()
    if category == "ip":
        try:
            q = _public_ip(q)
        except ValueError:
            return []
        search_query = f"ip:{q}"
    else:
        q = _domain(q)
        search_query = f"domain:{q}"
    api_key = __import__("os").getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        return []
    r = await _get("https://urlscan.io/api/v1/search/", params={"q": search_query, "size": 20}, headers={"api-key": api_key}, timeout=20)
    if r.status_code != 200:
        return []
    d = r.json()
    results = []
    for item in (d.get("results") or [])[:20]:
        task = item.get("task") or {}
        page = item.get("page") or {}
        results.append({
            "scan_id": item.get("_id"), "date": task.get("time"), "url": task.get("url"),
            "domain": page.get("domain"), "ip": page.get("ip"), "title": page.get("title"),
            "country": page.get("country"), "server": page.get("server"), "unique_ips": (item.get("stats") or {}).get("uniqIPs"),
            "result_url": f"https://urlscan.io/result/{item.get('_id')}/" if item.get("_id") else None,
        })
    return [_finding(f"urlscan:{search_query}", "urlscan.io", q, "https://urlscan.io/", "urlscan_public", {"query": search_query, "total": d.get("total"), "results": results, "submitted_or_scanned": False})] if results else []


async def virustotal_public(query: str, category: str):
    q = query.strip()
    api_key = __import__("os").getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return []
    if category == "ip":
        try:
            q = _public_ip(q)
        except ValueError:
            return []
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(q)}"
        key = f"ip:{q}"
        result_url = f"https://www.virustotal.com/gui/ip-address/{quote(q)}"
    else:
        q = _domain(q)
        endpoint = f"https://www.virustotal.com/api/v3/domains/{quote(q)}"
        key = f"domain:{q}"
        result_url = f"https://www.virustotal.com/gui/domain/{quote(q)}"
    r = await _get(endpoint, headers={"x-apikey": api_key}, timeout=20)
    if r.status_code != 200:
        return []
    attrs = (r.json().get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    ev = {k: attrs.get(k) for k in ("reputation", "country", "as_owner", "asn", "network", "last_analysis_date", "last_modification_date", "categories", "whois")}
    ev["last_analysis_stats"] = stats
    ev["note"] = "Reputation metadata only; verdicts can be wrong or stale."
    return [_finding(key, "VirusTotal", q, result_url, "virustotal_public", ev)]


async def abuseipdb_public(query: str, category: str):
    try:
        ip = _public_ip(query)
    except ValueError:
        return []
    api_key = __import__("os").getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return []
    r = await _get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}, headers={"Key": api_key, "Accept": "application/json"}, timeout=20)
    if r.status_code != 200:
        return []
    d = r.json().get("data") or {}
    ev = {k: d.get(k) for k in ("ipAddress", "isPublic", "ipVersion", "isWhitelisted", "abuseConfidenceScore", "countryCode", "usageType", "isp", "domain", "totalReports", "numDistinctUsers", "lastReportedAt")}
    return [_finding(f"ip:{ip}", "AbuseIPDB", ip, f"https://www.abuseipdb.com/check/{quote(ip)}", "abuseipdb_public", ev)]


async def greynoise_public(query: str, category: str):
    try:
        ip = _public_ip(query)
    except ValueError:
        return []
    api_key = __import__("os").getenv("GREYNOISE_API_KEY", "").strip()
    headers = {"key": api_key} if api_key else None
    r = await _get(f"https://api.greynoise.io/v3/community/{quote(ip)}", headers=headers, timeout=20)
    if r.status_code not in (200, 404):
        return []
    d = r.json()
    ev = {k: d.get(k) for k in ("ip", "noise", "riot", "classification", "name", "link", "last_seen", "message")}
    return [_finding(f"ip:{ip}", "GreyNoise Community", ip, f"https://viz.greynoise.io/ip/{quote(ip)}", "greynoise_public", ev)]


async def nvd_cve_public(query: str, category: str):
    cve = query.strip().upper()
    if not _CVE_RE.fullmatch(cve):
        return []
    r = await _get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve}, timeout=25)
    if r.status_code != 200:
        return []
    rows = r.json().get("vulnerabilities") or []
    out = []
    for row in rows[:5]:
        c = row.get("cve") or {}
        descriptions = c.get("descriptions") or []
        desc = next((x.get("value") for x in descriptions if x.get("lang") == "en"), "")
        metrics = c.get("metrics") or {}
        cvss = None
        for field in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(field):
                cvss = (metrics[field][0].get("cvssData") or {}).get("baseScore")
                break
        ev = {"cve_id": c.get("id"), "published": c.get("published"), "last_modified": c.get("lastModified"), "vuln_status": c.get("vulnStatus"), "cvss_base_score": cvss, "description": desc, "references": [x.get("url") for x in (c.get("references") or [])[:30] if x.get("url")]}
        out.append(_finding(f"cve:{c.get('id', cve)}", "NIST NVD", c.get("id", cve), f"https://nvd.nist.gov/vuln/detail/{c.get('id', cve)}", "nvd_cve_public", ev))
    return out


async def cisa_kev_public(query: str, category: str):
    import time
    cve = query.strip().upper()
    if not _CVE_RE.fullmatch(cve):
        return []
    now = time.monotonic()
    if now - _CISA_KEV_CACHE["loaded_at"] > _CISA_KEV_TTL or not _CISA_KEV_CACHE["by_cve"]:
        r = await _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=30)
        if r.status_code != 200:
            return []
        payload = r.json()
        _CISA_KEV_CACHE["by_cve"] = {str(x.get("cveID", "")).upper(): x for x in (payload.get("vulnerabilities") or []) if x.get("cveID")}
        _CISA_KEV_CACHE["loaded_at"] = now
    item = _CISA_KEV_CACHE["by_cve"].get(cve)
    if not item:
        return []
    ev = {k: item.get(k) for k in ("vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes")}
    return [_finding(f"cve:{cve}", "CISA KEV", cve, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "cisa_kev_public", ev)]


PROVIDERS = {
    "github_public": github_public,
    "gitlab_public": gitlab_public,
    "reddit_public": reddit_public,
    "hackernews_public": hackernews_public,
    "bluesky_public": bluesky_public,
    "gravatar_public": gravatar_public,
    "rdap_domain": rdap_domain,
    "rdap_ip": rdap_ip,
    "ipquery_public": ipquery_public,
    "crtsh_public": crtsh_public,
    "google_doh": google_doh,
    "cloudflare_doh": cloudflare_doh,
    "wayback_public": wayback_public,
    "commoncrawl_public": commoncrawl_public,
    "internetdb_public": internetdb_public,
    "ipwhois_public": ipwhois_public,
    "ripestat_public": ripestat_public,
    "certspotter_public": certspotter_public,
    "urlscan_public": urlscan_public,
    "virustotal_public": virustotal_public,
    "abuseipdb_public": abuseipdb_public,
    "greynoise_public": greynoise_public,
    "nvd_cve_public": nvd_cve_public,
    "cisa_kev_public": cisa_kev_public,
}


async def run(provider_id: str, query: str, category: str):
    fn = PROVIDERS.get(provider_id)
    if not fn:
        raise KeyError(provider_id)
    return await fn(query, category)

# ---- Extended public providers -------------------------------------------------
_WMN_CACHE = None

async def whatsmyname_public(query: str, category: str):
    """Use the community-maintained WhatsMyName dataset with bounded concurrency.

    Only exact usernames are checked. A shared AsyncClient and a small worker pool keep
    this deep provider from exhausting sockets or starving the local API on low-resource
    Windows systems.
    """
    global _WMN_CACHE
    q = _username(query)
    if _WMN_CACHE is None:
        r = await _get(
            "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
            timeout=20,
        )
        if r.status_code != 200:
            return []
        _WMN_CACHE = r.json()
    sites = (_WMN_CACHE or {}).get("sites", [])
    import asyncio
    sem = asyncio.Semaphore(8)
    limits = httpx.Limits(max_connections=8, max_keepalive_connections=4)

    async with httpx.AsyncClient(
        follow_redirects=True, timeout=8, headers=UA, limits=limits
    ) as client:
        async def check(site):
            if site.get("valid") is False:
                return None
            protections = set(site.get("protection") or [])
            if "user-auth" in protections:
                return None
            uri = site.get("uri_check") or ""
            if "{account}" not in uri and not site.get("post_body"):
                return None
            username = q
            for ch in site.get("strip_bad_char") or "":
                username = username.replace(ch, "")
            headers = {str(k): str(v) for k, v in (site.get("headers") or {}).items()}
            check_url = uri.replace("{account}", username)
            try:
                async with sem:
                    if site.get("post_body"):
                        body = str(site["post_body"]).replace("{account}", username)
                        resp = await client.post(check_url, content=body, headers=headers or None)
                    else:
                        resp = await client.get(check_url, headers=headers or None)
                text = resp.text[:250000]
                e_code = site.get("e_code")
                m_code = site.get("m_code")
                e_string = str(site.get("e_string") or "")
                m_string = str(site.get("m_string") or "")
                exists = (e_code is None or resp.status_code == int(e_code))
                if e_string:
                    exists = exists and e_string in text
                if m_string and m_string in text:
                    exists = False
                if m_code is not None and resp.status_code == int(m_code) and int(m_code) != int(e_code or -1):
                    exists = False
                if not exists:
                    return None
                pretty = (site.get("uri_pretty") or check_url).replace("{account}", username)
                host = re.sub(r"^www\.", "", httpx.URL(pretty).host or site.get("name", "")).lower()
                return _finding(
                    f"username:{host}:{q.lower()}",
                    str(site.get("name") or host),
                    q,
                    pretty,
                    "whatsmyname_public",
                    {"category": site.get("cat"), "http_status": resp.status_code, "dataset": "WhatsMyName"},
                )
            except Exception:
                return None

        # Keep the task set bounded as well as the connection pool. This avoids a burst
        # of hundreds of pending tasks on 8 GB Windows machines.
        values=[]
        batch_size=40
        for pos in range(0, len(sites), batch_size):
            batch = await asyncio.gather(*(check(site) for site in sites[pos:pos+batch_size]))
            values.extend(batch)
        return [x for x in values if x]


async def openmeteo_public(query: str, category: str):
    """Resolve a location/coordinates and return current public weather context."""
    q = query.strip()
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*", q)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        label = q
    else:
        r = await _get("https://nominatim.openstreetmap.org/search", params={"q": q, "format": "jsonv2", "limit": 1}, headers={"User-Agent": "WireSploit/0.3"})
        if r.status_code != 200 or not r.json():
            return []
        row = r.json()[0]
        lat, lon = float(row["lat"]), float(row["lon"])
        label = row.get("display_name") or q
    r = await _get(
        "https://api.open-meteo.com/v1/forecast",
        params={
            "latitude": lat,
            "longitude": lon,
            "current": "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,cloud_cover,wind_speed_10m,wind_direction_10m",
            "timezone": "auto",
        },
        timeout=15,
    )
    if r.status_code != 200:
        return []
    d = r.json()
    ev = {"latitude": lat, "longitude": lon, "display_name": label, "timezone": d.get("timezone"), "current": d.get("current"), "current_units": d.get("current_units")}
    return [_finding(f"geo:{lat:.5f},{lon:.5f}", "Open-Meteo", label, None, "openmeteo_public", ev)]


async def overpass_public(query: str, category: str):
    """Return a small set of nearby mapped features from OpenStreetMap Overpass."""
    q = query.strip()
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*", q)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
    else:
        r = await _get("https://nominatim.openstreetmap.org/search", params={"q": q, "format": "jsonv2", "limit": 1}, headers={"User-Agent": "WireSploit/0.3"})
        if r.status_code != 200 or not r.json():
            return []
        lat, lon = float(r.json()[0]["lat"]), float(r.json()[0]["lon"])
    overpass_q = f"[out:json][timeout:15];(nwr(around:800,{lat},{lon})[name];);out center tags 50;"
    async with httpx.AsyncClient(follow_redirects=True, timeout=20, headers=UA) as client:
        r = await client.post("https://overpass-api.de/api/interpreter", content=overpass_q)
    if r.status_code != 200:
        return []
    elements = []
    for e in r.json().get("elements", [])[:50]:
        tags = e.get("tags") or {}
        center = e.get("center") or {}
        elements.append({
            "type": e.get("type"), "id": e.get("id"), "name": tags.get("name"),
            "amenity": tags.get("amenity"), "shop": tags.get("shop"), "tourism": tags.get("tourism"),
            "lat": e.get("lat", center.get("lat")), "lon": e.get("lon", center.get("lon")),
        })
    if not elements:
        return []
    return [_finding(f"geo:{lat:.5f},{lon:.5f}", "OpenStreetMap Overpass", q, f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}", "overpass_public", {"latitude": lat, "longitude": lon, "nearby_features": elements})]


async def wikipedia_geo_public(query: str, category: str):
    q = query.strip()
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*", q)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
    else:
        r = await _get("https://nominatim.openstreetmap.org/search", params={"q": q, "format": "jsonv2", "limit": 1}, headers={"User-Agent": "WireSploit/0.3"})
        if r.status_code != 200 or not r.json():
            return []
        lat, lon = float(r.json()[0]["lat"]), float(r.json()[0]["lon"])
    r = await _get(
        "https://en.wikipedia.org/w/api.php",
        params={"action": "query", "list": "geosearch", "gscoord": f"{lat}|{lon}", "gsradius": 10000, "gslimit": 25, "format": "json", "origin": "*"},
        timeout=15,
    )
    if r.status_code != 200:
        return []
    rows = r.json().get("query", {}).get("geosearch", [])
    if not rows:
        return []
    return [_finding(f"geo:{lat:.5f},{lon:.5f}", "Wikipedia nearby", q, None, "wikipedia_geo_public", {"latitude": lat, "longitude": lon, "nearby_pages": rows})]


async def wikidata_public(query: str, category: str):
    q=query.strip()
    r=await _get('https://www.wikidata.org/w/api.php', params={'action':'wbsearchentities','search':q,'language':'en','format':'json','limit':10,'origin':'*'}, timeout=15)
    if r.status_code != 200: return []
    out=[]
    for row in r.json().get('search',[])[:10]:
        qid=row.get('id')
        if not qid: continue
        out.append(_finding(f'public:wikidata:{qid}', 'Wikidata', row.get('label') or qid, row.get('concepturi') or f'https://www.wikidata.org/wiki/{qid}', 'wikidata_public', {'id':qid,'label':row.get('label'),'description':row.get('description'),'aliases':row.get('aliases',[])[:20]}))
    return out


async def openalex_public(query: str, category: str):
    q=query.strip()
    r=await _get('https://api.openalex.org/authors', params={'search':q,'per-page':10}, timeout=15)
    if r.status_code != 200: return []
    out=[]
    for row in r.json().get('results',[])[:10]:
        oid=row.get('id')
        if not oid: continue
        ev={'display_name':row.get('display_name'),'orcid':row.get('orcid'),'works_count':row.get('works_count'),'cited_by_count':row.get('cited_by_count'),'last_known_institutions':row.get('last_known_institutions'),'topics':row.get('topics',[])[:10]}
        out.append(_finding(f'public:openalex:{oid}', 'OpenAlex', row.get('display_name') or oid, oid, 'openalex_public', ev))
    return out


PROVIDERS.update({
    "whatsmyname_public": whatsmyname_public,
    "openmeteo_public": openmeteo_public,
    "overpass_public": overpass_public,
    "wikipedia_geo_public": wikipedia_geo_public,
    "wikidata_public": wikidata_public,
    "openalex_public": openalex_public,
})
