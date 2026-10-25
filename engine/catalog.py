from __future__ import annotations

# Free/public web resources that complement the automated providers. These are
# launchers only; WireSploit never claims that a web resource is an automated result.
WEB_TOOLS = [
    {"id":"wmn","name":"WhatsMyName","category":"username","url":"https://whatsmyname.app/","description":"Public username-search interface backed by the WhatsMyName dataset."},
    {"id":"github","name":"GitHub","category":"social","url":"https://github.com/","query_template":"https://github.com/{query}","description":"Public developer profile and repository research."},
    {"id":"gitlab","name":"GitLab","category":"social","url":"https://gitlab.com/","query_template":"https://gitlab.com/{query}","description":"Public developer profile and project research."},
    {"id":"reddit","name":"Reddit","category":"social","url":"https://www.reddit.com/","query_template":"https://www.reddit.com/user/{query}/","description":"Public Reddit profile pages."},
    {"id":"bluesky","name":"Bluesky","category":"social","url":"https://bsky.app/","query_template":"https://bsky.app/profile/{query}","description":"Public Bluesky profile pages."},

    {"id":"rdap","name":"RDAP.org","category":"domain","url":"https://rdap.org/","description":"Registration data for domains, IP networks and ASNs."},
    {"id":"crtsh","name":"crt.sh","category":"domain","url":"https://crt.sh/","query_template":"https://crt.sh/?q={query}","description":"Certificate Transparency search."},
    {"id":"dnsgoogle","name":"Google Public DNS","category":"domain","url":"https://dns.google/","description":"DNS-over-HTTPS lookup and resolver information."},
    {"id":"cloudflaredns","name":"Cloudflare 1.1.1.1","category":"domain","url":"https://1.1.1.1/","description":"Public DNS resolver information."},
    {"id":"dnsdumpster","name":"DNSDumpster","category":"domain","url":"https://dnsdumpster.com/","description":"Public DNS reconnaissance web resource."},
    {"id":"urlscan","name":"urlscan.io","category":"domain","url":"https://urlscan.io/","query_template":"https://urlscan.io/search/#domain:{query}","description":"Search public website scan results."},
    {"id":"bgpview","name":"BGPView","category":"ip","url":"https://bgpview.io/","description":"ASN, prefix, peer and routing information."},
    {"id":"ipwhois","name":"IPWho.is","category":"ip","url":"https://ipwho.is/","description":"Public IP geolocation and network metadata."},
    {"id":"ipquery","name":"IPQuery","category":"ip","url":"https://ipquery.io/","description":"Public IP intelligence and geolocation service."},

    {"id":"wayback","name":"Wayback Machine","category":"archives","url":"https://web.archive.org/","query_template":"https://web.archive.org/web/*/{query}","description":"Historical public web snapshots."},
    {"id":"commoncrawl","name":"Common Crawl","category":"archives","url":"https://index.commoncrawl.org/","description":"Public web crawl indexes."},
    {"id":"archive_today","name":"archive.today","category":"archives","url":"https://archive.ph/","description":"Independent public web archive."},

    {"id":"osm","name":"OpenStreetMap","category":"geolocation","url":"https://www.openstreetmap.org/","description":"Open map data and place research."},
    {"id":"nominatim","name":"Nominatim","category":"geolocation","url":"https://nominatim.org/","description":"OpenStreetMap geocoding service."},
    {"id":"overpass","name":"Overpass Turbo","category":"geolocation","url":"https://overpass-turbo.eu/","description":"Explore and query OpenStreetMap features."},
    {"id":"openmeteo","name":"Open-Meteo","category":"geolocation","url":"https://open-meteo.com/","description":"Free weather and historical weather APIs useful for contextual geolocation."},
    {"id":"geohack","name":"GeoHack","category":"geolocation","url":"https://geohack.toolforge.org/","description":"Coordinate links to many public map resources."},

    {"id":"googlelens","name":"Google Lens","category":"images","url":"https://lens.google.com/","description":"Reverse-image and visual search launcher."},
    {"id":"bingvisual","name":"Bing Visual Search","category":"images","url":"https://www.bing.com/visualsearch","description":"Reverse-image and visual search launcher."},
    {"id":"yandeximages","name":"Yandex Images","category":"images","url":"https://yandex.com/images/","description":"Image search and reverse-image-search resource."},
    {"id":"tineye","name":"TinEye","category":"images","url":"https://tineye.com/","description":"Reverse-image-search resource."},

    {"id":"companieshouse","name":"UK Companies House","category":"public_records","url":"https://find-and-update.company-information.service.gov.uk/","description":"Official UK company register."},
    {"id":"opencorporates","name":"OpenCorporates","category":"public_records","url":"https://opencorporates.com/","description":"Public company and corporate registry search."},
    {"id":"sec_edgar","name":"SEC EDGAR","category":"public_records","url":"https://www.sec.gov/edgar/search/","description":"US public company filings."},
    {"id":"gazette","name":"The Gazette","category":"public_records","url":"https://www.thegazette.co.uk/","description":"Official UK public notices."},

    {"id":"google","name":"Google","category":"search","url":"https://www.google.com/","query_template":"https://www.google.com/search?q={query}","description":"General web search."},
    {"id":"bing","name":"Bing","category":"search","url":"https://www.bing.com/","query_template":"https://www.bing.com/search?q={query}","description":"General web search."},
    {"id":"duckduckgo","name":"DuckDuckGo","category":"search","url":"https://duckduckgo.com/","query_template":"https://duckduckgo.com/?q={query}","description":"General web search."},
    {"id":"brave","name":"Brave Search","category":"search","url":"https://search.brave.com/","query_template":"https://search.brave.com/search?q={query}","description":"Independent general web search."},
    {"id":"yandex","name":"Yandex Search","category":"search","url":"https://yandex.com/","query_template":"https://yandex.com/search/?text={query}","description":"General web search that can surface different indexed results."},

    {"id":"keybase","name":"Keybase","category":"social","url":"https://keybase.io/","query_template":"https://keybase.io/{query}","description":"Public cryptographic identity/profile pages."},
    {"id":"codeberg","name":"Codeberg","category":"social","url":"https://codeberg.org/","query_template":"https://codeberg.org/{query}","description":"Public open-source developer profiles and repositories."},
    {"id":"mastodon","name":"Mastodon","category":"social","url":"https://mastodon.social/","description":"Public Mastodon instance/profile research."},
    {"id":"sourcegraph","name":"Sourcegraph Public Search","category":"search","url":"https://sourcegraph.com/search","description":"Search public source-code repositories."},

    {"id":"icannlookup","name":"ICANN Lookup","category":"domain","url":"https://lookup.icann.org/","description":"Official registration-data lookup interface."},
    {"id":"dnsviz","name":"DNSViz","category":"domain","url":"https://dnsviz.net/","description":"Public DNS and DNSSEC analysis."},
    {"id":"hebgp","name":"Hurricane Electric BGP Toolkit","category":"ip","url":"https://bgp.he.net/","description":"Public ASN, prefix, routing, and peering research."},
    {"id":"virustotal","name":"VirusTotal","category":"domain","url":"https://www.virustotal.com/gui/home/search","description":"Public reputation/context searches for URLs, domains, IPs, and hashes; account limits may apply."},
    {"id":"urlhaus","name":"URLhaus","category":"domain","url":"https://urlhaus.abuse.ch/browse/","description":"Public malicious-URL intelligence database for defensive context."},
    {"id":"abuseipdb","name":"AbuseIPDB","category":"ip","url":"https://www.abuseipdb.com/","description":"Public IP reputation research; free account features may apply."},
    {"id":"greynoise","name":"GreyNoise Visualizer","category":"ip","url":"https://viz.greynoise.io/","description":"Community internet-noise/IP context; free account features may apply."},
    {"id":"webcheck","name":"Web-Check","category":"domain","url":"https://web-check.xyz/","description":"Open-source website OSINT dashboard for public technical information."},

    {"id":"googlemaps","name":"Google Maps","category":"geolocation","url":"https://maps.google.com/","query_template":"https://www.google.com/maps/search/{query}","description":"Place, imagery, business, and geographic context."},
    {"id":"wikidata","name":"Wikidata","category":"public_records","url":"https://www.wikidata.org/","description":"Open structured public knowledge base."},
    {"id":"wikidataquery","name":"Wikidata Query Service","category":"public_records","url":"https://query.wikidata.org/","description":"SPARQL queries over open Wikidata records."},
    {"id":"wikipedia","name":"Wikipedia","category":"public_records","url":"https://www.wikipedia.org/","description":"Public encyclopedia and source/reference discovery."},
    {"id":"nasaworldview","name":"NASA Worldview","category":"geolocation","url":"https://worldview.earthdata.nasa.gov/","description":"Free global satellite imagery and environmental layers."},
    {"id":"copernicus","name":"Copernicus Browser","category":"geolocation","url":"https://browser.dataspace.copernicus.eu/","description":"Public Earth-observation imagery; account may be required for some functions."},
    {"id":"openaerialmap","name":"OpenAerialMap","category":"geolocation","url":"https://openaerialmap.org/","description":"Openly licensed aerial imagery."},
    {"id":"suncalc","name":"SunCalc","category":"geolocation","url":"https://www.suncalc.org/","description":"Sun position and shadow context for visual geolocation."},
    {"id":"internetdb","name":"Shodan InternetDB","category":"ip","url":"https://internetdb.shodan.io/","description":"Passive public IP context including observed ports, hostnames, CPEs, tags and CVE references; it does not probe the supplied address."},
    {"id":"ipwhois","name":"IPWho.is","category":"ip","url":"https://ipwho.is/","description":"Public IP geolocation, ASN and network-provider context; geographic results are approximate."},
    {"id":"ripestat","name":"RIPEstat","category":"ip","url":"https://stat.ripe.net/","description":"Routing, prefix, ASN and registry data from the RIPE NCC."},
    {"id":"certspotter","name":"Cert Spotter","category":"domain","url":"https://sslmate.com/certspotter/","description":"Certificate Transparency search useful for passive hostname discovery."},
    {"id":"urlscan_api","name":"urlscan.io","category":"security","url":"https://urlscan.io/","description":"Searches historical scans and page/network context. WireSploit's adapter searches existing scans only and does not submit targets."},
    {"id":"greynoise_api","name":"GreyNoise Community","category":"ip","url":"https://viz.greynoise.io/","description":"Context on internet background noise and scanning activity associated with IP addresses."},
    {"id":"nvd_api","name":"NIST NVD API","category":"security","url":"https://nvd.nist.gov/developers/vulnerabilities","description":"Official CVE vulnerability metadata and CVSS metrics."},
    {"id":"cisa_kev_api","name":"CISA KEV Catalogue","category":"security","url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","description":"Authoritative list of vulnerabilities known to have been exploited in the wild."},
    {"id":"misp","name":"MISP Threat Intelligence","category":"security","url":"https://www.misp-project.org/","description":"Open-source threat-intelligence sharing platform and indicator management."},
    {"id":"mitre_attack","name":"MITRE ATT&CK","category":"security","url":"https://attack.mitre.org/","description":"Knowledge base of adversary tactics, techniques and defensive mitigations."},
    {"id":"otx","name":"AlienVault OTX","category":"security","url":"https://otx.alienvault.com/","description":"Community threat-intelligence context for domains, IP addresses and file hashes."},
    {"id":"urlhaus","name":"URLhaus","category":"security","url":"https://urlhaus.abuse.ch/","description":"Community-maintained malicious-URL intelligence for defensive research."},
    {"id":"bellingcat_toolkit","name":"Bellingcat Online Investigation Toolkit","category":"search","url":"https://bellingcat.gitbook.io/toolkit","description":"Methodology and tools for open-source investigations and verification."},
    {"id":"osintcurio","name":"OSINT Curious","category":"search","url":"https://osintcurio.us/","description":"Open-source investigation training, techniques and case examples."},
    {"id":"google_transparency","name":"Google Transparency Report","category":"security","url":"https://transparencyreport.google.com/safe-browsing/search","description":"Safe Browsing status checks for sites and domains."},
    {"id":"securitytxt","name":"security.txt Directory","category":"security","url":"https://securitytxt.org/","description":"Reference for locating published security contact and disclosure-policy files."},
]

# Security/defensive web resources. These are launchers; they do not become evidence
# unless the user explicitly captures/saves the result in an investigation.
WEB_TOOLS.extend([
    {"id":"securityheaders","name":"Security Headers","category":"security","url":"https://securityheaders.com/","description":"Public web-response security-header checker."},
    {"id":"mozilla_observatory","name":"Mozilla Observatory","category":"security","url":"https://developer.mozilla.org/en-US/observatory","description":"Mozilla web security configuration assessment service."},
    {"id":"ssllabs","name":"Qualys SSL Labs Server Test","category":"security","url":"https://www.ssllabs.com/ssltest/","description":"Public TLS/HTTPS configuration assessment."},
    {"id":"cveorg","name":"CVE.org","category":"security","url":"https://www.cve.org/","description":"Official CVE programme and vulnerability identifiers."},
    {"id":"nvd","name":"NIST NVD","category":"security","url":"https://nvd.nist.gov/vuln/search","description":"Public vulnerability and CVSS intelligence."},
    {"id":"cisa_kev","name":"CISA Known Exploited Vulnerabilities","category":"security","url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","description":"Defensive catalogue of vulnerabilities known to be exploited in the wild."},
    {"id":"mitre_attack","name":"MITRE ATT&CK","category":"security","url":"https://attack.mitre.org/","description":"Defensive knowledge base of adversary tactics and techniques."},
    {"id":"mitre_cwe","name":"MITRE CWE","category":"security","url":"https://cwe.mitre.org/","description":"Software weakness classification and mitigation reference."},
    {"id":"osv","name":"OSV.dev","category":"security","url":"https://osv.dev/","description":"Open-source vulnerability database for software packages."},
    {"id":"depsdev","name":"deps.dev","category":"security","url":"https://deps.dev/","description":"Open dependency and package security metadata."},
    {"id":"urlscan_security","name":"urlscan.io","category":"security","url":"https://urlscan.io/","description":"Public web-scan history and page/network context."},
    {"id":"virustotal_security","name":"VirusTotal","category":"security","url":"https://www.virustotal.com/gui/home/search","description":"Defensive public reputation/context lookup for hashes, URLs, domains and IPs."},
    {"id":"abusech","name":"abuse.ch","category":"security","url":"https://abuse.ch/","description":"Public defensive threat-intelligence projects and feeds."},
    {"id":"crtsh_security","name":"crt.sh","category":"security","url":"https://crt.sh/","description":"Certificate Transparency search for attack-surface discovery."},
    {"id":"dnsviz_security","name":"DNSViz","category":"security","url":"https://dnsviz.net/","description":"DNSSEC and DNS configuration visualization."},
])

# Additional investigator/privacy/attack-surface launchers used by the web workspace.
# These remain external resources and WireSploit does not claim their results automatically.
WEB_TOOLS.extend([
    {"id":"osintframework","name":"OSINT Framework","category":"search","url":"https://osintframework.com/","description":"Directory of OSINT resources organised by investigation type."},
    {"id":"inteltechniques","name":"IntelTechniques Search Tools","category":"search","url":"https://inteltechniques.com/tools/","description":"Public search-tool collection for structured OSINT research."},
    {"id":"epieos","name":"Epieos","category":"email","url":"https://epieos.com/","description":"Free/public account and email research interface; external-service limits may apply."},
    {"id":"hibp","name":"Have I Been Pwned","category":"email","url":"https://haveibeenpwned.com/","description":"Breach-awareness lookup. Use for your own accounts or accounts you are authorized to assess; WireSploit never retrieves passwords."},
    {"id":"namechk","name":"Namechk","category":"username","url":"https://namechk.com/","description":"Public username/domain availability cross-check."},
    {"id":"builtwith","name":"BuiltWith","category":"domain","url":"https://builtwith.com/","description":"Public website technology profiling; free lookup features are available."},
    {"id":"viewdns","name":"ViewDNS.info","category":"domain","url":"https://viewdns.info/","description":"Collection of public DNS, domain and network research utilities."},
    {"id":"mxtoolbox","name":"MXToolbox","category":"domain","url":"https://mxtoolbox.com/","description":"Public DNS, mail, blacklist and network diagnostic tools."},
    {"id":"robtex","name":"Robtex","category":"domain","url":"https://www.robtex.com/","description":"Public DNS, IP, ASN and infrastructure relationship research."},
    {"id":"shodan","name":"Shodan","category":"security","url":"https://www.shodan.io/","description":"Internet-exposure search engine; free browsing/account limits may apply."},
    {"id":"censys","name":"Censys Search","category":"security","url":"https://search.censys.io/","description":"Public internet asset/certificate search; free account limits may apply."},
    {"id":"otx","name":"AlienVault OTX","category":"security","url":"https://otx.alienvault.com/","description":"Community defensive threat-intelligence and indicator research."},
    {"id":"crtmonitor","name":"Certificate Search","category":"security","url":"https://crt.sh/","description":"Certificate-transparency exploration for domains and subdomains."},
    {"id":"githubcodesearch","name":"GitHub Code Search","category":"search","url":"https://github.com/search?type=code","description":"Search public code for known identifiers, domains and exposed references."},
    {"id":"stackoverflow","name":"Stack Overflow","category":"social","url":"https://stackoverflow.com/users","description":"Public technical profiles and authored content that can provide identity/career clues."},
])
