# Providers and Integrations

WireSploit V4 has two broad integration layers.

## Built-in providers

These are Python application integrations that can run without installing a separate CLI tool. The current source includes providers for areas such as:

- username/social lookup
- email handling and public-source lookups
- phone parsing and metadata
- IP validation, reverse DNS and public metadata
- DNS
- TLS/certificate information
- RDAP
- geolocation/public map data
- Wayback/CDX
- public search-link generation

Web adapters in the current source also cover services including GitHub, GitLab, Reddit, Hacker News, Bluesky, WhatsMyName, Gravatar, RDAP, IPQuery, crt.sh, Google DNS, Cloudflare DNS, Wayback, Common Crawl, Open-Meteo, OpenStreetMap Overpass, Wikipedia geosearch, Wikidata and OpenAlex.

Availability and behaviour depend on the remote service and its current response/API rules.

## Optional external tools

The V4 registry contains 94 tool definitions in the supplied source. Examples include Sherlock, GhostTrack, Maigret, Phunter, PhoneInfoga, GHunt, Amass, theHarvester, Subfinder, Assetfinder, Waymore, gau, yt-dlp, gallery-dl, SpiderFoot, ExifTool, Tesseract, MediaInfo, oletools, FFprobe, ImageMagick and Poppler.

**Important:** 94 registered tools does not mean 94 installed or working tools. Diagnostics inspect the current machine. The supplied V4 verification environment reported 27 ready integrations.

## Adding an integration

A new integration should include:

- a unique ID;
- a human-readable name;
- category/tags;
- installation information if it is external;
- a diagnostic command that can verify availability;
- clear authorisation expectations;
- failure handling;
- documentation and tests where practical.

Do not hard-code a tool as available simply because its entry exists in the catalogue.
