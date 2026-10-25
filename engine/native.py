from __future__ import annotations
import asyncio, hashlib, ipaddress, json, re, socket, ssl, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, urlparse

import dns.resolver
import httpx
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except ImportError:
    phonenumbers = None
    carrier = geocoder = timezone = None
from PIL import Image, ExifTags

UA={'User-Agent':'WireSploit/0.1 (local OSINT research client)'}

def _is_public_addr(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

async def _safe_get_public_host(url: str, timeout=10, max_redirects=3):
    """Fetch public HTTP(S) URLs while validating every redirect destination."""
    current = httpx.URL(url)
    for _ in range(max_redirects + 1):
        if current.scheme not in ('http', 'https') or not current.host:
            raise ValueError('Only absolute HTTP(S) URLs are permitted')
        host = current.host
        infos = await asyncio.to_thread(socket.getaddrinfo, host, current.port or (443 if current.scheme == 'https' else 80), 0, socket.SOCK_STREAM)
        addresses = {entry[4][0] for entry in infos}
        if not addresses or not all(_is_public_addr(addr) for addr in addresses):
            raise ValueError(f'Refusing to connect to non-public address for host {host}')
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=UA, verify=True) as client:
            response = await client.get(str(current))
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get('location'):
            current = current.join(response.headers['location'])
            continue
        return response
    raise ValueError('Too many redirects')


USERNAME_SITES=[
 ('GitHub','https://github.com/{u}'),('Reddit','https://www.reddit.com/user/{u}/'),('Twitch','https://www.twitch.tv/{u}'),
 ('TikTok','https://www.tiktok.com/@{u}'),('X','https://x.com/{u}'),('YouTube','https://www.youtube.com/@{u}'),('Instagram','https://www.instagram.com/{u}/'),
 ('Pinterest','https://www.pinterest.com/{u}/'),('Medium','https://medium.com/@{u}'),
 ('SoundCloud','https://soundcloud.com/{u}'),('Vimeo','https://vimeo.com/{u}'),('Behance','https://www.behance.net/{u}'),
 ('Keybase','https://keybase.io/{u}'),('GitLab','https://gitlab.com/{u}'),('Codeberg','https://codeberg.org/{u}'),
 ('HackerNews','https://news.ycombinator.com/user?id={u}'),('Steam','https://steamcommunity.com/id/{u}'),
 ('Telegram','https://t.me/{u}'),('Mastodon.social','https://mastodon.social/@{u}'),
]

async def _get(url, timeout=12, params=None, headers=None):
    async with httpx.AsyncClient(follow_redirects=True,timeout=timeout,headers={**UA,**(headers or {})}) as c:
        return await c.get(url,params=params)

async def username_lookup(query:str):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{2,64}',query):
        raise ValueError('Username must be an exact username containing letters, numbers, dot, underscore or hyphen.')
    sem=asyncio.Semaphore(6)
    async def check(name,tpl):
        url=tpl.format(u=query)
        try:
            async with sem:
                r=await _get(url,timeout=10)
            # Conservative: 200 plus no common "not found" markers in final URL/body prefix.
            text=(r.text[:5000] if 'text' in r.headers.get('content-type','') else '').lower()
            bad=('page not found','user not found','profile not found','doesn\'t exist','does not exist','nobody on reddit goes by that name')
            if r.status_code==200 and not any(x in text for x in bad):
                def meta(prop):
                    patterns=[
                        rf'<meta[^>]+(?:property|name)=["\']{re.escape(prop)}["\'][^>]+content=["\']([^"\']+)',
                        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']{re.escape(prop)}["\']'
                    ]
                    for pat in patterns:
                        m=re.search(pat,r.text,re.I)
                        if m:return m.group(1)[:1000]
                    return None
                title=None
                mt=re.search(r'<title[^>]*>(.*?)</title>',r.text,re.I|re.S)
                if mt:title=re.sub(r'\s+',' ',mt.group(1)).strip()[:500]
                ev={'exact_match':True,'http_status':r.status_code,'final_url':str(r.url),'page_title':title,'public_description':meta('og:description') or meta('description'),'public_image':meta('og:image')}
                return {'entity_key':f"username:{urlparse(str(r.url)).netloc.lower().removeprefix('www.') or name.lower()}:{query.lower()}",'platform':name,'value':query,'url':str(r.url),'source_tools':['native'],'evidence':ev}
        except Exception:
            return None
    vals=await asyncio.gather(*(check(n,t) for n,t in USERNAME_SITES))
    return [x for x in vals if x]


def phone_lookup(query:str):
    cleaned=re.sub(r'[^0-9+]','',query.strip())
    if not re.fullmatch(r'\+?\d{7,15}',cleaned): raise ValueError('Phone number must contain 7-15 digits, optionally starting with +.')
    if phonenumbers is None:
        ev={'exact_match':True,'input':query,'e164':cleaned if cleaned.startswith('+') else cleaned,'valid':'unknown','possible':'unknown','dependency_missing':'phonenumbers package','notice':'Install dependencies with SETUP_WINDOWS.ps1 for carrier/region metadata. Phone metadata is not live or precise device location.'}
        return [{'entity_key':f"phone:{ev['e164']}",'platform':'Phone metadata','value':ev['e164'],'url':None,'source_tools':['native'],'evidence':ev}]
    try: n=phonenumbers.parse(query,None if query.startswith('+') else 'GB')
    except Exception as e: raise ValueError(f'Could not parse phone number: {e}')
    typ=phonenumbers.number_type(n)
    types={v:k for k,v in vars(phonenumbers.PhoneNumberType).items() if isinstance(v,int)}
    ev={
      'exact_match':True,'valid':phonenumbers.is_valid_number(n),'possible':phonenumbers.is_possible_number(n),
      'international':phonenumbers.format_number(n,phonenumbers.PhoneNumberFormat.INTERNATIONAL),
      'e164':phonenumbers.format_number(n,phonenumbers.PhoneNumberFormat.E164),
      'country_region':phonenumbers.region_code_for_number(n),'carrier':carrier.name_for_number(n,'en'),
      'number_type':types.get(typ,str(typ)),'numbering_area':geocoder.description_for_number(n,'en'),
      'timezones':list(timezone.time_zones_for_number(n)),
      'notice':'Phone metadata indicates numbering/carrier regions only; it is not live or precise device location.'}
    return [{'entity_key':f"phone:{ev['e164']}",'platform':'Phone metadata','value':ev['e164'],'url':None,'source_tools':['native'],'evidence':ev}]


def email_lookup(query:str):
    q=query.strip().lower()
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',q): raise ValueError('Invalid email address format.')
    local,domain=q.rsplit('@',1); ev={'exact_match':True,'local_part':local,'domain':domain}
    try: ev['mx']=[str(x.exchange).rstrip('.') for x in dns.resolver.resolve(domain,'MX')]
    except Exception as e: ev['mx_error']=str(e)
    try: ev['addresses']=sorted({x[4][0] for x in socket.getaddrinfo(domain,None)})
    except Exception as e: ev['dns_error']=str(e)
    grav_hash=hashlib.md5(q.encode()).hexdigest()
    ev['gravatar_profile']=f'https://gravatar.com/{grav_hash}'
    ev['public_search_links']={
      'Google':f'https://www.google.com/search?q=%22{quote_plus(q)}%22',
      'Bing':f'https://www.bing.com/search?q=%22{quote_plus(q)}%22',
      'GitHub':f'https://github.com/search?q={quote_plus(q)}&type=code'}
    return [{'entity_key':f'email:{q}','platform':'Email/DNS','value':q,'url':None,'source_tools':['native'],'evidence':ev}]

async def ip_lookup(query:str):
    ip=str(ipaddress.ip_address(query.strip()))
    ev={'exact_match':True,'version':ipaddress.ip_address(ip).version,'is_private':ipaddress.ip_address(ip).is_private}
    try: ev['reverse_dns']=socket.gethostbyaddr(ip)[0]
    except Exception: ev['reverse_dns']=None
    if not ev['is_private']:
        try:
            r=await _get(f'https://ipwho.is/{ip}')
            d=r.json()
            if d.get('success',True):
                ev.update({k:d.get(k) for k in ['type','continent','country','country_code','region','city','latitude','longitude','postal']})
                conn=d.get('connection') or {}; ev.update({'asn':conn.get('asn'),'org':conn.get('org'),'isp':conn.get('isp'),'network_domain':conn.get('domain')})
        except Exception as e: ev['provider_error']=str(e)
    return [{'entity_key':f'ip:{ip}','platform':'IP/RDAP metadata','value':ip,'url':None,'source_tools':['native'],'evidence':ev}]


def _dns_records(domain):
    out={}
    for typ in ('A','AAAA','MX','NS','TXT','CNAME'):
        try: out[typ]=[str(x).strip('"') for x in dns.resolver.resolve(domain,typ)]
        except Exception: pass
    return out

async def domain_lookup(query:str, deep=False):
    domain=query.strip().lower().replace('http://','').replace('https://','').split('/')[0].split(':')[0]
    if not re.fullmatch(r'(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}',domain): raise ValueError('Invalid domain name.')
    ev={'exact_match':True,'dns':_dns_records(domain)}
    if deep:
        try:
            infos=socket.getaddrinfo(domain,443,0,socket.SOCK_STREAM)
            if not infos or not all(_is_public_addr(item[4][0]) for item in infos):
                raise ValueError('Refusing TLS connection to non-public address')
            ctx=ssl.create_default_context()
            with socket.create_connection((domain,443),timeout=6) as raw:
                with ctx.wrap_socket(raw,server_hostname=domain) as sock:
                    cert=sock.getpeercert()
                    ev['tls']={'issuer':dict(x[0] for x in cert.get('issuer',[])),'subject':dict(x[0] for x in cert.get('subject',[])),'notBefore':cert.get('notBefore'),'notAfter':cert.get('notAfter'),'subjectAltName':cert.get('subjectAltName',[])[:50]}
        except Exception as e: ev['tls_error']=str(e)
    try:
        r=await _get(f'https://rdap.org/domain/{domain}',timeout=15); ev['rdap']=r.json() if r.status_code==200 else {'status':r.status_code}
    except Exception as e: ev['rdap_error']=str(e)
    if deep:
        try:
            r=await _get('https://crt.sh/',params={'q':f'%.{domain}','output':'json'},timeout=20)
            if r.status_code==200:
                names=[]
                for row in r.json()[:500]: names.extend(str(row.get('name_value','')).splitlines())
                ev['certificate_names']=sorted(set(n.strip() for n in names if n.strip()))[:500]
        except Exception as e: ev['crtsh_error']=str(e)
    return [{'entity_key':f'domain:{domain}','platform':'Domain/DNS','value':domain,'url':f'https://{domain}','source_tools':['native'],'evidence':ev}]


async def geolocation_lookup(query:str):
    q=query.strip(); ev={'exact_match':True}
    m=re.fullmatch(r'\\s*(-?\\d+(?:\\.\\d+)?)\\s*,\\s*(-?\\d+(?:\\.\\d+)?)\\s*',q)
    if m:
        lat,lon=float(m.group(1)),float(m.group(2))
        if not (-90 <= lat <= 90 and -180 <= lon <= 180): raise ValueError('Coordinates must be within latitude -90..90 and longitude -180..180.')
        ev.update({'latitude':lat,'longitude':lon})
        try:
            r=await _get('https://nominatim.openstreetmap.org/reverse',params={'lat':lat,'lon':lon,'format':'jsonv2'},headers={'User-Agent':'WireSploit local app'})
            if r.status_code != 200: raise ValueError(f'Nominatim returned HTTP {r.status_code}')
            d=r.json()
            if isinstance(d,dict): ev['display_name']=d.get('display_name'); ev['address']=d.get('address')
        except Exception as e: ev['geocode_error']=str(e)
    else:
        try:
            r=await _get('https://nominatim.openstreetmap.org/search',params={'q':q,'format':'jsonv2','limit':5},headers={'User-Agent':'WireSploit local app'})
            if r.status_code != 200: return []
            vals=r.json()
            if not isinstance(vals,list) or not vals: return []
            d=vals[0]
            ev.update({'latitude':float(d['lat']),'longitude':float(d['lon']),'display_name':d.get('display_name'),'type':d.get('type'),'importance':d.get('importance')})
        except (ValueError,KeyError,TypeError): return []
    if 'latitude' not in ev or 'longitude' not in ev: return []
    lat,lon=ev['latitude'],ev['longitude']; ev['osm_url']=f'https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}'
    return [{'entity_key':f'geo:{round(lat,5)}:{round(lon,5)}','platform':'OpenStreetMap/Nominatim','value':ev.get('display_name') or q,'url':ev['osm_url'],'source_tools':['native'],'evidence':ev}]


async def archive_lookup(query:str):
    url=query.strip()
    if not re.match(r'^https?://',url): url='https://'+url
    r=await _get('https://web.archive.org/cdx/search/cdx',params={'url':url,'output':'json','fl':'timestamp,original,statuscode,digest','filter':'statuscode:200','collapse':'digest','limit':'100'},timeout=20)
    vals=r.json() if r.status_code==200 else []
    findings=[]
    if vals and isinstance(vals,list):
        rows=vals[1:] if vals and vals[0] and vals[0][0]=='timestamp' else vals
        for row in rows[:100]:
            ts,orig,status,digest=row[:4]; snap=f'https://web.archive.org/web/{ts}/{orig}'
            findings.append({'entity_key':f'archive:{digest}:{ts}','platform':'Wayback Machine','value':ts,'url':snap,'source_tools':['native'],'evidence':{'exact_match':True,'timestamp':ts,'original':orig,'status':status,'digest':digest}})
    return findings

async def technical_lookup(query:str, active_authorized=False):
    # Passive metadata is always safe to collect; active HTTP checks require a saved scope.
    base=await domain_lookup(query,deep=False)
    f=base[0]; f['platform']='Technical OSINT'; f['entity_key']='technical:'+f['value']
    if active_authorized:
        from . import security
        if not security.is_authorized(query):
            f['evidence']['authorized_active_checks_skipped']='Target is not in a saved authorized scope.'
        else:
            d=f['value']; checks={}
            try:
                r=await _safe_get_public_host(f'https://{d}',timeout=10)
                checks['https_status']=r.status_code; checks['final_url']=str(r.url); checks['server']=r.headers.get('server')
            except Exception as e: checks['https_error']=str(e)
            f['evidence']['authorized_active_checks']=checks
    return [f]


def public_records_lookup(query: str):
    q=query.strip()
    if not q or len(q)>200: raise ValueError('Enter a public-records search term.')
    enc=quote_plus(q)
    links={
      'UK Companies House':f'https://find-and-update.company-information.service.gov.uk/search?q={enc}',
      'OpenCorporates':f'https://opencorporates.com/companies?q={enc}',
      'SEC EDGAR':f'https://www.sec.gov/edgar/search/#/q={enc}',
      'The Gazette':f'https://www.thegazette.co.uk/all-notices/notice?text={enc}',
      'Wikidata':f'https://www.wikidata.org/w/index.php?search={enc}',
    }
    return [{'entity_key':'public_records:'+hashlib.sha1(q.lower().encode()).hexdigest(),'platform':'Public-records search','value':q,'url':links['UK Companies House'],'source_tools':['native'],'evidence':{'exact_match':True,'links':links,'notice':'These links search public registries/knowledge bases; matching names alone do not prove identity.'}}]


def search_links(query:str, options:dict|None=None):
    o=options or {}; terms=[]
    if o.get('exact',True): terms.append(f'"{query}"')
    else: terms.append(query)
    if o.get('site'): terms.append('site:'+o['site'])
    if o.get('filetype'): terms.append('filetype:'+o['filetype'])
    q=' '.join(terms)
    return [{'entity_key':'search:'+hashlib.sha1(q.encode()).hexdigest(),'platform':'Search query builder','value':q,'url':f'https://www.google.com/search?q={quote_plus(q)}','source_tools':['native'],'evidence':{'exact_match':True,'query':q,'links':{'Google':f'https://www.google.com/search?q={quote_plus(q)}','Bing':f'https://www.bing.com/search?q={quote_plus(q)}','DuckDuckGo':f'https://duckduckgo.com/?q={quote_plus(q)}'}}}]


def _image_perceptual_hash(im:Image.Image, size=8):
    g=im.convert('L').resize((size,size))
    vals=list(g.get_flattened_data()) if hasattr(g,'get_flattened_data') else list(g.getdata()); avg=sum(vals)/len(vals)
    bits=''.join('1' if x>=avg else '0' for x in vals)
    return f'{int(bits,2):0{size*size//4}x}'


def _office_core_metadata(path:Path):
    out={}
    try:
        with zipfile.ZipFile(path) as z:
            if 'docProps/core.xml' not in z.namelist(): return out
            root=ET.fromstring(z.read('docProps/core.xml'))
            for el in root.iter():
                tag=el.tag.split('}')[-1]
                if el.text and tag in {'title','subject','creator','keywords','description','lastModifiedBy','revision','created','modified','category','contentStatus'}:
                    out[tag]=el.text[:1000]
    except Exception:
        pass
    return out


def analyze_file(path:Path):
    data=path.read_bytes(); suffix=path.suffix.lower()
    ev={'exact_match':True,'filename':path.name,'size_bytes':len(data),'extension':suffix,'sha256':hashlib.sha256(data).hexdigest(),'sha1':hashlib.sha1(data).hexdigest(),'md5':hashlib.md5(data).hexdigest()}
    if suffix=='.pdf':
        try:
            from pypdf import PdfReader
            reader=PdfReader(str(path)); md=reader.metadata or {}
            ev['pdf']={'pages':len(reader.pages),'metadata':{str(k).lstrip('/'):str(v)[:1500] for k,v in md.items()}}
        except Exception as e: ev['pdf_error']=str(e)
    if suffix in {'.docx','.xlsx','.pptx','.odt','.ods','.odp'}:
        meta=_office_core_metadata(path)
        if meta: ev['office_metadata']=meta
    try:
        with Image.open(path) as im:
            ev.update({'image_format':im.format,'width':im.width,'height':im.height,'mode':im.mode})
            ex={}
            raw=im.getexif()
            for k,v in raw.items(): ex[ExifTags.TAGS.get(k,str(k))]=str(v)[:500]
            ev['exif']=ex
            ev['perceptual_hash']=_image_perceptual_hash(im)
            thumb=im.convert('RGB').resize((1,1)); ev['average_rgb']=list(thumb.getpixel((0,0)))
            try:
                import pytesseract
                text=pytesseract.image_to_string(im,timeout=15).strip()
                if text: ev['ocr_text']=text[:10000]
                else: ev['ocr_text']=''
            except Exception as e:
                ev['ocr_status']=f'Optional Tesseract OCR unavailable: {e}'[:500]
    except Exception: pass
    return {'entity_key':f"file:{ev['sha256']}",'platform':'Local file analysis','value':path.name,'url':None,'source_tools':['native'],'evidence':ev}
