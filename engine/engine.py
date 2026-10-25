import asyncio,re,time,traceback
from . import store, native, tooling, security
EMAIL=re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I); DOMAIN=re.compile(r'(?<!@)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b',re.I); USER=re.compile(r'(?<![\w@])@([A-Za-z0-9][A-Za-z0-9_.-]{2,31})'); CVE=re.compile(r'\bCVE-\d{4}-\d{4,}\b',re.I)

def classify(v):
 s=v.strip();
 if EMAIL.fullmatch(s):return 'email'
 if re.fullmatch(r'(?:https?://)?(?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/.*)?',s,re.I):return 'domain'
 try:
  import ipaddress; ipaddress.ip_address(s); return 'ip'
 except: pass
 if USER.fullmatch(s):return 'username'
 if sum(c.isdigit() for c in s)>=9 and re.fullmatch(r'[+0-9 ()().-]+',s):return 'phone'
 return 'search'

def cats(kind,srm):
 m={'username':['username','social','search','archives'],'email':['email','social','search','archives','public_records'],'phone':['phone','search','geolocation','public_records'],'domain':['domain','archives','search','public_records'],'ip':['ip','geolocation','search','archives'],'search':['search','social','public_records','archives']}
 out=list(dict.fromkeys(m.get(kind,['search','public_records','archives'])))
 if srm and kind in {'domain','ip'}: out.append('technical')
 return out

async def provider(pid,cat,target,srm):
 if pid=='native':
  if cat in ('username','social'):return await native.username_lookup(target)
  if cat=='email':return await native.email_lookup(target)
  if cat=='phone':return native.phone_lookup(target)
  if cat=='ip':return await native.ip_lookup(target)
  if cat=='domain':return await native.domain_lookup(target,deep=bool(srm and security.is_authorized(target)))
  if cat=='geolocation':return await native.geolocation_lookup(target)
  if cat=='archives':return await native.archive_lookup(target)
  if cat=='public_records':return native.public_records_lookup(target)
  if cat=='search':return native.search_links(target,{})
  if cat=='technical':return await native.technical_lookup(target,srm)
  return []
 spec=tooling.SPEC_BY_ID.get(pid)
 if not spec: return []
 if spec.kind=='web': return await tooling.web_providers.run(pid,target,cat)
 cmd=tooling.tool_command(pid,target,cat)
 if not cmd: raise FileNotFoundError(f'{spec.name} is not installed or ready')
 if len(cmd)==3:cw,wd,stdin=cmd
 else:cw,wd=cmd;stdin=None
 code,out,err=await tooling.run_subprocess(cw,wd,timeout=90,stdin_text=stdin)
 if code!=0 and not out:raise RuntimeError(err or f'exit code {code}')
 if cat in ('username','social','email') and pid in ('sherlock','maigret','blackbird','gosherlock','socialanalyzer'):return tooling.parse_username_output(pid,target,out,cat)
 if pid in ('subfinder','assetfinder','amass','theharvester','waymore','gau','waybackurls','findomain'):return tooling.parse_domain_lines(pid,target,out,cat)
 return tooling.parse_kv_output(pid,target,out,cat)

def discover(f):
 raw=' '.join(str(f.get(k,'')) for k in ('value','url','platform'))+' '+str(f.get('evidence',{})); out=[]
 for x in EMAIL.findall(raw):out.append(('email',x))
 for x in USER.findall(raw):out.append(('username',x))
 for x in DOMAIN.findall(raw):out.append(('domain',x))
 for x in CVE.findall(raw):out.append(('search',x.upper()))
 seen=set()
 for k,v in out:
  key=(k,v.lower())
  if key not in seen:seen.add(key);yield k,v

async def run(rid,iid):
 try:
  inv=store.get_investigation(iid)
  if inv is None:
   store.update_run(rid,status='error',error='Investigation not found',finished_at=store.now()); return
  store.set_status(iid,'running'); store.update_run(rid,status='running')
  # Requeue only original user inputs. Previously discovered identifiers/findings remain historical.
  for x in inv['inputs']:
   kind=x['kind'] or classify(x['value'])
   store.requeue_identifier(iid,kind,x['value'],0)
  srm=bool(inv['srm_authorized']); total=0; max_jobs=200; job_count=0
  for stage in range(8):
   store.update_run(rid,stage=stage,current='Selecting research targets')
   qs=store.queued_identifiers(iid,stage)
   if not qs: break
   store.event(rid,'info',f'Stage {stage+1}: {len(qs)} identifier(s) queued')
   for ident in qs:
    store.mark_identifier(ident['id'],'running')
    seen=set()
    for cat in cats(ident['kind'],srm):
     pids=['native']
     for spec in tooling.SPECS:
      if spec.id=='native' or not spec.automated or cat not in spec.categories: continue
      if spec.authorized_only and not srm: continue
      if spec.deep_only and not srm: continue
      # Keep geolocation providers that expect place names away from IP targets.
      if cat=='geolocation' and ident['kind']=='ip' and spec.id in {'overpass_public','wikipedia_geo_public'}: continue
      key=(spec.id,cat)
      if key in seen: continue
      seen.add(key)
      try:
       if tooling.diagnose(spec.id).get('status')=='ready': pids.append(spec.id)
      except Exception: pass
     for pid in dict.fromkeys(pids):
      if job_count >= max_jobs:
       store.event(rid,'warn',f'Job safety cap ({max_jobs}) reached; stopping additional provider work.')
       break
      job_count+=1
      store.update_run(rid,current=f'{cat} · {pid}')
      jid=store.add_job(rid,cat,ident['value'],pid); store.job_update(jid,status='running',started_at=store.now())
      store.event(rid,'info',f'Running {pid} for {ident["value"]}',{'category':cat,'provider':pid})
      try:
       res=await asyncio.wait_for(provider(pid,cat,ident['value'],srm),timeout=95)
       for f in res:
        store.add_finding(rid,cat,pid,f)
        for k,v in discover(f): store.add_identifier(iid,k,v,stage+1)
       store.job_update(jid,status='complete',message=f'{len(res)} finding(s)',finished_at=store.now())
      except asyncio.TimeoutError: store.job_update(jid,status='timeout',message='Provider timed out',finished_at=store.now()); store.event(rid,'warn',f'{pid} timed out',{'category':cat})
      except FileNotFoundError as e: store.job_update(jid,status='unavailable',message=str(e),finished_at=store.now())
      except Exception as e: store.job_update(jid,status='error',message=str(e)[:500],finished_at=store.now()); store.event(rid,'error',f'{pid} failed: {str(e)[:300]}',{'category':cat})
     if job_count >= max_jobs: break
    store.mark_identifier(ident['id'],'complete')
    if job_count >= max_jobs: break
   total+=1
   if job_count >= max_jobs: break
  store.update_run(rid,status='complete',stage=8,current='Investigation complete',finished_at=store.now());store.set_status(iid,'complete');store.event(rid,'success',f'Investigation completed ({job_count} jobs)')
 except Exception as e:
  try:
   store.update_run(rid,status='error',error=str(e),finished_at=store.now());store.set_status(iid,'error');store.event(rid,'error','Investigation engine failed',{'error':str(e),'trace':traceback.format_exc()})
  except Exception as inner:
   import sys
   print(f'[engine] CRITICAL: run {rid} failed and could not record failure: {inner}',file=sys.stderr)


def launch(rid,iid):
 import threading,asyncio
 def worker(): asyncio.run(run(rid,iid))
 threading.Thread(target=worker,name='wiresploit-run-'+rid[:8],daemon=True).start()