import asyncio,re,time,traceback
from . import store, native, tooling
EMAIL=re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I); DOMAIN=re.compile(r'(?<!@)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b',re.I); USER=re.compile(r'(?<![\w@])@([A-Za-z0-9][A-Za-z0-9_.-]{2,31})')

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
  if cat=='domain':return await native.domain_lookup(target,deep=True)
  if cat=='geolocation':return await native.geolocation_lookup(target)
  if cat=='archives':return await native.archive_lookup(target)
  if cat=='public_records':return native.public_records_lookup(target)
  if cat=='search':return native.search_links(target,{})
  if cat=='technical':return await native.technical_lookup(target,True)
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
 seen=set()
 for k,v in out:
  key=(k,v.lower())
  if key not in seen:seen.add(key);yield k,v

async def run(rid,iid):
 inv=store.get_investigation(iid); store.set_status(iid,'running'); store.update_run(rid,status='running')
 for x in inv['inputs']:store.add_identifier(iid,classify(x['value']),x['value'],0)
 srm=inv['srm_authorized']; total=0
 try:
  for stage in range(8):
   store.update_run(rid,stage=stage,current='Selecting research targets')
   qs=store.queued_identifiers(iid,stage)
   if not qs:break
   store.event(rid,'info',f'Stage {stage+1}: {len(qs)} identifier(s) queued')
   for ident in qs:
    store.mark_identifier(ident['id'],'running')
    for cat in cats(ident['kind'],srm):
     pids=['native']
     # Ready optional CLI tools are additive, never required for the core engine.
     for spec in tooling.SPECS:
      if spec.id!='native' and spec.automated and cat in spec.categories and (not spec.authorized_only or srm):
       try:
        if tooling.diagnose(spec.id).get('status')=='ready':pids.append(spec.id)
       except:pass
     for pid in dict.fromkeys(pids):
      store.update_run(rid,current=f'{cat} · {pid}'); jid=store.add_job(rid,cat,ident['value'],pid); store.job_update(jid,status='running',started_at=store.now()); store.event(rid,'info',f'Running {pid} for {ident["value"]}',{'category':cat,'provider':pid})
      try:
       res=await asyncio.wait_for(provider(pid,cat,ident['value'],srm),timeout=95)
       for f in res:
        store.add_finding(rid,cat,pid,f)
        for k,v in discover(f): store.add_identifier(iid,k,v,stage+1)
       store.job_update(jid,status='complete',message=f'{len(res)} finding(s)',finished_at=store.now())
      except asyncio.TimeoutError:store.job_update(jid,status='timeout',message='Provider timed out',finished_at=store.now());store.event(rid,'warn',f'{pid} timed out',{'category':cat})
      except FileNotFoundError as e:store.job_update(jid,status='unavailable',message=str(e),finished_at=store.now())
      except Exception as e:store.job_update(jid,status='error',message=str(e)[:500],finished_at=store.now());store.event(rid,'error',f'{pid} failed: {str(e)[:300]}',{'category':cat})
    store.mark_identifier(ident['id'],'complete')
   total+=1
  store.update_run(rid,status='complete',current='Investigation complete',finished_at=store.now());store.set_status(iid,'complete');store.event(rid,'success','Investigation completed')
 except Exception as e:
  store.update_run(rid,status='error',error=str(e)[:1000],finished_at=store.now());store.set_status(iid,'error');store.event(rid,'error','Investigation engine failed',{'error':str(e),'trace':traceback.format_exc()})


def launch(rid,iid):
 import threading,asyncio
 def worker(): asyncio.run(run(rid,iid))
 threading.Thread(target=worker,name='wiresploit-run-'+rid[:8],daemon=True).start()
