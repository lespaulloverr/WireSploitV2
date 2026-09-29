from fastapi import FastAPI,HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
import asyncio,platform,sys
from engine import store,engine,tooling
ROOT=Path(__file__).resolve().parent; WEB=ROOT/'web'; store.init()
app=FastAPI(title='WireSploit',version='4.0.0')
app.mount('/static',StaticFiles(directory=WEB),name='static')
class Inv(BaseModel): name:str='New Investigation'; srm_authorized:bool=False
class Input(BaseModel): kind:str='auto'; value:str
class Evidence(BaseModel): kind:str='finding'; title:str; source:str=''; url:str=''; description:str=''
@app.get('/')
def home():return FileResponse(WEB/'index.html')
@app.get('/api/health')
def health():return {'ok':True,'version':'4.0.0','python':sys.version.split()[0],'platform':platform.platform(),'providers':len(tooling.SPECS)}
@app.get('/api/investigations')
def investigations():return store.list_investigations()
@app.post('/api/investigations')
def create(x:Inv):return store.create_investigation(x.name,x.srm_authorized)
@app.get('/api/investigations/{iid}')
def get(iid):
 x=store.get_investigation(iid)
 if not x:raise HTTPException(404,'Investigation not found')
 runs=store.rows('SELECT * FROM runs WHERE investigation_id=? ORDER BY started_at DESC',(iid,)); x['runs']=[dict(r) for r in runs]; x['findings']=store.findings_for(iid); x['evidence']=store.evidence_for(iid); return x
@app.post('/api/investigations/{iid}/inputs')
def add_input(iid,x:Input):
 if not store.get_investigation(iid):raise HTTPException(404,'Investigation not found')
 return {'id':store.add_input(iid,x.kind if x.kind!='auto' else engine.classify(x.value),x.value)}
@app.post('/api/investigations/{iid}/start')
async def start(iid):
 inv=store.get_investigation(iid)
 if not inv:raise HTTPException(404,'Investigation not found')
 if not inv['inputs']:raise HTTPException(400,'Add at least one target before starting.')
 active=store.row("SELECT id FROM runs WHERE investigation_id=? AND status IN ('queued','running') ORDER BY started_at DESC",(iid,))
 if active:return store.get_run(active['id'])
 rid=store.create_run(iid,8); engine.launch(rid,iid); return store.get_run(rid)
@app.get('/api/runs/{rid}')
def run(rid):
 x=store.get_run(rid)
 if not x:raise HTTPException(404,'Run not found')
 return x
@app.post('/api/investigations/{iid}/evidence')
def evidence(iid,x:Evidence):
 if not store.get_investigation(iid):raise HTTPException(404,'Investigation not found')
 return {'id':store.add_evidence(iid,x.kind,x.title,x.source,x.url,x.description)}
@app.get('/api/tools')
def tools():return tooling.list_tools()
@app.get('/api/diagnostics')
def diagnostics():
 ts=tooling.list_tools();return {'system':platform.platform(),'python':sys.version,'registered':len(ts),'ready':sum(t.get('diagnostic',{}).get('status')=='ready' for t in ts),'tools':ts}
