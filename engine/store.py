import sqlite3, uuid, json, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; DB=ROOT/'data'/'wiresploit.sqlite3'

def now(): return datetime.now(timezone.utc).isoformat()
def connect():
 c=sqlite3.connect(DB, timeout=20); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init():
 DB.parent.mkdir(parents=True,exist_ok=True)
 with connect() as c:
  c.executescript('''
  CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,srm_authorized INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS inputs(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,normalized TEXT NOT NULL,source TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
  CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,status TEXT NOT NULL,stage INTEGER NOT NULL DEFAULT 0,total_stages INTEGER NOT NULL DEFAULT 0,current TEXT,started_at TEXT NOT NULL,finished_at TEXT,error TEXT,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
  CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,category TEXT NOT NULL,target TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL,message TEXT,started_at TEXT,finished_at TEXT,FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
  CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,category TEXT NOT NULL,provider TEXT NOT NULL,entity_key TEXT NOT NULL,value TEXT,url TEXT,confidence REAL NOT NULL DEFAULT .5,exact_match INTEGER NOT NULL DEFAULT 1,evidence_json TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(run_id,entity_key,provider),FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
  CREATE TABLE IF NOT EXISTS identifiers(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,normalized TEXT NOT NULL,status TEXT NOT NULL,stage INTEGER NOT NULL,UNIQUE(investigation_id,kind,normalized),FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
  CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT NOT NULL,level TEXT NOT NULL,message TEXT NOT NULL,meta_json TEXT,created_at TEXT NOT NULL,FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE);
  CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,investigation_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,source TEXT,url TEXT,description TEXT,sha256 TEXT,created_at TEXT NOT NULL,FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE);
  CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id); CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
  ''')

def row(q,args=()):
 with connect() as c: return c.execute(q,args).fetchone()
def rows(q,args=()):
 with connect() as c: return c.execute(q,args).fetchall()
def create_investigation(name,srm=False):
 i=str(uuid.uuid4()); t=now();
 with connect() as c:c.execute('INSERT INTO investigations VALUES(?,?,?,?,?,?)',(i,name.strip() or 'Untitled investigation','ready',t,t,int(srm)))
 return get_investigation(i)
def get_investigation(i):
 r=row('SELECT * FROM investigations WHERE id=?',(i,));
 if not r:return None
 d=dict(r); d['srm_authorized']=bool(d['srm_authorized']); d['inputs']=[dict(x) for x in rows('SELECT * FROM inputs WHERE investigation_id=? ORDER BY created_at',(i,))]; return d
def list_investigations():
 return [dict(r) for r in rows('SELECT * FROM investigations ORDER BY updated_at DESC')]
def add_input(i,kind,value):
 n=' '.join(value.strip().lower().split()); iid=str(uuid.uuid4())
 with connect() as c:c.execute('INSERT OR IGNORE INTO inputs VALUES(?,?,?,?,?,?,?)',(iid,i,kind,value.strip(),n,'user',now()))
 return iid
def set_status(i,status):
 with connect() as c:c.execute('UPDATE investigations SET status=?,updated_at=? WHERE id=?',(status,now(),i))
def create_run(i,total):
 rid=str(uuid.uuid4());
 with connect() as c:c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?)',(rid,i,'queued',0,total,'',now(),None,None))
 return rid
def update_run(rid,**kw):
 if not kw:return
 fields=[];vals=[]
 for k,v in kw.items():fields.append(k+'=?');vals.append(v)
 vals.append(rid)
 with connect() as c:c.execute('UPDATE runs SET '+','.join(fields)+' WHERE id=?',vals)
def get_run(rid):
 r=row('SELECT * FROM runs WHERE id=?',(rid,));
 if not r:return None
 d=dict(r); d['jobs']=[dict(x) for x in rows('SELECT * FROM jobs WHERE run_id=? ORDER BY started_at IS NULL, started_at',(rid,))]; d['findings_count']=row('SELECT COUNT(*) n FROM findings WHERE run_id=?',(rid,))['n']; d['events']=[dict(x) for x in rows('SELECT * FROM events WHERE run_id=? ORDER BY id',(rid,))]; return d
def add_job(rid,cat,target,provider):
 jid=str(uuid.uuid4());
 with connect() as c:c.execute('INSERT INTO jobs(id,run_id,category,target,provider,status) VALUES(?,?,?,?,?,?)',(jid,rid,cat,target,provider,'queued'))
 return jid
def job_update(jid,**kw):
 fields=[];vals=[]
 for k,v in kw.items():fields.append(k+'=?');vals.append(v)
 vals.append(jid)
 with connect() as c:c.execute('UPDATE jobs SET '+','.join(fields)+' WHERE id=?',vals)
def event(rid,level,msg,meta=None):
 with connect() as c:c.execute('INSERT INTO events(run_id,level,message,meta_json,created_at) VALUES(?,?,?,?,?)',(rid,level,msg,json.dumps(meta or {}),now()))
def add_identifier(i,kind,value,stage):
 n=' '.join(value.strip().lower().split());
 with connect() as c:
  before=c.total_changes;c.execute('INSERT OR IGNORE INTO identifiers VALUES(?,?,?,?,?,?,?)',(str(uuid.uuid4()),i,kind,value.strip(),n,'queued',stage)); return c.total_changes>before
def queued_identifiers(i,stage):
 return [dict(r) for r in rows('SELECT * FROM identifiers WHERE investigation_id=? AND status="queued" AND stage<=? ORDER BY stage,id',(i,stage))]
def mark_identifier(iid,status):
 with connect() as c:c.execute('UPDATE identifiers SET status=? WHERE id=?',(status,iid))
def add_finding(rid,cat,provider,f):
 eid=f.get('entity_key') or hashlib.sha1((cat+'|'+str(f.get('value',''))).encode()).hexdigest(); fid=str(uuid.uuid4());
 with connect() as c:c.execute('INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)',(fid,rid,cat,provider,eid,str(f.get('value','')),f.get('url'),float(f.get('confidence',.55)),int(bool((f.get('evidence') or {}).get('exact_match',True))),json.dumps(f.get('evidence') or {}),now()))
def findings_for(i):
 return [dict(r) for r in rows('SELECT f.* FROM findings f JOIN runs r ON r.id=f.run_id WHERE r.investigation_id=? ORDER BY f.created_at',(i,))]
def add_evidence(i,kind,title,source,url,description):
 eid=str(uuid.uuid4());
 with connect() as c:c.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)',(eid,i,kind,title,source,url,description,None,now()))
 return eid
def evidence_for(i):return [dict(r) for r in rows('SELECT * FROM evidence WHERE investigation_id=? ORDER BY created_at DESC',(i,))]
