import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from main import app,store

def test_health():
 r=TestClient(app).get('/api/health');assert r.status_code==200 and r.json()['version']=='4.0.0'
def test_static():
 c=TestClient(app);assert c.get('/').status_code==200;assert c.get('/static/app.js').status_code==200;assert c.get('/static/styles.css').status_code==200
def test_investigation_start_and_poll(monkeypatch):
 monkeypatch.setattr('engine.engine.provider', lambda *a,**k: __import__('asyncio').sleep(0, result=[{'entity_key':'mock:test','platform':'Mock','value':'test@example.com','url':'https://example.com','source_tools':['mock'],'evidence':{'exact_match':True}}]))
 c=TestClient(app); inv=c.post('/api/investigations',json={'name':'Smoke','srm_authorized':False}).json(); assert c.post(f"/api/investigations/{inv['id']}/inputs",json={'kind':'email','value':'test@example.com'}).status_code==200
 r=c.post(f"/api/investigations/{inv['id']}/start");assert r.status_code==200;rid=r.json()['id']; import time
 for _ in range(100):
  x=c.get(f'/api/runs/{rid}').json()
  if x['status'] in ('complete','error'):break
  time.sleep(.05)
 assert x['status']=='complete',x
