import io
import json
import csv
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def setup_investigation():
    # Create an investigation
    resp = client.post('/api/investigations', json={'name': 'Test Investigation for Export', 'srm_authorized': False})
    assert resp.status_code == 200
    inv = resp.json()
    iid = inv['id']
    return iid

def add_inputs(iid):
    # Add two inputs: a username and an email
    client.post(f'/api/investigations/{iid}/inputs', json={'kind': 'username', 'value': 'testuser'})
    client.post(f'/api/investigations/{iid}/inputs', json={'kind': 'email', 'value': 'test@example.com'})

def add_findings(iid):
    # We need to add a run and then a finding.
    # First, start a run to get a run ID.
    resp = client.post(f'/api/investigations/{iid}/start')
    assert resp.status_code == 200
    run = resp.json()
    rid = run['id']
    # For simplicity, we'll directly insert a finding via the store?
    # But we don't have direct access to store in the test. We'll use the engine?
    # Instead, we can simulate a finding by using the internal endpoint? There's no endpoint to add findings directly.
    # Findings are added by the engine during a run. We'll need to mock or we can add a finding via the store module directly.
    # Since we are in the test, we can import store and use it.
    from engine import store
    # Create a finding manually
    finding_id = str(store.uuid.uuid4())
    now = store.now()
    with store.connect() as c:
        c.execute('INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                  (finding_id, rid, 'test_category', 'test_provider', 'test_key', 'test_value', 'http://example.com', 0.9, 1, '{}', now))
    return rid

def add_evidence(iid):
    from engine import store
    # Add evidence with a file
    content = b'Test evidence content'
    eid = store.add_evidence(iid, 'test', 'Test Evidence', 'source', 'description', content_bytes=content, filename='test.txt')
    return eid

def test_json_export():
    iid = setup_investigation()
    add_inputs(iid)
    rid = add_findings(iid)
    add_evidence(iid)

    resp = client.get(f'/api/investigations/{iid}/export/json')
    assert resp.status_code == 200
    assert resp.headers['content-type'] == 'application/json'
    # Check that the content is valid JSON and contains expected fields
    data = resp.json()
    assert 'id' in data
    assert data['id'] == iid
    assert 'name' in data
    assert data['name'] == 'Test Investigation for Export'
    assert 'inputs' in data
    assert len(data['inputs']) == 2
    assert 'runs' in data
    assert len(data['runs']) == 1
    assert data['runs'][0]['id'] == rid
    assert 'findings' in data
    assert len(data['findings']) == 1
    assert data['findings'][0]['category'] == 'test_category'
    assert 'evidence' in data
    assert len(data['evidence']) == 1
    assert data['evidence'][0]['title'] == 'Test Evidence'

def test_csv_export():
    iid = setup_investigation()
    add_inputs(iid)
    rid = add_findings(iid)
    add_evidence(iid)

    resp = client.get(f'/api/investigations/{iid}/export/csv')
    assert resp.status_code == 200
    assert resp.headers['content-type'].startswith('text/csv')
    # Check that we get CSV content
    content = resp.content.decode('utf-8')
    # Parse CSV
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    # We expect at least one row (the finding)
    assert len(rows) >= 1
    # Check that the row has the expected columns
    assert 'category' in rows[0]
    assert rows[0]['category'] == 'test_category'

def test_html_export():
    iid = setup_investigation()
    add_inputs(iid)
    rid = add_findings(iid)
    add_evidence(iid)

    resp = client.get(f'/api/investigations/{iid}/export/html')
    assert resp.status_code == 200
    assert resp.headers['content-type'].startswith('text/html')
    content = resp.content.decode('utf-8')
    assert '<html>' in content
    assert 'Investigation Report' in content
    assert iid in content
    assert 'Test Investigation for Export' in content

def test_pdf_export():
    iid = setup_investigation()
    add_inputs(iid)
    rid = add_findings(iid)
    add_evidence(iid)

    resp = client.get(f'/api/investigations/{iid}/export/pdf')
    assert resp.status_code == 200
    assert resp.headers['content-type'] == 'application/pdf'
    # Check that we get a PDF file (starts with %PDF)
    content = resp.content
    assert content[:4] == b'%PDF'

def test_graph_export():
    iid = setup_investigation()
    add_inputs(iid)
    rid = add_findings(iid)
    add_evidence(iid)

    resp = client.get(f'/api/investigations/{iid}/graph')
    assert resp.status_code == 200
    assert resp.headers['content-type'] == 'application/json'
    data = resp.json()
    assert 'nodes' in data
    assert 'edges' in data
    assert len(data['nodes']) == 6
    assert len(data['edges']) == 5


if __name__ == '__main__':
    test_json_export()
    test_csv_export()
    test_html_export()
    test_pdf_export()
    print('All export tests passed')