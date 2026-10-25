import io
import hashlib
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_evidence_upload_and_retrieval():
    # Create an investigation
    resp = client.post('/api/investigations', json={'name': 'Test Investigation', 'srm_authorized': False})
    assert resp.status_code == 200
    inv = resp.json()
    iid = inv['id']

    # Prepare a file to upload
    file_content = b'This is a test file content.'
    file_hash = hashlib.sha256(file_content).hexdigest()

    # Upload the file as evidence
    resp = client.post(
        f'/api/investigations/{iid}/evidence/upload',
        files={'file': ('test.txt', file_content, 'text/plain')},
        data={'kind': 'file', 'title': 'Test File', 'source': 'upload', 'description': 'A test file'}
    )
    assert resp.status_code == 200
    data = resp.json()
    eid = data['id']

    # Check that the evidence record exists and has correct metadata
    # We can get the evidence list for the investigation
    resp = client.get(f'/api/investigations/{iid}')
    assert resp.status_code == 200
    inv_data = resp.json()
    evidence_list = inv_data['evidence']
    assert len(evidence_list) == 1
    evidence = evidence_list[0]
    assert evidence['id'] == eid
    assert evidence['kind'] == 'file'
    assert evidence['title'] == 'Test File'
    assert evidence['source'] == 'upload'
    assert evidence['description'] == 'A test file'
    assert evidence['url'] is not None  # stored filename
    assert evidence['sha256'] == file_hash

    # Retrieve the file via the evidence endpoint
    resp = client.get(f'/api/evidence/{eid}')
    assert resp.status_code == 200
    # Check that the content matches
    assert resp.content == file_content
    # Check that the filename is set in the Content-Disposition header
    # Actually, FileResponse sets the filename in the Content-Disposition header as attachment; filename=...
    # We can check the headers
    assert 'content-disposition' in resp.headers
    # The header should contain the filename
    disposition = resp.headers['content-disposition']
    assert 'filename=' in disposition
    # Check that the filename in Content-Disposition is the original filename (test.txt)
    assert f'filename="test.txt"' in disposition or f'filename=test.txt' in disposition

    # Also test that retrieving a non-existent evidence returns 404
    resp = client.get('/api/evidence/00000000-0000-0000-0000-000000000000')
    assert resp.status_code == 404

if __name__ == '__main__':
    test_evidence_upload_and_retrieval()
    print('All tests passed')