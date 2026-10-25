import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_notes_crud():
    # Create an investigation
    resp = client.post('/api/investigations', json={'name': 'Test Investigation for Notes', 'srm_authorized': False})
    assert resp.status_code == 200
    inv = resp.json()
    iid = inv['id']

    # Add a note
    note_content = 'This is a test note.'
    resp = client.post(
        f'/api/investigations/{iid}/notes',
        data={'note': note_content}
    )
    assert resp.status_code == 200
    note_data = resp.json()
    nid = note_data['id']
    assert nid is not None

    # Get notes for the investigation
    resp = client.get(f'/api/investigations/{iid}/notes')
    assert resp.status_code == 200
    notes = resp.json()
    assert len(notes) == 1
    note = notes[0]
    assert note['id'] == nid
    assert note['investigation_id'] == iid
    assert note['note'] == note_content
    # created_at should be present
    assert 'created_at' in note

    # Update the note
    updated_note_content = 'This is an updated test note.'
    resp = client.put(
        f'/api/investigations/notes/{nid}',
        data={'note': updated_note_content}
    )
    assert resp.status_code == 200
    updated_data = resp.json()
    assert updated_data['id'] == nid

    # Get notes again to verify update
    resp = client.get(f'/api/investigations/{iid}/notes')
    assert resp.status_code == 200
    notes = resp.json()
    assert len(notes) == 1
    note = notes[0]
    assert note['note'] == updated_note_content

    # Delete the note
    resp = client.delete(f'/api/investigations/notes/{nid}')
    assert resp.status_code == 200
    deleted_data = resp.json()
    assert deleted_data['id'] == nid

    # Get notes again to verify deletion
    resp = client.get(f'/api/investigations/{iid}/notes')
    assert resp.status_code == 200
    notes = resp.json()
    assert len(notes) == 0

if __name__ == '__main__':
    test_notes_crud()
    print('All notes tests passed')