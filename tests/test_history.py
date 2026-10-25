import sys
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Set environment variable for test database before importing the app
temp_db = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
temp_db.close()
os.environ['WIRESPOOL_DB'] = temp_db.name

sys.path.append(str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from engine import store

store.init()

client = TestClient(app)


def clear_history_table():
    """Clear the search_history table for test isolation."""
    with store.connect() as c:
        c.execute('DELETE FROM search_history')


def test_add_and_list_history():
    """Test adding and listing history entries."""
    clear_history_table()

    # Add a history entry
    resp = client.post(
        '/api/history',
        json={'query': 'test search', 'kind': 'search'}
    )
    assert resp.status_code == 200
    data = resp.json()
    hid = data['id']
    assert hid is not None

    # List history
    resp = client.get('/api/history')
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == 1
    assert history[0]['id'] == hid
    assert history[0]['query'] == 'test search'
    assert history[0]['kind'] == 'search'
    assert 'created_at' in history[0]


def test_history_limit():
    """Test history list limit parameter."""
    clear_history_table()

    # Add multiple entries
    for i in range(5):
        client.post('/api/history', json={'query': f'search {i}', 'kind': 'search'})

    # Test limit
    resp = client.get('/api/history?limit=3')
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == 3


def test_delete_history():
    """Test deleting a specific history entry."""
    clear_history_table()

    # Add entries
    resp1 = client.post('/api/history', json={'query': 'search 1', 'kind': 'search'})
    hid1 = resp1.json()['id']
    resp2 = client.post('/api/history', json={'query': 'search 2', 'kind': 'search'})
    hid2 = resp2.json()['id']

    # Delete first entry
    resp = client.delete(f'/api/history/{hid1}')
    assert resp.status_code == 200
    assert resp.json()['ok'] is True

    # Verify only second entry remains
    resp = client.get('/api/history')
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == 1
    assert history[0]['id'] == hid2

    # Try to delete non-existent entry
    resp = client.delete('/api/history/00000000-0000-0000-0000-000000000000')
    assert resp.status_code == 404


def test_clear_history():
    """Test clearing all history."""
    clear_history_table()

    # Add entries
    for i in range(3):
        client.post('/api/history', json={'query': f'search {i}', 'kind': 'search'})

    # Verify entries exist
    resp = client.get('/api/history')
    assert len(resp.json()) == 3

    # Clear all
    resp = client.delete('/api/history')
    assert resp.status_code == 200
    assert resp.json()['ok'] is True
    assert resp.json()['deleted'] == 3

    # Verify empty
    resp = client.get('/api/history')
    assert len(resp.json()) == 0


def test_history_expiry():
    """Test that old history entries are cleaned up."""
    clear_history_table()
    from engine import store

    # Add a history entry
    resp = client.post('/api/history', json={'query': 'old search', 'kind': 'search'})
    hid = resp.json()['id']

    # Manually set created_at to 4 days ago
    four_days_ago = datetime.now(timezone.utc) - timedelta(days=4)
    with store.connect() as c:
        c.execute('UPDATE search_history SET created_at = ? WHERE id = ?', (four_days_ago.isoformat(), hid))

    # Verify it exists before cleanup
    resp = client.get('/api/history')
    assert len(resp.json()) == 1

    # Run cleanup
    deleted = store.cleanup_search_history(days=3)
    assert deleted >= 1

    # Verify it's gone
    resp = client.get('/api/history')
    assert len(resp.json()) == 0


def test_history_separate_from_investigation_inputs():
    """Test that search history is separate from investigation inputs."""
    clear_history_table()

    # Create an investigation with inputs
    inv_resp = client.post('/api/investigations', json={'name': 'Test Inv', 'srm_authorized': False})
    iid = inv_resp.json()['id']

    client.post(f'/api/investigations/{iid}/inputs', json={'kind': 'email', 'value': 'test@example.com'})

    # Add search history
    client.post('/api/history', json={'query': 'search query', 'kind': 'search'})

    # Check investigation inputs
    inv_resp = client.get(f'/api/investigations/{iid}')
    inputs = inv_resp.json()['inputs']
    assert len(inputs) == 1
    assert inputs[0]['value'] == 'test@example.com'
    assert inputs[0]['kind'] == 'email'

    # Check search history (should be separate)
    hist_resp = client.get('/api/history')
    history = hist_resp.json()
    assert len(history) == 1
    assert history[0]['query'] == 'search query'
    assert history[0]['kind'] == 'search'

    # They should be completely separate


def test_history_validation():
    """Test history input validation."""
    clear_history_table()

    # Empty query should fail
    resp = client.post('/api/history', json={'query': '', 'kind': 'search'})
    assert resp.status_code == 400

    # Too long query should fail
    long_query = 'x' * 501
    resp = client.post('/api/history', json={'query': long_query, 'kind': 'search'})
    assert resp.status_code == 400

    # Valid query should succeed
    resp = client.post('/api/history', json={'query': 'valid', 'kind': 'username'})
    assert resp.status_code == 200


def test_history_kinds():
    """Test different history kinds."""
    clear_history_table()

    kinds = ['search', 'username', 'email', 'phone', 'domain', 'ip', 'url']
    for kind in kinds:
        resp = client.post('/api/history', json={'query': f'test {kind}', 'kind': kind})
        assert resp.status_code == 200

    # Verify all stored
    resp = client.get('/api/history')
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) == len(kinds)
    stored_kinds = {h['kind'] for h in history}
    assert stored_kinds == set(kinds)


if __name__ == '__main__':
    test_add_and_list_history()
    test_history_limit()
    test_delete_history()
    test_clear_history()
    test_history_expiry()
    test_history_separate_from_investigation_inputs()
    test_history_validation()
    test_history_kinds()
    print('All history tests passed')