import os
import tempfile
from pathlib import Path
import sys

# Set environment variable for test database before importing the app
# Create a temporary database file
temp_db = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
temp_db.close()
os.environ['WIRESPOOL_DB'] = temp_db.name

# Now we can import the app
sys.path.insert(0, str(Path(__file__).parents[1]))
from main import app

from fastapi.testclient import TestClient

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] == True
    assert "version" in data
    assert "python" in data
    assert "platform" in data
    assert "providers" in data
    assert isinstance(data["providers"], int)

def test_investigations_list_empty():
    response = client.get("/api/investigations")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # Since we just started, there might be no investigations
    # But note: the database is fresh, so it should be empty
    # However, we cannot guarantee because of possible leftover data from other tests?
    # We'll just check that it's a list.

def test_create_investigation_success():
    response = client.post(
        "/api/investigations",
        json={"name": "Test Investigation", "srm_authorized": False},
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["name"] == "Test Investigation"
    assert data["status"] == "ready"
    assert data["srm_authorized"] == False
    assert "created_at" in data
    assert "updated_at" in data
    assert data["inputs"] == []

def test_create_investigation_validation():
    # Empty name
    response = client.post(
        "/api/investigations",
        json={"name": "", "srm_authorized": False},
    )
    assert response.status_code == 400
    assert "Investigation name cannot be empty" in response.json()["detail"]

    # Name too long
    response = client.post(
        "/api/investigations",
        json={"name": "a" * 201, "srm_authorized": False},
    )
    assert response.status_code == 400
    assert "Investigation name too long" in response.json()["detail"]

    # Valid name (exactly 200)
    response = client.post(
        "/api/investigations",
        json={"name": "a" * 200, "srm_authorized": False},
    )
    assert response.status_code == 200

    # Missing name? The model has a default, but we test empty string above.
    # Test with no name field? The model will use default 'New Investigation'
    response = client.post(
        "/api/investigations",
        json={},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "New Investigation"

def test_get_investigation_not_found():
    response = client.get("/api/investigations/nonexistent-id")
    assert response.status_code == 404

def test_add_input_success():
    # First create an investigation
    resp = client.post(
        "/api/investigations",
        json={"name": "Test Investigation for Inputs", "srm_authorized": False},
    )
    assert resp.status_code == 200
    inv_id = resp.json()["id"]

    # Add a username input
    response = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "username", "value": "testuser"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    input_id = data["id"]

    # We can also check that the input is stored by getting the investigation
    resp = client.get(f"/api/investigations/{inv_id}")
    assert resp.status_code == 200
    inv_data = resp.json()
    assert len(inv_data["inputs"]) == 1
    inp = inv_data["inputs"][0]
    assert inp["id"] == input_id
    assert inp["kind"] == "username"
    assert inp["value"] == "testuser"
    assert inp["normalized"] == "testuser"  # lowercased

def test_add_input_validation():
    # Create an investigation
    resp = client.post(
        "/api/investigations",
        json={"name": "Test Investigation for Validation", "srm_authorized": False},
    )
    inv_id = resp.json()["id"]

    # Empty value
    response = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "username", "value": ""},
    )
    assert response.status_code == 400
    assert "Input value cannot be empty" in response.json()["detail"]

    # Invalid username
    response = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "username", "value": "ab"},  # too short
    )
    assert response.status_code == 400
    assert "Username must be 3-32 characters" in response.json()["detail"]

    # Invalid email
    response = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "email", "value": "notanemail"},
    )
    assert response.status_code == 400
    assert "Invalid email format" in response.json()["detail"]

    # Add first input (username)
    response1 = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "username", "value": "testuser"},
    )
    assert response1.status_code == 200
    input_id1 = response1.json()["id"]

    # Add second input (email via auto)
    response2 = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "auto", "value": "test@example.com"},
    )
    assert response2.status_code == 200
    input_id2 = response2.json()["id"]

    # Check that both inputs are stored
    resp = client.get(f"/api/investigations/{inv_id}")
    assert resp.status_code == 200
    inv_data = resp.json()
    assert len(inv_data["inputs"]) == 2
    # Find the username input
    username_inp = None
    email_inp = None
    for inp in inv_data["inputs"]:
        if inp["kind"] == "username":
            username_inp = inp
        elif inp["kind"] == "email":
            email_inp = inp
    assert username_inp is not None
    assert username_inp["value"] == "testuser"
    assert username_inp["normalized"] == "testuser"
    assert email_inp is not None
    assert email_inp["value"] == "test@example.com"
    assert email_inp["normalized"] == "test@example.com"

    # Invalid auto (empty)
    response = client.post(
        f"/api/investigations/{inv_id}/inputs",
        json={"kind": "auto", "value": ""},
    )
    assert response.status_code == 400

def test_tools_endpoint():
    response = client.get("/api/tools")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # Each tool should have certain fields
    if len(data) > 0:
        tool = data[0]
        assert "name" in tool
        assert "kind" in tool
        assert "url" in tool
        assert "diagnostic" in tool

def test_catalog_endpoint():
    response = client.get("/api/catalog")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        item = data[0]
        assert "name" in item
        assert "url" in item
        assert "integration" in item
        assert item["integration"] == "external-resource"

# Clean up the temporary database file after tests
import atexit
def cleanup_temp_db():
    try:
        os.unlink(temp_db.name)
    except:
        pass
atexit.register(cleanup_temp_db)