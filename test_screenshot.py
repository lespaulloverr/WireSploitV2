import asyncio
import io
import sys
import time
import threading
import requests
import uvicorn
from fastapi.testclient import TestClient
from main import app
from engine import store, security
import os

# Helper to start the server in a thread
def start_server():
    uvicorn.run(app, host="127.0.0.1", port=8769, log_level="error")

# We'll test the screenshot endpoint
def test_screenshot_endpoint():
    # First, we need to set up an authorized scope for a test URL
    # We'll use a localhost URL for testing, but we need to authorize it
    # We'll create a scope for localhost
    scope_value = "http://localhost:8769"
    scope_label = "Test localhost"

    # Check if the scope already exists, if not add it
    scopes = security.list_scopes()
    scope_exists = any(s['value'] == scope_value for s in scopes)
    if not scope_exists:
        security.add_scope(scope_value, scope_label)

    # Now we need to create an investigation to associate with the screenshot
    # But the screenshot endpoint doesn't require an investigation ID; it just returns the image.
    # The user will then upload the image as evidence using the existing endpoint.
    # So we test that the screenshot endpoint returns an image for an authorized URL.

    # We'll start a simple HTTP server in the background to serve a test page
    # We'll use a simple Python http.server on a random port
    # We'll authorize that scope.

    # For simplicity, we'll test with a URL that we know will work: we'll use a local file served by a simple server.
    # We'll create a temporary directory and serve a simple HTML file.

    import http.server
    import socketserver
    from urllib.parse import urlparse

    # Find a free port
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    # Create a temporary directory and an HTML file
    import tempfile
    temp_dir = tempfile.mkdtemp()
    html_file = os.path.join(temp_dir, "test.html")
    with open(html_file, "w") as f:
        f.write("<html><body><h1>Test Page</h1></body></html>")

    # Start the server in a thread
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    httpd_thread = threading.Thread(target=httpd.serve_forever)
    httpd_thread.daemon = True
    httpd_thread.start()

    # Give the server a moment to start
    time.sleep(0.5)

    # The URL to capture
    test_url = f"http://localhost:{port}/test.html"

    # Authorize this URL (we already authorized localhost, but we need to be more specific)
    # We'll authorize the exact URL
    security.add_scope(test_url, "Test URL for screenshot")

    # Now we can test the screenshot endpoint
    client = TestClient(app)
    response = client.post(
        "/api/screenshot",
        data={"url": test_url}
    )

    # Check that we got a successful response
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    assert response.headers["content-type"] == "image/png"
    # Check that the content is not empty
    assert len(response.content) > 0
    # Optionally, we can check that it's a valid PNG by checking the first few bytes
    assert response.content[:8] == b'\x89PNG\r\n\x1a\n', "Not a valid PNG file"

    # Clean up
    httpd.shutdown()
    httpd_thread.join()
    # Remove the scopes we added (optional)
    # We'll leave them for now

    print("Screenshot endpoint test passed.")

# We'll also test that unauthorized URLs are blocked
def test_screenshot_unauthorized():
    # We'll use a URL that is not authorized
    test_url = "http://example.com"
    client = TestClient(app)
    response = client.post(
        "/api/screenshot",
        data={"url": test_url}
    )
    # We expect 403 because the URL is not authorized
    assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"
    print("Screenshot endpoint unauthorized test passed.")

# We'll test that the existing evidence upload still works
def test_evidence_upload():
    # Create an investigation
    client = TestClient(app)
    inv_response = client.post(
        "/api/investigations",
        json={"name": "Test Investigation", "srm_authorized": False}
    )
    assert inv_response.status_code == 200
    inv_id = inv_response.json()["id"]

    # Upload a file
    file_content = b"test file content"
    files = {"file": ("test.txt", file_content, "text/plain")}
    data = {"kind": "file", "title": "Test File", "source": "test", "description": "Just a test"}
    upload_response = client.post(
        f"/api/investigations/{inv_id}/evidence/upload",
        files=files,
        data=data
    )
    assert upload_response.status_code == 200
    eid = upload_response.json()["id"]

    # Check that the evidence is listed
    get_response = client.get(f"/api/investigations/{inv_id}")
    assert get_response.status_code == 200
    data = get_response.json()
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["id"] == eid
    assert data["evidence"][0]["kind"] == "file"
    assert data["evidence"][0]["title"] == "Test File"

    print("Evidence upload test passed.")

def test_export():
    # Create an investigation
    client = TestClient(app)
    inv_response = client.post(
        "/api/investigations",
        json={"name": "Test Investigation for Export", "srm_authorized": False}
    )
    assert inv_response.status_code == 200
    inv_id = inv_response.json()["id"]

    # Add some evidence
    file_content = b"test evidence content"
    files = {"file": ("evidence.txt", file_content, "text/plain")}
    data = {"kind": "file", "title": "Test Evidence", "source": "test", "description": "Just a test"}
    upload_response = client.post(
        f"/api/investigations/{inv_id}/evidence/upload",
        files=files,
        data=data
    )
    assert upload_response.status_code == 200
    from engine import store

    # Add a note
    note_response = client.post(
        f"/api/investigations/{inv_id}/notes",
        data={"note": "This is a test note for export"}
    )
    assert note_response.status_code == 200
    # Debug: print notes
    notes = store.get_investigation_notes(inv_id)
    print(f"Notes after adding: {notes}")

    # Create a run and a finding for the investigation
    import uuid
    run_id = store.create_run(inv_id, 1)  # total_stages=1
    finding_id = str(uuid.uuid4())
    with store.connect() as c:
        c.execute('''
            INSERT INTO findings (id, run_id, category, provider, entity_key, value, url, confidence, exact_match, evidence_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding_id,
            run_id,
            'test-category',
            'test-provider',
            'test-entity-key',
            'test-value',
            'http://example.com',
            0.9,
            1,
            '{"test": "json"}',
            store.now()
        ))
        c.commit()

    # Test each export format
    for fmt in ["json", "csv", "html", "pdf"]:
        export_response = client.get(
            f"/api/investigations/{inv_id}/export/{fmt}"
        )
        assert export_response.status_code == 200, f"Export {fmt} failed: {export_response.text}"
        # Check content-type
        if fmt == "json":
            assert export_response.headers["content-type"].startswith("application/json")
            # Check that we can parse the JSON
            data = export_response.json()
            assert data["name"] == "Test Investigation for Export"
            assert len(data["evidence"]) == 1
            assert len(data["notes"]) == 1
            # Check that the finding is present
            found = any(f.get('id') == finding_id for f in data.get('findings', []))
            if not found:
                print(f"Findings in JSON: {data.get('findings', [])}")
            assert found, "Test finding not found in JSON export"
        elif fmt == "csv":
            assert export_response.headers["content-type"].startswith("text/csv")
            # Check that we get some CSV content
            assert len(export_response.content) > 0
            csv_text = export_response.content.decode('utf-8')
            # The CSV should contain the note and the finding
            if "This is a test note for export" not in csv_text:
                print(f"CSV content: {csv_text}")
            assert "This is a test note for export" in csv_text
            # Check that the finding is present
            assert finding_id in csv_text
            assert "test-category" in csv_text
            assert "test-value" in csv_text
            # Check that the finding is present in the CSV
            assert finding_id in csv_text
            assert "test-category" in csv_text
            assert "test-value" in csv_text
        elif fmt == "html":
            assert export_response.headers["content-type"].startswith("text/html")
            assert len(export_response.content) > 0
            html_text = export_response.content.decode('utf-8')
            assert "Test Investigation for Export" in html_text
            assert "Test Evidence" in html_text
            if "This is a test note for export" not in html_text:
                print(f"HTML content: {html_text}")
            assert "This is a test note for export" in html_text
            # Check that the finding is present in the HTML
            assert finding_id in html_text
            assert "test-category" in html_text
            assert "test-value" in html_text
        elif fmt == "pdf":
            assert export_response.headers["content-type"].startswith("application/pdf")
            assert len(export_response.content) > 0
            # Check that it's a PDF by looking for the PDF header
            assert export_response.content[:4] == b'%PDF'
            # We cannot easily check the PDF content, but we trust that the finding is included

    print("Export functionality test passed.")

if __name__ == "__main__":
    # Start the server in a thread
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Give the server a moment to start
    time.sleep(2)

    try:
        test_screenshot_endpoint()
        test_screenshot_unauthorized()
        test_evidence_upload()
        test_export()
        print("All tests passed.")
    except Exception as e:
        print(f"Test failed: {e}")
        raise
    finally:
        # We cannot easily stop the server because it's running in a daemon thread.
        # We'll just let it be killed when the main thread exits.
        pass