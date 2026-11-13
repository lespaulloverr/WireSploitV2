import io
import sys
import os
import tempfile
import threading
import time
import http.server
import socketserver
import socket
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from engine import security

client = TestClient(app)


def test_screenshot_endpoint():
    """Test that the screenshot endpoint works for authorized public URLs.
    Uses example.com as a reliable public test domain that serves a simple HTML page."""
    # Use example.com - a reliable public test domain that resolves to public IPs
    # and serves a simple HTML page. This avoids external dependency on httpbin.org.
    test_url = "https://example.com"

    # Authorize this URL
    security.add_scope(test_url, "Test URL for screenshot")

    # Test the screenshot endpoint
    response = client.post(
        "/api/screenshot",
        data={"url": test_url}
    )

    # Should succeed for authorized public URL
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    assert response.headers["content-type"] == "image/png"
    assert len(response.content) > 0
    assert response.content[:8] == b'\x89PNG\r\n\x1a\n', "Not a valid PNG file"


def test_screenshot_blocks_private_ips():
    """Test that SSRF protection blocks private/loopback IPs even when authorized."""
    # Create a temporary HTTP server on localhost
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    temp_dir = tempfile.mkdtemp()
    html_file = os.path.join(temp_dir, "test.html")
    with open(html_file, "w") as f:
        f.write("<html><body><h1>Test Page</h1></body></html>")

    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    httpd_thread = threading.Thread(target=httpd.serve_forever)
    httpd_thread.daemon = True
    httpd_thread.start()

    time.sleep(0.5)

    test_url = f"http://localhost:{port}/test.html"

    # Authorize this URL (even though authorized, should be blocked by SSRF protection)
    security.add_scope(test_url, "Test URL for screenshot")

    # Test the screenshot endpoint - should be blocked
    response = client.post(
        "/api/screenshot",
        data={"url": test_url}
    )

    # Should be blocked (400) due to SSRF protection
    assert response.status_code == 400, f"Expected 400 for private IP, got {response.status_code}: {response.text}"
    assert "non-public address" in response.text.lower() or "refusing to connect" in response.text.lower()

    httpd.shutdown()
    httpd_thread.join()


def test_screenshot_unauthorized():
    """Test that unauthorized URLs are blocked."""
    # Use a URL that is NOT authorized (example.org is different from example.com)
    test_url = "http://example.org"
    response = client.post(
        "/api/screenshot",
        data={"url": test_url}
    )
    assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"


def test_screenshot_invalid_url():
    """Test that invalid/unauthorized URLs are rejected with 403."""
    # The endpoint checks authorization first, so an invalid URL that isn't authorized returns 403
    response = client.post(
        "/api/screenshot",
        data={"url": "not-a-url"}
    )
    assert response.status_code == 403, f"Expected 403, got {response.status_code}: {response.text}"


def test_screenshot_integration_with_evidence():
    """Test capturing a screenshot and saving it as evidence.
    Uses example.com as a reliable public test domain that serves a simple HTML page."""
    # Create an investigation
    inv_response = client.post(
        "/api/investigations",
        json={"name": "Test Investigation for Screenshot", "srm_authorized": False}
    )
    assert inv_response.status_code == 200
    inv_id = inv_response.json()["id"]

    # Use example.com as a reliable public test domain
    test_url = "https://example.com"
    security.add_scope(test_url, "Test URL for screenshot integration")

    # Capture screenshot
    response = client.post(
        "/api/screenshot",
        data={"url": test_url}
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    screenshot_content = response.content

    # Upload as evidence
    files = {"file": ("screenshot.png", screenshot_content, "image/png")}
    data = {
        "kind": "screenshot",
        "title": "Test Screenshot",
        "source": test_url,
        "description": "Captured via screenshot endpoint"
    }
    upload_response = client.post(
        f"/api/investigations/{inv_id}/evidence/upload",
        files=files,
        data=data
    )
    assert upload_response.status_code == 200
    eid = upload_response.json()["id"]

    # Verify evidence appears in investigation
    get_response = client.get(f"/api/investigations/{inv_id}")
    assert get_response.status_code == 200
    inv_data = get_response.json()
    evidence_list = inv_data["evidence"]
    assert len(evidence_list) == 1
    evidence = evidence_list[0]
    assert evidence["id"] == eid
    assert evidence["kind"] == "screenshot"
    assert evidence["title"] == "Test Screenshot"
    assert evidence["source"] == test_url
    assert evidence["sha256"] is not None

    # Verify the evidence file can be retrieved
    file_response = client.get(f"/api/evidence/{eid}")
    assert file_response.status_code == 200
    assert file_response.content == screenshot_content


if __name__ == '__main__':
    test_screenshot_endpoint()
    test_screenshot_unauthorized()
    test_screenshot_invalid_url()
    test_screenshot_integration_with_evidence()
    print('All screenshot tests passed')