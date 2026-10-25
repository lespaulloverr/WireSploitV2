"""
Cross-origin GET tests for all sensitive GET endpoints with same-origin protection.
Finding 5: Cross-Origin Missing on Sensitive GETs (P2)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def create_test_investigation_with_run_and_evidence():
    """Create a test investigation with inputs, start a run, and upload evidence."""
    # Create investigation
    resp = client.post('/api/investigations', json={'name': 'Test', 'srm_authorized': False})
    assert resp.status_code == 200
    inv = resp.json()
    iid = inv['id']

    # Add an input (required to start a run)
    resp = client.post(f'/api/investigations/{iid}/inputs', json={'kind': 'domain', 'value': 'example.com', 'source': 'test'})
    assert resp.status_code == 200

    # Start a run
    resp = client.post(f'/api/investigations/{iid}/start')
    assert resp.status_code == 200
    run = resp.json()
    rid = run['id']

    # Upload evidence
    file_content = b'test'
    resp = client.post(
        f'/api/investigations/{iid}/evidence/upload',
        files={'file': ('test.txt', file_content, 'text/plain')},
        data={'kind': 'file', 'title': 'Test', 'source': 'upload'}
    )
    assert resp.status_code == 200
    evidence = resp.json()
    eid = evidence['id']

    return iid, rid, eid


def test_cross_origin_get_rejected():
    """Test that sensitive GET endpoints reject foreign Origin headers."""
    iid, rid, eid = create_test_investigation_with_run_and_evidence()

    # Test each sensitive GET endpoint with foreign Origin
    # These are all GET endpoints that have Depends(require_same_origin)
    sensitive_endpoints = [
        "/api/investigations",
        f"/api/investigations/{iid}",
        f"/api/runs/{rid}",
        f"/api/investigations/{iid}/export/json",
        f"/api/investigations/{iid}/export/csv",
        f"/api/investigations/{iid}/export/html",
        f"/api/investigations/{iid}/export/pdf",
        f"/api/investigations/{iid}/graph",
        "/api/scopes",
        "/api/history",
        "/api/diagnostics",
        f"/api/evidence/{eid}",
        f"/api/investigations/{iid}/notes",
    ]

    for endpoint in sensitive_endpoints:
        resp = client.get(endpoint, headers={"Origin": "https://evil.com"})
        # Should be rejected (403) - same-origin check blocks foreign origins
        assert resp.status_code == 403, f"Endpoint {endpoint} should reject foreign origin, got {resp.status_code}: {resp.text}"


def test_cross_origin_get_allowed_same_origin():
    """Test that sensitive GET endpoints allow same-origin requests."""
    iid, rid, eid = create_test_investigation_with_run_and_evidence()

    # Test each sensitive endpoint WITHOUT foreign Origin (same-origin)
    sensitive_endpoints = [
        "/api/investigations",
        f"/api/investigations/{iid}",
        f"/api/runs/{rid}",
        f"/api/investigations/{iid}/export/json",
        f"/api/investigations/{iid}/export/csv",
        f"/api/investigations/{iid}/export/html",
        f"/api/investigations/{iid}/export/pdf",
        f"/api/investigations/{iid}/graph",
        "/api/scopes",
        "/api/history",
        "/api/diagnostics",
        f"/api/evidence/{eid}",
        f"/api/investigations/{iid}/notes",
    ]

    for endpoint in sensitive_endpoints:
        resp = client.get(endpoint)  # No Origin header = same-origin
        # Should succeed (200) or return 404 for non-existent, but NOT 403
        assert resp.status_code != 403, f"Endpoint {endpoint} should allow same-origin, got {resp.status_code}: {resp.text}"


def test_public_endpoints_allow_foreign_origin():
    """Test that public GET endpoints allow foreign Origin headers."""
    public_endpoints = [
        "/api/health",
        "/api/catalog",
        "/api/tools",
    ]

    for endpoint in public_endpoints:
        resp = client.get(endpoint, headers={"Origin": "https://evil.com"})
        # Should succeed (200) - no same-origin check on public endpoints
        assert resp.status_code == 200, f"Public endpoint {endpoint} should allow foreign origin, got {resp.status_code}: {resp.text}"


def test_origin_header_case_insensitive():
    """Test that Origin header check is case-insensitive."""
    iid, _, _ = create_test_investigation_with_run_and_evidence()

    # Test with different case variations of Origin header
    headers_list = [
        {"Origin": "https://evil.com"},
        {"origin": "https://evil.com"},
        {"ORIGIN": "https://evil.com"},
        {"OrIgIn": "https://evil.com"},
    ]

    for headers in headers_list:
        resp = client.get(f"/api/investigations/{iid}", headers=headers)
        assert resp.status_code == 403, f"Should reject foreign origin with headers {headers}"


def test_referer_header_also_checked():
    """Test that Referer header is also validated for same-origin."""
    iid, _, _ = create_test_investigation_with_run_and_evidence()

    # Test with foreign Referer but no Origin
    resp = client.get(f"/api/investigations/{iid}", headers={"Referer": "https://evil.com/page"})
    # Should be rejected based on Referer
    assert resp.status_code == 403, f"Should reject foreign Referer, got {resp.status_code}: {resp.text}"


if __name__ == '__main__':
    test_cross_origin_get_rejected()
    test_cross_origin_get_allowed_same_origin()
    test_public_endpoints_allow_foreign_origin()
    test_origin_header_case_insensitive()
    test_referer_header_also_checked()
    print('All cross-origin GET tests passed')