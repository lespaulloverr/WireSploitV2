import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from main import app
from engine import native, security


def test_repair_rejects_foreign_origin():
    r = TestClient(app).post('/api/tools/native/repair', headers={'Origin':'https://evil.example'})
    assert r.status_code == 403


def test_mutating_routes_reject_foreign_origin():
    r = TestClient(app).post('/api/investigations', json={'name':'x'}, headers={'Origin':'https://evil.example'})
    assert r.status_code == 403


def test_geolocation_handles_nominatim_rate_limit(monkeypatch):
    class Response:
        status_code = 429
        def json(self):
            raise ValueError('not json')
    async def fake_get(*args, **kwargs):
        return Response()
    monkeypatch.setattr(native, '_get', fake_get)
    assert asyncio.run(native.geolocation_lookup('some place')) == []


def test_safe_fetch_rejects_private_address(monkeypatch):
    async def fake_to_thread(func, *args, **kwargs):
        return [(None,None,None,None,('127.0.0.1',443))]
    monkeypatch.setattr(native.asyncio, 'to_thread', fake_to_thread)
    try:
        asyncio.run(native._safe_get_public_host('https://example.com'))
    except ValueError as e:
        assert 'non-public' in str(e)
    else:
        raise AssertionError('private address must be rejected')


def test_technical_lookup_needs_saved_scope(monkeypatch):
    async def fake_domain(*args, **kwargs):
        return [{'entity_key':'domain:example.com','platform':'Domain','value':'example.com','url':None,'source_tools':['native'],'evidence':{}}]
    monkeypatch.setattr(native, 'domain_lookup', fake_domain)
    monkeypatch.setattr(security, 'is_authorized', lambda target: False)
    result = asyncio.run(native.technical_lookup('example.com', True))
    assert 'authorized_active_checks' not in result[0]['evidence']
    assert 'authorized_active_checks_skipped' in result[0]['evidence']


def test_scope_wildcard_syntax():
    """Test that *.example.com is normalized to example.com with wildcard flag."""
    result = security.normalize_target("*.example.com")
    assert result["type"] == "domain"
    assert result["value"] == "example.com"
    assert result["host"] == "example.com"
    assert result["wildcard"] == True


def test_scope_wildcard_normalized_same_as_domain():
    """Test that *.example.com and example.com produce same normalized value."""
    wildcard = security.normalize_target("*.example.com")
    regular = security.normalize_target("example.com")
    assert wildcard["value"] == regular["value"]
    assert wildcard["host"] == regular["host"]
    assert wildcard["type"] == regular["type"]


def test_scope_subdomain_inheritance():
    """Test that authorizing example.com also authorizes subdomains."""
    # Clear any existing scopes
    import json
    security.SCOPE_PATH.write_text("[]")

    # Add example.com as authorized scope
    security.add_scope("example.com", "Test scope")

    # Check authorization
    assert security.is_authorized("example.com") == True
    assert security.is_authorized("www.example.com") == True
    assert security.is_authorized("api.example.com") == True
    assert security.is_authorized("sub.sub.example.com") == True
    assert security.is_authorized("other.com") == False
    assert security.is_authorized("example.org") == False


def test_scope_wildcard_explicit_authorization():
    """Test that *.example.com explicitly added works the same as example.com."""
    import json
    security.SCOPE_PATH.write_text("[]")

    # Add *.example.com as authorized scope
    security.add_scope("*.example.com", "Test wildcard scope")

    # Check authorization - should work the same as example.com
    assert security.is_authorized("example.com") == True
    assert security.is_authorized("www.example.com") == True
    assert security.is_authorized("api.example.com") == True


def test_scope_url_exact_host_match():
    """Test that URL scopes match by exact host (no subdomain inheritance)."""
    import json
    security.SCOPE_PATH.write_text("[]")

    # Add URL scope
    security.add_scope("https://example.com/path", "Test URL scope")

    # Exact host should match (including domain type with same host)
    assert security.is_authorized("https://example.com/path") == True
    assert security.is_authorized("https://www.example.com/path") == False
    assert security.is_authorized("https://example.com/other") == True  # same host, different path
    assert security.is_authorized("example.com") == True  # URL scope matches by host

    # But subdomains should NOT match (no subdomain inheritance for URL scopes)
    assert security.is_authorized("www.example.com") == False
    assert security.is_authorized("api.example.com") == False


def test_scope_cidr_ip_containment():
    """Test that CIDR scopes use IP network containment."""
    import json
    security.SCOPE_PATH.write_text("[]")

    # Add CIDR scope
    security.add_scope("192.0.2.0/24", "Test CIDR scope")

    # IPs within range should be authorized
    assert security.is_authorized("192.0.2.1") == True
    assert security.is_authorized("192.0.2.255") == True
    # IPs outside range should not
    assert security.is_authorized("192.0.3.1") == False
    assert security.is_authorized("10.0.0.1") == False


def test_idn_normalization():
    """Test that IDN domains are normalized to Punycode (A-label form)."""
    # Test IDN domain normalization
    # "bücher.de" -> "xn--bcher-kva.de"
    idn_domain = "bücher.de"
    result = security.normalize_target(idn_domain)
    assert result["type"] == "domain"
    assert result["value"] == "xn--bcher-kva.de"
    assert result["host"] == "xn--bcher-kva.de"

    # Test IDN URL normalization
    idn_url = "https://bücher.de/path"
    result = security.normalize_target(idn_url)
    assert result["type"] == "url"
    assert result["host"] == "xn--bcher-kva.de"

    # Test IDN wildcard normalization
    idn_wildcard = "*.bücher.de"
    result = security.normalize_target(idn_wildcard)
    assert result["type"] == "domain"
    assert result["wildcard"] == True
    assert result["value"] == "xn--bcher-kva.de"
    assert result["host"] == "xn--bcher-kva.de"


def test_idn_scope_authorization():
    """Test that IDN scopes authorize correctly with subdomain inheritance."""
    import json
    security.SCOPE_PATH.write_text("[]")

    # Add IDN domain as scope (stored in Punycode)
    security.add_scope("bücher.de", "Test IDN scope")

    # The scope value is stored in Punycode
    scopes = security.list_scopes()
    assert scopes[0]["value"] == "xn--bcher-kva.de"

    # Authorization should work with both Unicode and Punycode forms
    assert security.is_authorized("bücher.de") == True
    assert security.is_authorized("xn--bcher-kva.de") == True
    assert security.is_authorized("www.bücher.de") == True
    assert security.is_authorized("www.xn--bcher-kva.de") == True
    assert security.is_authorized("other.de") == False
