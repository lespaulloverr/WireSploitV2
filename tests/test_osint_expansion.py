import asyncio
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from main import app
from engine import engine as investigation_engine, tooling, web_providers


def test_catalog_api_returns_integrations_as_external_resources():
    client = TestClient(app)
    response = client.get('/api/catalog')
    assert response.status_code == 200
    resources = response.json()
    assert len(resources) >= 100
    assert all(row['integration'] == 'external-resource' for row in resources)
    urls = [row['url'].rstrip('/').lower() for row in resources]
    assert len(urls) == len(set(urls))
    names = {row['name'] for row in resources}
    assert 'Shodan InternetDB' in names
    assert 'NIST NVD API' in names or 'NIST NVD' in names


def test_all_automated_web_specs_have_a_provider_implementation():
    missing = [
        spec.id for spec in tooling.SPECS
        if spec.kind == 'web' and spec.automated and spec.id not in web_providers.PROVIDERS
    ]
    assert missing == []


def test_credentialed_provider_reports_missing_key_without_leaking_secrets(monkeypatch):
    monkeypatch.delenv('URLSCAN_API_KEY', raising=False)
    diagnostic = tooling.diagnose('urlscan_public')
    assert diagnostic['status'] == 'missing'
    assert any('URLSCAN_API_KEY' in check['detail'] for check in diagnostic['checks'])
    assert all('secret-value' not in str(check) for check in diagnostic['checks'])


def test_credentialed_provider_becomes_ready_when_key_is_set(monkeypatch):
    monkeypatch.setenv('URLSCAN_API_KEY', 'secret-value-for-test')
    diagnostic = tooling.diagnose('urlscan_public')
    assert diagnostic['status'] == 'ready'
    assert 'secret-value-for-test' not in str(diagnostic)


def test_private_ip_is_rejected_without_network_call(monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError('Network call must not be attempted for a private IP')

    monkeypatch.setattr(web_providers, '_get', fail_if_called)
    assert asyncio.run(web_providers.internetdb_public('127.0.0.1', 'ip')) == []


def test_internetdb_parses_passive_ip_context(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                'ip': '8.8.8.8', 'ports': [53, 443], 'hostnames': ['dns.google'],
                'cpes': ['cpe:/a:google:dns'], 'tags': ['dns'], 'vulns': [],
            }

    async def fake_get(url, **kwargs):
        assert url == 'https://internetdb.shodan.io/8.8.8.8'
        return Response()

    monkeypatch.setattr(web_providers, '_get', fake_get)
    result = asyncio.run(web_providers.internetdb_public('8.8.8.8', 'ip'))
    assert len(result) == 1
    assert result[0]['source_tools'] == ['internetdb_public']
    assert result[0]['evidence']['ports'] == [53, 443]
    assert result[0]['evidence']['passive'] is True


def test_nvd_ignores_non_cve_search_without_request(monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError('NVD must not be queried for arbitrary search terms')

    monkeypatch.setattr(web_providers, '_get', fail_if_called)
    assert asyncio.run(web_providers.nvd_cve_public('example company', 'search')) == []


def test_nvd_parses_exact_cve_and_cvss(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                'vulnerabilities': [{
                    'cve': {
                        'id': 'CVE-2024-12345', 'published': '2024-01-01T00:00:00.000',
                        'lastModified': '2024-01-02T00:00:00.000', 'vulnStatus': 'Analyzed',
                        'descriptions': [{'lang': 'en', 'value': 'Test vulnerability'}],
                        'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 8.1}}]},
                        'references': [{'url': 'https://example.test/advisory'}],
                    }
                }]
            }

    async def fake_get(url, *, params=None, **kwargs):
        assert url.endswith('/cves/2.0')
        assert params['cveId'] == 'CVE-2024-12345'
        return Response()

    monkeypatch.setattr(web_providers, '_get', fake_get)
    result = asyncio.run(web_providers.nvd_cve_public('CVE-2024-12345', 'search'))
    assert len(result) == 1
    assert result[0]['value'] == 'CVE-2024-12345'
    assert result[0]['evidence']['cvss_base_score'] == 8.1
    assert result[0]['evidence']['description'] == 'Test vulnerability'


def test_nonrepairable_tool_repair_endpoint_is_safe():
    response = TestClient(app).post('/api/tools/urlscan_public/repair')
    assert response.status_code == 400
    assert 'no automatic install/repair workflow' in response.json()['detail']


def test_safe_zip_extractor_rejects_path_traversal(tmp_path):
    import io
    import zipfile
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, 'w') as archive:
        archive.writestr('../outside.txt', 'not allowed')
    archive_bytes.seek(0)
    destination = tmp_path / 'safe'
    destination.mkdir()
    with zipfile.ZipFile(archive_bytes) as archive:
        with pytest.raises(ValueError, match='Unsafe ZIP member path'):
            tooling._safe_extract_zip(archive, destination)
    assert not (tmp_path / 'outside.txt').exists()

def test_private_ip_is_skipped_by_all_public_ip_providers(monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError('Public services must not be queried with a private IP')
    monkeypatch.setattr(web_providers, '_get', fail_if_called)
    for provider in (web_providers.ipwhois_public, web_providers.ripestat_public, web_providers.abuseipdb_public, web_providers.greynoise_public):
        assert asyncio.run(provider('192.168.1.10', 'ip')) == []

def test_env_loader_preserves_existing_environment_values(tmp_path, monkeypatch):
    from main import _load_local_env
    env_file = tmp_path / '.env'
    env_file.write_text("WIRESPLOIT_TEST_KEY='from-file'\nWIRESPLOIT_TEST_OTHER=visible\n", encoding='utf-8')
    monkeypatch.setenv('WIRESPLOIT_TEST_KEY', 'from-environment')
    monkeypatch.delenv('WIRESPLOIT_TEST_OTHER', raising=False)
    _load_local_env(env_file)
    import os
    assert os.getenv('WIRESPLOIT_TEST_KEY') == 'from-environment'
    assert os.getenv('WIRESPLOIT_TEST_OTHER') == 'visible'
    monkeypatch.delenv('WIRESPLOIT_TEST_OTHER', raising=False)


def test_greynoise_community_supports_limited_unauthenticated_lookup(monkeypatch):
    monkeypatch.delenv('GREYNOISE_API_KEY', raising=False)
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return {'ip': '8.8.8.8', 'noise': False, 'riot': True, 'classification': 'benign', 'name': 'Google DNS'}
    async def fake_get(url, *, headers=None, **kwargs):
        assert url.endswith('/v3/community/8.8.8.8')
        assert headers is None
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.greynoise_public('8.8.8.8', 'ip'))
    assert len(rows) == 1
    assert rows[0]['evidence']['riot'] is True


def test_certspotter_parses_passive_certificate_names_without_unsupported_limit(monkeypatch):
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return [{
                'id': 123, 'not_before': '2025-01-01T00:00:00Z', 'not_after': '2026-01-01T00:00:00Z',
                'dns_names': ['example.org', 'www.example.org'], 'issuer': {'name': 'Example CA'},
            }]
    async def fake_get(url, *, params=None, **kwargs):
        assert url == 'https://api.certspotter.com/v1/issuances'
        assert params['domain'] == 'example.org'
        assert 'limit' not in params
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.certspotter_public('example.org', 'domain'))
    assert rows[0]['evidence']['passive'] is True
    assert rows[0]['evidence']['certificate_names'] == ['example.org', 'www.example.org']
    assert rows[0]['evidence']['certificates'][0]['issuer'] == 'Example CA'


def test_urlscan_search_requires_key_and_never_submits_a_target(monkeypatch):
    monkeypatch.delenv('URLSCAN_API_KEY', raising=False)
    async def fail_if_called(*args, **kwargs):
        raise AssertionError('No key should mean no urlscan request')
    monkeypatch.setattr(web_providers, '_get', fail_if_called)
    assert asyncio.run(web_providers.urlscan_public('example.org', 'domain')) == []

    monkeypatch.setenv('URLSCAN_API_KEY', 'test-key')
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return {'total': 1, 'results': [{
                '_id': 'abc123', 'task': {'time': '2026-01-01T00:00:00Z', 'url': 'https://example.org/'},
                'page': {'domain': 'example.org', 'ip': '8.8.8.8', 'title': 'Example'}, 'stats': {'uniqIPs': 2},
            }]}
    async def fake_get(url, *, params=None, headers=None, **kwargs):
        assert url == 'https://urlscan.io/api/v1/search/'
        assert params == {'q': 'domain:example.org', 'size': 20}
        assert headers == {'api-key': 'test-key'}
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.urlscan_public('example.org', 'domain'))
    assert rows[0]['evidence']['submitted_or_scanned'] is False
    assert rows[0]['evidence']['results'][0]['result_url'].endswith('/abc123/')


def test_virustotal_requires_key_and_uses_reputation_only(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    async def fail_if_called(*args, **kwargs):
        raise AssertionError('No key should mean no VirusTotal request')
    monkeypatch.setattr(web_providers, '_get', fail_if_called)
    assert asyncio.run(web_providers.virustotal_public('example.org', 'domain')) == []

    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-vt-key')
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return {'data': {'attributes': {'reputation': 7, 'last_analysis_stats': {'malicious': 0, 'harmless': 70}, 'categories': {'example': 'reference'}}}}
    async def fake_get(url, *, headers=None, **kwargs):
        assert url.endswith('/api/v3/domains/example.org')
        assert headers == {'x-apikey': 'test-vt-key'}
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.virustotal_public('example.org', 'domain'))
    assert rows[0]['evidence']['reputation'] == 7
    assert rows[0]['evidence']['last_analysis_stats']['malicious'] == 0


def test_ipwhois_parses_public_ip_context(monkeypatch):
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return {'success': True, 'ip': '8.8.8.8', 'country': 'United States', 'city': 'Mountain View', 'latitude': 37.4, 'longitude': -122.1, 'connection': {'asn': 15169, 'org': 'Google LLC'}, 'timezone': {'id': 'America/Los_Angeles'}}
    async def fake_get(url, **kwargs):
        assert url == 'https://ipwho.is/8.8.8.8'
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.ipwhois_public('8.8.8.8', 'ip'))
    assert rows[0]['evidence']['asn'] == 15169
    assert rows[0]['evidence']['timezone'] == 'America/Los_Angeles'


def test_ripestat_parses_asn_and_prefix_context(monkeypatch):
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return {'status': 'ok', 'time': '2026-01-01T00:00:00', 'data': {'resource': '8.8.8.8', 'prefix': '8.8.8.0/24', 'asns': [15169]}}
    async def fake_get(url, *, params=None, **kwargs):
        assert url.endswith('/network-info/data.json')
        assert params['resource'] == '8.8.8.8'
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.ripestat_public('8.8.8.8', 'ip'))
    assert rows[0]['evidence']['prefix'] == '8.8.8.0/24'
    assert rows[0]['evidence']['asns'] == [15169]


def test_cisa_kev_caches_feed_and_matches_exact_cve(monkeypatch):
    import time
    web_providers._CISA_KEV_CACHE['loaded_at'] = 0
    web_providers._CISA_KEV_CACHE['by_cve'] = {}
    class Response:
        status_code = 200
        @staticmethod
        def json():
            return {'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'vendorProject': 'Example', 'product': 'Thing', 'vulnerabilityName': 'Example vuln', 'dateAdded': '2024-01-01', 'requiredAction': 'Patch'}]}
    hits = []
    async def fake_get(url, **kwargs):
        hits.append(url)
        return Response()
    monkeypatch.setattr(web_providers, '_get', fake_get)
    rows = asyncio.run(web_providers.cisa_kev_public('CVE-2024-12345', 'search'))
    assert rows[0]['evidence']['vendorProject'] == 'Example'
    assert len(hits) == 1
    # A still-fresh cache is reused for subsequent exact lookups.
    rows2 = asyncio.run(web_providers.cisa_kev_public('CVE-2024-12345', 'search'))
    assert len(rows2) == 1
    assert len(hits) == 1



def test_discover_queues_cve_ids_for_nvd_and_kev_enrichment():
    finding = {
        'value': '8.8.8.8', 'url': 'https://internetdb.shodan.io/8.8.8.8',
        'platform': 'Shodan InternetDB',
        'evidence': {'vulns': ['CVE-2024-12345', 'CVE-2023-9876']},
    }
    discovered = set(investigation_engine.discover(finding))
    assert ('search', 'CVE-2024-12345') in discovered
    assert ('search', 'CVE-2023-9876') in discovered
