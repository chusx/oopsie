"""public source imports are bounded, pinned, and do not claim repo exploitability."""

import asyncio
import base64
import json

import pytest

from worker import realworld_sources as sources


def test_normalizers_reject_hosts_paths_and_imprecise_ids():
    assert sources.normalize_github('https://github.com/acme/app.git/') == 'acme/app'
    assert sources.normalize_cve('cve-2025-29927') == 'CVE-2025-29927'
    for value in ('https://github.com.evil.test/acme/app',
                  'https://github.com@evil.test/acme/app',
                  'https://github.com/acme/app/tree/main',
                  'https://github.com/acme/app?ref=evil',
                  'http://github.com/acme/app', '../app'):
        with pytest.raises(sources.source_error):
            sources.normalize_github(value)
    with pytest.raises(sources.source_error):
        sources.normalize_cve('CVE-2025-29927/../../x')


def test_github_scan_pins_manifest_and_pairs_osv_results(monkeypatch):
    calls = []
    lock = {'lockfileVersion': 3, 'packages': {
        '': {'dependencies': {'next': '^15.2.2'}},
        'node_modules/next': {'version': '15.2.2'},
        'node_modules/evil': {'version': 'file:../evil'},
    }}
    manifest = {'type': 'file', 'encoding': 'base64',
                'content': base64.b64encode(json.dumps(lock).encode()).decode()}

    async def fake_fetch(client, method, url, *, body=None, missing_ok=False):
        calls.append((method, url, body))
        if url.endswith('/repos/acme/app'):
            return {'full_name': 'acme/app', 'private': False, 'default_branch': 'main'}
        if url.endswith('/commits/main'):
            return {'sha': 'a' * 40}
        if '/contents/package-lock.json?' in url:
            return manifest
        if url == sources._OSV_BATCH:
            assert body == {'queries': [{'version': '15.2.2',
                                          'package': {'name': 'next', 'ecosystem': 'npm'}}]}
            return {'results': [{'vulns': [{'id': 'GHSA-f82v-jwr5-mffw'}]}]}
        raise AssertionError(url)

    monkeypatch.setattr(sources, '_fetch_json', fake_fetch)
    result = asyncio.run(sources.scan_github('https://github.com/acme/app'))
    assert result['manifest'] == 'package-lock.json'
    assert result['commit'] == 'a' * 40
    assert result['source_url'].endswith('/blob/' + 'a' * 40 + '/package-lock.json')
    assert result['dependencies_scanned'] == result['total_dependencies'] == 1
    assert result['total_matches'] == 1 and result['partial'] is False
    assert result['findings'][0]['source_url'] == 'https://osv.dev/vulnerability/GHSA-f82v-jwr5-mffw'
    assert len(calls) == 4


def test_requirements_only_exact_pins_and_partial_batch(monkeypatch):
    contents = 'requests==2.31.0\nflask>=3\nfoo==1.*\nconditional==1.2.3 ; python_version < "3.12"\n'
    assert sources._packages_from_requirements(contents) == [('requests', '2.31.0', 'PyPI')]
    assert sources._packages_from_lock({'packages': {
        '': {'dependencies': {'z': '1.0'}},
        'node_modules/a': {'version': '1.0.0'},
        'node_modules/z': {'version': '2.0.0'},
    }})[0][0] == 'z'

    async def fake_fetch(client, method, url, *, body=None, missing_ok=False):
        if url.endswith('/repos/acme/app'):
            return {'full_name': 'acme/app', 'private': False, 'default_branch': 'main'}
        if url.endswith('/commits/main'):
            return {'sha': 'b' * 40}
        if '/contents/package-lock.json?' in url:
            return None
        if '/contents/requirements.txt?' in url:
            return {'type': 'file', 'encoding': 'base64',
                    'content': base64.b64encode(contents.encode()).decode()}
        if url == sources._OSV_BATCH:
            return {'results': [{'vulns': [], 'next_page_token': 'more'}]}
        raise AssertionError(url)

    monkeypatch.setattr(sources, '_fetch_json', fake_fetch)
    result = asyncio.run(sources.scan_github('acme/app'))
    assert result['manifest'] == 'requirements.txt'
    assert result['status'] == 'partial'
    assert result['partial'] is True
    assert result['findings'] == []


def test_cve_source_record_only(monkeypatch):
    async def fake_fetch(client, method, url, *, body=None, missing_ok=False):
        assert url == 'https://cveawg.mitre.org/api/cve/CVE-2025-29927'
        return {'cveMetadata': {'cveId': 'CVE-2025-29927', 'state': 'PUBLISHED',
                                'dateUpdated': '2025-04-08T15:17:05Z'},
                'containers': {'cna': {'title': 'Authorization Bypass in Next.js Middleware',
                                       'descriptions': [{'lang': 'en', 'value': 'A middleware boundary can be bypassed.'}],
                                       'references': [{'url': 'https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw',
                                                       'tags': ['vendor-advisory']}]}}}

    monkeypatch.setattr(sources, '_fetch_json', fake_fetch)
    result = asyncio.run(sources.scan_cve('cve-2025-29927'))
    assert result['state'] == 'published'
    assert result['advisory_url'].startswith('https://github.com/vercel/')
    assert 'workspace is affected' in result['note']


def test_outbound_host_guard():
    with pytest.raises(sources.source_error, match='source host'):
        asyncio.run(sources._fetch_json(None, 'GET', 'https://localhost/internal'))
