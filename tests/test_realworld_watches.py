"""Outside-source watches stay read-only, workspace-scoped, and URL-owned."""
import asyncio
import uuid

import pytest
from worker import engine, realworld


@pytest.fixture
def isolated_watches(monkeypatch):
    name = 'oopsie_watch_test_' + uuid.uuid4().hex
    database = engine.client[name]
    monkeypatch.setattr(realworld, 'db', database)
    try:
        yield database
    finally:
        engine.client.drop_database(name)


def test_public_cve_watch_is_scoped_and_keeps_source_receipt(isolated_watches, monkeypatch):
    revision = {'updated': '2025-04-08T15:17:05Z'}
    async def source(value):
        assert value == 'CVE-2025-29927'
        return {'cve_id': value, 'state': 'published', 'title': 'next.js middleware authorization bypass',
            'source_url': 'https://cveawg.mitre.org/api/cve/' + value, 'updated': revision['updated']}
    monkeypatch.setattr(realworld.realworld_sources, 'scan_cve', source)
    owner, stranger = uuid.uuid4().hex, uuid.uuid4().hex
    item = asyncio.run(realworld.create_watch(owner, 'cve', 'cve-2025-29927'))
    assert item['state'] == 'published'
    assert item['result']['source_url'].startswith('https://cveawg.mitre.org/api/cve/')
    assert item['history'][0]['summary'] == 'official cve record published'
    assert asyncio.run(realworld.create_watch(owner, 'cve', 'CVE-2025-29927'))['id'] == item['id']
    revision['updated'] = '2025-04-09T15:17:05Z'
    changed = asyncio.run(realworld.refresh_watch(owner, item['id']))
    assert changed['result']['change'] == 'official record update timestamp changed'
    assert len(changed['history']) == 2
    with pytest.raises(realworld.watch_error, match='not found in this workspace'):
        asyncio.run(realworld.refresh_watch(stranger, item['id']))
    assert isolated_watches.watch_targets.count_documents({'workspace': stranger}) == 0


def test_custom_url_waits_for_dns_proof_before_any_request(isolated_watches, monkeypatch):
    calls = []
    async def dns(url, token):
        calls.append(('dns', url, token))
        return True
    async def scan(url, expected_status, marker):
        calls.append(('scan', url, expected_status, marker))
        return {'status': 200, 'expected_status': 200, 'marker_matched': True,
            'passed': True, 'source_url': url, 'body_sha256': 'a' * 64}
    monkeypatch.setattr(realworld.realworld_urls, 'verify_dns', dns)
    monkeypatch.setattr(realworld.realworld_urls, 'scan_url', scan)
    workspace = uuid.uuid4().hex
    pending = asyncio.run(realworld.create_watch(workspace, 'url', 'https://example.com/health', 200, 'ready'))
    assert pending['state'] == 'awaiting verification'
    assert pending['result']['verification']['record'] == '_oopsie-challenge.example.com'
    assert calls == []
    with pytest.raises(realworld.watch_error, match='remove the existing url watch'):
        asyncio.run(realworld.create_watch(workspace, 'url', 'https://example.com/health', 200, 'different'))
    with pytest.raises(realworld.watch_error, match='verify dns ownership'):
        asyncio.run(realworld.refresh_watch(workspace, pending['id']))
    verified = asyncio.run(realworld.verify_url_watch(workspace, pending['id']))
    assert verified['state'] == 'passing' and verified['result']['marker_matched']
    assert [call[0] for call in calls] == ['dns', 'scan']
    assert 'verification_token' not in verified
