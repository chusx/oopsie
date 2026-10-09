"""the recovery floor must survive real candidate execution and a failed live switch."""
import asyncio
import runpy
import shutil
import uuid

import pytest
from pymongo import MongoClient

from worker import engine


def test_security_fixture_is_distinct_and_preserves_amount_while_leaking_tenant():
    releases = engine.root / 'demo-app/releases'
    names = ('faulty', 'healthy', 'legacy', 'prior', 'unsafe_ai_fix')
    artifacts = {name: engine.digest((releases / f'{name}.py').read_bytes()) for name in names}
    assert len(set(artifacts.values())) == len(names)

    handle = runpy.run_path(str(releases / 'unsafe_ai_fix.py'))['handle']
    invoices = {
        'inv_a': {'tenant_id': 'a', 'amount_minor': 1299, 'currency': 'usd'},
        'inv_b': {'tenant_id': 'b', 'amount_minor': 4200, 'currency': 'usd'},
    }
    assert handle('a', 'inv_a', invoices) == (200, {'id': 'inv_a', 'amount_minor': 1299, 'currency': 'usd'})
    assert handle('b', 'inv_b', invoices) == (200, {'id': 'inv_b', 'amount_minor': 4200, 'currency': 'usd'})
    assert handle('a', 'inv_b', invoices)[0] == 200  # synthetic cross-tenant fault
    assert handle(None, 'inv_a', invoices)[0] == 401
    assert handle('a', 'missing', invoices)[0] == 403


@pytest.fixture
def isolated_db(monkeypatch):
    client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=1000)
    try:
        client.admin.command('ping')
    except Exception:
        pytest.skip('local mongodb is unavailable')
    name = 'oopsie_test_' + uuid.uuid4().hex
    database = client[name]
    monkeypatch.setattr(engine, 'db', database)
    try:
        yield database
    finally:
        client.drop_database(name)
        client.close()


def test_guild_reads_final_structured_reply():
    # Guild emits more than one runtime_done; the earlier one can carry a list.
    payload = {'items': [
        {'type': 'runtime_done', 'content': {'type': 'text', 'text': '```json\n{"action":"recover","reason":"current amount breach"}\n```'}},
        {'type': 'runtime_done', 'content': [{'type': 'text', 'text': 'partial'}]},
    ]}
    assert engine.guild_decision(payload, 'coordinator')['action'] == 'recover'
    assert engine.guild_decision({'items': [{'type': 'runtime_done', 'content': []}]}, 'coordinator') is None
    with pytest.raises(engine.conflict):
        engine.guild_decision({'items': [{'type': 'runtime_done', 'content': {'text': '{"action":"ignore"}'}}]}, 'coordinator')


def test_only_the_approved_forward_patch_fits_change_surface():
    healthy = (engine.root / 'demo-app/releases/healthy.py').read_text()
    engine.bounded_patch(healthy)
    # A second correct implementation is allowed; an old exact-AST gate was not.
    engine.bounded_patch(healthy.replace('invoices.get(invoice_id)', 'invoices.get(invoice_id, None)'))
    # A guardless handler is structurally safe to execute, then behavioral and
    # Semgrep gates must reject it rather than confusing shape with correctness.
    engine.bounded_patch(healthy.replace("invoice['tenant_id'] != tenant", 'False'))
    with pytest.raises(engine.conflict):
        engine.bounded_patch('import os\n'+healthy)
    with pytest.raises(engine.conflict):
        engine.bounded_patch(healthy+'\nopen("/tmp/escape", "w")\n')


@pytest.mark.skipif(shutil.which('sudo') is None or not (engine.root / '.venv/bin/semgrep').exists(), reason='demo runtime unavailable')
def test_executable_floor_rejects_both_rollbacks_and_accepts_repair(isolated_db):
    async def run():
        incident = {'id': uuid.uuid4().hex, 'candidates': [], 'events': []}
        isolated_db.incidents.insert_one(incident)
        results = {}
        for release in ('legacy', 'prior', 'faulty', 'unsafe_ai_fix', 'healthy'):
            source = (engine.root / f'demo-app/releases/{release}.py').read_text()
            results[release] = await engine.evaluate(incident, release, source)
        source=(engine.root/'demo-app/releases/healthy.py').read_text()
        results['novel'] = await engine.evaluate(incident,'novel safe source',source.replace('invoices.get(invoice_id)', 'invoices.get(invoice_id, None)'))
        results['guardless'] = await engine.evaluate(incident,'guardless generated-shaped source',source.replace("invoice['tenant_id'] != tenant", 'False'))
        return results

    results = asyncio.run(run())
    assert results['legacy']['passed'] is False
    assert results['legacy']['scan']['findings']
    assert results['prior']['passed'] is False
    assert any(row['name'] == 'amount and current schema' and not row['passed'] for row in results['prior']['checks'])
    assert results['faulty']['passed'] is False
    assert results['unsafe_ai_fix']['passed'] is False
    assert results['unsafe_ai_fix']['scan']['findings']
    assert [row['name'] for row in results['unsafe_ai_fix']['checks'] if not row['passed']] == ['tenant boundary']
    assert all(row['passed'] for row in results['unsafe_ai_fix']['checks'] if row['name']=='amount and current schema')
    assert results['healthy']['passed'] is True
    assert results['novel']['passed'] is True
    assert results['guardless']['passed'] is False
    assert results['guardless']['scan']['findings']
    assert all(row['passed'] for row in results['healthy']['checks'])
    assert len({item['floor'] for item in results.values()}) == 1


def test_recovery_skips_rollback_identical_to_running_artifact(isolated_db, monkeypatch, tmp_path):
    releases = tmp_path / 'demo-app/releases'
    releases.mkdir(parents=True)
    for name in ('legacy', 'prior'):
        source = (engine.root / f'demo-app/releases/{name}.py').read_text()
        (releases / f'{name}.py').write_text(source)
    # Reproduce the earlier synthetic fixture collision without changing the
    # real fixtures: the running release and legacy rollback have one hash.
    legacy_source = (releases / 'legacy.py').read_text()
    (releases / 'unsafe_ai_fix.py').write_text(legacy_source)
    monkeypatch.setattr(engine, 'root', tmp_path)

    service_id, incident_id, workspace, revision = (uuid.uuid4().hex for _ in range(4))
    artifact = engine.digest(legacy_source)
    isolated_db.services.insert_one({'id': service_id, 'workspace': workspace,
        'artifact': artifact, 'revision': revision, 'floor': engine.floor,
        'mode': 'auto', 'release': 'unsafe_ai_fix'})
    isolated_db.incidents.insert_one({'id': incident_id, 'service': service_id,
        'workspace': workspace, 'faulty_artifact': artifact, 'revision': revision,
        'floor': engine.floor, 'state': 'oops', 'evidence': [], 'events': [], 'candidates': []})

    async def violations(*args):
        return {'rows': [{'check_id': 'tenant boundary', 'failures': 2}]}
    async def context():
        return {'policy_hash': 'test-policy', 'sources': [{'version_id': 'test-v1'}]}
    evaluated = []
    async def stop_after_skip(incident, name, source):
        evaluated.append(name)
        raise RuntimeError('stop before model calls')
    monkeypatch.setattr(engine.vendors, 'violations', violations)
    monkeypatch.setattr(engine.vendors, 'context', context)
    monkeypatch.setattr(engine, 'evaluate', stop_after_skip)

    with pytest.raises(RuntimeError, match='stop before model calls'):
        asyncio.run(engine.recover(incident_id))
    incident = isolated_db.incidents.find_one({'id': incident_id})
    assert evaluated == ['prior rollback']
    assert len(incident['candidates']) == 1
    skipped = incident['candidates'][0]
    assert (skipped['name'], skipped['verdict'], skipped['artifact']) == (
        'legacy rollback', 'skipped', artifact)
    assert skipped['gate_error'] == 'same as current release'
    assert any('legacy rollback: same as current release' in row['message'] for row in incident['events'])
    assert isolated_db.services.find_one({'id': service_id}).get('lease') is None


def test_security_report_publishes_only_fixed_synthetic_counterexample(isolated_db):
    incident_id=uuid.uuid4().hex
    selected={'name':'openai forward repair','artifact':'sha256-test','passed':True,'checks':[],'scan':{'findings':[]}}
    evidence={'name':'tenant boundary','passed':False,'status':200,'expected_status':403,
        'identity':'a','path':'/invoices/inv_b','observed':{'id':'inv_b','amount_minor':4200,'currency':'usd'}}
    isolated_db.incidents.insert_one({'id':incident_id,'state':'recovered','deployment':{'artifact':'sha256-test'},
        'verification':[{'name':'tenant boundary','passed':True}], 'evidence':[evidence],
        'candidates':[selected], 'proposal_vendor':'openai', 'recovered_at':1, 'events':[],
        'fixture_origin':'synthetic, not recorded model output'})
    report=engine.publish_report(incident_id)
    assert report['fault']=={'kind':'tenant_boundary','http_status':200,'expected_status':403,
        'observed_status':200,'identity':'a','target':'inv_b'}
    assert report['selected']['artifact']=='sha256-test'
    assert 'amount_minor' not in str(report)


def test_failed_public_verification_restores_previous_route(isolated_db, monkeypatch):
    faulty = (engine.root / 'demo-app/releases/faulty.py').read_text()
    healthy = (engine.root / 'demo-app/releases/healthy.py').read_text()
    service_id, incident_id, workspace = uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex
    faulty_hash, healthy_hash = engine.digest(faulty), engine.digest(healthy)
    isolated_db.services.insert_one({'id': service_id, 'workspace': workspace, 'artifact': faulty_hash, 'floor': engine.floor, 'mode': 'auto', 'container': 'oopsie-old', 'port': 8123, 'release': 'faulty'})
    isolated_db.incidents.insert_one({'id': incident_id, 'workspace': workspace, 'service': service_id, 'faulty_artifact': faulty_hash, 'floor': engine.floor, 'state': 'oops', 'evidence': [{'passed': False}], 'events': [], 'candidates': []})
    async def violations(*args): return {'rows': [{'check_id': 'amount and current schema', 'failures': 1}]}
    async def context(): return {'sources': [{'text': 'minor units'}]}
    async def proposal(*args,**kwargs): return {'source': healthy, 'model': 'test', 'explanation': 'fix units', 'request_id': 'test'}
    async def no_openai(*args): raise engine.intelligence.intelligence_error('test quota unavailable')
    async def evaluate(*args): return {'passed': True, 'artifact': healthy_hash}
    async def launch(*args): return {'artifact': healthy_hash, 'container': 'oopsie-new', 'port': 8124}
    async def probe(*args, **kwargs): return [{'name': 'amount and current schema', 'passed': False}]
    removed = []
    async def remove(name): removed.append(name)
    async def no_delay(*args): return None
    monkeypatch.setattr(engine.vendors, 'violations', violations)
    monkeypatch.setattr(engine.vendors, 'context', context)
    monkeypatch.setattr(engine.vendors, 'proposal', proposal)
    monkeypatch.setattr(engine.intelligence, 'plan', no_openai)
    monkeypatch.setattr(engine, 'evaluate', evaluate)
    monkeypatch.setattr(engine, 'launch', launch)
    monkeypatch.setattr(engine, 'probe', probe)
    monkeypatch.setattr(engine, 'remove', remove)
    monkeypatch.setattr(engine.asyncio, 'sleep', no_delay)
    with pytest.raises(engine.conflict, match='public post-deploy verification failed'):
        asyncio.run(engine.recover(incident_id))
    route = isolated_db.services.find_one({'id': service_id})
    incident = isolated_db.incidents.find_one({'id': incident_id})
    receipt = isolated_db.deployments.find_one({'incident': incident_id})
    assert (route['artifact'], route['container'], route['port']) == (faulty_hash, 'oopsie-old', 8123)
    assert 'lease' not in route
    assert incident['state'] == 'needs attention'
    assert receipt['rolled_back'] is True
    assert removed == ['oopsie-new']


def test_same_faulty_artifact_can_raise_a_new_oops_after_a_new_deploy(isolated_db, monkeypatch):
    isolated_db.incidents.create_index([('service', 1), ('faulty_artifact', 1), ('revision', 1)], unique=True)
    service_id, workspace = uuid.uuid4().hex, uuid.uuid4().hex
    faulty_hash = engine.digest((engine.root / 'demo-app/releases/faulty.py').read_text())
    isolated_db.services.insert_one({'id': service_id, 'workspace': workspace, 'artifact': faulty_hash, 'revision': 'first', 'floor': engine.floor})
    async def failed_probe(*args): return [{'name': 'amount and current schema', 'passed': False, 'status': 200}]
    async def stored_observations(*args): return None
    async def violations(*args): return {'rows': [{'check_id':'amount and current schema','failures':2}]}
    monkeypatch.setattr(engine, 'probe', failed_probe)
    monkeypatch.setattr(engine.vendors, 'observations', stored_observations)
    monkeypatch.setattr(engine.vendors, 'violations', violations)
    first = asyncio.run(engine.check(isolated_db.services.find_one({'id': service_id})))['incident']
    isolated_db.incidents.update_one({'id': first['id']}, {'$set': {'state': 'recovered'}})
    isolated_db.services.update_one({'id': service_id}, {'$set': {'revision': 'second'}})
    second = asyncio.run(engine.check(isolated_db.services.find_one({'id': service_id})))['incident']
    assert first['id'] != second['id']
    assert second['state'] == 'oops'


def test_stale_revision_cannot_take_recovery_lease(isolated_db):
    service_id, incident_id, workspace = uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex
    artifact = engine.digest((engine.root / 'demo-app/releases/faulty.py').read_text())
    isolated_db.services.insert_one({'id': service_id, 'workspace': workspace, 'artifact': artifact, 'revision': 'current', 'floor': engine.floor, 'mode': 'auto'})
    isolated_db.incidents.insert_one({'id': incident_id, 'workspace': workspace, 'service': service_id, 'faulty_artifact': artifact, 'revision': 'old', 'floor': engine.floor, 'state': 'oops', 'events': []})
    with pytest.raises(engine.conflict, match='stale recovery'):
        asyncio.run(engine.recover(incident_id))
    assert isolated_db.services.find_one({'id': service_id}).get('lease') is None
    assert isolated_db.incidents.find_one({'id': incident_id})['state'] == 'oops'


def test_changed_senso_version_holds_recovery(isolated_db, monkeypatch):
    service_id, incident_id, workspace = uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex
    artifact = engine.digest((engine.root / 'demo-app/releases/faulty.py').read_text())
    isolated_db.services.insert_one({'id': service_id, 'workspace': workspace, 'artifact': artifact,
        'revision': 'current', 'floor': engine.floor, 'mode': 'auto', 'senso_version': 'approved-v1',
        'senso_policy_hash': 'policy-hash'})
    isolated_db.incidents.insert_one({'id': incident_id, 'workspace': workspace, 'service': service_id,
        'faulty_artifact': artifact, 'revision': 'current', 'floor': engine.floor, 'state': 'oops',
        'events': [], 'candidates': []})
    async def violations(*args): return {'rows': [{'check_id': 'amount', 'failures': 2}]}
    async def context(): return {'policy_hash': 'policy-hash', 'sources': [{'version_id': 'changed-v2'}]}
    monkeypatch.setattr(engine.vendors, 'violations', violations)
    monkeypatch.setattr(engine.vendors, 'context', context)
    with pytest.raises(engine.conflict, match='policy version changed'):
        asyncio.run(engine.recover(incident_id))
    item=isolated_db.incidents.find_one({'id':incident_id})
    assert item['state']=='needs attention'
    assert any(e.get('vendor')=='senso' and 'changed' in e['message'] for e in item['events'])
    assert isolated_db.services.find_one({'id':service_id}).get('lease') is None


def test_guild_poll_survives_a_transient_504_and_uses_small_pages(isolated_db, monkeypatch):
    # guild answered, but a 50-event page timed out at its gateway; one 504 must not kill recovery.
    incident_id = uuid.uuid4().hex
    isolated_db.incidents.insert_one({'id': incident_id, 'events': []})
    calls = []
    async def guild(method, path, body=None):
        calls.append((method, path))
        if method == 'POST': return {'id': 'session-1'}
        if sum(m == 'GET' for m, _ in calls) == 1: raise engine.vendors.vendor_error('api.guild.ai: http 504')
        return {'items': [{'type': 'runtime_done', 'content': {'type': 'text', 'text': '{"action":"recover","reason":"evidenced breach"}'}}]}
    async def no_delay(*args): return None
    monkeypatch.setattr(engine.vendors, 'guild', guild)
    monkeypatch.setattr(engine.asyncio, 'sleep', no_delay)
    monkeypatch.setattr(engine, 'runtime', lambda: {'guild_workspace': 'w', 'guild_coordinator': 'agent'})
    decision = asyncio.run(engine.guild_turn('coordinator', '{}', incident_id))
    assert decision['action'] == 'recover'
    assert all(path.endswith('limit=10') for method, path in calls if method == 'GET')
    assert any('retrying' in e['message'] for e in isolated_db.incidents.find_one({'id': incident_id})['events'])


def test_guild_poll_still_stops_on_non_transient_errors(isolated_db, monkeypatch):
    incident_id = uuid.uuid4().hex
    isolated_db.incidents.insert_one({'id': incident_id, 'events': []})
    async def guild(method, path, body=None):
        if method == 'POST': return {'id': 'session-1'}
        raise engine.vendors.vendor_error('api.guild.ai: http 401')
    async def no_delay(*args): return None
    monkeypatch.setattr(engine.vendors, 'guild', guild)
    monkeypatch.setattr(engine.asyncio, 'sleep', no_delay)
    monkeypatch.setattr(engine, 'runtime', lambda: {'guild_workspace': 'w', 'guild_investigator': 'agent'})
    with pytest.raises(engine.vendors.vendor_error, match='401'):
        asyncio.run(engine.guild_turn('investigator', '{}', incident_id))
