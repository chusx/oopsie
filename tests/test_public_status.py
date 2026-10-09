"""A published receipt is a redacted projection of a verified synthetic action."""
import uuid

from worker import engine


def test_public_report_requires_verified_switch_and_excludes_private_state(monkeypatch):
    name='oopsie_report_test_'+uuid.uuid4().hex
    test_db=engine.client[name]
    monkeypatch.setattr(engine,'db',test_db)
    incident_id=uuid.uuid4().hex
    test_db.incidents.insert_one({'id':incident_id,'workspace':'private-workspace','state':'recovered',
        'recovered_at':1700000000.0,'demo_tokens':{'a':'private-token'},
        'evidence':[{'name':'amount and current schema','passed':False,'status':200,'expected':{'amount_minor':1299,'currency':'usd'},'observed':{'amount_minor':129900}}],
        'deployment':{'artifact':'tested-hash'},'verification':[{'name':'tenant boundary','passed':True}],
        'proposal_vendor':'akash','candidates':[
            {'name':'legacy rollback','passed':False,'artifact':'old-hash','scan':{'findings':[{'rule':'tenant'}]},'source':'private source'},
            {'name':'akash forward 1','passed':True,'artifact':'tested-hash','source':'private repair source'}],
        'events':[]})
    try:
        report=engine.publish_report(incident_id)
        assert report['selected']['artifact']=='tested-hash'
        assert report['rejected'][0]['reason']=='guard pattern absent'
        assert 'private-workspace' not in str(report)
        assert 'private-token' not in str(report)
        assert 'private source' not in str(report)
        assert test_db.incidents.find_one({'id':incident_id})['public_report'].endswith(incident_id)
        assert test_db.public_reports.find_one({'id':incident_id})
    finally:
        engine.client.drop_database(name)


def test_unverified_incident_cannot_publish(monkeypatch):
    name='oopsie_report_test_'+uuid.uuid4().hex
    test_db=engine.client[name]
    monkeypatch.setattr(engine,'db',test_db)
    incident_id=uuid.uuid4().hex
    test_db.incidents.insert_one({'id':incident_id,'state':'recovered','deployment':{'artifact':'x'},
        'verification':[{'passed':False}],'events':[]})
    try:
        try: engine.publish_report(incident_id)
        except engine.conflict: pass
        else: assert False,'unverified release must not be published'
        assert test_db.public_reports.count_documents({})==0
    finally:
        engine.client.drop_database(name)
