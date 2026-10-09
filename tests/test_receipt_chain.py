"""Export-time receipt chains cover ordered events and stay publicly recomputable."""
import hashlib
import json
import uuid

from worker import engine


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def test_private_chain_is_stable_and_sensitive_to_event_edits():
    original={'id':'incident-1','floor':'floor-hash','faulty_artifact':'fault-hash','events':[
        {'id':'first','at':1,'message':'observed'},
        {'id':'second','at':2,'message':'verified'},
    ]}
    first=engine.receipt_chain(original)
    assert first==engine.receipt_chain(original)
    edited={**original,'events':[dict(original['events'][0],message='changed'),original['events'][1]]}
    reordered={**original,'events':list(reversed(original['events']))}
    dropped={**original,'events':original['events'][:1]}
    assert len({first['head'],engine.receipt_chain(edited)['head'],
                engine.receipt_chain(reordered)['head'],engine.receipt_chain(dropped)['head']})==4


def test_public_chain_recomputes_from_redacted_json_alone(monkeypatch):
    name='oopsie_chain_test_'+uuid.uuid4().hex
    test_db=engine.client[name]
    monkeypatch.setattr(engine,'db',test_db)
    incident_id=uuid.uuid4().hex
    test_db.incidents.insert_one({'id':incident_id,'floor':'approved-floor','faulty_artifact':'faulty-hash',
        'candidates':[{'name':'legacy rollback','checks':[{'name':'tenant boundary','passed':False}],
            'source':'private-source'}],
        'events':[
            {'id':'one','at':1.25,'vendor':'mongodb','message':'tenant boundary failed: cross-tenant invoice returned','data':{'token':'secret-token'}},
            {'id':'two','at':2.5,'vendor':'akash','message':'vendor error containing secret-token','data':{'source':'private-source'}},
            {'id':'three','at':4.5,'message':'audio generated after publication','data':{'key':'private-key'}},
        ]})
    report={'id':incident_id,'title':'synthetic tenant fault','synthetic':True,'fixture_origin':'synthetic',
            'published_at':3.0,'recovered_at':2.0,
            'fault':{'kind':'tenant_boundary','observed_status':200,'expected_status':403},
            'rejected':[{'name':'legacy rollback','reason':'tenant-isolation scan finding'}],
            'matrix':[],'selected':{'artifact':'repair-hash','name':'forward repair'},
            'verification':{'passed':5,'total':5,'checks':['tenant boundary']}}
    try:
        exported=engine.public_receipt(report)
        assert exported['chain_basis']=={'incident':incident_id,'floor':'approved-floor','faulty_artifact':'faulty-hash'}
        assert len(exported['events'])==2
        assert exported['events'][0]['message']=='tenant boundary failed: cross-tenant invoice returned'
        assert exported['events'][1]['message']=='event details redacted'
        assert 'secret-token' not in str(exported)
        assert 'private-source' not in str(exported)
        assert 'private-key' not in str(exported)
        assert exported['rejected'][0]['reason']=='guard pattern absent; failed executable checks'
        assert report['rejected'][0]['reason']=='tenant-isolation scan finding'
        head=hashlib.sha256(canonical(exported['chain_basis'])).hexdigest()
        assert head==exported['chain']['genesis']
        for event in exported['events']:
            head=hashlib.sha256(head.encode('ascii')+canonical(event)).hexdigest()
        assert head==exported['chain']['head']
        assert exported['chain']['events']==len(exported['events'])
    finally:
        engine.client.drop_database(name)
