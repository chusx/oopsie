"""live workspace, api-key, mcp and synthetic gateway isolation check."""
import secrets
import json
import httpx
from worker.engine import db, remove
import asyncio

users=[]; services=[]
try:
    clients=[httpx.Client(base_url='https://app.oopsie.website',timeout=70) for _ in range(2)]
    for client in clients:
        email='isolation-'+secrets.token_hex(5)+'@oopsie.website'
        response=client.post('/api/auth/register',json={'email':email,'password':secrets.token_urlsafe(18)})
        assert response.status_code==200,response.text[:200]
        users.append(response.json())
    owner,other=clients
    response=owner.post('/api/services')
    assert response.status_code==200,response.text[:200]
    service=response.json(); services.append(service)
    service_id=service['id']
    watch=owner.post('/api/watches',json={'kind':'cve','value':'CVE-2025-29927'})
    assert watch.status_code==200,watch.text[:200]
    watch_id=watch.json()['id']
    assert watch.json()['result']['source_url']=='https://cveawg.mitre.org/api/cve/CVE-2025-29927'
    assert other.get('/api/watches/'+watch_id).status_code==404
    assert other.get('/api/watches').json()==[]
    assert other.get('/api/services/'+service_id).status_code==404
    assert other.get('/api/services/'+service_id+'/credentials').status_code==404
    assert other.post('/api/services/'+service_id+'/check').status_code==404
    tokens=owner.get('/api/services/'+service_id+'/credentials').json()['tokens']
    with httpx.Client(base_url='https://api.oopsie.website',timeout=15) as outside:
        path=f'/demo/{service_id}/invoices/inv_a'
        assert outside.get(path).status_code==401
        assert outside.get(path,headers={'X-Demo-Token':tokens['a']}).json()['amount_minor']==1299
        assert outside.get(f'/demo/{service_id}/invoices/inv_b',headers={'X-Demo-Token':tokens['a']}).status_code==403
        assert outside.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'}).status_code==401
        key=owner.post('/api/keys').json()
        auth={'Authorization':'Bearer '+key['key']}
        tools=outside.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list'},headers=auth).json()['result']['tools']
        assert {'replay_auth_bypass','recover_oops','check_service','inject_security_fault','get_release_timeline','list_watches','add_public_watch','add_url_watch','refresh_watch','verify_url_watch'} <= {t['name'] for t in tools}
        assert len(tools)==18
        call=outside.post('/mcp',json={'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'check_service','arguments':{'service_id':service_id}}},headers=auth).json()
        assert not call['result']['isError'],call
        timeline=outside.post('/mcp',json={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'get_release_timeline','arguments':{'service_id':service_id}}},headers=auth).json()
        assert not timeline['result']['isError'],timeline
        trace=json.loads(timeline['result']['content'][0]['text'])
        assert trace['vendor']=='clickhouse' and trace['rows'],trace
        watched=outside.post('/mcp',json={'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'list_watches','arguments':{}}},headers=auth).json()
        assert not watched['result']['isError'],watched
        assert json.loads(watched['result']['content'][0]['text'])[0]['id']==watch_id
        owner.delete('/api/keys/'+key['id'])
        assert outside.get('/api/me',headers=auth).status_code==401
    print('passed: workspace isolation, cve watch, gateway tenant boundary, api key revoke, 18 mcp tools and release trace')
finally:
    for service in services:
        row=db.services.find_one({'id':service['id']})
        if row: asyncio.run(remove(row['container']))
    for user in users:
        workspace=user['workspace']; uid=user['id']
        for name in ['services','workspaces','deployments','incidents','security_labs','watchpoints','contracts','watch_targets']:
            db[name].delete_many({'workspace':workspace} if name!='workspaces' else {'id':workspace})
        db.sessions.delete_many({'user':uid});db.api_keys.delete_many({'user':uid});db.users.delete_many({'id':uid})
    for client in locals().get('clients',[]): client.close()
