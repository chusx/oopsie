"""end-to-end acceptance test using a fresh synthetic workspace; no credentials are printed."""
import json
import secrets
import sys
import time
import httpx

scenario=sys.argv[1] if len(sys.argv)>1 else 'amount'
if scenario not in {'amount','security'}: raise SystemExit('usage: smoke_live.py [amount|security]')

email='smoke-'+secrets.token_hex(5)+'@oopsie.website'
password=secrets.token_urlsafe(20)
with httpx.Client(base_url='https://app.oopsie.website',timeout=90) as web:
    def call(method,path,**kwargs):
        response=web.request(method,path,**kwargs)
        if response.status_code>=400: raise RuntimeError(f'{method} {path}: http {response.status_code}: {response.text[:260]}')
        return response.json()
    call('POST','/api/auth/register',json={'email':email,'password':password})
    s=call('POST','/api/services')
    print('service',s['id'],s['release'])
    clean=call('POST',f"/api/services/{s['id']}/check")
    assert all(x['passed'] for x in clean['checks'])
    print('healthy checks',len(clean['checks']))
    fault=call('POST',f"/api/services/{s['id']}/fault",json={'scenario':scenario})
    assert fault['incident'] and any(not x['passed'] and x['status']==200 for x in fault['checks'])
    failed=[x['name'] for x in fault['checks'] if not x['passed']]
    assert failed==(['tenant boundary'] if scenario=='security' else ['amount and current schema']),failed
    incident=fault['incident']
    print('fault',incident['id'],'up-but-wrong',[(x['name'],x['status'],x['observed']) for x in fault['checks'] if not x['passed']])
    for i in range(65):
        time.sleep(5)
        item=call('GET',f"/api/incidents/{incident['id']}")
        print('poll',i,item['state'],'events',len(item.get('events',[])),'candidates',len(item.get('candidates',[])),flush=True)
        if item['state'] in {'recovered','needs attention'}:
            print('final',item['state'])
            print('events',[(x.get('vendor'),x['message']) for x in item.get('events',[])])
            print('candidates',[(x['name'],x['verdict']) for x in item.get('candidates',[])])
            if item['state']=='recovered':
                live=call('POST',f"/api/incidents/{incident['id']}/verify")
                print('public checks',[(x['name'],x['passed']) for x in live['checks']])
                assert all(x['passed'] for x in live['checks'])
                for _ in range(20):
                    item=call('GET',f"/api/incidents/{incident['id']}")
                    if item.get('public_report') and item.get('audio'): break
                    time.sleep(3)
                assert item.get('public_report'),'verified recovery did not publish status'
                assert item.get('audio'),'verified recovery did not generate audio'
                report=httpx.get(item['public_report'],timeout=15)
                assert report.status_code==200,report.status_code
                public=call('GET',f"/api/public/status/{incident['id']}")
                assert public['fault']['kind']==('tenant_boundary' if scenario=='security' else 'amount')
                print('published',item['public_report'],'audio_bytes',item['audio']['bytes'])
            else:
                raise RuntimeError('fresh recovery reached needs attention; inspect the incident receipt')
            break
    else: raise TimeoutError('fresh recovery did not reach a terminal state')
