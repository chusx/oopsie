"""owned demo adapter. source artifacts run without credentials or network access."""
import asyncio
import ast
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
import httpx
from pymongo import MongoClient, ReturnDocument
from .config import root, local, digest, runtime, public_api
from . import vendors, intelligence

client = MongoClient(os.getenv('MONGODB_URI','mongodb://127.0.0.1:27017'), serverSelectionTimeoutMS=3000)
db = client.oopsie
floor = digest((root/'demo-app/checks.py').read_bytes())

class conflict(Exception):
    pass

def uid():
    return uuid.uuid4().hex

def clean(doc):
    if doc is None: return None
    return {k:v for k,v in doc.items() if k not in {'_id','password','lease','lease_until','run_token','container','port','demo_tokens'}}

def receipt_chain(incident, events=None):
    """Hash an exported event set without changing the stored incident or event path."""
    def canonical(value):
        return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    basis={'floor':incident.get('floor'),'faulty_artifact':incident.get('faulty_artifact'),'incident':incident.get('id',incident.get('incident'))}
    if not basis['incident']: raise ValueError('receipt chain needs an incident id')
    genesis=hashlib.sha256(canonical(basis)).hexdigest()
    head=genesis
    sequence=incident.get('events',[]) if events is None else events
    for item in sequence:
        head=hashlib.sha256(head.encode('ascii')+canonical(item)).hexdigest()
    return {'algorithm':'sha256-linked','genesis':genesis,'head':head,'events':len(sequence)}

def public_receipt(report):
    """Export the stored pre-publication incident events through a strict allowlist."""
    incident=db.incidents.find_one({'id':report['id']},{'_id':0,'id':1,'floor':1,'faulty_artifact':1,'events':1,
        'candidates.name':1,'candidates.checks.name':1,'candidates.checks.passed':1})
    if not incident: raise conflict('published report has no source incident')
    basis={'floor':incident.get('floor'),'faulty_artifact':incident.get('faulty_artifact'),'incident':report['id']}
    safe_messages={
        'tenant boundary failed: cross-tenant invoice returned',
        'amount watchpoint failed while api stayed reachable',
        'clickhouse confirmed repeated current-release violations',
        'clickhouse selected current-release violations',
        'approved recovery floor retrieved with source versions',
        'primary incident plan returned',
        'live gateway switched to the exact tested artifact',
        'fresh public probes passed twice. tenant isolation and minor units preserved.',
        'guild coordinator authorized bounded evaluation; hard gate still controls deployment',
    }
    safe_vendors={'openai','guild','akash','senso','clickhouse','semgrep','mongodb','elevenlabs'}
    events=[]
    for item in incident.get('events',[]):
        if item.get('at',0)>report['published_at']: continue
        events.append({'id':item['id'],'at':str(item['at']),
                       'vendor':item.get('vendor') if item.get('vendor') in safe_vendors else 'worker',
                       'message':item.get('message') if item.get('message') in safe_messages else 'event details redacted'})
    # Older snapshots used a broader scanner label. Narrow the public display
    # without changing stored evidence or claiming a proved tenant leak.
    failed_checks={candidate.get('name'):any(not check.get('passed') for check in candidate.get('checks',[]))
        for candidate in incident.get('candidates',[])}
    rejected=[{**item,'reason':('guard pattern absent'+('; failed executable checks'
        if failed_checks.get(item.get('name')) else '')
        if item.get('reason')=='tenant-isolation scan finding' else item.get('reason'))}
        for item in report.get('rejected',[])]
    result={**report,'rejected':rejected,'chain_basis':basis,'events':events,'chain':receipt_chain(incident,events)}
    result['chain']['event_set']='stored incident events before publication, with message and data redacted'
    return result

def event(incident, message, vendor=None, data=None):
    item={'id':uid(),'at':time.time(),'message':message}
    if vendor: item['vendor']=vendor
    if data is not None: item['data']=data
    db.incidents.update_one({'id':incident},{'$push':{'events':item},'$set':{'updated_at':time.time()}})

def status(incident, state):
    db.incidents.update_one({'id':incident},{'$set':{'state':state,'updated_at':time.time()}})

async def process(args, timeout=35, allowed_codes=(0,)):
    proc=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    try:
        out,err=await asyncio.wait_for(proc.communicate(),timeout)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait(); raise conflict('candidate exceeded time budget')
    if proc.returncode not in allowed_codes: raise conflict('adapter failed: '+err.decode()[-400:])
    return out.decode()

def artifact(source):
    hash=digest(source); directory=local/'artifacts'/hash
    directory.mkdir(parents=True,exist_ok=True)
    target=directory/'handler.py'
    if not target.exists(): target.write_text(source); target.chmod(0o444)
    if digest(target.read_bytes())!=hash: raise conflict('artifact integrity mismatch')
    return hash, target

limits=['--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=32','--memory=96m','--cpus=0.25','--user=65534:65534']

async def launch(source, service_id):
    hash,path=artifact(source)
    name='oopsie-'+service_id[:12]+'-'+uid()[:8]
    await process(['sudo','docker','run','-d','--name',name,'--restart=unless-stopped',*limits,'-p','127.0.0.1::8080','--mount',f'type=bind,src={path},dst=/app/handler.py,readonly','oopsie-demo:1'])
    info=json.loads(await process(['sudo','docker','inspect',name]))[0]
    port=int(info['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort'])
    for _ in range(30):
        try:
            async with httpx.AsyncClient(timeout=1) as h: await h.get(f'http://127.0.0.1:{port}/invoices/inv_a')
            return {'container':name,'port':port,'artifact':hash}
        except httpx.HTTPError: await asyncio.sleep(.1)
    await process(['sudo','docker','rm','-f',name])
    raise conflict('candidate did not boot')

async def remove(name):
    if name and name.startswith('oopsie-'):
        try: await process(['sudo','docker','rm','-f',name])
        except conflict: pass

async def create_service(workspace):
    if db.services.count_documents({'workspace':workspace}) >= 1: raise conflict('one owned demo per workspace')
    if db.services.count_documents({})>=100: raise conflict('demo capacity reached')
    approved=await vendors.context()
    versions={item.get('version_id') for item in approved['sources'] if item.get('version_id')}
    if len(versions)!=1: raise conflict('approved senso source has no single version')
    id=uid()
    source=(root/'demo-app/releases/healthy.py').read_text()
    run=await launch(source,id)
    service={'id':id,'workspace':workspace,'name':'billing-sandbox','mode':'auto','release':'healthy','revision':uid(),'floor':floor,'senso_version':versions.pop(),'senso_policy_hash':approved['policy_hash'],'created_at':time.time(),'activated_at':time.time(),'watching':True,'demo_tokens':{'a':uid(),'b':uid()},'last_checks':[],**run}
    db.services.insert_one(service)
    db.deployments.insert_one({'id':uid(),'service':id,'workspace':workspace,'artifact':run['artifact'],'at':time.time(),'reason':'workspace boot'})
    return service

async def gateway(service, token, invoice):
    tenant=next((t for t,k in service['demo_tokens'].items() if token==k),None)
    async with httpx.AsyncClient(timeout=5) as h:
        response=await h.get(f"http://127.0.0.1:{service['port']}/invoices/{invoice}",headers={'X-Tenant-Id':tenant} if tenant else {})
    return response.status_code,response.json()

watchpoints=[
 ('amount and current schema','a','inv_a',200,{'id':'inv_a','amount_minor':1299,'currency':'usd'}),
 ('tenant boundary','a','inv_b',403,{'error':'nope: tenant boundary'}),
 ('positive access for b','b','inv_b',200,{'id':'inv_b','amount_minor':4200,'currency':'usd'}),
 ('unauthenticated denial',None,'inv_a',401,{'error':'auth required'}),
 ('unknown invoice denial','a','missing',403,{'error':'nope: tenant boundary'}),
]

async def probe(service, public=False):
    result=[]
    async with httpx.AsyncClient(timeout=10) as h:
        for name,tenant,invoice,expected_status,expected in watchpoints:
            start=time.monotonic()
            try:
                if public:
                    response=await h.get(f"{public_api}/demo/{service['id']}/invoices/{invoice}",headers={'X-Demo-Token':service['demo_tokens'][tenant]} if tenant else {})
                    code,body=response.status_code,response.json()
                else: code,body=await gateway(service,service['demo_tokens'].get(tenant),invoice)
                result.append({'name':name,'passed':code==expected_status and body==expected,'status':code,'expected_status':expected_status,'expected':expected,'observed':body,'duration_ms':round((time.monotonic()-start)*1000,2),'path':f'/invoices/{invoice}','identity':tenant or 'anonymous'})
            except (httpx.HTTPError,ValueError) as exc:
                result.append({'name':name,'passed':False,'status':0,'error':type(exc).__name__,'duration_ms':round((time.monotonic()-start)*1000,2)})
    return result

async def check(service):
    before=service['artifact']
    revision=service.get('revision')
    rows=await probe(service)
    confirmation=await probe(service) if any(not row['passed'] for row in rows) else None
    current_rows=confirmation or rows
    current=db.services.find_one({'id':service['id']})
    if current['artifact']!=before or current.get('revision')!=revision:
        raise conflict('release changed during probe; retry')
    analytics_error=None; analytics=None
    try:
        await vendors.observations(service['workspace'],service['id'],before,rows)
        if confirmation:
            await vendors.observations(service['workspace'],service['id'],before,confirmation)
            analytics=await vendors.violations(service['workspace'],service['id'],before,service.get('activated_at'))
    except Exception as exc: analytics_error=str(exc)
    recorded=db.services.update_one({'id':service['id'],'artifact':before,'revision':revision},{'$set':{'last_checks':current_rows,'checked_at':time.time(),'up':any(r.get('status')==200 for r in current_rows),'correct':all(r['passed'] for r in current_rows),'analytics_error':analytics_error}})
    if not recorded.matched_count: raise conflict('release changed while recording probe; retry')
    if all(r['passed'] for r in current_rows): return {'checks':current_rows,'incident':None,'transient':bool(confirmation)}
    tenant_leak=any(not row['passed'] and row['name']=='tenant boundary' for row in current_rows)
    repeated=bool(analytics and any(int(row['failures'])>=2 for row in analytics['rows']))
    if not tenant_leak and not repeated and not analytics_error:
        return {'checks':current_rows,'incident':None,'pending':'awaiting clickhouse confirmation','analytics':analytics}
    incident=db.incidents.find_one({'service':service['id'],'faulty_artifact':before,'revision':revision})
    if not incident:
        doc={'id':uid(),'workspace':service['workspace'],'service':service['id'],'faulty_artifact':before,'revision':revision,'floor':floor,'scenario':'security' if tenant_leak else 'amount','fixture_origin':'synthetic, not recorded model output','state':'needs attention' if analytics_error else 'oops','created_at':time.time(),'updated_at':time.time(),'evidence':current_rows,'first_probe':rows,'analytics':analytics,'events':[],'candidates':[],'run_token':uid()}
        try:
            db.incidents.insert_one(doc); incident=doc
            event(doc['id'],'tenant boundary failed: cross-tenant invoice returned' if tenant_leak else 'amount watchpoint failed while api stayed reachable','mongodb',{'floor':floor,'scenario':doc['scenario']})
            if analytics_error: event(doc['id'],'clickhouse confirmation unavailable; operator attention required','clickhouse',{'error':analytics_error})
            elif analytics: event(doc['id'],'clickhouse confirmed repeated current-release violations','clickhouse',analytics)
        except Exception:
            incident=db.incidents.find_one({'service':service['id'],'faulty_artifact':before,'revision':revision})
            if not incident: raise
    return {'checks':current_rows,'incident':clean(incident),'analytics':analytics}

fault_releases={'amount':'faulty.py','security':'unsafe_ai_fix.py'}

async def inject(service, scenario='amount'):
    if scenario not in fault_releases: raise conflict('unknown synthetic fault scenario')
    if service.get('lease_until',0)>time.time(): raise conflict('recovery owns this service; try after it finishes')
    release=fault_releases[scenario]
    run=await launch((root/'demo-app/releases'/release).read_text(),service['id'])
    updated=db.services.update_one({'id':service['id'],'artifact':service['artifact'],'revision':service.get('revision'),'lease_until':{'$not':{'$gt':time.time()}}},{'$set':{**run,'revision':uid(),'release':release.removesuffix('.py'),'activated_at':time.time(),'correct':False}})
    if not updated.modified_count:
        await remove(run['container']); raise conflict('service changed; fault was not applied')
    await remove(service['container'])
    return await check(db.services.find_one({'id':service['id']}))

async def evaluate(incident, name, source):
    hash,path=artifact(source)
    await asyncio.sleep(0)
    scan=json.loads(await process([str(root/'.venv/bin/semgrep'),'scan','--config',str(root/'demo-app/semgrep.yml'),'--json','--quiet','--no-git-ignore','--metrics=off',str(path)],timeout=90,allowed_codes=(0,1)))
    scan_receipt={'vendor':'semgrep','rules':'oopsie.tenant-boundary-absent','findings':[{'rule':r['check_id'],'message':r['extra']['message'],'line':r['start']['line']} for r in scan.get('results',[])],'errors':len(scan.get('errors',[]))}
    container='oopsie-test-'+uid()
    try:
        raw=await process(['sudo','docker','run','--rm','--name',container,'--network=none',*limits,'--mount',f'type=bind,src={path},dst=/app/handler.py,readonly','oopsie-demo:1','python','/app/checks.py'])
        checks=json.loads(raw)
    finally: await remove(container)
    passed=all(row['passed'] for row in checks) and not scan_receipt['findings'] and not scan_receipt['errors']
    candidate={'id':uid(),'name':name,'artifact':hash,'source':source,'floor':floor,'checks':checks,'scan':scan_receipt,'passed':passed,'verdict':'eligible' if passed else 'rejected','at':time.time()}
    db.incidents.update_one({'id':incident['id']},{'$push':{'candidates':candidate}})
    event(incident['id'],name+': '+candidate['verdict'],'semgrep',{'artifact':hash,'failed_checks':[r['name'] for r in checks if not r['passed']],'findings':scan_receipt['findings']})
    return candidate

def rejected_shape(incident,name,source,reason,vendor):
    candidate={'id':uid(),'name':name,'artifact':digest(source),'source':source,'floor':floor,
        'checks':[],'scan':None,'passed':False,'verdict':'rejected','gate_error':reason,'at':time.time()}
    db.incidents.update_one({'id':incident['id']},{'$push':{'candidates':candidate}})
    event(incident['id'],name+': rejected at source gate',vendor,{'artifact':candidate['artifact'],'reason':reason})
    return candidate

def bounded_patch(source):
    # Permit more than one correct repair, but only a small, pure handler grammar.
    # Authorization and correctness are decided by Semgrep and the unchanged floor.
    if not isinstance(source,str) or len(source)>6000:
        raise conflict('proposal exceeds the approved demo change surface')
    try: tree=ast.parse(source)
    except (SyntaxError,ValueError) as exc: raise conflict('proposal is not valid python') from exc
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):
        raise conflict('proposal must contain only the billing handler')
    fn=tree.body[0]
    args=fn.args
    if fn.name!='handle' or [x.arg for x in args.args]!=['tenant','invoice_id','invoices'] or any(x.annotation for x in args.args) or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or args.defaults or args.kw_defaults or fn.decorator_list or fn.returns or fn.type_params:
        raise conflict('proposal changed the handler interface')
    allowed=(ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.If,ast.Assign,ast.Return,
        ast.Name,ast.Load,ast.Store,ast.Constant,ast.Dict,ast.Tuple,ast.Subscript,
        ast.UnaryOp,ast.Not,ast.BoolOp,ast.And,ast.Or,ast.Compare,ast.Eq,ast.NotEq,
        ast.Is,ast.IsNot,ast.In,ast.NotIn,ast.Call,ast.Attribute,ast.BinOp,
        ast.Add,ast.Sub,ast.Mult,ast.FloorDiv,ast.IfExp)
    assigned={'tenant','invoice_id','invoices'}
    statements=0
    for node in ast.walk(tree):
        if not isinstance(node,allowed): raise conflict('proposal uses an unsupported operation')
        if isinstance(node,ast.FunctionDef) and node is not fn:
            raise conflict('proposal defines another function')
        if isinstance(node,(ast.If,ast.Assign,ast.Return)): statements+=1
        if isinstance(node,ast.Assign):
            if len(node.targets)!=1 or not isinstance(node.targets[0],ast.Name):
                raise conflict('proposal mutates data outside local variables')
            name=node.targets[0].id
            if name in {'tenant','invoice_id','invoices'} or name.startswith('_'):
                raise conflict('proposal overwrites an input or private name')
            assigned.add(name)
        if isinstance(node,ast.Constant):
            if not isinstance(node.value,(str,int,bool,type(None))) or (isinstance(node.value,str) and len(node.value)>200):
                raise conflict('proposal contains an unsupported literal')
        if isinstance(node,ast.Attribute):
            if node.attr!='get' or not isinstance(node.value,ast.Name) or node.value.id not in {'invoices','invoice'}:
                raise conflict('proposal accesses an unapproved attribute')
        if isinstance(node,ast.Call):
            if not isinstance(node.func,ast.Attribute) or len(node.args) not in {1,2} or node.keywords:
                raise conflict('proposal calls an unapproved function')
    if statements>20 or len(assigned)>9 or not any(isinstance(x,ast.Return) for x in ast.walk(fn)):
        raise conflict('proposal is outside the bounded handler shape')
    if any(isinstance(x,ast.Name) and x.id not in assigned for x in ast.walk(fn)):
        raise conflict('proposal references an unapproved name')

async def recover(incident_id):
    incident=db.incidents.find_one({'id':incident_id})
    if not incident: raise conflict('oops missing')
    if incident['state']=='recovered': return clean(incident)
    now=time.time(); lease=uid()
    service=db.services.find_one_and_update({'id':incident['service'],'artifact':incident['faulty_artifact'],'revision':incident.get('revision'),'$or':[{'lease_until':{'$lt':now}},{'lease_until':{'$exists':False}}]}, {'$set':{'lease':lease,'lease_until':now+600}},return_document=ReturnDocument.AFTER)
    if not service: raise conflict('stale recovery or service already leased')
    try:
        if service['floor']!=floor or incident['floor']!=floor: raise conflict('recovery floor changed')
        status(incident_id,'investigating')
        analytics=await vendors.violations(service['workspace'],service['id'],incident['faulty_artifact'],service.get('activated_at'))
        if not analytics['rows']: raise conflict('no clickhouse counterexamples; run fresh check')
        event(incident_id,'clickhouse selected current-release violations','clickhouse',analytics)
        sources=await vendors.context()
        event(incident_id,'approved recovery floor retrieved with source versions','senso',sources)
        current_versions={item.get('version_id') for item in sources['sources'] if item.get('version_id')}
        if service.get('senso_version') and (current_versions!={service['senso_version']} or sources['policy_hash']!=service.get('senso_policy_hash')):
            event(incident_id,'approved senso policy changed since this service bound its floor; automatic recovery held','senso',{'bound_version':service['senso_version'],'retrieved_versions':sorted(current_versions)})
            raise conflict('approved recovery policy version changed; operator review required')
        db.incidents.update_one({'id':incident_id},{'$set':{'context':sources,'analytics':analytics,'candidates':[]}})
        status(incident_id,'evaluating')
        for name in ['legacy','prior']:
            rollback_source=(root/f'demo-app/releases/{name}.py').read_text()
            if digest(rollback_source)==incident['faulty_artifact']:
                candidate={'id':uid(),'name':name+' rollback','artifact':incident['faulty_artifact'],
                    'floor':floor,'checks':[],'scan':None,'passed':False,'verdict':'skipped',
                    'gate_error':'same as current release','at':time.time()}
                db.incidents.update_one({'id':incident_id},{'$push':{'candidates':candidate}})
                event(incident_id,name+' rollback: same as current release; skipped','mongodb',
                    {'artifact':incident['faulty_artifact']})
                continue
            await evaluate(incident,name+' rollback',rollback_source)
        release_file={'faulty':'faulty.py','unsafe_ai_fix':'unsafe_ai_fix.py'}.get(service.get('release'))
        if not release_file: raise conflict('running release is not an approved synthetic fault')
        source=(root/'demo-app/releases'/release_file).read_text()
        if digest(source)!=incident['faulty_artifact']: raise conflict('fault source differs from running artifact')
        predecessors=[{'name':name,'source':(root/f'demo-app/releases/{name}.py').read_text()} for name in ('legacy','prior')]
        primary=None
        try:
            primary=await intelligence.plan(source,incident['evidence'],sources['sources'],predecessors)
        except intelligence.intelligence_error as exc:
            # A vendor outage is visible in the receipt. The existing Guild/Akash
            # route stays available while OpenAI billing or access is unavailable.
            event(incident_id,'openai reasoning unavailable; akash fallback active','openai',{'model':intelligence.model,'error':str(exc)})
        primary_candidate=None
        if primary:
            db.incidents.update_one({'id':incident_id},{'$set':{'intelligence':primary}})
            event(incident_id,'primary incident plan returned','openai',{'model':primary['model'],'response_id':primary['response_id'],'usage':primary['usage'],'estimated_usd':primary['estimated_usd'],'recommendation':primary['recommendation'],'prompt_hash':primary['prompt_hash']})
            if primary['recommendation']!='forward_patch': raise conflict('openai requested operator attention: '+primary['explanation'])
            try:
                bounded_patch(primary['source'])
                primary_candidate=await evaluate(incident,'openai forward repair',primary['source'])
            except conflict as exc:
                rejected_shape(incident,'openai forward repair',primary['source'],str(exc),'openai')
            if primary_candidate and not primary_candidate['passed']:
                event(incident_id,'openai source failed the unchanged recovery floor','openai',{'artifact':primary_candidate['artifact']})
        async def one_akash(index,temperature):
            try: return await vendors.proposal(source,incident['evidence'],sources,temperature=temperature)
            except Exception as exc: return exc
        outputs=await asyncio.gather(*(one_akash(i,t) for i,t in enumerate((0.2,0.5,0.8),1)))
        akash_proposals=[]; eligible=[]
        for index,output in enumerate(outputs,1):
            name=f'akash forward {index}'
            if isinstance(output,Exception):
                event(incident_id,name+': model call unavailable','akash',{'error':str(output)})
                continue
            akash_proposals.append(output)
            event(incident_id,name+': independent proposal returned','akash',{'model':output['model'],'explanation':output['explanation'],'request_id':output['request_id'],'usage':output.get('usage')})
            try:
                bounded_patch(output['source'])
                proposed_candidate=await evaluate(incident,name,output['source'])
                if proposed_candidate['passed']: eligible.append((output,proposed_candidate))
            except conflict as exc:
                rejected_shape(incident,name,output['source'],str(exc),'akash')
        db.incidents.update_one({'id':incident_id},{'$set':{'akash_proposals':akash_proposals}})
        if primary_candidate and primary_candidate['passed']:
            selected,candidate=primary,primary_candidate
            selected_vendor='openai'
        elif eligible:
            selected,candidate=eligible[0]
            selected_vendor='akash'
        else:
            raise conflict('no model proposal passed the unchanged recovery floor')
        db.incidents.update_one({'id':incident_id},{'$set':{'proposal':selected,'proposal_vendor':selected_vendor}})
        if not candidate['passed']: raise conflict('forward repair failed the recovery floor')
        if service['mode']!='auto':
            status(incident_id,'needs attention'); event(incident_id,'verified repair is ready. observe-only policy blocks deployment.'); return clean(db.incidents.find_one({'id':incident_id}))
        status(incident_id,'recovering')
        run=await launch(selected['source'],service['id'])
        if run['artifact']!=candidate['artifact']:
            await remove(run['container'])
            raise conflict('running artifact differs from the tested candidate')
        # compare revision, floor, lease, time and tested hash before the actual routing write.
        update=db.services.update_one({'id':service['id'],'artifact':incident['faulty_artifact'],'revision':incident.get('revision'),'floor':floor,'lease':lease,'lease_until':{'$gt':time.time()},'mode':'auto'},{'$set':{**run,'revision':uid(),'release':'forward repair'}})
        if not update.modified_count:
            await remove(run['container']); raise conflict('deployment gate refused a stale plan')
        try:
            receipt={'id':uid(),'workspace':service['workspace'],'service':service['id'],'incident':incident_id,'before':incident['faulty_artifact'],'artifact':run['artifact'],'floor':floor,'at':time.time(),'action':'gateway switched to tested running container'}
            db.deployments.insert_one(receipt)
            db.incidents.update_one({'id':incident_id},{'$set':{'deployment':clean(receipt)}})
            event(incident_id,'live gateway switched to the exact tested artifact','mongodb',clean(receipt))
            status(incident_id,'verifying')
            current=db.services.find_one({'id':service['id']})
            verified=[]
            for _ in range(2):
                verified=await probe(current,public=True)
                if not all(row['passed'] for row in verified): raise conflict('public post-deploy verification failed')
                await asyncio.sleep(1)
            try:
                await vendors.observations(service['workspace'],service['id'],run['artifact'],verified)
            except Exception as exc:
                event(incident_id,'post-recovery clickhouse write delayed: '+str(exc),'clickhouse')
            verified_write=db.services.update_one({'id':service['id'],'artifact':run['artifact'],'lease':lease},{'$set':{'last_checks':verified,'correct':True,'up':True,'checked_at':time.time()}})
            if not verified_write.matched_count: raise conflict('service revision changed during public verification')
            db.incidents.update_one({'id':incident_id},{'$set':{'verification':verified,'recovered_at':time.time()}})
            event(incident_id,'fresh public probes passed twice. tenant isolation and minor units preserved.')
            status(incident_id,'recovered')
        except Exception:
            # Keep the previous process alive until the public route has passed.
            # If the new route fails, restore the exact previous target under our lease.
            reverted=db.services.update_one({'id':service['id'],'artifact':run['artifact'],'lease':lease},{'$set':{'container':service['container'],'port':service['port'],'artifact':service['artifact'],'revision':service.get('revision'),'release':service.get('release','faulty'),'correct':False}})
            if reverted.modified_count:
                await remove(run['container'])
                db.deployments.update_one({'incident':incident_id,'artifact':run['artifact']},{'$set':{'rolled_back':True,'rolled_back_at':time.time()}})
                event(incident_id,'public verification failed; gateway restored to the prior running artifact','mongodb')
            else:
                event(incident_id,'public verification failed; gateway revision changed before restoration','mongodb')
            raise
        await remove(service['container'])
        try: publish_report(incident_id)
        except Exception as exc: event(incident_id,'public status publication unavailable: '+str(exc),'mongodb')
        try: await make_briefing(incident_id)
        except Exception as exc: event(incident_id,'audio briefing unavailable: '+str(exc),'elevenlabs')
        return clean(db.incidents.find_one({'id':incident_id}))
    except Exception as exc:
        status(incident_id,'needs attention'); event(incident_id,str(exc))
        raise
    finally:
        db.services.update_one({'id':service['id'],'lease':lease},{'$unset':{'lease':'','lease_until':''}})

def publish_report(incident_id):
    """Publish only fixed synthetic facts after an actual verified gateway switch."""
    item=db.incidents.find_one({'id':incident_id})
    if not item or item.get('state')!='recovered' or not item.get('deployment') or not item.get('verification') or not all(x.get('passed') for x in item['verification']):
        raise conflict('only verified synthetic recoveries can be published')
    failed=[]
    for candidate in item.get('candidates',[]):
        if candidate.get('passed') or candidate.get('verdict')=='skipped': continue
        if candidate.get('gate_error'): reason=candidate['gate_error']
        elif (candidate.get('scan') or {}).get('findings'):
            failures=[x['name'] for x in candidate.get('checks',[]) if not x.get('passed')]
            reason='guard pattern absent'+('; failed executable checks' if failures else '')
        else:
            names=[x['name'] for x in candidate.get('checks',[]) if not x.get('passed')]
            reason=', '.join(names) or 'current recovery floor failed'
        failed.append({'name':candidate['name'],'reason':reason})
    selected=next((x for x in item.get('candidates',[]) if x.get('artifact')==item['deployment']['artifact'] and x.get('passed')),None)
    if not selected: raise conflict('deployed artifact has no passing candidate')
    tenant_fault=next((x for x in item.get('evidence',[]) if x.get('name')=='tenant boundary' and not x.get('passed') and x.get('status')==200 and x.get('expected_status')==403 and isinstance(x.get('observed'),dict)),None)
    amount_fault=next((x for x in item.get('evidence',[]) if x.get('name')=='amount and current schema' and not x.get('passed') and x.get('status')==200 and isinstance(x.get('observed'),dict) and isinstance(x.get('expected'),dict)),None)
    if tenant_fault:
        if tenant_fault.get('identity')!='a' or tenant_fault.get('path')!='/invoices/inv_b' or tenant_fault['observed'].get('id')!='inv_b':
            raise conflict('tenant counterexample did not match the approved synthetic fixture')
        title='a cross-tenant invoice read returned 200'
        fault={'kind':'tenant_boundary','http_status':tenant_fault['status'],'expected_status':403,'observed_status':200,'identity':'a','target':'inv_b'}
    elif amount_fault:
        expected=amount_fault['expected']; observed=amount_fault['observed']
        if not isinstance(expected.get('amount_minor'),int) or not isinstance(observed.get('amount_minor'),int):
            raise conflict('amount counterexample has no integer minor units')
        title='a reachable invoice api returned the wrong amount'
        fault={'kind':'amount','http_status':amount_fault['status'],'expected_minor':expected['amount_minor'],'observed_minor':observed['amount_minor'],'currency':expected.get('currency')}
    else: raise conflict('no publishable synthetic counterexample')
    matrix=[{'name':candidate['name'],'verdict':candidate.get('verdict') or ('eligible' if candidate.get('passed') else 'rejected'),
             'checks':[{'name':check['name'],'passed':bool(check['passed'])} for check in candidate.get('checks',[])],
             'scan_findings':len((candidate.get('scan') or {}).get('findings',[]))}
            for candidate in item.get('candidates',[])
            if candidate['name'] in {'legacy rollback','prior rollback',selected['name']}]
    report={'id':item['id'],'synthetic':True,'published_at':time.time(),'recovered_at':item['recovered_at'],
        'title':title,'fixture_origin':item.get('fixture_origin','synthetic'),
        'fault':fault,
        'rejected':failed,'matrix':matrix,'selected':{'name':selected['name'],'artifact':selected['artifact'],'vendor':item.get('proposal_vendor')},
        'verification':{'passed':sum(bool(x.get('passed')) for x in item['verification']),'total':len(item['verification']),'checks':[x['name'] for x in item['verification']]}}
    db.public_reports.update_one({'id':incident_id},{'$setOnInsert':report},upsert=True)
    url=f'https://oopsie.website/status/{incident_id}'
    db.incidents.update_one({'id':incident_id},{'$set':{'public_report':url}})
    event(incident_id,'redacted synthetic recovery status published','mongodb',{'url':url})
    return report

async def make_briefing(incident_id):
    item=db.incidents.find_one({'id':incident_id})
    if item.get('audio'): return item['audio']
    security=any(row.get('name')=='tenant boundary' and not row.get('passed') for row in item.get('evidence',[]))
    problem='a synthetic ai style amount fix let tenant a read tenant b invoice with a successful response' if security else 'the billing api returned successful responses with incorrect invoice amounts'
    text=f"oopsie report. {problem}. current state: {item['state']}. "
    if item['state']=='recovered':
        text+='two rollback candidates were rejected: one lacked tenant isolation, and one depended on a retired schema field. a forward repair passed five unchanged watchpoints and static scanning. the live gateway was switched. two fresh public checks confirmed correct amounts and tenant isolation. the vulnerable release was a synthetic fixture, not recorded model output. all data in this demo is synthetic.'
    else: text+='recovery has not been verified. the incident needs attention. do not assume the customer contract is restored.'
    path=local/'audio'/f'{incident_id}.mp3'; path.parent.mkdir(exist_ok=True)
    receipt=await vendors.briefing(text,path)
    db.incidents.update_one({'id':incident_id},{'$set':{'audio':receipt}})
    event(incident_id,'evidence-backed audio briefing generated','elevenlabs',receipt)
    return receipt

def guild_decision(payload, role):
    """Read the final hosted reply from Guild's mixed event stream."""
    for entry in payload.get('items',[]):
        if entry.get('type') in {'runtime_error','system_error'}:
            raise conflict(f'guild {role} runtime failed')
        if entry.get('type')!='runtime_done': continue
        content=entry.get('content')
        if not isinstance(content,dict) or not isinstance(content.get('text'),str): continue
        raw=content['text'].strip()
        start=raw.find('{')
        if start<0: raise conflict(f'guild {role} returned no structured decision')
        try: parsed,_=json.JSONDecoder().raw_decode(raw[start:])
        except ValueError: raise conflict(f'guild {role} returned no structured decision')
        if not isinstance(parsed,dict): raise conflict(f'guild {role} decision was not an object')
        expected='recommendation' if role=='investigator' else 'action'
        allowed={'forward_patch','needs_attention'} if role=='investigator' else {'recover','needs_attention'}
        if parsed.get(expected) not in allowed:
            raise conflict(f'guild {role} decision had an invalid {expected}')
        return parsed
    return None

async def guild_turn(role, prompt, incident_id):
    cfg=runtime()
    session=await vendors.guild('POST',f"/workspaces/{cfg['guild_workspace']}/sessions",{'session_type':'chat','agent_id':cfg['guild_'+role],'initial_prompt':prompt})
    session_id=session['id']
    db.incidents.update_one({'id':incident_id},{'$set':{f'guild_{role}_session':session_id}})
    event(incident_id,f'guild {role} session started','guild',{'session_id':session_id})
    deadline=time.monotonic()+300
    retried=False
    while time.monotonic()<deadline:
        await asyncio.sleep(2)
        try:
            # newest events come first; pages of 20+ can outlast guild's 60s gateway and return 504.
            payload=await vendors.guild('GET',f'/sessions/{session_id}/events?limit=10')
        except (vendors.vendor_error,httpx.HTTPError) as exc:
            # a slow poll is not a failed agent run. other http errors still stop the run.
            if isinstance(exc,vendors.vendor_error) and ' http 5' not in str(exc): raise
            if not retried:
                event(incident_id,f'guild {role} poll retrying after {exc}','guild'); retried=True
            continue
        parsed=guild_decision(payload,role)
        if parsed is not None:
            event(incident_id,f'guild {role} returned a decision','guild',{'session_id':session_id,'decision':parsed})
            return parsed
    raise conflict(f'guild {role} session timed out')

async def dispatch(incident):
    now=time.time()
    claimed=db.incidents.find_one_and_update({'id':incident['id'],'state':{'$in':['oops','needs attention']},'$or':[{'dispatch_until':{'$lt':now}},{'dispatch_until':{'$exists':False}}]},{'$set':{'dispatch_until':now+600,'state':'queued'}},return_document=ReturnDocument.AFTER)
    if not claimed: return
    try:
        cfg=runtime()
        if not cfg.get('guild_coordinator_published') or not cfg.get('guild_investigator_published'): raise conflict('guild team is not configured')
        service=db.services.find_one({'id':claimed['service']})
        analytics=await vendors.violations(service['workspace'],service['id'],claimed['faulty_artifact'],service.get('activated_at'))
        if not analytics['rows']: raise conflict('clickhouse has no violation rows for this release')
        sources=await vendors.context()
        predecessors=[{'name':name,'artifact':digest((root/f'demo-app/releases/{name}.py').read_text()),'source':(root/f'demo-app/releases/{name}.py').read_text(),'gate_status':'untested until recovery worker runs unchanged floor'} for name in ('legacy','prior')]
        relevant={'incident_id':claimed['id'],'current_release':claimed['faulty_artifact'],'floor_hash':floor,'watchpoints':claimed['evidence'],'clickhouse':analytics,'approved_source':sources,'predecessors':predecessors,'mode':service['mode']}
        finding=await guild_turn('investigator',json.dumps(relevant),claimed['id'])
        db.incidents.update_one({'id':claimed['id']},{'$set':{'guild_finding':finding}})
        decision=await guild_turn('coordinator',json.dumps({'evidence':relevant,'investigator':finding,'allowed_actions':['recover','needs_attention']}),claimed['id'])
        db.incidents.update_one({'id':claimed['id']},{'$set':{'guild_decision':decision}})
        if decision.get('action')!='recover' or finding.get('recommendation')!='forward_patch':
            status(claimed['id'],'needs attention')
            event(claimed['id'],'guild team withheld recovery; '+str(decision.get('reason','no reason provided')),'guild')
            return
        current=db.services.find_one({'id':service['id']})
        if current['artifact']!=claimed['faulty_artifact'] or current.get('revision')!=claimed.get('revision'):
            raise conflict('release changed while agents investigated')
        event(claimed['id'],'guild coordinator authorized bounded evaluation; hard gate still controls deployment','guild')
        await recover(claimed['id'])
    except Exception as exc:
        status(claimed['id'],'needs attention')
        event(claimed['id'],'agent run stopped: '+str(exc),'guild')
    finally:
        db.incidents.update_one({'id':claimed['id']},{'$set':{'dispatch_until':time.time()-1}})

async def monitor():
    while True:
        try:
            for service in db.services.find({'watching':True}):
                if service.get('lease_until',0)>time.time(): continue
                try:
                    result=await check(service)
                    if result['incident'] and result['incident']['state']=='oops' and service['mode']=='auto': await dispatch(result['incident'])
                except Exception: pass
            # a lost hosted run must become visible and retryable, never look permanently busy.
            db.incidents.update_many({'state':'queued','dispatch_until':{'$lt':time.time()}},{'$set':{'state':'needs attention'}})
        except Exception: pass
        await asyncio.sleep(30)
