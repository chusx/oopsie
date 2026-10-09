import asyncio
import contextlib
import hashlib
import json
import re
import secrets
import time
from html import escape
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
import bcrypt
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pymongo.errors import DuplicateKeyError
from .config import root, local, runtime, digest
from . import engine, vendors, realworld

attempts=defaultdict(deque)
background=set()

def spawn(coro):
    task=asyncio.create_task(coro); background.add(task)
    def done(t):
        background.discard(t)
        if not t.cancelled(): t.exception()  # errors already recorded by the job
    task.add_done_callback(done)
    return task

@asynccontextmanager
async def lifespan(app):
    db=engine.db
    db.users.create_index('email',unique=True)
    db.users.create_index('id',unique=True)
    db.sessions.create_index('hash',unique=True)
    db.sessions.create_index('expires',expireAfterSeconds=0)
    db.services.create_index('workspace',unique=True)
    if 'service_1_faulty_artifact_1' in db.incidents.index_information():
        db.incidents.drop_index('service_1_faulty_artifact_1')
    db.incidents.create_index([('service',1),('faulty_artifact',1),('revision',1)],unique=True)
    db.api_keys.create_index('hash',unique=True)
    db.public_reports.create_index('id',unique=True)
    db.watch_targets.create_index([('workspace',1),('kind',1),('value',1)],unique=True)
    db.watch_targets.create_index('next_check_at')
    db.incidents.update_many({'state':{'$in':['investigating','evaluating','recovering','verifying']}},{'$set':{'state':'needs attention'}})
    task=spawn(engine.monitor())
    watch_task=spawn(realworld.monitor_watches())
    yield
    task.cancel()
    watch_task.cancel()
    for item in list(background): item.cancel()

app=FastAPI(title='oopsie api',version='1.0.0',lifespan=lifespan,description='workspace-scoped autonomous recovery for owned synthetic billing services. use a bearer api key from the web app.')

@app.exception_handler(engine.conflict)
async def conflict(request,exc): return JSONResponse({'detail':str(exc)},status_code=409)

@app.exception_handler(vendors.vendor_error)
async def vendor_problem(request,exc): return JSONResponse({'detail':str(exc)},status_code=502)

@app.exception_handler(realworld.watch_error)
async def watch_problem(request,exc): return JSONResponse({'detail':str(exc)},status_code=409)

@app.middleware('http')
async def boundary(request,call_next):
    origin=request.headers.get('origin')
    if origin and origin not in {'https://app.oopsie.website','https://api.oopsie.website','http://127.0.0.1:8000','http://localhost:8000'}:
        return JSONResponse({'detail':'origin rejected'},status_code=403)
    if request.method in {'POST','PUT','PATCH','DELETE'}:
        length=request.headers.get('content-length')
        if length and int(length)>131072: return JSONResponse({'detail':'request too large'},status_code=413)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.url.scheme=='https' or request.headers.get('x-forwarded-proto')=='https':
        response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    if request.url.path.startswith(('/api/','/mcp','/internal/')):
        response.headers['Cache-Control']='no-store'
    return response

def limit(request,action,count=12):
    now=time.time(); address=request.client.host if request.client else 'unknown'
    # trust caddy's overwrite of forwarding headers only from the loopback proxy.
    if address in {'127.0.0.1','::1'}: address=request.headers.get('x-forwarded-for',address).split(',')[0]
    queue=attempts[(address,action)]
    while queue and queue[0]<now-60: queue.popleft()
    if len(queue)>=count: raise HTTPException(429,'slow down a sec')
    queue.append(now)

def principal(request):
    token=request.headers.get('authorization','')
    if token.startswith('Bearer '):
        row=engine.db.api_keys.find_one({'hash':digest(token[7:]),'revoked':False})
        if row: return engine.db.users.find_one({'id':row['user']})
    session=request.cookies.get('__Host-oopsie') or request.cookies.get('oopsie_local')
    if session:
        row=engine.db.sessions.find_one({'hash':digest(session),'expires':{'$gt':datetime.now(timezone.utc)}})
        if row: return engine.db.users.find_one({'id':row['user']})
    raise HTTPException(401,'log in to your workspace')

def owned(user,collection,id):
    doc=engine.db[collection].find_one({'id':id,'workspace':user['workspace']})
    if not doc: raise HTTPException(404,'not found in your workspace')
    return doc

def signin(response,user,request):
    token=secrets.token_urlsafe(40)
    engine.db.sessions.insert_one({'hash':digest(token),'user':user['id'],'expires':datetime.now(timezone.utc)+timedelta(days=7)})
    secure=request.url.scheme=='https' or request.headers.get('x-forwarded-proto')=='https'
    response.set_cookie('__Host-oopsie' if secure else 'oopsie_local',token,max_age=604800,secure=secure,httponly=True,samesite='lax',path='/')
    return {'id':user['id'],'email':user['email'],'workspace':user['workspace']}

class auth_input(BaseModel):
    email: str = Field(min_length=3,max_length=254)
    password: str = Field(min_length=10,max_length=72)

@app.post('/api/auth/register')
async def register(body:auth_input,request:Request,response:Response):
    limit(request,'register',5)
    email=body.email.strip().lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email): raise HTTPException(422,'enter a valid email')
    user={'id':engine.uid(),'workspace':engine.uid(),'email':email,'password':bcrypt.hashpw(body.password.encode(),bcrypt.gensalt()).decode(),'created_at':time.time()}
    try: engine.db.users.insert_one(user)
    except DuplicateKeyError: raise HTTPException(409,'email already registered; log in')
    engine.db.workspaces.insert_one({'id':user['workspace'],'owner':user['id'],'created_at':time.time()})
    return signin(response,user,request)

@app.post('/api/auth/login')
async def login(body:auth_input,request:Request,response:Response):
    limit(request,'login')
    user=engine.db.users.find_one({'email':body.email.strip().lower()})
    if not user or not bcrypt.checkpw(body.password.encode(),user['password'].encode()): raise HTTPException(401,'email or password did not match')
    return signin(response,user,request)

@app.post('/api/auth/logout')
async def logout(request:Request,response:Response):
    for name in ['__Host-oopsie','oopsie_local']:
        token=request.cookies.get(name)
        if token: engine.db.sessions.delete_one({'hash':digest(token)})
        response.delete_cookie(name,path='/',secure=name.startswith('__Host'))
    return {'ok':True}

@app.get('/api/me')
async def me(request:Request):
    user=principal(request)
    return {k:user[k] for k in ['id','email','workspace']}

class password_input(BaseModel):
    current_password: str = Field(min_length=1,max_length=72)
    new_password: str = Field(min_length=10,max_length=72)

@app.post('/api/me/password')
async def change_password(body:password_input,request:Request,response:Response):
    user=principal(request); limit(request,'change password',4)
    current=body.current_password.encode()
    new=body.new_password.encode()
    if len(new)>72: raise HTTPException(422,'password must be at most 72 utf-8 bytes')
    if not bcrypt.checkpw(current,user['password'].encode()):
        raise HTTPException(401,'current password did not match')
    if bcrypt.checkpw(new,user['password'].encode()):
        raise HTTPException(409,'choose a different password')
    updated=engine.db.users.update_one({'id':user['id'],'password':user['password']},
        {'$set':{'password':bcrypt.hashpw(new,bcrypt.gensalt()).decode()}})
    if updated.modified_count!=1: raise HTTPException(409,'account changed; log in and retry')
    engine.db.sessions.delete_many({'user':user['id']})
    engine.db.api_keys.delete_many({'user':user['id']})
    for name in ['__Host-oopsie','oopsie_local']:
        response.delete_cookie(name,path='/',secure=name.startswith('__Host'))
    return {'ok':True,'sessions_revoked':True,'api_keys_revoked':True}

@app.get('/api/services')
async def services(request:Request):
    user=principal(request)
    return [engine.clean(s) for s in engine.db.services.find({'workspace':user['workspace']})]

@app.post('/api/services')
async def new_service(request:Request):
    user=principal(request); limit(request,'new service',3)
    return engine.clean(await engine.create_service(user['workspace']))

@app.get('/api/services/{id}')
async def service(id:str,request:Request): return engine.clean(owned(principal(request),'services',id))

@app.get('/api/services/{id}/credentials')
async def demo_credentials(id:str,request:Request):
    item=owned(principal(request),'services',id)
    return {'url':f'https://api.oopsie.website/demo/{id}/invoices/inv_a','header':'X-Demo-Token','tokens':item['demo_tokens'],'synthetic':True}

@app.post('/api/services/{id}/check')
async def check(id:str,request:Request):
    item=owned(principal(request),'services',id); limit(request,'checks',10)
    result=await engine.check(item)
    if result['incident'] and result['incident']['state']=='oops' and item['mode']=='auto': spawn(engine.dispatch(result['incident']))
    return result

class policy_input(BaseModel):
    mode: str

@app.patch('/api/services/{id}/recovery-policy')
async def policy(id:str,body:policy_input,request:Request):
    item=owned(principal(request),'services',id)
    if body.mode not in {'auto','observe'}: raise HTTPException(422,'choose auto or observe')
    engine.db.services.update_one({'id':id},{'$set':{'mode':body.mode}})
    return {'mode':body.mode,'floor':item['floor']}

@app.get('/api/services/{id}/watchpoints')
async def watchpoints(id:str,request:Request):
    item=owned(principal(request),'services',id)
    return {'floor':item['floor'],'policy':vendors.policy,'immutable':True,'checks':[{'name':n,'identity':t or 'anonymous','invoice':i,'expected_status':c,'expected':b} for n,t,i,c,b in engine.watchpoints],'source':(root/'demo-app/checks.py').read_text()}

@app.get('/api/services/{id}/timeline')
async def release_timeline(id:str,request:Request):
    item=owned(principal(request),'services',id); limit(request,'timeline',12)
    return await vendors.release_timeline(item['workspace'],item['id'])

class fault_input(BaseModel):
    scenario: str = 'amount'

@app.post('/api/services/{id}/fault')
async def fault(id:str,request:Request,body:fault_input|None=None):
    item=owned(principal(request),'services',id); limit(request,'fault',3)
    scenario=body.scenario if body else 'amount'
    if scenario not in engine.fault_releases: raise HTTPException(422,'choose amount or security')
    latest=engine.db.incidents.find_one({'service':id},sort=[('created_at',-1)])
    if latest and latest.get('created_at',0)>time.time()-45: raise HTTPException(429,'wait 45 seconds between fault runs')
    result=await engine.inject(item,scenario)
    if result['incident'] and result['incident']['state']=='oops' and item['mode']=='auto': spawn(engine.dispatch(result['incident']))
    return result

@app.get('/api/incidents')
async def incidents(request:Request):
    user=principal(request)
    return [engine.clean(x) for x in engine.db.incidents.find({'workspace':user['workspace']}).sort('created_at',-1).limit(50)]

@app.get('/api/incidents/{id}')
async def incident(id:str,request:Request): return engine.clean(owned(principal(request),'incidents',id))

@app.post('/api/incidents/{id}/recover')
async def recover(id:str,request:Request):
    item=owned(principal(request),'incidents',id); limit(request,'recover',4)
    if item['state']=='recovered': return engine.clean(item)
    spawn(engine.dispatch(item))
    return {'id':id,'status':'recovery requested'}

@app.post('/api/incidents/{id}/verify')
async def verify(id:str,request:Request):
    item=owned(principal(request),'incidents',id)
    service=owned(principal(request),'services',item['service'])
    return {'checks':await engine.probe(service,public=True),'artifact':service['artifact']}

@app.get('/api/incidents/{id}/receipt')
async def receipt(id:str,request:Request):
    item=engine.clean(owned(principal(request),'incidents',id))
    item['chain']=engine.receipt_chain(item)
    item['chain']['event_set']='stored private incident events at export'
    return JSONResponse(item,headers={'Content-Disposition':f'attachment; filename="oops-{id[:8]}.json"'})

@app.post('/api/incidents/{id}/briefing')
async def briefing(id:str,request:Request):
    owned(principal(request),'incidents',id); limit(request,'briefing',3)
    return await engine.make_briefing(id)

@app.get('/api/incidents/{id}/audio')
async def audio(id:str,request:Request):
    owned(principal(request),'incidents',id)
    path=local/'audio'/f'{id}.mp3'
    if not path.exists(): raise HTTPException(404,'briefing not generated yet')
    return FileResponse(path,media_type='audio/mpeg')

class watch_input(BaseModel):
    kind: str = Field(min_length=3,max_length=16)
    value: str = Field(min_length=3,max_length=1024)
    expected_status: int = 200
    marker: str = Field(default='',max_length=100)

@app.get('/api/watches')
async def watches(request:Request):
    user=principal(request)
    return [realworld.public_watch(item) for item in engine.db.watch_targets.find(
        {'workspace':user['workspace']}).sort('created_at',-1).limit(20)]

@app.post('/api/watches')
async def add_watch(body:watch_input,request:Request):
    user=principal(request); limit(request,'add watch',5)
    return await realworld.create_watch(user['workspace'],body.kind,body.value,body.expected_status,body.marker)

@app.get('/api/watches/{id}')
async def watch(id:str,request:Request):
    item=owned(principal(request),'watch_targets',id)
    return realworld.public_watch(item)

@app.post('/api/watches/{id}/refresh')
async def refresh_watch(id:str,request:Request):
    user=principal(request); limit(request,'refresh watch',6)
    return await realworld.refresh_watch(user['workspace'],id,manual=True)

@app.post('/api/watches/{id}/verify')
async def verify_watch(id:str,request:Request):
    user=principal(request); limit(request,'verify watch',6)
    return await realworld.verify_url_watch(user['workspace'],id)

@app.delete('/api/watches/{id}')
async def delete_watch(id:str,request:Request):
    user=principal(request)
    result=engine.db.watch_targets.delete_one({'id':id,'workspace':user['workspace']})
    if not result.deleted_count: raise HTTPException(404,'not found in your workspace')
    return {'ok':True}

@app.get('/api/integrations')
async def integrations(request:Request):
    user=principal(request)
    cfg=runtime()
    latest=engine.db.incidents.find_one({'workspace':user['workspace']},sort=[('created_at',-1)])
    events=latest.get('events',[]) if latest else []
    names=['openai','guild','akash','senso','clickhouse','semgrep','mongodb','elevenlabs']
    available={
        'openai':bool(vendors.key('openai','OPENAI_API_KEY')),
        'guild':bool(cfg.get('guild_coordinator_published') and cfg.get('guild_investigator_published')),
        'akash':bool(vendors.key('akashml','AKASHML_API_KEY')),
        'senso':bool(cfg.get('senso_node')),
        'clickhouse':bool(cfg.get('ch_bound')),
        'semgrep':(root/'.venv/bin/semgrep').exists(),
        'mongodb':True,
        'elevenlabs':bool(vendors.key('elevenlabs','ELEVENLABS_API_KEY')),
    }
    return [{'name':name,'configured':available[name],'latest_incident':latest['id'] if latest else None,'observed':any(e.get('vendor')==name and (name!='openai' or e.get('message')=='primary incident plan returned') for e in events),'last_event':next(({'at':e['at'],'message':e['message']} for e in reversed(events) if e.get('vendor')==name),None)} for name in names]

def status_shell(content,title):
    return HTMLResponse('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+escape(title)+' — oopsie</title><link rel="icon" href="/assets/icon.svg"><link rel="stylesheet" href="/assets/style.css"><script src="/assets/theme.js" defer></script></head><body class="status-page"><div class="site"><header class="nav"><a class="brand" href="/"><span class="glyph">o.</span>oopsie</a><nav><a href="/">home</a><a href="/status">public status</a><button class="theme-toggle" type="button" aria-label="switch to light mode" title="switch theme">◐</button><a class="nav-cta" href="https://app.oopsie.website">open the console ↗</a></nav></header><main class="status-main"><p class="kicker"><span class="kicker-rule"></span> published synthetic receipts</p>'+content+'</main><footer><a class="brand" href="/"><span class="glyph">o.</span>oopsie</a><span>synthetic data · real actions · public receipts</span><a href="/">home</a></footer></div></body></html>')

def status_matrix(report):
    rows=report.get('matrix') or []
    if not rows:
        return '<p class="empty">candidate check details were not included in this earlier publication.</p>'
    checks=report['verification']['checks']
    head=''.join('<th scope="col">'+escape(name)+'</th>' for name in checks)
    body=''
    for row in rows:
        results={entry['name']:entry['passed'] for entry in row.get('checks',[])}
        cells=''
        for name in checks:
            result=results.get(name)
            label='pass' if result is True else 'fail' if result is False else 'not run'
            kind='pass' if result is True else 'fail' if result is False else 'pending'
            symbol='✓' if result is True else '×' if result is False else '—'
            cells+='<td class="matrix-cell '+kind+'" aria-label="'+label+'"><span aria-hidden="true">'+symbol+'</span></td>'
        body+='<tr><th scope="row">'+escape(row['name'])+'<small>'+escape(row['verdict'])+'</small></th>'+cells+'</tr>'
    return '<table class="candidate-matrix"><thead><tr><th scope="col">candidate</th>'+head+'</tr></thead><tbody>'+body+'</tbody></table>'

@app.get('/status')
async def public_status_index():
    items=list(engine.db.public_reports.find({}, {'_id':0,'id':1,'published_at':1}).sort('published_at',-1).limit(20))
    rows=''.join('<a class="status-list-item" href="/status/'+escape(x['id'])+'"><span class="status-list-stamp">verified recovery</span><strong>oops '+escape(x['id'][:8])+'</strong><time>'+escape(datetime.fromtimestamp(x['published_at'],timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))+'</time><span aria-hidden="true">↗</span></a>' for x in items)
    return status_shell('<h1>public status.</h1><p class="lede">each report records a real gateway switch and fresh public checks on an owned synthetic invoice service. customer identities and credentials stay private.</p><div class="status-list">'+(rows or '<p>no verified synthetic recovery has been published yet.</p>')+'</div>','public status')

@app.get('/status/{id}')
async def public_status_report(id:str):
    report=engine.db.public_reports.find_one({'id':id},{'_id':0})
    if not report: raise HTTPException(404,'published report not found')
    report=engine.public_receipt(report)
    selected=report['selected']; verification=report['verification']; fault=report['fault']
    money=lambda minor: ('$'+f'{minor/100:,.2f}') if fault.get('currency')=='usd' else str(minor)+' minor units'
    when=escape(datetime.fromtimestamp(report['recovered_at'],timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    rejected=''.join('<div class="ticket-line"><span>'+escape(x['name'])+'</span><strong class="rejected">rejected</strong><small>'+escape(x['reason'])+'</small></div>' for x in report['rejected'])
    security=fault.get('kind')=='tenant_boundary'
    if security:
        lede='tenant a received tenant b\'s invoice with http 200. the boundary check caught the cross-tenant read; a tested repair was shipped and verified on the public endpoint.'
        facts=[('request identity','tenant '+escape(fault['identity'])),('target invoice',escape(fault['target'])),('expected http',str(fault['expected_status'])),('observed http',str(fault['observed_status']))]
    else:
        lede='the api returned '+str(fault['http_status'])+' with the wrong invoice amount. old releases failed current checks; a tested repair was shipped and verified on the public endpoint.'
        facts=[('http response',str(fault['http_status'])+' ok'),('expected amount',escape(money(fault['expected_minor']))),('amount returned',escape(money(fault['observed_minor']))),('public checks',str(verification['passed'])+'/'+str(verification['total'])+' passed')]
    content='<div class="report-heading"><div><h1>oops '+escape(id[:8])+'.</h1><p class="lede">'+lede+'</p></div><span class="recovered-stamp">recovered <span aria-hidden="true">✓</span></span></div>'
    content+='<div class="report-facts">'+''.join('<div><span>'+label+'</span><strong'+(' class="wrong"' if label in {'amount returned','observed http'} else '')+'>'+value+'</strong></div>' for label,value in facts)+'</div>'
    content+='<article class="recovery-ticket"><div class="ticket-head"><div><span class="ticket-label">published recovery receipt</span><h2>the rollback trap, resolved.</h2></div><span class="ticket-id">oops '+escape(id[:8])+'</span></div><div class="ticket-lines">'+rejected+'<div class="ticket-line shipped"><span>'+escape(selected['name'])+'</span><strong>shipped</strong><small>'+escape(selected.get('vendor') or 'model')+' proposal</small></div></div><div class="ticket-foot"><span>verified '+when+'</span><span>artifact sha256 <code>'+escape(selected['artifact'])+'</code></span></div></article>'
    content+='<section class="report-matrix"><h2>the unchanged recovery floor.</h2><p>the same five watchpoints were run for each candidate. blank cells mean the candidate was stopped before execution.</p><div class="matrix-wrap">'+status_matrix(report)+'</div><p class="matrix-swipe">swipe across the table to see all five checks →</p></section>'
    if (local/'audio'/f'{id}.mp3').exists():
        content+='<section class="report-audio"><h2>listen to the recovery.</h2><p>an evidence-backed briefing generated after the verified gateway switch.</p><audio controls preload="none" src="/status/'+escape(id)+'/audio"></audio></section>'
    chain_head=report['chain']['head']
    content+='<section class="report-audio"><h2>check the receipt chain.</h2><p>recompute the hash over redacted incident events recorded before publication. save this head independently to notice later server-side changes.</p><p>published head <code class="chain-head">'+escape(chain_head)+'</code></p><button class="button ghost" type="button" id="recompute-chain" data-incident="'+escape(id)+'" data-head="'+escape(chain_head)+'">recompute head</button><p id="chain-result" role="status" aria-live="polite"></p><p>detects edits relative to the published head. it is not a signature and does not prove the events were true.</p></section>'
    content+='<p class="report-note">this report uses synthetic data. the vulnerable release was a synthetic fixture, not recorded model output. it contains no customer identities, access tokens, or source code.</p>'
    content+='<script src="/assets/status-chain.js" defer></script>'
    return status_shell(content,'oops '+id[:8]+' recovered')

@app.get('/status/{id}/audio')
async def public_status_audio(id:str):
    if not engine.db.public_reports.find_one({'id':id},{'_id':1}):
        raise HTTPException(404,'published report not found')
    path=local/'audio'/f'{id}.mp3'
    if not path.exists(): raise HTTPException(404,'briefing not generated yet')
    return FileResponse(path,media_type='audio/mpeg')

@app.get('/api/public/status/latest')
async def public_status_latest():
    report=engine.db.public_reports.find_one({}, {'_id':0},sort=[('published_at',-1)])
    if not report: raise HTTPException(404,'no published report yet')
    return engine.public_receipt(report)

@app.get('/api/public/status/{id}')
async def public_status_json(id:str):
    report=engine.db.public_reports.find_one({'id':id},{'_id':0})
    if not report: raise HTTPException(404,'published report not found')
    return engine.public_receipt(report)


@app.post('/api/keys')
async def create_key(request:Request):
    user=principal(request); limit(request,'keys',4)
    if engine.db.api_keys.count_documents({'user':user['id'],'revoked':False})>=5: raise HTTPException(409,'five active keys max; revoke one first')
    token='oops_'+secrets.token_urlsafe(36); id=engine.uid()
    engine.db.api_keys.insert_one({'id':id,'user':user['id'],'workspace':user['workspace'],'hash':digest(token),'prefix':token[:12],'revoked':False,'created_at':time.time()})
    return {'id':id,'key':token,'note':'copy once. use Authorization: Bearer on api and mcp.'}

@app.get('/api/keys')
async def keys(request:Request):
    user=principal(request)
    return list(engine.db.api_keys.find({'user':user['id']},{'_id':0,'hash':0,'workspace':0,'user':0}))

@app.delete('/api/keys/{id}')
async def revoke(id:str,request:Request):
    user=principal(request)
    engine.db.api_keys.update_one({'id':id,'user':user['id']},{'$set':{'revoked':True}})
    return {'ok':True}

class worker_input(BaseModel):
    incident_id: str = Field(pattern='^[a-f0-9]{32}$')
    run_token: str = Field(pattern='^[a-f0-9]{32}$')

def worker_auth(request,body):
    auth=request.headers.get('x-api-key','')
    if not secrets.compare_digest(auth,runtime()['worker_key']): raise HTTPException(401,'worker credential required')
    item=engine.db.incidents.find_one({'id':body.incident_id,'run_token':body.run_token})
    if not item: raise HTTPException(404,'scoped run missing')
    return item

@app.post('/internal/inspect',operation_id='inspect_oops',include_in_schema=False)
async def inspect(body:worker_input,request:Request):
    item=worker_auth(request,body)
    engine.event(item['id'],'hosted agent inspected the counterexample','guild')
    return engine.clean(item)

@app.post('/internal/recover',operation_id='execute_recovery',include_in_schema=False)
async def execute(body:worker_input,request:Request):
    item=worker_auth(request,body)
    if item['state']=='recovered': return {'id':item['id'],'state':'recovered'}
    engine.event(item['id'],'hosted agent invoked the bounded recovery worker','guild')
    # tool returns quickly; durable incident state is polled by the next agent operation.
    spawn(engine.recover(item['id']))
    return {'id':item['id'],'state':'running','message':'worker started. inspect_oops to read evidence; never claim success before recovered.'}

# stateless streamable http mcp: json responses, no session resources or sse needed.
mcp_tools=[
 ('list_services','list owned services',{}),('boot_service','boot your isolated synthetic billing sandbox',{}),
 ('check_service','run five immutable watchpoints',{'service_id':{'type':'string'}}),
 ('inject_fault','introduce the incorrect amount fault into your owned synthetic service',{'service_id':{'type':'string'}}),
 ('inject_security_fault','introduce a synthetic cross-tenant invoice read into your owned service',{'service_id':{'type':'string'}}),
 ('list_oops','list workspace oops reports',{}),
 ('get_oops','read an oops and candidate evidence',{'incident_id':{'type':'string'}}),
 ('recover_oops','dispatch hosted recovery; policy and verification gate all writes',{'incident_id':{'type':'string'}}),
 ('get_recovery_floor','read immutable policy and executable checks',{'service_id':{'type':'string'}}),
 ('get_release_timeline','read clickhouse watchpoint counts by minute and release',{'service_id':{'type':'string'}}),
 ('verify_live_service','fresh checks through public gateway',{'incident_id':{'type':'string'}}),
 ('create_briefing','generate evidence-backed audio briefing',{'incident_id':{'type':'string'}}),
 ('replay_auth_bypass','reproduce cve-2025-29927 in the isolated synthetic next.js lab',{}),
 ('list_watches','list workspace-scoped, read-only outside signal watches',{}),
 ('add_public_watch','watch a public github repository or official cve record; no outside deployment',{'kind':{'type':'string','enum':['github','cve']},'value':{'type':'string'}}),
 ('add_url_watch','create a custom https contract watch pending dns ownership verification',{'url':{'type':'string'},'expected_status':{'type':'integer'},'marker':{'type':'string'}}),
 ('refresh_watch','refresh one owned public repo, cve, or verified https watch',{'watch_id':{'type':'string'}}),
 ('verify_url_watch','check dns ownership proof for an owned custom https watch',{'watch_id':{'type':'string'}}),
]

@app.post('/mcp')
async def mcp(request:Request):
    user=principal(request); limit(request,'mcp',60)
    msg=await request.json(); id=msg.get('id'); method=msg.get('method'); params=msg.get('params',{})
    if isinstance(method,str) and method.startswith('notifications/'):
        return Response(status_code=202)
    def result(value): return {'jsonrpc':'2.0','id':id,'result':value}
    if method=='initialize':
        supported=['2024-11-05','2025-03-26','2025-06-18']
        return result({'protocolVersion':params.get('protocolVersion') if params.get('protocolVersion') in supported else '2025-03-26','capabilities':{'tools':{'listChanged':False}},'serverInfo':{'name':'oopsie','version':'1.0.0'},'instructions':'all operations apply only to your workspace. demo data is synthetic. recovery dispatches a hosted job; poll get_oops for the actual result.'})
    if method=='ping': return result({})
    if method=='tools/list': return result({'tools':[{'name':n,'description':d,'inputSchema':{'type':'object','properties':p,'required':list(p),'additionalProperties':False}} for n,d,p in mcp_tools]})
    if method=='tools/call':
        name=params.get('name'); args=params.get('arguments',{})
        try:
            if name=='list_services': value=await services(request)
            elif name=='boot_service': value=await new_service(request)
            elif name=='check_service': value=await check(args['service_id'],request)
            elif name=='inject_fault': value=await fault(args['service_id'],request)
            elif name=='inject_security_fault': value=await fault(args['service_id'],request,fault_input(scenario='security'))
            elif name=='list_oops': value=await incidents(request)
            elif name=='get_oops': value=await incident(args['incident_id'],request)
            elif name=='recover_oops': value=await recover(args['incident_id'],request)
            elif name=='get_recovery_floor': value=await watchpoints(args['service_id'],request)
            elif name=='get_release_timeline': value=await release_timeline(args['service_id'],request)
            elif name=='verify_live_service': value=await verify(args['incident_id'],request)
            elif name=='create_briefing': value=await briefing(args['incident_id'],request)
            elif name=='replay_auth_bypass': value=await replay_lab(request)
            elif name=='list_watches': value=await watches(request)
            elif name=='add_public_watch': value=await add_watch(watch_input(kind=args['kind'],value=args['value']),request)
            elif name=='add_url_watch': value=await add_watch(watch_input(kind='url',value=args['url'],expected_status=args['expected_status'],marker=args['marker']),request)
            elif name=='refresh_watch': value=await refresh_watch(args['watch_id'],request)
            elif name=='verify_url_watch': value=await verify_watch(args['watch_id'],request)
            else: return {'jsonrpc':'2.0','id':id,'error':{'code':-32602,'message':'unknown tool'}}
            return result({'content':[{'type':'text','text':json.dumps(value)}],'isError':False})
        except (HTTPException,engine.conflict,vendors.vendor_error,realworld.watch_error,KeyError) as exc:
            return result({'content':[{'type':'text','text':str(getattr(exc,'detail',exc))}],'isError':True})
    return {'jsonrpc':'2.0','id':id,'error':{'code':-32601,'message':'method not found'}}

@app.get('/mcp')
async def mcp_get(): return Response(status_code=405,headers={'Allow':'POST'})

@app.get('/demo/{service_id}/invoices/{invoice_id}')
async def public_demo(service_id:str,invoice_id:str,request:Request):
    # this is the workspace owner's synthetic service, reached with a separate demo token.
    if invoice_id not in {'inv_a','inv_b','missing'}: raise HTTPException(404,'synthetic invoice not found')
    item=engine.db.services.find_one({'id':service_id})
    if not item: raise HTTPException(404,'demo service not found')
    code,body=await engine.gateway(item,request.headers.get('x-demo-token'),invoice_id)
    return JSONResponse(body,status_code=code)

@app.get('/api/labs/nextjs')
async def lab(request:Request):
    user=principal(request)
    receipt=engine.db.security_labs.find_one({'workspace':user['workspace']},sort=[('at',-1)])
    return {'name':'next.js middleware auth bypass','cve':'cve-2025-29927','version':'14.2.24','advisory':'https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw','scope':'isolated, synthetic, locally bound lab; separate from the billing recovery fixture','latest':engine.clean(receipt)}

@app.post('/api/labs/nextjs/replay')
async def replay_lab(request:Request):
    user=principal(request); limit(request,'security lab',3)
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        baseline=await client.get('http://127.0.0.1:3111/api/vault')
        bypass=await client.get('http://127.0.0.1:3111/api/vault',headers={'x-middleware-subrequest':'middleware:middleware:middleware:middleware:middleware'})
        patched=await client.get('http://127.0.0.1:3112/api/vault',headers={'x-middleware-subrequest':'middleware:middleware:middleware:middleware:middleware'})
        patched_auth=await client.get('http://127.0.0.1:3112/api/vault',headers={'x-demo-auth':'a'})
    if baseline.status_code!=401 or bypass.status_code!=200 or patched.status_code!=401 or patched_auth.status_code!=200 or not bypass.json().get('synthetic'):
        raise HTTPException(502,'lab reproduction did not match advisory')
    item={'id':engine.uid(),'workspace':user['workspace'],'at':time.time(),'cve':'cve-2025-29927','version':'next.js 14.2.24','baseline':{'status':baseline.status_code,'body':baseline.json()},'bypass':{'status':bypass.status_code,'body':bypass.json(),'header':'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'},'patched':{'version':'next.js 14.2.25','status':patched.status_code,'body':patched.json(),'authorized_status':patched_auth.status_code},'advisory':'https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw','scope':'synthetic data on a loopback-bound container'}
    engine.db.security_labs.insert_one(item)
    return engine.clean(item)

@app.get('/healthz')
async def health():
    engine.db.command('ping')
    return {'status':'ok','service':'oopsie'}

app.mount('/assets',StaticFiles(directory=root/'web'),name='assets')

@app.get('/')
async def index(request:Request):
    host=request.headers.get('host','').split(':')[0]
    if host=='api.oopsie.website': return {'service':'oopsie api','openapi':'/docs','mcp':'/mcp','health':'/healthz','authentication':'bearer api key from app.oopsie.website'}
    return FileResponse(root/'web'/('landing.html' if host=='oopsie.website' else 'app.html'))
