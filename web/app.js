const q=(s)=>document.querySelector(s);
const h=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let state={me:null,services:[],incidents:[],view:new URLSearchParams(location.search).get('view')==='watch'?'realwatch':'overview',active:null,authMode:'register',keyOnce:null,busy:false,timeline:null,timelineService:null,timelineArtifact:null,timelineAt:0,watches:null,watchLoading:false,watchError:null,watchAt:0};
let loadSerial=0;
function toast(text){let e=q('#toast');e.textContent=text;e.style.display='block';clearTimeout(toast.t);toast.t=setTimeout(()=>e.style.display='none',5500)}
async function api(path,options={}){let r=await fetch('/api'+path,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(options.headers||{})},...options});let b=await r.json().catch(()=>({detail:'bad server response'}));if(!r.ok)throw Error(typeof b.detail==='string'?b.detail:'request failed');return b}
function clearPrivateState(){state.me=null;state.services=[];state.incidents=[];state.active=null;state.watches=null;state.keyOnce=null}
async function load(background=false){
  const serial=++loadSerial,wasAuthed=!!state.me,viewAtStart=state.view;
  const before=background?JSON.stringify([state.me,state.services,state.incidents]):null;
  try{
    const me=await api('/me');
    const [services,incidents]=await Promise.all([api('/services'),api('/incidents')]);
    if(serial!==loadSerial)return;
    state.me=me;state.services=services;state.incidents=incidents;
    if(background&&wasAuthed&&state.view!==viewAtStart)return;
    if(background&&before===JSON.stringify([me,services,incidents]))return;
    if(!['realwatch','profile'].includes(state.view)||!wasAuthed){
      const scrollTop=background&&wasAuthed?q('.console-main')?.scrollTop:null;
      render();
      if(scrollTop!==null&&q('.console-main'))q('.console-main').scrollTop=scrollTop;
    }
  }catch(e){if(serial!==loadSerial)return;clearPrivateState();render()}
}
function action(fn){return async(...args)=>{if(state.busy)return;state.busy=true;try{await fn(...args)}catch(e){toast(e.message)}finally{state.busy=false}}}
function auth(){let register=state.authMode==='register';q('#app').innerHTML=`<div class="auth"><div class="auth-art"><a class="brand" href="https://oopsie.website"><span class="glyph">o.</span>oopsie</a><button class="theme-toggle" type="button" aria-label="switch to light mode" title="switch theme">◐</button><div><div class="kicker"><span class="kicker-rule"></span> autonomous recovery agent</div><h1>the api stayed up.<br><em>the promise broke.</em></h1><p>oopsie catches wrong results behind healthy responses, tests proposed repairs against the current contract, and verifies the one that goes live.</p></div><span class="small mono">owned demo service · public recovery receipts</span></div><div class="auth-form"><div><div class="section-label">${register?'new workspace':'welcome back'}</div><h2>${register?'create a workspace.':'log into oopsie.'}</h2><p class="small">${register?'your own isolated demo service starts after signup.':'your recovery receipts are waiting.'}</p><form id="auth-form"><label class="field">email<input name="email" type="email" autocomplete="email" required maxlength="254"></label><label class="field">password<input name="password" type="password" autocomplete="${register?'new-password':'current-password'}" minlength="10" required></label><button class="btn primary" type="submit">${register?'create workspace →':'log in →'}</button></form><div class="auth-toggle">${register?'already have a workspace?':'new here?'} <button id="toggle-auth">${register?'log in':'create one'}</button></div></div></div></div>`;q('#toggle-auth').onclick=()=>{state.authMode=register?'login':'register';render()};q('#auth-form').onsubmit=action(async(e)=>{e.preventDefault();let f=new FormData(e.target);await api('/auth/'+state.authMode,{method:'POST',body:JSON.stringify({email:f.get('email'),password:f.get('password')})});await load()})}
function nav(){
  let items=[['overview','⌁','overview'],['realwatch','◉','real-world watch'],['watchpoints','◎','watchpoints'],['oops','⚡','oops reports'],['lab','↯','security lab'],['systems','▦','systems'],['access','⌘','api + mcp']];
  let email=state.me.email,initial=email.slice(0,1).toLowerCase()||'o';
  return `<aside class="sidebar"><a class="brand" href="https://oopsie.website"><span class="glyph">o.</span>oopsie</a><button class="theme-toggle" type="button" aria-label="switch to light mode" title="switch theme">◐</button><div class="side-sub">recovery console · v1</div><div class="side-nav">${items.map(([id,icon,label])=>`<button data-view="${id}" class="${state.view===id?'active':''}">${icon}&nbsp; ${label}</button>`).join('')}</div><div class="sidebar-account"><div class="sidebar-account-head"><span class="sidebar-avatar" aria-hidden="true">${h(initial)}</span><div><span>signed in as</span><strong title="${h(email)}">${h(email)}</strong></div></div><div class="sidebar-account-actions"><button type="button" data-view="profile" class="${state.view==='profile'?'active':''}">profile / password</button><button type="button" id="logout">log out</button></div></div></aside>`
}
function shell(html){q('#app').innerHTML=`<div class="console">${nav()}<main class="console-main"><div class="console-top"><div>workspace / <span class="mono">${h(state.me.workspace.slice(0,8))}</span></div></div>${html}</main></div>`;document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>{state.view=b.dataset.view;state.active=null;render()});q('.sidebar').addEventListener('wheel',e=>{if(Math.abs(e.deltaY)>=Math.abs(e.deltaX))e.preventDefault()},{passive:false});q('#logout').onclick=action(async()=>{await api('/auth/logout',{method:'POST'});clearPrivateState();state.authMode='login';state.view='overview';render()})}
function badge(x){let good=x==='recovered'||x===true||x==='healthy';return `<span class="status-pill ${good?'good':x==='oops'||x==='needs attention'||x===false?'bad':''}">${h(typeof x==='boolean'?(x?'passing':'fault'):x||'watching')}</span>`}
function renderTimeline(data){
  const el=q('#timeline-content');if(!el)return;
  const allRows=(data.rows||[]).filter(r=>Number.isFinite(Number(r.probes))&&Number(r.probes)>0&&Number.isFinite(Number(r.failures)));
  if(!allRows.length){el.innerHTML='<div class="empty">no clickhouse observations yet. run the five watchpoints to start this trace.</div>';return}
  const releases=new Map();
  for(const r of allRows){const key=String(r.release),entry=releases.get(key)||{probes:0,failures:0};entry.probes+=Number(r.probes);entry.failures+=Number(r.failures);releases.set(key,entry)}
  const totalProbes=[...releases.values()].reduce((sum,x)=>sum+x.probes,0);
  const totalFailures=[...releases.values()].reduce((sum,x)=>sum+x.failures,0);
  const latest=allRows.at(-1),latestProbes=Number(latest.probes),latestFailures=Number(latest.failures);
  const stride=Math.max(1,Math.ceil(allRows.length/55));
  const rows=allRows.filter((r,i)=>i%stride===0||Number(r.failures)>0||i===allRows.length-1);
  const max=Math.max(...allRows.map(r=>Number(r.probes)));
  const bars=rows.map((r,index)=>{
    const probes=Number(r.probes),failures=Math.min(probes,Math.max(0,Number(r.failures)));
    const heightBucket=Math.max(1,Math.ceil(probes/max*10)),failureBucket=failures?Math.max(1,Math.round(failures/probes*10)):0;
    const label=`${r.minute} · release ${String(r.release).slice(0,12)} · ${failures}/${probes} failed`;
    return `<button type="button" class="timeline-bar h-${heightBucket} f-${failureBucket}" data-timeline-index="${index}" title="${h(label)}" aria-label="${h(label)}"><span></span></button>`;
  }).join('');
  const summary=[...releases].map(([release,x])=>`<div class="timeline-release"><span class="timeline-swatch ${x.failures?'fault':''}"></span><code>${h(release.slice(0,12))}</code><strong>${h(x.failures)}/${h(x.probes)} failed</strong></div>`).join('');
  const stats=data.statistics||{};
  el.innerHTML=`<div class="timeline-readout"><div class="timeline-readout-primary ${totalFailures?'fault':''}"><span class="section-label">observed / last 24h</span><div class="timeline-signal"><strong>${h(totalFailures)}</strong><span>failed checks<br>of ${h(totalProbes)} probes</span></div></div><div class="timeline-readout-latest"><span class="small">latest minute</span><strong>${h(latestFailures)}/${h(latestProbes)} failed</strong><span class="mono small">${h(latest.minute)} · ${h(String(latest.release).slice(0,12))}</span></div></div><p class="small">select a minute to inspect it. rust marks failed checks; green marks passing checks.${stride>1?' long traces sample passing minutes and keep every failed minute.':''}</p><div class="timeline-plot" role="group" aria-label="${allRows.length} measured release-minute buckets from clickhouse">${bars}</div><div class="timeline-axis"><span>${h(allRows[0].minute)}</span><span>${h(allRows.at(-1).minute)}</span></div><div class="timeline-selected" id="timeline-selected" aria-live="polite"></div><div class="timeline-releases">${summary}</div><div class="mono small">clickhouse query ${h(data.query_id||'unavailable')} · ${h(stats.elapsed_ms??'—')} ms · ${h(stats.rows_read??'—')} rows read</div>`;
  const select=(index)=>{
    const r=rows[index],probes=Number(r.probes),failures=Math.min(probes,Math.max(0,Number(r.failures)));
    el.querySelectorAll('.timeline-bar').forEach((bar,i)=>bar.classList.toggle('selected',i===index));
    const detail=el.querySelector('#timeline-selected');detail.classList.toggle('fault',!!failures);
    detail.innerHTML=`<span class="timeline-selected-state ${failures?'fault':''}">${failures?'fault seen':'checks passing'}</span><strong>${h(failures)}/${h(probes)} failed</strong><span class="mono small">${h(r.minute)} · release ${h(String(r.release).slice(0,12))}</span>`;
  };
  el.querySelectorAll('.timeline-bar').forEach((bar,index)=>bar.onclick=()=>select(index));
  let selected=rows.length-1;for(let i=0;i<rows.length;i++)if(Number(rows[i].failures)>0)selected=i;
  select(selected);
}
async function loadTimeline(service){let same=state.timelineService===service.id&&state.timelineArtifact===service.artifact;if(same&&state.timeline&&Date.now()-state.timelineAt<60000){renderTimeline(state.timeline);return}try{let data=await api('/services/'+service.id+'/timeline');state.timeline=data;state.timelineService=service.id;state.timelineArtifact=service.artifact;state.timelineAt=Date.now();if(state.view==='overview'&&state.services[0]?.id===service.id)renderTimeline(data)}catch(e){let el=q('#timeline-content');if(el)el.innerHTML='<div class="empty">release trace unavailable: '+h(e.message)+'</div>'}}
function overview(){let s=state.services[0],open=state.incidents.filter(i=>i.state!=='recovered');let content=`<div class="section-label">workspace online</div><h1>your services.</h1><p class="lede">your service can be up and still be wrong. this console keeps score on the promises that matter.</p><div class="stats"><div class="card"><div class="card-label">services watched</div><div class="card-value">${state.services.length}</div><p>isolated synthetic billing api</p></div><div class="card"><div class="card-label">open oops</div><div class="card-value">${open.length}</div><p>contract violations to inspect</p></div><div class="card"><div class="card-label">recovered</div><div class="card-value">${state.incidents.filter(i=>i.state==='recovered').length}</div><p>live repairs with receipts</p></div></div>`;
if(!s) content+=`<div class="panel"><div class="panel-body"><div class="section-label">start here</div><h2>boot your billing sandbox.</h2><p class="small">this starts a private running api with two synthetic customers and a locked five-check recovery floor.</p><button class="btn primary" id="boot">boot sandbox →</button></div></div>`;
else content+=`<div class="panel"><div class="panel-head"><h2>billing-sandbox</h2>${badge(s.correct===undefined?'watching':s.correct)}</div><div class="panel-body"><div class="row"><div><div class="mono">${h(s.release)}</div><div class="mono small">artifact ${h(s.artifact.slice(0,18))}...</div></div><div class="btn-row"><button class="btn" id="check">run watchpoints</button><button class="btn warn" id="security-fault">inject tenant leak</button><button class="btn" id="fault">inject amount fault</button></div></div><p class="small">both faults use synthetic releases. the tenant leak mimics an unsafe ai-style amount fix; it is not recorded model output. wait 45 seconds between runs.</p><p class="small">reachability: ${s.up?'up':'not checked'} · correctness: ${s.correct===true?'verified':s.correct===false?'broken':'not checked'} · recovery mode: ${h(s.mode)}</p></div></div>`;
if(s)content+=`<div class="panel"><div class="panel-head"><h2>release pulse.</h2><a class="small link" href="/api/services/${h(s.id)}/timeline" target="_blank" rel="noreferrer">raw clickhouse json ↗</a></div><div class="panel-body" id="timeline-content"><div class="empty">reading the release trace...</div></div></div>`;
content+=`<div class="panel"><div class="panel-head"><h2>latest oops reports</h2><span class="small mono">${state.incidents.length} total</span></div><div class="panel-body">${state.incidents.length?state.incidents.slice(0,5).map(i=>`<div class="row"><div><a href="#oops/${i.id}" class="link incident-link" data-id="${i.id}">oops ${h(i.id.slice(0,8))}</a><div class="small mono">${new Date(i.created_at*1000).toLocaleString()}</div></div>${badge(i.state)}</div>`).join(''):'<div class="empty">no oops yet. boot the sandbox, then inject a synthetic tenant leak.</div>'}</div></div>`;
shell(content);bindCommon();if(s)loadTimeline(s);if(q('#boot'))q('#boot').onclick=action(async()=>{await api('/services',{method:'POST'});toast('sandbox booted. live invoices ready.');await load()});if(q('#check'))q('#check').onclick=action(async()=>{let r=await api('/services/'+s.id+'/check',{method:'POST'});toast(r.incident?'oops found. recovery team dispatched.':r.pending?'fault seen; awaiting clickhouse confirmation.':r.transient?'transient fault cleared on confirmation.':'five watchpoints pass.');await load()});async function inject(scenario){let x=await api('/services/'+s.id+'/fault',{method:'POST',body:JSON.stringify({scenario})});toast(x.incident?.state==='oops'?(scenario==='security'?'tenant leak found. recovery team dispatched.':'amount fault found. recovery team dispatched.'):'fault detected. operator attention may be needed.');state.view='oops';await load()}if(q('#fault'))q('#fault').onclick=action(()=>inject('amount'));if(q('#security-fault'))q('#security-fault').onclick=action(()=>inject('security'))}
function bindCommon(){document.querySelectorAll('.incident-link').forEach(x=>x.onclick=(e)=>{e.preventDefault();state.view='oops';state.active=x.dataset.id;render()})}
function watchpoints(){let s=state.services[0];let content=`<div class="section-label">current recovery floor</div><h1>watchpoints.</h1><p class="lede">five executable promises. the agent can propose a fix; it cannot edit these tests or dial the floor down.</p>`;if(!s){content+='<div class="empty">boot a sandbox on the overview first.</div>';shell(content);return}content+=`<div class="panel"><div class="panel-head"><h2>contract / billing v1</h2><span class="status-pill good">locked</span></div><div class="panel-body"><div class="mono small">sha256 ${h(s.floor)}</div><div class="checks">${(s.last_checks||[]).length?s.last_checks.map(r=>`<div class="check"><span class="${r.passed?'pass':'fail'}">${r.passed?'✓':'×'}</span><span>${h(r.name)}</span><span>${r.status||'err'}</span></div>`).join(''):'<div class="empty">run the checks to see live results.</div>'}</div></div></div><div class="panel"><div class="panel-head"><h2>recovery mode</h2></div><div class="panel-body"><p class="small">auto recovers only the owned demo after passing every check. observe collects evidence without a deploy.</p><div class="btn-row"><button class="btn ${s.mode==='auto'?'primary':''}" data-mode="auto">auto</button><button class="btn ${s.mode==='observe'?'primary':''}" data-mode="observe">observe</button><button class="btn" id="view-floor">view exact floor</button></div><pre id="floor-detail" hidden></pre></div></div>`;shell(content);document.querySelectorAll('[data-mode]').forEach(b=>b.onclick=action(async()=>{await api('/services/'+s.id+'/recovery-policy',{method:'PATCH',body:JSON.stringify({mode:b.dataset.mode})});await load()}));q('#view-floor').onclick=action(async()=>{let data=await api('/services/'+s.id+'/watchpoints');let pre=q('#floor-detail');pre.textContent=data.policy+'\n\n'+data.source;pre.hidden=!pre.hidden})}
function checkList(rows){return `<div class="checks">${(rows||[]).map(r=>`<div class="check"><span class="${r.passed?'pass':'fail'}">${r.passed?'✓':'×'}</span><span>${h(r.name)}</span><span>${h(r.status??'err')}</span></div>`).join('')}</div>`}
function money(minor,currency){
  if(!Number.isInteger(minor))return null;
  try{return new Intl.NumberFormat('en-US',{style:'currency',currency:String(currency||'usd').toUpperCase()}).format(minor/100)}
  catch{return String(minor)+' minor units'}
}
function incidentSummary(item){
  const boundary=(item.evidence||[]).find(r=>r.name==='tenant boundary'&&!r.passed&&r.status===200);
  const row=(item.evidence||[]).find(r=>r.name==='amount and current schema'&&!r.passed&&r.status===200);
  const expected=money(row?.expected?.amount_minor,row?.expected?.currency);
  const observed=money(row?.observed?.amount_minor,row?.expected?.currency);
  let fault=boundary?'tenant a read tenant b invoice with http 200. the cross-tenant boundary failed.':expected&&observed?'the api returned http 200 while an invoice showed '+observed+' instead of '+expected+'.':'a live watchpoint found a broken invoice contract while the api stayed reachable.';
  const old=(item.candidates||[]).filter(c=>['legacy rollback','prior rollback'].includes(c.name));
  const rejected=old.filter(c=>c.verdict==='rejected').length;
  if(rejected)fault+=' '+rejected+' old '+(rejected===1?'release was':'releases were')+' rejected against the current checks.';
  if(item.state==='recovered'&&item.verification?.length&&item.verification.every(r=>r.passed))
    return fault+' a tested repair shipped and the public checks passed twice.';
  if(item.state==='needs attention')return fault+' automatic recovery is held; inspect the timeline before treating this as fixed.';
  return fault+' recovery is '+(item.state==='queued'?'queued':item.state)+'. no repaired claim yet.';
}
function stateRail(item){
  const names=['watching','oops','investigating','evaluating','recovering','verifying','recovered'];
  let active=names.indexOf(item.state);
  if(active<0){
    if(item.deployment)active=5;
    else if(item.candidates?.length)active=3;
    else if(item.guild_investigator_session||item.guild_coordinator_session)active=2;
    else active=1;
  }
  return '<div class="state-rail" aria-label="incident progress">'+names.map((name,index)=>
    '<div class="state-step '+(index===active?'current':index<active?'done':'')+'" '+(index===active?'aria-current="step"':'')+'><span class="state-index">'+String(index+1).padStart(2,'0')+'</span><span>'+h(name)+'</span></div>'
  ).join('')+'</div>'+(item.state==='needs attention'?'<p class="small">automatic recovery is held. the rail stops at the last recorded stage.</p>':'');
}
function candidateNote(candidate){
  if(candidate.gate_error)return 'source gate: '+candidate.gate_error;
  const findings=candidate.scan?.findings?.length||0;
  const failed=(candidate.checks||[]).filter(r=>!r.passed).map(r=>r.name);
  if(findings)return findings+' static scan '+(findings===1?'finding':'findings')+(failed.length?'; failed '+failed.join(', '):'');
  if(failed.length)return 'failed '+failed.join(', ');
  if(candidate.passed)return 'five unchanged checks passed; static scan clear';
  return 'evaluation incomplete';
}
function eventReference(event){
  const data=event.data;
  if(!data||typeof data!=='object')return '';
  const refs=[];
  const add=(label,value)=>{if(value!==undefined&&value!==null&&value!=='')refs.push(label+' '+value)};
  if(event.vendor==='clickhouse'){
    add('query',data.query_id);
    add('rows read',data.statistics?.rows_read);
  }else if(event.vendor==='senso'){
    const sources=Array.isArray(data.sources)?data.sources:[];
    add('version',[...new Set(sources.map(x=>x.version_id).filter(Boolean))].join(', '));
  }else if(event.vendor==='guild'){
    add('session',data.session_id);
    add('decision',data.decision?.action);
  }else if(event.vendor==='openai'){
    add('response',data.response_id);
    add('model',data.model);
  }else if(event.vendor==='akash'){
    add('request',data.request_id);
    add('model',data.model);
  }else if(event.vendor==='semgrep'){
    add('findings',data.findings?.length);
  }else if(event.vendor==='elevenlabs'){
    add('audio bytes',data.bytes);
  }else if(event.vendor==='mongodb'){
    add('deployment',data.id);
  }
  return refs.length?'<div class="event-ref mono small">'+refs.map(h).join(' · ')+'</div>':'';
}
function candidateMatrix(item){
  const all=item.candidates||[];
  const checkNames=(all.find(c=>c.checks?.length)?.checks||item.evidence||[]).map(r=>r.name).filter(Boolean).slice(0,5);
  if(!checkNames.length)return '<div class="empty">candidate checks will appear after evaluation.</div>';
  const selected=all.find(c=>item.deployment?.artifact&&c.artifact===item.deployment.artifact&&c.passed);
  const forward=selected||all.find(c=>c.name!=='legacy rollback'&&c.name!=='prior rollback'&&c.passed)||all.find(c=>c.name!=='legacy rollback'&&c.name!=='prior rollback');
  const rows=[
    ['legacy rollback',all.find(c=>c.name==='legacy rollback')],
    ['prior rollback',all.find(c=>c.name==='prior rollback')],
    [forward?.name||'forward repair',forward]
  ];
  const head=checkNames.map((name,i)=>'<th scope="col"><abbr title="'+h(name)+'">'+String(i+1).padStart(2,'0')+'</abbr></th>').join('');
  const body=rows.map(([label,c])=>{
    const checks=new Map((c?.checks||[]).map(r=>[r.name,r]));
    const cells=checkNames.map(name=>{
      const row=checks.get(name),result=row?(row.passed?'pass':'fail'):'pending';
      return '<td class="matrix-cell '+result+'" title="'+h(name+': '+(row?(row.passed?'pass':'fail'):'not run'))+'" aria-label="'+h(name+': '+(row?(row.passed?'pass':'fail'):'not run'))+'">'+(row?(row.passed?'✓':'×'):'—')+'</td>';
    }).join('');
    const result=c?(selected&&c.id===selected.id?'shipped':c.verdict):'not run';
    return '<tr><th scope="row"><span>'+h(label)+'</span><small>'+h(result)+'</small></th>'+cells+'</tr>';
  }).join('');
  return '<div class="matrix-wrap"><table class="candidate-matrix"><caption>candidate checks from the unchanged recovery floor</caption><thead><tr><th scope="col">candidate</th>'+head+'</tr></thead><tbody>'+body+'</tbody></table></div><div class="matrix-legend">'+checkNames.map((name,i)=>'<span><b>'+String(i+1).padStart(2,'0')+'</b> '+h(name)+'</span>').join('')+'</div><p class="small">✓ pass · × fail · — not run. each cell comes from a recorded candidate check.</p>';
}
function oops(){
  const item=state.incidents.find(i=>i.id===state.active)||state.incidents[0];
  let content='<div class="section-label">incident ledger</div><h1>oops reports.</h1><p class="lede">the running api can answer every request and still break an invoice or tenant boundary. this is the evidence trail.</p>';
  if(!item){shell(content+'<div class="empty">no oops on record. create one from your owned sandbox.</div>');return}
  state.active=item.id;
  const events=(item.events||[]).slice().reverse();
  content+='<div class="panel incident-ticket"><div class="panel-head"><div><span class="incident-kicker">synthetic billing incident</span><h2>oops '+h(item.id.slice(0,8))+'</h2></div>'+badge(item.state)+'</div><div class="panel-body">'+
    '<p class="incident-summary">'+h(incidentSummary(item))+'</p>'+stateRail(item)+
    '<div class="incident-meta mono small">faulty artifact '+h(item.faulty_artifact||'pending')+'<br>locked floor '+h(item.floor||'pending')+'</div>'+
    '<div class="btn-row"><button class="btn primary" id="recover">'+(item.state==='recovered'?'recovered ✓':item.state==='needs attention'?'attention required':item.state==='oops'?'dispatch recovery':'recovery in progress')+'</button><button class="btn" id="verify">fresh public check</button><button class="btn" id="brief">'+(item.audio?'play briefing':'make audio brief')+'</button><a class="btn" href="/api/incidents/'+h(item.id)+'/receipt">download receipt</a>'+(item.public_report?'<a class="btn" href="'+h(item.public_report)+'" target="_blank" rel="noreferrer">public status</a>':'')+'</div><audio id="player" controls hidden></audio></div></div>'+
    '<div class="panel"><div class="panel-head"><h2>what broke</h2><span class="small mono">http status ≠ contract status</span></div><div class="panel-body">'+checkList(item.evidence)+'</div></div>';
  if(item.analytics?.statistics){
    const stats=item.analytics.statistics;
    content+='<div class="panel"><div class="panel-head"><h2>clickhouse confirmation</h2></div><div class="panel-body"><p>'+h(item.analytics.rows?.map(r=>r.check_id+': '+r.failures+' failures').join(' · ')||'query completed')+'</p><div class="mono small">query '+h(item.analytics.query_id||'pending')+' · '+h(stats.elapsed_ms)+' ms · '+h(stats.rows_read)+' rows read · '+h(stats.bytes_read)+' bytes read</div></div></div>';
  }
  content+='<div class="panel"><div class="panel-head"><h2>which repair held up?</h2><span class="small mono">floor '+h(item.floor?.slice(0,12)||'pending')+'</span></div><div class="panel-body">'+candidateMatrix(item)+
    (item.candidates?.length?item.candidates.map(c=>'<div class="candidate"><h3>'+h(c.name)+' <span class="badge '+h(c.verdict)+'">'+h(c.verdict)+'</span></h3><p class="candidate-note">'+h(candidateNote(c))+'</p><div class="small mono">artifact '+h(c.artifact?.slice(0,20)||'unavailable')+' · semgrep '+(c.scan?.findings?.length||0)+' findings</div><details><summary class="small mono">inspect tested source and checks</summary>'+checkList(c.checks)+(c.source?'<pre>'+h(c.source)+'</pre>':'')+'</details></div>').join(''):'<div class="empty">the hosted team has not evaluated candidates yet.</div>')+
    '</div></div><div class="panel"><div class="panel-head"><h2>who did what</h2><span class="small mono">'+events.length+' events · latest first</span></div><div class="panel-body">'+
    (events.length?events.map(e=>'<div class="event"><div class="event-meta"><time class="time" datetime="'+h(new Date(e.at*1000).toISOString())+'">'+h(new Date(e.at*1000).toLocaleString())+'</time><span class="event-vendor">'+h(e.vendor||'oopsie')+'</span></div><p>'+h(e.message)+'</p>'+eventReference(e)+'</div>').join(''):'<div class="empty">event receipts are pending.</div>')+'</div></div>';
  shell(content);
  q('#recover').disabled=item.state!=='oops';
  q('#recover').onclick=action(async()=>{await api('/incidents/'+item.id+'/recover',{method:'POST'});toast('hosted team dispatched. evidence will update here.');await load()});
  q('#verify').onclick=action(async()=>{let x=await api('/incidents/'+item.id+'/verify',{method:'POST'});toast(x.checks.every(c=>c.passed)?'fresh public watchpoints pass.':'fresh public check found a fault.');await load()});
  q('#brief').onclick=action(async()=>{if(!item.audio)await api('/incidents/'+item.id+'/briefing',{method:'POST'});let p=q('#player');p.src='/api/incidents/'+item.id+'/audio';p.hidden=false;await p.play()});
  if(item.audio){let p=q('#player');p.src='/api/incidents/'+item.id+'/audio';p.hidden=false}
}
function watchDate(value){if(!value)return 'pending';let date=typeof value==='number'?new Date(value*1000):new Date(value);return Number.isNaN(date.getTime())?'pending':date.toLocaleString()}
function watchSource(url,label){try{let parsed=new URL(String(url));if(parsed.protocol!=='https:'||parsed.username||parsed.password)return '';return `<a class="link" href="${h(parsed.href)}" target="_blank" rel="noopener noreferrer">${h(label)} ↗</a>`}catch{return ''}}
function watchKind(kind){return {github:'github repo',cve:'cve record',url:'https page'}[kind]||'public source'}
function watchResult(w){
  const r=w.result||{};
  if(w.state==='awaiting verification'){
    const proof=r.verification||{};
    return `<div class="watch-dns"><strong>prove control before the first request</strong><p>add this public dns txt record for your domain, then verify it here. oopsie will not probe the page until ownership is checked.</p><div class="watch-dns-row"><span>txt name</span><code>${h(proof.record||'pending')}</code></div><div class="watch-dns-row"><span>txt value</span><code>${h(proof.value||'pending')}</code></div></div>`;
  }
  if(r.error)return `<p class="watch-error">${h(r.error)}</p>`;
  if(!w.checked_at)return '<p class="small">first source check is queued. no finding yet.</p>';
  if(w.kind==='github'){
    const findings=Array.isArray(r.findings)?r.findings:[];
    const count=Number.isFinite(Number(r.total_matches))?Number(r.total_matches):findings.length;
    const scope=r.status==='unsupported'?'unsupported: no supported root manifest was found. no dependency scan ran.':r.partial?'partial scan: only supported public root manifests and up to 80 pinned versions were checked.':'supported public root manifest checked.';
    return `<div class="watch-result-grid"><div><span>advisory matches</span><strong>${h(count)}</strong></div><div><span>pinned versions checked</span><strong>${h(r.dependencies_scanned??'—')}</strong></div><div><span>latest commit</span><code>${h(String(r.commit||'—').slice(0,12))}</code></div></div><p class="small">${scope} matches are leads, not proof that vulnerable code is exploitable; no matches do not establish safety.</p>${r.note?`<p class="mono small">source note: ${h(r.note)}</p>`:''}${r.manifest?`<div class="mono small">manifest ${h(r.manifest)} · ${watchSource(r.source_url,'manifest source')}</div>`:watchSource(r.source_url,'scan source')}${findings.length?`<div class="watch-findings">${findings.slice(0,8).map(f=>`<div class="watch-finding"><div><strong>${h(f.package||'package')}</strong> <code>${h(f.version||'version unknown')}</code><span class="mono small">${h(f.id||'advisory')}</span></div>${watchSource(f.source_url,'advisory')}</div>`).join('')}</div>`:''}${count>findings.length?`<p class="small">${h(count-findings.length)} more signal${count-findings.length===1?'':'s'} in the source result.</p>`:''}`;
  }
  if(w.kind==='cve')return `<div class="watch-cve"><div class="watch-result-grid"><div><span>record state</span><strong>${h(String(r.state||'unknown').toLowerCase())}</strong></div><div><span>updated upstream</span><strong class="watch-date">${h(watchDate(r.updated))}</strong></div></div>${r.title?`<h3>${h(r.title)}</h3>`:''}${r.summary?`<p>${h(r.summary)}</p>`:''}<p class="small">this tracks a public cve record. it does not establish that any of your systems are affected.</p>${watchSource(r.source_url,'cve source')} ${watchSource(r.advisory_url,'maintainer advisory')}</div>`;
  if(w.kind==='url')return `<div class="watch-result-grid"><div><span>http response</span><strong>${h(r.status??'—')}</strong></div><div><span>expected</span><strong>${h(r.expected_status??w.expected_status??'—')}</strong></div><div><span>public text marker</span><strong>${r.marker_matched===null||r.marker_matched===undefined?'not set':r.marker_matched?'found':'missing'}</strong></div></div><p class="small">${r.passed===true?'response matched this watchpoint.':r.passed===false?'response differed from this watchpoint.':'response not evaluated.'} status and public text checks do not prove the page is secure.</p>${r.body_sha256?`<div class="mono small">response sha256 ${h(r.body_sha256)}</div>`:''}`;
  return '<p class="small">source result is pending.</p>';
}
function watchCard(w){
  const kind=watchKind(w.kind),source=w.kind==='cve'&&/^CVE-\d{4}-\d{4,}$/i.test(w.value)?`https://www.cve.org/CVERecord?id=${encodeURIComponent(w.value)}`:w.kind==='github'&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(w.value)?`https://github.com/${w.value}`:w.value;
  const history=Array.isArray(w.history)?w.history:[];
  const status=String(w.state||'queued').toLowerCase(),signal=['matches','changed','needs attention','failing'].includes(status),tone=signal?'signal':status==='passing'?'clear':'pending';
  return `<article class="watch-card"><div class="watch-card-top"><div><span class="watch-kind">${h(kind)} / ${h(String(w.id||'').slice(0,8))}</span><h3>${h(w.value)}</h3>${watchSource(source,'open public source')}</div><span class="watch-state ${tone}">${h(status)}</span></div><div class="watch-card-body">${watchResult(w)}${w.result?.change?`<p class="watch-change">${h(w.result.change)}</p>`:''}<div class="watch-meta"><span>checked <strong>${h(watchDate(w.checked_at))}</strong></span><span>next check <strong>${h(watchDate(w.next_check_at))}</strong></span></div>${history.length?`<details class="watch-history"><summary>check history / ${h(history.length)}</summary>${history.slice(-6).reverse().map(x=>`<div><time>${h(watchDate(x.at))}</time><span>${h(x.state||'checked')}</span><p>${h(x.summary||'source checked')}</p></div>`).join('')}</details>`:''}<div class="btn-row">${status==='awaiting verification'?`<button class="btn primary" data-watch-verify="${h(w.id)}">verify ownership</button>`:`<button class="btn" data-watch-refresh="${h(w.id)}">check now</button>`}<button class="btn danger" data-watch-remove="${h(w.id)}">remove watch</button></div></div></article>`;
}
async function loadWatches(){
  if(state.watchLoading)return;
  state.watchLoading=true;state.watchError=null;
  const list=q('#watch-list');if(list&&state.watches===null)list.innerHTML='<div class="empty">reading public-source watches...</div>';
  try{const rows=await api('/watches');if(!Array.isArray(rows))throw Error('bad watch response');state.watches=rows;state.watchAt=Date.now()}
  catch(e){state.watchError=e.message}
  finally{state.watchLoading=false;if(state.view==='realwatch')renderWatchList()}
}
function renderWatchList(){
  const el=q('#watch-list'),counter=q('#watch-count');if(!el)return;
  if(counter)counter.textContent=state.watches===null?'—':String(state.watches.length);
  if(state.watchError){el.innerHTML=`<div class="watch-load-error"><strong>source list unavailable.</strong><p>${h(state.watchError)}</p><button class="btn" id="retry-watches">retry</button></div>`;q('#retry-watches').onclick=loadWatches;return}
  if(!state.watches?.length){el.innerHTML='<div class="watch-empty"><span>◉</span><h3>no public signals yet.</h3><p>add a public github repo, a cve id, or a domain you control. the first read leaves a timestamped trace here.</p></div>';return}
  el.innerHTML=state.watches.map(watchCard).join('');
  el.querySelectorAll('[data-watch-refresh]').forEach(b=>b.onclick=action(async()=>{b.disabled=true;b.textContent='checking...';await api('/watches/'+encodeURIComponent(b.dataset.watchRefresh)+'/refresh',{method:'POST'});toast('source checked. read the new signal below.');await loadWatches()}));
  el.querySelectorAll('[data-watch-verify]').forEach(b=>b.onclick=action(async()=>{b.disabled=true;b.textContent='verifying...';await api('/watches/'+encodeURIComponent(b.dataset.watchVerify)+'/verify',{method:'POST'});toast('ownership checked.');await loadWatches()}));
  el.querySelectorAll('[data-watch-remove]').forEach(b=>b.onclick=action(async()=>{if(!window.confirm('remove this watch and its history?'))return;await api('/watches/'+encodeURIComponent(b.dataset.watchRemove),{method:'DELETE'});toast('watch removed.');await loadWatches()}));
}
function realwatch(){
  shell(`<div class="watch-heading"><div><div class="section-label">public-source observatory</div><h1>real-world watch.</h1><p class="lede">point oopsie at public evidence you care about. see what changed, where it came from, and when we checked.</p></div><div class="watch-count"><strong id="watch-count">${state.watches===null?'—':h(state.watches.length)}</strong><span>sources watched</span></div></div><div class="watch-boundary"><strong>signal ≠ exploitability.</strong><span>external watches read public sources only. they cannot patch, deploy, transact, or access private github repos. recovery automation remains inside your owned demo sandbox.</span></div><div class="panel"><div class="panel-head"><h2>add a source</h2><span class="small mono">public evidence / scoped to this workspace</span></div><div class="panel-body"><form id="watch-form" class="watch-form"><label class="field">watch type<select name="kind" id="watch-kind"><option value="github">public github repo</option><option value="cve">cve record</option><option value="url">https page you control</option></select></label><label class="field"><span id="watch-value-label">github repository url</span><input name="value" id="watch-value" type="url" placeholder="https://github.com/owner/repo" required maxlength="1024" autocomplete="off"></label><div id="watch-url-fields" class="watch-url-fields" hidden><label class="field">expected http status<input name="expected_status" type="number" min="100" max="599" value="200"></label><label class="field">public text marker <span class="small">optional; never enter a secret</span><input name="marker" type="text" maxlength="100" placeholder="status: operational" autocomplete="off"></label><p class="small">use a public hostname on standard https; no query strings or tokens. add a dns txt record before the first request. only status, marker match, and response hash are kept.</p></div><div class="watch-form-foot"><p class="small" id="watch-form-help">public repositories only. oopsie reads supported dependency manifests and links matching advisories.</p><button class="btn primary" type="submit">add watch →</button></div></form></div></div><div class="panel"><div class="panel-head"><h2>source signals</h2><button class="btn" id="reload-watches" type="button">reload</button></div><div class="panel-body watch-list" id="watch-list"><div class="empty">reading public-source watches...</div></div></div>`);
  const kind=q('#watch-kind'),value=q('#watch-value'),help=q('#watch-form-help'),extra=q('#watch-url-fields');
  const sync=()=>{const selected=kind.value,field=q('#watch-value-label');extra.hidden=selected!=='url';value.type=selected==='cve'?'text':'url';value.value='';field.textContent=selected==='cve'?'cve id':selected==='url'?'page url':'github repository url';value.placeholder=selected==='cve'?'CVE-2025-29927':selected==='url'?'https://status.example.com/health':'https://github.com/owner/repo';help.textContent=selected==='cve'?'watch a public cve record. a record alone does not mean your service is affected.':selected==='url'?'https only; no query strings or tokens. prove domain control with dns before the first request.':'public repositories only. oopsie reads supported dependency manifests and links matching advisories.'};
  kind.onchange=sync;
  q('#watch-form').onsubmit=action(async(e)=>{e.preventDefault();const f=new FormData(e.target),selected=String(f.get('kind')),input=String(f.get('value')||'').trim();let body={kind:selected,value:input};if(selected==='url'){body.expected_status=Number(f.get('expected_status'));const marker=String(f.get('marker')||'').trim();if(marker)body.marker=marker}await api('/watches',{method:'POST',body:JSON.stringify(body)});toast(selected==='url'?'watch created. add the dns txt record below to verify ownership.':'watch created. checking the public source.');e.target.reset();sync();await loadWatches()});
  q('#reload-watches').onclick=()=>loadWatches();if(state.watches===null)loadWatches();else renderWatchList();
}
function lab(){let content=`<div class="section-label">owned security lab</div><h1>the rollback trap.</h1><p class="lede">a real, documented auth bypass in an isolated next.js 14.2.24 app. all data is synthetic; the lab only listens on this server.</p><div class="panel"><div class="panel-head"><h2>cve-2025-29927 / middleware bypass</h2><span class="status-pill bad">vulnerable fixture</span></div><div class="panel-body"><p>the middleware should reject an unauthenticated invoice request. the advisory documents a header that can skip that check. replay both requests and compare the actual responses.</p><button class="btn primary" id="run-lab">replay the bypass</button><a class="btn" href="https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw" target="_blank" rel="noreferrer">maintainer advisory ↗</a><div id="lab-result"></div></div></div><div class="panel"><div class="panel-head"><h2>why oopsie cares</h2></div><div class="panel-body"><p>an old release can restore a visible feature while bringing back an authorization flaw. the billing recovery demo separately proves this with its own tenant-isolation check. this lab gives you a real public vulnerability to reproduce in owned infrastructure.</p></div></div>`;shell(content);q('#run-lab').onclick=action(async()=>{let x=await api('/labs/nextjs/replay',{method:'POST'});displayLab(x)});api('/labs/nextjs').then(x=>{if(x.latest)displayLab(x.latest)}).catch(e=>toast(e.message))}
function displayLab(x){let el=q('#lab-result');if(!el)return;el.innerHTML=`<div class="cards"><div class="card"><div class="card-label">normal request</div><div class="card-value bad">${h(x.baseline.status)}</div><p>middleware rejects the unauthenticated request.</p></div><div class="card"><div class="card-label">bypass header</div><div class="card-value good">${h(x.bypass.status)}</div><p>the same synthetic invoice escaped the guard.</p></div><div class="card"><div class="card-label">patched 14.2.25</div><div class="card-value good">${h(x.patched?.status??'—')}</div><p>the bypass header is denied; authorized access still works.</p></div></div><pre>${h(x.bypass.header)}\n\n${h(JSON.stringify(x.bypass.body,null,2))}</pre><div class="mono small">replayed ${new Date(x.at*1000).toLocaleString()} · ${h(x.version)}</div>`}
function systems(){shell(`<div class="section-label">integration receipts</div><h1>systems.</h1><p class="lede">configured means this server can call the service. observed means an actual call left evidence on your latest oops.</p><div class="panel"><div class="panel-head"><h2>integration receipts</h2></div><div class="panel-body" id="system-list"><div class="empty">checking receipts...</div></div></div>`);api('/integrations').then(rows=>{let el=q('#system-list');if(el)el.innerHTML=rows.map(r=>`<div class="row"><div><div class="mono">${h(r.name)}</div><div class="small">${h(r.last_event?.message||'no incident receipt in this workspace yet')}</div></div>${badge(r.observed?'observed':r.configured?'configured':'pending')}</div>`).join('')}).catch(e=>toast(e.message))}
function profile(){
  shell(`<div class="section-label">account</div><h1>your profile.</h1><p class="lede">your workspace and sign-in details stay here.</p><div class="panel profile-panel"><div class="panel-head"><h2>account</h2></div><div class="panel-body"><div class="row"><span>email</span><strong class="mono">${h(state.me.email)}</strong></div><div class="row"><span>workspace</span><code>${h(state.me.workspace)}</code></div></div></div><div class="panel profile-panel"><div class="panel-head"><h2>change password</h2></div><div class="panel-body"><p class="small">use at least 10 characters. changing it signs out every session and revokes your api keys.</p><form id="password-form"><label class="field">current password<input name="current_password" type="password" autocomplete="current-password" required></label><label class="field">new password<input name="new_password" type="password" autocomplete="new-password" minlength="10" maxlength="72" required></label><label class="field">confirm new password<input name="confirm_password" type="password" autocomplete="new-password" minlength="10" maxlength="72" required></label><button class="btn primary" type="submit">change password →</button></form></div></div>`);
  q('#password-form').onsubmit=action(async(e)=>{e.preventDefault();const values=new FormData(e.target),current=String(values.get('current_password')||''),next=String(values.get('new_password')||''),confirm=String(values.get('confirm_password')||'');if(next!==confirm)throw Error('new passwords do not match');await api('/me/password',{method:'POST',body:JSON.stringify({current_password:current,new_password:next})});clearPrivateState();state.authMode='login';state.view='overview';render();toast('password changed. sign in again; old sessions and api keys were revoked.')});
}
function access(){let content=`<div class="section-label">your credentials</div><h1>api + mcp.</h1><p class="lede">every tool is bound to your workspace. create a bearer key once, then use the same surface from scripts or an mcp client.</p><div class="panel"><div class="panel-head"><h2>make an api key</h2></div><div class="panel-body"><p class="small">a key appears once. store it in your own secret manager. you can revoke it here.</p><button class="btn primary" id="new-key">generate key →</button>${state.keyOnce?`<p class="small">copy this now:</p><div class="api-key">${h(state.keyOnce)}</div>`:''}<div id="key-list"></div></div></div><div class="panel"><div class="panel-head"><h2>connect via mcp</h2></div><div class="panel-body"><div class="row"><div>mcp endpoint <span class="small mono">streamable http / json-rpc</span></div><code>https://api.oopsie.website/mcp</code></div><div class="row"><div>authorization</div><code>bearer &lt;your key&gt;</code></div><div class="row"><div>openapi</div><a class="link" href="https://api.oopsie.website/docs" target="_blank" rel="noreferrer">browse api docs ↗</a></div><p class="small">mcp exposes the owned recovery workflow and read-only public-source watches. deployment still obeys the unchanged recovery floor.</p></div></div>`;shell(content);q('#new-key').onclick=action(async()=>{let x=await api('/keys',{method:'POST'});state.keyOnce=x.key;access()});api('/keys').then(x=>{let el=q('#key-list');if(el)el.innerHTML=x.map(k=>`<div class="row"><span class="mono small">${h(k.prefix)}…</span><button class="btn danger" data-revoke="${h(k.id)}">revoke</button></div>`).join('')}).then(()=>document.querySelectorAll('[data-revoke]').forEach(b=>b.onclick=action(async()=>{await api('/keys/'+b.dataset.revoke,{method:'DELETE'});toast('key revoked');access()}))).catch(e=>toast(e.message))}
function render(){document.documentElement.classList.toggle('console-open',!!state.me);if(!state.me)return auth();if(state.view==='realwatch')realwatch();else if(state.view==='watchpoints')watchpoints();else if(state.view==='oops')oops();else if(state.view==='access')access();else if(state.view==='profile')profile();else if(state.view==='lab')lab();else if(state.view==='systems')systems();else overview()}
load();setInterval(()=>{if(state.me && document.visibilityState==='visible' && !state.busy){load(true);if(state.view==='realwatch'&&Date.now()-state.watchAt>30000)loadWatches()}},10000);
