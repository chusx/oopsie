const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const byId = id => document.getElementById(id);
const money = (minor, currency) => currency === 'usd'
  ? new Intl.NumberFormat('en-US', {style:'currency',currency:'USD'}).format(minor / 100)
  : `${minor} minor units`;
const date = timestamp => new Date(timestamp * 1000).toLocaleString('en-US', {timeZone:'UTC',year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}) + ' utc';

function renderMatrix(report) {
  const rows = report.matrix || [];
  if (!rows.length) {
    byId('public-matrix').innerHTML = '<p class="empty">this earlier report did not publish per-candidate check results. see the rejected reasons in the receipt above.</p>';
    return;
  }
  const checks = report.verification.checks || [];
  const header = checks.map(name => `<th scope="col">${esc(name)}</th>`).join('');
  const body = rows.map(row => {
    const results = new Map((row.checks || []).map(check => [check.name,check.passed]));
    const cells = checks.map(name => {
      const result = results.get(name);
      const word = result === true ? 'pass' : result === false ? 'fail' : 'not run';
      const kind = result === true ? 'pass' : result === false ? 'fail' : 'pending';
      const symbol = result === true ? '✓' : result === false ? '×' : '—';
      return `<td class="matrix-cell ${kind}" aria-label="${word}"><span aria-hidden="true">${symbol}</span></td>`;
    }).join('');
    return `<tr><th scope="row">${esc(row.name)}<small>${esc(row.verdict)}</small></th>${cells}</tr>`;
  }).join('');
  byId('public-matrix').innerHTML = `<table class="candidate-matrix"><thead><tr><th scope="col">candidate</th>${header}</tr></thead><tbody>${body}</tbody></table>`;
}

function renderReport(report) {
  const rejected = (report.rejected || []).map(item => `<div class="ticket-line"><span>${esc(item.name)}</span><strong class="rejected">rejected</strong><small>${esc(item.reason)}</small></div>`).join('');
  const selected = report.selected || {};
  const url = `/status/${encodeURIComponent(report.id)}`;
  byId('latest-ticket').innerHTML = `<div class="ticket-head"><div><span class="ticket-label">verified recovery · ${esc(date(report.recovered_at))}</span><h3>oops ${esc(report.id.slice(0,8))}</h3></div><span class="recovered-stamp">recovered <span aria-hidden="true">✓</span></span></div><div class="ticket-lines">${rejected}<div class="ticket-line shipped"><span>${esc(selected.name)}</span><strong>shipped</strong><small>${esc(selected.vendor || 'model')} proposal</small></div></div><div class="ticket-foot"><span>${esc(report.verification.passed)}/${esc(report.verification.total)} fresh public checks passed</span><span>artifact sha256 <code>${esc(selected.artifact)}</code></span></div><a class="ticket-link" href="${url}">inspect the full public receipt <span aria-hidden="true">↗</span></a>`;
  renderMatrix(report);
}

async function publicReport(path) {
  const response = await fetch(path, {headers:{'Accept':'application/json'}});
  if (!response.ok) throw new Error('published receipt unavailable');
  return response.json();
}

publicReport('/api/public/status/7baa3c1a1c564d9db1e80586ef34def5')
  .then(report => {
    const fault = report.fault || {};
    if ((fault.kind && fault.kind !== 'amount') || !Number.isInteger(fault.observed_minor) || !Number.isInteger(fault.expected_minor)) throw new Error('amount receipt changed');
    byId('amount-observed').textContent = money(fault.observed_minor,fault.currency);
    byId('amount-expected').textContent = money(fault.expected_minor,fault.currency);
    byId('amount-state').textContent = 'verified · ' + report.verification.passed + '/' + report.verification.total;
  })
  .catch(() => { byId('amount-state').textContent = 'historical receipt'; });

publicReport('/api/public/status/3177f589d3234e399a574a1920753ef2')
  .then(report => {
    const fault = report.fault || {};
    if (fault.kind !== 'tenant_boundary' || fault.identity !== 'a' || fault.target !== 'inv_b') throw new Error('tenant receipt changed');
    byId('tenant-observed').textContent = fault.observed_status;
    byId('tenant-expected').textContent = fault.expected_status + ' denied';
    byId('tenant-state').textContent = 'verified · ' + report.verification.passed + '/' + report.verification.total;
  })
  .catch(() => { byId('tenant-state').textContent = 'historical receipt'; });

publicReport('/api/public/status/latest')
  .then(renderReport)
  .catch(error => {
    byId('latest-ticket').innerHTML = `<p class="ticket-loading">${esc(error.message)}</p><a class="ticket-link" href="/status">check public status ↗</a>`;
  });
