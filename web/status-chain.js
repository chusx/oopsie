// recompute the public projection only; a matching digest is not proof of truth.
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
};

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function recompute() {
  const button = document.getElementById('recompute-chain');
  const result = document.getElementById('chain-result');
  if (!button || !result) return;
  button.disabled = true;
  result.textContent = 'recomputing…';
  try {
    const response = await fetch(`/api/public/status/${encodeURIComponent(button.dataset.incident)}`);
    if (!response.ok) throw new Error(`public receipt returned ${response.status}`);
    const receipt = await response.json();
    if (receipt.chain?.algorithm !== 'sha256-linked' || !Array.isArray(receipt.events) || !receipt.chain_basis) {
      throw new Error('chain inputs are missing');
    }
    let head = await sha256(JSON.stringify(canonical(receipt.chain_basis)));
    const genesisMatches = head === receipt.chain.genesis;
    for (const event of receipt.events) {
      head = await sha256(head + JSON.stringify(canonical(event)));
    }
    const matches = genesisMatches && head === receipt.chain.head && head === button.dataset.head && receipt.events.length === receipt.chain.events;
    result.textContent = matches
      ? `head matches · ${receipt.events.length} redacted events · ${head.slice(0, 16)}…`
      : 'head differs · exported events or chain metadata changed';
  } catch (error) {
    result.textContent = `could not check chain · ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

document.getElementById('recompute-chain')?.addEventListener('click', recompute);
