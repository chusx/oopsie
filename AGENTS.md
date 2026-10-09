# oopsie agent handoff

this is the judge-facing source snapshot for oopsie. keep code, tests, and public documentation consistent with observed receipts. start with [`README.md`](README.md), [`docs/architecture.md`](docs/architecture.md), and [`docs/reproduce.md`](docs/reproduce.md). user-facing copy is lowercase; preserve required case in api symbols, headers, model ids, and source names.

oopsie operates one owned synthetic multi-tenant billing service per workspace. a healthy http status can hide a wrong invoice amount or a cross-tenant read. public github, cve, and dns-verified https watches are read-only. the next.js advisory lab is an isolated synthetic fixture, separate from billing recovery; its vulnerable port stays loopback-only. do not claim arbitrary customer repo repair, production transactions, third-party exploitation, or an outside deployment connector.

[`demo-app/checks.py`](demo-app/checks.py) is the recovery floor. its hash is bound to services and incidents; a model cannot edit its expected results. the worker accepts a candidate only through constrained source shape, semgrep, independent no-network container checks, current floor/revision/lease gates, live gateway switch, and fresh public probes. positive tenant reads must pass along with denials. an uncertain call or changed source revision becomes `needs attention`.

protect workspace boundaries in browser, api, and mcp routes. browser sessions use the `__Host-oopsie` cookie; programmatic calls use scoped bearer keys. never log or publish vendor keys, raw one-time api keys, demo tokens, customer records, or private incident source. clickhouse observations exclude invoice bodies. public reports are redacted and require verified recovery.

the security injection in [`unsafe_ai_fix.py`](demo-app/releases/unsafe_ai_fix.py) is a **synthetic ai-style fixture, not recorded model output**. an earlier real openai call returned `429 credit_balance_exhausted` and used akash fallback; later recovered incidents used `gpt-6-sol`. preserve both facts. cite primary sources for security claims, and distinguish a queued or dispatched job from an actual recovered receipt.

run `OOPSIE_CREDENTIAL_FILE=/dev/null .venv/bin/python -m pytest -q` and relevant browser checks before claiming a changed recovery path. never commit `.env`, `.local/`, credentials, sessions, generated customer data, or sponsor tokens. keep deployment examples portable and the intentionally vulnerable lab off the public network.
