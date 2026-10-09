# run and inspect oopsie

## no-key source checks

from the repository root on python 3.12 with docker available for the full runtime:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
OOPSIE_CREDENTIAL_FILE=/dev/null .venv/bin/python -m pytest -q
node --check web/app.js
```

the test suite stubs external sponsor calls and uses isolated state; it does not need vendor keys or a live clickhouse account. at this snapshot, 41 tests pass. the application itself also needs mongodb community on loopback, docker images, and sponsor configuration for a complete recovery. use [`.env.example`](../.env.example) as an environment reference; it is not loaded automatically. keep the populated file and all `.local/` runtime files out of git.

## inspect the live receipts

1. open the [tenant-boundary report](https://oopsie.website/status/3177f589d3234e399a574a1920753ef2). it begins with an owned synthetic `200` cross-tenant read, shows rejected rollbacks and proposals, then the selected artifact and two rounds of five public checks. use the raw json link to inspect the redacted event chain; independently save its head if you want to compare a later export.
2. open the [amount-fault report](https://oopsie.website/status/7baa3c1a1c564d9db1e80586ef34def5) for the separate `$1,299.00` versus `$12.99` case. do not combine these two incidents into one request.
3. register at [the console](https://app.oopsie.website/), boot the synthetic billing sandbox, run watchpoints, then inject either supported fault. follow the oops report through `queued`, `investigating`, `evaluating`, `recovering`, `verifying`, and `recovered` or `needs attention`. a dispatched job alone is not a repair receipt.
4. the `real-world watch` view accepts a public github repository, a specific official cve id, or an https page you control after dns txt proof. try `https://github.com/OWASP/NodeGoat` or `CVE-2025-29927`. these are read-only leads, not third-party repairs.
5. the authenticated `security lab` replays [the next.js middleware advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) against our separate synthetic `14.2.24` fixture and a `14.2.25` comparator. the intended sequence is ordinary vulnerable request `401`, crafted-header vulnerable request `200`, patched crafted-header request `401`, and patched authorized request `200`. the lab is separate from billing recovery.

## deploy a new instance

the live site uses caddy in front of fastapi, loopback mongodb, docker for synthetic releases and the isolated lab, guild hosted agents, and a clickhouse cloud service. [`deploy/`](../deploy/) provides portable starting templates. install the package dependencies, build `oopsie-demo:1` from [`demo-app/`](../demo-app/), bind all service and lab ports to loopback, configure dns/tls, and supply your own sponsor credentials outside the repository. the worker requires a restricted clickhouse runtime identity and a separately provisioned observations table. no customer-service deployment connector is included.

do not expose the intentionally vulnerable lab's port `3111` or copy a live credential file into this repository. `GET /healthz` checks fastapi and mongodb only; it does not prove that a guild, clickhouse, senso, openai, akash, semgrep, or elevenlabs operation completed. use an incident receipt for those claims.
