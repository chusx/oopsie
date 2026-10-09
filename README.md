# oopsie

**the api returned `200`. the invoice was wrong.** oopsie is an autonomous recovery agent for silent failures in a multi-tenant billing api. on an owned synthetic service, it observed a `$1,299.00` invoice where the current contract required `$12.99`; a separate release let tenant a read tenant b's invoice with `200` instead of `403`. the agent team investigates the counterexample, proposes a repair, and publishes a receipt only after a constrained worker tests and verifies the exact artifact it deploys.

the current release supports one isolated synthetic billing service per workspace. public github repositories, official cve records, and owner-verified https pages can be watched for changes, but outside services are read-only inputs. oopsie does not deploy to a customer's infrastructure or claim a third-party exploit.

## try the live build

| surface | link |
| --- | --- |
| landing | [oopsie.website](https://oopsie.website/) |
| authenticated console | [app.oopsie.website](https://app.oopsie.website/) |
| public-source watch | [app.oopsie.website/?view=watch](https://app.oopsie.website/?view=watch) |
| api schema | [api.oopsie.website/docs](https://api.oopsie.website/docs) |
| mcp | `https://api.oopsie.website/mcp` (scoped bearer key required) |
| recovery reports | [oopsie.website/status](https://oopsie.website/status) |

the [tenant-boundary recovery](https://oopsie.website/status/3177f589d3234e399a574a1920753ef2) is the clearest receipt: the faulty and rollback artifacts are distinct, unsafe candidates fail the current five-check floor, a `gpt-6-sol` proposal is selected, the gateway switches to its tested artifact, and five public checks pass twice. the [amount-fault receipt](https://oopsie.website/status/7baa3c1a1c564d9db1e80586ef34def5) shows the separate `$1,299.00` versus `$12.99` case. both use synthetic invoices.

to run the flow yourself, register in the console, boot the sandbox, inject a synthetic fault, and inspect its oops report. the agent may take several minutes; a queued job is not a completed recovery. the console's `api + mcp` view creates a workspace bearer key shown once. [the demo path](docs/reproduce.md) lists each check and the expected evidence.

## how it works

1. five executable watchpoints cover the current amount/schema and allowed tenant a read, an allowed tenant b read, denied cross-tenant and anonymous reads, and an unknown-invoice denial. the hash of [`demo-app/checks.py`](demo-app/checks.py) is bound to the service and incident. a model cannot edit this floor.
2. clickhouse observations confirm the live failure. senso supplies version-bound approved context. guild hosts an investigator and coordinator whose decisions gate recovery. openai `gpt-6-sol` proposes the primary forward handler; akash proposals are evaluated independently.
3. the worker constrains the source shape, scans it with semgrep, runs the unchanged checks in isolated containers, and requires a current release, floor, revision, and lease before switching the owned gateway. it probes the public route again and publishes a redacted receipt only after verification. uncertainty becomes `needs attention`.

the older `legacy` release violates tenant isolation; the `prior` release reads a retired field. the `unsafe_ai_fix.py` security injection is a **synthetic ai-style fixture, not recorded model output**. the selected handler in the showcase matched the known healthy source, so the result demonstrates autonomous evidence gathering and gated recovery within a bounded handler, not a novel repair algorithm. [the architecture](docs/architecture.md) explains the boundary.

## sponsor use with receipts

| tool | actual role | where to verify |
| --- | --- | --- |
| guild | hosts investigator and coordinator sessions | session decisions in the authenticated incident receipt |
| openai | `gpt-6-sol` primary reasoning and selected handler | response id, token usage, source hash, and candidate verdict |
| akash | three independent forward candidates | request ids and separate rejected candidate rows |
| clickhouse | stores check observations and confirms current-release violations | query id, timing, rows read, and release pulse |
| senso | retrieves approved, version-bound recovery context | source version and policy hash in the incident |
| semgrep | scans each candidate's tenant-guard pattern | finding and scan verdict per candidate |
| mongodb community | stores workspace-bound state and receipts | incident, deployment, lease, and public report records |
| elevenlabs | generates the post-recovery audio briefing | playable briefing on the published report |

the [sponsor evidence map](docs/sponsor-evidence.md) identifies the observed showcase fields and limitations. pi is an event prize sponsor, not a connected tool.

## source map

| path | purpose |
| --- | --- |
| [`worker/app.py`](worker/app.py) | browser, scoped api, mcp, public reports, gateway |
| [`worker/engine.py`](worker/engine.py) | watchpoints, hosted dispatch, candidate gate, deployment |
| [`worker/vendors.py`](worker/vendors.py) | sponsor adapters and receipts |
| [`worker/realworld.py`](worker/realworld.py) | public-source watch orchestration |
| [`web/`](web/) | landing, console, receipt interactions |
| [`demo-app/`](demo-app/) | owned billing releases and immutable recovery floor |
| [`security-demo/`](security-demo/) | isolated synthetic next.js advisory replay |
| [`guild/`](guild/) | hosted-agent integration contract |
| [`tests/`](tests/) | recovery, auth, source, receipt, and integration-boundary tests |

run `python -m pytest -q` from the repository root after installing [`requirements.txt`](requirements.txt). the snapshot passed **41 tests** with the guild poll retry included. live sponsor calls require your own credentials and services; [local setup](docs/reproduce.md) separates the no-key test path from deployment.

## team

- [chris (@chusx)](https://github.com/chusx)
- [@gadaugherty](https://github.com/gadaugherty)

keys, sessions, workspace data, and generated customer records belong outside git. see [`AGENTS.md`](AGENTS.md) before changing the recovery gate.
