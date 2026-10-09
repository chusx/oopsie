# observed sponsor evidence

the showcase is the [owned synthetic tenant-boundary incident `3177f589…`](https://oopsie.website/status/3177f589d3234e399a574a1920753ef2). tenant a received tenant b's invoice with `200` where the frozen contract required `403`. the faulty fixture, two rollback artifacts, and selected handler had distinct hashes. the selected artifact passed the gate, switched the live gateway, and passed five public checks twice before publication.

| tool | operation in that incident | observed receipt |
| --- | --- | --- |
| guild | hosted investigator and coordinator turns | sessions `01a12287-8d72…` (`forward_patch`) and `01a12288-ce32…` (`recover`) |
| openai | `gpt-6-sol` primary handler proposal | response `resp_0e02bb52822d1f37016…`; 1,269 input / 229 output tokens; estimated `$0.004828`; selected source passed and shipped |
| clickhouse | confirmed current-release violations from watchpoint observations | 12 failures; 8,202 rows read; 8.839 ms query; id `b2f5925c…` |
| senso | supplied approved, version-bound recovery context | revision 2 version `dae521e4-c076…`; policy text hash checked before use |
| akash | generated three distinct independent candidates | three request ids and artifact hashes; none passed all gates |
| semgrep | scanned each candidate with the tenant-guard pattern rule | flagged `legacy` and two akash drafts for a missing approved guard pattern; independent runtime checks also rejected them |
| mongodb community | retained workspace, incident, candidate, lease, deployment, and public-report state | artifact `dce9363a…` changed to `edbb1a2a…`; five public checks passed twice |
| elevenlabs | generated briefing after recovery | `570,976` audio bytes, playable from the published report |

the private authenticated receipt contains vendor request ids, model usage, full candidate details, and workspace-scoped operational state. the public page deliberately redacts identities, tokens, and raw candidate source. semgrep's guard-pattern finding is defense in depth; the two flagged akash drafts denied legitimate reads in the executable checks, so this incident does **not** demonstrate an exploitable ai-generated tenant leak.

an earlier incident recorded openai `429 credit_balance_exhausted` and used a visible akash fallback. later incidents successfully used `gpt-6-sol`; both outcomes remain part of the evidence. the security injection that opened the showcase was a synthetic fixture, not recorded model output. pi is a prize sponsor without product access here and is not counted as an integration.
