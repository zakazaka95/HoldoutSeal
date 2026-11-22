# HoldoutSeal — release record

Published **November 22, 2026**. Native source-schema and local controlled-output
checks passed. The deployment's complete source and initial persisted stats were
retrieved successfully. Both semantic assessments and fixed-deadline benchmark
finalizations below have stored outcomes. All eleven network transactions were
successful and `FINALIZED`. Portal status is recorded separately and no award is
claimed.

| Item | Current evidence |
| --- | --- |
| Contract version / receipt schema | `1.0.0` / `holdoutseal-v1` |
| Exact released source-file SHA-256 | `989cbccd67e0f17274818c2d56f15e844b93a8301f6b550181b94d978aceb972` |
| Public repository | https://github.com/zakazaka95/HoldoutSeal |
| Immutable tracked source | https://github.com/zakazaka95/HoldoutSeal/blob/8b4413ebdf1d98a44087f9a781c55d760442189c/HoldoutSeal.py |
| Local suite on released source | 41 passing controlled-output tests |
| Native source-schema check | Passed with the pinned v0.4.0 runner during this release |
| Network / chain ID / RPC | Studio Devnet / `61997` / `https://studio-dev.genlayer.com/api` |
| Contract | [0xa336823415BaD11521844DE9a477b85d7ec7d687](https://explorer-studio-dev.genlayer.com/address/0xa336823415BaD11521844DE9a477b85d7ec7d687) |
| Deployment transaction | [0xfb68936f5ffd88868ef8ac5cda4304d909c55f7caae89273df64174bc692c437](https://explorer-studio-dev.genlayer.com/tx/0xfb68936f5ffd88868ef8ac5cda4304d909c55f7caae89273df64174bc692c437) |
| Full tracked/deployed source comparison | Complete source matches after CRLF-to-LF conversion and outer-whitespace trim; normalized SHA-256 `ca0f9c3c2563f9b25ca8f05de1fdf356886f43215240d75008e060b945bb0889` |
| Initial persisted readback | `get_stats` retrieved successfully after deployment |
| First application write | [Benchmark opened successfully](https://explorer-studio-dev.genlayer.com/tx/0xc99a1e225b42f21bd3f0c9a4dfd8c9b5f552fcecf2e1345f2f76ce72d4c81c06); persisted chain, contract and transaction-clock context checked |
| Frozen policy enrollment | [Policy enrolled successfully](https://explorer-studio-dev.genlayer.com/tx/0xed89221aa2539f58788861cd1d0e17684f7b81509a243fa3902d5531c51a838c) |
| Committed corpus reveal | [Corpus revealed successfully](https://explorer-studio-dev.genlayer.com/tx/0x251a8919515ec988856d3f3e2928e039dfb83d456c337c01f47277d6f89f987d); exact corpus persisted |
| First live semantic assessment | [Accepted assessment](https://explorer-studio-dev.genlayer.com/tx/0x3c5e9778a51fa4fb0acf6f634dc813481ef1d2f25be278584c12da4a1bd744ac) returned terminal `INCONCLUSIVE`; no certificate issued |
| Clarified synthetic benchmark | Benchmark `1`, candidate `1`; [accepted assessment](https://explorer-studio-dev.genlayer.com/tx/0xbe17aaab13dea6d7dca77a8c025178c98068ce2717947b3d761088cbdf41baa1) stored `CERTIFIED` with predictions `["ALLOW", "ALLOW", "DENY", "DENY"]` |
| Clarified benchmark metrics | True allow `2`, true deny `2`, false allow `0`, false deny `0`; accuracy `10000` basis points |
| Clarified benchmark receipt SHA-256 | `35b930229ac89f837f0a4d2c60c9ac375d7c3671db67fb5767e44224c9986831` |
| Clarified certificate readback | Scoped certificate retrieved and checked against the stored receipt; scope `EXACT_OWNER_DECLARED_BENCHMARK_ONLY` |
| Original benchmark finalization | [Benchmark 0 finalized](https://explorer-studio-dev.genlayer.com/tx/0x07c46fc32fe8ad9a93dcd448f04f288a564a503068e65f1b7115bb1d4c75c7ff) after its fixed deadline, preserving terminal `INCONCLUSIVE` and no certificate |
| Clarified benchmark finalization | [Benchmark 1 finalized](https://explorer-studio-dev.genlayer.com/tx/0xedb3ed64a6e61ae89e533335ecde5045e884955df899e19043e3fc6a1df10b1b) after its fixed deadline; the exact scoped certificate remains unchanged |
| Transaction finality | All eleven synthetic network transactions successful and `FINALIZED`, including both benchmark finalizations; complete check November 22 at 09:44:42 UTC |
| Portal contribution ID / status | Not submitted yet |

## Minimal runner migration

The archived November 8 preparation pinned the v0.3.0 runner. The current host
rejected that runner during the native source-schema check. Only the first two
source header lines changed for compatibility:

```text
# v0.4.0
# { "Depends": "py-genlayer:kzybg95x1gn21dw72m7hyg0maaap04n4nx55j9yt6fkdqxtz6bz0" }
```

The contract body, API and consensus/state logic are unchanged. The released
source passed native source-schema validation and the complete local suite.
The archived prepared source had raw SHA-256 `d64d4317c0277d9ec41d5a7262acb5c15c1b124635043cee3050f1ca6bc20b8e`; it is historical and is
not the source identified by the current release hash above.

Raw file-byte hashes are distinct from the separately normalized complete
deployed-source comparison above. The immutable GitHub file was independently
retrieved and matches the exact released raw-file hash. Schema validation and
initial stats alone do not prove a successful application write. The benchmark-open
write above additionally persisted and checked the chain, contract and clock
context. The complete semantic assessments and their different deterministic
outcomes are recorded separately above.

## Reproduce and interpret the evidence

The public [combined demonstration](evidence/demo-result.json) includes both
the [original inconclusive result](evidence/original-inconclusive.json) and the
[clarified scoped certificate](evidence/positive-certificate.json). The
[transaction list](evidence/transactions.json), [complete source comparison](evidence/source-verification.json)
and [native schema result](evidence/native-schema.json) preserve the exact observed
evidence separately.

Follow [STUDIO-TEST.md](STUDIO-TEST.md) using synthetic or public material and
0 GEN transaction value. Require GenVM SUCCESS and persisted relevant state, not
consensus acceptance alone. The controlled-output suite and actual synthetic
network walkthrough are separate evidence; neither is a model-accuracy benchmark.
Keep failed or undetermined attempts in the release record.

## First terminal semantic result

The first benchmark used `Export A has current owner approval.` for case 0 while
the locked policy required approval covering its scope. Validators returned
`["UNCERTAIN", "ALLOW", "DENY", "DENY"]`. The complete accepted receipt records
full inspection, no truncation and omitted structured reference-label fields.
The deterministic outcome is terminal `INCONCLUSIVE`, with `metrics: null` and
`certificate_payload: null`. This is preserved as a successful fail-closed
assessment, not presented as a certificate or discarded technical failure.

The separate clarified benchmark changes only that case text to `Export A has
current owner approval and is within its approved scope.`, retaining the same
policy and reference labels. It uses a new nonce, salt and commitment, with
60-second enrollment, 120-second reveal and 180-second evaluation phases. It
does not rerun, overwrite or change the first terminal benchmark.

The original benchmark/candidate IDs are `0`/`0`; the clarified benchmark/candidate
IDs are `1`/`1`. Both accepted assessment hashes remain part of the release record.
This benchmarks supplied policy text against owner-declared reference
labels, not execution of actual software, curator independence or performance
on unseen inputs.
