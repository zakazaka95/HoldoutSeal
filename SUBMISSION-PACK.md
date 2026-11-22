# HoldoutSeal Portal package

Published November 22, 2026. Category: Builder → Intelligent Contracts.
See [DEPLOYMENT.md](DEPLOYMENT.md) for the current verified release evidence.

## Title

HoldoutSeal: Precommitted Policy-Description Benchmarks with Consensus-Scored Certificates

## Notes / Description

HoldoutSeal evaluates a frozen natural-language policy description against an exact owner-declared corpus committed before enrollment. A salted digest binds chain, deployment, owner, specification, thresholds, nonce and every case. Up to four declared candidates lock one policy each before reveal. Independent GenLayer validators classify all complete cases using a prompt that omits structured reference-label fields, salt, commitments and thresholds, then rebuild the full receipt. Deterministic confusion counts apply separate false-allow and false-deny caps; uncertainty produces no partial score or certificate. Timed reveal, immutable policies, exact case coverage, bounded retries, expiry and backward-time guards control finality. Certificates cover this benchmark only: curator hints or leaks remain possible, labels are assumptions, and no deployed program is executed. Includes adversarial tests, an offline commitment helper and a Studio walkthrough.

## Evidence

1. GitHub Repository — https://github.com/zakazaka95/HoldoutSeal
2. GitHub File — https://github.com/zakazaka95/HoldoutSeal/blob/8b4413ebdf1d98a44087f9a781c55d760442189c/HoldoutSeal.py
3. GenLayer Explorer Contract — https://explorer-studio-dev.genlayer.com/address/0xa336823415BaD11521844DE9a477b85d7ec7d687
4. Other — https://explorer-studio-dev.genlayer.com/tx/0xbe17aaab13dea6d7dca77a8c025178c98068ce2717947b3d761088cbdf41baa1

The clarified benchmark assessment is linked above. DEPLOYMENT.md also preserves
the first terminal `INCONCLUSIVE` result, the exact input clarification and the
separate benchmark identities; no result is hidden or overwritten.
The [complete public demonstration](evidence/demo-result.json) includes both
outcomes and successful fixed-deadline finalization.

The description has 963 characters. All 41 controlled-output unit tests and the
current native source-schema check pass. Deployment, live-model and Portal
observations are separate evidence in [DEPLOYMENT.md](DEPLOYMENT.md); neither a
schema check nor a synthetic walkthrough is a model-accuracy benchmark.
