# HoldoutSeal reproducible Studio walkthrough

This is a future procedure, not evidence that it was run. **Local preparation only:
wait for explicit go before publishing, deploying, transacting or submitting.**
Use synthetic material, Normal / Full Consensus, simulation off, value **0 GEN**.
Network execution fees are separate. Do not switch Studio source while Sending or
Deploying; wait until the transaction is visibly submitted to the intended address.

## 1. Deploy exact tracked source

After go, publish the source, tests, offline helper and documentation together.
Deploy this exact `HoldoutSeal.py` with no constructor arguments. Recheck the actual
host, schema, runner and network; the pinned API family was used by earlier
contracts but this source has not been deployed. Require GenVM SUCCESS, inspect
the complete Explorer source and compare it with the immutable tracked file.

Read `get_stats`: version `1.0.0`, schema `holdoutseal-v1`, zero counters. Copy the
actual deployed contract address, actual chain ID and benchmark owner's Studio
address. Portal wallet and Studio account can differ; use the actual sender.

## 2. Prepare commitment offline

Choose a fresh secret salt and nonce. Keep the corpus and salt offline until the
enrollment stage ends. This published illustrative fixture is synthetic and **not
an empirically hidden test set**; using one account for both roles demonstrates
mechanics, not curator independence.

Use a specification like this, replacing the candidate address with the actual
account that will enroll and assess:

```json
{
  "title": "Synthetic export policy holdout",
  "purpose": "Classify synthetic file-export permission cases under the supplied policy text.",
  "label_rule": "ALLOW when the policy explicitly permits the exact export; DENY when it explicitly forbids it; otherwise UNCERTAIN.",
  "candidates": ["<actual candidate address>"],
  "case_count": 4,
  "max_false_allows": 0,
  "max_false_denies": 0,
  "nonce": "<fresh owner nonce>",
  "enrollment_seconds": 120,
  "reveal_seconds": 120,
  "evaluation_seconds": 1200
}
```

The complete corpus is:

```json
[
  {"case_id":0,"text":"Export A has current owner approval.","expected":"ALLOW"},
  {"case_id":1,"text":"Export B has current owner approval and is within its approved scope.","expected":"ALLOW"},
  {"case_id":2,"text":"Export C has no owner approval.","expected":"DENY"},
  {"case_id":3,"text":"Export D's only owner approval expired yesterday.","expected":"DENY"}
]
```

Make a local `private-fixture.json` with `owner`, `contract_address`, `chain_id`,
`spec` (the exact specification), `cases` (the exact corpus), and `salt`. Use actual
deployment context; the helper does not query a network. Compute locally:

```text
python commitment.py < private-fixture.json
```

The helper canonicalizes spec/cases exactly like the contract and prints a SHA-256
digest. It preserves actual text, case order and owner/deployment/chain domain.
Do not commit the private file, send it to an onchain view, or publish its salt.

## 3. Commit, then enroll policy

As benchmark owner call `open_benchmark(spec_json, copied_digest)`. On a fresh
deployment the returned benchmark ID is `0`; use actual returned IDs thereafter.
Read `get_benchmark` and verify commitment, complete spec and all three absolute
deadlines. This first write also tests native contract/chain context and the real
clock adapter; schema/constructor success alone does not establish compatibility.

Before `enrollment_deadline`, from the exact candidate account call:

```text
enroll_policy(benchmark_id,
  "An export is ALLOW only when current owner approval is explicitly present and covers its scope. Without owner approval, or when its approval is expired, the export is DENY.")
```

Read its candidate ID and immutable policy/address/hash. No model has run yet.
The same account cannot overwrite or enroll another policy for this benchmark.
The owner may also be a candidate in this synthetic fixture, which is not a
demonstration of hidden knowledge from that account.

## 4. Reveal after enrollment closes

Only once the transaction time reaches the recorded enrollment deadline, and
strictly before `reveal_deadline`, call as owner:

```text
reveal_benchmark(benchmark_id, complete_cases_json, exact_salt)
```

Read benchmark status `REVEALED`, full corpus and its hash. The salt is public in
the reveal transaction; it is no longer a secret. Wrong salt, altered cases or
labels, early reveal and late enrollment must fail without changing state.

## 5. Assess complete frozen policy

Before `evaluation_deadline`, as that exact candidate call `assess_policy(id)`.
Independent validators classify every complete case without the structured
reference-label fields. The expected positive fixture predicts ALLOW, ALLOW, DENY,
DENY, producing true_allow `2`, true_deny `2`, zero errors and accuracy `10000` bps.

Read the actual candidate, accepted attempt and `get_certificate`. A successful
stored result must be `CERTIFIED`, semantic inspection complete, no truncation,
all case predictions, complete metrics, exact policy/corpus hashes and certificate
scope `EXACT_OWNER_DECLARED_BENCHMARK_ONLY`. The certificate's receipt hash must
match the stored full receipt. This is GenLayer interpretation of policy **text**,
not execution of a candidate model or program.

Live models can disagree or classify a case UNCERTAIN. Record that result honestly;
do not call an unaccepted leader result a certificate. A readable failure or
uncertainty is final. Only technical UNRESOLVED results can retry, at most three
accepted attempts. No partial metrics exist for any UNCERTAIN case.

## 6. Deterministic expiry and optional negatives

At the fixed final deadline, `finalize_expired(benchmark_id)` is callable by anyone.
It finalizes the revealed benchmark and expires pending evaluations. Earlier valid
certificates remain unchanged scoped history. An unrevealed benchmark can instead
be expired at its reveal deadline, with no fabricated score or certificate.

The local suite covers wrong domains/salt, modified labels/case coverage, duplicate
case text, constant predictors, false allows/denies, uncertainty, complete receipt
tampering, report replay, unauthorized assessment, maximum Unicode transport,
full prompt budgets and backward transaction time. These are local observations,
not executed network negatives unless actual transactions are recorded.

For a live failed policy, enroll a second allowed candidate **before** reveal with
"Deny every export." If the actual accepted predictions are all DENY, it must fail
the false-deny cap. Do not enroll after seeing revealed corpus or overwrite the
first candidate. Save actual receipts and IDs, including adverse outcomes.

## Evidence to preserve

Update [DEPLOYMENT.md](DEPLOYMENT.md) only with actual source commit, address,
deployment/assessment/finalization transactions, GenVM results and persisted reads.
Attach its own repository, immutable source file, exact Explorer address and a real
semantic assessment transaction to the future Portal contribution. No automatic
release or submission is configured.
