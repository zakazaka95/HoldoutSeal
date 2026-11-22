# HoldoutSeal

HoldoutSeal preserves the order of a finite policy-description evaluation:
**commit the corpus, lock candidate policy text, reveal, then score**.

**Published November 22, 2026.** The complete source, tests and reproducible
walkthrough are included. See [DEPLOYMENT.md](DEPLOYMENT.md) for the current
network verification and release evidence.

[Immutable contract source](https://github.com/zakazaka95/HoldoutSeal/blob/8b4413ebdf1d98a44087f9a781c55d760442189c/HoldoutSeal.py).
The current native source-schema check passes with the pinned v0.4.0 runner.
Only the two runner-header lines changed from the archived prepared source;
contract behavior is unchanged and all 41 controlled-output tests pass.

The [live demonstration](evidence/demo-result.json) preserves an original
`INCONCLUSIVE` benchmark and a separately committed, clarified `CERTIFIED`
benchmark. Both finalizations and all eleven transactions succeeded and reached
`FINALIZED`; the exact scoped certificate survives finalization.

## What becomes state

An owner freezes the task, label definition, candidate roster, error caps, stage
durations and an owner nonce. A salted commitment binds that complete specification
and the exact normalized case corpus to the owner, deployed contract and chain.
The deployment context is already known before `open_benchmark`; no unknown future
benchmark ID is needed to construct its commitment.

One to four declared candidate addresses may each enroll one immutable
natural-language policy description before the enrollment cutoff. Only after that
cutoff may the owner reveal the precommitted corpus, before a fixed reveal deadline.
All policies and thresholds remain fixed. The owner cannot edit a corpus, extend
deadlines, substitute a policy or reuse their nonce inside this deployment.

Independent GenLayer executions apply each candidate's full policy description to
every complete case. **This interprets supplied policy text; it does not execute a
candidate's real deployed model, agent, binary or program.** Only the evaluating
candidate may request its assessments, so another account cannot burn its retries.

The classifier prompt has an explicit field whitelist: purpose, label rule,
candidate policy, and each case's ID and complete text. Structured `expected`
reference-label fields, salt, commitment, error caps and previous results are not
included. The receipt flag `reference_label_fields_in_prompt: false` means exactly
that structural omission. It does not prove that a curator supplied no answer hints
inside ordinary case text or communicated no information outside the contract.

The model returns only ordered `ALLOW`, `DENY` or `UNCERTAIN` predictions. Contract
code calculates the confusion matrix, false allows, false denies, correct count
and integer accuracy in basis points. Separate frozen error caps decide whether a
benchmark-specific certificate is issued. The model does not choose a score or
change those caps. Any `UNCERTAIN` makes the whole result final `INCONCLUSIVE`,
with **no partial score and no certificate**.

## What the certificate means

A certificate binds the exact benchmark, corpus hash, candidate policy hash,
complete metrics and accepted receipt hash. Its scope is
`EXACT_OWNER_DECLARED_BENCHMARK_ONLY`. A finalized benchmark preserves earlier
completed certificates as immutable history; it does not expand their scope.

Reference labels are **owner-declared assumptions**, not objective ground truth.
The curator knows the corpus and can choose weak cases, leak them, or embed hints.
The salt should have cryptographic entropy, but this contract cannot prove that it
does. It is not a proof of cryptographic blindness, unbiased sampling, curator
independence, real software accuracy, safety, permission or performance on unseen
inputs. After reveal, corpus and reference labels are public; the reveal transaction
also exposes the salt. Use synthetic or already-public examples, not private data.

Consumers must pin the exact contract, chain, benchmark and candidate IDs and inspect
the public task, corpus, labels, caps and metrics. A `CERTIFIED` word alone is not a
general quality endorsement: permissive declared caps can still accept substantial
error. No funds are held and no external execution or deployment is authorized.

## Corpus, timing and finality

The corpus has four to six cases with at least two reference `ALLOW` and at least
two reference `DENY` cases. This is minimum class representation, not necessarily
equal class balance. Exact duplicate case text is rejected; semantic paraphrases
are not deduplicated. IDs must cover `0..case_count-1` in order. The false-allow cap
must be below the number of reference DENY cases, and the false-deny cap below the
ALLOW count. Thus either constant single-label predictor must fail. Impossible
public cap/count combinations are rejected before storing the benchmark.

```text
Benchmark COMMITTED -> REVEALED -> FINALIZED
                    \-> EXPIRED if no timely reveal

Candidate ENROLLED / RETRYABLE -> CERTIFIED / FAILED / INCONCLUSIVE
                            \-> RETRYABLE -> UNRESOLVED_FINAL
Pending candidate -> EXPIRED at its applicable final deadline
```

Enrollment is exclusive at its deadline. Reveal is allowed at the enrollment
deadline, but not at the reveal deadline. Assessment is exclusive at the evaluation
deadline. Three accepted technical attempts are allowed for malformed/model-error
receipts. Readable success, failure or uncertainty is final and cannot be rerolled.
Consensus disagreement is a rejected transaction, not an accepted contract attempt.

`finalize_expired` is permissionless and bounded by four enrolled candidates.
Missing reveal expires pending candidates without fabricating predictions or scores.
At evaluation end it finalizes the benchmark and expires pending evaluations.
Effective expiry views do not write. Time is captured in deterministic public
methods, outside model callbacks. A per-benchmark persisted time floor rejects older
transaction contexts before state can change. Completed certificate history remains
readable independently of that pending-work check.

## Complete consensus and inspection

Every validator independently runs the whole classification task and rebuilds the
full canonical receipt. Exact equality binds the full benchmark/candidate input,
reference corpus, every prediction, metrics, decision, certificate payload, attempt,
time, full prompt digest, character/UTF-8 counts and inspection flags. The accepted
receipt hash is derived deterministically when storing the certificate. No free-form
model narrative is persisted. Agreement still does not guarantee semantic correctness.

The entire escaped prompt is checked against both character and UTF-8 byte budgets.
It is never sliced. Reveal validates the complete corpus and every enrolled policy
against the prompt budget before persisting any reveal. Rejected writes do not
partially reveal, enroll, advance a time floor or consume an assessment attempt.
JSON transport bounds also accommodate maximum emoji text using ordinary escaped
`json.dumps`; the decoded semantic text is preserved exactly.

## API

```text
open_benchmark(spec_json, corpus_commitment) -> benchmark_id
enroll_policy(benchmark_id, policy_text) -> candidate_id
reveal_benchmark(benchmark_id, cases_json, salt)
assess_policy(candidate_id) -> complete receipt
finalize_expired(benchmark_id) -> number of candidates expired

get_benchmark(benchmark_id) -> {record, effective_status, observed_at}
get_candidate(candidate_id) -> {record, effective_status}
get_certificate(candidate_id) -> {payload, receipt_hash}
get_attempt(candidate_id, attempt)
get_stats()
```

The exact spec keys are `title`, `purpose`, `label_rule`, `candidates`, `case_count`,
`max_false_allows`, `max_false_denies`, `nonce`, `enrollment_seconds`,
`reveal_seconds`, `evaluation_seconds`. Candidate addresses are lowercased and
sorted. Strings retain their exact valid Unicode text. Hashes use canonical JSON
with sorted keys, compact separators and UTF-8; JSON formatting/key order is not
part of the commitment. Case array order and actual text are part of it.

| Bound | Value |
| --- | --- |
| Candidate roster | 1–4 fixed distinct addresses |
| Complete cases | 4–6, at least two of each reference class |
| Title / purpose / label rule / nonce | 100 / 400 / 500 / 80 characters |
| Policy / each case | 1,000 / 500 characters |
| Salt | 16–128 characters; choose fresh cryptographic entropy |
| Each stage duration | 60–86,400 seconds |
| Prompt | 34,000 characters and 65,000 UTF-8 bytes |
| Accepted technical attempts | 3 per candidate |

## Verification and reproducible release

```text
python -m unittest -v test_holdoutseal
```

**41 controlled-output tests passed.** They exercise commitment/helper agreement,
domain separation, phase ordering, immutability, scorer consequences, constant
predictor rejection, uncertainty, retries, independent disagreement, every receipt
leaf, label-field omission in both prompts, maximum escaped Unicode input, staged
write failures, backward time, finalization and clock callback boundaries. They are
not live-model accuracy benchmarks, native GenVM schema checks or network evidence.

`commitment.py` is a standalone **offline** helper. It is not imported by the
single-file deployed contract. Feed a local object containing `owner`,
`contract_address`, `chain_id`, `spec`, `cases`, `salt` to its standard input; it
prints only the digest. Do not upload the secret fixture or salt before enrollment
closes. See [STUDIO-TEST.md](STUDIO-TEST.md) for the exact reproducible flow and
[DEPLOYMENT.md](DEPLOYMENT.md) for observed release evidence and
[SUBMISSION-PACK.md](SUBMISSION-PACK.md) for the Portal description and links.
