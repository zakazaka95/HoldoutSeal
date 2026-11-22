# HoldoutSeal — local preparation record

Prepared November 8, 2026 for the week beginning November 16.
**NOT PUBLISHED / NOT DEPLOYED / NOT SUBMITTED.** All external actions wait for go.

| Item | Current record |
| --- | --- |
| Source version / receipt schema | `1.0.0` / `holdoutseal-v1` |
| Exact source-file SHA-256 | `d64d4317c0277d9ec41d5a7262acb5c15c1b124635043cee3050f1ca6bc20b8e` |
| Local tests | 41 controlled-output unit tests passed |
| Offline helper | `commitment.py`, exact digest agreement/domain tests passed |
| Native GenVM schema / execution | NOT RUN for this source |
| Public repository / immutable source URL | NOT PUBLISHED |
| Current network / chain ID | PENDING: verify actual host at release |
| Contract address / deployment transaction | NOT DEPLOYED / NONE |
| GenVM result / full source match | PENDING: no live deployment |
| Committed reveal / real semantic assessment | NOT RUN |
| Certificate / expiry live readback | NOT RUN |
| Portal submission / points | NOT SUBMITTED; no award claimed |

The pinned `# v0.3.0` / `py-genlayer:babwp9t37jw9g4j2bccgn14g6x7x9s1f7dsmh7emvz735pz4zxa0`
API family and deterministic `datetime.now(timezone.utc)` clock were used by earlier
contracts. This source additionally reads native `gl.message.contract_address` and
`gl.message.chain_id` to domain-bind commitments; the local SDK exposes them, but
their actual future host behavior remains to be verified. Schema success alone
does not demonstrate the first write's execution compatibility.

The fingerprint above is the exact local file-byte hash. Later Explorer-rendered
text comparisons must state any separate whitespace normalization and normalized
hash explicitly. Deploy the exact tracked source, not an older corrected variant.

After go, follow [STUDIO-TEST.md](STUDIO-TEST.md). Require GenVM SUCCESS and persisted
benchmark, candidate, complete receipt and certificate state. A leader output alone
or Accepted transaction with GenVM ERROR is not a successful contract call. Preserve
adverse attempts honestly and distinguish local controlled outputs from live-model
accuracy. The certificate concerns supplied policy text and owner-declared reference
cases only; it does not attest actual software execution or an unbiased holdout.
