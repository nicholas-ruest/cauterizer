# Release acceptance records

Status: template/schema only. No filled-in record exists in this directory —
none is created until a real critical/high finding actually needs one, and
only with a real accountable security decider's approval. Do not add a
filled-in file here that isn't backed by an actual reviewed decision.

## When this applies

`docs/architecture/abuse-case-test-matrix.md`'s "Minimum release gates"
section is fail-closed for critical cases: a critical finding cannot ship
silently, cannot be quarantined, and cannot be retried to green. The **only**
way a release proceeds with a known critical/high finding still open is a
signed acceptance record meeting every field below, per that section:

> Any critical failure blocks the conformant release. An exception must
> identify the failed claim, affected deployment/profile, owner,
> compensating control, expiry, and approval by the accountable security
> decider; it must also force truthful non-conformant labeling wherever the
> failed claim is material.

## Required fields

Each acceptance record is one Markdown file in this directory, named
`<ac-id-or-finding-id>-<yyyy-mm-dd>.md`, containing at minimum:

| Field | Meaning |
|---|---|
| `failed_claim` | The exact abuse-case ID (`AC-0NN`) or ADR invariant that did not pass, quoted verbatim from `abuse-case-test-matrix.md`. |
| `affected_deployment` | The specific deployment/profile this exception covers (for example `hosted-production`, `local-nonconformant`). An exception never silently covers every deployment. |
| `owner` | The named accountable individual (not a team alias) who owns remediation. |
| `compensating_control` | The concrete control standing in for the failed claim until remediation lands, and why it bounds the same risk. |
| `expiry` | An absolute date. The exception is void after this date; it cannot be renewed by editing the same file — a new record with a new justification is required. |
| `security_decider_approval` | Name, role, and date of the accountable security decider who approved this exception. A record with this field blank or self-approved by `owner` is not a valid acceptance record. |
| `non_conformant_labeling` | Confirmation of exactly where truthful non-conformant/exception labeling was added (evidence bundle, release notes, deployment manifest) so the failed claim is never silently presented as passing. |

## What this is not

- Not a mechanism to quarantine a flaky test — see
  `docs/architecture/quarantined-tests.tsv` and
  `scripts/ci/verify-release-gates.sh` for that (owner + reason + expiry
  ≤14 days, and a quarantined test still cannot satisfy a release gate).
- Not available for critical cases at all if the matrix marks them
  fail-closed with no exception path; re-read the specific `AC-0NN` row
  before drafting one.
- Not self-service: `verify-release-gates.sh` does not (and should not)
  auto-approve anything written here — a human security decider's sign-off
  is the entire point of this format.
