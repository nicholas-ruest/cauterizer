# Security Threat Model Scaffold

Status: required before ADR acceptance

## Assets

- Tenant identity, membership, policy, connector credentials, and approval grants.
- Embargoed advisories, source, exploit tests, patches, prompts, logs, and evidence.
- Hidden verifier tests, gold controls, result oracle, signing/encryption keys.
- Control-plane authority, worker images, dependency bundles, audit records, usage/billing records.

## Trust zones

1. Public/API edge.
2. Tenant-authenticated control plane.
3. Transactional data, artifact, audit, and key services.
4. Networked acquisition workers.
5. Solver workers and provider boundary.
6. Verifier workers and hidden artifact store.
7. Evidence signer/verifier.
8. External connector destinations.
9. Operator/support plane.

No zone trusts another merely because it is internal. Every crossing authenticates workload and tenant, authorizes capability, validates schema/size, applies classification, sets deadline/budget, and emits audit where relevant.

## Principal threat scenarios

| Threat | Required controls |
|---|---|
| Cross-tenant object reference | tenant-bound IDs, policy, storage predicates, negative tests |
| Malicious repository/build/test escape | ADR-004/018/020 isolation, no secrets/egress, resource limits |
| Hidden-oracle leakage | ADR-005 identity/store/cache/log/telemetry/memory segregation |
| Solver prompt/data exfiltration | minimal briefs, provider policy, redaction, egress controls |
| Artifact/result tampering | content addressing, immutable descriptors, signatures, verification |
| Confused-deputy connector action | exact capability/action/destination grant and step-up approval |
| Credential/key theft | workload identity, secret manager/KMS/HSM, rotation/revocation |
| Dependency/build compromise | pins, SBOM, scanning, hermetic build, provenance, signature policy |
| Event replay/forgery | authenticated producers, event IDs, inbox, sequence, schema validation |
| Billing/quota bypass | atomic reservation, tenant consistency, immutable settlement |
| Support/operator abuse | JIT break-glass, separation of duties, audit, customer visibility |
| Privacy/retention failure | classification, region, cryptographic erasure, backup lifecycle |
| Availability/cost attack | quotas, admission, backpressure, bulkheads, load shedding, alerts |

## Required analysis artifacts

- Data-flow diagrams with protocols, identities, data classes, and storage.
- STRIDE or equivalent review per trust boundary.
- Abuse-case catalog linked to tests and alerts.
- Secrets/key inventory and rotation table.
- Third-party/provider risk register.
- Residual-risk acceptance signed by accountable deciders.

## Security release bar

No production launch until critical/high findings are remediated or explicitly risk-accepted with owner and expiry; tenant isolation, sandbox escape resistance, authorization, hidden-data segregation, evidence integrity, and external-action gating have independent adversarial review.
