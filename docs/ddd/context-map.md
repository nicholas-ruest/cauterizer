# Cauterizer Context Map

Status: proposed  
Governing decisions: [ADR-002](../adr/ADR-002-separate-the-system-into-seven-bounded-contexts.md) and [ADR-009](../adr/ADR-009-add-enterprise-platform-bounded-contexts.md)

## Map

```text
                [Organization & Access]
                   | tenant/actor/policy
       +-----------+-------------------------------+
       |                                           |
[Commercial Entitlements]                    [Asset Portfolio]
       | grants/reservations                       | authorized target/scope
       +-------------------+-----------------------+
                           v
External advisory sources
        |
        | ACL: raw records -> AdvisorySnapshot
        v
[Advisory Intake] --AdvisorySnapshotted--> [Remediation Runs]
                                                 |
                     ExecutionRequested --------+-------- ProposalRequested
                            |                                  |
                            v                                  v
                  [Isolated Execution]                 [Patch Proposals]
                            |                                  |
                     ExecutionObserved                  PatchProposed
                            |                                  |
                            +--------------+-------------------+
                                           v
                                    [Verification]
                                           |
                                  CandidateAssessed
                                           |
                      +--------------------+------------------+
                      v                                       v
                  [Evidence]                         [Remediation Runs]
                      |                                       |
              EvidenceBundleFinalized                         |
                      +--------------------+------------------+
                                           v
                                  [External Actions]
                                           |
                                 governed connector action
                                           |
                              [Integration Management]
```

## Relationships

| Upstream | Downstream | Pattern | Contract | Rule |
|---|---|---|---|---|
| Organization & Access | All contexts | Published language | tenant/actor/policy decision | Every operation is tenant scoped |
| Commercial Entitlements | Cost-incurring contexts | Published language | grant/reservation/settlement | Commercial state cannot weaken security gates |
| Asset Portfolio | Remediation Runs | Published language | authorized immutable target and scope | Only owned/in-scope targets enter runs |
| Integration Management | Context adapter ports | Anti-corruption layer | capability-bound installation | Connector cannot exceed consented capability |
| Advisory source | Advisory Intake | Anti-corruption layer | Source-specific record | Raw types never cross into the domain |
| Advisory Intake | Remediation Runs | Published language | `AdvisorySnapshotted` | Consume immutable ID and digest |
| Remediation Runs | Isolated Execution | Customer/supplier | `ExecutionRequest` | Request declares capability/resource envelope |
| Remediation Runs | Patch Proposals | Customer/supplier | `ProposalRequest` | Contains only approved solver-view references |
| Patch Proposals | Verification | Published language | `PatchProposed` | One-way candidate submission; no oracle feedback |
| Isolated Execution | Verification | Conformist at observation schema only | `ExecutionObservation` | Worker reports facts and never a verdict |
| Verification | Evidence | Published language | `CandidateAssessed` | Verdict and reasons are immutable inputs |
| Verification | Remediation Runs | Published language | `CandidateAssessed` | Run records status without recomputing verdict |
| Remediation Runs | Evidence | Published language | `RunRecordSealed` | Evidence consumes complete event-chain reference |
| Evidence | External Actions | Published language | `EvidenceBundleFinalized` | Only eligible verified bundles can be authorized |

## Information-flow constraints

- Patch Proposals cannot call Verification or subscribe to `CandidateAssessed` for a conformant run.
- Patch Proposals cannot access verifier artifact stores, caches, logs, identities, or timing telemetry.
- Isolated Execution cannot access policy signing keys or approval capabilities.
- Evidence can read immutable published artifacts by digest but cannot alter their owning aggregates.
- External Actions cannot alter a verdict or bundle; a new bundle is required after any input changes.
- Remediation Runs coordinates work but cannot fabricate another context's completion event.

## Shared kernel

Only these syntax-level concepts may be shared:

- opaque context-qualified identifiers;
- cryptographic digest and algorithm identifiers;
- canonical instant/duration representation;
- schema name/version envelope;
- pagination and result/error envelope.

Domain enums, entities, policies, repository interfaces, and events remain context-owned.

## Consistency model

- Within an aggregate: strongly consistent invariant enforcement.
- Across contexts: eventual consistency through immutable events and idempotent handlers.
- Process progress: Remediation Runs projections may lag but can rebuild.
- Verdict and evidence: once finalized they are immutable; correction creates a superseding assessment or bundle.

## Forbidden dependencies

- Direct database reads across contexts.
- Cross-context imports of internal domain entities or repositories.
- A shared `Run` object mutated by intake, solver, verifier, and evidence code.
- Orchestrator-specific task objects in canonical contracts.
- Upstream SDK types in domain APIs.
- A callback from hidden grading to a conformant solver.
- Billing-provider availability in verification decisions.
- Connector secret values inside domain aggregates or events.
- Tenant filtering implemented only in presentation/API code.
