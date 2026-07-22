# DDD Implementation Scaffold

This is a documentation blueprint, not created source code. Each bounded context maps to the following future package shape:

```text
src/contexts/<context>/
  domain/
    aggregates/
    entities/
    value-objects/
    events/
    policies/
    services/
    repositories/
  application/
    commands/
    queries/
    handlers/
    ports/
    dto/
  infrastructure/
    persistence/
    messaging/
    adapters/
    projections/
  contracts/
    api/
    events/
    schemas/
  tests/
    domain/
    contract/
    integration/
    architecture/
  index
```

## Dependency rules

- Domain depends only on its own domain and approved shared syntax primitives.
- Application depends on its domain and declared ports.
- Infrastructure implements ports and depends inward.
- Contracts contain serialized public shapes, not domain entities.
- A context public index exports its application facade and contracts, never infrastructure.
- Cross-context calls target application facades or consume integration contracts.
- Architecture tests reject internal cross-context imports and cyclic context dependencies.

## Shared platform packages

Allowed shared packages are syntax/mechanism only: identifiers/digests, time abstractions, schema envelope, authorization context, telemetry interfaces, cryptographic interfaces, transactional unit/outbox primitives, and test fixtures. They cannot define `Run`, `Advisory`, `Patch`, `Verdict`, `Evidence`, `Organization`, `Asset`, or `Entitlement` domain meaning.

## Per-context completeness

Each of the eleven directories under `docs/ddd/contexts/` supplies the six required specifications that must be reflected in its future source package: overview, domain model, application model, published contracts, operations/security, and tests.
