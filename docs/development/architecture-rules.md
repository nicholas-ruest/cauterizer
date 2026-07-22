# Enforced Architecture Rules

The `architecture-tests` crate turns the dependency direction in ADR-002, ADR-008, ADR-019, ADR-021, ADR-022, and the DDD implementation scaffold into a CI gate. It scans package manifests and Rust source without compiling product crates, so structural violations are reported even when a workspace is otherwise broken.

## Package declaration

Every product crate declares `package.metadata.cauterizer.layer`. Bounded-context crates also declare `package.metadata.cauterizer.context`. Name/path inference is a fallback and must not be treated as the durable source of ownership.

Layers are:

- `domain`: aggregate behavior, value objects, domain events, policies, and repository interfaces.
- `application`: use-case handlers, ports, commands, queries, and anti-corruption translation.
- `infrastructure`: persistence, messaging, network/provider, filesystem, runtime, and telemetry implementations.
- `contracts`: versioned serialized API/event/schema shapes.
- `shared`: context-neutral syntax or mechanism only.
- `binary`: composition roots such as CLI, API, and workers.

## Enforced invariants

| Rule | Enforcement |
|---|---|
| Domain purity | Domain packages may depend only on domain/shared packages and reject known database, network, web, queue, cloud, and runtime/framework crates. |
| Dependency direction | Domain cannot depend on application, infrastructure, contracts, or binaries. Infrastructure depends inward through owned ports. |
| Context ownership | A package cannot depend on another bounded context's internal crate. Versioned contract packages are the only direct cross-context dependency allowed; application facades remain runtime boundaries. |
| Acyclic workspace | Cycles among local packages fail regardless of layer. |
| No hidden source import | Source-level references to an internal crate from another context fail even if a dependency declaration is missing or malformed. |
| Canonical independence | Domain and contract source cannot mention Ruflo, Claude Flow, agentic-flow, OSV/CVE-Bench, cloud, model-provider, or other upstream SDK markers. Translate these in infrastructure adapters. |
| Unsafe default | Unsafe blocks, functions, traits, implementations, unsafe extern declarations, and local `allow(unsafe_code)` suppressions fail. |

The marker/dependency lists are defense in depth, not an exhaustive definition of infrastructure. Reviewers must reject a novel framework or SDK that has not yet been added to the list.

## Allowed cross-context shape

```text
context A application -> context B contracts -> serialized/versioned fact
          |                         |
          +-> A-owned ACL/port <----+

context A domain -X-> context B domain/application/infrastructure
```

Contract dependency does not confer payload access or authority. Authorization, organization binding, classification, schema validation, idempotency, and anti-corruption translation still apply at every crossing.

## Unsafe exception process

There is no implicit exception for performance or FFI convenience. A proposed exception must first:

1. demonstrate that a safe Rust implementation or isolated process boundary is impractical;
2. isolate unsafe code in a dedicated minimal mechanism crate with no domain authority;
3. document each safety invariant, input/trust boundary, platform assumption, and failure mode;
4. include targeted tests, sanitizers/Miri and fuzzing where applicable;
5. receive named architecture and security approval; and
6. amend this checker narrowly, with a regression test proving that other unsafe code remains rejected.

Until all six steps are merged, `unsafe` is a release-blocking violation.

## Running the gate

Run the architecture package test through the workspace's pinned Cargo command. The integration gate discovers the workspace from `CARGO_MANIFEST_DIR` and prints all deterministic findings with a stable rule identifier. Fixture tests prove both allowed and forbidden dependency shapes.

