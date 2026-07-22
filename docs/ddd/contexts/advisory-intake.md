# Bounded Context: Advisory Intake

## Purpose and ownership

Normalize untrusted vulnerability information into immutable, attributable snapshots suitable for remediation selection. It owns source retrieval metadata, normalization status, aliases, affected ranges, severity vectors, withdrawal state, and snapshot digests.

It does not decide whether a patch works, prioritize solely from CVSS, execute exploit code, or mutate an external advisory source.

## Aggregate

### `AdvisoryRecord`

Identity: stable internal `AdvisoryRecordId`; source IDs and CVE aliases are attributes, not identity.

Contains a sequence of immutable `AdvisorySnapshot` references and the current source-observation status.

Invariants:

- Every snapshot identifies its source, retrieval instant, schema version, raw-content digest, and canonical-content digest.
- A source revision cannot replace or mutate a prior snapshot.
- Withdrawal is represented by a new snapshot/fact, never deletion of history.
- Aliases cannot merge records automatically when the mapping is ambiguous.
- Parsed affected ranges retain ecosystem semantics and original source evidence.
- Severity retains metric system and version; no bare numeric “score” is canonical.

Repository: `AdvisoryRecordRepository`.

## Value objects

- `AdvisorySource`, `ExternalAdvisoryId`, `AdvisoryAlias`
- `AffectedPackage`, `AffectedRange`, `FixedRange`
- `SeverityVector`, `WeaknessClassification`
- `SourceAttribution`, `RetrievalReceipt`
- `AdvisorySnapshotRef`, `ContentDigest`

## Domain services and policies

- `AdvisoryNormalizer`: source record to canonical candidate snapshot.
- `AliasResolutionPolicy`: determines exact, ambiguous, or unrelated mappings.
- `SnapshotAcceptancePolicy`: schema, size, timestamp, and attribution checks.

## Commands and queries

- `AcquireAdvisory`, `RecordAdvisorySnapshot`, `RecordWithdrawal`, `ResolveAlias`
- `GetAdvisorySnapshot`, `FindSnapshotsByAlias`, `ListChangedAdvisories`

## Domain events

- `AdvisorySnapshotted` — carries `AdvisoryRecordId` and snapshot digest.
- `AdvisoryWithdrawalObserved` — carries record ID and withdrawing snapshot.
- `AdvisoryAliasResolved` — carries record ID and resolution evidence.
- `AdvisoryNormalizationFailed` — carries record ID and non-sensitive reason code.

All are immutable, past-tense, and carry the aggregate ID.

## Published language

Publishes `AdvisorySnapshotDescriptor` and the events above. Raw OSV, HackerOne, NVD, or other source types are translated by source-specific anti-corruption layers.

## External adapters

- Initial: OSV read-only acquisition with snapshot caching and update/withdrawal handling.
- Optional: source-pinned HackerOne mock/read-only adapter.
- Every adapter is rate-limited, schema/size validated, provenance tagged, and incapable of external writes in the MVP.

## Security and privacy

Remote content is untrusted. Private-report support is deferred; before it exists, retention, access, PII, exploit-material, and log-redaction policy must be defined.
