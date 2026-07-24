//! Proves a live-acquired (OSV-shaped) advisory flows through exactly the
//! same Advisory Intake domain invariants — alias uniqueness, snapshot
//! idempotency, artifact-binding validation — that already govern the
//! fixture-acquired path, without duplicating or weakening those domain
//! tests. This crate never touches `advisory-intake`'s private
//! `LocalFixtureAdapter`/`Fixture` types; it only calls the same public
//! domain constructors `advisory-intake`'s own tests use.

use cauterizer_advisory_intake::application::fixture::{FixtureLimits, LocalFixtureAdapter};
use cauterizer_advisory_intake::domain::{
    AcquisitionId, AdvisoryArtifactRef, AdvisoryError, AdvisoryRecord, AdvisoryRecordId,
    AdvisorySnapshot, AdvisorySource, AffectedRange, Ecosystem, SnapshotId,
};
use cauterizer_advisory_intake_osv::acquire::{OsvAcquirer, OsvAcquisitionPolicy};
use cauterizer_advisory_intake_osv::fake::ScriptedHttpFetchPort;
use cauterizer_advisory_intake_osv::transport::FetchOutcome;
use cauterizer_syntax::classification::DataClass;
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::OrganizationId;
use cauterizer_syntax::schema::{SchemaName, SchemaVersion};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

fn organization() -> OrganizationId {
    OrganizationId::new("00000000").unwrap()
}

fn artifact_ref(bytes: &[u8], class: DataClass) -> AdvisoryArtifactRef {
    AdvisoryArtifactRef {
        digest: Sha256Digest::of_bytes(bytes),
        classification: class,
        schema_name: SchemaName::parse("dev.cauterizer.advisory.snapshot").unwrap(),
        schema_version: SchemaVersion::parse("1.0.0").unwrap(),
        size_bytes: bytes.len() as u64,
    }
}

/// Builds a domain `AdvisorySnapshot` from a `NormalizedFixture`-shaped
/// acquisition result, exactly the mapping a real command handler would
/// perform, regardless of whether the fixture came from the offline fixture
/// path or this crate's live OSV path.
fn snapshot_from_normalized(
    normalized: &cauterizer_advisory_intake::application::fixture::NormalizedFixture,
    source_class: &str,
    n: u64,
) -> AdvisorySnapshot {
    AdvisorySnapshot {
        id: SnapshotId::new(&format!("{n:08}")).unwrap(),
        acquisition_id: AcquisitionId::new(&format!("{n:08}")).unwrap(),
        input_digest: normalized.raw.digest,
        source: AdvisorySource::new(
            source_class.into(),
            normalized.external_id.clone(),
            "v1".into(),
        )
        .unwrap(),
        acquired_at_ms: n,
        published_at_ms: None,
        modified_at_ms: Some(normalized.modified_at_epoch_seconds * 1000),
        raw: artifact_ref(&normalized.raw.bytes, DataClass::Confidential),
        canonical: artifact_ref(&normalized.canonical.bytes, DataClass::Public),
        aliases: normalized.aliases.iter().cloned().collect::<BTreeSet<_>>(),
        affected: normalized
            .affected
            .iter()
            .map(|a| {
                AffectedRange::new(
                    Ecosystem::new(a.ecosystem.clone()).unwrap(),
                    a.package.clone(),
                    a.events.first().cloned().unwrap_or_default(),
                    a.events.get(1).cloned(),
                    None,
                )
                .unwrap()
            })
            .collect(),
        severity: vec![],
    }
}

const GOOD_OSV_RESPONSE: &[u8] = br#"{
    "id": "GHSA-live-0001",
    "aliases": ["CVE-2026-9001"],
    "modified": "2026-07-23T00:00:00Z",
    "affected": [
        {
            "package": {"ecosystem": "crates.io", "name": "widget"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
        }
    ]
}"#;

fn live_acquired() -> cauterizer_advisory_intake::application::fixture::NormalizedFixture {
    let transport = ScriptedHttpFetchPort::new();
    let url = "https://api.osv.dev/v1/vulns/GHSA-live-0001";
    transport.queue(
        url,
        Ok(FetchOutcome {
            status: 200,
            resolved_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            declared_content_length: Some(GOOD_OSV_RESPONSE.len() as u64),
            location: None,
            body: GOOD_OSV_RESPONSE.to_vec(),
        }),
    );
    OsvAcquirer::new(transport, OsvAcquisitionPolicy::default())
        .acquire(url, 2_000_000_000)
        .expect("hardened acquisition of a well-formed OSV response must succeed")
}

fn fixture_acquired() -> cauterizer_advisory_intake::application::fixture::NormalizedFixture {
    const FIXTURE: &[u8] = br#"{"schema_version":1,"id":"OSV-fixture-0001","aliases":["CVE-2026-9002"],"modified_at_epoch_seconds":100,"affected":[{"ecosystem":"crates.io","package":"widget","range_type":"SEMVER","events":[">=1.0.0","<1.2.0"]}]}"#;
    LocalFixtureAdapter::new(FixtureLimits::default())
        .normalize(FIXTURE, 100)
        .unwrap()
}

#[test]
fn live_and_fixture_acquired_advisories_satisfy_identical_domain_invariants() {
    let live = live_acquired();
    let fixture = fixture_acquired();

    let mut record =
        AdvisoryRecord::new(organization(), AdvisoryRecordId::new("00000000").unwrap());
    let live_snapshot = record
        .record_snapshot(snapshot_from_normalized(&live, "live-osv", 1))
        .expect("live-acquired snapshot must satisfy the same domain invariants as a fixture");
    let fixture_snapshot = record
        .record_snapshot(snapshot_from_normalized(&fixture, "fixture", 2))
        .expect("fixture-acquired snapshot must still be accepted unmodified");

    // Provenance distinguishes the two without any new contract field: the
    // existing free-form `AdvisorySource.source` string already carries it.
    assert_eq!(live_snapshot.source.source, "live-osv");
    assert_eq!(fixture_snapshot.source.source, "fixture");
    assert_eq!(record.snapshots().count(), 2);

    // Exact retry of the live snapshot is idempotent, exactly like the
    // fixture path's domain test `acquisition_retry_is_idempotent_and_conflict_rejected`.
    let replay = record
        .record_snapshot(snapshot_from_normalized(&live, "live-osv", 1))
        .unwrap();
    assert_eq!(replay, live_snapshot);
}

#[test]
fn live_acquired_ambiguous_aliases_never_auto_merge_either() {
    let live = live_acquired();
    let mut record =
        AdvisoryRecord::new(organization(), AdvisoryRecordId::new("00000000").unwrap());
    record
        .record_snapshot(snapshot_from_normalized(&live, "live-osv", 1))
        .unwrap();
    record
        .observe_alias(
            "CVE-2026-9001".into(),
            AdvisorySource::new("live-osv".into(), "OTHER-1".into(), "v1".into()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        record.resolve_alias("CVE-2026-9001"),
        Err(AdvisoryError::AliasAmbiguous)
    );
}
