//! Immutable fixture acquisition separated from hermetic evaluation.

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::OrganizationId;
use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use url::Url;

const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REDIRECTS: usize = 10;

/// P00-selected benchmark case.
pub const FIXTURE_ID: &str = "CVE-2022-29217";
/// Immutable CVE-Bench repository revision selected in P00.
pub const CVE_BENCH_COMMIT: &str = "47abc2b2b522f4d8afd07296d2a35042d8639f1d";
/// Immutable vulnerable `PyJWT` revision selected in P00.
pub const PYJWT_BASE_COMMIT: &str = "24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc";

/// One immutable remotely acquired object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedSource {
    /// HTTPS source URL, without mutable query selectors.
    pub url: String,
    /// Exact immutable revision, when the source is a repository archive.
    pub revision: Option<String>,
    /// Expected digest of downloaded bytes.
    pub digest: Sha256Digest,
    /// Upstream signature decision.
    pub signature: SignatureEvidence,
}

/// Explicit upstream-signature status; absence is never confused with verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureEvidence {
    /// Upstream publishes no signature for this object under the approved policy.
    NotPublished {
        /// Named, versioned policy exception proving absence was evaluated.
        policy_exception: String,
    },
    /// Signature was verified against an immutable trusted key reference.
    Verified {
        /// Trust-store key reference.
        key_id: String,
        /// Digest of detached signature bytes.
        signature_digest: Sha256Digest,
    },
}

/// One fully locked dependency artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyLock {
    /// Normalized package name.
    pub name: String,
    /// Exact non-range version.
    pub version: String,
    /// Registry wheel/source digest.
    pub artifact_digest: Sha256Digest,
    /// Exact platform tag.
    pub platform: String,
}

/// Explicit license gate result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LicenseDecision {
    /// Named policy approved all fixture and dependency licenses.
    Approved {
        /// Immutable policy revision.
        policy_revision: String,
        /// Sorted SPDX expressions observed in the bundle.
        spdx_expressions: BTreeSet<String>,
    },
    /// At least one license is rejected or unresolved.
    Denied,
}

/// Explicit vulnerability gate result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VulnerabilityDecision {
    /// Scan completed under a pinned policy and database snapshot.
    Passed {
        /// Vulnerability policy revision.
        policy_revision: String,
        /// Content digest of the vulnerability database snapshot.
        database_digest: Sha256Digest,
    },
    /// Scan failed or found a policy-blocking vulnerability outside the fixture target.
    Failed,
}

/// Content-addressed SBOM evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbomDescriptor {
    /// SPDX or `CycloneDX` media type.
    pub media_type: String,
    /// Digest of canonical SBOM bytes.
    pub digest: Sha256Digest,
    /// Number of described components.
    pub component_count: u32,
}

/// Complete immutable acquisition intent for the selected fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureAcquisitionManifest {
    /// Tenant boundary.
    pub organization_id: OrganizationId,
    /// Must be [`FIXTURE_ID`].
    pub fixture_id: String,
    /// Pinned CVE-Bench source object.
    pub benchmark: PinnedSource,
    /// Pinned `PyJWT` source object.
    pub target: PinnedSource,
    /// Independently hashed dataset record.
    pub dataset_record: PinnedSource,
    /// Independently hashed hidden test patch.
    pub test_patch: PinnedSource,
    /// Independently hashed gold patch.
    pub gold_patch: PinnedSource,
    /// Independently hashed environment recipe.
    pub environment_recipe: PinnedSource,
    /// Immutable `CPython` toolchain artifact.
    pub toolchain: PinnedSource,
    /// Immutable base-image manifest digest.
    pub base_image_manifest_digest: Sha256Digest,
    /// Fully resolved wheel/source dependency locks.
    pub dependencies: Vec<DependencyLock>,
    /// License policy result.
    pub license: LicenseDecision,
    /// Vulnerability policy result.
    pub vulnerability: VulnerabilityDecision,
    /// Complete SBOM descriptor.
    pub sbom: SbomDescriptor,
    /// Exact acquisition proxy host allowlist.
    pub allowed_hosts: BTreeSet<String>,
    /// Digest binding the canonical manifest supplied by the trusted application.
    pub manifest_digest: Sha256Digest,
}

impl FixtureAcquisitionManifest {
    /// Validates fixture identity, immutable pins, checksums, locks, and policy gates.
    ///
    /// # Errors
    /// Rejects mutable/unverified inputs, malformed allowlists, missing locks/SBOM,
    /// or failed license/vulnerability decisions.
    pub fn validate(&self) -> Result<(), AcquisitionError> {
        if self.fixture_id != FIXTURE_ID
            || self.benchmark.revision.as_deref() != Some(CVE_BENCH_COMMIT)
            || self.target.revision.as_deref() != Some(PYJWT_BASE_COMMIT)
        {
            return Err(AcquisitionError::FixturePinMismatch);
        }
        let sources = self.sources();
        if sources.iter().any(|source| {
            !safe_https_url(&source.url)
                || source.revision.as_ref().is_some_and(|revision| !full_commit(revision))
                || matches!(&source.signature, SignatureEvidence::NotPublished { policy_exception } if !approved_signature_exception(policy_exception))
                || matches!(&source.signature, SignatureEvidence::Verified { key_id, .. } if key_id.trim().is_empty())
        }) {
            return Err(AcquisitionError::MutableOrUnverifiedSource);
        }
        if self.allowed_hosts.is_empty()
            || self.allowed_hosts.iter().any(|host| !safe_host(host))
            || sources.iter().any(|source| {
                host_of(&source.url).is_none_or(|host| !self.allowed_hosts.contains(&host))
            })
        {
            return Err(AcquisitionError::HostNotAllowed);
        }
        let mut dependency_keys = BTreeSet::new();
        if self.dependencies.is_empty()
            || self.dependencies.iter().any(|dependency| {
                !valid_package_name(&dependency.name)
                    || !strict_version(&dependency.version)
                    || !valid_platform(&dependency.platform)
                    || !dependency_keys.insert((
                        dependency.name.to_ascii_lowercase().replace('_', "-"),
                        dependency.platform.to_ascii_lowercase(),
                    ))
            })
        {
            return Err(AcquisitionError::MutableDependency);
        }
        match &self.license {
            LicenseDecision::Approved {
                policy_revision,
                spdx_expressions,
            } if !policy_revision.trim().is_empty() && !spdx_expressions.is_empty() => {}
            _ => return Err(AcquisitionError::LicenseDenied),
        }
        if !matches!(&self.vulnerability, VulnerabilityDecision::Passed { policy_revision, .. } if !policy_revision.trim().is_empty())
        {
            return Err(AcquisitionError::VulnerabilityDenied);
        }
        if !matches!(
            self.sbom.media_type.as_str(),
            "application/spdx+json" | "application/vnd.cyclonedx+json"
        ) || self.sbom.component_count == 0
        {
            return Err(AcquisitionError::InvalidSbom);
        }
        if self.manifest_digest != self.canonical_digest() {
            return Err(AcquisitionError::ManifestDigestMismatch);
        }
        Ok(())
    }

    /// Computes a domain-separated digest over every security-relevant field.
    #[must_use]
    pub fn canonical_digest(&self) -> Sha256Digest {
        let mut bytes = b"cauterizer.fixture-acquisition-manifest.v1\0".to_vec();
        append(&mut bytes, self.organization_id.as_str());
        append(&mut bytes, &self.fixture_id);
        for source in self.sources() {
            append(&mut bytes, &source.url);
            append(&mut bytes, source.revision.as_deref().unwrap_or(""));
            bytes.extend_from_slice(source.digest.as_bytes());
            match &source.signature {
                SignatureEvidence::NotPublished { policy_exception } => {
                    append(&mut bytes, "not-published");
                    append(&mut bytes, policy_exception);
                }
                SignatureEvidence::Verified {
                    key_id,
                    signature_digest,
                } => {
                    append(&mut bytes, "verified");
                    append(&mut bytes, key_id);
                    bytes.extend_from_slice(signature_digest.as_bytes());
                }
            }
        }
        bytes.extend_from_slice(self.base_image_manifest_digest.as_bytes());
        let mut dependencies = self.dependencies.iter().collect::<Vec<_>>();
        dependencies.sort_by(|left, right| {
            (
                left.name.to_ascii_lowercase().replace('_', "-"),
                left.platform.to_ascii_lowercase(),
                left.version.as_str(),
                left.artifact_digest.as_bytes(),
            )
                .cmp(&(
                    right.name.to_ascii_lowercase().replace('_', "-"),
                    right.platform.to_ascii_lowercase(),
                    right.version.as_str(),
                    right.artifact_digest.as_bytes(),
                ))
        });
        for dependency in dependencies {
            append(&mut bytes, &dependency.name);
            append(&mut bytes, &dependency.version);
            bytes.extend_from_slice(dependency.artifact_digest.as_bytes());
            append(&mut bytes, &dependency.platform);
        }
        match &self.license {
            LicenseDecision::Approved {
                policy_revision,
                spdx_expressions,
            } => {
                append(&mut bytes, policy_revision);
                for expression in spdx_expressions {
                    append(&mut bytes, expression);
                }
            }
            LicenseDecision::Denied => append(&mut bytes, "license-denied"),
        }
        match &self.vulnerability {
            VulnerabilityDecision::Passed {
                policy_revision,
                database_digest,
            } => {
                append(&mut bytes, policy_revision);
                bytes.extend_from_slice(database_digest.as_bytes());
            }
            VulnerabilityDecision::Failed => append(&mut bytes, "vulnerability-failed"),
        }
        append(&mut bytes, &self.sbom.media_type);
        bytes.extend_from_slice(self.sbom.digest.as_bytes());
        bytes.extend_from_slice(&self.sbom.component_count.to_be_bytes());
        for host in &self.allowed_hosts {
            append(&mut bytes, host);
        }
        Sha256Digest::of_bytes(bytes)
    }

    fn sources(&self) -> [&PinnedSource; 7] {
        [
            &self.benchmark,
            &self.target,
            &self.dataset_record,
            &self.test_patch,
            &self.gold_patch,
            &self.environment_recipe,
            &self.toolchain,
        ]
    }
}

/// Narrow acquisition-plane fetch request; evaluation never receives this authority.
pub struct AcquisitionFetch<'a> {
    /// Tenant boundary.
    pub organization_id: &'a OrganizationId,
    /// Initial approved HTTPS URL.
    pub url: &'a str,
    /// Expected immutable bytes digest.
    pub expected_digest: Sha256Digest,
    /// Exact redirect/proxy host allowlist.
    pub allowed_hosts: &'a BTreeSet<String>,
    /// Hard response-body limit enforced by the acquisition proxy and rechecked by the service.
    pub max_bytes: u64,
}

/// Bytes returned from quarantine with the complete redirect chain.
pub struct QuarantinedDownload {
    /// Initial URL plus every observed redirect destination, in order.
    pub resolved_urls: Vec<String>,
    /// Downloaded bytes, still untrusted until verified.
    pub bytes: Vec<u8>,
    /// Content length observed before body decoding.
    pub declared_content_length: u64,
    /// Every network peer used by the proxy, including redirects.
    pub resolved_peer_ips: Vec<IpAddr>,
    /// Authenticated TLS peer identity recorded by the restricted proxy.
    pub tls_peer_identity: String,
    /// Immutable acquisition-proxy policy revision.
    pub proxy_policy_revision: String,
    /// Whether the expected upstream signature was verified by trusted acquisition code.
    pub signature_verified: bool,
}

/// Acquisition-only network port.
pub trait AcquisitionNetworkPort {
    /// Fetches through an allowlisted acquisition proxy into quarantine.
    ///
    /// # Errors
    /// Returns a stable transport failure without exposing credentials or provider details.
    fn fetch(&self, request: AcquisitionFetch<'_>) -> Result<QuarantinedDownload, NetworkError>;
}

/// Verified immutable bundle descriptor safe for network-denied evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAcquisitionBundle {
    /// Tenant boundary.
    pub organization_id: OrganizationId,
    /// Selected fixture.
    pub fixture_id: String,
    /// Trusted manifest digest.
    pub manifest_digest: Sha256Digest,
    /// Verified source object digests.
    pub source_digests: Vec<Sha256Digest>,
    /// SBOM digest.
    pub sbom_digest: Sha256Digest,
    /// Digest of download provenance and verified bytes for every source.
    pub integrity_evidence_digest: Sha256Digest,
    /// Explicitly network-denied evaluation contract.
    pub evaluation_network_denied: bool,
}

/// Executes acquisition verification without granting network authority to evaluation.
pub struct AcquisitionService<N> {
    network: N,
}
impl<N: AcquisitionNetworkPort> AcquisitionService<N> {
    /// Creates a service over a restricted acquisition network adapter.
    #[must_use]
    pub const fn new(network: N) -> Self {
        Self { network }
    }

    /// Fetches and verifies every pinned object before publishing a bundle descriptor.
    ///
    /// # Errors
    /// Rejects manifest policy, redirect escapes, transport failure, or checksum mismatch.
    pub fn acquire(
        &self,
        manifest: &FixtureAcquisitionManifest,
    ) -> Result<VerifiedAcquisitionBundle, AcquisitionError> {
        manifest.validate()?;
        let mut source_digests = Vec::with_capacity(7);
        let mut evidence = b"cauterizer.acquisition-evidence.v1\0".to_vec();
        evidence.extend_from_slice(manifest.manifest_digest.as_bytes());
        for source in manifest.sources() {
            let download = self
                .network
                .fetch(AcquisitionFetch {
                    organization_id: &manifest.organization_id,
                    url: &source.url,
                    expected_digest: source.digest,
                    allowed_hosts: &manifest.allowed_hosts,
                    max_bytes: MAX_SOURCE_BYTES,
                })
                .map_err(|_| AcquisitionError::NetworkUnavailable)?;
            if download.resolved_urls.is_empty()
                || download.resolved_urls.len() > MAX_REDIRECTS
                || download.resolved_urls.first().map(String::as_str) != Some(source.url.as_str())
                || download.resolved_urls.iter().any(|url| {
                    !safe_https_url(url)
                        || host_of(url).is_none_or(|host| !manifest.allowed_hosts.contains(&host))
                })
            {
                return Err(AcquisitionError::RedirectEscape);
            }
            if download.declared_content_length > MAX_SOURCE_BYTES
                || u64::try_from(download.bytes.len()).unwrap_or(u64::MAX) > MAX_SOURCE_BYTES
                || download.declared_content_length
                    != u64::try_from(download.bytes.len()).unwrap_or(u64::MAX)
            {
                return Err(AcquisitionError::DownloadTooLarge);
            }
            if download.resolved_peer_ips.len() != download.resolved_urls.len()
                || download.resolved_peer_ips.iter().any(|ip| !public_ip(*ip))
                || download.tls_peer_identity.trim().is_empty()
                || download.proxy_policy_revision.trim().is_empty()
            {
                return Err(AcquisitionError::InvalidTransportProvenance);
            }
            if matches!(source.signature, SignatureEvidence::Verified { .. })
                && !download.signature_verified
            {
                return Err(AcquisitionError::SignatureVerificationFailed);
            }
            if Sha256Digest::of_bytes(&download.bytes) != source.digest {
                return Err(AcquisitionError::ChecksumMismatch);
            }
            evidence.extend_from_slice(source.digest.as_bytes());
            for url in &download.resolved_urls {
                append(&mut evidence, url);
            }
            for ip in &download.resolved_peer_ips {
                append(&mut evidence, &ip.to_string());
            }
            append(&mut evidence, &download.tls_peer_identity);
            append(&mut evidence, &download.proxy_policy_revision);
            evidence.push(u8::from(download.signature_verified));
            source_digests.push(source.digest);
        }
        Ok(VerifiedAcquisitionBundle {
            organization_id: manifest.organization_id.clone(),
            fixture_id: manifest.fixture_id.clone(),
            manifest_digest: manifest.manifest_digest,
            source_digests,
            sbom_digest: manifest.sbom.digest,
            integrity_evidence_digest: Sha256Digest::of_bytes(evidence),
            evaluation_network_denied: true,
        })
    }
}

fn full_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn safe_host(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && !matches!(lower.as_str(), "localhost" | "metadata.google.internal")
        && !lower
            .rsplit_once('.')
            .is_some_and(|(_, suffix)| matches!(suffix, "localhost" | "local" | "internal"))
        && value.parse::<IpAddr>().is_err()
}
fn safe_https_url(value: &str) -> bool {
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    let authority = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    let raw_lower = value.to_ascii_lowercase();
    parsed.scheme() == "https"
        && !authority.contains(':')
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.port().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.host_str().is_some_and(safe_host)
        && !raw_lower.contains("%2e")
        && !raw_lower.contains("%2f")
        && !parsed.path_segments().is_none_or(|segments| {
            segments.into_iter().any(|segment| {
                let lower = segment.to_ascii_lowercase();
                segment == ".." || lower == "%2e%2e" || lower.contains("%2f")
            })
        })
}
fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
fn strict_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && !value.starts_with(['.', '-', '_', '+'])
        && !value.ends_with(['.', '-', '_', '+'])
}
fn valid_platform(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168))
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.segments()[0] & 0xfe00 == 0xfc00
                || ip.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}
fn host_of(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    if parsed.scheme() != "https" || parsed.port().is_some() {
        return None;
    }
    parsed
        .host_str()
        .filter(|host| safe_host(host))
        .map(str::to_ascii_lowercase)
}
fn approved_signature_exception(value: &str) -> bool {
    matches!(
        value,
        "upstream-does-not-publish-signatures:v1"
            | "p00-approved-public-fixture-signature-exception:v1"
    )
}
fn append(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}

/// Stable acquisition failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionError {
    /// Selected case or repository pins differ from P00.
    FixturePinMismatch,
    /// Source is mutable, unsafe, or lacks explicit signature policy.
    MutableOrUnverifiedSource,
    /// Source or redirect destination is outside the allowlist.
    HostNotAllowed,
    /// Dependency version is absent or expressed as a range.
    MutableDependency,
    /// License policy did not approve the bundle.
    LicenseDenied,
    /// Vulnerability policy did not approve the bundle.
    VulnerabilityDenied,
    /// SBOM is absent or unsupported.
    InvalidSbom,
    /// Restricted acquisition transport failed.
    NetworkUnavailable,
    /// Redirect chain escaped the approved hosts.
    RedirectEscape,
    /// Downloaded bytes differ from their immutable expected digest.
    ChecksumMismatch,
    /// The response body exceeded its hard limit or disagreed with its declared length.
    DownloadTooLarge,
    /// Proxy, TLS, or resolved-peer evidence was absent or unsafe.
    InvalidTransportProvenance,
    /// A source requiring a signature did not carry trusted verification evidence.
    SignatureVerificationFailed,
    /// Supplied manifest digest does not bind the canonical manifest.
    ManifestDigestMismatch,
}
impl fmt::Display for AcquisitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AcquisitionError {}

/// Stable restricted-network transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkError;
impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("acquisition_network_unavailable")
    }
}
impl std::error::Error for NetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Mode {
        Valid,
        Tampered,
        RedirectEscape,
        Oversized,
        PrivatePeer,
        SignatureMissing,
    }
    struct MockNetwork(Mode);
    impl AcquisitionNetworkPort for MockNetwork {
        fn fetch(
            &self,
            request: AcquisitionFetch<'_>,
        ) -> Result<QuarantinedDownload, NetworkError> {
            let resolved = match self.0 {
                Mode::RedirectEscape => "https://evil.example/payload".into(),
                _ => request.url.into(),
            };
            let bytes = match self.0 {
                Mode::Tampered => b"tampered".to_vec(),
                _ => b"verified".to_vec(),
            };
            Ok(QuarantinedDownload {
                resolved_urls: vec![resolved],
                declared_content_length: if matches!(self.0, Mode::Oversized) {
                    MAX_SOURCE_BYTES + 1
                } else {
                    bytes.len() as u64
                },
                resolved_peer_ips: vec![if matches!(self.0, Mode::PrivatePeer) {
                    "127.0.0.1".parse().unwrap()
                } else {
                    "203.0.113.10".parse().unwrap()
                }],
                tls_peer_identity: "fixtures.example".into(),
                proxy_policy_revision: "acquisition-proxy-v1".into(),
                signature_verified: !matches!(self.0, Mode::SignatureMissing),
                bytes,
            })
        }
    }
    fn source(url: &str, revision: Option<&str>) -> PinnedSource {
        PinnedSource {
            url: url.into(),
            revision: revision.map(Into::into),
            digest: Sha256Digest::of_bytes(b"verified"),
            signature: SignatureEvidence::NotPublished {
                policy_exception: "upstream-does-not-publish-signatures:v1".into(),
            },
        }
    }
    fn manifest() -> FixtureAcquisitionManifest {
        let host = "fixtures.example";
        let mut manifest = FixtureAcquisitionManifest {
            organization_id: OrganizationId::new("00000000").unwrap(),
            fixture_id: FIXTURE_ID.into(),
            benchmark: source(
                &format!("https://{host}/cve-bench.tar"),
                Some(CVE_BENCH_COMMIT),
            ),
            target: source(
                &format!("https://{host}/pyjwt.tar"),
                Some(PYJWT_BASE_COMMIT),
            ),
            dataset_record: source(&format!("https://{host}/record.json"), None),
            test_patch: source(&format!("https://{host}/test.patch"), None),
            gold_patch: source(&format!("https://{host}/gold.patch"), None),
            environment_recipe: source(&format!("https://{host}/environment.json"), None),
            toolchain: source(
                &format!("https://{host}/cpython.tar"),
                Some("1111111111111111111111111111111111111111"),
            ),
            base_image_manifest_digest: Sha256Digest::of_bytes(b"base-image"),
            dependencies: vec![DependencyLock {
                name: "cryptography".into(),
                version: "42.0.0".into(),
                artifact_digest: Sha256Digest::of_bytes(b"wheel"),
                platform: "cp311-manylinux_x86_64".into(),
            }],
            license: LicenseDecision::Approved {
                policy_revision: "license-policy-v1".into(),
                spdx_expressions: BTreeSet::from(["MIT".into(), "Apache-2.0".into()]),
            },
            vulnerability: VulnerabilityDecision::Passed {
                policy_revision: "vulnerability-policy-v1".into(),
                database_digest: Sha256Digest::of_bytes(b"vulnerability-db"),
            },
            sbom: SbomDescriptor {
                media_type: "application/spdx+json".into(),
                digest: Sha256Digest::of_bytes(b"sbom"),
                component_count: 2,
            },
            allowed_hosts: BTreeSet::from([host.into()]),
            manifest_digest: Sha256Digest::of_bytes([]),
        };
        manifest.manifest_digest = manifest.canonical_digest();
        manifest
    }

    #[test]
    fn exact_pinned_fixture_acquires_observably_network_denied_bundle() {
        let manifest = manifest();
        let result = AcquisitionService::new(MockNetwork(Mode::Valid))
            .acquire(&manifest)
            .unwrap();
        assert_eq!(result.fixture_id, FIXTURE_ID);
        assert_eq!(result.source_digests.len(), 7);
        assert!(result.evaluation_network_denied);
    }
    #[test]
    fn mutable_fixture_dependency_and_unverified_signature_fail_before_fetch() {
        let mut value = manifest();
        value.target.revision = Some("main".into());
        assert_eq!(value.validate(), Err(AcquisitionError::FixturePinMismatch));
        let mut value = manifest();
        value.dependencies[0].version = ">=42".into();
        assert_eq!(value.validate(), Err(AcquisitionError::MutableDependency));
        let mut value = manifest();
        value.gold_patch.signature = SignatureEvidence::NotPublished {
            policy_exception: String::new(),
        };
        assert_eq!(
            value.validate(),
            Err(AcquisitionError::MutableOrUnverifiedSource)
        );
    }
    #[test]
    fn checksum_substitution_and_redirect_escape_fail_closed() {
        let manifest = manifest();
        assert_eq!(
            AcquisitionService::new(MockNetwork(Mode::Tampered)).acquire(&manifest),
            Err(AcquisitionError::ChecksumMismatch)
        );
        assert_eq!(
            AcquisitionService::new(MockNetwork(Mode::RedirectEscape)).acquire(&manifest),
            Err(AcquisitionError::RedirectEscape)
        );
    }
    #[test]
    fn canonical_manifest_and_url_boundary_fail_closed() {
        let mut value = manifest();
        value.dependencies[0].version = "42.0.1".into();
        assert_eq!(
            value.validate(),
            Err(AcquisitionError::ManifestDigestMismatch)
        );
        for url in [
            "https://127.0.0.1/object",
            "https://[::1]/object",
            "https://user@fixtures.example/object",
            "https://fixtures.example:443/object",
            "https://fixtures.example/object?ref=main",
            "https://fixtures.example/%2e%2e/secret",
            "http://fixtures.example/object",
        ] {
            assert!(!safe_https_url(url), "accepted unsafe URL: {url}");
        }
    }
    #[test]
    fn dependency_set_is_unique_strict_and_canonical() {
        let mut value = manifest();
        value.dependencies.push(DependencyLock {
            name: "Cryptography".into(),
            version: "42.0.1".into(),
            artifact_digest: Sha256Digest::of_bytes(b"other-wheel"),
            platform: "cp311-manylinux_x86_64".into(),
        });
        value.manifest_digest = value.canonical_digest();
        assert_eq!(value.validate(), Err(AcquisitionError::MutableDependency));

        let mut left = manifest();
        left.dependencies.push(DependencyLock {
            name: "pyjwt".into(),
            version: "2.4.0".into(),
            artifact_digest: Sha256Digest::of_bytes(b"pyjwt-wheel"),
            platform: "py3-none-any".into(),
        });
        let mut right = left.clone();
        right.dependencies.reverse();
        assert_eq!(left.canonical_digest(), right.canonical_digest());

        left.dependencies[0].version = "https://registry.example/pkg.whl".into();
        left.manifest_digest = left.canonical_digest();
        assert_eq!(left.validate(), Err(AcquisitionError::MutableDependency));
    }
    #[test]
    fn bounded_download_and_transport_provenance_fail_closed() {
        let manifest = manifest();
        assert_eq!(
            AcquisitionService::new(MockNetwork(Mode::Oversized)).acquire(&manifest),
            Err(AcquisitionError::DownloadTooLarge)
        );
        assert_eq!(
            AcquisitionService::new(MockNetwork(Mode::PrivatePeer)).acquire(&manifest),
            Err(AcquisitionError::InvalidTransportProvenance)
        );
    }
    #[test]
    fn verified_signature_requires_transport_evidence() {
        let mut value = manifest();
        value.gold_patch.signature = SignatureEvidence::Verified {
            key_id: "fixture-signing-key-v1".into(),
            signature_digest: Sha256Digest::of_bytes(b"signature"),
        };
        value.manifest_digest = value.canonical_digest();
        assert_eq!(
            AcquisitionService::new(MockNetwork(Mode::SignatureMissing)).acquire(&value),
            Err(AcquisitionError::SignatureVerificationFailed)
        );
    }
    #[test]
    fn denied_license_vulnerability_and_missing_sbom_block_publication() {
        let mut value = manifest();
        value.license = LicenseDecision::Denied;
        assert_eq!(value.validate(), Err(AcquisitionError::LicenseDenied));
        let mut value = manifest();
        value.vulnerability = VulnerabilityDecision::Failed;
        assert_eq!(value.validate(), Err(AcquisitionError::VulnerabilityDenied));
        let mut value = manifest();
        value.sbom.component_count = 0;
        assert_eq!(value.validate(), Err(AcquisitionError::InvalidSbom));
    }
}
