//! Hardened live OSV.dev acquisition: destination allowlisting, same-origin
//! redirect handling, DNS-rebinding-resistant IP checks, a pre-parse byte
//! limit, and a fixed (non-adaptive) retry policy. This module owns every
//! SSRF-relevant decision; [`crate::transport::HttpFetchPort`] implementations
//! must not follow redirects or retry on their own.

use crate::transport::{FetchOutcome, HttpFetchPort};
use cauterizer_advisory_intake::application::fixture::NormalizedFixture;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The real production OSV.dev API host. Only host in the default policy.
pub const DEFAULT_ALLOWED_HOST: &str = "api.osv.dev";

/// Immutable acquisition policy. Every bound is fixed at construction; none
/// is derived from prior request outcomes, so it cannot become a timing or
/// state oracle.
#[derive(Clone, Debug)]
pub struct OsvAcquisitionPolicy {
    /// Exact allowed destination hosts. Redirects may not cross this set,
    /// and additionally may never cross the *origin* host of the request
    /// that produced them (see [`OsvAcquisitionReason::CrossOriginRedirect`]).
    pub allowed_hosts: BTreeSet<String>,
    /// Hard response-body limit enforced before any JSON parse is attempted.
    pub max_response_bytes: usize,
    /// Maximum redirect hops before the chain is rejected.
    pub max_redirects: u8,
    /// Fixed number of attempts per hop. No backoff, jitter, or adaptive
    /// delay is computed between attempts.
    pub attempts: u8,
}
impl Default for OsvAcquisitionPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: BTreeSet::from([DEFAULT_ALLOWED_HOST.to_owned()]),
            max_response_bytes: 1_048_576,
            max_redirects: 3,
            attempts: 3,
        }
    }
}

/// Stable, payload-safe acquisition failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsvAcquisitionReason {
    /// Locator syntax is ambiguous, oversized, or unsafe.
    InvalidLocator,
    /// Only HTTPS acquisition is permitted.
    HttpsRequired,
    /// Host, port, or IP literal is not allowlisted.
    DestinationDenied,
    /// A redirect attempted to leave the origin host of the original request.
    CrossOriginRedirect,
    /// The redirect chain exceeded its fixed bound.
    RedirectLimitExceeded,
    /// The transport's actually-connected peer address is link-local,
    /// private, loopback, or otherwise non-public, even though the
    /// hostname passed allowlist validation (DNS rebinding defense).
    PrivateOrLinkLocalAddress,
    /// Declared or actual response size exceeded the configured limit.
    ResponseTooLarge,
    /// Every fixed-retry attempt failed to reach the peer.
    TransportUnavailable,
    /// The peer returned a non-2xx, non-3xx status.
    UnexpectedStatus,
    /// The response was not valid JSON, or a 3xx response had no `Location`.
    MalformedResponse,
    /// Source `modified`/`published` time was invalid or implausibly future.
    InvalidTimestamp,
    /// A bounded string or collection exceeded its limit.
    ReferenceLimitExceeded,
    /// A duplicate alias made the source representation ambiguous.
    AmbiguousAlias,
    /// Ecosystem or range semantics were missing or unknown.
    UnsupportedRangeSemantics,
}

/// Fetches and normalizes advisories from the real OSV.dev API behind a
/// hardened, allowlist-enforcing transport boundary.
pub struct OsvAcquirer<T> {
    transport: T,
    policy: OsvAcquisitionPolicy,
}
impl<T: HttpFetchPort> OsvAcquirer<T> {
    /// Creates an acquirer bound to a transport and an explicit policy.
    #[must_use]
    pub const fn new(transport: T, policy: OsvAcquisitionPolicy) -> Self {
        Self { transport, policy }
    }
    /// Fetches exactly one OSV advisory and normalizes it into the same
    /// provider-neutral shape the fixture acquisition path produces.
    ///
    /// # Errors
    /// Returns a stable reason. No quarantine or artifact-store call is ever
    /// made by this crate, so a rejected fetch leaves no partial state.
    pub fn acquire(
        &self,
        url: &str,
        retrieved_at_epoch_seconds: u64,
    ) -> Result<NormalizedFixture, OsvAcquisitionReason> {
        let body = self.fetch_validated(url)?;
        crate::osv::normalize(
            &body,
            retrieved_at_epoch_seconds,
            &crate::osv::OsvLimits::default(),
        )
    }
    fn fetch_validated(&self, url: &str) -> Result<Vec<u8>, OsvAcquisitionReason> {
        let origin_host = validate_destination(url, &self.policy.allowed_hosts)?;
        let mut current = url.to_owned();
        let mut redirects = 0u8;
        loop {
            let outcome = self.fetch_with_fixed_retries(&current)?;
            validate_resolved_address(outcome.resolved_ip)?;
            check_size(&outcome, self.policy.max_response_bytes)?;
            if (300..400).contains(&outcome.status) {
                redirects += 1;
                if redirects > self.policy.max_redirects {
                    return Err(OsvAcquisitionReason::RedirectLimitExceeded);
                }
                let location = outcome
                    .location
                    .ok_or(OsvAcquisitionReason::MalformedResponse)?;
                let target_host = validate_destination(&location, &self.policy.allowed_hosts)?;
                if target_host != origin_host {
                    return Err(OsvAcquisitionReason::CrossOriginRedirect);
                }
                current = location;
                continue;
            }
            if outcome.status != 200 {
                return Err(OsvAcquisitionReason::UnexpectedStatus);
            }
            return Ok(outcome.body);
        }
    }
    /// Performs a fixed number of attempts with no delay computed from
    /// prior failures, so retry timing cannot become a state oracle.
    fn fetch_with_fixed_retries(&self, url: &str) -> Result<FetchOutcome, OsvAcquisitionReason> {
        for _ in 0..self.policy.attempts.max(1) {
            if let Ok(outcome) = self.transport.get(url) {
                return Ok(outcome);
            }
        }
        Err(OsvAcquisitionReason::TransportUnavailable)
    }
}

fn check_size(outcome: &FetchOutcome, max_bytes: usize) -> Result<(), OsvAcquisitionReason> {
    let limit = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if outcome
        .declared_content_length
        .is_some_and(|len| len > limit)
    {
        return Err(OsvAcquisitionReason::ResponseTooLarge);
    }
    if outcome.body.len() > max_bytes {
        return Err(OsvAcquisitionReason::ResponseTooLarge);
    }
    Ok(())
}

/// Validates HTTPS-only, allowlisted, unambiguous locator syntax and
/// returns the exact validated host, mirroring the hardened idiom in
/// `asset-portfolio`'s `HardenedFixtureResolver`.
fn validate_destination(
    locator: &str,
    allowed: &BTreeSet<String>,
) -> Result<String, OsvAcquisitionReason> {
    if locator.is_empty()
        || locator.len() > 2048
        || locator.trim() != locator
        || locator.bytes().any(|b| b.is_ascii_control())
    {
        return Err(OsvAcquisitionReason::InvalidLocator);
    }
    let rest = locator
        .strip_prefix("https://")
        .ok_or(OsvAcquisitionReason::HttpsRequired)?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains(['@', '?', '#']) {
        return Err(OsvAcquisitionReason::InvalidLocator);
    }
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') || port != "443" {
            return Err(OsvAcquisitionReason::DestinationDenied);
        }
        host
    } else {
        authority
    };
    validate_host(host)?;
    if !allowed.contains(host) {
        return Err(OsvAcquisitionReason::DestinationDenied);
    }
    let lower = path.to_ascii_lowercase();
    if path.contains(['\\', '?', '#'])
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
        || path.split('/').any(|s| matches!(s, "." | ".."))
    {
        return Err(OsvAcquisitionReason::InvalidLocator);
    }
    Ok(host.to_owned())
}

fn validate_host(host: &str) -> Result<(), OsvAcquisitionReason> {
    if host.is_empty()
        || host.len() > 253
        || host != host.to_ascii_lowercase()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.rsplit('.').next() == Some("local")
        || host == "metadata.google.internal"
        || host.parse::<IpAddr>().is_ok()
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return Err(OsvAcquisitionReason::DestinationDenied);
    }
    Ok(())
}

/// Rejects a connection whose actually-resolved peer address is
/// link-local, RFC1918 private, loopback, unspecified, IPv6 unique-local,
/// or IPv6 link-local — regardless of whether the hostname passed the
/// allowlist check. This is the DNS-rebinding defense: DNS for an
/// allowlisted-looking hostname can still resolve to an internal address
/// between validation and connection, so the connected address itself must
/// be checked too.
fn validate_resolved_address(ip: IpAddr) -> Result<(), OsvAcquisitionReason> {
    let denied = match ip {
        IpAddr::V4(v4) => is_denied_ipv4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| is_denied_ipv6(v6), is_denied_ipv4),
    };
    if denied {
        Err(OsvAcquisitionReason::PrivateOrLinkLocalAddress)
    } else {
        Ok(())
    }
}
fn is_denied_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_link_local() || ip.is_private() || ip.is_unspecified()
}
fn is_denied_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.segments()[0] & 0xfe00 == 0xfc00 // unique local fc00::/7
        || ip.segments()[0] & 0xffc0 == 0xfe80 // link-local fe80::/10
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::ScriptedHttpFetchPort;
    use crate::transport::TransportError;

    const PUBLIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    const GOOD_BODY: &[u8] = br#"{"id":"OSV-1","modified":"2026-07-23T00:00:00Z","affected":[]}"#;

    // These always return `Ok`, but `ScriptedHttpFetchPort::queue` requires
    // exactly the transport's `Result<FetchOutcome, TransportError>` shape.
    #[allow(clippy::unnecessary_wraps)]
    fn ok(status: u16, body: &[u8]) -> Result<FetchOutcome, TransportError> {
        Ok(FetchOutcome {
            status,
            resolved_ip: PUBLIC_IP,
            declared_content_length: Some(body.len() as u64),
            location: None,
            body: body.to_vec(),
        })
    }
    #[allow(clippy::unnecessary_wraps)]
    fn redirect(location: &str) -> Result<FetchOutcome, TransportError> {
        Ok(FetchOutcome {
            status: 302,
            resolved_ip: PUBLIC_IP,
            declared_content_length: Some(0),
            location: Some(location.into()),
            body: vec![],
        })
    }
    fn acquirer(transport: ScriptedHttpFetchPort) -> OsvAcquirer<ScriptedHttpFetchPort> {
        OsvAcquirer::new(transport, OsvAcquisitionPolicy::default())
    }

    #[test]
    fn resolves_happy_path_and_leaves_no_partial_state_on_rejection() {
        let transport = ScriptedHttpFetchPort::new();
        let url = "https://api.osv.dev/v1/vulns/OSV-1";
        transport.queue(url, ok(200, GOOD_BODY));
        let advisory = acquirer(transport).acquire(url, 2_000_000_000).unwrap();
        assert_eq!(advisory.external_id, "OSV-1");

        // A rejected fetch never even reaches the artifact-commit boundary:
        // this crate makes no `ArtifactStore` call at all, so there is
        // nothing to roll back.
        let transport = ScriptedHttpFetchPort::new();
        transport.queue(url, ok(500, b"error"));
        assert_eq!(
            acquirer(transport).acquire(url, 2_000_000_000),
            Err(OsvAcquisitionReason::UnexpectedStatus)
        );
    }

    #[test]
    fn rejects_ssrf_and_locator_confusion() {
        let allowed = BTreeSet::from(["api.osv.dev".into()]);
        for u in [
            "http://api.osv.dev/v1/vulns/OSV-1",
            "https://user@api.osv.dev/v1/vulns/OSV-1",
            "https://api.osv.dev:444/v1/vulns/OSV-1",
            "https://api.osv.dev/v1/../secret",
            "https://api.osv.dev/v1/%2e%2e/secret",
            "https://api.osv.dev/v1/vulns/OSV-1?x=1",
            "https://evil.example/v1/vulns/OSV-1",
        ] {
            assert!(validate_destination(u, &allowed).is_err(), "accepted {u}");
        }
        for h in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "::1",
            "localhost",
            "x.local",
            "metadata.google.internal",
        ] {
            assert!(validate_host(h).is_err(), "accepted {h}");
        }
    }

    #[test]
    fn rejects_cross_origin_and_over_limit_redirects() {
        let transport = ScriptedHttpFetchPort::new();
        let start = "https://api.osv.dev/v1/vulns/OSV-1";
        transport.queue(start, redirect("https://evil.example/v1/vulns/OSV-1"));
        assert_eq!(
            acquirer(transport).acquire(start, 2_000_000_000),
            Err(OsvAcquisitionReason::DestinationDenied)
        );

        // A redirect to a different, but still allowlisted, host would still
        // be rejected because it leaves the request's *origin* host.
        let two_host_policy = OsvAcquisitionPolicy {
            allowed_hosts: BTreeSet::from(["api.osv.dev".into(), "other.osv.dev".into()]),
            ..OsvAcquisitionPolicy::default()
        };
        let transport = ScriptedHttpFetchPort::new();
        transport.queue(start, redirect("https://other.osv.dev/v1/vulns/OSV-1"));
        assert_eq!(
            OsvAcquirer::new(transport, two_host_policy).acquire(start, 2_000_000_000),
            Err(OsvAcquisitionReason::CrossOriginRedirect)
        );

        let transport = ScriptedHttpFetchPort::new();
        let mut current = start.to_owned();
        for hop in 0..10 {
            let next = format!("https://api.osv.dev/v1/vulns/OSV-1?hop={hop}");
            transport.queue(&current, redirect(&next));
            current = next;
        }
        assert_eq!(
            acquirer(transport).acquire(start, 2_000_000_000),
            Err(OsvAcquisitionReason::InvalidLocator)
        );
    }

    #[test]
    fn rejects_redirect_loop_via_fixed_hop_limit() {
        let transport = ScriptedHttpFetchPort::new();
        let a = "https://api.osv.dev/v1/vulns/a";
        let b = "https://api.osv.dev/v1/vulns/b";
        for _ in 0..6 {
            transport.queue(a, redirect(b));
            transport.queue(b, redirect(a));
        }
        assert_eq!(
            acquirer(transport).acquire(a, 2_000_000_000),
            Err(OsvAcquisitionReason::RedirectLimitExceeded)
        );
    }

    #[test]
    fn rejects_dns_rebinding_to_private_and_link_local_peers() {
        let url = "https://api.osv.dev/v1/vulns/OSV-1";
        for peer in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 5, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            // IPv4-mapped IPv6 embedding a private address.
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe)),
        ] {
            let transport = ScriptedHttpFetchPort::new();
            transport.queue(
                url,
                Ok(FetchOutcome {
                    status: 200,
                    resolved_ip: peer,
                    declared_content_length: Some(GOOD_BODY.len() as u64),
                    location: None,
                    body: GOOD_BODY.to_vec(),
                }),
            );
            assert_eq!(
                acquirer(transport).acquire(url, 2_000_000_000),
                Err(OsvAcquisitionReason::PrivateOrLinkLocalAddress),
                "accepted peer {peer}"
            );
        }
    }

    #[test]
    fn rejects_oversized_response_before_parse() {
        let url = "https://api.osv.dev/v1/vulns/OSV-1";
        let policy = OsvAcquisitionPolicy {
            max_response_bytes: 4,
            ..OsvAcquisitionPolicy::default()
        };
        let transport = ScriptedHttpFetchPort::new();
        transport.queue(url, ok(200, GOOD_BODY));
        assert_eq!(
            OsvAcquirer::new(transport, policy).acquire(url, 2_000_000_000),
            Err(OsvAcquisitionReason::ResponseTooLarge)
        );

        // A lying `Content-Length` header is rejected even before the body
        // (which may be smaller) is inspected.
        let transport = ScriptedHttpFetchPort::new();
        transport.queue(
            url,
            Ok(FetchOutcome {
                status: 200,
                resolved_ip: PUBLIC_IP,
                declared_content_length: Some(10 * 1024 * 1024),
                location: None,
                body: GOOD_BODY.to_vec(),
            }),
        );
        assert_eq!(
            acquirer(transport).acquire(url, 2_000_000_000),
            Err(OsvAcquisitionReason::ResponseTooLarge)
        );
    }

    #[test]
    fn rejects_malformed_schema_without_weakening_other_checks() {
        let url = "https://api.osv.dev/v1/vulns/OSV-1";
        let transport = ScriptedHttpFetchPort::new();
        transport.queue(url, ok(200, b"not json"));
        assert_eq!(
            acquirer(transport).acquire(url, 2_000_000_000),
            Err(OsvAcquisitionReason::MalformedResponse)
        );
    }

    #[test]
    fn fixed_retry_policy_recovers_from_transient_failure_and_exhausts_deterministically() {
        let url = "https://api.osv.dev/v1/vulns/OSV-1";
        let transport = ScriptedHttpFetchPort::new();
        let observed = transport.clone();
        transport.queue(url, Err(TransportError::Timeout));
        transport.queue(url, ok(200, GOOD_BODY));
        let advisory = acquirer(transport).acquire(url, 2_000_000_000).unwrap();
        assert_eq!(advisory.external_id, "OSV-1");
        assert_eq!(observed.calls().len(), 2);

        let attempts = OsvAcquisitionPolicy::default().attempts;
        let transport = ScriptedHttpFetchPort::new();
        let observed = transport.clone();
        for _ in 0..attempts {
            transport.queue(url, Err(TransportError::Unavailable));
        }
        assert_eq!(
            acquirer(transport).acquire(url, 2_000_000_000),
            Err(OsvAcquisitionReason::TransportUnavailable)
        );
        // Exactly `attempts` requests were made: the retry policy is fixed,
        // never adaptive, and never exceeds its configured bound.
        assert_eq!(observed.calls().len(), usize::from(attempts));
    }
}
