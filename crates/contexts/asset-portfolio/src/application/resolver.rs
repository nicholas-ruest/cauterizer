//! Provider-neutral target resolver and hardened recorded-fixture adapter.

use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::OrganizationId;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Immutable target-resolution request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceResolutionRequest {
    /// Owning tenant.
    pub organization_id: OrganizationId,
    /// Strict HTTPS locator.
    pub locator: String,
    /// Exact immutable revision.
    pub revision: String,
}
/// Digest-bound resolution result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceResolutionReceipt {
    /// Same tenant as the request.
    pub organization_id: OrganizationId,
    /// Final validated locator.
    pub final_locator: String,
    /// Exact provider revision.
    pub revision: String,
    /// Acquired source digest.
    pub source_digest: Sha256Digest,
    /// Validated redirect chain.
    pub redirects: Vec<String>,
}
/// Network acquisition boundary; domains never resolve URLs.
pub trait TargetResolver {
    /// Resolves an approved locator without returning provider types.
    ///
    /// # Errors
    /// Denies malformed, unapproved, mutable, redirected, or missing input.
    fn resolve(
        &self,
        request: &SourceResolutionRequest,
    ) -> Result<SourceResolutionReceipt, ResolutionError>;
}
/// Recorded provider response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureRoute {
    /// Redirect response.
    Redirect(String),
    /// Immutable resolution response.
    Resolved {
        /// Exact provider revision.
        revision: String,
        /// Digest of the acquired source.
        source_digest: Sha256Digest,
    },
}
/// Fixture resolver applying destination policy at every redirect.
#[derive(Clone, Debug)]
pub struct HardenedFixtureResolver {
    allowed_hosts: BTreeSet<String>,
    routes: BTreeMap<String, FixtureRoute>,
}
impl HardenedFixtureResolver {
    /// Builds a fail-closed fixture resolver.
    ///
    /// # Errors
    /// Rejects empty/unsafe allowlists and invalid route destinations.
    pub fn new(
        hosts: impl IntoIterator<Item = String>,
        routes: impl IntoIterator<Item = (String, FixtureRoute)>,
    ) -> Result<Self, ResolutionError> {
        let allowed_hosts = BTreeSet::from_iter(hosts);
        if allowed_hosts.is_empty() || allowed_hosts.iter().any(|h| validate_host(h).is_err()) {
            return Err(ResolutionError::DestinationDenied);
        }
        let routes = BTreeMap::from_iter(routes);
        for (source, route) in &routes {
            validate_locator(source, &allowed_hosts)?;
            if let FixtureRoute::Redirect(target) = route {
                validate_locator(target, &allowed_hosts)?;
            }
        }
        Ok(Self {
            allowed_hosts,
            routes,
        })
    }
}
impl TargetResolver for HardenedFixtureResolver {
    fn resolve(
        &self,
        request: &SourceResolutionRequest,
    ) -> Result<SourceResolutionReceipt, ResolutionError> {
        if !(40..=64).contains(&request.revision.len())
            || !request
                .revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ResolutionError::InvalidRevision);
        }
        validate_locator(&request.locator, &self.allowed_hosts)?;
        let mut current = request.locator.clone();
        let mut redirects = Vec::new();
        let mut visited = BTreeSet::from([current.clone()]);
        loop {
            match self.routes.get(&current).ok_or(ResolutionError::NotFound)? {
                FixtureRoute::Redirect(target) => {
                    if redirects.len() >= 5 {
                        return Err(ResolutionError::RedirectLimit);
                    }
                    if !visited.insert(target.clone()) {
                        return Err(ResolutionError::RedirectLoop);
                    }
                    validate_locator(target, &self.allowed_hosts)?;
                    redirects.push(target.clone());
                    current.clone_from(target);
                }
                FixtureRoute::Resolved {
                    revision,
                    source_digest,
                } => {
                    if revision != &request.revision {
                        return Err(ResolutionError::RevisionSubstitution);
                    }
                    return Ok(SourceResolutionReceipt {
                        organization_id: request.organization_id.clone(),
                        final_locator: current,
                        revision: revision.clone(),
                        source_digest: *source_digest,
                        redirects,
                    });
                }
            }
        }
    }
}
fn validate_locator(locator: &str, allowed: &BTreeSet<String>) -> Result<(), ResolutionError> {
    if locator.is_empty()
        || locator.len() > 2048
        || locator.trim() != locator
        || locator.bytes().any(|b| b.is_ascii_control())
    {
        return Err(ResolutionError::InvalidLocator);
    }
    let rest = locator
        .strip_prefix("https://")
        .ok_or(ResolutionError::HttpsRequired)?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains(['@', '?', '#']) {
        return Err(ResolutionError::InvalidLocator);
    }
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') || port != "443" {
            return Err(ResolutionError::DestinationDenied);
        }
        host
    } else {
        authority
    };
    validate_host(host)?;
    if !allowed.contains(host) {
        return Err(ResolutionError::DestinationDenied);
    }
    let lower = path.to_ascii_lowercase();
    if path.contains(['\\', '?', '#'])
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
        || path.split('/').any(|s| matches!(s, "." | ".."))
    {
        return Err(ResolutionError::InvalidLocator);
    }
    Ok(())
}
fn validate_host(host: &str) -> Result<(), ResolutionError> {
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
        return Err(ResolutionError::DestinationDenied);
    }
    Ok(())
}
/// Stable resolver failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    /// Locator syntax is ambiguous or unsafe.
    InvalidLocator,
    /// Only HTTPS acquisition is permitted.
    HttpsRequired,
    /// Host, port, IP literal, or redirect is not allowlisted.
    DestinationDenied,
    /// Revision is empty, oversized, or mutable syntax.
    InvalidRevision,
    /// No recorded fixture response exists.
    NotFound,
    /// Redirect chain exceeded its fixed bound.
    RedirectLimit,
    /// Redirect chain repeated a destination.
    RedirectLoop,
    /// Provider returned a different immutable revision.
    RevisionSubstitution,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(url: &str) -> SourceResolutionRequest {
        SourceResolutionRequest {
            organization_id: OrganizationId::new("00000000").unwrap(),
            locator: url.into(),
            revision: "24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc".into(),
        }
    }
    #[test]
    fn resolves_safe_redirect() {
        let a = "https://github.com/a/b";
        let b = "https://github.com/a/b.git";
        let d = Sha256Digest::of_bytes("source");
        let r = HardenedFixtureResolver::new(
            ["github.com".into()],
            [
                (a.into(), FixtureRoute::Redirect(b.into())),
                (
                    b.into(),
                    FixtureRoute::Resolved {
                        revision: req(a).revision,
                        source_digest: d,
                    },
                ),
            ],
        )
        .unwrap();
        let receipt = r.resolve(&req(a)).unwrap();
        assert_eq!(receipt.source_digest, d);
        assert_eq!(
            receipt.organization_id,
            OrganizationId::new("00000000").unwrap()
        );
    }
    #[test]
    fn rejects_ssrf_and_locator_confusion() {
        let allowed = BTreeSet::from(["github.com".into()]);
        for u in [
            "http://github.com/a",
            "https://user@github.com/a",
            "https://github.com:444/a",
            "https://github.com/a/../b",
            "https://github.com/a/%2e%2e/b",
            "https://github.com/a?x=1",
        ] {
            assert!(validate_locator(u, &allowed).is_err(), "accepted {u}");
        }
        for h in [
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "localhost",
            "x.local",
            "metadata.google.internal",
        ] {
            assert!(validate_host(h).is_err(), "accepted {h}");
        }
        let mut mutable = req("https://github.com/a");
        mutable.revision = "main".into();
        let resolver = HardenedFixtureResolver::new(
            ["github.com".into()],
            [(
                mutable.locator.clone(),
                FixtureRoute::Resolved {
                    revision: mutable.revision.clone(),
                    source_digest: Sha256Digest::of_bytes("source"),
                },
            )],
        )
        .unwrap();
        assert_eq!(
            resolver.resolve(&mutable),
            Err(ResolutionError::InvalidRevision)
        );
    }
    #[test]
    fn rejects_redirect_substitution_and_loops() {
        assert!(matches!(
            HardenedFixtureResolver::new(
                ["github.com".into()],
                [(
                    "https://github.com/a".into(),
                    FixtureRoute::Redirect("https://evil.example/a".into())
                )]
            ),
            Err(ResolutionError::DestinationDenied)
        ));
        let a = "https://github.com/a";
        let b = "https://github.com/b";
        let r = HardenedFixtureResolver::new(
            ["github.com".into()],
            [
                (a.into(), FixtureRoute::Redirect(b.into())),
                (b.into(), FixtureRoute::Redirect(a.into())),
            ],
        )
        .unwrap();
        assert_eq!(r.resolve(&req(a)), Err(ResolutionError::RedirectLoop));
    }
}
