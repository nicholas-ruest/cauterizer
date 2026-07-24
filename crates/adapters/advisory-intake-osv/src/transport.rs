//! Network transport boundary. Domain and application code never call an
//! HTTP client directly; every acquisition goes through this narrow port so
//! tests can inject a fake transport and no test in this workspace performs
//! real network I/O.

use std::net::IpAddr;

/// One untrusted HTTP response, exactly as observed on the wire.
///
/// Implementations MUST NOT follow redirects themselves: [`OsvAcquirer`]
/// (see `crate::acquire`) re-validates every redirect destination against
/// policy before issuing the next request, so a transport that silently
/// follows redirects would bypass the SSRF defense entirely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchOutcome {
    /// HTTP status code.
    pub status: u16,
    /// The IP address the transport actually connected to for this request.
    ///
    /// This is captured post-DNS-resolution so callers can reject a
    /// connection to a private/link-local/loopback/metadata address even
    /// when the hostname itself looked allowlisted (DNS rebinding defense).
    pub resolved_ip: IpAddr,
    /// The `Content-Length` header, when the peer declared one.
    pub declared_content_length: Option<u64>,
    /// The `Location` header, present only for 3xx responses.
    pub location: Option<String>,
    /// Exact response body bytes actually received.
    pub body: Vec<u8>,
}

/// Stable transport-layer failure. Never carries provider-specific detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The peer did not respond, refused the connection, or TLS failed.
    Unavailable,
    /// The fixed per-attempt deadline elapsed.
    Timeout,
}

/// Narrow HTTP transport port. Real implementations perform network I/O;
/// test implementations are scripted and deterministic.
pub trait HttpFetchPort {
    /// Performs exactly one HTTP GET request. Implementations must not
    /// retry or follow redirects internally; both are policy decisions
    /// owned by the caller.
    ///
    /// # Errors
    /// Returns [`TransportError`] for connection/timeout failure only;
    /// HTTP-level status codes (including redirects and error statuses) are
    /// returned as a normal `Ok(FetchOutcome)`.
    fn get(&self, url: &str) -> Result<FetchOutcome, TransportError>;
}
