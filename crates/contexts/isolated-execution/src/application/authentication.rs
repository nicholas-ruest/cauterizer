//! Fail-closed authentication for declarative worker protocol requests.

use crate::contracts::{ExecutionRequestV1, SignatureAlgorithmV1, SignedExecutionRequestV1};
use cauterizer_syntax::identifiers::ContextQualifiedId;
use serde::Serialize;
use std::fmt;

/// Trust-store-backed detached signature verification port.
pub trait RequestSignatureVerifier {
    /// Verifies `signature` over the exact canonical payload for `key_id`.
    ///
    /// Implementations must reject unknown, revoked, expired, or wrong-purpose keys.
    fn verify(
        &self,
        key_id: &ContextQualifiedId,
        algorithm: SignatureAlgorithmV1,
        canonical_payload: &[u8],
        signature: &str,
    ) -> SignatureDecision;
}

/// Closed verifier decision; dependency errors fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureDecision {
    /// Key, algorithm, payload, and signature are valid for execution admission.
    Valid,
    /// Key is unknown or not authorized for worker requests.
    UnknownSigner,
    /// Detached signature does not authenticate the payload.
    InvalidSignature,
    /// Trust service is unavailable.
    Unavailable,
}

/// Authenticated request ready for ordinary admission validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedExecutionRequest {
    /// Complete authenticated request payload.
    pub request: ExecutionRequestV1,
    /// Signer identity whose execution-admission authority was verified.
    pub signing_key_id: ContextQualifiedId,
}

/// Verifies signed envelopes before invoking any state-changing operation.
pub struct SignedRequestAuthenticator<V> {
    verifier: V,
}
impl<V: RequestSignatureVerifier> SignedRequestAuthenticator<V> {
    /// Creates an authentication boundary around a verifier port.
    #[must_use]
    pub const fn new(verifier: V) -> Self {
        Self { verifier }
    }

    /// Authenticates, validates, and then passes a request to the supplied mutation.
    ///
    /// # Errors
    ///
    /// Rejects unsupported protocol/algorithm, canonicalization failure, unknown signer,
    /// invalid signature, verifier outage, or request admission validation failure.
    pub fn authenticate_then<T>(
        &self,
        envelope: SignedExecutionRequestV1,
        mutation: impl FnOnce(AuthenticatedExecutionRequest) -> T,
    ) -> Result<T, AuthenticationError> {
        if envelope.protocol_version.to_string() != crate::contracts::PROTOCOL_VERSION {
            return Err(AuthenticationError::UnsupportedProtocol);
        }
        let payload = canonical_payload(&envelope)?;
        match self.verifier.verify(
            &envelope.signing_key_id,
            envelope.signature_algorithm,
            &payload,
            &envelope.signature,
        ) {
            SignatureDecision::Valid => {}
            SignatureDecision::UnknownSigner => return Err(AuthenticationError::UnknownSigner),
            SignatureDecision::InvalidSignature => {
                return Err(AuthenticationError::InvalidSignature);
            }
            SignatureDecision::Unavailable => return Err(AuthenticationError::VerifierUnavailable),
        }
        envelope
            .request
            .validate()
            .map_err(|_| AuthenticationError::InvalidRequest)?;
        Ok(mutation(AuthenticatedExecutionRequest {
            request: envelope.request,
            signing_key_id: envelope.signing_key_id,
        }))
    }
}

#[derive(Serialize)]
struct SignedPayload<'a> {
    protocol_version: &'a cauterizer_syntax::schema::SchemaVersion,
    request: &'a ExecutionRequestV1,
    signing_key_id: &'a ContextQualifiedId,
    signature_algorithm: SignatureAlgorithmV1,
}

fn canonical_payload(envelope: &SignedExecutionRequestV1) -> Result<Vec<u8>, AuthenticationError> {
    serde_jcs::to_vec(&SignedPayload {
        protocol_version: &envelope.protocol_version,
        request: &envelope.request,
        signing_key_id: &envelope.signing_key_id,
        signature_algorithm: envelope.signature_algorithm,
    })
    .map_err(|_| AuthenticationError::Canonicalization)
}

/// Stable authentication failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    /// Protocol major/minor/profile is unsupported.
    UnsupportedProtocol,
    /// Payload could not be represented in canonical form.
    Canonicalization,
    /// Signing key is unknown or lacks request-signing authority.
    UnknownSigner,
    /// Detached signature does not bind this payload.
    InvalidSignature,
    /// Trust service was unavailable; admission fails closed.
    VerifierUnavailable,
    /// Authenticated request fails declarative admission validation.
    InvalidRequest,
}
impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for AuthenticationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        EnvironmentEnvelopeV1, JobClassV1, NetworkPolicyV1, PROTOCOL_VERSION, ResourceLimitsV1,
        WorkerCapabilityV1,
    };
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::OrganizationId;
    use cauterizer_syntax::schema::SchemaVersion;
    use cauterizer_syntax::time::UtcInstant;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    struct DeterministicVerifier {
        key: ContextQualifiedId,
    }
    impl RequestSignatureVerifier for DeterministicVerifier {
        fn verify(
            &self,
            key_id: &ContextQualifiedId,
            algorithm: SignatureAlgorithmV1,
            payload: &[u8],
            signature: &str,
        ) -> SignatureDecision {
            if key_id != &self.key {
                return SignatureDecision::UnknownSigner;
            }
            if algorithm != SignatureAlgorithmV1::Ed25519 {
                return SignatureDecision::InvalidSignature;
            }
            let expected = Sha256Digest::of_bytes(payload).to_tagged_hex();
            if signature == expected {
                SignatureDecision::Valid
            } else {
                SignatureDecision::InvalidSignature
            }
        }
    }
    fn unsigned() -> SignedExecutionRequestV1 {
        SignedExecutionRequestV1 {
            protocol_version: SchemaVersion::parse(PROTOCOL_VERSION).unwrap(),
            request: ExecutionRequestV1 {
                organization_id: OrganizationId::new("00000000").unwrap(),
                lease_id: ContextQualifiedId::new("execution-lease", "00000000").unwrap(),
                worker_identity: ContextQualifiedId::new("worker", "00000000").unwrap(),
                job_class: JobClassV1::Verifier,
                environment: EnvironmentEnvelopeV1 {
                    image_digest: Sha256Digest::of_bytes(b"image"),
                    environment_digest: Sha256Digest::of_bytes(b"environment"),
                    sandbox_profile: "qualified-v1".into(),
                    conformant_backend: true,
                },
                argv: vec!["/workspace/test".into()],
                environment_variables: BTreeMap::new(),
                input_artifacts: vec![],
                capabilities: vec![WorkerCapabilityV1::WriteObservation],
                network_policy: NetworkPolicyV1::EgressDenied,
                resources: ResourceLimitsV1 {
                    cpu_millis: 1,
                    wall_millis: 1,
                    memory_bytes: 1,
                    disk_bytes: 1,
                    process_count: 1,
                    output_bytes: 1,
                },
                expires_at: UtcInstant::parse("2026-07-23T01:00:00Z").unwrap(),
            },
            signing_key_id: ContextQualifiedId::new("key", "00000000").unwrap(),
            signature_algorithm: SignatureAlgorithmV1::Ed25519,
            signature: String::new(),
        }
    }
    fn signed() -> SignedExecutionRequestV1 {
        let mut value = unsigned();
        value.signature =
            Sha256Digest::of_bytes(canonical_payload(&value).unwrap()).to_tagged_hex();
        value
    }
    fn authenticator() -> SignedRequestAuthenticator<DeterministicVerifier> {
        SignedRequestAuthenticator::new(DeterministicVerifier {
            key: ContextQualifiedId::new("key", "00000000").unwrap(),
        })
    }
    #[test]
    fn valid_canonical_signature_allows_exactly_one_mutation() {
        let calls = Cell::new(0);
        let result = authenticator().authenticate_then(signed(), |_| calls.set(calls.get() + 1));
        assert_eq!(result, Ok(()));
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn tamper_wrong_signer_and_invalid_signature_never_mutate() {
        let mut cases = Vec::new();
        let mut tampered = signed();
        tampered.request.argv.push("changed".into());
        cases.push((tampered, AuthenticationError::InvalidSignature));
        let mut signer = signed();
        signer.signing_key_id = ContextQualifiedId::new("key", "00000001").unwrap();
        cases.push((signer, AuthenticationError::UnknownSigner));
        let mut signature = signed();
        signature.signature = "invalid".into();
        cases.push((signature, AuthenticationError::InvalidSignature));
        for (envelope, expected) in cases {
            let calls = Cell::new(0);
            assert_eq!(
                authenticator().authenticate_then(envelope, |_| calls.set(1)),
                Err(expected)
            );
            assert_eq!(calls.get(), 0);
        }
    }
}
