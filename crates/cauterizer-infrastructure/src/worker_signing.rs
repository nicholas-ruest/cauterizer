//! Wires Isolated Execution's worker-protocol
//! [`RequestSignatureVerifier`] port through the P12
//! [`SignerPort`]/[`KeyLifecyclePort`] key-lifecycle boundary, instead of any
//! private-key handling inside that bounded context.

use crate::crypto::{
    KeyLifecycleError, KeyLifecyclePort, KeySignature, SignerPort, SigningAlgorithm, TrustDomain,
};
use cauterizer_isolated_execution::application::authentication::{
    RequestSignatureVerifier, SignatureDecision,
};
use cauterizer_isolated_execution::contracts::SignatureAlgorithmV1;
use cauterizer_syntax::identifiers::ContextQualifiedId;

/// Adapts a P12 key-lifecycle port into Isolated Execution's worker-protocol
/// verifier port for one trust domain.
///
/// Isolated Execution never sees key material or lifecycle operations: it
/// only calls [`RequestSignatureVerifier::verify`], which this adapter
/// answers by looking up the signer's non-secret trust metadata and
/// delegating the cryptographic check to the port. Every failure mode the
/// port can report (unknown, revoked, destroyed, expired, not-yet-valid)
/// collapses to [`SignatureDecision::UnknownSigner`]: the worker protocol has
/// no vocabulary for *why* a signer is untrusted, only that it is.
pub struct WorkerProtocolSignatureVerifier<P> {
    port: P,
    trust_domain: TrustDomain,
}

impl<P> WorkerProtocolSignatureVerifier<P> {
    /// Binds a key-lifecycle port to the trust domain worker-protocol
    /// signing keys are provisioned under.
    #[must_use]
    pub const fn new(port: P, trust_domain: TrustDomain) -> Self {
        Self { port, trust_domain }
    }
}

impl<P: SignerPort + KeyLifecyclePort> RequestSignatureVerifier for WorkerProtocolSignatureVerifier<P> {
    fn verify(
        &self,
        key_id: &ContextQualifiedId,
        algorithm: SignatureAlgorithmV1,
        canonical_payload: &[u8],
        signature: &str,
    ) -> SignatureDecision {
        if algorithm != SignatureAlgorithmV1::Ed25519 {
            return SignatureDecision::InvalidSignature;
        }
        let metadata = match self.port.metadata(key_id) {
            Ok(metadata) => metadata,
            Err(KeyLifecycleError::UnknownKey) => return SignatureDecision::UnknownSigner,
            Err(_) => return SignatureDecision::Unavailable,
        };
        if metadata.trust_domain != self.trust_domain {
            return SignatureDecision::UnknownSigner;
        }
        let Some(signature_bytes) = decode_signature_hex(signature) else {
            return SignatureDecision::InvalidSignature;
        };
        let key_signature = KeySignature {
            key_id: key_id.clone(),
            trust_domain: metadata.trust_domain,
            algorithm: SigningAlgorithm::Ed25519,
            signature: signature_bytes,
            trust_label: "untrusted-development",
        };
        match self.port.verify(canonical_payload, &key_signature) {
            Ok(()) => SignatureDecision::Valid,
            Err(KeyLifecycleError::InvalidSignature) => SignatureDecision::InvalidSignature,
            Err(
                KeyLifecycleError::UnknownKey
                | KeyLifecycleError::KeyRevoked
                | KeyLifecycleError::KeyDestroyed
                | KeyLifecycleError::KeyExpired
                | KeyLifecycleError::KeyNotYetValid,
            ) => SignatureDecision::UnknownSigner,
            Err(_) => SignatureDecision::Unavailable,
        }
    }
}

/// Encodes a raw Ed25519 signature as lowercase hex for the worker
/// protocol's string signature field.
#[must_use]
pub fn encode_signature_hex(signature: &[u8; 64]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(128);
    for byte in signature {
        write!(hex, "{byte:02x}").expect("writing to String is infallible");
    }
    hex
}

/// Decodes a lowercase-hex worker-protocol signature. Returns `None` for any
/// malformed input rather than panicking.
fn decode_signature_hex(signature: &str) -> Option<[u8; 64]> {
    let bytes = signature.as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    let mut decoded = [0u8; 64];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = (decode_hex_nibble(pair[0])? << 4) | decode_hex_nibble(pair[1])?;
    }
    Some(decoded)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{GenerateKeyRequest, UntrustedDevelopmentKeyLifecycle};
    use cauterizer_isolated_execution::application::authentication::{
        AuthenticationError, SignedRequestAuthenticator,
    };
    use cauterizer_isolated_execution::contracts::{
        EnvironmentEnvelopeV1, ExecutionRequestV1, JobClassV1, NetworkPolicyV1, PROTOCOL_VERSION,
        ResourceLimitsV1, SignedExecutionRequestV1, WorkerCapabilityV1,
    };
    use cauterizer_syntax::digest::Sha256Digest;
    use cauterizer_syntax::identifiers::OrganizationId;
    use cauterizer_syntax::schema::SchemaVersion;
    use cauterizer_syntax::time::UtcInstant;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    fn trust_domain() -> TrustDomain {
        TrustDomain::new("isolated-execution-worker")
    }

    fn adapter() -> UntrustedDevelopmentKeyLifecycle {
        let directory = tempfile::tempdir().unwrap();
        UntrustedDevelopmentKeyLifecycle::open(directory.keep()).unwrap()
    }

    fn generate(adapter: &UntrustedDevelopmentKeyLifecycle) -> ContextQualifiedId {
        adapter
            .generate(GenerateKeyRequest {
                trust_domain: trust_domain(),
                not_before: UtcInstant::parse("2020-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2100-01-01T00:00:00Z").unwrap(),
            })
            .unwrap()
            .key_id
    }

    #[test]
    fn unknown_key_id_is_reported_as_unknown_signer() {
        let verifier = WorkerProtocolSignatureVerifier::new(adapter(), trust_domain());
        let unknown = ContextQualifiedId::new("signing-key", "0000000000000000").unwrap();
        assert_eq!(
            verifier.verify(&unknown, SignatureAlgorithmV1::Ed25519, b"payload", &"0".repeat(128)),
            SignatureDecision::UnknownSigner
        );
    }

    #[test]
    fn valid_lifecycle_signature_verifies_and_tamper_is_rejected() {
        let port = adapter();
        let key_id = generate(&port);
        let signature = port.sign(&key_id, b"payload").unwrap();
        let encoded = encode_signature_hex(&signature.signature);
        let verifier = WorkerProtocolSignatureVerifier::new(port, trust_domain());

        assert_eq!(
            verifier.verify(&key_id, SignatureAlgorithmV1::Ed25519, b"payload", &encoded),
            SignatureDecision::Valid
        );
        assert_eq!(
            verifier.verify(&key_id, SignatureAlgorithmV1::Ed25519, b"tampered", &encoded),
            SignatureDecision::InvalidSignature
        );
        assert_eq!(
            verifier.verify(&key_id, SignatureAlgorithmV1::Ed25519, b"payload", "not-hex"),
            SignatureDecision::InvalidSignature
        );
    }

    #[test]
    fn key_from_a_different_trust_domain_is_never_accepted() {
        let port = adapter();
        let key_id = generate(&port);
        let signature = port.sign(&key_id, b"payload").unwrap();
        let encoded = encode_signature_hex(&signature.signature);
        let verifier =
            WorkerProtocolSignatureVerifier::new(port, TrustDomain::new("some-other-domain"));
        assert_eq!(
            verifier.verify(&key_id, SignatureAlgorithmV1::Ed25519, b"payload", &encoded),
            SignatureDecision::UnknownSigner
        );
    }

    #[test]
    fn revoked_key_fails_closed_as_unknown_signer_on_the_next_check() {
        let port = adapter();
        let key_id = generate(&port);
        let signature = port.sign(&key_id, b"payload").unwrap();
        let encoded = encode_signature_hex(&signature.signature);
        port.revoke(&key_id, "compromise-drill").unwrap();
        let verifier = WorkerProtocolSignatureVerifier::new(port, trust_domain());
        assert_eq!(
            verifier.verify(&key_id, SignatureAlgorithmV1::Ed25519, b"payload", &encoded),
            SignatureDecision::UnknownSigner
        );
    }

    fn worker_request() -> ExecutionRequestV1 {
        ExecutionRequestV1 {
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
            expires_at: UtcInstant::parse("2100-01-01T00:00:00Z").unwrap(),
        }
    }

    /// Reconstructs the same RFC 8785 canonical bytes Isolated Execution's
    /// private `authentication::canonical_payload` computes. JCS output
    /// depends only on JSON content (keys are sorted), not on which Rust
    /// struct produced it, so an equivalently shaped JSON object canonicalizes
    /// identically without needing that function exported.
    fn canonical_payload_for_signing(
        request: &ExecutionRequestV1,
        signing_key_id: &ContextQualifiedId,
    ) -> Vec<u8> {
        let value = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request": serde_json::to_value(request).unwrap(),
            "signing_key_id": signing_key_id,
            "signature_algorithm": "ed25519",
        });
        serde_jcs::to_vec(&value).unwrap()
    }

    #[test]
    fn isolated_execution_admits_a_p12_signed_request_and_fails_closed_after_revocation() {
        let port = adapter();
        let key_id = generate(&port);
        let request = worker_request();
        let payload = canonical_payload_for_signing(&request, &key_id);
        let signature = port.sign(&key_id, &payload).unwrap();
        let envelope = SignedExecutionRequestV1 {
            protocol_version: SchemaVersion::parse(PROTOCOL_VERSION).unwrap(),
            request: request.clone(),
            signing_key_id: key_id.clone(),
            signature_algorithm: SignatureAlgorithmV1::Ed25519,
            signature: encode_signature_hex(&signature.signature),
        };

        // The verifier borrows the port rather than owning it, so the test
        // keeps its own handle to revoke through afterward. Interior
        // mutability (the port is `&self`-only) makes both uses sound.
        let verifier = WorkerProtocolSignatureVerifier::new(&port, trust_domain());
        let authenticator = SignedRequestAuthenticator::new(verifier);

        let calls = Cell::new(0);
        let result =
            authenticator.authenticate_then(envelope.clone(), |_| calls.set(calls.get() + 1));
        assert_eq!(result, Ok(()));
        assert_eq!(calls.get(), 1);

        // Prove the P12 port is genuinely load-bearing: revoking the key
        // through the lifecycle port (not through isolated-execution at all)
        // makes an identical, previously valid envelope fail closed on the
        // very next check, through isolated-execution's own unmodified
        // `authenticate_then`.
        port.revoke(&key_id, "compromise-drill").unwrap();
        let calls_after_revoke = Cell::new(0);
        let result_after_revoke = authenticator.authenticate_then(envelope, |_| {
            calls_after_revoke.set(calls_after_revoke.get() + 1);
        });
        assert_eq!(result_after_revoke, Err(AuthenticationError::UnknownSigner));
        assert_eq!(calls_after_revoke.get(), 0);
    }
}
