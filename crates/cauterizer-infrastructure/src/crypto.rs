//! Cryptographic operation ports and explicitly untrusted development adapters.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use cauterizer_syntax::identifiers::{ContextQualifiedId, OrganizationId};
use cauterizer_syntax::sensitive::Sensitive;
use cauterizer_syntax::time::UtcInstant;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Fixed AES-256-GCM nonce length.
pub const NONCE_LENGTH: usize = 12;

/// Authenticated envelope ciphertext owned by a referenced key operation.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvelopeCiphertext {
    /// Non-secret key reference; raw key bytes are never returned.
    pub key_ref: ContextQualifiedId,
    /// Unique nonce supplied by the trusted caller/random source.
    pub nonce: [u8; NONCE_LENGTH],
    /// Ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EnvelopeCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeCiphertext")
            .field("key_ref", &self.key_ref)
            .field("nonce", &"[REDACTED]")
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .finish()
    }
}

/// Stable cryptographic operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Tenant/key reference did not match this adapter.
    UnauthorizedKey,
    /// Authentication failed or ciphertext was corrupted.
    AuthenticationFailed,
    /// Signature did not verify.
    InvalidSignature,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnauthorizedKey => "unauthorized_key_reference",
            Self::AuthenticationFailed => "ciphertext_authentication_failed",
            Self::InvalidSignature => "signature_invalid",
        })
    }
}
impl std::error::Error for CryptoError {}

/// Operation-only envelope encryption boundary suitable for a production KMS.
pub trait EnvelopeEncryptionPort {
    /// Encrypts exact bytes with tenant/key-bound associated data.
    ///
    /// # Errors
    ///
    /// Fails closed for an unauthorized key or encryption failure.
    fn encrypt(
        &self,
        organization_id: &OrganizationId,
        key_ref: &ContextQualifiedId,
        nonce: [u8; NONCE_LENGTH],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EnvelopeCiphertext, CryptoError>;

    /// Authenticates and decrypts exact bytes.
    ///
    /// # Errors
    ///
    /// Fails closed for tenant/key mismatch, tampering, or wrong associated data.
    fn decrypt(
        &self,
        organization_id: &OrganizationId,
        value: &EnvelopeCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Signature metadata returned without exposing private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevelopmentSignature {
    /// Non-secret signing-key reference.
    pub key_ref: ContextQualifiedId,
    /// Ed25519 signature bytes.
    pub signature: [u8; 64],
    /// Trust label that prevents production-authentication claims.
    pub trust_label: &'static str,
}

/// Operation-only signing boundary suitable for a production HSM/KMS.
pub trait SigningPort {
    /// Signs exact caller-canonicalized bytes.
    ///
    /// # Errors
    ///
    /// Fails when the key reference is not authorized for this signer.
    fn sign(
        &self,
        key_ref: &ContextQualifiedId,
        message: &[u8],
    ) -> Result<DevelopmentSignature, CryptoError>;

    /// Verifies an exact message and signature.
    ///
    /// # Errors
    ///
    /// Fails for a key mismatch or invalid signature.
    fn verify(&self, message: &[u8], signature: &DevelopmentSignature) -> Result<(), CryptoError>;
}

/// Local AES-256-GCM adapter. It is never a production KMS or key store.
pub struct UntrustedDevelopmentEnvelopeEncryption {
    organization_id: OrganizationId,
    key_ref: ContextQualifiedId,
    cipher: Aes256Gcm,
}

impl UntrustedDevelopmentEnvelopeEncryption {
    /// Creates the explicitly local adapter from test/development key bytes.
    #[must_use]
    pub fn new(
        organization_id: OrganizationId,
        key_ref: ContextQualifiedId,
        key: [u8; 32],
    ) -> Self {
        Self {
            organization_id,
            key_ref,
            cipher: Aes256Gcm::new(&key.into()),
        }
    }
}

impl EnvelopeEncryptionPort for UntrustedDevelopmentEnvelopeEncryption {
    fn encrypt(
        &self,
        organization_id: &OrganizationId,
        key_ref: &ContextQualifiedId,
        nonce: [u8; NONCE_LENGTH],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EnvelopeCiphertext, CryptoError> {
        if organization_id != &self.organization_id || key_ref != &self.key_ref {
            return Err(CryptoError::UnauthorizedKey);
        }
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(EnvelopeCiphertext {
            key_ref: key_ref.clone(),
            nonce,
            ciphertext,
        })
    }

    fn decrypt(
        &self,
        organization_id: &OrganizationId,
        value: &EnvelopeCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if organization_id != &self.organization_id || value.key_ref != self.key_ref {
            return Err(CryptoError::UnauthorizedKey);
        }
        self.cipher
            .decrypt(
                Nonce::from_slice(&value.nonce),
                Payload {
                    msg: &value.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// Local Ed25519 adapter labeled `untrusted-development` on every signature.
pub struct UntrustedDevelopmentSigner {
    key_ref: ContextQualifiedId,
    signing_key: SigningKey,
}

impl UntrustedDevelopmentSigner {
    /// Creates a development signer from local key bytes.
    #[must_use]
    pub fn new(key_ref: ContextQualifiedId, secret: [u8; 32]) -> Self {
        Self {
            key_ref,
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Returns the non-secret verification key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl SigningPort for UntrustedDevelopmentSigner {
    fn sign(
        &self,
        key_ref: &ContextQualifiedId,
        message: &[u8],
    ) -> Result<DevelopmentSignature, CryptoError> {
        if key_ref != &self.key_ref {
            return Err(CryptoError::UnauthorizedKey);
        }
        Ok(DevelopmentSignature {
            key_ref: key_ref.clone(),
            signature: self.signing_key.sign(message).to_bytes(),
            trust_label: "untrusted-development",
        })
    }

    fn verify(&self, message: &[u8], signature: &DevelopmentSignature) -> Result<(), CryptoError> {
        if signature.key_ref != self.key_ref || signature.trust_label != "untrusted-development" {
            return Err(CryptoError::UnauthorizedKey);
        }
        self.signing_key
            .verifying_key()
            .verify(message, &Signature::from_bytes(&signature.signature))
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Non-secret population tag naming which signing-key lineage a caller
/// trusts (for example, one worker protocol).
///
/// Distinct from an [`OrganizationId`]: a trust domain names a *purpose*,
/// not a tenant. Callers that need tenant scoping fold the organization into
/// the label themselves.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustDomain(String);

impl TrustDomain {
    /// Wraps an already-chosen non-secret trust-domain label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// Returns the label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Signing algorithm recorded on every trust metadata record and signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningAlgorithm {
    /// Edwards-curve digital signature over Curve25519.
    Ed25519,
}

impl SigningAlgorithm {
    /// Canonical lowercase wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }

    /// Parses the canonical lowercase wire label produced by [`Self::as_str`].
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Lifecycle state of one signing key's trust metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLifecycleState {
    /// Current signing key for its trust domain.
    Active,
    /// Superseded by rotation. Still valid for verification until its
    /// (shortened) expiry; never valid for new signatures.
    Overlap,
    /// Explicitly revoked. Fails verification immediately, regardless of
    /// time: there is no cache and no stale-acceptance window.
    Revoked,
    /// Private key material has been destroyed; unusable for sign or verify.
    Destroyed,
}

impl KeyLifecycleState {
    /// Canonical lowercase wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Overlap => "overlap",
            Self::Revoked => "revoked",
            Self::Destroyed => "destroyed",
        }
    }

    /// Parses the canonical lowercase wire label produced by [`Self::as_str`].
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "active" => Some(Self::Active),
            "overlap" => Some(Self::Overlap),
            "revoked" => Some(Self::Revoked),
            "destroyed" => Some(Self::Destroyed),
            _ => None,
        }
    }
}

/// Non-secret, versioned trust metadata for one signing key.
///
/// `metadata_version` increases every time this key's own record changes
/// (creation, rotation-into-overlap, revocation, destruction), giving each
/// key identity a versioned history independent of any other key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMetadata {
    /// Non-secret key identity.
    pub key_id: ContextQualifiedId,
    /// Purpose-scoped population this key belongs to.
    pub trust_domain: TrustDomain,
    /// Signing algorithm.
    pub algorithm: SigningAlgorithm,
    /// Earliest instant this key is valid.
    pub not_before: UtcInstant,
    /// Latest instant this key is valid (or, once rotated into overlap, the
    /// shortened overlap deadline).
    pub expires_at: UtcInstant,
    /// Current lifecycle state.
    pub state: KeyLifecycleState,
    /// Instant of revocation, if any.
    pub revoked_at: Option<UtcInstant>,
    /// Operator-supplied revocation reason, if any.
    pub revocation_reason: Option<String>,
    /// Monotonic version of this key's own trust metadata record.
    pub metadata_version: u64,
}

/// Stable key-lifecycle failure vocabulary. Every branch fails closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyLifecycleError {
    /// No key exists with the given key ID.
    UnknownKey,
    /// No key has ever been generated for the given trust domain.
    UnknownTrustDomain,
    /// The trust domain has no currently active key.
    NoActiveKey,
    /// A trust domain already has an active key; use rotation instead.
    AlreadyActive,
    /// `not_before` is not strictly earlier than `expires_at`.
    InvalidWindow,
    /// The key is not yet within its validity window.
    KeyNotYetValid,
    /// The key's validity (or overlap) window has elapsed.
    KeyExpired,
    /// The key has been explicitly revoked.
    KeyRevoked,
    /// The key's private material has been destroyed.
    KeyDestroyed,
    /// The key is not the active signer for its trust domain (for example,
    /// an overlap key may still verify but may never sign).
    NotActiveForSigning,
    /// The message, key, or trust-domain binding does not authenticate.
    InvalidSignature,
    /// The key-lifecycle boundary is unavailable; callers must fail closed.
    Unavailable,
}

impl fmt::Display for KeyLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownKey => "signing_key_unknown",
            Self::UnknownTrustDomain => "trust_domain_unknown",
            Self::NoActiveKey => "trust_domain_has_no_active_key",
            Self::AlreadyActive => "trust_domain_already_has_active_key",
            Self::InvalidWindow => "key_validity_window_invalid",
            Self::KeyNotYetValid => "signing_key_not_yet_valid",
            Self::KeyExpired => "signing_key_expired",
            Self::KeyRevoked => "signing_key_revoked",
            Self::KeyDestroyed => "signing_key_destroyed",
            Self::NotActiveForSigning => "signing_key_not_active_for_signing",
            Self::InvalidSignature => "signature_invalid",
            Self::Unavailable => "key_lifecycle_unavailable",
        })
    }
}
impl std::error::Error for KeyLifecycleError {}

/// Signature produced by a lifecycle-managed key.
///
/// Carries only public metadata plus the signature bytes; the private key
/// never appears in this type or anywhere it is formatted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySignature {
    /// Signing key identity.
    pub key_id: ContextQualifiedId,
    /// Trust domain the signing key belongs to.
    pub trust_domain: TrustDomain,
    /// Signing algorithm.
    pub algorithm: SigningAlgorithm,
    /// Raw Ed25519 signature bytes. Not secret.
    pub signature: [u8; 64],
    /// Trust label that prevents production-authentication claims.
    pub trust_label: &'static str,
}

/// Request to create the first key for a trust domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateKeyRequest {
    /// Purpose-scoped population the new key belongs to.
    pub trust_domain: TrustDomain,
    /// Earliest instant the new key is valid.
    pub not_before: UtcInstant,
    /// Latest instant the new key is valid.
    pub expires_at: UtcInstant,
}

/// Request to rotate a trust domain's active key with a bounded overlap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotateKeyRequest {
    /// Trust domain being rotated. Must already have an active key.
    pub trust_domain: TrustDomain,
    /// Instant after which the outgoing key no longer verifies.
    pub overlap_until: UtcInstant,
    /// Latest instant the newly generated key is valid.
    pub new_expires_at: UtcInstant,
}

/// Operation-only signing boundary over a lifecycle-managed key population,
/// suitable for a production HSM/KMS client to implement.
pub trait SignerPort {
    /// Signs exact caller-canonicalized bytes with the named key.
    ///
    /// # Errors
    ///
    /// Fails closed when the key is unknown, not the active signer for its
    /// trust domain, revoked, destroyed, or outside its validity window.
    fn sign(&self, key_id: &ContextQualifiedId, message: &[u8]) -> Result<KeySignature, KeyLifecycleError>;

    /// Verifies an exact message and signature.
    ///
    /// Every check is immediate against current key state: there is no
    /// cache and no TTL, so a revoked or destroyed key fails on the very
    /// next call.
    ///
    /// # Errors
    ///
    /// Fails closed for an unknown key, revoked/destroyed/expired/not-yet-valid
    /// key, or invalid signature.
    fn verify(&self, message: &[u8], signature: &KeySignature) -> Result<(), KeyLifecycleError>;
}

/// Key generation, rotation, revocation, and destruction boundary, suitable
/// for a production HSM/KMS client to implement.
pub trait KeyLifecyclePort {
    /// Creates the first key for a trust domain.
    ///
    /// # Errors
    ///
    /// Fails when the domain already has an active key or the validity
    /// window is not increasing.
    fn generate(&self, request: GenerateKeyRequest) -> Result<KeyMetadata, KeyLifecycleError>;

    /// Returns the current active key for a trust domain.
    ///
    /// # Errors
    ///
    /// Fails when the domain has no active key (including immediately after
    /// that key was revoked or destroyed) or the active key is outside its
    /// validity window.
    fn current_key(&self, trust_domain: &TrustDomain) -> Result<KeyMetadata, KeyLifecycleError>;

    /// Generates a new active key and demotes the previous active key to a
    /// verify-only overlap window.
    ///
    /// # Errors
    ///
    /// Fails when the domain has no active key to rotate from or either
    /// validity window is not increasing.
    fn rotate_with_overlap(&self, request: RotateKeyRequest) -> Result<KeyMetadata, KeyLifecycleError>;

    /// Marks a key revoked. Revocation is immediate and unconditional: the
    /// very next verification against this key fails, and a revoked active
    /// key is never silently treated as still current.
    ///
    /// # Errors
    ///
    /// Fails when the key is unknown or already destroyed.
    fn revoke(&self, key_id: &ContextQualifiedId, reason: &str) -> Result<(), KeyLifecycleError>;

    /// Erases a key's private material. Idempotent.
    ///
    /// # Errors
    ///
    /// Fails when the key is unknown.
    fn destroy(&self, key_id: &ContextQualifiedId) -> Result<(), KeyLifecycleError>;

    /// Returns the current trust metadata for a key, regardless of state.
    ///
    /// # Errors
    ///
    /// Fails when the key is unknown.
    fn metadata(&self, key_id: &ContextQualifiedId) -> Result<KeyMetadata, KeyLifecycleError>;
}

/// Deterministic time source for key-lifecycle validity checks.
///
/// A production HSM/KMS client would use its own trusted clock rather than
/// accept a caller-supplied instant; this mirrors that boundary and lets
/// tests inject a controllable one.
pub trait KeyLifecycleClock: Send + Sync {
    /// Returns the current canonical instant.
    fn now(&self) -> UtcInstant;
}

/// Deterministic, externally settable clock for downstream integration tests
/// that must observe key-lifecycle behavior at two different instants against
/// the same [`UntrustedDevelopmentKeyLifecycle`] — for example, signing
/// successfully and then confirming rejection after simulated time advances
/// past a key's expiry. [`UntrustedDevelopmentKeyLifecycle`] deliberately
/// keeps its injected clock private, so a caller outside this crate cannot
/// advance time through the adapter itself; this type is the supported way to
/// do so from a downstream crate's own tests. Never construct it outside test
/// code: production callers must use [`SystemClock`].
#[derive(Debug)]
pub struct SharedFixedClock(Mutex<UtcInstant>);

impl SharedFixedClock {
    /// Creates a clock fixed at `instant`.
    ///
    /// # Panics
    ///
    /// Panics if `instant` is not a canonical UTC instant.
    #[must_use]
    pub fn at(instant: &str) -> Self {
        Self(Mutex::new(
            UtcInstant::parse(instant).expect("caller-supplied canonical instant"),
        ))
    }

    /// Advances (or rewinds) the clock to `instant`.
    ///
    /// # Panics
    ///
    /// Panics if `instant` is not a canonical UTC instant.
    pub fn set(&self, instant: &str) {
        *self.0.lock().expect("clock lock poisoned") =
            UtcInstant::parse(instant).expect("caller-supplied canonical instant");
    }
}

impl KeyLifecycleClock for SharedFixedClock {
    fn now(&self) -> UtcInstant {
        self.0.lock().expect("clock lock poisoned").clone()
    }
}

impl<T: KeyLifecycleClock + ?Sized> KeyLifecycleClock for &T {
    fn now(&self) -> UtcInstant {
        (**self).now()
    }
}

/// Real wall-clock time source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl KeyLifecycleClock for SystemClock {
    fn now(&self) -> UtcInstant {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        millis_to_instant(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
    }
}

/// Converts Unix milliseconds to a canonical [`UtcInstant`] using the
/// proleptic Gregorian calendar (Howard Hinnant's `civil_from_days`).
fn millis_to_instant(unix_millis: i64) -> UtcInstant {
    let millis_per_day = 86_400_000i64;
    let days = unix_millis.div_euclid(millis_per_day);
    let millis_of_day = unix_millis.rem_euclid(millis_per_day);
    let (year, month, day) = civil_from_days(days);
    let hour = millis_of_day / 3_600_000;
    let minute = (millis_of_day / 60_000) % 60;
    let second = (millis_of_day / 1_000) % 60;
    let millis = millis_of_day % 1_000;
    let formatted = if millis == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        // The canonical instant forbids a trailing-zero fractional digit, so
        // a zero-padded three-digit millisecond count must be trimmed (for
        // example 500ms is the fraction "5", not "500").
        let mut fraction = format!("{millis:03}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction}Z")
    };
    UtcInstant::parse(formatted).expect("computed instant is always canonical")
}

/// Howard Hinnant's `civil_from_days`: days-since-1970-01-01 to a proleptic
/// Gregorian `(year, month, day)`. Public domain algorithm.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let era_year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * month_index + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    })
    .unwrap_or(1);
    let year = if month <= 2 { era_year + 1 } else { era_year };
    (year, month, day)
}

struct KeyRecord {
    metadata: KeyMetadata,
    secret: Option<Sensitive<[u8; 32]>>,
}
impl fmt::Debug for KeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRecord")
            .field("metadata", &self.metadata)
            .field("secret", &self.secret)
            .finish()
    }
}

#[derive(Debug, Default)]
struct AdapterState {
    keys: HashMap<ContextQualifiedId, KeyRecord>,
    current: HashMap<TrustDomain, ContextQualifiedId>,
}

/// Local file-and-memory key-lifecycle adapter. It is never a production
/// KMS/HSM: every signature it produces carries an explicit
/// `untrusted-development` [`KeySignature::trust_label`].
///
/// Private key bytes are generated per installation and written with owner-
/// only (`0600`) file permissions under a caller-selected directory outside
/// the repository. They are never logged, never persisted in domain state,
/// and never returned from any port method. Only non-secret [`KeyMetadata`]
/// is queryable.
///
/// Metadata lives in process memory for the lifetime of this adapter; a
/// restart re-provisions rather than reloads. Durable, queryable trust
/// metadata history is the separate concern of the `signing_key_trust_metadata`
/// migration and its `PostgresMetadataStore` methods.
pub struct UntrustedDevelopmentKeyLifecycle<C: KeyLifecycleClock = SystemClock> {
    root: PathBuf,
    clock: C,
    state: Mutex<AdapterState>,
}

impl UntrustedDevelopmentKeyLifecycle<SystemClock> {
    /// Opens (creating if absent) an owner-only directory as private key
    /// custody, using the real wall clock.
    ///
    /// # Errors
    ///
    /// Returns [`KeyLifecycleError::Unavailable`] if `root` is relative or
    /// cannot be created/secured.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, KeyLifecycleError> {
        Self::open_with_clock(root, SystemClock)
    }
}

impl<C: KeyLifecycleClock> UntrustedDevelopmentKeyLifecycle<C> {
    /// Opens (creating if absent) an owner-only directory as private key
    /// custody, using an injected clock.
    ///
    /// # Errors
    ///
    /// Returns [`KeyLifecycleError::Unavailable`] if `root` is relative or
    /// cannot be created/secured.
    pub fn open_with_clock(root: impl AsRef<Path>, clock: C) -> Result<Self, KeyLifecycleError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(KeyLifecycleError::Unavailable);
        }
        fs::create_dir_all(root).map_err(|_| KeyLifecycleError::Unavailable)?;
        restrict_key_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            clock,
            state: Mutex::new(AdapterState::default()),
        })
    }

    fn write_secret_file(&self, key_id: &ContextQualifiedId, secret: &[u8; 32]) -> Result<(), KeyLifecycleError> {
        let path = self.root.join(key_id.opaque());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path).map_err(|_| KeyLifecycleError::Unavailable)?;
        file.write_all(secret).map_err(|_| KeyLifecycleError::Unavailable)?;
        Ok(())
    }

    fn remove_secret_file(&self, key_id: &ContextQualifiedId) {
        let _ = fs::remove_file(self.root.join(key_id.opaque()));
    }
}

fn restrict_key_directory(root: &Path) -> Result<(), KeyLifecycleError> {
    #[cfg(unix)]
    {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|_| KeyLifecycleError::Unavailable)?;
    }
    #[cfg(not(unix))]
    {
        let _ = root;
    }
    Ok(())
}

fn generate_key_id() -> ContextQualifiedId {
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).expect("OS randomness is required to generate a signing key");
    let digest = cauterizer_syntax::digest::Sha256Digest::of_bytes(random).to_tagged_hex();
    let opaque = digest.strip_prefix("sha256:").unwrap_or(&digest);
    ContextQualifiedId::new("signing-key", opaque).expect("digest hex is always a valid opaque component")
}

fn generate_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("OS randomness is required to generate a signing key");
    secret
}

impl<C: KeyLifecycleClock> KeyLifecyclePort for UntrustedDevelopmentKeyLifecycle<C> {
    fn generate(&self, request: GenerateKeyRequest) -> Result<KeyMetadata, KeyLifecycleError> {
        if request.not_before >= request.expires_at {
            return Err(KeyLifecycleError::InvalidWindow);
        }
        let mut state = self.state.lock().expect("key lifecycle lock poisoned");
        if state.current.contains_key(&request.trust_domain) {
            return Err(KeyLifecycleError::AlreadyActive);
        }
        let key_id = generate_key_id();
        let secret = generate_secret();
        self.write_secret_file(&key_id, &secret)?;
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            trust_domain: request.trust_domain.clone(),
            algorithm: SigningAlgorithm::Ed25519,
            not_before: request.not_before,
            expires_at: request.expires_at,
            state: KeyLifecycleState::Active,
            revoked_at: None,
            revocation_reason: None,
            metadata_version: 1,
        };
        state.keys.insert(
            key_id.clone(),
            KeyRecord {
                metadata: metadata.clone(),
                secret: Some(Sensitive::new(secret)),
            },
        );
        state.current.insert(request.trust_domain, key_id);
        Ok(metadata)
    }

    fn current_key(&self, trust_domain: &TrustDomain) -> Result<KeyMetadata, KeyLifecycleError> {
        let state = self.state.lock().expect("key lifecycle lock poisoned");
        let key_id = state
            .current
            .get(trust_domain)
            .ok_or(KeyLifecycleError::NoActiveKey)?;
        let record = state.keys.get(key_id).ok_or(KeyLifecycleError::NoActiveKey)?;
        check_time_bounds(&record.metadata, &self.clock.now())?;
        Ok(record.metadata.clone())
    }

    fn rotate_with_overlap(&self, request: RotateKeyRequest) -> Result<KeyMetadata, KeyLifecycleError> {
        let now = self.clock.now();
        if now >= request.overlap_until || now >= request.new_expires_at {
            return Err(KeyLifecycleError::InvalidWindow);
        }
        let mut state = self.state.lock().expect("key lifecycle lock poisoned");
        let old_key_id = state
            .current
            .get(&request.trust_domain)
            .cloned()
            .ok_or(KeyLifecycleError::NoActiveKey)?;

        let new_key_id = generate_key_id();
        let secret = generate_secret();
        self.write_secret_file(&new_key_id, &secret)?;
        let new_metadata = KeyMetadata {
            key_id: new_key_id.clone(),
            trust_domain: request.trust_domain.clone(),
            algorithm: SigningAlgorithm::Ed25519,
            not_before: now.clone(),
            expires_at: request.new_expires_at,
            state: KeyLifecycleState::Active,
            revoked_at: None,
            revocation_reason: None,
            metadata_version: 1,
        };
        state.keys.insert(
            new_key_id.clone(),
            KeyRecord {
                metadata: new_metadata.clone(),
                secret: Some(Sensitive::new(secret)),
            },
        );

        let old_record = state
            .keys
            .get_mut(&old_key_id)
            .ok_or(KeyLifecycleError::UnknownKey)?;
        old_record.metadata.state = KeyLifecycleState::Overlap;
        old_record.metadata.expires_at = request.overlap_until;
        old_record.metadata.metadata_version += 1;

        state.current.insert(request.trust_domain, new_key_id);
        Ok(new_metadata)
    }

    fn revoke(&self, key_id: &ContextQualifiedId, reason: &str) -> Result<(), KeyLifecycleError> {
        let revoked_at = self.clock.now();
        let mut state = self.state.lock().expect("key lifecycle lock poisoned");
        let record = state.keys.get_mut(key_id).ok_or(KeyLifecycleError::UnknownKey)?;
        if record.metadata.state == KeyLifecycleState::Destroyed {
            return Err(KeyLifecycleError::KeyDestroyed);
        }
        record.metadata.state = KeyLifecycleState::Revoked;
        record.metadata.revoked_at = Some(revoked_at);
        record.metadata.revocation_reason = Some(reason.to_owned());
        record.metadata.metadata_version += 1;
        let trust_domain = record.metadata.trust_domain.clone();
        if state.current.get(&trust_domain) == Some(key_id) {
            state.current.remove(&trust_domain);
        }
        Ok(())
    }

    fn destroy(&self, key_id: &ContextQualifiedId) -> Result<(), KeyLifecycleError> {
        let mut state = self.state.lock().expect("key lifecycle lock poisoned");
        let record = state.keys.get_mut(key_id).ok_or(KeyLifecycleError::UnknownKey)?;
        if record.metadata.state == KeyLifecycleState::Destroyed {
            return Ok(());
        }
        record.secret = None;
        record.metadata.state = KeyLifecycleState::Destroyed;
        record.metadata.metadata_version += 1;
        let trust_domain = record.metadata.trust_domain.clone();
        if state.current.get(&trust_domain) == Some(key_id) {
            state.current.remove(&trust_domain);
        }
        self.remove_secret_file(key_id);
        Ok(())
    }

    fn metadata(&self, key_id: &ContextQualifiedId) -> Result<KeyMetadata, KeyLifecycleError> {
        let state = self.state.lock().expect("key lifecycle lock poisoned");
        state
            .keys
            .get(key_id)
            .map(|record| record.metadata.clone())
            .ok_or(KeyLifecycleError::UnknownKey)
    }
}

fn check_time_bounds(metadata: &KeyMetadata, now: &UtcInstant) -> Result<(), KeyLifecycleError> {
    if now < &metadata.not_before {
        return Err(KeyLifecycleError::KeyNotYetValid);
    }
    if now > &metadata.expires_at {
        return Err(KeyLifecycleError::KeyExpired);
    }
    Ok(())
}

impl<C: KeyLifecycleClock> SignerPort for UntrustedDevelopmentKeyLifecycle<C> {
    fn sign(&self, key_id: &ContextQualifiedId, message: &[u8]) -> Result<KeySignature, KeyLifecycleError> {
        let state = self.state.lock().expect("key lifecycle lock poisoned");
        let record = state.keys.get(key_id).ok_or(KeyLifecycleError::UnknownKey)?;
        match record.metadata.state {
            KeyLifecycleState::Revoked => return Err(KeyLifecycleError::KeyRevoked),
            KeyLifecycleState::Destroyed => return Err(KeyLifecycleError::KeyDestroyed),
            KeyLifecycleState::Overlap => return Err(KeyLifecycleError::NotActiveForSigning),
            KeyLifecycleState::Active => {}
        }
        check_time_bounds(&record.metadata, &self.clock.now())?;
        let secret = record.secret.as_ref().ok_or(KeyLifecycleError::KeyDestroyed)?;
        let signing_key = SigningKey::from_bytes(secret.expose_sensitive());
        Ok(KeySignature {
            key_id: key_id.clone(),
            trust_domain: record.metadata.trust_domain.clone(),
            algorithm: record.metadata.algorithm,
            signature: signing_key.sign(message).to_bytes(),
            trust_label: "untrusted-development",
        })
    }

    fn verify(&self, message: &[u8], signature: &KeySignature) -> Result<(), KeyLifecycleError> {
        let state = self.state.lock().expect("key lifecycle lock poisoned");
        let record = state
            .keys
            .get(&signature.key_id)
            .ok_or(KeyLifecycleError::UnknownKey)?;
        if signature.trust_domain != record.metadata.trust_domain
            || signature.algorithm as u8 != record.metadata.algorithm as u8
            || signature.trust_label != "untrusted-development"
        {
            return Err(KeyLifecycleError::InvalidSignature);
        }
        match record.metadata.state {
            KeyLifecycleState::Revoked => return Err(KeyLifecycleError::KeyRevoked),
            KeyLifecycleState::Destroyed => return Err(KeyLifecycleError::KeyDestroyed),
            KeyLifecycleState::Active | KeyLifecycleState::Overlap => {}
        }
        check_time_bounds(&record.metadata, &self.clock.now())?;
        let secret = record.secret.as_ref().ok_or(KeyLifecycleError::KeyDestroyed)?;
        let signing_key = SigningKey::from_bytes(secret.expose_sensitive());
        signing_key
            .verifying_key()
            .verify(message, &Signature::from_bytes(&signature.signature))
            .map_err(|_| KeyLifecycleError::InvalidSignature)
    }
}

impl<T: SignerPort + ?Sized> SignerPort for &T {
    fn sign(&self, key_id: &ContextQualifiedId, message: &[u8]) -> Result<KeySignature, KeyLifecycleError> {
        (**self).sign(key_id, message)
    }

    fn verify(&self, message: &[u8], signature: &KeySignature) -> Result<(), KeyLifecycleError> {
        (**self).verify(message, signature)
    }
}

impl<T: KeyLifecyclePort + ?Sized> KeyLifecyclePort for &T {
    fn generate(&self, request: GenerateKeyRequest) -> Result<KeyMetadata, KeyLifecycleError> {
        (**self).generate(request)
    }

    fn current_key(&self, trust_domain: &TrustDomain) -> Result<KeyMetadata, KeyLifecycleError> {
        (**self).current_key(trust_domain)
    }

    fn rotate_with_overlap(&self, request: RotateKeyRequest) -> Result<KeyMetadata, KeyLifecycleError> {
        (**self).rotate_with_overlap(request)
    }

    fn revoke(&self, key_id: &ContextQualifiedId, reason: &str) -> Result<(), KeyLifecycleError> {
        (**self).revoke(key_id, reason)
    }

    fn destroy(&self, key_id: &ContextQualifiedId) -> Result<(), KeyLifecycleError> {
        (**self).destroy(key_id)
    }

    fn metadata(&self, key_id: &ContextQualifiedId) -> Result<KeyMetadata, KeyLifecycleError> {
        (**self).metadata(key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> OrganizationId {
        OrganizationId::new("00000000").unwrap()
    }
    fn key() -> ContextQualifiedId {
        ContextQualifiedId::new("key", "00000000").unwrap()
    }

    #[test]
    fn envelope_encryption_binds_tenant_key_nonce_and_associated_data() {
        let adapter = UntrustedDevelopmentEnvelopeEncryption::new(org(), key(), [7; 32]);
        let encrypted = adapter
            .encrypt(&org(), &key(), [9; 12], b"secret", b"descriptor")
            .unwrap();
        assert_eq!(
            adapter.decrypt(&org(), &encrypted, b"descriptor").unwrap(),
            b"secret"
        );
        assert_eq!(
            adapter.decrypt(&org(), &encrypted, b"other"),
            Err(CryptoError::AuthenticationFailed)
        );
        let mut corrupted = encrypted.clone();
        corrupted.ciphertext[0] ^= 1;
        assert_eq!(
            adapter.decrypt(&org(), &corrupted, b"descriptor"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            adapter.encrypt(
                &OrganizationId::new("00000001").unwrap(),
                &key(),
                [8; 12],
                b"secret",
                b"descriptor"
            ),
            Err(CryptoError::UnauthorizedKey)
        );
        assert!(!format!("{encrypted:?}").contains("secret"));
    }

    #[test]
    fn development_signatures_are_labeled_and_detect_tampering() {
        let signer = UntrustedDevelopmentSigner::new(key(), [3; 32]);
        let signature = signer.sign(&key(), b"canonical").unwrap();
        assert_eq!(signature.trust_label, "untrusted-development");
        signer.verify(b"canonical", &signature).unwrap();
        assert_eq!(
            signer.verify(b"changed", &signature),
            Err(CryptoError::InvalidSignature)
        );
    }
}

#[cfg(test)]
mod key_lifecycle_tests {
    use super::*;
    use cauterizer_syntax::time::UtcInstant;
    use proptest::prelude::*;
    use std::sync::Mutex as StdMutex;

    /// Deterministic, externally advanced clock for lifecycle tests.
    struct FixedClock(StdMutex<UtcInstant>);
    impl FixedClock {
        fn at(instant: &str) -> Self {
            Self(StdMutex::new(UtcInstant::parse(instant).unwrap()))
        }
        fn set(&self, instant: &str) {
            *self.0.lock().unwrap() = UtcInstant::parse(instant).unwrap();
        }
    }
    impl KeyLifecycleClock for FixedClock {
        fn now(&self) -> UtcInstant {
            self.0.lock().unwrap().clone()
        }
    }

    fn domain() -> TrustDomain {
        TrustDomain::new("isolated-execution-worker")
    }

    fn adapter(clock_at: &str) -> UntrustedDevelopmentKeyLifecycle<FixedClock> {
        let directory = tempfile::tempdir().unwrap();
        UntrustedDevelopmentKeyLifecycle::open_with_clock(
            directory.keep(),
            FixedClock::at(clock_at),
        )
        .unwrap()
    }

    #[test]
    fn generated_key_signs_and_verifies_with_domain_and_untrusted_label() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-02-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        assert_eq!(metadata.state, KeyLifecycleState::Active);
        let signature = adapter.sign(&metadata.key_id, b"payload").unwrap();
        assert_eq!(signature.trust_domain, domain());
        assert_eq!(signature.trust_label, "untrusted-development");
        adapter.verify(b"payload", &signature).unwrap();
        assert_eq!(
            adapter.verify(b"tampered", &signature),
            Err(KeyLifecycleError::InvalidSignature)
        );
    }

    #[test]
    fn not_yet_valid_and_expired_keys_fail_closed_without_being_revoked() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-02T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-01-10T00:00:00Z").unwrap(),
            })
            .unwrap();
        assert_eq!(
            adapter.current_key(&domain()),
            Err(KeyLifecycleError::KeyNotYetValid)
        );
        assert_eq!(
            adapter.sign(&metadata.key_id, b"payload"),
            Err(KeyLifecycleError::KeyNotYetValid)
        );

        adapter.clock.set("2026-01-11T00:00:00Z");
        assert_eq!(
            adapter.current_key(&domain()),
            Err(KeyLifecycleError::KeyExpired)
        );
        assert_eq!(
            adapter.sign(&metadata.key_id, b"payload"),
            Err(KeyLifecycleError::KeyExpired)
        );
    }

    #[test]
    fn verify_rejects_a_signature_relabeled_to_a_different_trust_domain() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let mut signature = adapter.sign(&metadata.key_id, b"payload").unwrap();
        signature.trust_domain = TrustDomain::new("some-other-domain");
        assert_eq!(
            adapter.verify(b"payload", &signature),
            Err(KeyLifecycleError::InvalidSignature)
        );
    }

    #[test]
    fn revoking_or_destroying_an_unknown_key_fails_closed() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let unknown = ContextQualifiedId::new("signing-key", "0000000000000000").unwrap();
        assert_eq!(
            adapter.revoke(&unknown, "n/a"),
            Err(KeyLifecycleError::UnknownKey)
        );
        assert_eq!(adapter.destroy(&unknown), Err(KeyLifecycleError::UnknownKey));
        assert_eq!(
            adapter.metadata(&unknown),
            Err(KeyLifecycleError::UnknownKey)
        );
    }

    #[test]
    fn revoking_an_already_destroyed_key_fails_closed() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        adapter.destroy(&metadata.key_id).unwrap();
        assert_eq!(
            adapter.revoke(&metadata.key_id, "too-late"),
            Err(KeyLifecycleError::KeyDestroyed)
        );
    }

    #[test]
    fn system_clock_millis_to_instant_matches_known_reference_dates() {
        assert_eq!(millis_to_instant(0).as_str(), "1970-01-01T00:00:00Z");
        assert_eq!(
            millis_to_instant(1_735_689_600_000).as_str(),
            "2025-01-01T00:00:00Z"
        );
        assert_eq!(
            millis_to_instant(1_784_900_730_000).as_str(),
            "2026-07-24T13:45:30Z"
        );
        assert_eq!(
            millis_to_instant(951_782_400_000).as_str(),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn millis_to_instant_never_emits_a_forbidden_trailing_zero_fraction() {
        // The canonical instant format rejects a trailing-zero fractional
        // digit; every parseable fractional millisecond value must trim to
        // its shortest non-trailing-zero form.
        assert_eq!(
            millis_to_instant(1_500).as_str(),
            "1970-01-01T00:00:01.5Z"
        );
        assert_eq!(
            millis_to_instant(1_050).as_str(),
            "1970-01-01T00:00:01.05Z"
        );
        assert_eq!(
            millis_to_instant(1_005).as_str(),
            "1970-01-01T00:00:01.005Z"
        );
        assert_eq!(
            millis_to_instant(1_990).as_str(),
            "1970-01-01T00:00:01.99Z"
        );
        for millis_of_second in 1u32..1000 {
            UtcInstant::parse(millis_to_instant(i64::from(millis_of_second)).into_string())
                .expect("every non-zero millisecond value must format canonically");
        }
    }

    #[test]
    fn signing_algorithm_and_lifecycle_state_wire_labels_round_trip() {
        assert_eq!(SigningAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(SigningAlgorithm::parse("ed25519"), Some(SigningAlgorithm::Ed25519));
        assert_eq!(SigningAlgorithm::parse("rsa"), None);

        for (state, label) in [
            (KeyLifecycleState::Active, "active"),
            (KeyLifecycleState::Overlap, "overlap"),
            (KeyLifecycleState::Revoked, "revoked"),
            (KeyLifecycleState::Destroyed, "destroyed"),
        ] {
            assert_eq!(state.as_str(), label);
            assert_eq!(KeyLifecycleState::parse(label), Some(state));
        }
        assert_eq!(KeyLifecycleState::parse("unknown"), None);
    }

    #[test]
    fn second_generate_for_same_domain_is_rejected() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let request = || GenerateKeyRequest {
            trust_domain: domain(),
            not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
            expires_at: UtcInstant::parse("2026-02-01T00:00:00Z").unwrap(),
        };
        adapter.generate(request()).unwrap();
        assert_eq!(
            adapter.generate(request()),
            Err(KeyLifecycleError::AlreadyActive)
        );
    }

    #[test]
    fn rotate_with_overlap_keeps_old_key_verifiable_until_overlap_elapses() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let first = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let old_signature = adapter.sign(&first.key_id, b"payload").unwrap();

        let second = adapter
            .rotate_with_overlap(RotateKeyRequest {
                trust_domain: domain(),
                overlap_until: UtcInstant::parse("2026-01-08T00:00:00Z").unwrap(),
                new_expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        assert_ne!(first.key_id, second.key_id);
        assert_eq!(second.state, KeyLifecycleState::Active);
        assert_eq!(
            adapter.metadata(&first.key_id).unwrap().state,
            KeyLifecycleState::Overlap
        );

        // Old key still verifies its own prior signature during the overlap window.
        adapter.verify(b"payload", &old_signature).unwrap();
        // Old key can no longer sign new messages.
        assert_eq!(
            adapter.sign(&first.key_id, b"new payload"),
            Err(KeyLifecycleError::NotActiveForSigning)
        );
        // New key is now current for the domain and can sign.
        assert_eq!(
            adapter.current_key(&domain()).unwrap().key_id,
            second.key_id
        );
        let new_signature = adapter.sign(&second.key_id, b"payload").unwrap();
        adapter.verify(b"payload", &new_signature).unwrap();

        // Advance past the overlap window: the old signature now fails closed.
        adapter.clock.set("2026-01-09T00:00:00Z");
        assert_eq!(
            adapter.verify(b"payload", &old_signature),
            Err(KeyLifecycleError::KeyExpired)
        );
        // The rotated-in key is unaffected.
        adapter.verify(b"payload", &new_signature).unwrap();
    }

    #[test]
    fn revoke_fails_verification_on_the_immediate_next_check_with_no_cache() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let signature = adapter.sign(&metadata.key_id, b"payload").unwrap();
        adapter.verify(b"payload", &signature).unwrap();

        adapter
            .revoke(&metadata.key_id, "key-compromise-drill")
            .unwrap();

        // No TTL, no cache: the very next check fails closed.
        assert_eq!(
            adapter.verify(b"payload", &signature),
            Err(KeyLifecycleError::KeyRevoked)
        );
        // A revoked key is never silently re-promoted to current.
        assert_eq!(
            adapter.current_key(&domain()),
            Err(KeyLifecycleError::NoActiveKey)
        );
        assert_eq!(
            adapter.sign(&metadata.key_id, b"payload"),
            Err(KeyLifecycleError::KeyRevoked)
        );
    }

    #[test]
    fn destroy_erases_private_key_material_and_fails_closed() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let signature = adapter.sign(&metadata.key_id, b"payload").unwrap();

        adapter.destroy(&metadata.key_id).unwrap();

        assert!(
            adapter
                .state
                .lock()
                .unwrap()
                .keys
                .get(&metadata.key_id)
                .unwrap()
                .secret
                .is_none()
        );
        assert_eq!(
            adapter.metadata(&metadata.key_id).unwrap().state,
            KeyLifecycleState::Destroyed
        );
        assert_eq!(
            adapter.sign(&metadata.key_id, b"payload"),
            Err(KeyLifecycleError::KeyDestroyed)
        );
        assert_eq!(
            adapter.verify(b"payload", &signature),
            Err(KeyLifecycleError::KeyDestroyed)
        );
        // Destroy is idempotent.
        adapter.destroy(&metadata.key_id).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.keep();
        let adapter =
            UntrustedDevelopmentKeyLifecycle::open_with_clock(root.clone(), FixedClock::at("2026-01-01T00:00:00Z"))
                .unwrap();
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let path = root.join(metadata.key_id.opaque());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn no_private_key_byte_appears_in_any_debug_or_display_output() {
        let adapter = adapter("2026-01-01T00:00:00Z");
        let metadata = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        let signature = adapter.sign(&metadata.key_id, b"payload").unwrap();

        let raw_secret_hex = {
            use std::fmt::Write as _;
            let state = adapter.state.lock().unwrap();
            let secret = state.keys[&metadata.key_id]
                .secret
                .as_ref()
                .unwrap()
                .expose_sensitive();
            let mut hex = String::with_capacity(secret.len() * 2);
            for byte in secret {
                write!(hex, "{byte:02x}").unwrap();
            }
            hex
        };
        assert_eq!(raw_secret_hex.len(), 64);

        let mut haystacks = vec![
            format!("{metadata:?}"),
            format!("{signature:?}"),
            format!("{:?}", KeyLifecycleError::KeyRevoked),
            format!("{:?}", adapter.state.lock().unwrap()),
        ];
        let error = adapter
            .generate(GenerateKeyRequest {
                trust_domain: domain(),
                not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                expires_at: UtcInstant::parse("2026-06-01T00:00:00Z").unwrap(),
            })
            .unwrap_err();
        haystacks.push(format!("{error:?}"));
        haystacks.push(format!("{error}"));

        for haystack in haystacks {
            assert!(
                !haystack.contains(&raw_secret_hex),
                "secret leaked through: {haystack}"
            );
        }
    }

    proptest! {
        #[test]
        fn revoked_key_never_verifies_regardless_of_arbitrary_future_time(
            reason in "[a-z-]{4,40}",
            advance_days in 0u32..400,
        ) {
            let adapter = adapter("2026-01-01T00:00:00Z");
            let metadata = adapter
                .generate(GenerateKeyRequest {
                    trust_domain: domain(),
                    not_before: UtcInstant::parse("2026-01-01T00:00:00Z").unwrap(),
                    expires_at: UtcInstant::parse("2027-01-01T00:00:00Z").unwrap(),
                })
                .unwrap();
            let signature = adapter.sign(&metadata.key_id, b"payload").unwrap();
            adapter.revoke(&metadata.key_id, &reason).unwrap();
            adapter.clock.set(&days_from_2020(2_192 + i64::from(advance_days)).to_string());

            // Revocation is immediate and not time-dependent: any later check,
            // at the original clock reading or any later one, fails closed.
            prop_assert_eq!(
                adapter.verify(b"payload", &signature),
                Err(KeyLifecycleError::KeyRevoked)
            );
        }

        #[test]
        fn generate_rejects_every_non_increasing_validity_window(
            not_before_days in 0i64..3650,
            offset_days in 0i64..30,
        ) {
            let adapter = adapter("2026-01-01T00:00:00Z");
            let not_before = days_from_2020(not_before_days);
            let expires_at = days_from_2020(not_before_days - offset_days);
            prop_assert_eq!(
                adapter.generate(GenerateKeyRequest {
                    trust_domain: TrustDomain::new(format!("domain-{not_before_days}-{offset_days}")),
                    not_before,
                    expires_at,
                }),
                Err(KeyLifecycleError::InvalidWindow)
            );
        }
    }

    /// Minimal deterministic calendar arithmetic sufficient for property-test
    /// bounds, well within the proleptic Gregorian range this adapter uses.
    fn days_from_2020(days: i64) -> UtcInstant {
        let millis_per_day: i64 = 86_400_000;
        let epoch_millis: i64 = 1_577_836_800_000; // 2020-01-01T00:00:00Z
        millis_to_instant(epoch_millis + days * millis_per_day)
    }
}
