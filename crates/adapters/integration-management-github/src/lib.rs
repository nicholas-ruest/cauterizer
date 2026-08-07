//! Capability-restricted GitHub SCM connector.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use cauterizer_integration_management::application::{ConnectorError, ScmConnector};
use cauterizer_integration_management::contracts::{
    DeliveryDisposition, DeliveryReceipt, DeliveryRequest, RemoteObject, ScmMutation,
};
use cauterizer_integration_management::domain::{
    CapabilityManifest, InstallationGrant, ScmCapability,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::IdempotencyKey;
use serde_json::{Value, json};

const MAX_TEXT: usize = 60_000;

/// Secret material returned only at the last responsible moment.
pub struct Secret(String);
impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}
impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

/// Credential-provider boundary. Credentials never enter domain values.
pub trait SecretProvider: Send + Sync {
    /// Loads the token for an installation.
    ///
    /// # Errors
    /// Returns a coarse unavailable or denied error without secret detail.
    fn github_token(&self, installation_id: &str) -> Result<Secret, ConnectorError>;
}

/// Provider-neutral request passed to the narrow HTTP transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    /// HTTP verb.
    pub method: &'static str,
    /// Absolute GitHub API URL.
    pub url: String,
    /// Serialized JSON body.
    pub body: Vec<u8>,
}

/// Coarsened HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Bounded response bytes.
    pub body: Vec<u8>,
}

/// Testable authenticated HTTP boundary.
pub trait HttpTransport: Send + Sync {
    /// Sends one request with a bearer token.
    ///
    /// # Errors
    /// Returns only coarse connector failures; response bodies must not be
    /// incorporated into errors.
    fn send(&self, request: &HttpRequest, bearer: &Secret) -> Result<HttpResponse, ConnectorError>;
}

/// Blocking rustls production transport with a fixed timeout.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}
impl ReqwestTransport {
    /// Builds a hardened GitHub transport.
    ///
    /// # Errors
    /// Returns unavailable if the TLS HTTP client cannot be constructed.
    pub fn new() -> Result<Self, ConnectorError> {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(|client| Self { client })
            .map_err(|_| ConnectorError::Unavailable)
    }
}
impl HttpTransport for ReqwestTransport {
    fn send(&self, request: &HttpRequest, bearer: &Secret) -> Result<HttpResponse, ConnectorError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| ConnectorError::InvalidRequest)?;
        let response = self
            .client
            .request(method, &request.url)
            .bearer_auth(bearer.expose())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "cauterizer")
            .body(request.body.clone())
            .send()
            .map_err(|_| ConnectorError::Unavailable)?;
        let status = response.status().as_u16();
        let body = response.bytes().map_err(|_| ConnectorError::Unavailable)?;
        if body.len() > 1_048_576 {
            return Err(ConnectorError::Unavailable);
        }
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
        })
    }
}

#[derive(Clone)]
struct Record {
    digest: Sha256Digest,
    object: RemoteObject,
}
#[derive(Default)]
struct State {
    attempts: BTreeMap<(String, IdempotencyKey), Record>,
    objects: BTreeMap<(String, String, String), RemoteObject>,
}

/// GitHub implementation of the safe Integration Management connector port.
pub struct GitHubConnector<T, S> {
    api_base: String,
    transport: T,
    secrets: S,
    manifest: CapabilityManifest,
    state: Arc<Mutex<State>>,
}
impl<T, S> GitHubConnector<T, S> {
    /// Constructs an adapter. Production should use `https://api.github.com`.
    ///
    /// # Panics
    /// Panics when the configured API base is not a credential-free HTTPS origin.
    #[must_use]
    pub fn new(api_base: impl Into<String>, transport: T, secrets: S) -> Self {
        let capabilities: BTreeSet<_> = [
            ScmCapability::CreateIssue,
            ScmCapability::UpdateIssue,
            ScmCapability::CreateBranch,
            ScmCapability::PushCandidateCommit,
            ScmCapability::CreatePullRequest,
            ScmCapability::UpdatePullRequest,
            ScmCapability::PostEvidenceSummary,
        ]
        .into_iter()
        .collect();
        let api_base = api_base.into();
        assert!(
            safe_api_base(&api_base),
            "GitHub API base must be an HTTPS origin"
        );
        Self {
            api_base: api_base.trim_end_matches('/').into(),
            transport,
            secrets,
            manifest: CapabilityManifest {
                connector_id: "github".into(),
                capabilities,
            },
            state: Arc::new(Mutex::new(State::default())),
        }
    }
}

impl<T: HttpTransport, S: SecretProvider> GitHubConnector<T, S> {
    /// Performs the read-only repository-policy gate required before any SCM
    /// mutation. It verifies the observed default branch and evaluates rules
    /// applying to the exact proposed remediation source ref.
    ///
    /// # Errors
    /// Denies mismatched defaults, protected/default source refs, ungranted
    /// targets, malformed or oversized responses, and unavailable policy data.
    pub fn preflight_repository_policy(
        &self,
        grant: &InstallationGrant,
        repository: &str,
        source_branch: &str,
        target_branch: &str,
        now: u64,
    ) -> Result<(), ConnectorError> {
        grant.validate(&self.manifest)?;
        grant.authorize(
            repository,
            Some(source_branch),
            ScmCapability::CreateBranch,
            now,
        )?;
        grant.authorize_target_branch(target_branch)?;
        if !safe_git_ref(source_branch) || !safe_git_ref(target_branch) {
            return Err(ConnectorError::Denied);
        }
        let token = self.secrets.github_token(grant.installation_id.as_str())?;
        let repository_response = self.transport.send(
            &HttpRequest {
                method: "GET",
                url: format!("{}/repos/{repository}", self.api_base),
                body: vec![],
            },
            &token,
        )?;
        let repository_policy = bounded_success_json(&repository_response)?;
        let observed_default = repository_policy
            .get("default_branch")
            .and_then(Value::as_str)
            .filter(|branch| safe_git_ref(branch))
            .ok_or(ConnectorError::Unavailable)?;
        if observed_default != grant.default_branch
            || observed_default != target_branch
            || source_branch == observed_default
        {
            return Err(ConnectorError::Denied);
        }
        let rules_response = self.transport.send(
            &HttpRequest {
                method: "GET",
                url: format!(
                    "{}/repos/{repository}/rules/branches/{}",
                    self.api_base,
                    encode_ref(source_branch)
                ),
                body: vec![],
            },
            &token,
        )?;
        let rules = bounded_success_json(&rules_response)?;
        if !rules.as_array().is_some_and(Vec::is_empty) {
            return Err(ConnectorError::Denied);
        }
        Ok(())
    }
}

fn bounded_success_json(response: &HttpResponse) -> Result<Value, ConnectorError> {
    if !(200..300).contains(&response.status) || response.body.len() > 1_048_576 {
        return Err(ConnectorError::Unavailable);
    }
    serde_json::from_slice(&response.body).map_err(|_| ConnectorError::Unavailable)
}

fn encode_ref(value: &str) -> String {
    value.replace('/', "%2F")
}

impl<T: HttpTransport, S: SecretProvider> ScmConnector for GitHubConnector<T, S> {
    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    #[allow(clippy::too_many_lines)]
    fn deliver(
        &self,
        grant: &InstallationGrant,
        request: DeliveryRequest,
        now: u64,
    ) -> Result<DeliveryReceipt, ConnectorError> {
        if request.installation_id != grant.installation_id.as_str() {
            return Err(ConnectorError::Denied);
        }
        if request.organization_id != grant.organization_id {
            return Err(ConnectorError::Denied);
        }
        grant
            .validate(&self.manifest)
            .map_err(ConnectorError::from)?;
        grant
            .authorize(
                &request.repository,
                request.mutation.branch(),
                request.mutation.capability(),
                now,
            )
            .map_err(ConnectorError::from)?;
        if let ScmMutation::CreatePullRequest { base_branch, .. } = &request.mutation {
            grant
                .authorize_target_branch(base_branch)
                .map_err(ConnectorError::from)?;
        }
        validate_request(&request)?;
        let attempt = (
            request.installation_id.clone(),
            request.idempotency_key.clone(),
        );
        let object_key = (
            request.installation_id.clone(),
            request.repository.clone(),
            request.correlation_key.clone(),
        );
        {
            let state = self.state.lock().map_err(|_| ConnectorError::Unavailable)?;
            if let Some(prior) = state.attempts.get(&attempt) {
                return if prior.digest == request.request_digest {
                    Ok(DeliveryReceipt {
                        disposition: DeliveryDisposition::Replayed,
                        object: prior.object.clone(),
                    })
                } else {
                    Err(ConnectorError::IdempotencyConflict)
                };
            }
            if let Some(object) = state.objects.get(&object_key) {
                if object.applied_digest == request.request_digest {
                    return Ok(DeliveryReceipt {
                        disposition: DeliveryDisposition::Reconciled,
                        object: object.clone(),
                    });
                }
                if !matches!(
                    request.mutation,
                    ScmMutation::CreateIssue { .. } | ScmMutation::CreatePullRequest { .. }
                ) {
                    return Err(ConnectorError::ReconciliationConflict);
                }
            }
        }
        let token = self.secrets.github_token(&request.installation_id)?;
        let mut desired_update = false;
        let response = if matches!(
            request.mutation,
            ScmMutation::CreateIssue { .. } | ScmMutation::CreatePullRequest { .. }
        ) {
            if let Some(existing) =
                find_correlated_object(&self.api_base, &self.transport, &token, &request)?
            {
                desired_update = true;
                let http = translate_desired_update(&self.api_base, &request, &existing)?;
                self.transport.send(&http, &token)?
            } else {
                let http = translate(&self.api_base, &request)?;
                self.transport.send(&http, &token)?
            }
        } else if let ScmMutation::PushCandidateCommit {
            branch,
            commit_oid,
            transfer: Some(transfer),
            ..
        } = &request.mutation
        {
            transfer_commit(
                &self.api_base,
                &self.transport,
                &token,
                &request.repository,
                branch,
                commit_oid,
                transfer,
            )?
        } else {
            let http = translate(&self.api_base, &request)?;
            self.transport.send(&http, &token)?
        };
        if !(200..300).contains(&response.status) {
            return Err(if response.status == 401 || response.status == 403 {
                ConnectorError::Denied
            } else {
                ConnectorError::Unavailable
            });
        }
        let value: Value =
            serde_json::from_slice(&response.body).map_err(|_| ConnectorError::Unavailable)?;
        let id = value
            .get("number")
            .or_else(|| value.get("id"))
            .and_then(Value::as_u64)
            .map_or_else(|| request.correlation_key.clone(), |id| id.to_string());
        let url = value
            .get("html_url")
            .or_else(|| value.get("url"))
            .and_then(Value::as_str)
            .filter(|url| safe_remote_url(url, &self.api_base))
            .ok_or(ConnectorError::Unavailable)?
            .to_owned();
        let object = RemoteObject {
            remote_id: id,
            url,
            applied_digest: request.request_digest,
        };
        let disposition = if desired_update
            || matches!(
                request.mutation,
                ScmMutation::UpdateIssue { .. }
                    | ScmMutation::UpdatePullRequest { .. }
                    | ScmMutation::PostEvidenceSummary { .. }
            ) {
            DeliveryDisposition::Updated
        } else {
            DeliveryDisposition::Created
        };
        let mut state = self.state.lock().map_err(|_| ConnectorError::Unavailable)?;
        state.objects.insert(object_key, object.clone());
        state.attempts.insert(
            attempt,
            Record {
                digest: request.request_digest,
                object: object.clone(),
            },
        );
        Ok(DeliveryReceipt {
            disposition,
            object,
        })
    }
    fn reconcile(
        &self,
        grant: &InstallationGrant,
        request: &DeliveryRequest,
        now: u64,
    ) -> Result<Option<RemoteObject>, ConnectorError> {
        if request.installation_id != grant.installation_id.as_str()
            || request.organization_id != grant.organization_id
        {
            return Err(ConnectorError::Denied);
        }
        grant.authorize(
            &request.repository,
            request.mutation.branch(),
            request.mutation.capability(),
            now,
        )?;
        if let ScmMutation::CreatePullRequest { base_branch, .. } = &request.mutation {
            grant.authorize_target_branch(base_branch)?;
        }
        validate_request(request)?;
        if let Some(object) = self
            .state
            .lock()
            .map_err(|_| ConnectorError::Unavailable)?
            .objects
            .get(&(
                request.installation_id.clone(),
                request.repository.clone(),
                request.correlation_key.clone(),
            ))
            .cloned()
        {
            return Ok(Some(object));
        }
        let token = self.secrets.github_token(&request.installation_id)?;
        remote_reconcile(&self.api_base, &self.transport, &token, request)
    }
}

fn validate_request(request: &DeliveryRequest) -> Result<(), ConnectorError> {
    if request.correlation_key.is_empty()
        || request.correlation_key.len() > 128
        || !request
            .correlation_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ConnectorError::InvalidRequest);
    }
    let texts: Vec<&str> = match &request.mutation {
        ScmMutation::CreateIssue { title, body }
        | ScmMutation::UpdateIssue { title, body, .. }
        | ScmMutation::CreatePullRequest { title, body, .. }
        | ScmMutation::UpdatePullRequest { title, body, .. } => vec![title, body],
        ScmMutation::PushCandidateCommit { .. } | ScmMutation::CreateBranch { .. } => vec![],
        ScmMutation::PostEvidenceSummary { summary, .. } => vec![summary],
    };
    if texts
        .iter()
        .any(|text| text.len() > MAX_TEXT || contains_secret(text))
    {
        return Err(ConnectorError::InvalidRequest);
    }
    let remote_ids: Vec<&str> = match &request.mutation {
        ScmMutation::UpdateIssue { remote_id, .. }
        | ScmMutation::UpdatePullRequest { remote_id, .. }
        | ScmMutation::PostEvidenceSummary { remote_id, .. } => vec![remote_id],
        _ => vec![],
    };
    if remote_ids
        .iter()
        .any(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ConnectorError::InvalidRequest);
    }
    match &request.mutation {
        ScmMutation::CreateBranch {
            branch,
            base_revision,
        } => {
            if !safe_git_ref(branch) || !raw_git_oid(base_revision) {
                return Err(ConnectorError::InvalidRequest);
            }
        }
        ScmMutation::PushCandidateCommit { branch, .. } => {
            if !safe_git_ref(branch) {
                return Err(ConnectorError::InvalidRequest);
            }
        }
        ScmMutation::CreatePullRequest {
            branch,
            base_branch,
            ..
        } => {
            if !safe_git_ref(branch) || !safe_git_ref(base_branch) {
                return Err(ConnectorError::InvalidRequest);
            }
        }
        _ => {}
    }
    Ok(())
}
fn safe_git_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains("@{")
        && !value.to_ascii_lowercase().ends_with(".lock")
        && !value.contains(['?', '#', '\\', '~', '^', ':', ' '])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}
fn raw_git_oid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn safe_api_base(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
    })
}
fn safe_remote_url(value: &str, api_base: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    let Ok(api) = reqwest::Url::parse(api_base) else {
        return false;
    };
    let expected = api.host_str();
    let observed = url.host_str();
    let github_pair = expected == Some("api.github.com") && observed == Some("github.com");
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && (observed == expected || github_pair)
}
fn contains_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "ghp_",
        "github_pat_",
        "private key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}
fn translate(base: &str, request: &DeliveryRequest) -> Result<HttpRequest, ConnectorError> {
    let repo = &request.repository;
    let (method, path, body) = match &request.mutation {
        ScmMutation::CreateIssue { title, body } => (
            "POST",
            format!("/repos/{repo}/issues"),
            json!({"title":title,"body":marked_body(request, body)}),
        ),
        ScmMutation::UpdateIssue {
            remote_id,
            title,
            body,
        } => (
            "PATCH",
            format!("/repos/{repo}/issues/{remote_id}"),
            json!({"title":title,"body":marked_body(request, body)}),
        ),
        ScmMutation::CreateBranch {
            branch,
            base_revision,
        } => (
            "POST",
            format!("/repos/{repo}/git/refs"),
            json!({"ref":format!("refs/heads/{branch}"),"sha":base_revision}),
        ),
        ScmMutation::PushCandidateCommit {
            branch, commit_oid, ..
        } => (
            "PATCH",
            format!("/repos/{repo}/git/refs/heads/{branch}"),
            json!({"sha":commit_oid.as_str(),"force":false}),
        ),
        ScmMutation::CreatePullRequest {
            branch,
            base_branch,
            title,
            body,
        } => (
            "POST",
            format!("/repos/{repo}/pulls"),
            json!({"head":branch,"base":base_branch,"title":title,"body":marked_body(request, body),"draft":false}),
        ),
        ScmMutation::UpdatePullRequest {
            remote_id,
            title,
            body,
        } => (
            "PATCH",
            format!("/repos/{repo}/pulls/{remote_id}"),
            json!({"title":title,"body":marked_body(request, body)}),
        ),
        ScmMutation::PostEvidenceSummary {
            remote_id,
            summary,
            evidence_digest,
        } => (
            "POST",
            format!("/repos/{repo}/issues/{remote_id}/comments"),
            json!({"body":marked_body(request, &format!("{summary}\n\nEvidence: {}", evidence_digest.to_tagged_hex()))}),
        ),
    };
    Ok(HttpRequest {
        method,
        url: format!("{base}{path}"),
        body: serde_json::to_vec(&body).map_err(|_| ConnectorError::InvalidRequest)?,
    })
}

fn transfer_commit<T: HttpTransport>(
    base: &str,
    transport: &T,
    token: &Secret,
    repo: &str,
    branch: &str,
    expected_commit_oid: &cauterizer_integration_management::contracts::GitCommitOid,
    transfer: &cauterizer_integration_management::contracts::GitCommitTransfer,
) -> Result<HttpResponse, ConnectorError> {
    if transfer.files.is_empty() || transfer.files.len() > 100 {
        return Err(ConnectorError::InvalidRequest);
    }
    let total_bytes = transfer
        .files
        .iter()
        .try_fold(0usize, |total, file| total.checked_add(file.content.len()))
        .ok_or(ConnectorError::InvalidRequest)?;
    if total_bytes > 8 * 1024 * 1024 {
        return Err(ConnectorError::InvalidRequest);
    }
    let base_commit = api(
        transport,
        token,
        "GET",
        format!(
            "{base}/repos/{repo}/git/commits/{}",
            transfer.base_commit_oid.as_str()
        ),
        &json!(null),
    )?;
    let base_tree = base_commit
        .pointer("/tree/sha")
        .and_then(Value::as_str)
        .filter(|sha| raw_git_oid(sha))
        .ok_or(ConnectorError::Unavailable)?;
    let mut entries = Vec::new();
    let mut paths = std::collections::BTreeSet::new();
    for file in &transfer.files {
        if !safe_git_path(&file.path)
            || !paths.insert(file.path.clone())
            || file.content.len() > 1_048_576
        {
            return Err(ConnectorError::InvalidRequest);
        }
        let blob = api(
            transport,
            token,
            "POST",
            format!("{base}/repos/{repo}/git/blobs"),
            &json!({"content":base64::engine::general_purpose::STANDARD.encode(&file.content),"encoding":"base64"}),
        )?;
        let sha = blob
            .get("sha")
            .and_then(Value::as_str)
            .filter(|sha| raw_git_oid(sha))
            .ok_or(ConnectorError::Unavailable)?;
        entries.push(json!({"path":file.path,"mode":if file.executable { "100755" } else { "100644" },"type":"blob","sha":sha}));
    }
    let tree = api(
        transport,
        token,
        "POST",
        format!("{base}/repos/{repo}/git/trees"),
        &json!({"base_tree":base_tree,"tree":entries}),
    )?;
    let tree_sha = tree
        .get("sha")
        .and_then(Value::as_str)
        .filter(|sha| raw_git_oid(sha))
        .ok_or(ConnectorError::Unavailable)?;
    if transfer.commit_message.is_empty() || transfer.commit_message.len() > 1024 {
        return Err(ConnectorError::InvalidRequest);
    }
    let commit = api(
        transport,
        token,
        "POST",
        format!("{base}/repos/{repo}/git/commits"),
        &json!({
            "message":transfer.commit_message,"tree":tree_sha,"parents":[transfer.base_commit_oid.as_str()],
            "author":{"name":"Cauterizer","email":"cauterizer@invalid","date":"2000-01-01T00:00:00Z"},
            "committer":{"name":"Cauterizer","email":"cauterizer@invalid","date":"2000-01-01T00:00:00Z"}
        }),
    )?;
    let sha = commit
        .get("sha")
        .and_then(Value::as_str)
        .filter(|sha| raw_git_oid(sha))
        .ok_or(ConnectorError::Unavailable)?;
    if sha != expected_commit_oid.as_str() {
        return Err(ConnectorError::ReconciliationConflict);
    }
    let request = HttpRequest {
        method: "PATCH",
        url: format!("{base}/repos/{repo}/git/refs/heads/{branch}"),
        body: serde_json::to_vec(&json!({"sha":sha,"force":false}))
            .map_err(|_| ConnectorError::InvalidRequest)?,
    };
    transport.send(&request, token)
}

fn api<T: HttpTransport>(
    transport: &T,
    token: &Secret,
    method: &'static str,
    url: String,
    body: &Value,
) -> Result<Value, ConnectorError> {
    let bytes = if body.is_null() {
        vec![]
    } else {
        serde_json::to_vec(&body).map_err(|_| ConnectorError::InvalidRequest)?
    };
    let response = transport.send(
        &HttpRequest {
            method,
            url,
            body: bytes,
        },
        token,
    )?;
    if !(200..300).contains(&response.status) {
        return Err(ConnectorError::Unavailable);
    }
    serde_json::from_slice(&response.body).map_err(|_| ConnectorError::Unavailable)
}

fn safe_git_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.split('/').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".git")
        })
}

fn marker(request: &DeliveryRequest) -> String {
    format!(
        "<!-- cauterizer:{}:{} -->",
        request.installation_id, request.correlation_key
    )
}

fn state_marker(request: &DeliveryRequest) -> String {
    format!(
        "<!-- cauterizer-state:{} -->",
        request.request_digest.to_tagged_hex()
    )
}

fn marked_body(request: &DeliveryRequest, body: &str) -> String {
    format!("{body}\n\n{}\n{}", marker(request), state_marker(request))
}

fn find_correlated_object<T: HttpTransport>(
    base: &str,
    transport: &T,
    token: &Secret,
    request: &DeliveryRequest,
) -> Result<Option<Value>, ConnectorError> {
    let repo = &request.repository;
    let response = transport.send(
        &HttpRequest {
            method: "GET",
            url: format!(
                "{base}/search/issues?q=repo%3A{}%20%22{}%22",
                repo.replace('/', "%2F"),
                request.correlation_key
            ),
            body: vec![],
        },
        token,
    )?;
    if !(200..300).contains(&response.status) {
        return Err(ConnectorError::Unavailable);
    }
    let value: Value =
        serde_json::from_slice(&response.body).map_err(|_| ConnectorError::Unavailable)?;
    let items = value
        .as_array()
        .or_else(|| value.get("items").and_then(Value::as_array))
        .ok_or(ConnectorError::Unavailable)?;
    let ownership_marker = marker(request);
    let wants_pull = matches!(request.mutation, ScmMutation::CreatePullRequest { .. });
    let candidates: Vec<_> = items
        .iter()
        .filter(|item| {
            item.get("body")
                .and_then(Value::as_str)
                .is_some_and(|body| body.contains(&ownership_marker))
                && item.get("pull_request").is_some() == wants_pull
        })
        .cloned()
        .collect();
    let object = match candidates.as_slice() {
        [] => Ok(None),
        [item] => Ok(Some(item.clone())),
        _ => Err(ConnectorError::ReconciliationConflict),
    }?;
    let Some(object) = object else {
        return Ok(None);
    };
    if !wants_pull {
        return Ok(Some(object));
    }
    let number = object
        .get("number")
        .and_then(Value::as_u64)
        .ok_or(ConnectorError::ReconciliationConflict)?;
    let detail = api(
        transport,
        token,
        "GET",
        format!("{base}/repos/{repo}/pulls/{number}"),
        &Value::Null,
    )?;
    if detail
        .get("body")
        .and_then(Value::as_str)
        .is_none_or(|body| !body.contains(&ownership_marker))
    {
        return Err(ConnectorError::ReconciliationConflict);
    }
    Ok(Some(detail))
}

fn translate_desired_update(
    base: &str,
    request: &DeliveryRequest,
    existing: &Value,
) -> Result<HttpRequest, ConnectorError> {
    let number = existing
        .get("number")
        .and_then(Value::as_u64)
        .ok_or(ConnectorError::ReconciliationConflict)?;
    let repo = &request.repository;
    let (url, body) = match &request.mutation {
        ScmMutation::CreateIssue { title, body } => (
            format!("{base}/repos/{repo}/issues/{number}"),
            json!({"title":title,"body":marked_body(request, body)}),
        ),
        ScmMutation::CreatePullRequest {
            branch,
            base_branch,
            title,
            body,
        } => {
            if existing.pointer("/head/ref").and_then(Value::as_str) != Some(branch) {
                return Err(ConnectorError::ReconciliationConflict);
            }
            (
                format!("{base}/repos/{repo}/pulls/{number}"),
                json!({"title":title,"body":marked_body(request, body),"base":base_branch}),
            )
        }
        _ => return Err(ConnectorError::InvalidRequest),
    };
    Ok(HttpRequest {
        method: "PATCH",
        url,
        body: serde_json::to_vec(&body).map_err(|_| ConnectorError::InvalidRequest)?,
    })
}

#[allow(clippy::too_many_lines)]
fn remote_reconcile<T: HttpTransport>(
    base: &str,
    transport: &T,
    token: &Secret,
    request: &DeliveryRequest,
) -> Result<Option<RemoteObject>, ConnectorError> {
    let marker = marker(request);
    let repo = &request.repository;
    let (path, list, expected_oid) = match &request.mutation {
        ScmMutation::CreateIssue { .. } | ScmMutation::CreatePullRequest { .. } => (
            format!(
                "/search/issues?q=repo%3A{}%20%22{}%22",
                repo.replace('/', "%2F"),
                request.correlation_key
            ),
            true,
            None,
        ),
        ScmMutation::UpdateIssue { remote_id, .. } => {
            (format!("/repos/{repo}/issues/{remote_id}"), false, None)
        }
        ScmMutation::UpdatePullRequest { remote_id, .. } => {
            (format!("/repos/{repo}/pulls/{remote_id}"), false, None)
        }
        ScmMutation::PostEvidenceSummary { remote_id, .. } => (
            format!("/repos/{repo}/issues/{remote_id}/comments"),
            true,
            None,
        ),
        ScmMutation::CreateBranch {
            branch,
            base_revision,
        } => (
            format!("/repos/{repo}/git/ref/heads/{branch}"),
            false,
            Some(base_revision.as_str()),
        ),
        ScmMutation::PushCandidateCommit {
            branch, commit_oid, ..
        } => (
            format!("/repos/{repo}/git/ref/heads/{branch}"),
            false,
            Some(commit_oid.as_str()),
        ),
    };
    let response = transport.send(
        &HttpRequest {
            method: "GET",
            url: format!("{base}{path}"),
            body: vec![],
        },
        token,
    )?;
    if response.status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&response.status) {
        return Err(ConnectorError::Unavailable);
    }
    let value: Value =
        serde_json::from_slice(&response.body).map_err(|_| ConnectorError::Unavailable)?;
    let candidates: Vec<&Value> = if list {
        value
            .as_array()
            .or_else(|| value.get("items").and_then(Value::as_array))
            .map_or_else(Vec::new, |items| items.iter().collect())
    } else {
        vec![&value]
    };
    let state = state_marker(request);
    let wants_pull = matches!(request.mutation, ScmMutation::CreatePullRequest { .. });
    let found: Vec<_> = candidates
        .into_iter()
        .filter(|item| {
            if let Some(expected) = expected_oid {
                return item.pointer("/object/sha").and_then(Value::as_str) == Some(expected);
            }
            item.get("body")
                .and_then(Value::as_str)
                .is_some_and(|body| body.contains(&marker) && body.contains(&state))
                && (!matches!(
                    request.mutation,
                    ScmMutation::CreateIssue { .. } | ScmMutation::CreatePullRequest { .. }
                ) || item.get("pull_request").is_some() == wants_pull)
        })
        .collect();
    let found = match found.as_slice() {
        [] => return Ok(None),
        [found] => *found,
        _ => return Err(ConnectorError::ReconciliationConflict),
    };
    let remote_id = found
        .get("number")
        .or_else(|| found.get("id"))
        .and_then(Value::as_u64)
        .map_or_else(|| request.correlation_key.clone(), |id| id.to_string());
    let url = found
        .get("html_url")
        .or_else(|| found.get("url"))
        .and_then(Value::as_str)
        .filter(|url| safe_remote_url(url, base))
        .ok_or(ConnectorError::Unavailable)?
        .to_owned();
    Ok(Some(RemoteObject {
        remote_id,
        url,
        applied_digest: request.request_digest,
    }))
}
