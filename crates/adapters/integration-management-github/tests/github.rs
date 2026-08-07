//! Contract tests for the GitHub integration adapter.

use cauterizer_integration_management::application::{ConnectorError, ScmConnector};
use cauterizer_integration_management::contracts::{
    DeliveryDisposition, DeliveryRequest, GitCommitOid, GitCommitTransfer, GitFileObject,
    ScmMutation,
};
use cauterizer_integration_management::domain::{InstallationGrant, ScmCapability};
use cauterizer_integration_management_github::{
    GitHubConnector, HttpRequest, HttpResponse, HttpTransport, Secret, SecretProvider,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey, OrganizationId};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Secrets;
impl SecretProvider for Secrets {
    fn github_token(&self, _: &str) -> Result<Secret, ConnectorError> {
        Ok(Secret::from("token"))
    }
}

#[derive(Clone, Default)]
struct Script {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    responses: Arc<Mutex<Vec<HttpResponse>>>,
}
impl Script {
    fn response(body: &str) -> Self {
        Self {
            responses: Arc::new(Mutex::new(vec![HttpResponse {
                status: 201,
                body: body.as_bytes().to_vec(),
            }])),
            ..Self::default()
        }
    }
}
impl HttpTransport for Script {
    fn send(&self, request: &HttpRequest, _: &Secret) -> Result<HttpResponse, ConnectorError> {
        self.requests.lock().unwrap().push(request.clone());
        self.responses
            .lock()
            .unwrap()
            .pop()
            .ok_or(ConnectorError::Unavailable)
    }
}

#[derive(Clone, Default)]
struct CrashAfterCreate {
    remote_issue: Arc<Mutex<Option<serde_json::Value>>>,
}
impl HttpTransport for CrashAfterCreate {
    fn send(&self, request: &HttpRequest, _: &Secret) -> Result<HttpResponse, ConnectorError> {
        if request.method == "POST" {
            let sent: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            *self.remote_issue.lock().unwrap() = Some(serde_json::json!({
                "id": 91,
                "html_url": "https://api.github.test/acme/widget/issues/91",
                "body": sent["body"]
            }));
            return Err(ConnectorError::Unavailable);
        }
        let items = self
            .remote_issue
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({"items":items})).unwrap(),
        })
    }
}
fn grant() -> InstallationGrant {
    InstallationGrant {
        installation_id: ContextQualifiedId::new("installation", "00000000").unwrap(),
        organization_id: OrganizationId::new("00000000").unwrap(),
        repositories: ["acme/widget".into()].into_iter().collect(),
        branch_prefix: "cauterizer/".into(),
        allowed_target_branches: BTreeSet::from(["main".into()]),
        default_branch: "main".into(),
        protected_branches: BTreeSet::from(["main".into()]),
        capabilities: [
            ScmCapability::CreateIssue,
            ScmCapability::CreateBranch,
            ScmCapability::PushCandidateCommit,
            ScmCapability::PostEvidenceSummary,
            ScmCapability::CreatePullRequest,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        expires_at_unix: None,
    }
}

#[test]
fn candidate_push_uses_exact_git_ref_shape_and_raw_commit_oid() {
    assert!(
        GitCommitOid::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_none()
    );
    let http = Script::response(r#"{"id":7,"html_url":"https://api.github.test/ref"}"#);
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let oid = "0123456789abcdef0123456789abcdef01234567";
    connector
        .deliver(
            &grant(),
            request(
                "push-one",
                "commit",
                ScmMutation::PushCandidateCommit {
                    branch: "cauterizer/run-1".into(),
                    candidate_digest: Sha256Digest::of_bytes(b"candidate"),
                    commit_oid: GitCommitOid::parse(oid).unwrap(),
                    transfer: None,
                },
            ),
            1,
        )
        .unwrap();
    let sent = &http.requests.lock().unwrap()[0];
    assert_eq!(sent.method, "PATCH");
    assert_eq!(
        sent.url,
        "https://api.github.test/repos/acme/widget/git/refs/heads/cauterizer/run-1"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent.body).unwrap(),
        serde_json::json!({"sha":oid,"force":false})
    );
}

#[test]
fn transfers_git_objects_then_advances_only_remediation_ref() {
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse {
                status: 200,
                body: br#"{"id":9,"url":"https://api.github.test/ref"}"#.to_vec(),
            },
            HttpResponse {
                status: 201,
                body: br#"{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec(),
            },
            HttpResponse {
                status: 201,
                body: br#"{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#.to_vec(),
            },
            HttpResponse {
                status: 201,
                body: br#"{"sha":"cccccccccccccccccccccccccccccccccccccccc"}"#.to_vec(),
            },
            HttpResponse {
                status: 200,
                body: br#"{"tree":{"sha":"dddddddddddddddddddddddddddddddddddddddd"}}"#.to_vec(),
            },
        ])),
        ..Script::default()
    };
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let base = GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
    let expected = GitCommitOid::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let mutation = ScmMutation::PushCandidateCommit {
        branch: "cauterizer/run-2".into(),
        candidate_digest: Sha256Digest::of_bytes(b"candidate"),
        commit_oid: expected,
        transfer: Some(GitCommitTransfer {
            base_commit_oid: base,
            commit_message: "Automated vulnerability remediation\n\nCauterizer-Run: run:00000001"
                .into(),
            files: vec![GitFileObject {
                path: "src/lib.rs".into(),
                content: b"fixed\n".to_vec(),
                executable: false,
            }],
        }),
    };
    connector
        .deliver(&grant(), request("transfer-one", "transfer", mutation), 1)
        .unwrap();
    let sent = http.requests.lock().unwrap();
    assert_eq!(
        sent.iter()
            .map(|request| request.method)
            .collect::<Vec<_>>(),
        ["GET", "POST", "POST", "POST", "PATCH"]
    );
    assert_eq!(
        sent[4].url,
        "https://api.github.test/repos/acme/widget/git/refs/heads/cauterizer/run-2"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent[4].body).unwrap(),
        serde_json::json!({"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","force":false})
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent[2].body).unwrap(),
        serde_json::json!({"base_tree":"dddddddddddddddddddddddddddddddddddddddd","tree":[{"path":"src/lib.rs","mode":"100644","type":"blob","sha":"cccccccccccccccccccccccccccccccccccccccc"}]})
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent[3].body).unwrap(),
        serde_json::json!({
            "message":"Automated vulnerability remediation\n\nCauterizer-Run: run:00000001","tree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "parents":["0123456789abcdef0123456789abcdef01234567"],
            "author":{"name":"Cauterizer","email":"cauterizer@invalid","date":"2000-01-01T00:00:00Z"},
            "committer":{"name":"Cauterizer","email":"cauterizer@invalid","date":"2000-01-01T00:00:00Z"}
        })
    );
}

#[test]
fn fresh_connector_reconciles_transferred_commit_from_remote_ref() {
    let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let http = Script::response(&format!(
        r#"{{"url":"https://api.github.test/ref","object":{{"sha":"{oid}"}}}}"#
    ));
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let request = request(
        "restart-transfer",
        "restart-transfer",
        ScmMutation::PushCandidateCommit {
            branch: "cauterizer/run-restart".into(),
            candidate_digest: Sha256Digest::of_bytes(b"candidate"),
            commit_oid: GitCommitOid::parse(oid).unwrap(),
            transfer: Some(GitCommitTransfer {
                base_commit_oid: GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567")
                    .unwrap(),
                commit_message: "Automated vulnerability remediation".into(),
                files: vec![GitFileObject {
                    path: "src/lib.rs".into(),
                    content: b"fixed\n".to_vec(),
                    executable: false,
                }],
            }),
        },
    );
    let found = connector.reconcile(&grant(), &request, 1).unwrap().unwrap();
    assert_eq!(found.applied_digest, request.request_digest);
    assert_eq!(http.requests.lock().unwrap()[0].method, "GET");
}
fn request(key: &str, correlation: &str, mutation: ScmMutation) -> DeliveryRequest {
    DeliveryRequest {
        organization_id: OrganizationId::new("00000000").unwrap(),
        installation_id: "installation_00000000".into(),
        repository: "acme/widget".into(),
        correlation_key: correlation.into(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        request_digest: Sha256Digest::of_bytes(correlation),
        mutation,
    }
}

#[test]
fn creates_issue_and_replays_without_second_http_call() {
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse {
                status: 201,
                body:
                    br#"{"number":42,"html_url":"https://api.github.test/acme/widget/issues/42"}"#
                        .to_vec(),
            },
            HttpResponse {
                status: 200,
                body: br#"{"items":[]}"#.to_vec(),
            },
        ])),
        ..Script::default()
    };
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let req = request(
        "retry-one",
        "issue-one",
        ScmMutation::CreateIssue {
            title: "security fix".into(),
            body: "evidence".into(),
        },
    );
    let first = connector.deliver(&grant(), req.clone(), 1).unwrap();
    let replay = connector.deliver(&grant(), req, 1).unwrap();
    assert_eq!(first.object.remote_id, "42");
    assert_eq!(replay.disposition, DeliveryDisposition::Replayed);
    assert_eq!(http.requests.lock().unwrap().len(), 2);
}

#[test]
fn fresh_connector_recovers_issue_after_ambiguous_remote_success() {
    let remote = CrashAfterCreate::default();
    let request = request(
        "crash-one",
        "run-crash",
        ScmMutation::CreateIssue {
            title: "fix".into(),
            body: "safe".into(),
        },
    );
    let first = GitHubConnector::new("https://api.github.test", remote.clone(), Secrets);
    assert_eq!(
        first.deliver(&grant(), request.clone(), 1),
        Err(ConnectorError::Unavailable)
    );
    let restarted = GitHubConnector::new("https://api.github.test", remote, Secrets);
    let recovered = restarted.reconcile(&grant(), &request, 1).unwrap().unwrap();
    assert_eq!(recovered.remote_id, "91");
    assert_eq!(recovered.applied_digest, request.request_digest);
}

#[test]
fn tenant_mismatch_is_denied_before_http() {
    let http = Script::response(r#"{"id":1,"html_url":"https://api.github.test/1"}"#);
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let mut request = request(
        "tenant-one",
        "tenant",
        ScmMutation::CreateIssue {
            title: "fix".into(),
            body: "safe".into(),
        },
    );
    request.organization_id = OrganizationId::new("11111111").unwrap();
    assert_eq!(
        connector.deliver(&grant(), request, 1),
        Err(ConnectorError::Denied)
    );
    assert!(http.requests.lock().unwrap().is_empty());
}

#[test]
fn correlation_reconciles_and_protected_branch_is_denied_before_http() {
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse {
                status: 201,
                body: br#"{"number":1,"html_url":"https://api.github.test/1"}"#.to_vec(),
            },
            HttpResponse {
                status: 200,
                body: br#"{"items":[]}"#.to_vec(),
            },
        ])),
        ..Script::default()
    };
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let mutation = ScmMutation::CreateIssue {
        title: "fix".into(),
        body: "body".into(),
    };
    connector
        .deliver(
            &grant(),
            request("attempt-one", "same", mutation.clone()),
            1,
        )
        .unwrap();
    let reconciled = connector
        .deliver(&grant(), request("attempt-two", "same", mutation), 1)
        .unwrap();
    assert_eq!(reconciled.disposition, DeliveryDisposition::Reconciled);
    let denied = request(
        "branch-one",
        "branch",
        ScmMutation::CreateBranch {
            branch: "main".into(),
            base_revision: "abc".into(),
        },
    );
    assert_eq!(
        connector.deliver(&grant(), denied, 1),
        Err(ConnectorError::Denied)
    );
    assert_eq!(http.requests.lock().unwrap().len(), 2);
}

#[test]
fn ungranted_pull_request_target_is_denied_before_http() {
    let http = Script::default();
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    let denied = request(
        "pr-target",
        "pr-target",
        ScmMutation::CreatePullRequest {
            branch: "cauterizer/candidate".into(),
            base_branch: "develop".into(),
            title: "repair".into(),
            body: "review".into(),
        },
    );
    assert_eq!(
        connector.deliver(&grant(), denied, 1),
        Err(ConnectorError::Denied)
    );
    assert!(http.requests.lock().unwrap().is_empty());
}

#[test]
fn repository_policy_preflight_allows_unprotected_namespaced_source() {
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse {
                status: 200,
                body: br"[]".to_vec(),
            },
            HttpResponse {
                status: 200,
                body: br#"{"default_branch":"main"}"#.to_vec(),
            },
        ])),
        ..Script::default()
    };
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    connector
        .preflight_repository_policy(&grant(), "acme/widget", "cauterizer/candidate", "main", 1)
        .unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(
        requests[1]
            .url
            .ends_with("/rules/branches/cauterizer%2Fcandidate")
    );
}

#[test]
fn repository_policy_preflight_denies_observed_default_mismatch_without_write() {
    let http = Script::response(r#"{"default_branch":"trunk"}"#);
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    assert_eq!(
        connector.preflight_repository_policy(
            &grant(),
            "acme/widget",
            "cauterizer/candidate",
            "main",
            1,
        ),
        Err(ConnectorError::Denied)
    );
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
}

#[test]
fn repository_policy_preflight_denies_applicable_rules_without_write() {
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse {
                status: 200,
                body: br#"[{"type":"required_pull_request"}]"#.to_vec(),
            },
            HttpResponse {
                status: 200,
                body: br#"{"default_branch":"main"}"#.to_vec(),
            },
        ])),
        ..Script::default()
    };
    let connector = GitHubConnector::new("https://api.github.test", http.clone(), Secrets);
    assert_eq!(
        connector.preflight_repository_policy(
            &grant(),
            "acme/widget",
            "cauterizer/candidate",
            "main",
            1,
        ),
        Err(ConnectorError::Denied)
    );
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.method == "GET"));
}

#[test]
fn fresh_connector_updates_owned_issue_without_duplicate_post() {
    let request = request(
        "candidate-two",
        "stable-issue",
        ScmMutation::CreateIssue {
            title: "new title".into(),
            body: "new body".into(),
        },
    );
    let owner = "<!-- cauterizer:installation_00000000:stable-issue -->";
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse { status: 200, body: br#"{"number":7,"html_url":"https://api.github.test/acme/widget/issues/7"}"#.to_vec() },
            HttpResponse { status: 200, body: serde_json::to_vec(&serde_json::json!({"items":[{"number":7,"body":owner,"html_url":"https://api.github.test/acme/widget/issues/7"}]})).unwrap() },
        ])),
        ..Script::default()
    };
    let receipt = GitHubConnector::new("https://api.github.test", http.clone(), Secrets)
        .deliver(&grant(), request, 1)
        .unwrap();
    assert_eq!(receipt.disposition, DeliveryDisposition::Updated);
    let sent = http.requests.lock().unwrap();
    assert_eq!(
        sent.iter().map(|r| r.method).collect::<Vec<_>>(),
        ["GET", "PATCH"]
    );
    assert!(sent[1].url.ends_with("/issues/7"));
    let body: serde_json::Value = serde_json::from_slice(&sent[1].body).unwrap();
    assert_eq!(body["title"], "new title");
    assert!(body["body"].as_str().unwrap().contains("new body"));
}

#[test]
fn fresh_connector_updates_owned_pull_request_and_validates_head() {
    let request = request(
        "candidate-two-pr",
        "stable-pr",
        ScmMutation::CreatePullRequest {
            branch: "cauterizer/run-1".into(),
            base_branch: "main".into(),
            title: "new pr".into(),
            body: "new evidence".into(),
        },
    );
    let owner = "<!-- cauterizer:installation_00000000:stable-pr -->";
    let http = Script {
        responses: Arc::new(Mutex::new(vec![
            HttpResponse { status: 200, body: br#"{"number":8,"html_url":"https://api.github.test/acme/widget/pull/8"}"#.to_vec() },
            HttpResponse { status: 200, body: serde_json::to_vec(&serde_json::json!({"number":8,"body":owner,"head":{"ref":"cauterizer/run-1"},"html_url":"https://api.github.test/acme/widget/pull/8"})).unwrap() },
            HttpResponse { status: 200, body: serde_json::to_vec(&serde_json::json!({"items":[{"number":8,"body":owner,"pull_request":{},"html_url":"https://api.github.test/acme/widget/pull/8"}]})).unwrap() },
        ])),
        ..Script::default()
    };
    let receipt = GitHubConnector::new("https://api.github.test", http.clone(), Secrets)
        .deliver(&grant(), request, 1)
        .unwrap();
    assert_eq!(receipt.disposition, DeliveryDisposition::Updated);
    let sent = http.requests.lock().unwrap();
    assert_eq!(
        sent.iter().map(|r| r.method).collect::<Vec<_>>(),
        ["GET", "GET", "PATCH"]
    );
    assert!(sent[2].url.ends_with("/pulls/8"));
}

#[test]
fn ambiguous_owned_objects_fail_closed_without_mutation() {
    let owner = "<!-- cauterizer:installation_00000000:stable-issue -->";
    let item = serde_json::json!({"number":7,"body":owner,"html_url":"https://api.github.test/acme/widget/issues/7"});
    let http = Script {
        responses: Arc::new(Mutex::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({"items":[item.clone(), item]})).unwrap(),
        }])),
        ..Script::default()
    };
    let result = GitHubConnector::new("https://api.github.test", http.clone(), Secrets).deliver(
        &grant(),
        request(
            "candidate",
            "stable-issue",
            ScmMutation::CreateIssue {
                title: "fix".into(),
                body: "body".into(),
            },
        ),
        1,
    );
    assert_eq!(result, Err(ConnectorError::ReconciliationConflict));
    assert_eq!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.method)
            .collect::<Vec<_>>(),
        ["GET"]
    );
}

#[test]
fn rejects_secrets_and_oversized_content_and_coarsens_api_errors() {
    for body in ["Authorization: Bearer hidden".into(), "x".repeat(60_001)] {
        let connector = GitHubConnector::new("https://api.github.test", Script::default(), Secrets);
        let req = request(
            "unsafe-one",
            "unsafe",
            ScmMutation::CreateIssue {
                title: "fix".into(),
                body,
            },
        );
        assert_eq!(
            connector.deliver(&grant(), req, 1),
            Err(ConnectorError::InvalidRequest)
        );
    }
    let http = Script {
        responses: Arc::new(Mutex::new(vec![HttpResponse {
            status: 500,
            body: b"provider stack trace and token".to_vec(),
        }])),
        ..Script::default()
    };
    let connector = GitHubConnector::new("https://api.github.test", http, Secrets);
    let req = request(
        "error-one",
        "error",
        ScmMutation::CreateIssue {
            title: "fix".into(),
            body: "body".into(),
        },
    );
    assert_eq!(
        connector.deliver(&grant(), req, 1),
        Err(ConnectorError::Unavailable)
    );
}

#[test]
fn rejects_path_injection_mutable_revisions_and_untrusted_receipt_urls() {
    let connector = GitHubConnector::new("https://api.github.test", Script::default(), Secrets);
    for remote_id in ["1/comments", "../1", "1?state=closed"] {
        let req = request(
            "bad-path",
            remote_id,
            ScmMutation::PostEvidenceSummary {
                remote_id: remote_id.into(),
                summary: "safe".into(),
                evidence_digest: Sha256Digest::of_bytes(b"evidence"),
            },
        );
        assert_eq!(
            connector.deliver(&grant(), req, 1),
            Err(ConnectorError::InvalidRequest)
        );
    }
    let req = request(
        "bad-revision",
        "branch-bad",
        ScmMutation::CreateBranch {
            branch: "cauterizer/run".into(),
            base_revision: "main".into(),
        },
    );
    assert_eq!(
        connector.deliver(&grant(), req, 1),
        Err(ConnectorError::InvalidRequest)
    );

    let http = Script::response(r#"{"id":1,"html_url":"http://evil.invalid/token"}"#);
    let connector = GitHubConnector::new("https://api.github.test", http, Secrets);
    let req = request(
        "bad-url",
        "issue-url",
        ScmMutation::CreateIssue {
            title: "fix".into(),
            body: "safe".into(),
        },
    );
    assert_eq!(
        connector.deliver(&grant(), req, 1),
        Err(ConnectorError::Unavailable)
    );
}
