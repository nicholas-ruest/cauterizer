//! Contract tests for the provider-neutral SCM integration boundary.

use std::collections::BTreeSet;

use cauterizer_integration_management::application::{
    ConnectorError, FakeScmConnector, ScmConnector,
};
use cauterizer_integration_management::contracts::{
    DeliveryDisposition, DeliveryRequest, GitCommitOid, ScmMutation,
};
use cauterizer_integration_management::domain::{
    CapabilityManifest, InstallationGrant, ScmCapability,
};
use cauterizer_syntax::digest::Sha256Digest;
use cauterizer_syntax::identifiers::{ContextQualifiedId, IdempotencyKey, OrganizationId};

fn all_capabilities() -> BTreeSet<ScmCapability> {
    [
        ScmCapability::CreateIssue,
        ScmCapability::UpdateIssue,
        ScmCapability::CreateBranch,
        ScmCapability::PushCandidateCommit,
        ScmCapability::CreatePullRequest,
        ScmCapability::UpdatePullRequest,
        ScmCapability::PostEvidenceSummary,
    ]
    .into_iter()
    .collect()
}

fn fixture() -> (FakeScmConnector, InstallationGrant) {
    let capabilities = all_capabilities();
    let manifest = CapabilityManifest::new("fake", capabilities.clone()).unwrap();
    let connector = FakeScmConnector::new(manifest);
    let grant = InstallationGrant {
        installation_id: ContextQualifiedId::new("installation", "00000000").unwrap(),
        organization_id: OrganizationId::new("00000000").unwrap(),
        repositories: ["acme/widget".to_owned()].into_iter().collect(),
        branch_prefix: "cauterizer/".into(),
        allowed_target_branches: BTreeSet::from(["main".into()]),
        default_branch: "main".into(),
        protected_branches: BTreeSet::from(["main".into()]),
        capabilities,
        expires_at_unix: Some(200),
    };
    (connector, grant)
}

fn request(key: &str, correlation: &str, digest: &[u8], mutation: ScmMutation) -> DeliveryRequest {
    DeliveryRequest {
        organization_id: OrganizationId::new("00000000").unwrap(),
        installation_id: "installation_00000000".into(),
        repository: "acme/widget".into(),
        correlation_key: correlation.into(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        request_digest: Sha256Digest::of_bytes(digest),
        mutation,
    }
}

#[test]
fn supports_complete_safe_delivery_vocabulary() {
    let (connector, grant) = fixture();
    let operations = vec![
        ScmMutation::CreateIssue {
            title: "fix".into(),
            body: "body".into(),
        },
        ScmMutation::UpdateIssue {
            remote_id: "1".into(),
            title: "fix".into(),
            body: "body".into(),
        },
        ScmMutation::CreateBranch {
            branch: "cauterizer/run-1".into(),
            base_revision: "abc".into(),
        },
        ScmMutation::PushCandidateCommit {
            branch: "cauterizer/run-1".into(),
            candidate_digest: Sha256Digest::of_bytes(b"patch"),
            commit_oid: GitCommitOid::parse("0123456789abcdef0123456789abcdef01234567").unwrap(),
            transfer: None,
        },
        ScmMutation::CreatePullRequest {
            branch: "cauterizer/run-1".into(),
            base_branch: "main".into(),
            title: "fix".into(),
            body: "body".into(),
        },
        ScmMutation::UpdatePullRequest {
            remote_id: "2".into(),
            title: "fix".into(),
            body: "body".into(),
        },
        ScmMutation::PostEvidenceSummary {
            remote_id: "2".into(),
            summary: "verified".into(),
            evidence_digest: Sha256Digest::of_bytes(b"evidence"),
        },
    ];
    for (index, mutation) in operations.into_iter().enumerate() {
        let receipt = connector
            .deliver(
                &grant,
                request(
                    &format!("retry-{index}"),
                    &format!("object-{index}"),
                    format!("request-{index}").as_bytes(),
                    mutation,
                ),
                100,
            )
            .unwrap();
        assert!(matches!(
            receipt.disposition,
            DeliveryDisposition::Created | DeliveryDisposition::Updated
        ));
    }
}

#[test]
fn retry_is_idempotent_and_substitution_is_rejected() {
    let (connector, grant) = fixture();
    let mutation = ScmMutation::CreateIssue {
        title: "fix".into(),
        body: "body".into(),
    };
    let first = connector
        .deliver(
            &grant,
            request("retry-one", "issue-run", b"same", mutation.clone()),
            100,
        )
        .unwrap();
    let replay = connector
        .deliver(
            &grant,
            request("retry-one", "issue-run", b"same", mutation.clone()),
            100,
        )
        .unwrap();
    assert_eq!(replay.disposition, DeliveryDisposition::Replayed);
    assert_eq!(first.object, replay.object);
    assert_eq!(
        connector.deliver(
            &grant,
            request("retry-one", "issue-run", b"different", mutation),
            100
        ),
        Err(ConnectorError::IdempotencyConflict)
    );
}

#[test]
fn correlation_reconciles_ambiguous_retry_without_duplicate_object() {
    let (connector, grant) = fixture();
    let mutation = ScmMutation::CreateIssue {
        title: "fix".into(),
        body: "body".into(),
    };
    let first = connector
        .deliver(
            &grant,
            request("attempt-one", "issue-run", b"same", mutation.clone()),
            100,
        )
        .unwrap();
    let recovered = connector
        .deliver(
            &grant,
            request("attempt-two", "issue-run", b"same", mutation),
            100,
        )
        .unwrap();
    assert_eq!(recovered.disposition, DeliveryDisposition::Reconciled);
    assert_eq!(first.object, recovered.object);
}

#[test]
fn denies_foreign_repository_protected_namespace_missing_capability_and_expiry() {
    let (connector, mut grant) = fixture();
    let branch = |name: &str| ScmMutation::CreateBranch {
        branch: name.into(),
        base_revision: "abc".into(),
    };
    let mut foreign = request("foreign-r", "foreign-c", b"1", branch("cauterizer/x"));
    foreign.repository = "other/widget".into();
    assert_eq!(
        connector.deliver(&grant, foreign, 100),
        Err(ConnectorError::Denied)
    );
    assert_eq!(
        connector.deliver(
            &grant,
            request("protected-r", "protected-c", b"2", branch("main")),
            100
        ),
        Err(ConnectorError::Denied)
    );
    grant.capabilities.remove(&ScmCapability::CreateIssue);
    assert_eq!(
        connector.deliver(
            &grant,
            request(
                "missing-r",
                "missing-c",
                b"3",
                ScmMutation::CreateIssue {
                    title: "x".into(),
                    body: "x".into()
                }
            ),
            100
        ),
        Err(ConnectorError::Denied)
    );
    assert_eq!(
        connector.deliver(
            &grant,
            request("expired-r", "expired-c", b"4", branch("cauterizer/x")),
            200
        ),
        Err(ConnectorError::Denied)
    );
}

#[test]
fn forbidden_authorities_cannot_be_deserialized_as_capabilities() {
    for forbidden in [
        "merge_pull_request",
        "approve_pull_request",
        "push_protected_branch",
        "administer_repository",
        "create_release",
        "deploy",
    ] {
        let json = format!(r#"{{"connector_id":"bad","capabilities":["{forbidden}"]}}"#);
        assert!(
            serde_json::from_str::<CapabilityManifest>(&json).is_err(),
            "unexpected capability: {forbidden}"
        );
    }
}
