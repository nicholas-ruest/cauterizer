//! Pure, deny-by-default authorization over Organization aggregate snapshots.

use std::collections::BTreeSet;

use cauterizer_syntax::authorization::{AuthorizationRequestContext, ResourceRef};
use cauterizer_syntax::identifiers::{IdentityRef, OrganizationId};

use super::{
    BreakGlassGrant, Membership, MembershipStatus, Permission, Role, RoleDefinition,
    ServicePrincipal,
};

/// Request-time attributes authenticated at the application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionContext {
    /// Current Unix time in milliseconds.
    pub now_ms: u64,
    /// Whether authentication of the request identity succeeded.
    pub authenticated: bool,
    /// Whether a policy-acceptable MFA ceremony succeeded.
    pub mfa_verified: bool,
    /// Canonical environment name, such as `production`.
    pub environment: String,
    /// Validated contextual claims. Claims never imply permissions by themselves.
    pub claims: BTreeSet<String>,
}

/// Resource scope attached to a permission rule.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceSelector {
    /// Any resource owned by the already matched organization.
    AnyInOrganization,
    /// One exact resource.
    Exact(ResourceRef),
    /// A resource namespace separated from descendants by `/` or `:`.
    Prefix(String),
}

impl ResourceSelector {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Prefix(prefix) => {
                !prefix.is_empty()
                    && !prefix.ends_with(['/', ':'])
                    && ResourceRef::parse(prefix.clone()).is_ok()
            }
            Self::AnyInOrganization | Self::Exact(_) => true,
        }
    }

    pub(crate) fn matches(&self, resource: &ResourceRef) -> bool {
        match self {
            Self::AnyInOrganization => true,
            Self::Exact(expected) => expected == resource,
            Self::Prefix(prefix) => {
                resource.as_str() == prefix
                    || resource
                        .as_str()
                        .strip_prefix(prefix)
                        .is_some_and(|tail| tail.starts_with('/') || tail.starts_with(':'))
            }
        }
    }
}

/// Contextual ABAC constraints on an RBAC rule.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyConditions {
    /// Requires MFA and therefore excludes workload identities.
    pub require_mfa: bool,
    /// Requires one exact canonical environment.
    pub environment: Option<String>,
    /// Requires one of these exact declared purposes; empty means unrestricted.
    pub allowed_purposes: BTreeSet<String>,
    /// Requires all these authenticated contextual claims.
    pub required_claims: BTreeSet<String>,
}

impl PolicyConditions {
    pub(crate) fn valid(&self) -> bool {
        self.environment.as_ref().is_none_or(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }) && self.allowed_purposes.iter().all(|value| !value.is_empty())
            && self.required_claims.iter().all(|value| {
                !value.is_empty()
                    && value.len() <= 96
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b':' | b'-' | b'_')
                    })
            })
    }

    pub(crate) fn matches(
        &self,
        request: &AuthorizationRequestContext,
        context: &DecisionContext,
    ) -> bool {
        (!self.require_mfa || context.mfa_verified)
            && self
                .environment
                .as_ref()
                .is_none_or(|value| value == &context.environment)
            && (self.allowed_purposes.is_empty()
                || self.allowed_purposes.contains(request.purpose().as_str()))
            && self.required_claims.is_subset(&context.claims)
    }
}

/// A policy-specific resource and condition refinement of a domain permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRule {
    /// Exact domain permission.
    pub permission: Permission,
    /// Resource subset for the permission.
    pub resources: ResourceSelector,
    /// Contextual restrictions applied after RBAC matches.
    pub conditions: PolicyConditions,
}

/// Policy refinement for one assigned domain role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleRule {
    /// Aggregate-owned role assignment this rule refines.
    pub role: Role,
    /// Explicit permission rules. Empty grants nothing.
    pub permissions: Vec<PermissionRule>,
}

/// Read-only access records selected from one Organization aggregate snapshot.
#[derive(Clone, Copy)]
pub enum SubjectAccess<'a> {
    /// Active or inactive workforce membership, custom role definitions, and
    /// emergency grants selected for the same actor.
    Human {
        /// Aggregate-owned membership.
        membership: &'a Membership,
        /// Definitions referenced by assigned custom roles.
        custom_roles: &'a [&'a RoleDefinition],
        /// Grants whose beneficiary is the membership actor.
        break_glass: &'a [&'a BreakGlassGrant],
    },
    /// Aggregate-owned workload identity and its explicit scopes.
    Service(&'a ServicePrincipal),
}

/// Stable, audit-safe reason for a decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    /// An active role or workload scope and all ABAC constraints matched.
    RoleGrant,
    /// A valid, independently approved break-glass grant matched.
    BreakGlass,
    /// Authentication was absent.
    Unauthenticated,
    /// Policy, request, resource, or subject organization did not match.
    OrganizationMismatch,
    /// The supplied aggregate subject did not match the request identity.
    IdentityMismatch,
    /// The membership, workload identity, or emergency grant was revoked/expired.
    Inactive,
    /// No exact permission and resource rule matched.
    NoMatchingGrant,
    /// RBAC matched but contextual ABAC did not.
    ConditionsNotSatisfied,
}

/// Complete deny-or-explicit-allow result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    allowed: bool,
    reason: DecisionReason,
}

impl AuthorizationDecision {
    /// Whether the exact operation was explicitly allowed.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        self.allowed
    }

    /// Stable reason suitable for a redacted audit fact.
    #[must_use]
    pub const fn reason(self) -> DecisionReason {
        self.reason
    }

    const fn allow(reason: DecisionReason) -> Self {
        Self {
            allowed: true,
            reason,
        }
    }

    const fn deny(reason: DecisionReason) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }

    /// Creates a fail-closed decision for an aggregate lookup failure.
    #[must_use]
    pub const fn denied(reason: DecisionReason) -> Self {
        Self::deny(reason)
    }
}

/// Pure RBAC plus contextual ABAC policy for one organization.
#[derive(Clone, Debug)]
pub struct AuthorizationPolicy {
    organization_id: OrganizationId,
    role_rules: Vec<RoleRule>,
}

impl AuthorizationPolicy {
    /// Creates a policy snapshot. Missing and invalid rules safely grant nothing.
    #[must_use]
    pub const fn new(organization_id: OrganizationId, role_rules: Vec<RoleRule>) -> Self {
        Self {
            organization_id,
            role_rules,
        }
    }

    /// Returns the organization whose policy this snapshot represents.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Decides one operation using records read from the same Organization snapshot.
    #[must_use]
    pub fn decide(
        &self,
        request: &AuthorizationRequestContext,
        resource_organization_id: &OrganizationId,
        context: &DecisionContext,
        subject: SubjectAccess<'_>,
    ) -> AuthorizationDecision {
        if !context.authenticated {
            return AuthorizationDecision::deny(DecisionReason::Unauthenticated);
        }
        if &self.organization_id != request.organization_id()
            || &self.organization_id != resource_organization_id
        {
            return AuthorizationDecision::deny(DecisionReason::OrganizationMismatch);
        }
        match subject {
            SubjectAccess::Human {
                membership,
                custom_roles,
                break_glass,
            } => self.decide_human(request, context, membership, custom_roles, break_glass),
            SubjectAccess::Service(principal) => Self::decide_service(request, context, principal),
        }
    }

    fn decide_human(
        &self,
        request: &AuthorizationRequestContext,
        context: &DecisionContext,
        membership: &Membership,
        custom_roles: &[&RoleDefinition],
        break_glass: &[&BreakGlassGrant],
    ) -> AuthorizationDecision {
        let IdentityRef::Human(actor) = request.actor() else {
            return AuthorizationDecision::deny(DecisionReason::IdentityMismatch);
        };
        if membership.actor_id() != actor {
            return AuthorizationDecision::deny(DecisionReason::IdentityMismatch);
        }

        let membership_active = membership.status() == MembershipStatus::Active;
        if membership_active {
            let assigned_permissions = membership.roles().iter().flat_map(|role| {
                custom_roles
                    .iter()
                    .filter(move |definition| *role == Role::Custom(definition.id().to_owned()))
                    .flat_map(|definition| definition.permissions().iter())
            });
            if let Some(decision) = self.evaluate_roles(
                request,
                context,
                membership.roles().iter(),
                assigned_permissions,
            ) {
                return decision;
            }
        }

        if context.mfa_verified
            && break_glass.iter().any(|grant| {
                grant.beneficiary() == actor
                    && grant.beneficiary() != grant.approved_by()
                    && grant.is_active_at(context.now_ms)
                    && !grant.justification().trim().is_empty()
                    && grant
                        .permissions()
                        .iter()
                        .any(|permission| permission.matches(request, context))
            })
        {
            return AuthorizationDecision::allow(DecisionReason::BreakGlass);
        }

        AuthorizationDecision::deny(if membership_active {
            DecisionReason::NoMatchingGrant
        } else {
            DecisionReason::Inactive
        })
    }

    fn evaluate_roles<'a>(
        &self,
        request: &AuthorizationRequestContext,
        context: &DecisionContext,
        roles: impl Iterator<Item = &'a Role>,
        custom_permissions: impl Iterator<Item = &'a Permission>,
    ) -> Option<AuthorizationDecision> {
        let custom_permissions = custom_permissions.collect::<BTreeSet<_>>();
        let mut condition_failed = false;
        for role in roles {
            for rule in self.role_rules.iter().filter(|rule| &rule.role == role) {
                for grant in &rule.permissions {
                    if !grant.resources.valid()
                        || grant.permission.as_str() != request.action().as_str()
                    {
                        continue;
                    }
                    if matches!(role, Role::Custom(_))
                        && !custom_permissions.contains(&grant.permission)
                    {
                        continue;
                    }
                    if grant.resources.matches(request.resource()) {
                        if grant.conditions.valid() && grant.conditions.matches(request, context) {
                            return Some(AuthorizationDecision::allow(DecisionReason::RoleGrant));
                        }
                        condition_failed = true;
                    }
                }
            }
        }
        condition_failed
            .then(|| AuthorizationDecision::deny(DecisionReason::ConditionsNotSatisfied))
    }

    fn decide_service(
        request: &AuthorizationRequestContext,
        context: &DecisionContext,
        principal: &ServicePrincipal,
    ) -> AuthorizationDecision {
        let IdentityRef::Service(service_id) = request.actor() else {
            return AuthorizationDecision::deny(DecisionReason::IdentityMismatch);
        };
        let expected = principal
            .id()
            .as_str()
            .strip_prefix("workload_")
            .is_some_and(|opaque| opaque == service_id.opaque());
        if !expected {
            return AuthorizationDecision::deny(DecisionReason::IdentityMismatch);
        }
        if principal.is_revoked() || context.now_ms >= principal.expires_at_ms() {
            return AuthorizationDecision::deny(DecisionReason::Inactive);
        }
        if principal
            .scopes()
            .iter()
            .any(|permission| permission.matches(request, context))
        {
            AuthorizationDecision::allow(DecisionReason::RoleGrant)
        } else {
            AuthorizationDecision::deny(DecisionReason::NoMatchingGrant)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cauterizer_syntax::authorization::{ActionName, Purpose};
    use cauterizer_syntax::identifiers::{ActorId, ServicePrincipalId};
    use proptest::prelude::*;

    fn org(value: &str) -> OrganizationId {
        OrganizationId::new(value).unwrap()
    }
    fn actor(value: &str) -> cauterizer_syntax::identifiers::ActorId {
        ActorId::new(value).unwrap()
    }
    fn permission(value: &str) -> Permission {
        Permission::new(value).unwrap()
    }
    fn request(
        org: OrganizationId,
        identity: IdentityRef,
        action: &str,
    ) -> AuthorizationRequestContext {
        AuthorizationRequestContext::new(
            org,
            identity,
            ActionName::parse(action).unwrap(),
            ResourceRef::parse("run:abcdefgh").unwrap(),
            Purpose::parse("incident response").unwrap(),
        )
    }
    fn context(now_ms: u64) -> DecisionContext {
        DecisionContext {
            now_ms,
            authenticated: true,
            mfa_verified: true,
            environment: "production".into(),
            claims: BTreeSet::new(),
        }
    }
    fn owner_rule(conditions: PolicyConditions) -> RoleRule {
        RoleRule {
            role: Role::Owner,
            permissions: vec![PermissionRule {
                permission: permission("runs.read"),
                resources: ResourceSelector::AnyInOrganization,
                conditions,
            }],
        }
    }

    #[test]
    fn cross_organization_property_matrix_denies_every_mismatch() {
        let home = org("aaaaaaaa");
        let foreign = org("bbbbbbbb");
        let owner = Membership::initial_owner(
            super::super::MemberId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
        );
        let policy =
            AuthorizationPolicy::new(home.clone(), vec![owner_rule(PolicyConditions::default())]);
        for request_org in [&home, &foreign] {
            for resource_org in [&home, &foreign] {
                let request = request(
                    request_org.clone(),
                    IdentityRef::Human(actor("aaaaaaaa")),
                    "runs.read",
                );
                let decision = policy.decide(
                    &request,
                    resource_org,
                    &context(1),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[],
                    },
                );
                assert_eq!(
                    decision.is_allowed(),
                    request_org == &home && resource_org == &home
                );
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_foreign_tenant_substitution_is_denied(
            foreign in "[a-z0-9]{8,32}"
        ) {
            prop_assume!(foreign != "aaaaaaaa");
            let home = org("aaaaaaaa");
            let owner = Membership::initial_owner(
                super::super::MemberId::new("aaaaaaaa").unwrap(),
                actor("aaaaaaaa"),
            );
            let policy = AuthorizationPolicy::new(
                home.clone(),
                vec![owner_rule(PolicyConditions::default())],
            );
            let request = request(
                OrganizationId::new(&foreign).unwrap(),
                IdentityRef::Human(actor("aaaaaaaa")),
                "runs.read",
            );
            let decision = policy.decide(
                &request,
                &home,
                &context(1),
                SubjectAccess::Human {
                    membership: &owner,
                    custom_roles: &[],
                    break_glass: &[],
                },
            );
            prop_assert!(!decision.is_allowed());
            prop_assert_eq!(decision.reason(), DecisionReason::OrganizationMismatch);
        }
    }

    #[test]
    fn role_and_condition_table_is_deny_by_default() {
        let home = org("aaaaaaaa");
        let owner = Membership::initial_owner(
            super::super::MemberId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
        );
        for (authenticated, mfa, environment, action, allowed, reason) in [
            (
                true,
                true,
                "production",
                "runs.read",
                true,
                DecisionReason::RoleGrant,
            ),
            (
                false,
                true,
                "production",
                "runs.read",
                false,
                DecisionReason::Unauthenticated,
            ),
            (
                true,
                false,
                "production",
                "runs.read",
                false,
                DecisionReason::ConditionsNotSatisfied,
            ),
            (
                true,
                true,
                "development",
                "runs.read",
                false,
                DecisionReason::ConditionsNotSatisfied,
            ),
            (
                true,
                true,
                "production",
                "runs.write",
                false,
                DecisionReason::NoMatchingGrant,
            ),
        ] {
            let conditions = PolicyConditions {
                require_mfa: true,
                environment: Some("production".into()),
                ..PolicyConditions::default()
            };
            let policy = AuthorizationPolicy::new(home.clone(), vec![owner_rule(conditions)]);
            let request = request(home.clone(), IdentityRef::Human(actor("aaaaaaaa")), action);
            let mut ctx = context(1);
            ctx.authenticated = authenticated;
            ctx.mfa_verified = mfa;
            ctx.environment = environment.into();
            let decision = policy.decide(
                &request,
                &home,
                &ctx,
                SubjectAccess::Human {
                    membership: &owner,
                    custom_roles: &[],
                    break_glass: &[],
                },
            );
            assert_eq!(
                (decision.is_allowed(), decision.reason()),
                (allowed, reason)
            );
        }
    }

    #[test]
    fn purpose_and_claim_conditions_require_an_exact_complete_match() {
        let home = org("aaaaaaaa");
        let owner = Membership::initial_owner(
            super::super::MemberId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
        );
        let conditions = PolicyConditions {
            allowed_purposes: BTreeSet::from(["incident response".into()]),
            required_claims: BTreeSet::from(["team:security".into(), "region:us".into()]),
            ..PolicyConditions::default()
        };
        let policy = AuthorizationPolicy::new(home.clone(), vec![owner_rule(conditions)]);
        let matching = request(
            home.clone(),
            IdentityRef::Human(actor("aaaaaaaa")),
            "runs.read",
        );

        for (claims, expected) in [
            (
                BTreeSet::from(["team:security".into(), "region:us".into()]),
                true,
            ),
            (BTreeSet::from(["team:security".into()]), false),
            (BTreeSet::from(["region:us".into()]), false),
            (BTreeSet::new(), false),
        ] {
            let mut ctx = context(1);
            ctx.claims = claims;
            assert_eq!(
                policy
                    .decide(
                        &matching,
                        &home,
                        &ctx,
                        SubjectAccess::Human {
                            membership: &owner,
                            custom_roles: &[],
                            break_glass: &[],
                        },
                    )
                    .is_allowed(),
                expected
            );
        }

        let wrong_purpose = AuthorizationRequestContext::new(
            home.clone(),
            IdentityRef::Human(actor("aaaaaaaa")),
            ActionName::parse("runs.read").unwrap(),
            ResourceRef::parse("run:abcdefgh").unwrap(),
            Purpose::parse("routine review").unwrap(),
        );
        let mut ctx = context(1);
        ctx.claims = BTreeSet::from(["team:security".into(), "region:us".into()]);
        let decision = policy.decide(
            &wrong_purpose,
            &home,
            &ctx,
            SubjectAccess::Human {
                membership: &owner,
                custom_roles: &[],
                break_glass: &[],
            },
        );
        assert_eq!(decision.reason(), DecisionReason::ConditionsNotSatisfied);
    }

    #[test]
    fn resource_prefix_matches_only_exact_or_delimited_descendants() {
        let home = org("aaaaaaaa");
        let owner = Membership::initial_owner(
            super::super::MemberId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
        );
        let policy = AuthorizationPolicy::new(
            home.clone(),
            vec![RoleRule {
                role: Role::Owner,
                permissions: vec![PermissionRule {
                    permission: permission("runs.read"),
                    resources: ResourceSelector::Prefix("run:abcdefgh".into()),
                    conditions: PolicyConditions::default(),
                }],
            }],
        );
        for (resource, expected) in [
            ("run:abcdefgh", true),
            ("run:abcdefgh/child", true),
            ("run:abcdefgh:child", true),
            ("run:abcdefgh-child", false),
            ("run:abcdefghij", false),
        ] {
            let request = AuthorizationRequestContext::new(
                home.clone(),
                IdentityRef::Human(actor("aaaaaaaa")),
                ActionName::parse("runs.read").unwrap(),
                ResourceRef::parse(resource).unwrap(),
                Purpose::parse("incident response").unwrap(),
            );
            assert_eq!(
                policy
                    .decide(
                        &request,
                        &home,
                        &context(1),
                        SubjectAccess::Human {
                            membership: &owner,
                            custom_roles: &[],
                            break_glass: &[],
                        },
                    )
                    .is_allowed(),
                expected,
                "resource {resource}"
            );
        }
    }

    #[test]
    fn service_revocation_expiry_and_scope_are_enforced() {
        let home = org("aaaaaaaa");
        let service = ServicePrincipal::new(
            super::super::WorkloadPrincipalId::new("aaaaaaaa").unwrap(),
            BTreeSet::from([permission("runs.read")]),
            10,
        );
        let service_request = request(
            home.clone(),
            IdentityRef::Service(ServicePrincipalId::new("aaaaaaaa").unwrap()),
            "runs.read",
        );
        let policy = AuthorizationPolicy::new(home.clone(), vec![]);
        assert!(
            policy
                .decide(
                    &service_request,
                    &home,
                    &context(9),
                    SubjectAccess::Service(&service)
                )
                .is_allowed()
        );
        assert_eq!(
            policy
                .decide(
                    &service_request,
                    &home,
                    &context(10),
                    SubjectAccess::Service(&service)
                )
                .reason(),
            DecisionReason::Inactive
        );
        let mut revoked = service.clone();
        revoked.revoke();
        assert_eq!(
            policy
                .decide(
                    &service_request,
                    &home,
                    &context(9),
                    SubjectAccess::Service(&revoked)
                )
                .reason(),
            DecisionReason::Inactive
        );
        let no_scope = request(
            home.clone(),
            IdentityRef::Service(ServicePrincipalId::new("aaaaaaaa").unwrap()),
            "runs.write",
        );
        assert_eq!(
            policy
                .decide(
                    &no_scope,
                    &home,
                    &context(9),
                    SubjectAccess::Service(&service)
                )
                .reason(),
            DecisionReason::NoMatchingGrant
        );
    }

    #[test]
    fn identity_substitution_is_denied() {
        let home = org("aaaaaaaa");
        let owner = Membership::initial_owner(
            super::super::MemberId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
        );
        let policy =
            AuthorizationPolicy::new(home.clone(), vec![owner_rule(PolicyConditions::default())]);
        let request = request(
            home.clone(),
            IdentityRef::Human(actor("bbbbbbbb")),
            "runs.read",
        );
        assert_eq!(
            policy
                .decide(
                    &request,
                    &home,
                    &context(1),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[]
                    }
                )
                .reason(),
            DecisionReason::IdentityMismatch
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn break_glass_is_mfa_bound_and_expires_and_revokes_at_boundaries() {
        let home = org("aaaaaaaa");
        let owner = Membership::initial_owner(
            super::super::MemberId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
        );
        let mut grant = BreakGlassGrant::create(
            super::super::BreakGlassGrantId::new("aaaaaaaa").unwrap(),
            actor("aaaaaaaa"),
            actor("bbbbbbbb"),
            BTreeSet::from([permission("support.read")]),
            "approved incident investigation".into(),
            10,
            20,
        )
        .unwrap();
        let policy = AuthorizationPolicy::new(home.clone(), vec![]);
        let request = request(
            home.clone(),
            IdentityRef::Human(actor("aaaaaaaa")),
            "support.read",
        );
        assert!(
            !policy
                .decide(
                    &request,
                    &home,
                    &context(9),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[&grant],
                    },
                )
                .is_allowed()
        );
        assert_eq!(
            policy
                .decide(
                    &request,
                    &home,
                    &context(10),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[&grant],
                    },
                )
                .reason(),
            DecisionReason::BreakGlass
        );
        assert_eq!(
            policy
                .decide(
                    &request,
                    &home,
                    &context(19),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[&grant],
                    },
                )
                .reason(),
            DecisionReason::BreakGlass
        );
        assert!(
            !policy
                .decide(
                    &request,
                    &home,
                    &context(20),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[&grant],
                    },
                )
                .is_allowed()
        );
        grant.revoke();
        assert!(
            !policy
                .decide(
                    &request,
                    &home,
                    &context(15),
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[&grant],
                    },
                )
                .is_allowed()
        );
        let mut no_mfa = context(15);
        no_mfa.mfa_verified = false;
        assert!(
            !policy
                .decide(
                    &request,
                    &home,
                    &no_mfa,
                    SubjectAccess::Human {
                        membership: &owner,
                        custom_roles: &[],
                        break_glass: &[&grant],
                    },
                )
                .is_allowed()
        );
    }
}
