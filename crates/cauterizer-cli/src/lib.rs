//! Minimal local remediation-control command parser.

#![forbid(unsafe_code)]

/// Parsed version 1 remediation control command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemediationCommandV1 {
    /// Trigger one run through an idempotent application command.
    Trigger {
        /// Tenant reference.
        organization: String,
        /// Run opaque component.
        run: String,
        /// Exact retry key.
        idempotency_key: String,
    },
    /// Read tenant-scoped status.
    Status {
        /// Tenant reference.
        organization: String,
        /// Run opaque component.
        run: String,
    },
    /// Cancel one run under optimistic concurrency and exact retry binding.
    Cancel {
        /// Tenant reference.
        organization: String,
        /// Run opaque component.
        run: String,
        /// Caller-observed aggregate version.
        expected_version: u64,
        /// Exact retry key.
        idempotency_key: String,
        /// Auditable cancellation reason.
        reason: String,
    },
    /// Request authorized reconciliation scheduling without connector access.
    Reconcile {
        /// Tenant reference.
        organization: String,
        /// Run opaque component.
        run: String,
    },
}

/// Stable local parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    /// Command shape was absent or unsupported.
    Usage,
    /// Expected version was not an unsigned integer.
    InvalidVersion,
}

/// Parses `remediation trigger|status|cancel|reconcile` arguments.
///
/// # Errors
/// Returns [`CliError`] for an unsupported shape or invalid version.
pub fn parse_args(args: &[String]) -> Result<RemediationCommandV1, CliError> {
    let values: Vec<&str> = args.iter().map(String::as_str).collect();
    match values.as_slice() {
        ["remediation", "trigger", organization, run, key] => Ok(RemediationCommandV1::Trigger {
            organization: (*organization).into(),
            run: (*run).into(),
            idempotency_key: (*key).into(),
        }),
        ["remediation", "status", organization, run] => Ok(RemediationCommandV1::Status {
            organization: (*organization).into(),
            run: (*run).into(),
        }),
        ["remediation", "reconcile", organization, run] => Ok(RemediationCommandV1::Reconcile {
            organization: (*organization).into(),
            run: (*run).into(),
        }),
        [
            "remediation",
            "cancel",
            organization,
            run,
            version,
            key,
            reason @ ..,
        ] if !reason.is_empty() => Ok(RemediationCommandV1::Cancel {
            organization: (*organization).into(),
            run: (*run).into(),
            expected_version: version.parse().map_err(|_| CliError::InvalidVersion)?,
            idempotency_key: (*key).into(),
            reason: reason.join(" "),
        }),
        _ => Err(CliError::Usage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn parses_all_coarse_commands_without_provider_options() {
        assert!(matches!(
            parse_args(&args(&["remediation", "trigger", "org_x", "run1", "key"])),
            Ok(RemediationCommandV1::Trigger { .. })
        ));
        assert!(matches!(
            parse_args(&args(&["remediation", "status", "org_x", "run1"])),
            Ok(RemediationCommandV1::Status { .. })
        ));
        assert!(matches!(
            parse_args(&args(&["remediation", "reconcile", "org_x", "run1"])),
            Ok(RemediationCommandV1::Reconcile { .. })
        ));
        assert!(matches!(
            parse_args(&args(&[
                "remediation",
                "cancel",
                "org_x",
                "run1",
                "3",
                "key",
                "stop",
                "now"
            ])),
            Ok(RemediationCommandV1::Cancel {
                expected_version: 3,
                ..
            })
        ));
    }

    #[test]
    fn rejects_connector_or_merge_shaped_commands() {
        assert_eq!(
            parse_args(&args(&["remediation", "merge", "org_x", "run1"])),
            Err(CliError::Usage)
        );
        assert_eq!(
            parse_args(&args(&[
                "remediation",
                "cancel",
                "org_x",
                "run1",
                "bad",
                "key",
                "reason"
            ])),
            Err(CliError::InvalidVersion)
        );
    }
}
