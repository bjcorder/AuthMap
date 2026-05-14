use std::path::PathBuf;

use authmap_core::{Confidence, EvidenceType, ScanMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_CONFIG_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub limits: ScanLimits,
    pub authorization: AuthorizationConfig,
    pub sensitivity: SensitivityConfig,
    pub drift: DriftConfig,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Advisory,
            include: Vec::new(),
            exclude: Vec::new(),
            limits: ScanLimits::default(),
            authorization: AuthorizationConfig::default(),
            sensitivity: SensitivityConfig::default(),
            drift: DriftConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizationConfig {
    pub rules: Vec<AuthorizationRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRule {
    pub name: String,
    pub evidence_type: EvidenceType,
    pub mechanism: String,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    #[serde(rename = "match")]
    pub matcher: AuthorizationRuleMatch,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizationRuleMatch {
    pub exact: Vec<String>,
    pub contains: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensitivityConfig {
    pub routes: Vec<RouteSensitivityRule>,
    pub resources: Vec<ResourceSensitivityRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DriftConfig {
    pub fail_on: Vec<DriftFailCategory>,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            fail_on: default_drift_fail_on(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftFailCategory {
    AddedHighRiskRoute,
    AddedReviewRequiredRoute,
    AuthDowngrade,
    NewLinkedMutation,
}

pub fn default_drift_fail_on() -> Vec<DriftFailCategory> {
    vec![
        DriftFailCategory::AddedHighRiskRoute,
        DriftFailCategory::AuthDowngrade,
        DriftFailCategory::NewLinkedMutation,
    ]
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSensitivityRule {
    pub name: String,
    pub labels: Vec<String>,
    #[serde(rename = "match")]
    pub matcher: AuthorizationRuleMatch,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub reviewer_questions: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSensitivityRule {
    pub name: String,
    pub labels: Vec<String>,
    #[serde(rename = "match")]
    pub matcher: AuthorizationRuleMatch,
    #[serde(default)]
    pub reviewer_questions: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanLimits {
    pub max_files: usize,
    pub max_file_size_bytes: u64,
    pub max_total_bytes: u64,
    pub max_runtime_ms: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_files: 50_000,
            max_file_size_bytes: 2 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_runtime_ms: 120_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanPlan {
    pub targets: Vec<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub config: ScanConfig,
}

impl ScanPlan {
    pub fn new(targets: Vec<PathBuf>, config_path: Option<PathBuf>, config: ScanConfig) -> Self {
        Self {
            targets,
            config_path,
            config,
        }
    }
}

pub fn load_config(path: Option<PathBuf>) -> Result<(Option<PathBuf>, ScanConfig), ConfigError> {
    let Some(path) = path else {
        return Ok((None, ScanConfig::default()));
    };

    let metadata = std::fs::metadata(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Validate {
            path,
            message: format!("config file exceeds maximum size of {MAX_CONFIG_BYTES} bytes"),
        });
    }

    let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    let config: ScanConfig = serde_yaml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;
    config.validate(&path)?;
    Ok((Some(path), config))
}

impl ScanConfig {
    fn validate(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        if self.limits.max_files == 0 {
            return Err(ConfigError::Validate {
                path: path.to_path_buf(),
                message: "limits.max_files must be greater than zero".to_string(),
            });
        }
        if self.limits.max_file_size_bytes == 0 {
            return Err(ConfigError::Validate {
                path: path.to_path_buf(),
                message: "limits.max_file_size_bytes must be greater than zero".to_string(),
            });
        }
        if self.limits.max_total_bytes == 0 {
            return Err(ConfigError::Validate {
                path: path.to_path_buf(),
                message: "limits.max_total_bytes must be greater than zero".to_string(),
            });
        }
        if self.limits.max_runtime_ms == 0 {
            return Err(ConfigError::Validate {
                path: path.to_path_buf(),
                message: "limits.max_runtime_ms must be greater than zero".to_string(),
            });
        }
        for (index, rule) in self.authorization.rules.iter().enumerate() {
            if rule.name.trim().is_empty() {
                return Err(ConfigError::Validate {
                    path: path.to_path_buf(),
                    message: format!("authorization.rules[{index}].name must not be empty"),
                });
            }
            if rule.mechanism.trim().is_empty() {
                return Err(ConfigError::Validate {
                    path: path.to_path_buf(),
                    message: format!("authorization.rules[{index}].mechanism must not be empty"),
                });
            }
            validate_matcher(
                path,
                &format!("authorization.rules[{index}].match"),
                &rule.matcher,
            )?;
        }
        for (index, rule) in self.sensitivity.routes.iter().enumerate() {
            validate_name(
                path,
                &format!("sensitivity.routes[{index}].name"),
                &rule.name,
            )?;
            validate_nonempty_list(
                path,
                &format!("sensitivity.routes[{index}].labels"),
                &rule.labels,
            )?;
            validate_matcher(
                path,
                &format!("sensitivity.routes[{index}].match"),
                &rule.matcher,
            )?;
            validate_optional_list(
                path,
                &format!("sensitivity.routes[{index}].reviewer_questions"),
                &rule.reviewer_questions,
            )?;
            validate_optional_list(
                path,
                &format!("sensitivity.routes[{index}].notes"),
                &rule.notes,
            )?;
            for method in &rule.methods {
                if method.trim().is_empty() {
                    return Err(ConfigError::Validate {
                        path: path.to_path_buf(),
                        message: format!(
                            "sensitivity.routes[{index}].methods entries must not be empty"
                        ),
                    });
                }
                let upper = method.to_ascii_uppercase();
                if !matches!(
                    upper.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "ANY"
                ) {
                    return Err(ConfigError::Validate {
                        path: path.to_path_buf(),
                        message: format!(
                            "sensitivity.routes[{index}].methods contains unsupported HTTP method {method:?}"
                        ),
                    });
                }
            }
        }
        for (index, rule) in self.sensitivity.resources.iter().enumerate() {
            validate_name(
                path,
                &format!("sensitivity.resources[{index}].name"),
                &rule.name,
            )?;
            validate_nonempty_list(
                path,
                &format!("sensitivity.resources[{index}].labels"),
                &rule.labels,
            )?;
            validate_matcher(
                path,
                &format!("sensitivity.resources[{index}].match"),
                &rule.matcher,
            )?;
            validate_optional_list(
                path,
                &format!("sensitivity.resources[{index}].reviewer_questions"),
                &rule.reviewer_questions,
            )?;
            validate_optional_list(
                path,
                &format!("sensitivity.resources[{index}].notes"),
                &rule.notes,
            )?;
        }
        Ok(())
    }
}

fn validate_name(path: &std::path::Path, field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::Validate {
            path: path.to_path_buf(),
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_nonempty_list(
    path: &std::path::Path,
    field: &str,
    values: &[String],
) -> Result<(), ConfigError> {
    if values.is_empty() {
        return Err(ConfigError::Validate {
            path: path.to_path_buf(),
            message: format!("{field} must not be empty"),
        });
    }
    validate_optional_list(path, field, values)
}

fn validate_optional_list(
    path: &std::path::Path,
    field: &str,
    values: &[String],
) -> Result<(), ConfigError> {
    if values.iter().any(|item| item.trim().is_empty()) {
        return Err(ConfigError::Validate {
            path: path.to_path_buf(),
            message: format!("{field} entries must not be empty"),
        });
    }
    Ok(())
}

fn validate_matcher(
    path: &std::path::Path,
    field: &str,
    matcher: &AuthorizationRuleMatch,
) -> Result<(), ConfigError> {
    if matcher.exact.is_empty() && matcher.contains.is_empty() {
        return Err(ConfigError::Validate {
            path: path.to_path_buf(),
            message: format!("{field} must include exact or contains"),
        });
    }
    if matcher
        .exact
        .iter()
        .chain(matcher.contains.iter())
        .any(|item| item.trim().is_empty())
    {
        return Err(ConfigError::Validate {
            path: path.to_path_buf(),
            message: format!("{field} entries must not be empty"),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("invalid config {path}: {message}")]
    Validate { path: PathBuf, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_config_uses_defaults() {
        let config: ScanConfig =
            serde_yaml::from_str("mode: enforce\n").expect("partial config should parse");

        assert_eq!(config.mode, ScanMode::Enforce);
        assert_eq!(config.include, Vec::<String>::new());
        assert_eq!(config.exclude, Vec::<String>::new());
        assert_eq!(config.limits, ScanLimits::default());
        assert_eq!(config.authorization, AuthorizationConfig::default());
        assert_eq!(config.sensitivity, SensitivityConfig::default());
        assert_eq!(config.drift, DriftConfig::default());
    }

    #[test]
    fn scan_limits_parse_all_budget_fields() {
        let config: ScanConfig = serde_yaml::from_str(
            r#"
limits:
  max_files: 42
  max_file_size_bytes: 1024
  max_total_bytes: 4096
  max_runtime_ms: 5000
"#,
        )
        .expect("scan limits should parse");

        assert_eq!(
            config.limits,
            ScanLimits {
                max_files: 42,
                max_file_size_bytes: 1024,
                max_total_bytes: 4096,
                max_runtime_ms: 5000,
            }
        );
    }

    #[test]
    fn unknown_config_fields_are_rejected() {
        let error = serde_yaml::from_str::<ScanConfig>("unknown_key: true\n")
            .expect_err("unknown fields should be rejected");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn drift_fail_on_uses_defaults_and_parses_overrides() {
        let default_config: ScanConfig =
            serde_yaml::from_str("").expect("default config should parse");
        assert_eq!(default_config.drift.fail_on, default_drift_fail_on());

        let config: ScanConfig = serde_yaml::from_str(
            r#"
drift:
  fail_on:
    - added_review_required_route
    - auth_downgrade
"#,
        )
        .expect("drift config should parse");

        assert_eq!(
            config.drift.fail_on,
            vec![
                DriftFailCategory::AddedReviewRequiredRoute,
                DriftFailCategory::AuthDowngrade,
            ]
        );
    }

    #[test]
    fn drift_fail_on_rejects_unknown_categories() {
        let error = serde_yaml::from_str::<ScanConfig>(
            r#"
drift:
  fail_on: [unknown_drift]
"#,
        )
        .expect_err("unknown drift category should fail");

        assert!(error.to_string().contains("unknown_drift"));
    }

    #[test]
    fn rich_authorization_rules_parse() {
        let config: ScanConfig = serde_yaml::from_str(
            r#"
authorization:
  rules:
    - name: custom permission
      evidence_type: permission_check
      mechanism: custom_permission_guard
      confidence: medium
      match:
        exact: [can_edit_account]
        contains: [permission]
      notes:
        - configured by project
"#,
        )
        .expect("authorization config should parse");

        let rule = &config.authorization.rules[0];
        assert_eq!(rule.name, "custom permission");
        assert_eq!(rule.evidence_type, EvidenceType::PermissionCheck);
        assert_eq!(rule.confidence, Some(Confidence::Medium));
        assert_eq!(rule.matcher.exact, vec!["can_edit_account"]);
        assert_eq!(rule.matcher.contains, vec!["permission"]);
    }

    #[test]
    fn unknown_authorization_rule_fields_are_rejected() {
        let error = serde_yaml::from_str::<ScanConfig>(
            r#"
authorization:
  rules:
    - name: custom
      evidence_type: authn
      mechanism: custom_guard
      unknown: true
      match:
        exact: [guard]
"#,
        )
        .expect_err("unknown rule fields should be rejected");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn invalid_authorization_evidence_type_is_rejected() {
        let error = serde_yaml::from_str::<ScanConfig>(
            r#"
authorization:
  rules:
    - name: custom
      evidence_type: not_a_type
      mechanism: custom_guard
      match:
        exact: [guard]
"#,
        )
        .expect_err("unknown evidence types should be rejected");

        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn authorization_rules_require_matchers() {
        let temp = std::env::temp_dir().join("authmap-config-empty-auth-rule.yml");
        std::fs::write(
            &temp,
            r#"
authorization:
  rules:
    - name: custom
      evidence_type: authn
      mechanism: custom_guard
      match: {}
"#,
        )
        .expect("test config should be written");

        let error = load_config(Some(temp.clone())).expect_err("empty matchers should be invalid");
        let _ = std::fs::remove_file(temp);

        assert!(
            error
                .to_string()
                .contains("authorization.rules[0].match must include exact or contains")
        );
    }

    #[test]
    fn scan_limits_reject_zero_values() {
        for (name, field) in [
            ("max-files", "max_files"),
            ("max-file-size", "max_file_size_bytes"),
            ("max-total-bytes", "max_total_bytes"),
            ("max-runtime", "max_runtime_ms"),
        ] {
            let temp = std::env::temp_dir().join(format!("authmap-config-{name}.yml"));
            std::fs::write(
                &temp,
                format!(
                    r#"
limits:
  {field}: 0
"#
                ),
            )
            .expect("test config should be written");

            let error = load_config(Some(temp.clone())).expect_err("zero limit should be invalid");
            let _ = std::fs::remove_file(temp);

            assert!(
                error
                    .to_string()
                    .contains(&format!("limits.{field} must be greater than zero")),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn rich_sensitivity_rules_parse_and_validate() {
        let temp = std::env::temp_dir().join("authmap-config-rich-sensitivity.yml");
        std::fs::write(
            &temp,
            r#"
sensitivity:
  routes:
    - name: account routes
      labels: [account_data, pii]
      match:
        contains: [/accounts]
      methods: [GET, PATCH]
      reviewer_questions:
        - Should account routes require ownership checks?
      notes:
        - project-specific sensitive route
  resources:
    - name: invoice writes
      labels: [financial]
      match:
        exact: [Invoice]
      reviewer_questions:
        - Should invoice writes require finance approval?
"#,
        )
        .expect("test config should be written");

        let (_, config) = load_config(Some(temp.clone())).expect("sensitivity config should load");
        let _ = std::fs::remove_file(temp);

        assert_eq!(config.sensitivity.routes[0].name, "account routes");
        assert_eq!(
            config.sensitivity.routes[0].labels,
            vec!["account_data", "pii"]
        );
        assert_eq!(config.sensitivity.routes[0].methods, vec!["GET", "PATCH"]);
        assert_eq!(config.sensitivity.resources[0].labels, vec!["financial"]);
    }

    #[test]
    fn sensitivity_rules_reject_empty_names_labels_and_matchers() {
        for (name, body, expected) in [
            (
                "empty-name",
                r#"
sensitivity:
  routes:
    - name: ""
      labels: [sensitive]
      match:
        exact: [/accounts]
"#,
                "sensitivity.routes[0].name must not be empty",
            ),
            (
                "empty-labels",
                r#"
sensitivity:
  routes:
    - name: accounts
      labels: []
      match:
        exact: [/accounts]
"#,
                "sensitivity.routes[0].labels must not be empty",
            ),
            (
                "empty-matcher",
                r#"
sensitivity:
  resources:
    - name: invoices
      labels: [financial]
      match: {}
"#,
                "sensitivity.resources[0].match must include exact or contains",
            ),
        ] {
            let temp = std::env::temp_dir().join(format!("authmap-config-{name}.yml"));
            std::fs::write(&temp, body).expect("test config should be written");

            let error = load_config(Some(temp.clone())).expect_err("config should be invalid");
            let _ = std::fs::remove_file(temp);

            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn sensitivity_rules_reject_empty_questions_and_invalid_methods() {
        for (name, body, expected) in [
            (
                "empty-question",
                r#"
sensitivity:
  routes:
    - name: accounts
      labels: [sensitive]
      match:
        exact: [/accounts]
      reviewer_questions: [""]
"#,
                "sensitivity.routes[0].reviewer_questions entries must not be empty",
            ),
            (
                "invalid-method",
                r#"
sensitivity:
  routes:
    - name: accounts
      labels: [sensitive]
      match:
        exact: [/accounts]
      methods: [FETCH]
"#,
                "sensitivity.routes[0].methods contains unsupported HTTP method",
            ),
        ] {
            let temp = std::env::temp_dir().join(format!("authmap-config-{name}.yml"));
            std::fs::write(&temp, body).expect("test config should be written");

            let error = load_config(Some(temp.clone())).expect_err("config should be invalid");
            let _ = std::fs::remove_file(temp);

            assert!(
                error.to_string().contains(expected),
                "expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn unknown_sensitivity_rule_fields_are_rejected() {
        let error = serde_yaml::from_str::<ScanConfig>(
            r#"
sensitivity:
  routes:
    - name: accounts
      labels: [sensitive]
      unknown: true
      match:
        exact: [/accounts]
"#,
        )
        .expect_err("unknown rule fields should be rejected");

        assert!(error.to_string().contains("unknown field"));
    }
}
