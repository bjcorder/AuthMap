use std::path::PathBuf;

use authmap_core::{Confidence, EvidenceType, ScanMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub limits: ScanLimits,
    pub authorization: AuthorizationConfig,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Advisory,
            include: Vec::new(),
            exclude: Vec::new(),
            limits: ScanLimits::default(),
            authorization: AuthorizationConfig::default(),
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanLimits {
    pub max_files: usize,
    pub max_file_size_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_files: 50_000,
            max_file_size_bytes: 2 * 1024 * 1024,
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
        for rule in &self.authorization.rules {
            if rule.name.trim().is_empty() {
                return Err(ConfigError::Validate {
                    path: path.to_path_buf(),
                    message: "authorization.rules[].name must not be empty".to_string(),
                });
            }
            if rule.mechanism.trim().is_empty() {
                return Err(ConfigError::Validate {
                    path: path.to_path_buf(),
                    message: format!(
                        "authorization rule {:?} mechanism must not be empty",
                        rule.name
                    ),
                });
            }
            if rule.matcher.exact.is_empty() && rule.matcher.contains.is_empty() {
                return Err(ConfigError::Validate {
                    path: path.to_path_buf(),
                    message: format!(
                        "authorization rule {:?} must include match.exact or match.contains",
                        rule.name
                    ),
                });
            }
            if rule
                .matcher
                .exact
                .iter()
                .chain(rule.matcher.contains.iter())
                .any(|item| item.trim().is_empty())
            {
                return Err(ConfigError::Validate {
                    path: path.to_path_buf(),
                    message: format!(
                        "authorization rule {:?} match entries must not be empty",
                        rule.name
                    ),
                });
            }
        }
        Ok(())
    }
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
    }

    #[test]
    fn unknown_config_fields_are_rejected() {
        let error = serde_yaml::from_str::<ScanConfig>("unknown_key: true\n")
            .expect_err("unknown fields should be rejected");

        assert!(error.to_string().contains("unknown field"));
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

        assert!(error.to_string().contains("match.exact or match.contains"));
    }
}
