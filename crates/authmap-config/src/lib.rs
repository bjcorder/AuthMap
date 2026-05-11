use std::path::PathBuf;

use authmap_core::ScanMode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub limits: ScanLimits,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Advisory,
            include: Vec::new(),
            exclude: Vec::new(),
            limits: ScanLimits::default(),
        }
    }
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
    }

    #[test]
    fn unknown_config_fields_are_rejected() {
        let error = serde_yaml::from_str::<ScanConfig>("unknown_key: true\n")
            .expect_err("unknown fields should be rejected");

        assert!(error.to_string().contains("unknown field"));
    }
}
