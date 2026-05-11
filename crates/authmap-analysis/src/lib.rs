use std::fs;

use authmap_adapters::AdapterRegistry;
use authmap_config::ScanPlan;
use authmap_core::{AuthMapDocument, Diagnostic, Evidence, Mutation, ScanMetadata};
use authmap_discovery::discover_sources;
use authmap_parsers::{ParseError, TreeSitterBackend, parse_files_in_parallel};
use thiserror::Error;

pub trait EvidenceExtractor: Send + Sync {
    fn extract_evidence(&self, input: &AnalysisInput) -> AnalysisFacts;
}

pub trait MutationExtractor: Send + Sync {
    fn extract_mutations(&self, input: &AnalysisInput) -> AnalysisFacts;
}

#[derive(Clone, Debug, Default)]
pub struct AnalysisInput {
    pub routes: Vec<authmap_core::Route>,
    pub evidence: Vec<Evidence>,
    pub mutations: Vec<Mutation>,
}

#[derive(Clone, Debug, Default)]
pub struct AnalysisFacts {
    pub evidence: Vec<Evidence>,
    pub mutations: Vec<Mutation>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn run_scan(plan: &ScanPlan) -> Result<AuthMapDocument, ScanError> {
    let discovery = discover_sources(plan)?;
    let backend = TreeSitterBackend;
    let parse_output = parse_files_in_parallel(&backend, &discovery.files, |file| {
        fs::read_to_string(&file.path).map_err(|source| ParseError::Read {
            path: file.path.clone(),
            message: source.to_string(),
        })
    });

    let _adapter_registry = AdapterRegistry::built_in();

    let mut document = AuthMapDocument::empty(ScanMetadata {
        mode: plan.config.mode,
        target_roots: plan
            .targets
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect(),
        config_path: plan
            .config_path
            .as_ref()
            .map(|path| path.to_string_lossy().replace('\\', "/")),
        ..ScanMetadata::default()
    });
    document.source_files = discovery.files;
    document.diagnostics = parse_output.diagnostics;
    document.diagnostics.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then(left.message.cmp(&right.message))
    });
    Ok(document)
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error(transparent)]
    Discovery(#[from] authmap_discovery::DiscoveryError),
}

impl ScanError {
    pub fn is_target_unavailable(&self) -> bool {
        matches!(
            self,
            ScanError::Discovery(
                authmap_discovery::DiscoveryError::TargetUnavailable { .. }
                    | authmap_discovery::DiscoveryError::UnsupportedTarget { .. }
            )
        )
    }

    pub fn is_empty_target(&self) -> bool {
        matches!(
            self,
            ScanError::Discovery(authmap_discovery::DiscoveryError::EmptyTarget { .. })
        )
    }
}
