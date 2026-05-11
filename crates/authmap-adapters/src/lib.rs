use authmap_core::{Diagnostic, Route};
use authmap_parsers::ParsedFile;

#[derive(Clone, Debug, Default)]
pub struct AdapterContext {
    pub enabled_frameworks: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AdapterOutput {
    pub routes: Vec<Route>,
    pub diagnostics: Vec<Diagnostic>,
}

pub trait FrameworkAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn discover_routes(&self, parsed: &ParsedFile, context: &AdapterContext) -> AdapterOutput;
}

#[derive(Clone, Debug, Default)]
pub struct AdapterRegistry {
    adapters: Vec<&'static str>,
}

impl AdapterRegistry {
    pub fn built_in() -> Self {
        Self {
            adapters: vec!["fastapi", "express", "django_drf", "nextjs_app_router"],
        }
    }

    pub fn names(&self) -> &[&'static str] {
        &self.adapters
    }
}
