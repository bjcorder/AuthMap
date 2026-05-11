use authmap_core::{Diagnostic, Language, SourceFile};
use rayon::prelude::*;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ParsedFile {
    pub source: SourceFile,
    pub language: Language,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Default)]
pub struct ParseOutput {
    pub parsed_files: Vec<ParsedFile>,
    pub diagnostics: Vec<Diagnostic>,
}

pub trait ParserBackend: Send + Sync {
    fn parse(&self, source: &SourceFile, text: &str) -> Result<ParsedFile, ParseError>;
}

pub fn parse_files_in_parallel<B>(
    backend: &B,
    files: &[SourceFile],
    read_source: impl Fn(&SourceFile) -> Result<String, ParseError> + Send + Sync,
) -> ParseOutput
where
    B: ParserBackend,
{
    let mut parsed_or_errors = files
        .par_iter()
        .filter(|file| file.skipped.is_none())
        .map(|file| {
            let text = read_source(file)?;
            backend.parse(file, &text)
        })
        .collect::<Vec<_>>();

    let mut output = ParseOutput::default();
    for result in parsed_or_errors.drain(..) {
        match result {
            Ok(parsed) => output.parsed_files.push(parsed),
            Err(error) => output.diagnostics.push(error.into_diagnostic()),
        }
    }
    output
}

#[derive(Clone, Debug, Default)]
pub struct TreeSitterBackend;

impl ParserBackend for TreeSitterBackend {
    fn parse(&self, source: &SourceFile, _text: &str) -> Result<ParsedFile, ParseError> {
        Ok(ParsedFile {
            source: source.clone(),
            language: source.language,
            diagnostics: Vec::new(),
        })
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to read source {path}: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse source {path}: {message}")]
    Parse { path: String, message: String },
}

impl ParseError {
    pub fn into_diagnostic(self) -> Diagnostic {
        match self {
            ParseError::Read { path, message } => Diagnostic {
                code: "source_read_failed".to_string(),
                severity: authmap_core::DiagnosticSeverity::Warning,
                recoverability: authmap_core::Recoverability::Recoverable,
                span: Some(authmap_core::Span {
                    file: path,
                    line: 1,
                    column: 1,
                    byte_range: None,
                }),
                message,
            },
            ParseError::Parse { path, message } => Diagnostic {
                code: "source_parse_failed".to_string(),
                severity: authmap_core::DiagnosticSeverity::Warning,
                recoverability: authmap_core::Recoverability::Recoverable,
                span: Some(authmap_core::Span {
                    file: path,
                    line: 1,
                    column: 1,
                    byte_range: None,
                }),
                message,
            },
        }
    }
}
