use authmap_core::{Diagnostic, Language, SourceFile};
use rayon::prelude::*;
use thiserror::Error;
use tree_sitter::{Parser, Tree};

pub use tree_sitter::Node;

#[derive(Debug)]
pub struct ParsedFile {
    pub source: SourceFile,
    pub language: Language,
    pub text: String,
    pub syntax: Option<ParsedSyntax>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ParsedFile {
    pub fn root_node(&self) -> Option<Node<'_>> {
        match &self.syntax {
            Some(ParsedSyntax::TreeSitter(tree)) => Some(tree.root_node()),
            None => None,
        }
    }

    pub fn text_for(&self, node: Node<'_>) -> Option<&str> {
        node.utf8_text(self.text.as_bytes()).ok()
    }

    pub fn span_for(&self, node: Node<'_>) -> authmap_core::Span {
        let point = node.start_position();
        authmap_core::Span {
            file: self.source.path.clone(),
            line: point.row as u32 + 1,
            column: point.column as u32 + 1,
            byte_range: Some(authmap_core::ByteRange {
                start: node.start_byte() as u64,
                end: node.end_byte() as u64,
            }),
        }
    }
}

#[derive(Debug)]
pub enum ParsedSyntax {
    TreeSitter(Tree),
}

#[derive(Debug, Default)]
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
    fn parse(&self, source: &SourceFile, text: &str) -> Result<ParsedFile, ParseError> {
        let syntax = match source.language {
            Language::JavaScript | Language::JavaScriptReact => {
                parse_with_language(source, text, tree_sitter_javascript::LANGUAGE.into())?
            }
            Language::Python => {
                parse_with_language(source, text, tree_sitter_python::LANGUAGE.into())?
            }
            Language::TypeScript => parse_with_language(
                source,
                text,
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            )?,
            Language::TypeScriptReact => {
                parse_with_language(source, text, tree_sitter_typescript::LANGUAGE_TSX.into())?
            }
            _ => None,
        };

        Ok(ParsedFile {
            source: source.clone(),
            language: source.language,
            text: text.to_string(),
            syntax,
            diagnostics: Vec::new(),
        })
    }
}

fn parse_with_language(
    source: &SourceFile,
    text: &str,
    language: tree_sitter::Language,
) -> Result<Option<ParsedSyntax>, ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::Parse {
            path: source.path.clone(),
            message: error.to_string(),
        })?;
    let tree = parser.parse(text, None).ok_or_else(|| ParseError::Parse {
        path: source.path.clone(),
        message: "tree-sitter returned no parse tree".to_string(),
    })?;
    Ok(Some(ParsedSyntax::TreeSitter(tree)))
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
