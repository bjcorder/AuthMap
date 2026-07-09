use std::cell::RefCell;
use std::collections::BTreeMap;

use authmap_core::{
    ByteRange, Diagnostic, DiagnosticCategory, DiagnosticSeverity, Language, Recoverability,
    SourceFile, Span, diagnostic_codes,
};
use rayon::prelude::*;
use thiserror::Error;
use tree_sitter::{Node, Parser, Tree};

thread_local! {
    static TREE_SITTER_PARSERS: RefCell<BTreeMap<Language, Parser>> = RefCell::new(BTreeMap::new());
}

#[derive(Debug)]
pub struct ParsedFile {
    pub source: SourceFile,
    pub language: Language,
    pub text: String,
    pub tree: Option<Tree>,
    pub status: ParseStatus,
    pub diagnostics: Vec<Diagnostic>,
}

impl ParsedFile {
    pub fn root_node(&self) -> Option<Node<'_>> {
        self.tree.as_ref().map(|tree| tree.root_node())
    }

    pub fn text_for(&self, node: Node<'_>) -> Option<&str> {
        node.utf8_text(self.text.as_bytes()).ok()
    }

    pub fn span_for(&self, node: Node<'_>) -> Span {
        span_for_node(&self.source, node)
    }

    pub fn tree(&self) -> Option<&Tree> {
        self.tree.as_ref()
    }

    pub fn span_for_node(&self, node: Node<'_>) -> Span {
        span_for_node(&self.source, node)
    }

    pub fn snippet(&self, span: &Span) -> Option<&str> {
        let range = span.byte_range?;
        self.text.get(range.start as usize..range.end as usize)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseStatus {
    Parsed,
    Recovered,
    TextOnly,
    Unsupported,
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
            Ok(parsed) => {
                output.diagnostics.extend(parsed.diagnostics.clone());
                output.parsed_files.push(parsed);
            }
            Err(error) => output.diagnostics.push(error.into_diagnostic()),
        }
    }
    output
}

pub fn parse_files_in_parallel_selective<B>(
    backend: &B,
    files: &[SourceFile],
    read_source: impl Fn(&SourceFile) -> Result<String, ParseError> + Send + Sync,
    should_parse: impl Fn(&SourceFile, &str) -> bool + Send + Sync,
) -> ParseOutput
where
    B: ParserBackend,
{
    let mut parsed_or_errors = files
        .par_iter()
        .filter(|file| file.skipped.is_none())
        .map(|file| {
            let text = read_source(file)?;
            if should_parse(file, &text) {
                backend.parse(file, &text)
            } else {
                Ok(ParsedFile {
                    source: file.clone(),
                    language: file.language,
                    text,
                    tree: None,
                    status: ParseStatus::TextOnly,
                    diagnostics: Vec::new(),
                })
            }
        })
        .collect::<Vec<_>>();

    let mut output = ParseOutput::default();
    for result in parsed_or_errors.drain(..) {
        match result {
            Ok(parsed) => {
                output.diagnostics.extend(parsed.diagnostics.clone());
                output.parsed_files.push(parsed);
            }
            Err(error) => output.diagnostics.push(error.into_diagnostic()),
        }
    }
    output
}

pub fn parse_diagnostics_in_parallel<B>(
    backend: &B,
    files: &[SourceFile],
    read_source: impl Fn(&SourceFile) -> Result<String, ParseError> + Send + Sync,
) -> Vec<Diagnostic>
where
    B: ParserBackend,
{
    let mut diagnostics = files
        .par_iter()
        .filter(|file| file.skipped.is_none())
        .flat_map(|file| {
            let result = read_source(file).and_then(|text| backend.parse(file, &text));
            match result {
                Ok(parsed) => parsed.diagnostics,
                Err(error) => vec![error.into_diagnostic()],
            }
        })
        .collect::<Vec<_>>();
    diagnostics.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
    diagnostics
}

#[derive(Clone, Debug, Default)]
pub struct TreeSitterBackend;

impl ParserBackend for TreeSitterBackend {
    fn parse(&self, source: &SourceFile, text: &str) -> Result<ParsedFile, ParseError> {
        let Some(language) = language_for(source.language) else {
            let diagnostic = diagnostic(
                diagnostic_codes::PARSER_SOURCE_LANGUAGE_UNSUPPORTED,
                source.path.clone(),
                DiagnosticSeverity::Warning,
                None,
                format!("no parser backend is configured for {:?}", source.language),
            );
            return Ok(ParsedFile {
                source: source.clone(),
                language: source.language,
                text: text.to_string(),
                tree: None,
                status: ParseStatus::Unsupported,
                diagnostics: vec![diagnostic],
            });
        };

        let tree = parse_with_thread_local_parser(source, language, text)?;
        let mut diagnostics = Vec::new();
        let status = if tree.root_node().has_error() {
            let span = first_error_node(tree.root_node()).map(|node| span_for_node(source, node));
            diagnostics.push(diagnostic(
                diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED,
                source.path.clone(),
                DiagnosticSeverity::Warning,
                span,
                "source parsed with syntax errors; partial tree is available".to_string(),
            ));
            ParseStatus::Recovered
        } else {
            ParseStatus::Parsed
        };

        Ok(ParsedFile {
            source: source.clone(),
            language: source.language,
            text: text.to_string(),
            tree: Some(tree),
            status,
            diagnostics,
        })
    }
}

fn parse_with_thread_local_parser(
    source: &SourceFile,
    grammar: tree_sitter::Language,
    text: &str,
) -> Result<Tree, ParseError> {
    TREE_SITTER_PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        if !parsers.contains_key(&source.language) {
            let mut parser = Parser::new();
            parser
                .set_language(&grammar)
                .map_err(|source_error| ParseError::Parse {
                    path: source.path.clone(),
                    message: format!("failed to initialize parser grammar: {source_error}"),
                })?;
            parsers.insert(source.language, parser);
        }

        parsers
            .get_mut(&source.language)
            .expect("parser should be initialized")
            .parse(text, None)
            .ok_or_else(|| ParseError::Parse {
                path: source.path.clone(),
                message: "tree-sitter did not return a parse tree".to_string(),
            })
    })
}

pub fn span_for_node(source: &SourceFile, node: Node<'_>) -> Span {
    let start = node.start_position();
    Span {
        file: source.path.clone(),
        line: (start.row + 1) as u32,
        column: (start.column + 1) as u32,
        byte_range: Some(ByteRange {
            start: node.start_byte() as u64,
            end: node.end_byte() as u64,
        }),
    }
}

fn language_for(language: Language) -> Option<tree_sitter::Language> {
    match language {
        Language::Python => Some(tree_sitter_python::LANGUAGE.into()),
        Language::JavaScript | Language::JavaScriptReact => {
            Some(tree_sitter_javascript::LANGUAGE.into())
        }
        Language::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Language::TypeScriptReact => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Language::Unknown => None,
    }
}

fn diagnostic(
    code: impl Into<String>,
    path: String,
    severity: DiagnosticSeverity,
    span: Option<Span>,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic {
        category: DiagnosticCategory::Parser,
        code: code.into(),
        severity,
        recoverability: Recoverability::Recoverable,
        span: span.or(Some(Span {
            file: path,
            line: 1,
            column: 1,
            byte_range: None,
        })),
        message: message.into(),
    }
}

fn first_error_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.is_error() || node.is_missing() {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.has_error()
            && let Some(error) = first_error_node(child)
        {
            return Some(error);
        }
    }
    None
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
            ParseError::Read { path, message } => diagnostic(
                diagnostic_codes::PARSER_SOURCE_READ_FAILED,
                path,
                DiagnosticSeverity::Error,
                None,
                message,
            ),
            ParseError::Parse { path, message } => diagnostic(
                diagnostic_codes::PARSER_SOURCE_PARSE_FAILED,
                path,
                DiagnosticSeverity::Error,
                None,
                message,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authmap_core::{ProjectHint, SkipReason, diagnostic_codes};

    fn source(path: &str, language: Language) -> SourceFile {
        SourceFile {
            path: path.to_string(),
            language,
            size_bytes: 0,
            sha256: None,
            project_hints: Vec::<ProjectHint>::new(),
            skipped: None::<SkipReason>,
        }
    }

    #[test]
    fn parses_supported_languages_without_diagnostics() {
        let backend = TreeSitterBackend;
        for (path, language, text) in [
            ("app.py", Language::Python, "def route():\n    return 1\n"),
            (
                "app.js",
                Language::JavaScript,
                "export function route() { return 1; }\n",
            ),
            (
                "app.ts",
                Language::TypeScript,
                "export function route(): number { return 1; }\n",
            ),
            (
                "app.tsx",
                Language::TypeScriptReact,
                "export function View() { return <div />; }\n",
            ),
        ] {
            let parsed = backend
                .parse(&source(path, language), text)
                .expect("source should parse");
            assert_eq!(parsed.status, ParseStatus::Parsed);
            assert!(parsed.tree().is_some());
            assert!(parsed.root_node().is_some());
            assert!(parsed.diagnostics.is_empty());
        }
    }

    #[test]
    fn invalid_source_returns_partial_tree_and_recovery_diagnostic() {
        let backend = TreeSitterBackend;
        let parsed = backend
            .parse(&source("broken.py", Language::Python), "def broken(:\n")
            .expect("recoverable parse should return a parsed file");

        assert_eq!(parsed.status, ParseStatus::Recovered);
        assert!(parsed.tree().is_some());
        assert_eq!(
            parsed.diagnostics[0].code,
            diagnostic_codes::PARSER_SOURCE_PARSE_RECOVERED
        );
    }

    #[test]
    fn recovery_diagnostic_points_to_error_node_when_available() {
        let backend = TreeSitterBackend;
        let parsed = backend
            .parse(
                &source("broken.py", Language::Python),
                "def ok():\n    return 1\ndef broken(:\n",
            )
            .expect("recoverable parse should return a parsed file");

        assert_eq!(parsed.status, ParseStatus::Recovered);
        assert_eq!(
            parsed.diagnostics[0]
                .span
                .as_ref()
                .expect("recovery diagnostic should have a span")
                .line,
            3
        );
    }

    #[test]
    fn unsupported_language_returns_recoverable_diagnostic() {
        let backend = TreeSitterBackend;
        let parsed = backend
            .parse(&source("README.md", Language::Unknown), "# hello\n")
            .expect("unsupported language should not panic");

        assert_eq!(parsed.status, ParseStatus::Unsupported);
        assert!(parsed.tree().is_none());
        assert_eq!(
            parsed.diagnostics[0].code,
            diagnostic_codes::PARSER_SOURCE_LANGUAGE_UNSUPPORTED
        );
    }

    #[test]
    fn selective_parse_keeps_text_without_building_unneeded_trees() {
        let backend = TreeSitterBackend;
        let files = vec![
            source("parsed.py", Language::Python),
            source("text_only.py", Language::Python),
        ];
        let output = parse_files_in_parallel_selective(
            &backend,
            &files,
            |file| Ok(format!("# {}\n", file.path)),
            |file, _| file.path == "parsed.py",
        );

        let parsed = output
            .parsed_files
            .iter()
            .find(|file| file.source.path == "parsed.py")
            .expect("parsed file should be present");
        assert_eq!(parsed.status, ParseStatus::Parsed);
        assert!(parsed.tree().is_some());

        let text_only = output
            .parsed_files
            .iter()
            .find(|file| file.source.path == "text_only.py")
            .expect("text-only file should be present");
        assert_eq!(text_only.status, ParseStatus::TextOnly);
        assert!(text_only.tree().is_none());
        assert_eq!(text_only.text, "# text_only.py\n");
        assert!(output.diagnostics.is_empty());
    }

    #[test]
    fn span_helper_uses_one_based_points_and_zero_based_byte_ranges() {
        let backend = TreeSitterBackend;
        let parsed = backend
            .parse(
                &source("src/app.js", Language::JavaScript),
                "\nfunction route() {}\n",
            )
            .expect("source should parse");
        let root = parsed.tree().expect("tree should exist").root_node();
        let function = root
            .named_child(0)
            .expect("root should contain the function declaration");
        let span = parsed.span_for_node(function);

        assert_eq!(span.file, "src/app.js");
        assert_eq!(span.line, 2);
        assert_eq!(span.column, 1);
        assert_eq!(span.byte_range.expect("byte range should exist").start, 1);
        assert_eq!(parsed.snippet(&span), Some("function route() {}"));
    }
}
