use std::collections::{BTreeMap, BTreeSet};

use authmap_core::{
    Confidence, Diagnostic, DiagnosticCategory, DiagnosticSeverity, Framework, Recoverability,
    Route, SourceEvidence, Span, SymbolRef, diagnostic_codes,
};
use authmap_parsers::ParsedFile;
use tree_sitter::Node;

use crate::{AdapterContext, AdapterOutput, FrameworkAdapter};

#[derive(Clone, Debug, Default)]
pub struct NextJsAdapter;

impl FrameworkAdapter for NextJsAdapter {
    fn name(&self) -> &'static str {
        "nextjs"
    }

    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        _context: &AdapterContext,
    ) -> AdapterOutput {
        let mut routes = Vec::new();
        let mut diagnostics = Vec::new();
        let mut seen = BTreeSet::<(String, String, String)>::new();
        let module_index = build_js_module_index(parsed_files);
        let parsed_by_path = parsed_files
            .iter()
            .map(|parsed| (parsed.source.path.clone(), parsed))
            .collect::<BTreeMap<_, _>>();

        for parsed in parsed_files.iter().filter(|file| is_js_like(file.language)) {
            if !is_next_route_file(&parsed.source.path) {
                continue;
            }
            let path_info = route_path_for_file(&parsed.source.path);
            diagnostics.extend(path_info.diagnostics.clone());
            let Some(root) = parsed.root_node() else {
                continue;
            };
            let definitions = collect_definitions(parsed, root);
            for export in collect_route_exports(
                parsed,
                root,
                &definitions,
                &module_index,
                &parsed_by_path,
                &mut diagnostics,
            ) {
                let key = (
                    parsed.source.path.clone(),
                    export.method.clone(),
                    export.handler.name.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                routes.push(build_route(parsed, &path_info, export));
            }
        }

        routes.sort_by_key(route_sort_key);
        for (index, route) in routes.iter_mut().enumerate() {
            route.id = format!("route_{:04}", index + 1);
        }
        diagnostics.sort_by_key(diagnostic_sort_key);

        AdapterOutput {
            routes,
            diagnostics,
            ..AdapterOutput::default()
        }
    }
}

#[derive(Clone, Debug)]
struct PathInfo {
    path: String,
    confidence: Confidence,
    notes: Vec<String>,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug)]
struct Definition {
    span: Span,
}

#[derive(Clone, Debug)]
struct RouteExport {
    method: String,
    handler: SymbolRef,
    export_kind: ExportKind,
    wrapper: Option<String>,
    span: Span,
    confidence: Confidence,
    notes: Vec<String>,
}

impl RouteExport {
    fn reexported_as(mut self, method: &str, span: Span) -> Self {
        self.method = method.to_string();
        self.span = span;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportKind {
    Function,
    ConstFunction,
    ReExport,
    Wrapped,
}

fn build_route(parsed: &ParsedFile, path_info: &PathInfo, export: RouteExport) -> Route {
    let confidence = weaker_confidence(path_info.confidence, export.confidence);
    let mut notes = path_info.notes.clone();
    notes.extend(export.notes.clone());
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.nextjs".to_string(),
        serde_json::json!({
            "route_file": parsed.source.path,
            "export_name": export.method,
            "export_kind": export_kind_name(export.export_kind),
            "wrapper": export.wrapper,
        }),
    );
    let source_evidence = vec![SourceEvidence {
        mechanism: "nextjs_route_handler_export".to_string(),
        symbol: Some(export.handler.clone()),
        span: Some(export.span.clone()),
        confidence,
        notes: notes.clone(),
        extensions: authmap_core::ExtensionMap::new(),
    }];

    Route {
        id: String::new(),
        framework: Framework::NextJs,
        method: export.method,
        path: path_info.path.clone(),
        name: None,
        tags: Vec::new(),
        middleware: Vec::new(),
        params: Vec::new(),
        declared_protection: Vec::new(),
        handler: Some(export.handler),
        span: Some(export.span),
        source_evidence,
        confidence,
        notes,
        extensions,
    }
}

fn collect_route_exports(
    parsed: &ParsedFile,
    root: Node<'_>,
    definitions: &BTreeMap<String, Definition>,
    module_index: &BTreeMap<String, String>,
    parsed_by_path: &BTreeMap<String, &ParsedFile>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<RouteExport> {
    let mut exports = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "export_statement" {
            collect_export_statement(
                parsed,
                node,
                definitions,
                module_index,
                parsed_by_path,
                diagnostics,
                &mut exports,
            );
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    exports
}

fn collect_export_statement(
    parsed: &ParsedFile,
    node: Node<'_>,
    definitions: &BTreeMap<String, Definition>,
    module_index: &BTreeMap<String, String>,
    parsed_by_path: &BTreeMap<String, &ParsedFile>,
    diagnostics: &mut Vec<Diagnostic>,
    exports: &mut Vec<RouteExport>,
) {
    for child in named_children(node) {
        match child.kind() {
            "function_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name")
                    && let Some(name) = parsed.text_for(name_node)
                    && is_http_method(name)
                {
                    exports.push(RouteExport {
                        method: name.to_string(),
                        handler: SymbolRef {
                            name: name.to_string(),
                            span: Some(parsed.span_for(name_node)),
                        },
                        export_kind: ExportKind::Function,
                        wrapper: None,
                        span: parsed.span_for(child),
                        confidence: Confidence::High,
                        notes: Vec::new(),
                    });
                    return;
                }
            }
            "lexical_declaration" => {
                collect_exported_variables(parsed, child, diagnostics, exports);
                return;
            }
            _ => {}
        }
    }

    if let Some(specifiers) = export_clause_text(parsed, node) {
        collect_export_clause(
            parsed,
            node,
            specifiers,
            definitions,
            module_index,
            parsed_by_path,
            diagnostics,
            exports,
        );
    }
}

fn collect_exported_variables(
    parsed: &ParsedFile,
    declaration: Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    exports: &mut Vec<RouteExport>,
) {
    for node in top_level_variable_declarators(declaration) {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let Some(name) = parsed.text_for(name_node) else {
            continue;
        };
        if is_http_method(name) {
            exports.push(route_export_from_variable(
                parsed,
                node,
                name,
                name_node,
                diagnostics,
            ));
        }
    }
}

fn top_level_variable_declarators(declaration: Node<'_>) -> Vec<Node<'_>> {
    let mut declarators = Vec::new();
    let mut stack = vec![declaration];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "arrow_function" | "function" | "function_expression"
        ) {
            continue;
        }
        if node.kind() == "variable_declarator" {
            declarators.push(node);
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor).filter(|child| child.is_named()));
    }
    declarators
}

fn route_export_from_variable(
    parsed: &ParsedFile,
    node: Node<'_>,
    method: &str,
    name_node: Node<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> RouteExport {
    let value = node.child_by_field_name("value");
    let mut export_kind = ExportKind::ReExport;
    let mut wrapper = None;
    let mut confidence = Confidence::High;
    let mut notes = Vec::new();
    let mut handler = SymbolRef {
        name: method.to_string(),
        span: Some(parsed.span_for(name_node)),
    };

    match value.map(|value| value.kind()) {
        Some("arrow_function" | "function" | "function_expression") => {
            export_kind = ExportKind::ConstFunction;
        }
        Some("identifier") => {
            if let Some(value) = value
                && let Some(local_name) = parsed.text_for(value)
            {
                handler = SymbolRef {
                    name: local_name.to_string(),
                    span: Some(parsed.span_for(value)),
                };
                export_kind = ExportKind::ReExport;
            }
        }
        Some("call_expression") => {
            export_kind = ExportKind::Wrapped;
            confidence = Confidence::Medium;
            notes.push(
                "Next.js route handler export is wrapped; wrapper behavior requires review"
                    .to_string(),
            );
            if let Some(value) = value {
                let function = value.child_by_field_name("function");
                wrapper = function
                    .and_then(|function| parsed.text_for(function))
                    .map(terminal_symbol_name);
                if let Some(first_arg) = call_arguments(value).first().copied()
                    && let Some(arg_name) = symbol_name(parsed, first_arg)
                {
                    handler = SymbolRef {
                        name: arg_name,
                        span: Some(parsed.span_for(first_arg)),
                    };
                }
            }
        }
        Some(_) | None => {
            confidence = Confidence::Medium;
            notes.push(
                "Next.js route handler export value is dynamic or unsupported; review required"
                    .to_string(),
            );
            diagnostics.push(diagnostic(
                diagnostic_codes::NEXTJS_DYNAMIC_ROUTE_EXPORT,
                parsed.span_for(node),
                "Next.js route handler export value is dynamic or unsupported",
            ));
        }
    }

    RouteExport {
        method: method.to_string(),
        handler,
        export_kind,
        wrapper,
        span: parsed.span_for(node),
        confidence,
        notes,
    }
}

fn collect_export_clause(
    parsed: &ParsedFile,
    node: Node<'_>,
    specifiers: &str,
    definitions: &BTreeMap<String, Definition>,
    module_index: &BTreeMap<String, String>,
    parsed_by_path: &BTreeMap<String, &ParsedFile>,
    diagnostics: &mut Vec<Diagnostic>,
    exports: &mut Vec<RouteExport>,
) {
    let specifiers = specifiers.trim();
    if !specifiers.starts_with('{') || !specifiers.ends_with('}') {
        return;
    }
    let specifiers = &specifiers[1..specifiers.len() - 1];
    let external_module = export_module_literal(parsed, node);
    let external_file =
        external_module.and_then(|module| resolve_js_module(parsed, module_index, module));
    let external_definitions = external_file
        .as_ref()
        .and_then(|file| parsed_by_path.get(file))
        .and_then(|external| {
            external
                .root_node()
                .map(|root| collect_definitions(external, root))
        });
    let unresolved_external_module = external_module.is_some() && external_file.is_none();
    if unresolved_external_module {
        diagnostics.push(diagnostic(
            diagnostic_codes::NEXTJS_EXTERNAL_REEXPORT_UNRESOLVED,
            parsed.span_for(node),
            "Next.js route handler re-export target could not be resolved statically",
        ));
    }
    for specifier in specifiers
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (local, exported) = specifier
            .split_once(" as ")
            .map_or((specifier, specifier), |(local, exported)| {
                (local.trim(), exported.trim())
            });
        if !is_http_method(exported) {
            continue;
        }
        if let Some(external) = external_file
            .as_ref()
            .and_then(|file| parsed_by_path.get(file))
            .and_then(|external| resolved_external_route_export(external, local))
        {
            exports.push(external.reexported_as(exported, parsed.span_for(node)));
            continue;
        }
        let definition = external_definitions
            .as_ref()
            .and_then(|definitions| definitions.get(local))
            .or_else(|| definitions.get(local));
        let unresolved_external = external_module.is_some() && definition.is_none();
        if unresolved_external && !unresolved_external_module {
            diagnostics.push(diagnostic(
                diagnostic_codes::NEXTJS_EXTERNAL_REEXPORT_UNRESOLVED,
                parsed.span_for(node),
                "Next.js route handler re-export target could not be analyzed statically",
            ));
        }
        exports.push(RouteExport {
            method: exported.to_string(),
            handler: SymbolRef {
                name: local.to_string(),
                span: definition
                    .map(|definition| definition.span.clone())
                    .or_else(|| Some(parsed.span_for(node))),
            },
            export_kind: ExportKind::ReExport,
            wrapper: None,
            span: parsed.span_for(node),
            confidence: if unresolved_external {
                Confidence::Medium
            } else {
                Confidence::High
            },
            notes: if unresolved_external {
                vec![
                    "Next.js route handler re-export target could not be analyzed statically"
                        .to_string(),
                ]
            } else {
                Vec::new()
            },
        });
    }
}

fn resolved_external_route_export(parsed: &ParsedFile, method: &str) -> Option<RouteExport> {
    let root = parsed.root_node()?;
    let mut diagnostics = Vec::new();
    let definitions = collect_definitions(parsed, root);
    let empty_module_index = BTreeMap::new();
    let empty_parsed_by_path = BTreeMap::new();
    collect_route_exports(
        parsed,
        root,
        &definitions,
        &empty_module_index,
        &empty_parsed_by_path,
        &mut diagnostics,
    )
    .into_iter()
    .find(|item| item.method == method)
}

fn export_clause_text<'a>(parsed: &'a ParsedFile, node: Node<'_>) -> Option<&'a str> {
    if parsed
        .text_for(node)
        .is_some_and(|text| text.trim_start().starts_with("export type"))
    {
        return None;
    }
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "export_clause")
        .and_then(|child| parsed.text_for(child))
        .or_else(|| {
            parsed.text_for(node).and_then(|text| {
                text.trim()
                    .strip_prefix("export")
                    .and_then(|rest| rest.split_once('}').map(|(items, _)| items))
                    .map(|items| {
                        let start = text.find('{').unwrap_or(0);
                        &text[start..start + items.len() + 2]
                    })
            })
        })
}

fn collect_definitions(parsed: &ParsedFile, root: Node<'_>) -> BTreeMap<String, Definition> {
    let mut definitions = BTreeMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && let Some(name) = parsed.text_for(name_node)
                {
                    definitions.insert(
                        name.to_string(),
                        Definition {
                            span: parsed.span_for(name_node),
                        },
                    );
                }
            }
            "variable_declarator" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && let Some(value) = node.child_by_field_name("value")
                    && matches!(
                        value.kind(),
                        "arrow_function" | "function" | "function_expression"
                    )
                    && let Some(name) = parsed.text_for(name_node)
                {
                    definitions.insert(
                        name.to_string(),
                        Definition {
                            span: parsed.span_for(name_node),
                        },
                    );
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    definitions
}

fn build_js_module_index(parsed_files: &[ParsedFile]) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for parsed in parsed_files.iter().filter(|file| is_js_like(file.language)) {
        let normalized = parsed.source.path.replace('\\', "/");
        let Some(stem) = strip_js_extension(&normalized) else {
            continue;
        };
        index.insert(stem.to_string(), parsed.source.path.clone());
        if let Some(index_stem) = stem.strip_suffix("/index") {
            index.insert(index_stem.to_string(), parsed.source.path.clone());
        }
    }
    index
}

fn strip_js_extension(path: &str) -> Option<&str> {
    [".js", ".jsx", ".ts", ".tsx"]
        .iter()
        .find_map(|extension| path.strip_suffix(extension))
}

fn export_module_literal<'a>(parsed: &'a ParsedFile, node: Node<'_>) -> Option<&'a str> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "string")
        .and_then(|string| js_string_literal(parsed, string))
}

fn js_string_literal<'a>(parsed: &'a ParsedFile, node: Node<'_>) -> Option<&'a str> {
    let text = parsed.text_for(node)?.trim();
    if text.len() < 2 {
        return None;
    }
    let quote = text.as_bytes()[0] as char;
    if !matches!(quote, '"' | '\'' | '`') || !text.ends_with(quote) {
        return None;
    }
    Some(&text[1..text.len() - 1])
}

fn resolve_js_module(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
    module: &str,
) -> Option<String> {
    if !module.starts_with('.') {
        return None;
    }
    let current = parsed.source.path.replace('\\', "/");
    let current_dir = current.rsplit_once('/').map_or("", |(dir, _)| dir);
    let candidate = normalize_js_module_path(current_dir, module);
    module_index.get(&candidate).cloned()
}

fn normalize_js_module_path(current_dir: &str, module: &str) -> String {
    let is_absolute = current_dir.starts_with('/');
    let mut parts = current_dir
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for part in module.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_string()),
        }
    }
    let normalized = parts.join("/");
    if is_absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

fn route_path_for_file(path: &str) -> PathInfo {
    let normalized = path.replace('\\', "/");
    let parts = normalized.split('/').collect::<Vec<_>>();
    let app_indexes = parts
        .iter()
        .enumerate()
        .filter_map(|(index, part)| (*part == "app").then_some(index))
        .collect::<Vec<_>>();
    let app_index = app_indexes.first().copied();
    let Some(app_index) = app_index else {
        return PathInfo {
            path: "/".to_string(),
            confidence: Confidence::Medium,
            notes: vec!["Next.js route file path did not contain an app segment".to_string()],
            diagnostics: Vec::new(),
        };
    };
    let mut confidence = Confidence::High;
    let mut notes = Vec::new();
    let mut diagnostics = Vec::new();
    if app_indexes.len() > 1 {
        confidence = Confidence::Medium;
        notes.push(
            "Next.js route file path contains nested app segments; first app segment was used"
                .to_string(),
        );
        diagnostics.push(diagnostic(
            diagnostic_codes::NEXTJS_NESTED_APP_SEGMENT,
            span_for_path(path),
            "Next.js route file path contains nested app segments",
        ));
    }
    let mut segments = Vec::new();
    // Drop the final route.* file tail; remaining segments form the route path.
    for segment in parts
        .iter()
        .skip(app_index + 1)
        .take(parts.len().saturating_sub(app_index + 2))
    {
        if segment.starts_with('@') || is_route_group(segment) {
            continue;
        }
        if is_unusual_segment(segment) {
            confidence = Confidence::Medium;
            notes.push(format!(
                "Next.js route segment `{segment}` uses an unusual routing convention and was normalized for review"
            ));
            diagnostics.push(diagnostic(
                diagnostic_codes::NEXTJS_UNUSUAL_ROUTE_SEGMENT,
                span_for_path(path),
                "Next.js route segment uses an unusual routing convention; emitted path is normalized for review",
            ));
        }
        let segment = normalize_nextjs_segment(segment);
        if !segment.is_empty() {
            segments.push(segment);
        }
    }
    let path = if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    };
    PathInfo {
        path,
        confidence,
        notes,
        diagnostics,
    }
}

fn is_next_route_file(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let parts = normalized.split('/').collect::<Vec<_>>();
    parts.iter().any(|part| *part == "app")
        && matches!(
            parts.last().copied(),
            Some("route.js" | "route.ts" | "route.jsx" | "route.tsx")
        )
}

fn is_route_group(segment: &str) -> bool {
    segment.starts_with('(')
        && segment.ends_with(')')
        && !segment.starts_with("(.)")
        && !segment.starts_with("(..)")
        && !segment.starts_with("(...)")
}

fn is_unusual_segment(segment: &str) -> bool {
    segment.starts_with("(.)") || segment.starts_with("(..)") || segment.starts_with("(...)")
}

fn normalize_nextjs_segment(segment: &str) -> String {
    for prefix in ["(...)", "(..)", "(.)"] {
        if let Some(rest) = segment.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    segment.to_string()
}

fn is_http_method(name: &str) -> bool {
    matches!(
        name,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn is_js_like(language: authmap_core::Language) -> bool {
    matches!(
        language,
        authmap_core::Language::JavaScript
            | authmap_core::Language::JavaScriptReact
            | authmap_core::Language::TypeScript
            | authmap_core::Language::TypeScriptReact
    )
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|child| child.is_named())
        .collect()
}

fn call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .filter(|child| child.is_named())
        .collect()
}

fn symbol_name(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    match node.kind() {
        "identifier" | "member_expression" => parsed.text_for(node).map(terminal_symbol_name),
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|function| parsed.text_for(function).map(terminal_symbol_name)),
        _ => None,
    }
}

fn terminal_symbol_name(text: &str) -> String {
    text.rsplit(['.', ':']).next().unwrap_or(text).to_string()
}

fn weaker_confidence(left: Confidence, right: Confidence) -> Confidence {
    match (left, right) {
        (Confidence::Low, _) | (_, Confidence::Low) => Confidence::Low,
        (Confidence::Medium, _) | (_, Confidence::Medium) => Confidence::Medium,
        (Confidence::High, Confidence::High) => Confidence::High,
    }
}

fn export_kind_name(kind: ExportKind) -> &'static str {
    match kind {
        ExportKind::Function => "function",
        ExportKind::ConstFunction => "const_function",
        ExportKind::ReExport => "re_export",
        ExportKind::Wrapped => "wrapped",
    }
}

fn route_sort_key(route: &Route) -> (String, u32, String, String, String) {
    (
        route
            .span
            .as_ref()
            .map_or_else(String::new, |span| span.file.clone()),
        route.span.as_ref().map_or(0, |span| span.line),
        route.method.clone(),
        route.path.clone(),
        route
            .handler
            .as_ref()
            .map_or_else(String::new, |handler| handler.name.clone()),
    )
}

fn diagnostic_sort_key(diagnostic: &Diagnostic) -> (String, u32, String, String) {
    (
        diagnostic
            .span
            .as_ref()
            .map_or_else(String::new, |span| span.file.clone()),
        diagnostic.span.as_ref().map_or(0, |span| span.line),
        diagnostic.code.clone(),
        diagnostic.message.clone(),
    )
}

fn span_for_path(path: &str) -> Span {
    Span {
        file: path.to_string(),
        line: 1,
        column: 1,
        byte_range: None,
    }
}

fn diagnostic(code: &str, span: Span, message: &str) -> Diagnostic {
    Diagnostic {
        category: DiagnosticCategory::Adapter,
        code: code.to_string(),
        severity: DiagnosticSeverity::Warning,
        recoverability: Recoverability::Recoverable,
        span: Some(span),
        message: message.to_string(),
    }
}
