use std::collections::{BTreeMap, BTreeSet, HashMap};

use authmap_core::{
    Confidence, Diagnostic, DiagnosticCategory, DiagnosticSeverity, Evidence, Framework, Mutation,
    Recoverability, Route, Span, SymbolRef,
};
use authmap_parsers::ParsedFile;
use tree_sitter::{Node, Tree};

mod django;

pub use django::DjangoAdapter;

#[derive(Clone, Debug, Default)]
pub struct AdapterContext {
    pub enabled_frameworks: Vec<String>,
}

pub struct AdapterInput<'a> {
    pub parsed: &'a ParsedFile,
    pub context: &'a AdapterContext,
}

impl<'a> AdapterInput<'a> {
    pub fn new(parsed: &'a ParsedFile, context: &'a AdapterContext) -> Self {
        Self { parsed, context }
    }

    pub fn source_text(&self) -> &'a str {
        &self.parsed.text
    }

    pub fn tree(&self) -> Option<&'a Tree> {
        self.parsed.tree()
    }

    pub fn span_for_node(&self, node: Node<'_>) -> Span {
        self.parsed.span_for_node(node)
    }

    pub fn snippet(&self, span: &Span) -> Option<&'a str> {
        self.parsed.snippet(span)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AdapterOutput {
    pub routes: Vec<Route>,
    pub evidence: Vec<Evidence>,
    pub mutations: Vec<Mutation>,
    pub diagnostics: Vec<Diagnostic>,
}

pub trait FrameworkAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        context: &AdapterContext,
    ) -> AdapterOutput;
}

#[derive(Default)]
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn FrameworkAdapter>>,
}

impl AdapterRegistry {
    pub fn built_in() -> Self {
        Self {
            adapters: vec![
                Box::new(FastApiAdapter),
                Box::new(DjangoAdapter),
                Box::new(ExpressAdapter),
            ],
        }
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.adapters.iter().map(|adapter| adapter.name()).collect()
    }

    pub fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        context: &AdapterContext,
    ) -> AdapterOutput {
        let mut output = AdapterOutput::default();
        for adapter in &self.adapters {
            if !context.enabled_frameworks.is_empty()
                && !context
                    .enabled_frameworks
                    .iter()
                    .any(|name| name == adapter.name())
            {
                continue;
            }

            let adapter_output = adapter.discover_routes(parsed_files, context);
            output.routes.extend(adapter_output.routes);
            output.evidence.extend(adapter_output.evidence);
            output.mutations.extend(adapter_output.mutations);
            output.diagnostics.extend(adapter_output.diagnostics);
        }
        output
    }
}

#[derive(Clone, Debug, Default)]
pub struct FastApiAdapter;

impl FrameworkAdapter for FastApiAdapter {
    fn name(&self) -> &'static str {
        "fastapi"
    }

    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        _context: &AdapterContext,
    ) -> AdapterOutput {
        let mut index = FastApiIndex::default();
        let module_index = build_module_index(parsed_files);

        for parsed in parsed_files
            .iter()
            .filter(|file| file.language == authmap_core::Language::Python)
        {
            let Some(root) = parsed.root_node() else {
                continue;
            };
            let mut collector = FileCollector {
                parsed,
                module_index: &module_index,
                index: &mut index,
            };
            collector.collect(root);
        }

        index.into_output()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BindingKind {
    App,
    Router,
}

#[derive(Clone, Debug)]
struct Binding {
    file: String,
    name: String,
    kind: BindingKind,
    prefix: Option<String>,
    tags: Vec<String>,
    dynamic_prefix: bool,
}

#[derive(Clone, Debug)]
struct ImportBinding {
    module: String,
    imported: String,
}

#[derive(Clone, Debug)]
struct IncludeRouter {
    file: String,
    app_name: String,
    router_name: String,
    imported: Option<ImportBinding>,
    prefix: Option<String>,
    dynamic_prefix: bool,
}

#[derive(Clone, Debug)]
struct DiscoveredRoute {
    owner_file: String,
    owner_name: String,
    method: String,
    path: Option<String>,
    dynamic_path: bool,
    name: Option<String>,
    tags: Vec<String>,
    handler: SymbolRef,
    span: Span,
    notes: Vec<String>,
}

#[derive(Default)]
struct FastApiIndex {
    bindings: Vec<Binding>,
    imports_by_file: HashMap<String, HashMap<String, ImportBinding>>,
    includes: Vec<IncludeRouter>,
    routes: Vec<DiscoveredRoute>,
    diagnostics: Vec<Diagnostic>,
}

impl FastApiIndex {
    fn into_output(self) -> AdapterOutput {
        let mut bindings_by_file_name = HashMap::<(String, String), Binding>::new();
        let mut router_bindings_by_file_name = HashMap::<(String, String), Binding>::new();
        for binding in self.bindings {
            if binding.kind == BindingKind::Router {
                router_bindings_by_file_name.insert(
                    (binding.file.clone(), binding.name.clone()),
                    binding.clone(),
                );
            }
            bindings_by_file_name.insert((binding.file.clone(), binding.name.clone()), binding);
        }

        let mut emitted = Vec::<Route>::new();
        let mut seen = BTreeSet::<(String, u32, String, String, String)>::new();

        for route in &self.routes {
            let Some(binding) =
                bindings_by_file_name.get(&(route.owner_file.clone(), route.owner_name.clone()))
            else {
                continue;
            };

            if binding.kind == BindingKind::App
                && let Some(emitted_route) = build_route(route, None, false, binding)
            {
                push_unique(&mut emitted, &mut seen, emitted_route);
            }
        }

        for include in &self.includes {
            let Some(app_binding) =
                bindings_by_file_name.get(&(include.file.clone(), include.app_name.clone()))
            else {
                continue;
            };
            if app_binding.kind != BindingKind::App {
                continue;
            }

            let target = if let Some(imported) = &include.imported {
                router_bindings_by_file_name
                    .iter()
                    .find(|((file, name), _)| {
                        name == &imported.imported && module_matches(file, &imported.module)
                    })
                    .map(|(_, binding)| binding.clone())
            } else {
                router_bindings_by_file_name
                    .get(&(include.file.clone(), include.router_name.clone()))
                    .cloned()
            };

            let Some(router_binding) = target else {
                continue;
            };

            for route in self.routes.iter().filter(|route| {
                route.owner_file == router_binding.file && route.owner_name == router_binding.name
            }) {
                if let Some(emitted_route) = build_route(
                    route,
                    include.prefix.as_deref(),
                    include.dynamic_prefix,
                    &router_binding,
                ) {
                    push_unique(&mut emitted, &mut seen, emitted_route);
                }
            }
        }

        emitted.sort_by_key(route_sort_key);
        for (index, route) in emitted.iter_mut().enumerate() {
            route.id = format!("route_{:04}", index + 1);
        }

        let mut diagnostics = self.diagnostics;
        diagnostics.sort_by_key(diagnostic_sort_key);

        AdapterOutput {
            routes: emitted,
            diagnostics,
            ..AdapterOutput::default()
        }
    }
}

fn build_route(
    route: &DiscoveredRoute,
    include_prefix: Option<&str>,
    include_dynamic_prefix: bool,
    owner_binding: &Binding,
) -> Option<Route> {
    let mut notes = route.notes.clone();
    let mut confidence = Confidence::High;
    let mut path = route.path.clone()?;

    if route.dynamic_path {
        confidence = Confidence::Medium;
        notes.push("route path is dynamic and was not fully resolved".to_string());
    }
    if owner_binding.dynamic_prefix {
        confidence = Confidence::Medium;
        notes.push("router prefix is dynamic and was not included in the route path".to_string());
    }
    if include_dynamic_prefix {
        confidence = Confidence::Medium;
        notes.push(
            "include_router prefix is dynamic and was not included in the route path".to_string(),
        );
    }
    if !route.notes.is_empty() {
        confidence = Confidence::Medium;
    }

    if let Some(prefix) = &owner_binding.prefix {
        path = join_paths(prefix, &path);
    }
    if let Some(prefix) = include_prefix {
        path = join_paths(prefix, &path);
    }
    let mut tags = owner_binding.tags.clone();
    tags.extend(route.tags.clone());

    Some(Route {
        id: String::new(),
        framework: Framework::FastApi,
        method: route.method.clone(),
        path,
        name: route.name.clone(),
        tags,
        middleware: Vec::new(),
        handler: Some(route.handler.clone()),
        span: Some(route.span.clone()),
        source_evidence: Vec::new(),
        confidence,
        notes,
        extensions: authmap_core::ExtensionMap::new(),
    })
}

fn push_unique(
    routes: &mut Vec<Route>,
    seen: &mut BTreeSet<(String, u32, String, String, String)>,
    route: Route,
) {
    let key = (
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
    );
    if seen.insert(key) {
        routes.push(route);
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

struct FileCollector<'a> {
    parsed: &'a ParsedFile,
    module_index: &'a BTreeMap<String, String>,
    index: &'a mut FastApiIndex,
}

impl<'a> FileCollector<'a> {
    fn collect(&mut self, root: Node<'_>) {
        self.index.imports_by_file.insert(
            self.parsed.source.path.clone(),
            parse_imports(self.parsed, self.module_index),
        );
        self.walk_for_bindings(root);
        self.walk_for_routes_and_includes(root);
    }

    fn walk_for_bindings(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "assignment" {
                self.collect_assignment(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn walk_for_routes_and_includes(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "decorated_definition" => self.collect_decorated_definition(node),
                "call" => self.collect_include_router(node),
                _ => {}
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn collect_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Some(name) = identifier_text(self.parsed, left) else {
            return;
        };
        let Some(call) = find_first_kind(right, "call") else {
            return;
        };
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let Some(function_name) = terminal_name(self.parsed, function) else {
            return;
        };

        let kind = match function_name.as_str() {
            "FastAPI" => BindingKind::App,
            "APIRouter" => BindingKind::Router,
            _ => return,
        };
        let prefix = keyword_string(self.parsed, call, "prefix");
        let dynamic_prefix = keyword_exists(self.parsed, call, "prefix") && prefix.is_none();
        if dynamic_prefix {
            self.index.diagnostics.push(diagnostic(
                "fastapi_dynamic_router_prefix",
                self.parsed.span_for(call),
                "FastAPI router prefix is dynamic and could not be resolved",
            ));
        }

        self.index.bindings.push(Binding {
            file: self.parsed.source.path.clone(),
            name,
            kind,
            prefix,
            tags: keyword_string_list(self.parsed, call, "tags"),
            dynamic_prefix,
        });
    }

    fn collect_decorated_definition(&mut self, node: Node<'_>) {
        let Some(function) = find_direct_child_kind(node, "function_definition") else {
            return;
        };
        let Some(handler_name_node) = function.child_by_field_name("name") else {
            return;
        };
        let Some(handler_name) = identifier_text(self.parsed, handler_name_node) else {
            return;
        };
        let handler = SymbolRef {
            name: handler_name,
            span: Some(self.parsed.span_for(handler_name_node)),
        };

        let mut cursor = node.walk();
        for child in node
            .children(&mut cursor)
            .filter(|child| child.kind() == "decorator")
        {
            let Some(call) = find_first_kind(child, "call") else {
                continue;
            };
            let Some((owner_name, decorator_name)) = decorator_target(self.parsed, call) else {
                continue;
            };
            let Some(methods) = methods_for_decorator(self.parsed, call, &decorator_name) else {
                continue;
            };
            let (mut path, dynamic_path) = route_path(self.parsed, call);
            if path.is_none() {
                self.index.diagnostics.push(diagnostic(
                    "fastapi_dynamic_route_path",
                    self.parsed.span_for(call),
                    "FastAPI route path is dynamic and could not be resolved",
                ));
                if dynamic_path {
                    path = Some("<dynamic>".to_string());
                } else {
                    continue;
                }
            }
            let mut notes = Vec::new();
            if dynamic_path {
                notes.push("route path is dynamic and was emitted as <dynamic>".to_string());
            }
            if decorator_name == "api_route" && methods.iter().any(|method| method == "ANY") {
                notes.push("api_route methods are dynamic or missing; emitted as ANY".to_string());
                self.index.diagnostics.push(diagnostic(
                    "fastapi_dynamic_api_route_methods",
                    self.parsed.span_for(call),
                    "FastAPI api_route methods are dynamic or missing",
                ));
            }

            for method in methods {
                self.index.routes.push(DiscoveredRoute {
                    owner_file: self.parsed.source.path.clone(),
                    owner_name: owner_name.clone(),
                    method,
                    path: path.clone(),
                    dynamic_path,
                    name: keyword_string(self.parsed, call, "name"),
                    tags: keyword_string_list(self.parsed, call, "tags"),
                    handler: handler.clone(),
                    span: self.parsed.span_for(call),
                    notes: notes.clone(),
                });
            }
        }
    }

    fn collect_include_router(&mut self, node: Node<'_>) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let Some((app_name, call_name)) = attribute_target(self.parsed, function) else {
            return;
        };
        if call_name != "include_router" {
            return;
        }

        let Some(router_name) = first_identifier_argument(self.parsed, node) else {
            return;
        };

        let imported = self
            .index
            .imports_by_file
            .get(&self.parsed.source.path)
            .and_then(|imports| imports.get(&router_name))
            .cloned();
        let prefix = keyword_string(self.parsed, node, "prefix");
        let dynamic_prefix = keyword_exists(self.parsed, node, "prefix") && prefix.is_none();
        if dynamic_prefix {
            self.index.diagnostics.push(diagnostic(
                "fastapi_dynamic_include_router_prefix",
                self.parsed.span_for(node),
                "FastAPI include_router prefix is dynamic and could not be resolved",
            ));
        }

        self.index.includes.push(IncludeRouter {
            file: self.parsed.source.path.clone(),
            app_name: app_name.clone(),
            router_name,
            imported,
            prefix,
            dynamic_prefix,
        });

        if !self
            .index
            .bindings
            .iter()
            .any(|binding| binding.file == self.parsed.source.path && binding.name == app_name)
        {
            self.index.diagnostics.push(diagnostic(
                "fastapi_include_without_known_app",
                self.parsed.span_for(node),
                "include_router call is not on a statically detected FastAPI app",
            ));
        }
    }
}

fn build_module_index(parsed_files: &[ParsedFile]) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for parsed in parsed_files {
        if parsed.language != authmap_core::Language::Python {
            continue;
        }
        let normalized = parsed.source.path.replace('\\', "/");
        let Some(stripped) = normalized.strip_suffix(".py") else {
            continue;
        };
        let module_path = stripped.strip_suffix("/__init__").unwrap_or(stripped);
        let parts = module_path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        for start in 0..parts.len() {
            index.insert(parts[start..].join("."), parsed.source.path.clone());
        }
    }
    index
}

fn parse_imports(
    parsed: &ParsedFile,
    module_index: &BTreeMap<String, String>,
) -> HashMap<String, ImportBinding> {
    let mut imports = HashMap::new();
    for line in parsed.text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("from ") else {
            continue;
        };
        let Some((module, imported_names)) = rest.split_once(" import ") else {
            continue;
        };
        let Some(module) = resolve_python_import_module(parsed, module.trim(), module_index) else {
            continue;
        };
        for imported in imported_names.split(',') {
            let imported = imported.trim();
            if imported.is_empty() || imported == "*" {
                continue;
            }
            let (original, local) = imported
                .split_once(" as ")
                .map_or((imported, imported), |(original, local)| {
                    (original.trim(), local.trim())
                });
            imports.insert(
                local.to_string(),
                ImportBinding {
                    module: module.clone(),
                    imported: original.to_string(),
                },
            );
        }
    }
    imports
}

fn resolve_python_import_module(
    parsed: &ParsedFile,
    module: &str,
    module_index: &BTreeMap<String, String>,
) -> Option<String> {
    if !module.starts_with('.') {
        return module_index
            .contains_key(module)
            .then(|| module.to_string());
    }

    let level = module.chars().take_while(|ch| *ch == '.').count();
    let rest = module.trim_start_matches('.');
    let normalized = parsed.source.path.replace('\\', "/");
    let stripped = normalized.strip_suffix(".py")?;
    let mut parts = stripped
        .strip_suffix("/__init__")
        .unwrap_or(stripped)
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if !normalized.ends_with("/__init__.py") {
        parts.pop();
    }

    for start in 0..parts.len() {
        let mut base = parts[start..].to_vec();
        for _ in 1..level {
            base.pop();
        }
        if !rest.is_empty() {
            base.extend(rest.split('.').filter(|part| !part.is_empty()));
        }
        let candidate = base.join(".");
        if module_index.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn module_matches(file: &str, module: &str) -> bool {
    let normalized = file.replace('\\', "/");
    let Some(stripped) = normalized.strip_suffix(".py") else {
        return false;
    };
    let dotted = stripped.replace('/', ".");
    dotted.ends_with(module)
}

fn find_first_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn find_direct_child_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn identifier_text(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    (node.kind() == "identifier")
        .then(|| parsed.text_for(node).map(str::to_string))
        .flatten()
}

fn terminal_name(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    if node.kind() == "identifier" {
        return parsed.text_for(node).map(str::to_string);
    }
    if node.kind() == "attribute" {
        let attr = node.child_by_field_name("attribute")?;
        return parsed.text_for(attr).map(str::to_string);
    }
    parsed
        .text_for(node)
        .and_then(|text| text.rsplit('.').next().map(str::to_string))
}

fn decorator_target(parsed: &ParsedFile, call: Node<'_>) -> Option<(String, String)> {
    let function = call.child_by_field_name("function")?;
    attribute_target(parsed, function)
}

fn attribute_target(parsed: &ParsedFile, node: Node<'_>) -> Option<(String, String)> {
    if node.kind() != "attribute" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let attribute = node.child_by_field_name("attribute")?;
    Some((
        parsed.text_for(object)?.to_string(),
        parsed.text_for(attribute)?.to_string(),
    ))
}

fn methods_for_decorator(
    parsed: &ParsedFile,
    call: Node<'_>,
    decorator_name: &str,
) -> Option<Vec<String>> {
    match decorator_name {
        "get" | "post" | "put" | "patch" | "delete" => Some(vec![decorator_name.to_uppercase()]),
        "api_route" => {
            let methods = keyword_string_list(parsed, call, "methods");
            if methods.is_empty() {
                Some(vec!["ANY".to_string()])
            } else {
                Some(
                    methods
                        .into_iter()
                        .map(|method| method.to_uppercase())
                        .collect(),
                )
            }
        }
        _ => None,
    }
}

fn route_path(parsed: &ParsedFile, call: Node<'_>) -> (Option<String>, bool) {
    if let Some(path) = first_string_argument(parsed, call) {
        return (Some(path), false);
    }
    let keyword_path = keyword_string(parsed, call, "path");
    let unresolved_keyword_path = keyword_path.is_none();
    let dynamic = keyword_exists(parsed, call, "path") || first_argument_exists(call);
    (keyword_path, dynamic && unresolved_keyword_path)
}

fn first_argument_exists(call: Node<'_>) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .any(|child| child.is_named() && child.kind() != "keyword_argument")
}

fn first_string_argument(parsed: &ParsedFile, call: Node<'_>) -> Option<String> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        if !child.is_named() || child.kind() == "keyword_argument" {
            continue;
        }
        return string_literal(parsed, child);
    }
    None
}

fn first_identifier_argument(parsed: &ParsedFile, call: Node<'_>) -> Option<String> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        if !child.is_named() || child.kind() == "keyword_argument" {
            continue;
        }
        return identifier_text(parsed, child);
    }
    None
}

fn keyword_exists(parsed: &ParsedFile, call: Node<'_>, name: &str) -> bool {
    keyword_value(parsed, call, name).is_some()
}

fn keyword_string(parsed: &ParsedFile, call: Node<'_>, name: &str) -> Option<String> {
    keyword_value(parsed, call, name).and_then(|value| string_literal(parsed, value))
}

fn keyword_string_list(parsed: &ParsedFile, call: Node<'_>, name: &str) -> Vec<String> {
    let Some(value) = keyword_value(parsed, call, name) else {
        return Vec::new();
    };
    if let Some(single) = string_literal(parsed, value) {
        return vec![single];
    }
    if !matches!(value.kind(), "list" | "tuple") {
        return Vec::new();
    }
    let mut values = Vec::new();
    let mut cursor = value.walk();
    for child in value.children(&mut cursor) {
        if let Some(item) = string_literal(parsed, child) {
            values.push(item);
        }
    }
    values
}

fn keyword_value<'tree>(parsed: &ParsedFile, call: Node<'tree>, name: &str) -> Option<Node<'tree>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        if child.kind() != "keyword_argument" {
            continue;
        }
        let Some(keyword_name) = child.child_by_field_name("name") else {
            continue;
        };
        if parsed.text_for(keyword_name)? == name {
            return child.child_by_field_name("value");
        }
    }
    None
}

fn string_literal(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = parsed.text_for(node)?.trim();
    decode_python_string_literal(text)
}

fn decode_python_string_literal(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let quote_index = trimmed.find(['\'', '"'])?;
    if trimmed[..quote_index]
        .chars()
        .any(|ch| matches!(ch, 'f' | 'F' | 'b' | 'B'))
    {
        return None;
    }
    let quote = trimmed.as_bytes()[quote_index] as char;
    let triple = trimmed[quote_index..].starts_with(&format!("{quote}{quote}{quote}"));
    let start = quote_index + if triple { 3 } else { 1 };
    let end_marker = if triple {
        format!("{quote}{quote}{quote}")
    } else {
        quote.to_string()
    };
    let end = trimmed[start..].rfind(&end_marker)? + start;
    Some(
        trimmed[start..end]
            .replace("\\\"", "\"")
            .replace("\\'", "'"),
    )
}

fn join_paths(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    match (prefix.is_empty(), path.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{path}"),
        (false, true) => prefix.to_string(),
        (false, false) => format!("{prefix}/{path}"),
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

#[derive(Clone, Debug, Default)]
pub struct ExpressAdapter;

impl FrameworkAdapter for ExpressAdapter {
    fn name(&self) -> &'static str {
        "express"
    }

    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        _context: &AdapterContext,
    ) -> AdapterOutput {
        let mut index = ExpressIndex::default();
        let module_index = build_js_module_index(parsed_files);

        for parsed in parsed_files.iter().filter(|file| is_js_like(file.language)) {
            let Some(root) = parsed.root_node() else {
                continue;
            };
            index.imports_by_file.insert(
                parsed.source.path.clone(),
                parse_js_imports(parsed, &module_index),
            );
            index
                .exports_by_file
                .insert(parsed.source.path.clone(), parse_js_exports(parsed));
            let mut collector = ExpressCollector {
                parsed,
                index: &mut index,
            };
            collector.collect(root);
        }

        index.into_output()
    }
}

#[derive(Clone, Debug)]
struct ExpressBinding {
    file: String,
    name: String,
    kind: BindingKind,
}

#[derive(Clone, Debug)]
struct ExpressImport {
    module_file: String,
    export_name: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct ExpressExports {
    default: Option<String>,
    named: HashMap<String, String>,
}

#[derive(Clone, Debug)]
struct ExpressMount {
    file: String,
    parent_name: String,
    child_name: String,
    imported: Option<ExpressImport>,
    prefix: Option<String>,
    middleware: Vec<SymbolRef>,
    dynamic_prefix: bool,
    span: Span,
}

#[derive(Clone, Debug)]
struct MountedRouter {
    binding: ExpressBinding,
    prefixes: Vec<String>,
    middleware: Vec<SymbolRef>,
    dynamic_prefix: bool,
    lineage: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
struct ExpressRouteFact {
    owner_file: String,
    owner_name: String,
    method: String,
    path: String,
    dynamic_path: bool,
    handler: SymbolRef,
    middleware: Vec<SymbolRef>,
    span: Span,
    notes: Vec<String>,
}

#[derive(Default)]
struct ExpressIndex {
    bindings: Vec<ExpressBinding>,
    imports_by_file: HashMap<String, HashMap<String, ExpressImport>>,
    exports_by_file: HashMap<String, ExpressExports>,
    definitions_by_file: HashMap<String, HashMap<String, Span>>,
    mounts: Vec<ExpressMount>,
    routes: Vec<ExpressRouteFact>,
    diagnostics: Vec<Diagnostic>,
}

impl ExpressIndex {
    fn into_output(self) -> AdapterOutput {
        let mut diagnostics = self.diagnostics;
        let mut bindings = HashMap::<(String, String), ExpressBinding>::new();
        for binding in self.bindings {
            bindings.insert((binding.file.clone(), binding.name.clone()), binding);
        }

        let mut routes = Vec::<Route>::new();
        let mut seen = BTreeSet::<(String, u32, String, String, String)>::new();
        for fact in &self.routes {
            let Some(binding) = bindings.get(&(fact.owner_file.clone(), fact.owner_name.clone()))
            else {
                continue;
            };
            if binding.kind == BindingKind::App {
                push_unique(
                    &mut routes,
                    &mut seen,
                    express_route(fact, None, &[], false),
                );
            }
        }

        let mut mounted = Vec::<MountedRouter>::new();
        let mut unresolved_mounts = BTreeSet::<(String, u32, String)>::new();
        let mut cyclic_mounts = BTreeSet::<(String, u32, String)>::new();
        for mount in &self.mounts {
            let Some(parent) = bindings.get(&(mount.file.clone(), mount.parent_name.clone()))
            else {
                continue;
            };
            if parent.kind != BindingKind::App {
                continue;
            }

            let target = resolve_express_mount_target(mount, &bindings, &self.exports_by_file);
            let Some(child) = target else {
                push_mount_diagnostic(
                    &mut diagnostics,
                    &mut unresolved_mounts,
                    mount,
                    "express_unresolved_mount_router",
                    "Express mounted router could not be resolved statically",
                );
                continue;
            };

            let mut prefixes = Vec::new();
            if let Some(prefix) = &mount.prefix {
                prefixes.push(prefix.clone());
            }
            let lineage = vec![binding_key(&child)];
            mounted.push(MountedRouter {
                binding: child,
                prefixes,
                middleware: mount.middleware.clone(),
                dynamic_prefix: mount.dynamic_prefix,
                lineage,
            });
        }

        let mut changed = true;
        while changed {
            changed = false;
            for mount in &self.mounts {
                let Some(parent_mount) = mounted
                    .iter()
                    .find(|mounted| {
                        mounted.binding.file == mount.file
                            && mounted.binding.name == mount.parent_name
                    })
                    .cloned()
                else {
                    continue;
                };
                let target = resolve_express_mount_target(mount, &bindings, &self.exports_by_file);
                let Some(child) = target else {
                    push_mount_diagnostic(
                        &mut diagnostics,
                        &mut unresolved_mounts,
                        mount,
                        "express_unresolved_mount_router",
                        "Express mounted router could not be resolved statically",
                    );
                    continue;
                };
                let child_key = binding_key(&child);
                if parent_mount.lineage.contains(&child_key) {
                    push_mount_diagnostic(
                        &mut diagnostics,
                        &mut cyclic_mounts,
                        mount,
                        "express_cyclic_mount_router",
                        "Express mounted router cycle was ignored",
                    );
                    continue;
                }
                let mut prefixes = parent_mount.prefixes;
                if let Some(prefix) = &mount.prefix {
                    prefixes.push(prefix.clone());
                }
                let mut middleware = parent_mount.middleware;
                middleware.extend(mount.middleware.clone());
                let dynamic = parent_mount.dynamic_prefix || mount.dynamic_prefix;
                let mut lineage = parent_mount.lineage;
                lineage.push(child_key);
                if mounted.iter().any(|mounted| {
                    mounted.binding.file == child.file
                        && mounted.binding.name == child.name
                        && mounted.prefixes == prefixes
                        && mounted.middleware == middleware
                        && mounted.dynamic_prefix == dynamic
                }) {
                    continue;
                }
                mounted.push(MountedRouter {
                    binding: child,
                    prefixes,
                    middleware,
                    dynamic_prefix: dynamic,
                    lineage,
                });
                changed = true;
            }
        }

        for mounted in &mounted {
            for fact in self.routes.iter().filter(|fact| {
                fact.owner_file == mounted.binding.file && fact.owner_name == mounted.binding.name
            }) {
                let prefix = mounted.prefixes.iter().fold(String::new(), |prefix, next| {
                    if prefix.is_empty() {
                        next.clone()
                    } else {
                        join_paths(&prefix, next)
                    }
                });
                let prefix = (!prefix.is_empty()).then_some(prefix);
                push_unique(
                    &mut routes,
                    &mut seen,
                    express_route(
                        fact,
                        prefix.as_deref(),
                        &mounted.middleware,
                        mounted.dynamic_prefix,
                    ),
                );
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

fn express_route(
    fact: &ExpressRouteFact,
    prefix: Option<&str>,
    mount_middleware: &[SymbolRef],
    dynamic_prefix: bool,
) -> Route {
    let mut path = fact.path.clone();
    let mut confidence = if fact.dynamic_path {
        Confidence::Low
    } else {
        Confidence::High
    };
    let mut notes = fact.notes.clone();

    if let Some(prefix) = prefix {
        path = join_paths(prefix, &path);
    }
    if dynamic_prefix {
        if confidence != Confidence::Low {
            confidence = Confidence::Medium;
        }
        notes.push(
            "Express mount prefix is dynamic and was not included in the route path".to_string(),
        );
    }

    Route {
        id: String::new(),
        framework: Framework::Express,
        method: fact.method.clone(),
        path,
        name: None,
        tags: Vec::new(),
        middleware: merged_middleware(mount_middleware, &fact.middleware),
        handler: Some(fact.handler.clone()),
        span: Some(fact.span.clone()),
        source_evidence: Vec::new(),
        confidence,
        notes,
        extensions: authmap_core::ExtensionMap::new(),
    }
}

fn merged_middleware(
    mount_middleware: &[SymbolRef],
    route_middleware: &[SymbolRef],
) -> Vec<SymbolRef> {
    let mut middleware = Vec::with_capacity(mount_middleware.len() + route_middleware.len());
    middleware.extend(mount_middleware.iter().cloned());
    middleware.extend(route_middleware.iter().cloned());
    middleware
}

fn binding_key(binding: &ExpressBinding) -> (String, String) {
    (binding.file.clone(), binding.name.clone())
}

fn push_mount_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    seen: &mut BTreeSet<(String, u32, String)>,
    mount: &ExpressMount,
    code: &str,
    message: &str,
) {
    let key = (mount.span.file.clone(), mount.span.line, code.to_string());
    if seen.insert(key) {
        diagnostics.push(diagnostic(code, mount.span.clone(), message));
    }
}

fn resolve_express_mount_target(
    mount: &ExpressMount,
    bindings: &HashMap<(String, String), ExpressBinding>,
    exports_by_file: &HashMap<String, ExpressExports>,
) -> Option<ExpressBinding> {
    if let Some(imported) = &mount.imported {
        let exports = exports_by_file.get(&imported.module_file)?;
        let local = imported
            .export_name
            .as_ref()
            .and_then(|name| exports.named.get(name))
            .or(exports.default.as_ref())?;
        return bindings
            .get(&(imported.module_file.clone(), local.clone()))
            .cloned();
    }

    bindings
        .get(&(mount.file.clone(), mount.child_name.clone()))
        .cloned()
}

struct ExpressCollector<'a> {
    parsed: &'a ParsedFile,
    index: &'a mut ExpressIndex,
}

impl<'a> ExpressCollector<'a> {
    fn collect(&mut self, root: Node<'_>) {
        self.walk_for_definitions(root);
        self.walk_for_bindings(root);
        self.walk_for_routes_and_mounts(root);
    }

    fn walk_for_definitions(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            self.collect_definition(node);
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn walk_for_bindings(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                self.collect_binding(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn walk_for_routes_and_mounts(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                self.collect_route_or_mount(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn collect_definition(&mut self, node: Node<'_>) {
        let name_node = match node.kind() {
            "function_declaration" => node.child_by_field_name("name"),
            "variable_declarator" => {
                let value = node.child_by_field_name("value");
                if value.is_some_and(|value| {
                    matches!(
                        value.kind(),
                        "arrow_function" | "function" | "function_expression"
                    )
                }) {
                    node.child_by_field_name("name")
                } else {
                    None
                }
            }
            _ => None,
        };
        let Some(name_node) = name_node else {
            return;
        };
        let Some(name) = self.parsed.text_for(name_node).map(str::to_string) else {
            return;
        };
        self.index
            .definitions_by_file
            .entry(self.parsed.source.path.clone())
            .or_default()
            .entry(name)
            .or_insert_with(|| self.parsed.span_for(name_node));
    }

    fn collect_binding(&mut self, call: Node<'_>) {
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let function_text = self.parsed.text_for(function).unwrap_or_default();
        let kind = if function_text == "express" {
            BindingKind::App
        } else if function_text == "express.Router" || function_text == "Router" {
            BindingKind::Router
        } else {
            return;
        };

        let Some(name) = assigned_name(self.parsed, call) else {
            return;
        };
        if self
            .index
            .bindings
            .iter()
            .any(|binding| binding.file == self.parsed.source.path && binding.name == name)
        {
            return;
        }
        self.index.bindings.push(ExpressBinding {
            file: self.parsed.source.path.clone(),
            name,
            kind,
        });
    }

    fn collect_route_or_mount(&mut self, call: Node<'_>) {
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let Some((owner, member)) = js_member_target(self.parsed, function) else {
            return;
        };

        if member == "use" {
            self.collect_mount(call, &owner);
            return;
        }

        if let Some(method) = express_method(&member) {
            let definitions = self.index.definitions_by_file.get(&self.parsed.source.path);
            if let Some(chain) = express_route_chain(self.parsed, call, method, definitions) {
                self.push_route(chain);
            } else if let Some(direct) =
                express_direct_route(self.parsed, call, &owner, method, definitions)
            {
                self.push_route(direct);
            }
        }
    }

    fn collect_mount(&mut self, call: Node<'_>, parent_name: &str) {
        let args = call_arguments(call);
        if args.is_empty() {
            return;
        }

        let mut dynamic_prefix = false;
        let (prefix, child_candidates) = if let Some(prefix) = js_path_literal(self.parsed, args[0])
        {
            (Some(prefix), &args[1..])
        } else if args.len() >= 2 {
            dynamic_prefix = true;
            self.index.diagnostics.push(diagnostic(
                "express_dynamic_mount_prefix",
                self.parsed.span_for(args[0]),
                "Express mount prefix is dynamic and could not be resolved",
            ));
            (None, &args[1..])
        } else if is_symbol_reference(args[0]) {
            (None, &args[..])
        } else {
            dynamic_prefix = true;
            self.index.diagnostics.push(diagnostic(
                "express_dynamic_mount_prefix",
                self.parsed.span_for(args[0]),
                "Express mount prefix is dynamic and could not be resolved",
            ));
            (None, &args[1..])
        };

        let selected = select_mount_child(self.parsed, child_candidates, self.index);
        let Some((child_index, child_node)) = selected else {
            return;
        };
        let middleware =
            symbols_from_route_args(self.parsed, &child_candidates[..child_index], None);
        let Some(child_name) = symbol_name(self.parsed, child_node, "<inline_middleware>") else {
            return;
        };
        let imported = self
            .index
            .imports_by_file
            .get(&self.parsed.source.path)
            .and_then(|imports| imports.get(&child_name))
            .cloned();

        self.index.mounts.push(ExpressMount {
            file: self.parsed.source.path.clone(),
            parent_name: parent_name.to_string(),
            child_name,
            imported,
            prefix,
            middleware,
            dynamic_prefix,
            span: self.parsed.span_for(call),
        });
    }

    fn push_route(&mut self, candidate: ExpressRouteCandidate) {
        let mut route = ExpressRouteFact {
            owner_file: self.parsed.source.path.clone(),
            owner_name: candidate.owner,
            method: candidate.method,
            path: candidate.path,
            dynamic_path: candidate.dynamic_path,
            handler: candidate.handler,
            middleware: candidate.middleware,
            span: candidate.span,
            notes: Vec::new(),
        };
        if route.dynamic_path {
            self.index.diagnostics.push(diagnostic(
                "express_dynamic_route_path",
                route.span.clone(),
                "Express route path is dynamic and could not be resolved",
            ));
            route
                .notes
                .push("Express route path is dynamic and was emitted as <dynamic>".to_string());
        }
        self.index.routes.push(route);
    }
}

struct ExpressRouteCandidate {
    owner: String,
    method: String,
    path: String,
    dynamic_path: bool,
    handler: SymbolRef,
    middleware: Vec<SymbolRef>,
    span: Span,
}

fn express_direct_route(
    parsed: &ParsedFile,
    call: Node<'_>,
    owner: &str,
    method: &str,
    definitions: Option<&HashMap<String, Span>>,
) -> Option<ExpressRouteCandidate> {
    let args = call_arguments(call);
    if args.len() < 2 {
        return None;
    }
    let (path, dynamic_path) = express_path(parsed, args[0]);
    let symbols = symbols_from_route_args(parsed, &args[1..], definitions);
    let (handler, middleware) = split_handler_middleware(symbols)?;
    Some(ExpressRouteCandidate {
        owner: owner.to_string(),
        method: method.to_string(),
        path,
        dynamic_path,
        handler,
        middleware,
        span: parsed.span_for(call),
    })
}

fn express_route_chain(
    parsed: &ParsedFile,
    call: Node<'_>,
    method: &str,
    definitions: Option<&HashMap<String, Span>>,
) -> Option<ExpressRouteCandidate> {
    let function = call.child_by_field_name("function")?;
    let object = function.child_by_field_name("object")?;
    let route_call = find_route_call_in_chain(parsed, object)?;
    let route_function = route_call.child_by_field_name("function")?;
    let (owner, member) = js_member_target(parsed, route_function)?;
    if member != "route" {
        return None;
    }
    let route_args = call_arguments(route_call);
    let path_arg = *route_args.first()?;
    let (path, dynamic_path) = express_path(parsed, path_arg);
    let args = call_arguments(call);
    let symbols = symbols_from_route_args(parsed, &args, definitions);
    let (handler, middleware) = split_handler_middleware(symbols)?;
    Some(ExpressRouteCandidate {
        owner,
        method: method.to_string(),
        path,
        dynamic_path,
        handler,
        middleware,
        span: parsed.span_for(call),
    })
}

fn find_route_call_in_chain<'tree>(
    parsed: &ParsedFile,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if node.kind() != "call_expression" {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if let Some((_, member)) = js_member_target(parsed, function)
            && member == "route"
        {
            return Some(node);
        }
        if function.kind() == "member_expression"
            && let Some(object) = function.child_by_field_name("object")
        {
            node = object;
            continue;
        }
        return None;
    }
}

fn split_handler_middleware(mut symbols: Vec<SymbolRef>) -> Option<(SymbolRef, Vec<SymbolRef>)> {
    let handler = symbols.pop()?;
    Some((handler, symbols))
}

fn express_method(member: &str) -> Option<&'static str> {
    match member {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "patch" => Some("PATCH"),
        "delete" => Some("DELETE"),
        _ => None,
    }
}

fn express_path(parsed: &ParsedFile, node: Node<'_>) -> (String, bool) {
    js_path_literal(parsed, node)
        .map_or_else(|| ("<dynamic>".to_string(), true), |path| (path, false))
}

fn symbols_from_route_args(
    parsed: &ParsedFile,
    args: &[Node<'_>],
    definitions: Option<&HashMap<String, Span>>,
) -> Vec<SymbolRef> {
    let mut symbols = Vec::new();
    for arg in args {
        if arg.kind() == "array" {
            let mut cursor = arg.walk();
            for child in arg.children(&mut cursor).filter(|child| child.is_named()) {
                if let Some(symbol) = symbol_ref(parsed, child, "<inline_middleware>", definitions)
                {
                    symbols.push(symbol);
                }
            }
            continue;
        }
        if let Some(symbol) = symbol_ref(parsed, *arg, "<inline_handler>", definitions) {
            symbols.push(symbol);
        }
    }
    symbols
}

fn symbol_ref(
    parsed: &ParsedFile,
    node: Node<'_>,
    inline_name: &str,
    definitions: Option<&HashMap<String, Span>>,
) -> Option<SymbolRef> {
    let name = symbol_name(parsed, node, inline_name)?;
    let span = definitions
        .and_then(|definitions| definitions.get(&name).cloned())
        .or_else(|| Some(parsed.span_for(node)));
    Some(SymbolRef { name, span })
}

fn symbol_name(parsed: &ParsedFile, node: Node<'_>, inline_name: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "member_expression" => parsed.text_for(node).map(str::to_string),
        "arrow_function" | "function" | "function_expression" => Some(inline_name.to_string()),
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|function| parsed.text_for(function).map(str::to_string)),
        _ => None,
    }
}

fn is_symbol_reference(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "member_expression" | "call_expression"
    )
}

fn select_mount_child<'tree>(
    parsed: &ParsedFile,
    candidates: &[Node<'tree>],
    index: &ExpressIndex,
) -> Option<(usize, Node<'tree>)> {
    let symbol_candidates = candidates
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, candidate)| is_symbol_reference(*candidate))
        .collect::<Vec<_>>();

    symbol_candidates
        .iter()
        .rev()
        .copied()
        .find(|(_, candidate)| {
            let Some(name) = symbol_name(parsed, *candidate, "<inline_middleware>") else {
                return false;
            };
            index.bindings.iter().any(|binding| {
                binding.file == parsed.source.path
                    && binding.name == name
                    && binding.kind == BindingKind::Router
            }) || index
                .imports_by_file
                .get(&parsed.source.path)
                .is_some_and(|imports| imports.contains_key(&name))
        })
        .or_else(|| symbol_candidates.last().copied())
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

fn js_member_target(parsed: &ParsedFile, node: Node<'_>) -> Option<(String, String)> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    Some((
        parsed.text_for(object)?.to_string(),
        parsed.text_for(property)?.to_string(),
    ))
}

fn js_path_literal(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    match node.kind() {
        "string" => decode_js_string(parsed.text_for(node)?),
        "template_string" => decode_js_template(parsed.text_for(node)?),
        _ => None,
    }
}

fn decode_js_string(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let end = trimmed.rfind(quote)?;
    (end > 0).then(|| {
        trimmed[1..end]
            .replace("\\\"", "\"")
            .replace("\\'", "'")
            .replace("\\/", "/")
    })
}

fn decode_js_template(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if !trimmed.starts_with('`') || !trimmed.ends_with('`') || trimmed.contains("${") {
        return None;
    }
    Some(trimmed[1..trimmed.len() - 1].to_string())
}

fn assigned_name(parsed: &ParsedFile, call: Node<'_>) -> Option<String> {
    let mut current = call.parent()?;
    loop {
        match current.kind() {
            "variable_declarator" => {
                return current
                    .child_by_field_name("name")
                    .and_then(|node| parsed.text_for(node).map(str::to_string));
            }
            "assignment_expression" => {
                return current
                    .child_by_field_name("left")
                    .and_then(|node| parsed.text_for(node).map(str::to_string));
            }
            _ => current = current.parent()?,
        }
    }
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

fn build_js_module_index(parsed_files: &[ParsedFile]) -> HashMap<String, String> {
    let mut index = HashMap::new();
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

fn parse_js_imports(
    parsed: &ParsedFile,
    module_index: &HashMap<String, String>,
) -> HashMap<String, ExpressImport> {
    let mut imports = HashMap::new();
    for line in parsed.text.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        parse_require_import(parsed, module_index, trimmed, &mut imports);
        parse_es_import(parsed, module_index, trimmed, &mut imports);
    }
    imports
}

fn parse_require_import(
    parsed: &ParsedFile,
    module_index: &HashMap<String, String>,
    line: &str,
    imports: &mut HashMap<String, ExpressImport>,
) {
    let Some((left, right)) = line.split_once("require(") else {
        return;
    };
    let Some(module_literal) = right.split(')').next() else {
        return;
    };
    let Some(module_file) = resolve_js_module(parsed, module_index, module_literal.trim()) else {
        return;
    };
    let required_property = right
        .split_once(").")
        .map(|(_, property)| property.trim().to_string());
    let left = left
        .trim()
        .strip_prefix("const ")
        .or_else(|| left.trim().strip_prefix("let "))
        .or_else(|| left.trim().strip_prefix("var "));
    let Some(left) = left else {
        return;
    };
    let Some(local) = left.trim().strip_suffix('=') else {
        return;
    };
    let local = local.trim();
    if local.starts_with('{') && local.ends_with('}') {
        for part in local[1..local.len() - 1].split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (export_name, local_name) = part
                .split_once(':')
                .map_or((part, part), |(export_name, local_name)| {
                    (export_name.trim(), local_name.trim())
                });
            imports.insert(
                local_name.to_string(),
                ExpressImport {
                    module_file: module_file.clone(),
                    export_name: Some(export_name.to_string()),
                },
            );
        }
    } else {
        imports.insert(
            local.to_string(),
            ExpressImport {
                module_file,
                export_name: required_property,
            },
        );
    }
}

fn parse_es_import(
    parsed: &ParsedFile,
    module_index: &HashMap<String, String>,
    line: &str,
    imports: &mut HashMap<String, ExpressImport>,
) {
    let Some(rest) = line.strip_prefix("import ") else {
        return;
    };
    let Some((specifiers, module_part)) = rest.split_once(" from ") else {
        return;
    };
    let Some(module_file) = resolve_js_module(parsed, module_index, module_part.trim()) else {
        return;
    };
    let specifiers = specifiers.trim();
    if specifiers.starts_with('{') && specifiers.ends_with('}') {
        for part in specifiers[1..specifiers.len() - 1].split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (export_name, local_name) = part
                .split_once(" as ")
                .map_or((part, part), |(export_name, local_name)| {
                    (export_name.trim(), local_name.trim())
                });
            imports.insert(
                local_name.to_string(),
                ExpressImport {
                    module_file: module_file.clone(),
                    export_name: Some(export_name.to_string()),
                },
            );
        }
    } else {
        imports.insert(
            specifiers.to_string(),
            ExpressImport {
                module_file,
                export_name: None,
            },
        );
    }
}

fn parse_js_exports(parsed: &ParsedFile) -> ExpressExports {
    let mut exports = ExpressExports::default();
    for line in parsed.text.lines() {
        let trimmed = line.trim().trim_end_matches(';');
        if let Some(value) = trimmed.strip_prefix("module.exports = ") {
            exports.default = Some(value.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("exports.") {
            if let Some((name, value)) = rest.split_once(" = ") {
                exports
                    .named
                    .insert(name.trim().to_string(), value.trim().to_string());
            }
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("export default ") {
            exports.default = Some(value.trim().to_string());
            continue;
        }
        for prefix in ["export const ", "export let ", "export var "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                if let Some((name, _)) = rest.split_once('=') {
                    let name = name.trim();
                    if !name.is_empty() {
                        exports.named.insert(name.to_string(), name.to_string());
                    }
                }
                continue;
            }
        }
        if let Some(rest) = trimmed.strip_prefix("export {") {
            let rest = rest.trim().trim_end_matches('}').trim();
            for part in rest.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (local, exported) = part
                    .split_once(" as ")
                    .map_or((part, part), |(local, exported)| {
                        (local.trim(), exported.trim())
                    });
                exports
                    .named
                    .insert(exported.to_string(), local.to_string());
            }
        }
    }
    exports
}

fn resolve_js_module(
    parsed: &ParsedFile,
    module_index: &HashMap<String, String>,
    module_literal: &str,
) -> Option<String> {
    let module = module_literal.trim().trim_matches('"').trim_matches('\'');
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

#[cfg(test)]
mod tests {
    use std::fs;

    use authmap_core::{Confidence, Framework, Language, SourceFile};
    use authmap_parsers::{ParserBackend, TreeSitterBackend};
    use authmap_testkit::fixture_path;

    use super::{AdapterContext, DjangoAdapter, ExpressAdapter, FastApiAdapter, FrameworkAdapter};

    #[test]
    fn discovers_fastapi_routes_from_apps_routers_and_imported_includes() {
        let parsed = parse_fixtures(&[
            "fastapi/main.py",
            "fastapi/app/main_relative.py",
            "fastapi/app/routes/users.py",
        ]);
        let output = FastApiAdapter.discover_routes(&parsed, &AdapterContext::default());

        let summaries = output
            .routes
            .iter()
            .map(|route| {
                (
                    route.method.as_str(),
                    route.path.as_str(),
                    route.handler.as_ref().map(|handler| handler.name.as_str()),
                    route.name.as_deref(),
                    route.tags.clone(),
                    route.confidence,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(output.routes.len(), 15);
        assert!(summaries.contains(&(
            "GET",
            "/health",
            Some("health"),
            Some("healthcheck"),
            vec!["system".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "POST",
            "/items",
            Some("create_item"),
            None,
            vec!["items".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "DELETE",
            "/api/local/{item_id}",
            Some("delete_local"),
            Some("delete_local"),
            vec!["local-default".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/v1/users/{user_id}",
            Some("get_user"),
            Some("get_user"),
            vec!["users".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "PUT",
            "/v1/users/{user_id}",
            Some("update_user"),
            None,
            vec!["users".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/relative/users/{user_id}",
            Some("get_user"),
            Some("get_user"),
            vec!["users".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "PUT",
            "/relative/users/{user_id}",
            Some("update_user"),
            None,
            vec!["users".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/search",
            Some("search"),
            None,
            vec!["search".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "POST",
            "/search",
            Some("search"),
            None,
            vec!["search".to_string()],
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "ANY",
            "/fallback",
            Some("fallback"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::Medium,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/reports",
            Some("dynamic_reports"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::Medium,
        )));
        assert!(summaries.contains(&(
            "GET",
            "<dynamic>",
            Some("generated_path"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::Medium,
        )));

        assert!(output.routes.iter().all(|route| route.span.is_some()));
        assert!(output.routes.iter().all(|route| {
            route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .is_some()
        }));
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fastapi_dynamic_api_route_methods")
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fastapi_dynamic_router_prefix")
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fastapi_dynamic_include_router_prefix")
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "fastapi_dynamic_route_path")
        );
    }

    #[test]
    fn discovers_express_routes_middleware_chains_and_mounted_prefixes() {
        let parsed = parse_fixtures(&[
            "express/app.js",
            "express/routes/admin.js",
            "express/routes/exported.ts",
            "express/routes/users.ts",
        ]);
        let output = ExpressAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(output.routes.len(), 16);
        assert!(
            output
                .routes
                .iter()
                .all(|route| route.framework == Framework::Express)
        );
        assert!(output.routes.iter().all(|route| route.span.is_some()));
        assert!(output.routes.iter().all(|route| {
            route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .is_some()
        }));

        let health = route(&output, "GET", "/health");
        assert_eq!(
            health.handler.as_ref().map(|handler| handler.name.as_str()),
            Some("<inline_handler>")
        );
        assert_eq!(middleware_names(health), vec!["requireAuth"]);
        assert_eq!(health.confidence, Confidence::High);

        let accounts = route(&output, "POST", "/accounts");
        assert_eq!(
            accounts
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("listAccounts")
        );
        assert_eq!(middleware_names(accounts), vec!["requireAuth", "audit"]);
        assert_eq!(
            accounts
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .map(|span| span.line),
            Some(42)
        );

        let admin_jobs = route(&output, "POST", "/admin/jobs");
        assert_eq!(
            middleware_names(admin_jobs),
            vec!["requireAuth", "requireRole"]
        );

        let permissions = route(&output, "PATCH", "/accounts/:id/permissions");
        assert_eq!(middleware_names(permissions), vec!["requirePermission"]);

        let dynamic = route(&output, "DELETE", "<dynamic>");
        assert_eq!(dynamic.confidence, Confidence::Low);
        assert!(
            dynamic
                .notes
                .iter()
                .any(|note| note.contains("dynamic") && note.contains("<dynamic>"))
        );

        let mounted = route(&output, "PUT", "/api/:id");
        assert_eq!(middleware_names(mounted), vec!["requireAuth"]);

        let nested = route(&output, "GET", "/api/nested/child");
        assert_eq!(
            nested.handler.as_ref().map(|handler| handler.name.as_str()),
            Some("listAccounts")
        );
        assert_eq!(middleware_names(nested), vec!["requireAuth", "audit"]);

        let dynamic_mount = route(&output, "GET", "/child");
        assert_eq!(dynamic_mount.confidence, Confidence::Medium);
        assert!(
            dynamic_mount
                .notes
                .iter()
                .any(|note| note.contains("mount prefix is dynamic"))
        );

        let admin = route(&output, "GET", "/admin/dashboard");
        assert_eq!(
            admin.handler.as_ref().map(|handler| handler.name.as_str()),
            Some("listAdmins")
        );
        assert_eq!(middleware_names(admin), vec!["requireAdmin"]);

        let users_get = route(&output, "GET", "/v1/:userId");
        assert_eq!(
            users_get
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("<inline_handler>")
        );
        assert_eq!(middleware_names(users_get), vec!["requireUser"]);

        let secure_users_get = route(&output, "GET", "/secure/:userId");
        assert_eq!(
            middleware_names(secure_users_get),
            vec!["requireAuth", "requireUser"]
        );

        let users_post = route(&output, "POST", "/v1/:userId");
        assert_eq!(
            users_post
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("updateUser")
        );
        assert_eq!(
            users_post
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .map(|span| span.line),
            Some(16)
        );

        let tenant_settings = route(&output, "GET", "/v1/:tenantId/settings");
        assert_eq!(middleware_names(tenant_settings), vec!["requireTenant"]);

        let exported = route(&output, "PATCH", "/exported/audit");
        assert_eq!(
            exported
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("exportAudit")
        );

        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "express_dynamic_route_path")
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "express_dynamic_mount_prefix")
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "express_unresolved_mount_router")
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "express_cyclic_mount_router")
        );
    }

    #[test]
    fn discovers_django_urlpatterns_drf_routers_and_uncertainty() {
        let parsed = parse_fixtures(&[
            "django/project/urls.py",
            "django/accounts/urls.py",
            "django/accounts/views.py",
            "django/accounts/services.py",
            "django/accounts/models.py",
        ]);
        let output = DjangoAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(output.routes.len(), 13);
        assert!(output.routes.iter().all(|route| route.span.is_some()));
        assert!(output.routes.iter().all(|route| {
            route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .is_some()
        }));

        let index = route(&output, "ANY", "/accounts");
        assert_eq!(index.framework, Framework::Django);
        assert_eq!(
            index.handler.as_ref().map(|handler| handler.name.as_str()),
            Some("index")
        );
        assert!(
            index
                .source_evidence
                .iter()
                .any(|evidence| evidence.mechanism == "django_include")
        );

        let class_based = route(&output, "ANY", "/accounts/users/<int:pk>/");
        assert_eq!(
            class_based
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("AccountDetailView")
        );
        assert_eq!(
            class_based
                .extensions
                .get("authmap.django")
                .and_then(|value| value.get("handler_kind"))
                .and_then(serde_json::Value::as_str),
            Some("class_based_view")
        );

        let create = route(&output, "POST", "/accounts/api/users");
        assert_eq!(create.framework, Framework::DjangoRestFramework);
        assert_eq!(
            create
                .extensions
                .get("authmap.django")
                .and_then(|value| value.get("handler_kind"))
                .and_then(serde_json::Value::as_str),
            Some("viewset_standard")
        );

        let action = route(&output, "POST", "/accounts/api/users/{uuid}/disable");
        assert_eq!(
            action
                .extensions
                .get("authmap.django")
                .and_then(|value| value.get("method_name"))
                .and_then(serde_json::Value::as_str),
            Some("disable")
        );
        assert!(
            output
                .routes
                .iter()
                .any(|route| route.path == "<dynamic>" && route.confidence == Confidence::Medium)
        );

        for code in [
            "django_dynamic_include",
            "django_dynamic_url_path",
            "drf_dynamic_router_prefix",
            "drf_dynamic_basename",
            "django_custom_router",
        ] {
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "missing diagnostic {code}"
            );
        }
    }

    #[test]
    fn normalizes_posix_absolute_relative_js_imports() {
        assert_eq!(
            super::normalize_js_module_path(
                "/home/runner/project/tests/fixtures/express",
                "./routes/users"
            ),
            "/home/runner/project/tests/fixtures/express/routes/users"
        );
        assert_eq!(
            super::normalize_js_module_path(
                "/home/runner/project/tests/fixtures/express/routes",
                "../shared/index"
            ),
            "/home/runner/project/tests/fixtures/express/shared/index"
        );
    }

    fn route<'a>(
        output: &'a super::AdapterOutput,
        method: &str,
        path: &str,
    ) -> &'a authmap_core::Route {
        output
            .routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("missing {method} {path}"))
    }

    fn middleware_names(route: &authmap_core::Route) -> Vec<&str> {
        route
            .middleware
            .iter()
            .map(|middleware| middleware.name.as_str())
            .collect()
    }

    fn parse_fixtures(names: &[&str]) -> Vec<authmap_parsers::ParsedFile> {
        let backend = TreeSitterBackend;
        names
            .iter()
            .map(|name| {
                let path = fixture_path(name);
                let text = fs::read_to_string(&path).expect("fixture should be readable");
                let source = SourceFile {
                    path: path.to_string_lossy().replace('\\', "/"),
                    language: language_for_fixture(name),
                    size_bytes: text.len() as u64,
                    sha256: None,
                    project_hints: Vec::new(),
                    skipped: None,
                };
                backend
                    .parse(&source, &text)
                    .expect("fixture should parse as Python")
            })
            .collect()
    }

    fn language_for_fixture(name: &str) -> Language {
        match name.rsplit('.').next() {
            Some("py") => Language::Python,
            Some("js") => Language::JavaScript,
            Some("jsx") => Language::JavaScriptReact,
            Some("ts") => Language::TypeScript,
            Some("tsx") => Language::TypeScriptReact,
            _ => Language::Unknown,
        }
    }
}
