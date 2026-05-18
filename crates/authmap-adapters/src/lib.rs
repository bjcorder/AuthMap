use std::collections::{BTreeMap, BTreeSet, HashMap};

use authmap_core::{
    Confidence, Diagnostic, DiagnosticCategory, DiagnosticSeverity, Evidence, Framework, Mutation,
    Recoverability, Route, SourceEvidence, Span, SymbolRef,
};
use authmap_parsers::ParsedFile;
use tree_sitter::{Node, Tree};

mod django;
mod nextjs;

pub use django::DjangoAdapter;
pub use nextjs::NextJsAdapter;

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

#[derive(Clone, Debug, Default)]
pub struct TrpcAdapter;

impl FrameworkAdapter for TrpcAdapter {
    fn name(&self) -> &'static str {
        "trpc"
    }

    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        _context: &AdapterContext,
    ) -> AdapterOutput {
        let mut routes = Vec::new();
        for parsed in parsed_files.iter().filter(|file| {
            matches!(
                file.language,
                authmap_core::Language::JavaScript
                    | authmap_core::Language::JavaScriptReact
                    | authmap_core::Language::TypeScript
                    | authmap_core::Language::TypeScriptReact
            )
        }) {
            if !parsed.text.contains("Procedure") && !parsed.text.contains("procedure") {
                continue;
            }
            let router_name = trpc_router_name(&parsed.source.path);
            for (line_index, line) in parsed.text.lines().enumerate() {
                let Some((name, procedure)) = trpc_procedure_from_line(line) else {
                    continue;
                };
                let Some(kind) = trpc_operation_kind(line) else {
                    continue;
                };
                let span = Span {
                    file: parsed.source.path.clone(),
                    line: line_index as u32 + 1,
                    column: line.find(&name).unwrap_or_default() as u32,
                    byte_range: None,
                };
                let mut extensions = authmap_core::ExtensionMap::new();
                extensions.insert(
                    "authmap.trpc".to_string(),
                    serde_json::json!({
                        "router": router_name,
                        "procedure": name,
                        "procedure_root": procedure,
                        "operation_kind": kind,
                    }),
                );
                let path = format!("/trpc/{router_name}/{name}");
                routes.push(Route {
                    id: String::new(),
                    framework: Framework::Trpc,
                    method: if kind == "mutation" { "POST" } else { "GET" }.to_string(),
                    path,
                    name: Some(name.clone()),
                    tags: Vec::new(),
                    middleware: Vec::new(),
                    handler: Some(SymbolRef {
                        name: format!("{router_name}.{name}"),
                        span: Some(span.clone()),
                    }),
                    span: Some(span.clone()),
                    source_evidence: vec![authmap_source_evidence(
                        "trpc_procedure",
                        &procedure,
                        span.clone(),
                        Confidence::Medium,
                    )],
                    confidence: Confidence::Medium,
                    notes: Vec::new(),
                    extensions,
                });
            }
        }
        routes.sort_by_key(route_sort_key);
        for (index, route) in routes.iter_mut().enumerate() {
            route.id = format!("route_{:04}", index + 1);
        }
        AdapterOutput {
            routes,
            ..AdapterOutput::default()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GraphqlAdapter;

impl FrameworkAdapter for GraphqlAdapter {
    fn name(&self) -> &'static str {
        "graphql"
    }

    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        _context: &AdapterContext,
    ) -> AdapterOutput {
        let mut candidates = Vec::new();
        for parsed in parsed_files
            .iter()
            .filter(|file| file.language == authmap_core::Language::Python)
        {
            if !parsed.text.contains("graphene")
                && !parsed.text.contains("BaseMutation")
                && !parsed.text.contains("permissions")
            {
                continue;
            }
            for class in python_top_level_classes(parsed) {
                if graphql_schema_container_class(&class) {
                    candidates.extend(graphql_routes_from_container(parsed, &class));
                } else if let Some(route) = graphql_route_from_class(parsed, &class) {
                    candidates.push(route);
                }
            }
        }
        let mut routes = dedup_graphql_routes(candidates);
        routes.sort_by_key(route_sort_key);
        for (index, route) in routes.iter_mut().enumerate() {
            route.id = format!("route_{:04}", index + 1);
        }
        AdapterOutput {
            routes,
            ..AdapterOutput::default()
        }
    }
}

fn trpc_router_name(path: &str) -> String {
    path.replace('\\', "/")
        .rsplit_once('/')
        .map_or(path, |(_, file)| file)
        .trim_end_matches(".ts")
        .trim_end_matches(".tsx")
        .trim_end_matches(".js")
        .trim_end_matches(".jsx")
        .trim_start_matches('_')
        .trim_end_matches("_router")
        .to_string()
}

fn trpc_procedure_from_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(':')?;
    let name = name
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    for procedure in [
        "authedAdminProcedure",
        "authedOrgAdminProcedure",
        "authedProcedure",
        "protectedProcedure",
        "publicProcedure",
    ] {
        if rest.contains(procedure) {
            return Some((name.to_string(), procedure.to_string()));
        }
    }
    None
}

fn trpc_operation_kind(line: &str) -> Option<&'static str> {
    if line.contains(".mutation") {
        Some("mutation")
    } else if line.contains(".query") {
        Some("query")
    } else {
        None
    }
}

fn python_class_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("class ")?;
    let end = rest.find(['(', ':']).unwrap_or(rest.len());
    let name = rest[..end].trim();
    (!name.is_empty()).then(|| name.to_string())
}

#[derive(Clone, Debug)]
struct PythonTopLevelClass {
    name: String,
    line: usize,
    declaration: String,
    body: Vec<(usize, String)>,
}

fn python_top_level_classes(parsed: &ParsedFile) -> Vec<PythonTopLevelClass> {
    let mut classes = Vec::new();
    let mut current: Option<PythonTopLevelClass> = None;
    for (line_index, line) in parsed.text.lines().enumerate() {
        let line_number = line_index + 1;
        let trimmed = line.trim();
        if line == line.trim_start()
            && let Some(name) = python_class_name(trimmed)
        {
            if let Some(class) = current.take() {
                classes.push(class);
            }
            current = Some(PythonTopLevelClass {
                name,
                line: line_number,
                declaration: trimmed.to_string(),
                body: Vec::new(),
            });
        } else if let Some(class) = current.as_mut() {
            class.body.push((line_number, line.to_string()));
        }
    }
    if let Some(class) = current {
        classes.push(class);
    }
    classes
}

fn graphql_class_bases(class: &PythonTopLevelClass) -> Vec<String> {
    let Some((_, rest)) = class.declaration.split_once('(') else {
        return Vec::new();
    };
    let Some((bases, _)) = rest.rsplit_once(')') else {
        return Vec::new();
    };
    bases
        .split(',')
        .map(|base| base.trim().to_string())
        .filter(|base| !base.is_empty())
        .collect()
}

fn graphql_schema_container_class(class: &PythonTopLevelClass) -> bool {
    (class.name.ends_with("Queries") || class.name.ends_with("Mutations"))
        && graphql_class_bases(class)
            .iter()
            .any(|base| graphql_terminal_base(base) == "ObjectType")
}

fn graphql_concrete_operation_class(class: &PythonTopLevelClass) -> bool {
    if graphql_abstract_mutation_class_name(&class.name) || graphql_schema_container_class(class) {
        return false;
    }
    graphql_class_bases(class).iter().any(|base| {
        let terminal = graphql_terminal_base(base);
        matches!(
            terminal.as_str(),
            "BaseMutation" | "ModelMutation" | "ModelDeleteMutation" | "DeprecatedModelMutation"
        ) || terminal == "Mutation"
            || terminal.ends_with("Mutation") && !matches!(terminal.as_str(), "InputObjectType")
    })
}

fn graphql_abstract_mutation_class_name(name: &str) -> bool {
    matches!(
        name,
        "BaseMutation" | "ModelMutation" | "ModelDeleteMutation" | "DeprecatedModelMutation"
    )
}

fn graphql_terminal_base(base: &str) -> String {
    base.rsplit('.').next().unwrap_or(base).trim().to_string()
}

fn graphql_route_from_class(parsed: &ParsedFile, class: &PythonTopLevelClass) -> Option<Route> {
    if !graphql_concrete_operation_class(class) {
        return None;
    }
    let permissions = graphql_class_permissions(class);
    Some(graphql_route(
        parsed,
        class.line,
        "mutation",
        lower_camel(&class.name),
        Some(class.name.clone()),
        None,
        permissions,
        &class.name,
        "graphql_operation_class",
    ))
}

fn graphql_routes_from_container(parsed: &ParsedFile, class: &PythonTopLevelClass) -> Vec<Route> {
    let operation_kind = if class.name.ends_with("Queries") {
        "query"
    } else {
        "mutation"
    };
    let mut routes = Vec::new();
    for block in graphql_container_field_blocks(class) {
        let Some((field_name, target_name)) = graphql_field_operation(&block) else {
            continue;
        };
        let operation_name = lower_camel(target_name.as_deref().unwrap_or(&field_name));
        let permissions = graphql_permissions_from_lines(block.iter().map(|(_, line)| line));
        let line = block.first().map_or(class.line, |(line, _)| *line);
        let handler_name = target_name.clone().unwrap_or_else(|| field_name.clone());
        routes.push(graphql_route(
            parsed,
            line,
            operation_kind,
            operation_name,
            target_name,
            Some(field_name),
            permissions,
            &handler_name,
            "graphql_root_field",
        ));
    }
    routes
}

fn graphql_container_field_blocks(class: &PythonTopLevelClass) -> Vec<Vec<(usize, String)>> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<(usize, String)>> = None;
    for (line, text) in &class.body {
        if graphql_direct_class_assignment(text) {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(vec![(*line, text.clone())]);
        } else if let Some(block) = current.as_mut()
            && (text.trim().is_empty() || leading_spaces(text) > 4)
        {
            block.push((*line, text.clone()));
        } else if let Some(block) = current.take() {
            blocks.push(block);
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }
    blocks
}

fn graphql_direct_class_assignment(line: &str) -> bool {
    leading_spaces(line) == 4
        && !line.trim_start().starts_with('@')
        && !line.trim_start().starts_with("def ")
        && !line.trim_start().starts_with("class ")
        && line.trim().contains(" = ")
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn graphql_field_operation(block: &[(usize, String)]) -> Option<(String, Option<String>)> {
    let first = block.first()?.1.trim();
    let (field, right) = first.split_once('=')?;
    let field_name = field.trim().to_string();
    if field_name.is_empty() || field_name.starts_with('_') {
        return None;
    }
    if let Some((target, _)) = right.split_once(".Field(") {
        let target = graphql_terminal_base(target.trim());
        if !target.is_empty() {
            return Some((field_name, Some(target)));
        }
    }
    let joined = block
        .iter()
        .map(|(_, line)| line.trim())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.contains("Field(")
        || joined.contains("graphene.List(")
        || joined.contains("graphene.Field(")
    {
        Some((field_name, None))
    } else {
        None
    }
}

fn graphql_class_permissions(class: &PythonTopLevelClass) -> Option<String> {
    graphql_permissions_from_lines(class.body.iter().map(|(_, line)| line))
}

fn graphql_permissions_from_lines<'a>(lines: impl Iterator<Item = &'a String>) -> Option<String> {
    let lines = lines.collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let permission_offset = trimmed
            .find("permissions =")
            .or_else(|| trimmed.find("permissions="));
        if let Some(offset) = permission_offset {
            let mut value = trimmed[offset..].trim_end_matches(',').to_string();
            if !graphql_permissions_balanced(&value) {
                for next in lines.iter().skip(index + 1) {
                    let next_trimmed = next.trim();
                    value.push(' ');
                    value.push_str(next_trimmed.trim_end_matches(','));
                    if graphql_permissions_balanced(&value) {
                        break;
                    }
                }
            }
            return Some(value);
        }
    }
    None
}

fn graphql_permissions_balanced(value: &str) -> bool {
    let open_parens = value.matches('(').count();
    let close_parens = value.matches(')').count();
    let open_brackets = value.matches('[').count();
    let close_brackets = value.matches(']').count();
    open_parens <= close_parens && open_brackets <= close_brackets
}

fn graphql_route(
    parsed: &ParsedFile,
    line: usize,
    operation_kind: &str,
    operation_name: String,
    class_name: Option<String>,
    field_name: Option<String>,
    permissions: Option<String>,
    handler_name: &str,
    source_mechanism: &str,
) -> Route {
    let span = Span {
        file: parsed.source.path.clone(),
        line: line as u32,
        column: 0,
        byte_range: None,
    };
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.graphql".to_string(),
        serde_json::json!({
            "operation": operation_name,
            "operation_kind": operation_kind,
            "class_name": class_name,
            "field_name": field_name,
            "permissions": permissions,
        }),
    );
    Route {
        id: String::new(),
        framework: Framework::Graphql,
        method: if operation_kind == "mutation" {
            "MUTATION"
        } else {
            "QUERY"
        }
        .to_string(),
        path: format!("/graphql/{operation_name}"),
        name: Some(operation_name),
        tags: Vec::new(),
        middleware: Vec::new(),
        handler: Some(SymbolRef {
            name: handler_name.to_string(),
            span: Some(span.clone()),
        }),
        span: Some(span.clone()),
        source_evidence: vec![authmap_source_evidence(
            source_mechanism,
            handler_name,
            span.clone(),
            Confidence::Medium,
        )],
        confidence: Confidence::Medium,
        notes: Vec::new(),
        extensions,
    }
}

fn dedup_graphql_routes(routes: Vec<Route>) -> Vec<Route> {
    let mut deduped: BTreeMap<(String, String), Route> = BTreeMap::new();
    for route in routes {
        let key = (route.method.clone(), route.path.clone());
        match deduped.get(&key) {
            Some(existing) if graphql_route_rank(existing) >= graphql_route_rank(&route) => {}
            _ => {
                deduped.insert(key, route);
            }
        }
    }
    deduped.into_values().collect()
}

fn graphql_route_rank(route: &Route) -> u8 {
    let has_permissions = route
        .extensions
        .get("authmap.graphql")
        .and_then(|value| value.get("permissions"))
        .is_some_and(|value| !value.is_null());
    let is_class_route = route
        .source_evidence
        .iter()
        .any(|item| item.mechanism == "graphql_operation_class");
    match (has_permissions, is_class_route) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

fn lower_camel(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    format!(
        "{}{}",
        first.to_ascii_lowercase(),
        chars.collect::<String>()
    )
}

fn authmap_source_evidence(
    mechanism: &str,
    symbol_name: &str,
    span: Span,
    confidence: Confidence,
) -> SourceEvidence {
    SourceEvidence {
        mechanism: mechanism.to_string(),
        symbol: Some(SymbolRef {
            name: symbol_name.to_string(),
            span: Some(span.clone()),
        }),
        span: Some(span),
        confidence,
        notes: Vec::new(),
        extensions: authmap_core::ExtensionMap::new(),
    }
}

impl AdapterRegistry {
    pub fn built_in() -> Self {
        Self {
            adapters: vec![
                Box::new(FastApiAdapter),
                Box::new(DjangoAdapter),
                Box::new(ExpressAdapter),
                Box::new(NextJsAdapter),
                Box::new(TrpcAdapter),
                Box::new(GraphqlAdapter),
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
                static_strings: HashMap::new(),
                dependency_lists: Vec::new(),
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
    dependencies: Vec<SymbolRef>,
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
    collection_name: Option<String>,
    prefix: Option<String>,
    dependencies: Vec<SymbolRef>,
    dynamic_prefix: bool,
}

#[derive(Clone, Debug)]
struct RouterFactory {
    file: String,
    name: String,
    router_name: String,
}

#[derive(Clone, Debug)]
struct RouterReference {
    file: String,
    name: String,
}

#[derive(Clone, Debug)]
struct RouterCollection {
    file: String,
    name: String,
    routers: Vec<RouterReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DependencyListUpdateKind {
    Assignment,
    Mutation,
}

#[derive(Clone, Debug)]
struct DependencyListUpdate {
    name: String,
    symbols: Vec<SymbolRef>,
    dynamic: bool,
    span: Span,
    start_byte: usize,
    kind: DependencyListUpdateKind,
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
    dependencies: Vec<SymbolRef>,
    handler: SymbolRef,
    span: Span,
    notes: Vec<String>,
}

#[derive(Default)]
struct FastApiIndex {
    bindings: Vec<Binding>,
    imports_by_file: HashMap<String, HashMap<String, ImportBinding>>,
    factories: Vec<RouterFactory>,
    collections: Vec<RouterCollection>,
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
        let factories_by_file_name = self
            .factories
            .iter()
            .map(|factory| {
                (
                    (factory.file.clone(), factory.name.clone()),
                    factory.router_name.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        let collections_by_file_name = self
            .collections
            .iter()
            .map(|collection| {
                (
                    (collection.file.clone(), collection.name.clone()),
                    collection.routers.clone(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut emitted = Vec::<Route>::new();
        let mut seen = BTreeSet::<(String, u32, String, String, String)>::new();

        let mut includes_by_parent = HashMap::<(String, String), Vec<IncludeRouter>>::new();

        for include in &self.includes {
            let Some(parent_binding) =
                bindings_by_file_name.get(&(include.file.clone(), include.app_name.clone()))
            else {
                continue;
            };
            includes_by_parent
                .entry((parent_binding.file.clone(), parent_binding.name.clone()))
                .or_default()
                .push(include.clone());
        }

        let routes_by_owner = self.routes.iter().fold(
            HashMap::<(String, String), Vec<&DiscoveredRoute>>::new(),
            |mut routes, route| {
                routes
                    .entry((route.owner_file.clone(), route.owner_name.clone()))
                    .or_default()
                    .push(route);
                routes
            },
        );

        for app_binding in bindings_by_file_name
            .values()
            .filter(|binding| binding.kind == BindingKind::App)
        {
            let mut stack = vec![(
                app_binding.clone(),
                None::<String>,
                Vec::<SymbolRef>::new(),
                false,
            )];
            let mut visited = BTreeSet::<(String, String, String, String, bool)>::new();
            while let Some((binding, prefix, dependencies, dynamic_prefix)) = stack.pop() {
                let visit_key = (
                    binding.file.clone(),
                    binding.name.clone(),
                    prefix.clone().unwrap_or_default(),
                    dependencies
                        .iter()
                        .map(|dependency| dependency.name.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    dynamic_prefix,
                );
                if !visited.insert(visit_key) {
                    continue;
                }

                if let Some(routes) =
                    routes_by_owner.get(&(binding.file.clone(), binding.name.clone()))
                {
                    for route in routes {
                        if let Some(emitted_route) = build_route(
                            route,
                            prefix.as_deref(),
                            &dependencies,
                            dynamic_prefix,
                            &binding,
                        ) {
                            push_unique(&mut emitted, &mut seen, emitted_route);
                        }
                    }
                }

                let parent_prefix = prefix_with_binding(prefix.as_deref(), &binding);
                let Some(includes) =
                    includes_by_parent.get(&(binding.file.clone(), binding.name.clone()))
                else {
                    continue;
                };
                for include in includes {
                    let include_prefix =
                        join_optional_paths(parent_prefix.as_deref(), include.prefix.as_deref());
                    let mut include_dependencies = dependencies.clone();
                    include_dependencies.extend(include.dependencies.clone());
                    let include_dynamic_prefix =
                        dynamic_prefix || binding.dynamic_prefix || include.dynamic_prefix;
                    for target in resolve_fastapi_include_targets(
                        include,
                        &router_bindings_by_file_name,
                        &factories_by_file_name,
                        &collections_by_file_name,
                    ) {
                        stack.push((
                            target,
                            include_prefix.clone(),
                            include_dependencies.clone(),
                            include_dynamic_prefix,
                        ));
                    }
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
    include_dependencies: &[SymbolRef],
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
    let mut middleware = owner_binding.dependencies.clone();
    middleware.extend(include_dependencies.iter().cloned());
    middleware.extend(route.dependencies.clone());

    Some(Route {
        id: String::new(),
        framework: Framework::FastApi,
        method: route.method.clone(),
        path,
        name: route.name.clone(),
        tags,
        middleware,
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
) -> bool {
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
        true
    } else {
        false
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
    static_strings: HashMap<String, String>,
    dependency_lists: Vec<DependencyListUpdate>,
}

impl<'a> FileCollector<'a> {
    fn collect(&mut self, root: Node<'_>) {
        self.index.imports_by_file.insert(
            self.parsed.source.path.clone(),
            parse_imports(self.parsed, self.module_index),
        );
        self.static_strings = collect_module_static_strings(self.parsed, root);
        self.walk_for_bindings(root);
        self.walk_for_dependency_lists(root);
        self.walk_for_factories(root);
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

    fn walk_for_factories(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_definition" {
                self.collect_router_factory(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn walk_for_dependency_lists(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "assignment" => self.collect_dependency_list_assignment(node),
                "call" => self.collect_dependency_list_mutation(node),
                _ => {}
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
        self.dependency_lists
            .sort_by_key(|update| (update.start_byte, update.name.clone()));
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
        if is_router_collection_literal(self.parsed, right) {
            self.collect_router_collection(name, right);
            return;
        }
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
            name if name.ends_with("Router") => BindingKind::Router,
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
            dependencies: fastapi_dependencies_from_keyword(self.parsed, call, "dependencies"),
            dynamic_prefix,
        });
    }

    fn collect_dependency_list_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Some(name) = identifier_text(self.parsed, left) else {
            return;
        };
        let symbols = fastapi_dependency_symbols(self.parsed, right);
        let sequence = matches!(right.kind(), "list" | "tuple");
        if symbols.is_empty() && !(sequence && name.to_ascii_lowercase().contains("dependenc")) {
            return;
        }
        self.dependency_lists.push(DependencyListUpdate {
            name,
            symbols,
            dynamic: !sequence,
            span: self.parsed.span_for(right),
            start_byte: node.start_byte(),
            kind: DependencyListUpdateKind::Assignment,
        });
    }

    fn collect_dependency_list_mutation(&mut self, node: Node<'_>) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let Some((name, method)) = attribute_target(self.parsed, function) else {
            return;
        };
        if !matches!(method.as_str(), "append" | "extend") {
            return;
        }
        let Some(argument) = first_argument_node(node) else {
            return;
        };
        let symbols = fastapi_dependency_symbols(self.parsed, argument);
        if symbols.is_empty() && !name.to_ascii_lowercase().contains("dependenc") {
            return;
        }
        let dynamic = symbols.is_empty();
        self.dependency_lists.push(DependencyListUpdate {
            name,
            symbols,
            dynamic,
            span: self.parsed.span_for(argument),
            start_byte: node.start_byte(),
            kind: DependencyListUpdateKind::Mutation,
        });
    }

    fn collect_router_collection(&mut self, name: String, value: Node<'_>) {
        let routers = router_references_from_collection(
            self.parsed,
            value,
            self.index.imports_by_file.get(&self.parsed.source.path),
        );
        if routers.is_empty() {
            return;
        }
        self.index.collections.push(RouterCollection {
            file: self.parsed.source.path.clone(),
            name,
            routers,
        });
    }

    fn collect_router_factory(&mut self, node: Node<'_>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(name) = identifier_text(self.parsed, name_node) else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let mut stack = vec![body];
        while let Some(current) = stack.pop() {
            if current.kind() == "return_statement"
                && let Some(argument) = return_argument(current)
                && let Some(router_name) = identifier_text(self.parsed, argument)
            {
                self.index.factories.push(RouterFactory {
                    file: self.parsed.source.path.clone(),
                    name,
                    router_name,
                });
                return;
            }
            let mut cursor = current.walk();
            stack.extend(current.children(&mut cursor));
        }
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
            let route_path_strings = route_path_static_strings(
                self.parsed,
                call,
                function_default_static_strings(
                    self.parsed,
                    enclosing_python_function(call),
                    &self.static_strings,
                ),
                &self.static_strings,
            );
            let (mut path, dynamic_path) = route_path(self.parsed, call, &route_path_strings);
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
                    dependencies: fastapi_dependencies_from_keyword(
                        self.parsed,
                        call,
                        "dependencies",
                    ),
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

        let Some((router_name, mut collection_name)) = first_router_argument(self.parsed, node)
        else {
            return;
        };
        if collection_name.is_none() {
            collection_name = enclosing_for_collection(self.parsed, node, &router_name);
        }

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
            collection_name,
            prefix,
            dependencies: self.fastapi_include_dependencies(node),
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

    fn fastapi_include_dependencies(&self, call: Node<'_>) -> Vec<SymbolRef> {
        let Some(value) = keyword_value(self.parsed, call, "dependencies") else {
            return Vec::new();
        };
        let direct = fastapi_dependency_symbols(self.parsed, value);
        if !direct.is_empty() || matches!(value.kind(), "list" | "tuple") {
            return direct;
        }
        if let Some(name) = identifier_text(self.parsed, value) {
            if let Some(mut resolved) = self.resolve_dependency_list(&name, call.start_byte()) {
                if resolved.is_empty() {
                    return Vec::new();
                }
                return resolved.drain(..).collect();
            }
        }
        vec![dynamic_fastapi_dependency_symbol(self.parsed, value)]
    }

    fn resolve_dependency_list(&self, name: &str, before_byte: usize) -> Option<Vec<SymbolRef>> {
        let updates = self
            .dependency_lists
            .iter()
            .filter(|update| update.name == name && update.start_byte < before_byte)
            .collect::<Vec<_>>();
        if updates.is_empty() {
            return None;
        }
        let start = updates
            .iter()
            .rposition(|update| update.kind == DependencyListUpdateKind::Assignment)
            .unwrap_or(0);
        let mut symbols = Vec::new();
        let mut dynamic_span = None;
        for update in updates.into_iter().skip(start) {
            for symbol in &update.symbols {
                push_unique_symbol_ref(&mut symbols, symbol.clone());
            }
            if update.dynamic {
                dynamic_span = Some(update.span.clone());
            }
        }
        if let Some(span) = dynamic_span {
            push_unique_symbol_ref(
                &mut symbols,
                SymbolRef {
                    name: "dynamic_policy_dependencies".to_string(),
                    span: Some(span),
                },
            );
        }
        Some(symbols)
    }
}

fn return_argument(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|child| child.is_named())
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

#[derive(Clone, Debug)]
enum StaticStringExpr {
    Literal(String),
    Alias(String),
}

fn collect_module_static_strings(parsed: &ParsedFile, root: Node<'_>) -> HashMap<String, String> {
    let mut raw = Vec::<(String, StaticStringExpr)>::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "assignment" | "annotated_assignment")
            && !is_inside_python_definition(node)
            && let Some((name, value)) = static_string_assignment(parsed, node)
        {
            raw.push((name, value));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor).filter(|child| child.is_named()));
    }
    resolve_static_string_assignments(raw, &HashMap::new())
}

fn function_default_static_strings(
    parsed: &ParsedFile,
    function: Option<Node<'_>>,
    module_strings: &HashMap<String, String>,
) -> HashMap<String, String> {
    let Some(function) = function else {
        return HashMap::new();
    };
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return HashMap::new();
    };
    let mut raw = Vec::<(String, StaticStringExpr)>::new();
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "default_parameter" | "typed_default_parameter")
            && let Some(name_node) = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("pattern"))
            && let Some(value_node) = node.child_by_field_name("value")
            && let Some(name) = identifier_text(parsed, name_node)
            && let Some(value) = static_string_expr(parsed, value_node)
        {
            raw.push((name, value));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor).filter(|child| child.is_named()));
    }
    if raw.is_empty() {
        raw = function_default_static_strings_from_text(parsed, parameters);
    }
    resolve_static_string_assignments(raw, module_strings)
}

fn function_local_static_strings(
    parsed: &ParsedFile,
    function: Node<'_>,
    base_strings: &HashMap<String, String>,
) -> HashMap<String, String> {
    let Some(body) = function.child_by_field_name("body") else {
        return HashMap::new();
    };
    let mut raw = Vec::<(String, StaticStringExpr)>::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "assignment" | "annotated_assignment")
            && enclosing_python_function(node).is_some_and(|parent| parent.id() == function.id())
            && let Some((name, value)) = static_string_assignment(parsed, node)
        {
            raw.push((name, value));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor).filter(|child| child.is_named()));
    }
    resolve_static_string_assignments(raw, base_strings)
}

fn static_string_assignment(
    parsed: &ParsedFile,
    node: Node<'_>,
) -> Option<(String, StaticStringExpr)> {
    let left = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))?;
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))?;
    let name = identifier_text(parsed, left)?;
    let value = static_string_expr(parsed, right)?;
    Some((name, value))
}

fn static_string_expr(parsed: &ParsedFile, node: Node<'_>) -> Option<StaticStringExpr> {
    if let Some(value) = string_literal(parsed, node) {
        return Some(StaticStringExpr::Literal(value));
    }
    identifier_text(parsed, node).map(StaticStringExpr::Alias)
}

fn resolve_static_string_assignments(
    raw: Vec<(String, StaticStringExpr)>,
    base: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut resolved = base.clone();
    let mut pending = raw;
    let mut changed = true;
    while changed {
        changed = false;
        pending.retain(|(name, value)| {
            let next = match value {
                StaticStringExpr::Literal(value) => Some(value.clone()),
                StaticStringExpr::Alias(alias) => resolved.get(alias).cloned(),
            };
            if let Some(next) = next {
                resolved.insert(name.clone(), next);
                changed = true;
                false
            } else {
                true
            }
        });
    }
    resolved
        .into_iter()
        .filter(|(name, _)| !base.contains_key(name))
        .collect()
}

fn function_default_static_strings_from_text(
    parsed: &ParsedFile,
    parameters: Node<'_>,
) -> Vec<(String, StaticStringExpr)> {
    let Some(text) = parsed.text_for(parameters) else {
        return Vec::new();
    };
    text.trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(',')
        .filter_map(|parameter| {
            let (left, right) = parameter.split_once('=')?;
            let name = left
                .rsplit_once(':')
                .map_or(left, |(name, _)| name)
                .trim()
                .trim_start_matches('*')
                .trim();
            if name.is_empty() {
                return None;
            }
            let value = decode_python_string_literal(right.trim())
                .map(StaticStringExpr::Literal)
                .or_else(|| {
                    right
                        .trim()
                        .chars()
                        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
                        .then(|| StaticStringExpr::Alias(right.trim().to_string()))
                })?;
            Some((name.to_string(), value))
        })
        .collect()
}

fn enclosing_python_function(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(node) = current {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        current = node.parent();
    }
    None
}

fn is_inside_python_definition(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(node) = current {
        if matches!(node.kind(), "function_definition" | "class_definition") {
            return true;
        }
        current = node.parent();
    }
    false
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

fn route_path(
    parsed: &ParsedFile,
    call: Node<'_>,
    static_strings: &HashMap<String, String>,
) -> (Option<String>, bool) {
    if let Some(argument) = first_argument_node(call) {
        return (
            static_string_value(parsed, argument, static_strings),
            !static_string_expr_is_resolved(parsed, argument, static_strings),
        );
    }
    let keyword_path = keyword_value(parsed, call, "path")
        .and_then(|value| static_string_value(parsed, value, static_strings));
    let unresolved_keyword_path = keyword_path.is_none();
    let dynamic = keyword_exists(parsed, call, "path") || first_argument_exists(call);
    (keyword_path, dynamic && unresolved_keyword_path)
}

fn route_path_static_strings(
    parsed: &ParsedFile,
    call: Node<'_>,
    function_strings: HashMap<String, String>,
    module_strings: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut strings = module_strings.clone();
    strings.extend(function_strings);
    if let Some(function) = enclosing_python_function(call) {
        strings.extend(function_local_static_strings(parsed, function, &strings));
    }
    strings
}

fn static_string_expr_is_resolved(
    parsed: &ParsedFile,
    node: Node<'_>,
    static_strings: &HashMap<String, String>,
) -> bool {
    static_string_value(parsed, node, static_strings).is_some()
}

fn static_string_value(
    parsed: &ParsedFile,
    node: Node<'_>,
    static_strings: &HashMap<String, String>,
) -> Option<String> {
    if let Some(value) = string_literal(parsed, node) {
        return Some(value);
    }
    identifier_text(parsed, node).and_then(|name| static_strings.get(&name).cloned())
}

fn first_argument_node(call: Node<'_>) -> Option<Node<'_>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .find(|child| child.is_named() && child.kind() != "keyword_argument")
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

fn first_router_argument(parsed: &ParsedFile, call: Node<'_>) -> Option<(String, Option<String>)> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        if !child.is_named() || child.kind() == "keyword_argument" {
            continue;
        }
        if let Some(name) = identifier_text(parsed, child) {
            return Some((name, None));
        }
        if child.kind() == "call" {
            let function = child.child_by_field_name("function")?;
            if let Some(name) = terminal_name(parsed, function) {
                return Some((name, None));
            }
        }
        return None;
    }
    None
}

fn enclosing_for_collection(
    parsed: &ParsedFile,
    call: Node<'_>,
    loop_variable: &str,
) -> Option<String> {
    let mut current = call.parent();
    while let Some(node) = current {
        if node.kind() == "for_statement"
            && let Some(text) = parsed.text_for(node)
            && let Some(rest) = text.trim_start().strip_prefix("for ")
            && let Some((left, right)) = rest.split_once(" in ")
            && left.trim() == loop_variable
        {
            let collection = right
                .split([':', '\n'])
                .next()
                .map(str::trim)
                .unwrap_or_default();
            if collection
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
                && !collection.is_empty()
            {
                return Some(collection.to_string());
            }
        }
        current = node.parent();
    }
    None
}

fn router_references_from_collection(
    parsed: &ParsedFile,
    value: Node<'_>,
    imports: Option<&HashMap<String, ImportBinding>>,
) -> Vec<RouterReference> {
    let mut routers = Vec::new();
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        if node != value
            && let Some(reference) = router_reference_from_node(parsed, node, imports)
        {
            routers.push(reference);
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor).filter(|child| child.is_named()));
    }
    routers
}

fn is_router_collection_literal(parsed: &ParsedFile, node: Node<'_>) -> bool {
    if matches!(node.kind(), "list" | "tuple") {
        return true;
    }
    parsed
        .text_for(node)
        .is_some_and(|text| text.trim_start().starts_with('(') && text.contains(','))
}

fn router_reference_from_node(
    parsed: &ParsedFile,
    node: Node<'_>,
    imports: Option<&HashMap<String, ImportBinding>>,
) -> Option<RouterReference> {
    if let Some(name) = identifier_text(parsed, node) {
        if let Some(imported) = imports.and_then(|imports| imports.get(&name)) {
            return Some(RouterReference {
                file: imported.module.clone(),
                name: imported.imported.clone(),
            });
        }
        return Some(RouterReference {
            file: parsed.source.path.clone(),
            name,
        });
    }
    if node.kind() == "call" {
        let function = node.child_by_field_name("function")?;
        let name = terminal_name(parsed, function)?;
        if let Some(imported) = imports.and_then(|imports| imports.get(&name)) {
            return Some(RouterReference {
                file: imported.module.clone(),
                name: imported.imported.clone(),
            });
        }
        return Some(RouterReference {
            file: parsed.source.path.clone(),
            name,
        });
    }
    let text = parsed.text_for(node)?;
    let parts = text
        .split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    let local = parts[0];
    let name = parts.last()?.to_string();
    let module = if let Some(imported) = imports.and_then(|imports| imports.get(local)) {
        let mut module = imported.module.clone();
        module.push('.');
        module.push_str(&imported.imported);
        if parts.len() > 2 {
            module.push('.');
            module.push_str(&parts[1..parts.len() - 1].join("."));
        }
        module
    } else {
        parts[..parts.len() - 1].join(".")
    };
    Some(RouterReference { file: module, name })
}

fn resolve_fastapi_include_targets(
    include: &IncludeRouter,
    router_bindings: &HashMap<(String, String), Binding>,
    factories: &HashMap<(String, String), String>,
    collections: &HashMap<(String, String), Vec<RouterReference>>,
) -> Vec<Binding> {
    if let Some(collection_name) = &include.collection_name {
        let Some(routers) = collections.get(&(include.file.clone(), collection_name.clone()))
        else {
            return Vec::new();
        };
        return routers
            .iter()
            .filter_map(|reference| {
                resolve_fastapi_router_reference(reference, router_bindings, factories)
            })
            .collect();
    }

    let reference = if let Some(imported) = &include.imported {
        RouterReference {
            file: imported.module.clone(),
            name: imported.imported.clone(),
        }
    } else {
        RouterReference {
            file: include.file.clone(),
            name: include.router_name.clone(),
        }
    };
    resolve_fastapi_router_reference(&reference, router_bindings, factories)
        .into_iter()
        .collect()
}

fn resolve_fastapi_router_reference(
    reference: &RouterReference,
    router_bindings: &HashMap<(String, String), Binding>,
    factories: &HashMap<(String, String), String>,
) -> Option<Binding> {
    if let Some(binding) = router_bindings.get(&(reference.file.clone(), reference.name.clone())) {
        return Some(binding.clone());
    }
    if let Some(router_name) = factories.get(&(reference.file.clone(), reference.name.clone())) {
        return router_bindings
            .get(&(reference.file.clone(), router_name.clone()))
            .cloned();
    }
    router_bindings
        .iter()
        .find(|((file, name), _)| name == &reference.name && module_matches(file, &reference.file))
        .map(|(_, binding)| binding.clone())
        .or_else(|| {
            factories
                .iter()
                .find(|((file, name), _)| {
                    name == &reference.name && module_matches(file, &reference.file)
                })
                .and_then(|((file, _), router_name)| {
                    router_bindings
                        .get(&(file.clone(), router_name.clone()))
                        .cloned()
                })
        })
}

fn prefix_with_binding(prefix: Option<&str>, binding: &Binding) -> Option<String> {
    join_optional_paths(prefix, binding.prefix.as_deref())
}

fn join_optional_paths(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(join_paths(left, right)),
        (Some(left), None) => Some(left.to_string()),
        (None, Some(right)) => Some(right.to_string()),
        (None, None) => None,
    }
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

fn fastapi_dependencies_from_keyword(
    parsed: &ParsedFile,
    call: Node<'_>,
    name: &str,
) -> Vec<SymbolRef> {
    let Some(value) = keyword_value(parsed, call, name) else {
        return Vec::new();
    };
    fastapi_dependency_symbols(parsed, value)
}

fn fastapi_dependency_symbols(parsed: &ParsedFile, node: Node<'_>) -> Vec<SymbolRef> {
    let mut symbols = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "call"
            && let Some(function) = current.child_by_field_name("function")
            && terminal_name(parsed, function).as_deref() == Some("Depends")
            && let Some(symbol) = first_python_symbol_argument(parsed, current)
        {
            symbols.push(symbol);
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(
            current
                .children(&mut cursor)
                .filter(|child| child.is_named()),
        );
    }
    symbols
}

fn dynamic_fastapi_dependency_symbol(parsed: &ParsedFile, node: Node<'_>) -> SymbolRef {
    SymbolRef {
        name: "dynamic_policy_dependencies".to_string(),
        span: Some(parsed.span_for(node)),
    }
}

fn push_unique_symbol_ref(symbols: &mut Vec<SymbolRef>, candidate: SymbolRef) {
    if symbols.iter().any(|symbol| symbol.name == candidate.name) {
        return;
    }
    symbols.push(candidate);
}

fn first_python_symbol_argument(parsed: &ParsedFile, call: Node<'_>) -> Option<SymbolRef> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments
        .children(&mut cursor)
        .filter(|child| child.is_named() && child.kind() != "keyword_argument")
    {
        let symbol_node = if child.kind() == "call" {
            child.child_by_field_name("function")?
        } else {
            child
        };
        let name = match symbol_node.kind() {
            "identifier" | "attribute" => parsed.text_for(symbol_node),
            _ => None,
        }?;
        return Some(SymbolRef {
            name: terminal_name(parsed, symbol_node).unwrap_or_else(|| name.to_string()),
            span: Some(parsed.span_for(symbol_node)),
        });
    }
    None
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
    dynamic_prefix_span: Option<Span>,
    span: Span,
}

#[derive(Clone, Debug)]
struct ExpressPrefixMiddleware {
    prefix: String,
    middleware: Vec<SymbolRef>,
}

#[derive(Clone, Debug)]
struct MountedRouter {
    binding: ExpressBinding,
    prefixes: Vec<String>,
    middleware: Vec<SymbolRef>,
    dynamic_prefix: bool,
    dynamic_prefix_spans: Vec<Span>,
    lineage: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
struct ExpressRouteFact {
    owner_file: String,
    owner_name: String,
    scope: Option<String>,
    method: String,
    path: String,
    dynamic_path: bool,
    allow_unbound_owner: bool,
    handler: SymbolRef,
    middleware: Vec<SymbolRef>,
    span: Span,
    notes: Vec<String>,
}

#[derive(Clone, Debug)]
struct ExpressFactory {
    file: String,
    name: String,
    owner_param: String,
    params: Vec<String>,
}

#[derive(Clone, Debug)]
struct ExpressFactoryCall {
    file: String,
    factory_name: String,
    owner_name: String,
    param_values: HashMap<String, String>,
}

#[derive(Default)]
struct ExpressIndex {
    bindings: Vec<ExpressBinding>,
    imports_by_file: HashMap<String, HashMap<String, ExpressImport>>,
    exports_by_file: HashMap<String, ExpressExports>,
    definitions_by_file: HashMap<String, HashMap<String, Span>>,
    mounts: Vec<ExpressMount>,
    prefix_middleware: Vec<ExpressPrefixMiddleware>,
    routes: Vec<ExpressRouteFact>,
    factories: Vec<ExpressFactory>,
    factory_calls: Vec<ExpressFactoryCall>,
    diagnostics: Vec<Diagnostic>,
}

impl ExpressIndex {
    fn into_output(self) -> AdapterOutput {
        let route_facts = self.expanded_route_facts();
        let mut diagnostics = self.diagnostics;
        let mut bindings = HashMap::<(String, String), ExpressBinding>::new();
        for binding in &self.bindings {
            bindings.insert(
                (binding.file.clone(), binding.name.clone()),
                binding.clone(),
            );
        }

        let mut routes = Vec::<Route>::new();
        let mut seen = BTreeSet::<(String, u32, String, String, String)>::new();
        let mut route_diagnostics = BTreeSet::<(String, u32, String)>::new();
        for fact in route_facts
            .iter()
            .filter(|fact| fact.scope.is_none() || fact.allow_unbound_owner)
        {
            let binding = bindings.get(&(fact.owner_file.clone(), fact.owner_name.clone()));
            let Some(binding) = binding else {
                if fact.allow_unbound_owner {
                    if push_unique(
                        &mut routes,
                        &mut seen,
                        express_route(fact, None, &[], false),
                    ) {
                        push_dynamic_route_diagnostic(
                            &mut diagnostics,
                            &mut route_diagnostics,
                            fact,
                        );
                    }
                }
                continue;
            };
            if binding.kind == BindingKind::App {
                if push_unique(
                    &mut routes,
                    &mut seen,
                    express_route(fact, None, &[], false),
                ) {
                    push_dynamic_route_diagnostic(&mut diagnostics, &mut route_diagnostics, fact);
                }
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
                dynamic_prefix_spans: mount.dynamic_prefix_span.iter().cloned().collect(),
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
                let mut dynamic_prefix_spans = parent_mount.dynamic_prefix_spans;
                dynamic_prefix_spans.extend(mount.dynamic_prefix_span.iter().cloned());
                let mut lineage = parent_mount.lineage;
                lineage.push(child_key);
                if mounted.iter().any(|mounted| {
                    mounted.binding.file == child.file
                        && mounted.binding.name == child.name
                        && mounted.prefixes == prefixes
                        && mounted.middleware == middleware
                        && mounted.dynamic_prefix == dynamic
                        && mounted.dynamic_prefix_spans == dynamic_prefix_spans
                }) {
                    continue;
                }
                mounted.push(MountedRouter {
                    binding: child,
                    prefixes,
                    middleware,
                    dynamic_prefix: dynamic,
                    dynamic_prefix_spans,
                    lineage,
                });
                changed = true;
            }
        }

        for mounted in &mounted {
            for fact in route_facts.iter().filter(|fact| {
                fact.scope.is_none()
                    && fact.owner_file == mounted.binding.file
                    && fact.owner_name == mounted.binding.name
            }) {
                let prefix = mounted.prefixes.iter().fold(String::new(), |prefix, next| {
                    if prefix.is_empty() {
                        next.clone()
                    } else {
                        join_paths(&prefix, next)
                    }
                });
                let prefix = (!prefix.is_empty()).then_some(prefix);
                if push_unique(
                    &mut routes,
                    &mut seen,
                    express_route(
                        fact,
                        prefix.as_deref(),
                        &mounted.middleware,
                        mounted.dynamic_prefix,
                    ),
                ) {
                    push_dynamic_route_diagnostic(&mut diagnostics, &mut route_diagnostics, fact);
                    push_dynamic_mount_prefix_diagnostics(
                        &mut diagnostics,
                        &mut route_diagnostics,
                        &mounted.dynamic_prefix_spans,
                    );
                }
            }
        }

        routes.sort_by_key(route_sort_key);
        apply_express_prefix_middleware(&mut routes, &self.prefix_middleware);
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

    fn expanded_route_facts(&self) -> Vec<ExpressRouteFact> {
        let mut facts = self.routes.clone();
        let factories = self
            .factories
            .iter()
            .map(|factory| {
                (
                    (factory.file.clone(), factory.name.clone()),
                    factory.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        for call in &self.factory_calls {
            let Some(factory) = factories.get(&(call.file.clone(), call.factory_name.clone()))
            else {
                continue;
            };
            for fact in self.routes.iter().filter(|fact| {
                fact.owner_file == factory.file
                    && fact.scope.as_deref() == Some(factory.name.as_str())
                    && fact.owner_name == factory.owner_param
            }) {
                let mut fact = fact.clone();
                fact.owner_name = call.owner_name.clone();
                fact.scope = None;
                fact.path = substitute_express_factory_params(&fact.path, &call.param_values);
                facts.push(fact);
            }
        }
        facts
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

fn substitute_express_factory_params(path: &str, values: &HashMap<String, String>) -> String {
    let mut path = path.to_string();
    for (name, value) in values {
        let placeholder = format!("{{{name}}}");
        if path.contains(&placeholder) {
            path = path.replace(&placeholder, value.trim_matches('/'));
        }
    }
    path
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

fn apply_express_prefix_middleware(
    routes: &mut [Route],
    prefix_middleware: &[ExpressPrefixMiddleware],
) {
    for route in routes {
        let mut added = Vec::new();
        for prefix in prefix_middleware {
            if express_path_matches_prefix(&route.path, &prefix.prefix) {
                added.extend(prefix.middleware.clone());
            }
        }
        if added.is_empty() {
            continue;
        }
        added.extend(route.middleware.clone());
        route.middleware = dedup_symbol_refs(added);
    }
}

fn express_path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn dedup_symbol_refs(symbols: Vec<SymbolRef>) -> Vec<SymbolRef> {
    let mut seen = BTreeSet::new();
    symbols
        .into_iter()
        .filter(|symbol| seen.insert(symbol.name.clone()))
        .collect()
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

fn push_span_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    seen: &mut BTreeSet<(String, u32, String)>,
    span: Span,
    code: &str,
    message: &str,
) {
    let key = (span.file.clone(), span.line, code.to_string());
    if seen.insert(key) {
        diagnostics.push(diagnostic(code, span, message));
    }
}

fn push_dynamic_route_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    seen: &mut BTreeSet<(String, u32, String)>,
    fact: &ExpressRouteFact,
) {
    if fact.dynamic_path {
        push_span_diagnostic(
            diagnostics,
            seen,
            fact.span.clone(),
            "express_dynamic_route_path",
            "Express route path is dynamic and could not be resolved",
        );
    }
}

fn push_dynamic_mount_prefix_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    seen: &mut BTreeSet<(String, u32, String)>,
    spans: &[Span],
) {
    for span in spans {
        push_span_diagnostic(
            diagnostics,
            seen,
            span.clone(),
            "express_dynamic_mount_prefix",
            "Express mount prefix is dynamic and could not be resolved",
        );
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
        self.collect_factory_definition(node);
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

    fn collect_factory_definition(&mut self, node: Node<'_>) {
        let Some((name, function)) = express_factory_definition(self.parsed, node) else {
            return;
        };
        let params = function_param_names(self.parsed, function);
        let Some(owner_param) = params.first().cloned() else {
            return;
        };
        if self
            .index
            .factories
            .iter()
            .any(|factory| factory.file == self.parsed.source.path && factory.name == name)
        {
            return;
        }
        self.index.factories.push(ExpressFactory {
            file: self.parsed.source.path.clone(),
            name,
            owner_param,
            params,
        });
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

        if let Some(function_text) = self.parsed.text_for(function)
            && self.collect_factory_call(call, function_text)
        {
            return;
        }

        if let Some(helper) = self.parsed.text_for(function).filter(|name| {
            matches!(
                *name,
                "setupPageRoute" | "setupAdminPageRoute" | "setupApiRoute"
            )
        }) {
            self.collect_helper_route(call, helper);
            return;
        }

        let Some((owner, member)) = js_member_target(self.parsed, function) else {
            return;
        };

        if member == "use" {
            self.collect_mount(call, &owner);
            return;
        }
        if member == "all" {
            self.collect_prefix_middleware(call);
            return;
        }

        if matches!(
            member.as_str(),
            "setupPageRoute" | "setupAdminPageRoute" | "setupApiRoute"
        ) {
            self.collect_helper_route(call, &member);
            return;
        }

        if let Some(method) = express_method(&member) {
            let definitions = self.index.definitions_by_file.get(&self.parsed.source.path);
            let scope = self.current_factory_scope(call);
            if let Some(mut chain) = express_route_chain(self.parsed, call, method, definitions) {
                chain.scope = scope.clone();
                self.push_route(chain);
            } else if let Some(mut direct) =
                express_direct_route(self.parsed, call, &owner, method, definitions)
            {
                direct.scope = scope;
                self.push_route(direct);
            }
        }
    }

    fn collect_factory_call(&mut self, call: Node<'_>, function_text: &str) -> bool {
        let Some(factory) = self
            .index
            .factories
            .iter()
            .find(|factory| {
                factory.file == self.parsed.source.path && factory.name == function_text
            })
            .cloned()
        else {
            return false;
        };
        let args = call_arguments(call);
        let Some(owner_node) = args.first().copied() else {
            return false;
        };
        let Some(owner_name) = symbol_name(self.parsed, owner_node, "<inline_middleware>") else {
            return false;
        };
        let mut param_values = HashMap::new();
        for (param, arg) in factory.params.iter().zip(args.iter().copied()) {
            if let Some(value) = js_path_literal(self.parsed, arg) {
                param_values.insert(param.clone(), value);
            }
        }
        self.index.factory_calls.push(ExpressFactoryCall {
            file: self.parsed.source.path.clone(),
            factory_name: factory.name,
            owner_name,
            param_values,
        });
        true
    }

    fn collect_helper_route(&mut self, call: Node<'_>, helper: &str) {
        let args = call_arguments(call);
        let Some(owner_node) = args.first() else {
            return;
        };
        let Some(owner) = symbol_name(self.parsed, *owner_node, "<inline_middleware>") else {
            return;
        };
        let definitions = self.index.definitions_by_file.get(&self.parsed.source.path);
        let scope = self.current_factory_scope(call);
        match helper {
            "setupPageRoute" | "setupAdminPageRoute" => {
                if args.len() < 3 {
                    return;
                }
                let (path, dynamic_path) = express_path(self.parsed, args[1]);
                let handler_node = *args.last().expect("args length checked");
                let handler =
                    symbol_ref(self.parsed, handler_node, "<inline_handler>", definitions)
                        .unwrap_or_else(|| SymbolRef {
                            name: "<inline_handler>".to_string(),
                            span: Some(self.parsed.span_for(handler_node)),
                        });
                let mut middleware = helper_profile_middleware(self.parsed, call, helper);
                if args.len() > 3 {
                    symbols_from_route_args(self.parsed, &args[2..args.len() - 1], definitions)
                } else {
                    Vec::new()
                }
                .into_iter()
                .for_each(|symbol| middleware.push(symbol));
                for emitted_path in [path.clone(), join_paths("/api", &path)] {
                    self.push_route(ExpressRouteCandidate {
                        owner: owner.clone(),
                        method: "GET".to_string(),
                        path: emitted_path,
                        dynamic_path,
                        allow_unbound_owner: true,
                        handler: handler.clone(),
                        middleware: middleware.clone(),
                        scope: scope.clone(),
                        span: self.parsed.span_for(call),
                    });
                }
            }
            "setupApiRoute" => {
                if args.len() < 4 {
                    return;
                }
                let Some(method) =
                    string_literal(self.parsed, args[1]).map(|value| value.to_uppercase())
                else {
                    return;
                };
                let (path, dynamic_path) = express_path(self.parsed, args[2]);
                let handler_node = *args.last().expect("args length checked");
                let handler =
                    symbol_ref(self.parsed, handler_node, "<inline_handler>", definitions)
                        .unwrap_or_else(|| SymbolRef {
                            name: "<inline_handler>".to_string(),
                            span: Some(self.parsed.span_for(handler_node)),
                        });
                let mut middleware = helper_profile_middleware(self.parsed, call, helper);
                if args.len() > 4 {
                    symbols_from_route_args(self.parsed, &args[3..args.len() - 1], definitions)
                } else {
                    Vec::new()
                }
                .into_iter()
                .for_each(|symbol| middleware.push(symbol));
                self.push_route(ExpressRouteCandidate {
                    owner,
                    method,
                    path,
                    dynamic_path,
                    allow_unbound_owner: true,
                    handler,
                    middleware,
                    scope,
                    span: self.parsed.span_for(call),
                });
            }
            _ => {}
        }
    }

    fn collect_mount(&mut self, call: Node<'_>, parent_name: &str) {
        let args = call_arguments(call);
        if args.is_empty() {
            return;
        }

        let mut dynamic_prefix = false;
        let mut dynamic_prefix_span = None;
        let (prefix, child_candidates) = if let Some(prefix) = js_path_literal(self.parsed, args[0])
        {
            (Some(prefix), &args[1..])
        } else if args.len() >= 2 {
            dynamic_prefix = true;
            dynamic_prefix_span = Some(self.parsed.span_for(args[0]));
            (None, &args[1..])
        } else if is_symbol_reference(args[0]) {
            (None, &args[..])
        } else {
            dynamic_prefix = true;
            dynamic_prefix_span = Some(self.parsed.span_for(args[0]));
            (None, &args[1..])
        };

        let selected = select_mount_child(self.parsed, child_candidates, self.index);
        if selected.is_none() {
            if let Some(prefix) = prefix.clone() {
                let middleware = symbols_from_route_args(self.parsed, child_candidates, None);
                self.push_prefix_middleware(vec![prefix], middleware);
            }
            return;
        }
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
            dynamic_prefix_span,
            span: self.parsed.span_for(call),
        });
    }

    fn current_factory_scope(&self, node: Node<'_>) -> Option<String> {
        let factories = self
            .index
            .factories
            .iter()
            .filter(|factory| factory.file == self.parsed.source.path)
            .map(|factory| factory.name.as_str())
            .collect::<BTreeSet<_>>();
        let mut current = node.parent();
        while let Some(node) = current {
            if is_js_function_node(node)
                && let Some(name) = express_factory_name_for_function(self.parsed, node)
                && factories.contains(name.as_str())
            {
                return Some(name);
            }
            current = node.parent();
        }
        None
    }

    fn collect_prefix_middleware(&mut self, call: Node<'_>) {
        let args = call_arguments(call);
        if args.len() < 2 {
            return;
        }
        let prefixes = express_prefixes(self.parsed, args[0]);
        if prefixes.is_empty() {
            return;
        }
        let middleware = symbols_from_route_args(self.parsed, &args[1..], None);
        self.push_prefix_middleware(prefixes, middleware);
    }

    fn push_prefix_middleware(&mut self, prefixes: Vec<String>, middleware: Vec<SymbolRef>) {
        if middleware.is_empty() {
            return;
        }
        for prefix in prefixes {
            self.index.prefix_middleware.push(ExpressPrefixMiddleware {
                prefix,
                middleware: middleware.clone(),
            });
        }
    }

    fn push_route(&mut self, candidate: ExpressRouteCandidate) {
        let mut route = ExpressRouteFact {
            owner_file: self.parsed.source.path.clone(),
            owner_name: candidate.owner,
            scope: candidate.scope,
            method: candidate.method,
            path: candidate.path,
            dynamic_path: candidate.dynamic_path,
            allow_unbound_owner: candidate.allow_unbound_owner,
            handler: candidate.handler,
            middleware: candidate.middleware,
            span: candidate.span,
            notes: Vec::new(),
        };
        if route.dynamic_path {
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
    allow_unbound_owner: bool,
    handler: SymbolRef,
    middleware: Vec<SymbolRef>,
    scope: Option<String>,
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
        allow_unbound_owner: false,
        handler,
        middleware,
        scope: None,
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
        allow_unbound_owner: false,
        handler,
        middleware,
        scope: None,
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

fn express_prefixes(parsed: &ParsedFile, node: Node<'_>) -> Vec<String> {
    if let Some(path) = js_path_literal(parsed, node) {
        return vec![path];
    }
    parsed
        .text_for(node)
        .map(prefixes_from_js_route_pattern)
        .unwrap_or_default()
}

fn prefixes_from_js_route_pattern(text: &str) -> Vec<String> {
    let normalized = text
        .trim()
        .trim_matches(|ch| matches!(ch, '`' | '\'' | '"' | '/'));
    let mut prefixes = BTreeSet::new();
    let bytes = normalized.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'/' && bytes[index + 1] == b'+' {
            index += 2;
            let start = index;
            while index < bytes.len() {
                let ch = bytes[index] as char;
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '/') {
                    index += 1;
                } else {
                    break;
                }
            }
            if index > start {
                prefixes.insert(format!("/{}", &normalized[start..index]));
            }
        } else {
            index += 1;
        }
    }
    prefixes.into_iter().collect()
}

fn helper_profile_middleware(parsed: &ParsedFile, call: Node<'_>, helper: &str) -> Vec<SymbolRef> {
    let names: &[&str] = match helper {
        "setupAdminPageRoute" => &[
            "middleware.ensureLoggedIn",
            "middleware.admin.checkPrivileges",
        ],
        "setupPageRoute" => &["middleware.authenticateRequest"],
        "setupApiRoute" => &["middleware.authenticateRequest"],
        _ => &[],
    };
    names
        .iter()
        .map(|name| SymbolRef {
            name: (*name).to_string(),
            span: Some(parsed.span_for(call)),
        })
        .collect()
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

fn express_factory_definition<'tree>(
    parsed: &ParsedFile,
    node: Node<'tree>,
) -> Option<(String, Node<'tree>)> {
    match node.kind() {
        "function_declaration" => {
            let name = node
                .child_by_field_name("name")
                .and_then(|name| parsed.text_for(name))?;
            Some((name.to_string(), node))
        }
        "variable_declarator" => {
            let function = node.child_by_field_name("value")?;
            if !is_js_function_node(function) {
                return None;
            }
            let name = node
                .child_by_field_name("name")
                .and_then(|name| parsed.text_for(name))?;
            Some((name.to_string(), function))
        }
        "assignment_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            if !is_js_function_node(right) {
                return None;
            }
            let name = parsed.text_for(left)?.to_string();
            Some((name, right))
        }
        "pair" => {
            let value = node.child_by_field_name("value")?;
            if !is_js_function_node(value) {
                return None;
            }
            let key = node.child_by_field_name("key")?;
            let name = parsed.text_for(key).map(|name| {
                name.trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
                    .to_string()
            })?;
            Some((name, value))
        }
        _ => None,
    }
}

fn express_factory_name_for_function(parsed: &ParsedFile, function: Node<'_>) -> Option<String> {
    let parent = function.parent()?;
    express_factory_definition(parsed, parent)
        .filter(|(_, candidate)| candidate.id() == function.id())
        .map(|(name, _)| name)
}

fn is_js_function_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "arrow_function" | "function" | "function_declaration" | "function_expression"
    )
}

fn function_param_names(parsed: &ParsedFile, function: Node<'_>) -> Vec<String> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    if parameters.kind() == "identifier" {
        return parsed
            .text_for(parameters)
            .map(|name| vec![name.to_string()])
            .unwrap_or_default();
    }
    let mut params = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters
        .children(&mut cursor)
        .filter(|child| child.is_named())
    {
        if child.kind() == "identifier" {
            if let Some(name) = parsed.text_for(child) {
                params.push(name.to_string());
            }
        } else if let Some(pattern) = child.child_by_field_name("pattern")
            && pattern.kind() == "identifier"
            && let Some(name) = parsed.text_for(pattern)
        {
            params.push(name.to_string());
        }
    }
    params
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

    if let Some(candidate) = symbol_candidates
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
    {
        return Some(candidate);
    }

    symbol_candidates
        .iter()
        .rev()
        .copied()
        .find(|(_, candidate)| {
            matches!(candidate.kind(), "identifier" | "member_expression")
                && symbol_name(parsed, *candidate, "<inline_middleware>")
                    .is_some_and(|name| looks_like_express_router_symbol(&name))
        })
}

fn looks_like_express_router_symbol(name: &str) -> bool {
    let terminal = terminal_js_symbol_name(name);
    let lower = terminal.to_ascii_lowercase();
    lower == "router" || lower.ends_with("router")
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
    if !trimmed.starts_with('`') || !trimmed.ends_with('`') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    if !inner.contains("${") {
        return Some(inner.to_string());
    }
    decode_js_template_with_placeholders(inner)
}

fn decode_js_template_with_placeholders(inner: &str) -> Option<String> {
    let mut output = String::new();
    let mut rest = inner;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let end = after_start.find('}')?;
        let expression = after_start[..end].trim();
        if expression.is_empty()
            || expression.contains('?')
            || expression.contains(':')
            || expression.contains('(')
            || expression.contains(')')
        {
            return None;
        }
        output.push('{');
        output.push_str(&terminal_js_symbol_name(expression));
        output.push('}');
        rest = &after_start[end + 1..];
    }
    output.push_str(rest);
    Some(output)
}

fn terminal_js_symbol_name(text: &str) -> String {
    text.rsplit(['.', ':'])
        .next()
        .unwrap_or(text)
        .trim()
        .to_string()
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
    use std::collections::BTreeSet;
    use std::fs;

    use authmap_core::{Confidence, Framework, Language, SourceFile};
    use authmap_parsers::{ParserBackend, TreeSitterBackend};
    use authmap_testkit::fixture_path;

    use super::{
        AdapterContext, DjangoAdapter, ExpressAdapter, FastApiAdapter, FrameworkAdapter,
        GraphqlAdapter, NextJsAdapter, TrpcAdapter,
    };

    #[test]
    fn discovers_fastapi_routes_from_apps_routers_and_imported_includes() {
        let parsed = parse_fixtures(&[
            "fastapi/main.py",
            "fastapi/app/main_relative.py",
            "fastapi/app/routes/users.py",
            "fastapi/app/factories/collection.py",
            "fastapi/app/factories/custom.py",
            "fastapi/app/factories/nested.py",
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

        assert_eq!(output.routes.len(), 26);
        assert!(summaries.contains(&(
            "POST",
            "/service/accounts",
            Some("service_account"),
            None,
            Vec::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "DELETE",
            "/collection/items/{item_id}",
            Some("delete_collection_item"),
            None,
            Vec::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "POST",
            "/factory/items",
            Some("create_factory_item"),
            None,
            Vec::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/factory/nested/status",
            Some("nested_status"),
            None,
            Vec::new(),
            authmap_core::Confidence::High,
        )));
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
            "/generated",
            Some("generated_path"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/constant",
            Some("constant_alias_path"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/factory/status",
            Some("default_status_path"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/factory/ready",
            Some("default_ready_path"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "/shared/variable/settings",
            Some("variable_settings"),
            None,
            Vec::<String>::new(),
            authmap_core::Confidence::High,
        )));
        assert!(summaries.contains(&(
            "GET",
            "<dynamic>",
            Some("unresolved_runtime_path"),
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
                .filter(|diagnostic| diagnostic.code == "fastapi_dynamic_route_path")
                .count()
                == 1
        );

        assert_eq!(
            middleware_names(route(&output, "GET", "/shared/variable/settings")),
            vec![
                "require_user",
                "can_edit_account",
                "provide_database_interface"
            ]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/shared/users/{user_id}")),
            vec![
                "require_user",
                "can_edit_account",
                "provide_database_interface"
            ]
        );
    }

    #[test]
    fn marks_unresolved_fastapi_include_dependencies_as_dynamic_context() {
        let parsed = parse_sources(&[(
            "app.py".to_string(),
            Language::Python,
            r#"
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()

@router.get("/items")
def list_items():
    return []

app.include_router(router, dependencies=build_runtime_dependencies())
"#
            .to_string(),
        )]);
        let output = FastApiAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(
            middleware_names(route(&output, "GET", "/items")),
            vec!["dynamic_policy_dependencies"]
        );
    }

    #[test]
    fn discovers_express_routes_middleware_chains_and_mounted_prefixes() {
        let parsed = parse_fixtures(&[
            "express/app.js",
            "express/helpers/app.js",
            "express/routes/admin.js",
            "express/routes/exported.ts",
            "express/routes/users.ts",
        ]);
        let output = ExpressAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(output.routes.len(), 25);
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

        assert_eq!(
            middleware_names(route(&output, "GET", "/profile")),
            vec!["middleware.authenticateRequest", "requireAuth"]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/api/profile")),
            vec!["middleware.authenticateRequest", "requireAuth"]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/admin")),
            vec![
                "requireAuth",
                "requirePermission",
                "middleware.ensureLoggedIn",
                "middleware.admin.checkPrivileges",
                "requireAdmin"
            ]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/api/admin")),
            vec![
                "middleware.ensureLoggedIn",
                "middleware.admin.checkPrivileges",
                "requireAdmin"
            ]
        );
        assert_eq!(
            middleware_names(route(&output, "POST", "/api/write")),
            vec!["middleware.authenticateRequest", "requirePermission"]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/direct")),
            vec!["middleware.authenticateRequest", "requireAuth"]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/api/direct")),
            vec!["middleware.authenticateRequest", "requireAuth"]
        );

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
            Some(43)
        );

        let admin_jobs = route(&output, "POST", "/admin/jobs");
        assert_eq!(
            middleware_names(admin_jobs),
            vec!["requireAuth", "requirePermission", "requireRole"]
        );
        assert_eq!(
            middleware_names(route(&output, "GET", "/{tenant}/reports")),
            vec!["requireAuth"]
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

        let mapped_factory = route(&output, "GET", "/api/mapped/factory");
        assert_eq!(
            mapped_factory
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("listAccounts")
        );
        assert_eq!(middleware_names(mapped_factory), vec!["requireAuth"]);

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
        assert_eq!(
            middleware_names(admin),
            vec!["requireAuth", "requirePermission", "requireAdmin"]
        );

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
        assert_eq!(
            output
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "express_dynamic_route_path")
                .count(),
            1
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "express_dynamic_mount_prefix")
        );
        assert_eq!(
            output
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "express_dynamic_mount_prefix")
                .count(),
            1
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
            "django/accounts/api_urls.py",
            "django/accounts/urls.py",
            "django/accounts/views.py",
            "django/accounts/services.py",
            "django/accounts/models.py",
        ]);
        let output = DjangoAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(output.routes.len(), 34);
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
                .any(|route| route.method == "GET" && route.path == "/accounts/api/readonly")
        );
        assert!(
            output.routes.iter().any(|route| {
                route.method == "GET" && route.path == "/accounts/api/readonly/{pk}"
            })
        );
        assert!(!output.routes.iter().any(|route| {
            matches!(route.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
                && route.path.starts_with("/accounts/api/readonly")
        }));
        assert!(output.routes.iter().any(|route| {
            route.method == "POST" && route.path == "/accounts/readonly-api/audit/refresh"
        }));
        assert!(
            output.routes.iter().any(|route| {
                route.method == "GET" && route.path == "/accounts/api/custom-model"
            })
        );
        assert!(output.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/accounts/api/custom-model/recalculate"
                && route.confidence == Confidence::Medium
        }));
        assert!(!output.routes.iter().any(|route| {
            matches!(route.method.as_str(), "PUT" | "PATCH" | "DELETE")
                && route.path.starts_with("/accounts/api/custom-model")
        }));
        assert!(output.routes.iter().any(|route| {
            route.method == "DELETE" && route.path == "/accounts/api/inherited/{pk}"
        }));
        assert!(output.routes.iter().any(|route| {
            route.method == "GET" && route.path == "/accounts/api/inherited-readonly/{pk}"
        }));
        assert!(!output.routes.iter().any(|route| {
            matches!(route.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
                && route.path.starts_with("/accounts/api/inherited-readonly")
        }));
        assert!(
            output.routes.iter().any(|route| {
                route.method == "POST" && route.path == "/accounts/api/mixin-backed"
            })
        );
        assert!(!output.routes.iter().any(|route| {
            matches!(route.method.as_str(), "PUT" | "PATCH" | "DELETE")
                && route.path.starts_with("/accounts/api/mixin-backed")
        }));
        assert!(
            output.routes.iter().any(|route| {
                route.method == "GET" && route.path == "/exported-api/exported/{pk}"
            })
        );
        let generated_list = route(&output, "ANY", "/accounts/generated");
        assert_eq!(
            generated_list
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("GeneratedAccountListView")
        );
        assert!(
            generated_list
                .source_evidence
                .iter()
                .any(|evidence| { evidence.mechanism == "django_generated_include" })
        );
        let generated_detail = route(&output, "ANY", "/accounts/generated/<int:pk>/edit");
        assert_eq!(
            generated_detail
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("GeneratedAccountEditView")
        );
        assert!(
            generated_detail
                .source_evidence
                .iter()
                .any(|evidence| { evidence.mechanism == "django_model_view_registration" })
        );
        assert_eq!(
            route(&output, "ANY", "/legacy/{slug}/").path,
            "/legacy/{slug}/"
        );
        assert!(
            !output
                .routes
                .iter()
                .any(|route| route.path == "/accounts/not-a-django-route/")
        );
        assert!(
            output
                .routes
                .iter()
                .any(|route| route.path == "<dynamic>" && route.confidence == Confidence::Medium)
        );

        for code in [
            "django_dynamic_include_helper",
            "django_dynamic_url_path",
            "drf_dynamic_router_prefix",
            "drf_dynamic_basename",
            "django_custom_router",
            "django_urlpattern_context_uncertain",
        ] {
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "missing diagnostic {code}"
            );
        }
        assert!(
            !output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "drf_unresolved_viewset_base")
        );
    }

    #[test]
    fn discovers_nextjs_app_router_handlers_segments_and_wrappers() {
        let parsed = parse_fixtures(&[
            "nextjs/app/route.ts",
            "nextjs/app/users/[id]/route.ts",
            "nextjs/app/blog/[...slug]/route.ts",
            "nextjs/app/docs/[[...slug]]/route.ts",
            "nextjs/app/(admin)/reports/route.ts",
            "nextjs/app/(.)modal/route.ts",
            "nextjs/app/dynamic-export/route.ts",
            "nextjs/app/head/route.js",
            "nextjs/app/options/route.jsx",
            "nextjs/app/tsx/route.tsx",
            "nextjs/app/wrapped-named/route.ts",
            "nextjs/app/external/route.ts",
            "nextjs/app/external/handler.ts",
            "nextjs/app/nested/app/users/route.ts",
        ]);
        let output = NextJsAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(output.routes.len(), 17);
        assert!(output.routes.iter().all(|route| route.span.is_some()));
        assert!(output.routes.iter().all(|route| {
            route
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .is_some()
        }));

        let root_get = route(&output, "GET", "/");
        assert_eq!(root_get.framework, Framework::NextJs);
        assert_eq!(
            root_get
                .extensions
                .get("authmap.nextjs")
                .and_then(|value| value.get("export_kind"))
                .and_then(serde_json::Value::as_str),
            Some("function")
        );

        let dynamic = route(&output, "PATCH", "/users/[id]");
        assert_eq!(
            dynamic
                .extensions
                .get("authmap.nextjs")
                .and_then(|value| value.get("export_kind"))
                .and_then(serde_json::Value::as_str),
            Some("const_function")
        );

        let catch_all = route(&output, "GET", "/blog/[...slug]");
        assert_eq!(catch_all.confidence, Confidence::Medium);
        assert_eq!(
            catch_all
                .extensions
                .get("authmap.nextjs")
                .and_then(|value| value.get("wrapper"))
                .and_then(serde_json::Value::as_str),
            Some("withAuth")
        );

        let optional = route(&output, "PUT", "/docs/[[...slug]]");
        assert_eq!(
            optional
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("updateDoc")
        );

        let grouped = route(&output, "DELETE", "/reports");
        assert_eq!(
            grouped
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("handleDelete")
        );

        let unusual = route(&output, "GET", "/modal");
        assert_eq!(unusual.confidence, Confidence::Medium);
        assert_eq!(
            route(&output, "GET", "/nested/app/users").confidence,
            Confidence::Medium
        );
        assert_eq!(route(&output, "HEAD", "/head").framework, Framework::NextJs);
        assert_eq!(
            route(&output, "OPTIONS", "/options").framework,
            Framework::NextJs
        );
        assert!(
            output
                .routes
                .iter()
                .any(|route| route.method == "GET" && route.path == "/tsx")
        );
        assert!(
            !output
                .routes
                .iter()
                .any(|route| route.method == "DELETE" && route.path == "/tsx")
        );
        assert_eq!(
            route(&output, "PATCH", "/wrapped-named")
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("updateProfile")
        );
        assert_eq!(
            route(&output, "POST", "/external")
                .handler
                .as_ref()
                .and_then(|handler| handler.span.as_ref())
                .map(|span| span.file.replace('\\', "/"))
                .is_some_and(|file| file.ends_with("tests/fixtures/nextjs/app/external/handler.ts")),
            true
        );
        let external_delete = route(&output, "DELETE", "/external");
        assert_eq!(
            external_delete
                .extensions
                .get("authmap.nextjs")
                .and_then(|value| value.get("wrapper"))
                .and_then(serde_json::Value::as_str),
            Some("withAuth")
        );
        assert_eq!(
            external_delete
                .handler
                .as_ref()
                .map(|handler| handler.name.as_str()),
            Some("deleteExternal")
        );
        assert!(output.routes.iter().all(|route| {
            route
                .source_evidence
                .iter()
                .any(|evidence| evidence.mechanism == "nextjs_route_handler_export")
        }));

        for code in [
            "nextjs_unusual_route_segment",
            "nextjs_dynamic_route_export",
            "nextjs_nested_app_segment",
            "nextjs_external_reexport_unresolved",
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
    fn django_include_depth_limit_stops_deep_chains() {
        let mut sources = Vec::new();
        for index in 0..66 {
            let path = format!("tests/fixtures/generated_django_depth/urls{index}.py");
            let text = if index < 65 {
                format!(
                    "from django.urls import include, path\nurlpatterns = [path('', include('urls{}'))]\n",
                    index + 1
                )
            } else {
                "from django.urls import path\n\ndef terminal(request):\n    return {}\n\nurlpatterns = [path('terminal/', terminal)]\n".to_string()
            };
            sources.push((path, Language::Python, text));
        }
        let parsed = parse_sources(&sources);
        let output = DjangoAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert!(output.routes.is_empty());
        assert_eq!(
            output
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "django_include_depth_exceeded")
                .count(),
            1
        );
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

    #[test]
    fn discovers_trpc_procedures_as_operations() {
        let parsed = parse_fixtures(&["trpc/router.ts"]);
        let output = TrpcAdapter.discover_routes(&parsed, &AdapterContext::default());

        assert_eq!(output.routes.len(), 3);
        assert_eq!(
            route(&output, "GET", "/trpc/router/publicInfo").framework,
            Framework::Trpc
        );
        assert_eq!(
            route(&output, "POST", "/trpc/router/updateProfile").framework,
            Framework::Trpc
        );
        assert_eq!(
            route(&output, "GET", "/trpc/router/adminStats")
                .extensions
                .get("authmap.trpc")
                .and_then(|value| value.get("procedure_root"))
                .and_then(serde_json::Value::as_str),
            Some("authedAdminProcedure")
        );
    }

    #[test]
    fn discovers_graphql_graphene_operations() {
        let parsed = parse_fixtures(&["graphql/mutations.py"]);
        let output = GraphqlAdapter.discover_routes(&parsed, &AdapterContext::default());

        let paths = output
            .routes
            .iter()
            .map(|route| route.path.as_str())
            .collect::<BTreeSet<_>>();
        assert!(output.routes.iter().any(|route| {
            route.framework == Framework::Graphql
                && route.method == "MUTATION"
                && route.path == "/graphql/productCreate"
        }));
        assert!(output.routes.iter().any(|route| {
            route.framework == Framework::Graphql
                && route.method == "QUERY"
                && route.path == "/graphql/customers"
        }));
        assert!(paths.contains("/graphql/createToken"));
        assert!(paths.contains("/graphql/requestPasswordReset"));
        assert!(paths.contains("/graphql/checkoutCreate"));
        assert!(paths.contains("/graphql/products"));
        for excluded in [
            "/graphql/accountQueries",
            "/graphql/accountMutations",
            "/graphql/choiceValue",
            "/graphql/baseMutation",
            "/graphql/modelDeleteMutation",
            "/graphql/generatedSchemaField",
        ] {
            assert!(!paths.contains(excluded), "unexpected route {excluded}");
        }
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

    fn parse_sources(sources: &[(String, Language, String)]) -> Vec<authmap_parsers::ParsedFile> {
        let backend = TreeSitterBackend;
        sources
            .iter()
            .map(|(path, language, text)| {
                let source = SourceFile {
                    path: path.clone(),
                    language: *language,
                    size_bytes: text.len() as u64,
                    sha256: None,
                    project_hints: Vec::new(),
                    skipped: None,
                };
                backend
                    .parse(&source, text)
                    .expect("inline fixture should parse")
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
