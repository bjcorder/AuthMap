use std::collections::{BTreeMap, BTreeSet};

use authmap_core::{
    Confidence, Diagnostic, DiagnosticCategory, DiagnosticSeverity, Framework, Recoverability,
    Route, SourceEvidence, Span, SymbolRef,
};
use authmap_parsers::ParsedFile;
use tree_sitter::Node;

use crate::{AdapterContext, AdapterOutput, FrameworkAdapter};

#[derive(Clone, Debug, Default)]
pub struct DjangoAdapter;

impl FrameworkAdapter for DjangoAdapter {
    fn name(&self) -> &'static str {
        "django"
    }

    fn discover_routes(
        &self,
        parsed_files: &[ParsedFile],
        _context: &AdapterContext,
    ) -> AdapterOutput {
        let mut index = DjangoIndex::default();
        index.module_index = build_module_index(parsed_files);

        for parsed in parsed_files
            .iter()
            .filter(|file| file.language == authmap_core::Language::Python)
        {
            index.imports_by_file.insert(
                parsed.source.path.clone(),
                parse_imports(parsed, &index.module_index),
            );

            let Some(root) = parsed.root_node() else {
                continue;
            };
            collect_symbols(parsed, root, &mut index);
        }

        for parsed in parsed_files
            .iter()
            .filter(|file| file.language == authmap_core::Language::Python)
        {
            let Some(root) = parsed.root_node() else {
                continue;
            };
            let mut collector = DjangoCollector {
                parsed,
                index: &mut index,
            };
            collector.collect(root);
        }

        index.into_output()
    }
}

#[derive(Clone, Debug)]
struct ImportTarget {
    file: Option<String>,
    name: Option<String>,
}

#[derive(Clone, Debug)]
struct SymbolDef {
    name: String,
    span: Span,
}

#[derive(Clone, Debug)]
struct ClassInfo {
    name: String,
    span: Span,
    bases: Vec<String>,
    methods: BTreeMap<String, Span>,
    actions: Vec<ViewSetAction>,
    lookup_field: Option<String>,
}

#[derive(Clone, Debug)]
struct ViewSetAction {
    name: String,
    span: Span,
    detail: bool,
    methods: Vec<String>,
    url_path: Option<String>,
    dynamic_methods: bool,
}

#[derive(Clone, Debug)]
struct UrlPattern {
    file: String,
    kind: UrlPatternKind,
    path: Option<String>,
    dynamic_path: bool,
    name: Option<String>,
    target: PatternTarget,
    span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UrlPatternKind {
    Path,
    RePath,
}

#[derive(Clone, Debug)]
enum PatternTarget {
    Handler(HandlerTarget),
    Include(IncludeTarget),
}

#[derive(Clone, Debug)]
struct HandlerTarget {
    name: String,
    span: Span,
    kind: HandlerKind,
    class_name: Option<String>,
    method_name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandlerKind {
    Function,
    ClassBasedView,
}

#[derive(Clone, Debug)]
struct IncludeTarget {
    file: Option<String>,
    router_name: Option<String>,
    dynamic: bool,
}

#[derive(Clone, Debug)]
struct RouterBinding {
    file: String,
    name: String,
    kind: RouterKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouterKind {
    Simple,
    Default,
    Custom,
}

#[derive(Clone, Debug)]
struct RouterRegistration {
    file: String,
    router_name: String,
    prefix: Option<String>,
    dynamic_prefix: bool,
    basename: Option<String>,
    dynamic_basename: bool,
    viewset: Option<ClassInfo>,
    span: Span,
}

#[derive(Default)]
struct DjangoIndex {
    module_index: BTreeMap<String, String>,
    imports_by_file: BTreeMap<String, BTreeMap<String, ImportTarget>>,
    functions: BTreeMap<(String, String), SymbolDef>,
    classes: BTreeMap<(String, String), ClassInfo>,
    patterns: Vec<UrlPattern>,
    routers: BTreeMap<(String, String), RouterBinding>,
    registrations: Vec<RouterRegistration>,
    diagnostics: Vec<Diagnostic>,
}

impl DjangoIndex {
    fn into_output(self) -> AdapterOutput {
        let mut emitted = Vec::new();
        let mut seen = BTreeSet::<(String, u32, String, String, String)>::new();
        let included_files = self
            .patterns
            .iter()
            .filter_map(|pattern| match &pattern.target {
                PatternTarget::Include(include) => include.file.clone(),
                PatternTarget::Handler(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let roots = self
            .patterns
            .iter()
            .filter(|pattern| !included_files.contains(&pattern.file))
            .collect::<Vec<_>>();
        let roots = if roots.is_empty() {
            self.patterns.iter().collect::<Vec<_>>()
        } else {
            roots
        };

        for pattern in roots {
            emit_pattern_routes(
                &self,
                pattern,
                "",
                Vec::new(),
                &mut BTreeSet::new(),
                &mut emitted,
                &mut seen,
            );
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

struct DjangoCollector<'a> {
    parsed: &'a ParsedFile,
    index: &'a mut DjangoIndex,
}

impl<'a> DjangoCollector<'a> {
    fn collect(&mut self, root: Node<'_>) {
        self.walk_for_assignments(root);
        self.walk_for_calls(root);
    }

    fn walk_for_assignments(&mut self, root: Node<'_>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "assignment" {
                self.collect_assignment(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn walk_for_calls(&mut self, root: Node<'_>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "call" {
                self.collect_call(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    fn collect_assignment(&mut self, node: Node<'_>) {
        let Some((left, _right)) = assignment_sides(self.parsed, node) else {
            return;
        };
        let Some(call) = node
            .child_by_field_name("right")
            .and_then(|right| find_first_kind(right, "call"))
        else {
            return;
        };
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let function_name = terminal_name(self.parsed, function).unwrap_or_default();
        let kind = match function_name.as_str() {
            "DefaultRouter" => RouterKind::Default,
            "SimpleRouter" => RouterKind::Simple,
            name if name.ends_with("Router") && self.parsed.text.contains("rest_framework") => {
                RouterKind::Custom
            }
            _ => return,
        };
        let name = clean_symbol(&left);
        if name.is_empty() {
            return;
        }
        if kind == RouterKind::Custom {
            self.index.diagnostics.push(diagnostic(
                "django_custom_router",
                self.parsed.span_for(call),
                "DRF custom router behavior could not be resolved statically",
            ));
        }
        self.index.routers.insert(
            (self.parsed.source.path.clone(), name.clone()),
            RouterBinding {
                file: self.parsed.source.path.clone(),
                name,
                kind,
            },
        );
    }

    fn collect_call(&mut self, node: Node<'_>) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let function_name = terminal_name(self.parsed, function).unwrap_or_default();
        match function_name.as_str() {
            "path" | "re_path" => self.collect_url_pattern(node, function_name.as_str()),
            "register" => self.collect_router_register(node, function),
            _ => {}
        }
    }

    fn collect_url_pattern(&mut self, call: Node<'_>, function_name: &str) {
        let args = call_argument_nodes(call);
        if args.len() < 2 {
            return;
        }
        let path = string_literal(self.parsed, args[0]);
        let dynamic_path = path.is_none();
        if dynamic_path {
            self.index.diagnostics.push(diagnostic(
                "django_dynamic_url_path",
                self.parsed.span_for(args[0]),
                "Django URL path is dynamic and could not be resolved",
            ));
        }
        let kind = if function_name == "re_path" {
            UrlPatternKind::RePath
        } else {
            UrlPatternKind::Path
        };
        let target = if include_call(self.parsed, args[1]).is_some() {
            PatternTarget::Include(self.include_target(args[1]))
        } else if let Some(include) = self.router_urls_include(args[1]) {
            PatternTarget::Include(include)
        } else if let Some(handler) = self.handler_target(args[1]) {
            PatternTarget::Handler(handler)
        } else {
            self.index.diagnostics.push(diagnostic(
                "django_unresolved_handler",
                self.parsed.span_for(args[1]),
                "Django URL handler could not be resolved statically",
            ));
            return;
        };

        self.index.patterns.push(UrlPattern {
            file: self.parsed.source.path.clone(),
            kind,
            path,
            dynamic_path,
            name: keyword_string(self.parsed, call, "name"),
            target,
            span: self.parsed.span_for(call),
        });
    }

    fn include_target(&mut self, node: Node<'_>) -> IncludeTarget {
        let Some(call) = include_call(self.parsed, node) else {
            return IncludeTarget {
                file: None,
                router_name: None,
                dynamic: true,
            };
        };
        let args = call_argument_nodes(call);
        let Some(first) = args.first().copied() else {
            self.index.diagnostics.push(diagnostic(
                "django_dynamic_include",
                self.parsed.span_for(call),
                "Django include target is missing or dynamic",
            ));
            return IncludeTarget {
                file: None,
                router_name: None,
                dynamic: true,
            };
        };
        if let Some(module) = string_literal(self.parsed, first) {
            let file = resolve_absolute_module_file(&self.index.module_index, &module);
            if file.is_none() {
                self.index.diagnostics.push(diagnostic(
                    "django_unresolved_include",
                    self.parsed.span_for(first),
                    "Django include module could not be resolved statically",
                ));
            }
            return IncludeTarget {
                file,
                router_name: None,
                dynamic: false,
            };
        }
        if let Some((router_name, attr)) = attribute_target(self.parsed, first)
            && attr == "urls"
        {
            return IncludeTarget {
                file: None,
                router_name: Some(router_name),
                dynamic: false,
            };
        }
        if first.kind() == "tuple" {
            if let Some(file) = self.tuple_include_file(first) {
                return IncludeTarget {
                    file: Some(file),
                    router_name: None,
                    dynamic: false,
                };
            }
        }
        let symbol = self.parsed.text_for(first).unwrap_or_default().trim();
        if let Some(target) = self.resolve_import(symbol) {
            return IncludeTarget {
                file: target.file,
                router_name: None,
                dynamic: false,
            };
        }
        self.index.diagnostics.push(diagnostic(
            "django_dynamic_include",
            self.parsed.span_for(first),
            "Django include target is dynamic and could not be resolved",
        ));
        IncludeTarget {
            file: None,
            router_name: None,
            dynamic: true,
        }
    }

    fn router_urls_include(&self, node: Node<'_>) -> Option<IncludeTarget> {
        let (router_name, attr) = attribute_target(self.parsed, node)?;
        (attr == "urls").then_some(IncludeTarget {
            file: None,
            router_name: Some(router_name),
            dynamic: false,
        })
    }

    fn tuple_include_file(&self, tuple: Node<'_>) -> Option<String> {
        let mut cursor = tuple.walk();
        for child in tuple.children(&mut cursor).filter(|child| child.is_named()) {
            let symbol = self.parsed.text_for(child).unwrap_or_default().trim();
            if let Some(target) = self.resolve_import(symbol)
                && let Some(file) = target.file
            {
                return Some(file);
            }
        }
        None
    }

    fn handler_target(&self, node: Node<'_>) -> Option<HandlerTarget> {
        if let Some(class_name) = as_view_class(self.parsed, node) {
            let class = self.resolve_class(&class_name)?;
            return Some(HandlerTarget {
                name: class.name.clone(),
                span: class.span.clone(),
                kind: HandlerKind::ClassBasedView,
                class_name: Some(class.name.clone()),
                method_name: None,
            });
        }
        let text = self.parsed.text_for(node)?.trim();
        if let Some(function) = self.resolve_function(text) {
            return Some(HandlerTarget {
                name: function.name,
                span: function.span,
                kind: HandlerKind::Function,
                class_name: None,
                method_name: None,
            });
        }
        None
    }

    fn collect_router_register(&mut self, call: Node<'_>, function: Node<'_>) {
        let Some((router_name, _)) = attribute_target(self.parsed, function) else {
            return;
        };
        let Some(router) = self
            .index
            .routers
            .get(&(self.parsed.source.path.clone(), router_name.clone()))
            .cloned()
        else {
            return;
        };
        if router.kind == RouterKind::Custom {
            return;
        }
        let args = call_argument_nodes(call);
        if args.len() < 2 {
            return;
        }
        let prefix = string_literal(self.parsed, args[0]);
        let dynamic_prefix = prefix.is_none();
        if dynamic_prefix {
            self.index.diagnostics.push(diagnostic(
                "drf_dynamic_router_prefix",
                self.parsed.span_for(args[0]),
                "DRF router registration prefix is dynamic and could not be resolved",
            ));
        }
        let viewset_text = self.parsed.text_for(args[1]).unwrap_or_default().trim();
        let viewset = self.resolve_class(viewset_text);
        if viewset.is_none() {
            self.index.diagnostics.push(diagnostic(
                "drf_unresolved_viewset",
                self.parsed.span_for(args[1]),
                "DRF router viewset could not be resolved statically",
            ));
        }
        let basename = keyword_string(self.parsed, call, "basename");
        let dynamic_basename = keyword_exists(self.parsed, call, "basename") && basename.is_none();
        if dynamic_basename {
            self.index.diagnostics.push(diagnostic(
                "drf_dynamic_basename",
                self.parsed.span_for(call),
                "DRF router basename is dynamic and could not be resolved",
            ));
        }
        self.index.registrations.push(RouterRegistration {
            file: router.file,
            router_name: router.name,
            prefix,
            dynamic_prefix,
            basename,
            dynamic_basename,
            viewset,
            span: self.parsed.span_for(call),
        });
    }

    fn resolve_import(&self, symbol: &str) -> Option<ImportTarget> {
        self.index
            .imports_by_file
            .get(&self.parsed.source.path)?
            .get(symbol)
            .cloned()
    }

    fn resolve_function(&self, symbol: &str) -> Option<SymbolDef> {
        if let Some((object, member)) = symbol.rsplit_once('.')
            && let Some(target) = self.resolve_import(object)
            && let Some(file) = target.file
        {
            return self
                .index
                .functions
                .get(&(file, clean_symbol(member)))
                .cloned();
        }
        let name = clean_symbol(symbol);
        if let Some(function) = self
            .index
            .functions
            .get(&(self.parsed.source.path.clone(), name.clone()))
            .cloned()
        {
            return Some(function);
        }
        if let Some(target) = self.resolve_import(&name)
            && let Some(file) = target.file
        {
            let target_name = target.name.unwrap_or(name);
            return self.index.functions.get(&(file, target_name)).cloned();
        }
        None
    }

    fn resolve_class(&self, symbol: &str) -> Option<ClassInfo> {
        if let Some((object, member)) = symbol.rsplit_once('.')
            && let Some(target) = self.resolve_import(object)
            && let Some(file) = target.file
        {
            return self
                .index
                .classes
                .get(&(file, clean_symbol(member)))
                .cloned();
        }
        let name = clean_symbol(symbol);
        if let Some(class) = self
            .index
            .classes
            .get(&(self.parsed.source.path.clone(), name.clone()))
            .cloned()
        {
            return Some(class);
        }
        if let Some(target) = self.resolve_import(&name)
            && let Some(file) = target.file
        {
            let target_name = target.name.unwrap_or(name);
            return self.index.classes.get(&(file, target_name)).cloned();
        }
        None
    }
}

fn emit_pattern_routes(
    index: &DjangoIndex,
    pattern: &UrlPattern,
    prefix: &str,
    inherited_evidence: Vec<SourceEvidence>,
    active_includes: &mut BTreeSet<String>,
    routes: &mut Vec<Route>,
    seen: &mut BTreeSet<(String, u32, String, String, String)>,
) {
    let mut notes = Vec::new();
    let mut confidence = Confidence::High;
    let local_path = if pattern.dynamic_path {
        confidence = Confidence::Medium;
        notes.push("Django URL path is dynamic and was emitted as <dynamic>".to_string());
        "<dynamic>".to_string()
    } else {
        pattern.path.clone().unwrap_or_default()
    };
    let full_path = if local_path == "<dynamic>" {
        "<dynamic>".to_string()
    } else {
        join_paths(prefix, &local_path)
    };
    if pattern.kind == UrlPatternKind::RePath {
        notes.push("Django re_path regex literal preserved as route path".to_string());
    }

    match &pattern.target {
        PatternTarget::Handler(handler) => {
            let mut source_evidence = inherited_evidence;
            source_evidence.push(source_evidence_item(
                match pattern.kind {
                    UrlPatternKind::Path => "django_urlpattern",
                    UrlPatternKind::RePath => "django_re_path",
                },
                Some(SymbolRef {
                    name: handler.name.clone(),
                    span: Some(handler.span.clone()),
                }),
                pattern.span.clone(),
                confidence,
                notes.clone(),
            ));
            let mut extensions = authmap_core::ExtensionMap::new();
            extensions.insert(
                "authmap.django".to_string(),
                serde_json::json!({
                    "route_pattern_kind": pattern_kind_name(pattern.kind),
                    "handler_kind": handler_kind_name(handler.kind),
                    "class_name": handler.class_name,
                    "method_name": handler.method_name,
                }),
            );
            push_route_unique(
                routes,
                seen,
                Route {
                    id: String::new(),
                    framework: Framework::Django,
                    method: "ANY".to_string(),
                    path: full_path,
                    name: pattern.name.clone(),
                    tags: Vec::new(),
                    middleware: Vec::new(),
                    handler: Some(SymbolRef {
                        name: handler.name.clone(),
                        span: Some(handler.span.clone()),
                    }),
                    span: Some(pattern.span.clone()),
                    source_evidence,
                    confidence,
                    notes,
                    extensions,
                },
            );
        }
        PatternTarget::Include(include) => {
            let mut include_evidence = inherited_evidence;
            include_evidence.push(source_evidence_item(
                "django_include",
                None,
                pattern.span.clone(),
                confidence,
                notes.clone(),
            ));
            if include.dynamic {
                return;
            }
            if let Some(file) = &include.file {
                if !active_includes.insert(file.clone()) {
                    return;
                }
                for child in index.patterns.iter().filter(|child| &child.file == file) {
                    emit_pattern_routes(
                        index,
                        child,
                        &full_path,
                        include_evidence.clone(),
                        active_includes,
                        routes,
                        seen,
                    );
                }
                active_includes.remove(file);
            }
            if let Some(router_name) = &include.router_name {
                emit_router_routes(
                    index,
                    &pattern.file,
                    router_name,
                    &full_path,
                    include_evidence,
                    routes,
                    seen,
                );
            }
        }
    }
}

fn emit_router_routes(
    index: &DjangoIndex,
    file: &str,
    router_name: &str,
    prefix: &str,
    inherited_evidence: Vec<SourceEvidence>,
    routes: &mut Vec<Route>,
    seen: &mut BTreeSet<(String, u32, String, String, String)>,
) {
    let Some(router) = index
        .routers
        .get(&(file.to_string(), router_name.to_string()))
    else {
        return;
    };
    for registration in index.registrations.iter().filter(|registration| {
        registration.file == router.file && registration.router_name == router.name
    }) {
        let Some(viewset) = &registration.viewset else {
            continue;
        };
        let route_prefix = registration
            .prefix
            .clone()
            .unwrap_or_else(|| "<dynamic>".to_string());
        let mut base_confidence = Confidence::High;
        let mut base_notes = Vec::new();
        if registration.dynamic_prefix {
            base_confidence = Confidence::Medium;
            base_notes
                .push("DRF router prefix is dynamic and was emitted as <dynamic>".to_string());
        }
        if registration.dynamic_basename {
            base_confidence = Confidence::Medium;
            base_notes.push("DRF router basename is dynamic".to_string());
        }
        for action in standard_viewset_actions(viewset) {
            let mut action_path = route_prefix.clone();
            if action.detail {
                action_path = join_paths(&action_path, &format!("{{{}}}", lookup_field(viewset)));
            }
            emit_drf_route(
                routes,
                seen,
                prefix,
                &action_path,
                registration,
                viewset,
                action.method,
                action.name,
                action.span,
                "viewset_standard",
                inherited_evidence.clone(),
                base_confidence,
                base_notes.clone(),
            );
        }
        for action in &viewset.actions {
            let mut notes = base_notes.clone();
            let mut confidence = base_confidence;
            if action.dynamic_methods {
                confidence = Confidence::Medium;
                notes.push("DRF action methods are dynamic or missing; emitted as GET".to_string());
            }
            let action_segment = action
                .url_path
                .clone()
                .unwrap_or_else(|| action.name.clone());
            let mut action_path = route_prefix.clone();
            if action.detail {
                action_path = join_paths(&action_path, &format!("{{{}}}", lookup_field(viewset)));
            }
            action_path = join_paths(&action_path, &action_segment);
            for method in &action.methods {
                emit_drf_route(
                    routes,
                    seen,
                    prefix,
                    &action_path,
                    registration,
                    viewset,
                    method,
                    &action.name,
                    action.span.clone(),
                    "viewset_action",
                    inherited_evidence.clone(),
                    confidence,
                    notes.clone(),
                );
            }
        }
    }
}

struct StandardAction<'a> {
    name: &'a str,
    method: &'a str,
    detail: bool,
    span: Span,
}

fn standard_viewset_actions(viewset: &ClassInfo) -> Vec<StandardAction<'_>> {
    let model_viewset = viewset
        .bases
        .iter()
        .any(|base| base.ends_with("ModelViewSet") || base.ends_with("ReadOnlyModelViewSet"));
    let candidates = [
        ("list", "GET", false),
        ("create", "POST", false),
        ("retrieve", "GET", true),
        ("update", "PUT", true),
        ("partial_update", "PATCH", true),
        ("destroy", "DELETE", true),
    ];
    candidates
        .into_iter()
        .filter_map(|(name, method, detail)| {
            if model_viewset || viewset.methods.contains_key(name) {
                Some(StandardAction {
                    name,
                    method,
                    detail,
                    span: viewset
                        .methods
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| viewset.span.clone()),
                })
            } else {
                None
            }
        })
        .collect()
}

fn emit_drf_route(
    routes: &mut Vec<Route>,
    seen: &mut BTreeSet<(String, u32, String, String, String)>,
    mount_prefix: &str,
    action_path: &str,
    registration: &RouterRegistration,
    viewset: &ClassInfo,
    method: &str,
    action_name: &str,
    action_span: Span,
    handler_kind: &str,
    mut source_evidence: Vec<SourceEvidence>,
    confidence: Confidence,
    notes: Vec<String>,
) {
    source_evidence.push(source_evidence_item(
        "drf_router_register",
        Some(SymbolRef {
            name: viewset.name.clone(),
            span: Some(viewset.span.clone()),
        }),
        registration.span.clone(),
        confidence,
        notes.clone(),
    ));
    if handler_kind == "viewset_action" {
        source_evidence.push(source_evidence_item(
            "drf_viewset_action",
            Some(SymbolRef {
                name: action_name.to_string(),
                span: Some(action_span.clone()),
            }),
            action_span.clone(),
            confidence,
            notes.clone(),
        ));
    }
    let mut extensions = authmap_core::ExtensionMap::new();
    extensions.insert(
        "authmap.django".to_string(),
        serde_json::json!({
            "route_pattern_kind": "drf_router",
            "handler_kind": handler_kind,
            "class_name": viewset.name,
            "method_name": action_name,
            "router_name": registration.router_name,
            "basename": registration.basename,
            "lookup_field": lookup_field(viewset),
        }),
    );
    push_route_unique(
        routes,
        seen,
        Route {
            id: String::new(),
            framework: Framework::DjangoRestFramework,
            method: method.to_string(),
            path: if action_path == "<dynamic>" {
                "<dynamic>".to_string()
            } else {
                join_paths(mount_prefix, action_path)
            },
            name: registration
                .basename
                .clone()
                .map(|basename| format!("{}-{}", basename, action_name.replace('_', "-"))),
            tags: Vec::new(),
            middleware: Vec::new(),
            handler: Some(SymbolRef {
                name: format!("{}.{}", viewset.name, action_name),
                span: Some(action_span),
            }),
            span: Some(registration.span.clone()),
            source_evidence,
            confidence,
            notes,
            extensions,
        },
    );
}

fn collect_symbols(parsed: &ParsedFile, root: Node<'_>, index: &mut DjangoIndex) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && let Some(name) = parsed.text_for(name_node)
                {
                    index.functions.insert(
                        (parsed.source.path.clone(), name.to_string()),
                        SymbolDef {
                            name: name.to_string(),
                            span: parsed.span_for(name_node),
                        },
                    );
                }
            }
            "class_definition" => {
                if let Some(class) = class_info(parsed, node) {
                    index
                        .classes
                        .insert((parsed.source.path.clone(), class.name.clone()), class);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
}

fn class_info(parsed: &ParsedFile, node: Node<'_>) -> Option<ClassInfo> {
    let name_node = node.child_by_field_name("name")?;
    let name = parsed.text_for(name_node)?.to_string();
    let mut methods = BTreeMap::new();
    let mut actions = Vec::new();
    let mut lookup_field = None;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "function_definition" => {
                if let Some(name_node) = current.child_by_field_name("name")
                    && let Some(method_name) = parsed.text_for(name_node)
                {
                    methods.insert(method_name.to_string(), parsed.span_for(name_node));
                }
            }
            "decorated_definition" => {
                if let Some(function) = find_direct_child_kind(current, "function_definition")
                    && let Some(name_node) = function.child_by_field_name("name")
                    && let Some(action_name) = parsed.text_for(name_node)
                {
                    methods.insert(action_name.to_string(), parsed.span_for(name_node));
                    if let Some(action) = viewset_action(parsed, current, action_name, name_node) {
                        actions.push(action);
                    }
                }
            }
            "assignment" => {
                if let Some((left, right)) = assignment_sides(parsed, current)
                    && left.trim() == "lookup_field"
                    && let Some(value) = assignment_right_node(current)
                        .and_then(|right| string_literal(parsed, right))
                {
                    let _ = right;
                    lookup_field = Some(value);
                }
            }
            _ => {}
        }
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    let bases = class_bases(parsed, node);
    Some(ClassInfo {
        name,
        span: parsed.span_for(name_node),
        bases,
        methods,
        actions,
        lookup_field,
    })
}

fn class_bases(parsed: &ParsedFile, node: Node<'_>) -> Vec<String> {
    node.child_by_field_name("superclasses")
        .or_else(|| {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .find(|child| child.kind() == "argument_list")
        })
        .map(|bases| {
            let mut cursor = bases.walk();
            bases
                .children(&mut cursor)
                .filter(|base| base.is_named())
                .filter_map(|base| parsed.text_for(base).map(clean_symbol))
                .collect()
        })
        .unwrap_or_default()
}

fn viewset_action(
    parsed: &ParsedFile,
    decorated: Node<'_>,
    action_name: &str,
    name_node: Node<'_>,
) -> Option<ViewSetAction> {
    let mut cursor = decorated.walk();
    for child in decorated
        .children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
    {
        let call = find_first_kind(child, "call")?;
        let function = call.child_by_field_name("function")?;
        if terminal_name(parsed, function).as_deref() != Some("action") {
            continue;
        }
        let methods = keyword_string_list(parsed, call, "methods");
        let dynamic_methods = keyword_exists(parsed, call, "methods") && methods.is_empty();
        return Some(ViewSetAction {
            name: action_name.to_string(),
            span: parsed.span_for(name_node),
            detail: keyword_bool(parsed, call, "detail").unwrap_or(false),
            methods: if methods.is_empty() {
                vec!["GET".to_string()]
            } else {
                methods
                    .into_iter()
                    .map(|method| method.to_uppercase())
                    .collect()
            },
            url_path: keyword_string(parsed, call, "url_path"),
            dynamic_methods,
        });
    }
    None
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
) -> BTreeMap<String, ImportTarget> {
    let mut imports = BTreeMap::new();
    for line in parsed.text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("from ") {
            let Some((module, imported_names)) = rest.split_once(" import ") else {
                continue;
            };
            let module = module.trim();
            let base_file = resolve_python_import_module(parsed, module, module_index);
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
                let submodule = if module.starts_with('.') {
                    resolve_relative_submodule(parsed, module, original, module_index)
                } else {
                    resolve_absolute_module_file(module_index, &format!("{module}.{original}"))
                };
                let file = submodule.clone().or_else(|| base_file.clone());
                let name = if submodule.is_some() {
                    None
                } else {
                    Some(original.to_string())
                };
                imports.insert(local.to_string(), ImportTarget { file, name });
            }
        } else if let Some(rest) = trimmed.strip_prefix("import ") {
            for imported in rest.split(',') {
                let imported = imported.trim();
                let (module, local) = imported.split_once(" as ").map_or(
                    (imported, imported.rsplit('.').next().unwrap_or(imported)),
                    |(module, local)| (module.trim(), local.trim()),
                );
                imports.insert(
                    local.to_string(),
                    ImportTarget {
                        file: resolve_absolute_module_file(module_index, module),
                        name: None,
                    },
                );
            }
        }
    }
    imports
}

fn resolve_relative_submodule(
    parsed: &ParsedFile,
    module: &str,
    imported: &str,
    module_index: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(base) = resolve_python_import_module_name(parsed, module, module_index)
        && let Some(file) =
            resolve_absolute_module_file(module_index, &format!("{base}.{imported}"))
    {
        return Some(file);
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
    for _ in 1..level {
        parts.pop();
    }
    if !rest.is_empty() {
        parts.extend(rest.split('.').filter(|part| !part.is_empty()));
    }
    parts.extend(imported.split('.').filter(|part| !part.is_empty()));
    for start in 0..parts.len() {
        let candidate = parts[start..].join(".");
        if let Some(file) = resolve_absolute_module_file(module_index, &candidate) {
            return Some(file);
        }
    }
    None
}

fn resolve_absolute_module_file(
    module_index: &BTreeMap<String, String>,
    module: &str,
) -> Option<String> {
    module_index.get(module).cloned().or_else(|| {
        module_index
            .iter()
            .find(|(candidate, _)| candidate.ends_with(&format!(".{module}")))
            .map(|(_, file)| file.clone())
    })
}

fn resolve_python_import_module(
    parsed: &ParsedFile,
    module: &str,
    module_index: &BTreeMap<String, String>,
) -> Option<String> {
    let module_name = resolve_python_import_module_name(parsed, module, module_index)?;
    resolve_absolute_module_file(module_index, &module_name)
}

fn resolve_python_import_module_name(
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
        if module_index.contains_key(&candidate)
            || module_index
                .keys()
                .any(|module| module.ends_with(&format!(".{candidate}")))
        {
            return Some(candidate);
        }
    }
    None
}

fn as_view_class(parsed: &ParsedFile, node: Node<'_>) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let (class_name, attr) = attribute_target(parsed, function)?;
    (attr == "as_view").then_some(class_name)
}

fn include_call<'tree>(parsed: &ParsedFile, node: Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() == "call" {
        let function = node.child_by_field_name("function")?;
        if terminal_name(parsed, function).as_deref() == Some("include") {
            return Some(node);
        }
    }
    None
}

fn source_evidence_item(
    mechanism: &str,
    symbol: Option<SymbolRef>,
    span: Span,
    confidence: Confidence,
    notes: Vec<String>,
) -> SourceEvidence {
    SourceEvidence {
        mechanism: mechanism.to_string(),
        symbol,
        span: Some(span),
        confidence,
        notes,
        extensions: authmap_core::ExtensionMap::new(),
    }
}

fn push_route_unique(
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

fn pattern_kind_name(kind: UrlPatternKind) -> &'static str {
    match kind {
        UrlPatternKind::Path => "path",
        UrlPatternKind::RePath => "re_path",
    }
}

fn handler_kind_name(kind: HandlerKind) -> &'static str {
    match kind {
        HandlerKind::Function => "function",
        HandlerKind::ClassBasedView => "class_based_view",
    }
}

fn lookup_field(viewset: &ClassInfo) -> String {
    viewset
        .lookup_field
        .clone()
        .unwrap_or_else(|| "pk".to_string())
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

fn assignment_sides(parsed: &ParsedFile, assignment: Node<'_>) -> Option<(String, String)> {
    let left = assignment
        .child_by_field_name("left")
        .or_else(|| assignment.child_by_field_name("target"))
        .and_then(|node| parsed.text_for(node))
        .map(str::trim)
        .map(str::to_string);
    let right = assignment
        .child_by_field_name("right")
        .and_then(|node| parsed.text_for(node))
        .map(str::trim)
        .map(str::to_string);
    left.zip(right)
}

fn assignment_right_node(assignment: Node<'_>) -> Option<Node<'_>> {
    assignment.child_by_field_name("right")
}

fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .filter(|child| child.is_named() && child.kind() != "keyword_argument")
        .collect()
}

fn keyword_exists(parsed: &ParsedFile, call: Node<'_>, name: &str) -> bool {
    keyword_value(parsed, call, name).is_some()
}

fn keyword_string(parsed: &ParsedFile, call: Node<'_>, name: &str) -> Option<String> {
    keyword_value(parsed, call, name).and_then(|value| string_literal(parsed, value))
}

fn keyword_bool(parsed: &ParsedFile, call: Node<'_>, name: &str) -> Option<bool> {
    keyword_value(parsed, call, name).and_then(|value| {
        parsed
            .text_for(value)
            .map(str::trim)
            .and_then(|text| match text {
                "True" => Some(true),
                "False" => Some(false),
                _ => None,
            })
    })
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

fn clean_symbol(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ' ' | '\n' | '\r' | '\t'))
        .rsplit('.')
        .next()
        .unwrap_or(value)
        .trim()
        .to_string()
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
