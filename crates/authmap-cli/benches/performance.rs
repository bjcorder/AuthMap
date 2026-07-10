use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};

use authmap_adapters::{AdapterContext, AdapterRegistry};
use authmap_analysis::{
    AnalysisInput, BuiltInEvidenceExtractor, BuiltInMutationExtractor, BuiltInReachabilityLinker,
    EvidenceExtractor, MutationExtractor, ReachabilityLinker, run_scan,
};
use authmap_config::{ScanConfig, ScanPlan};
use authmap_core::{Language, SourceFile};
use authmap_parsers::{ParserBackend, TreeSitterBackend, parse_files_in_parallel_selective};
use criterion::{Criterion, criterion_group, criterion_main};

fn parse_throughput(c: &mut Criterion) {
    let backend = TreeSitterBackend;
    let samples = [
        (
            "python",
            source_file("bench.py", Language::Python),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items():\n    return []\n".repeat(64),
        ),
        (
            "javascript",
            source_file("bench.js", Language::JavaScript),
            "const express = require('express');\nconst app = express();\napp.get('/items', requireAuth, (req, res) => res.json([]));\n".repeat(64),
        ),
        (
            "typescript",
            source_file("bench.ts", Language::TypeScript),
            "export async function GET() { const user = await auth(); return Response.json({ user }); }\n".repeat(64),
        ),
    ];

    let mut group = c.benchmark_group("parse_throughput");
    for (name, source, text) in samples {
        group.bench_function(name, |b| {
            b.iter(|| {
                backend
                    .parse(black_box(&source), black_box(&text))
                    .expect("benchmark source should parse")
            });
        });
    }
    group.finish();
}

fn full_pipeline_scan(c: &mut Criterion) {
    let root = workspace_root();
    let fixtures = [
        (
            "realistic_express",
            root.join("tests/fixtures/realistic/express"),
        ),
        (
            "realistic_fastapi",
            root.join("tests/fixtures/realistic/fastapi"),
        ),
        ("django", root.join("tests/fixtures/django")),
    ];

    let mut group = c.benchmark_group("full_pipeline_scan");
    for (name, target) in fixtures {
        group.bench_function(name, |b| {
            b.iter(|| {
                let plan = ScanPlan::new(vec![target.clone()], None, ScanConfig::default());
                run_scan(black_box(&plan)).expect("fixture scan should succeed")
            });
        });
    }
    group.finish();
}

fn analysis_only(c: &mut Criterion) {
    let root = workspace_root();
    let files = [
        root.join("tests/fixtures/realistic/express/app.ts"),
        root.join("tests/fixtures/realistic/express/routes/accounts.ts"),
        root.join("tests/fixtures/realistic/express/services/accounts.ts"),
        root.join("tests/fixtures/realistic/fastapi/main.py"),
        root.join("tests/fixtures/realistic/fastapi/app/routers/accounts.py"),
        root.join("tests/fixtures/realistic/fastapi/app/services/accounts.py"),
    ];
    let sources = files
        .iter()
        .map(|path| source_file(path.to_string_lossy(), language_for_path(path)))
        .collect::<Vec<_>>();
    let backend = TreeSitterBackend;
    let parsed = parse_files_in_parallel_selective(
        &backend,
        &sources,
        |source| {
            fs::read_to_string(&source.path).map_err(|source_error| {
                authmap_parsers::ParseError::Read {
                    path: source.path.clone(),
                    message: source_error.to_string(),
                }
            })
        },
        |_, _| true,
    );
    let adapter_output = AdapterRegistry::built_in().discover_routes(
        &parsed.parsed_files,
        &AdapterContext {
            enabled_frameworks: vec!["express".to_string(), "fastapi".to_string()],
        },
    );
    let config = ScanConfig::default();

    c.bench_function("analysis_only/extract_and_link", |b| {
        b.iter(|| {
            let input = AnalysisInput {
                routes: black_box(&adapter_output.routes),
                parsed_files: black_box(&parsed.parsed_files),
                config: black_box(&config),
                adapter_evidence: black_box(&adapter_output.evidence),
                mutations: black_box(&adapter_output.mutations),
            };
            let evidence = BuiltInEvidenceExtractor.extract_evidence(&input);
            let mutations = BuiltInMutationExtractor.extract_mutations(&input);
            let link_input = AnalysisInput {
                mutations: black_box(&mutations.mutations),
                ..input
            };
            let links = BuiltInReachabilityLinker.link_reachability(&link_input);
            black_box((evidence, mutations, links))
        });
    });
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("authmap-cli should be under crates/authmap-cli")
        .to_path_buf()
}

fn language_for_path(path: &Path) -> Language {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("py") => Language::Python,
        Some("js") => Language::JavaScript,
        Some("jsx") => Language::JavaScriptReact,
        Some("ts") => Language::TypeScript,
        Some("tsx") => Language::TypeScriptReact,
        _ => Language::Unknown,
    }
}

fn source_file(path: impl Into<String>, language: Language) -> SourceFile {
    SourceFile {
        path: path.into(),
        language,
        size_bytes: 0,
        sha256: None,
        project_hints: Vec::new(),
        skipped: None,
    }
}

criterion_group!(benches, parse_throughput, full_pipeline_scan, analysis_only);
criterion_main!(benches);
