//! Generate DEPENDENCIES.md from `cargo metadata`.
//!
//! Usage:
//!   hah-deps                     # writes to stdout
//!   hah-deps --check             # exits 1 if output differs from DEPENDENCIES.md

use std::collections::{HashMap, HashSet};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde::Deserialize;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "hah-deps", about = "Generate DEPENDENCIES.md from cargo metadata")]
struct Args {
    /// Instead of printing, verify that DEPENDENCIES.md matches the generated output.
    /// Exits with code 1 and a diff summary if they differ.
    #[arg(long)]
    check: bool,

    /// Path to DEPENDENCIES.md (only used with --check)
    #[arg(long, default_value = "DEPENDENCIES.md")]
    file: String,
}

// ── Cargo metadata types ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Metadata {
    workspace_members: Vec<String>,
    packages: Vec<Package>,
    resolve: Resolve,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    license: Option<String>,
    description: Option<String>,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    name: String,
    req: String,
    #[serde(default)]
    optional: bool,
}

#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<NodeDep>,
}

#[derive(Deserialize)]
struct NodeDep {
    pkg: String,
    dep_kinds: Vec<DepKind>,
}

#[derive(Deserialize)]
struct DepKind {
    kind: Option<String>, // null = normal, "dev", "build"
}

// ── Version display ───────────────────────────────────────────────────────────

/// Convert a cargo version requirement to a short display string.
/// `^0.9.35` → `0.9`, `^1` → `1`, `^0.0.12` → `0.0`
fn req_display(req: &str) -> String {
    let s = req.trim_start_matches(|c: char| "^~=><".contains(c) || c == ' ');
    let s = s.split(',').next().unwrap_or(s).trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.first().copied() == Some("0") && parts.len() >= 2 {
        format!("0.{}", parts[1])
    } else {
        parts[0].to_string()
    }
}

// ── Description sanitization ──────────────────────────────────────────────────

/// Collapse whitespace/newlines and strip a trailing period so the description
/// fits cleanly in a single Markdown table cell.
fn sanitize_description(raw: &str) -> String {
    raw.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('.')
        .to_string()
}

// ── Dependency collection ─────────────────────────────────────────────────────

struct DepInfo {
    runtime: bool,
    req: String,
    license: String,
    description: String,
}

fn collect_deps(meta: &Metadata) -> HashMap<String, DepInfo> {
    let workspace_ids: HashSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();
    let pkgs_by_id: HashMap<&str, &Package> =
        meta.packages.iter().map(|p| (p.id.as_str(), p)).collect();
    let workspace_names: HashSet<&str> = workspace_ids
        .iter()
        .filter_map(|id| pkgs_by_id.get(id))
        .map(|p| p.name.as_str())
        .collect();

    // Per-workspace-member: which dep names are optional / what req was declared
    let mut optional_in: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut req_in: HashMap<&str, HashMap<&str, &str>> = HashMap::new();
    for id in &workspace_ids {
        if let Some(pkg) = pkgs_by_id.get(id) {
            optional_in.insert(
                pkg.name.as_str(),
                pkg.dependencies
                    .iter()
                    .filter(|d| d.optional)
                    .map(|d| d.name.as_str())
                    .collect(),
            );
            req_in.insert(
                pkg.name.as_str(),
                pkg.dependencies
                    .iter()
                    .map(|d| (d.name.as_str(), d.req.as_str()))
                    .collect(),
            );
        }
    }

    let mut direct: HashMap<String, DepInfo> = HashMap::new();

    for node in &meta.resolve.nodes {
        if !workspace_ids.contains(node.id.as_str()) {
            continue;
        }
        let wm_name = match pkgs_by_id.get(node.id.as_str()) {
            Some(p) => p.name.as_str(),
            None => continue,
        };

        for dep in &node.deps {
            let dep_pkg = match pkgs_by_id.get(dep.pkg.as_str()) {
                Some(p) => p,
                None => continue,
            };
            if workspace_names.contains(dep_pkg.name.as_str()) {
                continue; // skip internal workspace crates
            }

            let is_optional = optional_in
                .get(wm_name)
                .map(|s| s.contains(dep_pkg.name.as_str()))
                .unwrap_or(false);

            let is_normal_runtime = dep
                .dep_kinds
                .iter()
                .any(|k| k.kind.is_none() && !is_optional);

            let entry = direct.entry(dep_pkg.name.clone()).or_insert_with(|| {
                let req = req_in
                    .get(wm_name)
                    .and_then(|m| m.get(dep_pkg.name.as_str()))
                    .copied()
                    .unwrap_or("?");
                DepInfo {
                    runtime: false,
                    req: req_display(req),
                    license: dep_pkg
                        .license
                        .as_deref()
                        .unwrap_or("unknown")
                        .trim()
                        .to_string(),
                    description: sanitize_description(
                        dep_pkg.description.as_deref().unwrap_or(""),
                    ),
                }
            });

            if is_normal_runtime {
                entry.runtime = true;
            }
        }
    }

    direct
}

// ── Markdown rendering ────────────────────────────────────────────────────────

fn table_header() -> &'static str {
    "| Crate | Version | License | Purpose |\n| ----- | ------- | ------- | ------- |"
}

fn table_row(name: &str, info: &DepInfo) -> String {
    format!(
        "| [{}](https://crates.io/crates/{}) | {} | {} | {} |",
        name, name, info.req, info.license, info.description
    )
}

fn render(deps: &HashMap<String, DepInfo>) -> String {
    let mut runtime: Vec<(&str, &DepInfo)> = deps
        .iter()
        .filter(|(_, d)| d.runtime)
        .map(|(n, d)| (n.as_str(), d))
        .collect();
    runtime.sort_by_key(|(n, _)| n.to_ascii_lowercase());

    let mut dev_only: Vec<(&str, &DepInfo)> = deps
        .iter()
        .filter(|(_, d)| !d.runtime)
        .map(|(n, d)| (n.as_str(), d))
        .collect();
    dev_only.sort_by_key(|(n, _)| n.to_ascii_lowercase());

    let mut lines: Vec<String> = vec![
        "# Dependencies".into(),
        String::new(),
        "Direct dependencies of the HaH workspace crates.".into(),
        "_Generated by `make doc-dependencies` — do not edit by hand._".into(),
        String::new(),
        "## Runtime Dependencies".into(),
        String::new(),
        table_header().into(),
    ];
    for (name, info) in &runtime {
        lines.push(table_row(name, info));
    }

    lines.push(String::new());
    lines.push("## Development-only Dependencies".into());
    lines.push(String::new());
    lines.push(table_header().into());
    for (name, info) in &dev_only {
        lines.push(table_row(name, info));
    }

    lines.push(String::new());
    lines.join("\n")
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .stderr(std::process::Stdio::null())
        .output()
        .context("failed to run `cargo metadata`")?;

    if !output.status.success() {
        return Err(anyhow!("`cargo metadata` exited with {}", output.status));
    }

    let meta: Metadata =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata JSON")?;

    let deps = collect_deps(&meta);
    let generated = render(&deps);

    if args.check {
        let on_disk = std::fs::read_to_string(&args.file)
            .with_context(|| format!("failed to read {}", args.file))?;
        if generated == on_disk {
            eprintln!("{} is up to date.", args.file);
            return Ok(());
        }
        eprintln!(
            "ERROR: {} is out of date. Run `make doc-dependencies` to regenerate.",
            args.file
        );
        // Print a simple line-diff summary
        let old: Vec<&str> = on_disk.lines().collect();
        let new: Vec<&str> = generated.lines().collect();
        for (i, (a, b)) in old.iter().zip(new.iter()).enumerate() {
            if a != b {
                eprintln!("  line {}: -{}", i + 1, a);
                eprintln!("  line {}: +{}", i + 1, b);
            }
        }
        if old.len() != new.len() {
            eprintln!(
                "  (line count differs: {} vs {})",
                old.len(),
                new.len()
            );
        }
        std::process::exit(1);
    }

    print!("{}", generated);
    Ok(())
}
