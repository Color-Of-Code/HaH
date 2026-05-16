use clap::Parser;
use std::path::Path;
use syn::{
    visit::{self, Visit},
    Arm, Attribute, BinOp, Block, ExprBinary, ExprForLoop, ExprIf, ExprTry, ExprWhile,
    Ident, ImplItemFn, ItemFn, ItemMod, Signature,
};
use walkdir::WalkDir;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "hah-metrics",
    about = "AST-accurate Rust code metrics analyser"
)]
struct Args {
    /// Maximum allowed cyclomatic complexity per function
    #[arg(long, default_value_t = 15)]
    max_complexity: usize,

    /// Maximum allowed function length in lines
    #[arg(long, default_value_t = 60)]
    max_length: usize,

    /// Root directory to analyse (defaults to "crates")
    #[arg(default_value = "crates")]
    dir: String,
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

struct FnMetrics {
    name: String,
    file: String,
    start_line: usize,
    length: usize,
    complexity: usize,
    is_test: bool,
}

// ---------------------------------------------------------------------------
// Complexity visitor
//
// Cyclomatic complexity = 1 + decision points.
// Decision points counted:
//   if / else-if (+1 each)     while (+1)     for (+1)
//   match arms (+1 each)       && / || (+1)   ? try-operator (+1)
//
// Nested *named* function definitions are NOT counted as part of the
// enclosing function (stop recursion via visit_item_fn / visit_impl_item_fn).
// Closures are treated as inline expressions and DO count.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ComplexityVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for ComplexityVisitor {
    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        self.count += 1;
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        self.count += 1;
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        self.count += 1;
        visit::visit_expr_for_loop(self, node);
    }

    fn visit_arm(&mut self, node: &'ast Arm) {
        self.count += 1;
        visit::visit_arm(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        if matches!(node.op, BinOp::And(_) | BinOp::Or(_)) {
            self.count += 1;
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast ExprTry) {
        self.count += 1;
        visit::visit_expr_try(self, node);
    }

    // Stop recursion into nested named functions so their complexity is
    // attributed to themselves, not the outer function.
    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
    fn visit_impl_item_fn(&mut self, _node: &'ast ImplItemFn) {}
}

fn compute_complexity(block: &Block) -> usize {
    let mut v = ComplexityVisitor { count: 1 };
    v.visit_block(block);
    v.count
}

// ---------------------------------------------------------------------------
// File visitor — collects FnMetrics for every function in a file
// ---------------------------------------------------------------------------

struct FileVisitor {
    metrics: Vec<FnMetrics>,
    in_test: bool,
    filepath: String,
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<Ident>()
                .map(|id| id == "test")
                .unwrap_or(false)
    })
}

fn has_test_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("test"))
}

impl FileVisitor {
    fn record(&mut self, sig: &Signature, block: &Block, attrs: &[Attribute]) {
        let is_test = self.in_test || has_test_attr(attrs);
        let start_line = sig.fn_token.span.start().line;
        let end_line = block.brace_token.span.close().end().line;
        let length = end_line.saturating_sub(start_line).saturating_add(1);
        self.metrics.push(FnMetrics {
            name: sig.ident.to_string(),
            file: self.filepath.clone(),
            start_line,
            length,
            complexity: compute_complexity(block),
            is_test,
        });
    }
}

impl<'ast> Visit<'ast> for FileVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let prev = self.in_test;
        if has_cfg_test(&node.attrs) {
            self.in_test = true;
        }
        visit::visit_item_mod(self, node);
        self.in_test = prev;
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.record(&node.sig, &node.block, &node.attrs);
        // Recurse so nested functions inside the body are also collected.
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.record(&node.sig, &node.block, &node.attrs);
        visit::visit_impl_item_fn(self, node);
    }
}

// ---------------------------------------------------------------------------
// Per-file analysis
// ---------------------------------------------------------------------------

fn analyze_file(path: &Path) -> Result<(Vec<FnMetrics>, usize)> {
    let content = std::fs::read_to_string(path)?;
    let total_loc = content.lines().count();
    let syntax = syn::parse_file(&content)?;

    let path_str = path.to_string_lossy();
    // Treat whole-file test files as entirely test code.
    let is_test_file = path_str.contains("/tests/")
        || path_str.ends_with("integration.rs")
        || path_str.ends_with("tests.rs");

    let mut visitor = FileVisitor {
        metrics: Vec::new(),
        in_test: is_test_file,
        filepath: path_str.to_string(),
    };
    visitor.visit_file(&syntax);

    Ok((visitor.metrics, total_loc))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args = Args::parse();

    let mut all_metrics: Vec<FnMetrics> = Vec::new();
    let mut total_loc: usize = 0;
    let mut parse_errors: usize = 0;

    for entry in WalkDir::new(&args.dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
    {
        match analyze_file(entry.path()) {
            Ok((metrics, loc)) => {
                total_loc += loc;
                all_metrics.extend(metrics);
            }
            Err(e) => {
                eprintln!("Warning: could not parse {}: {}", entry.path().display(), e);
                parse_errors += 1;
            }
        }
    }

    // Approximate test LoC as the sum of lengths of all test-marked functions.
    let test_loc: usize = all_metrics
        .iter()
        .filter(|m| m.is_test)
        .map(|m| m.length)
        .sum();
    let source_loc = total_loc.saturating_sub(test_loc);

    let source: Vec<&FnMetrics> = all_metrics.iter().filter(|m| !m.is_test).collect();

    // --- Summary -----------------------------------------------------------
    println!("Code Metrics Report");
    println!("===================");
    println!("Total LoC:  {total_loc}");
    println!("Source LoC: {source_loc}");
    println!("Test LoC:   {test_loc}  (sum of test-function lengths)");
    if source_loc > 0 {
        println!(
            "Ratio (Test/Source): {:.2}",
            test_loc as f64 / source_loc as f64
        );
    }
    println!();

    let complexities: Vec<usize> = source.iter().map(|m| m.complexity).collect();
    if !complexities.is_empty() {
        println!("Function Complexity ({} source functions):", complexities.len());
        println!("  Min: {}", complexities.iter().min().unwrap());
        println!("  Max: {}", complexities.iter().max().unwrap());
        println!(
            "  Avg: {:.2}",
            complexities.iter().sum::<usize>() as f64 / complexities.len() as f64
        );
    }

    let lengths: Vec<usize> = source.iter().map(|m| m.length).collect();
    if !lengths.is_empty() {
        println!("Function Length (lines):");
        println!("  Min: {}", lengths.iter().min().unwrap());
        println!("  Max: {}", lengths.iter().max().unwrap());
        println!(
            "  Avg: {:.2}",
            lengths.iter().sum::<usize>() as f64 / lengths.len() as f64
        );
    }

    // --- Violations --------------------------------------------------------
    let mut violations: Vec<String> = Vec::new();

    for m in &source {
        if m.complexity > args.max_complexity {
            violations.push(format!(
                "HIGH COMPLEXITY: {}:{} - fn `{}` complexity {} (limit {})",
                m.file, m.start_line, m.name, m.complexity, args.max_complexity
            ));
        }
        if m.length > args.max_length {
            violations.push(format!(
                "LONG FUNCTION: {}:{} - fn `{}` {} lines (limit {})",
                m.file, m.start_line, m.name, m.length, args.max_length
            ));
        }
    }

    if !violations.is_empty() {
        println!("\nThreshold Violations:");
        for v in &violations {
            println!("  {v}");
        }
        std::process::exit(1);
    }

    if parse_errors > 0 {
        eprintln!("Note: {parse_errors} file(s) had parse errors");
    }
}
