use std::{collections::HashSet, fs, path::Path};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

// ── LegacySourcesFormatCheck ─────────────────────────────────────────────────

pub struct LegacySourcesFormatCheck;

/// Collect legacy one-line `deb` source files from `sources_list` and every
/// `.list` file inside `sources_d`.  Extracted so it can be tested with
/// temporary paths.
pub(crate) fn collect_legacy_source_files(sources_list: &Path, sources_d: &Path) -> Vec<String> {
    let mut legacy: Vec<String> = Vec::new();

    if sources_list.exists()
        && let Ok(content) = fs::read_to_string(sources_list)
        && content
            .lines()
            .any(|l| l.starts_with("deb ") || l.starts_with("deb-src "))
    {
        legacy.push(sources_list.to_string_lossy().into_owned());
    }

    if let Ok(entries) = fs::read_dir(sources_d) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("list")
                && let Ok(content) = fs::read_to_string(&path)
                && content
                    .lines()
                    .any(|l| l.starts_with("deb ") || l.starts_with("deb-src "))
            {
                legacy.push(path.to_string_lossy().into_owned());
            }
        }
    }

    legacy
}

fn legacy_sources_finding(legacy_files: Vec<String>) -> Option<Finding> {
    if legacy_files.is_empty() {
        return None;
    }
    let list = legacy_files.join(", ");
    Some(Finding {
        id: "legacy-sources-format".into(),
        title: format!(
            "{} file(s) using legacy one-line APT source format",
            legacy_files.len()
        ),
        description: format!(
            "The following files use the deprecated one-line `deb` format: {list}. \
             The modern DEB822 `.sources` format is preferred."
        ),
        severity: Severity::Info,
        remediation: Some(Remediation {
            description: "Convert to DEB822 format (one .sources file per repository).".into(),
            commands: vec!["# See: https://wiki.debian.org/SourcesList#DEB822_format".into()],
        }),
    })
}

impl Check for LegacySourcesFormatCheck {
    fn id(&self) -> &str {
        "legacy-sources-format"
    }

    fn title(&self) -> &str {
        "Legacy one-line APT source entries"
    }

    fn run(&self, _ctx: &Context) -> CheckResult {
        let files = collect_legacy_source_files(
            Path::new("/etc/apt/sources.list"),
            Path::new("/etc/apt/sources.list.d"),
        );
        legacy_sources_finding(files).map_or_else(CheckResult::default, |f| {
            CheckResult::default().with_finding(f)
        })
    }
}

// ── UserDefinedPackageCheck ──────────────────────────────────────────────────

pub struct UserDefinedPackageCheck;

impl Check for UserDefinedPackageCheck {
    fn id(&self) -> &str {
        "user-denylist"
    }

    fn title(&self) -> &str {
        "Packages matching user denylist"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        if ctx.config.denylist.packages.is_empty() {
            return CheckResult::default();
        }
        if !ctx.distro.is_debian_family() {
            return CheckResult::default();
        }

        let out = match ctx.runner.run("dpkg-query", &["-W", "-f=${Package}\n"]) {
            Ok(o) => o,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        let installed: HashSet<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect();

        let mut result = CheckResult::default();
        for entry in &ctx.config.denylist.packages {
            if installed.contains(&entry.name) {
                result = result.with_finding(Finding {
                    id: format!("user-denylist-{}", entry.name),
                    title: format!("Package '{}' should not be installed", entry.name),
                    description: entry.reason.clone(),
                    severity: Severity::Warning,
                    remediation: Some(Remediation {
                        description: format!("Remove {}", entry.name),
                        commands: vec![format!("sudo apt remove --purge {}", entry.name)],
                    }),
                });
            }
        }
        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use hah_core::{
        check::Context,
        config::{Config, DenylistEntry},
        distro::DistroInfo,
        runner::{CommandOutput, CommandRunner},
    };
    use mockall::mock;
    use std::sync::Arc;

    mock! {
        Runner {}
        impl CommandRunner for Runner {
            fn run<'a>(&self, program: &'a str, args: &'a [&'a str]) -> std::io::Result<CommandOutput>;
        }
    }

    fn ok_output(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: vec![],
            success: true,
        }
    }

    fn make_ctx(runner: Arc<dyn CommandRunner>, config: Config, distro_id: &str) -> Context {
        Context {
            verbose: false,
            config,
            distro: DistroInfo {
                id: distro_id.into(),
                ..DistroInfo::default()
            },
            runner,
        }
    }

    fn debian_ctx(runner: Arc<dyn CommandRunner>) -> Context {
        make_ctx(runner, Config::default(), "debian")
    }

    // ── UserDefinedPackageCheck ──────────────────────────────────────────────

    #[test]
    fn user_denylist_skips_empty_denylist() {
        assert!(
            UserDefinedPackageCheck
                .run(&debian_ctx(Arc::new(MockRunner::new())))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn user_denylist_skips_non_debian() {
        let mut config = Config::default();
        config.denylist.packages = vec![DenylistEntry {
            name: "bad-pkg".into(),
            reason: "insecure".into(),
        }];
        let ctx = make_ctx(Arc::new(MockRunner::new()), config, "arch");
        assert!(UserDefinedPackageCheck.run(&ctx).findings.is_empty());
    }

    #[test]
    fn user_denylist_installed_package_flagged() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("bash\nbad-pkg\nvim\n")));
        let mut config = Config::default();
        config.denylist.packages = vec![DenylistEntry {
            name: "bad-pkg".into(),
            reason: "this is insecure".into(),
        }];
        let ctx = make_ctx(Arc::new(runner), config, "debian");
        let result = UserDefinedPackageCheck.run(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].id.contains("bad-pkg"));
    }

    #[test]
    fn user_denylist_not_installed_no_finding() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("bash\nvim\n")));
        let mut config = Config::default();
        config.denylist.packages = vec![DenylistEntry {
            name: "bad-pkg".into(),
            reason: "insecure".into(),
        }];
        let ctx = make_ctx(Arc::new(runner), config, "debian");
        assert!(UserDefinedPackageCheck.run(&ctx).findings.is_empty());
    }

    // ── collect_legacy_source_files ───────────────────────────────────────────

    #[test]
    fn collect_legacy_sources_empty_when_no_deb_lines() {
        let tmp = std::env::temp_dir();
        let list = tmp.join(format!("hah_src_{}.list", std::process::id()));
        std::fs::write(&list, "# just a comment\n").unwrap();
        let d = tmp.join(format!("hah_srcd_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let result = collect_legacy_source_files(&list, &d);
        let _ = std::fs::remove_file(&list);
        let _ = std::fs::remove_dir_all(&d);
        assert!(result.is_empty());
    }

    #[test]
    fn collect_legacy_sources_detects_deb_line_in_sources_list() {
        let tmp = std::env::temp_dir();
        let list = tmp.join(format!("hah_srclist_{}.list", std::process::id()));
        std::fs::write(&list, "deb http://archive.ubuntu.com/ubuntu focal main\n").unwrap();
        let d = tmp.join(format!("hah_srcd2_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let result = collect_legacy_source_files(&list, &d);
        let _ = std::fs::remove_file(&list);
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn collect_legacy_sources_detects_deb_line_in_sources_d() {
        let tmp = std::env::temp_dir();
        let absent_list = tmp.join(format!("hah_absent_{}.list", std::process::id()));
        let d = tmp.join(format!("hah_srcd3_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("extra.list"),
            "deb-src http://archive.ubuntu.com/ubuntu focal main\n",
        )
        .unwrap();
        let result = collect_legacy_source_files(&absent_list, &d);
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn legacy_sources_format_check_id_and_title() {
        assert_eq!(LegacySourcesFormatCheck.id(), "legacy-sources-format");
        assert!(!LegacySourcesFormatCheck.title().is_empty());
    }

    #[test]
    fn legacy_sources_format_check_runs_without_panic_on_real_system() {
        let ctx = make_ctx(Arc::new(MockRunner::new()), Config::default(), "debian");
        let _ = LegacySourcesFormatCheck.run(&ctx);
    }
}
