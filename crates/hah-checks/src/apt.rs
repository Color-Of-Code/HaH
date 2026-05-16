use std::{collections::HashSet, fs, path::Path};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

// ── ResidualConfigCheck ──────────────────────────────────────────────────────

pub struct ResidualConfigCheck;

impl Check for ResidualConfigCheck {
    fn id(&self) -> &str {
        "residual-config"
    }

    fn title(&self) -> &str {
        "Residual package configuration files"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        if !ctx.distro.is_debian_family() {
            return CheckResult::default();
        }

        let out = match ctx
            .runner
            .run("dpkg-query", &["-W", "-f=${Status} ${Package}\n"])
        {
            Ok(o) => o,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let rc_packages: Vec<String> = stdout
            .lines()
            .filter(|l| l.starts_with("deinstall ok config-files "))
            .map(|l| {
                l.trim_start_matches("deinstall ok config-files ")
                    .to_string()
            })
            .filter(|pkg| !ctx.config.allowlist.packages.contains(pkg))
            .collect();

        if rc_packages.is_empty() {
            return CheckResult::default();
        }

        let list = rc_packages.join(" ");
        CheckResult::default().with_finding(Finding {
            id: "residual-config".into(),
            title: format!(
                "{} package(s) with residual configuration",
                rc_packages.len()
            ),
            description: format!(
                "These packages were removed but their configuration files remain: {list}."
            ),
            severity: Severity::Info,
            remediation: Some(Remediation {
                description: "Purge residual configurations.".into(),
                commands: vec![format!("sudo dpkg --purge {list}")],
                safe: false,
            }),
        })
    }
}

// ── DpkgStateCheck ───────────────────────────────────────────────────────────

pub struct DpkgStateCheck;

impl Check for DpkgStateCheck {
    fn id(&self) -> &str {
        "dpkg-state"
    }

    fn title(&self) -> &str {
        "Broken dpkg package states"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        if !ctx.distro.is_debian_family() {
            return CheckResult::default();
        }

        let out = match ctx.runner.run("dpkg", &["--audit"]) {
            Ok(o) => o,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if stdout.trim().is_empty() {
            return CheckResult::default();
        }

        CheckResult::default().with_finding(Finding {
            id: "dpkg-audit".into(),
            title: "dpkg audit reports package state problems".into(),
            description: stdout.trim().to_string(),
            severity: Severity::Critical,
            remediation: Some(Remediation {
                description: "Attempt to fix broken packages.".into(),
                commands: vec![
                    "sudo dpkg --configure -a".into(),
                    "sudo apt-get install -f".into(),
                ],
                safe: false,
            }),
        })
    }
}

// ── AutoremovableCheck ───────────────────────────────────────────────────────

pub struct AutoremovableCheck;

impl Check for AutoremovableCheck {
    fn id(&self) -> &str {
        "autoremovable"
    }

    fn title(&self) -> &str {
        "Auto-removable packages"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        if !ctx.distro.is_debian_family() {
            return CheckResult::default();
        }

        let out = match ctx.runner.run("apt-get", &["--dry-run", "autoremove"]) {
            Ok(o) => o,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let count = stdout
            .lines()
            .filter(|l| l.trim_start().starts_with("Remv "))
            .count();

        if count == 0 {
            return CheckResult::default();
        }

        CheckResult::default().with_finding(Finding {
            id: "autoremovable".into(),
            title: format!("{count} auto-removable package(s)"),
            description: format!("{count} package(s) are no longer needed and can be removed."),
            severity: Severity::Info,
            remediation: Some(Remediation {
                description: "Remove unused auto-installed packages.".into(),
                commands: vec!["sudo apt autoremove --purge".into()],
                safe: false,
            }),
        })
    }
}

// ── AptKeyCheck ──────────────────────────────────────────────────────────────

pub struct AptKeyCheck;

/// Return a finding if `path` exists and is non-empty (legacy keyring).
pub(crate) fn apt_key_finding(path: &Path) -> Option<Finding> {
    if path.exists()
        && let Ok(meta) = path.metadata()
        && meta.len() > 0
    {
        Some(Finding {
            id: "apt-key-legacy-gpg".into(),
            title: "Legacy /etc/apt/trusted.gpg keyring is in use".into(),
            description: "The file /etc/apt/trusted.gpg is non-empty. Keys managed here \
                         were added with the deprecated `apt-key` command. They should be \
                         migrated to named keyring files under /usr/share/keyrings/ and \
                         referenced via the signed-by= option in source entries."
                .into(),
            severity: Severity::Warning,
            remediation: Some(Remediation {
                description: "Export each key to a dedicated keyring file.".into(),
                commands: vec![
                    "apt-key list".into(),
                    "# For each key: sudo gpg --no-default-keyring \
                             --keyring /usr/share/keyrings/NAME.gpg \
                             --import /tmp/key.asc"
                        .into(),
                ],
                safe: true,
            }),
        })
    } else {
        None
    }
}

impl Check for AptKeyCheck {
    fn id(&self) -> &str {
        "apt-key"
    }

    fn title(&self) -> &str {
        "Deprecated apt-key signing keys"
    }

    fn run(&self, _ctx: &Context) -> CheckResult {
        apt_key_finding(Path::new("/etc/apt/trusted.gpg")).map_or_else(CheckResult::default, |f| {
            CheckResult::default().with_finding(f)
        })
    }
}

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
            safe: true,
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
                        safe: false,
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
            dry_run: false,
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

    fn non_debian_ctx() -> Context {
        make_ctx(Arc::new(MockRunner::new()), Config::default(), "arch")
    }

    // ── ResidualConfigCheck ──────────────────────────────────────────────────

    #[test]
    fn residual_config_skips_non_debian() {
        assert!(
            ResidualConfigCheck
                .run(&non_debian_ctx())
                .findings
                .is_empty()
        );
    }

    #[test]
    fn residual_config_clean() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("install ok installed bash\n")));
        let result = ResidualConfigCheck.run(&debian_ctx(Arc::new(runner)));
        assert!(result.findings.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn residual_config_finds_rc_packages() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "deinstall ok config-files pkg-a\ninstall ok installed bash\n",
            ))
        });
        let result = ResidualConfigCheck.run(&debian_ctx(Arc::new(runner)));
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].title.contains('1'));
    }

    #[test]
    fn residual_config_allowlist_filters_package() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("deinstall ok config-files known-pkg\n")));
        let mut config = Config::default();
        config.allowlist.packages = vec!["known-pkg".into()];
        let ctx = make_ctx(Arc::new(runner), config, "debian");
        assert!(ResidualConfigCheck.run(&ctx).findings.is_empty());
    }

    #[test]
    fn residual_config_runner_error_returns_error() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            ))
        });
        let result = ResidualConfigCheck.run(&debian_ctx(Arc::new(runner)));
        assert!(result.errors.len() == 1);
    }

    // ── DpkgStateCheck ───────────────────────────────────────────────────────

    #[test]
    fn dpkg_state_skips_non_debian() {
        assert!(DpkgStateCheck.run(&non_debian_ctx()).findings.is_empty());
    }

    #[test]
    fn dpkg_state_clean() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| Ok(ok_output("")));
        let result = DpkgStateCheck.run(&debian_ctx(Arc::new(runner)));
        assert!(result.findings.is_empty());
    }

    #[test]
    fn dpkg_state_broken_packages() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("broken package state info\n")));
        let result = DpkgStateCheck.run(&debian_ctx(Arc::new(runner)));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
    }

    // ── AutoremovableCheck ───────────────────────────────────────────────────

    #[test]
    fn autoremovable_skips_non_debian() {
        assert!(
            AutoremovableCheck
                .run(&non_debian_ctx())
                .findings
                .is_empty()
        );
    }

    #[test]
    fn autoremovable_none() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("Reading package lists...\n")));
        let result = AutoremovableCheck.run(&debian_ctx(Arc::new(runner)));
        assert!(result.findings.is_empty());
    }

    #[test]
    fn autoremovable_finds_packages() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "Reading package lists...\n  Remv old-lib [1.0]\n  Remv unused-tool [2.3]\n",
            ))
        });
        let result = AutoremovableCheck.run(&debian_ctx(Arc::new(runner)));
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].title.contains('2'));
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

    // ── apt_key_finding ───────────────────────────────────────────────────────

    #[test]
    fn apt_key_finding_returns_none_when_file_absent() {
        assert!(apt_key_finding(std::path::Path::new("/nonexistent/trusted.gpg")).is_none());
    }

    #[test]
    fn apt_key_finding_returns_none_when_file_empty() {
        let path = std::env::temp_dir().join(format!("hah_gpg_empty_{}.gpg", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let result = apt_key_finding(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_none());
    }

    #[test]
    fn apt_key_finding_returns_warning_when_file_nonempty() {
        let path =
            std::env::temp_dir().join(format!("hah_gpg_nonempty_{}.gpg", std::process::id()));
        std::fs::write(&path, b"fake-gpg-data").unwrap();
        let finding = apt_key_finding(&path);
        let _ = std::fs::remove_file(&path);
        let f = finding.expect("expected a finding for non-empty gpg file");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.id, "apt-key-legacy-gpg");
    }

    #[test]
    fn apt_key_check_id_and_title() {
        assert_eq!(AptKeyCheck.id(), "apt-key");
        assert!(!AptKeyCheck.title().is_empty());
    }

    #[test]
    fn apt_key_check_runs_without_panic_on_real_system() {
        let ctx = make_ctx(Arc::new(MockRunner::new()), Config::default(), "debian");
        let result = AptKeyCheck.run(&ctx);
        for f in &result.findings {
            assert_eq!(f.severity, Severity::Warning);
        }
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
