use std::path::Path;

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

pub use hah_utils::fs::sanitize_id;

// ── InitramfsCheck ───────────────────────────────────────────────────────────

pub struct InitramfsCheck;

impl Check for InitramfsCheck {
    fn id(&self) -> &str {
        "initramfs-size"
    }

    fn title(&self) -> &str {
        "Oversized initramfs images"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let threshold_mb = ctx.config.threshold("initramfs_size_mb", 100);
        let threshold_bytes = threshold_mb * 1024 * 1024;

        let mut result = CheckResult::default();
        let entries = match std::fs::read_dir("/boot") {
            Ok(e) => e,
            Err(e) => return result.with_error(format!("read_dir /boot: {e}")),
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("initrd.img-") && !name_str.starts_with("initramfs-") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                let size = meta.len();
                if size > threshold_bytes {
                    let size_mb = size / 1024 / 1024;
                    result = result.with_finding(Finding {
                        id: format!("initramfs-large-{}", sanitize_id(&name_str)),
                        title: format!("{name_str} is {size_mb} MB"),
                        description: format!(
                            "initramfs image {name_str} exceeds the {threshold_mb} MB threshold. \
                             Large images slow boot and consume /boot space."
                        ),
                        severity: Severity::Warning,
                        remediation: Some(Remediation {
                            description: "Regenerate initramfs images.".into(),
                            commands: vec!["sudo update-initramfs -u -k all".into()],
                        }),
                    });
                }
            }
        }
        result
    }
}

// ── DkmsStatusCheck ──────────────────────────────────────────────────────────

pub struct DkmsStatusCheck;

impl Check for DkmsStatusCheck {
    fn id(&self) -> &str {
        "dkms-status"
    }

    fn title(&self) -> &str {
        "DKMS module build status"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let out = match ctx.runner.run("dkms", &["status"]) {
            Ok(o) => o,
            Err(_) => return CheckResult::default(), // dkms not installed
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut result = CheckResult::default();

        for line in stdout.lines() {
            let lower = line.to_lowercase();
            if lower.contains("broken") || lower.contains("not installed") {
                result = result.with_finding(Finding {
                    id: format!("dkms-broken-{}", sanitize_id(line)),
                    title: format!("DKMS module problem: {line}"),
                    description: format!(
                        "DKMS reports a problem with: {line}. \
                         This module may not work with the current kernel."
                    ),
                    severity: Severity::Warning,
                    remediation: Some(Remediation {
                        description: "Attempt DKMS rebuild.".into(),
                        commands: vec!["sudo dkms autoinstall".into()],
                    }),
                });
            }
        }
        result
    }
}

// ── InitramfsCompressionCheck ────────────────────────────────────────────────

pub struct InitramfsCompressionCheck;

impl Check for InitramfsCompressionCheck {
    fn id(&self) -> &str {
        "initramfs-compression"
    }

    fn title(&self) -> &str {
        "Non-optimal initramfs compression"
    }

    fn run(&self, _ctx: &Context) -> CheckResult {
        // Read the preferred compression from /etc/initramfs-tools/initramfs.conf
        let conf_path = Path::new("/etc/initramfs-tools/initramfs.conf");
        if !conf_path.exists() {
            return CheckResult::default();
        }

        let content = match std::fs::read_to_string(conf_path) {
            Ok(c) => c,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        classify_compression(&content).map_or_else(CheckResult::default, |f| {
            CheckResult::default().with_finding(f)
        })
    }
}

/// Parse compression algorithm from `/etc/initramfs-tools/initramfs.conf`
/// content and return a finding when the algorithm is not `zstd` or `lz4`.
pub(crate) fn classify_compression(content: &str) -> Option<Finding> {
    let compression = content
        .lines()
        .rfind(|l| l.starts_with("COMPRESS="))
        .and_then(|l| l.split_once('='))
        .map_or_else(|| "gzip".into(), |(_, v)| v.trim().to_lowercase());

    if compression != "zstd" && compression != "lz4" {
        Some(Finding {
            id: "initramfs-compression-suboptimal".into(),
            title: format!("initramfs uses {compression} compression instead of zstd"),
            description: format!(
                "The initramfs-tools configuration uses '{compression}' compression. \
                 Switching to 'zstd' reduces initramfs size and speeds up boot."
            ),
            severity: Severity::Info,
            remediation: Some(Remediation {
                description: "Set COMPRESS=zstd in initramfs.conf and regenerate.".into(),
                commands: vec![
                    "sudo sed -i 's/^COMPRESS=.*/COMPRESS=zstd/' \
                     /etc/initramfs-tools/initramfs.conf"
                        .into(),
                    "sudo update-initramfs -u -k all".into(),
                ],
            }),
        })
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use hah_core::{
        check::Context,
        config::Config,
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

    fn make_ctx(runner: Arc<dyn CommandRunner>, distro_id: &str) -> Context {
        Context {
            verbose: false,
            config: Config::default(),
            distro: DistroInfo {
                id: distro_id.into(),
                ..DistroInfo::default()
            },
            runner,
        }
    }

    // ── DkmsStatusCheck ───────────────────────────────────────────────────────

    #[test]
    fn dkms_status_check_id_and_title() {
        assert_eq!(DkmsStatusCheck.id(), "dkms-status");
        assert!(!DkmsStatusCheck.title().is_empty());
    }

    #[test]
    fn dkms_status_all_installed() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "virtualbox/6.1, 5.15.0-89-generic, x86_64: installed\n",
            ))
        });
        assert!(
            DkmsStatusCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn dkms_status_broken_module_flagged() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "virtualbox/6.1, 5.15.0-89-generic, x86_64: broken\n",
            ))
        });
        let result = DkmsStatusCheck.run(&make_ctx(Arc::new(runner), "any"));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn dkms_status_not_installed_module_flagged() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Ok(ok_output(
                "vbox/6.0, 5.15.0-89-generic, x86_64: not installed\n",
            ))
        });
        assert_eq!(
            DkmsStatusCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .len(),
            1
        );
    }

    #[test]
    fn dkms_runner_error_returns_empty() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "dkms missing",
            ))
        });
        assert!(
            DkmsStatusCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .is_empty()
        );
    }

    // ── InitramfsCheck ────────────────────────────────────────────────────────

    #[test]
    fn initramfs_check_id_and_title() {
        assert_eq!(InitramfsCheck.id(), "initramfs-size");
        assert!(!InitramfsCheck.title().is_empty());
    }

    #[test]
    fn initramfs_check_runs_without_panic() {
        let ctx = make_ctx(Arc::new(MockRunner::new()), "any");
        let _ = InitramfsCheck.run(&ctx);
    }

    // ── InitramfsCompressionCheck ─────────────────────────────────────────────

    #[test]
    fn initramfs_compression_check_id_and_title() {
        assert_eq!(InitramfsCompressionCheck.id(), "initramfs-compression");
        assert!(!InitramfsCompressionCheck.title().is_empty());
    }

    #[test]
    fn initramfs_compression_runs_without_panic() {
        let ctx = make_ctx(Arc::new(MockRunner::new()), "any");
        let _ = InitramfsCompressionCheck.run(&ctx);
    }

    // ── classify_compression ──────────────────────────────────────────────────

    #[test]
    fn classify_compression_gzip_produces_finding() {
        let f = classify_compression("COMPRESS=gzip\n").expect("expected finding for gzip");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains("gzip"));
    }

    #[test]
    fn classify_compression_zstd_returns_none() {
        assert!(classify_compression("COMPRESS=zstd\n").is_none());
    }

    #[test]
    fn classify_compression_lz4_returns_none() {
        assert!(classify_compression("COMPRESS=lz4\n").is_none());
    }

    #[test]
    fn classify_compression_default_gzip_when_no_compress_line() {
        // No COMPRESS= line → defaults to gzip → finding
        let f = classify_compression("# just a comment\n").expect("expected gzip default finding");
        assert!(f.title.contains("gzip"));
    }

    #[test]
    fn classify_compression_last_compress_line_wins() {
        let content = "COMPRESS=gzip\nCOMPRESS=zstd\n";
        // rfind picks the LAST line → zstd → no finding
        assert!(classify_compression(content).is_none());
    }
}
