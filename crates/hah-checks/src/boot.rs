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
}
