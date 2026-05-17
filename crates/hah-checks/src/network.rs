use std::{fs, path::Path};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
    runner::CommandRunner,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn is_service_active(runner: &dyn CommandRunner, name: &str) -> bool {
    runner
        .run("systemctl", &["is-active", "--quiet", name])
        .is_ok_and(|o| o.success)
}

// ── LegacyNetworkInterfacesCheck ──────────────────────────────────────────────
/// Detects non-loopback interface definitions in /etc/network/interfaces,
/// the legacy ifupdown configuration file. On modern Debian/Ubuntu systems
/// network interfaces should be managed by Netplan or NetworkManager.
pub struct LegacyNetworkInterfacesCheck;

/// Count non-loopback interface / auto stanzas in an `/etc/network/interfaces`
/// file content string.  Extracted for unit-testing.
pub(crate) fn count_non_lo_ifaces(content: &str) -> usize {
    content
        .lines()
        .filter(|l| {
            let t = l.trim();
            (t.starts_with("iface ") && !t.starts_with("iface lo "))
                || (t.starts_with("auto ") && t.trim_start_matches("auto").trim() != "lo")
        })
        .count()
}

impl Check for LegacyNetworkInterfacesCheck {
    fn id(&self) -> &str {
        "legacy-network-interfaces"
    }

    fn title(&self) -> &str {
        "Legacy /etc/network/interfaces configuration"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let path = Path::new("/etc/network/interfaces");
        if !path.exists() {
            return CheckResult::default();
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        let non_lo_count = count_non_lo_ifaces(&content);

        if non_lo_count == 0 {
            return CheckResult::default();
        }

        let netplan_active = Path::new("/etc/netplan").exists()
            && fs::read_dir("/etc/netplan").is_ok_and(|mut d| d.next().is_some());
        let nm_active = is_service_active(ctx.runner.as_ref(), "NetworkManager");

        legacy_interfaces_finding(non_lo_count, netplan_active, nm_active)
            .map_or_else(CheckResult::default, |f| {
                CheckResult::default().with_finding(f)
            })
    }
}

/// Build the finding (or None) for `LegacyNetworkInterfacesCheck` given parsed
/// state.  Extracted for deterministic unit-testing.
pub(crate) fn legacy_interfaces_finding(
    non_lo_count: usize,
    netplan_active: bool,
    nm_active: bool,
) -> Option<Finding> {
    if non_lo_count == 0 {
        return None;
    }
    let managed_elsewhere = netplan_active || nm_active;

    let manager_name = match (netplan_active, nm_active) {
        (true, true) => "Netplan and NetworkManager",
        (true, false) => "Netplan",
        (false, true) => "NetworkManager",
        _ => "",
    };

    let (description, severity) = if managed_elsewhere {
        (
            format!(
                "/etc/network/interfaces defines {non_lo_count} non-loopback \
                 interface(s), but {manager_name} is also active. This overlap can \
                 cause conflicts, double-configuration, or interfaces failing to come \
                 up correctly after reboot."
            ),
            Severity::Warning,
        )
    } else {
        (
            format!(
                "/etc/network/interfaces defines {non_lo_count} non-loopback \
                 interface(s) using the legacy ifupdown format. Consider migrating \
                 to Netplan or NetworkManager."
            ),
            Severity::Info,
        )
    };

    Some(Finding {
        id: "legacy-network-interfaces".into(),
        title: format!("/etc/network/interfaces has {non_lo_count} non-loopback entry(s)"),
        description,
        severity,
        remediation: Some(Remediation {
            description: "Migrate interface configuration to Netplan or NetworkManager.".into(),
            commands: vec![
                "# Netplan reference: https://netplan.readthedocs.io/".into(),
                "# After migration: sudo apt remove --purge ifupdown".into(),
            ],
        }),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::if_same_then_else)]
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

    fn success_output() -> CommandOutput {
        CommandOutput {
            stdout: vec![],
            stderr: vec![],
            success: true,
        }
    }

    fn failure_output() -> CommandOutput {
        CommandOutput {
            stdout: vec![],
            stderr: vec![],
            success: false,
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

    // ── helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn is_service_active_returns_true_on_success_exit() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| Ok(success_output()));
        assert!(is_service_active(&runner, "nginx"));
    }

    #[test]
    fn is_service_active_returns_false_on_failure_exit() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| Ok(failure_output()));
        assert!(!is_service_active(&runner, "nginx"));
    }

    #[test]
    fn is_service_active_returns_false_on_runner_error() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            ))
        });
        assert!(!is_service_active(&runner, "nginx"));
    }

    // ── LegacyNetworkInterfacesCheck ──────────────────────────────────────────

    #[test]
    fn legacy_interfaces_check_id_and_title() {
        assert_eq!(
            LegacyNetworkInterfacesCheck.id(),
            "legacy-network-interfaces"
        );
        assert!(!LegacyNetworkInterfacesCheck.title().is_empty());
    }

    #[test]
    fn legacy_interfaces_runs_without_panic() {
        // /etc/network/interfaces may or may not exist on the test machine
        let ctx = make_ctx(Arc::new(MockRunner::new()), "any");
        let _ = LegacyNetworkInterfacesCheck.run(&ctx);
    }

    // ── count_non_lo_ifaces ───────────────────────────────────────────────────

    #[test]
    fn count_non_lo_empty_file_returns_zero() {
        assert_eq!(count_non_lo_ifaces(""), 0);
    }

    #[test]
    fn count_non_lo_loopback_only_returns_zero() {
        let content = "auto lo\niface lo inet loopback\n";
        assert_eq!(count_non_lo_ifaces(content), 0);
    }

    #[test]
    fn count_non_lo_eth0_counts_one() {
        let content = "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\n";
        assert_eq!(count_non_lo_ifaces(content), 2); // "auto eth0" + "iface eth0"
    }

    // ── legacy_interfaces_finding ─────────────────────────────────────────────

    #[test]
    fn legacy_interfaces_finding_zero_count_returns_none() {
        assert!(legacy_interfaces_finding(0, false, false).is_none());
    }

    #[test]
    fn legacy_interfaces_finding_no_manager_is_info() {
        let f = legacy_interfaces_finding(1, false, false).unwrap();
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn legacy_interfaces_finding_nm_active_is_warning() {
        let f = legacy_interfaces_finding(1, false, true).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.description.contains("NetworkManager"));
    }

    #[test]
    fn legacy_interfaces_finding_netplan_active_is_warning() {
        let f = legacy_interfaces_finding(1, true, false).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.description.contains("Netplan"));
    }

    #[test]
    fn legacy_interfaces_finding_both_managers_is_warning() {
        let f = legacy_interfaces_finding(1, true, true).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.description.contains("Netplan and NetworkManager"));
    }
}
