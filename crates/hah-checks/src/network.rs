use std::{fs, path::Path};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
    runner::CommandRunner,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn is_package_installed(runner: &dyn CommandRunner, name: &str) -> bool {
    runner
        .run("dpkg-query", &["-W", "-f=${Status}", name])
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("install ok installed"))
}

fn is_service_active(runner: &dyn CommandRunner, name: &str) -> bool {
    runner
        .run("systemctl", &["is-active", "--quiet", name])
        .is_ok_and(|o| o.success)
}

// ── NtpConflictCheck ──────────────────────────────────────────────────────────
/// Detects multiple NTP services active simultaneously, which causes competing
/// clock adjustments and potential time instability.
pub struct NtpConflictCheck;

impl Check for NtpConflictCheck {
    fn id(&self) -> &str {
        "ntp-conflict"
    }

    fn title(&self) -> &str {
        "Multiple NTP services active simultaneously"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let candidates: &[(&str, &str)] = &[
            ("ntp", "ntp (ntpd)"),
            ("chrony", "chrony"),
            ("openntpd", "openntpd"),
        ];

        let active_daemons: Vec<&str> = candidates
            .iter()
            .filter(|(svc, _)| is_service_active(ctx.runner.as_ref(), svc))
            .map(|(_, label)| *label)
            .collect();

        let timesyncd = is_service_active(ctx.runner.as_ref(), "systemd-timesyncd");

        // Conflict: more than one real NTP daemon, or a real daemon + timesyncd
        let conflict = active_daemons.len() > 1 || (timesyncd && !active_daemons.is_empty());

        if !conflict {
            return CheckResult::default();
        }

        let mut all = active_daemons.clone();
        if timesyncd {
            all.push("systemd-timesyncd");
        }
        let list = all.join(", ");

        CheckResult::default().with_finding(Finding {
            id: "ntp-conflict".into(),
            title: format!("Multiple NTP services active: {list}"),
            description: format!(
                "The following time-sync services are all active: {list}. \
                 Competing daemons can fight over the system clock and cause \
                 time jumps, log timestamp corruption, or TLS certificate errors."
            ),
            severity: Severity::Warning,
            remediation: Some(Remediation {
                description: "Disable all but one NTP service (chrony is recommended).".into(),
                commands: vec![
                    "sudo systemctl disable --now ntp".into(),
                    "sudo systemctl disable --now openntpd".into(),
                    "sudo systemctl disable --now systemd-timesyncd".into(),
                    "# Then enable only one: sudo systemctl enable --now chrony".into(),
                ],
            }),
        })
    }
}

// ── LegacyDhcpClientCheck ─────────────────────────────────────────────────────
/// Detects the legacy isc-dhcp-client (dhclient) package on systems where
/// NetworkManager or systemd-networkd already handles DHCP.
pub struct LegacyDhcpClientCheck;

impl Check for LegacyDhcpClientCheck {
    fn id(&self) -> &str {
        "legacy-dhcp-client"
    }

    fn title(&self) -> &str {
        "Legacy ISC DHCP client (dhclient)"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        if !ctx.distro.is_debian_family() {
            return CheckResult::default();
        }
        if !is_package_installed(ctx.runner.as_ref(), "isc-dhcp-client") {
            return CheckResult::default();
        }

        let nm = is_package_installed(ctx.runner.as_ref(), "network-manager");
        let networkd = is_service_active(ctx.runner.as_ref(), "systemd-networkd");

        if !nm && !networkd {
            return CheckResult::default();
        }

        let manager = match (nm, networkd) {
            (true, true) => "NetworkManager and systemd-networkd",
            (true, false) => "NetworkManager",
            _ => "systemd-networkd",
        };

        CheckResult::default().with_finding(Finding {
            id: "legacy-dhcp-client".into(),
            title: "Legacy isc-dhcp-client installed alongside a modern network manager".into(),
            description: format!(
                "The `isc-dhcp-client` (dhclient) package is installed, but {manager} is \
                 already managing DHCP. The legacy client is redundant, unmaintained \
                 upstream, and can be safely removed."
            ),
            severity: Severity::Info,
            remediation: Some(Remediation {
                description: "Remove the legacy ISC DHCP client.".into(),
                commands: vec!["sudo apt remove --purge isc-dhcp-client".into()],
            }),
        })
    }
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

// ── ResolvedConfigCheck ───────────────────────────────────────────────────────
/// Detects a misconfigured /etc/resolv.conf on systems where systemd-resolved
/// is active. The file should be a symlink to the stub resolver so that
/// DNS caching, DNSSEC validation, and per-link DNS settings work correctly.
pub struct ResolvedConfigCheck;

impl Check for ResolvedConfigCheck {
    fn id(&self) -> &str {
        "resolved-config"
    }

    fn title(&self) -> &str {
        "systemd-resolved DNS resolver configuration"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        if !is_service_active(ctx.runner.as_ref(), "systemd-resolved") {
            return CheckResult::default();
        }

        let resolv = Path::new("/etc/resolv.conf");
        let correct_targets = [
            "/run/systemd/resolve/stub-resolv.conf",
            "../run/systemd/resolve/stub-resolv.conf",
        ];

        let is_correct = resolv.is_symlink()
            && fs::read_link(resolv).is_ok_and(|t| {
                let s = t.to_string_lossy().into_owned();
                correct_targets.iter().any(|ok| s == *ok) || s.contains("systemd/resolve")
            });

        if is_correct {
            return CheckResult::default();
        }

        let current = if resolv.is_symlink() {
            fs::read_link(resolv).map_or_else(
                |_| "an unreadable symlink".into(),
                |t| format!("a symlink to {}", t.display()),
            )
        } else {
            "a plain file (not managed by systemd-resolved)".into()
        };

        CheckResult::default().with_finding(Finding {
            id: "resolved-config".into(),
            title: "/etc/resolv.conf is not linked to systemd-resolved".into(),
            description: format!(
                "systemd-resolved is active but /etc/resolv.conf is {current}. \
                 It should be a symlink to /run/systemd/resolve/stub-resolv.conf \
                 so that DNS caching, DNSSEC validation, and split-DNS work correctly. \
                 This is a common misconfiguration left over after upgrades."
            ),
            severity: Severity::Warning,
            remediation: Some(Remediation {
                description: "Link /etc/resolv.conf to the systemd-resolved stub resolver.".into(),
                commands: vec![
                    "sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf".into(),
                ],
            }),
        })
    }
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

    fn ok_output(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.as_bytes().to_vec(),
            stderr: vec![],
            success: true,
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

    fn debian_ctx(runner: Arc<dyn CommandRunner>) -> Context {
        make_ctx(runner, "debian")
    }

    fn non_debian_ctx() -> Context {
        make_ctx(Arc::new(MockRunner::new()), "arch")
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn is_package_installed_returns_true_when_status_matches() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("install ok installed")));
        assert!(is_package_installed(&runner, "bash"));
    }

    #[test]
    fn is_package_installed_returns_false_when_not_installed() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("deinstall ok config-files")));
        assert!(!is_package_installed(&runner, "bash"));
    }

    #[test]
    fn is_package_installed_returns_false_on_runner_error() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            ))
        });
        assert!(!is_package_installed(&runner, "bash"));
    }

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

    // ── NtpConflictCheck ──────────────────────────────────────────────────────

    #[test]
    fn ntp_conflict_check_id_and_title() {
        assert_eq!(NtpConflictCheck.id(), "ntp-conflict");
        assert!(!NtpConflictCheck.title().is_empty());
    }

    #[test]
    fn ntp_conflict_no_daemons_active() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| Ok(failure_output()));
        assert!(
            NtpConflictCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn ntp_conflict_single_daemon_no_conflict() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // calls: ntp(fail), chrony(ok), openntpd(fail), timesyncd(fail)
            if n == 1 {
                Ok(success_output())
            } else {
                Ok(failure_output())
            }
        });
        assert!(
            NtpConflictCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn ntp_conflict_two_daemons_flagged() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // ntp(ok), chrony(ok), openntpd(fail), timesyncd(fail)
            if n <= 1 {
                Ok(success_output())
            } else {
                Ok(failure_output())
            }
        });
        let result = NtpConflictCheck.run(&make_ctx(Arc::new(runner), "any"));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn ntp_conflict_daemon_plus_timesyncd_flagged() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // ntp(fail), chrony(ok), openntpd(fail), timesyncd(ok)
            if n == 1 || n == 3 {
                Ok(success_output())
            } else {
                Ok(failure_output())
            }
        });
        assert_eq!(
            NtpConflictCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .len(),
            1
        );
    }

    // ── LegacyDhcpClientCheck ─────────────────────────────────────────────────

    #[test]
    fn legacy_dhcp_check_id_and_title() {
        assert_eq!(LegacyDhcpClientCheck.id(), "legacy-dhcp-client");
        assert!(!LegacyDhcpClientCheck.title().is_empty());
    }

    #[test]
    fn legacy_dhcp_skips_non_debian() {
        assert!(
            LegacyDhcpClientCheck
                .run(&non_debian_ctx())
                .findings
                .is_empty()
        );
    }

    #[test]
    fn legacy_dhcp_not_installed_returns_empty() {
        let mut runner = MockRunner::new();
        runner
            .expect_run()
            .returning(|_, _| Ok(ok_output("unknown ok not-installed")));
        assert!(
            LegacyDhcpClientCheck
                .run(&debian_ctx(Arc::new(runner)))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn legacy_dhcp_installed_no_modern_manager_returns_empty() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Ok(ok_output("install ok installed")) // isc-dhcp-client installed
            } else if n == 1 {
                Ok(ok_output("unknown ok not-installed")) // network-manager not installed
            } else {
                Ok(failure_output()) // systemd-networkd not active
            }
        });
        assert!(
            LegacyDhcpClientCheck
                .run(&debian_ctx(Arc::new(runner)))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn legacy_dhcp_installed_with_nm_flagged() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Ok(ok_output("install ok installed")) // isc-dhcp-client
            } else if n == 1 {
                Ok(ok_output("install ok installed")) // network-manager
            } else {
                Ok(failure_output()) // systemd-networkd inactive
            }
        });
        let result = LegacyDhcpClientCheck.run(&debian_ctx(Arc::new(runner)));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Info);
    }

    #[test]
    fn legacy_dhcp_installed_with_networkd_flagged() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Ok(ok_output("install ok installed")) // isc-dhcp-client
            } else if n == 1 {
                Ok(ok_output("unknown ok not-installed")) // network-manager absent
            } else {
                Ok(success_output()) // systemd-networkd active
            }
        });
        assert_eq!(
            LegacyDhcpClientCheck
                .run(&debian_ctx(Arc::new(runner)))
                .findings
                .len(),
            1
        );
    }

    #[test]
    fn legacy_dhcp_installed_with_both_managers_flagged() {
        let mut runner = MockRunner::new();
        let call = std::sync::atomic::AtomicUsize::new(0);
        runner.expect_run().returning(move |_, _| {
            let n = call.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 || n == 1 {
                Ok(ok_output("install ok installed")) // dhcp-client + nm installed
            } else {
                Ok(success_output()) // networkd active too
            }
        });
        assert_eq!(
            LegacyDhcpClientCheck
                .run(&debian_ctx(Arc::new(runner)))
                .findings
                .len(),
            1
        );
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

    // ── ResolvedConfigCheck ───────────────────────────────────────────────────

    #[test]
    fn resolved_config_check_id_and_title() {
        assert_eq!(ResolvedConfigCheck.id(), "resolved-config");
        assert!(!ResolvedConfigCheck.title().is_empty());
    }

    #[test]
    fn resolved_config_skips_when_resolved_inactive() {
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| Ok(failure_output()));
        assert!(
            ResolvedConfigCheck
                .run(&make_ctx(Arc::new(runner), "any"))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn resolved_config_active_resolved_runs_without_panic() {
        // systemd-resolved is active → check reads /etc/resolv.conf
        let mut runner = MockRunner::new();
        runner.expect_run().returning(|_, _| Ok(success_output()));
        let ctx = make_ctx(Arc::new(runner), "any");
        let _ = ResolvedConfigCheck.run(&ctx);
    }
}
