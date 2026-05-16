use std::collections::{HashMap, HashSet};

use hah_core::{
    check::{Check, Context},
    model::{CheckResult, Finding, Remediation, Severity},
};

// ── Finding builders ────────────────────────────────────────────────────────

fn disabled_revision_finding(name: &str, rev: &str) -> Finding {
    Finding {
        id: format!("snap-disabled-{name}-{rev}"),
        title: format!("Snap '{name}' revision {rev} is disabled"),
        description: format!(
            "Disabled snap revisions still consume disk space. \
             Consider removing old revisions of '{name}'."
        ),
        severity: Severity::Info,
        remediation: Some(Remediation {
            description: format!("Remove disabled revision {rev} of {name}."),
            commands: vec![format!("sudo snap remove {name} --revision={rev}")],
            safe: false,
        }),
    }
}

fn excess_revisions_finding(name: &str, count: u32, max_revisions: u64) -> Finding {
    Finding {
        id: format!("snap-too-many-revisions-{name}"),
        title: format!("Snap '{name}' has {count} retained revisions (threshold: {max_revisions})"),
        description: format!(
            "Snap retains {count} revisions of '{name}', which wastes disk space."
        ),
        severity: Severity::Info,
        remediation: Some(Remediation {
            description: "Reduce the number of snap revisions retained.".into(),
            commands: vec![format!(
                "sudo snap set system refresh.retain={max_revisions}"
            )],
            safe: true,
        }),
    }
}

// ── SnapHealthCheck ──────────────────────────────────────────────────────────

pub struct SnapHealthCheck;

impl Check for SnapHealthCheck {
    fn id(&self) -> &str {
        "snap-health"
    }

    fn title(&self) -> &str {
        "Snap package health"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let max_revisions = ctx.config.threshold("snap_max_revisions", 2);
        let out = match ctx.runner.run("snap", &["list", "--all"]) {
            Ok(o) => o,
            Err(_) => return CheckResult::default(), // snap not installed
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut snap_revisions: HashMap<String, u32> = HashMap::new();
        let mut result = CheckResult::default();
        for line in stdout.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let name = fields[0].to_string();
            let rev = fields[2].to_string();
            if fields.last().copied().unwrap_or("").contains("disabled") {
                result = result.with_finding(disabled_revision_finding(&name, &rev));
            }
            *snap_revisions.entry(name).or_default() += 1;
        }
        for (name, count) in &snap_revisions {
            if *count > max_revisions as u32 {
                result = result.with_finding(excess_revisions_finding(name, *count, max_revisions));
            }
        }
        result
    }
}

// ── SnapAptDuplicateCheck ────────────────────────────────────────────────────

pub struct SnapAptDuplicateCheck;

impl Check for SnapAptDuplicateCheck {
    fn id(&self) -> &str {
        "snap-apt-duplicate"
    }

    fn title(&self) -> &str {
        "Software installed via both Snap and APT"
    }

    fn run(&self, ctx: &Context) -> CheckResult {
        let snap_out = match ctx.runner.run("snap", &["list"]) {
            Ok(o) => o,
            Err(_) => return CheckResult::default(),
        };

        let apt_out = match ctx.runner.run("dpkg-query", &["-W", "-f=${Package}\n"]) {
            Ok(o) => o,
            Err(e) => return CheckResult::default().with_error(e.to_string()),
        };

        let snaps: HashSet<String> = String::from_utf8_lossy(&snap_out.stdout)
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .collect();

        let apt: HashSet<String> = String::from_utf8_lossy(&apt_out.stdout)
            .lines()
            .map(str::to_string)
            .collect();

        let mut result = CheckResult::default();
        for name in snaps.intersection(&apt) {
            // snapd is intentionally present in both: the Debian package
            // bootstraps the host, then the snapd snap takes over for
            // self-updates. Reporting it as a duplicate is a false positive.
            if name == "snapd" {
                continue;
            }
            if ctx.config.allowlist.packages.contains(name) {
                continue;
            }
            result = result.with_finding(Finding {
                id: format!("snap-apt-dup-{name}"),
                title: format!("'{name}' is installed via both APT and Snap"),
                description: format!(
                    "Having '{name}' installed twice wastes space and may cause \
                     version conflicts or confusion."
                ),
                severity: Severity::Warning,
                remediation: Some(Remediation {
                    description: "Remove the APT version if the Snap is preferred.".into(),
                    commands: vec![format!("sudo apt remove --purge {name}")],
                    safe: false,
                }),
            });
        }
        result
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Mutex::lock().unwrap() is idiomatic in tests
mod tests {
    use std::{
        collections::HashMap,
        io,
        sync::{Arc, Mutex},
    };

    use hah_core::{
        check::{Check, Context},
        config::Config,
        distro::DistroInfo,
        runner::{CommandOutput, CommandRunner},
    };

    use super::{SnapAptDuplicateCheck, SnapHealthCheck};

    // ── MockRunner ───────────────────────────────────────────────────────────

    struct MockRunner {
        responses: Mutex<HashMap<String, (Vec<u8>, bool)>>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
            }
        }

        fn on(&self, program: &str, stdout: &[u8], success: bool) {
            self.responses
                .lock()
                .unwrap()
                .insert(program.to_string(), (stdout.to_vec(), success));
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, _args: &[&str]) -> io::Result<CommandOutput> {
            self.responses
                .lock()
                .unwrap()
                .get(program)
                .map(|(stdout, success)| CommandOutput {
                    stdout: stdout.clone(),
                    stderr: vec![],
                    success: *success,
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("mock: '{program}' not registered"),
                    )
                })
        }
    }

    fn ctx(runner: Arc<dyn CommandRunner>) -> Context {
        Context {
            dry_run: false,
            verbose: false,
            config: Config::default(),
            distro: DistroInfo::default(),
            runner,
        }
    }

    // ── SnapHealthCheck ───────────────────────────────────────────────────────

    #[test]
    fn snap_not_installed_returns_empty_result() {
        // No "snap" registered → run() returns NotFound → check returns default
        let result = SnapHealthCheck.run(&ctx(Arc::new(MockRunner::new())));
        assert!(result.findings.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn snap_no_disabled_revisions_no_findings() {
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name     Version  Rev  Tracking        Publisher  Notes\n\
              firefox  120.0    100  latest/stable   mozilla    -\n",
            true,
        );
        let result = SnapHealthCheck.run(&ctx(Arc::new(mock)));
        assert!(result.findings.is_empty());
    }

    #[test]
    fn snap_disabled_revision_is_reported() {
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name     Version  Rev  Tracking        Publisher  Notes\n\
              firefox  119.0    99   latest/stable   mozilla    disabled\n\
              firefox  120.0    100  latest/stable   mozilla    -\n",
            true,
        );
        let result = SnapHealthCheck.run(&ctx(Arc::new(mock)));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.id.contains("snap-disabled-firefox")),
            "expected a snap-disabled-firefox finding, got: {:?}",
            result.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn snap_too_many_revisions_is_reported() {
        let mock = MockRunner::new();
        // 3 revisions for firefox; default threshold is 2 → finding expected
        mock.on(
            "snap",
            b"Name     Version  Rev  Tracking        Publisher  Notes\n\
              firefox  118.0    98   latest/stable   mozilla    disabled\n\
              firefox  119.0    99   latest/stable   mozilla    disabled\n\
              firefox  120.0    100  latest/stable   mozilla    -\n",
            true,
        );
        let result = SnapHealthCheck.run(&ctx(Arc::new(mock)));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.id.contains("snap-too-many-revisions-firefox")),
            "expected a snap-too-many-revisions-firefox finding"
        );
    }

    // ── SnapAptDuplicateCheck ─────────────────────────────────────────────────

    #[test]
    fn no_snap_apt_overlap_returns_no_findings() {
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name     Version  Rev  Tracking        Publisher  Notes\n\
              firefox  120.0    100  latest/stable   mozilla    -\n",
            true,
        );
        mock.on("dpkg-query", b"vim\ngit\ncurl\n", true);
        let result = SnapAptDuplicateCheck.run(&ctx(Arc::new(mock)));
        assert!(result.findings.is_empty());
    }

    #[test]
    fn snap_apt_duplicate_package_is_reported() {
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name  Version  Rev  Tracking        Publisher  Notes\n\
              vlc   3.0.18   2    latest/stable   videolan   -\n",
            true,
        );
        mock.on("dpkg-query", b"vlc\ngit\n", true);
        let result = SnapAptDuplicateCheck.run(&ctx(Arc::new(mock)));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.id.contains("snap-apt-dup-vlc")),
            "expected a snap-apt-dup-vlc finding"
        );
    }

    #[test]
    fn snap_apt_duplicate_package_in_allowlist_is_skipped() {
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name     Version  Rev  Tracking        Publisher  Notes\n\
              firefox  120.0    100  latest/stable   mozilla    -\n",
            true,
        );
        mock.on("dpkg-query", b"firefox\nvim\n", true);
        let mut config = Config::default();
        config.allowlist.packages = vec!["firefox".into()];
        let c = Context {
            config,
            ..ctx(Arc::new(mock))
        };
        assert!(
            SnapAptDuplicateCheck.run(&c).findings.is_empty(),
            "allowlisted package must not produce a finding"
        );
    }

    #[test]
    fn snapd_present_in_both_apt_and_snap_is_not_reported() {
        // snapd Debian package is the bootstrap; the snap updates itself.
        // Having both is expected and must not produce a finding.
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name   Version  Rev  Tracking        Publisher  Notes\n\
              snapd  2.63     21   latest/stable   canonical  -\n",
            true,
        );
        mock.on("dpkg-query", b"snapd\n", true);
        let result = SnapAptDuplicateCheck.run(&ctx(Arc::new(mock)));
        assert!(
            result.findings.is_empty(),
            "snapd must not be reported as a snap/apt duplicate"
        );
    }

    #[test]
    fn snap_apt_duplicate_dpkg_error_returns_result_with_error() {
        let mock = MockRunner::new();
        mock.on(
            "snap",
            b"Name     Version  Rev  Tracking        Publisher  Notes\n\
              firefox  120.0    100  latest/stable   mozilla    -\n",
            true,
        );
        // "dpkg-query" not registered → NotFound error
        let result = SnapAptDuplicateCheck.run(&ctx(Arc::new(mock)));
        assert!(
            !result.errors.is_empty(),
            "dpkg-query failure should be reported as an error"
        );
    }
}
