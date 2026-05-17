//! Legacy network interfaces detection capability.

use std::{fs, path::Path};

use anyhow::{Result, anyhow};
use hah_core::runner::CommandRunner;

use crate::CapValue;

/// Return a status string describing legacy `/etc/network/interfaces` state.
///
/// Returns:
/// - `""` (empty) when no non-loopback entries exist or file is absent
/// - `"overlap:<count>:<managers>"` when a modern manager is also active
/// - `"legacy:<count>"` when only ifupdown is in use
pub fn legacy_network_interfaces(runner: &dyn CommandRunner) -> Result<CapValue> {
    evaluate_network_interfaces(
        Path::new("/etc/network/interfaces"),
        Path::new("/etc/netplan"),
        runner,
    )
}

pub(crate) fn evaluate_network_interfaces(
    interfaces_path: &Path,
    netplan_dir: &Path,
    runner: &dyn CommandRunner,
) -> Result<CapValue> {
    if !interfaces_path.exists() {
        return Ok(CapValue::Str(String::new()));
    }
    let content = fs::read_to_string(interfaces_path)
        .map_err(|e| anyhow!("{}: {e}", interfaces_path.display()))?;

    let non_lo_count = content
        .lines()
        .filter(|l| {
            let t = l.trim();
            (t.starts_with("iface ") && !t.starts_with("iface lo "))
                || (t.starts_with("auto ") && t.trim_start_matches("auto").trim() != "lo")
        })
        .count();

    if non_lo_count == 0 {
        return Ok(CapValue::Str(String::new()));
    }

    let netplan_active =
        netplan_dir.exists() && fs::read_dir(netplan_dir).is_ok_and(|mut d| d.next().is_some());
    let nm_active = runner
        .run("systemctl", &["is-active", "--quiet", "NetworkManager"])
        .is_ok_and(|o| o.success);

    if netplan_active || nm_active {
        let managers = match (netplan_active, nm_active) {
            (true, true) => "Netplan and NetworkManager",
            (true, false) => "Netplan",
            _ => "NetworkManager",
        };
        Ok(CapValue::Str(format!("overlap:{non_lo_count}:{managers}")))
    } else {
        Ok(CapValue::Str(format!("legacy:{non_lo_count}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use hah_core::runner::{CommandOutput, MockCommandRunner};
    use tempfile::TempDir;

    #[test]
    fn returns_ok_on_real_system() {
        let mock = MockCommandRunner::new();
        let result = legacy_network_interfaces(&mock);
        assert!(result.is_ok());
    }

    #[test]
    fn absent_returns_empty() {
        let mock = MockCommandRunner::new();
        let result = evaluate_network_interfaces(
            Path::new("/nonexistent"),
            Path::new("/nonexistent"),
            &mock,
        )
        .unwrap();
        assert_eq!(result, CapValue::Str(String::new()));
    }

    #[test]
    fn loopback_only_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let ifaces = tmp.path().join("interfaces");
        std::fs::write(&ifaces, "auto lo\niface lo inet loopback\n").unwrap();
        let mock = MockCommandRunner::new();
        let result =
            evaluate_network_interfaces(&ifaces, Path::new("/nonexistent"), &mock).unwrap();
        assert_eq!(result, CapValue::Str(String::new()));
    }

    #[test]
    fn legacy_no_manager() {
        let tmp = TempDir::new().unwrap();
        let ifaces = tmp.path().join("interfaces");
        std::fs::write(&ifaces, "auto eth0\niface eth0 inet dhcp\n").unwrap();
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| {
            Ok(CommandOutput {
                stdout: vec![],
                stderr: vec![],
                success: false,
            })
        });
        let result =
            evaluate_network_interfaces(&ifaces, Path::new("/nonexistent"), &mock).unwrap();
        assert_eq!(result, CapValue::Str("legacy:2".into()));
    }

    #[test]
    fn overlap_with_netplan() {
        let tmp = TempDir::new().unwrap();
        let ifaces = tmp.path().join("interfaces");
        std::fs::write(&ifaces, "auto eth0\niface eth0 inet dhcp\n").unwrap();
        let netplan = tmp.path().join("netplan");
        std::fs::create_dir_all(&netplan).unwrap();
        std::fs::write(netplan.join("01-config.yaml"), "network:\n").unwrap();
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| {
            Ok(CommandOutput {
                stdout: vec![],
                stderr: vec![],
                success: false,
            })
        });
        let result = evaluate_network_interfaces(&ifaces, &netplan, &mock).unwrap();
        assert_eq!(result, CapValue::Str("overlap:2:Netplan".into()));
    }

    #[test]
    fn overlap_with_nm() {
        let tmp = TempDir::new().unwrap();
        let ifaces = tmp.path().join("interfaces");
        std::fs::write(&ifaces, "auto eth0\niface eth0 inet dhcp\n").unwrap();
        let mut mock = MockCommandRunner::new();
        mock.expect_run().returning(|_, _| {
            Ok(CommandOutput {
                stdout: vec![],
                stderr: vec![],
                success: true,
            })
        });
        let result =
            evaluate_network_interfaces(&ifaces, Path::new("/nonexistent"), &mock).unwrap();
        assert_eq!(result, CapValue::Str("overlap:2:NetworkManager".into()));
    }
}
