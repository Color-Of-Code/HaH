use std::{collections::HashMap, fs};

use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct DistroInfo {
    pub id: String,
    pub id_like: String,
    pub version_codename: String,
    pub version_id: String,
    pub pretty_name: String,
}

impl DistroInfo {
    pub fn detect() -> Result<Self> {
        let content = fs::read_to_string("/etc/os-release")?;
        let map: HashMap<String, String> = content
            .lines()
            .filter_map(|line| {
                let (k, v) = line.split_once('=')?;
                Some((k.to_string(), v.trim_matches('"').to_string()))
            })
            .collect();

        Ok(Self {
            id: map.get("ID").cloned().unwrap_or_default(),
            id_like: map.get("ID_LIKE").cloned().unwrap_or_default(),
            version_codename: map.get("VERSION_CODENAME").cloned().unwrap_or_default(),
            version_id: map.get("VERSION_ID").cloned().unwrap_or_default(),
            pretty_name: map.get("PRETTY_NAME").cloned().unwrap_or_default(),
        })
    }

    pub fn is_debian_family(&self) -> bool {
        self.id == "debian"
            || self.id == "ubuntu"
            || self.id_like.contains("debian")
            || self.id_like.contains("ubuntu")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn distro(id: &str, id_like: &str) -> DistroInfo {
        DistroInfo {
            id: id.into(),
            id_like: id_like.into(),
            ..DistroInfo::default()
        }
    }

    #[test]
    fn is_debian_family_debian_id() {
        assert!(distro("debian", "").is_debian_family());
    }

    #[test]
    fn is_debian_family_ubuntu_id() {
        assert!(distro("ubuntu", "").is_debian_family());
    }

    #[test]
    fn is_debian_family_via_id_like_debian() {
        assert!(distro("linuxmint", "ubuntu debian").is_debian_family());
    }

    #[test]
    fn is_debian_family_via_id_like_ubuntu() {
        assert!(distro("pop", "ubuntu").is_debian_family());
    }

    #[test]
    fn is_not_debian_family_for_arch() {
        assert!(!distro("arch", "").is_debian_family());
    }

    #[test]
    fn is_not_debian_family_for_fedora() {
        assert!(!distro("fedora", "rhel").is_debian_family());
    }

    #[test]
    fn detect_reads_current_system() {
        // /etc/os-release exists on all Linux systems under test
        let result = DistroInfo::detect();
        assert!(result.is_ok(), "detect() failed: {:?}", result.err());
        let info = result.unwrap();
        assert!(!info.id.is_empty());
        // exercise is_debian_family on a real system value
        let _ = info.is_debian_family();
    }
}
