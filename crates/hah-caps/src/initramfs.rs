//! Large initramfs detection capability.

use std::fs;

use anyhow::{Result, anyhow};

use crate::CapValue;

/// Return a list of `"filename size_mb"` strings for initramfs images in
/// `/boot` that exceed `threshold_mb`.
pub fn large_initramfs(threshold_mb: u64) -> Result<CapValue> {
    let threshold_bytes = threshold_mb * 1024 * 1024;
    let entries = fs::read_dir("/boot").map_err(|e| anyhow!("read_dir /boot: {e}"))?;
    let mut large = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().into_owned();
        if !name_str.starts_with("initrd.img-") && !name_str.starts_with("initramfs-") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            let size = meta.len();
            if size > threshold_bytes {
                let size_mb = size / 1024 / 1024;
                large.push(format!("{name_str} {size_mb}"));
            }
        }
    }
    Ok(CapValue::List(large))
}
