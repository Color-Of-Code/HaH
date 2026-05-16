//! Human-readable byte-size parsing.
//!
//! Import from this module rather than from any specific size-parsing library
//! so that the underlying implementation can be swapped without touching
//! callers.

use bytesize::ByteSize;

// ── parse_bytes ───────────────────────────────────────────────────────────────

/// Parse a human-readable SI byte-size token (e.g. `"1.5G"`, `"512M"`,
/// `"256K"`) into a raw byte count.
///
/// A trailing `.` is stripped before parsing because `journalctl` sometimes
/// emits values like `"1.2G."`.
///
/// Returns `None` if the token cannot be parsed.
pub fn parse_bytes(s: &str) -> Option<u64> {
    s.trim_end_matches('.')
        .parse::<ByteSize>()
        .ok()
        .map(|b| b.0)
}

// ── parse_journal_disk_usage ──────────────────────────────────────────────────

/// Extract the journal size in bytes from a `journalctl --disk-usage` output
/// line.
///
/// Expects a line such as:
/// ```text
/// Archived and active journals take up 1.2G in the file system.
/// ```
///
/// Returns `None` if the expected pattern is not found or the size token
/// cannot be parsed.
pub fn parse_journal_disk_usage(output: &str) -> Option<u64> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let idx = tokens.iter().position(|&t| t == "up")?;
    parse_bytes(tokens.get(idx + 1)?)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── parse_bytes ───────────────────────────────────────────────────────────

    #[test]
    fn parse_bytes_gigabytes_suffix_g() {
        assert_eq!(parse_bytes("2G").unwrap(), 2_000_000_000);
    }

    #[test]
    fn parse_bytes_gigabytes_suffix_gb() {
        assert_eq!(parse_bytes("1GB").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parse_bytes_megabytes_suffix_m() {
        assert_eq!(parse_bytes("100M").unwrap(), 100_000_000);
    }

    #[test]
    fn parse_bytes_megabytes_suffix_mb() {
        assert_eq!(parse_bytes("200MB").unwrap(), 200_000_000);
    }

    #[test]
    fn parse_bytes_kilobytes_suffix_k() {
        assert_eq!(parse_bytes("512K").unwrap(), 512_000);
    }

    #[test]
    fn parse_bytes_kilobytes_suffix_kb() {
        assert_eq!(parse_bytes("1024KB").unwrap(), 1_024_000);
    }

    #[test]
    fn parse_bytes_unknown_unit_returns_none() {
        assert!(parse_bytes("100XB").is_none());
        assert!(parse_bytes("").is_none());
        assert!(parse_bytes("abc").is_none());
    }

    #[test]
    fn parse_bytes_trailing_dot_stripped() {
        assert!(parse_bytes("1.2G.").is_some());
    }

    // ── parse_journal_disk_usage ──────────────────────────────────────────────

    #[test]
    fn parse_journal_disk_usage_gigabytes() {
        let output = "Archived and active journals take up 1.2G in the file system.";
        assert!(parse_journal_disk_usage(output).unwrap() > 1_000_000_000);
    }

    #[test]
    fn parse_journal_disk_usage_megabytes() {
        let output = "Archived and active journals take up 300M in the file system.";
        assert!(parse_journal_disk_usage(output).unwrap() > 100_000_000);
    }

    #[test]
    fn parse_journal_disk_usage_malformed_returns_none() {
        assert!(parse_journal_disk_usage("no size information here").is_none());
        assert!(parse_journal_disk_usage("").is_none());
    }
}
