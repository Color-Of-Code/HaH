//! Adapter bridging `hah-caps` capability values into the DSL pipeline.
//!
//! This module dispatches [`CapabilitySpec`] to `hah-caps` functions and
//! converts the resulting [`CapValue`] into [`RuleValue`].

use anyhow::Result;
use hah_caps::CapValue;
use hah_core::check::Context;

use crate::pipeline::RuleValue;
use crate::rule::CapabilitySpec;

/// Convert a [`CapValue`] from `hah-caps` into a [`RuleValue`].
fn convert(cap: CapValue) -> RuleValue {
    match cap {
        CapValue::Int(n) => RuleValue::Int(n),
        CapValue::Str(s) => RuleValue::Str(s),
        CapValue::List(items) => RuleValue::List(items.into_iter().map(RuleValue::Str).collect()),
    }
}

/// Dispatch a capability spec to the matching `hah-caps` function and
/// return the result as a [`RuleValue`].
pub fn dispatch(spec: &CapabilitySpec, ctx: &Context) -> Result<RuleValue> {
    let runner = ctx.runner.as_ref();
    let result: Result<CapValue> = match spec {
        CapabilitySpec::JournalUsage => hah_caps::journal::journal_usage_mb(runner),
        CapabilitySpec::OldFiles {
            paths,
            older_than_days,
        } => hah_caps::files::old_files(paths, *older_than_days),
        CapabilitySpec::BrokenSymlinks { paths } => hah_caps::files::broken_symlinks(paths),
        CapabilitySpec::SysctlConflicts { paths } => hah_caps::sysctl::sysctl_conflicts(paths),
        CapabilitySpec::KernelInventory => hah_caps::kernel::kernel_inventory(runner),
        CapabilitySpec::StaleKernelHeaders => hah_caps::kernel::stale_kernel_headers(runner),
        CapabilitySpec::LargeInitramfs { threshold_mb } => {
            hah_caps::initramfs::large_initramfs(*threshold_mb)
        }
        CapabilitySpec::LegacyAptSources => hah_caps::files::legacy_apt_sources(),
        CapabilitySpec::LegacyNetworkInterfaces => {
            hah_caps::network::legacy_network_interfaces(runner)
        }
        CapabilitySpec::InstalledDenylist => {
            hah_caps::apt::installed_denylist(runner, &ctx.config.denylist.packages)
        }
    };
    Ok(convert(result?))
}
