use crate::{Action, Bundle, ServiceStartType};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DenylistViolation {
    #[error("Bundle '{bundle_id}' action #{action_index}: package family '{pfn}' matches protected OS denylist rule '{rule}'")]
    ProtectedAppxPackage {
        bundle_id: String,
        action_index: usize,
        pfn: String,
        rule: &'static str,
    },
    #[error("Bundle '{bundle_id}' action #{action_index}: registry path '{path}' matches protected OS denylist subtree '{rule}'")]
    ProtectedRegistryPath {
        bundle_id: String,
        action_index: usize,
        path: String,
        rule: &'static str,
    },
    #[error("Bundle '{bundle_id}' action #{action_index}: service '{service}' is a protected boot/security-critical OS service")]
    ProtectedService {
        bundle_id: String,
        action_index: usize,
        service: String,
    },
    #[error("Bundle '{bundle_id}' action #{action_index}: scheduled task '{task}' matches a protected security task prefix '{rule}'")]
    ProtectedScheduledTask {
        bundle_id: String,
        action_index: usize,
        task: String,
        rule: &'static str,
    },
    #[error("Bundle '{bundle_id}' action #{action_index}: capability '{capability}' matches a protected security capability '{rule}'")]
    ProtectedCapability {
        bundle_id: String,
        action_index: usize,
        capability: String,
        rule: &'static str,
    },
}

/// Protected Appx Package Family patterns per SDS v3 §2.3
pub const PROTECTED_APPX_PREFIXES: &[&str] = &[
    "MicrosoftWindows.Client.",
    "Microsoft.Windows.ShellExperienceHost",
    "Microsoft.Windows.StartMenuExperienceHost",
    "Microsoft.SecHealthUI",
    "Microsoft.UI.Xaml.",
    "Microsoft.VCLibs.",
    "Microsoft.NET.Native.",
    "Microsoft.WindowsStore",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.XboxIdentityProvider",
];

/// Boot-critical and core security services under HKLM\SYSTEM\CurrentControlSet\Services
pub const PROTECTED_SERVICES: &[&str] = &[
    "acpi",
    "bfe",
    "clfs",
    "cng",
    "cryptsvc",
    "dcomlaunch",
    "disk",
    "dnsclient",
    "dnscache",
    "eventlog",
    "fltmgr",
    "gpsvc",
    "http",
    "ksecdd",
    "ksecpkg",
    "lanmanworkstation",
    "lsm",
    "mountmgr",
    "mpssvc",
    "msiserver",
    "ndis",
    "netlogon",
    "nsi",
    "ntfs",
    "partmgr",
    "pcw",
    "plugplay",
    "power",
    "profsvc",
    "rpceptmapper",
    "rpcss",
    "samss",
    "schedule",
    "securityhealthservice",
    "sense",
    "spaceport",
    "storachi",
    "stornvme",
    "sysmain",
    "tcpip",
    "trustedinstaller",
    "volmgr",
    "volmgrx",
    "volsnap",
    "wdf01000",
    "wdboot",
    "wdfilter",
    "wdnissvc",
    "windefend",
    "wininit",
    "winlogon",
    "wscsvc",
    "wuauserv",
];

/// Protected registry subtrees (normalized to uppercase, backslash-separated without hive root)
pub const PROTECTED_REGISTRY_SUBTREES: &[&str] = &[
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS",
    "SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS",
    "SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS",
    "SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS",
    "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA",
    "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SAFEBOOT",
    "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\KNOWNDLLS",
    "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\APPCERTDLLS",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE",
    "SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN",
    "SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES\\EXPLORER\\RUN",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\AUTHENTICATION",
    // WebView2 Evergreen runtime registration keys (§2.3)
    "SOFTWARE\\MICROSOFT\\EDGEUPDATE\\CLIENTS\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "SOFTWARE\\WOW6432NODE\\MICROSOFT\\EDGEUPDATE\\CLIENTS\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL\\MICROSOFT EDGEWEBVIEW",
    "SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL\\MICROSOFT EDGEWEBVIEW",
];

/// Scheduled-task path prefixes that must not be disabled (normalized, case-insensitive).
pub const PROTECTED_TASK_PREFIXES: &[&str] = &[
    "\\MICROSOFT\\WINDOWS\\WINDOWS DEFENDER",
    "\\MICROSOFT\\WINDOWS\\WINDOWSDEFENDER",
    "\\MICROSOFT\\WINDOWS\\WINDOWSUPDATE",
    "\\MICROSOFT\\WINDOWS\\WINDOWS UPDATE",
    "\\MICROSOFT\\WINDOWS\\EXPLOITGUARD",
    "\\MICROSOFT\\WINDOWS\\WINDOWS DEFENDER SCHEDULED SCAN",
];

/// Capability name fragments that must not be removed.
pub const PROTECTED_CAPABILITY_FRAGMENTS: &[&str] = &[
    "sechealth",
    "windowshello",
    "credentialguard",
    "secureboot",
    "isolatedusermode",
    "hvci",
];

pub fn check_bundle_against_denylist(bundle: &Bundle) -> Result<(), DenylistViolation> {
    for (idx, action) in bundle.actions.iter().enumerate() {
        check_action_against_denylist(&bundle.id, idx, action)?;
    }
    Ok(())
}

pub fn check_action_against_denylist(
    bundle_id: &str,
    action_index: usize,
    action: &Action,
) -> Result<(), DenylistViolation> {
    match action {
        Action::AppxRemove {
            package_family_name,
            ..
        }
        | Action::AppxProvisionedRemove {
            package_family_name,
            ..
        } => {
            let pfn_lower = package_family_name.to_ascii_lowercase();
            for &prefix in PROTECTED_APPX_PREFIXES {
                if pfn_lower.starts_with(&prefix.to_ascii_lowercase()) {
                    return Err(DenylistViolation::ProtectedAppxPackage {
                        bundle_id: bundle_id.to_string(),
                        action_index,
                        pfn: package_family_name.clone(),
                        rule: prefix,
                    });
                }
            }
            if pfn_lower.contains("edgewebview") || pfn_lower.contains("webview2") {
                return Err(DenylistViolation::ProtectedAppxPackage {
                    bundle_id: bundle_id.to_string(),
                    action_index,
                    pfn: package_family_name.clone(),
                    rule: "WebView2 Runtime",
                });
            }
        }
        Action::RegistrySet { path, .. } => {
            let norm = path.trim_matches('\\').replace('/', "\\").to_ascii_uppercase();
            for &subtree in PROTECTED_REGISTRY_SUBTREES {
                if norm == subtree || norm.starts_with(&format!("{}\\", subtree)) {
                    return Err(DenylistViolation::ProtectedRegistryPath {
                        bundle_id: bundle_id.to_string(),
                        action_index,
                        path: path.clone(),
                        rule: subtree,
                    });
                }
            }
            // Also block direct registry tampering of protected services under SYSTEM\CurrentControlSet\Services\<svc>
            let services_prefix = "SYSTEM\\CURRENTCONTROLSET\\SERVICES\\";
            if let Some(rest) = norm.strip_prefix(services_prefix) {
                let svc_name = rest.split('\\').next().unwrap_or("").to_ascii_lowercase();
                if PROTECTED_SERVICES.contains(&svc_name.as_str()) {
                    return Err(DenylistViolation::ProtectedRegistryPath {
                        bundle_id: bundle_id.to_string(),
                        action_index,
                        path: path.clone(),
                        rule: "SYSTEM\\CurrentControlSet\\Services\\<BootCritical>",
                    });
                }
            }
        }
        Action::ServiceStartup {
            service_name,
            start_type,
            ..
        } => {
            let svc_lower = service_name.to_ascii_lowercase();
            if PROTECTED_SERVICES.contains(&svc_lower.as_str())
                && matches!(start_type, ServiceStartType::Disabled | ServiceStartType::Manual)
            {
                return Err(DenylistViolation::ProtectedService {
                    bundle_id: bundle_id.to_string(),
                    action_index,
                    service: service_name.clone(),
                });
            }
        }
        Action::ScheduledTaskDisable { task_path, .. } => {
            let norm = task_path.replace('/', "\\").to_ascii_uppercase();
            let norm = if norm.starts_with('\\') {
                norm
            } else {
                format!("\\{}", norm)
            };
            for &prefix in PROTECTED_TASK_PREFIXES {
                if norm == prefix || norm.starts_with(&format!("{}\\", prefix)) {
                    return Err(DenylistViolation::ProtectedScheduledTask {
                        bundle_id: bundle_id.to_string(),
                        action_index,
                        task: task_path.clone(),
                        rule: prefix,
                    });
                }
            }
        }
        Action::CapabilityRemove {
            capability_name, ..
        } => {
            let lower = capability_name.to_ascii_lowercase();
            for &frag in PROTECTED_CAPABILITY_FRAGMENTS {
                if lower.contains(frag) {
                    return Err(DenylistViolation::ProtectedCapability {
                        bundle_id: bundle_id.to_string(),
                        action_index,
                        capability: capability_name.clone(),
                        rule: frag,
                    });
                }
            }
        }
        _ => {}
    }
    Ok(())
}
