use serde::{Deserialize, Serialize};
use thiserror::Error;
use windebloat_schema::{Action, HiveAlias};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    /// Explicit user SID, e.g. `S-1-5-21-...`
    Sid(String),
    /// Default user template hive (`C:\Users\Default\NTUSER.DAT`)
    Default,
    /// All user profiles under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
    AllProfiles,
}

pub fn is_valid_sid_str(sid: &str) -> bool {
    if sid.len() < 8 || sid.len() > 256 || !sid.starts_with("S-1-5-") {
        return false;
    }
    let rest = &sid[6..];
    !rest.is_empty()
        && rest
            .split('-')
            .all(|g| !g.is_empty() && g.chars().all(|c| c.is_ascii_digit()))
}

impl TargetScope {
    pub fn parse_cli(raw: &str) -> Result<Self, TargetResolutionError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "default" => Ok(TargetScope::Default),
            "all-profiles" | "all_profiles" => Ok(TargetScope::AllProfiles),
            _ => {
                let s = raw.trim();
                if is_valid_sid_str(s) {
                    Ok(TargetScope::Sid(s.to_string()))
                } else {
                    Err(TargetResolutionError::InvalidSid(s.to_string()))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfileInfo {
    pub sid: String,
    pub profile_image_path: String,
    pub is_loaded: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetResolutionError {
    #[error("Invalid security identifier (SID): '{0}'")]
    InvalidSid(String),
    #[error("Action requires a user SID or profile scope, but none was provided")]
    MissingUserScope,
}

/// Rewrites logical registry hive aliases (`HKCU`, `HKCU\Software\Classes`) per SDS v3 §2.2.
///
/// - `HKCU\Software\Classes\<rest>` -> `HKU\<SID>_Classes\<rest>`
/// - `HKCU\<rest>` -> `HKU\<SID>\<rest>`
/// - `HKLM\<rest>` -> `HKLM\<rest>`
pub fn rewrite_registry_target(
    hive: &HiveAlias,
    path: &str,
    value_name: &str,
    target_sid: &str,
) -> Result<String, TargetResolutionError> {
    let clean_path = path.trim_matches('\\').replace('/', "\\");
    let suffix = if value_name.is_empty() {
        "@Default".to_string()
    } else {
        value_name.to_string()
    };

    match hive {
        HiveAlias::HKLM => Ok(format!("HKLM\\{}\\{}", clean_path, suffix)),
        HiveAlias::HKCU => {
            if !is_valid_sid_str(target_sid) && target_sid != "DEFAULT" {
                return Err(TargetResolutionError::InvalidSid(target_sid.to_string()));
            }
            if target_sid == "DEFAULT" {
                return Ok(format!(
                    "HKU\\WINDEBLOAT_DEFAULT\\{}\\{}",
                    clean_path, suffix
                ));
            }
            // Check if path targets Software\Classes (§2.2)
            let upper = clean_path.to_ascii_uppercase();
            if upper == "SOFTWARE\\CLASSES" {
                Ok(format!("HKU\\{}_Classes\\{}", target_sid, suffix))
            } else if upper.starts_with("SOFTWARE\\CLASSES\\") {
                let sub = &clean_path["Software\\Classes\\".len()..];
                Ok(format!("HKU\\{}_Classes\\{}\\{}", target_sid, sub, suffix))
            } else {
                Ok(format!("HKU\\{}\\{}\\{}", target_sid, clean_path, suffix))
            }
        }
        HiveAlias::DEFAULT => Ok(format!(
            "HKU\\WINDEBLOAT_DEFAULT\\{}\\{}",
            clean_path, suffix
        )),
        HiveAlias::ALL_PROFILES => {
            if target_sid == "DEFAULT" {
                Ok(format!(
                    "HKU\\WINDEBLOAT_DEFAULT\\{}\\{}",
                    clean_path, suffix
                ))
            } else {
                rewrite_registry_target(&HiveAlias::HKCU, path, value_name, target_sid)
            }
        }
        HiveAlias::ExplicitSid(sid_str) => {
            let sid = sid_str.strip_prefix("HKU\\").unwrap_or(sid_str.as_str());
            rewrite_registry_target(&HiveAlias::HKCU, path, value_name, sid)
        }
    }
}

/// Resolves the canonical target identifier stored in `journal.json` for a given action and user SID.
pub fn resolve_action_targets(
    action: &Action,
    scope: &TargetScope,
    profiles: &[UserProfileInfo],
) -> Result<Vec<String>, TargetResolutionError> {
    match action {
        Action::RegistrySet {
            hive, path, name, ..
        } => match hive {
            // Machine-scope actions run once regardless of user scope (§7.1)
            HiveAlias::HKLM => Ok(vec![rewrite_registry_target(hive, path, name, "S-1-5-18")?]),
            HiveAlias::DEFAULT => Ok(vec![rewrite_registry_target(hive, path, name, "DEFAULT")?]),
            HiveAlias::HKCU | HiveAlias::ALL_PROFILES | HiveAlias::ExplicitSid(_) => match scope {
                TargetScope::Sid(sid) => Ok(vec![rewrite_registry_target(hive, path, name, sid)?]),
                TargetScope::Default => {
                    Ok(vec![rewrite_registry_target(hive, path, name, "DEFAULT")?])
                }
                TargetScope::AllProfiles => {
                    let mut out = Vec::new();
                    for p in profiles {
                        out.push(rewrite_registry_target(hive, path, name, &p.sid)?);
                    }
                    if out.is_empty() {
                        out.push(rewrite_registry_target(hive, path, name, "DEFAULT")?);
                    }
                    Ok(out)
                }
            },
        },
        Action::AppxRemove {
            package_family_name,
            ..
        } => Ok(vec![format!("Appx\\{}", package_family_name)]),
        Action::AppxProvisionedRemove {
            package_family_name,
            ..
        } => Ok(vec![format!("AppxProvisioned\\{}", package_family_name)]),
        Action::ScheduledTaskDisable { task_path, .. } => {
            Ok(vec![format!("ScheduledTask\\{}", task_path)])
        }
        Action::ServiceStartup { service_name, .. } => {
            Ok(vec![format!("Service\\{}", service_name)])
        }
        Action::CapabilityRemove {
            capability_name, ..
        } => Ok(vec![format!("Capability\\{}", capability_name)]),
        Action::OptionalFeature { feature_name, .. } => {
            Ok(vec![format!("OptionalFeature\\{}", feature_name)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_hkcu_and_hkcu_classes_correctly() {
        let sid = "S-1-5-21-123456789-1001";
        let reg = rewrite_registry_target(
            &HiveAlias::HKCU,
            r"Software\Policies\Microsoft\Windows\WindowsCopilot",
            "TurnOffWindowsCopilot",
            sid,
        )
        .unwrap();
        assert_eq!(
            reg,
            "HKU\\S-1-5-21-123456789-1001\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot\\TurnOffWindowsCopilot"
        );

        let classes = rewrite_registry_target(
            &HiveAlias::HKCU,
            r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
            "",
            sid,
        )
        .unwrap();
        assert_eq!(
            classes,
            "HKU\\S-1-5-21-123456789-1001_Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32\\@Default"
        );

        assert!(TargetScope::parse_cli("S-1-5-21-123-456").is_ok());
        assert!(TargetScope::parse_cli("S-1-5-21-1)(A;;GA;;;WD)").is_err());
        assert!(TargetScope::parse_cli(r"S-1-5-21-..\..\Evil").is_err());
    }
}
