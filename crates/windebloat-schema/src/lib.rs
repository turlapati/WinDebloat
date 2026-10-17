pub mod denylist;
pub mod signature;
pub mod validation;

use serde::{Deserialize, Serialize};

/// Canonical full display/release version string (`Year-Month-Date_<Alpha|Beta|Rel>_<x.y.z>`).
/// Can be overridden at compile time via `WINDEBLOAT_DISPLAY_VERSION`.
pub const APP_DISPLAY_VERSION: &str = match option_env!("WINDEBLOAT_DISPLAY_VERSION") {
    Some(v) => v,
    None => "2026-10-17_Beta_0.9.101",
};

pub const EMBEDDED_BASE_MANIFEST_JSON: &str =
    include_str!("../../../manifests/base_manifest.json");
pub const PROFILE_MINIMAL_JSON: &str = include_str!("../../../manifests/profiles/minimal.json");
pub const PROFILE_PRIVACY_JSON: &str = include_str!("../../../manifests/profiles/privacy.json");
pub const PROFILE_GAMER_JSON: &str = include_str!("../../../manifests/profiles/gamer.json");
pub const PROFILE_ENTERPRISE_JSON: &str =
    include_str!("../../../manifests/profiles/enterprise.json");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestFile {
    pub manifest_version: u32,
    #[serde(default)]
    pub manifest_name: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signer_key_id: Option<String>,
    pub bundles: Vec<Bundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bundle {
    pub manifest_version: u32,
    pub id: String,
    pub display_name: String,
    pub category: Category,
    pub rating: Rating,
    pub description: String,
    pub side_effects: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    pub applies_to: AppliesTo,
    pub ui_impact: UiImpact,
    pub bundle_policy: BundlePolicy,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Category {
    #[serde(rename = "Apps")]
    Apps,
    #[serde(rename = "Privacy and telemetry")]
    PrivacyAndTelemetry,
    #[serde(rename = "AI features")]
    AiFeatures,
    #[serde(rename = "Windows Update")]
    WindowsUpdate,
    #[serde(rename = "Appearance")]
    Appearance,
    #[serde(rename = "Start and taskbar")]
    StartAndTaskbar,
    #[serde(rename = "Explorer")]
    Explorer,
    #[serde(rename = "Optional features")]
    OptionalFeatures,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Apps => "Apps",
            Category::PrivacyAndTelemetry => "Privacy and telemetry",
            Category::AiFeatures => "AI features",
            Category::WindowsUpdate => "Windows Update",
            Category::Appearance => "Appearance",
            Category::StartAndTaskbar => "Start and taskbar",
            Category::Explorer => "Explorer",
            Category::OptionalFeatures => "Optional features",
        }
    }

    pub const ALL: &'static [Category] = &[
        Category::Apps,
        Category::PrivacyAndTelemetry,
        Category::AiFeatures,
        Category::WindowsUpdate,
        Category::Appearance,
        Category::StartAndTaskbar,
        Category::Explorer,
        Category::OptionalFeatures,
    ];
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Rating {
    Recommended,
    Limited,
    Expert,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BundlePolicy {
    ContinueOnFail,
    AbortOnFail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliesTo {
    pub os_min_build: u32,
    #[serde(default)]
    pub os_max_build: Option<u32>,
    #[serde(default)]
    pub sku_exclude: Vec<String>,
    #[serde(default)]
    pub region_exclude: Vec<String>,
    #[serde(default)]
    pub effective_on: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiImpact {
    pub explorer_restart: bool,
    pub reboot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    RegistrySet {
        hive: HiveAlias,
        path: String,
        name: String,
        value_type: RegValueType,
        #[serde(default)]
        value: serde_json::Value,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
    AppxRemove {
        scope: AppxScope,
        package_family_name: String,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
    AppxProvisionedRemove {
        package_family_name: String,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
    ScheduledTaskDisable {
        task_path: String,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
    ServiceStartup {
        service_name: String,
        start_type: ServiceStartType,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
    CapabilityRemove {
        capability_name: String,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
    OptionalFeature {
        feature_name: String,
        feature_enabled: bool,
        probe: ProbeSpec,
        undo: UndoSpec,
    },
}

impl Action {
    pub fn probe(&self) -> &ProbeSpec {
        match self {
            Action::RegistrySet { probe, .. }
            | Action::AppxRemove { probe, .. }
            | Action::AppxProvisionedRemove { probe, .. }
            | Action::ScheduledTaskDisable { probe, .. }
            | Action::ServiceStartup { probe, .. }
            | Action::CapabilityRemove { probe, .. }
            | Action::OptionalFeature { probe, .. } => probe,
        }
    }

    pub fn undo(&self) -> &UndoSpec {
        match self {
            Action::RegistrySet { undo, .. }
            | Action::AppxRemove { undo, .. }
            | Action::AppxProvisionedRemove { undo, .. }
            | Action::ScheduledTaskDisable { undo, .. }
            | Action::ServiceStartup { undo, .. }
            | Action::CapabilityRemove { undo, .. }
            | Action::OptionalFeature { undo, .. } => undo,
        }
    }

    pub fn action_type_name(&self) -> &'static str {
        match self {
            Action::RegistrySet { .. } => "registry_set",
            Action::AppxRemove { .. } => "appx_remove",
            Action::AppxProvisionedRemove { .. } => "appx_provisioned_remove",
            Action::ScheduledTaskDisable { .. } => "scheduled_task_disable",
            Action::ServiceStartup { .. } => "service_startup",
            Action::CapabilityRemove { .. } => "capability_remove",
            Action::OptionalFeature { .. } => "optional_feature",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HiveAlias {
    HKLM,
    HKCU,
    DEFAULT,
    ALL_PROFILES,
    #[serde(untagged)]
    ExplicitSid(String),
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegValueType {
    DWORD,
    QWORD,
    SZ,
    EXPAND_SZ,
    MULTI_SZ,
    BINARY,
    DELETE,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppxScope {
    CurrentUser,
    AllUsers,
    AllUsersAndProvisioned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStartType {
    Disabled,
    Manual,
    Automatic,
    DelayedAuto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeSpec {
    pub kind: ProbeKind,
    #[serde(default)]
    pub expected: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    RegistryEquals,
    RegistryAbsent,
    AppxTristate,
    ProvisionedAbsent,
    TaskDisabled,
    ServiceStartType,
    CapabilityAbsent,
    FeatureState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UndoSpec {
    pub tier: UndoTier,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub route: Option<UndoRoute>,
    #[serde(default)]
    pub product_id: Option<String>,
    #[serde(default)]
    pub package_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UndoTier {
    Automatic,
    ManualAssisted,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UndoRoute {
    Store,
    Winget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectionProfile {
    pub profile_version: u32,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub bundles: Vec<String>,
    #[serde(default)]
    pub custom_manifests: Vec<String>,
}

pub fn load_embedded_base_manifest() -> ManifestFile {
    let manifest: ManifestFile =
        serde_json::from_str(EMBEDDED_BASE_MANIFEST_JSON).expect("valid embedded base_manifest.json");
    validation::validate_manifest(&manifest).expect("embedded base_manifest.json passes validation");
    manifest
}

pub fn load_embedded_profiles() -> Vec<SelectionProfile> {
    [
        PROFILE_MINIMAL_JSON,
        PROFILE_PRIVACY_JSON,
        PROFILE_GAMER_JSON,
        PROFILE_ENTERPRISE_JSON,
    ]
    .into_iter()
    .map(|raw| serde_json::from_str::<SelectionProfile>(raw).expect("valid embedded profile"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::denylist::DenylistViolation;
    use crate::signature::{sign_manifest_bundles, verify_manifest_signature};
    use crate::validation::{validate_bundle, validate_manifest, ValidationError};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn embedded_base_manifest_and_profiles_are_valid() {
        let manifest = load_embedded_base_manifest();
        assert!(manifest.bundles.len() >= 14);
        assert!(validate_manifest(&manifest).is_ok());

        let bundle_ids: std::collections::HashSet<_> =
            manifest.bundles.iter().map(|b| b.id.as_str()).collect();
        let profiles = load_embedded_profiles();
        assert_eq!(profiles.len(), 4);
        for profile in &profiles {
            for bid in &profile.bundles {
                assert!(
                    bundle_ids.contains(bid.as_str()),
                    "Profile '{}' references unknown bundle '{}'",
                    profile.id,
                    bid
                );
            }
        }
    }

    #[test]
    fn rejects_wildcard_pfn_and_protected_packages() {
        let mut manifest = load_embedded_base_manifest();
        let mut bundle = manifest.bundles[0].clone();
        bundle.id = "bad_wildcard".to_string();
        bundle.actions = vec![Action::AppxRemove {
            scope: AppxScope::AllUsersAndProvisioned,
            package_family_name: "Microsoft.Xbox*".to_string(),
            probe: ProbeSpec {
                kind: ProbeKind::AppxTristate,
                expected: None,
            },
            undo: UndoSpec {
                tier: UndoTier::None,
                strategy: None,
                route: None,
                product_id: None,
                package_id: None,
            },
        }];
        assert!(matches!(
            validate_bundle(&bundle),
            Err(ValidationError::WildcardOrInvalidPfn { .. })
        ));

        // Now test exact protected package family
        bundle.actions = vec![Action::AppxRemove {
            scope: AppxScope::AllUsersAndProvisioned,
            package_family_name: "Microsoft.WindowsStore_8wekyb3d8bbwe".to_string(),
            probe: ProbeSpec {
                kind: ProbeKind::AppxTristate,
                expected: None,
            },
            undo: UndoSpec {
                tier: UndoTier::None,
                strategy: None,
                route: None,
                product_id: None,
                package_id: None,
            },
        }];
        assert!(matches!(
            validate_bundle(&bundle),
            Err(ValidationError::Denylist(
                DenylistViolation::ProtectedAppxPackage { .. }
            ))
        ));
        manifest.bundles.push(bundle);
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn rejects_abort_on_fail_with_manual_assisted_undo() {
        let manifest = load_embedded_base_manifest();
        let mut bundle = manifest.bundles[0].clone(); // copilot_disable has a manual_assisted Store undo
        bundle.bundle_policy = BundlePolicy::AbortOnFail;
        assert!(matches!(
            validate_bundle(&bundle),
            Err(ValidationError::AbortOnFailWithNonAutoUndo { .. })
        ));
    }

    #[test]
    fn rejects_protected_persistence_and_security_primitives() {
        let manifest = load_embedded_base_manifest();
        let mut bundle = manifest.bundles[0].clone();
        bundle.id = "bad_run_key".to_string();
        bundle.actions = vec![Action::RegistrySet {
            hive: HiveAlias::HKLM,
            path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
            name: "evil".to_string(),
            value_type: RegValueType::SZ,
            value: serde_json::Value::String("x".to_string()),
            probe: ProbeSpec {
                kind: ProbeKind::RegistryEquals,
                expected: None,
            },
            undo: UndoSpec {
                tier: UndoTier::Automatic,
                strategy: None,
                route: None,
                product_id: None,
                package_id: None,
            },
        }];
        assert!(matches!(
            validate_bundle(&bundle),
            Err(ValidationError::Denylist(
                DenylistViolation::ProtectedRegistryPath { .. }
            ))
        ));

        bundle.id = "bad_defender_task".to_string();
        bundle.actions = vec![Action::ScheduledTaskDisable {
            task_path: r"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
                .to_string(),
            probe: ProbeSpec {
                kind: ProbeKind::TaskDisabled,
                expected: None,
            },
            undo: UndoSpec {
                tier: UndoTier::Automatic,
                strategy: None,
                route: None,
                product_id: None,
                package_id: None,
            },
        }];
        assert!(matches!(
            validate_bundle(&bundle),
            Err(ValidationError::Denylist(
                DenylistViolation::ProtectedScheduledTask { .. }
            ))
        ));

        bundle.id = "bad_capability".to_string();
        bundle.actions = vec![Action::CapabilityRemove {
            capability_name: "Windows.SecHealth.UI~~~~0.0.1.0".to_string(),
            probe: ProbeSpec {
                kind: ProbeKind::CapabilityAbsent,
                expected: None,
            },
            undo: UndoSpec {
                tier: UndoTier::None,
                strategy: None,
                route: None,
                product_id: None,
                package_id: None,
            },
        }];
        assert!(matches!(
            validate_bundle(&bundle),
            Err(ValidationError::Denylist(
                DenylistViolation::ProtectedCapability { .. }
            ))
        ));
    }

    #[test]
    fn ed25519_manifest_signature_roundtrip() {
        let manifest = load_embedded_base_manifest();
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let sig_hex = sign_manifest_bundles(&manifest.bundles, &signing_key).unwrap();
        assert!(verify_manifest_signature(
            &manifest.bundles,
            Some(&sig_hex),
            std::slice::from_ref(&pubkey_hex)
        )
        .is_ok());

        // Tampering with bundle description invalidates signature
        let mut tampered = manifest.bundles.clone();
        tampered[0].description.push_str(" tampered");
        assert!(
            verify_manifest_signature(&tampered, Some(&sig_hex), &[pubkey_hex]).is_err()
        );
    }
}
