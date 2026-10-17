use crate::backend::{BackendError, OsBackend};
use crate::gating::OsEnvironment;
use crate::journal::{AppxInstallState, TargetState};
use crate::target::{TargetScope, UserProfileInfo};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use windebloat_schema::{
    denylist::check_action_against_denylist, Action, RegValueType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxOsBackend {
    pub env: OsEnvironment,
    pub pending_reboot_reason: Option<String>,
    pub profiles: Vec<UserProfileInfo>,
    pub state_map: HashMap<String, TargetState>,
    #[serde(skip)]
    pub fail_targets: HashSet<String>,
    #[serde(skip)]
    pub persist_path: Option<PathBuf>,
}

impl Default for SandboxOsBackend {
    fn default() -> Self {
        let mut backend = Self {
            env: OsEnvironment {
                build_number: 26100, // Windows 11 24H2 default so all bundles can be exercised
                edition_id: "Professional".to_string(),
                region_code: "US".to_string(),
                is_eea: false,
            },
            pending_reboot_reason: None,
            profiles: vec![
                UserProfileInfo {
                    sid: "S-1-5-21-100000000-200000000-300000000-1001".to_string(),
                    profile_image_path: r"C:\Users\InteractiveUser".to_string(),
                    is_loaded: true,
                },
                UserProfileInfo {
                    sid: "S-1-5-21-100000000-200000000-300000000-1002".to_string(),
                    profile_image_path: r"C:\Users\SecondaryUser".to_string(),
                    is_loaded: false,
                },
            ],
            state_map: HashMap::new(),
            fail_targets: HashSet::new(),
            persist_path: None,
        };
        backend.seed_realistic_defaults();
        backend
    }
}

impl SandboxOsBackend {
    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            if let Ok(raw) = fs::read_to_string(path) {
                if let Ok(mut loaded) = serde_json::from_str::<SandboxOsBackend>(&raw) {
                    let fresh = Self::default();
                    for (k, v) in fresh.state_map {
                        loaded.state_map.entry(k).or_insert(v);
                    }
                    loaded.persist_path = Some(path.to_path_buf());
                    let _ = loaded.save();
                    return loaded;
                }
            }
        }
        let mut b = Self::default();
        b.persist_path = Some(path.to_path_buf());
        let _ = b.save();
        b
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(p) = &self.persist_path {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?;
            }
            let json = serde_json::to_string_pretty(self)?;
            fs::write(p, json)?;
        }
        Ok(())
    }

    fn seed_realistic_defaults(&mut self) {
        // Seed preinstalled bloatware Appx packages as Installed
        for pfn in [
            "Microsoft.Copilot_8wekyb3d8bbwe",
            "Microsoft.Windows.AIHub_8wekyb3d8bbwe",
            "Microsoft.Windows.DevHome_8wekyb3d8bbwe",
            "Clipchamp.Clipchamp_yxz26nhyzhsrt",
            "Microsoft.BingNews_8wekyb3d8bbwe",
            "Microsoft.BingWeather_8wekyb3d8bbwe",
            "Microsoft.BingFinance_8wekyb3d8bbwe",
            "Microsoft.BingSports_8wekyb3d8bbwe",
            "Microsoft.BingSearch_8wekyb3d8bbwe",
            "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe",
            "Microsoft.OutlookForWindows_8wekyb3d8bbwe",
            "MSTeams_8wekyb3d8bbwe",
            "Microsoft.549981C3F5F10_8wekyb3d8bbwe",
            "Microsoft.Getstarted_8wekyb3d8bbwe",
            "Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe",
            "Microsoft.Microsoft3DViewer_8wekyb3d8bbwe",
            "Microsoft.MSPaint_8wekyb3d8bbwe",
            "Microsoft.MixedReality.Portal_8wekyb3d8bbwe",
            "Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe",
            "Microsoft.M365Companions_8wekyb3d8bbwe",
            "Microsoft.Office.OneNote_8wekyb3d8bbwe",
            "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe",
            "Microsoft.Todos_8wekyb3d8bbwe",
            "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe",
            "MicrosoftCorporationII.MicrosoftFamily_8wekyb3d8bbwe",
            "Microsoft.People_8wekyb3d8bbwe",
            "Microsoft.windowscommunicationsapps_8wekyb3d8bbwe",
            "Microsoft.WindowsMaps_8wekyb3d8bbwe",
            "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe",
            "Microsoft.WindowsCamera_8wekyb3d8bbwe",
            "Microsoft.WindowsAlarms_8wekyb3d8bbwe",
            "Microsoft.YourPhone_8wekyb3d8bbwe",
            "MicrosoftWindows.CrossDevice_cw5n1h2txyewy",
            "Microsoft.ZuneVideo_8wekyb3d8bbwe",
            "Microsoft.ZuneMusic_8wekyb3d8bbwe",
            "Microsoft.GamingApp_8wekyb3d8bbwe",
            "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
            "SpotifyAB.SpotifyMusic_zpdnekdrzrea0",
            "Disney.37853FC22B2CE_6rarf9sa4v8jt",
        ] {
            self.state_map.insert(
                format!("Appx\\{}", pfn),
                TargetState::AppxTristate(AppxInstallState::Installed),
            );
            self.state_map.insert(
                format!("AppxProvisioned\\{}", pfn),
                TargetState::ProvisionedPresent(true),
            );
        }

        // Seed services & tasks in their default enabled state
        self.state_map.insert(
            "Service\\DiagTrack".to_string(),
            TargetState::ServiceStart("automatic".to_string()),
        );
        self.state_map.insert(
            "Service\\dmwappushservice".to_string(),
            TargetState::ServiceStart("manual".to_string()),
        );
        self.state_map.insert(
            "ScheduledTask\\\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
                .to_string(),
            TargetState::TaskDisabled(false),
        );
        self.state_map.insert(
            "ScheduledTask\\\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator"
                .to_string(),
            TargetState::TaskDisabled(false),
        );
        self.state_map.insert(
            "OptionalFeature\\Recall".to_string(),
            TargetState::FeatureEnabled(true),
        );
        self.state_map.insert(
            "Capability\\Microsoft.Windows.WordPad~~~~0.0.1.0".to_string(),
            TargetState::CapabilityPresent(true),
        );
        self.state_map.insert(
            "Capability\\App.StepsRecorder~~~~0.0.1.0".to_string(),
            TargetState::CapabilityPresent(true),
        );
        self.state_map.insert(
            "Capability\\MathRecognizer~~~~0.0.1.0".to_string(),
            TargetState::CapabilityPresent(true),
        );
        self.state_map.insert(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}\".to_string(),
            TargetState::RegistryValue(serde_json::Value::String("Removable Drives".to_string())),
        );
    }
}

impl OsBackend for SandboxOsBackend {
    fn environment(&self) -> OsEnvironment {
        self.env.clone()
    }

    fn check_pending_reboot(&self) -> Option<String> {
        self.pending_reboot_reason.clone()
    }

    fn list_user_profiles(&self, scope: &TargetScope) -> Result<Vec<UserProfileInfo>, BackendError> {
        match scope {
            TargetScope::Sid(sid) => Ok(vec![UserProfileInfo {
                sid: sid.clone(),
                profile_image_path: format!(r"C:\Users\{}", sid),
                is_loaded: true,
            }]),
            TargetScope::Default => Ok(vec![UserProfileInfo {
                sid: "DEFAULT".to_string(),
                profile_image_path: r"C:\Users\Default".to_string(),
                is_loaded: false,
            }]),
            TargetScope::AllProfiles => Ok(self.profiles.clone()),
        }
    }

    fn probe_target(
        &self,
        action: &Action,
        resolved_target: &str,
    ) -> Result<TargetState, BackendError> {
        if let Some(st) = self.state_map.get(resolved_target) {
            return Ok(st.clone());
        }
        let default_state = match action {
            Action::RegistrySet { .. } => TargetState::Absent,
            Action::AppxRemove { .. } => TargetState::AppxTristate(AppxInstallState::Absent),
            Action::AppxProvisionedRemove { .. } => TargetState::ProvisionedPresent(false),
            Action::ScheduledTaskDisable { .. } => TargetState::TaskDisabled(false),
            Action::ServiceStartup { .. } => TargetState::ServiceStart("automatic".to_string()),
            Action::CapabilityRemove { .. } => TargetState::CapabilityPresent(false),
            Action::OptionalFeature { .. } => TargetState::FeatureEnabled(false),
        };
        Ok(default_state)
    }

    fn apply_target(
        &mut self,
        action: &Action,
        resolved_target: &str,
    ) -> Result<TargetState, BackendError> {
        if let Err(v) = check_action_against_denylist("runtime", 0, action) {
            return Err(BackendError::DenylistBlocked(v.to_string()));
        }

        if matches!(
            action,
            Action::AppxProvisionedRemove { .. }
                | Action::CapabilityRemove { .. }
                | Action::OptionalFeature { .. }
        ) {
            if let Some(reason) = self.check_pending_reboot() {
                return Err(BackendError::PendingReboot(reason));
            }
        }

        if self.fail_targets.contains(resolved_target) {
            return Err(BackendError::OsError {
                target: resolved_target.to_string(),
                message: "Simulated fault injection failure".to_string(),
            });
        }

        let new_state = match action {
            Action::RegistrySet {
                value_type, value, ..
            } => {
                if matches!(value_type, RegValueType::DELETE) {
                    TargetState::Absent
                } else {
                    TargetState::RegistryValue(value.clone())
                }
            }
            Action::AppxRemove { .. } => TargetState::AppxTristate(AppxInstallState::Absent),
            Action::AppxProvisionedRemove { .. } => TargetState::ProvisionedPresent(false),
            Action::ScheduledTaskDisable { .. } => TargetState::TaskDisabled(true),
            Action::ServiceStartup { start_type, .. } => {
                let st = serde_json::to_value(start_type)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "disabled".to_string());
                TargetState::ServiceStart(st)
            }
            Action::CapabilityRemove { .. } => TargetState::CapabilityPresent(false),
            Action::OptionalFeature {
                feature_enabled, ..
            } => TargetState::FeatureEnabled(*feature_enabled),
        };

        self.state_map
            .insert(resolved_target.to_string(), new_state.clone());
        let _ = self.save();
        Ok(new_state)
    }

    fn restore_target(
        &mut self,
        _action: &Action,
        resolved_target: &str,
        prior: &TargetState,
    ) -> Result<(), BackendError> {
        self.state_map
            .insert(resolved_target.to_string(), prior.clone());
        let _ = self.save();
        Ok(())
    }
}
