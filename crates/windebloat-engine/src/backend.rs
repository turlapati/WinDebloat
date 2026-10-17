use crate::gating::OsEnvironment;
use crate::journal::TargetState;
use crate::target::{TargetScope, UserProfileInfo};
use thiserror::Error;
use windebloat_schema::Action;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("DISM actions blocked by pending system reboot: {0}")]
    PendingReboot(String),
    #[error("Protected OS target blocked by denylist: {0}")]
    DenylistBlocked(String),
    #[error("OS API error on '{target}': {message}")]
    OsError { target: String, message: String },
    #[error("Unsupported or invalid target format: '{0}'")]
    InvalidTarget(String),
}

pub trait OsBackend {
    /// Returns current OS build, EditionID SKU, and Geo/DMA region.
    fn environment(&self) -> OsEnvironment;

    /// Checks pending reboot markers before any DISM call (§4.2):
    /// - `Component Based Servicing\RebootPending`
    /// - `WindowsUpdate\Auto Update\RebootRequired`
    /// - `Session Manager\PendingFileRenameOperations`
    fn check_pending_reboot(&self) -> Option<String>;

    /// Enumerates user profiles matching `scope` (`ProfileList` or explicit SID).
    fn list_user_profiles(&self, scope: &TargetScope) -> Result<Vec<UserProfileInfo>, BackendError>;

    /// Probes the current state of `resolved_target` for `action`.
    fn probe_target(
        &self,
        action: &Action,
        resolved_target: &str,
    ) -> Result<TargetState, BackendError>;

    /// Applies `action` to `resolved_target` and returns the written `TargetState`.
    fn apply_target(
        &mut self,
        action: &Action,
        resolved_target: &str,
    ) -> Result<TargetState, BackendError>;

    /// Restores `prior` state to `resolved_target` during automatic undo or `abort_on_fail` rollback.
    fn restore_target(
        &mut self,
        action: &Action,
        resolved_target: &str,
        prior: &TargetState,
    ) -> Result<(), BackendError>;

    /// Returns whether an action matches its target post-state based on `action.probe()` and `current`.
    fn is_target_state_satisfied(&self, action: &Action, current: &TargetState) -> bool {
        if matches!(current, TargetState::NotApplicable) {
            return true;
        }
        match (action, current) {
            (Action::RegistrySet { value, value_type, .. }, TargetState::RegistryValue(cur_val)) => {
                if matches!(value_type, windebloat_schema::RegValueType::DELETE) {
                    false
                } else {
                    cur_val == value
                }
            }
            (Action::RegistrySet { value_type, .. }, TargetState::Absent) => {
                matches!(value_type, windebloat_schema::RegValueType::DELETE)
            }
            (Action::AppxRemove { .. }, TargetState::AppxTristate(state)) => {
                *state == crate::journal::AppxInstallState::Absent
            }
            (Action::AppxProvisionedRemove { .. }, TargetState::ProvisionedPresent(present)) => {
                !*present
            }
            (Action::ScheduledTaskDisable { .. }, TargetState::TaskDisabled(disabled)) => *disabled,
            (
                Action::ServiceStartup { start_type, .. },
                TargetState::ServiceStart(cur_start),
            ) => {
                let expected = serde_json::to_value(start_type)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default();
                cur_start.eq_ignore_ascii_case(&expected)
            }
            (Action::CapabilityRemove { .. }, TargetState::CapabilityPresent(present)) => !*present,
            (
                Action::OptionalFeature {
                    feature_enabled, ..
                },
                TargetState::FeatureEnabled(cur_enabled),
            ) => cur_enabled == feature_enabled,
            _ => false,
        }
    }
}
