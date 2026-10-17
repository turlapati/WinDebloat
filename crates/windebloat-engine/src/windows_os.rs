use crate::backend::{BackendError, OsBackend};
use crate::gating::{OsEnvironment, EEA_REGION_CODES};
use crate::journal::{AppxInstallState, TargetState};
use crate::target::{TargetScope, UserProfileInfo};
use std::path::Path;
use std::sync::Mutex;
use windebloat_schema::{
    denylist::check_action_against_denylist, Action, AppxScope, RegValueType, ServiceStartType,
};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

/// Global mutex serializing all DISM sessions in this process (§4.2).
static DISM_GLOBAL_MUTEX: Mutex<()> = Mutex::new(());

/// Native Windows OS adapter using `winreg`, `RegLoadKeyW`, `OpenSCManagerW`, `ITaskService` COM,
/// `Windows.Management.Deployment.PackageManager`, and `dismapi.dll` (§4.2).
#[derive(Debug, Default)]
pub struct WindowsOsBackend;

impl WindowsOsBackend {
    pub fn new() -> Self {
        Self
    }
}

/// RAII guard for an offline registry hive mounted via `RegLoadKeyW` under `HKEY_USERS`.
/// Ensures `RegUnLoadKeyW` is always called on `Drop` even if a thread panics (§4.2).
pub struct OfflineHiveGuard {
    subkey_name: String,
    mounted: bool,
}

impl OfflineHiveGuard {
    pub fn mount(subkey_name: &str, ntuser_dat_path: &Path) -> Result<Self, BackendError> {
        enable_backup_restore_privileges()?;
        unsafe {
            use windows::core::PCWSTR;
            use windows::Win32::System::Registry::{RegLoadKeyW, HKEY_USERS};

            let subkey_w: Vec<u16> = format!("{}\0", subkey_name).encode_utf16().collect();
            let file_w: Vec<u16> = format!("{}\0", ntuser_dat_path.display())
                .encode_utf16()
                .collect();

            let status = RegLoadKeyW(
                HKEY_USERS,
                PCWSTR(subkey_w.as_ptr()),
                PCWSTR(file_w.as_ptr()),
            );
            if status.is_err() {
                return Err(BackendError::OsError {
                    target: ntuser_dat_path.display().to_string(),
                    message: format!("RegLoadKeyW failed with status {:?}", status),
                });
            }
        }
        Ok(Self {
            subkey_name: subkey_name.to_string(),
            mounted: true,
        })
    }
}

impl Drop for OfflineHiveGuard {
    fn drop(&mut self) {
        if self.mounted {
            unsafe {
                use windows::core::PCWSTR;
                use windows::Win32::System::Registry::{RegUnLoadKeyW, HKEY_USERS};

                let subkey_w: Vec<u16> = format!("{}\0", self.subkey_name).encode_utf16().collect();
                let _ = RegUnLoadKeyW(HKEY_USERS, PCWSTR(subkey_w.as_ptr()));
            }
            self.mounted = false;
        }
    }
}

fn enable_backup_restore_privileges() -> Result<(), BackendError> {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
        use windows::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| BackendError::OsError {
            target: "ProcessToken".to_string(),
            message: format!("OpenProcessToken failed: {}", e),
        })?;

        for priv_name in ["SeBackupPrivilege\0", "SeRestorePrivilege\0"] {
            let name_w: Vec<u16> = priv_name.encode_utf16().collect();
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(None, PCWSTR(name_w.as_ptr()), &mut luid).is_ok() {
                let tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                let _ = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
            }
        }
        let _ = CloseHandle(token);
        Ok(())
    }
}

fn parse_resolved_registry_target(
    resolved_target: &str,
) -> Result<(winreg::HKEY, String, String), BackendError> {
    let parts: Vec<&str> = resolved_target.split('\\').collect();
    if parts.len() < 3 {
        return Err(BackendError::InvalidTarget(resolved_target.to_string()));
    }
    let root_hive = match parts[0] {
        "HKLM" => HKEY_LOCAL_MACHINE,
        "HKU" => HKEY_USERS,
        _ => return Err(BackendError::InvalidTarget(resolved_target.to_string())),
    };
    let value_part = *parts.last().unwrap();
    let value_name = if value_part == "@Default" {
        String::new()
    } else {
        value_part.to_string()
    };
    let subkey = parts[1..parts.len() - 1].join("\\");
    Ok((root_hive, subkey, value_name))
}

fn reg_value_to_json(val: &RegValue) -> serde_json::Value {
    match val.vtype {
        REG_DWORD => {
            if val.bytes.len() >= 4 {
                let n = u32::from_le_bytes([val.bytes[0], val.bytes[1], val.bytes[2], val.bytes[3]]);
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::Null
            }
        }
        REG_QWORD => {
            if val.bytes.len() >= 8 {
                let n = u64::from_le_bytes([
                    val.bytes[0],
                    val.bytes[1],
                    val.bytes[2],
                    val.bytes[3],
                    val.bytes[4],
                    val.bytes[5],
                    val.bytes[6],
                    val.bytes[7],
                ]);
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::Null
            }
        }
        REG_SZ | REG_EXPAND_SZ => {
            let u16_slice: Vec<u16> = val
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&ch| ch != 0)
                .collect();
            serde_json::Value::String(String::from_utf16_lossy(&u16_slice))
        }
        _ => serde_json::Value::String(hex::encode(&val.bytes)),
    }
}

fn write_json_to_reg_key(
    key: &RegKey,
    value_name: &str,
    vtype: RegValueType,
    val: &serde_json::Value,
) -> std::io::Result<()> {
    match vtype {
        RegValueType::DELETE => match key.delete_value(value_name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
        RegValueType::DWORD => {
            let n = val.as_u64().unwrap_or(0) as u32;
            key.set_value(value_name, &n)
        }
        RegValueType::QWORD => {
            let n = val.as_u64().unwrap_or(0);
            key.set_value(value_name, &n)
        }
        RegValueType::SZ | RegValueType::EXPAND_SZ => {
            let s = val.as_str().unwrap_or("");
            key.set_value(value_name, &s)
        }
        RegValueType::MULTI_SZ => {
            let list: Vec<String> = val
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            key.set_value(value_name, &list)
        }
        RegValueType::BINARY => {
            let bytes = val
                .as_str()
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_default();
            let raw = RegValue {
                bytes,
                vtype: REG_BINARY,
            };
            key.set_raw_value(value_name, &raw)
        }
    }
}

impl OsBackend for WindowsOsBackend {
    fn environment(&self) -> OsEnvironment {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (build_number, edition_id) = hklm
            .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
            .map(|cv| {
                let b_str: String = cv.get_value("CurrentBuildNumber").unwrap_or_default();
                let b = b_str.trim().parse::<u32>().unwrap_or(22631);
                let ed: String = cv
                    .get_value("EditionID")
                    .unwrap_or_else(|_| "Professional".to_string());
                (b, ed)
            })
            .unwrap_or((22631, "Professional".to_string()));

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let region_code = hkcu
            .open_subkey_with_flags(r"Control Panel\International\Geo", KEY_READ)
            .and_then(|geo| geo.get_value::<String, _>("Name"))
            .unwrap_or_else(|_| "US".to_string())
            .to_ascii_uppercase();

        let is_eea = EEA_REGION_CODES.contains(&region_code.as_str());

        OsEnvironment {
            build_number,
            edition_id,
            region_code,
            is_eea,
        }
    }

    fn check_pending_reboot(&self) -> Option<String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        if hklm
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                KEY_READ,
            )
            .is_ok()
        {
            return Some(
                "Windows Component Based Servicing requires a restart to finish installing updates"
                    .to_string(),
            );
        }

        if hklm
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                KEY_READ,
            )
            .is_ok()
        {
            return Some(
                "Windows Update requires a restart to finish installing updates".to_string(),
            );
        }

        // Only treat PendingFileRenameOperations as a servicing blocker if CBS PackagesPending is also present
        if hklm
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
                KEY_READ,
            )
            .is_ok()
        {
            if let Ok(sm) = hklm.open_subkey_with_flags(
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                KEY_READ,
            ) {
                if let Ok(ops) = sm.get_raw_value("PendingFileRenameOperations") {
                    if !ops.bytes.is_empty() && ops.bytes.iter().any(|&b| b != 0) {
                        return Some(
                            "Windows servicing has pending file rename operations requiring a restart"
                                .to_string(),
                        );
                    }
                }
            }
        }

        None
    }

    fn list_user_profiles(&self, scope: &TargetScope) -> Result<Vec<UserProfileInfo>, BackendError> {
        match scope {
            TargetScope::Sid(sid) => {
                let hku = RegKey::predef(HKEY_USERS);
                let is_loaded = hku.open_subkey_with_flags(sid, KEY_READ).is_ok();
                Ok(vec![UserProfileInfo {
                    sid: sid.clone(),
                    profile_image_path: String::new(),
                    is_loaded,
                }])
            }
            TargetScope::Default => Ok(vec![UserProfileInfo {
                sid: "DEFAULT".to_string(),
                profile_image_path: r"C:\Users\Default".to_string(),
                is_loaded: false,
            }]),
            TargetScope::AllProfiles => {
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                let hku = RegKey::predef(HKEY_USERS);
                let plist = hklm
                    .open_subkey_with_flags(
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                        KEY_READ,
                    )
                    .map_err(|e| BackendError::OsError {
                        target: "ProfileList".to_string(),
                        message: e.to_string(),
                    })?;

                let mut profiles = Vec::new();
                for sid in plist.enum_keys().flatten() {
                    if !sid.starts_with("S-1-5-21-") {
                        continue;
                    }
                    if let Ok(sub) = plist.open_subkey_with_flags(&sid, KEY_READ) {
                        let path: String = sub.get_value("ProfileImagePath").unwrap_or_default();
                        let is_loaded = hku.open_subkey_with_flags(&sid, KEY_READ).is_ok();
                        profiles.push(UserProfileInfo {
                            sid,
                            profile_image_path: path,
                            is_loaded,
                        });
                    }
                }
                Ok(profiles)
            }
        }
    }

    fn probe_target(
        &self,
        action: &Action,
        resolved_target: &str,
    ) -> Result<TargetState, BackendError> {
        match action {
            Action::RegistrySet { .. } => {
                let (root, subkey, value_name) = parse_resolved_registry_target(resolved_target)?;
                let hive = RegKey::predef(root);
                let _guard = if resolved_target.starts_with("HKU\\WINDEBLOAT_DEFAULT\\") {
                    OfflineHiveGuard::mount(
                        "WINDEBLOAT_DEFAULT",
                        Path::new(r"C:\Users\Default\NTUSER.DAT"),
                    )
                    .ok()
                } else {
                    None
                };
                match hive.open_subkey_with_flags(&subkey, KEY_READ) {
                    Ok(k) => match k.get_raw_value(&value_name) {
                        Ok(raw) => Ok(TargetState::RegistryValue(reg_value_to_json(&raw))),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            Ok(TargetState::Absent)
                        }
                        Err(e) => Err(BackendError::OsError {
                            target: resolved_target.to_string(),
                            message: e.to_string(),
                        }),
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TargetState::Absent),
                    Err(e) => Err(BackendError::OsError {
                        target: resolved_target.to_string(),
                        message: e.to_string(),
                    }),
                }
            }
            Action::AppxRemove {
                package_family_name,
                ..
            } => probe_appx_tristate(package_family_name),
            Action::AppxProvisionedRemove {
                package_family_name,
                ..
            } => {
                let st = probe_appx_tristate(package_family_name)?;
                let present = matches!(
                    st,
                    TargetState::AppxTristate(AppxInstallState::Installed)
                        | TargetState::AppxTristate(AppxInstallState::ProvisionedOnly)
                );
                Ok(TargetState::ProvisionedPresent(present))
            }
            Action::ServiceStartup { service_name, .. } => probe_service_startup(service_name),
            Action::ScheduledTaskDisable { task_path, .. } => probe_scheduled_task(task_path),
            Action::CapabilityRemove {
                capability_name, ..
            } => probe_dism_capability(capability_name),
            Action::OptionalFeature { feature_name, .. } => probe_dism_feature(feature_name),
        }
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

        match action {
            Action::RegistrySet {
                value_type, value, ..
            } => {
                let (root, subkey, value_name) = parse_resolved_registry_target(resolved_target)?;
                let hive = RegKey::predef(root);
                let _guard = if resolved_target.starts_with("HKU\\WINDEBLOAT_DEFAULT\\") {
                    Some(OfflineHiveGuard::mount(
                        "WINDEBLOAT_DEFAULT",
                        Path::new(r"C:\Users\Default\NTUSER.DAT"),
                    )?)
                } else {
                    None
                };

                let normal_res = hive
                    .create_subkey(&subkey)
                    .and_then(|(k, _)| write_json_to_reg_key(&k, &value_name, *value_type, value));

                if let Err(e) = normal_res {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        write_reg_value_via_restore_hive(
                            root,
                            &subkey,
                            &value_name,
                            *value_type,
                            Some(value),
                            resolved_target,
                        )?;
                    } else {
                        return Err(BackendError::OsError {
                            target: resolved_target.to_string(),
                            message: e.to_string(),
                        });
                    }
                }

                if matches!(value_type, RegValueType::DELETE) {
                    Ok(TargetState::Absent)
                } else {
                    Ok(TargetState::RegistryValue(value.clone()))
                }
            }
            Action::AppxRemove {
                scope,
                package_family_name,
                ..
            } => remove_appx_package(package_family_name, *scope),
            Action::AppxProvisionedRemove {
                package_family_name,
                ..
            } => {
                let _ = remove_appx_package(package_family_name, AppxScope::AllUsersAndProvisioned)?;
                Ok(TargetState::ProvisionedPresent(false))
            }
            Action::ServiceStartup {
                service_name,
                start_type,
                ..
            } => set_service_startup(service_name, *start_type),
            Action::ScheduledTaskDisable { task_path, .. } => {
                set_scheduled_task_enabled(task_path, false)?;
                Ok(TargetState::TaskDisabled(true))
            }
            Action::CapabilityRemove {
                capability_name, ..
            } => set_dism_capability(capability_name, false),
            Action::OptionalFeature {
                feature_name,
                feature_enabled,
                ..
            } => set_dism_feature(feature_name, *feature_enabled),
        }
    }

    fn restore_target(
        &mut self,
        action: &Action,
        resolved_target: &str,
        prior: &TargetState,
    ) -> Result<(), BackendError> {
        match (action, prior) {
            (Action::RegistrySet { value_type, .. }, TargetState::Absent) => {
                let (root, subkey, value_name) = parse_resolved_registry_target(resolved_target)?;
                let hive = RegKey::predef(root);
                match hive.open_subkey_with_flags(&subkey, KEY_WRITE) {
                    Ok(k) => {
                        if let Err(e) = k.delete_value(&value_name) {
                            if e.kind() == std::io::ErrorKind::PermissionDenied {
                                write_reg_value_via_restore_hive(
                                    root,
                                    &subkey,
                                    &value_name,
                                    RegValueType::DELETE,
                                    None,
                                    resolved_target,
                                )?;
                            }
                        }
                        if value_name.is_empty() {
                            let _ = hive.delete_subkey(&subkey);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        write_reg_value_via_restore_hive(
                            root,
                            &subkey,
                            &value_name,
                            RegValueType::DELETE,
                            None,
                            resolved_target,
                        )?;
                    }
                    _ => {}
                }
                let _ = value_type;
                Ok(())
            }
            (Action::RegistrySet { value_type, .. }, TargetState::RegistryValue(val)) => {
                let (root, subkey, value_name) = parse_resolved_registry_target(resolved_target)?;
                let hive = RegKey::predef(root);
                let normal_res = hive
                    .create_subkey(&subkey)
                    .and_then(|(k, _)| write_json_to_reg_key(&k, &value_name, *value_type, val));
                if let Err(e) = normal_res {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        write_reg_value_via_restore_hive(
                            root,
                            &subkey,
                            &value_name,
                            *value_type,
                            Some(val),
                            resolved_target,
                        )?;
                        return Ok(());
                    }
                    return Err(BackendError::OsError {
                        target: resolved_target.to_string(),
                        message: e.to_string(),
                    });
                }
                Ok(())
            }
            (Action::ServiceStartup { service_name, .. }, TargetState::ServiceStart(prior_st)) => {
                let parsed = match prior_st.as_str() {
                    "disabled" => ServiceStartType::Disabled,
                    "manual" => ServiceStartType::Manual,
                    "delayed_auto" => ServiceStartType::DelayedAuto,
                    _ => ServiceStartType::Automatic,
                };
                let _ = set_service_startup(service_name, parsed)?;
                Ok(())
            }
            (
                Action::ScheduledTaskDisable { task_path, .. },
                TargetState::TaskDisabled(was_disabled),
            ) => set_scheduled_task_enabled(task_path, !*was_disabled),
            (
                Action::CapabilityRemove {
                    capability_name, ..
                },
                TargetState::CapabilityPresent(true),
            ) => {
                let _ = set_dism_capability(capability_name, true)?;
                Ok(())
            }
            (
                Action::OptionalFeature { feature_name, .. },
                TargetState::FeatureEnabled(was_enabled),
            ) => {
                let _ = set_dism_feature(feature_name, *was_enabled)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn is_current_process_elevated() -> bool {
    static ELEVATED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ELEVATED.get_or_init(|| unsafe {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            len,
            &mut len,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0;
        let _ = CloseHandle(token);
        ok
    })
}

/// Fallback registry writer using `RegSaveKeyW` + `RegRestoreKeyW(REG_FORCE_RESTORE)` with
/// `SeBackupPrivilege` / `SeRestorePrivilege`.
///
/// On Windows 11, Microsoft's kernel registry filter driver `UCPD.sys` intercepts `RegNtPreSetValueKey`
/// and `RegNtPreDeleteValueKey` on specific keys (such as `HKLM\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests`
/// and `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa`) and returns
/// `ERROR_ACCESS_DENIED` (os error 5) even to elevated Administrator processes. Because `UCPD.sys` does
/// not hook `RegNtPreRestoreKey`, staging the updated key in a temporary subkey, saving it via
/// `RegSaveKeyW`, and restoring it over the target key with `RegRestoreKeyW(..., REG_FORCE_RESTORE)`
/// succeeds cleanly.
fn write_reg_value_via_restore_hive(
    root: winreg::HKEY,
    subkey: &str,
    value_name: &str,
    vtype: RegValueType,
    val: Option<&serde_json::Value>,
    resolved_target: &str,
) -> Result<(), BackendError> {
    enable_backup_restore_privileges()?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let staging_subkey = format!("SOFTWARE\\WinDebloat_Stage_{}", uuid::Uuid::new_v4().simple());
    let _ = hklm.delete_subkey_all(&staging_subkey);

    let (staging_key, _) = hklm
        .create_subkey(&staging_subkey)
        .map_err(|e| BackendError::OsError {
            target: resolved_target.to_string(),
            message: format!("Failed to create staging registry key: {}", e),
        })?;

    // Copy existing values and subkeys from the target key (if it already exists) into staging_key
    let target_hive = RegKey::predef(root);
    if let Ok(existing_key) = target_hive.open_subkey_with_flags(subkey, KEY_READ) {
        unsafe {
            use windows::core::PCWSTR;
            use windows::Win32::System::Registry::{RegCopyTreeW, HKEY};
            let _ = RegCopyTreeW(
                HKEY(existing_key.raw_handle() as _),
                PCWSTR::null(),
                HKEY(staging_key.raw_handle() as _),
            );
        }
        for (vname, vraw) in existing_key.enum_values().flatten() {
            let _ = staging_key.set_raw_value(&vname, &vraw);
        }
    }

    // Apply the requested mutation on the staging key (which is not watched by UCPD.sys)
    let mutate_res = match (vtype, val) {
        (RegValueType::DELETE, _) | (_, None) => match staging_key.delete_value(value_name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
        (_, Some(v)) => write_json_to_reg_key(&staging_key, value_name, vtype, v),
    };
    if let Err(e) = mutate_res {
        drop(staging_key);
        let _ = hklm.delete_subkey_all(&staging_subkey);
        return Err(BackendError::OsError {
            target: resolved_target.to_string(),
            message: format!("Staging key write failed: {}", e),
        });
    }

    let temp_file = std::env::temp_dir().join(format!(
        "windebloat-reg-{}.hiv",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = std::fs::remove_file(&temp_file);
    let temp_file_w: Vec<u16> = format!("{}\0", temp_file.display()).encode_utf16().collect();

    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegRestoreKeyW, RegSaveKeyW, HKEY, KEY_READ, KEY_WRITE,
            REG_FORCE_RESTORE, REG_OPTION_BACKUP_RESTORE,
        };

        let save_status = RegSaveKeyW(
            HKEY(staging_key.raw_handle() as _),
            PCWSTR(temp_file_w.as_ptr()),
            None,
        );
        drop(staging_key);
        let _ = hklm.delete_subkey_all(&staging_subkey);

        if save_status.is_err() {
            let _ = std::fs::remove_file(&temp_file);
            return Err(BackendError::OsError {
                target: resolved_target.to_string(),
                message: format!("RegSaveKeyW failed: {:?}", save_status),
            });
        }

        let subkey_w: Vec<u16> = format!("{}\0", subkey).encode_utf16().collect();
        let mut target_hkey = HKEY::default();
        let open_status = RegCreateKeyExW(
            HKEY(root as _),
            PCWSTR(subkey_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_BACKUP_RESTORE,
            KEY_WRITE | KEY_READ,
            None,
            &mut target_hkey,
            None,
        );
        if open_status.is_err() {
            let _ = std::fs::remove_file(&temp_file);
            return Err(BackendError::OsError {
                target: resolved_target.to_string(),
                message: format!(
                    "RegCreateKeyExW(REG_OPTION_BACKUP_RESTORE) failed: {:?}",
                    open_status
                ),
            });
        }

        let restore_status = RegRestoreKeyW(
            target_hkey,
            PCWSTR(temp_file_w.as_ptr()),
            REG_FORCE_RESTORE,
        );
        let _ = RegCloseKey(target_hkey);
        let _ = std::fs::remove_file(&temp_file);

        if restore_status.is_err() {
            return Err(BackendError::OsError {
                target: resolved_target.to_string(),
                message: format!("RegRestoreKeyW(REG_FORCE_RESTORE) failed: {:?}", restore_status),
            });
        }
    }

    Ok(())
}

fn probe_appx_tristate(package_family_name: &str) -> Result<TargetState, BackendError> {
    use windows::core::HSTRING;
    use windows::Management::Deployment::PackageManager;

    let pm = PackageManager::new().map_err(|e| BackendError::OsError {
        target: package_family_name.to_string(),
        message: format!("PackageManager::new failed: {}", e),
    })?;

    let pfn_h = HSTRING::from(package_family_name);

    if is_current_process_elevated() {
        let empty_sid = HSTRING::from("");
        if let Ok(pkgs) = pm.FindPackagesByUserSecurityIdPackageFamilyName(&empty_sid, &pfn_h) {
            if pkgs.First().and_then(|it| it.HasCurrent()).unwrap_or(false) {
                return Ok(TargetState::AppxTristate(AppxInstallState::Installed));
            }
        }
    } else if let Ok(pkgs) = pm.FindPackagesByPackageFamilyName(&pfn_h) {
        if pkgs.First().and_then(|it| it.HasCurrent()).unwrap_or(false) {
            return Ok(TargetState::AppxTristate(AppxInstallState::Installed));
        }
    }

    // Check provisioned packages list under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(store) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications",
        KEY_READ,
    ) {
        let prefix = package_family_name
            .split('_')
            .next()
            .unwrap_or(package_family_name);
        for key_name in store.enum_keys().flatten() {
            if key_name.starts_with(prefix) {
                return Ok(TargetState::AppxTristate(AppxInstallState::ProvisionedOnly));
            }
        }
    }

    Ok(TargetState::AppxTristate(AppxInstallState::Absent))
}

fn remove_appx_package(
    package_family_name: &str,
    scope: AppxScope,
) -> Result<TargetState, BackendError> {
    use windows::core::HSTRING;
    use windows::Management::Deployment::{PackageManager, RemovalOptions};

    let pm = PackageManager::new().map_err(|e| BackendError::OsError {
        target: package_family_name.to_string(),
        message: format!("PackageManager::new failed: {}", e),
    })?;

    let empty_sid = HSTRING::from("");
    let pfn_h = HSTRING::from(package_family_name);

    if let Ok(pkgs) = pm.FindPackagesByUserSecurityIdPackageFamilyName(&empty_sid, &pfn_h) {
        if let Ok(iter) = pkgs.First() {
            while iter.HasCurrent().unwrap_or(false) {
                if let Ok(pkg) = iter.Current() {
                    if let Ok(id) = pkg.Id() {
                        if let Ok(full_name) = id.FullName() {
                            let op = match scope {
                                AppxScope::CurrentUser => pm
                                    .RemovePackageWithOptionsAsync(
                                        &full_name,
                                        RemovalOptions::None,
                                    ),
                                AppxScope::AllUsers | AppxScope::AllUsersAndProvisioned => pm
                                    .RemovePackageWithOptionsAsync(
                                        &full_name,
                                        RemovalOptions::RemoveForAllUsers,
                                    ),
                            };
                            if let Ok(async_op) = op {
                                let _ = async_op.get();
                            }
                        }
                    }
                }
                let _ = iter.MoveNext();
            }
        }
    }

    if matches!(scope, AppxScope::AllUsersAndProvisioned) {
        if let Ok(deprov) = pm.DeprovisionPackageForAllUsersAsync(&pfn_h) {
            let _ = deprov.get();
        }
    }

    Ok(TargetState::AppxTristate(AppxInstallState::Absent))
}

fn probe_service_startup(service_name: &str) -> Result<TargetState, BackendError> {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
            QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_AUTO_START, SERVICE_DEMAND_START,
            SERVICE_DISABLED, SERVICE_QUERY_CONFIG,
        };

        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).map_err(|e| {
            BackendError::OsError {
                target: service_name.to_string(),
                message: format!("OpenSCManagerW failed: {}", e),
            }
        })?;

        let svc_w: Vec<u16> = format!("{}\0", service_name).encode_utf16().collect();
        let svc = match OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), SERVICE_QUERY_CONFIG) {
            Ok(s) => s,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return Ok(TargetState::NotApplicable);
            }
        };

        let mut bytes_needed = 0u32;
        let _ = QueryServiceConfigW(svc, None, 0, &mut bytes_needed);
        let mut buf = vec![0u8; (bytes_needed as usize).max(512)];
        let cfg_ptr = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;

        let res = QueryServiceConfigW(svc, Some(cfg_ptr), buf.len() as u32, &mut bytes_needed);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);

        res.map_err(|e| BackendError::OsError {
            target: service_name.to_string(),
            message: format!("QueryServiceConfigW failed: {}", e),
        })?;

        let start_type = (*cfg_ptr).dwStartType;
        let label = match start_type {
            SERVICE_DISABLED => "disabled",
            SERVICE_DEMAND_START => "manual",
            SERVICE_AUTO_START => "automatic",
            _ => "automatic",
        };
        Ok(TargetState::ServiceStart(label.to_string()))
    }
}

fn set_service_startup(
    service_name: &str,
    start_type: ServiceStartType,
) -> Result<TargetState, BackendError> {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::{
            ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW, OpenServiceW,
            ENUM_SERVICE_TYPE, SC_MANAGER_CONNECT, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
            SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE,
        };

        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).map_err(|e| {
            BackendError::OsError {
                target: service_name.to_string(),
                message: format!("OpenSCManagerW failed: {}", e),
            }
        })?;

        let svc_w: Vec<u16> = format!("{}\0", service_name).encode_utf16().collect();
        let svc = OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), SERVICE_CHANGE_CONFIG).map_err(|e| {
            let _ = CloseServiceHandle(scm);
            BackendError::OsError {
                target: service_name.to_string(),
                message: format!("OpenServiceW(SERVICE_CHANGE_CONFIG) failed: {}", e),
            }
        })?;

        let dw_start = match start_type {
            ServiceStartType::Disabled => SERVICE_DISABLED,
            ServiceStartType::Manual => SERVICE_DEMAND_START,
            ServiceStartType::Automatic | ServiceStartType::DelayedAuto => SERVICE_AUTO_START,
        };

        let res = ChangeServiceConfigW(
            svc,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            dw_start,
            SERVICE_ERROR_NORMAL,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);

        res.map_err(|e| BackendError::OsError {
            target: service_name.to_string(),
            message: format!("ChangeServiceConfigW failed: {}", e),
        })?;

        let label = match start_type {
            ServiceStartType::Disabled => "disabled",
            ServiceStartType::Manual => "manual",
            ServiceStartType::Automatic => "automatic",
            ServiceStartType::DelayedAuto => "delayed_auto",
        };
        Ok(TargetState::ServiceStart(label.to_string()))
    }
}

unsafe fn resolve_registered_task(
    folder: &windows::Win32::System::TaskScheduler::ITaskFolder,
    task_name: &str,
) -> windows::core::Result<windows::Win32::System::TaskScheduler::IRegisteredTask> {
    use windows::core::BSTR;
    match folder.GetTask(&BSTR::from(task_name)) {
        Ok(task) => Ok(task),
        Err(first_err) => {
            // On Windows 11 24H2/25H2, Microsoft renamed "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
            // to "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp".
            if !task_name.ends_with(" Exp") {
                let exp_name = format!("{} Exp", task_name);
                if let Ok(task) = folder.GetTask(&BSTR::from(exp_name.as_str())) {
                    return Ok(task);
                }
            }
            Err(first_err)
        }
    }
}

fn probe_scheduled_task(task_path: &str) -> Result<TargetState, BackendError> {
    unsafe {
        use windows::core::{BSTR, VARIANT};
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
        };
        use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};

        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(|e| {
                BackendError::OsError {
                    target: task_path.to_string(),
                    message: format!("CoCreateInstance(TaskScheduler) failed: {}", e),
                }
            })?;

        service
            .Connect(
                &VARIANT::default(),
                &VARIANT::default(),
                &VARIANT::default(),
                &VARIANT::default(),
            )
            .map_err(|e| BackendError::OsError {
                target: task_path.to_string(),
                message: format!("ITaskService::Connect failed: {}", e),
            })?;

        let (folder_path, task_name) = match task_path.rfind('\\') {
            Some(0) | None => ("\\", task_path.trim_start_matches('\\')),
            Some(idx) => (&task_path[..idx], &task_path[idx + 1..]),
        };

        let Ok(folder) = service.GetFolder(&BSTR::from(folder_path)) else {
            return Ok(TargetState::NotApplicable);
        };
        let Ok(task) = resolve_registered_task(&folder, task_name) else {
            return Ok(TargetState::NotApplicable);
        };
        let enabled = task
            .Enabled()
            .map(|vb| vb.as_bool())
            .unwrap_or(true);
        Ok(TargetState::TaskDisabled(!enabled))
    }
}

fn set_scheduled_task_enabled(task_path: &str, enabled: bool) -> Result<(), BackendError> {
    unsafe {
        use windows::core::{BSTR, VARIANT};
        use windows::Win32::Foundation::VARIANT_BOOL;
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
        };
        use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};

        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(|e| {
                BackendError::OsError {
                    target: task_path.to_string(),
                    message: format!("CoCreateInstance(TaskScheduler) failed: {}", e),
                }
            })?;

        service
            .Connect(
                &VARIANT::default(),
                &VARIANT::default(),
                &VARIANT::default(),
                &VARIANT::default(),
            )
            .map_err(|e| BackendError::OsError {
                target: task_path.to_string(),
                message: format!("ITaskService::Connect failed: {}", e),
            })?;

        let (folder_path, task_name) = match task_path.rfind('\\') {
            Some(0) | None => ("\\", task_path.trim_start_matches('\\')),
            Some(idx) => (&task_path[..idx], &task_path[idx + 1..]),
        };

        let folder = match service.GetFolder(&BSTR::from(folder_path)) {
            Ok(f) => f,
            Err(_) if !enabled => return Ok(()),
            Err(e) => {
                return Err(BackendError::OsError {
                    target: task_path.to_string(),
                    message: format!("GetFolder failed: {}", e),
                });
            }
        };
        let task = match resolve_registered_task(&folder, task_name) {
            Ok(t) => t,
            Err(_) if !enabled => return Ok(()),
            Err(e) => {
                return Err(BackendError::OsError {
                    target: task_path.to_string(),
                    message: format!("GetTask failed: {}", e),
                });
            }
        };

        task.SetEnabled(VARIANT_BOOL::from(enabled))
            .map_err(|e| BackendError::OsError {
                target: task_path.to_string(),
                message: format!("IRegisteredTask::SetEnabled failed: {}", e),
            })?;
        Ok(())
    }
}

// --- DISM API (`dismapi.dll`) dynamic FFI adapter behind `DISM_GLOBAL_MUTEX` (§4.2) ---

type DismSession = u32;
const DISM_ONLINE_IMAGE: &str = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}\0";
const DISM_INSTALL_STATE_INSTALLED: i32 = 4;

#[repr(C)]
struct DismCapabilityInfo {
    name: *const u16,
    state: i32,
    display_name: *const u16,
    description: *const u16,
    download_size: u32,
    install_size: u32,
}

#[repr(C)]
struct DismFeatureInfo {
    feature_name: *const u16,
    feature_state: i32,
    display_name: *const u16,
    description: *const u16,
    restart_required: i32,
    custom_properties: *const core::ffi::c_void,
    custom_property_count: u32,
}

fn with_dism_session<F, R>(target: &str, f: F) -> Result<R, BackendError>
where
    F: FnOnce(windows::Win32::Foundation::HMODULE, DismSession) -> Result<R, BackendError>,
{
    let _guard = DISM_GLOBAL_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let dll_w: Vec<u16> = "dismapi.dll\0".encode_utf16().collect();
        let hmod = LoadLibraryW(PCWSTR(dll_w.as_ptr())).map_err(|e| BackendError::OsError {
            target: target.to_string(),
            message: format!("LoadLibraryW(dismapi.dll) failed: {}", e),
        })?;

        type FnInit = unsafe extern "system" fn(i32, *const u16, *const u16) -> i32;
        type FnOpen =
            unsafe extern "system" fn(*const u16, *const u16, *const u16, *mut DismSession) -> i32;
        type FnClose = unsafe extern "system" fn(DismSession) -> i32;
        type FnShutdown = unsafe extern "system" fn() -> i32;

        let init: FnInit = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismInitialize\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: target.to_string(),
                    message: "Missing DismInitialize".to_string(),
                }
            })?,
        );
        let open: FnOpen = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismOpenSession\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: target.to_string(),
                    message: "Missing DismOpenSession".to_string(),
                }
            })?,
        );
        let close: FnClose = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismCloseSession\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: target.to_string(),
                    message: "Missing DismCloseSession".to_string(),
                }
            })?,
        );
        let shutdown: FnShutdown = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismShutdown\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: target.to_string(),
                    message: "Missing DismShutdown".to_string(),
                }
            })?,
        );

        let hr_init = init(0, std::ptr::null(), std::ptr::null());
        if hr_init < 0 {
            return Err(BackendError::OsError {
                target: target.to_string(),
                message: format!("DismInitialize failed (HRESULT 0x{:08X})", hr_init as u32),
            });
        }

        let online_w: Vec<u16> = DISM_ONLINE_IMAGE.encode_utf16().collect();
        let mut session: DismSession = 0;
        let hr_open = open(
            online_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            &mut session,
        );
        if hr_open < 0 {
            let _ = shutdown();
            return Err(BackendError::OsError {
                target: target.to_string(),
                message: format!("DismOpenSession failed (HRESULT 0x{:08X})", hr_open as u32),
            });
        }

        let result = f(hmod, session);
        let _ = close(session);
        let _ = shutdown();
        result
    }
}

fn probe_capability_from_cbs_registry(capability_name: &str) -> TargetState {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // Check Component Based Servicing\Packages for matching capability package state (CurrentState == 112 / 0x70 is Installed)
    if let Ok(pkgs) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages",
        KEY_READ,
    ) {
        let prefix = capability_name.split('~').next().unwrap_or(capability_name);
        for key_name in pkgs.enum_keys().flatten() {
            if key_name.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()) {
                if let Ok(sub) = pkgs.open_subkey_with_flags(&key_name, KEY_READ) {
                    let state: u32 = sub.get_value("CurrentState").unwrap_or(0);
                    if state == 112 || state == 0x70 {
                        return TargetState::CapabilityPresent(true);
                    }
                }
            }
        }
    }
    TargetState::CapabilityPresent(false)
}

fn probe_feature_from_cbs_registry(feature_name: &str) -> TargetState {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // Check Windows AI Recall policy or CBS FeatureIndex if unelevated
    if feature_name.eq_ignore_ascii_case("Recall") {
        if let Ok(ai_key) = hklm.open_subkey_with_flags(
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
            KEY_READ,
        ) {
            let disabled: u32 = ai_key.get_value("DisableAIDataAnalysis").unwrap_or(0);
            if disabled == 1 {
                return TargetState::FeatureEnabled(false);
            }
        }
    }
    if let Ok(feat_idx) = hklm.open_subkey_with_flags(
        format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\FeatureIndex\{}",
            feature_name
        ),
        KEY_READ,
    ) {
        let has_installed = feat_idx.enum_values().flatten().next().is_some();
        return TargetState::FeatureEnabled(has_installed);
    }
    TargetState::FeatureEnabled(true)
}

fn probe_dism_capability(capability_name: &str) -> Result<TargetState, BackendError> {
    if !is_current_process_elevated() {
        return Ok(probe_capability_from_cbs_registry(capability_name));
    }
    let res = with_dism_session(capability_name, |hmod, session| unsafe {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::GetProcAddress;

        type FnGetCap = unsafe extern "system" fn(
            DismSession,
            *const u16,
            *mut *mut DismCapabilityInfo,
        ) -> i32;
        type FnDelete = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

        let get_cap: FnGetCap = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismGetCapabilityInfo\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: capability_name.to_string(),
                    message: "Missing DismGetCapabilityInfo".to_string(),
                }
            })?,
        );
        let del_buf: FnDelete = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismDelete\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: capability_name.to_string(),
                    message: "Missing DismDelete".to_string(),
                }
            })?,
        );

        let name_w: Vec<u16> = format!("{}\0", capability_name).encode_utf16().collect();
        let mut info_ptr: *mut DismCapabilityInfo = std::ptr::null_mut();
        let hr = get_cap(session, name_w.as_ptr(), &mut info_ptr);
        if hr < 0 || info_ptr.is_null() {
            return Ok(TargetState::CapabilityPresent(false));
        }
        let state = (*info_ptr).state;
        let _ = del_buf(info_ptr as *mut _);
        Ok(TargetState::CapabilityPresent(
            state == DISM_INSTALL_STATE_INSTALLED,
        ))
    });

    match res {
        Ok(st) => Ok(st),
        // When probing from the unelevated UI (0x800702E4 = ERROR_ELEVATION_REQUIRED), fall back to read-only CBS registry probe
        Err(_) => Ok(probe_capability_from_cbs_registry(capability_name)),
    }
}

fn set_dism_capability(capability_name: &str, install: bool) -> Result<TargetState, BackendError> {
    with_dism_session(capability_name, |hmod, session| unsafe {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::GetProcAddress;

        let name_w: Vec<u16> = format!("{}\0", capability_name).encode_utf16().collect();
        let hr = if install {
            type FnAddCap = unsafe extern "system" fn(
                DismSession,
                *const u16,
                i32,
                *const *const u16,
                u32,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
            ) -> i32;
            let add_cap: FnAddCap = std::mem::transmute(
                GetProcAddress(hmod, PCSTR(b"DismAddCapability\0".as_ptr())).ok_or_else(|| {
                    BackendError::OsError {
                        target: capability_name.to_string(),
                        message: "Missing DismAddCapability".to_string(),
                    }
                })?,
            );
            add_cap(
                session,
                name_w.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } else {
            type FnRemCap = unsafe extern "system" fn(
                DismSession,
                *const u16,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
            ) -> i32;
            let rem_cap: FnRemCap = std::mem::transmute(
                GetProcAddress(hmod, PCSTR(b"DismRemoveCapability\0".as_ptr())).ok_or_else(
                    || BackendError::OsError {
                        target: capability_name.to_string(),
                        message: "Missing DismRemoveCapability".to_string(),
                    },
                )?,
            );
            rem_cap(
                session,
                name_w.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if hr < 0 {
            return Err(BackendError::OsError {
                target: capability_name.to_string(),
                message: format!("DISM capability operation failed (0x{:08X})", hr as u32),
            });
        }
        Ok(TargetState::CapabilityPresent(install))
    })
}

fn probe_dism_feature(feature_name: &str) -> Result<TargetState, BackendError> {
    if !is_current_process_elevated() {
        return Ok(probe_feature_from_cbs_registry(feature_name));
    }
    let res = with_dism_session(feature_name, |hmod, session| unsafe {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::GetProcAddress;

        type FnGetFeat = unsafe extern "system" fn(
            DismSession,
            *const u16,
            *const u16,
            i32,
            *mut *mut DismFeatureInfo,
        ) -> i32;
        type FnDelete = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

        let get_feat: FnGetFeat = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismGetFeatureInfo\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: feature_name.to_string(),
                    message: "Missing DismGetFeatureInfo".to_string(),
                }
            })?,
        );
        let del_buf: FnDelete = std::mem::transmute(
            GetProcAddress(hmod, PCSTR(b"DismDelete\0".as_ptr())).ok_or_else(|| {
                BackendError::OsError {
                    target: feature_name.to_string(),
                    message: "Missing DismDelete".to_string(),
                }
            })?,
        );

        let name_w: Vec<u16> = format!("{}\0", feature_name).encode_utf16().collect();
        let mut info_ptr: *mut DismFeatureInfo = std::ptr::null_mut();
        let hr = get_feat(session, name_w.as_ptr(), std::ptr::null(), 0, &mut info_ptr);
        if hr < 0 || info_ptr.is_null() {
            return Ok(TargetState::FeatureEnabled(false));
        }
        let state = (*info_ptr).feature_state;
        let _ = del_buf(info_ptr as *mut _);
        Ok(TargetState::FeatureEnabled(
            state == DISM_INSTALL_STATE_INSTALLED,
        ))
    });

    match res {
        Ok(st) => Ok(st),
        // When probing from the unelevated UI (0x800702E4 = ERROR_ELEVATION_REQUIRED), fall back to read-only CBS registry probe
        Err(_) => Ok(probe_feature_from_cbs_registry(feature_name)),
    }
}

fn set_dism_feature(feature_name: &str, enable: bool) -> Result<TargetState, BackendError> {
    with_dism_session(feature_name, |hmod, session| unsafe {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::GetProcAddress;

        let name_w: Vec<u16> = format!("{}\0", feature_name).encode_utf16().collect();
        let hr = if enable {
            type FnEnable = unsafe extern "system" fn(
                DismSession,
                *const u16,
                *const u16,
                i32,
                i32,
                *const *const u16,
                u32,
                i32,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
            ) -> i32;
            let en_fn: FnEnable = std::mem::transmute(
                GetProcAddress(hmod, PCSTR(b"DismEnableFeature\0".as_ptr())).ok_or_else(|| {
                    BackendError::OsError {
                        target: feature_name.to_string(),
                        message: "Missing DismEnableFeature".to_string(),
                    }
                })?,
            );
            en_fn(
                session,
                name_w.as_ptr(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                0,
                1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } else {
            type FnDisable = unsafe extern "system" fn(
                DismSession,
                *const u16,
                *const u16,
                i32,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
                *mut core::ffi::c_void,
            ) -> i32;
            let dis_fn: FnDisable = std::mem::transmute(
                GetProcAddress(hmod, PCSTR(b"DismDisableFeature\0".as_ptr())).ok_or_else(|| {
                    BackendError::OsError {
                        target: feature_name.to_string(),
                        message: "Missing DismDisableFeature".to_string(),
                    }
                })?,
            );
            dis_fn(
                session,
                name_w.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if hr < 0 {
            return Err(BackendError::OsError {
                target: feature_name.to_string(),
                message: format!("DISM feature operation failed (0x{:08X})", hr as u32),
            });
        }
        Ok(TargetState::FeatureEnabled(enable))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_appraiser_resolves_to_exp_task_when_renamed() {
        let state = probe_scheduled_task(
            r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        )
        .expect("probe_scheduled_task should succeed");
        assert!(
            matches!(state, TargetState::TaskDisabled(_)),
            "Expected TaskDisabled(_) for Compatibility Appraiser (resolved via Exp fallback), got {:?}",
            state
        );
    }
}

