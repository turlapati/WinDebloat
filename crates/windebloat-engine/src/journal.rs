use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionState {
    Planned,
    Skipped,
    Captured,
    Applied,
    Verified,
    Failed,
    RolledBack,
    Undone,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionContext {
    Interactive,
    Headless,
}

/// Normalized representation of a target's state (registry value, Appx tristate, service start type, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TargetState {
    Absent,
    NotApplicable,
    RegistryValue(serde_json::Value),
    AppxTristate(AppxInstallState),
    ProvisionedPresent(bool),
    TaskDisabled(bool),
    ServiceStart(String),
    CapabilityPresent(bool),
    FeatureEnabled(bool),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppxInstallState {
    Installed,
    ProvisionedOnly,
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEntry {
    pub entry_id: String,
    pub bundle_id: String,
    pub action_index: usize,
    pub target: String,
    pub prior: TargetState,
    pub written: Option<TargetState>,
    pub applied_at: DateTime<Utc>,
    pub run_id: String,
    pub context: ExecutionContext,
    pub state: ActionState,
    pub error: Option<String>,
    pub sha256: String,
}

impl JournalEntry {
    pub fn new_captured(
        bundle_id: &str,
        action_index: usize,
        target: &str,
        prior: TargetState,
        run_id: &str,
        context: ExecutionContext,
    ) -> Self {
        let mut entry = Self {
            entry_id: Uuid::new_v4().to_string(),
            bundle_id: bundle_id.to_string(),
            action_index,
            target: target.to_string(),
            prior,
            written: None,
            applied_at: Utc::now(),
            run_id: run_id.to_string(),
            context,
            state: ActionState::Captured,
            error: None,
            sha256: String::new(),
        };
        entry.recompute_hash();
        entry
    }

    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.entry_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.bundle_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.action_index.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(self.target.as_bytes());
        hasher.update(b"|");
        hasher.update(serde_json::to_string(&self.prior).unwrap_or_default().as_bytes());
        hasher.update(b"|");
        hasher.update(serde_json::to_string(&self.written).unwrap_or_default().as_bytes());
        hasher.update(b"|");
        hasher.update(self.applied_at.to_rfc3339().as_bytes());
        hasher.update(b"|");
        hasher.update(self.run_id.as_bytes());
        hasher.update(b"|");
        hasher.update(serde_json::to_string(&self.context).unwrap_or_default().as_bytes());
        hasher.update(b"|");
        hasher.update(serde_json::to_string(&self.state).unwrap_or_default().as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn recompute_hash(&mut self) {
        self.sha256 = self.compute_hash();
    }

    pub fn verify_hash(&self) -> bool {
        self.sha256 == self.compute_hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalFile {
    pub schema_version: u32,
    pub entries: Vec<JournalEntry>,
}

impl Default for JournalFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("Journal I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Journal JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Journal entry '{0}' failed SHA-256 integrity check (corrupted journal)")]
    IntegrityViolation(String),
    #[error("Unsupported journal schema_version {0}")]
    UnsupportedSchema(u32),
}

pub fn default_journal_path() -> PathBuf {
    // Env override is debug-only so a inherited user environment cannot redirect
    // the elevated daemon's journal in release builds.
    if cfg!(debug_assertions) {
        if let Ok(custom) = std::env::var("WINDEBLOAT_JOURNAL_PATH") {
            if !custom.trim().is_empty() {
                return PathBuf::from(custom);
            }
        }
    }
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data)
        .join("WinDebloat")
        .join("journal.json")
}

fn is_protected_journal_location(path: &Path) -> bool {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let root = PathBuf::from(program_data).join("WinDebloat");
    let root_norm = root.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    let root_clean = root_norm.strip_prefix(r"\\?\").unwrap_or(&root_norm).trim_end_matches('\\');
    let path_norm = path.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    let path_clean = path_norm.strip_prefix(r"\\?\").unwrap_or(&path_norm);
    path_clean == root_clean || path_clean.starts_with(&format!("{}\\", root_clean))
}

/// Applies a DACL granting Full Control (`FA`) only to SYSTEM (`SY`) and Administrators (`BA`),
/// plus Read-Only (`GR`) to Builtin Users (`BU`) so the unelevated UI can display Undo History
/// and Drift status without modifying the journal (§5).
#[cfg(windows)]
fn apply_admin_only_acl(path: &Path) {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, ACL,
        };

        let sddl = if path.is_dir() {
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;BU)\0"
        } else {
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)\0"
        };
        let sddl_w: Vec<u16> = sddl.encode_utf16().collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .is_err()
        {
            return;
        }

        let mut dacl_present = BOOL::default();
        let mut dacl_defaulted = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let dacl_ok = GetSecurityDescriptorDacl(
            sd,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
        .is_ok()
            && dacl_present.as_bool()
            && !dacl.is_null();

        if dacl_ok {
            let path_w: Vec<u16> = format!("{}\0", path.display()).encode_utf16().collect();
            let _ = SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl as *const ACL),
                None,
            );
        }
        let _ = LocalFree(HLOCAL(sd.0));
    }
}

#[cfg(not(windows))]
fn apply_admin_only_acl(_path: &Path) {}

/// Ensures the journal directory and file have the expected SYSTEM/Admin write + Users read ACL,
/// and prunes any stale `Failed`/`RolledBack` entries from older runs when elevated.
pub fn ensure_journal_acl(path: &Path) {
    if !is_protected_journal_location(path) {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
        apply_admin_only_acl(parent);
    }
    if path.exists() {
        apply_admin_only_acl(path);
        if let Ok(mut journal) = JournalFile::load_or_create(path) {
            let before_len = journal.entries.len();
            journal.entries.retain(|e| {
                !matches!(e.state, ActionState::Failed | ActionState::RolledBack)
                    && !e.target.ends_with("Microsoft Compatibility Appraiser Exp")
            });
            if journal.entries.len() != before_len {
                let _ = journal.save(path);
            }
        }
    }
}

impl JournalFile {
    pub fn load_or_create(path: &Path) -> Result<Self, JournalError> {
        let raw = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(JournalError::Io(e)),
        };
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        let journal: JournalFile = serde_json::from_str(&raw)?;
        if journal.schema_version != 1 {
            return Err(JournalError::UnsupportedSchema(journal.schema_version));
        }
        for entry in &journal.entries {
            if !entry.verify_hash() {
                return Err(JournalError::IntegrityViolation(entry.entry_id.clone()));
            }
        }
        Ok(journal)
    }

    pub fn save(&self, path: &Path) -> Result<(), JournalError> {
        let protected = is_protected_journal_location(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            if protected {
                apply_admin_only_acl(parent);
            }
        }
        let tmp_path = path.with_extension("json.tmp");
        let serialized = serde_json::to_string_pretty(self)?;
        fs::write(&tmp_path, serialized)?;
        if protected {
            apply_admin_only_acl(&tmp_path);
        }
        fs::rename(&tmp_path, path)?;
        if protected {
            apply_admin_only_acl(path);
        }
        Ok(())
    }

    pub fn upsert_entry(&mut self, mut entry: JournalEntry) {
        if entry.state == ActionState::Verified {
            self.entries.retain(|e| {
                e.entry_id == entry.entry_id
                    || e.target != entry.target
                    || !matches!(
                        e.state,
                        ActionState::Failed | ActionState::RolledBack | ActionState::Undone
                    )
            });
        }
        entry.recompute_hash();
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.entry_id == entry.entry_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }
}

/// Classification of a verified journal entry during drift detection (§5.3).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriftStatus {
    /// `current == written`
    Intact,
    /// `current != written` and `current == prior` (the usual Windows Update case)
    Reverted,
    /// `current != written` and `current != prior`
    ChangedByOther,
    /// Target no longer exists (e.g. key removed by a feature update)
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftReportItem {
    pub entry_id: String,
    pub bundle_id: String,
    pub action_index: usize,
    pub target: String,
    pub prior: TargetState,
    pub written: TargetState,
    pub current: TargetState,
    pub status: DriftStatus,
    pub applied_at: DateTime<Utc>,
    pub run_id: String,
}

pub fn classify_drift(
    prior: &TargetState,
    written: &TargetState,
    current: &TargetState,
) -> DriftStatus {
    if matches!(current, TargetState::NotApplicable) {
        return DriftStatus::NotApplicable;
    }
    if current == written {
        DriftStatus::Intact
    } else if current == prior {
        DriftStatus::Reverted
    } else {
        DriftStatus::ChangedByOther
    }
}
