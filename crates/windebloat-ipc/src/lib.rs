use serde::{Deserialize, Serialize};
use thiserror::Error;
use windebloat_engine::{
    gating::OsEnvironment,
    journal::{DriftReportItem, JournalEntry},
    ActionProgressEvent, ApplySummary, BundleProbeStatus, DryRunReport, UndoItemResult,
};

/// Production Authenticode publisher Common Name. Compared with exact equality (§2.1, §8).
pub const PINNED_PUBLISHER_CN: &str = "WinDebloat";
/// Local-dev certificate CN from `scripts/setup-dev-cert.ps1`. Accepted only in debug builds.
pub const LOCAL_DEV_PUBLISHER_CN: &str = "WinDebloat-Local-Dev";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHandshake {
    pub nonce: String,
    pub user_sid: String,
    pub session_luid: String,
}

/// RPC requests over the named pipe (§2.1.4).
/// Strictly carries manifest bundle IDs and target-user SIDs only—never raw registry paths or package names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    GetEnvironment {
        target_sid: String,
    },
    ProbeBundles {
        bundle_ids: Vec<String>,
        target_sid: String,
    },
    DryRun {
        bundle_ids: Vec<String>,
        target_sid: String,
    },
    ApplyBundles {
        bundle_ids: Vec<String>,
        target_sid: String,
    },
    GetJournal,
    CheckDrift,
    Undo {
        run_id: Option<String>,
        entry_id: Option<String>,
        force_undo: bool,
    },
    LoadCustomManifest {
        manifest_path: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong,
    Environment {
        env: OsEnvironment,
        pending_reboot: Option<String>,
    },
    ProbeResults(Vec<BundleProbeStatus>),
    DryRunResult(DryRunReport),
    ApplyProgress(ActionProgressEvent),
    ApplyComplete(ApplySummary),
    JournalEntries(Vec<JournalEntry>),
    DriftReport(Vec<DriftReportItem>),
    UndoResults(Vec<UndoItemResult>),
    CustomManifestLoaded {
        manifest_name: String,
        signed_and_trusted: bool,
        bundle_ids: Vec<String>,
    },
    Ack,
    Error(String),
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Pipe security / SDDL error: {0}")]
    Security(String),
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("Peer Authenticode signature or publisher verification failed: {0}")]
    PeerVerificationFailed(String),
}

pub fn pipe_name_for_session(session_luid: &str) -> String {
    let clean: String = session_luid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    format!(r"\\.\pipe\WinDebloat.Daemon.{}", clean)
}

/// Accepts only `S-1-5(-<decimal>)+`. Rejects SDDL metacharacters.
pub fn validate_user_sid(user_sid: &str) -> Result<(), IpcError> {
    if user_sid.len() < 8 || user_sid.len() > 256 || !user_sid.starts_with("S-1-5-") {
        return Err(IpcError::Security(format!(
            "Invalid user SID for pipe SDDL: '{}'",
            user_sid
        )));
    }
    let rest = &user_sid[6..];
    let groups_ok = !rest.is_empty()
        && rest.split('-').all(|g| !g.is_empty() && g.chars().all(|c| c.is_ascii_digit()));
    if !groups_ok {
        return Err(IpcError::Security(format!(
            "Invalid user SID for pipe SDDL: '{}'",
            user_sid
        )));
    }
    Ok(())
}

/// Parses the `{:08x}-{:08x}` logon-session LUID emitted by `query_current_process_identity`.
pub fn parse_session_luid(session_luid: &str) -> Result<(u32, u32), IpcError> {
    let mut parts = session_luid.split('-');
    let (Some(high_hex), Some(low_hex), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(IpcError::Security(format!(
            "Invalid session LUID '{}'",
            session_luid
        )));
    };
    if high_hex.len() != 8
        || low_hex.len() != 8
        || !high_hex.chars().all(|c| c.is_ascii_hexdigit())
        || !low_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(IpcError::Security(format!(
            "Invalid session LUID '{}'",
            session_luid
        )));
    }
    let high = u32::from_str_radix(high_hex, 16)
        .map_err(|_| IpcError::Security(format!("Invalid session LUID '{}'", session_luid)))?;
    let low = u32::from_str_radix(low_hex, 16)
        .map_err(|_| IpcError::Security(format!("Invalid session LUID '{}'", session_luid)))?;
    Ok((high, low))
}

pub fn logon_sid_from_session_luid(session_luid: &str) -> Result<String, IpcError> {
    let (high, low) = parse_session_luid(session_luid)?;
    Ok(format!("S-1-5-5-{}-{}", high, low))
}

/// True when `subject_cn` is the production publisher, or the local-dev CN in debug builds.
pub fn publisher_cn_allowed(subject_cn: &str) -> bool {
    let cn = subject_cn.trim();
    if cn.eq_ignore_ascii_case(PINNED_PUBLISHER_CN) {
        return true;
    }
    cfg!(debug_assertions) && cn.eq_ignore_ascii_case(LOCAL_DEV_PUBLISHER_CN)
}

/// True when `image_path` is under `%ProgramFiles%\WinDebloat\` (or the x86 equivalent)
/// with no parent-directory (`..`) traversal segments.
pub fn is_protected_install_path(image_path: &str) -> bool {
    let norm = image_path.replace('/', "\\").to_ascii_lowercase();
    let clean = norm.strip_prefix(r"\\?\").unwrap_or(&norm);
    if clean.split('\\').any(|seg| seg == "..") {
        return false;
    }
    let mut prefixes = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(pf) = std::env::var(var) {
            let pf_clean = pf.replace('/', "\\").to_ascii_lowercase();
            let pf_clean = pf_clean.strip_prefix(r"\\?\").unwrap_or(&pf_clean).trim_end_matches('\\');
            prefixes.push(format!("{}\\windebloat\\", pf_clean));
        }
    }
    prefixes.push(r"c:\program files\windebloat\".to_string());
    prefixes.push(r"c:\program files (x86)\windebloat\".to_string());
    prefixes.iter().any(|p| clean.starts_with(p))
}

/// `true` when this build rejects peer binaries that carry no Authenticode signature.
/// Controlled by the `require-signed-peers` Cargo feature; off for community builds.
pub const REQUIRE_SIGNED_PEERS: bool = cfg!(feature = "require-signed-peers");

/// Outcome of a successful peer-binary trust check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// Valid Authenticode signature chaining to a trusted root, with the pinned publisher CN.
    SignedByPinnedPublisher,
    /// No Authenticode signature at all, running from the protected install directory.
    /// Only possible when [`REQUIRE_SIGNED_PEERS`] is `false`.
    UnsignedCommunityBuild,
}

/// Classification of a `WinVerifyTrust` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature present and trusted.
    Valid,
    /// File carries no Authenticode signature.
    NotSigned,
    /// Signature present but invalid (tampered, untrusted root, revoked, expired, ...),
    /// or the file could not be checked. Holds the `WinVerifyTrust` status.
    Invalid(u32),
}

const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;

/// Maps a `WinVerifyTrust` return value to a [`SignatureStatus`].
///
/// `TRUST_E_NOSIGNATURE` is always "unsigned". The Win32 sample also consults
/// `GetLastError()`, but `WinVerifyTrust` often leaves a stale last-error from an
/// earlier API (token queries, pipe setup, …). That misclassified unsigned
/// community binaries as broken signatures. Tampered or untrusted signatures
/// return other status codes (`TRUST_E_BAD_DIGEST`, `CERT_E_UNTRUSTEDROOT`, …).
pub fn classify_winverifytrust(status: u32, _last_error: u32) -> SignatureStatus {
    match status {
        0 => SignatureStatus::Valid,
        TRUST_E_NOSIGNATURE => SignatureStatus::NotSigned,
        other => SignatureStatus::Invalid(other),
    }
}

/// Unsigned peers are accepted only when strict mode is off and the image lives under
/// `%ProgramFiles%\WinDebloat\`, which only administrators can write to.
pub fn unsigned_peer_allowed(require_signed: bool, in_protected_dir: bool) -> bool {
    !require_signed && in_protected_dir
}

pub fn generate_256bit_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Builds the SDDL string granting pipe access only to SYSTEM (`SY`), Administrators (`BA`),
/// and the interactive logon-session SID derived from `session_luid` (§2.1.2).
///
/// The user SID is validated but not granted its own ACE: a user-SID ACE would
/// allow the same account in a different logon session to connect.
///
/// `S:(ML;;NW;;;ME)` sets a **Medium** mandatory integrity label. The elevated
/// daemon otherwise creates a High-integrity pipe, and Windows No-Write-Up
/// blocks the unelevated (Medium) UI from opening it — which surfaces as a
/// connect timeout, not an access-denied error.
pub fn build_pipe_sddl(user_sid: &str, session_luid: &str) -> Result<String, IpcError> {
    validate_user_sid(user_sid)?;
    let logon_sid = logon_sid_from_session_luid(session_luid)?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{})S:(ML;;NW;;;ME)",
        logon_sid
    ))
}

/// UI log: `%LOCALAPPDATA%\WinDebloat\ui-ipc.log`
/// Daemon log: `%ProgramData%\WinDebloat\daemon-ipc.log`
pub fn ipc_debug_log_path(role: &str) -> std::path::PathBuf {
    let dir = if role.eq_ignore_ascii_case("daemon") {
        std::env::var("ProgramData")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\ProgramData"))
            .join("WinDebloat")
    } else {
        std::env::var("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("WinDebloat")
    };
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{role}-ipc.log"))
}

pub fn ipc_debug_log(role: &str, message: &str) {
    use std::io::Write;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!("{ts} [{role} pid={}] {message}\n", std::process::id());
    let path = ipc_debug_log_path(role);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

#[derive(Debug, Clone)]
pub struct ProcessTokenDebug {
    pub pid: u32,
    pub user_sid: String,
    pub session_luid: String,
    pub derived_logon_sid: String,
    pub token_logon_sid: String,
    pub integrity_rid: u32,
    pub integrity_name: String,
    pub elevated: bool,
}

impl std::fmt::Display for ProcessTokenDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pid={} user_sid={} session_luid={} derived_logon_sid={} token_logon_sid={} integrity={} (0x{:04X}) elevated={}",
            self.pid,
            self.user_sid,
            self.session_luid,
            self.derived_logon_sid,
            self.token_logon_sid,
            self.integrity_name,
            self.integrity_rid,
            self.elevated
        )
    }
}

fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x0000 => "Untrusted",
        0x1000 => "Low",
        0x2000 => "Medium",
        0x2100 => "MediumPlus",
        0x3000 => "High",
        0x4000 => "System",
        0x5000 => "ProtectedProcess",
        _ => "Unknown",
    }
}

/// Snapshot of the current process token used for pipe DACL / integrity diagnosis.
#[cfg(windows)]
pub fn query_process_token_debug() -> Result<ProcessTokenDebug, IpcError> {
    let (user_sid, session_luid) = query_current_process_identity()?;
    let derived_logon_sid = logon_sid_from_session_luid(&session_luid).unwrap_or_else(|e| format!("<err:{e}>"));
    unsafe {
        use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
            TokenIntegrityLevel, TokenLogonSid, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL,
            TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| IpcError::Security(format!("OpenProcessToken failed: {e}")))?;

        let sid_to_string = |sid: windows::Win32::Security::PSID| -> String {
            let mut p = windows::core::PWSTR::null();
            if ConvertSidToStringSidW(sid, &mut p).is_err() {
                return "<ConvertSidToStringSidW failed>".to_string();
            }
            let s = p.to_string().unwrap_or_else(|_| "<utf16>".to_string());
            let _ = LocalFree(HLOCAL(p.0 as *mut _));
            s
        };

        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenLogonSid, None, 0, &mut needed);
        let mut logon_buf = vec![0u8; needed.max(1) as usize];
        let token_logon_sid = if GetTokenInformation(
            token,
            TokenLogonSid,
            Some(logon_buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .is_ok()
        {
            let groups = &*(logon_buf.as_ptr() as *const TOKEN_GROUPS);
            if groups.GroupCount > 0 {
                sid_to_string(groups.Groups[0].Sid)
            } else {
                "<TokenLogonSid empty>".to_string()
            }
        } else {
            "<TokenLogonSid query failed>".to_string()
        };

        needed = 0;
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed);
        let mut il_buf = vec![0u8; needed.max(1) as usize];
        let integrity_rid = if GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(il_buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .is_ok()
        {
            let label = &*(il_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let count = *GetSidSubAuthorityCount(label.Label.Sid);
            if count > 0 {
                *GetSidSubAuthority(label.Label.Sid, (count as u32) - 1)
            } else {
                0
            }
        } else {
            0
        };

        let mut elevation = TOKEN_ELEVATION::default();
        let mut elev_len = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let elevated = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            elev_len,
            &mut elev_len,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0;

        let _ = CloseHandle(token);
        Ok(ProcessTokenDebug {
            pid: std::process::id(),
            user_sid,
            session_luid,
            derived_logon_sid,
            token_logon_sid,
            integrity_rid,
            integrity_name: integrity_name(integrity_rid).to_string(),
            elevated,
        })
    }
}

/// Reads DACL + mandatory label from a kernel object as SDDL.
#[cfg(windows)]
pub fn handle_security_sddl(handle: windows::Win32::Foundation::HANDLE) -> String {
    unsafe {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
            LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            OBJECT_SECURITY_INFORMATION,
        };

        let info = OWNER_SECURITY_INFORMATION.0
            | GROUP_SECURITY_INFORMATION.0
            | DACL_SECURITY_INFORMATION.0
            | LABEL_SECURITY_INFORMATION.0;
        let mut needed = 0u32;
        let _ = GetKernelObjectSecurity(
            handle,
            info,
            PSECURITY_DESCRIPTOR::default(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return "<GetKernelObjectSecurity size=0>".to_string();
        }
        let mut buf = vec![0u8; needed as usize];
        if GetKernelObjectSecurity(
            handle,
            info,
            PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .is_err()
        {
            return format!("<GetKernelObjectSecurity failed, needed={needed}>");
        }
        let mut sddl = windows::core::PWSTR::null();
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(buf.as_ptr() as *mut _),
            SDDL_REVISION_1,
            OBJECT_SECURITY_INFORMATION(info),
            &mut sddl,
            None,
        )
        .is_err()
        {
            return "<ConvertSecurityDescriptorToStringSecurityDescriptorW failed>".to_string();
        }
        let out = sddl.to_string().unwrap_or_else(|_| "<utf16>".to_string());
        let _ = LocalFree(HLOCAL(sddl.0 as *mut _));
        out
    }
}

/// Applies a Medium mandatory integrity label via `LABEL_SECURITY_INFORMATION`.
/// This does not require `SE_SECURITY_NAME`; embedding `S:(ML;;...)` in the create-time
/// SDDL often silently drops the SACL when that privilege is not enabled.
#[cfg(windows)]
pub fn set_medium_integrity_label(
    handle: windows::Win32::Foundation::HANDLE,
) -> Result<(), IpcError> {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            SetKernelObjectSecurity, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        };

        let sddl_w: Vec<u16> = "S:(ML;;NW;;;ME)\0".encode_utf16().collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| IpcError::Security(format!("medium-label SDDL conversion failed: {e}")))?;
        let result = SetKernelObjectSecurity(handle, LABEL_SECURITY_INFORMATION, sd);
        let _ = LocalFree(HLOCAL(sd.0));
        result.map_err(|e| IpcError::Security(format!("SetKernelObjectSecurity(LABEL Medium) failed: {e}")))
    }
}

/// Queries the current process token for its User SID string (`S-1-5-21-...`) and Logon SID LUID (`high-low` hex) (§2.1.1).
///
/// Reads `TokenLogonSid` (`S-1-5-5-<high>-<low>`) first so that `logon_sid_from_session_luid`
/// reconstructs the exact Logon SID present in the token's groups during pipe DACL checks.
/// (Under UAC split tokens, `TokenStatistics.AuthenticationId` differs from the `TokenLogonSid`
/// LUID and is not a SID in the token's group list.)
#[cfg(windows)]
pub fn query_current_process_identity() -> Result<(String, String), IpcError> {
    unsafe {
        use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenLogonSid,
            TokenStatistics, TokenUser, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| IpcError::Security(format!("OpenProcessToken failed: {}", e)))?;

        // 1. Read TokenUser -> SID string
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut user_buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(user_buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .map_err(|e| {
            let _ = CloseHandle(token);
            IpcError::Security(format!("GetTokenInformation(TokenUser) failed: {}", e))
        })?;

        let token_user = &*(user_buf.as_ptr() as *const TOKEN_USER);
        let mut sid_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(token_user.User.Sid, &mut sid_ptr).map_err(|e| {
            let _ = CloseHandle(token);
            IpcError::Security(format!("ConvertSidToStringSidW failed: {}", e))
        })?;
        let sid_string = sid_ptr
            .to_string()
            .map_err(|e| IpcError::Security(e.to_string()))?;
        let _ = LocalFree(HLOCAL(sid_ptr.0 as *mut _));

        // 2. Prefer TokenLogonSid (S-1-5-5-<high>-<low>) so the SDDL logon SID ACE
        // matches the interactive token's actual logon group SID.
        let mut logon_needed = 0u32;
        let _ = GetTokenInformation(token, TokenLogonSid, None, 0, &mut logon_needed);
        let mut logon_luid_hex: Option<String> = None;
        if logon_needed > 0 {
            let mut logon_buf = vec![0u8; logon_needed as usize];
            if GetTokenInformation(
                token,
                TokenLogonSid,
                Some(logon_buf.as_mut_ptr() as *mut _),
                logon_needed,
                &mut logon_needed,
            )
            .is_ok()
            {
                let groups = &*(logon_buf.as_ptr() as *const TOKEN_GROUPS);
                if groups.GroupCount > 0 {
                    let logon_sid = groups.Groups[0].Sid;
                    let sub_count = *GetSidSubAuthorityCount(logon_sid);
                    if sub_count >= 3 && *GetSidSubAuthority(logon_sid, 0) == 5 {
                        let high = *GetSidSubAuthority(logon_sid, 1);
                        let low = *GetSidSubAuthority(logon_sid, 2);
                        logon_luid_hex = Some(format!("{:08x}-{:08x}", high, low));
                    }
                }
            }
        }

        // 3. Fallback to TokenStatistics -> AuthenticationId for tokens without TokenLogonSid
        let luid_hex = match logon_luid_hex {
            Some(hex) => hex,
            None => {
                let mut stats = TOKEN_STATISTICS::default();
                let mut stats_len = std::mem::size_of::<TOKEN_STATISTICS>() as u32;
                GetTokenInformation(
                    token,
                    TokenStatistics,
                    Some(&mut stats as *mut _ as *mut _),
                    stats_len,
                    &mut stats_len,
                )
                .map_err(|e| {
                    let _ = CloseHandle(token);
                    IpcError::Security(format!(
                        "GetTokenInformation(TokenStatistics) failed: {}",
                        e
                    ))
                })?;
                format!(
                    "{:08x}-{:08x}",
                    stats.AuthenticationId.HighPart as u32, stats.AuthenticationId.LowPart
                )
            }
        };

        let _ = CloseHandle(token);
        Ok((sid_string, luid_hex))
    }
}

/// Creates a first-instance Named Pipe server handle secured with `build_pipe_sddl` (§2.1.2).
#[cfg(windows)]
pub fn create_secured_named_pipe(
    pipe_name: &str,
    user_sid: &str,
    session_luid: &str,
) -> Result<windows::Win32::Foundation::HANDLE, IpcError> {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{GetLastError, LocalFree, HLOCAL, INVALID_HANDLE_VALUE};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
        };
        use windows::Win32::System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_MESSAGE, PIPE_WAIT,
        };

        let sddl = build_pipe_sddl(user_sid, session_luid)?;
        ipc_debug_log(
            "daemon",
            &format!("create_secured_named_pipe name={pipe_name} requested_sddl={sddl}"),
        );
        let sddl_w: Vec<u16> = format!("{}\0", sddl).encode_utf16().collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();

        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| IpcError::Security(format!("SDDL conversion failed: {}", e)))?;

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };

        let pipe_w: Vec<u16> = format!("{}\0", pipe_name).encode_utf16().collect();
        let handle = CreateNamedPipeW(
            PCWSTR(pipe_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            Some(&sa),
        );

        let _ = LocalFree(HLOCAL(sd.0));

        if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
            let err = format!(
                "CreateNamedPipeW(FILE_FLAG_FIRST_PIPE_INSTANCE) failed for {} (GetLastError 0x{:08X})",
                pipe_name,
                GetLastError().0
            );
            ipc_debug_log("daemon", &err);
            return Err(IpcError::Security(err));
        }

        ipc_debug_log(
            "daemon",
            &format!("pipe SD after CreateNamedPipe: {}", handle_security_sddl(handle)),
        );
        match set_medium_integrity_label(handle) {
            Ok(()) => ipc_debug_log("daemon", "SetKernelObjectSecurity(LABEL Medium) succeeded"),
            Err(e) => ipc_debug_log("daemon", &format!("SetKernelObjectSecurity(LABEL Medium) failed: {e}")),
        }
        ipc_debug_log(
            "daemon",
            &format!("pipe SD after label set: {}", handle_security_sddl(handle)),
        );

        Ok(handle)
    }
}

/// Verifies an on-disk peer image (§2.1.3, §8).
///
/// - Signed images must carry a valid Authenticode signature with the exact pinned publisher CN.
/// - Unsigned images are accepted only in community builds (see [`REQUIRE_SIGNED_PEERS`]) and
///   only from `%ProgramFiles%\WinDebloat\`, regardless of `require_protected_dir`.
/// - Present-but-invalid signatures (tampered, untrusted, revoked) are always rejected.
#[cfg(windows)]
pub fn verify_image_authenticode(
    image_path: &str,
    require_protected_dir: bool,
) -> Result<PeerTrust, IpcError> {
    let in_protected_dir = is_protected_install_path(image_path);
    if require_protected_dir && !in_protected_dir {
        return Err(IpcError::PeerVerificationFailed(format!(
            "Binary '{}' is not located in a protected install directory",
            image_path
        )));
    }

    unsafe {
        use windows::core::{GUID, PCWSTR};
        use windows::Win32::Foundation::{GetLastError, HWND};
        use windows::Win32::Security::Cryptography::{
            CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
            CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_INFO,
            CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
            CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
            PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };
        use windows::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
            WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_REVOCATION_CHECKS,
            WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UICHOICE,
            WINTRUST_DATA_UNION_CHOICE, WINTRUST_FILE_INFO,
        };

        let file_w: Vec<u16> = format!("{}\0", image_path).encode_utf16().collect();
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(file_w.as_ptr()),
            ..Default::default()
        };

        // WTD_REVOKE_WHOLECHAIN (1) + WTD_REVOCATION_CHECK_CHAIN (0x40)
        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WINTRUST_DATA_UICHOICE(2),
            fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(1),
            dwUnionChoice: WINTRUST_DATA_UNION_CHOICE(1),
            dwStateAction: WINTRUST_DATA_STATE_ACTION(0),
            dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0x40),
            dwUIContext: WINTRUST_DATA_UICONTEXT(0),
            Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            ..Default::default()
        };

        let mut action_guid: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            HWND::default(),
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        ) as u32;
        // Must be read immediately after WinVerifyTrust.
        let last_error = GetLastError().0;

        match classify_winverifytrust(status, last_error) {
            SignatureStatus::Valid => {}
            SignatureStatus::NotSigned => {
                return if unsigned_peer_allowed(REQUIRE_SIGNED_PEERS, in_protected_dir) {
                    Ok(PeerTrust::UnsignedCommunityBuild)
                } else if REQUIRE_SIGNED_PEERS {
                    Err(IpcError::PeerVerificationFailed(format!(
                        "Binary '{}' is unsigned; this build requires Authenticode-signed binaries",
                        image_path
                    )))
                } else {
                    Err(IpcError::PeerVerificationFailed(format!(
                        "Binary '{}' is unsigned and not located in %ProgramFiles%\\WinDebloat",
                        image_path
                    )))
                };
            }
            SignatureStatus::Invalid(code) => {
                return Err(IpcError::PeerVerificationFailed(format!(
                    "WinVerifyTrust failed for '{}' with status 0x{:08X} (GetLastError 0x{:08X})",
                    image_path, code, last_error
                )));
            }
        }

        let mut hstore = HCERTSTORE::default();
        let mut hmsg: *mut core::ffi::c_void = std::ptr::null_mut();
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            file_w.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut hstore),
            Some(&mut hmsg),
            None,
        )
        .map_err(|e| IpcError::PeerVerificationFailed(format!("CryptQueryObject failed: {}", e)))?;

        let cleanup = |store: HCERTSTORE, msg: *mut core::ffi::c_void| {
            let _ = CryptMsgClose(Some(msg));
            let _ = CertCloseStore(store, 0);
        };

        let mut signer_len = 0u32;
        let _ = CryptMsgGetParam(hmsg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_len);
        if signer_len == 0 {
            cleanup(hstore, hmsg);
            return Err(IpcError::PeerVerificationFailed(
                "Authenticode signer info missing".to_string(),
            ));
        }
        let mut signer_buf = vec![0u8; signer_len as usize];
        CryptMsgGetParam(
            hmsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_buf.as_mut_ptr() as *mut _),
            &mut signer_len,
        )
        .map_err(|e| {
            cleanup(hstore, hmsg);
            IpcError::PeerVerificationFailed(format!("CryptMsgGetParam failed: {}", e))
        })?;

        let signer_info = &*(signer_buf.as_ptr() as *const CMSG_SIGNER_INFO);
        let mut cert_info = CERT_INFO::default();
        cert_info.Issuer = signer_info.Issuer;
        cert_info.SerialNumber = signer_info.SerialNumber;

        let cert_ctx = CertFindCertificateInStore(
            hstore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const CERT_INFO as *const _),
            None,
        );
        if cert_ctx.is_null() {
            cleanup(hstore, hmsg);
            return Err(IpcError::PeerVerificationFailed(
                "No signer certificate found in Authenticode store".to_string(),
            ));
        }

        let mut name_buf = vec![0u16; 256];
        let name_len = CertGetNameStringW(
            cert_ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        let subject_cn = if name_len > 1 {
            String::from_utf16_lossy(&name_buf[..(name_len as usize - 1)])
        } else {
            String::new()
        };

        let _ = CertFreeCertificateContext(Some(cert_ctx));
        cleanup(hstore, hmsg);

        if !publisher_cn_allowed(&subject_cn) {
            return Err(IpcError::PeerVerificationFailed(format!(
                "Publisher CN '{}' does not match pinned publisher '{}'",
                subject_cn, PINNED_PUBLISHER_CN
            )));
        }

        Ok(PeerTrust::SignedByPinnedPublisher)
    }
}

/// Verifies the connected named pipe client process via `GetNamedPipeClientProcessId` ->
/// `QueryFullProcessImageNameW` -> `WinVerifyTrust` Authenticode check + Publisher Subject check (§2.1.3).
#[cfg(windows)]
pub fn verify_pipe_client_authenticode(
    pipe_handle: windows::Win32::Foundation::HANDLE,
    dev_no_verify: bool,
    expected_client_pid: u32,
) -> Result<String, IpcError> {
    unsafe {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let mut client_pid = 0u32;
        GetNamedPipeClientProcessId(pipe_handle, &mut client_pid).map_err(|e| {
            IpcError::PeerVerificationFailed(format!("GetNamedPipeClientProcessId failed: {}", e))
        })?;

        if expected_client_pid == 0 || client_pid != expected_client_pid {
            return Err(IpcError::PeerVerificationFailed(format!(
                "Pipe client PID {} does not match launching UI PID {}",
                client_pid, expected_client_pid
            )));
        }

        let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
            .map_err(|e| {
                IpcError::PeerVerificationFailed(format!(
                    "OpenProcess(PID {}) failed: {}",
                    client_pid, e
                ))
            })?;

        let mut path_buf = vec![0u16; 1024];
        let mut path_len = path_buf.len() as u32;
        let query_res = QueryFullProcessImageNameW(
            proc_handle,
            PROCESS_NAME_WIN32,
            PWSTR(path_buf.as_mut_ptr()),
            &mut path_len,
        );
        let _ = CloseHandle(proc_handle);

        query_res.map_err(|e| {
            IpcError::PeerVerificationFailed(format!("QueryFullProcessImageNameW failed: {}", e))
        })?;

        let image_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);

        if dev_no_verify {
            return Ok(image_path);
        }

        verify_image_authenticode(&image_path, true)?;
        Ok(image_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_pipe_sddl_and_rejects_bad_sid() {
        let sddl = build_pipe_sddl("S-1-5-21-123456-7890-1001", "00000000-0001a2b3").unwrap();
        assert_eq!(
            sddl,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-5-0-107187)S:(ML;;NW;;;ME)"
        );
        assert!(build_pipe_sddl("invalid_sid", "00000000-0001a2b3").is_err());
        assert!(build_pipe_sddl(
            "S-1-5-21-1)(A;;GA;;;WD",
            "00000000-0001a2b3"
        )
        .is_err());
        assert!(build_pipe_sddl("S-1-5-21-123456-7890-1001", "not-a-luid").is_err());
    }

    #[test]
    fn publisher_cn_is_exact_match_not_substring() {
        assert!(publisher_cn_allowed("WinDebloat"));
        assert!(publisher_cn_allowed("windebloat"));
        assert!(!publisher_cn_allowed("WinDebloat Dev Publisher"));
        assert!(!publisher_cn_allowed("NotWinDebloat"));
        assert!(!publisher_cn_allowed("WinDebloat-Local-Dev") || cfg!(debug_assertions));
    }

    #[test]
    fn generates_64_hex_char_256bit_nonce() {
        let n1 = generate_256bit_nonce();
        let n2 = generate_256bit_nonce();
        assert_eq!(n1.len(), 64);
        assert_ne!(n1, n2);
    }

    #[test]
    fn protected_install_path_accepts_program_files_and_rejects_traversal() {
        assert!(is_protected_install_path(
            r"C:\Program Files\WinDebloat\windebloat-daemon.exe"
        ));
        assert!(is_protected_install_path(
            r"\\?\C:\Program Files\WinDebloat\windebloat.exe"
        ));
        assert!(!is_protected_install_path(
            r"C:\Program Files\WinDebloat\..\..\Users\Public\windebloat-daemon.exe"
        ));
        assert!(!is_protected_install_path(
            r"C:\Users\alice\Downloads\windebloat-daemon.exe"
        ));
    }

    #[test]
    fn classifies_winverifytrust_results() {
        assert_eq!(classify_winverifytrust(0, 0), SignatureStatus::Valid);
        for le in [
            0,
            TRUST_E_NOSIGNATURE,
            0x800B_0001, // TRUST_E_PROVIDER_UNKNOWN (stale last-error)
            0x800B_0003, // TRUST_E_SUBJECT_FORM_UNKNOWN (stale last-error)
            0x8009_6010, // TRUST_E_BAD_DIGEST leftover must not override NOSIGNATURE
        ] {
            assert_eq!(
                classify_winverifytrust(TRUST_E_NOSIGNATURE, le),
                SignatureStatus::NotSigned
            );
        }
        // TRUST_E_BAD_DIGEST (tampered) and CERT_E_UNTRUSTEDROOT (self-signed) stay invalid.
        assert_eq!(
            classify_winverifytrust(0x8009_6010, 0),
            SignatureStatus::Invalid(0x8009_6010)
        );
        assert_eq!(
            classify_winverifytrust(0x800B_0109, 0),
            SignatureStatus::Invalid(0x800B_0109)
        );
    }

    #[test]
    fn unsigned_peers_need_community_build_and_protected_dir() {
        assert!(unsigned_peer_allowed(false, true));
        assert!(!unsigned_peer_allowed(false, false));
        assert!(!unsigned_peer_allowed(true, true));
        assert!(!unsigned_peer_allowed(true, false));
        assert_eq!(REQUIRE_SIGNED_PEERS, cfg!(feature = "require-signed-peers"));
    }

    /// The cargo test binary is unsigned and lives under `target\`, so it must be
    /// classified as unsigned (not as a broken signature) and then rejected for its location.
    #[cfg(windows)]
    #[test]
    fn unsigned_binary_outside_program_files_is_rejected_as_unsigned() {
        let exe = std::env::current_exe().unwrap();
        let err = verify_image_authenticode(&exe.to_string_lossy(), false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("is unsigned"), "unexpected error: {msg}");
    }

    #[cfg(windows)]
    #[test]
    fn current_process_can_open_secured_named_pipe() {
        let dbg = query_process_token_debug().unwrap();
        assert_eq!(
            dbg.derived_logon_sid, dbg.token_logon_sid,
            "derived_logon_sid must match TokenLogonSid: {dbg}"
        );
        let pipe_name = format!(
            r"\\.\pipe\WinDebloat.Test.{}.{}",
            std::process::id(),
            dbg.session_luid
        );
        let server_handle =
            create_secured_named_pipe(&pipe_name, &dbg.user_sid, &dbg.session_luid).unwrap();
        let client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_name);
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(server_handle);
        }
        client.expect("interactive client in same logon session should open secured named pipe");

        // Regression check: for a non-elevated client (which does not match the `(A;;GA;;;BA)`
        // Administrators ACE), a LUID that does not match TokenLogonSid is denied by the DACL.
        // Note: GitHub Actions Windows runners execute tests elevated as `BUILTIN\Administrators`,
        // which intentionally matches `(A;;GA;;;BA)` in `build_pipe_sddl`.
        if !dbg.elevated {
            let wrong_luid = "00000000-deadbeef";
            let wrong_pipe = format!(r"\\.\pipe\WinDebloat.Test.{}.wrong", std::process::id());
            let wrong_handle =
                create_secured_named_pipe(&wrong_pipe, &dbg.user_sid, wrong_luid).unwrap();
            let wrong_err = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&wrong_pipe)
                .unwrap_err();
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(wrong_handle);
            }
            assert_eq!(wrong_err.kind(), std::io::ErrorKind::PermissionDenied);
        }
    }
}
