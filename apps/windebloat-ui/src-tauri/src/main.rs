#![windows_subsystem = "windows"]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{Emitter, State};
use windebloat_engine::{
    backend::OsBackend,
    gating::OsEnvironment,
    journal::{default_journal_path, DriftReportItem, ExecutionContext, JournalEntry, JournalFile},
    sandbox::SandboxOsBackend,
    target::TargetScope,
    windows_os::WindowsOsBackend,
    ApplySummary, BundleProbeStatus, DryRunReport, ExecutionEngine, UndoItemResult,
};
use windebloat_ipc::{
    generate_256bit_nonce, ipc_debug_log, ipc_debug_log_path, is_protected_install_path,
    pipe_name_for_session, query_current_process_identity, query_process_token_debug,
    verify_image_authenticode, ClientHandshake, IpcRequest, IpcResponse, REQUIRE_SIGNED_PEERS,
};
use windebloat_schema::{
    load_embedded_base_manifest, load_embedded_profiles,
    signature::{load_system_trusted_keys, verify_manifest_signature},
    validation::validate_manifest,
    Bundle, ManifestFile, SelectionProfile,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiBootstrapPayload {
    pub app_version: String,
    pub user_sid: String,
    pub session_luid: String,
    pub environment: OsEnvironment,
    pub pending_reboot: Option<String>,
    pub bundles: Vec<Bundle>,
    pub profiles: Vec<SelectionProfile>,
    pub custom_bundle_sources: HashMap<String, CustomSourceBadge>,
    pub sandbox_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSourceBadge {
    pub manifest_name: String,
    pub trusted: bool,
}

struct AppStateInner {
    user_sid: String,
    session_luid: String,
    sandbox_mode: Mutex<bool>,
    bundles: Mutex<Vec<Bundle>>,
    custom_sources: Mutex<HashMap<String, CustomSourceBadge>>,
    daemon_pipe: Mutex<Option<File>>,
}

#[derive(Clone)]
struct AppState(std::sync::Arc<AppStateInner>);

impl std::ops::Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Applies process mitigation policies on the UI process per SDS v3 §2.1.5
/// (`ProcessImageLoadPolicy`: NoRemoteImages | NoLowMandatoryLabelImages; `ProcessSignaturePolicy` in signed builds).
fn apply_ui_process_mitigations() {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Threading::{
            ProcessImageLoadPolicy, SetProcessMitigationPolicy,
        };

        // PROCESS_MITIGATION_IMAGE_LOAD_POLICY is a 32-bit flags structure:
        // Bit 0: NoRemoteImages = 1, Bit 1: NoLowMandatoryLabelImages = 1
        let image_load_flags: u32 = 0x3;
        let _ = SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            &image_load_flags as *const u32 as *const _,
            std::mem::size_of::<u32>(),
        );

        // MicrosoftSignedOnly would block the unsigned community MSI from loading
        // non-Microsoft DLLs (including the local-dev toolchain). Enable it only in
        // Authenticode-signed production builds (`require-signed-peers`).
        if REQUIRE_SIGNED_PEERS {
            use windows::Win32::System::Threading::ProcessSignaturePolicy;
            // PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY: MicrosoftSignedOnly = bit 0
            let signature_flags: u32 = 0x1;
            let _ = SetProcessMitigationPolicy(
                ProcessSignaturePolicy,
                &signature_flags as *const u32 as *const _,
                std::mem::size_of::<u32>(),
            );
        }
    }
}

fn normalize_windows_display_path(path: &std::path::Path) -> std::path::PathBuf {
    let raw = path.to_string_lossy();
    if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        std::path::PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

fn assert_daemon_safe_to_elevate(daemon_exe: &std::path::Path) -> Result<(), String> {
    if cfg!(debug_assertions) {
        let _ = daemon_exe;
        return Ok(());
    }

    let path = daemon_exe.to_string_lossy();
    if !is_protected_install_path(&path) {
        return Err(format!(
            "Refusing to elevate '{}' because it is not under %ProgramFiles%\\WinDebloat",
            path
        ));
    }
    // Community builds accept an unsigned daemon from this directory; signed
    // production builds (`require-signed-peers`) still require Authenticode.
    verify_image_authenticode(&path, true).map_err(|e| e.to_string())?;
    Ok(())
}

/// Broadcasts `WM_SETTINGCHANGE` to all top-level desktop windows after Apply (§4.2).
fn broadcast_wm_settingchange() {
    #[cfg(windows)]
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };

        for param in ["Policy\0", "ImmersiveColorSet\0", "Environment\0"] {
            let w: Vec<u16> = param.encode_utf16().collect();
            let mut result = 0usize;
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(PCWSTR(w.as_ptr()).0 as isize),
                SMTO_ABORTIFHUNG,
                1000,
                Some(&mut result),
            );
        }
    }
}

/// Spawns `windebloat-daemon.exe` via `ShellExecuteExW(runas)` and establishes the authenticated Named Pipe channel (§2.1.1).
fn ensure_daemon_connected(state: &AppState) -> Result<File, String> {
    let mut guard = state.daemon_pipe.lock().map_err(|e| e.to_string())?;
    if let Some(existing) = guard.as_mut() {
        // Test if pipe is still alive with Ping
        if send_daemon_request(existing, &IpcRequest::Ping).is_ok() {
            return existing.try_clone().map_err(|e| e.to_string());
        }
        *guard = None;
    }

    ipc_debug_log("ui", "===== ensure_daemon_connected =====");
    match query_process_token_debug() {
        Ok(dbg) => ipc_debug_log("ui", &format!("ui token: {dbg}")),
        Err(e) => ipc_debug_log("ui", &format!("ui token query failed: {e}")),
    }
    ipc_debug_log(
        "ui",
        &format!(
            "state session_luid={} user_sid={} ui_log={}",
            state.session_luid,
            state.user_sid,
            ipc_debug_log_path("ui").display()
        ),
    );

    let nonce = generate_256bit_nonce();
    let pipe_name = pipe_name_for_session(&state.session_luid);
    ipc_debug_log("ui", &format!("pipe_name={pipe_name} nonce_prefix={}", nonce.chars().take(8).collect::<String>()));

    // Locate windebloat-daemon.exe next to current executable
    let cur_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let candidate_exe = cur_exe
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("windebloat-daemon.exe");

    if !candidate_exe.exists() {
        return Err(format!(
            "windebloat-daemon.exe not found at '{}'",
            candidate_exe.display()
        ));
    }

    let canon_exe = candidate_exe
        .canonicalize()
        .map_err(|e| format!("Failed to resolve '{}': {}", candidate_exe.display(), e))?;
    let daemon_exe = normalize_windows_display_path(&canon_exe);

    ipc_debug_log("ui", &format!("daemon_exe={}", daemon_exe.display()));
    match assert_daemon_safe_to_elevate(&daemon_exe) {
        Ok(()) => ipc_debug_log("ui", "assert_daemon_safe_to_elevate ok"),
        Err(e) => {
            ipc_debug_log("ui", &format!("assert_daemon_safe_to_elevate failed: {e}"));
            return Err(e);
        }
    }

    let dev_flag = if cfg!(debug_assertions) {
        " --dev-no-verify"
    } else {
        ""
    };
    let params = format!(
        "--nonce {} --session-luid {} --user-sid {} --client-pid {}{}",
        nonce,
        state.session_luid,
        state.user_sid,
        std::process::id(),
        dev_flag
    );

    let daemon_process = unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW, SEE_MASK_NOCLOSEPROCESS};
        use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

        let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
        let file_w: Vec<u16> = format!("{}\0", daemon_exe.display()).encode_utf16().collect();
        let params_w: Vec<u16> = format!("{}\0", params).encode_utf16().collect();

        let mut sei = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(file_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            nShow: SW_HIDE.0 as i32,
            ..Default::default()
        };

        ShellExecuteExW(&mut sei).map_err(|e| format!("UAC elevation cancelled or failed: {}", e))?;
        ipc_debug_log("ui", "ShellExecuteExW(runas) succeeded");
        sei.hProcess
    };

    // Connect to the named pipe with retry while daemon starts up.
    // STILL_ACTIVE (259): GetExitCodeProcess returns this while the process is running.
    const STILL_ACTIVE: u32 = 259;
    let mut last_open_err = None;
    let mut pipe_file = None;
    for attempt in 0..40 {
        match OpenOptions::new().read(true).write(true).open(&pipe_name) {
            Ok(f) => {
                ipc_debug_log("ui", &format!("pipe open succeeded on attempt {attempt}"));
                pipe_file = Some(f);
                break;
            }
            Err(e) => {
                if attempt == 0 || attempt == 39 || attempt % 10 == 0 {
                    ipc_debug_log(
                        "ui",
                        &format!(
                            "pipe open attempt {attempt} failed: {e} kind={:?} raw={:?}",
                            e.kind(),
                            e.raw_os_error()
                        ),
                    );
                }
                last_open_err = Some(e);
            }
        }
        if !daemon_process.is_invalid() {
            let mut code = 0u32;
            let exited = unsafe {
                use windows::Win32::System::Threading::GetExitCodeProcess;
                GetExitCodeProcess(daemon_process, &mut code).is_ok() && code != STILL_ACTIVE
            };
            if exited {
                unsafe {
                    use windows::Win32::Foundation::CloseHandle;
                    let _ = CloseHandle(daemon_process);
                }
                let detail = last_open_err
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "pipe not opened".to_string());
                ipc_debug_log("ui", &format!("daemon exited {code} before pipe ready; {detail}"));
                return Err(format!(
                    "Elevated daemon exited before the pipe was ready (exit {code}). Last pipe error: {detail}. UI log: {}  Daemon log: {}",
                    ipc_debug_log_path("ui").display(),
                    ipc_debug_log_path("daemon").display()
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    if !daemon_process.is_invalid() {
        unsafe {
            use windows::Win32::Foundation::CloseHandle;
            let _ = CloseHandle(daemon_process);
        }
    }

    let mut file = pipe_file.ok_or_else(|| {
        let detail = last_open_err
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "pipe not opened".to_string());
        ipc_debug_log("ui", &format!("timeout opening {pipe_name}: {detail}"));
        format!(
            "Timed out waiting for elevated daemon pipe '{pipe_name}': {detail}\nUI log: {}\nDaemon log: {}",
            ipc_debug_log_path("ui").display(),
            ipc_debug_log_path("daemon").display()
        )
    })?;

    // Send ClientHandshake
    let handshake = ClientHandshake {
        nonce,
        user_sid: state.user_sid.clone(),
        session_luid: state.session_luid.clone(),
    };
    let mut hs_bytes = serde_json::to_vec(&handshake).map_err(|e| e.to_string())?;
    hs_bytes.push(b'\n');
    file.write_all(&hs_bytes).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(file.try_clone().map_err(|e| e.to_string())?);
    let mut ack_line = String::new();
    reader
        .read_line(&mut ack_line)
        .map_err(|e| e.to_string())?;
    let ack: IpcResponse = serde_json::from_str(&ack_line).map_err(|e| e.to_string())?;
    if let IpcResponse::Error(err) = ack {
        return Err(format!("Daemon handshake rejected: {}", err));
    }

    let cloned = file.try_clone().map_err(|e| e.to_string())?;
    *guard = Some(file);
    Ok(cloned)
}

fn send_daemon_request(pipe: &mut File, req: &IpcRequest) -> Result<IpcResponse, String> {
    let mut bytes = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    pipe.write_all(&bytes).map_err(|e| e.to_string())?;
    pipe.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(pipe.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("Daemon closed pipe unexpectedly".to_string());
    }
    let resp: IpcResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    if let IpcResponse::Error(msg) = resp {
        return Err(msg);
    }
    Ok(resp)
}

fn create_local_engine(sandbox: bool) -> (Option<ExecutionEngine<SandboxOsBackend>>, Option<ExecutionEngine<WindowsOsBackend>>) {
    let journal_path = default_journal_path();
    if sandbox {
        let state_path = std::env::temp_dir()
            .join("WinDebloatSandbox")
            .join("sandbox_os_state.json");
        let backend = SandboxOsBackend::load_or_default(&state_path);
        (Some(ExecutionEngine::new(backend, journal_path)), None)
    } else {
        let backend = WindowsOsBackend::new();
        (None, Some(ExecutionEngine::new(backend, journal_path)))
    }
}

fn build_bootstrap_payload(state: &AppState) -> Result<UiBootstrapPayload, String> {
    let sandbox = *state.sandbox_mode.lock().map_err(|e| e.to_string())?;
    let (sb_eng, win_eng) = create_local_engine(sandbox);
    let (environment, pending_reboot) = if let Some(eng) = sb_eng {
        (eng.backend.environment(), eng.backend.check_pending_reboot())
    } else if let Some(eng) = win_eng {
        (eng.backend.environment(), eng.backend.check_pending_reboot())
    } else {
        unreachable!()
    };

    let bundles = state.bundles.lock().map_err(|e| e.to_string())?.clone();
    let custom_bundle_sources = state
        .custom_sources
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    let profiles = load_embedded_profiles();

    Ok(UiBootstrapPayload {
        app_version: windebloat_schema::APP_DISPLAY_VERSION.to_string(),
        user_sid: state.user_sid.clone(),
        session_luid: state.session_luid.clone(),
        environment,
        pending_reboot,
        bundles,
        profiles,
        custom_bundle_sources,
        sandbox_mode: sandbox,
    })
}

#[tauri::command]
async fn get_bootstrap_data(state: State<'_, AppState>) -> Result<UiBootstrapPayload, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || build_bootstrap_payload(&st))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn set_sandbox_mode(enabled: bool, state: State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.sandbox_mode.lock().map_err(|e| e.to_string())?;
    *guard = enabled;
    Ok(*guard)
}

#[tauri::command]
async fn probe_all_bundles(state: State<'_, AppState>) -> Result<Vec<BundleProbeStatus>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sandbox = *st.sandbox_mode.lock().map_err(|e| e.to_string())?;
        let bundles = st.bundles.lock().map_err(|e| e.to_string())?.clone();
        let scope = TargetScope::Sid(st.user_sid.clone());

        let (sb_eng, win_eng) = create_local_engine(sandbox);
        let mut results = Vec::with_capacity(bundles.len());
        for b in &bundles {
            let status = if let Some(ref eng) = sb_eng {
                eng.probe_bundle(b, &scope).map_err(|e| e.to_string())?
            } else if let Some(ref eng) = win_eng {
                eng.probe_bundle(b, &scope).map_err(|e| e.to_string())?
            } else {
                unreachable!()
            };
            results.push(status);
        }
        Ok(results)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_dry_run(
    bundle_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<DryRunReport, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sandbox = *st.sandbox_mode.lock().map_err(|e| e.to_string())?;
        let all_bundles = st.bundles.lock().map_err(|e| e.to_string())?.clone();
        let selected: Vec<Bundle> = all_bundles
            .into_iter()
            .filter(|b| bundle_ids.contains(&b.id))
            .collect();
        let scope = TargetScope::Sid(st.user_sid.clone());

        let (sb_eng, win_eng) = create_local_engine(sandbox);
        if let Some(eng) = sb_eng {
            eng.dry_run(&selected, &scope, ExecutionContext::Interactive)
                .map_err(|e| e.to_string())
        } else if let Some(eng) = win_eng {
            eng.dry_run(&selected, &scope, ExecutionContext::Interactive)
                .map_err(|e| e.to_string())
        } else {
            unreachable!()
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn apply_selected_bundles(
    bundle_ids: Vec<String>,
    window: tauri::Window,
    state: State<'_, AppState>,
) -> Result<ApplySummary, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sandbox = *st.sandbox_mode.lock().map_err(|e| e.to_string())?;

        let summary = if sandbox {
            let all_bundles = st.bundles.lock().map_err(|e| e.to_string())?.clone();
            let selected: Vec<Bundle> = all_bundles
                .into_iter()
                .filter(|b| bundle_ids.contains(&b.id))
                .collect();
            let scope = TargetScope::Sid(st.user_sid.clone());
            let (Some(mut sb_eng), _) = create_local_engine(true) else {
                return Err("Failed to initialize sandbox engine".to_string());
            };
            sb_eng
                .apply_bundles(&selected, &scope, ExecutionContext::Interactive, |ev| {
                    let _ = window.emit("windebloat://apply-progress", ev);
                })
                .map_err(|e| e.to_string())?
        } else {
            // Connect to elevated daemon via UAC and stream events over the named pipe (§2.1, §6)
            let mut pipe = ensure_daemon_connected(&st)?;
            let req = IpcRequest::ApplyBundles {
                bundle_ids,
                target_sid: st.user_sid.clone(),
            };
            let mut bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
            bytes.push(b'\n');
            pipe.write_all(&bytes).map_err(|e| e.to_string())?;
            pipe.flush().map_err(|e| e.to_string())?;

            let mut reader = BufReader::new(pipe);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("Elevated daemon closed connection during Apply".to_string());
                }
                let resp: IpcResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;
                match resp {
                    IpcResponse::ApplyProgress(ev) => {
                        let _ = window.emit("windebloat://apply-progress", &ev);
                    }
                    IpcResponse::ApplyComplete(sum) => break sum,
                    IpcResponse::Error(err) => return Err(err),
                    _ => {}
                }
            }
        };

        // §4.2 Desktop refresh: UI broadcasts WM_SETTINGCHANGE after run
        broadcast_wm_settingchange();
        Ok(summary)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_journal_history(state: State<'_, AppState>) -> Result<Vec<JournalEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let path = default_journal_path();
        match JournalFile::load_or_create(&path) {
            Ok(mut j) => {
                j.entries.sort_by(|a, b| b.applied_at.cmp(&a.applied_at));
                return Ok(j.entries);
            }
            Err(local_err) => {
                // If an elevated daemon pipe is already connected, query the journal through it
                if let Ok(mut guard) = st.daemon_pipe.lock() {
                    if let Some(pipe) = guard.as_mut() {
                        if let Ok(IpcResponse::JournalEntries(mut entries)) =
                            send_daemon_request(pipe, &IpcRequest::GetJournal)
                        {
                            entries.sort_by(|a, b| b.applied_at.cmp(&a.applied_at));
                            return Ok(entries);
                        }
                    }
                }
                ipc_debug_log(
                    "ui",
                    &format!("get_journal_history local read failed: {local_err}"),
                );
                Ok(Vec::new())
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn check_drift_report(state: State<'_, AppState>) -> Result<Vec<DriftReportItem>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sandbox = *st.sandbox_mode.lock().map_err(|e| e.to_string())?;
        let bundles = st.bundles.lock().map_err(|e| e.to_string())?.clone();
        let (sb_eng, win_eng) = create_local_engine(sandbox);
        let res = if let Some(eng) = sb_eng {
            eng.check_drift(&bundles)
        } else if let Some(eng) = win_eng {
            eng.check_drift(&bundles)
        } else {
            unreachable!()
        };
        match res {
            Ok(items) => Ok(items),
            Err(local_err) => {
                if !sandbox {
                    if let Ok(mut guard) = st.daemon_pipe.lock() {
                        if let Some(pipe) = guard.as_mut() {
                            if let Ok(IpcResponse::DriftReport(items)) =
                                send_daemon_request(pipe, &IpcRequest::CheckDrift)
                            {
                                return Ok(items);
                            }
                        }
                    }
                }
                ipc_debug_log(
                    "ui",
                    &format!("check_drift_report local read failed: {local_err}"),
                );
                Ok(Vec::new())
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn undo_journal_item(
    run_id: Option<String>,
    entry_id: Option<String>,
    entry_ids: Option<Vec<String>>,
    force_undo: bool,
    state: State<'_, AppState>,
) -> Result<Vec<UndoItemResult>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sandbox = *st.sandbox_mode.lock().map_err(|e| e.to_string())?;
        if sandbox {
            let bundles = st.bundles.lock().map_err(|e| e.to_string())?.clone();
            let (Some(mut sb_eng), _) = create_local_engine(true) else {
                return Err("Failed to initialize sandbox engine".to_string());
            };
            if let Some(ids) = entry_ids.filter(|v| !v.is_empty()) {
                let mut all_results = Vec::new();
                for id in ids {
                    let mut r = sb_eng
                        .undo_entries(&bundles, None, Some(id.as_str()), force_undo)
                        .map_err(|e| e.to_string())?;
                    all_results.append(&mut r);
                }
                Ok(all_results)
            } else {
                sb_eng
                    .undo_entries(
                        &bundles,
                        run_id.as_deref(),
                        entry_id.as_deref(),
                        force_undo,
                    )
                    .map_err(|e| e.to_string())
            }
        } else {
            let mut pipe = ensure_daemon_connected(&st)?;
            if let Some(ids) = entry_ids.filter(|v| !v.is_empty()) {
                let mut all_results = Vec::new();
                for id in ids {
                    let resp = send_daemon_request(
                        &mut pipe,
                        &IpcRequest::Undo {
                            run_id: None,
                            entry_id: Some(id),
                            force_undo,
                        },
                    )?;
                    match resp {
                        IpcResponse::UndoResults(mut r) => all_results.append(&mut r),
                        _ => return Err("Unexpected response from daemon during undo".to_string()),
                    }
                }
                broadcast_wm_settingchange();
                Ok(all_results)
            } else {
                let resp = send_daemon_request(
                    &mut pipe,
                    &IpcRequest::Undo {
                        run_id,
                        entry_id,
                        force_undo,
                    },
                )?;
                match resp {
                    IpcResponse::UndoResults(r) => {
                        broadcast_wm_settingchange();
                        Ok(r)
                    }
                    _ => Err("Unexpected response from daemon during undo".to_string()),
                }
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn load_custom_manifest_json(
    raw_json: String,
    admin_session_override: bool,
    state: State<'_, AppState>,
) -> Result<UiBootstrapPayload, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let parsed: ManifestFile =
            serde_json::from_str(&raw_json).map_err(|e| format!("Invalid manifest JSON: {}", e))?;
        validate_manifest(&parsed).map_err(|e| format!("Manifest validation failed: {}", e))?;

        let trusted_keys = load_system_trusted_keys();
        let is_trusted = verify_manifest_signature(
            &parsed.bundles,
            parsed.signature.as_deref(),
            &trusted_keys,
        )
        .is_ok();

        if !is_trusted && !admin_session_override {
            return Err(
                "UNSIGNED_MANIFEST: Custom manifest is not signed by a key in HKLM\\SOFTWARE\\Policies\\WinDebloat\\TrustedKeys. Confirm session override to load it with an Untrusted badge."
                    .to_string(),
            );
        }

        let manifest_name = parsed
            .manifest_name
            .unwrap_or_else(|| "Custom Manifest".to_string());

        {
            let mut bundles_guard = st.bundles.lock().map_err(|e| e.to_string())?;
            let mut sources_guard = st.custom_sources.lock().map_err(|e| e.to_string())?;
            for bundle in parsed.bundles {
                sources_guard.insert(
                    bundle.id.clone(),
                    CustomSourceBadge {
                        manifest_name: manifest_name.clone(),
                        trusted: is_trusted,
                    },
                );
                if let Some(pos) = bundles_guard.iter().position(|b| b.id == bundle.id) {
                    bundles_guard[pos] = bundle;
                } else {
                    bundles_guard.push(bundle);
                }
            }
        }

        build_bootstrap_payload(&st)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn open_store_product_page(product_id: String) -> Result<(), String> {
    if !product_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("Invalid Store product_id".to_string());
    }
    let uri = format!("ms-windows-store://pdp/?productid={}", product_id);
    #[cfg(windows)]
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let op_w: Vec<u16> = "open\0".encode_utf16().collect();
        let uri_w: Vec<u16> = format!("{}\0", uri).encode_utf16().collect();
        ShellExecuteW(
            HWND::default(),
            PCWSTR(op_w.as_ptr()),
            PCWSTR(uri_w.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        );
    }
    Ok(())
}

#[tauri::command]
async fn restart_explorer_shell() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "explorer.exe"])
            .status();
        std::process::Command::new("explorer.exe")
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn save_json_export(filename: String, content: String) -> Result<String, String> {
    let safe_name: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let base_dir = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .map(|p| {
            let dl = p.join("Downloads");
            if dl.exists() {
                dl
            } else {
                p
            }
        })
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));

    let _ = std::fs::create_dir_all(&base_dir);
    if safe_name.is_empty()
        || safe_name == "."
        || safe_name == ".."
        || safe_name.contains("..")
    {
        return Err("Invalid export filename".to_string());
    }

    let target_path = base_dir.join(safe_name);
    if target_path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("Export path must stay inside the destination folder".to_string());
    }

    std::fs::write(&target_path, content.as_bytes())
        .map_err(|e| format!("Failed to save '{}': {}", target_path.display(), e))?;

    Ok(target_path.to_string_lossy().to_string())
}

#[tauri::command]
fn reveal_in_explorer(file_path: String) -> Result<(), String> {
    if file_path.contains(',') || file_path.contains('\0') {
        return Err("Invalid path".to_string());
    }
    let path = std::path::PathBuf::from(&file_path);
    let canon = path
        .canonicalize()
        .or_else(|_| {
            path.parent()
                .map(|p| p.canonicalize())
                .transpose()
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "Invalid path".to_string())
        })
        .map_err(|e| e.to_string())?;
    let display_path = normalize_windows_display_path(&canon);
    if display_path.to_string_lossy().contains(',') {
        return Err("Invalid path".to_string());
    }
    if path.exists() {
        std::process::Command::new("explorer.exe")
            .arg(format!("/select,{}", display_path.display()))
            .spawn()
            .map_err(|e| e.to_string())?;
    } else {
        std::process::Command::new("explorer.exe")
            .arg(&display_path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn open_admin_panel(panel_id: String) -> Result<(), String> {
    let (program, args): (&str, &[&str]) = match panel_id.as_str() {
        "ncpa" => ("control.exe", &["ncpa.cpl"]),
        "appwiz" => ("control.exe", &["appwiz.cpl"]),
        "sysdm" => ("control.exe", &["sysdm.cpl"]),
        "mmsys" => ("control.exe", &["mmsys.cpl"]),
        "powercfg" => ("control.exe", &["powercfg.cpl"]),
        "main_mouse" => ("control.exe", &["main.cpl"]),
        "timedate" => ("control.exe", &["timedate.cpl"]),
        "control" => ("control.exe", &[]),
        "services" => ("cmd.exe", &["/C", "start", "", "services.msc"]),
        "devmgmt" => ("cmd.exe", &["/C", "start", "", "devmgmt.msc"]),
        "diskmgmt" => ("cmd.exe", &["/C", "start", "", "diskmgmt.msc"]),
        "taskschd" => ("cmd.exe", &["/C", "start", "", "taskschd.msc"]),
        "compmgmt" => ("cmd.exe", &["/C", "start", "", "compmgmt.msc"]),
        "firewall" => ("cmd.exe", &["/C", "start", "", "wf.msc"]),
        "sysrestore" => ("SystemPropertiesProtection.exe", &[]),
        "resmon" => ("resmon.exe", &[]),
        _ => return Err(format!("Unknown admin panel id '{}'", panel_id)),
    };

    std::process::Command::new(program)
        .args(args)
        .spawn()
        .map_err(|e| format!("Failed to open '{}': {}", panel_id, e))?;
    Ok(())
}

fn main() {
    apply_ui_process_mitigations();

    let (user_sid, session_luid) = match query_current_process_identity() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("WinDebloat cannot start: failed to read process identity: {}", e);
            std::process::exit(1);
        }
    };

    // Startup OS build check (§8: Windows 10 22H2 build 19045 or Windows 11 23H2 build 22631+)
    let env = WindowsOsBackend::new().environment();
    if env.build_number < 19045 {
        eprintln!(
            "WinDebloat requires Windows 10 22H2 (build 19045) or later; detected build {}.",
            env.build_number
        );
        std::process::exit(1);
    }

    let default_sandbox = std::env::var("WINDEBLOAT_SANDBOX").as_deref() == Ok("1");
    let base_manifest = load_embedded_base_manifest();

    let app_state = AppState(std::sync::Arc::new(AppStateInner {
        user_sid,
        session_luid,
        sandbox_mode: Mutex::new(default_sandbox),
        bundles: Mutex::new(base_manifest.bundles),
        custom_sources: Mutex::new(HashMap::new()),
        daemon_pipe: Mutex::new(None),
    }));

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_bootstrap_data,
            set_sandbox_mode,
            probe_all_bundles,
            preview_dry_run,
            apply_selected_bundles,
            get_journal_history,
            check_drift_report,
            undo_journal_item,
            load_custom_manifest_json,
            open_store_product_page,
            restart_explorer_shell,
            save_json_export,
            reveal_in_explorer,
            open_admin_panel,
        ])
        .run(tauri::generate_context!())
        .expect("error while running WinDebloat UI");
}
