use clap::{Parser, Subcommand};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use windebloat_engine::{
    backend::{BackendError, OsBackend},
    journal::{default_journal_path, DriftStatus, ExecutionContext},
    sandbox::SandboxOsBackend,
    target::TargetScope,
    windows_os::WindowsOsBackend,
    EngineError, ExecutionEngine, UndoItemResult,
};
use windebloat_schema::{
    load_embedded_base_manifest, load_embedded_profiles,
    signature::{load_system_trusted_keys, verify_manifest_signature},
    validation::validate_manifest,
    Bundle, ManifestFile, SelectionProfile,
};

#[derive(Debug, Parser)]
#[command(
    name = "windebloat-cli",
    version = windebloat_schema::APP_DISPLAY_VERSION,
    about = "Headless SYSTEM/Enterprise CLI for WinDebloat"
)]
struct Cli {
    /// Optional path to write structured JSONL log lines (§7.2)
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,

    /// Optional override for journal.json path
    #[arg(long, global = true)]
    journal_path: Option<PathBuf>,

    /// Run against the safe local sandbox OS backend instead of mutating live Windows state
    #[arg(long, global = true)]
    sandbox: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Apply a selection profile (§7.1: 0 success, 3010 reboot required, 1 failure, 2 invalid input, 3 pending reboot)
    Apply {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        target_user: String,
    },
    /// Intune Win32 app detection rule probe (§7.1: 0 fully applied, 1 not applied)
    Detect {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        target_user: String,
    },
    /// Emit section 5.3 drift classification (§7.1: 0 no drift, 4 drift found)
    Drift {
        #[arg(long)]
        json: bool,
    },
    /// Reverse a run; automatic tier only (§7.1: 0 success, 1 failure/conflict)
    Undo {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        force_undo: bool,
    },
    /// Print the delta without changes (§7.1: 0)
    DryRun {
        #[arg(long)]
        profile: String,
        #[arg(long, default_value = "all-profiles")]
        target_user: String,
    },
    /// Schema, denylist and signature check (§7.1: 0 valid, 2 invalid)
    VerifyManifest {
        file: PathBuf,
        /// Optional hex-encoded Ed25519 public key for verification
        #[arg(long)]
        trusted_key: Option<String>,
        /// Require valid Ed25519 signature in addition to schema & denylist
        #[arg(long)]
        require_signature: bool,
    },
}

/// Structured JSONL log line emitted per SDS v3 §7.2.
#[derive(Debug, Serialize)]
struct JsonlLogRecord<'a> {
    schema_version: u32,
    timestamp: String,
    run_id: &'a str,
    machine_name: &'a str,
    bundle_id: &'a str,
    action_index: usize,
    action: &'a str,
    target: &'a str,
    state: String,
    error: Option<&'a str>,
}

fn emit_jsonl_line<T: Serialize>(record: &T, log_file: Option<&Path>) {
    if let Ok(line) = serde_json::to_string(record) {
        println!("{}", line);
        if let Some(p) = log_file {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }
}

fn load_profile_by_arg(profile_arg: &str) -> Result<SelectionProfile, String> {
    let path = Path::new(profile_arg);
    if path.exists() {
        let raw = fs::read_to_string(path).map_err(|e| format!("Failed to read profile: {}", e))?;
        return serde_json::from_str::<SelectionProfile>(&raw)
            .map_err(|e| format!("Invalid profile JSON: {}", e));
    }

    // Also allow built-in preset IDs ("minimal", "privacy", "gamer", "enterprise")
    let presets = load_embedded_profiles();
    if let Some(found) = presets
        .into_iter()
        .find(|p| p.id.eq_ignore_ascii_case(profile_arg.trim()))
    {
        return Ok(found);
    }

    Err(format!(
        "Profile '{}' not found as file or built-in preset",
        profile_arg
    ))
}

fn resolve_profile_bundles(profile: &SelectionProfile) -> Result<Vec<Bundle>, String> {
    let base = load_embedded_base_manifest();
    let mut catalog: HashMap<String, Bundle> =
        base.bundles.into_iter().map(|b| (b.id.clone(), b)).collect();

    // §3.4 & §7.2: Custom manifests in CLI/SYSTEM mode MUST be signed by a key in HKLM\SOFTWARE\Policies\WinDebloat\TrustedKeys
    let trusted_keys = load_system_trusted_keys();
    for custom_path in &profile.custom_manifests {
        let raw = fs::read_to_string(custom_path)
            .map_err(|e| format!("Failed to read custom manifest '{}': {}", custom_path, e))?;
        let custom_manifest: ManifestFile = serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid custom manifest JSON '{}': {}", custom_path, e))?;
        validate_manifest(&custom_manifest)
            .map_err(|e| format!("Custom manifest validation failed: {}", e))?;
        verify_manifest_signature(
            &custom_manifest.bundles,
            custom_manifest.signature.as_deref(),
            &trusted_keys,
        )
        .map_err(|e| {
            format!(
                "Headless CLI refuses unsigned/untrusted custom manifest '{}': {}",
                custom_path, e
            )
        })?;

        for b in custom_manifest.bundles {
            catalog.insert(b.id.clone(), b);
        }
    }

    let mut selected = Vec::new();
    for bid in &profile.bundles {
        let b = catalog
            .get(bid)
            .ok_or_else(|| format!("Profile references unknown bundle ID '{}'", bid))?;
        selected.push(b.clone());
    }
    Ok(selected)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let journal_path = cli.journal_path.clone().unwrap_or_else(default_journal_path);
    let use_sandbox = cli.sandbox || std::env::var("WINDEBLOAT_SANDBOX").as_deref() == Ok("1");

    let sandbox_state_path = std::env::temp_dir()
        .join("WinDebloatSandbox")
        .join("sandbox_os_state.json");

    let code = if use_sandbox {
        let backend = SandboxOsBackend::load_or_default(&sandbox_state_path);
        let engine = ExecutionEngine::new(backend, journal_path);
        execute_cli_command(engine, &cli)
    } else {
        let backend = WindowsOsBackend::new();
        let engine = ExecutionEngine::new(backend, journal_path);
        execute_cli_command(engine, &cli)
    };

    // Note: Windows process exit codes are 32-bit (`u32`, e.g. 3010 for ERROR_SUCCESS_REBOOT_REQUIRED).
    if code == 3010 {
        std::process::exit(3010);
    }
    ExitCode::from(code as u8)
}

fn execute_cli_command<B: OsBackend>(mut engine: ExecutionEngine<B>, cli: &Cli) -> i32 {
    let machine_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "LOCALHOST".to_string());

    match &cli.command {
        Commands::VerifyManifest {
            file,
            trusted_key,
            require_signature,
        } => {
            let Ok(raw) = fs::read_to_string(file) else {
                eprintln!("Error: Failed to read manifest file '{}'", file.display());
                return 2;
            };
            let parsed: ManifestFile = match serde_json::from_str(&raw) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Schema parse error: {}", e);
                    return 2;
                }
            };
            if let Err(e) = validate_manifest(&parsed) {
                eprintln!("Manifest validation error: {}", e);
                return 2;
            }
            if *require_signature || parsed.signature.is_some() {
                let mut keys = load_system_trusted_keys();
                if let Some(k) = trusted_key {
                    keys.push(k.clone());
                }
                if let Err(e) = verify_manifest_signature(
                    &parsed.bundles,
                    parsed.signature.as_deref(),
                    &keys,
                ) {
                    eprintln!("Manifest signature verification failed: {}", e);
                    return 2;
                }
            }
            println!(
                "{{\"status\":\"valid\",\"manifest_version\":{},\"bundle_count\":{}}}",
                parsed.manifest_version,
                parsed.bundles.len()
            );
            0
        }

        Commands::DryRun {
            profile,
            target_user,
        } => {
            let prof = match load_profile_by_arg(profile) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let bundles = match resolve_profile_bundles(&prof) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let scope = match TargetScope::parse_cli(target_user) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            match engine.dry_run(&bundles, &scope, ExecutionContext::Headless) {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    0
                }
                Err(EngineError::ManualAssistedRefusedInHeadless { .. }) => {
                    eprintln!("Error: Profile contains manual_assisted undo actions, which are refused in headless/SYSTEM mode.");
                    2
                }
                Err(e) => {
                    eprintln!("Dry-run failed: {}", e);
                    1
                }
            }
        }

        Commands::Apply {
            profile,
            target_user,
        } => {
            let prof = match load_profile_by_arg(profile) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let bundles = match resolve_profile_bundles(&prof) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let scope = match TargetScope::parse_cli(target_user) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };

            let log_path = cli.log_file.as_deref();
            let res = engine.apply_bundles(
                &bundles,
                &scope,
                ExecutionContext::Headless,
                |ev| {
                    let rec = JsonlLogRecord {
                        schema_version: 1,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        run_id: &ev.run_id,
                        machine_name: &machine_name,
                        bundle_id: &ev.bundle_id,
                        action_index: ev.action_index,
                        action: &ev.action_type,
                        target: &ev.target,
                        state: format!("{:?}", ev.state),
                        error: ev.error.as_deref(),
                    };
                    emit_jsonl_line(&rec, log_path);
                },
            );

            match res {
                Ok(summary) => {
                    if summary.failed_count > 0 {
                        1
                    } else if summary.requires_reboot {
                        3010
                    } else {
                        0
                    }
                }
                Err(EngineError::ManualAssistedRefusedInHeadless {
                    bundle_id,
                    action_index,
                }) => {
                    eprintln!(
                        "Refused at plan time: bundle '{}' action #{} uses manual_assisted undo tier",
                        bundle_id, action_index
                    );
                    2
                }
                Err(EngineError::Backend(BackendError::PendingReboot(reason))) => {
                    eprintln!("Blocked by pending reboot: {}", reason);
                    3
                }
                Err(EngineError::TargetResolution(e)) => {
                    eprintln!("Invalid input: {}", e);
                    2
                }
                Err(e) => {
                    eprintln!("Apply error: {}", e);
                    1
                }
            }
        }

        Commands::Detect {
            profile,
            target_user,
        } => {
            let prof = match load_profile_by_arg(profile) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let bundles = match resolve_profile_bundles(&prof) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };
            let scope = match TargetScope::parse_cli(target_user) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", e);
                    return 2;
                }
            };

            match engine.detect_profile(&bundles, &scope) {
                Ok(true) => {
                    println!("{{\"detected\":true}}");
                    0
                }
                Ok(false) => {
                    println!("{{\"detected\":false}}");
                    1
                }
                Err(e) => {
                    eprintln!("Detect error: {}", e);
                    1
                }
            }
        }

        Commands::Drift { json } => {
            let base = load_embedded_base_manifest();
            match engine.check_drift(&base.bundles) {
                Ok(items) => {
                    let has_drift = items.iter().any(|i| {
                        matches!(i.status, DriftStatus::Reverted | DriftStatus::ChangedByOther)
                    });
                    if *json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&items).unwrap_or_default()
                        );
                    } else {
                        for item in &items {
                            println!(
                                "[{:?}] {} (action #{}) -> {}",
                                item.status, item.bundle_id, item.action_index, item.target
                            );
                        }
                    }
                    if has_drift {
                        4
                    } else {
                        0
                    }
                }
                Err(e) => {
                    eprintln!("Drift check failed: {}", e);
                    1
                }
            }
        }

        Commands::Undo { run_id, force_undo } => {
            let base = load_embedded_base_manifest();
            match engine.undo_entries(&base.bundles, Some(run_id.as_str()), None, *force_undo) {
                Ok(results) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&results).unwrap_or_default()
                    );
                    let any_conflict_or_unhandled = results.iter().any(|r| {
                        matches!(
                            r,
                            UndoItemResult::Conflict { .. }
                                | UndoItemResult::ManualAssisted { .. }
                                | UndoItemResult::Irreversible { .. }
                        )
                    });
                    if any_conflict_or_unhandled {
                        1
                    } else {
                        0
                    }
                }
                Err(e) => {
                    eprintln!("Undo failed: {}", e);
                    1
                }
            }
        }
    }
}
