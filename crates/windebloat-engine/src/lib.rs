pub mod backend;
pub mod gating;
pub mod journal;
pub mod lock;
pub mod sandbox;
pub mod target;
#[cfg(windows)]
pub mod windows_os;

use backend::{BackendError, OsBackend};
use gating::{evaluate_bundle_gating, GatingResult, OsEnvironment};
use journal::{
    classify_drift, ActionState, DriftReportItem, ExecutionContext, JournalEntry,
    JournalError, JournalFile, TargetState,
};
use lock::{ConcurrencyError, RunLockGuard};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use target::{resolve_action_targets, TargetResolutionError, TargetScope};
use thiserror::Error;
use uuid::Uuid;
use windebloat_schema::{
    denylist::check_bundle_against_denylist, Action, Bundle, BundlePolicy, UndoRoute, UndoTier,
};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Concurrency(#[from] ConcurrencyError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    TargetResolution(#[from] TargetResolutionError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error("Bundle '{0}' not found in loaded manifests")]
    UnknownBundle(String),
    #[error("Headless/SYSTEM run refused bundle '{bundle_id}' action #{action_index}: manual_assisted undo tier is prohibited in headless mode")]
    ManualAssistedRefusedInHeadless {
        bundle_id: String,
        action_index: usize,
    },
    #[error("Action blocked by OS preservation denylist: {0}")]
    Denylist(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProgressEvent {
    pub run_id: String,
    pub bundle_id: String,
    pub action_index: usize,
    pub action_type: String,
    pub target: String,
    pub state: ActionState,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunActionDelta {
    pub action_index: usize,
    pub action_type: String,
    pub target: String,
    pub current_state: TargetState,
    pub planned_state: ActionState,
    pub undo_tier: UndoTier,
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunBundleDelta {
    pub bundle_id: String,
    pub display_name: String,
    pub gating: GatingResult,
    pub explorer_restart: bool,
    pub reboot: bool,
    pub actions: Vec<DryRunActionDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunReport {
    pub environment: OsEnvironment,
    pub pending_reboot_blocker: Option<String>,
    pub bundles: Vec<DryRunBundleDelta>,
    pub estimated_applied_count: usize,
    pub estimated_skipped_count: usize,
    pub requires_explorer_restart: bool,
    pub requires_reboot: bool,
    pub has_irreversible_actions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplySummary {
    pub run_id: String,
    pub events: Vec<ActionProgressEvent>,
    pub verified_count: usize,
    pub skipped_count: usize,
    pub failed_count: usize,
    pub rolled_back_count: usize,
    pub requires_explorer_restart: bool,
    pub requires_reboot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum UndoItemResult {
    Restored {
        entry_id: String,
        target: String,
    },
    Conflict {
        entry_id: String,
        target: String,
        written: TargetState,
        current: TargetState,
        prior: TargetState,
    },
    ManualAssisted {
        entry_id: String,
        target: String,
        route: Option<UndoRoute>,
        store_uri: Option<String>,
        product_id: Option<String>,
        package_id: Option<String>,
    },
    Irreversible {
        entry_id: String,
        target: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProbeStatus {
    pub bundle_id: String,
    pub gating: GatingResult,
    pub is_fully_applied: bool,
    pub action_states: Vec<(String, TargetState, bool)>,
}

pub struct ExecutionEngine<B: OsBackend> {
    pub backend: B,
    pub journal_path: PathBuf,
}

impl<B: OsBackend> ExecutionEngine<B> {
    pub fn new(backend: B, journal_path: PathBuf) -> Self {
        Self {
            backend,
            journal_path,
        }
    }

    /// Probes a single bundle across `scope` without mutating state.
    pub fn probe_bundle(
        &self,
        bundle: &Bundle,
        scope: &TargetScope,
    ) -> Result<BundleProbeStatus, EngineError> {
        let env = self.backend.environment();
        let gating = evaluate_bundle_gating(bundle, &env);
        if !gating.applicable {
            return Ok(BundleProbeStatus {
                bundle_id: bundle.id.clone(),
                gating,
                is_fully_applied: false,
                action_states: Vec::new(),
            });
        }

        let profiles = self.backend.list_user_profiles(scope)?;
        let mut action_states = Vec::new();
        let mut all_satisfied = true;

        for action in &bundle.actions {
            let targets = resolve_action_targets(action, scope, &profiles)?;
            for target in targets {
                let current = self.backend.probe_target(action, &target)?;
                let satisfied = self.backend.is_target_state_satisfied(action, &current);
                if !satisfied {
                    all_satisfied = false;
                }
                action_states.push((target, current, satisfied));
            }
        }

        Ok(BundleProbeStatus {
            bundle_id: bundle.id.clone(),
            gating,
            is_fully_applied: all_satisfied && !action_states.is_empty(),
            action_states,
        })
    }

    /// Computes the `--dry-run` / Review screen delta without mutating the OS or journal (§6, §7.1).
    pub fn dry_run(
        &self,
        bundles: &[Bundle],
        scope: &TargetScope,
        context: ExecutionContext,
    ) -> Result<DryRunReport, EngineError> {
        let env = self.backend.environment();
        let pending_reboot = self.backend.check_pending_reboot();
        let profiles = self.backend.list_user_profiles(scope)?;

        let mut bundle_deltas = Vec::new();
        let mut estimated_applied_count = 0;
        let mut estimated_skipped_count = 0;
        let mut requires_explorer_restart = false;
        let mut requires_reboot = false;
        let mut has_irreversible_actions = false;

        for bundle in bundles {
            check_bundle_against_denylist(bundle)
                .map_err(|e| EngineError::Denylist(e.to_string()))?;

            if context == ExecutionContext::Headless {
                for (idx, act) in bundle.actions.iter().enumerate() {
                    if act.undo().tier == UndoTier::ManualAssisted {
                        return Err(EngineError::ManualAssistedRefusedInHeadless {
                            bundle_id: bundle.id.clone(),
                            action_index: idx,
                        });
                    }
                }
            }

            let gating = evaluate_bundle_gating(bundle, &env);
            let mut action_deltas = Vec::new();
            let mut bundle_will_apply_any = false;

            if !gating.applicable {
                for (idx, action) in bundle.actions.iter().enumerate() {
                    let targets = resolve_action_targets(action, scope, &profiles)?;
                    for target in targets {
                        estimated_skipped_count += 1;
                        action_deltas.push(DryRunActionDelta {
                            action_index: idx,
                            action_type: action.action_type_name().to_string(),
                            target,
                            current_state: TargetState::NotApplicable,
                            planned_state: ActionState::Skipped,
                            undo_tier: action.undo().tier,
                            skip_reason: gating.skip_reason.clone(),
                        });
                    }
                }
            } else {
                for (idx, action) in bundle.actions.iter().enumerate() {
                    let targets = resolve_action_targets(action, scope, &profiles)?;
                    for target in targets {
                        let current = self.backend.probe_target(action, &target)?;
                        let already_satisfied =
                            self.backend.is_target_state_satisfied(action, &current);
                        if already_satisfied {
                            estimated_skipped_count += 1;
                            action_deltas.push(DryRunActionDelta {
                                action_index: idx,
                                action_type: action.action_type_name().to_string(),
                                target,
                                current_state: current,
                                planned_state: ActionState::Skipped,
                                undo_tier: action.undo().tier,
                                skip_reason: Some("Target already in desired state".to_string()),
                            });
                        } else {
                            estimated_applied_count += 1;
                            bundle_will_apply_any = true;
                            if action.undo().tier == UndoTier::None {
                                has_irreversible_actions = true;
                            }
                            action_deltas.push(DryRunActionDelta {
                                action_index: idx,
                                action_type: action.action_type_name().to_string(),
                                target,
                                current_state: current,
                                planned_state: ActionState::Planned,
                                undo_tier: action.undo().tier,
                                skip_reason: None,
                            });
                        }
                    }
                }
            }

            if bundle_will_apply_any {
                if bundle.ui_impact.explorer_restart {
                    requires_explorer_restart = true;
                }
                if bundle.ui_impact.reboot {
                    requires_reboot = true;
                }
            }

            bundle_deltas.push(DryRunBundleDelta {
                bundle_id: bundle.id.clone(),
                display_name: bundle.display_name.clone(),
                gating,
                explorer_restart: bundle.ui_impact.explorer_restart,
                reboot: bundle.ui_impact.reboot,
                actions: action_deltas,
            });
        }

        Ok(DryRunReport {
            environment: env,
            pending_reboot_blocker: pending_reboot,
            bundles: bundle_deltas,
            estimated_applied_count,
            estimated_skipped_count,
            requires_explorer_restart,
            requires_reboot,
            has_irreversible_actions,
        })
    }

    /// Executes selected `bundles` through the 7-state machine (`Planned → Captured → Applied → Verified`,
    /// or `Skipped`, `Failed`, `RolledBack`) with full journal persistence (§4.1).
    pub fn apply_bundles<F>(
        &mut self,
        bundles: &[Bundle],
        scope: &TargetScope,
        context: ExecutionContext,
        mut on_event: F,
    ) -> Result<ApplySummary, EngineError>
    where
        F: FnMut(&ActionProgressEvent),
    {
        // 1. Pre-flight validation: denylist, headless manual_assisted check, and DISM pending reboot check
        for bundle in bundles {
            check_bundle_against_denylist(bundle)
                .map_err(|e| EngineError::Denylist(e.to_string()))?;

            if context == ExecutionContext::Headless {
                for (idx, act) in bundle.actions.iter().enumerate() {
                    if act.undo().tier == UndoTier::ManualAssisted {
                        return Err(EngineError::ManualAssistedRefusedInHeadless {
                            bundle_id: bundle.id.clone(),
                            action_index: idx,
                        });
                    }
                }
            }

            let uses_dism = bundle.actions.iter().any(|a| {
                matches!(
                    a,
                    Action::AppxProvisionedRemove { .. }
                        | Action::CapabilityRemove { .. }
                        | Action::OptionalFeature { .. }
                )
            });
            if uses_dism {
                if let Some(reason) = self.backend.check_pending_reboot() {
                    return Err(EngineError::Backend(BackendError::PendingReboot(reason)));
                }
            }
        }

        // 2. Acquire machine-wide run lock before `Captured` (§4.3)
        let _run_lock = RunLockGuard::acquire()?;
        let mut journal = JournalFile::load_or_create(&self.journal_path)?;
        let env = self.backend.environment();
        let profiles = self.backend.list_user_profiles(scope)?;
        let run_id = Uuid::new_v4().to_string();

        let mut events = Vec::new();
        let mut verified_count = 0;
        let mut skipped_count = 0;
        let mut failed_count = 0;
        let mut rolled_back_count = 0;
        let mut requires_explorer_restart = false;
        let mut requires_reboot = false;

        for bundle in bundles {
            let gating = evaluate_bundle_gating(bundle, &env);
            if !gating.applicable {
                for (idx, action) in bundle.actions.iter().enumerate() {
                    let targets = resolve_action_targets(action, scope, &profiles)?;
                    for target in targets {
                        skipped_count += 1;
                        let ev = ActionProgressEvent {
                            run_id: run_id.clone(),
                            bundle_id: bundle.id.clone(),
                            action_index: idx,
                            action_type: action.action_type_name().to_string(),
                            target,
                            state: ActionState::Skipped,
                            error: gating.skip_reason.clone(),
                        };
                        on_event(&ev);
                        events.push(ev);
                    }
                }
                continue;
            }

            // Track applied actions within this bundle in case `abort_on_fail` triggers a rollback
            let mut applied_in_bundle: Vec<(usize, Action, String, TargetState, String)> =
                Vec::new();
            let mut bundle_failed = false;
            let mut bundle_applied_any = false;

            'action_loop: for (idx, action) in bundle.actions.iter().enumerate() {
                let targets = resolve_action_targets(action, scope, &profiles)?;
                for target in targets {
                    // Probe current state first
                    let current = match self.backend.probe_target(action, &target) {
                        Ok(st) => st,
                        Err(e) => {
                            failed_count += 1;
                            let ev = ActionProgressEvent {
                                run_id: run_id.clone(),
                                bundle_id: bundle.id.clone(),
                                action_index: idx,
                                action_type: action.action_type_name().to_string(),
                                target: target.clone(),
                                state: ActionState::Failed,
                                error: Some(e.to_string()),
                            };
                            on_event(&ev);
                            events.push(ev);
                            bundle_failed = true;
                            if bundle.bundle_policy == BundlePolicy::AbortOnFail {
                                break 'action_loop;
                            }
                            continue;
                        }
                    };

                    // §4.1: Idempotency check -> if probe already shows target state, transition to `Skipped` with no journal writes
                    if self.backend.is_target_state_satisfied(action, &current) {
                        skipped_count += 1;
                        let ev = ActionProgressEvent {
                            run_id: run_id.clone(),
                            bundle_id: bundle.id.clone(),
                            action_index: idx,
                            action_type: action.action_type_name().to_string(),
                            target,
                            state: ActionState::Skipped,
                            error: None,
                        };
                        on_event(&ev);
                        events.push(ev);
                        continue;
                    }

                    // Transition: Planned
                    let planned_ev = ActionProgressEvent {
                        run_id: run_id.clone(),
                        bundle_id: bundle.id.clone(),
                        action_index: idx,
                        action_type: action.action_type_name().to_string(),
                        target: target.clone(),
                        state: ActionState::Planned,
                        error: None,
                    };
                    on_event(&planned_ev);

                    // Transition: Captured (write prior state to journal before mutation)
                    let mut entry = JournalEntry::new_captured(
                        &bundle.id,
                        idx,
                        &target,
                        current.clone(),
                        &run_id,
                        context,
                    );
                    journal.upsert_entry(entry.clone());
                    journal.save(&self.journal_path)?;

                    let captured_ev = ActionProgressEvent {
                        run_id: run_id.clone(),
                        bundle_id: bundle.id.clone(),
                        action_index: idx,
                        action_type: action.action_type_name().to_string(),
                        target: target.clone(),
                        state: ActionState::Captured,
                        error: None,
                    };
                    on_event(&captured_ev);

                    // Execute mutation
                    match self.backend.apply_target(action, &target) {
                        Ok(written_state) => {
                            entry.written = Some(written_state);
                            entry.state = ActionState::Applied;
                            journal.upsert_entry(entry.clone());
                            journal.save(&self.journal_path)?;

                            let applied_ev = ActionProgressEvent {
                                run_id: run_id.clone(),
                                bundle_id: bundle.id.clone(),
                                action_index: idx,
                                action_type: action.action_type_name().to_string(),
                                target: target.clone(),
                                state: ActionState::Applied,
                                error: None,
                            };
                            on_event(&applied_ev);

                            // Post-apply verification probe
                            match self.backend.probe_target(action, &target) {
                                Ok(post_state)
                                    if self
                                        .backend
                                        .is_target_state_satisfied(action, &post_state) =>
                                {
                                    entry.state = ActionState::Verified;
                                    journal.upsert_entry(entry.clone());
                                    journal.save(&self.journal_path)?;

                                    verified_count += 1;
                                    bundle_applied_any = true;
                                    applied_in_bundle.push((
                                        idx,
                                        action.clone(),
                                        target.clone(),
                                        current,
                                        entry.entry_id.clone(),
                                    ));

                                    let verified_ev = ActionProgressEvent {
                                        run_id: run_id.clone(),
                                        bundle_id: bundle.id.clone(),
                                        action_index: idx,
                                        action_type: action.action_type_name().to_string(),
                                        target,
                                        state: ActionState::Verified,
                                        error: None,
                                    };
                                    on_event(&verified_ev);
                                    events.push(verified_ev);
                                }
                                Ok(post_state) => {
                                    let err_msg = format!(
                                        "Post-apply verification probe did not match expected state (got {:?})",
                                        post_state
                                    );
                                    entry.state = ActionState::Failed;
                                    entry.error = Some(err_msg.clone());
                                    journal.upsert_entry(entry.clone());
                                    journal.save(&self.journal_path)?;

                                    failed_count += 1;
                                    bundle_failed = true;
                                    let fail_ev = ActionProgressEvent {
                                        run_id: run_id.clone(),
                                        bundle_id: bundle.id.clone(),
                                        action_index: idx,
                                        action_type: action.action_type_name().to_string(),
                                        target,
                                        state: ActionState::Failed,
                                        error: Some(err_msg),
                                    };
                                    on_event(&fail_ev);
                                    events.push(fail_ev);
                                    if bundle.bundle_policy == BundlePolicy::AbortOnFail {
                                        break 'action_loop;
                                    }
                                }
                                Err(e) => {
                                    let err_msg = e.to_string();
                                    entry.state = ActionState::Failed;
                                    entry.error = Some(err_msg.clone());
                                    journal.upsert_entry(entry.clone());
                                    journal.save(&self.journal_path)?;

                                    failed_count += 1;
                                    bundle_failed = true;
                                    let fail_ev = ActionProgressEvent {
                                        run_id: run_id.clone(),
                                        bundle_id: bundle.id.clone(),
                                        action_index: idx,
                                        action_type: action.action_type_name().to_string(),
                                        target,
                                        state: ActionState::Failed,
                                        error: Some(err_msg),
                                    };
                                    on_event(&fail_ev);
                                    events.push(fail_ev);
                                    if bundle.bundle_policy == BundlePolicy::AbortOnFail {
                                        break 'action_loop;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let err_msg = e.to_string();
                            entry.state = ActionState::Failed;
                            entry.error = Some(err_msg.clone());
                            journal.upsert_entry(entry.clone());
                            journal.save(&self.journal_path)?;

                            failed_count += 1;
                            bundle_failed = true;
                            let fail_ev = ActionProgressEvent {
                                run_id: run_id.clone(),
                                bundle_id: bundle.id.clone(),
                                action_index: idx,
                                action_type: action.action_type_name().to_string(),
                                target,
                                state: ActionState::Failed,
                                error: Some(err_msg),
                            };
                            on_event(&fail_ev);
                            events.push(fail_ev);
                            if bundle.bundle_policy == BundlePolicy::AbortOnFail {
                                break 'action_loop;
                            }
                        }
                    }
                }
            }

            // §4.1: If `abort_on_fail` and an action failed, roll back earlier Applied/Verified actions in this bundle
            if bundle_failed && bundle.bundle_policy == BundlePolicy::AbortOnFail {
                for (rb_idx, rb_action, rb_target, rb_prior, rb_entry_id) in
                    applied_in_bundle.into_iter().rev()
                {
                    let _ = self.backend.restore_target(&rb_action, &rb_target, &rb_prior);
                    if let Some(j_entry) = journal
                        .entries
                        .iter_mut()
                        .find(|e| e.entry_id == rb_entry_id)
                    {
                        j_entry.state = ActionState::RolledBack;
                        j_entry.recompute_hash();
                    }
                    journal.save(&self.journal_path)?;
                    if verified_count > 0 {
                        verified_count -= 1;
                    }
                    rolled_back_count += 1;

                    let rb_ev = ActionProgressEvent {
                        run_id: run_id.clone(),
                        bundle_id: bundle.id.clone(),
                        action_index: rb_idx,
                        action_type: rb_action.action_type_name().to_string(),
                        target: rb_target,
                        state: ActionState::RolledBack,
                        error: None,
                    };
                    on_event(&rb_ev);
                    events.push(rb_ev);
                }
            } else if bundle_applied_any {
                if bundle.ui_impact.explorer_restart {
                    requires_explorer_restart = true;
                }
                if bundle.ui_impact.reboot {
                    requires_reboot = true;
                }
            }
        }

        Ok(ApplySummary {
            run_id,
            events,
            verified_count,
            skipped_count,
            failed_count,
            rolled_back_count,
            requires_explorer_restart,
            requires_reboot,
        })
    }

    /// Detects whether all applicable bundles in a profile are currently applied (§7.1 `detect`).
    pub fn detect_profile(
        &self,
        bundles: &[Bundle],
        scope: &TargetScope,
    ) -> Result<bool, EngineError> {
        for bundle in bundles {
            let status = self.probe_bundle(bundle, scope)?;
            if status.gating.applicable && !status.is_fully_applied {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluates drift across all `Verified` entries in `journal.json` (§5.3).
    pub fn check_drift(&self, bundles: &[Bundle]) -> Result<Vec<DriftReportItem>, EngineError> {
        let journal = JournalFile::load_or_create(&self.journal_path)?;
        let bundle_map: HashMap<&str, &Bundle> =
            bundles.iter().map(|b| (b.id.as_str(), b)).collect();

        // Keep only the latest Verified entry per target
        let mut latest_by_target: HashMap<String, &JournalEntry> = HashMap::new();
        for entry in &journal.entries {
            if entry.state == ActionState::Verified {
                latest_by_target.insert(entry.target.clone(), entry);
            } else if entry.state == ActionState::Undone {
                latest_by_target.remove(&entry.target);
            }
        }

        let mut report = Vec::new();
        for entry in latest_by_target.into_values() {
            let Some(bundle) = bundle_map.get(entry.bundle_id.as_str()) else {
                continue;
            };
            let Some(action) = bundle.actions.get(entry.action_index) else {
                continue;
            };
            let Some(written) = &entry.written else {
                continue;
            };

            let current = self
                .backend
                .probe_target(action, &entry.target)
                .unwrap_or(TargetState::NotApplicable);
            let status = classify_drift(&entry.prior, written, &current);

            report.push(DriftReportItem {
                entry_id: entry.entry_id.clone(),
                bundle_id: entry.bundle_id.clone(),
                action_index: entry.action_index,
                target: entry.target.clone(),
                prior: entry.prior.clone(),
                written: written.clone(),
                current,
                status,
                applied_at: entry.applied_at,
                run_id: entry.run_id.clone(),
            });
        }

        report.sort_by(|a, b| b.applied_at.cmp(&a.applied_at));
        Ok(report)
    }

    /// Performs three-way undo for either a full `run_id` or a specific `entry_id` (§5.2).
    pub fn undo_entries(
        &mut self,
        bundles: &[Bundle],
        run_id_filter: Option<&str>,
        entry_id_filter: Option<&str>,
        force_undo: bool,
    ) -> Result<Vec<UndoItemResult>, EngineError> {
        let _run_lock = RunLockGuard::acquire()?;
        let mut journal = JournalFile::load_or_create(&self.journal_path)?;
        let bundle_map: HashMap<&str, &Bundle> =
            bundles.iter().map(|b| (b.id.as_str(), b)).collect();

        let mut results = Vec::new();
        // Undo in reverse chronological order
        let indices: Vec<usize> = (0..journal.entries.len()).rev().collect();

        for idx in indices {
            let entry = journal.entries[idx].clone();
            if entry.state != ActionState::Verified {
                continue;
            }
            if let Some(rid) = run_id_filter {
                if entry.run_id != rid {
                    continue;
                }
            }
            if let Some(eid) = entry_id_filter {
                if entry.entry_id != eid {
                    continue;
                }
            }

            let Some(bundle) = bundle_map.get(entry.bundle_id.as_str()) else {
                continue;
            };
            let Some(action) = bundle.actions.get(entry.action_index) else {
                continue;
            };

            let undo_spec = action.undo();
            match undo_spec.tier {
                UndoTier::None => {
                    results.push(UndoItemResult::Irreversible {
                        entry_id: entry.entry_id.clone(),
                        target: entry.target.clone(),
                    });
                }
                UndoTier::ManualAssisted => {
                    let store_uri = undo_spec
                        .product_id
                        .as_ref()
                        .map(|pid| format!("ms-windows-store://pdp/?productid={}", pid));
                    results.push(UndoItemResult::ManualAssisted {
                        entry_id: entry.entry_id.clone(),
                        target: entry.target.clone(),
                        route: undo_spec.route,
                        store_uri,
                        product_id: undo_spec.product_id.clone(),
                        package_id: undo_spec.package_id.clone(),
                    });
                }
                UndoTier::Automatic => {
                    let current = self.backend.probe_target(action, &entry.target)?;
                    let written = entry.written.clone().unwrap_or(TargetState::Absent);

                    if current == written || force_undo {
                        self.backend
                            .restore_target(action, &entry.target, &entry.prior)?;
                        journal.entries[idx].state = ActionState::Undone;
                        journal.entries[idx].recompute_hash();
                        journal.save(&self.journal_path)?;
                        results.push(UndoItemResult::Restored {
                            entry_id: entry.entry_id.clone(),
                            target: entry.target.clone(),
                        });
                    } else {
                        results.push(UndoItemResult::Conflict {
                            entry_id: entry.entry_id.clone(),
                            target: entry.target.clone(),
                            written,
                            current,
                            prior: entry.prior.clone(),
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

pub fn load_journal_entries(path: &Path) -> Result<JournalFile, JournalError> {
    JournalFile::load_or_create(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::DriftStatus;
    use crate::sandbox::SandboxOsBackend;
    use std::sync::Mutex;
    use windebloat_schema::load_embedded_base_manifest;

    static TEST_RUN_MUTEX: Mutex<()> = Mutex::new(());

    fn temp_journal_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("windebloat_unit_tests");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{}_{}.json", name, Uuid::new_v4()))
    }

    #[test]
    fn second_instance_fails_fast_when_run_lock_is_held() {
        let _serial = TEST_RUN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let _first_guard = RunLockGuard::acquire().expect("first lock succeeds");
        let second = RunLockGuard::acquire();
        assert!(matches!(second, Err(ConcurrencyError::AlreadyRunning)));
    }

    #[test]
    fn state_machine_idempotency_three_way_undo_and_drift() {
        let _serial = TEST_RUN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let manifest = load_embedded_base_manifest();
        let telemetry_bundle = manifest
            .bundles
            .iter()
            .find(|b| b.id == "telemetry_minimal")
            .unwrap()
            .clone();

        let j_path = temp_journal_path("idempotency");
        let backend = SandboxOsBackend::default();
        let mut engine = ExecutionEngine::new(backend, j_path.clone());
        let scope = TargetScope::Sid("S-1-5-21-100000000-200000000-300000000-1001".to_string());

        let expected_len = telemetry_bundle.actions.len();

        // 1. First pass: all actions should transition to Verified
        let run1 = engine
            .apply_bundles(
                std::slice::from_ref(&telemetry_bundle),
                &scope,
                ExecutionContext::Interactive,
                |_| {},
            )
            .unwrap();
        assert_eq!(run1.verified_count, expected_len);
        assert_eq!(run1.skipped_count, 0);

        let journal_after_run1 = JournalFile::load_or_create(&j_path).unwrap();
        assert_eq!(journal_after_run1.entries.len(), expected_len);

        // 2. Second pass (idempotency §4.1): every action must be Skipped with NO new journal writes
        let run2 = engine
            .apply_bundles(
                std::slice::from_ref(&telemetry_bundle),
                &scope,
                ExecutionContext::Interactive,
                |_| {},
            )
            .unwrap();
        assert_eq!(run2.verified_count, 0);
        assert_eq!(run2.skipped_count, expected_len);

        let journal_after_run2 = JournalFile::load_or_create(&j_path).unwrap();
        assert_eq!(journal_after_run2.entries.len(), expected_len);

        // 3. Drift check right now -> all are Intact
        let drift1 = engine
            .check_drift(std::slice::from_ref(&telemetry_bundle))
            .unwrap();
        assert_eq!(drift1.len(), expected_len);
        assert!(drift1.iter().all(|d| d.status == DriftStatus::Intact));

        // 4. Simulate Windows Update reverting AllowTelemetry back to Absent (its `prior` state)
        // and another tool changing AdvertisingInfo\Enabled to 2 (`ChangedByOther`)
        engine.backend.state_map.insert(
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry"
                .to_string(),
            TargetState::Absent,
        );
        engine.backend.state_map.insert(
            "HKU\\S-1-5-21-100000000-200000000-300000000-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\\Enabled"
                .to_string(),
            TargetState::RegistryValue(serde_json::json!(2)),
        );

        let drift2 = engine
            .check_drift(std::slice::from_ref(&telemetry_bundle))
            .unwrap();
        let allow_tel_drift = drift2
            .iter()
            .find(|d| d.target.ends_with("AllowTelemetry"))
            .unwrap();
        assert_eq!(allow_tel_drift.status, DriftStatus::Reverted);

        let adv_drift = drift2
            .iter()
            .find(|d| d.target.ends_with("AdvertisingInfo\\Enabled"))
            .unwrap();
        assert_eq!(adv_drift.status, DriftStatus::ChangedByOther);

        // 5. Three-way undo without force_undo -> reports Conflict on the 2 modified targets and Restored on the 2 intact tasks
        let undo_res = engine
            .undo_entries(
                std::slice::from_ref(&telemetry_bundle),
                Some(&run1.run_id),
                None,
                false,
            )
            .unwrap();
        let conflicts = undo_res
            .iter()
            .filter(|r| matches!(r, UndoItemResult::Conflict { .. }))
            .count();
        let restored = undo_res
            .iter()
            .filter(|r| matches!(r, UndoItemResult::Restored { .. }))
            .count();
        assert_eq!(conflicts, 2);
        assert_eq!(restored, expected_len - 2);

        // 6. Force undo resolves the remaining 2 conflicts
        let undo_forced = engine
            .undo_entries(
                std::slice::from_ref(&telemetry_bundle),
                Some(&run1.run_id),
                None,
                true,
            )
            .unwrap();
        assert_eq!(undo_forced.len(), 2);
        assert!(undo_forced
            .iter()
            .all(|r| matches!(r, UndoItemResult::Restored { .. })));

        let _ = std::fs::remove_file(&j_path);
    }

    #[test]
    fn abort_on_fail_rolls_back_earlier_actions_in_bundle() {
        let _serial = TEST_RUN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let manifest = load_embedded_base_manifest();
        let telemetry_bundle = manifest
            .bundles
            .iter()
            .find(|b| b.id == "telemetry_minimal")
            .unwrap()
            .clone();

        let j_path = temp_journal_path("rollback");
        let mut backend = SandboxOsBackend::default();
        // Inject failure on the 3rd action (Compatibility Appraiser scheduled task)
        backend.fail_targets.insert(
            "ScheduledTask\\\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
                .to_string(),
        );

        let mut engine = ExecutionEngine::new(backend, j_path.clone());
        let scope = TargetScope::Sid("S-1-5-21-100000000-200000000-300000000-1001".to_string());

        let summary = engine
            .apply_bundles(
                std::slice::from_ref(&telemetry_bundle),
                &scope,
                ExecutionContext::Headless,
                |_| {},
            )
            .unwrap();

        assert_eq!(summary.failed_count, 1);
        assert_eq!(summary.rolled_back_count, 2);
        assert_eq!(summary.verified_count, 0);

        // Verify the first 2 registry actions were restored to Absent in the backend
        assert_eq!(
            engine.backend.state_map.get(
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry"
            ),
            Some(&TargetState::Absent)
        );
        let _ = std::fs::remove_file(&j_path);
    }
}
