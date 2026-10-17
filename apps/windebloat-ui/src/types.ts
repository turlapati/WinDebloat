export type CategoryName =
  | "Apps"
  | "Privacy and telemetry"
  | "AI features"
  | "Windows Update"
  | "Appearance"
  | "Start and taskbar"
  | "Explorer"
  | "Optional features";

export type Rating = "recommended" | "limited" | "expert";
export type BundlePolicy = "continue_on_fail" | "abort_on_fail";
export type UndoTier = "automatic" | "manual_assisted" | "none";
export type ActionState =
  | "Planned"
  | "Skipped"
  | "Captured"
  | "Applied"
  | "Verified"
  | "Failed"
  | "RolledBack"
  | "Undone";

export type DriftStatus =
  | "intact"
  | "reverted"
  | "changed_by_other"
  | "not_applicable";

export interface OsEnvironment {
  build_number: number;
  edition_id: string;
  region_code: string;
  is_eea: boolean;
}

export interface GatingResult {
  applicable: boolean;
  skip_reason: string | null;
  effective_on_note: string | null;
}

export interface UndoSpec {
  tier: UndoTier;
  strategy?: string | null;
  route?: "store" | "winget" | null;
  product_id?: string | null;
  package_id?: string | null;
}

export interface ProbeSpec {
  kind: string;
  expected?: unknown;
}

export interface BundleAction {
  type:
    | "registry_set"
    | "appx_remove"
    | "appx_provisioned_remove"
    | "scheduled_task_disable"
    | "service_startup"
    | "capability_remove"
    | "optional_feature";
  hive?: string;
  path?: string;
  name?: string;
  value_type?: string;
  value?: unknown;
  scope?: string;
  package_family_name?: string;
  task_path?: string;
  service_name?: string;
  start_type?: string;
  capability_name?: string;
  feature_name?: string;
  feature_enabled?: boolean;
  probe: ProbeSpec;
  undo: UndoSpec;
}

export interface Bundle {
  manifest_version: number;
  id: string;
  display_name: string;
  category: CategoryName;
  rating: Rating;
  description: string;
  side_effects: string[];
  sources?: string[];
  applies_to: {
    os_min_build: number;
    os_max_build?: number | null;
    sku_exclude: string[];
    region_exclude: string[];
    effective_on?: string[] | null;
  };
  ui_impact: {
    explorer_restart: boolean;
    reboot: boolean;
  };
  bundle_policy: BundlePolicy;
  actions: BundleAction[];
}

export interface SelectionProfile {
  profile_version: number;
  id: string;
  name: string;
  description?: string | null;
  bundles: string[];
  custom_manifests?: string[];
}

export interface TargetState {
  kind: string;
  value?: unknown;
}

export interface BundleProbeStatus {
  bundle_id: string;
  gating: GatingResult;
  is_fully_applied: boolean;
  action_states: [string, TargetState, boolean][];
}

export interface DryRunActionDelta {
  action_index: number;
  action_type: string;
  target: string;
  current_state: TargetState;
  planned_state: ActionState;
  undo_tier: UndoTier;
  skip_reason: string | null;
}

export interface DryRunBundleDelta {
  bundle_id: string;
  display_name: string;
  gating: GatingResult;
  explorer_restart: boolean;
  reboot: boolean;
  actions: DryRunActionDelta[];
}

export interface DryRunReport {
  environment: OsEnvironment;
  pending_reboot_blocker: string | null;
  bundles: DryRunBundleDelta[];
  estimated_applied_count: number;
  estimated_skipped_count: number;
  requires_explorer_restart: boolean;
  requires_reboot: boolean;
  has_irreversible_actions: boolean;
}

export interface ActionProgressEvent {
  run_id: string;
  bundle_id: string;
  action_index: number;
  action_type: string;
  target: string;
  state: ActionState;
  error: string | null;
}

export interface ApplySummary {
  run_id: string;
  events: ActionProgressEvent[];
  verified_count: number;
  skipped_count: number;
  failed_count: number;
  rolled_back_count: number;
  requires_explorer_restart: boolean;
  requires_reboot: boolean;
}

export interface JournalEntry {
  entry_id: string;
  bundle_id: string;
  action_index: number;
  target: string;
  prior: TargetState;
  written: TargetState | null;
  applied_at: string;
  run_id: string;
  context: "interactive" | "headless";
  state: ActionState;
  error: string | null;
  sha256: string;
}

export interface DriftReportItem {
  entry_id: string;
  bundle_id: string;
  action_index: number;
  target: string;
  prior: TargetState;
  written: TargetState;
  current: TargetState;
  status: DriftStatus;
  applied_at: string;
  run_id: string;
}

export type UndoItemResult =
  | { outcome: "restored"; entry_id: string; target: string }
  | {
      outcome: "conflict";
      entry_id: string;
      target: string;
      written: TargetState;
      current: TargetState;
      prior: TargetState;
    }
  | {
      outcome: "manual_assisted";
      entry_id: string;
      target: string;
      route?: "store" | "winget" | null;
      store_uri?: string | null;
      product_id?: string | null;
      package_id?: string | null;
    }
  | { outcome: "irreversible"; entry_id: string; target: string };

export interface CustomSourceBadge {
  manifest_name: string;
  trusted: boolean;
}

export interface UiBootstrapPayload {
  app_version: string;
  user_sid: string;
  session_luid: string;
  environment: OsEnvironment;
  pending_reboot: string | null;
  bundles: Bundle[];
  profiles: SelectionProfile[];
  custom_bundle_sources: Record<string, CustomSourceBadge>;
  sandbox_mode: boolean;
}
