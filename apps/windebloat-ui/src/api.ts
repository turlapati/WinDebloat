import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  ActionProgressEvent,
  ApplySummary,
  BundleProbeStatus,
  DriftReportItem,
  DryRunReport,
  JournalEntry,
  UiBootstrapPayload,
  UndoItemResult,
} from "./types";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function getBootstrapData(): Promise<UiBootstrapPayload> {
  if (!isTauriRuntime()) {
    throw new Error("Tauri WebView2 runtime required");
  }
  return invoke<UiBootstrapPayload>("get_bootstrap_data");
}

export async function setSandboxMode(enabled: boolean): Promise<boolean> {
  return invoke<boolean>("set_sandbox_mode", { enabled });
}

export async function probeAllBundles(): Promise<BundleProbeStatus[]> {
  return invoke<BundleProbeStatus[]>("probe_all_bundles");
}

export async function previewDryRun(bundleIds: string[]): Promise<DryRunReport> {
  return invoke<DryRunReport>("preview_dry_run", { bundleIds });
}

export async function applySelectedBundles(
  bundleIds: string[],
  onProgress: (ev: ActionProgressEvent) => void
): Promise<ApplySummary> {
  const unlisten = await listen<ActionProgressEvent>(
    "windebloat://apply-progress",
    (event) => {
      onProgress(event.payload);
    }
  );
  try {
    return await invoke<ApplySummary>("apply_selected_bundles", { bundleIds });
  } finally {
    unlisten();
  }
}

export async function getJournalHistory(): Promise<JournalEntry[]> {
  return invoke<JournalEntry[]>("get_journal_history");
}

export async function checkDriftReport(): Promise<DriftReportItem[]> {
  return invoke<DriftReportItem[]>("check_drift_report");
}

export async function undoJournalItem(params: {
  runId?: string;
  entryId?: string;
  entryIds?: string[];
  forceUndo: boolean;
}): Promise<UndoItemResult[]> {
  return invoke<UndoItemResult[]>("undo_journal_item", {
    runId: params.runId ?? null,
    entryId: params.entryId ?? null,
    entryIds: params.entryIds ?? null,
    forceUndo: params.forceUndo,
  });
}

export async function loadCustomManifestJson(
  rawJson: string,
  adminSessionOverride: boolean
): Promise<UiBootstrapPayload> {
  return invoke<UiBootstrapPayload>("load_custom_manifest_json", {
    rawJson,
    adminSessionOverride,
  });
}

export async function openStoreProductPage(productId: string): Promise<void> {
  return invoke<void>("open_store_product_page", { productId });
}

export async function restartExplorerShell(): Promise<void> {
  return invoke<void>("restart_explorer_shell");
}

export async function saveJsonExport(filename: string, content: string): Promise<string> {
  return invoke<string>("save_json_export", { filename, content });
}

export async function revealInExplorer(filePath: string): Promise<void> {
  return invoke<void>("reveal_in_explorer", { filePath });
}

export async function openAdminPanel(panelId: string): Promise<void> {
  return invoke<void>("open_admin_panel", { panelId });
}


