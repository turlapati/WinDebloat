import React, { useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  AppLogoIcon,
  CategoryIcon,
  PresetIcon,
  TabIcon,
} from "./Icons";
import {
  applySelectedBundles,
  checkDriftReport,
  getBootstrapData,
  getJournalHistory,
  loadCustomManifestJson,
  openAdminPanel,
  openStoreProductPage,
  previewDryRun,
  probeAllBundles,
  restartExplorerShell,
  revealInExplorer,
  saveJsonExport,
  setSandboxMode,
  undoJournalItem,
} from "./api";
import type {
  ActionProgressEvent,
  ApplySummary,
  Bundle,
  BundleProbeStatus,
  CategoryName,
  DriftReportItem,
  DryRunReport,
  JournalEntry,
  Rating,
  SelectionProfile,
  UiBootstrapPayload,
  UndoItemResult,
} from "./types";

type MainTab = "configure" | "history" | "drift" | "panels" | "about";
type CategoryFilter = "ALL" | CategoryName;

const ADMIN_PANELS: {
  id: string;
  title: string;
  commandLabel: string;
  description: string;
  group: "Classic Control Panels (.cpl)" | "System & Management Consoles (.msc)";
}[] = [
  {
    id: "ncpa",
    title: "Network Connections (Adapters)",
    commandLabel: "ncpa.cpl",
    description: "Directly configure IPv4/IPv6 DNS, Ethernet/Wi-Fi adapters, and virtual switches.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "appwiz",
    title: "Programs and Features",
    commandLabel: "appwiz.cpl",
    description: "Classic Win32 uninstaller and 'Turn Windows features on or off' dialog.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "sysdm",
    title: "System Properties & Env Variables",
    commandLabel: "sysdm.cpl",
    description: "Edit PATH / Environment Variables, Computer Name, Domain, and Pagefile settings.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "mmsys",
    title: "Classic Sound Control Panel",
    commandLabel: "mmsys.cpl",
    description: "Configure playback/recording devices, default communication devices, and sample rates.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "powercfg",
    title: "Power Options & Plans",
    commandLabel: "powercfg.cpl",
    description: "Switch between Balanced / High Performance plans and lid close actions.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "main_mouse",
    title: "Mouse Properties (Pointer Precision)",
    commandLabel: "main.cpl",
    description: "Configure pointer speed, Enhance Pointer Precision, and scroll wheel lines.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "sysrestore",
    title: "System Protection & Restore Points",
    commandLabel: "SystemPropertiesProtection",
    description: "Create a manual Windows System Restore Point or configure shadow copy storage.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "control",
    title: "Classic Control Panel Home",
    commandLabel: "control.exe",
    description: "Open the full classic Windows Control Panel category/icon view.",
    group: "Classic Control Panels (.cpl)",
  },
  {
    id: "services",
    title: "Windows Services Console",
    commandLabel: "services.msc",
    description: "Inspect, start, stop, or configure startup types for all Windows background services.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "taskschd",
    title: "Task Scheduler",
    commandLabel: "taskschd.msc",
    description: "Inspect and manage scheduled background tasks and startup triggers.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "devmgmt",
    title: "Device Manager",
    commandLabel: "devmgmt.msc",
    description: "Inspect hardware drivers, USB controllers, and hidden devices.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "diskmgmt",
    title: "Disk Management",
    commandLabel: "diskmgmt.msc",
    description: "Format, partition, assign drive letters, and inspect NVMe/SATA volumes.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "compmgmt",
    title: "Computer Management",
    commandLabel: "compmgmt.msc",
    description: "Unified console for Event Viewer, Shared Folders, Local Users/Groups, and Disks.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "firewall",
    title: "Windows Defender Firewall (Advanced)",
    commandLabel: "wf.msc",
    description: "Configure inbound and outbound application firewall rules.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "resmon",
    title: "Resource Monitor",
    commandLabel: "resmon.exe",
    description: "Live per-process CPU, Disk I/O, Network TCP connections, and Memory commit inspector.",
    group: "System & Management Consoles (.msc)",
  },
  {
    id: "timedate",
    title: "Date, Time & NTP Servers",
    commandLabel: "timedate.cpl",
    description: "Configure Internet Time (NTP) server sync and additional clocks.",
    group: "System & Management Consoles (.msc)",
  },
];

const ALL_CATEGORIES: CategoryName[] = [
  "Apps",
  "Privacy and telemetry",
  "AI features",
  "Windows Update",
  "Appearance",
  "Start and taskbar",
  "Explorer",
  "Optional features",
];

const RATING_LABELS: Record<Rating, { title: string; subtitle: string }> = {
  recommended: {
    title: "Recommended (Safe for Most Users)",
    subtitle: "Removes bloatware and disables telemetry/ads without breaking everyday features.",
  },
  limited: {
    title: "Optional / Situational (Review Side Effects)",
    subtitle: "Changes appearance or disables services some users rely on.",
  },
  expert: {
    title: "Expert (Collapsed by Default)",
    subtitle: "Deep system component changes that require Windows install media or reboot to undo.",
  },
};

export default function App() {
  const [bootstrap, setBootstrap] = useState<UiBootstrapPayload | null>(null);
  const [probes, setProbes] = useState<Record<string, BundleProbeStatus>>({});
  const [probing, setProbing] = useState<boolean>(true);

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [activePresetId, setActivePresetId] = useState<string | null>(null);
  const [presetInfoBanner, setPresetInfoBanner] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<MainTab>("configure");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [inspectedBundleId, setInspectedBundleId] = useState<string | null>(null);
  const [showExpertItems, setShowExpertItems] = useState<boolean>(false);
  const [showHiddenGatedItems, setShowHiddenGatedItems] = useState<boolean>(false);

  // Review & Apply Modal State
  const [reviewModalOpen, setReviewModalOpen] = useState<boolean>(false);
  const [previewingDryRun, setPreviewingDryRun] = useState<boolean>(false);
  const [dryRunReport, setDryRunReport] = useState<DryRunReport | null>(null);
  const [applying, setApplying] = useState<boolean>(false);
  const [applyEvents, setApplyEvents] = useState<ActionProgressEvent[]>([]);
  const [applySummary, setApplySummary] = useState<ApplySummary | null>(null);

  // History, Drift & Action Busy State
  const [journal, setJournal] = useState<JournalEntry[]>([]);
  const [historySelectedIds, setHistorySelectedIds] = useState<Set<string>>(new Set());
  const [undoSummaryBanner, setUndoSummaryBanner] = useState<string | null>(null);
  const [driftItems, setDriftItems] = useState<DriftReportItem[]>([]);
  const [driftSelectedBundles, setDriftSelectedBundles] = useState<Set<string>>(new Set());
  const [undoConflictModal, setUndoConflictModal] = useState<UndoItemResult | null>(null);
  const [undoingEntryId, setUndoingEntryId] = useState<string | null>(null);
  const [restartingExplorer, setRestartingExplorer] = useState<boolean>(false);
  const [explorerRestarted, setExplorerRestarted] = useState<boolean>(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [exportSuccessBanner, setExportSuccessBanner] = useState<{
    message: string;
    filePath: string;
  } | null>(null);

  async function refreshAllState() {
    setProbing(true);
    setErrorBanner(null);
    try {
      const data = await getBootstrapData();
      setBootstrap(data);

      // Load journal history & drift report immediately in parallel with bundle probing
      getJournalHistory()
        .then((hist) => setJournal(hist))
        .catch((err) => setErrorBanner(String(err)));

      checkDriftReport()
        .then((drift) => setDriftItems(drift))
        .catch((err) => setErrorBanner(String(err)));

      const probeList = await probeAllBundles();
      const map: Record<string, BundleProbeStatus> = {};
      for (const p of probeList) {
        map[p.bundle_id] = p;
      }
      setProbes(map);
      // Automatically uncheck any items that are now 100% applied
      setSelectedIds((prev) => {
        const next = new Set<string>();
        for (const id of prev) {
          if (!map[id]?.is_fully_applied) {
            next.add(id);
          }
        }
        return next;
      });
    } catch (e) {
      setErrorBanner(String(e));
    } finally {
      setProbing(false);
    }
  }

  useEffect(() => {
    refreshAllState();
  }, []);

  const bundles = bootstrap?.bundles ?? [];
  const inspectedBundle: Bundle | null = useMemo(
    () => bundles.find((b) => b.id === inspectedBundleId) ?? null,
    [bundles, inspectedBundleId]
  );

  const driftedCount = useMemo(
    () =>
      driftItems.filter(
        (d) => d.status === "reverted" || d.status === "changed_by_other"
      ).length,
    [driftItems]
  );

  function isBundleAlreadyDone(bundleId: string): boolean {
    return probes[bundleId]?.is_fully_applied ?? false;
  }

  function toggleBundle(id: string, bundle?: Bundle) {
    // Do not allow checking an item that is already 100% applied/uninstalled on this PC
    if (isBundleAlreadyDone(id)) {
      return;
    }

    if (bundle?.rating === "expert" && !selectedIds.has(id)) {
      const confirmed = window.confirm(
        `"${bundle.display_name}" is an Expert tweak.\n\nSide effects:\n• ${bundle.side_effects.join(
          "\n• "
        )}\n\nSelect this item anyway?`
      );
      if (!confirmed) return;
    }
    setActivePresetId(null);
    setPresetInfoBanner(null);
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function applyPresetProfile(profile: SelectionProfile) {
    setActivePresetId(profile.id);
    const needed: string[] = [];
    let alreadyDoneCount = 0;

    for (const bid of profile.bundles) {
      const st = probes[bid];
      if (st && !st.gating.applicable) {
        continue;
      }
      if (st?.is_fully_applied) {
        alreadyDoneCount += 1;
      } else {
        needed.push(bid);
      }
    }

    setSelectedIds(new Set(needed));
    if (alreadyDoneCount > 0) {
      setPresetInfoBanner(
        `"${profile.name}" preset selected ${needed.length} item(s) that need changes (${alreadyDoneCount} other item(s) in this preset are already applied/uninstalled on your PC).`
      );
    } else {
      setPresetInfoBanner(
        `"${profile.name}" preset selected ${needed.length} item(s) to apply.`
      );
    }
  }

  function clearSelection() {
    setActivePresetId(null);
    setPresetInfoBanner(null);
    setSelectedIds(new Set());
  }

  async function handleExportProfileJson() {
    if (selectedIds.size === 0) {
      setErrorBanner(
        "Please select at least one tweak (or click a Quick-Start Preset) before exporting a profile."
      );
      return;
    }
    const profile: SelectionProfile = {
      profile_version: 1,
      id: activePresetId ?? "custom_selection",
      name: "Custom WinDebloat Profile",
      description: `Exported from WinDebloat UI (${selectedIds.size} selected tweaks).`,
      bundles: Array.from(selectedIds),
    };
    try {
      setErrorBanner(null);
      const savedPath = await saveJsonExport(
        "windebloat-profile.json",
        JSON.stringify(profile, null, 2)
      );
      setExportSuccessBanner({
        message: `Exported profile (${selectedIds.size} tweaks) to ${savedPath}`,
        filePath: savedPath,
      });
    } catch (e) {
      setErrorBanner(String(e));
    }
  }

  async function handleSaveSampleCustomManifest() {
    const sampleManifest = {
      manifest_version: 3,
      manifest_name: "My Organization / Power-User Custom Tweaks",
      bundles: [
        {
          manifest_version: 3,
          id: "custom_verbose_status_messages",
          display_name: "Enable Verbose Windows Boot & Shutdown Status Messages",
          category: "Appearance",
          rating: "recommended",
          description:
            "Displays detailed service and policy status messages during Windows sign-in, restart, and shutdown.",
          side_effects: [
            "Boot and shutdown screens show detailed status text instead of a generic spinner.",
          ],
          sources: ["Custom Manifest Template"],
          applies_to: {
            os_min_build: 19045,
            sku_exclude: [],
            region_exclude: [],
          },
          ui_impact: { explorer_restart: false, reboot: false },
          bundle_policy: "abort_on_fail",
          actions: [
            {
              type: "registry_set",
              hive: "HKLM",
              path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
              name: "VerboseStatus",
              value_type: "DWORD",
              value: 1,
              probe: { kind: "registry_equals", expected: 1 },
              undo: { tier: "automatic", strategy: "restore_prior_or_delete" },
            },
          ],
        },
      ],
    };
    try {
      setErrorBanner(null);
      const savedPath = await saveJsonExport(
        "sample-custom-manifest.v3.json",
        JSON.stringify(sampleManifest, null, 2)
      );
      setExportSuccessBanner({
        message: `Saved sample Custom Manifest template to ${savedPath}`,
        filePath: savedPath,
      });
    } catch (e) {
      setErrorBanner(String(e));
    }
  }

  function handleImportProfileJson() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text) as SelectionProfile;
        if (!Array.isArray(parsed.bundles)) {
          throw new Error("Invalid profile JSON: missing 'bundles' array");
        }
        setActivePresetId(null);
        const needed = parsed.bundles.filter((bid) => !isBundleAlreadyDone(bid));
        setSelectedIds(new Set(needed));
        setPresetInfoBanner(
          `Imported profile "${parsed.name || file.name}" (${needed.length} applicable item(s) selected).`
        );
      } catch (e) {
        setErrorBanner(String(e));
      }
    };
    input.click();
  }

  function handleLoadCustomManifest() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      const raw = await file.text();
      try {
        const updated = await loadCustomManifestJson(raw, false);
        setBootstrap(updated);
        await refreshAllState();
      } catch (err) {
        const msg = String(err);
        if (msg.includes("UNSIGNED_MANIFEST")) {
          const override = window.confirm(
            "This custom manifest is unsigned.\n\nLoad for this session anyway and mark its items as Untrusted?"
          );
          if (override) {
            try {
              const updated = await loadCustomManifestJson(raw, true);
              setBootstrap(updated);
              await refreshAllState();
              setActiveTab("configure");
            } catch (e2) {
              setErrorBanner(String(e2));
            }
          }
        } else {
          setErrorBanner(msg);
        }
      }
    };
    input.click();
  }

  async function handleOpenReviewModal() {
    if (selectedIds.size === 0) {
      setErrorBanner("Please check at least one item (or choose a Preset) before clicking Review & Apply.");
      return;
    }
    setErrorBanner(null);
    setDryRunReport(null);
    setApplyEvents([]);
    setApplySummary(null);
    setExplorerRestarted(false);
    setReviewModalOpen(true);
    setPreviewingDryRun(true);
    try {
      const report = await previewDryRun(Array.from(selectedIds));
      setDryRunReport(report);
    } catch (e) {
      setErrorBanner(String(e));
      setReviewModalOpen(false);
    } finally {
      setPreviewingDryRun(false);
    }
  }

  async function handleExecuteApply(bundleIdsToApply?: string[]) {
    const ids = bundleIdsToApply ?? Array.from(selectedIds);
    if (ids.length === 0) return;

    setReviewModalOpen(true);
    setApplying(true);
    setApplyEvents([]);
    setApplySummary(null);
    setExplorerRestarted(false);
    setErrorBanner(null);

    try {
      const summary = await applySelectedBundles(ids, (ev) => {
        setApplyEvents((prev) => {
          const idx = prev.findIndex(
            (p) =>
              p.bundle_id === ev.bundle_id &&
              p.action_index === ev.action_index &&
              p.target === ev.target
          );
          if (idx === -1) return [...prev, ev];
          const next = [...prev];
          next[idx] = ev;
          return next;
        });
      });
      setApplyEvents(summary.events);
      setApplySummary(summary);
      setPresetInfoBanner(null);
      await refreshAllState();
    } catch (e) {
      setErrorBanner(String(e));
    } finally {
      setApplying(false);
    }
  }

  async function handleRestartExplorer() {
    setRestartingExplorer(true);
    setErrorBanner(null);
    try {
      await restartExplorerShell();
      setExplorerRestarted(true);
      setApplySummary((prev) =>
        prev ? { ...prev, requires_explorer_restart: false } : prev
      );
    } catch (e) {
      setErrorBanner(String(e));
    } finally {
      setRestartingExplorer(false);
    }
  }

  async function handleUndoEntry(entryId: string, forceUndo = false) {
    setUndoingEntryId(entryId);
    try {
      setErrorBanner(null);
      setUndoSummaryBanner(null);
      const results = await undoJournalItem({ entryId, forceUndo });
      for (const r of results) {
        if (r.outcome === "conflict") {
          setUndoConflictModal(r);
          return;
        }
        if (r.outcome === "manual_assisted" && r.product_id) {
          const openStore = window.confirm(
            `This app was uninstalled and can be reinstalled from the Microsoft Store (Product ID: ${r.product_id}).\n\nOpen Microsoft Store now?`
          );
          if (openStore) {
            await openStoreProductPage(r.product_id);
          }
        }
      }
      setUndoConflictModal(null);
      setHistorySelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(entryId);
        return next;
      });
      await refreshAllState();
    } catch (e) {
      setErrorBanner(String(e));
    } finally {
      setUndoingEntryId(null);
    }
  }

  async function handleUndoMultiple(mode: "selected" | "all", forceUndo = false) {
    const verifiedIds = journal
      .filter((e) => e.state === "Verified")
      .map((e) => e.entry_id);
    const idsToUndo =
      mode === "all"
        ? verifiedIds
        : verifiedIds.filter((id) => historySelectedIds.has(id));
    if (idsToUndo.length === 0) return;

    setUndoingEntryId(mode === "all" ? "__ALL__" : "__SELECTED__");
    try {
      setErrorBanner(null);
      setUndoSummaryBanner(null);
      const results = await undoJournalItem(
        mode === "all"
          ? { forceUndo }
          : { entryIds: idsToUndo, forceUndo }
      );
      let restoredCount = 0;
      let manualStoreCount = 0;
      let firstConflict: UndoItemResult | null = null;
      const restoredIds = new Set<string>();

      for (const r of results) {
        if (r.outcome === "restored") {
          restoredCount += 1;
          restoredIds.add(r.entry_id);
        } else if (r.outcome === "manual_assisted") {
          manualStoreCount += 1;
        } else if (r.outcome === "conflict" && !firstConflict) {
          firstConflict = r;
        }
      }

      setHistorySelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of restoredIds) {
          next.delete(id);
        }
        if (mode === "all" && !firstConflict) {
          next.clear();
        }
        return next;
      });

      const parts: string[] = [];
      if (restoredCount > 0) {
        parts.push(`Restored ${restoredCount} setting(s) to their original values.`);
      }
      if (manualStoreCount > 0) {
        parts.push(
          `${manualStoreCount} removed Store app(s) require manual reinstallation from Microsoft Store (click "Undo This Change" on an app row to open its Store page).`
        );
      }
      if (parts.length > 0) {
        setUndoSummaryBanner(parts.join(" "));
      }

      if (firstConflict) {
        setUndoConflictModal(firstConflict);
      } else {
        setUndoConflictModal(null);
      }

      await refreshAllState();
    } catch (e) {
      setErrorBanner(String(e));
    } finally {
      setUndoingEntryId(null);
    }
  }

  async function handleExportJournalJson() {
    try {
      setErrorBanner(null);
      const savedPath = await saveJsonExport(
        "windebloat-journal.json",
        JSON.stringify({ schema_version: 1, entries: journal }, null, 2)
      );
      setExportSuccessBanner({
        message: `Exported Undo Journal (${journal.length} entries) to ${savedPath}`,
        filePath: savedPath,
      });
    } catch (e) {
      setErrorBanner(String(e));
    }
  }

  function isPureAppRemovalBundle(bundle: Bundle): boolean {
    return bundle.actions.every(
      (a) => a.type === "appx_remove" || a.type === "appx_provisioned_remove"
    );
  }

  function getStoreProductId(bundle: Bundle): string | null {
    for (const act of bundle.actions) {
      if (act.undo.product_id) {
        return act.undo.product_id;
      }
    }
    return null;
  }

  function renderStatusAndActionBadges(bundle: Bundle, isSelected: boolean) {
    if (probing && !probes[bundle.id]) {
      return (
        <span className="inline-block h-6 w-36 rounded bg-slate-200 dark:bg-slate-800 animate-pulse" />
      );
    }

    const st = probes[bundle.id];
    const isPureApp = isPureAppRemovalBundle(bundle);
    const fullyApplied = st?.is_fully_applied ?? false;
    const storeProductId = getStoreProductId(bundle);

    // Case 1: Bundle is 100% already applied / already uninstalled on this PC
    if (fullyApplied) {
      return (
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="px-2.5 py-1 text-xs rounded-md font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300">
            {isPureApp ? "✓ Already Uninstalled" : "✓ Already Applied"}
          </span>
          {isPureApp && storeProductId ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                openStoreProductPage(storeProductId);
              }}
              className="px-2 py-1 text-[11px] font-medium rounded border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              title="Open Microsoft Store if you want to reinstall this app"
            >
              Reinstall via Store ↗
            </button>
          ) : (
            <span className="px-2 py-1 text-[11px] text-slate-400 dark:text-slate-500">
              Already done
            </span>
          )}
        </div>
      );
    }

    // Case 2: Bundle is NOT yet fully applied
    const appxState = st?.action_states.find(
      ([, targetState]) => targetState.kind === "appx_tristate"
    );
    const appxVal = appxState ? String(appxState[1].value) : null;

    let currentBadgeText = "Status: Not Applied";
    let checkedActionText = "✓ Selected → Will Apply Setting";
    let uncheckedHintText = "Check box to apply";

    if (isPureApp) {
      if (appxVal === "provisioned_only") {
        currentBadgeText = "App: Provisioned for New Users";
        checkedActionText = "✓ Selected → Will Remove Package";
        uncheckedHintText = "Check box to remove";
      } else {
        currentBadgeText = "App: Currently Installed";
        checkedActionText = "✓ Selected → Will Uninstall App";
        uncheckedHintText = "Check box to uninstall";
      }
    } else if (appxVal === "absent") {
      // Hybrid bundle (e.g. Disable Windows Copilot) where app isn't installed, but registry policy isn't set yet
      currentBadgeText = "App Absent · Policy Not Applied";
      checkedActionText = "✓ Selected → Will Apply Block Policy";
      uncheckedHintText = "Check box to apply policy";
    } else if (appxVal === "installed") {
      currentBadgeText = "App Installed & Policy Not Applied";
      checkedActionText = "✓ Selected → Will Uninstall & Block";
      uncheckedHintText = "Check box to uninstall & block";
    }

    return (
      <div className="flex items-center gap-2 flex-shrink-0">
        <span className="px-2.5 py-1 text-xs rounded-md font-medium bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
          {currentBadgeText}
        </span>

        {isSelected ? (
          <span className="px-2.5 py-1 text-xs font-semibold rounded-md bg-blue-600 text-white shadow-sm">
            {checkedActionText}
          </span>
        ) : (
          <span className="px-2 py-1 text-[11px] text-slate-500 dark:text-slate-400">
            {uncheckedHintText}
          </span>
        )}
      </div>
    );
  }

  const visibleBundles = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return bundles.filter((b) => {
      const applicable = probes[b.id]?.gating.applicable ?? true;
      if (!applicable) return false;
      if (categoryFilter !== "ALL" && b.category !== categoryFilter) return false;
      if (q) {
        const hay = `${b.display_name} ${b.description} ${b.id} ${b.category} ${JSON.stringify(
          b.actions
        )}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [bundles, probes, categoryFilter, searchQuery]);

  const gatedOutBundles = useMemo(() => {
    return bundles.filter((b) => {
      const applicable = probes[b.id]?.gating.applicable ?? true;
      if (applicable) return false;
      if (categoryFilter !== "ALL" && b.category !== categoryFilter) return false;
      return true;
    });
  }, [bundles, probes, categoryFilter]);

  function selectAllVisibleRecommended() {
    setActivePresetId(null);
    setSelectedIds((prev) => {
      const next = new Set(prev);
      for (const b of visibleBundles) {
        if (b.rating === "recommended" && !isBundleAlreadyDone(b.id)) {
          next.add(b.id);
        }
      }
      return next;
    });
  }

  return (
    <div className="h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      {/* Top Header */}
      <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-3.5 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-3.5">
          <AppLogoIcon className="w-9 h-9 flex-shrink-0 drop-shadow-sm" />
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-bold tracking-tight">WinDebloat</h1>
              <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800">
                {bootstrap?.app_version ?? "2026-10-17_Beta_0.9.101"}
              </span>
              <span className="text-xs font-medium px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                Windows {bootstrap?.environment.edition_id ?? "..."} (Build{" "}
                {bootstrap?.environment.build_number ?? "..."}) · Region:{" "}
                {bootstrap?.environment.region_code ?? "US"}
              </span>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300">
                {bundles.length} Power-User Tweaks
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Remove pre-installed bloatware, reduce telemetry & AI features, and customize Windows 10
              & 11 with full Undo support.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleImportProfileJson}
            className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center gap-1.5"
            title="Load a previously exported selection profile (.json)"
          >
            <ActionIcon name="import" className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
            <span>Import Profile</span>
          </button>
          <button
            onClick={handleExportProfileJson}
            className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center gap-1.5"
            title="Save your currently checked items to Downloads as windebloat-profile.json"
          >
            <ActionIcon name="export" className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
            <span>Export Profile {selectedIds.size > 0 ? `(${selectedIds.size})` : ""}</span>
          </button>
          <button
            onClick={handleOpenReviewModal}
            disabled={previewingDryRun || applying}
            className="px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-60 shadow-sm flex items-center gap-1.5"
          >
            {previewingDryRun || applying ? (
              <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : (
              <ActionIcon name="apply" className="w-3.5 h-3.5" />
            )}
            <span>
              {applying
                ? "Applying…"
                : previewingDryRun
                ? "Preparing Review…"
                : `Review & Apply (${selectedIds.size} selected) →`}
            </span>
          </button>
        </div>
      </header>

      {/* Main Navigation Bar */}
      <nav className="border-b border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-900/60 px-6 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-1">
          {(
            [
              ["configure", "Configure & Debloat"],
              ["history", `Undo History (${journal.filter((j) => j.state === "Verified").length})`],
              ["drift", `Drift Check (${driftedCount} changed)`],
              ["panels", "Quick Admin Panels"],
              ["about", "About & Custom Manifests"],
            ] as [MainTab, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeTab === id
                  ? "border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400 bg-white dark:bg-slate-950"
                  : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
              }`}
            >
              <TabIcon tab={id} className="w-3.5 h-3.5" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {selectedIds.size > 0 && (
          <div className="flex items-center gap-3 text-xs">
            <span className="font-medium text-blue-600 dark:text-blue-400">
              {selectedIds.size} change(s) selected to apply
            </span>
            <button
              onClick={clearSelection}
              className="text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 underline"
            >
              Clear selection
            </button>
          </div>
        )}
      </nav>

      {/* Global Busy Indicator Bar */}
      {(probing || previewingDryRun || applying || undoingEntryId !== null || restartingExplorer) && (
        <div className="bg-blue-50 dark:bg-blue-950/80 border-b border-blue-200 dark:border-blue-800 px-6 py-2 text-xs text-blue-900 dark:text-blue-200 flex items-center gap-2.5 flex-shrink-0">
          <span className="inline-block w-3.5 h-3.5 border-2 border-blue-600 dark:border-blue-400 border-t-transparent rounded-full animate-spin flex-shrink-0" />
          <span className="font-medium">
            {applying
              ? `Applying changes via elevated Administrator daemon (${applyEvents.length} status update(s))…`
              : previewingDryRun
              ? "Inspecting selected tweaks and preparing Dry-Run Review…"
              : undoingEntryId !== null
              ? "Reverting change via elevated Administrator daemon…"
              : restartingExplorer
              ? "Restarting Windows Explorer shell…"
              : "Scanning your PC's current app, registry, service, and policy states in the background…"}
          </span>
        </div>
      )}

      {/* Genuine Servicing Reboot Warning, Export Confirmation, or Error Banner */}
      {bootstrap?.pending_reboot && (
        <div className="bg-amber-100 dark:bg-amber-950 border-b border-amber-300 dark:border-amber-800 px-6 py-2 text-xs text-amber-900 dark:text-amber-200 flex-shrink-0">
          <strong>Windows Update Restart Pending:</strong> {bootstrap.pending_reboot}. Please
          restart Windows before modifying Optional Features.
        </div>
      )}
      {exportSuccessBanner && (
        <div className="bg-emerald-100 dark:bg-emerald-950 border-b border-emerald-300 dark:border-emerald-800 px-6 py-2 text-xs text-emerald-900 dark:text-emerald-200 flex justify-between items-center flex-shrink-0">
          <span>
            <strong>✓ Saved:</strong> {exportSuccessBanner.message}
          </span>
          <div className="flex items-center gap-3 ml-4">
            <button
              onClick={() => revealInExplorer(exportSuccessBanner.filePath)}
              className="px-2.5 py-1 rounded bg-emerald-700 text-white font-semibold hover:bg-emerald-800"
            >
              📂 Show in File Explorer
            </button>
            <button
              onClick={() => setExportSuccessBanner(null)}
              className="underline font-semibold"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}
      {errorBanner && (
        <div className="bg-red-100 dark:bg-red-950 border-b border-red-300 dark:border-red-800 px-6 py-2 text-xs text-red-900 dark:text-red-200 flex justify-between items-center flex-shrink-0">
          <span>{errorBanner}</span>
          <button onClick={() => setErrorBanner(null)} className="underline ml-4 font-semibold">
            Dismiss
          </button>
        </div>
      )}

      {/* TAB 1: UNIFIED CONFIGURE & DEBLOAT WORKSPACE */}
      {activeTab === "configure" && (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Drift Alert Banner when previous changes reverted */}
          {driftedCount > 0 && (
            <div className="mx-6 mt-4 p-3 rounded-lg border border-amber-300 bg-amber-50 dark:bg-amber-950/50 dark:border-amber-800 flex items-center justify-between text-xs flex-shrink-0">
              <div>
                <strong>{driftedCount} previously applied item(s) have changed</strong> since you
                applied them (for example, after a Windows Update).
              </div>
              <button
                onClick={() => setActiveTab("drift")}
                className="px-3 py-1 rounded bg-amber-700 text-white font-semibold"
              >
                Review Drift
              </button>
            </div>
          )}

          {/* STEP 1: Quick-Start Preset Bar */}
          <div className="px-6 pt-3.5 pb-3 border-b border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-900/30 flex-shrink-0">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Step 1 — Quick-Start Preset (Optional: click a preset to select items not yet
                applied on your PC)
              </div>
              {presetInfoBanner && (
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">
                  {presetInfoBanner}
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
              {(bootstrap?.profiles ?? []).map((prof) => {
                const isSelectedPreset = activePresetId === prof.id;
                return (
                  <button
                    key={prof.id}
                    onClick={() => applyPresetProfile(prof)}
                    className={`text-left p-3 rounded-lg border transition-all ${
                      isSelectedPreset
                        ? "border-blue-600 bg-blue-50/70 dark:bg-blue-950/40 ring-1 ring-blue-600"
                        : "border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-blue-400"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs flex items-center gap-1.5">
                        <PresetIcon
                          presetId={prof.id}
                          className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 flex-shrink-0"
                        />
                        <span>
                          {isSelectedPreset ? `✓ ${prof.name} Preset` : `${prof.name} Preset`}
                        </span>
                      </span>
                      <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-200">
                        {prof.bundles.length} items
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 line-clamp-2">
                      {prof.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* STEP 2: Left Category Filter + Center Item List + Optional Right Details Drawer */}
          <div className="flex-1 flex overflow-hidden">
            {/* Left Sidebar: Category Filter */}
            <aside className="w-60 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 overflow-y-auto flex-shrink-0">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-2.5 mb-2">
                Step 2 — Filter by Category
              </div>
              <div className="space-y-1">
                <button
                  onClick={() => setCategoryFilter("ALL")}
                  className={`w-full text-left px-3 py-2 rounded-md text-xs font-medium flex items-center justify-between ${
                    categoryFilter === "ALL"
                      ? "bg-blue-600 text-white"
                      : "text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                  }`}
                >
                  <span className="flex items-center gap-2 min-w-0">
                    <CategoryIcon category="ALL" className="w-3.5 h-3.5 flex-shrink-0 opacity-90" />
                    <span className="truncate">All Categories</span>
                  </span>
                  <span className="text-[11px] opacity-80">
                    {selectedIds.size > 0
                      ? `${selectedIds.size}/${bundles.filter((b) => probes[b.id]?.gating.applicable ?? true).length}`
                      : bundles.filter((b) => probes[b.id]?.gating.applicable ?? true).length}
                  </span>
                </button>

                {ALL_CATEGORIES.map((cat) => {
                  const catBundles = bundles.filter(
                    (b) => b.category === cat && (probes[b.id]?.gating.applicable ?? true)
                  );
                  const checkedCount = catBundles.filter((b) => selectedIds.has(b.id)).length;
                  const isActive = categoryFilter === cat;
                  return (
                    <button
                      key={cat}
                      onClick={() => setCategoryFilter(cat)}
                      className={`w-full text-left px-3 py-2 rounded-md text-xs font-medium flex items-center justify-between ${
                        isActive
                          ? "bg-blue-600 text-white"
                          : "text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                      }`}
                    >
                      <span className="flex items-center gap-2 min-w-0">
                        <CategoryIcon category={cat} className="w-3.5 h-3.5 flex-shrink-0 opacity-90" />
                        <span className="truncate">{cat}</span>
                      </span>
                      <span
                        className={`text-[11px] px-1.5 py-0.5 rounded ${
                          isActive
                            ? "bg-blue-700 text-white"
                            : checkedCount > 0
                            ? "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 font-semibold"
                            : "text-slate-400"
                        }`}
                      >
                        {checkedCount > 0
                          ? `${checkedCount}/${catBundles.length}`
                          : catBundles.length}
                      </span>
                    </button>
                  );
                })}
              </div>
            </aside>

            {/* Center: Item List */}
            <main className="flex-1 overflow-y-auto p-5 space-y-4">
              {/* Power-User Search & Quick Filter Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 bg-white dark:bg-slate-900 p-3 rounded-lg border border-slate-200 dark:border-slate-800 shadow-sm">
                <div className="flex-1 min-w-[260px] flex items-center gap-2 relative">
                  <ActionIcon
                    name="search"
                    className="w-3.5 h-3.5 text-slate-400 absolute left-3 pointer-events-none"
                  />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search tweaks, apps, registry keys, or services (e.g. Copilot, Recall, Xbox, Taskbar, OneDrive, Paint)..."
                    className="w-full pl-8 pr-3 py-1.5 text-xs rounded-md border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery("")}
                      className="text-xs px-2 py-1 rounded bg-slate-200 dark:bg-slate-800"
                    >
                      Clear
                    </button>
                  )}
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <button
                    onClick={selectAllVisibleRecommended}
                    className="px-2.5 py-1.5 rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 font-medium"
                  >
                    + Select Recommended in View
                  </button>
                  <button
                    onClick={() => setShowExpertItems(!showExpertItems)}
                    className="px-2.5 py-1.5 rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 font-medium"
                  >
                    {showExpertItems ? "Hide Expert Tweaks" : "Show Expert Tweaks"}
                  </button>
                </div>
              </div>
              {(["recommended", "limited", "expert"] as Rating[]).map((rating) => {
                const items = visibleBundles.filter((b) => b.rating === rating);
                if (items.length === 0) return null;

                const isExpertCollapsed = rating === "expert" && !showExpertItems;
                return (
                  <div
                    key={rating}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm"
                  >
                    <div className="px-4 py-3 bg-slate-100/80 dark:bg-slate-800/60 flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
                      <div>
                        <span className="text-xs font-bold uppercase tracking-wider">
                          {RATING_LABELS[rating].title} ({items.length})
                        </span>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">
                          {RATING_LABELS[rating].subtitle}
                        </p>
                      </div>
                      {rating === "expert" && (
                        <button
                          onClick={() => setShowExpertItems(!showExpertItems)}
                          className="text-xs font-semibold text-blue-600 dark:text-blue-400 underline"
                        >
                          {showExpertItems ? "Hide Expert Items" : "Show Expert Items"}
                        </button>
                      )}
                    </div>

                    {!isExpertCollapsed && (
                      <div className="divide-y divide-slate-200 dark:divide-slate-800">
                        {items.map((bundle) => {
                          const alreadyDone = isBundleAlreadyDone(bundle.id);
                          const isChecked = selectedIds.has(bundle.id);
                          const isInspected = inspectedBundleId === bundle.id;

                          return (
                            <div
                              key={bundle.id}
                              onClick={() => toggleBundle(bundle.id, bundle)}
                              className={`p-4 flex items-center justify-between gap-4 transition-colors ${
                                alreadyDone
                                  ? "bg-slate-50/60 dark:bg-slate-900/40 cursor-default"
                                  : isChecked
                                  ? "bg-blue-50/60 dark:bg-blue-950/30 cursor-pointer"
                                  : "hover:bg-slate-50 dark:hover:bg-slate-800/40 cursor-pointer"
                              }`}
                            >
                              <div className="flex items-start gap-3.5 min-w-0">
                                <input
                                  type="checkbox"
                                  disabled={alreadyDone}
                                  checked={isChecked}
                                  onChange={() => {}}
                                  title={
                                    alreadyDone
                                      ? "This item is already applied/uninstalled on your PC"
                                      : "Select this item to apply it"
                                  }
                                  className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 disabled:opacity-40"
                                />
                                <div className="min-w-0">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span
                                      className={`text-sm font-semibold ${
                                        alreadyDone
                                          ? "text-slate-500 dark:text-slate-400"
                                          : ""
                                      }`}
                                    >
                                      {bundle.display_name}
                                    </span>
                                    <span className="text-[11px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500">
                                      {bundle.category}
                                    </span>
                                  </div>
                                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                                    {bundle.description}
                                  </p>
                                  <div className="mt-1.5 flex items-center gap-3 text-[11px]">
                                    <span className="text-slate-500">
                                      Effect: {bundle.side_effects[0]}
                                    </span>
                                    <button
                                      type="button"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setInspectedBundleId(isInspected ? null : bundle.id);
                                      }}
                                      className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
                                    >
                                      {isInspected
                                        ? "Hide technical targets"
                                        : "Inspect registry / package targets →"}
                                    </button>
                                  </div>
                                </div>
                              </div>

                              {renderStatusAndActionBadges(bundle, isChecked)}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Gated-Out Items Disclosure */}
              {gatedOutBundles.length > 0 && (
                <div className="pt-1">
                  <button
                    onClick={() => setShowHiddenGatedItems(!showHiddenGatedItems)}
                    className="text-xs text-slate-500 dark:text-slate-400 underline"
                  >
                    {showHiddenGatedItems
                      ? "Hide items not applicable to this Windows edition/build"
                      : `${gatedOutBundles.length} item(s) hidden because they do not apply to Windows Build ${bootstrap?.environment.build_number} — click to view`}
                  </button>
                  {showHiddenGatedItems && (
                    <div className="mt-2 space-y-2">
                      {gatedOutBundles.map((b) => (
                        <div
                          key={b.id}
                          className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-900 text-xs flex justify-between"
                        >
                          <span className="font-medium">{b.display_name}</span>
                          <span className="text-amber-700 dark:text-amber-400">
                            {probes[b.id]?.gating.skip_reason}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </main>

            {/* Right Technical Drawer: ONLY opens when the user clicks "Inspect registry / package targets" */}
            {inspectedBundle && (
              <aside className="w-96 border-l border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 overflow-y-auto flex-shrink-0">
                <div className="flex items-start justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
                  <div>
                    <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                      Technical Target Inspector
                    </div>
                    <h3 className="text-sm font-bold mt-0.5">{inspectedBundle.display_name}</h3>
                  </div>
                  <button
                    onClick={() => setInspectedBundleId(null)}
                    className="text-xs px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200"
                  >
                    ✕ Close
                  </button>
                </div>

                <div className="space-y-4 text-xs mt-4">
                  <p className="text-slate-600 dark:text-slate-300">
                    {inspectedBundle.description}
                  </p>

                  {probes[inspectedBundle.id]?.gating.effective_on_note && (
                    <div className="p-2.5 rounded border border-amber-300 bg-amber-50 dark:bg-amber-950/50 dark:border-amber-800 text-amber-900 dark:text-amber-200">
                      {probes[inspectedBundle.id].gating.effective_on_note}
                    </div>
                  )}

                  <div>
                    <div className="font-semibold mb-1">Side Effects</div>
                    <ul className="list-disc list-inside space-y-1 text-slate-600 dark:text-slate-400">
                      {inspectedBundle.side_effects.map((se, i) => (
                        <li key={i}>{se}</li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <div className="font-semibold mb-1.5">
                      Exact OS Operations ({inspectedBundle.actions.length})
                    </div>
                    <div className="space-y-2">
                      {inspectedBundle.actions.map((act, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 space-y-1 font-mono text-[11px] break-all"
                        >
                          <div className="font-bold text-blue-600 dark:text-blue-400">
                            #{idx + 1} {act.type}
                          </div>
                          {act.type === "registry_set" && (
                            <div>
                              {act.hive}\{act.path}\{act.name || "(Default)"} ={" "}
                              {JSON.stringify(act.value)} ({act.value_type})
                            </div>
                          )}
                          {(act.type === "appx_remove" ||
                            act.type === "appx_provisioned_remove") && (
                            <div>Package: {act.package_family_name}</div>
                          )}
                          {act.type === "service_startup" && (
                            <div>
                              Service: {act.service_name} → {act.start_type}
                            </div>
                          )}
                          {act.type === "scheduled_task_disable" && (
                            <div>Task: {act.task_path}</div>
                          )}
                          {act.type === "capability_remove" && (
                            <div>Capability: {act.capability_name}</div>
                          )}
                          {act.type === "optional_feature" && (
                            <div>
                              Feature: {act.feature_name} → enabled={String(act.feature_enabled)}
                            </div>
                          )}
                          <div className="font-sans text-slate-500 pt-1 border-t border-slate-200 dark:border-slate-800 break-normal">
                            Undo:{" "}
                            <strong>
                              {act.undo.tier === "automatic"
                                ? "Automatic (Restores previous value)"
                                : act.undo.tier === "manual_assisted"
                                ? `Reinstall via Microsoft Store (${act.undo.product_id})`
                                : "Irreversible"}
                            </strong>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </aside>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: UNDO HISTORY */}
      {activeTab === "history" && (
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-4xl space-y-4">
            {(() => {
              const verifiedEntries = journal.filter((e) => e.state === "Verified");
              const selectedVerifiedCount = verifiedEntries.filter((e) =>
                historySelectedIds.has(e.entry_id)
              ).length;
              const allVerifiedSelected =
                verifiedEntries.length > 0 &&
                selectedVerifiedCount === verifiedEntries.length;

              return (
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="text-base font-bold">Undo History</h2>
                    <p className="text-xs text-slate-500">
                      Every change WinDebloat makes is recorded before modification so you can revert
                      individual items, selected items, or all changes at once.
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {verifiedEntries.length > 0 && (
                      <>
                        <button
                          disabled={undoingEntryId !== null}
                          onClick={() => {
                            if (allVerifiedSelected) {
                              setHistorySelectedIds(new Set());
                            } else {
                              setHistorySelectedIds(
                                new Set(verifiedEntries.map((e) => e.entry_id))
                              );
                            }
                          }}
                          className="px-3 py-1.5 text-xs font-medium rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
                        >
                          {allVerifiedSelected
                            ? "Clear Selection"
                            : `Select All (${verifiedEntries.length})`}
                        </button>
                        <button
                          disabled={selectedVerifiedCount === 0 || undoingEntryId !== null}
                          onClick={() => handleUndoMultiple("selected", false)}
                          className="px-3.5 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1.5"
                        >
                          {undoingEntryId === "__SELECTED__" && (
                            <span className="inline-block h-3 w-3 rounded-full border-2 border-white border-t-transparent animate-spin" />
                          )}
                          {undoingEntryId === "__SELECTED__"
                            ? "Undoing Selected…"
                            : `Undo Selected (${selectedVerifiedCount})`}
                        </button>
                        <button
                          disabled={undoingEntryId !== null}
                          onClick={() => handleUndoMultiple("all", false)}
                          className="px-3.5 py-1.5 text-xs font-semibold rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 hover:opacity-90 disabled:opacity-50 flex items-center gap-1.5"
                        >
                          {undoingEntryId === "__ALL__" && (
                            <span className="inline-block h-3 w-3 rounded-full border-2 border-current border-t-transparent animate-spin" />
                          )}
                          {undoingEntryId === "__ALL__"
                            ? "Undoing All…"
                            : `Undo All (${verifiedEntries.length})`}
                        </button>
                      </>
                    )}
                    <button
                      onClick={handleExportJournalJson}
                      className="px-3 py-1.5 text-xs font-medium rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      Export Journal JSON
                    </button>
                  </div>
                </div>
              );
            })()}

            {undoSummaryBanner && (
              <div className="p-3 rounded-lg border border-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 dark:border-emerald-800 flex items-center justify-between gap-3 text-xs text-emerald-900 dark:text-emerald-200">
                <span>✓ {undoSummaryBanner}</span>
                <button
                  onClick={() => setUndoSummaryBanner(null)}
                  className="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/60 font-medium"
                >
                  Dismiss
                </button>
              </div>
            )}

            {undoConflictModal && undoConflictModal.outcome === "conflict" && (
              <div className="p-4 rounded-lg border-2 border-amber-500 bg-amber-50 dark:bg-amber-950/60 space-y-2 text-xs">
                <div className="font-bold text-sm">
                  Setting Modified Externally Since WinDebloat Applied It
                </div>
                <p className="break-all">
                  Target <code>{undoConflictModal.target}</code> was changed by another program or
                  user after WinDebloat set it:
                </p>
                <div className="font-mono bg-white dark:bg-slate-900 p-2 rounded space-y-1">
                  <div>
                    Original value before WinDebloat: {JSON.stringify(undoConflictModal.prior)}
                  </div>
                  <div>
                    Value written by WinDebloat: {JSON.stringify(undoConflictModal.written)}
                  </div>
                  <div>Current value on PC: {JSON.stringify(undoConflictModal.current)}</div>
                </div>
                <div className="flex gap-2 pt-1">
                  <button
                    disabled={undoingEntryId !== null}
                    onClick={() => handleUndoEntry(undoConflictModal.entry_id, true)}
                    className="px-3 py-1.5 rounded bg-amber-600 text-white font-semibold disabled:opacity-50"
                  >
                    {undoingEntryId === undoConflictModal.entry_id
                      ? "Overwriting & Restoring…"
                      : "Overwrite & Restore Original Value"}
                  </button>
                  <button
                    disabled={undoingEntryId !== null}
                    onClick={() => setUndoConflictModal(null)}
                    className="px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 disabled:opacity-50"
                  >
                    Keep Current Value
                  </button>
                </div>
              </div>
            )}

            <div className="space-y-2">
              {journal
                .filter((e) => e.state === "Verified" || e.state === "Undone")
                .map((entry) => {
                  const matchedBundle = bootstrap?.bundles.find(
                    (b) => b.id === entry.bundle_id
                  );
                  const isUndoing = undoingEntryId === entry.entry_id;
                  const isChecked = historySelectedIds.has(entry.entry_id);
                  return (
                    <div
                      key={entry.entry_id}
                      className="p-3.5 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between gap-4 text-xs"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        {entry.state === "Verified" && (
                          <input
                            type="checkbox"
                            checked={isChecked}
                            disabled={undoingEntryId !== null}
                            onChange={() => {
                              setHistorySelectedIds((prev) => {
                                const next = new Set(prev);
                                if (next.has(entry.entry_id)) next.delete(entry.entry_id);
                                else next.add(entry.entry_id);
                                return next;
                              });
                            }}
                            className="mt-1 h-3.5 w-3.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500 flex-shrink-0"
                          />
                        )}
                        <div className="space-y-1 min-w-0">
                          <div className="font-semibold flex flex-wrap items-center gap-2">
                            <span>
                              {matchedBundle
                                ? `${matchedBundle.display_name} (${entry.bundle_id})`
                                : entry.bundle_id}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded font-semibold ${
                                entry.state === "Verified"
                                  ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                                  : entry.state === "Undone"
                                  ? "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300"
                                  : "bg-slate-100 dark:bg-slate-800"
                              }`}
                            >
                              {entry.state}
                            </span>
                            <span className="text-slate-400">{entry.applied_at}</span>
                          </div>
                          <div className="font-mono text-slate-600 dark:text-slate-300 break-all">
                            {entry.target}
                          </div>
                        </div>
                      </div>

                      {entry.state === "Verified" && (
                        <button
                          disabled={undoingEntryId !== null}
                          onClick={() => handleUndoEntry(entry.entry_id, false)}
                          className="px-3 py-1.5 rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 font-semibold flex-shrink-0 disabled:opacity-50 flex items-center gap-1.5"
                        >
                          {isUndoing && (
                            <span className="inline-block h-3 w-3 rounded-full border-2 border-current border-t-transparent animate-spin" />
                          )}
                          {isUndoing ? "Undoing…" : "Undo This Change"}
                        </button>
                      )}
                    </div>
                  );
                })}
              {journal.filter((e) => e.state === "Verified" || e.state === "Undone")
                .length === 0 && (
                <p className="text-xs text-slate-500">
                  No changes have been applied yet. Select tweaks on the Configure & Debloat tab to
                  get started.
                </p>
              )}
            </div>
          </div>
        </main>
      )}

      {/* TAB 3: DRIFT CHECK */}
      {activeTab === "drift" && (
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-4xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold">Configuration Drift Detection</h2>
                <p className="text-xs text-slate-500">
                  Checks whether Windows Update or another app has reverted any of your previously
                  applied tweaks.
                </p>
              </div>
              <button
                disabled={driftSelectedBundles.size === 0 || applying}
                onClick={() => handleExecuteApply(Array.from(driftSelectedBundles))}
                className="px-4 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white disabled:opacity-50"
              >
                Re-apply Selected ({driftSelectedBundles.size})
              </button>
            </div>

            <div className="space-y-2">
              {driftItems.map((item) => {
                const isDrifted =
                  item.status === "reverted" || item.status === "changed_by_other";
                return (
                  <div
                    key={item.entry_id}
                    className="p-3.5 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between gap-4 text-xs"
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      {isDrifted && (
                        <input
                          type="checkbox"
                          checked={driftSelectedBundles.has(item.bundle_id)}
                          onChange={() => {
                            setDriftSelectedBundles((prev) => {
                              const next = new Set(prev);
                              if (next.has(item.bundle_id)) next.delete(item.bundle_id);
                              else next.add(item.bundle_id);
                              return next;
                            });
                          }}
                          className="mt-1"
                        />
                      )}
                      <div className="min-w-0">
                        <div className="font-semibold">{item.bundle_id}</div>
                        <div className="font-mono text-slate-500 mt-0.5 break-all">
                          {item.target}
                        </div>
                      </div>
                    </div>
                    <span
                      className={`px-2.5 py-1 rounded font-semibold flex-shrink-0 ${
                        item.status === "intact"
                          ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                          : "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300"
                      }`}
                    >
                      {item.status === "intact"
                        ? "✓ Still Applied"
                        : "Changed Since You Applied It"}
                    </span>
                  </div>
                );
              })}
              {driftItems.length === 0 && (
                <p className="text-xs text-slate-500">
                  No previously applied items to check for drift yet.
                </p>
              )}
            </div>
          </div>
        </main>
      )}

      {/* TAB 4: QUICK ADMIN PANELS (Inspired by ChrisTitusTech/winutil) */}
      {activeTab === "panels" && (
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-5xl space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold">
                  Quick Windows Admin & Classic Control Panels
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  One-click access to classic Windows Control Panel applets (<code>.cpl</code>) and
                  Microsoft Management Consoles (<code>.msc</code>) that Windows 11 buries behind
                  Settings menus.
                </p>
              </div>
              <button
                disabled={restartingExplorer}
                onClick={handleRestartExplorer}
                className="px-3 py-1.5 text-xs font-semibold rounded border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 flex items-center gap-1.5"
              >
                {restartingExplorer ? (
                  <>
                    <span className="inline-block h-3 w-3 rounded-full border-2 border-current border-t-transparent animate-spin" />
                    Restarting Explorer…
                  </>
                ) : explorerRestarted ? (
                  "✓ Explorer Restarted (Click to Restart Again)"
                ) : (
                  "↻ Restart Windows Explorer"
                )}
              </button>
            </div>

            {(
              [
                "Classic Control Panels (.cpl)",
                "System & Management Consoles (.msc)",
              ] as const
            ).map((groupName) => (
              <div key={groupName} className="space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {groupName}
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {ADMIN_PANELS.filter((p) => p.group === groupName).map((panel) => (
                    <button
                      key={panel.id}
                      onClick={async () => {
                        try {
                          await openAdminPanel(panel.id);
                        } catch (e) {
                          setErrorBanner(String(e));
                        }
                      }}
                      className="text-left p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-blue-500 hover:shadow-sm transition-all flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-bold text-xs text-slate-900 dark:text-slate-100">
                            {panel.title}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-blue-600 dark:text-blue-400 flex-shrink-0">
                            {panel.commandLabel}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1.5">
                          {panel.description}
                        </p>
                      </div>
                      <div className="mt-3 text-[11px] font-semibold text-blue-600 dark:text-blue-400">
                        Open Panel ↗
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </main>
      )}

      {/* TAB 5: ABOUT & CUSTOM MANIFESTS */}
      {activeTab === "about" && (
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-2xl space-y-5 text-xs leading-relaxed">
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-base font-bold">About WinDebloat</h2>
                <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800">
                  {bootstrap?.app_version ?? "2026-10-17_Beta_0.9.101"}
                </span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 mt-1">
                WinDebloat is a native Windows 10 (22H2+) & Windows 11 configuration and debloat
                engine that executes via native Win32, WinRT PackageManager, DISM, SCM, and Task
                Scheduler COM APIs without relying on PowerShell scripts.
              </p>
            </div>

            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
              <div className="font-semibold text-sm">
                Custom Manifests (.json) — For Power Users & IT Admins
              </div>
              <p className="text-slate-600 dark:text-slate-400">
                While <strong>Export / Import Profile</strong> saves a simple checklist of which
                built-in tweaks you selected, <strong>Load Custom Manifest</strong> lets IT
                administrators, sysadmins, and enthusiasts add <em>brand-new</em> registry policies,
                service rules, scheduled task blocks, or company-specific app removals into
                WinDebloat without recompiling the executable.
              </p>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <button
                  onClick={handleLoadCustomManifest}
                  className="px-3 py-1.5 rounded bg-blue-600 text-white font-semibold hover:bg-blue-700"
                >
                  Load Custom Manifest (.json)…
                </button>
                <button
                  onClick={handleSaveSampleCustomManifest}
                  className="px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 font-medium hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  Save Sample Custom Manifest Template to Downloads
                </button>
              </div>
            </div>

            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
              <div className="font-semibold text-sm">Developer & Testing Options</div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">Simulation / Test Mode (No Real OS Changes)</div>
                  <div className="text-slate-500">
                    When enabled, Apply and Undo run against a temporary sandbox file instead of
                    modifying your real Windows installation or prompting for UAC.
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={bootstrap?.sandbox_mode ?? false}
                  onChange={async (e) => {
                    await setSandboxMode(e.target.checked);
                    await refreshAllState();
                  }}
                  className="h-4 w-4"
                />
              </div>

              <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-slate-400 font-mono text-[11px]">
                Interactive User SID: {bootstrap?.user_sid} · Session LUID:{" "}
                {bootstrap?.session_luid}
              </div>
            </div>

            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-1">
              <div className="font-semibold">Credits & License (MIT)</div>
              <p className="text-slate-600 dark:text-slate-400">
                Base manifest app lists, service policies, and registry tweaks draw upon{" "}
                <strong>Raphire/Win11Debloat</strong>, <strong>ChrisTitusTech/winutil</strong>, and{" "}
                <strong>Sycnex/Windows10Debloater</strong>.
              </p>
            </div>
          </div>
        </main>
      )}

      {/* GUIDED REVIEW (DRY RUN) & APPLY MODAL OVERLAY */}
      {reviewModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-6">
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold">
                  {applySummary
                    ? "Changes Applied"
                    : applying
                    ? "Applying Changes…"
                    : previewingDryRun
                    ? "Calculating Dry-Run Preview…"
                    : "Review Planned Changes Before Applying"}
                </h2>
                <p className="text-xs text-slate-500">
                  {bootstrap?.sandbox_mode
                    ? "Running in Simulation Mode (no real Windows changes will be made)."
                    : "Applying will prompt for Administrator permission (UAC) once to execute these changes."}
                </p>
              </div>
              <button
                disabled={applying}
                onClick={() => setReviewModalOpen(false)}
                className="px-2.5 py-1 text-xs rounded bg-slate-100 dark:bg-slate-800 disabled:opacity-50"
              >
                ✕ Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs">
              {/* Loading state while dry-run preview is being computed */}
              {previewingDryRun && !applying && !applySummary && (
                <div className="p-8 rounded-lg border border-blue-200 bg-blue-50/60 dark:border-blue-900 dark:bg-blue-950/30 flex flex-col items-center justify-center gap-3 text-center">
                  <span className="inline-block h-6 w-6 rounded-full border-2 border-blue-600 border-t-transparent animate-spin" />
                  <div className="font-semibold text-sm text-blue-900 dark:text-blue-200">
                    Inspecting Selected Bundles Against Current PC State…
                  </div>
                  <p className="text-slate-600 dark:text-slate-400 max-w-md">
                    Checking registry keys, Windows services, scheduled tasks, and Appx packages to
                    determine which actions need to run and which are already applied.
                  </p>
                </div>
              )}

              {/* Pre-Apply Dry Run Summary */}
              {!previewingDryRun && !applying && !applySummary && dryRunReport && (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-slate-500">Actions to Execute</div>
                      <div className="text-lg font-bold text-blue-600">
                        {dryRunReport.estimated_applied_count}
                      </div>
                    </div>
                    <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-slate-500">Already Done (Skipped)</div>
                      <div className="text-lg font-bold text-slate-600 dark:text-slate-300">
                        {dryRunReport.estimated_skipped_count}
                      </div>
                    </div>
                    <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-slate-500">Explorer Restart</div>
                      <div className="font-semibold mt-1">
                        {dryRunReport.requires_explorer_restart ? "Recommended" : "Not Needed"}
                      </div>
                    </div>
                    <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                      <div className="text-slate-500">System Reboot</div>
                      <div className="font-semibold mt-1">
                        {dryRunReport.requires_reboot ? "Required After Run" : "Not Needed"}
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2.5">
                    {dryRunReport.bundles.map((b) => (
                      <div
                        key={b.bundle_id}
                        className="rounded border border-slate-200 dark:border-slate-800 p-3.5"
                      >
                        <div className="font-semibold text-sm mb-2">{b.display_name}</div>
                        <div className="space-y-1.5">
                          {b.actions.map((act) => (
                            <div
                              key={`${b.bundle_id}-${act.action_index}-${act.target}`}
                              className="font-mono text-[11px] p-2 rounded bg-slate-50 dark:bg-slate-950 flex justify-between items-center gap-3 break-all"
                            >
                              <div>
                                <span className="font-bold text-blue-600 dark:text-blue-400">
                                  [{act.action_type}]
                                </span>{" "}
                                {act.target}
                              </div>
                              <span
                                className={`px-2 py-0.5 rounded font-sans font-semibold flex-shrink-0 ${
                                  act.planned_state === "Planned"
                                    ? "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300"
                                    : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-400"
                                }`}
                              >
                                {act.planned_state === "Planned" ? "Will Execute" : "Already Done"}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}

              {/* Live Apply Progress & Final Summary */}
              {(applying || applySummary) && (
                <div className="space-y-3">
                  {applying && (
                    <div className="p-4 rounded-lg border border-blue-300 bg-blue-50 dark:bg-blue-950/40 dark:border-blue-800 flex items-center gap-3">
                      <span className="inline-block h-5 w-5 rounded-full border-2 border-blue-600 border-t-transparent animate-spin flex-shrink-0" />
                      <div>
                        <div className="font-bold text-sm text-blue-900 dark:text-blue-200">
                          Applying Selected Changes… ({applyEvents.length} actions processed)
                        </div>
                        <div className="text-slate-600 dark:text-slate-400 mt-0.5">
                          {applyEvents.length === 0
                            ? "Waiting for Administrator (UAC) approval and elevated daemon connection…"
                            : "Executing native registry, service, task, and package operations…"}
                        </div>
                      </div>
                    </div>
                  )}

                  {applySummary && (
                    <div className="p-4 rounded-lg border border-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 dark:border-emerald-800 space-y-2">
                      <div className="font-bold text-sm">
                        Run Complete — {applySummary.verified_count} applied & verified,{" "}
                        {applySummary.skipped_count} already in desired state,{" "}
                        {applySummary.failed_count} failed.
                      </div>
                      {applySummary.requires_explorer_restart && !explorerRestarted && (
                        <div className="flex items-center justify-between pt-2 gap-3">
                          <span>
                            Restart Windows Explorer now so taskbar and context-menu changes take
                            effect immediately?
                          </span>
                          <button
                            disabled={restartingExplorer}
                            onClick={handleRestartExplorer}
                            className="px-3 py-1 rounded bg-blue-600 text-white font-semibold hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1.5 flex-shrink-0"
                          >
                            {restartingExplorer && (
                              <span className="inline-block h-3 w-3 rounded-full border-2 border-white border-t-transparent animate-spin" />
                            )}
                            {restartingExplorer ? "Restarting…" : "Restart Explorer Now"}
                          </button>
                        </div>
                      )}
                      {explorerRestarted && (
                        <div className="pt-2 text-emerald-800 dark:text-emerald-300 font-semibold flex items-center gap-1.5">
                          <span>✓ Windows Explorer has been restarted — taskbar and context-menu changes are now active.</span>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="space-y-1.5">
                    {applyEvents.map((ev, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3"
                      >
                        <div className="font-mono text-[11px] break-all">
                          <strong>{ev.bundle_id}</strong> · {ev.target}
                          {ev.error && <div className="text-red-600 mt-0.5">{ev.error}</div>}
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded font-semibold flex-shrink-0 ${
                            ev.state === "Verified"
                              ? "bg-emerald-100 text-emerald-800"
                              : ev.state === "Failed"
                              ? "bg-red-100 text-red-800"
                              : "bg-slate-200 text-slate-700"
                          }`}
                        >
                          {ev.state}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 flex items-center justify-end gap-3">
              {!applying && !applySummary && (
                <>
                  <button
                    onClick={() => setReviewModalOpen(false)}
                    className="px-4 py-2 text-xs font-medium rounded-md border border-slate-300 dark:border-slate-700"
                  >
                    Cancel
                  </button>
                  <button
                    disabled={previewingDryRun}
                    onClick={() => handleExecuteApply()}
                    className="px-5 py-2 text-xs font-semibold rounded-md bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm disabled:opacity-50"
                  >
                    {previewingDryRun ? "Calculating Preview…" : "Confirm & Apply Changes Now"}
                  </button>
                </>
              )}
              {applySummary && (
                <button
                  onClick={() => setReviewModalOpen(false)}
                  className="px-5 py-2 text-xs font-semibold rounded-md bg-blue-600 text-white"
                >
                  Done
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
