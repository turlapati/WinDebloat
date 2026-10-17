<div align="center">
  <img src="apps/windebloat-ui/src-tauri/icons/128x128.png" width="96" height="96" alt="WinDebloat Icon" />
  <h1>WinDebloat</h1>
  <p>
    <strong>Native Windows 10 (22H2+) & Windows 11 Configuration, Privacy, and Debloat Engine</strong>
  </p>
  <p>
    <code>2026-10-17_Beta_0.9.101</code>
  </p>
</div>

WinDebloat is a native Windows configuration and debloat utility. Unlike legacy PowerShell scripts, WinDebloat executes via native Win32, WinRT `PackageManager`, DISM (`dismapi.dll`), Service Control Manager (SCM), and Task Scheduler (`ITaskService`) COM APIs through a transactional Rust engine with **per-item and batch three-way undo** and **post-update drift detection**.

---

## Install

Community releases are **not Authenticode-signed** yet (no paid certificate). That is expected for a new open-source Windows tool.

### MSI from GitHub Releases

1. Download `WinDebloat-2026-10-17_Beta_0.9.101-x64.msi` from [Releases](https://github.com/turlapati/WinDebloat/releases).
2. If SmartScreen shows **"Windows protected your PC"**, click **More info** → **Run anyway**. UAC will show **Unknown publisher**.
3. The installer writes to `C:\Program Files\WinDebloat` and adds a Start Menu shortcut. **That location is required** — the elevated daemon refuses copies run from Downloads or other user-writable folders.

Optional integrity check:

```powershell
(Get-FileHash .\WinDebloat-2026-10-17_Beta_0.9.101-x64.msi -Algorithm SHA256).Hash
```

Compare with the matching `.msi.sha256` file on the release.

---

## Key Features

- **98 Power-User Tweaks Across 8 Categories**:
  - **Apps (42 items)**: Consumer bloatware (Clipchamp, News, Weather, Bing Search, Solitaire, Sticky Notes, Sound Recorder, Todos, Your Phone), Xbox overlays, communication apps (Teams Personal, New Outlook), Edge/OneDrive background policies, and system apps (Paint, Notepad, Calculator, Snipping Tool, Media Player).
  - **Privacy and telemetry (18 items)**: Diagnostic data, Advertising ID, Tailored Experiences, Activity History, Cloud Clipboard, Location tracking, Wi-Fi Sense, Windows Error Reporting, CEIP scheduled tasks, `DiagTrack`/`dmwappushservice`, and Teredo/IPv6 transition disabled.
  - **AI features (5 items)**: Windows Copilot, Windows Recall policy & NPU capability removal, Copilot in Edge, and AI Actions in Notepad/Paint.
  - **Windows Update (4 items)**: Driver exclusions from Windows Update, active-hours auto-restart suppression, Delivery Optimization P2P restriction, and 365-day feature update deferral.
  - **Appearance (6 items)**: System & app Dark Mode, transparency effects, UI animations, mouse acceleration (`Enhance pointer precision`), and Sticky Keys prompt suppression.
  - **Start and taskbar (12 items)**: Left-align taskbar, hide Search/Task View/Widgets/Chat, remove Start menu recommendations & Bing web search, restore classic Windows 10 context menu, End Task on taskbar right-click, and show all system tray icons.
  - **Explorer (8 items)**: Show file extensions & hidden files, open Explorer to `This PC`, remove Gallery/Home/3D Objects, disable Shake-to-Minimize (Aero Shake), and disable network folder discovery (`NoNetCrawling`).
  - **Optional features (3 items)**: Disable SMBv1 protocol, Internet Explorer 11 mode, and Work Folders client.
- **4 Quick-Start Presets**:
  - **Minimal**, **Privacy**, **Gamer**, and **Enterprise**.
- **Quick Windows Admin & Classic Control Panels**:
  - One-click launcher for classic `.cpl` and `.msc` applets (`ncpa.cpl`, `appwiz.cpl`, `sysdm.cpl`, `mmsys.cpl`, `powercfg.cpl`, `inetcpl.cpl`, `main.cpl`, `timedate.cpl`, `services.msc`, `taskschd.msc`, `devmgmt.msc`, `diskmgmt.msc`, `eventvwr.msc`, `gpedit.msc`, `lusrmgr.msc`, `OptionalFeatures.exe`).
- **Three-Way Transactional Undo Journal (Single, Selected, or Undo All)**:
  - Every action records its prior state to `%ProgramData%\WinDebloat\journal.json` with a SHA-256 integrity hash before modification. Undoing a change compares the current OS value against both the prior value and the written value to detect external edits before overwriting.
- **Post-Update Configuration Drift Detection**:
  - Detects when a Windows Feature Update or cumulative update silently reverts any previously applied tweak and allows one-click re-application.

---

## Architecture (3 Binaries, 1 Shared Engine Crate)

| Binary | Runs As | Role |
| --- | --- | --- |
| `windebloat.exe` | Standard user (Tauri v2, WebView2, React, Tailwind) | Rendering, manifest inspector, `--dry-run` review, drift dashboard, Quick Admin Panels, `WM_SETTINGCHANGE` broadcast, Explorer restart |
| `windebloat-daemon.exe` | Elevated on demand via UAC (`ShellExecuteExW(runas)`) | Executes manifest actions by ID over an SDDL-secured Named Pipe (PID + `%ProgramFiles%\WinDebloat` path check; Authenticode when `require-signed-peers` is on); auto-exits after 60s idle |
| `windebloat-cli.exe` | `NT AUTHORITY\SYSTEM` or Elevated Admin | Headless `apply`, `detect`, `drift`, `undo`, `dry-run`, and `verify-manifest` for Intune, SCCM, MDT, and imaging |

---

## Repository Structure

- [`schemas/`](schemas): Canonical JSON Schemas for Manifest v3, Selection Profiles, and the Undo Journal.
- [`manifests/`](manifests): Embedded [`base_manifest.json`](manifests/base_manifest.json) and preset profiles ([`minimal.json`](manifests/profiles/minimal.json), [`privacy.json`](manifests/profiles/privacy.json), [`gamer.json`](manifests/profiles/gamer.json), [`enterprise.json`](manifests/profiles/enterprise.json)).
- [`crates/windebloat-schema`](crates/windebloat-schema): Manifest v3 types, OS Preservation Denylist, structural validator, and Ed25519 signature verifier.
- [`crates/windebloat-engine`](crates/windebloat-engine): 7-state action state machine (`Planned → Captured → Applied → Verified` / `Skipped` / `Failed` / `RolledBack`), `HKCU` → `HKU\<SID>` alias rewriter, `%ProgramData%\WinDebloat\journal.json` with SHA-256 entry hashes, three-way undo, drift classifier, Native Windows adapters (`winreg`, `RegLoadKeyW`, `RegRestoreKeyW`, `PackageManager`, `dismapi.dll`, SCM, `ITaskService`), and `SandboxOsBackend`.
- [`crates/windebloat-ipc`](crates/windebloat-ipc): Named Pipe SDDL builder, token SID/LUID inspector, 256-bit nonce handshake, protected-path check, and `WinVerifyTrust` Authenticode + publisher verification (`require-signed-peers` for signed production builds).
- [`crates/windebloat-daemon`](crates/windebloat-daemon): Elevated RPC daemon binary.
- [`crates/windebloat-cli`](crates/windebloat-cli): Headless CLI binary.
- [`apps/windebloat-ui`](apps/windebloat-ui): Tauri v2 + React + TypeScript + Tailwind UI.
- [`installer/`](installer): WiX v4/v5 MSI installer definition ([`windebloat.wxs`](installer/windebloat.wxs)).

---

## Quick Start (Local Development)

### 1. Run Unit & Manifest Validation Tests
```powershell
cargo test -p windebloat-schema -p windebloat-engine -p windebloat-ipc
```

### 2. Build All Three Binaries
```powershell
npm --prefix apps/windebloat-ui install
npm --prefix apps/windebloat-ui run build
cargo build
```

### 3. Run Headless CLI (Safe Sandbox or Live Mode)
```powershell
# Validate a manifest against Schema v3 and the OS Preservation Denylist
.\target\debug\windebloat-cli.exe verify-manifest manifests\base_manifest.json

# Preview a profile delta (--dry-run) in safe sandbox mode
.\target\debug\windebloat-cli.exe --sandbox dry-run --profile enterprise --target-user all-profiles

# Apply a profile in safe sandbox mode with structured JSONL output
.\target\debug\windebloat-cli.exe --sandbox apply --profile enterprise --target-user all-profiles --log-file run.jsonl

# Check Intune detection status (exit code 0 = applied, 1 = not applied)
.\target\debug\windebloat-cli.exe --sandbox detect --profile enterprise --target-user all-profiles

# Check configuration drift (exit code 0 = intact, 4 = drift detected)
.\target\debug\windebloat-cli.exe --sandbox drift --json
```

---

## License & Attribution

MIT Licensed. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Manifest bundle definitions, package family identifiers, and Windows policy tweaks draw upon:
- [Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat)
- [ChrisTitusTech/winutil](https://github.com/ChrisTitusTech/winutil)
- [Sycnex/Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)
