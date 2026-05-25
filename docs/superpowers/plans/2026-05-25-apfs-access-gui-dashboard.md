# APFS Access GUI Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a simple GUI dashboard that launches with APFS Access, lists APFS drives/partitions and their health, and keeps the tray icon/lifecycle behavior intact.

**Architecture:** Extend the existing `ApfsAccess.Tray` WinForms process instead of creating a second app. Keep service discovery, status subscription, eject, quit, and refresh IPC in one tray/dashboard host; isolate state classification and button enablement into small testable helpers before wiring the visual form.

**Tech Stack:** .NET 9 Windows Forms, existing `ApfsAccess.Ipc` named-pipe messages, existing `ApfsAccess.Core` status models, xUnit tray tests, native/publish validation scripts.

---

## Current Status As Of 2026-05-25

**Branch:** `optimize/read-write-performance`

**Implementation state:** Implemented and validated with focused automated tests plus live APFS smoke. Latest pass adds content-driven row/button sizing, tray left-click dashboard restore, render diffing to avoid refresh flicker, targeted per-volume `Fix`, recoverable safe-ejected dashboard state, and removes the close-to-tray footer reminder.

**Latest validation as of 2026-05-25 17:10 Asia/Shanghai:**

- `dotnet test .\tests\ApfsAccess.Service.Tests\ApfsAccess.Service.Tests.csproj -c Release --no-restore --filter "ApfsMountWorkerAutoMountTests"` passed: 8/8.
- `dotnet test .\tests\ApfsAccess.Ipc.Tests\ApfsAccess.Ipc.Tests.csproj -c Release --no-restore` passed: 6/6.
- `dotnet test .\tests\ApfsAccess.Tray.Tests\ApfsAccess.Tray.Tests.csproj -c Release --no-restore` passed: 66/66.
- `git diff --check` passed with only existing CRLF conversion warnings.
- Full solution test attempt with `dotnet test .\APFSAccess.sln -c Release --no-restore -m:1 --logger "console;verbosity=minimal"` timed out after 10 minutes before producing a final pass/fail summary; no full-suite pass is claimed for this latest GUI state.
- Published portable succeeded and root `APFSAccess_Portable.exe` was overwritten.
- Latest root portable SHA256: `53CCEF1BEB12D6E9ABA49B82C15587191CCF1A829DDCDEA9E1C831711A513231`.
- Relaunched from root portable into payload `C:\Users\guosen\AppData\Local\ApfsAccessPortable\payload-6C1A514698C2A561`.
- Running processes after relaunch: tray PID `38700`, service PID `17360`, host PID `30736`.
- Latest host status for `E:\`: Native, CanonicalApfsCheckpoint, CommitReady, PilotReadWrite, recovery inactive, dirty transactions `0`.
- Physical RW smoke passed: `artifacts\physical-rw-validation\physical-rw-smoke-20260525-170904.json`; post-status stayed RW/healthy.
- Live service IPC eject/remount cycle passed: `E:\` disappeared after `EjectRequested`, FsHost exited, `RefreshRequested(clearUserEjectedVolumes=true, volumeId=...)` remounted it, and new host status reported RW/healthy.

**User-facing requirements:**

- App launch shows both a GUI window and the tray icon.
- GUI lists all currently installed/detected APFS drives/partitions.
- Each row shows physical drive name, partition/volume name, drive letter, and current state.
- State is color coded like the tray icon but more nuanced:
  - green: healthy full read/write
  - yellow: read-only but usable
  - orange: mounted but attention needed
  - red: problematic/error/recovery blocked
  - gray: starting/idle/no APFS drive/service disconnected
- Each partition has actions:
  - `Open`: open the mounted drive in Explorer when a mount point exists.
  - `Eject`: safely eject that APFS partition/device through the existing service path.
  - `Fix`: disabled when green/healthy; for degraded/problem states it should try safe software recovery first, then show ELI5 manual steps if software cannot restore green.
  - `Details`: show backend/readiness/recovery/warnings/commit information without cluttering the main view.
- Closing the GUI hides/minimizes to tray and does not quit the app.
- The app quits only through tray right-click `Quit`.
- Tray menu should include a way to reopen the dashboard after it is hidden.

**Non-goals for this pass:**

- No dangerous disk repair button.
- No raw APFS repair/mutation beyond existing safe refresh/remount/eject behavior.
- No installer redesign.
- No marketing/landing UI.

---

## File Structure

**Create:**

- `src/ApfsAccess.Tray/DriveDashboardModels.cs`
  - Defines dashboard state enum, colors, row view model, and action enablement.
- `src/ApfsAccess.Tray/DriveDashboardPresenter.cs`
  - Converts `StatusChangedPayload` into dashboard rows and summary text.
  - Builds human-readable fix guidance.
- `src/ApfsAccess.Tray/DashboardForm.cs`
  - Owns the WinForms window, list layout, buttons, details dialog, close-to-tray behavior.
- `tests/ApfsAccess.Tray.Tests/DriveDashboardPresenterTests.cs`
  - Tests state classification, color mapping, row labels, and button enablement.

**Modify:**

- `src/ApfsAccess.Tray/TrayApplicationContext.cs`
  - Create/show `DashboardForm` at startup.
  - Keep latest status payload.
  - Reopen dashboard from tray.
  - Reuse existing eject and new refresh helper for dashboard buttons.
- `src/ApfsAccess.Tray/Program.cs`
  - Keep startup path unchanged unless app lifetime needs a tiny adjustment.
- `src/ApfsAccess.Tray/ApfsAccess.Tray.csproj`
  - Include any new content only if required; SDK-style compile includes `.cs` automatically.
- `tests/ApfsAccess.Tray.Tests/TrayApplicationContextPrioritizationTests.cs`
  - Add/adjust tests for tray menu dashboard reopen and close-to-tray helpers if helpers are extractable.

**Validation artifacts:**

- Root portable must be overwritten after successful publish:
  `D:\SynologyDrive\电脑工具\Codex Projects\APFS Access\APFSAccess_Portable.exe`

---

## Dashboard State Model

Use one dashboard state per row:

| State | Color | Meaning | Fix Button |
|---|---|---|---|
| `HealthyReadWrite` | Green | Mounted RW, native write healthy, recovery inactive, dirty count zero, no active drain/mutation warning | Disabled |
| `ReadOnly` | Yellow | Mounted RO/read-only fallback but still readable | Enabled: try refresh/remount |
| `Attention` | Orange | Mounted but has warnings, dirty transactions, shutdown drain, in-flight mutations, or validation/recovery note that is not fatal | Enabled: refresh/remount or show wait/close-files guidance |
| `Problem` | Red | Runtime error, service error, recovery blocked, failed mount, disconnected service with expected drive state unknown | Enabled: refresh first, then manual guidance |
| `Idle` | Gray | No mounted APFS volumes, starting/stopping, or no APFS drive detected | Disabled unless refresh is globally available |

Classification rules must be deterministic and tested. Prefer conservative status: red beats orange, orange beats yellow, yellow beats green.

---

## Task 1: Add Testable Dashboard State Mapping

**Files:**

- Create: `src/ApfsAccess.Tray/DriveDashboardModels.cs`
- Create: `src/ApfsAccess.Tray/DriveDashboardPresenter.cs`
- Create: `tests/ApfsAccess.Tray.Tests/DriveDashboardPresenterTests.cs`

- [x] **Step 1: Write failing tests for healthy RW and read-only rows**

Add tests:

```csharp
[Fact]
public void BuildRows_ClassifiesHealthyReadWriteVolumeAsGreenAndDisablesFix()
{
    var payload = NewPayload(
        RuntimeState.MountedRw,
        writeEnabled: true,
        mountedVolumes:
        [
            NewMountedVolume(MountAccessMode.ReadWrite)
        ],
        nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
        recoveryActive: false,
        dirtyTransactionCount: 0);

    var rows = DriveDashboardPresenter.BuildRows(payload);

    var row = Assert.Single(rows);
    Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
    Assert.Equal("Healthy read/write", row.StateText);
    Assert.Equal(DashboardPalette.Green, row.Palette);
    Assert.False(row.CanFix);
    Assert.True(row.CanEject);
    Assert.True(row.CanOpen);
}

[Fact]
public void BuildRows_ClassifiesReadOnlyVolumeAsYellowAndEnablesFix()
{
    var payload = NewPayload(
        RuntimeState.MountedRo,
        writeEnabled: false,
        mountedVolumes:
        [
            NewMountedVolume(MountAccessMode.ReadOnly)
        ],
        nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
        recoveryActive: false,
        dirtyTransactionCount: 0);

    var rows = DriveDashboardPresenter.BuildRows(payload);

    var row = Assert.Single(rows);
    Assert.Equal(DriveDashboardState.ReadOnly, row.State);
    Assert.Equal("Read-only", row.StateText);
    Assert.Equal(DashboardPalette.Yellow, row.Palette);
    Assert.True(row.CanFix);
    Assert.True(row.CanEject);
    Assert.True(row.CanOpen);
}
```

- [x] **Step 2: Run tests and verify they fail**

Run:

```powershell
dotnet test .\tests\ApfsAccess.Tray.Tests\ApfsAccess.Tray.Tests.csproj -c Release --no-restore --filter DriveDashboardPresenterTests
```

Expected: fail because `DriveDashboardPresenter`, `DriveDashboardState`, and `DashboardPalette` do not exist.

- [x] **Step 3: Implement minimal models and presenter**

Create:

```csharp
namespace ApfsAccess.Tray;

public enum DriveDashboardState
{
    Idle = 0,
    HealthyReadWrite = 1,
    ReadOnly = 2,
    Attention = 3,
    Problem = 4,
}

public enum DashboardPalette
{
    Gray = 0,
    Green = 1,
    Yellow = 2,
    Orange = 3,
    Red = 4,
}

public sealed record DriveDashboardRow(
    string VolumeId,
    string DeviceName,
    string VolumeName,
    string MountPoint,
    DriveDashboardState State,
    DashboardPalette Palette,
    string StateText,
    string Summary,
    bool CanOpen,
    bool CanEject,
    bool CanFix,
    IReadOnlyList<string> Details
);
```

Create presenter with:

```csharp
public static class DriveDashboardPresenter
{
    public static IReadOnlyList<DriveDashboardRow> BuildRows(StatusChangedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.MountedVolumes is not { Count: > 0 })
        {
            return Array.Empty<DriveDashboardRow>();
        }

        return payload.MountedVolumes
            .Where(static volume => !string.IsNullOrWhiteSpace(volume.VolumeId))
            .OrderBy(static volume => NormalizeDriveLabel(volume.MountPoint), StringComparer.OrdinalIgnoreCase)
            .Select(volume => BuildRow(payload, volume))
            .ToArray();
    }
}
```

Implement only enough for green/yellow tests, using mounted volume access mode and top-level safety fields.

- [x] **Step 4: Run tests and verify they pass**

Run the same filtered test command.

Expected: `DriveDashboardPresenterTests` pass.

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Add dashboard drive state mapping
```

---

## Task 2: Cover Attention, Problem, Empty, Labels, And Details

**Files:**

- Modify: `src/ApfsAccess.Tray/DriveDashboardModels.cs`
- Modify: `src/ApfsAccess.Tray/DriveDashboardPresenter.cs`
- Modify: `tests/ApfsAccess.Tray.Tests/DriveDashboardPresenterTests.cs`

- [x] **Step 1: Write failing tests for red/orange/gray precedence**

Add tests:

```csharp
[Fact]
public void BuildRows_ClassifiesRecoveryBlockedAsProblemEvenIfMounted()
{
    var payload = NewPayload(
        RuntimeState.MountedRw,
        writeEnabled: false,
        mountedVolumes:
        [
            NewMountedVolume(MountAccessMode.ReadWrite)
        ],
        nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
        recoveryActive: true,
        recoveryReason: "ReplayCanonicalCandidateMissing");

    var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

    Assert.Equal(DriveDashboardState.Problem, row.State);
    Assert.Equal(DashboardPalette.Red, row.Palette);
    Assert.True(row.CanFix);
    Assert.Contains(row.Details, detail => detail.Contains("ReplayCanonicalCandidateMissing", StringComparison.OrdinalIgnoreCase));
}

[Fact]
public void BuildRows_ClassifiesDirtyTransactionsAsAttention()
{
    var payload = NewPayload(
        RuntimeState.MountedRw,
        writeEnabled: true,
        mountedVolumes:
        [
            NewMountedVolume(MountAccessMode.ReadWrite)
        ],
        nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
        dirtyTransactionCount: 2);

    var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

    Assert.Equal(DriveDashboardState.Attention, row.State);
    Assert.Equal(DashboardPalette.Orange, row.Palette);
    Assert.True(row.CanFix);
}

[Fact]
public void BuildRows_ReturnsIdlePlaceholderWhenNoVolumeMounted()
{
    var payload = NewPayload(
        RuntimeState.Idle,
        writeEnabled: false,
        mountedVolumes: []);

    var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

    Assert.Equal(DriveDashboardState.Idle, row.State);
    Assert.Equal(DashboardPalette.Gray, row.Palette);
    Assert.Equal("No APFS drives mounted", row.DeviceName);
    Assert.False(row.CanOpen);
    Assert.False(row.CanEject);
    Assert.False(row.CanFix);
}
```

- [x] **Step 2: Run tests and verify they fail**

Run:

```powershell
dotnet test .\tests\ApfsAccess.Tray.Tests\ApfsAccess.Tray.Tests.csproj -c Release --no-restore --filter DriveDashboardPresenterTests
```

Expected: fail because state precedence and idle placeholder are not implemented.

- [x] **Step 3: Implement full state precedence and labels**

Implement:

```csharp
private static DriveDashboardState Classify(StatusChangedPayload payload, MountedVolumeDisplay volume)
{
    if (payload.State == RuntimeState.Error ||
        payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked ||
        payload.RecoveryActive)
    {
        return DriveDashboardState.Problem;
    }

    if (payload.DirtyTransactionCount > 0 ||
        payload.ShutdownDrainActive ||
        payload.InFlightMutationCallbacks > 0 ||
        HasWarnings(payload))
    {
        return DriveDashboardState.Attention;
    }

    if (volume.AccessMode == MountAccessMode.ReadOnly ||
        payload.State == RuntimeState.MountedRo ||
        !payload.WriteEnabled ||
        payload.NativeWriteSafetyState == NativeWriteSafetyState.ReadOnlyFallback)
    {
        return DriveDashboardState.ReadOnly;
    }

    if (volume.AccessMode == MountAccessMode.ReadWrite &&
        payload.State == RuntimeState.MountedRw &&
        payload.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite)
    {
        return DriveDashboardState.HealthyReadWrite;
    }

    return DriveDashboardState.Idle;
}
```

Build row labels:

- Device name: prefer `DeviceDisplayName`, then `DeviceId`, then `APFS drive`.
- Volume name: prefer `VolumeName`, then `APFS volume`.
- Mount point: normalized `E:` label when present.
- Details include backend, commit model, readiness, validation state, recovery reason, dirty count, warnings, and diagnostics.

- [x] **Step 4: Run tests and verify they pass**

Run same filtered command.

Expected: all dashboard presenter tests pass.

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Classify dashboard health states
```

---

## Task 3: Add Refresh/Fix IPC Helpers To Tray Context

**Files:**

- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`
- Test: `tests/ApfsAccess.Tray.Tests/TrayApplicationContextPrioritizationTests.cs`

- [x] **Step 1: Write failing test for refresh request timeout**

Add test:

```csharp
[Fact]
public void FixRequestTimeout_AllowsServiceRefreshAndRemountBudget()
{
    var timeout = InvokeFixRequestTimeout();

    Assert.True(timeout >= TimeSpan.FromSeconds(60));
}
```

Add reflection helper:

```csharp
private static TimeSpan InvokeFixRequestTimeout()
{
    var field = typeof(TrayApplicationContext).GetField(
        "FixRequestTimeout",
        BindingFlags.NonPublic | BindingFlags.Static);
    Assert.NotNull(field);

    var result = field!.GetValue(null);
    return Assert.IsType<TimeSpan>(result);
}
```

- [x] **Step 2: Run test and verify it fails**

Run:

```powershell
dotnet test .\tests\ApfsAccess.Tray.Tests\ApfsAccess.Tray.Tests.csproj -c Release --no-restore --filter FixRequestTimeout
```

Expected: fail because `FixRequestTimeout` does not exist.

- [x] **Step 3: Implement refresh/fix request helper**

In `TrayApplicationContext.cs`:

- Add `private static readonly TimeSpan FixRequestTimeout = TimeSpan.FromSeconds(90);`
- Add `RequestFixAsync(string? volumeId)` that:
  - disables dashboard buttons while running
  - sends `RefreshRequestedPayload(clearUserEjectedVolumes: true)`
  - shows success/failure balloon and dashboard status message
- Add `TrySendRefreshAsync(bool clearUserEjectedVolumes)` using same pattern as `TrySendEjectAsync`.

The first pass can refresh all APFS volumes because service refresh is global today. Keep the method parameter ready for row-specific UI messages, but do not invent backend APIs.

- [x] **Step 4: Run tests and verify they pass**

Run the filtered test command.

Expected: pass.

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Add dashboard fix refresh request path
```

---

## Task 4: Build Dashboard Form UI

**Files:**

- Create: `src/ApfsAccess.Tray/DashboardForm.cs`
- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`

- [x] **Step 1: Add form skeleton**

Create `DashboardForm : Form` with:

- fixed minimum size around `760x420`
- title `APFS Access`
- top summary label
- scrollable rows panel
- bottom status label
- no nested card-inside-card layout
- restrained system UI palette

Use WinForms controls only:

- `TableLayoutPanel` for rows
- `Panel` for color strip
- `Label` for device/volume/state
- `Button` for `Open`, `Eject`, `Fix`, `Details`

- [x] **Step 2: Add close-to-tray behavior**

Override form closing:

```csharp
protected override void OnFormClosing(FormClosingEventArgs e)
{
    if (!_allowClose && e.CloseReason == CloseReason.UserClosing)
    {
        e.Cancel = true;
        Hide();
        return;
    }

    base.OnFormClosing(e);
}
```

Expose:

```csharp
public void AllowCloseForApplicationExit()
{
    _allowClose = true;
}
```

- [x] **Step 3: Add row rendering**

Add:

```csharp
public void ApplyStatus(StatusChangedPayload payload)
{
    var rows = DriveDashboardPresenter.BuildRows(payload);
    RenderRows(rows);
}
```

Map palette to colors:

- Green: `Color.FromArgb(34, 139, 84)`
- Yellow: `Color.FromArgb(214, 158, 46)`
- Orange: `Color.FromArgb(221, 107, 32)`
- Red: `Color.FromArgb(197, 48, 48)`
- Gray: `Color.FromArgb(113, 128, 150)`

- [x] **Step 4: Add button events**

Constructor accepts callbacks:

```csharp
Func<string?, Task> openAsync
Func<string?, Task> ejectAsync
Func<string?, Task> fixAsync
```

For `Details`, show a modal `MessageBox` or small dialog with `row.Details`.

For `Open`, call callback with row mount point.

For `Eject`, call callback with row volume ID.

For `Fix`, call callback with row volume ID.

- [x] **Step 5: Manually compile**

Run:

```powershell
dotnet build .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c Release --no-restore
```

Expected: build succeeds.

- [ ] **Step 6: Commit checkpoint**

Commit message:

```text
Add APFS dashboard window
```

---

## Task 5: Wire Dashboard Into Tray Lifecycle

**Files:**

- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`
- Test: `tests/ApfsAccess.Tray.Tests/TrayApplicationContextPrioritizationTests.cs`

- [x] **Step 1: Add dashboard menu behavior test if extractable**

Covered by tray project tests for presenter/action behavior plus compile validation; constructor-level menu extraction is not present in the current code shape.

If tray menu creation is easy to test without launching a form, add test:

```csharp
[Fact]
public void TrayMenu_IncludesShowDashboardBeforeEject()
{
    var labels = InvokeBuildTrayMenuLabels();

    Assert.Contains("Show APFS Access", labels);
    Assert.Contains("Quit", labels);
}
```

If the current constructor makes this impractical, document that this behavior will be covered by manual UI smoke and keep presenter/action tests automated.

- [x] **Step 2: Instantiate dashboard at startup**

In constructor:

- create `DashboardForm`
- pass callbacks:
  - open mount point in Explorer
  - request eject
  - request fix/refresh
- show form after tray icon creation

- [x] **Step 3: Update dashboard on status changes**

In `UpdateUi(StatusChangedPayload payload)`:

- update tray icon as before
- update eject menu as before
- call `_dashboard.ApplyStatus(payload)`
- store `_latestStatus = payload`

- [x] **Step 4: Add tray reopen menu**

Add `Show APFS Access` menu item before eject:

```csharp
var showItem = new ToolStripMenuItem("Show APFS Access");
showItem.Click += (_, _) => ShowDashboard();
menu.Items.Add(showItem);
```

`ShowDashboard()` should `Show`, normalize window state, and `Activate`.

- [x] **Step 5: Keep quit as only app exit path**

In `ExitThreadCore()`:

- call `_dashboard.AllowCloseForApplicationExit()`
- close/dispose dashboard
- keep tray cleanup behavior

- [x] **Step 6: Run tray tests**

Run:

```powershell
dotnet test .\tests\ApfsAccess.Tray.Tests\ApfsAccess.Tray.Tests.csproj -c Release --no-restore
```

Expected: all tray tests pass.

- [ ] **Step 7: Commit checkpoint**

Commit message:

```text
Wire dashboard into tray lifecycle
```

---

## Task 6: User-Facing Button Behavior

**Files:**

- Modify: `src/ApfsAccess.Tray/DashboardForm.cs`
- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`

- [x] **Step 1: Implement Open button**

Callback:

```csharp
private static Task OpenMountPointAsync(string? mountPoint)
{
    if (string.IsNullOrWhiteSpace(mountPoint))
    {
        return Task.CompletedTask;
    }

    Process.Start(new ProcessStartInfo
    {
        FileName = mountPoint,
        UseShellExecute = true,
    });

    return Task.CompletedTask;
}
```

- [x] **Step 2: Implement Eject button**

Use existing `RequestEjectAsync(volumeId)`.

While eject is running:

- disable row buttons
- show dashboard footer: `Ejecting APFS drive...`
- on completion rely on status update to remove/remount row

- [x] **Step 3: Implement Fix button**

Use `RequestFixAsync(volumeId)`.

On success:

- footer: `Refresh requested. APFS Access will remount the drive if it is safe.`

On failure:

- footer and balloon with short message
- details guidance:
  - close Explorer windows or files using the drive
  - click Eject and replug the drive
  - quit and relaunch APFS Access
  - if recovery remains blocked, copy important files off before further writes

- [x] **Step 4: Implement Details button**

Show a readable dialog:

```text
Device: Samsung Flash Drive FIT USB Device
Volume: Main
Drive: E:
State: Healthy read/write
Backend: Native
Commit model: CanonicalApfsCheckpoint
Readiness: CommitReady
Safety: PilotReadWrite
Recovery: inactive
Dirty transactions: 0
Last commit: 10316
Warnings: none
```

- [x] **Step 5: Build tray project**

Run:

```powershell
dotnet build .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c Release --no-restore
```

Expected: build succeeds.

- [ ] **Step 6: Commit checkpoint**

Commit message:

```text
Add dashboard drive actions
```

---

## Task 7: Full Automated Validation

**Files:**

- No source changes expected unless tests fail.

- [x] **Step 1: Run full .NET tests**

Run:

```powershell
dotnet test .\APFSAccess.sln -c Release --no-restore -m:1
```

Expected: all .NET tests pass.

- [ ] **Step 2: Run focused native smoke only if GUI changes did not touch native code**

If no native files changed in this GUI branch, native full suite is not required for every GUI iteration. Run focused smoke only after publish.

- [ ] **Step 3: Run diff check**

Run:

```powershell
git diff --check
```

Expected: no whitespace errors.

- [ ] **Step 4: Commit validation/doc checkpoint if needed**

Commit message:

```text
Validate APFS dashboard tests
```

---

## Task 8: Publish Portable And Overwrite Root App

**Files:**

- Build output: `artifacts/publish/portable/APFSAccess.Portable.exe`
- Required root copy: `APFSAccess_Portable.exe`

- [ ] **Step 1: Publish portable**

Run:

```powershell
pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
```

Expected: publish succeeds.

- [ ] **Step 2: Overwrite root portable**

Run:

```powershell
Copy-Item .\artifacts\publish\portable\APFSAccess.Portable.exe .\APFSAccess_Portable.exe -Force
```

Expected: root portable timestamp updates.

- [ ] **Step 3: Relaunch from root portable**

Stop the current app through tray quit or service quit path, then launch:

```powershell
Start-Process -FilePath .\APFSAccess_Portable.exe -WorkingDirectory (Get-Location).Path
```

Expected:

- GUI window appears.
- Tray icon appears.
- If APFS drive is connected, the row appears with device and partition name.

- [ ] **Step 4: Verify payload hash alignment**

Run:

```powershell
$payloadRoot = Join-Path $env:LOCALAPPDATA 'ApfsAccessPortable'
$latestPayload = Get-ChildItem -LiteralPath $payloadRoot -Directory -Filter 'payload-*' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
Get-FileHash -Algorithm SHA256 -LiteralPath .\APFSAccess_Portable.exe
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $latestPayload.FullName 'ApfsAccess.Tray.exe')
```

Expected: portable exists and latest payload contains the new tray executable.

- [ ] **Step 5: Commit publish-related source changes only**

Do not commit generated portable/build artifacts unless explicitly requested for release packaging.

---

## Task 9: Manual User-Facing Smoke

**Files:**

- No source changes expected unless bugs are found.

- [ ] **Step 1: Launch behavior**

Expected:

- Running `APFSAccess_Portable.exe` opens the GUI and tray icon.
- GUI shows `Starting` or `No APFS drives mounted` while service starts.
- With APFS drive connected, GUI updates to a partition row without relaunch.

- [ ] **Step 2: Healthy RW display**

Expected for healthy `E:\`:

- green state strip
- text `Healthy read/write`
- physical drive name visible
- partition name visible
- `Open`, `Eject`, `Details` enabled
- `Fix` disabled

- [ ] **Step 3: Close-to-tray**

Expected:

- clicking window X hides the GUI
- tray icon remains
- mounted drive remains available
- tray right-click `Show APFS Access` restores GUI

- [ ] **Step 4: Eject button**

Expected:

- clicking row `Eject` safely ejects the APFS drive
- `E:\` disappears from This PC
- GUI updates to no mounted APFS drive or idle state
- no stale drive letter remains

- [ ] **Step 5: Replug/refresh behavior**

Expected:

- replugging the drive while app is running remounts it
- if it does not remount immediately, `Fix` or tray refresh path gives clear guidance

- [ ] **Step 6: Details button**

Expected:

- details dialog is readable to a normal user
- technical values are available but not overwhelming
- recovery/warning messages are visible when present

- [ ] **Step 7: Quit behavior**

Expected:

- closing GUI does not quit
- tray right-click `Quit` exits GUI, tray icon, service, and host cleanly

---

## Task 10: Final Regression Gate

**Files:**

- No source changes expected unless bugs are found.

- [ ] **Step 1: Run full .NET tests**

Run:

```powershell
dotnet test .\APFSAccess.sln -c Release --no-restore -m:1
```

Expected: all pass.

- [x] **Step 2: Run physical smoke against mounted drive**

Run:

```powershell
$status = Get-ChildItem "$env:TEMP\ApfsAccess\host-status" -Filter 'host_E_*.status.json' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
pwsh -NoProfile -File .\scripts\run_physical_rw_validation.ps1 -Mode Smoke -MountRoot 'E:\' -StatusFile $status.FullName -FileCount 4 -LargeFileBytes 0 -Cleanup
```

Expected: status `passed`, post-status RW/healthy.

- [x] **Step 3: Record validation status in this plan**

Update `Current Status` with:

- implementation checkpoints
- test commands and pass counts
- publish hash
- manual smoke outcome
- remaining gaps

- [ ] **Step 4: Commit final checkpoint when user asks**

Before committing, follow `AGENTS.md` safety checklist and set git identity:

```powershell
git config user.name "wcwishson"
git config user.email "wcwishson@outlook.com"
git status --short
git status --ignored --short
git diff --cached --name-only
git ls-files -i --exclude-standard
```

Commit message:

```text
Add APFS Access dashboard GUI
```

---

## Self-Review Notes

- Covers launch GUI + tray icon.
- Covers close-to-tray and quit-only-from-tray.
- Covers physical drive name, partition name, drive letter, state, colors, and actions.
- Covers `Fix` behavior without promising unsafe repair.
- Covers `Eject` through existing service path.
- Covers details view.
- Includes TDD-first tasks for classification and action timeout behavior.
- Includes publish requirement to overwrite root `APFSAccess_Portable.exe`.
- Includes user-facing smoke because Explorer-style behavior matters more than synthetic-only checks.
