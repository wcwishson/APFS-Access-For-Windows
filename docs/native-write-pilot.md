# Native Write Pilot Runbook

## Scope

1. This runbook applies to v1 native-write validation for unencrypted/basic APFS volumes only.
2. Promotion stays fail-closed: `ScaffoldOnly -> PilotHardware -> Stable`.
3. `Stable` requires hardware evidence and macOS validation evidence.

## One-click Windows smoke automation

1. Build the beta bundle once:
```powershell
.\Build_APFS_Access_Beta.bat
```
2. Connect a sacrificial APFS drive.
3. Run the one-click launcher:
```powershell
.\Run_APFS_Pilot_Validation.bat
```
4. The launcher:
   - auto-discovers APFS raw drives and volumes;
   - rewrites the published click-run `appsettings.json` for native pilot mode;
   - uses a temporary session-local evidence ledger to unlock the writable Windows smoke session without editing the real `%ProgramData%\ApfsAccess\write-evidence.json`;
   - launches APFS Access, waits for mount, runs `CreateDirectory` / `Write` / `SetBasicInfo` / `Rename` / `SetFileSize` / `Delete`, restarts the app, verifies remount persistence, and zips a feedback bundle.
5. Feedback bundle location:
```text
artifacts\publish\click-run\pilot-feedback\<timestamp>.zip
```
6. The generated `validation-report.json` marks only the automated Windows `HardwarePilot` smoke result. It does not satisfy crash, hot-unplug, power-loss, or macOS evidence requirements by itself.

## Prerequisites

1. WinFsp installed and healthy (`docs/winfsp-setup.md`).
2. Native host and service/tray binaries built and deployed.
3. Service configured for native write pilot:
   - `Service.EnableNativeWrite = true`
   - `Service.WriteBackendMode = Native`
   - `Service.NativeWriteAllowRawPhysicalDevices = true`
   - `Service.NativeWritePromotionPolicy = PilotHardware` (or `Stable` after pilot evidence is complete)
   - `Service.NativeWriteHardwarePilotDeviceAllowList` contains target physical drives.

## Evidence profile

1. Evidence is keyed by profile id:
   - `raw::<normalized-device-id>::<normalized-volume-name>`
2. Example:
   - `raw::\\.\physicaldrive3::main`

## Pilot scenario capture

1. Crash-stage matrix pass:
```powershell
pwsh -NoProfile -File .\scripts\update_write_evidence.ps1 `
  -ProfileId "raw::\\.\physicaldrive3::main" `
  -Scenario CrashFault,CrashStageMatrix,HardwarePilot `
  -Count 1
```
2. Hot-unplug pass:
```powershell
pwsh -NoProfile -File .\scripts\update_write_evidence.ps1 `
  -ProfileId "raw::\\.\physicaldrive3::main" `
  -Scenario HotUnplug `
  -Count 1
```
3. Power-loss replay pass:
```powershell
pwsh -NoProfile -File .\scripts\update_write_evidence.ps1 `
  -ProfileId "raw::\\.\physicaldrive3::main" `
  -Scenario PowerLossReplay,PowerLossVerified `
  -Count 1
```
4. macOS validation pass:
```powershell
pwsh -NoProfile -File .\scripts\update_write_evidence.ps1 `
  -ProfileId "raw::\\.\physicaldrive3::main" `
  -Scenario MacOsValidation,MacOsConsistency `
  -Count 1
```

## Import structured validation reports

1. Report format supports either a top-level array or `{ "results": [ ... ] }`.
2. Record schema:
   - `profileId` (required)
   - `scenario` (`CrashFault|CrashStageMatrix|HardwarePilot|HotUnplug|MacOsValidation|MacOsConsistency|PowerLossReplay|PowerLossVerified`)
   - `passed` (`true` to apply evidence)
   - `count` (optional, default `1`)
   - `validatedUtc` (optional ISO-8601)
   - `volumeId` (optional)
3. Import command:
```powershell
pwsh -NoProfile -File .\scripts\import_validation_report.ps1 `
  -ReportPath .\artifacts\pilot\validation-report.json
```

## Report template generation

1. Create a per-profile report template before running pilot scenarios:
```powershell
pwsh -NoProfile -File .\scripts\new_validation_report.ps1 `
  -ProfileId "raw::\\.\physicaldrive3::main" `
  -VolumeId "\\.\PhysicalDrive3|Main" `
  -OutputPath .\artifacts\pilot\validation-report.json `
  -Overwrite
```

## Promotion readiness check

1. Evaluate whether current evidence and config gates satisfy the configured promotion policy:
```powershell
pwsh -NoProfile -File .\scripts\evaluate_write_promotion.ps1 `
  -AppSettingsPath .\src\ApfsAccess.Service\appsettings.json
```
2. Optional JSON output:
```powershell
pwsh -NoProfile -File .\scripts\evaluate_write_promotion.ps1 -AsJson
```
3. To evaluate a specific raw-device profile even before evidence exists in the store, pass the target profile id explicitly:
```powershell
pwsh -NoProfile -File .\scripts\evaluate_write_promotion.ps1 `
  -AppSettingsPath .\src\ApfsAccess.Service\appsettings.json `
  -ProfileId "raw::\\.\physicaldrive3::main" `
  -AsJson
```
4. Readiness output now includes config-gate fields (`configEligible`, `configReasons`, `allowListConfigured`, `allowListed`) in addition to evidence counters, so missing raw-device allow-list or pilot policy setup is reported before hardware evidence is interpreted.

## Manual boundary after the one-click launcher

1. Run the crash fault / crash-stage matrix on the same device and import the report or update evidence counters.
2. Run hot-unplug validation on the same device and import the result.
3. Attach the same media to macOS, confirm mount/read behavior and integrity, then import the macOS validation report.
4. For `Stable`, run the power-loss replay scenario and import that result as well.

## macOS validation checklist

1. Attach the same APFS media to macOS after Windows write sessions.
2. Verify mount succeeds.
3. Verify created/edited/deleted files match expected namespace and file contents.
4. Run APFS consistency tooling on macOS and confirm no integrity failures.
5. Record pass using the evidence script.

## Promotion rules

1. `PilotHardware` mount eligibility requires crash/hardware/hot-unplug counters and freshness thresholds.
2. `Stable` mount eligibility additionally requires macOS counters and power-loss evidence.
3. Missing or stale evidence always downgrades to read-only with structured diagnostics.

## Notes

1. Runtime sidecar status for raw devices no longer auto-promotes pilot/stable counters without explicit validation evidence signals.
2. Keep one evidence profile per physical device + APFS volume pairing.
