# Native Write Pilot Runbook

## Scope

1. This runbook applies to v1 native-write validation for unencrypted/basic APFS volumes only.
2. Promotion stays fail-closed: `ScaffoldOnly -> PilotHardware -> Stable`.
3. `Stable` requires hardware evidence and macOS validation evidence.

## Image-backed preflight

Run this before any physical-drive pilot. It creates a disposable normal file and proves that the native probe can discover APFS Access synthetic media without formatting or repartitioning a disk.

```powershell
pwsh -NoProfile -File .\scripts\create_test_image.ps1 `
  -Path .\artifacts\test-images\apfsaccess-test.apfs.img `
  -SizeMiB 64

pwsh -NoProfile -File .\scripts\native_probe.ps1 `
  -DeviceId .\artifacts\test-images\apfsaccess-test.apfs.img `
  -AsJson
```

Safety notes:

1. `create_test_image.ps1` refuses raw `\\.\PhysicalDrive*` paths.
2. It refuses to overwrite an existing file.
3. The image is APFS Access synthetic validation media, not a macOS-compatible APFS formatter output.
4. Physical drive testing is still required for real hardware behavior, hot-unplug, power-loss replay, and macOS mount/read/integrity evidence.

## One-click Windows smoke automation

1. Build the beta bundle once:
```powershell
.\Build_APFS_Access_Beta.bat
```
2. Connect a sacrificial APFS drive.
3. The repo-side pilot launcher now uses `scripts\native_probe.ps1`, which runs the self-developed native backend probe instead of `apfsutil`.
4. Run the one-click launcher:
```powershell
.\Run_APFS_Pilot_Validation.bat
```
5. The launcher:
   - auto-discovers APFS raw drives and volumes through the self-developed native probe path;
   - rewrites the published click-run `appsettings.json` for read-only native physical validation by default;
   - launches APFS Access, waits for mount, enumerates files, copies a bounded sample to the feedback folder, verifies SHA-256 hashes, and zips a feedback bundle.
6. Feedback bundle location:
```text
artifacts\publish\click-run\pilot-feedback\<timestamp>.zip
```
7. The generated `validation-report.json` marks only the automated Windows read-only hardware smoke result. It does not satisfy write promotion, crash, hot-unplug, power-loss, or macOS evidence requirements by itself.

Destructive raw-device write smoke is intentionally opt-in:

```powershell
pwsh -NoProfile -File .\scripts\run_pilot_validation.ps1 -AllowDestructiveWriteSmoke
```

Use that switch only after the native write allocator/spaceman safety blockers are cleared. Without it, the script does not enable native write, does not allow raw physical writes, and ignores bootstrap evidence.

## Mounted-volume Windows read/write validation

After the sacrificial APFS volume is mounted read/write, run the guarded mounted-volume validator against the APFS drive letter. It refuses non-APFS targets and writes only inside a generated `apfs-access-*` folder on that mounted volume.

```powershell
pwsh -NoProfile -File .\scripts\run_physical_rw_validation.ps1 `
  -Mode Storm `
  -MountRoot E:\ `
  -StatusFile "$env:TEMP\ApfsAccess\physical-rw-fixed\latest\fshost.status.json" `
  -ScratchRoot "$env:TEMP\ApfsAccessPhysicalRw"
```

The script covers create/copy/read/hash, direct APFS writes, rename, move, cross-volume move, recursive copy, delete, long path names, and an optional storm workload. Save the emitted manifest and rerun after remount:

```powershell
pwsh -NoProfile -File .\scripts\run_physical_rw_validation.ps1 `
  -Mode VerifyManifest `
  -ExistingManifest .\artifacts\physical-rw-validation\physical-rw-storm-YYYYMMDD-HHMMSS.json `
  -StatusFile "$env:TEMP\ApfsAccess\physical-rw-fixed\latest\fshost.status.json"
```

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

1. Complete canonical allocation/spaceman write safety before raw-device write smoke.
2. Run the crash fault / crash-stage matrix on the same device and import the report or update evidence counters.
3. Run hot-unplug validation on the same device and import the result.
4. Attach the same media to macOS, confirm mount/read behavior and integrity, then import the macOS validation report.
5. For `Stable`, run the power-loss replay scenario and import that result as well.

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
