# APFS Access

Windows APFS access app with service + tray architecture and a native WinFsp mount-host pipeline.

## Projects

- `src/ApfsAccess.Service` - orchestration, probing, mount lifecycle, IPC server.
- `src/ApfsAccess.Tray` - tray-only UX (left-click no-op, right-click `Quit`).
- `src/ApfsAccess.Core` - shared contracts/models/policy.
- `src/ApfsAccess.Ipc` - named pipe JSON protocol.
- `src/ApfsAccess.Backend.Mock` - deterministic attach/detach simulation.
- `src/ApfsAccess.Backend.Native` - native APFS discovery, policy, and host orchestration.
- `src-native/ApfsAccess.FsHost` - native per-volume mount host process.

## Build

```powershell
pwsh -NoProfile -File .\build\build.ps1 -Configuration Debug
```

## Publish click-run

```powershell
pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
```

Artifacts:

- `artifacts/publish/click-run/ApfsAccess.Tray.exe`
- `artifacts/publish/click-run/Run_APFS_Access_Silent.vbs`
- `artifacts/publish/click-run/Run_APFS_Access.bat`
- `artifacts/publish/portable/APFSAccess.Portable.exe`
- `APFSAccess_Portable.exe` (project root single-file launcher)
- `Run_APFS_Access.bat` (project root launcher)
- `Build_APFS_Access_Beta.bat` (project root one-click beta build)

## One-click beta + feedback flow

Build the beta bundle:

```powershell
.\Build_APFS_Access_Beta.bat
```

Hardware/pilot validation remains a manual branch task for now. Use the native host build plus the bundled validation/report scripts once you have a sacrificial APFS device ready.

Manual validation boundary:

- crash fault / crash-stage matrix
- hot unplug
- power-loss replay
- macOS mount/read/integrity checks

Those scenarios still require a human-run external matrix; the automated launcher is meant to make Windows-side smoke validation and feedback capture one click.

Portable launcher notes:

- `APFSAccess_Portable.exe` is self-contained and embeds the click-run bundle.
- On first run it extracts to `%LOCALAPPDATA%\ApfsAccessPortable\...` and launches tray/service from there.
- It automatically checks prerequisites (`WinFsp` + `VC++ x64 runtime`) and prompts for one-click auto-install.
- If `winget` is unavailable, it falls back to official download/install links and guides the user.
- You can copy this one `.exe` to another folder/PC.

Quiet startup notes:

- For normal app use, double-click `Run_APFS_Access.bat` or `Run_APFS_Access_Silent.vbs`; the launcher starts the tray app without leaving a visible terminal window.
- Set `APFSACCESS_VISIBLE_CONSOLE=1` before running `Run_APFS_Access.bat` only when troubleshooting startup output.

## Prerequisites

```powershell
pwsh -NoProfile -File .\scripts\install_prereqs.ps1
```

Developer prerequisite check:

```powershell
pwsh -NoProfile -File .\scripts\install_prereqs.ps1 -ForDeveloperBuild
```

## Native backend setup

1. Build native mount host:

```powershell
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
```

2. Configure published `appsettings.json`:

```powershell
pwsh -NoProfile -File .\scripts\configure_native_ce.ps1 `
  -NativeFsHostPath "C:\path\to\ApfsAccess.FsHost.exe" `
  -DeviceCandidates "\\.\PhysicalDrive1"
```

Enable experimental overlay write-path testing:

```powershell
pwsh -NoProfile -File .\scripts\configure_native_ce.ps1 `
  -NativeFsHostPath "C:\path\to\ApfsAccess.FsHost.exe" `
  -DeviceCandidates "\\.\PhysicalDrive1" `
  -EnableNativeWrite `
  -WriteRolloutChannel Pilot `
  -WriteBackendMode Overlay
```

Enable experimental native-mutation pipeline testing:

```powershell
pwsh -NoProfile -File .\scripts\configure_native_ce.ps1 `
  -NativeFsHostPath "C:\path\to\ApfsAccess.FsHost.exe" `
  -DeviceCandidates "\\.\PhysicalDrive1" `
  -EnableNativeWrite `
  -WriteRolloutChannel Pilot `
  -WriteBackendMode Native
```

Safe image-backed smoke test before physical media:

```powershell
pwsh -NoProfile -File .\scripts\create_test_image.ps1 `
  -Path .\artifacts\test-images\apfsaccess-test.apfs.img `
  -SizeMiB 64

pwsh -NoProfile -File .\scripts\native_probe.ps1 `
  -DeviceId .\artifacts\test-images\apfsaccess-test.apfs.img `
  -AsJson
```

This creates a normal file only, refuses to overwrite existing files, and refuses raw `\\.\PhysicalDrive*` paths. It is a safe APFS Access validation image, not a macOS-compatible `mkfs.apfs` formatter output.

## Current status and limits

- CE integration is read-only.
- Encrypted APFS volumes are skipped.
- Native host now mounts through WinFsp callbacks (no full-volume mirror step).
- Directory traversal and file payload hydration now use the native APFS metadata/file-range path for supported basic volumes.
- Default mode is read-only; copy-out from APFS to Windows filesystems is supported.
- Physical APFS USB read-only validation passed on 2026-05-18: the native stack mounted the sacrificial APFS volume, enumerated all 99 files, copied out 99/99 files with 0 failures, and matched representative SHA-256 hashes.
- Native probe flow now discovers raw APFS devices and volumes without `apfsutil`, preserving stable `raw::<device>::<volume>` evidence profile ids for pilot tooling.
- Native probe parsing now emits write-incompatibility hints for read-only and special-role APFS volumes (`role=preboot|recovery|vm`) to keep native write gating explicit.
- Experimental write paths are available as:
  - `WriteBackendMode=Overlay` (session overlay, non-persistent).
  - `WriteBackendMode=Native` (native mutation pipeline with canonical commit/replay persistence on image-backed media and pilot-gated raw-device support).
- In `WriteBackendMode=Overlay`:
  - Explorer write operations are accepted against a temporary overlay.
  - Overlay changes are session-scoped and are not persisted back to APFS media.
- In `WriteBackendMode=Native`:
  - FsHost stages write mutations into the native metadata store and commits on `Flush`.
  - Payload bytes are sourced from hydrated files and written to allocated extents during commit.
- Native commit/replay semantics are covered by the current in-repo native validation chain; raw physical APFS devices remain pilot-only until external crash/hot-unplug/power-loss/macOS evidence is collected.
- Synthetic image-backed validation can now create a disposable `.apfs.img` file and probe it through the native backend before touching physical media; this does not replace real hardware/macOS validation.
- Physical APFS write operations remain blocked by default. Do not run raw-device create/write/rename/delete validation until canonical allocation/spaceman safety and write-promotion evidence are complete.

## Native write status

- Service/config contracts include conservative write gates:
  - `EnableNativeWrite`
  - `WriteRolloutChannel` (`Disabled|Pilot|Enabled`)
  - `WriteSafetyLevel` (`Conservative`)
  - `AllowWriteOnUnsupportedFeatures`
  - `WriteCommitTimeoutSeconds`
  - `NativeWriteStrictMode` (default `true`)
  - `NativeWriteMaxDirtyTransactions` (default `128`)
  - `NativeWriteRecoveryPolicy` (default `FailClosed`)
  - `NativeWriteAllowRawPhysicalDevices` (default `false`)
  - `NativeWritePilotVolumeAllowList` (default empty)
  - `NativeWriteIntegrityCheckOnMount` (default `true`)
  - `NativeWriteCrashReplayMode` (`FailClosed|ReplayIfSafe`)
- In strict native mode:
  - `WriteBackendMode=Native` mounts RW only when FsHost reports `CommitReady`.
  - If readiness is below `CommitReady`, service falls back to read-only mount and emits compatibility warnings.
  - If `NativeWriteRequireCanonicalCommit=true`, service also requires FsHost `commitModel=CanonicalApfsCheckpoint`; otherwise RW is blocked with `NativeWriteCommitModelNotCanonical` and mount downgrades to RO.
  - FsHost now also enforces canonical-commit requirement locally when `writeRequireCanonicalCommit=true`: native mutating callbacks require canonical commit readiness, and native commit execution uses canonical commit entrypoints (`CommitCanonicalTransaction`) with explicit `CommitModelNotCanonical` recovery telemetry on mismatch.
  - Canonical commit readiness no longer uses a global kill switch; readiness is now derived from canonical-state invariants and fallback state.
  - Physical-device RW still remains fail-closed when FsHost reports fixture legacy fallback or scaffold commit-blob mode.
- In `FailClosed` recovery policy mode:
  - Native RW mount requests are blocked when FsHost reports recovery-active/degraded state.
  - Native RW mount requests are also blocked when runtime telemetry reports native dirty transactions above `NativeWriteMaxDirtyTransactions` (reason: `DirtyTransactionLimitExceeded`).
  - Mounted native sessions are continuously polled via host status sidecar and are downgraded to read-only if degraded/recovery state appears mid-session.
- FsHost publishes runtime status metadata (`writeBackend`, `nativeWriteReadiness`, `recoveryActive`, `recoveryReason`, `lastCommitXid`, `nativeWriteSafetyState`, `lastRecoveryAction`, `dirtyTransactionCount`) through a status sidecar consumed by service/tray IPC; service/runtime IPC then derives and publishes `nativeWriteEngineState` and `writeIncompatibilities`.
- FsHost status sidecar now also includes `commitModel`; service/runtime payloads propagate `commitModel` and `writeUnsupportedFeatures` end-to-end.
- FsHost status sidecar now includes `fixtureLegacyFallbackActive` and `usesScaffoldCommitBlob`; backend maps both for strict RW fail-closed gating on production media.
- FsHost status sidecar can now carry explicit validation-evidence payload fields (`validationCrashFaultPasses`, `validationHardwarePilotPasses`, `validationMacOsValidationPasses`, `validationPowerLossPassVerified`, `validationLastValidatedUtc`), and backend merges them into persisted volume/profile evidence ledgers.
- Validation-evidence counter promotion is session-scoped (per FsHost runtime session) so pilot/stable counters are not over-credited by status polling frequency.
- Service options now include `NativeWriteEvidenceSeed*` values for controlled pilot seeding of validation evidence telemetry without manual edits to `%ProgramData%\\ApfsAccess\\write-evidence.json`.
- Raw physical-device pilot/stable promotion ignores host-seeded validation evidence counters by default (`NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices=false`); physical promotion evidence should come from observed per-session native runtime behavior.
- Native backend now logs threshold-aware validation diagnostics on promotion failures (current vs required crash/hardware/macOS/power-loss evidence, staleness window, and last validation timestamp) to speed pilot triage.
- Service compatibility warnings now include the same threshold-aware validation evidence details for fail-closed validation states, so pilot gating gaps are visible without opening backend diagnostics files.
- Fixture fallback behavior is explicit:
  - `NativeWriteAllowLegacyScaffoldForFixtures=true` allows fallback metadata loading only for fixture-like image paths (for example `*.apfs.img`, `*.img`, `*.apfs.fixture`, or paths containing `synthetic`/`fixture`).
  - fallback usage is treated as non-canonical for commit-model promotion.
- Native RW commit path now runs on FsHost `Flush` (`CommitPendingMutations`) with deterministic commit-status results.
- Transaction journal entries are batched and finalized on FsHost `Flush` (with staged commit markers and dirty-limit checkpoints).
- Raw physical-device writable mounts remain allow-list/evidence gated and should be treated as pilot-only until the external validation matrix is completed.
- FsHost now persists a per-volume recovery marker for pending native writes and applies `NativeWriteRecoveryPolicy` on startup:
  - `FailClosed`: downgrade to degraded read-only if an interrupted write session is detected.
  - `BestEffort`: keep native write path enabled while reporting recovery-active status.
- Native backend emits structured diagnostics for blocked write requests under:
  - `%TEMP%\ApfsAccess\write-diagnostics`
- Native RW engine skeleton modules are added in:
  - `src-native/ApfsAccess.ApfsRwEngine`
- RW engine bootstrap progress:
  - `BlockDevice` implements real read/write/flush primitives for raw device/file handles.
  - `MetadataStore` parses APFS container superblock baseline fields for readiness checks.
  - `MetadataStore` now maintains structured inode + directory-entry mutation state for `Create/Write/SetFileSize/Rename/Delete`.
  - pending object-map update staging now canonicalizes to one latest record per object id within a transaction batch.
  - replay semantic validation now treats exact allocation/deallocation overlap pairs as net-zero extent churn and accepts replay recovery for interrupted create-write-delete ephemeral transactions.
  - commit preflight now enforces the same extent-overlap rule as replay validation: pending allocation/deallocation overlap is only valid for exact range matches (partial overlap is rejected before commit).
  - replay parser now rejects duplicate object-map entries for the same object id in commit blobs (fail-closed), and fault-injection coverage includes checksum-preserving duplicate-object-map tamper scenarios.
  - native backend fail-closed gating now emits `DirtyTransactionLimitExceeded` when runtime native dirty transactions exceed configured safety limit, with dedicated diagnostic/gate mapping.
  - persistent-state load path now enforces strict parser bounds (record-count caps, bounded inode/path string lengths, bounded btree key/value payload sizes, and overflow-safe extent checks) before hydrating mutable state.
  - persistent-state format `v6` now includes an end-to-end FNV checksum over serialized state (excluding checksum field) and rejects checksum/trailing-byte mismatches fail-closed before hydration.
  - persistent-state corruption coverage now includes oversized inode path-length metadata; parser rejection falls back to on-disk checkpoint/replay metadata and preserves fail-closed recovery semantics.
  - replay/commit checkpoint plumbing now validates commit-blob location metadata (alignment, bounds, reserved-region overlap) through a shared guard before persisting replay checkpoints or attempting replay reads.
  - load/replay reconciliation now treats malformed persistent commit-blob metadata as non-authoritative and prefers valid on-disk replay-checkpoint commit metadata when available.
  - load/replay reconciliation now also prefers on-disk replay-checkpoint commit metadata when xid ties occur between persistent-state and replay-checkpoint metadata.
  - replay-checkpoint candidate selection now validates referenced commit-blob headers/checksums/xid windows before promoting replay metadata into mount state.
  - replay-checkpoint candidate validation now also rejects duplicate object-map object ids and overlapping spaceman extent sets inside referenced commit blobs before selection.
  - replay-checkpoint persistence now validates referenced commit-blob headers/checksums/xid windows before writing checkpoint metadata.
  - commit-blob location validation now requires block-aligned byte lengths (not just aligned addresses), preventing truncated/non-aligned replay commit-blob metadata from being accepted.
  - fault-injection coverage now includes malformed persistent commit-blob address metadata and verifies recovery succeeds via replay-checkpoint fallback when replay metadata is valid.
  - replay-checkpoint selection now only accepts xid windows compatible with the active superblock (`target == superblock` or `source == superblock && target == superblock + 1`), ignoring out-of-window replay metadata instead of promoting unsafe/stale targets.
  - replay-checkpoint parser now requires the v1 payload length to match the canonical 24-byte schema exactly, rejecting checksum-valid over/under-sized payload metadata.
  - replay-checkpoint parser now also rejects non-zero trailing bytes beyond the canonical payload, closing checksum-uncovered trailing-data tamper space.
  - replay-checkpoint parser now requires a non-zero matching checksum for replay checkpoint blocks (no optional checksum bypass).
  - fault-injection coverage now includes checksum-preserving replay-checkpoint xid-window tampering and verifies remount recovery still succeeds via valid persistent replay metadata.
  - fault-injection coverage now includes replay-checkpoint commit-blob pointer tampering and verifies bad replay candidates are ignored in favor of valid persistent replay metadata.
  - fault-injection coverage now includes semantic replay-checkpoint commit-blob tampering (duplicate object-map id on highest replay-xid candidate) and verifies remount keeps persistent checkpoint state without entering recovery.
  - fault-injection coverage now includes non-aligned commit-blob byte-size tampering in both persistent-state and replay-checkpoint metadata, with deterministic fallback to valid replay metadata.
  - fault-injection coverage now includes replay-checkpoint payload-length tampering with recomputed checksums and confirms recovery falls back safely to persistent replay metadata.
  - fault-injection coverage now includes zeroed replay-checkpoint checksum tampering and confirms replay-checkpoint metadata is ignored in favor of valid persistent replay metadata.
  - fault-injection coverage now includes replay-checkpoint trailing-byte tampering (checksum-unaffected) and confirms replay-checkpoint metadata is ignored in favor of valid persistent replay metadata.
  - fault-injection coverage now includes persistent-state checksum-only tampering (v6) and confirms checksum-invalid state is rejected in favor of replay metadata fallback.
  - replay fault coverage now explicitly exercises persistent metadata xid-window jumps and asserts fail-closed `ReplayXidWindowInvalid` behavior with commit path still blocked.
  - `MetadataStore` persists committed object-map/spaceman scaffold state in `%TEMP%\ApfsAccess\rw-state\*.bin` and reloads it across remount.
  - persisted scaffold state now includes inode table metadata (path/name/parent/size/extent/xid) and is restored on remount.
  - native commit scaffold now resolves hydrated file payloads and persists payload bytes into allocated extents before commit metadata is finalized.
  - native commit scaffold now performs a checkpoint-switch stage that alternates between superblock slots and updates container superblock checkpoint XID on writable image-backed targets.
  - object-map and spaceman checkpoint parsing now uses dedicated canonical parser modules with checksum validation and stricter overlap/alias invariants.
  - volume-tree canonical parsing now performs semantic inode/directory/extent cross-link validation (not only key-prefix checks), fail-closing on mismatched child-parent or extent-inode metadata.
  - commit now performs object-map/spaceman checkpoint round-trip verification (persist -> re-read -> canonical parse/compare) before later commit stages continue.
  - commit now also performs inode/btree checkpoint round-trip structural verification (persist -> re-read -> header/count/payload/checksum validation), fail-closing on mismatch before replay/checkpoint-switch stages.
  - btree checkpoint round-trip verification now compares canonical record content (`kind/key/value/tombstone`) and exact target xid after reload, instead of xid-only progression checks.
  - inode checkpoint round-trip link comparison now validates stable link identity (`parent|name|child`) so link-xid churn does not cause false fail-closed commits.
  - replay checkpoint persistence now includes an immediate round-trip verification (persist -> reload -> parse -> commit-blob pointer/xid match), fail-closing with `CommitReplayRoundTripFailed` if replay metadata does not validate.
  - commit stage hooks now include `before-replay-roundtrip-verify`; interrupting this stage fail-closes with `CommitInterruptedBeforeReplayRoundTripVerify`.
  - checkpoint-switch commit now includes immediate superblock round-trip verification (re-read active superblock magic/block-size/xid), fail-closing with `CommitCheckpointRoundTripFailed` on mismatch.
  - commit stage hooks now include `before-checkpoint-roundtrip-verify`; interrupting this stage fail-closes with `CommitInterruptedBeforeCheckpointRoundTripVerify`.
  - FsHost now treats delete-pending ancestors as non-visible for path resolution, so open/create/rename operations on descendants fail conservatively instead of bypassing pending-delete state.
  - native commit finalization from `Flush`/`Close` is now serialized with a dedicated commit mutex to avoid overlapping commit state transitions under concurrent callback load.
  - FsHost rename no-op handling now validates source visibility first (`old == new` returns `OBJECT_NAME_NOT_FOUND` for missing paths and `DELETE_PENDING` for hidden/delete-pending paths).
  - native FsHost semantics regression target now exists (`ApfsAccess.FsHost.SemanticsTests`) and covers conflicting create flags plus delete-pending ancestor behavior across open/security/delete callbacks.
  - FsHost rename now rejects mismatched open contexts (`ctx` handle must match the source node) and cleanup-time delete latching now requires `DELETE` access on the open handle.
  - `ApfsAccess.FsHost.SemanticsTests` now also covers mismatched-`ctx` rename rejection and cleanup delete permission enforcement.
  - FsHost now applies `FILE_DELETE_CHILD` semantics for parent-directory operations (`CanDelete` accepts parent handles with `delete-child` access on direct children, and rename accepts parent-directory contexts with the required child-delete right).
  - `ApfsAccess.FsHost.SemanticsTests` now also covers parent-directory `FILE_DELETE_CHILD` allow/deny paths for `CanDelete` and `Rename`, plus cleanup-delete behavior for non-empty directories.
  - FsHost rename-replace now requires target-parent `FILE_DELETE_CHILD` rights when a handle context is provided, preventing source-handle-only replace operations from bypassing target delete-right checks.
  - `ApfsAccess.FsHost.SemanticsTests` now also covers rename-replace allow/deny paths (`source-handle replace denied`, `target-parent replace allowed`) and confirms parent `FILE_DELETE_CHILD` applies only to direct children.
  - FsHost rename now requires target-directory insert rights when operating via a target-parent handle (`FILE_ADD_FILE` for file moves, `FILE_ADD_SUBDIRECTORY` for directory moves), not only delete-child rights.
  - `ApfsAccess.FsHost.SemanticsTests` now also covers target-parent insert-right enforcement for both file and directory cross-parent renames.
  - Same-parent renames through parent-directory handles now also require insert rights (not just `FILE_DELETE_CHILD`), aligning parent-handle rename checks with destination-entry creation semantics.
  - Cross-parent renames now reject old-parent-only handle contexts; destination-entry authorization must come from a target-parent handle (or non-parent source-handle path), preventing ambiguous parent-handle authority.
  - Rename-replace via target-parent context now requires both destination insert rights and `FILE_DELETE_CHILD` (for target removal), with explicit allow/deny semantic tests.
  - `CanDelete` null-name flows now explicitly require `DELETE` on the context node (not `FILE_DELETE_CHILD`), and additional semantics tests lock same-parent/cross-parent replace edge cases for both file and directory paths.
  - Added open-handle conflict semantics coverage for delete/rename paths (`CanDelete`/`SetDelete` sharing violations, directory rename blocked by open descendant handles, and source-handle rename success when only the current handle is open).
  - Rename no-op (`old == new`) now validates context identity/rights (`source DELETE` or `parent FILE_DELETE_CHILD`) instead of silently succeeding for mismatched handles.
  - Cross-parent rename via source-handle context is now fail-closed (`ACCESS_DENIED`) to avoid destination-authority ambiguity in handle-context permission flows.
  - `SetDelete(FALSE)` now explicitly allows clearing delete intent through the same file handle even when the target is currently delete-pending.
  - Added mixed delete/rename conformance coverage for: source delete-pending rename recovery, replace vs delete-pending target, replace vs busy target handles, and cleanup-delete suppression when additional handles are open.
  - Added read-only callback consistency coverage: mutating callbacks (`Create/Rename/CanDelete/SetDelete/SetSecurity`) now have explicit semantics tests for `MEDIA_WRITE_PROTECTED`, and `Open` now has regression coverage for mutation-access denial in read-only mode.
  - Added lifecycle `Cleanup`/`Close` ordering coverage: cleanup-latched deletes now have explicit tests for rename-blocking before close, final source removal on close (file + empty directory), and non-delete close preservation.
  - FsHost now serializes mutating callback execution (`Create/Write/SetFileSize/SetBasicInfo/Rename/CanDelete/SetDelete/Cleanup/Close/Flush`) with a dedicated per-volume lock to avoid namespace/delete-intent interleaving races under concurrent callback load.
  - `ApfsAccess.FsHost.SemanticsTests` lifecycle/read-only coverage now also includes: delete-on-close removal only after last handle close, directory replace rejection for non-empty or open-handle targets, `Open(DELETE)` denial in read-only mode, and cleanup-delete no-op behavior in read-only mode.
  - FsHost shutdown now performs a mutation-drain phase before dispatcher stop: new external mutating callbacks (`Create/Write/SetFileSize/SetBasicInfo/Rename/CanDelete/SetDelete/Overwrite`) are rejected with `STATUS_VOLUME_DISMOUNTED`, and host waits for in-flight external mutation callbacks to drain (bounded timeout) before unmount progression.
  - `ApfsAccess.FsHost.SemanticsTests` now includes shutdown-drain rejection coverage for `Create` and `Rename`, plus direct drain-control coverage for in-flight callback wait and timeout behavior.
  - added concurrent namespace stress coverage: parallel `Create` requests for the same path now have deterministic serialized behavior (one success + one collision) with consistent parent-child index state.
  - commit preflight now validates projected post-mutation object-map/spaceman/volume-tree state through canonical store validators before any checkpoint persist stage.
- inode object-id allocation now uses a monotonic allocator (instead of path-hash probing), and persistent-state format version `6` persists allocator high-watermark with checksum/trailing-byte validation to avoid reuse and reject tampered state across remount/restart.
  - native bootstrap now reconciles persisted RW state checkpoint xid against superblock checkpoint xid and marks recovery-required when they diverge.
  - recovery-required state keeps native commit path blocked until reconciliation (surface state: `RecoveryMode`/fail-closed downgrade under policy).
  - `TransactionManager` now records mutation intents into a per-session journal (`%TEMP%\ApfsAccess\rw-journal\*.jsonl`) for begin/commit/abort traceability.
- Optional native RW engine build:
  - `pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release`
- Optional native RW engine build + native tests:
  - `pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release -RunTests`
- Deterministic harness:
  - `pwsh -NoProfile -File .\scripts\run_rw_harness.ps1 -Scenario basic -IncludeNative`
- Roadmap:
  - `docs/native-write-roadmap.md`
- Native write pilot runbook + evidence updater:
  - `docs/native-write-pilot.md`
  - `scripts/run_pilot_validation.ps1`
  - `scripts/update_write_evidence.ps1`
  - `scripts/import_validation_report.ps1`
  - `scripts/new_validation_report.ps1`
  - `scripts/evaluate_write_promotion.ps1`
