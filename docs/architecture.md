# Architecture

## Runtime model

1. `ApfsAccess.Service` is the orchestration process.
2. `ApfsAccess.Tray` is the tray-only UI shell (left-click no-op, right-click `Quit`).
3. IPC uses named pipe `\\.\pipe\ApfsAccess.Tray.v1`.
4. `ApfsAccess.FsHost.exe` is a per-volume native child process launched by `NativeApfsBackend`.

## Data flow

1. Service probes APFS devices and volumes through `IApfsBackend`.
2. Service applies `IMountPolicy` and host options (letter pool, encrypted-volume skip, remount behavior).
3. Native backend launches/stops `ApfsAccess.FsHost.exe` for each mounted volume.
4. Service publishes runtime state and warnings to tray over IPC `StatusChanged`.
5. Tray icon updates by state and supports only `Quit` action.

## Native backend (self-developed APFS + FsHost)

1. `BackendMode=Native` uses `src/ApfsAccess.Backend.Native`.
2. Native probe/discovery walks candidate raw devices and GPT partitions directly, then resolves APFS containers and volumes without `apfsutil` in the supported path.
3. `MountAsync` supports:
   - default read-only mode.
   - experimental `WriteBackendMode=Overlay` mode for session-scoped write-path testing (no APFS media mutation).
   - experimental `WriteBackendMode=Native` mode that executes the self-developed mutation/commit path for supported basic APFS data volumes, with fixture/image-backed validation currently ahead of real-device validation.
   - encrypted volumes are skipped/rejected in phase 1.
4. Mount lifecycle is process-based:
   - launch `ApfsAccess.FsHost.exe --device --volume --mount (--readonly|--readwrite) --lifetime-file --status-file`.
   - unmount via lifetime-file signal, then timeout kill fallback.
5. FsHost mounts a real WinFsp-backed drive letter.
6. Directory entries, inode metadata, and committed file ranges are served on-demand from the native APFS metadata store and extent readers.
7. Hydration/cache state remains session-scoped under `%TEMP%\ApfsAccess\sessions\<session>\hydrate` and is cleaned on host exit to avoid stale cross-session payload reuse.
8. Existing-file hydration is fail-closed: if the native metadata/extent path cannot supply bytes, the open fails instead of creating an empty placeholder.
9. FsHost `Create/Open` now derives writable-handle intent from WinFsp `GrantedAccess` instead of assuming all handles are writable, which tightens close-time commit/deletion semantics.
10. FsHost now implements WinFsp `SetDelete` and tracks per-handle delete intent plus cleanup latching, so delete-pending visibility/open-blocking remains consistent until final close.
11. FsHost rename path now blocks directory self/descendant moves and forces target-directory enumeration before replace checks, preventing invalid subtree cycles and stale non-empty replace outcomes.
12. FsHost rename now also checks source-subtree open-handle conflicts (with only the current rename handle optionally exempt), reducing rename/open race exposure under concurrent handle activity.
13. FsHost now normalizes WinFsp `GrantedAccess` (including generic access bits) and enforces read/list permissions in `Read`/`ReadDirectory`, preventing accidental over-broad handle capabilities.
14. Close-time native commit finalization now also triggers for delete-on-cleanup workflows after the delete latch is consumed, so delete mutations are not skipped when no explicit flush occurs.
15. Explorer browse/copy-out is supported from the mounted APFS drive; native write mode remains safety-gated for supported basic APFS volumes and still needs sacrificial-drive validation before release cutover.
16. Phase-A write scaffolding is in place:
   - write gate policy (`EnableNativeWrite`, rollout channel, safety level).
   - strict native gate (`NativeWriteStrictMode=true` by default) allows native RW mounts only when FsHost reports `CommitReady`; otherwise service falls back to read-only.
   - canonical commit gate (`NativeWriteRequireCanonicalCommit=true` by default) additionally requires FsHost `commitModel=CanonicalApfsCheckpoint`; scaffold checkpoint commit models are downgraded to RO.
   - fixture-only scaffold fallback is controlled by `NativeWriteAllowLegacyScaffoldForFixtures`; fallback usage is treated as non-canonical.
   - `FailClosed` recovery policy blocks native RW mount requests when host telemetry indicates recovery/degraded status.
   - mounted host sessions are re-polled for runtime status; if a native write session degrades/recovery-activates under `FailClosed`, service downgrades that mount state to read-only telemetry.
   - blocked write attempts emit diagnostics markers under `%TEMP%\ApfsAccess\write-diagnostics`.
   - write-mode mutation intents are journaled to `%TEMP%\ApfsAccess\rw-journal` for crash-traceability.
   - committed scaffold metadata state is persisted under `%TEMP%\ApfsAccess\rw-state` and restored on remount, including inode/path metadata for rename/delete continuity.
  - FsHost `Flush` invokes policy-aware native commit entrypoints:
    - `CommitCanonicalTransaction()` when canonical commit is required.
    - `CommitPendingMutations()` only when legacy/scaffold commit is explicitly allowed.
  - active commit flow persists payload + commit scaffold records and performs checkpoint-switch scaffolding (primary/secondary slot alternation) on writable image-backed targets when the configured safety policy allows it.
   - metadata bootstrap reconciles persisted RW state checkpoint xid with superblock checkpoint xid; mismatch forces recovery-required state and blocks commit-ready promotion.
   - FsHost maintains a per-volume recovery marker for pending native writes and applies `NativeWriteRecoveryPolicy` at startup (`FailClosed` degrades to RO; `BestEffort` keeps native path with recovery-active telemetry).
   - FsHost shutdown path performs a bounded mutation-drain before dispatcher stop: new external mutating callbacks are rejected (`STATUS_VOLUME_DISMOUNTED`) and in-flight external mutation callbacks are allowed to finish (timeout-bounded) before unmount progression.
   - FsHost writes runtime status (`writeBackend`, `commitModel`, `nativeWriteReadiness`, `recoveryActive`, `recoveryReason`, `lastCommitXid`) to a host status file consumed by the service backend and tray IPC payload.
   - native commit pipeline now latches recovery-required in-session after checkpoint-stage failures, forcing subsequent commit attempts into fail-closed (`NotWritable`) until remount/recovery.
   - native CTest coverage includes `ApfsAccess.ApfsRwEngine.MetadataStorePersistence` for deterministic commit/remount persistence checks.
   - native mutation staging now applies fail-atomic per-request rollback in `MetadataStore::ApplyMutation`, preventing partial pending-state drift when an operation returns `InvalidRequest` or `AllocationFailed`.
17. Service reconciliation loop unmounts stale volumes and can remount reconnected ones.

## Current implementation phase

1. Phase-1/2 bridge now includes host/process orchestration, direct WinFsp read callbacks, contracts, scripts, and packaging.
2. Phase-A/Phase-B write support adds contracts, safety gates, diagnostics, and overlay/native write scaffolds with partial persisted commit scaffolding, but without full APFS metadata transaction parity.
3. Full APFS mutation engine remains follow-up work (`docs/native-write-roadmap.md`).
