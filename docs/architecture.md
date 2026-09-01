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

## Write durability flow (WAL / payload spool / checkpoint)

1. Mutation acceptance and journaling:
   - FsHost mutation callbacks are admitted by `MetadataStore` only while the host is `CommitReady`; `ApplyMutation` stages fail-atomic per-request rollback and returns `NotReady` while a recovery-required latch is armed (e.g., after checkpoint-stage failures).
   - `TransactionManager` writes binary `WriteAheadLog` records bound to a partition identity (device path + partition offset + volume token + stable serial), with checksum/version/wrong-volume rejection, and persists buffered prepared records plus the transaction-end marker in one durable WAL append at commit time.
   - WAL recovery truncates torn tails with a flushed fix-up, compacts through write-through replacement, and enforces a runtime size cap with compaction retry before failing.
2. Payload spool staging:
   - `PayloadSpool` appends dirty payload chunks first, then indexes them by object/generation/logical range with bounded same-sequence coalescing; reads are checksum-protected and wrong-volume reads are rejected.
   - Payload ranges are staged before the WAL mutation record; a failed WAL prepare discards the just-staged payload range; dirty persisted spool evidence at startup forces recovery/fail-closed behavior.
   - The spool enforces a quota, cleans only after successful native checkpoints, and is pruned on host exit; hydration remains the fallback byte source.
3. Deferred close:
   - Close commits defer only when pending mutations are content writes (`PendingMutationsAreContentWritesOnly`); create, resize, timestamp, delete, rename, flush, shutdown, and dirty-limit remain synchronous safety barriers.
   - Deferred batches are accepted through grouped acceptance cohorts with a bounded worker drain; flush/eject/shutdown force a checkpoint; repeated status updates coalesce while in finishing-writes state.
4. Commit and checkpoint durability:
   - The commit builds a precise-reserve commit blob (`APFSRWCANON3`), validates pending state (one full sorted allocation pass plus a focused commit-extent check), and persists full canonical object-map, spaceman, inode, B-tree, and replay checkpoint families plus the sidecar state, then switches the alternate APFS checkpoint superblock and issues the final device flush.
   - Normal commits queue the checkpoint-family writes as one ordered raw-device batch (batch-owned storage); strict verification and commit-stage fault hooks keep immediate per-family writes.
   - Persist paths reuse cached inode/object-map orders, already-normalized committed vectors, and checkpoint block-index caches; committed deltas apply with per-key restore logs so rollback avoids full snapshots.
5. Recovery and fail-closed:
   - A per-volume recovery marker arms on pending native writes; `NativeWriteRecoveryPolicy` at startup maps `FailClosed` to read-only and `BestEffort` to native with recovery-active telemetry.
   - Checkpoint-stage failures latch recovery-required in-session, forcing later commit attempts to `NotWritable` until remount/recovery; metadata bootstrap reconciles persisted RW-state checkpoint xid with the superblock xid and forces recovery-required on mismatch.
6. Physical device layer:
   - `BlockDevice` issues aligned payload and checkpoint writes as ordered batch writes (adjacent-range merge, barriers preserved), uses a bounded overlapped event-handle pool for async batches by default, reuses aligned scratch buffers, and flushes once per durable batch.
   - Fault-injection switches and perf JSON counters (flush count/p95, batch and merged counts, scratch resize, WAL and spool latencies) keep ordering and barrier behavior observable.
7. Shutdown:
   - FsHost performs a bounded mutation drain before dispatcher stop: new external mutating callbacks are rejected (`STATUS_VOLUME_DISMOUNTED`) and in-flight callbacks finish within a timeout; the service then stops the host and updates tray/dashboard state.

## Current implementation scope

1. The application includes device discovery, host/process orchestration, WinFsp callbacks, guarded native reads and writes, recovery handling, dashboard/tray controls, and a structured CLI.
2. Writable mode is limited to supported APFS data volumes that pass the runtime safety and recovery gates.
3. Encrypted volumes, case-sensitive volumes, special APFS roles, snapshots, sealed/system layouts, and unsupported feature combinations remain read-only or unavailable.
