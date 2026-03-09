# Native Write Roadmap

## Scope baseline

1. First writable target is unencrypted/basic APFS volumes.
2. Tray UX remains unchanged (status-only tray with `Quit`).
3. Write rollout is conservative and gated.

## Current status

### Latest milestone progress (2026-02-24)

1. M1 canonical path proof telemetry propagation is now end-to-end:
   - FsHost sidecar emits `commitStage`, `replayStage`, `commitBlobMagic`, `canonicalPathActive`, and `canonicalGateFailure`.
   - FsHost sidecar now also emits replay-checkpoint availability telemetry (`replayCheckpointCandidatePresent`, `replayCheckpointPendingWindow`) from `MetadataStore`.
   - Native backend now attaches these fields to mount/runtime `NativeWriteDiagnostics`, including `deviceProfileId` correlation for evidence/pilot tracking.
2. Non-fixture fail-closed coverage has been expanded:
   - runtime safety checks now include scaffold replay-blob rejection and canonical-path proof enforcement for non-fixture native write mode.
   - strict canonical proof now requires explicit `canonicalPathActive=true`; missing proof (`null`) is treated as fail-closed (`CanonicalPathNotActive`) instead of being implicitly accepted.
   - when FsHost reports a canonical gate failure reason, backend now preserves that specific reason (for example `CanonicalStateNotLoaded`) instead of collapsing to a generic proof-gap reason.
   - backend fail-closed mapping/action tables now treat canonical gate failures (`CanonicalStateNotLoaded`, `NativeWriteNotReady`, `WriteDeviceNotAllowed`, `CommitPathNotReady`, `CanonicalCommitNotReady`) as first-class reasons with explicit diagnostics/actions.
   - service runtime compatibility warnings now include explicit canonical gate failure explanations so status output differentiates missing canonical proof from concrete canonical-gate blockers.
   - service warning aggregation now prioritizes canonical gate blockers ahead of generic recovery warnings across multi-volume status (`CanonicalStateNotLoaded`, `NativeWriteNotReady`, `WriteDeviceNotAllowed`, `CommitPathNotReady`, `CanonicalCommitNotReady`, then `CanonicalPathNotActive`).
   - tray status text/warning balloons now use the same recovery-priority ordering so canonical gate blockers are surfaced first in user-visible notifications.
   - new `ApfsAccess.Service.Tests` and `ApfsAccess.Tray.Tests` coverage now lock canonical-priority ordering and telemetry/reason selection (`GetRecoveryReasonPriority`, `GetCompatibilityWarningPriority`, `BuildRuntimeCompatibilityWarnings`, `ResolveWriteTelemetry`, `SelectPrimaryRecoveryReason`, `TryExtractReasonTokenFromWarning`) to prevent regression in warning ordering and primary recovery reason/action selection across service and tray surfaces.
   - FsHost native mutation gating now uses a consolidated canonical-gate requirement (`write_require_canonical_commit` plus strict non-fixture scaffold controls) for readiness reporting, mutation callback admission, and commit dispatch, with semantics-test coverage to prevent policy drift.
   - canonical non-fixture commit flow now treats sidecar state persistence (`before-state-persist`) as best-effort telemetry rather than a hard commit blocker; durable on-disk checkpoint/replay metadata remains authoritative for production media.
   - conformance-fault coverage now includes a canonical non-fixture scenario proving commits still succeed and advance xid when `before-state-persist` is faulted, while fixture rollback semantics remain unchanged.
   - FsHost metadata payload provider for native commit now reads only from existing hydration snapshots (`hydrate_if_missing=false`) to avoid lock re-entry into on-demand hydration/metadata fallback while commit already holds metadata locks.
   - semantics coverage now includes explicit hydration payload tests proving disabled hydrate-on-miss does not create files and still reads/pads existing hydration payload deterministically.
   - backend parsing tests now include explicit non-fixture safety assertions for scaffold replay blob and canonical proof gaps.
   - fail-closed reason resolution now prioritizes non-fixture canonical blockers (`FixtureCompatibilityPathActive`, `ScaffoldCommitBlobActive`, canonical-gate proof failures) ahead of generic runtime recovery markers so downgrade actions and diagnostics remain specific.
   - service/tray recovery-priority ordering now treats `FixtureCompatibilityPathActive` and `ScaffoldCommitBlobActive` as first-class canonical gate blockers (same priority tier as `CanonicalStateNotLoaded`/`CommitPathNotReady`) to keep user-visible warnings aligned with backend fail-closed decisions.
3. Strict non-fixture scaffold controls are now wired through host/runtime:
   - service/backend now pass strict replay/commit controls into FsHost (`write-disallow-scaffold-commit-on-non-fixture`, `write-reject-scaffold-replay-blob-on-non-fixture`, `write-require-canonical-replay-candidate-on-non-fixture`).
   - MetadataStore now enforces canonical replay-candidate requirements for non-fixture mode at replay-candidate validation and replay execution stages.
   - conformance-fault coverage now verifies:
     - default non-fixture scaffold replay rejection
     - relaxed non-fixture flags no longer re-enable scaffold replay compatibility
     - canonical replay-candidate strict mode still blocks scaffold replay (defense in depth).
   - FsHost semantics tests now cover argument parsing defaults and explicit overrides for the three strict non-fixture scaffold controls.
4. Non-fixture strictness is now fail-safe even under relaxed config:
   - backend now computes effective non-fixture scaffold controls per device and forces canonical-only strict controls for all non-fixture media (including `\\.\PhysicalDrive*`/`\\?\PhysicalDrive*`).
   - fixture/test media remains the only context where configured scaffold-compatibility toggles are honored.
   - the same effective control tuple is used for FsHost arg forwarding, mount-time fail-closed checks, and runtime reconciliation checks to avoid policy drift.
   - backend parsing tests cover direct device-id and mounted-volume-id resolution for non-fixture strictness and fixture-scoped override behavior.
5. Engine commit/replay strictness is further reduced to canonical-only on non-fixture write paths:
   - `MetadataStore` now centralizes canonical requirements (`RequiresCanonicalNonFixtureCommitPath`) so all non-fixture contexts always require canonical replay candidates, even when relaxed debug toggles are set.
   - non-fixture commit generation now always emits canonical commit blobs, and non-fixture replay no longer accepts scaffold commit blobs.
   - conformance-fault coverage now verifies scaffold replay remains fail-closed on non-fixture media even with relaxed non-fixture flags.
6. Mount-time replay metadata reconciliation is now stricter for canonical non-fixture mode:
   - `LoadPersistentState()` now tracks replay-checkpoint candidate priority and treats pending replay-checkpoint metadata as authoritative over persistent sidecar metadata in canonical non-fixture contexts.
   - persistent sidecar replay metadata is only used as a canonical non-fixture fallback when it still matches the pending xid window and no pending replay-checkpoint candidate is available.
   - fault-injection coverage now includes a non-fixture stale-sidecar replay scenario to assert replay-checkpoint precedence and fail-closed recovery behavior.
   - fault-injection coverage now also includes a non-fixture sidecar-fallback scenario where replay-checkpoint candidates are unavailable; replay succeeds only via valid sidecar pending-window metadata.
   - fault-injection coverage now includes a non-fixture fail-closed scenario that corrupts pending replay-checkpoint candidates while preserving applied-window metadata blocks, asserting remount remains recovery-blocked and reports canonical candidate absence rather than silently promoting sidecar metadata.
   - canonical non-fixture replay now can emit explicit fail-closed reason `ReplayCanonicalCandidateMissing` when replay metadata is incomplete for canonical recovery, and backend/service diagnostics now map that reason end-to-end.
7. Canonical replay fail-closed diagnostics now distinguish stale applied-window metadata from missing pending candidates:
   - canonical non-fixture replay can now emit `ReplayCheckpointNotPendingWindow` when replay metadata is present but outside the pending replay xid window.
   - backend/service reason normalization now maps `ReplayCheckpointNotPendingWindow` to fail-closed recovery diagnostics and compatibility warnings.
8. Fixture detection is now explicitly marker-based across native engine and managed backend:
   - `IsFixtureImagePath` now matches fixture/synthetic path segments and explicit fixture file extensions only; broad substring matching is removed.
   - non-fixture filenames containing the token `fixture` (for example `nonfixture-*.bin`) are no longer misclassified as fixture media.
   - parsing/conformance coverage now includes nonfixture-token paths to prevent regression.
9. Canonical non-fixture replay no longer uses sidecar commit-blob metadata as a recovery source:
   - `LoadPersistentState()` now only hydrates commit-blob replay metadata from on-disk replay-checkpoint candidates for canonical non-fixture mode.
   - sidecar state is retained only for xid diagnostics when replay-checkpoint metadata is absent; replay remains fail-closed without canonical pending replay candidates.
   - fault-injection scenarios now assert non-fixture sidecar-fallback attempts remain recovery-blocked with explicit canonical replay-failure reasons.
10. Canonical non-fixture committed metadata hydration is now disk-authoritative:
   - in canonical non-fixture mode, object-map/spaceman/inode/btree committed state is sourced from on-disk checkpoint/superblock projections, not sidecar payload snapshots.
   - sidecar payload remains diagnostic/telemetry input only for replay/xid fail-closed signaling, reducing production dependency on `%TEMP%` state payloads.
11. Canonical non-fixture mounts now ignore stale sidecar "behind superblock" state:
   - `LoadPersistentState()` no longer latches `PersistentStateBehindSuperblock` recovery from sidecar checkpoint xid drift in canonical non-fixture mode.
   - stale sidecar snapshots therefore do not downgrade healthy non-fixture mounts to recovery mode when on-disk checkpoint state is ahead and consistent.
   - persistence coverage now includes a canonical non-fixture remount scenario that injects stale sidecar metadata and verifies committed file/view state still comes from disk checkpoints.
12. Canonical non-fixture allocation planning no longer consumes sidecar high-watermark fields:
   - sidecar `next_extent` and `next_object_id` are ignored for canonical non-fixture mounts.
   - allocator high-watermark is recomputed from committed on-disk metadata projections after canonical non-fixture hydration.
   - this prevents stale sidecar allocator snapshots from skewing production non-fixture extent/object-id planning.
13. Canonical non-fixture remounts now latch recovery from on-disk replay pending windows even with stale sidecar state:
   - `LoadPersistentState()` now marks `ReplayCheckpointPendingWindow` when canonical non-fixture replay metadata shows a pending xid window and no stronger recovery reason is already active.
   - this guarantees recovery/replay is required before writable mode resumes, instead of allowing stale sidecar xid parity to mask pending replay work.
   - fault-injection coverage now includes a deterministic non-fixture pending-window latch remount (with stale sidecar state removed) that asserts `ReplayCheckpointPendingWindow` and verifies successful `ReplayIfSafe` recovery.
14. Canonical commit-blob telemetry is now mode-aligned at bootstrap:
   - `LoadContainerState()` now seeds `last_commit_blob_magic_` from active commit mode (`APFSRWCANON3` for non-scaffold contexts, `APFSRWSCAFF3` for fixture/scaffold contexts) instead of hard-defaulting to scaffold magic.
   - this avoids false scaffold-magic fail-closed signals in non-fixture canonical-ready startup status before first commit/replay.
   - conformance coverage now asserts canonical non-fixture mounts report canonical commit-blob magic before first commit.
15. Early runtime bootstrap defaults are now non-fixture fail-safe:
   - `MetadataStore` constructor defaults now seed commit-blob telemetry from context (`uses_scaffold_commit_blob_=false`, `last_commit_blob_magic_=APFSRWCANON3` on non-fixture media).
   - recovery/bootstrap paths now re-synchronize commit-blob telemetry whenever scaffold-mode activation is recomputed, preventing stale scaffold magic from leaking into non-fixture fail-closed decisions.
   - conformance-fault coverage now includes non-fixture constructor/bootstrap assertions for `UsesScaffoldCommitBlob=false`, `IsFixtureCompatibilityPathActive=false`, and canonical commit-blob magic.
16. Commit-model telemetry no longer conflates readiness:
   - `ActiveCommitModel()` now reports active commit format (`uses_scaffold_commit_blob_`) instead of deriving model from canonical readiness.
   - this keeps non-fixture canonical-format mounts from being mislabeled as scaffold during temporary readiness/recovery transitions.
   - conformance-fault coverage now asserts fixture seeds stay `ScaffoldCheckpoint` while non-fixture bootstrap defaults report `CanonicalApfsCheckpoint` even before commit-ready.
17. Canonical recovery-reason precedence now favors on-disk pending replay metadata:
   - in non-fixture canonical mode, `LoadPersistentState()` now reports `ReplayCheckpointPendingWindow` whenever a valid pending replay-checkpoint window exists, even if sidecar checkpoint xid also appears ahead.
   - this keeps recovery diagnostics anchored to authoritative on-disk replay state instead of sidecar drift markers.
   - conformance-fault coverage now expects canonical remounts to surface pending-window recovery reason before replay.
18. Backend fail-closed precedence now preserves replay-window diagnostics on non-fixture paths:
   - `GetFailClosedReasonForRuntimeStatus()` now returns explicit replay-window recovery reasons (`ReplayCheckpointPendingWindow` / `ReplayCheckpointNotPendingWindow`) before falling back to canonical-path-proof gaps.
   - this prevents canonical-proof fallback (`CanonicalPathNotActive`) from masking authoritative replay-window failure context.
   - parsing coverage now includes strict non-fixture scenarios that verify replay-window reasons remain stable under canonical gating.
19. Fixture-compatibility telemetry is now strictly fixture-scoped:
   - `MetadataStore::IsFixtureCompatibilityPathActive()` no longer aliases non-fixture scaffold observations into fixture-compatibility activity.
   - backend fail-closed precedence now evaluates scaffold signals before fixture-compatibility flags on non-fixture media so diagnostics stay specific (`ScaffoldCommitBlobActive` over `FixtureCompatibilityPathActive` when both are present).
   - conformance and backend parsing coverage now assert non-fixture scaffold-replay failures keep `IsFixtureCompatibilityPathActive=false` while still fail-closing on scaffold telemetry.
20. Validation status:
   - managed regression is green: `dotnet test APFSAccess.sln -c Release`.
   - native regression is green: `scripts/build_rw_engine.ps1 -Configuration Release -RunTests`, `scripts/build_native_host.ps1 -Configuration Release`, and `ctest --test-dir C:\\apfsaccess_native\\build\\Release -C Release --output-on-failure`.
21. Canonical non-fixture replay-window fault expectations were aligned with sidecar-independent reconciliation:
   - non-fixture fault scenarios with replay metadata outside the pending xid window now assert recovery-clear remount and no-op replay evaluation instead of sidecar-driven fail-closed recovery.
   - this locks the behavior introduced by canonical non-fixture sidecar drift suppression in `LoadPersistentState()` and prevents regressions back to sidecar-authoritative recovery in production paths.
22. Canonical non-fixture xid hydration no longer depends on sidecar commit xid fields:
   - `LoadPersistentState()` no longer applies `persisted_last_commit_xid` fallback for non-fixture canonical mode when replay-checkpoint metadata is absent/non-pending.
   - canonical non-fixture `last_committed_xid` is now derived from on-disk canonical sources only (container checkpoint, disk-loaded committed xid projections, and pending replay metadata when present).
   - this preserves integrity verification on non-fixture remounts without reintroducing sidecar commit-xid authority.
23. Disk-fallback canonical replay behavior is now explicitly covered for non-fixture mode:
   - fault-injection coverage adds a non-fixture remount scenario with sidecar state removed (forcing disk fallback), pending replay metadata corrupted, and only non-pending replay metadata retained.
   - expected behavior is now locked as fail-closed canonical recovery (`PersistentStateAheadOfSuperblock` before replay, then `ReplayCheckpointNotPendingWindow`/`ReplayCanonicalCandidateMissing` on replay attempt), with commit path remaining blocked.
   - this prevents accidental sidecar-dependent recovery bypass when non-fixture recovery must rely only on canonical pending-window replay metadata.
24. `apply_disk_fallback` canonical non-fixture replay hydration now matches primary persistent-state semantics:
   - canonical non-fixture fallback no longer promotes replay target xid/commit-blob metadata from non-pending replay candidates.
   - replay metadata contributes to `last_committed_xid`/commit-blob fields only when it is in the pending replay window.
   - this reduces non-pending replay metadata influence on canonical recovery state while preserving fixture-mode compatibility behavior.
25. FsHost shutdown-drain mutation semantics now include metadata mutators in explicit coverage:
   - semantics tests now verify `SetBasicInfo`, `SetFileSize`, `CanDelete`, and `SetDelete` return `STATUS_VOLUME_DISMOUNTED` while shutdown drain is active.
   - coverage asserts rejected metadata mutators do not alter file timestamp/size or delete-pending state and do not leak external-mutation callback counters.
   - this tightens M3 concurrency/drain safety guarantees without changing tray/service UX contracts.
26. FsHost shutdown-drain semantics now include data-path mutators:
   - semantics tests now verify `Write` and `Overwrite` return `STATUS_VOLUME_DISMOUNTED` while shutdown drain is active.
   - rejected data mutators are now explicitly asserted to preserve file size/timestamp and avoid mutation-callback counter leaks.
   - this closes another mutation path class under drain gating and strengthens deterministic fail-safe shutdown behavior.
27. FsHost `CB_Open` now fail-closes mutation-intent opens while shutdown drain is active:
   - mutation-access `Open` requests (`FILE_WRITE_DATA`, `DELETE`, and equivalent mutation masks) now return `STATUS_VOLUME_DISMOUNTED` when drain is latched.
   - read-only open requests remain unaffected; drain gating is scoped to mutation intent only.
   - semantics coverage now asserts rejected mutation-intent opens do not allocate open contexts, do not increment open/write handle counters, and do not leak external-mutation callback counters.
28. FsHost shutdown-drain gating now covers `SetSecurity` mutation requests:
   - `CB_SetSecurity` now uses the same external-mutation drain gate and returns `STATUS_VOLUME_DISMOUNTED` while shutdown drain is active.
   - write-enabled behavior remains unchanged outside drain (`STATUS_NOT_SUPPORTED`), and write-disabled behavior remains fail-closed via existing mutation-disabled path.
   - semantics coverage now locks both sides: mutation-drain `SetSecurity` rejection and continued read-only directory-open availability during drain.
29. FsHost cleanup delete-latch path is now drain-safe:
   - `CB_Cleanup` now short-circuits `FspCleanupDelete` mutation work when shutdown drain is active, preventing delete-intent latching during teardown.
   - semantics coverage now verifies cleanup delete under drain remains a strict no-op (no `delete_on_cleanup`, no `delete_pending`, no delete-intent count mutation).
   - this closes the remaining namespace-mutation edge in shutdown-drain teardown without changing normal cleanup behavior.
30. FsHost namespace visibility and mutation guards now fail closed on stale delete-intent state:
   - delete-block checks now treat `delete_pending`, `delete_latched`, and `delete_intent_count > 0` as equivalent blocked state across visibility, open, delete, rename, and close-removal paths.
   - this hardens concurrent interleavings where `delete_pending` visibility may lag momentarily while delete intent is already latched.
   - semantics coverage now includes stale-intent scenarios for rename and open to lock deterministic `STATUS_DELETE_PENDING` fail-closed behavior.
31. Ancestor-path stale delete-intent interleavings are now explicitly locked:
   - semantics coverage now verifies that stale ancestor delete intent (latched/intent-count state with `delete_pending` visibility lag) blocks both read `Open` and `Create` under that ancestor with `STATUS_DELETE_PENDING`.
   - rename same-path coverage now also verifies stale source delete-intent state is treated as delete-pending for fail-closed behavior.
   - this prevents ancestor-visibility lag from reopening namespace mutation/read windows during high-churn delete-on-close interleavings.
32. Parallel rename contention coverage now includes same-source and mixed set-delete races:
   - semantics tests now verify concurrent same-source renames to different targets resolve deterministically (one `STATUS_SUCCESS`, one `STATUS_OBJECT_NAME_NOT_FOUND`, one destination materialized).
   - semantics tests now verify concurrent `Rename(source->renamed)` and `SetDelete(source, TRUE)` on the same open context resolve to one serialized winner (rename-wins or delete-intent-wins) with consistent namespace state.
   - this strengthens M3 concurrency evidence for callback serialization and fail-closed outcomes under rename/delete interleavings.
33. Rename-replace contention coverage now includes delete-intent and delete-close target interleavings:
   - semantics tests now verify concurrent `Rename(source->target, replace=true)` and `SetDelete(target, TRUE)` on a busy target fail closed (`STATUS_SHARING_VIOLATION`/`STATUS_DELETE_PENDING`) with preserved namespace and latched target delete intent.
   - semantics tests now verify concurrent `Rename(source->target, replace=true)` and `Close(delete-latched target-handle)` resolve to consistent serialized outcomes (`STATUS_SUCCESS` move or `STATUS_DELETE_PENDING` with target removal), without duplicate parent-child entries.
   - this closes another high-churn rename-replace/delete-on-close race class under explicit deterministic assertions.
34. Multi-source same-target replace races are now explicitly covered, including target-handle transition:
   - semantics tests now verify concurrent `Rename(source-a->target, replace=true)` and `Rename(source-b->target, replace=true)` serialize without namespace duplication, converging to a single target path with both source paths removed.
   - semantics tests now verify the same dual-source replace race while a pre-existing target handle closes concurrently, accepting only deterministic status classes (`SUCCESS`/`SHARING_VIOLATION`) and asserting node-index/parent-children consistency for all serialized outcomes.
   - this strengthens M3 contention evidence for replace ordering and handle-transition stability under parallel mutators.
35. `CB_Rename` now enforces strict source-path identity for source-handle fallback:
   - when source lookup falls back through open-context state, rename now verifies `current_open->node->path` matches requested `old_path` before proceeding.
   - this prevents stale-handle/missing-source interleavings from renaming an unrelated node and creating inconsistent node-index aliases.
   - semantics coverage now includes explicit missing-source + source-handle fallback regression checks to lock fail-closed `STATUS_OBJECT_NAME_NOT_FOUND` behavior.
36. Shared-parent mixed sequencing coverage now includes rename with sibling delete-intent and delete-close flows:
   - semantics tests now verify concurrent `Rename(source-a->source-c)` and `SetDelete(source-b, TRUE)` under the same parent converge to consistent namespace and delete-intent state (`source-c` materialized, `source-b` delete-pending).
   - semantics tests now verify concurrent `Rename(source-a->source-c)` and `Cleanup+Close(source-b)` sibling delete-close flow converge to stable namespace state (`source-c` present, delete-closed `source-b` removed).
   - this expands M3 contention evidence for mixed rename/set-delete/close sequencing under shared-parent pressure.
37. Native fail-closed downgrade transition is now covered under concurrent mutators:
   - semantics tests now run concurrent native-path mutators (`Create` + `Rename`) while native commit readiness is unavailable and assert both fail with `STATUS_MEDIA_WRITE_PROTECTED`.
   - coverage asserts downgrade invariants remain stable after race (`recovery_active`, degraded write state, disabled write backends, preserved recovery reason/action, zero leaked external-mutation callback counters).
   - post-downgrade mutation-access `Open` denial is now explicitly verified to remain `MEDIA_WRITE_PROTECTED` with no context allocation.
38. Native fail-closed downgrade sidecar/status consistency is now covered under concurrent denial races:
   - semantics tests now configure a real `status_file` path and run concurrent native-path denials (`Create` + `Rename`) to force fail-closed downgrade while status writes are exercised.
   - coverage validates emitted status JSON fields stay coherent with downgrade state (`writeBackend=Disabled`, `nativeWriteReadiness=Degraded`, `recoveryActive=true`, `recoveryReason=NativeWriteUnavailable`, `lastRecoveryAction=DowngradedAfterNotReady`, `inFlightMutationCallbacks` present/non-negative at snapshot time).
   - this adds direct M3 evidence that runtime telemetry remains internally consistent at recovery/degrade boundaries under contention.
39. Shutdown-drain telemetry lifecycle now has explicit sidecar coverage:
   - semantics tests now run a real in-flight external mutation callback, write pre-drain status snapshot, and assert sidecar fields report `shutdownDrainActive=false` with one in-flight mutation callback.
   - tests then execute `BeginMutationShutdownDrain`, write post-drain snapshot, and assert sidecar transitions to `shutdownDrainActive=true` with zero in-flight mutation callbacks.
   - this adds M3 evidence that runtime drain telemetry remains coherent across drain activation/completion boundaries.
40. Canonical non-fixture remounts now treat sidecar parse failures as non-corrupting telemetry faults:
   - `MetadataStore::LoadPersistentState()` now falls back disk-authoritatively without sidecar `.corrupt` rotation when sidecar parsing fails in canonical non-fixture mode.
   - this keeps production non-fixture replay/commit hydration grounded in canonical disk/replay checkpoints while avoiding sidecar corruption-marker churn.
   - persistence coverage now corrupts injected non-fixture sidecar metadata and asserts remount remains disk-authoritative without producing sidecar `.corrupt` marker files.
41. Canonical non-fixture commits no longer emit sidecar state payloads:
   - `MetadataStore::PersistPersistentState()` now short-circuits as a non-fixture no-op (after commit-blob location validation), keeping sidecar persistence fixture/test-only.
   - non-fixture commit flow remains durable via canonical disk checkpoints; sidecar output is no longer produced as part of production commit success paths.
   - conformance-fault coverage now asserts non-fixture best-effort state-persist commits do not leave sidecar payload files behind.
42. Non-fixture scaffold-replay rejection now publishes explicit observed-blob telemetry:
   - `ReplayCanonicalCheckpoint()` now stamps `uses_scaffold_commit_blob_` and `last_commit_blob_magic_` immediately after commit-blob magic detection, before canonical-gate rejection is applied.
   - non-fixture scaffold replay candidates still fail closed (`ScaffoldCommitBlobActive`), but runtime diagnostics now preserve the observed scaffold blob format (`APFSRWSCAFF2`/`APFSRWSCAFF3`) for downstream policy/telemetry mapping.
   - conformance-fault coverage now asserts scaffold-replay rejection retains non-fixture fixture-compatibility isolation while exposing scaffold blob telemetry.
43. FsHost startup now hard-disables fixture legacy fallback on non-fixture media:
   - `ApplyNonFixtureCanonicalSafetyOverrides()` now forces `allow_legacy_scaffold_for_fixtures=false` whenever the device is non-fixture/unknown, in addition to strict canonical non-fixture scaffold controls.
   - fixture-tagged media still preserves explicit override values, including legacy scaffold fallback setting.
   - semantics coverage now locks both behaviors (non-fixture force-disable and fixture-preserve).
44. Native backend host-launch arg resolution now mirrors fixture-only legacy fallback policy:
   - `StartHostProcess` now computes effective `--allow-legacy-scaffold-for-fixtures` per device and forces `false` for unknown/non-fixture/raw-physical paths.
   - fixture-tagged media remains the only path where configured `NativeWriteAllowLegacyScaffoldForFixtures` can flow through to FsHost.
   - backend parsing coverage now includes explicit fixture-scoped effective-flag tests for this resolver.

### Milestone closure update (2026-03-03)

1. M1 "Production Canonical Path Lockdown" acceptance criteria were closed for fixture classification consistency:
   - FsHost canonical-gate fixture detection (`IsFixtureImagePathForCanonicalGate`) no longer infers fixture mode from parent-directory segments (`fixtures`, `synthetic`, etc.); it now uses explicit file/image naming patterns only.
   - This aligns FsHost with existing RW-engine and backend fixture classification behavior, removing the final cross-layer mismatch where non-fixture paths under fixture-like folders could be misclassified.
2. Native semantics coverage now locks this rule:
   - `FsHostSemanticsTests` now asserts `C:\\fixtures\\sample.bin` remains non-fixture for canonical gate evaluation.
   - `ApplyNonFixtureCanonicalSafetyOverrides` is now explicitly verified to keep strict non-fixture safety controls for fixture-like directory names without explicit fixture file patterns.
3. Validation evidence for this closure:
   - native build: `cmake --build C:\\apfsaccess_native\\build\\Release --config Release` (pass).
   - native tests: `ctest -C Release --output-on-failure` (7/7 pass).
   - managed regression: `dotnet test APFSAccess.sln -c Release --no-build` (276/276 pass).
4. M2 kickoff (started):
   - begin canonical mutation/commit/replay parity tightening by auditing remaining scaffold-era compatibility branches for non-fixture production paths and preparing the next consolidation batch.
5. M2 implementation batch 1 landed:
   - backend validation-evidence promotion now requires explicit canonical stage-proof telemetry for hardware-level counter accrual when runtime evidence seed is absent.
   - accepted proof signals are native runtime `commitStage` / `replayStage` or a positive `lastCommitXid`; without these, hardware/cross-OS/stable counter promotion is suppressed and validation freshness (`LastValidatedUtc`) is not refreshed.
   - this reduces promotion drift from ambiguous runtime payloads and keeps pilot/stable evidence tied to concrete canonical commit/replay activity.
6. Coverage and validation for M2 batch 1:
   - managed parsing coverage adds `MergeValidationEvidenceFromRuntimeStatus_DoesNotPromoteCounters_WhenHardwareValidationLacksStageProof`.
   - backend-native test project is green after the change (`206/206`).
   - native and managed regressions remain green (`ctest -C Release` 7/7, `dotnet test APFSAccess.sln -c Release --no-build` pass).
7. M2 implementation batch 2 landed:
   - `MetadataStore::CommitPendingMutations()` now emits explicit terminal `last_commit_stage_` markers for non-hook short-circuit exits (for example `not-ready`, `not-writable`, `preflight-validation-failed`, `commit-blob-build-failed`, payload-provider failures, and device-write/flush failures).
   - This removes ambiguous `"start"` telemetry on early commit failures and keeps commit-stage diagnostics authoritative for non-fixture canonical troubleshooting.
   - Existing hook-driven stage markers (`before-*`, `replay-*`) are unchanged; this batch only hardens uncovered non-hook exit paths.
8. Coverage and validation for M2 batch 2:
   - native rebuild is green after the change (`cmake --build C:\\apfsaccess_native\\build\\Release --config Release`).
   - native regression remains green (`ctest -C Release --output-on-failure` 7/7 pass).
9. M3 kickoff (started):
   - identified next hardening targets for high-contention semantics in `FsHost` and backend runtime reconciliation (`src-native/ApfsAccess.FsHost/src/main.cpp`, `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs`) with focus on deterministic mutation-admission under shutdown-drain pressure.
10. M3 implementation batch landed (mutation-admission hardening):
   - `FsHost` now treats `Open` requests with `FILE_DELETE_ON_CLOSE` as mutating intent even when access masks are minimal.
   - shutdown-drain and write-disabled gates therefore now fail-close those `Open` requests the same way as explicit write/delete access requests.
   - this closes a remaining high-contention edge where delete-on-close open intents could bypass mutation admission checks under teardown pressure.
11. Files touched for this batch:
   - `src-native/ApfsAccess.FsHost/src/main.cpp` (`HasOpenMutationIntent`, `CB_Open` mutation-intent gating).
12. What now works:
   - deterministic mutation admission for delete-on-close open intents under shutdown-drain and read-only fail-closed paths.
   - M3 acceptance criteria are considered complete in current scope (`sharing/rename/delete-on-close/drain determinism`, `evidence/staleness gate enforcement`, `explicit downgrade diagnostics/actions`).
13. New assumptions / risks:
   - assumes WinFsp surfaces delete-on-close via `create_options` consistently on this callback path.
   - remaining uncertainty is hardware-level race behavior under real-device workloads (handled in M4 pilot matrix).
14. Follow-ups (next milestone):
   - start M4 hardware reliability and cross-OS evidence execution (`hot-unplug`, `power-loss replay`, `macOS consistency`) before stable promotion.
15. M4 kickoff (started):
   - queued physical-device pilot evidence runbook execution and cross-OS validation collection as the next implementation block; no promotion-policy defaults were relaxed.
16. M4 implementation batch 1 landed (evidence hardening + runbook tooling):
   - raw-device validation-evidence promotion now requires explicit runtime validation-evidence signals before observed runtime validation states above `CanonicalImageValidated` are eligible for counter accrual.
   - this prevents raw-device pilot/stable counters from auto-advancing purely from reported runtime validation state without evidence payloads.
   - backend promotion still preserves existing fail-closed threshold/staleness enforcement; this batch narrows counter accrual eligibility.
17. Files touched for M4 batch 1:
   - `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs`
   - `tests/ApfsAccess.Backend.Native.Tests/NativeApfsBackendParsingTests.cs`
   - `scripts/update_write_evidence.ps1`
   - `docs/native-write-pilot.md`
   - `docs/winfsp-setup.md`
   - `build/publish.ps1`
18. What now works after M4 batch 1:
   - raw physical-device validation counters do not auto-promote from runtime validation-state telemetry alone.
   - pilot operators now have an explicit evidence-update utility (`scripts/update_write_evidence.ps1`) and a dedicated execution runbook (`docs/native-write-pilot.md`) for crash/hot-unplug/power-loss/macOS evidence capture.
   - click-run publish notes now reflect native write policy/evidence gating instead of obsolete mirror-only wording.
19. Remaining M4 external gates (not automatable in this workspace):
   - physical-device crash/hot-unplug/power-loss matrix execution.
   - macOS mount/read/integrity validation on Windows-written APFS media.
   - stable promotion sign-off after evidence thresholds are met on real hardware.
20. M4 status:
   - implementation is in progress; code-side enforcement and pilot tooling are complete, while hardware/cross-OS evidence execution remains open.
21. Validation and packaging for M4 batch 1:
   - managed validation gate passed: `dotnet test APFSAccess.sln -c Release`.
   - publish bundle refreshed: `pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64`.
   - updated artifacts:
     - `artifacts/publish/click-run`
     - `artifacts/publish/portable`
     - root launcher `APFSAccess_Portable.exe`.
22. M4 implementation batch 2 landed (profile-bound evidence integrity + pilot report ingestion):
   - backend runtime-evidence merge now rejects validation-evidence payloads whose `lastValidationProfileId` does not match the computed target profile id for the mounted volume.
   - accepted runtime evidence is normalized to the target profile id before counter promotion, preventing cross-profile contamination.
   - raw-device counter promotion already requiring explicit evidence signal now additionally requires profile-consistent evidence telemetry.
23. Pilot tooling additions:
   - added `scripts/import_validation_report.ps1` to ingest structured hardware/macOS validation results into `%ProgramData%\\ApfsAccess\\write-evidence.json`.
   - runbook updated with report schema/import flow (`docs/native-write-pilot.md`).
   - click-run publish now bundles pilot evidence scripts under `artifacts/publish/click-run/scripts/`.
24. Files touched for M4 batch 2:
   - `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs`
   - `tests/ApfsAccess.Backend.Native.Tests/NativeApfsBackendParsingTests.cs`
   - `scripts/import_validation_report.ps1`
   - `docs/native-write-pilot.md`
   - `build/publish.ps1`
   - `docs/api-contracts.md`
   - `README.md`
25. M4 batch 2 validation:
   - managed milestone check passed: `dotnet test APFSAccess.sln -c Release`.
26. M4 blocker status (unchanged):
   - remaining acceptance items require physical APFS hardware fault runs and macOS verification host; these cannot be completed inside this workspace-only execution context.
27. M4 implementation batch 3 landed (pilot execution tooling + readiness evaluation):
   - added `scripts/new_validation_report.ps1` to generate a deterministic pilot/macos scenario report template per device profile.
   - added `scripts/evaluate_write_promotion.ps1` to evaluate current evidence store vs `Service` thresholds/policy and emit eligibility + fail-closed reasons.
   - this enables repeatable pre-promotion audits without requiring backend process introspection.
28. Packaging/docs updates for batch 3:
   - click-run publish now includes pilot helper scripts (`new_validation_report.ps1`, `evaluate_write_promotion.ps1`) under `artifacts/publish/click-run/scripts/`.
   - runbook updated with template-generation/import/readiness-check workflow (`docs/native-write-pilot.md`).
29. Files touched for M4 batch 3:
   - `scripts/new_validation_report.ps1`
   - `scripts/evaluate_write_promotion.ps1`
   - `build/publish.ps1`
   - `docs/native-write-pilot.md`
   - `README.md`
30. M4 remaining acceptance blockers (unchanged):
   - physical APFS hardware fault/power-loss matrix execution.
   - macOS mount/read/integrity validation evidence collection.
   - stable promotion sign-off after external evidence thresholds are met.
31. M4 batch 3 validation:
   - managed milestone check passed: `dotnet test APFSAccess.sln -c Release`.
32. M5 closure update (2026-03-06):
   - `SetBasicInfo` timestamp payloads are now durably represented in the native write path instead of being xid-only bookkeeping.
   - native inode state, btree inode encoding, checkpoint persistence, and persisted sidecar state now carry `timestamp_utc`, preserving committed metadata across `Flush` and remount.
   - FsHost now forwards `SetBasicInfo` timestamps into native mutation requests and remount merge now reflects committed inode timestamps back into the live node index.
33. M5 validation/parity tightening:
   - volume-tree projection and commit preflight validation now decode the timestamp-bearing inode record layout instead of assuming the older value shape.
   - commit preflight now verifies decoded inode timestamps match working inode state, closing the parity gap for the admitted v1 mutation surface.
   - native persistence/fault/canonical test fixtures were updated for the new inode layout/version and now assert `SetBasicInfo` survives commit and remount.
34. M5 validation evidence:
   - native RW engine validation passed: `pwsh -NoProfile -File .\\scripts\\build_rw_engine.ps1 -Configuration Release -RunTests` (`6/6`).
   - native host build passed: `pwsh -NoProfile -File .\\scripts\\build_native_host.ps1 -Configuration Release`.
   - full native CTest validation passed: `ctest --test-dir C:\\apfsaccess_native\\build\\Release -C Release --output-on-failure` (`7/7`).
35. Post-M5 status:
   - the admitted v1 native mutation surface (`CreateFile`, `CreateDirectory`, `Write`, `SetFileSize`, `Rename`, `Delete`, `SetBasicInfo`) is now durably modeled or explicitly fail-closed in current scope.
   - `CB_SetSecurity` remains intentionally unsupported for v1 and is still out of scope.
36. Next milestone:
   - M6 external pilot evidence closure is now the next remaining execution block; completion depends on physical APFS media, controlled crash/hot-unplug/power-loss runs, and macOS verification.
37. M6 implementation batch 1 landed (pilot readiness evaluator hardening):
   - `scripts/evaluate_write_promotion.ps1` now returns structured JSON even when the evidence store is empty, so the planned `-AsJson` validation path remains machine-readable instead of emitting plain-text sentinel messages.
   - the evaluator now supports explicit target-profile checks (`-ProfileId`) by synthesizing a blank evidence baseline when no persisted record exists yet, allowing operators to validate a chosen raw-device profile before and after importing matrix evidence.
   - readiness output now includes config-gate eligibility alongside evidence thresholds (`configEligible`, `configReasons`, `allowListConfigured`, `allowListed`) so pilot closure can verify raw-device allow-list/policy setup, not only evidence counters.
38. M6 config-gate coverage added to the evaluator:
   - raw-profile evaluation now reports fail-closed blockers for disabled native write, blocked rollout channel, raw-physical write disabled, `ScaffoldOnly` promotion policy, missing hardware pilot allow-list, and non-allow-listed raw-device profiles.
   - non-raw profiles are explicitly reported as ineligible under `PilotHardware` / `Stable` promotion checks, matching the physical-device scope of M6 closure.
39. M6 runbook update:
   - `docs/native-write-pilot.md` now documents profile-target evaluation via `evaluate_write_promotion.ps1 -ProfileId ... -AsJson` and calls out the new config-gate fields in readiness output.
40. M6 blocker status:
   - this workspace currently has no `%ProgramData%\\ApfsAccess\\write-evidence.json` ledger and no attached/verified raw APFS pilot media, so the external crash/hot-unplug/power-loss/macOS evidence matrix still cannot be completed here.
   - milestone acceptance remains blocked on real hardware execution and macOS verification evidence import for at least one allow-listed raw-device profile.
41. M7 implementation batch 1 landed (release/docs alignment to current reality):
   - `README.md` now describes the product as a native WinFsp mount app rather than a generic scaffold and updates the top-level native-write status text to reflect the current state: direct read path is complete, image-backed native validation is in-repo, and raw physical-device write remains pilot-only pending external evidence.
   - user-facing stale wording such as `Phase-1 limits`, `Native write scaffolding (phase A)`, and generic RW-engine `scaffold` labels in release guidance has been reduced in the primary README/publish surfaces.
   - `docs/api-contracts.md` now explicitly states that raw physical-device native write remains pilot-only in current repo state and that `PilotHardware` / `Stable` promotion depends on externally imported evidence plus `evaluate_write_promotion.ps1`.
42. M7 publish/operator guidance update:
   - click-run publish guidance (`build/publish.ps1` -> `README_RUN.txt`) now points operators at the bundled pilot helper scripts (`new_validation_report.ps1`, `import_validation_report.ps1`, `evaluate_write_promotion.ps1`, `update_write_evidence.ps1`) instead of only the older evidence updater.
   - release guidance now distinguishes image-backed in-repo validation from raw-device pilot validation so published artifacts do not imply stable physical-device write.
43. M7 validation passed and the milestone is complete:
   - `pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64` completed successfully and refreshed the split publish outputs, click-run bundle, and portable launcher bundle.
   - publish output now includes the current native host, `apfsutil.exe`, native RW engine artifact, pilot runbook, and pilot helper scripts, satisfying the release-surface acceptance criteria without implying stable raw-device write.
44. Current project gate after M7:
   - the repo has reached the external-validation boundary: further progress toward the final native-write goal now depends on attaching at least one allow-listed raw APFS device, running the crash/hot-unplug/power-loss matrix, and importing matching macOS mount/read/integrity evidence.
   - until that external evidence exists, `M6` remains the only open milestone and raw physical-device writable validation cannot be completed from this workspace alone.

### Latest milestone progress (2026-03-06)

1. M0 stabilization is complete:
   - `.NET` solution builds cleanly after native write telemetry model updates.
   - Service status publishing now carries `nativeWriteEngineState` and `writeIncompatibilities`.
2. M1 canonical-read-model cutover is in progress:
   - metadata load path now validates object-map/spaceman/volume-tree projections through dedicated canonical parser modules.
   - service/backend/runtime contracts now include explicit commit-model telemetry (`ScaffoldCheckpoint|CanonicalApfsCheckpoint`) and `writeUnsupportedFeatures`.
   - runtime contracts now also expose native write validation progression (`Scaffold|CanonicalImageValidated|HardwarePilotValidated|CrossOsValidated|Stable`) plus shutdown-drain pressure telemetry (`shutdownDrainActive`, `inFlightMutationCallbacks`) from FsHost sidecar -> backend -> service IPC.
   - canonical commit readiness is now invariant-driven (global kill switch removed); strict mode still requires canonical commit model for RW.
   - FsHost/runtime telemetry now reports `fixtureLegacyFallbackActive` and `usesScaffoldCommitBlob` so production mounts can fail closed when scaffold/fixture paths are detected.
3. M1 strictness pass is in place:
   - Raw physical-device bootstrap now requires stricter object-map/spaceman readiness.
   - Synthetic/image-backed fixtures keep fallback bootstrap behavior so deterministic native test suites remain green.
4. Promotion gate policy is stricter:
   - `NativeWritePromotionPolicy=Stable` now requires backend validation-evidence thresholds (crash/hardware/cross-OS/power-loss as configured) before write stays enabled.
5. M2 mutation hardening increment landed:
   - object-map staging now canonicalizes pending updates to one entry per object id within a transaction.
   - replay semantic validation now permits exact allocation/deallocation overlap pairs (net-zero extent churn) while still rejecting partial/invalid overlap patterns.
   - conformance suite now covers object-map delta canonicalization and create-write-delete ephemeral transaction behavior.
   - replay validation now accepts exact-overlap deallocation entries without requiring committed free-extent coverage, and conformance now includes interrupted-checkpoint remount replay for ephemeral create-write-delete transactions.
   - commit preflight now mirrors replay overlap semantics by rejecting any partial pending allocation/deallocation overlap (exact overlap only), reducing commit-time acceptance of states that replay would fail closed.
   - fault-injection replay coverage now verifies a second remount after successful replay stays recovery-clear and commit-ready.
   - replay parser now rejects duplicate object-map entries in commit blobs (same object id repeated), eliminating last-write-wins ambiguity in crash-replay input.
   - fault-injection coverage now includes checksum-preserving duplicate object-map commit-blob tampering and asserts fail-closed replay behavior.
   - FsHost now latches dirty-transaction safety breaches as explicit runtime recovery telemetry (`DirtyTransactionLimitExceeded` / `DowngradedAfterDirtyTransactionLimit`), and native backend fail-closed evaluation enforces the same reason during mount/runtime refresh.
   - persistent-state parser now enforces structural bounds (count caps, inode/path length limits, btree payload limits, aligned/overflow-safe extent entries) to reject malformed metadata before hydration.
   - fault-injection coverage now includes oversized persistent-state inode path metadata corruption; rejected state falls back to disk checkpoint/replay metadata and recovery replay remains deterministic.
   - replay metadata handling now uses a shared commit-blob location validator (alignment/container-bound/reserved-region checks) across replay execution and replay-checkpoint persistence.
   - load/replay reconciliation now treats malformed persistent commit-blob location metadata as non-authoritative and falls back to valid on-disk replay-checkpoint commit metadata.
   - load/replay reconciliation now prefers on-disk replay-checkpoint commit metadata when persistent-state and replay-checkpoint metadata share the same commit xid but commit-blob metadata differs.
   - replay-checkpoint candidate selection now validates referenced commit-blob header/checksum/xid window consistency before replay metadata is accepted during mount-time reconciliation.
   - replay-checkpoint candidate validation now also rejects duplicate object-map object ids and overlapping allocation/deallocation extent sets inside referenced commit blobs.
   - replay-checkpoint persistence now validates referenced commit-blob header/checksum/xid window consistency before writing checkpoint metadata.
   - commit-blob location validation now requires block-aligned byte lengths in addition to aligned addresses, rejecting truncated/non-aligned replay metadata pointers.
   - fault-injection coverage now includes malformed persistent commit-blob location metadata and asserts replay-checkpoint fallback recovery remains deterministic when replay metadata is valid.
   - replay-checkpoint selection now filters to superblock-compatible xid windows (`target == superblock` or pending `source == superblock && target == superblock + 1`), preventing out-of-window checkpoint metadata from overriding valid replay state.
   - replay-checkpoint parser now enforces exact v1 payload length (`24` bytes), rejecting checksum-valid payload-size tampering instead of accepting ambiguous trailing metadata.
   - replay-checkpoint parser now enforces zero trailing bytes beyond the canonical payload, rejecting checksum-uncovered trailing-byte tampering.
   - replay-checkpoint parser now requires non-zero checksum validation for replay metadata blocks, removing checksum-optional acceptance.
   - fault-injection coverage now includes checksum-preserving replay-checkpoint xid-window tampering and asserts remount replay still succeeds by falling back to valid persistent replay metadata.
   - fault-injection coverage now includes replay-checkpoint commit-blob pointer tampering and asserts invalid replay candidates are filtered before replay metadata selection.
   - fault-injection coverage now includes semantic tampering of the highest-xid replay-checkpoint commit blob (duplicate object-map object id) and asserts remount stays on persistent checkpoint state.
   - fault-injection coverage now includes non-aligned commit-blob byte-size tampering in persistent-state and replay-checkpoint metadata, asserting deterministic fallback to valid replay metadata.
   - fault-injection coverage now includes checksum-preserving replay-checkpoint payload-length tampering and asserts remount replay safely ignores malformed checkpoint payload metadata.
   - fault-injection coverage now includes zeroed replay-checkpoint checksum tampering and asserts deterministic replay-checkpoint fallback behavior.
   - fault-injection coverage now includes replay-checkpoint trailing-byte tampering (without checksum changes) and asserts deterministic replay-checkpoint fallback behavior.
   - replay fault matrix now explicitly covers persistent-state xid-window jumps and asserts deterministic fail-closed `ReplayXidWindowInvalid` outcomes.

1. Phase-A scaffold is implemented:
   - Core contracts include write capability metadata and safety gate state.
   - Service options include rollout/safety controls.
   - IPC status payload includes `writeEnabled` and `compatibilityWarnings`.
   - Native backend emits write-block diagnostics markers.
   - Native RW engine modules are present (`BlockDevice`, `MetadataStore`, `TransactionManager`).
   - `BlockDevice` now performs real device/file read/write/flush I/O primitives.
   - `MetadataStore` now parses APFS container superblock baseline fields (`NXSB`, block size, total blocks, checkpoint xid) for bootstrap readiness checks.
   - `TransactionManager` now persists mutation intent journals for begin/commit/abort flows with staged commit notifications (`prepare`, `write-data`, `write-metadata`, `flush-data`, `switch-checkpoint`, `finalize`).
   - FsHost mutating callbacks now batch transaction-journal entries until `Flush` (plus dirty-limit checkpoints) and call native mutation-planning APIs.
   - `MetadataStore` now stages object-map/spaceman mutation records and exposes `CommitPendingMutations()` scaffold, including deterministic commit-status codes.
   - `MetadataStore` now tracks structured inode/directory mutation state and persists committed scaffold state (object-map/spaceman/inode metadata) under `%TEMP%\ApfsAccess\rw-state`, restoring it during remount bootstrap.
   - native mutation staging now allocates extents based on full logical file size for `Write`/`SetFileSize` paths and validates payload-size/extent invariants before commit.
   - FsHost now provides hydrated file payloads to the RW engine so `CommitPendingMutations()` writes payload bytes into staged extents before commit metadata is finalized.
   - commit stage machine now includes checkpoint-switch scaffolding that updates container superblock checkpoint xid on writable image-backed targets.
   - superblock bootstrap now scans primary/secondary checkpoint slots and selects the latest valid xid; commit switch alternates slots and exposes dedicated hook stages (`before-checkpoint-write`, `before-checkpoint-flush`).
   - metadata bootstrap now reconciles persisted RW state against superblock checkpoint xid and marks recovery-required when state is ahead/behind on remount.
   - recovery-required state keeps commit path blocked (readiness != `CommitReady`) so policy can fail-closed safely.
    - FsHost now invokes native commit scaffold during `Flush` and reports `CommitReady` only when commit path is writable under the current safety policy.
    - FsHost persists per-volume recovery markers for interrupted native-write sessions and applies startup policy (`FailClosed` vs `BestEffort`), propagating recovery telemetry to status sidecar output.
    - Recovery telemetry now includes explicit `recoveryReason` propagation from FsHost sidecar -> native backend -> mounted state compatibility warnings.
    - metadata path indexes now use canonical case-insensitive keys (Windows semantics), and rename mutation validation now blocks subtree/cycle moves (`dir -> dir\\child\\...`) plus directory/file type-mismatch replacements.
    - commit preflight now validates inode/path/link graph integrity (including cycle detection and link referential checks) and rejects inconsistent persisted state payloads during RW bootstrap.
     - case-only rename (`foo.txt` -> `FOO.txt`) now applies cleanly in native mutation state and persists requested destination casing.
     - post-persistence checkpoint-stage failures now latch `recoveryRequired` in-session (`commitPathReady=false`) so retry commits fail closed until remount/recovery.
     - fault-injection coverage now verifies fail-closed retry behavior for both `before-checkpoint-switch` and `before-checkpoint-flush` failure points.
     - Native rw-engine now has CTest coverage for commit/remount persistence and commit-stage fault injection against synthetic APFS container images.
     - FsHost now enforces delete-pending/open-handle guards in mutating callbacks: pending deletes block fresh opens (`STATUS_DELETE_PENDING`), replace/delete paths reject active-handle targets (`STATUS_SHARING_VIOLATION`), and cleanup/close now defer physical node removal until final handle close.
     - FsHost now funnels native commit policy through one shared path and runs finalize attempts on `Flush`, `Close` (write/delete handles), and `Shutdown`, reducing dependence on explicit flush-only persistence.
     - Native RW engine now includes a dedicated conformance suite (`MetadataStoreConformanceTests`) that asserts rename-replace behavior, non-empty directory delete protection, subtree-rename rejection, and truncate-to-zero deallocation semantics.
     - Native RW engine now includes a fault-injected conformance suite (`MetadataStoreConformanceFaultTests`) that validates rollback/retry semantics for rename-replace and directory-delete workflows, plus fail-closed recovery latching on checkpoint-write interruptions.
     - Native backend volume parsing for `listsubvolumes` output is hardened for noisy tokens/header variants, preserves unquoted multi-word volume names, and now surfaces read-only/special-role (`role=preboot|recovery|vm`) write-incompatibility hints with regression coverage in `ApfsAccess.Backend.Native.Tests`.
     - Native backend host-status parsing now normalizes backend/readiness/recovery telemetry defensively (including malformed/partial JSON fallback), with dedicated regression coverage in `NativeApfsBackendRuntimeStatusTests`.
     - FsHost now serializes native metadata-store mutation/commit access across callback threads and enforces `--write-commit-timeout` through commit-stage deadline hooks, with fail-closed timeout degradation telemetry (`CommitTimedOut`).
     - Native backend now applies reason-aware fail-closed write gating (`CommitTimedOut`, checkpoint/persist failures, recovery-marker states) with structured gate/diagnostic codes and runtime downgrade markers for post-mount write->read-only transitions.
     - Service/IPC telemetry now carries `RecoveryReason` end-to-end, and runtime compatibility warnings include human-readable explanations for known recovery/commit failure reasons.
     - MetadataStore now exposes committed inode snapshots plus direct committed file-range reads, enabling FsHost to hydrate files from native committed extents when `apfsutil readraw` cannot provide content.
     - FsHost startup now overlays committed inode state onto the in-memory node index after APFS root bootstrap, preserving prior committed native-write state in Explorer view across remounts.
     - FsHost now supports metadata-backed direct-read fallback for file opens/reads in read-only mode when hydrated handle creation is unavailable, using committed extent reads from the native metadata store.
     - Service/config contracts now include raw-physical-write gate controls (`NativeWriteAllowRawPhysicalDevices`, pilot allow-list, integrity-check and crash-replay mode settings), and `WriteGatePolicy` enforces pilot allow-list + raw-device default block.
     - Runtime telemetry now includes `nativeWriteSafetyState`, `lastRecoveryAction`, and `dirtyTransactionCount` from FsHost sidecar through backend/service/tray IPC.
     - Service/runtime IPC now also surfaces `nativeWriteEngineState` and aggregated `writeIncompatibilities` for mounted volumes.
     - Metadata bootstrap now applies strict canonical checkpoint requirements by default, with legacy fallback permitted only for fixture-like image paths when `allow_legacy_scaffold_for_fixtures` is enabled.
     - MetadataStore now exposes layered API entrypoints (`LoadContainerState`, `LoadVolumeState`, `StageMutation`, `CommitTransaction`, `ReplayOrRecover`, `VerifyIntegrity`) while preserving existing mutation/commit behavior.
     - FsHost now accepts new native write arguments (`--write-crash-replay-mode`, `--write-integrity-check-on-mount`, `--allow-raw-physical-write`) and forwards them into MetadataStore context.
     - `ReplayOrRecover` now replays against the on-disk checkpoint xid (not the promoted in-memory xid), validates commit-blob header offsets correctly, persists checkpoint-switch recovery in `ReplayIfSafe`, and restores commit readiness state after replay.
     - Fault-injection tests now include a replay scenario that verifies interrupted checkpoint-switch commits remain unreconciled on-disk before replay and become persisted to superblock checkpoints after replay.
     - Commit path now persists deterministic metadata checkpoint blocks directly on disk for object-map and spaceman state (`APFSRWOMAP3` and `APFSRWSPM3`) before checkpoint switch, and load path hydrates from these blocks on remount.
     - Object-map/spaceman checkpoint parse now uses dedicated canonical parser modules with checksum enforcement and overlap/alias invariants.
     - Commit path now performs object-map/spaceman checkpoint round-trip verification immediately after persistence (re-read + canonical parse/compare), fail-closing on mismatch.
     - Commit path now also performs inode/btree checkpoint round-trip structural verification after persistence (re-read + header/count/payload/checksum validation), fail-closing on mismatch before replay/checkpoint switch progression.
     - Btree checkpoint round-trip verification now compares full canonical record content (kind/key/value/tombstone) and exact target xid after reload, rather than accepting xid-only progression.
     - Inode checkpoint round-trip link comparison now validates stable link identity (`parent|name|child`) so benign xid churn in directory-link metadata does not trigger false fail-closed commits.
     - Replay checkpoint persistence now performs immediate round-trip verification (persisted metadata reload + xid/commit-blob pointer match + replay-candidate validation), fail-closing as `CommitReplayRoundTripFailed` on any mismatch.
     - Commit stage hooks now expose `before-replay-roundtrip-verify`; interruption at this stage fail-closes as `CommitInterruptedBeforeReplayRoundTripVerify`.
     - Fault-injection coverage now includes deterministic replay-checkpoint payload tampering at `before-replay-roundtrip-verify`, asserting `CommitReplayRoundTripFailed` + commit-path fail-closed behavior.
     - Checkpoint switch now performs immediate superblock round-trip verification (readback of active superblock magic/block-size/checkpoint-xid), fail-closing as `CommitCheckpointRoundTripFailed` on any mismatch.
     - Commit stage hooks now expose `before-checkpoint-roundtrip-verify`; interruption at this stage fail-closes as `CommitInterruptedBeforeCheckpointRoundTripVerify`.
     - Fault-injection coverage now includes deterministic superblock checkpoint-xid tampering at `before-checkpoint-roundtrip-verify`, asserting `CommitCheckpointRoundTripFailed` + commit-path fail-closed behavior.
     - FsHost path visibility now applies delete-pending ancestry checks so descendant create/open/rename operations fail conservatively while pending-delete state is active.
     - FsHost native commit finalization now serializes concurrent `Flush`/`Close` commit attempts via a dedicated commit mutex to prevent overlapping commit status transitions.
     - FsHost rename no-op path handling now validates source existence/visibility before returning success, avoiding silent success on missing or delete-pending paths.
     - Added `ApfsAccess.FsHost.SemanticsTests` native regression target to cover conflicting create flags and delete-pending ancestry behavior for open/security/delete callback paths.
     - FsHost rename now rejects mismatched open contexts (`ctx` must reference the source node) and cleanup delete-on-close latching now requires explicit `DELETE` access on the open handle.
     - `ApfsAccess.FsHost.SemanticsTests` coverage now includes mismatched-context rename rejection and cleanup delete permission enforcement.
     - FsHost now applies parent-directory `FILE_DELETE_CHILD` semantics in mutating namespace operations: `CanDelete` allows direct-child delete checks via parent handles, and `Rename` accepts parent-directory contexts when child-delete access is present.
     - `ApfsAccess.FsHost.SemanticsTests` coverage now includes parent-directory `FILE_DELETE_CHILD` allow/deny paths for `CanDelete` and `Rename`, plus cleanup-delete non-empty-directory guard behavior.
     - FsHost rename-replace now requires target-parent child-delete authorization (`FILE_DELETE_CHILD`) whenever rename executes with a handle context, blocking source-handle-only replace paths that cannot authorize target deletion.
     - `ApfsAccess.FsHost.SemanticsTests` now covers rename-replace permission hardening (source-handle replace denied, target-parent replace allowed) and verifies parent `FILE_DELETE_CHILD` is limited to direct-child paths.
     - FsHost rename via target-parent directory handles now enforces insert rights (`FILE_ADD_FILE` for file targets, `FILE_ADD_SUBDIRECTORY` for directory targets), preventing child-delete-only handles from creating destination entries.
     - `ApfsAccess.FsHost.SemanticsTests` now includes cross-parent rename insert-right enforcement for file and directory moves via target-parent handles.
     - FsHost same-parent rename via parent-directory context now also enforces destination insert rights in addition to child-delete authorization.
     - FsHost cross-parent rename now rejects old-parent-only directory-handle contexts; destination authority must be represented by target-parent handle permissions in parent-handle flows.
     - Rename-replace with target-parent contexts now explicitly requires both destination insert rights and `FILE_DELETE_CHILD`, with dedicated allow/deny semantic regression coverage.
     - `CanDelete` null-name context flows now require `DELETE` access on the opened node itself (not parent `FILE_DELETE_CHILD`), and semantic coverage now includes same-parent/cross-parent replace edge cases across file and directory targets.
     - Semantic coverage now also includes open-handle conflict behavior for delete/rename paths: `CanDelete`/`SetDelete` sharing-violation checks, directory-rename blocking on open descendants, and source-handle rename success when no conflicting handles exist.
     - Rename no-op (`old == new`) now enforces context identity/rights checks (source `DELETE` or parent `FILE_DELETE_CHILD`) instead of permitting mismatched-handle success.
     - Cross-parent rename via source-handle context is now fail-closed (`ACCESS_DENIED`) to avoid destination-authority ambiguity in handle-context permission flows.
     - `SetDelete(FALSE)` now explicitly clears delete intent via the same file handle even when the target is currently delete-pending.
     - Mixed delete/rename semantic coverage now includes source delete-pending rename recovery, replace-vs-delete-pending target behavior, replace-vs-busy-target sharing violations, and cleanup-delete suppression when additional handles remain open.
     - Read-only callback consistency coverage now includes explicit `MEDIA_WRITE_PROTECTED` expectations for mutating callbacks (`Create`, `Rename`, `CanDelete`, `SetDelete`, `SetSecurity`) plus mutation-access denial coverage for `Open` in write-disabled mode.
     - Lifecycle coverage now includes cleanup/close ordering semantics: rename-blocking under cleanup-latched delete pending state, final removal on close for files/empty directories, and explicit preservation when close occurs without delete latch.
     - FsHost now serializes mutating callback execution (`Create/Write/SetFileSize/SetBasicInfo/Rename/CanDelete/SetDelete/Cleanup/Close/Flush`) with a dedicated per-volume mutation lock, preventing concurrent namespace/delete-intent interleaving races.
     - Semantics coverage now also includes delete-on-close removal only after last handle close, directory replace rejection for non-empty/open-handle targets, `Open(DELETE)` denial in read-only mode, and cleanup-delete no-op behavior in read-only mode.
     - FsHost shutdown now runs a bounded mutation-drain phase before dispatcher stop: new external mutating callbacks are fail-closed with `STATUS_VOLUME_DISMOUNTED`, and host waits for in-flight external mutation callbacks to drain before unmount progression.
     - Semantics coverage now also includes shutdown-drain rejection checks for `Create` and `Rename`, plus direct drain wait/timeout behavior checks for in-flight external mutation callbacks.
     - Semantics coverage now also includes concurrent same-path create stress (`Create` race determinism: one success + one collision, consistent node/children state) to validate callback serialization under thread contention.
     - FsHost now enforces canonical-commit requirement locally (`--write-require-canonical-commit`): native mutating callbacks require canonical readiness, and native commit flow uses `CommitCanonicalTransaction()` when required, surfacing `CommitModelNotCanonical` as an explicit recovery reason/action on mismatch.
     - Commit path now also persists an inode/path checkpoint block (`APFSRWINOD4`) so remount can recover committed inode table/path index without relying only on `%TEMP%` state files.
     - Commit path now persists btree mutation records to rotating checkpoint blocks (`APFSRWBTR5`) with checksum validation, so remount can restore committed btree state without relying only on `%TEMP%` state files.
    - Inode object-id allocation now uses a monotonic allocator and persistent-state format `v6` stores allocator high-watermark with checksum/trailing-byte validation so delete/recreate cycles do not reuse inode object ids after remount and tampered state is rejected.
     - Btree mutation records are now canonicalized (last-write-wins by key with tombstone compaction) before persistence, reducing unbounded append-only growth and making checkpoint state represent current logical keys.
     - Commit preflight now cross-validates projected canonical btree keys against working inode/directory/extent state, failing closed if metadata keyspace drifts from the in-memory mutation graph.
     - Mount-time `VerifyIntegrity()` now performs committed-btree semantic decode/validation (inode, directory-entry, and extent coherence against committed inode/object-map state) before native write readiness is granted.
     - Fault-injection coverage now includes persisted-btree-corruption remount behavior (no `%TEMP%` state fallback), asserting native write initialization fails closed when checkpoint btree semantics are invalid.
     - MetadataStore bootstrap/replay now emits explicit recovery reasons for load/integrity/replay commit-blob failures, and PrepareNativeWritePath marks fail-closed recovery state when integrity/bootstrap gates fail.
     - FsHost now propagates MetadataStore-specific recovery reasons through commit/runtime status, and FailClosed policy now degrades startup/replay bootstrap failures directly to read-only mode with explicit recovery actions.
     - Backend/service recovery-reason mapping now includes bootstrap/integrity/replay reason families with dedicated diagnostic/gate states and warning explanations.
     - Fault-injection replay matrix now validates both commit-blob corruption (`ReplayCommitBlobInvalid`) and crash-replay `FailClosed` skip behavior, ensuring commit path remains blocked until recovery policy allows replay.
     - Backend runtime telemetry parsing now treats explicit recovery reasons as safety signals (even if host flags are inconsistent), forcing conservative recovery-blocked state and fail-closed downgrade decisions for native write mounts.
     - Persistence tests now assert object-map/spaceman checkpoint blocks exist in APFS metadata blocks and match committed in-memory counts/xid.
     - Fault-injection coverage now includes `before-object-map-persist`, `before-spaceman-persist`, `before-inode-persist`, and `before-btree-persist` stages, asserting fail-closed recovery latching and blocked retry behavior.
     - Remount path now preserves disk-hydrated object-map/spaceman/inode/btree checkpoint state even when `%TEMP%\\ApfsAccess\\rw-state` file is absent, with explicit persistence-test coverage.
     - Metadata checkpoint persistence now uses rotating dual-slot placement for object-map/spaceman/inode/btree blocks, with deterministic FNV-based checksum headers and latest-valid-slot selection on remount.
     - Persistent state file format is now `v6` with checksum/trailing-byte validation and allocator high-watermark persistence, so remount bootstrap rejects tampered state before hydration while preserving deterministic object-id monotonicity.
     - Fault-injection replay coverage now includes persistent-state checksum-only tampering for `v6`, verifying checksum-invalid state is rejected and replay metadata fallback remains recoverable.
     - FsHost hydration cache is now session-scoped (cleaned on exit), and existing-file hydration fails closed when `readraw`/metadata fallback cannot provide bytes (no silent empty-file placeholder fallback).
     - FsHost `Create/Open` callbacks now honor WinFsp `GrantedAccess` for mutation-intent tracking and hydrated-file access mode selection, reducing false writable-handle behavior under native/overlay write modes.
     - FsHost now handles WinFsp `SetDelete` with tracked per-handle delete intent plus cleanup-latched delete-pending state, improving delete-on-close/open-blocking consistency.
     - FsHost rename handling now blocks directory self/descendant targets and requires loaded target-directory state before replace decisions, tightening Windows-compat rename safeguards.
     - FsHost rename now performs explicit source-subtree open-handle conflict checks (allowing only current-handle self-rename), improving concurrent rename/open safety.
     - Native persistence tests now clear per-context `%TEMP%\\ApfsAccess\\rw-state` files before/after runs to avoid stale-state contamination between CTest executions.
     - FsHost now normalizes `GrantedAccess` (including generic access bits) before deriving per-handle rights, and `Read`/`ReadDirectory` enforce those rights to avoid over-permissive I/O callbacks.
     - FsHost close-time finalize logic now preserves delete-on-cleanup intent through close bookkeeping, ensuring delete mutations still commit without requiring an explicit flush call.
     - MetadataStore mutation application is now fail-atomic per request: failed `ApplyMutation` paths roll back staged working-state changes (inode/path/link/free-extent/object-map/btree pending state) instead of leaving partial state drift.
     - Native write mutation path now rejects `Write` requests whose `offset + length` overflows `uint64`, with conformance-fault coverage asserting invalid-request status and zero pending-state drift.
     - MetadataStore rename staging now emits object-map updates for renamed descendant inodes in directory subtree moves, keeping object-map xid/projection aligned with renamed inode metadata.
     - Conformance coverage now includes directory-subtree rename object-map projection checks (renamed descendants retain object ids and receive the rename commit xid in object-map state).
     - Conformance-fault coverage now includes checkpoint-flush interruption remount sync behavior: when checkpoint and persistent state are already aligned on disk, remount no longer remains recovery-latched.
     - MetadataStore allocation/deallocation staging now enforces container-capacity bounds (`totalBlocks * blockSize`) for pending extents, preventing out-of-container synthetic image growth during write planning.
     - Conformance-fault coverage now includes oversized-write atomicity checks: allocation failure returns `AllocationFailed` without mutating pending staged state, and subsequent commits remain deterministic.
     - Extent allocation/free/deallocation staging now rejects non-block-aligned ranges and any extent that overlaps reserved APFS metadata blocks (superblocks, tracked metadata/object-map roots), preventing staged writes from targeting protected container metadata.
     - Persistence regression coverage now verifies `FreeExtent` rejects both reserved-superblock ranges and non-aligned physical offsets.
     - Native integrity validation now enforces file-extent allocation coverage consistency (`object-map`/btree inode extents must resolve to committed spaceman allocations sized for the logical extent).
     - Commit preflight now projects pending mutation deltas through canonical object-map/spaceman/volume-tree validators before persistence, fail-closing on any projected-state mismatch.
     - `ApfsVolumeTreeStore` now enforces semantic projection checks (inode/parent/name linkage and extent-to-inode consistency) instead of key-prefix-only validation.
     - Fault-injection coverage now includes object-map semantic corruption with checksum-preserving remount validation, asserting `PrepareNativeWritePath()` fails closed with `IntegrityCheckFailedOnMount`.
     - Replay fault matrix now includes explicit `ReplayIfSafe` stage interruption coverage for `replay-before-checkpoint-switch` and `replay-before-checkpoint-flush`, with fail-closed recovery reason assertions.
     - Backend runtime parsing/mapping tests now explicitly cover replay-stage failure reasons (`ReplayInterruptedBeforeCheckpointSwitch|ReplayCheckpointWriteFailed|ReplayInterruptedBeforeCheckpointFlush|ReplayCheckpointFlushFailed`) for diagnostic/gate/action normalization.
     - Native fault-injection now supports deterministic replay I/O failure simulation (`APFSACCESS_RW_FAULT_WRITE`, `APFSACCESS_RW_FAULT_FLUSH`) and coverage asserts fail-closed recovery reasons `ReplayCheckpointWriteFailed` and `ReplayCheckpointFlushFailed`.
     - Replay corruption coverage now includes semantic corruption of persisted object-map/spaceman state for replay-required volumes, asserting `ReplayOrRecover()` fails closed with `ReplayIntegrityCheckFailed` when mount-time integrity checks are deferred.
     - Remount bootstrap now fail-closes when metadata xid is ahead/behind the selected superblock even without `%TEMP%` persistent state files, and replay fault coverage now asserts `ReplayMetadataStateMissing` when recovery metadata is unavailable.
     - Commit path now persists replay metadata checkpoint blocks (`APFSRWRPL1`) with commit-blob address/size and xid window, allowing `ReplayOrRecover()` to proceed even when `%TEMP%\\ApfsAccess\\rw-state` files are missing.
     - Replay metadata checkpoint blocks are treated as reserved for extent overlap checks, preventing staged allocation from targeting replay metadata slots.
     - Load/replay reconciliation now prefers newer on-disk replay-checkpoint commit-blob metadata over stale `%TEMP%` persistent-state commit-blob fields when xid windows disagree, with dedicated fault coverage.
     - Corrupt/unreadable `%TEMP%` persistent-state payloads now quarantine to `*.corrupt` and fall back to disk/replay checkpoint state instead of hard-failing native write bootstrap.
     - Remount bootstrap can now rebuild committed inode/path/link state directly from persisted btree checkpoints when inode checkpoint blocks are unavailable/corrupt, preserving clean-path mount readiness without `%TEMP%` state.
     - Commit-blob format now includes payload checksum validation (`APFSRWSCAFF3`) during replay, with backward-compatible parsing for legacy `APFSRWSCAFF2` blobs and fail-closed handling on checksum mismatch.
     - Replay path now performs semantic commit-blob cross-checks against committed object-map/spaceman/btree state, rejecting checksum-valid but state-inconsistent blob tampering as `ReplayCommitBlobInvalid`.
     - Replay semantic validation now enforces internal pending-delta coherence (`object-map` updates vs decoded inode/extent btree records) before checkpoint switch, catching checksum-valid delta tampering early.
     - Replay semantic validation now enforces inode-tombstone and directory-tombstone triplet linkage (`parent|name|child`) and has checksum-preserving fault coverage for mismatched directory tombstone child-object tampering.
     - Replay header validation now enforces non-zero/sane commit-blob mutation-count bounds (against parsed object-map/spaceman/btree component counts) with checksum-valid header-tamper fault coverage.
     - Replay semantic validation now requires each commit-blob object-map update to have a corresponding raw inode mutation record, with checksum-preserving fault coverage for dropped trailing btree records.
     - Replay semantic validation now requires parsed inode records to remain directory-linked either within the replay blob or pre-existing committed directory links, with checksum-preserving fault coverage for dropped create-path directory-entry records.
     - Replay parser now rejects non-zero trailing commit-blob padding bytes beyond the parsed payload cursor, with checksum-unaffected padding-tamper fault coverage.
   - Replay parser now enforces btree key kind-prefix consistency (`key[0] == record.kind`) for every raw btree record, with checksum-preserving tombstone-key tamper fault coverage.
   - Replay semantic validation now rejects duplicate or overlapping spaceman extent entries within commit blobs (allocation/deallocation sets), and enforces exact deallocation-to-raw-extent-tombstone mapping; checksum-preserving coverage now includes duplicate-allocation, duplicate-deallocation, overlapping-allocation, overlapping-deallocation, allocation-vs-deallocation overlap, and shifted-deallocation-source tampering.
   - Replay header/path validation now performs payload-size feasibility checks (`object-map`, `spaceman`, `btree` minimum bytes) and catches reserve-allocation failures fail-closed before parsing; fault coverage includes checksum-valid btree-count overflow tampering to prevent replay-time memory blowups.
   - Commit-blob mode separation is now explicitly covered in conformance-fault tests: fixture contexts remain scaffold commit-blob mode, non-fixture contexts stay canonical-only mode, and non-fixture replay now fail-closes when fed fixture/scaffold replay metadata.
   - Commit-blob generation now transitions fixture mounts to canonical mode once canonical checkpoints hydrate cleanly on remount (`legacy_fixture_fallback_used=false`), while replay still accepts scaffold blobs only within explicit fixture-legacy contexts for backward compatibility.
   - Commit path now persists replay commit blobs as block-aligned, zero-padded payloads and records aligned commit-blob byte lengths in replay metadata, matching strict replay location validation (alignment/container-bound checks) and removing raw-size/alignment mismatch at commit time.
   - Native backend mount gating now enforces promotion-policy validation thresholds (`ScaffoldOnly -> CanonicalImageValidated`, `PilotHardware -> HardwarePilotValidated`, `Stable -> Stable`) before allowing native RW mounts, with explicit diagnostic/gate codes when validation evidence is insufficient.
   - Native backend validation evidence now promotes from observed runtime validation state (canonical/hardware/cross-OS/stable), persists to `NativeWriteEvidenceStorePath`, and is reused across remount/restart when enforcing promotion thresholds.
   - Runtime mount-state reconciliation now also enforces promotion thresholds (`ScaffoldOnly|PilotHardware|Stable`) and fail-closes mounted native RW sessions to read-only when validation evidence drops below the configured requirement.
   - Replay semantic validation now normalizes raw tombstone extent bytes to block-aligned allocation units before deallocation linkage checks, and persistent-state load now correctly hydrates committed free extents from versioned state files.
   - Conformance-fault coverage now expects canonical non-fixture interrupted-commit replay to recover successfully (clear recovery + restore commit-ready) instead of remaining permanently fail-closed in that path.
   - Runtime native-write reconciliation now fail-closes live RW mounts when host telemetry flips into fixture fallback or (for raw physical devices) scaffold commit-blob mode, with explicit recovery reasons/actions (`FixtureLegacyFallbackActive`, `ScaffoldCommitBlobActive`) and diagnostic gate mapping coverage.
   - Backend mount/runtime paths now enforce `WriteGatePolicy` directly (defense-in-depth): writable mounts fail closed when policy blocks (`WriteGateBlocked`), and live RW sessions downgrade to read-only if gate eligibility changes.
   - Validation evidence fail-closed reasons are now threshold-specific (`ValidationCrashFaultEvidenceInsufficient`, `ValidationHardwarePilotEvidenceInsufficient`, `ValidationCrossOsEvidenceInsufficient`, `ValidationPowerLossEvidenceInsufficient`, etc.), improving runtime diagnostics for pilot/stable promotion gating.
   - Validation-evidence promotion is now media-scoped: non-raw (fixture/image-backed) volumes are clamped to canonical-image evidence only, preventing fixture runs from accumulating hardware/stable promotion counters.
   - Raw-device pilot/stable promotion now enforces evidence freshness (`Service.NativeWriteValidationEvidenceMaxAgeDays`): stale evidence triggers fail-closed downgrade reasons (`ValidationHardwarePilotEvidenceStale` / `ValidationStableEvidenceStale`) until validation is refreshed.
   - Validation evidence persistence now maintains both per-volume and per-profile ledgers; raw physical pilot/stable gates evaluate against the profile ledger to avoid accidental promotion from volume-id-only fixture history.
   - Runtime status sidecar ingestion now accepts explicit validation evidence payload fields (`validationCrashFaultPasses`, `validationHardwarePilotPasses`, `validationMacOsValidationPasses`, `validationPowerLossPassVerified`, `validationLastValidatedUtc`) and merges them into persisted volume/profile evidence ledgers.
   - Evidence counter promotion is now session-scoped (keyed by FsHost session/status sidecar identity and host PID) so pilot/stable counters do not climb on every runtime poll tick within a single mount session.
   - Raw physical-device promotion now ignores host-seeded validation evidence by default (`NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices=false`); counters for physical pilot/stable gating must accrue from observed session-level native runtime validation.
   - Validation fail-closed diagnostics now emit threshold-aware evidence details (`current/required` crash/hardware/macOS/power-loss, staleness window, last-validated timestamp) in mount/runtime downgrade markers for pilot troubleshooting.
   - Service runtime compatibility warnings now surface the same threshold-aware evidence details for validation fail-closed states, so pilot triage is visible directly in tray/status telemetry.
   - Mount/runtime state contracts now emit structured native-write diagnostics (`NativeWriteDiagnostics[]`) with fail-closed code/reason/action and evidence snapshots, so tray/service consumers no longer need to parse warning strings for promotion/recovery triage.
   - Service options now expose evidence seed fields (`NativeWriteEvidenceSeed*`) and pass them to FsHost so controlled pilot runs can feed evidence telemetry without direct ledger file edits.
   - Persistent-state commit-blob metadata selection now requires full replay-candidate semantic validation (xid window/header/checksum/payload), not just aligned location bounds, before it can override replay-checkpoint metadata.
   - Remount replay now avoids trusting invalid persisted `last_commit_xid` when valid replay-checkpoint metadata exists, allowing deterministic replay fallback instead of poisoning recovery xid checks.
   - Fault-injection replay matrix now treats additional strict fail-closed replay rejection reasons (`ReplayXidWindowInvalid`, `ReplayIntegrityCheckFailed`) as valid commit-blob rejection outcomes where semantic corruption is detected before full replay application.
   - Service pre-gating now defers `Stable` crash/cross-OS promotion decisions to backend validation-evidence enforcement, avoiding early static blocks that bypass persisted evidence thresholds.
   - Object-map bootstrap strictness now requires canonical checkpoint state on non-fixture paths; volume-header heuristic acceptance is fixture-only and latches explicit legacy-fallback telemetry.
   - Native backend scaffold commit-blob fail-closed gating now treats scaffold mode as fixture-only (blocked on non-fixture media, not just raw physical devices), and raw-device detection now covers both `\\\\.\\PhysicalDrive*` and `\\\\?\\PhysicalDrive*` prefixes.
   - Backend validation-state derivation now clamps runtime-reported validation levels behind canonical eligibility (`commitModel=Canonical`, readiness `MutationReady|CommitReady`, and no recovery), preventing over-promotion from inconsistent runtime telemetry.
   - Runtime status parsing now also enforces recovery-safe telemetry for native mode: any active recovery forces `RecoveryBlocked` safety state and clamps reported validation state to canonical eligibility before backend policy evaluation.
   - FsHost mutating-callback denials in native mode now latch explicit fail-closed recovery telemetry (`NativeWriteUnavailable|CommitNotReady|CommitModelNotCanonical`) on first blocked mutation attempt, and native safety-state reporting now returns `ReadOnlyFallback` whenever mutation writes are unavailable (instead of implying pilot RW).
   - Backend validation-evidence promotion now accrues counters incrementally per observed validated runtime cycle (crash/hardware/macOS counters increase toward configured thresholds instead of jumping to threshold values in one sample), so pilot/stable promotion requires sustained validated evidence.
   - Backend runtime sidecar ingestion now has a lenient JSON fallback parser: string-encoded bool/integer telemetry is accepted, oversized integer counters are clamped instead of dropping the entire payload, and invalid counter tokens degrade field-local values without forcing full runtime-status fallback.
   - Service runtime compatibility warnings now surface shutdown-drain pressure telemetry: when any mount reports `shutdownDrainActive`, warnings include the affected mount points and aggregated in-flight mutation callback count.
   - Backend runtime reconciliation now enforces strict non-fixture canonical safety signals (`ScaffoldCommitBlobActive`, fixture-compat path activity, canonical proof gaps, replay-window safety signals) regardless of `BestEffort` recovery policy so production RW eligibility cannot be relaxed by recovery-mode tuning.
   - Validation evidence promotion now also suppresses counter accrual for non-fixture native sessions whenever strict canonical safety proof is missing (fixture/scaffold telemetry active, canonical proof missing, or replay-window inconsistency), preventing pilot/stable promotion drift from unsafe runtime telemetry.
   - Service runtime compatibility warning ordering now uses effective recovery reasons (mount-level reason with diagnostic fallback), so canonical diagnostic blockers still surface ahead of generic reasons across multi-volume status even when `MountedVolumeState.RecoveryReason` is missing.
   - Service prioritization coverage now includes a multi-volume diagnostic-fallback ordering regression test (`BuildRuntimeCompatibilityWarnings_OrdersByDiagnosticFallbackRecoveryReason`) to keep warning ordering aligned with backend fail-closed reason precedence.
   - Service write-telemetry `LastRecoveryAction` fallback now resolves by prioritized effective recovery reasons (including diagnostic-derived reasons/actions), so primary action selection remains aligned with canonical fail-closed reason precedence even when mount-level `LastRecoveryAction` is absent.
   - Service prioritization coverage now includes `ResolveWriteTelemetry_FallsBackToDiagnosticActionFromPrioritizedRecoveryMount` to lock cross-mount diagnostic action fallback behavior.
   - Backend canonical-validation eligibility now requires native runtime readiness `CommitReady` (not `MutationReady`) before deriving `CanonicalImageValidated` fallback state for evidence/promotion flows, preventing premature validation promotion before canonical commit readiness is proven.
   - Backend parsing coverage now includes explicit `MutationReady` canonical-path cases in `ResolveObservedValidationStateForEvidence_DerivesExpectedState` to keep this stricter promotion gate stable.
   - Backend fail-closed precedence now always honors explicit non-fixture `canonicalGateFailure` runtime telemetry ahead of generic recovery markers, even when canonical replay-candidate toggle flags are relaxed, so canonical gate diagnostics remain specific and cannot be masked by `RecoveryRequired`.
   - Backend parsing coverage now includes a non-fixture relaxed-toggle regression (`GetFailClosedReasonForRuntimeStatus_UsesCanonicalGateFailure_OnNonFixtureEvenWhenCanonicalReplayToggleDisabled`) to lock canonical gate reason precedence.
   - Native RW engine canonical gate telemetry now surfaces the active recovery reason when recovery is latched (instead of collapsing to generic `RecoveryRequired`) so FsHost sidecar and backend fail-closed mapping receive specific canonical gate failure context during recovery.
   - Native conformance-fault coverage now asserts `LastCanonicalGateFailure()` mirrors checkpoint-write and remount recovery reasons in `TruncateCheckpointFault`.
   - FsHost status emission now derives `canonicalGateFailure` from canonical gate-class recovery reasons when metadata-store canonical gate fields are empty, so runtime downgrade paths still expose explicit canonical blockers in sidecar telemetry.
   - FsHost status emission now preserves canonical gate proof telemetry (`canonicalGateFailure`, `canonicalPathActive=false`) even after native write backend is fail-closed to `Disabled`, preventing sidecar ambiguity during post-downgrade reconciliation.
   - Backend runtime-status parsing now mirrors that behavior by deriving `CanonicalGateFailure` from canonical gate-class `RecoveryReason` when payload `canonicalGateFailure` is omitted, preserving non-fixture fail-closed specificity across FsHost-to-backend hops.
   - Backend runtime-status parsing now also derives `canonicalPathActive=false` whenever a canonical gate failure is present but `canonicalPathActive` payload telemetry is missing, keeping canonical proof-state diagnostics deterministic.
   - Managed runtime/parsing coverage now includes regressions for canonical-gate derivation from recovery reason when explicit `canonicalGateFailure` payload telemetry is missing.
   - Backend non-fixture runtime fail-closed now always requires explicit canonical path proof (`canonicalPathActive=true`) even when relaxed replay-candidate toggles are disabled; fixture/debug toggles no longer bypass production canonical-path proof gating.
    - Validation-evidence promotion blocking now applies the same unconditional non-fixture canonical-path proof requirement, preventing evidence accrual when canonical proof is missing even under relaxed debug toggle combinations.
    - FsHost canonical mutation gate now fail-closes to canonical-required for all non-fixture/unknown media regardless relaxed toggle flags; only explicit fixture paths can relax canonical gating in controlled test contexts.
    - FsHost startup now applies non-fixture canonical safety overrides before mount lifecycle begins, so manual/CLI relaxed flags cannot accidentally disable canonical-only enforcement on production media.
    - FsHost semantics coverage now includes a regression proving post-downgrade sidecar JSON still emits canonical gate failure fields when recovery reason is canonical.
    - Canonical non-fixture disk-fallback recovery latching now distinguishes sidecar-present and sidecar-missing states: pending replay windows still win (`ReplayCheckpointPendingWindow`), while sidecar-missing ahead-of-superblock xid drift now fail-closes as `PersistentStateAheadOfSuperblock` before replay evaluation.
    - Native fault/conformance suites are green again after this fallback refinement (`scripts/build_rw_engine.ps1 -Configuration Release -RunTests`), including scaffold/non-fixture replay rejection and sidecar-missing canonical fail-closed scenarios.
    - Native backend volume parsing now normalizes APFS role tokens (`role=...`, `role = ...`, `role ...`) and trims trailing role annotations consistently, preventing false volume drops from `apfsutil` formatting variance.
    - Write-unsupported feature detection now classifies `role=system` as `SealedSystemVolume` and keeps `role=data` volumes discoverable for native write eligibility evaluation; parsing coverage includes explicit `role = system` and `role = data` regressions.
    - FsHost `CB_Flush` shutdown-drain gating now uses an in-place optional external mutation scope (no temporary-scope assignment), preventing double-release/underflow risk in active mutation callback accounting during successful write-enabled flushes.
    - FsHost semantics coverage now includes shutdown-drain flush behavior and successful write-enabled flush scope-release regressions, locking callback accounting and flush availability semantics across read-only/write-enabled modes.
    - FsHost status sidecar now preserves explicit non-canonical compatibility fail-closed signals (`fixtureLegacyFallbackActive`, `fixtureCompatibilityPathActive`, `usesScaffoldCommitBlob`) even after native runtime downgrades `writeBackend` to `Disabled`.
    - Backend runtime-status parsing now derives those compatibility flags from canonicalized recovery reasons when payload booleans are missing, keeping fail-closed diagnostics deterministic for downgraded/partial sidecar payloads.
    - RW engine fixture detection now only uses explicit file/image naming (suffix/extension) and no longer infers fixture mode from parent-directory segment names (for example `\\fixtures\\...`), preventing accidental production fallback relaxation from incidental path structure.
    - Conformance-fault coverage now asserts that `.bin` media under fixture-named parent directories still behave as non-fixture and reject legacy scaffold object-map fallback (`CanonicalCheckpointRequiredNonFixtureSegment`).
    - Managed backend fixture detection is now aligned with RW-engine semantics: it no longer infers fixture mode from parent-directory names and now requires explicit image naming for fixture classification, so non-fixture safety gating cannot be relaxed by incidental `fixtures/synthetic` folder paths.
    - Backend parsing coverage now includes those stricter fixture-classification expectations for `*.bin` paths under fixture/synthetic directory names.
    - FsHost canonical gate fixture detection is now aligned with engine/backend semantics and no longer infers fixture mode from parent-directory names; only explicit fixture/image naming patterns can relax canonical mutation gating.
    - FsHost semantics coverage now includes regressions proving that `C:\\fixtures\\sample.bin` remains non-fixture for canonical gate and non-fixture safety override enforcement.
    - External pilot operator automation now exists in-repo: `Build_APFS_Access_Beta.bat`, `Run_APFS_Pilot_Validation.bat`, `scripts/build_beta_pilot.ps1`, and `scripts/run_pilot_validation.ps1`.
    - Publish output now ships the pilot launcher plus the helper scripts it depends on (`configure_native_ce.ps1`, `install_prereqs.ps1`, promotion/evidence scripts), so the click-run bundle can be handed to non-technical pilot users without manual script copying.
    - The Windows pilot launcher now auto-discovers APFS raw drives, rewrites click-run pilot config, seeds a temporary session-local pilot-only evidence ledger for sacrificial-drive smoke testing, waits for mount status, runs the admitted v1 mutation smoke surface, restarts/remounts, and zips a feedback bundle with config snapshots, diagnostics, and a structured validation report.
    - Assumption/risk remains unchanged: this automation is only a Windows-side smoke/bootstrap aid and intentionally does not manufacture real crash/hot-unplug/power-loss/macOS evidence.
  2. External physical-device reliability and cross-OS evidence remain incomplete; the admitted v1 native mutation surface now has durable metadata parity, but promotion still depends on real hardware/macOS validation.

## Remaining milestone

1. M6 external pilot evidence closure (`hot-unplug`, crash/power-loss replay, macOS mount/read/integrity import, promotion evaluation) on a real allow-listed raw APFS device.
   - Automation support added on `2026-03-06`: `Build_APFS_Access_Beta.bat`, `Run_APFS_Pilot_Validation.bat`, `scripts/build_beta_pilot.ps1`, and `scripts/run_pilot_validation.ps1` now provide one-click beta publish plus one-click Windows smoke/remount validation with a zipped feedback bundle. The launcher auto-discovers APFS raw drives, rewrites click-run pilot config, seeds a temporary session-local pilot-only evidence ledger so a fresh raw profile can enter a writable smoke run, captures status/diagnostics, and emits a structured validation report. Real crash/hot-unplug/power-loss/macOS evidence remains the only manual boundary.
