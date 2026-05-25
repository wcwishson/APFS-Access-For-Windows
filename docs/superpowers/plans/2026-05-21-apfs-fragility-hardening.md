# APFS Fragility Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Find and close the highest-risk correctness gaps that could corrupt bytes, show stale drive state, silently degrade to read-only, or behave differently from normal Explorer workflows.

**Architecture:** Treat this as a robustness pass, not a speed pass. Add integrity oracles first, then fix the riskiest code paths with small checkpoints so each fix can be reverted independently if user-facing behavior regresses.

**Tech Stack:** WinFsp FsHost C++ callbacks, APFS RW engine C++, .NET tray/service/backend lifecycle, PowerShell physical validation harnesses, SHA-256 file integrity checks.

---

## Current Status As Of 2026-05-22

**Branch:** `optimize/read-write-performance`

**Implementation state:** All planned hardening tasks have been implemented as checkpoint commits. The remaining work is validation and promotion, not new plan execution.

**Completed checkpoints:**

- [x] Task 1: Add user-facing Explorer/SHA-256 integrity validation harness. Commit: `e5fbe0a Add Explorer workflow integrity validation`
- [x] Task 2: Enforce copy-on-write for committed file writes. Commit: `28b28a1 Harden APFS file writes with copy-on-write extents`
- [x] Task 3: Fix rename-replace and local rollback on commit failure. Commit: `fa21fea Harden FsHost rename and mutation rollback`
- [x] Task 4: Remove full-file hydration as required read path. Commit: `d7e3aa0 Stream committed file reads without full hydration`
- [x] Task 5: Strengthen fragmented-extent accounting. Commit: `47f31ac Validate fragmented APFS extent accounting`
- [x] Task 6: Add torn-write and power-loss fault injection. Commit: `2cfaa41 Add torn-write recovery fault coverage`
- [x] Task 7: Stabilize mount, eject, and read-only fallback lifecycle. Commit: `b57cfd9 Harden APFS mount and eject lifecycle`
- [x] Task 8: Unify recovery reason priority and user messages. Commit: `c6d38a1 Unify native recovery diagnostics`
- [x] Task 9: Add named-stream, Office, recycle-bin, and path edge matrices. Commit: `3710f55 Expand Explorer workflow edge coverage`

**Latest delta from Task 9:**

- Missing read-only alternate data stream probes such as `:Zone.Identifier`, `:LH.Identifier`, and `:AFP_AfpInfo` now fail cleanly with not-found semantics instead of surfacing as device failures.
- Duplicate-case alternate data streams now coalesce to one stream metadata entry.
- Office-style lock-file and temp-save rename-replace workflows have focused FsHost semantics coverage.
- Recycle-bin `$I` metadata and `$R` payload pair workflows have focused FsHost semantics coverage.
- Risky Win32 path components are rejected before mutation, including reserved device names, invalid characters, trailing dot/space names, and over-255-character components.
- The physical Explorer workflow script is pinned by tests so SHA-256 format fixtures, recycle phases, many-small-file coverage, long-name coverage, and large-file roundtrips cannot be accidentally removed.

**Verification already run for the latest checkpoint:**

- Built `ApfsAccess.FsHost.SemanticsTests` with CMake in `C:\apfsaccess_native\build-fixed22\Release`.
- Ran focused FsHost incremental plus new edge tests:
  `recycle-bin-attributes volume-acl-flag stable-volume-serial named-stream-copy-compatibility named-stream-hidden-metadata legacy-named-stream-artifacts-hidden flush-finalizes-pending-journal metadata-read-open-no-hydration writable-sparse-hydration missing-named-stream-clean-failure duplicate-case-named-streams office-temp-rename-replace-workflow recycle-bin-metadata-pair-workflow path-normalization-edge-matrix`
- Ran focused service script tests:
  `PhysicalRwValidation_IncludesExplorerWorkflowIntegrityMode`, `PhysicalRwValidation_ScriptParses`, and `PhysicalRwValidation_CaseOnlyRenameUsesCaseSensitiveEntryCheck`.
- Ran `git diff --check`.
- 2026-05-22 validation pass after recursive directory delete hardening:
  - Clean native Release build: `pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release`.
  - Focused recursive-delete/recycle/volume FsHost semantics cluster passed.
  - Clean portable publish: `pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64`; root `APFSAccess_Portable.exe` overwritten.
  - Full native Release CTest at `C:\apfsaccess_native\build\Release`: 7/7 passed.
  - Full APFS RW engine Release CTest: 6/6 passed, including conformance, conformance fault, fault injection, persistence, canonical store, and transaction lifecycle tests.
  - Full .NET Release solution tests: 392/392 passed.
  - Physical `Smoke` validation on mounted `E:\` passed, including recursive directory delete and post-status RW/healthy.
  - Physical `ExplorerWorkflow` validation on mounted `E:\` passed with SHA-256 checks for format-like fixtures, rename/move/cut-paste, direct delete, recycle-style delete/restore, many-small-file sweep, long-name path, and a 64 MiB large-file roundtrip. Report: `artifacts\physical-rw-validation\physical-rw-explorerworkflow-20260522-194514.json`.
  - Focused script regression after manifest-path reporting fix: 7/7 `PhysicalRwValidation` service tests passed.
  - Physical `Smoke` validation after manifest-path reporting fix passed. Report: `artifacts\physical-rw-validation\physical-rw-smoke-20260522-194814.json`.
  - Real service/tray-pipe eject path validated by sending `EjectRequested` for `\\.\PhysicalDrive2|Main`: ACK succeeded with `APFS drive E: (Main) was safely ejected.`, `E:\` disappeared, `RefreshRequested(clearUserEjectedVolumes=true)` remounted it, and new host PID `57420` reported Native/PilotReadWrite/recovery inactive/dirty count zero.
  - Physical `Smoke` validation after service eject/remount passed against host PID `57420`. Report: `artifacts\physical-rw-validation\physical-rw-smoke-20260522-195307.json`.

**Remaining validation gates before promotion:**

- [x] Run full FsHost semantics suite.
- [x] Run APFS RW engine conformance tests.
- [x] Run APFS RW engine fault-injection tests.
- [x] Run relevant .NET backend, service, tray, and core tests.
- [x] Build the updated portable app artifact.
- [x] Run physical Explorer-style validation on the real APFS drive with SHA-256:
  create, copy in, rename, move within drive, cut/paste out, copy back, direct delete, recycle delete/restore, large-file roundtrip, and many-small-file sweep.
- [x] Run non-manual eject/remount lifecycle validation:
  service/tray-pipe eject removes `E:\`, refresh remounts the still-connected drive, and remounted host status is RW/healthy.
- [ ] Run disruptive physical lifecycle validation when the user is ready:
  unplug/replug, launch-before-plug, and plug-before-launch.
- [ ] Confirm remaining disruptive hard user-facing gates:
  no stale drive letter after physical unplug and expected automount behavior across app/drive launch order.
- [x] Confirm non-disruptive hard user-facing gates:
  no recycle-bin corruption warning in physical workflow, no stale drive letter after service eject, no unexpected read-only fallback after ordinary file operations, host status healthy, recovery inactive, and dirty transaction count zero.

---

## Why SHA-256 Belongs In The Test Plan

SHA-256 before/after comparison is one of the best practical tests for this app because APFS Access is ultimately moving bytes through a filesystem boundary. File formats like PNG, DOCX, XLSX, PDF, ZIP, and EXE do not need separate content logic in the filesystem layer; if their SHA-256 hashes match after copy, move, remount, and copy-back, the file bytes survived exactly.

MD5 is acceptable for quick accidental-corruption smoke checks, but SHA-256 should be the default because PowerShell supports it with `Get-FileHash -Algorithm SHA256` and it is stronger. Format-specific app testing still matters for workflows: Office temp files, alternate data streams, timestamps, hidden/system attributes, rename-over-original behavior, and recycle-bin behavior.

## Risk Map

**Critical / High**

- Same-size or partial overwrite may violate crash atomicity if old metadata still points to newly overwritten bytes.
- Rename-replace over an open target may desync namespace state from hydration/cache bytes.
- Native commit failures can happen after FsHost has already changed in-memory state.
- Large or sparse files can force full-file hydration into memory.
- RW fail-closed fallback, unmount failure, or startup cancellation can leave stale drive letters or orphan FsHost processes.

**Medium**

- Fragmented imported APFS files may not free all original extents on overwrite/delete/truncate.
- Power-loss simulation covers logical stages better than short/torn block writes.
- Named-stream support has missing-stream and old-WinFsp edge cases.
- Transient probe failures can look like physical removal.
- Tray/service recovery-reason priorities can drift.
- Office-style metadata and temp-file workflows need workflow-level coverage.

**Lower But Important**

- Unicode/case/long-path normalization is under-tested.
- Recycle Bin currently has attribute coverage, but needs full workflow coverage.
- User-facing error text can still be too developer-heavy.

---

### Task 1: Add A User-Facing Integrity Validation Harness

**Risk Level:** Low implementation risk, high confidence gain.

**Files:**
- Modify: `scripts/run_physical_rw_validation.ps1`
- Modify: `tests/ApfsAccess.Service.Tests/PilotScriptTests.cs`
- Optional create: `scripts/run_explorer_workflow_validation.ps1`

- [ ] **Step 1: Add an Explorer-style workflow mode**

Add a mode that performs the operations users actually do:

- Create folder.
- Copy file into APFS.
- Rename file.
- Move file within APFS.
- Cut/paste out of APFS to NTFS.
- Move/copy back into APFS.
- Delete direct.
- Delete through recycle-bin folder shape.
- Remount or refresh status.
- Copy back out and verify SHA-256.

Use at least these data shapes:

- zero-byte file
- 1 byte
- 4095, 4096, 4097 bytes
- 64 KiB
- 8 MiB
- one large file, default 256 MiB or user-configurable
- nested folder with many small files
- names with spaces, Chinese characters, emoji, long names, and case-only rename pairs
- at least one `.exe`, `.docx`, `.xlsx`, `.png`, `.zip`

- [ ] **Step 2: Make SHA-256 the oracle**

For every content-preserving operation, record:

- source path
- destination path
- size
- SHA-256 before
- SHA-256 after
- operation wall-clock time
- host status JSON before and after

Expected: every copy/move/remount/copy-back content hash matches. Delete tests should verify absence and no unexpected recovery/degraded state.

- [ ] **Step 3: Fail on bad user-facing status**

Fail the harness if any operation leaves:

- `recoveryActive=true`
- `nativeWriteSafetyState=RecoveryBlocked`
- dirty transaction count nonzero after flush/settle
- Explorer-visible drive still present after an asserted eject
- unexpected read-only fallback during a write workflow

- [ ] **Step 4: Keep the current faster incremental tests**

Preserve fast checks:

```powershell
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-attributes volume-acl-flag stable-volume-serial named-stream-copy-compatibility named-stream-hidden-metadata legacy-named-stream-artifacts-hidden flush-finalizes-pending-journal
```

Expected: selected FsHost semantics tests pass.

- [ ] **Step 5: Add script coverage assertions**

Extend `PilotScriptTests` to assert the script still contains the new SHA-256 workflow phases, so future refactors do not accidentally remove the integrity gate.

---

### Task 2: Enforce Copy-On-Write For All Committed File Writes

**Risk Level:** High impact, medium implementation risk.

**Files:**
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Test: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`
- Test: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`

- [ ] **Step 1: Write the failing crash-atomicity test**

Scenario:

1. Create file with payload A.
2. Commit and record SHA-256 A.
3. Overwrite same logical size with payload B.
4. Inject interruption at `before-checkpoint-switch`.
5. Remount/reload.
6. Assert file reads payload A, or mount fails closed with a precise recovery reason.

Expected before fix: current implementation may expose payload B through old metadata.

- [ ] **Step 2: Change write staging to allocate fresh extents**

For every `MutationOperation::Write` that changes file content, allocate a new physical extent and write the complete projected payload there. Do not overwrite existing committed file extents in place, including same-size and partial overwrites.

- [ ] **Step 3: Keep old extents live until checkpoint promotion**

Only stage deallocation of old extents as part of the same committed transaction. The previous checkpoint must remain readable until the superblock/checkpoint switch is durable.

- [ ] **Step 4: Add remount/replay tests**

Test same-size overwrite, partial middle overwrite, append, truncate, and grow after interruption at:

- before payload write
- after payload write, before commit blob
- before replay checkpoint
- before checkpoint switch
- before checkpoint flush

Expected: old file survives or recovery blocks writes; no mixed old/new payload.

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Harden APFS file writes with copy-on-write extents
```

---

### Task 3: Fix Rename-Replace And Commit-Failure State Rollback

**Risk Level:** High.

**Files:**
- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Test: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`

- [ ] **Step 1: Add rename-replace open-target tests**

Scenario:

1. Create `source.bin` with bytes A.
2. Create `target.bin` with bytes B.
3. Keep `target.bin` open through a read handle.
4. Attempt rename-replace from `source.bin` to `target.bin`.
5. Verify returned status, visible namespace, bytes read through old handle, bytes read from new `target.bin`, and no orphan hydration file.

Expected: either deterministic sharing violation before mutation, or a fully coherent replace.

- [ ] **Step 2: Make replacement removal result authoritative**

In `CB_Rename`, if replacing an existing node, treat failed recursive removal as a hard failure before reindexing the source. Do not ignore the return value.

- [ ] **Step 3: Add commit-failure fault tests**

Inject native commit failure after local state mutation for:

- rename
- resize/truncate
- delete-on-close

Expected: local state rolls back, or mount transitions to degraded/recovery-blocked and stops claiming the operation is cleanly durable.

- [ ] **Step 4: Add local-state rollback helpers**

For operations that mutate namespace or size before durable commit, snapshot the minimum local state needed to undo:

- source and destination node paths
- parent child sets
- file size/timestamp
- delete flags
- named stream size entries

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Harden FsHost rename and mutation rollback
```

---

### Task 4: Remove Full-File Hydration As A Required Read Path

**Risk Level:** High impact, medium-to-high implementation risk.

**Files:**
- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Test: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
- Test: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`

- [ ] **Step 1: Add large/sparse tests**

Use synthetic metadata/read extents to represent:

- 4 GiB plus 1 byte logical file
- sparse file with 1 byte at 1 TiB
- fragmented file with multiple extents

Expected: opening and reading small ranges does not allocate a vector equal to logical file size.

- [ ] **Step 2: Route read-only `CB_Read` through range reads**

For committed files that do not have a local writable hydration file, call `ReadCommittedFileRange(path, offset, length)` directly. Only hydrate to a local cache when a write handle requires it.

- [ ] **Step 3: Use chunked hydration for writable opens**

When a write handle requires a mutable cache file, stream content from metadata to the cache in fixed-size chunks instead of building a full payload vector.

- [ ] **Step 4: Add hard caps and clear errors**

If a workflow requires a full local cache and the file is too large for safe hydration, fail with a clear status and user-facing diagnostic rather than running out of memory or degrading mysteriously.

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Stream committed file reads without full hydration
```

---

### Task 5: Strengthen Fragmented-Extent Accounting

**Risk Level:** Medium-high.

**Files:**
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Test: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`

- [ ] **Step 1: Add fragmented-file mutation tests**

Create or simulate a file with multiple committed read extents and `data_physical_address == 0`. Then test:

- overwrite
- truncate
- delete
- rename
- remount

Expected: no old extent remains allocated after committed delete/overwrite/truncate; no live file references freed space.

- [ ] **Step 2: Track extent sets per file**

When staging a mutation for a fragmented file, operate on the full extent list from `committed_read_extents_`, not only `data_physical_address`.

- [ ] **Step 3: Validate allocation ledger after every mutation**

Extend `ValidatePendingCommitState` to assert every old extent is either:

- still referenced by the previous checkpoint,
- explicitly deallocated only after the new checkpoint is committed,
- or still referenced by another live clone/snapshot-safe owner.

For v1, if clone/snapshot ownership cannot be proven, block write promotion for that file.

- [ ] **Step 4: Commit checkpoint**

Commit message:

```text
Validate fragmented APFS extent accounting
```

---

### Task 6: Add Torn-Write And Power-Loss Fault Injection

**Risk Level:** Medium-high.

**Files:**
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/BlockDevice.h`
- Test: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`

- [ ] **Step 1: Add short-write injection hooks**

Support test-only failures where `BlockDevice::Write` writes:

- zero bytes
- first sector only
- all except last sector
- first half of buffer
- corrupted one-byte write

- [ ] **Step 2: Cover every durable write class**

Inject torn writes for:

- file payload extent
- commit blob
- object map checkpoint
- spaceman checkpoint
- inode checkpoint
- btree checkpoint
- replay checkpoint
- superblock checkpoint XID switch

- [ ] **Step 3: Remount after each injection**

Expected: remount selects the last coherent checkpoint, or reports recovery required with a precise reason. It must not mount writable with mixed metadata.

- [ ] **Step 4: Commit checkpoint**

Commit message:

```text
Add torn-write recovery fault coverage
```

---

### Task 7: Stabilize Mount, Eject, And RO Fallback Lifecycle

**Risk Level:** High user-facing reliability impact.

**Files:**
- Modify: `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs`
- Modify: `src/ApfsAccess.Service/ApfsMountWorker.cs`
- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`
- Test: `tests/ApfsAccess.Backend.Native.Tests/NativeApfsBackendRuntimeStatusTests.cs`
- Test: `tests/ApfsAccess.Service.Tests/ApfsMountWorkerAutoMountTests.cs`
- Test: `tests/ApfsAccess.Tray.Tests/TrayApplicationContextPrioritizationTests.cs`

- [ ] **Step 1: Test stale drive visibility during RW-to-RO fallback**

Fake a RW host that exposes a drive, reports fail-closed, exits slowly, and leaves stale visibility for a short window. Assert RO fallback waits for the old mount to disappear before treating the fallback as successful.

- [ ] **Step 2: Keep cleanup state after failed unmount**

If host exit succeeds but the drive letter remains visible, preserve enough host/mount state to retry cleanup. Mark the mount stale in status rather than making future ejection impossible.

- [ ] **Step 3: Stop orphan hosts on startup exceptions**

Register host lifetime immediately after process start, or use a `try/finally` guard that stops the child if status read, validation, cancellation, or marker write fails before `_hosts[mountPoint]` is assigned.

- [ ] **Step 4: Debounce transient probe misses**

Require at least two consecutive missing-device cycles before unmounting a previously mounted APFS volume, unless Windows explicitly reports device removal.

- [ ] **Step 5: Clear stale tray eject UI on disconnect**

When the service pipe disconnects, disable eject menu entries and show no mounted drives until a fresh status payload arrives.

- [ ] **Step 6: Commit checkpoint**

Commit message:

```text
Harden APFS mount and eject lifecycle
```

---

### Task 8: Unify Recovery Reason Priority And User Messages

**Risk Level:** Medium.

**Files:**
- Create or modify: `src/ApfsAccess.Core/NativeWriteRecoveryReasons.cs`
- Modify: `src/ApfsAccess.Service/ApfsMountWorker.cs`
- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`
- Modify: `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs`
- Test: `tests/ApfsAccess.Core.Tests`
- Test: `tests/ApfsAccess.Service.Tests/ApfsMountWorkerPrioritizationTests.cs`
- Test: `tests/ApfsAccess.Tray.Tests/TrayApplicationContextPrioritizationTests.cs`

- [ ] **Step 1: Move reason normalization into Core**

Create one shared table for:

- canonical gate reasons
- replay reasons
- mutation staging failures
- generic `RecoveryRequired`
- fixture/scaffold fallback reasons

- [ ] **Step 2: Use the shared priority in backend, service, and tray**

Expected: tray tooltip, service published status, and backend diagnostics select the same primary reason for the same payload.

- [ ] **Step 3: Split user text from diagnostic code**

Keep exact diagnostic codes, but show simpler user text:

- "APFS write mode paused to protect the drive."
- "APFS mount component is missing or not installed."
- "The drive is still busy; close Explorer windows or files and try eject again."

- [ ] **Step 4: Fix fallback wording**

Only say "falling back to read-only" when service mode will actually attempt read-only fallback. In strict RW mode, say "write mount was blocked."

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Unify native recovery diagnostics
```

---

### Task 9: Add Named-Stream, Office, Recycle Bin, And Path Edge Matrices

**Risk Level:** Medium.

**Files:**
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
- Modify: `scripts/run_physical_rw_validation.ps1`
- Optional modify: `src-native/ApfsAccess.FsHost/src/main.cpp`

- [ ] **Step 1: Named stream matrix**

Test:

- missing `:Zone.Identifier`
- missing `:LH.Identifier`
- missing `:AFP_AfpInfo`
- duplicate-case streams
- read-only open of missing ADS
- old-WinFsp path where `FspFileSystemAddStreamInfo` is unavailable

Expected: missing ADS does not read base file bytes; streams are hidden from normal directory enumeration.

- [ ] **Step 2: Office workflow matrix**

Test:

- Word/Excel-style `~$` lock file creation/deletion
- temp file write then rename-over-original
- hidden/temp/archive attributes
- reopen after save
- SHA-256 of saved content

Expected: no write-protected fallback, no visible ADS artifacts, no recycle-bin warning.

- [ ] **Step 3: Recycle workflow matrix**

Test:

- create `$RECYCLE.BIN\<SID>`
- create `$I` metadata and `$R` payload pair
- delete-to-recycle
- restore by rename
- empty recycle folder
- direct permanent delete

Expected: no corrupted recycle-bin warning and no stuck delete-pending nodes.

- [ ] **Step 4: Path normalization matrix**

Test:

- composed/decomposed Unicode
- Chinese names
- emoji/surrogates
- Turkish dotted/dotless I
- 255-character component
- deep path near Windows long-path limit
- case-only rename
- trailing dot and space through Win32-normalized callers
- reserved names such as `CON`, `AUX`, `NUL`

Expected: either correct behavior or deterministic rejection before mutation.

- [ ] **Step 5: Commit checkpoint**

Commit message:

```text
Expand Explorer workflow edge coverage
```

---

## Validation Gates Before Merging Robustness Work

- Focused FsHost semantics tests pass.
- Focused native backend/tray/service tests pass.
- APFS RW engine fault-injection tests pass.
- Physical Explorer-style workflow with SHA-256 passes on the real APFS USB drive.
- Manual user smoke passes: create, copy in, rename, move within drive, cut/paste out, copy back, delete, recycle delete, eject, unplug/replug, launch-before-plug and plug-before-launch.
- No recycle-bin warning.
- No stale drive letter after eject or unplug.
- No unexpected RO fallback after ordinary file operations.
- Host status ends healthy: native backend, commit ready, recovery inactive, dirty transaction count zero.

## Recommended Execution Order

1. Task 1: add the integrity/user-workflow harness.
2. Task 2: copy-on-write for all writes.
3. Task 3: rename/rollback consistency.
4. Task 7: stale mount/eject lifecycle.
5. Task 4: large-file streaming.
6. Task 5: fragmented extents.
7. Task 6: torn-write injection.
8. Task 8: shared recovery reasons.
9. Task 9: edge-case workflow matrix.

This order gives the app a stronger test net before changing the riskiest write paths, then closes the data-integrity issues before polishing user messaging and lower-level edge coverage.
