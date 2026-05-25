# APFS Performance Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve APFS Access read/write throughput, many-small-file performance, and UI/service responsiveness without weakening the current read/write safety and recovery model.

**Architecture:** Measure first, then optimize the hottest synchronous paths in small reversible checkpoints. Start with low-risk telemetry and benchmark work, then reduce allocation/scanning overhead, then refactor metadata mutation staging and raw block I/O only after benchmarks prove the earlier passes are not enough.

**Tech Stack:** WinFsp FsHost C++, APFS RW engine C++, Windows raw device I/O, .NET service/backend/tray, PowerShell physical validation and benchmark harnesses, SHA-256 integrity checks.

---

## Current Status As Of 2026-05-25

**Branch:** `optimize/read-write-performance`

**Scope:** Planning only. No performance implementation has been done in this pass.

**User-facing symptoms to target:**

- Copy/move operations can take noticeable time to start.
- Many small files are much slower than their total byte size suggests.
- Large-file throughput is better than small-file throughput, but still should move closer to the practical USB 3.0 ceiling for the actual flash drive.
- The tray/dashboard/service should stay responsive while the filesystem host is doing real work.

**Hard gates that must not regress:**

- No recycle-bin corruption warning.
- No unexpected read-only fallback during ordinary write workflows.
- No write-protected Explorer fallback while native RW is healthy.
- Eject still removes the mounted drive letter.
- Fix/refresh still remounts or gives practical user guidance.
- SHA-256 integrity passes for copy/move/copy-back workflows.
- Recovery stays fail-closed when the native write path is genuinely unsafe.

---

## Assumptions And Tradeoffs

- "USB 3.0 speed" means "close to the practical speed of this flash drive and Windows stack," not the 5 Gbps theoretical bus number.
- We should compare APFS Access to at least one control measurement: local NTFS copy speed and, when practical, raw/device or same-drive native filesystem speed.
- Explorer `Flush` semantics are a safety boundary. Do not make `Flush` lie about durability unless a separate explicit experimental mode is created and left off by default.
- Performance tests must be correctness tests too. Fast corruption is worse than slow correctness.
- Checkpoint commits should be made after each task during implementation so the user can fall back to any known-good stage.

---

## Hot Path Findings From Inspection

### Highest Impact

1. `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
   - `MetadataStore::ApplyMutation` currently copies large working maps/vectors before each mutation:
     `working_inodes_`, `working_path_index_`, `working_directory_links_`, `working_spaceman_free_extents_`, and pending mutation vectors.
   - This is likely the largest many-small-file cost because every create/write/rename/delete pays for whole-graph rollback protection.
   - `HasWorkingChildren`, `UpsertWorkingDirectoryLink`, and `RemoveWorkingDirectoryLink` scan `working_inodes_` or `working_directory_links_` linearly.

2. `src-native/ApfsAccess.FsHost/src/main.cpp`
   - Mutating WinFsp callbacks use `MutationCallbackScope`, which serializes create/write/truncate/rename/delete/flush/close work.
   - `CB_Write` stages native metadata before writing the hydration file.
   - `CB_SetFileSize`, `CB_Rename`, `CB_Close`, and `CB_Flush` can synchronously commit or finalize journal work on the Explorer foreground path.
   - `CB_ReadDirectory` builds a fresh entry snapshot for every directory read and resolves every child by joined path.

3. `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
   - Raw device reads/writes are serialized by one mutex and one file pointer.
   - I/O uses `SetFilePointerEx` plus synchronous `ReadFile`/`WriteFile`.
   - Aligned requests already avoid read-modify-write, which is good, but parallel random I/O and seek-free reads are still blocked.

4. `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
   - `ReadCommittedFileRange` allocates an output vector per FsHost read and allocates a chunk vector for fragmented extents.
   - This is much better than full hydration, but it still adds allocation/copy cost on read fallback.

5. `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs` and `src/ApfsAccess.Service/ApfsMountWorker.cs`
   - Mount/probe/status operations are gated by `_gate`.
   - Worker cycles can probe devices, probe volumes, read mount state, mount, then read mount state again.
   - Status file reads parse JSON repeatedly. This is less important than native file I/O, but it affects startup and dashboard snappiness.

### Secondary Opportunities

- `src-native/ApfsAccess.ApfsRwEngine/src/NativeApfsReader.cpp`
  - Object map and B-tree reads allocate vectors for records and can re-resolve object map values repeatedly during projection.
  - This mostly affects mount/load time and initial directory availability.

- `src/ApfsAccess.Tray/DashboardForm.cs`
  - The dashboard already avoids disruptive flashing in healthy states, but status payload churn can still cause extra UI work in non-green states.
  - This is a responsiveness polish item, not the main throughput blocker.

- `scripts/run_physical_rw_validation.ps1`
  - The script already records SHA-256 and operation timings for Explorer workflow validation.
  - It needs explicit benchmark modes for large sequential files and many small files so changes can be proven.

---

## Metrics To Track

Use these metrics for every benchmark report:

- `startupToVisibleDriveMs`: app launch or refresh to drive visible in Explorer.
- `operationStartLatencyMs`: user command start to first destination byte or first created file.
- `largeWriteMBps`: copy one large file from NTFS to APFS.
- `largeReadMBps`: copy one large APFS file back to NTFS.
- `smallFilesPerSecond`: create/copy many small files into APFS.
- `smallFileMoveFilesPerSecond`: move many small files within APFS and out/back.
- `p50CommitMs`, `p95CommitMs`, `maxCommitMs`: native commit duration.
- `p50ApplyMutationUs`, `p95ApplyMutationUs`: metadata mutation staging duration.
- `blockReadMBps`, `blockWriteMBps`, `blockIoP95Ms`: raw device I/O timing.
- `readDirectoryEntriesPerSecond`: Explorer-like enumeration of a directory with many files.
- `trayStatusLagMs`: service publish time to tray/dashboard apply time.
- `sha256MismatchCount`: must stay zero.
- `unexpectedFallbackCount`: must stay zero.
- `recoveryWarningCount`: must stay zero for normal workflows.

---

## Risk-Tiered Roadmap

### Low Risk

1. Add benchmark modes and stable measurements.
2. Add low-overhead timing counters that are disabled or quiet by default.
3. Reduce duplicate service status reads within one worker cycle.
4. Avoid unchanged dashboard row rebuilds and unchanged tray menu rebuilds.
5. Trim obvious read/directory allocation churn where no data model changes are needed.

### Medium Risk

1. Add direct-buffer committed reads from `MetadataStore` into FsHost buffers.
2. Add directory child indexes for O(1) child lookup and child-count checks.
3. Cache native projection/object-map lookups during mount-time APFS scanning.
4. Make commit/status telemetry cheaper and more structured.

### High Risk

1. Replace full mutation rollback snapshots with a delta undo log.
2. Coalesce redundant foreground commits while preserving explicit flush safety.
3. Move `BlockDevice` to offset-based I/O and separate read/write handles.
4. Batch adjacent small metadata writes before raw device flush.

### Experimental

1. Incremental checkpoint persistence instead of full checkpoint rebuilds.
2. Read-ahead and small-block cache for fragmented reads.
3. Write-back worker for native metadata commit with strict durability modes.
4. Multi-extent file layout and append growth strategy instead of reallocating whole-file extents.

---

## Checkpoint And Rollback Strategy

- Start each task from a clean branch state.
- Commit after each task with one focused message.
- Do not combine benchmark harness changes with engine behavior changes.
- After every engine task, build the portable app and overwrite:
  `D:\SynologyDrive\电脑工具\Codex Projects\APFS Access\APFSAccess_Portable.exe`
- Keep the previous portable executable available as a manually restorable artifact during implementation.
- If any user-facing gate regresses, revert only the latest checkpoint and keep the benchmark data.

---

## Task 1: Add Physical Performance Benchmark Mode

**Risk Level:** Low

**Purpose:** Build a repeatable baseline before changing engine behavior. This makes it obvious which optimizations actually help large sequential throughput, many-small-file throughput, and operation start delay.

**Files:**

- Modify: `scripts/run_physical_rw_validation.ps1`
- Modify: `tests/ApfsAccess.Service.Tests/PilotScriptTests.cs`
- Create: `docs/performance-baselines.md`

- [x] **Step 1: Add a `Performance` mode to the physical validation script**

Update the script parameter validation:

```powershell
[ValidateSet("Smoke", "Storm", "ExplorerWorkflow", "VerifyManifest", "Performance")]
```

Add a function named `Invoke-PerformanceBenchmark` that runs these benchmark cases:

- `large-copy-in`: create one source file on NTFS and copy it to APFS.
- `large-copy-back`: copy that APFS file back to NTFS and compare SHA-256.
- `small-copy-in`: create many small files on NTFS and copy them to APFS.
- `small-copy-back`: copy the APFS small-file tree back to NTFS and compare SHA-256 for a deterministic sample plus a full manifest option.
- `small-internal-move`: move the APFS small-file tree to another APFS folder.
- `small-move-out-and-back`: move the tree to NTFS, then move it back to APFS.
- `directory-enumeration`: enumerate the APFS tree with `Get-ChildItem -Recurse -Force`.
- `delete-tree`: delete the APFS tree and verify host status is still healthy.

Record at least:

```powershell
[ordered]@{
    name = $Name
    elapsedMs = [Math]::Round($Elapsed.TotalMilliseconds, 3)
    bytes = $Bytes
    files = $Files
    megabytesPerSecond = $MegabytesPerSecond
    filesPerSecond = $FilesPerSecond
    statusBefore = $StatusBefore
    statusAfter = $StatusAfter
    sha256SampleCount = $Sha256SampleCount
    sha256MismatchCount = 0
}
```

- [x] **Step 2: Add benchmark defaults that match the user's pain**

Use these defaults:

```powershell
[int]$FileCount = 1000
[UInt64]$LargeFileBytes = 1GB
[int]$SmallFileBytes = 16KB
[int]$SmallFileHashSampleCount = 100
```

Keep `FileCount` and `LargeFileBytes` existing-compatible so older Smoke/ExplorerWorkflow commands still work.

- [x] **Step 3: Add script tests**

Add tests in `tests/ApfsAccess.Service.Tests/PilotScriptTests.cs` that assert:

- the script parses with the new `Performance` mode;
- `Invoke-PerformanceBenchmark` exists;
- benchmark names include `large-copy-in`, `large-copy-back`, `small-copy-in`, `small-internal-move`, and `delete-tree`;
- the output schema includes `megabytesPerSecond`, `filesPerSecond`, and `sha256MismatchCount`.

Run:

```powershell
dotnet test .\APFSAccess.sln -c Release --filter "FullyQualifiedName~PilotScriptTests"
```

Expected: all filtered script tests pass.

- [ ] **Step 4: Capture a baseline**

Run after building the current app:

```powershell
.\scripts\run_physical_rw_validation.ps1 `
  -Mode Performance `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -FileCount 1000 `
  -LargeFileBytes 1GB `
  -Cleanup
```

Expected:

- JSON report is written under `artifacts\physical-rw-validation`.
- `sha256MismatchCount` is `0`.
- host status stays native RW, recovery inactive, dirty count zero after settle.
- no Explorer recycle-bin or write-protected warning appears during manual spot-check.

- [x] **Step 5: Save the baseline summary**

Create `docs/performance-baselines.md` with a small table:

```markdown
# APFS Access Performance Baselines

| Date | Branch | Commit | Drive | Mode | Large write MB/s | Large read MB/s | Small copy files/s | Small move files/s | p95 commit ms | Notes |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 2026-05-25 | optimize/read-write-performance | <commit> | <drive model> | pre-optimization | <value> | <value> | <value> | <value> | <value> | baseline before performance tasks |
```

- [ ] **Step 6: Commit**

```powershell
git add scripts/run_physical_rw_validation.ps1 tests/ApfsAccess.Service.Tests/PilotScriptTests.cs docs/performance-baselines.md
git commit -m "test: add APFS performance baseline harness"
```

---

## Task 2: Add Low-Overhead Timing Counters

**Risk Level:** Low

**Purpose:** Find the real wait time split between FsHost callbacks, metadata mutation staging, commits, block I/O, status publishing, and dashboard updates.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/BlockDevice.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
- Modify: `tests/ApfsAccess.Backend.Native.Tests/NativeApfsBackendRuntimeStatusTests.cs`
- Modify: `tests/ApfsAccess.FsHost` native status tests if needed in `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`

- [x] **Step 1: Add native timing structs**

Add simple counters for:

- count
- total ticks
- max ticks
- last ticks

Use `QueryPerformanceCounter` in FsHost and `std::chrono::steady_clock` in RW engine if that matches local style better. Keep all updates behind an environment flag:

```text
APFSACCESS_PERF_COUNTERS=1
```

Expected behavior when disabled: no extra status JSON fields and minimal branch overhead.

- [x] **Step 2: Time FsHost callback phases**

Time these callback scopes in `src-native/ApfsAccess.FsHost/src/main.cpp`:

- `CB_Create`
- `CB_Write`
- `CB_SetFileSize`
- `CB_SetBasicInfo`
- `CB_Rename`
- `CB_SetDelete`
- `CB_Cleanup`
- `CB_Close`
- `CB_Read`
- `CB_ReadDirectory`
- `CB_Flush`
- `EnsureDirectoryLoaded`
- `MergeCommittedInodeStateIntoNodeIndex`
- `CommitNativeMutationsBestEffort`

Expose p50 only if a small fixed histogram is cheap. Otherwise expose count, total, last, and max first.

- [x] **Step 3: Time RW engine phases**

Add counters in `MetadataStore` for:

- `ApplyMutation`
- `CommitTransaction`
- `CommitCanonicalTransaction`
- `ValidateInodeGraphState`
- `SnapshotCommittedInodes`
- `ReadCommittedFileRange`
- each `Persist*Checkpoint` method
- `BuildCommitBlob`

Expected: the status JSON can show whether small-file delay is dominated by mutation staging or commit persistence.

- [x] **Step 4: Time BlockDevice I/O**

Add counters in `BlockDevice` for:

- read calls
- read bytes
- write calls
- write bytes
- unaligned read-modify-write count
- flush count
- max read/write/flush duration

Expected: benchmark reports can show whether raw device writes are slow or the host is slow before raw I/O starts.

- [x] **Step 5: Add status JSON fields only when enabled**

When `APFSACCESS_PERF_COUNTERS=1`, add a compact object:

```json
"performance": {
  "callbacks": {},
  "metadata": {},
  "blockDevice": {}
}
```

When the variable is not set, status JSON should remain compatible with current tests and UI.

- [x] **Step 6: Verify**

Build native host:

```powershell
.\scripts\build_native_host.ps1 -Configuration Release
```

Run focused status tests:

```powershell
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-attributes volume-acl-flag stable-volume-serial
dotnet test .\APFSAccess.sln -c Release --filter "FullyQualifiedName~NativeApfsBackendRuntimeStatusTests"
```

Expected: tests pass with counters disabled; new tests pass with a sample perf-enabled status payload.

- [x] **Step 7: Commit**

```powershell
git add src-native/ApfsAccess.FsHost/src/main.cpp src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp src-native/ApfsAccess.ApfsRwEngine/include/BlockDevice.h src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp tests
git commit -m "perf: add APFS write path timing counters"
```

---

## Task 3: Reduce Service And Dashboard Polling Churn

**Risk Level:** Low

**Purpose:** Improve perceived responsiveness and avoid wasting CPU while Explorer operations are already stressing the host.

**Files:**

- Modify: `src/ApfsAccess.Service/ApfsMountWorker.cs`
- Modify: `src/ApfsAccess.Backend.Native/NativeApfsBackend.cs`
- Modify: `src/ApfsAccess.Service/TrayPipeHostService.cs`
- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`
- Modify: `src/ApfsAccess.Tray/DashboardForm.cs`
- Modify: `src/ApfsAccess.Tray/DriveDashboardPresenter.cs`
- Modify: relevant tests in `tests/ApfsAccess.Service.Tests`, `tests/ApfsAccess.Backend.Native.Tests`, and `tests/ApfsAccess.Tray.Tests`

- [x] **Step 1: Reuse mount state inside one worker cycle**

In `ApfsMountWorker.RunCycleCoreAsync`, avoid calling `_backend.GetMountStateAsync` twice when no mount/eject/refresh action changed the host list.

Expected: idle cycles do one host status refresh, not two.

- [x] **Step 2: Add short-lived runtime status caching**

Inside `NativeApfsBackend`, cache `HostRuntimeStatus` per status file path for one backend operation cycle or about 250 ms. Do not use stale status after mount/eject/refresh, and do not hide recovery transitions.

Expected: rapid tray/service requests reuse the same status file read instead of repeatedly parsing the same JSON.

- [x] **Step 3: Coalesce status broadcasts by payload equality**

In `RuntimeStatusPublisher` or `TrayPipeHostService`, skip publishing when the payload is equal to the previous payload except for timestamp fields.

Expected: dashboard does not repaint for semantically identical yellow/red states.

- [x] **Step 4: Avoid dashboard row rebuilds for unchanged rows**

In `DashboardForm.ApplyStatus`, compare row identity and state before removing/recreating row controls. Update text/color only when that row changed.

Expected: no visible flashing while a warning state is being refreshed.

- [x] **Step 5: Verify**

Run:

```powershell
dotnet test .\APFSAccess.sln -c Release --filter "ApfsMountWorker|NativeApfsBackend|TrayApplicationContext|DriveDashboardPresenter"
```

Manual check:

- Launch app.
- Leave a mounted healthy drive idle for 30 seconds.
- Simulate a warning state if a test hook exists.
- Confirm dashboard does not flash and tray menu still updates when the actual state changes.

- [x] **Step 6: Commit**

```powershell
git add src/ApfsAccess.Service src/ApfsAccess.Backend.Native src/ApfsAccess.Tray tests
git commit -m "perf: reduce service and dashboard status churn"
```

---

## Task 4: Add Direct-Buffer Committed Reads

**Risk Level:** Medium

**Purpose:** Reduce per-read allocations and copies when FsHost reads committed APFS file ranges through metadata fallback.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/BlockDevice.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`

- [x] **Step 1: Add a BlockDevice read-into API**

Add a method shaped like:

```cpp
[[nodiscard]] bool ReadInto(
    std::uint64_t offset_bytes,
    std::span<std::byte> destination,
    std::size_t& bytes_read) const;
```

If `std::span` is inconvenient in this project, use:

```cpp
[[nodiscard]] bool ReadInto(
    std::uint64_t offset_bytes,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& bytes_read) const;
```

Keep existing `Read` as a wrapper so callers can migrate one at a time.

- [x] **Step 2: Add MetadataStore direct range read**

Add:

```cpp
[[nodiscard]] bool ReadCommittedFileRangeInto(
    const std::wstring& path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read) const;
```

Behavior must match `ReadCommittedFileRange`:

- return `true` and `out_bytes_read = 0` for EOF or zero-length reads;
- fill sparse holes with zero bytes;
- fail on invalid extent accounting;
- never write past `destination_size`.

- [x] **Step 3: Use direct reads in FsHost**

In `CB_Read`, replace the `std::vector<std::byte> payload` fallback path with `ReadCommittedFileRangeInto` directly into the WinFsp-provided buffer.

Expected: no payload vector allocation for normal committed fallback reads.

- [x] **Step 4: Preserve existing API behavior**

Keep `ReadCommittedFileRange` and implement it on top of `ReadCommittedFileRangeInto`, or keep both with shared helper logic.

Expected: existing conformance tests continue to pass unchanged.

- [x] **Step 5: Verify**

Run:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
.\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe metadata-read-open-no-hydration writable-sparse-hydration
```

Expected: committed reads, sparse reads, and writable sparse hydration tests pass.

- [ ] **Step 6: Benchmark**

Run `Performance` mode and compare:

- large-copy-back MB/s;
- committed read max and total allocation counters if available;
- block read throughput.

- [x] **Step 7: Commit**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine src-native/ApfsAccess.FsHost
git commit -m "perf: stream committed APFS reads into caller buffers"
```

---

## Task 5: Add Directory And Child Lookup Indexes

**Risk Level:** Medium

**Purpose:** Improve many-small-file create/delete/rename/enumeration by avoiding repeated linear scans of directory link and child collections.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`

- [x] **Step 1: Add a working directory child index**

Add internal indexes in `MetadataStore`:

```cpp
std::unordered_map<std::uint64_t, std::size_t> working_child_count_by_parent_;
std::unordered_map<std::wstring, std::size_t> working_directory_link_index_;
```

Use a stable key:

```text
<parent_object_id>|<lowercase_entry_name>
```

Keep `working_directory_links_` as the persisted/serialized source of truth until later tasks prove the index is correct.

- [x] **Step 2: Rebuild indexes after load and commit state sync**

Call a new helper after:

- `SyncWorkingStateFromCommitted`
- checkpoint load
- native projection load
- any test helper that resets working state

Expected: index state matches `working_directory_links_`.

- [x] **Step 3: Update mutation helpers**

Replace linear helpers:

- `HasWorkingChildren`
- `UpsertWorkingDirectoryLink`
- `RemoveWorkingDirectoryLink`

with index-backed versions.

Expected:

- directory-not-empty checks become O(1);
- upsert/remove avoid scanning the whole link vector for every small file;
- existing vector remains correct for persistence.

- [x] **Step 4: Add FsHost directory child node cache**

In FsHost, avoid resolving every child through `TryGetNodeLocked(c, Join(parent, name))` during `CB_ReadDirectory` when the child node can be retained or looked up by canonical child path once.

Safe approach:

- keep `Node.children` as names for compatibility;
- add or reuse a path-to-node map lookup that does not rebuild path strings more than necessary;
- only cache visible, non-delete-pending child nodes;
- invalidate on create, rename, delete, and directory merge.

- [x] **Step 5: Verify correctness**

Run:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
.\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-metadata-pair-workflow office-temp-rename-replace-workflow path-normalization-edge-matrix
```

Expected: directory, rename, delete, recycle-bin, and path edge behavior is unchanged.

- [ ] **Step 6: Benchmark**

Run `Performance` mode and compare:

- `small-copy-in` files/s;
- `small-internal-move` files/s;
- `directory-enumeration` entries/s;
- `ApplyMutation` p95.

- [x] **Step 7: Commit**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine src-native/ApfsAccess.FsHost
git commit -m "perf: index APFS directory mutation lookups"
```

---

## Task 6: Replace Full Mutation Snapshots With A Delta Undo Log

**Risk Level:** High impact, medium-high implementation risk

**Purpose:** Remove the largest many-small-file CPU/memory cost while keeping rollback behavior on invalid mutations.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceFaultTests.cpp`

- [ ] **Step 1: Add rollback tests before refactor**

Add focused tests for failed mutations that currently rely on full snapshots:

- create duplicate without replace leaves all maps unchanged;
- create replacing a non-empty directory fails and leaves links unchanged;
- write allocation failure leaves inode size/extent unchanged;
- rename into a missing parent fails and leaves source/destination unchanged;
- delete non-empty directory fails and leaves child links unchanged;
- SetFileSize allocation failure leaves free extents unchanged.

Run:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
```

Expected: new tests pass before refactor.

- [ ] **Step 2: Add a `MutationUndoLog` helper**

Add a local helper inside `MetadataStore.cpp` or a private nested type in `MetadataStore` that records only touched state:

```cpp
struct MutationUndoLog
{
    std::size_t pending_object_map_updates_size;
    std::size_t pending_spaceman_allocations_size;
    std::size_t pending_spaceman_deallocations_size;
    std::size_t pending_btree_records_size;
    std::uint64_t working_next_ephemeral_extent;
    std::vector<InodeRestoreEntry> inode_restores;
    std::vector<PathIndexRestoreEntry> path_index_restores;
    std::vector<DirectoryLinkRestoreEntry> directory_link_restores;
    std::vector<SpacemanFreeExtentRestoreEntry> free_extent_restores;
};
```

The exact shape can differ, but it must restore only changed entries and truncate pending vectors back to their original sizes.

- [ ] **Step 3: Wrap every mutating helper**

Before changing any of these collections, record the old value or absence:

- `working_inodes_`
- `working_path_index_`
- `working_directory_links_`
- directory child indexes from Task 5
- `working_spaceman_free_extents_`
- pending vectors
- `working_next_ephemeral_extent_`

Expected: failed mutations restore identical state without whole-map copies.

- [ ] **Step 4: Remove full-state copies from `ApplyMutation`**

Delete these per-mutation copies:

- `working_inodes_snapshot`
- `working_path_index_snapshot`
- `working_directory_links_snapshot`
- `working_spaceman_free_extents_snapshot`
- `pending_object_map_updates_snapshot`
- `pending_spaceman_allocations_snapshot`
- `pending_spaceman_deallocations_snapshot`
- `pending_btree_records_snapshot`

Replace the rollback guard with `undo_log.Rollback(*this)`.

- [ ] **Step 5: Add state-equivalence assertions in tests**

For the new rollback tests, compare:

- inode lookup by path;
- pending mutation count;
- pending object map update count if accessible;
- committed/working inode count;
- free extent total bytes;
- directory child count.

If private access is needed, add test-only accessors guarded by the existing test compile pattern.

- [ ] **Step 6: Verify**

Run:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
.\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe rename-rollback set-file-size-rollback delete-on-close-rollback recycle-bin-metadata-pair-workflow
```

If exact FsHost test names differ, run the closest focused rollback cluster from `FsHostSemanticsTests`.

- [ ] **Step 7: Benchmark**

Run `Performance` mode and compare:

- `small-copy-in` files/s;
- `small-move-out-and-back` files/s;
- `ApplyMutation` p50/p95/max;
- memory growth during small-file sweep.

- [ ] **Step 8: Commit**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine
git commit -m "perf: replace metadata mutation snapshots with undo log"
```

---

## Task 7: Coalesce Redundant Foreground Commits Safely

**Risk Level:** High

**Purpose:** Reduce operation start/finish latency caused by synchronous commit work while preserving real flush and recovery guarantees.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`

- [ ] **Step 1: Use telemetry to identify redundant commits**

Before changing behavior, use Task 2 counters to list commit origins:

- `Flush`
- `Close`
- `Rename`
- `SetFileSize`
- `Shutdown`

Expected: the benchmark report shows which origins dominate small-file copy/move.

- [ ] **Step 2: Add a commit decision helper**

Centralize commit policy in FsHost:

```cpp
enum class CommitUrgency
{
    None,
    MetadataOnlyCanDelay,
    UserFlushMustCommit,
    CloseCanDrainIfDirty,
    NamespaceBoundaryMustCommit,
    ShutdownMustCommit
};
```

Expected: every current call to `CommitNativeMutationsBestEffort` documents why it is needed.

- [ ] **Step 3: Remove or delay only proven redundant commits**

Candidates to evaluate:

- repeated `Flush` calls when `PendingMutationCount() == 0`;
- `Close` commit when no delete/rename/size mutation was emitted;
- metadata-only timestamp updates that are immediately followed by a file-content flush;
- `SetFileSize` preallocation/truncate commits that are followed by writes and a flush in the same handle lifecycle.

Do not delay:

- explicit user flush with pending dirty native mutations;
- shutdown;
- recovery marker update;
- namespace replacement where local rollback depends on commit success.

- [ ] **Step 4: Add tests for commit origin behavior**

Add tests that assert:

- `Flush` commits pending content before returning success;
- repeated `Flush` without pending mutations does not call commit;
- `Close` without pending mutations does not call commit;
- delete-on-close still commits before the node disappears permanently;
- rename-replace rollback still works on forced commit failure.

- [ ] **Step 5: Verify**

Run:

```powershell
.\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe flush-finalizes-pending-journal close-commits-pending-native-metadata-after-directory-create recycle-bin-metadata-pair-workflow
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
```

Expected: safety semantics are unchanged, but redundant commit count drops in performance telemetry.

- [ ] **Step 6: Benchmark**

Run `Performance` mode and compare:

- operation start latency;
- small-file copy files/s;
- p95 commit latency;
- number of commits per 1000 files.

- [ ] **Step 7: Commit**

```powershell
git add src-native/ApfsAccess.FsHost src-native/ApfsAccess.ApfsRwEngine
git commit -m "perf: coalesce redundant native commit work"
```

---

## Task 8: Move BlockDevice To Offset-Based I/O

**Risk Level:** High

**Purpose:** Reduce raw I/O serialization and remove shared seek-pointer overhead, especially for random reads/writes and fragmented files.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/BlockDevice.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceFaultTests.cpp`

- [ ] **Step 1: Add separate read/write handle state**

Split current handle usage into:

- read handle;
- write handle;
- geometry cache lock;
- scratch buffer lock or per-call scratch buffers.

Expected: reads do not wait behind unrelated writes just because they share a file pointer.

- [ ] **Step 2: Use explicit offsets for reads and writes**

Replace `SetFilePointerEx` plus `ReadFile`/`WriteFile` with offset-based I/O. Use the safest Windows pattern for this codebase:

- open handles with compatible flags;
- pass an `OVERLAPPED` with `Offset` and `OffsetHigh`;
- wait synchronously for completion if the handle is overlapped;
- preserve exact short-read and fault-injection behavior.

- [ ] **Step 3: Keep unaligned write safety**

Preserve read-modify-write behavior for unaligned writes:

- read aligned block window;
- merge caller bytes;
- write aligned block window;
- count it as unaligned RMW in performance counters.

- [ ] **Step 4: Add adjacent write batching only after offset I/O passes**

Batch only adjacent small writes within one commit/checkpoint operation. Do not batch across an explicit flush boundary.

Expected: metadata checkpoint persistence uses fewer raw device calls when it writes adjacent blocks.

- [ ] **Step 5: Verify fault tests**

Run:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
```

Expected: persistence, conformance, conformance fault, fault injection, canonical store, and transaction tests pass.

- [ ] **Step 6: Benchmark**

Run `Performance` mode and compare:

- block read/write max duration;
- fragmented read throughput;
- large write throughput;
- small-file commit p95.

- [ ] **Step 7: Commit**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine/include/BlockDevice.h src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp src-native/ApfsAccess.ApfsRwEngine/tests
git commit -m "perf: use offset-based APFS block device I/O"
```

---

## Task 9: Cache Native APFS Projection Lookups

**Risk Level:** Medium

**Purpose:** Improve mount/start responsiveness and initial directory loading on larger APFS volumes.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/NativeApfsReader.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/NativeApfsReader.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`

- [ ] **Step 1: Add an object map lookup cache for one projection run**

During `NativeApfsReader::BuildProjection`, cache object map records by:

```text
map_oid|xid
```

and cache resolved object values by:

```text
map_oid|object_id|xid
```

Expected: repeated `ResolveObjectMapValue` calls do not reread the same object map B-tree.

- [ ] **Step 2: Avoid copying B-tree key/value bytes where safe**

Review `RawBtreeRecord` creation. If record bytes do not outlive the block, keep copies. If they can be parsed immediately, add a fast parse path that extracts inode, directory, and extent data without storing all raw key/value vectors.

Expected: mount projection uses less memory and does fewer allocations.

- [ ] **Step 3: Verify projection correctness**

Run:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
```

Expected: all native projection/conformance tests pass.

- [ ] **Step 4: Benchmark**

Measure:

- app launch to drive visible;
- refresh to drive visible;
- `EnsureDirectoryLoaded` timing;
- first root directory enumeration time.

- [ ] **Step 5: Commit**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine/include/NativeApfsReader.h src-native/ApfsAccess.ApfsRwEngine/src/NativeApfsReader.cpp src-native/ApfsAccess.ApfsRwEngine/tests
git commit -m "perf: cache native APFS projection lookups"
```

---

## Task 10: Evaluate Incremental Checkpoint Persistence

**Risk Level:** Experimental

**Purpose:** Reduce commit amplification after the lower-risk work is done. This is the deepest change and should only happen if benchmarks still show commit persistence dominates.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceFaultTests.cpp`

- [ ] **Step 1: Measure checkpoint amplification**

Use Task 2 counters to record:

- bytes written per commit;
- metadata bytes written per user payload byte;
- number of checkpoint blocks touched per small-file mutation;
- time per `PersistObjectMapCheckpoint`, `PersistSpacemanCheckpoint`, `PersistInodeCheckpoint`, `PersistBtreeCheckpoint`, and `PersistReplayCheckpoint`.

Expected: decide whether checkpoint persistence is the remaining bottleneck.

- [ ] **Step 2: Design an incremental checkpoint candidate**

The candidate must preserve:

- mount-time recovery;
- canonical commit readiness;
- fault-injection rollback guarantees;
- fail-closed behavior after torn writes;
- compatibility with existing full checkpoint blocks.

Minimum safe first version:

- keep periodic full checkpoints;
- add delta checkpoint records between full checkpoints;
- compact deltas after a threshold;
- reject mount if delta chain is incomplete or checksum-invalid.

- [ ] **Step 3: Add fault tests before implementation**

Add tests for:

- delta write fails before superblock update;
- superblock points to full checkpoint when delta write fails;
- delta chain replay after remount;
- corrupted delta checksum triggers recovery-required state;
- full checkpoint compaction clears old deltas.

- [ ] **Step 4: Implement only if the design survives review**

Do not implement this task casually. It changes the recovery model and should be reviewed separately before coding.

- [ ] **Step 5: Commit only after full validation**

Required validation:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
.\scripts\build_native_host.ps1 -Configuration Release
dotnet test .\APFSAccess.sln -c Release
.\scripts\run_physical_rw_validation.ps1 -Mode ExplorerWorkflow -MountRoot E:\ -StatusFile <current-host-status-json> -Cleanup
.\scripts\run_physical_rw_validation.ps1 -Mode Performance -MountRoot E:\ -StatusFile <current-host-status-json> -FileCount 1000 -LargeFileBytes 1GB -Cleanup
```

Expected: full correctness and physical validation pass before keeping this checkpoint.

---

## Validation Matrix For Every Engine Checkpoint

### Fast Synthetic Gate

Run first after every native code change:

```powershell
.\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-attributes volume-acl-flag stable-volume-serial
```

### Focused Performance Gate

Run after every task that touches FsHost, MetadataStore, BlockDevice, or NativeApfsReader:

```powershell
.\scripts\run_physical_rw_validation.ps1 `
  -Mode Performance `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -FileCount 1000 `
  -LargeFileBytes 1GB `
  -Cleanup
```

### User-Facing Explorer Smoke

Manually verify:

- create a folder;
- copy in one large file;
- copy in a folder with many small files;
- rename a file;
- move within the APFS drive;
- move out to NTFS and back;
- delete directly;
- delete through Explorer/recycle behavior;
- eject from tray;
- refresh/fix to remount.

Expected:

- no recycle-bin warning;
- no write-protected warning;
- no unexpected read-only fallback;
- dashboard state is stable and accurate;
- drive letter disappears after eject;
- SHA-256 checks match for files copied back out.

### Full Validation Gate Before Promoting To `master`

Run only after a batch of checkpoints is complete:

```powershell
.\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
.\scripts\build_native_host.ps1 -Configuration Release
dotnet test .\APFSAccess.sln -c Release
.\build\publish.ps1 -Configuration Release -Runtime win-x64
.\scripts\run_physical_rw_validation.ps1 -Mode ExplorerWorkflow -MountRoot E:\ -StatusFile <current-host-status-json> -Cleanup
.\scripts\run_physical_rw_validation.ps1 -Mode Performance -MountRoot E:\ -StatusFile <current-host-status-json> -FileCount 1000 -LargeFileBytes 1GB -Cleanup
git diff --check
```

Expected:

- all automated tests pass;
- portable app is rebuilt and root `APFSAccess_Portable.exe` is overwritten;
- physical Explorer workflow passes;
- physical performance report shows no correctness regression;
- no whitespace errors.

---

## Recommended Execution Order

1. Task 1: Add benchmark mode and baseline.
2. Task 2: Add timing counters.
3. Task 3: Reduce service/dashboard churn.
4. Task 4: Direct-buffer reads.
5. Task 5: Directory and child lookup indexes.
6. Task 6: Delta undo log for metadata mutations.
7. Re-run physical benchmark and decide whether commit or block I/O still dominates.
8. Task 7 if commit count/latency is still the bottleneck.
9. Task 8 if raw I/O serialization is still the bottleneck.
10. Task 9 if mount/start delay is still meaningful.
11. Task 10 only if checkpoint persistence remains the proven bottleneck after safer work.

---

## Expected Best Wins

**Most likely biggest win for many small files:** Task 6, because it removes whole-state copying from every metadata mutation.

**Most likely biggest win for Explorer directory operations:** Task 5, because it removes linear directory link and child lookup scans.

**Most likely biggest win for read/copy-back throughput:** Task 4, because it removes per-read payload allocation and copy.

**Most likely biggest win for large write throughput:** Task 7 or Task 8, depending on whether telemetry shows commit persistence or raw I/O serialization dominates.

**Most likely biggest win for startup snappiness:** Task 9 plus the service caching portion of Task 3.

---

## Open Questions To Answer With Benchmarks

- Is the slow "start movement" delay mostly `ApplyMutation`, commit, raw device flush, Defender/Explorer scanning, or status/service probing?
- During a many-small-file copy, how many native commits happen per 100 files?
- Does Explorer call `Flush` after each small file on this WinFsp mount?
- Is large-file throughput capped by the flash drive, raw APFS block writes, hydration cache writes, SHA-256 validation, or metadata commits?
- Does random read/write get faster after offset-based BlockDevice I/O, or is the real blocker still metadata serialization?
- How much performance is lost to APFS Access compared with a control copy to a normal Windows volume on the same machine?

---

## Stop Conditions

Stop and revert the latest checkpoint if any of these happen:

- SHA-256 mismatch.
- unexpected read-only fallback during normal copy/move/delete workflows.
- write-protected warning returns.
- recycle-bin corruption warning returns.
- eject no longer removes the drive letter.
- recovery-active state remains after a normal successful workflow.
- dirty transaction count does not settle to zero after validation.
- performance improves only by weakening durability or fail-closed safety.
