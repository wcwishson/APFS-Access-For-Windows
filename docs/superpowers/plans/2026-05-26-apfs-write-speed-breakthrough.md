# APFS Write Speed Breakthrough Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make APFS Access writes, especially many-small-file and random-write workflows, feel much closer to a normal fast USB drive while preserving correct Explorer behavior, full RW functionality, and fail-closed recovery.

**Architecture:** Treat the write path as a durability pipeline, not a raw I/O problem. First prove where each foreground write stalls, then reduce full APFS checkpoint frequency and flush amplification in safe checkpoints, then add a stronger durable payload journal so more aggressive deferred/background commits can be tested behind an explicit experimental switch before any default behavior changes.

**Tech Stack:** WinFsp FsHost C++ callbacks, APFS RW engine C++ metadata/checkpoint writer, Windows raw device I/O, TransactionManager/native mutation journal, PowerShell physical validation and benchmark scripts, SHA-256 integrity checks, .NET service/tray status reporting.

---

## Current Status As Of 2026-05-26

**Branch:** `optimize/read-write-performance`

**Baseline already observed:**

| Metric | Result |
| --- | ---: |
| CrystalDiskMark-style sequential read | about `883-951 MB/s` |
| CrystalDiskMark-style sequential write | about `4-10 MB/s` |
| CrystalDiskMark-style random 4K write | about `0.06 MB/s`, roughly `15 IOPS` |
| Explorer-style large copy into APFS | about `38.9 MB/s` |
| Explorer-style large copy back out | about `1197 MB/s` |
| Explorer-style small copy into APFS | about `4.1 files/s` |
| Explorer-style small move out and back | about `2.2 files/s` |
| Explorer-style delete tree | about `2.3 files/s` |

**Interpretation:**

- Reads are already strong.
- Writes are not limited by USB 3.0 bandwidth alone; small random writes are dominated by foreground commit and flush costs.
- The current native mutation journal records mutation intent, not durable file payload bytes. That means we cannot safely defer arbitrary APFS checkpoints for long unless we first make payload durability and replay stronger.
- The largest likely speed win is reducing how often Explorer foreground callbacks pay the full `MetadataStore::CommitPendingMutations()` cost.

---

## Assumptions And Tradeoffs

- The default app must stay conservative: no silent corruption, no false success on explicit flush, no recycle-bin warning, no write-protected fallback, no surprise read-only degradation during ordinary file operations.
- "Crack hard on write speed" means we are willing to refactor high-risk write-path architecture, but only with checkpoint commits and rollback points.
- `Flush`, eject, shutdown, and crash recovery semantics are safety boundaries. If we make them faster, we still need a credible durability story.
- Explorer may issue many `Close`, `Flush`, rename, delete, and metadata updates per user action. Optimizing one callback is not enough; the policy for when a full APFS commit is forced must be centralized.
- Some aggressive designs should start behind an explicit hidden flag, then graduate only after physical validation and manual Explorer testing.

---

## Hard Gates

Every implementation checkpoint must keep these true:

- No SHA-256 mismatch after copy in, copy back out, move, rename, remount, and delete workflows.
- No recycle-bin corruption warning.
- No Explorer write-protected warning.
- No unexpected fallback from RW to RO during ordinary writes.
- `Flush`, tray eject, app shutdown, and Windows unmount leave dirty native mutations drained or fail closed with a clear reason.
- After idle settle, `dirtyTransactionCount` and native pending mutation count return to zero.
- Eject removes the Explorer drive letter.
- Fix/refresh can recover from a software-level stale or degraded state where recovery is possible.
- Crash/fault-injection tests either recover the previous coherent checkpoint or block RW mode; never mount writable with mixed old/new state.

---

## Hot Path Diagnosis

### FsHost Foreground Boundaries

`src-native/ApfsAccess.FsHost/src/main.cpp`

- `CB_Write` stages native write metadata and writes the hydration file, but does not normally force the full APFS commit immediately.
- `CB_Close` commits when any native mutation is pending. This is a major many-small-file bottleneck because Explorer closes each file.
- `CB_Flush` commits pending native mutations. This must stay durable unless an explicitly experimental durability mode says otherwise.
- `CB_Rename` commits synchronously so local namespace rollback can be deterministic if native commit fails.
- Delete-on-close commits synchronously so removed files are not lost from local state before APFS persistence is proven.
- `DrainNativeMutationsForDirtyLimit` already drains once the dirty mutation limit is reached, but that is a safety throttle, not a throughput strategy.

### MetadataStore Commit Amplification

`src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`

- `CommitPendingMutations()` writes payload extents, a commit blob, object map checkpoint, spaceman checkpoint, inode checkpoint, btree checkpoint, replay checkpoint, superblock checkpoint, and at least two raw device flushes.
- Each small file can cause the same full checkpoint family to be rewritten.
- The normal path already avoids strict round-trip checkpoint verification unless strict verification or fault hooks are enabled, so the remaining bottleneck is mostly real persistence work and flush frequency.
- Payload writes are gathered by final file path, but payload bytes are loaded as whole vectors and written synchronously during commit.

### Block Device And Journal Constraints

`src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`

- Aligned writes already avoid read-modify-write.
- Offset-based I/O has already reduced shared seek-pointer serialization.
- Further raw I/O wins are likely smaller than commit-frequency wins unless batching reduces flush and write-call count inside a checkpoint.

`src-native/ApfsAccess.ApfsRwEngine/src/TransactionManager.cpp`

- `Commit()` appends mutation intent records, not payload bytes.
- A deferred APFS checkpoint can only be made default if the app can prove that file payload bytes needed for replay are durable somewhere outside the not-yet-persisted APFS checkpoint.

---

## Risk-Tiered Roadmap

### Low Risk

1. Improve write-specific telemetry and benchmark reporting.
2. Add explicit commit-origin histograms and per-origin flush counts.
3. Skip no-op or duplicate commit attempts that still reach expensive paths.
4. Batch adjacent payload/checkpoint writes inside one already-required commit.
5. Reuse payload buffers and avoid whole-payload copies where the commit path only needs slices.

### Medium Risk

1. Centralize commit policy so every synchronous commit has a named reason.
2. Coalesce `Close` commits for pure file-content writes when an explicit `Flush`, dirty-limit drain, eject, shutdown, or idle drain will safely commit soon.
3. Add a foreground commit debouncer that drains bursts after a short idle window.
4. Move post-commit status/recovery marker updates out of repeated success paths unless state actually changed.

### High Risk

1. Add a durable payload journal or write-ahead payload spool so deferred APFS commits can survive app crash or power loss.
2. Let background commit workers drain content writes after close without blocking Explorer for every file.
3. Defer selected rename/delete commits only after namespace rollback and journal replay semantics are proven.
4. Reduce full checkpoint rewrite amplification with incremental checkpoint/delta records.

### Experimental Only

1. Aggressive write-back mode that acknowledges `Close` before APFS checkpoint persistence.
2. Deferred namespace commits for rename/delete bursts.
3. Periodic full checkpoints with many delta checkpoints in between.
4. Any mode where explicit Windows `Flush` returns before durable APFS or durable replay journal persistence.

---

## File Structure And Responsibilities

- `src-native/ApfsAccess.FsHost/src/main.cpp`
  - Owns WinFsp callback behavior, commit-origin policy, close/flush/rename/delete boundaries, background drain thread, and user-visible RW/RO state transitions.
- `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
  - Exposes commit state, pending payload/mutation metadata, write-speed counters, and any new batch/streaming commit APIs.
- `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
  - Owns APFS mutation staging, payload persistence, checkpoint persistence, replay checkpoint updates, and commit compaction.
- `src-native/ApfsAccess.ApfsRwEngine/include/TransactionManager.h`
  - Owns mutation journal data structures and any durable payload journal interfaces.
- `src-native/ApfsAccess.ApfsRwEngine/src/TransactionManager.cpp`
  - Persists and replays intent/payload journal records.
- `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
  - Owns raw write batching, flush timing, alignment/RMW behavior, and device write metrics.
- `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
  - Pins callback-level semantics: flush durability, close commit policy, rename/delete rollback, dirty drain, recovery state.
- `src-native/ApfsAccess.ApfsRwEngine/tests/*`
  - Pins metadata commit, replay, fault-injection, and payload integrity behavior.
- `scripts/run_physical_rw_validation.ps1`
  - Runs Explorer-style correctness and write-speed benchmarks.
- `docs/performance-baselines.md`
  - Records before/after measurements for every write-speed checkpoint.

---

## Metrics To Track

Capture these before and after every write-path checkpoint:

- `largeWriteMBps`
- `smallCopyInFilesPerSecond`
- `smallMoveOutAndBackFilesPerSecond`
- `random4KWriteMBps`
- `random4KWriteIops`
- `operationStartLatencyMs`
- `commitCountByOrigin`
- `commitP50Ms`, `commitP95Ms`, `commitMaxMs`
- `flushCountByOrigin`
- `deviceFlushP95Ms`
- `payloadBytesPerCommit`
- `checkpointBytesPerCommit`
- `metadataBytesWrittenPerPayloadByte`
- `pendingMutationPeak`
- `dirtySettleMs`
- `sha256MismatchCount`
- `unexpectedFallbackCount`
- `recoveryWarningCount`

---

## Task 1: Build A Write-Speed Observatory

**Risk Level:** Low

**Purpose:** Make the next changes measurable. We need to know whether time is lost before first write, in close, in flush, in payload writes, in checkpoint writes, or in device flushes.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
- Modify: `scripts/run_physical_rw_validation.ps1`
- Modify: `docs/performance-baselines.md`

- [ ] **Step 1: Add commit-origin counters**

Track every call to `CommitNativeMutationsBestEffort` with:

```cpp
struct NativeCommitOriginStats
{
    std::uint64_t attempts = 0;
    std::uint64_t committed = 0;
    std::uint64_t nothing_to_commit = 0;
    std::uint64_t failed = 0;
    std::uint64_t total_ms = 0;
    std::uint64_t max_ms = 0;
    std::uint64_t pending_mutations_before = 0;
    std::uint64_t payload_bytes_before = 0;
};
```

Use origin labels already passed by call sites:

- `Close`
- `Flush`
- `Rename`
- `Shutdown`
- `DirtyLimit`

Expected: performance status can say "1000-file copy triggered X Close commits, Y Flush commits, and Z dirty-limit commits."

- [ ] **Step 2: Add checkpoint-byte counters inside `CommitPendingMutations()`**

Record:

- payload bytes written;
- commit blob bytes;
- checkpoint bytes by family: object map, spaceman, inode, btree, replay, superblock;
- raw device flush count for the commit;
- number of payload paths gathered;
- number of pending mutations merged.

Expected: one commit report shows write amplification, for example "16 KiB user payload caused 2.5 MiB metadata/checkpoint writes plus two flushes."

- [ ] **Step 3: Add first-byte latency to physical performance mode**

In `scripts/run_physical_rw_validation.ps1`, add a measurement for copy-in start delay:

```powershell
$destinationAppeared = Measure-Until {
    Test-Path -LiteralPath $destinationPath
}
```

Record:

- time from copy command start to destination path appearing;
- time from command start to first nonzero length if available;
- total elapsed time.

Expected: the benchmark distinguishes "slow to start" from "slow once moving."

- [ ] **Step 4: Verify**

Run:

```powershell
$env:TEMP='D:\ApfsAccessScratch\Temp'
$env:TMP='D:\ApfsAccessScratch\Temp'
$env:APFSACCESS_PERF_COUNTERS='1'
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-attributes volume-acl-flag stable-volume-serial
```

Expected:

- focused semantic tests pass;
- status JSON includes write-speed counters only when `APFSACCESS_PERF_COUNTERS=1`;
- counters are absent or quiet when the environment variable is unset.

- [ ] **Step 5: Capture baseline**

Run on the mounted APFS drive:

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

- JSON report written under `artifacts\physical-rw-validation`;
- `sha256MismatchCount` is `0`;
- no recycle-bin or write-protected warning;
- commit-origin histogram is captured.

- [ ] **Step 6: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.FsHost/src/main.cpp src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp scripts/run_physical_rw_validation.ps1 docs/performance-baselines.md
git commit -m "perf: add APFS write speed observability"
```

---

## Task 2: Centralize Commit Policy And Remove No-Op Foreground Commits

**Risk Level:** Low-to-medium

**Purpose:** Make every full APFS commit intentional. This should reduce accidental duplicate commits without changing durability rules.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`

- [ ] **Step 1: Add a commit policy enum**

Add:

```cpp
enum class NativeCommitUrgency
{
    None,
    MetadataOnlyCanDelay,
    FileContentCloseCanDelay,
    DirtyLimitMustCommit,
    UserFlushMustCommit,
    NamespaceBoundaryMustCommit,
    DeleteBoundaryMustCommit,
    ShutdownMustCommit
};
```

Add a helper:

```cpp
NativeCommitUrgency ClassifyNativeCommitRequest(
    const MountContext* c,
    const wchar_t* origin,
    bool has_delete_plans,
    bool namespace_boundary);
```

Expected: `Close`, `Flush`, `Rename`, dirty-limit, delete, and shutdown call a named policy path.

- [ ] **Step 2: Skip commits when pending mutation count is zero before taking the expensive path**

Before entering full commit work, check `HasPendingNativeMutations(c)` once under the metadata lock.

Expected:

- repeated `Flush` with no pending mutation returns success without touching `MetadataStore::CommitPendingMutations()`;
- `Close` after a read-only open does not call commit;
- status marker can clear stale dirty state if no pending native mutation remains.

- [ ] **Step 3: Add callback policy tests**

Add FsHost semantic tests:

```text
flush-without-pending-native-mutations-skips-commit
close-readonly-open-skips-native-commit
close-after-write-keeps-current-durable-behavior
rename-still-uses-namespace-boundary-commit
delete-on-close-still-uses-delete-boundary-commit
```

Expected:

- no behavior change for write, rename, and delete durability yet;
- no-op foreground callbacks no longer inflate commit counters.

- [ ] **Step 4: Verify**

Run:

```powershell
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe flush-without-pending-native-mutations-skips-commit close-readonly-open-skips-native-commit close-after-write-keeps-current-durable-behavior rename-still-uses-namespace-boundary-commit delete-on-close-still-uses-delete-boundary-commit
```

Expected: focused policy tests pass.

- [ ] **Step 5: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.FsHost/src/main.cpp src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp
git commit -m "perf: centralize native write commit policy"
```

---

## Task 3: Reduce Full Commit Cost Inside Already-Required Commits

**Risk Level:** Medium

**Purpose:** Make unavoidable commits cheaper before changing when commits happen. This improves safety-boundary operations such as flush, eject, shutdown, and rename/delete boundaries.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/BlockDevice.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`

- [ ] **Step 1: Batch adjacent payload writes within one commit**

Sort `pending_payload_writes` by physical address. Merge adjacent writes when:

```cpp
previous.physical_address + previous.bytes.size() == next.physical_address
```

Expected:

- one large contiguous payload uses fewer raw `device_.Write` calls;
- physical bytes are identical after copy-back SHA-256;
- no batching crosses commit boundaries.

- [ ] **Step 2: Stream payload slices instead of copying each slice into a new vector**

Replace per-extent slice vectors with a lightweight view:

```cpp
struct PendingPayloadWriteView
{
    std::uint64_t physical_address = 0;
    std::shared_ptr<std::vector<std::byte>> payload;
    std::size_t offset = 0;
    std::size_t length = 0;
};
```

Then write either:

- direct view if `BlockDevice::Write` gains span support;
- or one reusable scratch buffer for merged writes.

Expected: large-file commits allocate less and avoid copying the same payload into many extent vectors.

- [ ] **Step 3: Add `BlockDevice::WriteSpan` or equivalent**

Add an overload:

```cpp
bool Write(std::uint64_t offset_bytes, std::span<const std::byte> buffer);
```

Keep the existing vector overload as a wrapper.

Expected: commit code can write payload/checkpoint slices without allocating new vectors.

- [ ] **Step 4: Keep fault-injection behavior identical**

Run existing torn-write and persist-failure tests after the batching change.

Expected:

- injected short write still fails closed;
- interrupted payload write does not expose mixed data;
- interrupted checkpoint write does not mount writable.

- [ ] **Step 5: Verify**

Run:

```powershell
pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-attributes volume-acl-flag stable-volume-serial flush-finalizes-pending-journal
```

Expected: native RW engine and focused FsHost tests pass.

- [ ] **Step 6: Benchmark**

Run performance mode and compare:

- large write MB/s;
- payload write calls per large-file commit;
- checkpoint bytes per commit;
- device flush p95.

- [ ] **Step 7: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine
git commit -m "perf: reduce native commit payload write overhead"
```

---

## Task 4: Add A Safe Close-Commit Coalescer

**Risk Level:** High

**Purpose:** Stop making every small file pay a full APFS checkpoint on `Close`, while keeping explicit flush/eject/shutdown durable.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`

- [ ] **Step 1: Add hidden opt-in flag first**

Add an off-by-default option:

```text
APFSACCESS_DEFER_CLOSE_COMMITS=1
```

Default behavior remains current synchronous close commit.

Expected: users get no behavior change until the flag is enabled for testing.

- [ ] **Step 2: Add pending close-drain state**

Add to `MountContext`:

```cpp
std::atomic<bool> close_commit_deferred{false};
std::atomic<std::uint64_t> deferred_commit_deadline_tick_ms{0};
std::atomic<std::uint64_t> deferred_close_commit_count{0};
std::thread commit_drain_thread;
HANDLE commit_drain_event = nullptr;
```

Expected: `Close` can request a drain without doing the commit itself.

- [ ] **Step 3: Allow deferral only for pure content close**

Only defer `Close` when:

- no delete plan exists;
- no rename or namespace boundary is in progress;
- the file hydration handle has already been closed successfully;
- pending mutation count is below dirty limit;
- recovery is inactive;
- explicit flush has not been requested for this handle.

Do not defer:

- delete-on-close;
- rename/replace;
- directory create/delete where Explorer immediately depends on namespace durability;
- dirty-limit drains;
- app shutdown;
- tray eject;
- `CB_Flush`.

Expected: many small file content writes can be coalesced, but high-risk namespace operations stay synchronous.

- [ ] **Step 4: Drain after short idle window or thresholds**

Use these starting thresholds:

```text
idle debounce: 250 ms
max deferred mutations: min(write_max_dirty_transactions / 2, 128)
max deferred bytes: 64 MiB
max deferred age: 2 seconds
```

Expected:

- copying many small files triggers far fewer full commits;
- a large file does not leave too much dirty data waiting;
- dirty state settles shortly after Explorer finishes.

- [ ] **Step 5: Force drain at safety boundaries**

Force synchronous drain before returning success from:

- `CB_Flush`;
- tray eject;
- FsHost shutdown;
- dirty-limit drain;
- transition to read-only/degraded state.

Expected: safety boundaries remain durable.

- [ ] **Step 6: Add tests for deferred close behavior**

Add tests:

```text
deferred-close-does-not-commit-immediately-when-flag-enabled
deferred-close-drains-on-flush-before-success
deferred-close-drains-on-shutdown-before-success
deferred-close-drains-at-dirty-threshold
deferred-close-delete-still-commits-synchronously
deferred-close-rename-still-commits-synchronously
```

Expected: the new mode changes only pure close behavior.

- [ ] **Step 7: Verify with flag off and on**

Run with flag off:

```powershell
Remove-Item Env:\APFSACCESS_DEFER_CLOSE_COMMITS -ErrorAction SilentlyContinue
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe recycle-bin-attributes volume-acl-flag stable-volume-serial flush-finalizes-pending-journal
```

Run with flag on:

```powershell
$env:APFSACCESS_DEFER_CLOSE_COMMITS='1'
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe deferred-close-does-not-commit-immediately-when-flag-enabled deferred-close-drains-on-flush-before-success deferred-close-drains-on-shutdown-before-success deferred-close-drains-at-dirty-threshold deferred-close-delete-still-commits-synchronously deferred-close-rename-still-commits-synchronously
```

Expected: both modes pass.

- [ ] **Step 8: Physical benchmark in opt-in mode**

Run:

```powershell
$env:APFSACCESS_DEFER_CLOSE_COMMITS='1'
.\scripts\run_physical_rw_validation.ps1 `
  -Mode Performance `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -FileCount 1000 `
  -LargeFileBytes 1GB `
  -Cleanup
```

Expected:

- small-copy-in files/s improves materially;
- commit count per 1000 files drops materially;
- SHA-256 mismatch count remains zero;
- dirty count settles to zero after idle;
- no Explorer warning appears.

- [ ] **Step 9: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.FsHost src-native/ApfsAccess.ApfsRwEngine
git commit -m "perf: add opt-in close commit coalescing"
```

---

## Task 5: Build A Durable Payload Journal For Deferred Commits

**Risk Level:** High

**Purpose:** Make deferred commits robust enough to consider enabling close coalescing by default. This is the main safety unlock for bigger write-speed gains.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/TransactionManager.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/TransactionManager.cpp`
- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/TransactionManagerTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`

- [ ] **Step 1: Define durable journal record format**

Add records containing:

```text
transaction id
sequence number
operation kind
path
secondary path
offset
length
replace flag
payload spool path or payload inline offset
payload length
payload SHA-256
record CRC/checksum
state: prepared | committed-to-apfs | aborted
```

Expected: every deferred content write can be replayed or rejected deterministically after app restart.

- [ ] **Step 2: Persist payload bytes before acknowledging deferred close**

Before `Close` returns success in deferred mode, ensure:

- hydration file has been flushed with `FlushFileBuffers`;
- journal record has been written;
- journal file has been flushed;
- payload hash has been recorded.

Expected: if the app crashes after close but before APFS checkpoint, recovery has durable payload bytes or can fail closed.

- [ ] **Step 3: Add journal replay on mount**

On mount startup:

- read prepared journal records;
- validate checksum and payload hash;
- stage equivalent metadata mutations;
- provide payload bytes to `MetadataStore`;
- commit to APFS;
- mark records `committed-to-apfs`;
- flush journal state.

Expected: interrupted deferred writes are either replayed into APFS or block RW with a precise recovery reason.

- [ ] **Step 4: Add cleanup and compaction**

After successful APFS commit:

- delete payload spool files for committed records;
- compact journal to keep only unresolved records;
- cap journal size and dirty age to prevent unbounded disk use.

Expected: normal use does not accumulate large files in `AppData` or temp folders.

- [ ] **Step 5: Add fault-injection matrix**

Test crashes/failures at:

- before payload spool flush;
- after payload spool flush, before journal write;
- after journal write, before journal flush;
- after close returns, before APFS commit;
- during replay commit;
- after APFS commit, before journal cleanup.

Expected:

- either APFS shows previous coherent state;
- or replay completes and APFS shows new state;
- or RW mode is blocked with clear recovery reason.

- [ ] **Step 6: Verify**

Run:

```powershell
pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
C:\apfsaccess_native\build\Release\ApfsAccess.FsHost.SemanticsTests.exe flush-finalizes-pending-journal recovery-replays-deferred-payload-journal recovery-blocks-corrupt-deferred-payload-journal
```

Expected: all journal and replay tests pass.

- [ ] **Step 7: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine src-native/ApfsAccess.FsHost
git commit -m "perf: add durable payload journal for deferred writes"
```

---

## Task 6: Promote Safe Close Coalescing From Experimental To Default

**Risk Level:** High

**Purpose:** Turn the proven write-speed win into normal behavior once the durable payload journal exists.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
- Modify: `src/ApfsAccess.Tray/DashboardForm.cs`
- Modify: `src/ApfsAccess.Tray/TrayApplicationContext.cs`
- Modify: relevant tray/service tests if status wording changes

- [ ] **Step 1: Enable deferred close commits by default for pure content writes**

Change the feature flag from opt-in to opt-out:

```text
APFSACCESS_DISABLE_DEFER_CLOSE_COMMITS=1
```

Expected: normal users benefit from close coalescing without hidden setup.

- [ ] **Step 2: Surface "settling writes" accurately**

When dirty deferred writes exist, show a non-alarming state:

```text
RW mounted, finishing writes
```

Use yellow only if the drive is safe but not fully settled. Use red only for recovery/problem states.

Expected: users can distinguish "still flushing" from "read-only" or "broken."

- [ ] **Step 3: Make eject wait for drain with clear progress**

On eject:

- request synchronous drain;
- wait up to the existing commit timeout;
- report success when drive letter disappears;
- if timeout occurs, keep mount state and tell user which process/action is still busy.

Expected: eject remains reliable and does not leave stale drive letters.

- [ ] **Step 4: Verify**

Run:

```powershell
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
dotnet test .\APFSAccess.sln -c Release --filter "FullyQualifiedName~ApfsAccess.Tray.Tests|FullyQualifiedName~ApfsAccess.Service.Tests"
```

Expected:

- tray/service tests pass;
- deferred dirty state is displayed clearly;
- no read-only mislabeling.

- [ ] **Step 5: Physical validation**

Run:

```powershell
.\scripts\run_physical_rw_validation.ps1 `
  -Mode ExplorerWorkflow `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -Cleanup

.\scripts\run_physical_rw_validation.ps1 `
  -Mode Performance `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -FileCount 1000 `
  -LargeFileBytes 1GB `
  -Cleanup
```

Manual checks:

- copy a folder with many small files into the APFS drive;
- copy a large `.exe` into the APFS drive;
- rename files and folders;
- move within APFS;
- move out and back;
- delete directly;
- delete through Explorer recycle behavior;
- eject from tray.

Expected:

- no warning popups;
- dirty state settles;
- eject removes drive letter;
- SHA-256 checks pass.

- [ ] **Step 6: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.FsHost src/ApfsAccess.Tray tests
git commit -m "perf: enable safe close commit coalescing by default"
```

---

## Task 7: Evaluate Rename/Delete Burst Coalescing

**Risk Level:** Experimental-to-high

**Purpose:** Improve workflows like moving folders out/back and deleting trees, which are currently very slow because namespace operations force commits.

**Files:**

- Modify: `src-native/ApfsAccess.FsHost/src/main.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/TransactionManager.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/TransactionManager.cpp`
- Modify: `src-native/ApfsAccess.FsHost/tests/FsHostSemanticsTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`

- [ ] **Step 1: Keep this behind an explicit flag**

Use:

```text
APFSACCESS_EXPERIMENTAL_DEFER_NAMESPACE_COMMITS=1
```

Expected: default rename/delete behavior remains conservative.

- [ ] **Step 2: Add namespace journal records**

Record enough to replay or rollback:

- source path;
- destination path;
- replacement target metadata;
- delete subtree list;
- local rollback file snapshots;
- operation ordering.

Expected: if the app crashes mid-burst, recovery can either replay the namespace change or fail closed.

- [ ] **Step 3: Only defer simple non-replace renames first**

Allow deferral only when:

- rename is within the same mounted APFS volume;
- destination does not exist;
- no open target exists;
- no directory subtree delete is involved.

Expected: simplest move/rename workloads improve before high-risk replace/delete cases are attempted.

- [ ] **Step 4: Add delete-tree coalescing only after rename passes**

Batch delete mutations for a subtree and commit once at idle/eject/flush.

Expected: delete-tree files/s improves while recycle-bin workflow remains clean.

- [ ] **Step 5: Fault-injection tests**

Test:

- crash after local namespace update before journal flush;
- crash after journal flush before APFS commit;
- crash during replay;
- forced APFS commit failure after local namespace update.

Expected: no orphan local state, no missing APFS state, no writable mount with ambiguous namespace.

- [ ] **Step 6: Physical benchmark**

Run with the flag on:

```powershell
$env:APFSACCESS_EXPERIMENTAL_DEFER_NAMESPACE_COMMITS='1'
.\scripts\run_physical_rw_validation.ps1 `
  -Mode Performance `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -FileCount 1000 `
  -LargeFileBytes 1GB `
  -Cleanup
```

Expected:

- `small-move-out-and-back` improves;
- `delete-tree` improves;
- no recycle-bin warning;
- no write-protected warning;
- SHA-256 mismatches remain zero.

- [ ] **Step 7: Decide whether to keep experimental**

Only consider promoting if:

- fault-injection tests are strong;
- manual Explorer testing passes;
- improvement is large enough to justify complexity.

- [ ] **Step 8: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.FsHost src-native/ApfsAccess.ApfsRwEngine
git commit -m "perf: experiment with namespace commit coalescing"
```

---

## Task 8: Design And Prototype Incremental Checkpoints

**Risk Level:** Experimental

**Purpose:** Reduce the amount of metadata rewritten per commit. This is the deeper APFS persistence redesign and should only proceed if telemetry still shows checkpoint bytes dominate after close coalescing.

**Files:**

- Modify: `src-native/ApfsAccess.ApfsRwEngine/include/MetadataStore.h`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/src/MetadataStore.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreConformanceTests.cpp`
- Modify: `src-native/ApfsAccess.ApfsRwEngine/tests/MetadataStoreFaultInjectionTests.cpp`
- Modify: `docs/performance-baselines.md`

- [ ] **Step 1: Measure checkpoint amplification after Tasks 1-6**

Record:

- checkpoint bytes per commit;
- metadata bytes per payload byte;
- time per checkpoint family;
- full checkpoint count per 1000 files.

Expected: decide whether incremental checkpointing is worth the recovery complexity.

- [ ] **Step 2: Add a delta checkpoint format document inside code comments/tests**

The first design must include:

- base full checkpoint XID;
- delta XID;
- changed inode records;
- changed path-index records;
- changed directory links;
- changed object map records;
- changed spaceman allocations/deallocations;
- checksum;
- pointer to previous delta or base full checkpoint.

Expected: reviewer can understand replay order and failure behavior from tests and comments.

- [ ] **Step 3: Add tests before implementation**

Test:

- load full checkpoint only;
- load full checkpoint plus one delta;
- load full checkpoint plus many deltas;
- corrupted delta checksum blocks RW;
- missing delta blocks RW;
- compaction writes new full checkpoint and clears old deltas;
- crash before superblock points to delta leaves previous checkpoint active.

Expected: tests fail before implementation.

- [ ] **Step 4: Implement a prototype behind flag**

Use:

```text
APFSACCESS_EXPERIMENTAL_INCREMENTAL_CHECKPOINTS=1
```

Expected: default full checkpoint path remains untouched.

- [ ] **Step 5: Add periodic full checkpoint compaction**

Starting thresholds:

```text
full checkpoint every 256 committed mutations
full checkpoint when delta chain exceeds 16 MiB
full checkpoint before eject/shutdown
```

Expected: mount time and recovery chain length stay bounded.

- [ ] **Step 6: Verify**

Run:

```powershell
pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
dotnet test .\APFSAccess.sln -c Release --no-restore -m:1
```

Expected: full automated validation passes with default mode, and incremental-specific tests pass with the flag enabled.

- [ ] **Step 7: Physical benchmark**

Run with incremental checkpoints enabled:

```powershell
$env:APFSACCESS_EXPERIMENTAL_INCREMENTAL_CHECKPOINTS='1'
.\scripts\run_physical_rw_validation.ps1 `
  -Mode Performance `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -FileCount 1000 `
  -LargeFileBytes 1GB `
  -Cleanup
```

Expected:

- checkpoint bytes per commit drops significantly;
- small-file writes improve;
- no recovery or integrity regression.

- [ ] **Step 8: Commit checkpoint**

```powershell
git add src-native/ApfsAccess.ApfsRwEngine docs/performance-baselines.md
git commit -m "perf: prototype incremental APFS checkpoints"
```

---

## Task 9: Final Write-Speed Validation And Promotion Decision

**Risk Level:** Release gate

**Purpose:** Decide what should become default, what should stay experimental, and what should be reverted.

**Files:**

- Modify: `docs/performance-baselines.md`
- Modify: `README.md` if user-facing behavior changes
- Modify: release notes only when preparing a release

- [ ] **Step 1: Build final portable**

Run:

```powershell
$env:TEMP='D:\ApfsAccessScratch\Temp'
$env:TMP='D:\ApfsAccessScratch\Temp'
pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
```

Expected:

- build passes;
- root `APFSAccess_Portable.exe` is overwritten.

- [ ] **Step 2: Run automated validation**

Run:

```powershell
pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration Release -RunTests
pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
ctest --test-dir D:\apfsaccess_native\build\Release -C Release --output-on-failure
dotnet test .\APFSAccess.sln -c Release --no-restore -m:1
git diff --check
```

Expected:

- all automated tests pass;
- only known line-ending warnings from `git diff --check`, if any.

- [ ] **Step 3: Run physical correctness validation**

Run:

```powershell
.\scripts\run_physical_rw_validation.ps1 `
  -Mode ExplorerWorkflow `
  -MountRoot E:\ `
  -StatusFile <current-host-status-json> `
  -Cleanup
```

Expected:

- all SHA-256 checks pass;
- no warning popups;
- native RW state stays healthy.

- [ ] **Step 4: Run physical performance validation**

Run:

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

- large write throughput improves from the current baseline;
- many-small-file copy-in improves materially;
- small move out/back improves if namespace coalescing is kept;
- `sha256MismatchCount` remains zero.

- [ ] **Step 5: Manual Explorer smoke**

Manually test:

- copy a large installer `.exe` into APFS;
- copy many small files into APFS;
- move files within APFS;
- move files out and back;
- rename folder and file;
- delete direct;
- recycle-bin delete and restore;
- eject from tray;
- replug and remount.

Expected:

- no write-protected warning;
- no recycle-bin warning;
- dashboard state is accurate;
- drive ejects and remounts correctly.

- [ ] **Step 6: Decide defaults**

Promote only the modes that pass all gates:

- Close coalescing can become default only after durable payload journal replay passes fault tests.
- Namespace coalescing stays experimental unless manual and fault validation is extremely strong.
- Incremental checkpoints stay experimental unless recovery tests are exhaustive and performance gain is large.

- [ ] **Step 7: Commit final plan/baseline update**

```powershell
git add docs/performance-baselines.md docs/superpowers/plans/2026-05-26-apfs-write-speed-breakthrough.md
git commit -m "docs: record APFS write speed validation results"
```

---

## Recommended Execution Order

1. Task 1: observability and baseline.
2. Task 2: central commit policy and no-op commit removal.
3. Task 3: cheaper unavoidable commits.
4. Task 4: opt-in close commit coalescing.
5. Benchmark and manually test. If the speedup is small, inspect telemetry before going deeper.
6. Task 5: durable payload journal.
7. Task 6: promote safe close coalescing to default only if replay is robust.
8. Task 7: namespace coalescing only if move/delete remain painfully slow.
9. Task 8: incremental checkpoints only if checkpoint bytes remain the dominant bottleneck.
10. Task 9: final validation and default/experimental decision.

---

## Expected Best Wins

**Biggest likely win for many small files:** Task 4 plus Task 5, because they stop each file close from forcing a full APFS checkpoint while still preserving replay safety.

**Biggest likely win for large sequential writes:** Task 3 if payload/checkpoint write-call and allocation overhead is meaningful, plus Task 4 if Explorer closes/flushes in chunks.

**Biggest likely win for move/delete workflows:** Task 7, but it is high-risk because namespace changes are user-visible immediately and harder to replay safely.

**Biggest likely win for random 4K writes:** Task 4/5 first, then Task 8 if tiny writes are still paying huge full-checkpoint amplification.

---

## Stop And Revert Conditions

Revert the latest checkpoint immediately if any of these occur:

- SHA-256 mismatch.
- Recycle-bin corruption warning returns.
- Explorer write-protected warning returns.
- Ordinary copy/move/delete causes RW-to-RO fallback.
- Dirty mutations do not settle to zero after idle, flush, eject, or shutdown.
- Eject no longer removes the drive letter.
- App restart after interrupted deferred writes mounts writable with ambiguous state.
- Fault injection shows mixed old/new payload after crash.
- Throughput improves only by weakening explicit flush, eject, or shutdown durability.

