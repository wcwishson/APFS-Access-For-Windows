# Native Mount Host

## Location

- `src-native/ApfsAccess.FsHost`

## Current role (phase 2 read path + experimental overlay/native write)

1. Accepts service launch contract:
   - `--device <path>`
   - `--volume <name-or-id>`
   - `--mount <X:>`
   - `--readonly` or `--readwrite`
   - `--write-backend <Disabled|Overlay|Native>`
   - `--write-crash-replay-mode <FailClosed|ReplayIfSafe>`
   - `--write-integrity-check-on-mount <true|false>`
   - `--allow-raw-physical-write`
   - `--lifetime-file <path>`
2. Stays alive while lifetime file exists.
3. Exits when service removes lifetime file (or on process termination).
4. Supports service timeout kill fallback.

## Current mount behavior

1. Mounts the requested drive letter through WinFsp callbacks (no `subst`).
2. Implements read operations:
   - `GetVolumeInfo`, `GetFileInfo`, `ReadDirectory`, `Open`, `Read`, `Cleanup`, `Close`
3. Write behavior:
   - `--readonly`: write operations return write-protected status mappings.
   - `--readwrite --write-backend Overlay`: write operations are handled against a temporary overlay layer (`Create`, `Write`, `SetFileSize`, `Rename`, delete flow).
   - `--readwrite --write-backend Native`: write operations use the same Explorer-facing flow plus native mutation planning/journaling and flush-time commit scaffolding.
4. Overlay mode does not mutate APFS media and is not persisted across sessions.
5. Native mode now persists staged payload bytes and native checkpoint state through the self-developed RW engine; image-backed validation is green, while real-device validation is still pending.
6. Native metadata bootstrap reconciles persisted RW state against superblock checkpoint xid. Divergence marks recovery-required and keeps commit path blocked (`RecoveryMode` telemetry) with explicit `recoveryReason`.
7. Serves callbacks from the native APFS engine path:
   - directory enumeration and metadata lookup from committed inode/tree state
   - file payload hydration from native committed extent reads and staged native-write payloads
8. In readwrite mode, FsHost performs RW-engine bootstrap checks against the device path and logs container readiness warnings when APFS metadata bootstrap is unavailable.
9. In readwrite mode, mutating callbacks emit transaction journal records under `%TEMP%\ApfsAccess\rw-journal` (begin/commit/abort + mutation intent metadata).
10. Status sidecar telemetry includes `nativeWriteSafetyState`, `lastRecoveryAction`, and `dirtyTransactionCount`.

This provides direct Explorer mount semantics, with conservative safety gates and recovery reconciliation controlling native write activation.

## Phase-A/Phase-B write scaffolding currently implemented

1. FsHost accepts write arguments:
   - `--readwrite`
   - `--write-backend <Disabled|Overlay|Native>`
   - `--write-safety-level <mode>`
   - `--write-commit-timeout <seconds>`
   - `--write-crash-replay-mode <FailClosed|ReplayIfSafe>`
   - `--write-integrity-check-on-mount <true|false>`
   - `--allow-raw-physical-write`
2. Current implementation enables `--readwrite` for `--write-backend Overlay` and `--write-backend Native`.
3. Dedicated native RW engine skeleton exists under:
   - `src-native/ApfsAccess.ApfsRwEngine`
   - modules: `BlockDevice`, `MetadataStore`, `TransactionManager`
