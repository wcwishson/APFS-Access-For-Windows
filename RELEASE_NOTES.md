# APFS Access Release Notes

## APFS Access 1.0.6

APFS Access 1.0.6 is a major feature release that directly tackles the primary limitations of 1.0.5 and earlier versions. It introduces encrypted APFS volume support (passwords and recovery keys), APFS snapshot browsing and management, Apple Fusion drive pairing, volume management (renaming, quotas, resize), macOS System/Data firmlink navigation, an interactive visual disk-and-container hierarchy, automatic drive-letter remounting with in-use safety warnings, and background weekly update checks.

### Download

Most users should download:

- `APFS Access.exe` (Single-file portable application)

Advanced users can also download `APFSAccess-1.0.6-win-x64-click-run.zip` for the unpackaged folder.

---

### Breaking Past 1.0.5 Limitations

In previous releases, encrypted volumes, snapshots, Fusion drives, case-sensitive layouts, and volume modifications were strictly unsupported or read-only. Version 1.0.6 introduces first-class support for these scenarios:

1. **Encrypted APFS Volume Support (Unlock & Lock):**
   - In 1.0.5, encrypted APFS volumes were completely skipped and could not be accessed.
   - In 1.0.6, you can now register and unlock encrypted APFS volumes using your passphrase or Apple recovery key.
   - An interactive password prompt allows one-click **Unlock…**, mounting the volume directly into Windows File Explorer with guarded credentials, and **Lock** when you are finished.
   - Secure Key Management allows reviewing and rotating passphrases and recovery credentials safely.

2. **APFS Volume Snapshots (Browse, Copy Out, Create, Delete):**
   - In 1.0.5, snapshots were not supported.
   - In 1.0.6, the new **Volume snapshots** workflow lets you browse past volume snapshots in read-only Windows folders without modifying the drive.
   - Copy individual files or folders out of any historical snapshot, create new point-in-time snapshots, delete unwanted snapshots, or recover pending snapshot work.

3. **Apple Fusion Drive Support:**
   - In 1.0.5, Apple Fusion drives (split SSD and HDD tiers) were unsupported.
   - In 1.0.6, you can now register Apple Fusion storage pairs into unified APFS containers, allowing Windows to mount and browse Fusion drives with pooled storage recognition.

4. **Case-Sensitive & Unicode APFS Volume Support:**
   - In 1.0.5, case-sensitive volumes were often refused or restricted.
   - In 1.0.6, case-sensitive APFS volumes are fully supported with robust Unicode normalization (UTF-8 / UTF-16) and Windows collision handling.

5. **macOS System & Data Firmlink Navigation:**
   - On modern macOS installations (Catalina and later), files are split across read-only System and writable Data volumes connected by "firmlinks".
   - Version 1.0.6 introduces **System Data Browse**, linking the System and Data volumes into a seamless, unified browsing experience in File Explorer.

6. **Volume & Container Management (Rename, Quotas, Resize, Format):**
   - You can now manage volumes directly from the dashboard: rename volumes, adjust storage quotas and reserve space, create new volumes, delete old volumes, and format or resize image containers with built-in safety confirmations.

---

### Everyday User Experience & Front-End Enhancements

- **Interactive Visual Drive Hierarchy:** The Dashboard organizes your storage into an intuitive visual tree showing physical drives, partitions, APFS containers, and individual volumes, with live capacity bars displaying used and free space.
- **Drive Letter Customization with Instant Auto-Remount:** You can now change the preferred drive letter for any volume directly in the dashboard. Saving a new letter automatically unmounts and remounts the volume immediately onto your chosen drive letter.
- **Smart In-Use Safety Warning:** If files are open or File Explorer is browsing a volume when changing its drive letter, the app warns you and lets you choose:
  - **Queue Remount:** Remounts automatically as soon as applications finish using the drive.
  - **Cancel:** Reverts and keeps the current drive letter without interruption.
- **Automatic Weekly Update Checks:** APFS Access now checks GitHub in the background once weekly for new releases and notifies you when an update is available.
- **Direct GitHub Access Button:** A dedicated **GitHub** button right in the dashboard footer opens the project repository and releases in one click.
- **Theme Selection (Follow Windows, Light, Dark):** Choose your preferred appearance from the dashboard dropdown or the tray context menu; your preference is remembered across restarts.
- **Multi-Volume Container Co-Mounting:** APFS containers with multiple data volumes now cleanly co-mount sibling volumes, ensuring ejecting or remounting one volume never suppresses its siblings.
- **Durable Read/Write Performance:** High-throughput, low-latency file operations (copy, move, rename, delete) on supported ordinary APFS data volumes with safe checkpoint commits and write-drain guarantees.
- **Clean Safe Eject & Graceful Quit:** Ejection and application shutdown wait until all pending writes and background tasks are fully flushed, preventing filesystem inconsistencies.
- **Windows Recycle Bin Integration:** Deleting files to the Windows Recycle Bin preserves security descriptor metadata needed for standard recycling.
- **Clearer Error Guidance:** The dashboard details pane explains exact mounting states and includes a one-click **Copy info** button for easy reporting.

---

### Everyday Use

- **Green** means healthy read/write.
- **Yellow** means read-only but fully accessible for reading and copying files out.
- **Blue** means file operations or data synchronizations are finishing.
- **Red** means an issue was detected or recovery is required.
- **Fix** performs a safe refresh and remounts the volume if read/write mode is safe.
- **Eject** flushes all pending data and safely unmounts the drive before disconnecting.
- Closing the dashboard minimizes the app to the Windows system tray. Right-click the tray icon to access themes, eject drives, or quit.

### Known Limits

- Windows SmartScreen may show a one-time prompt on first launch for new releases (click "More info" -> "Run anyway").
- Physical system drives with T2/Secure Enclave hardware-locked encryption require macOS for key escrow; software-encrypted images and standard APFS passwords/recovery keys are supported.
- Always eject drives from the dashboard or tray icon before unplugging.

## APFS Access 1.0.5

APFS Access 1.0.5 improves day-to-day reliability, control, and performance for supported writable APFS data volumes. It also makes read-only states clearer and gives scripts and AI agents a complete command-line interface.

This revised 1.0.5 build adds in-app updating. People using the original 1.0.5 build need to download `APFS Access.exe` manually one more time; later updates can be checked and installed from the dashboard.

### Download

Most users should download:

- `APFS Access.exe`

Advanced users may also download the click-run zip for the same release.

### Quick Start

1. Download `APFS Access.exe`.
2. Double-click it and approve the administrator prompt.
3. Let APFS Access install WinFsp and the Microsoft Visual C++ runtime if requested.
4. Plug in an APFS drive.
5. Use the dashboard or open This PC and use the mounted drive letter.

### What Changed

- Improved responsiveness for common copy, move, rename, delete, and many-small-file workloads while preserving guarded commits and recovery behavior.
- Removed an arbitrary age limit that could make an otherwise healthy validated volume fall back to read-only.
- Improved mount, fix, eject, quit, and restart lifecycle handling so stale hosts and stale drive state are less likely to survive an operation.
- Supported drives on a fresh installation can reach read/write mode after passing the current-volume safety checks; old machine-specific validation history is no longer required.
- Added `ApfsAccess.Cli.exe` with structured commands for status, discovery, mounting, fixing, ejecting, and quitting.
- Made read-only status consistent: the tray icon is yellow and user-facing text says `read-only` instead of abbreviations.
- Added `Start with Windows` and `Start minimized` dashboard options.
- Added `Check for updates`. The first click downloads and verifies the latest launcher; a second confirmation safely ejects APFS drives, installs it, and restarts the app.

Representative same-drive medians for 1,000 files of 16 KiB each:

| Workload | 1.0.4 | Revised 1.0.5 |
| --- | ---: | ---: |
| Copy in | 11.964 files/s | 54.622 files/s |
| Move out and back | 5.906 files/s | 24.788 files/s |
| Delete | 6.365 files/s | 52.129 files/s |

These workload-specific runs completed with zero SHA-256 mismatches.

### User-Facing Behavior

- Green means the volume is healthy and mounted read/write.
- Yellow means the volume is mounted read-only but remains usable for reading and copying files out.
- `Fix` performs a safe refresh/remount when writable mode can be restored in software.
- `Eject` drains pending work, removes the mount, and verifies that APFS Access has released it.
- Closing the dashboard leaves the tray app running; use the tray `Quit` command to stop APFS Access.

### Known Limits

- No signed installer yet, so Windows SmartScreen may warn on first run.
- Encrypted APFS volumes are not supported.
- Case-sensitive volumes and some APFS roles or feature combinations remain read-only or unsupported.
- Writable mode remains conservative and can still fall back to read-only when a safety or recovery check fails.
- Write speed varies with the drive, USB adapter, Windows storage stack, workload, and APFS layout.

## APFS Access 1.0.4

APFS Access 1.0.4 is a performance-focused release for writable APFS drives. It keeps the same dashboard and tray workflow from 1.0.3, while making common write-heavy Explorer operations feel smoother, especially folders with many small files.

### Download

Most users should download:

- `APFS Access.exe`

Advanced users may also download the click-run zip for the same release.

### Quick Start

1. Download `APFS Access.exe`.
2. Double-click it.
3. Approve the administrator prompt.
4. Let the app install WinFsp and the Microsoft Visual C++ runtime if it asks.
5. Plug in an APFS drive.
6. Use the APFS Access dashboard or open This PC and use the mounted drive letter.

### What Changed

- Improved write responsiveness for folders with many small files.
- Reduced repeated APFS metadata work during ordinary copy, move, rename, and delete flows.
- Improved native write-path observability so future performance work can target the slowest parts of the pipeline more directly.
- Kept the conservative write-safety behavior from earlier releases: unsupported or uncertain APFS volumes still mount read-only instead of risking the drive.
- Kept the experimental prepared-payload write-through path disabled by default because the safer default path performed better in real Explorer-style use.

### User-Facing Behavior

- Writable APFS volumes should feel more responsive during many-small-file operations than 1.0.3.
- Large writes are improved in the safe default path, but APFS write speed is still not close to read speed yet.
- Dashboard states, `Open`, `Eject`, `Fix`, and `Details` work the same way as 1.0.3.
- Eject APFS drives from the dashboard or tray before unplugging.

### Known Limits

- No signed installer yet, so Windows SmartScreen may warn on first run.
- Encrypted APFS volumes are not supported.
- Some APFS roles and feature combinations are mounted read-only or skipped.
- Writable mode remains conservative and may fall back to read-only.
- Write performance still depends heavily on the APFS drive, USB adapter, Windows storage stack, and the current native engine path.

### Appendix: Technical Notes

This release reduces commit and metadata amplification in the native APFS write path and adds better performance counters around commit origins, payload writes, checkpoint work, and mounted-volume benchmarks. More aggressive write-back behavior remains experimental until it can preserve crash recovery and explicit flush/eject safety.

## APFS Access 1.0.3

APFS Access 1.0.3 improves everyday use with a new dashboard, stronger write-path hardening, more reliable eject/fix behavior, and a first throughput optimization pass.

### Download

Most users should download:

- `APFS Access.exe`

Advanced users may also download the click-run zip for the same release.

### Quick Start

1. Download `APFS Access.exe`.
2. Double-click it.
3. Approve the administrator prompt.
4. Let the app install WinFsp and the Microsoft Visual C++ runtime if it asks.
5. Plug in an APFS drive.
6. Use the APFS Access dashboard or open This PC and use the mounted drive letter.

### What Changed

- Added a dashboard window that opens with the app and lists APFS volumes by physical drive, volume name, drive letter, and health state.
- Added color-coded drive states: green for healthy read/write, yellow for read-only, orange for attention-needed, red for problem/recovery, and gray for idle/starting.
- Added per-volume dashboard actions: `Open`, `Eject`, `Fix`, and `Details`.
- Left-clicking the tray icon now opens the dashboard. Closing the dashboard keeps the app running in the tray.
- `Fix` can safely refresh and remount recoverable APFS volumes, including read-only mounts and safely-ejected-but-still-connected volumes.
- `Eject` and tray eject labels include the physical drive and APFS volume name when available.
- Improved mount lifecycle behavior so service-level eject removes the stale drive letter and refresh can remount the still-connected drive.
- Hardened write behavior around copy-on-write file updates, rename/replace rollback, fragmented extents, torn-write recovery, and recovery diagnostics.
- Improved APFS read/write responsiveness by reducing repeated metadata work, trimming status refresh churn, and making native commit handling more efficient.
- Improved handling for everyday file workflows including Office-style saves, recycle-bin deletes, many-small-file folders, long paths, and large file roundtrips.

### User-Facing Behavior

- `Healthy read/write` means normal Explorer write operations are enabled.
- `Read-only` means APFS Access can read the volume but did not currently consider writes safe.
- `Needs attention` means an operation is settling, a warning is present, or a safe refresh may help.
- `Problem` means APFS Access found an error or recovery-blocked state.
- `Fix` first tries a safe refresh/remount. If software recovery cannot restore the drive, use the dashboard details and unplug/replug guidance.
- Eject APFS drives from the dashboard or tray before unplugging.

### Known Limits

- No signed installer yet, so Windows SmartScreen may warn on first run.
- Encrypted APFS volumes are not supported.
- Some APFS roles and feature combinations are mounted read-only or skipped.
- Writable mode remains conservative and may fall back to read-only.
- Performance depends on the APFS drive, USB adapter, Windows storage stack, and the current native engine path.

### Appendix: Technical Notes

APFS Access uses a background service to discover APFS volumes, a tray/dashboard app for user status/control, and a native WinFsp host to expose APFS volumes as Windows drive letters. The native write path is fail-closed: commit readiness, recovery status, unsupported APFS features, and safety gates are checked before writable mode is allowed. When those checks do not pass, the mount is downgraded to read-only where possible.

## APFS Access 1.0.2

APFS Access 1.0.2 improves everyday use with a new dashboard, stronger write-path hardening, and more reliable eject/fix behavior.

### Download

Most users should download:

- `APFS Access.exe`

Advanced users may also download the click-run zip for the same release.

### Quick Start

1. Download `APFS Access.exe`.
2. Double-click it.
3. Approve the administrator prompt.
4. Let the app install WinFsp and the Microsoft Visual C++ runtime if it asks.
5. Plug in an APFS drive.
6. Use the APFS Access dashboard or open This PC and use the mounted drive letter.

### What Changed

- Added a dashboard window that opens with the app and lists APFS volumes by physical drive, volume name, drive letter, and health state.
- Added color-coded drive states: green for healthy read/write, yellow for read-only, orange for attention-needed, red for problem/recovery, and gray for idle/starting.
- Added per-volume dashboard actions: `Open`, `Eject`, `Fix`, and `Details`.
- Left-clicking the tray icon now opens the dashboard. Closing the dashboard keeps the app running in the tray.
- `Fix` can safely refresh and remount recoverable APFS volumes, including read-only mounts and safely-ejected-but-still-connected volumes.
- `Eject` and tray eject labels include the physical drive and APFS volume name when available.
- Improved mount lifecycle behavior so service-level eject removes the stale drive letter and refresh can remount the still-connected drive.
- Hardened write behavior around copy-on-write file updates, rename/replace rollback, fragmented extents, torn-write recovery, and recovery diagnostics.
- Improved compatibility with everyday Explorer workflows such as Office-style saves, recycle-bin operations, long paths, many small files, and large-file roundtrips.

### User-Facing Behavior

- `Healthy read/write` means normal Explorer write operations are enabled.
- `Read-only` means APFS Access can read the volume but did not currently consider writes safe.
- `Needs attention` means an operation is settling, a warning is present, or a safe refresh may help.
- `Problem` means APFS Access found an error or recovery-blocked state.
- `Fix` first tries a safe refresh/remount. If software recovery cannot restore the drive, use the dashboard details and unplug/replug guidance.
- Eject APFS drives from the dashboard or tray before unplugging.

### Known Limits

- No signed installer yet, so Windows SmartScreen may warn on first run.
- Encrypted APFS volumes are not supported.
- Some APFS roles and feature combinations are mounted read-only or skipped.
- Writable mode remains conservative and may fall back to read-only.
- Performance depends on the APFS drive, USB adapter, Windows storage stack, and the current native engine path.

### Appendix: Technical Notes

APFS Access uses a background service to discover APFS volumes, a tray/dashboard app for user status/control, and a native WinFsp host to expose APFS volumes as Windows drive letters. The native write path is fail-closed: commit readiness, recovery status, unsupported APFS features, and safety gates are checked before writable mode is allowed. When those checks do not pass, the mount is downgraded to read-only where possible.

## APFS Access 1.0.0

APFS Access 1.0.0 is the first public release of APFS Access for Windows. It packages the tray app, background service, native APFS reader/writer, and WinFsp mount host into a portable Windows download.

## Download

Most users should download:

- `APFS Access.exe`

Advanced users may also download:

- `APFSAccess-1.0.0-win-x64-click-run.zip`

## Quick Start

1. Download `APFS Access.exe`.
2. Double-click it.
3. Approve the administrator prompt.
4. Let the app install WinFsp and the Microsoft Visual C++ runtime if it asks.
5. Plug in an APFS drive.
6. Open This PC and use the APFS drive letter.

## What Is Included

- Portable one-file launcher.
- Automatic prerequisite check for WinFsp and Microsoft Visual C++ Redistributable x64.
- System tray app with mount status, eject, and quit actions.
- Automatic APFS physical-drive discovery.
- Explorer drive-letter mounting through WinFsp.
- Read support for supported APFS data volumes.
- Guarded write support for supported APFS data volumes that pass safety checks.
- Read-only fallback when writable mode is not safe.

## User-Facing Behavior

- `mounted RO` means the APFS volume is available read-only.
- `mounted RW` means normal Explorer write operations are enabled.
- Unsupported or risky volumes stay read-only when possible.
- Encrypted APFS volumes are skipped.
- Eject APFS drives from the tray before unplugging.

## Known Limits

- No signed installer yet, so Windows SmartScreen may warn on first run.
- Encrypted APFS volumes are not supported.
- Some APFS roles and feature combinations are mounted read-only or skipped.
- Writable mode is intentionally conservative and may fall back to read-only.
- Performance depends on the APFS drive, USB adapter, Windows storage stack, and the current native engine path.

## Appendix: Technical Notes

APFS Access uses a background service to discover APFS volumes, a tray app for user status/control, and a native WinFsp host to expose APFS volumes as Windows drive letters. The native write path is fail-closed: commit readiness, recovery status, unsupported APFS features, and safety gates are checked before writable mode is allowed. When those checks do not pass, the mount is downgraded to read-only where possible.
