# APFS Access Release Notes

## APFS Access 1.0.3

APFS Access 1.0.3 improves everyday use with a new dashboard, stronger write-path hardening, more reliable eject/fix behavior, and a first throughput optimization pass.

### Download

Most users should download:

- `APFSAccess_Portable.exe`

Advanced users may also download the click-run zip for the same release.

### Quick Start

1. Download `APFSAccess_Portable.exe`.
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

- `APFSAccess_Portable.exe`

Advanced users may also download the click-run zip for the same release.

### Quick Start

1. Download `APFSAccess_Portable.exe`.
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

- `APFSAccess_Portable.exe`

Advanced users may also download:

- `APFSAccess-1.0.0-win-x64-click-run.zip`

## Quick Start

1. Download `APFSAccess_Portable.exe`.
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
