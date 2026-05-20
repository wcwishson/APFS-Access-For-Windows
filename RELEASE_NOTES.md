# APFS Access 1.0.0

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

## Validation

The 1.0.0 release was validated with:

- Managed test suite: `dotnet test APFSAccess.sln -c Debug --no-restore -m:1`
- Native APFS engine CTest suite: `ctest --test-dir build/ApfsAccess.ApfsRwEngine -C Debug --output-on-failure`
- Native FsHost CTest suite: `ctest --test-dir build/ApfsAccess.FsHost -C Debug --output-on-failure`

## Appendix: Technical Notes

APFS Access uses a background service to discover APFS volumes, a tray app for user status/control, and a native WinFsp host to expose APFS volumes as Windows drive letters. The native write path is fail-closed: commit readiness, recovery status, unsupported APFS features, and validation gates are checked before writable mode is allowed. When those checks do not pass, the mount is downgraded to read-only where possible.
