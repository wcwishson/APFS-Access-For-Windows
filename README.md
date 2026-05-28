# APFS Access for Windows

APFS Access lets Windows mount Apple APFS drives in File Explorer. Plug in an APFS USB drive, start the app, and supported APFS volumes appear as normal drive letters in This PC.

The app is designed for practical day-to-day use: browse folders, open files, copy files out, and, when the volume passes the built-in safety checks, use normal Explorer file operations such as creating folders, copying files in, renaming, moving, and deleting.

## Quick Start

1. Go to the [latest release](https://github.com/wcwishson/APFS-Access-For-Windows/releases/latest).
2. Download `APFSAccess_Portable.exe`.
3. Double-click it.
4. Approve the Windows administrator prompt.
5. If prompted, let APFS Access install its required components.
6. Plug in your APFS drive.
7. Open This PC and use the new APFS drive letter.

The portable launcher automatically extracts the app under `%LOCALAPPDATA%\ApfsAccessPortable`, checks for WinFsp and the Microsoft Visual C++ runtime, and starts the tray app.

## What You Should See

APFS Access opens a small dashboard and also runs from the Windows system tray.

- The dashboard lists mounted APFS volumes with the physical drive name, volume name, drive letter, and health state.
- Green means healthy read/write.
- Yellow means read-only but usable.
- Orange means mounted but attention may be needed.
- Red means APFS Access found a problem or recovery-blocked state.
- Gray means starting, idle, or no APFS drive is mounted.
- The dashboard has `Open`, `Eject`, `Fix`, and `Details` actions for each volume.
- Closing the dashboard keeps APFS Access running in the tray.
- Left-click the tray icon to reopen the dashboard.
- Right-click the tray icon to eject APFS drives or quit the app.

When a supported APFS volume is mounted, it appears in This PC with a normal drive letter. Use it from Explorer, file dialogs, terminals, and other Windows apps.

## Everyday Use

Common supported operations:

- Browse APFS folders in File Explorer.
- Open files directly from the APFS drive.
- Copy files from APFS to Windows.
- Create files and folders on writable APFS mounts.
- Copy files onto writable APFS mounts.
- Rename, move, cut/paste, and delete files on writable APFS mounts.
- Eject APFS mounts from the dashboard or tray before unplugging the drive.
- Use `Fix` when a drive is read-only, safely ejected but still connected, or needs a safe refresh/remount.
- Use `Details` when you want to see why a drive is read-only or degraded.

APFS Access is conservative. If a volume is encrypted, special-purpose, uses unsupported APFS features, or fails a write-safety check, the app keeps it read-only instead of risking damage.

Writable APFS operations are improving, especially folders with many small files, but writes are still slower than reads in the current native engine. For important data, keep a backup and eject from APFS Access before unplugging.

## Requirements

- Windows 10 or Windows 11, 64-bit.
- Administrator permission when starting the app.
- WinFsp runtime.
- Microsoft Visual C++ Redistributable x64.

`APFSAccess_Portable.exe` checks the last two requirements for you and can install them automatically. If automatic installation does not work, install them manually and then run APFS Access again:

- [WinFsp](https://winfsp.dev/rel/)
- [Microsoft Visual C++ Redistributable x64](https://aka.ms/vs/17/release/vc_redist.x64.exe)

## Download Choices

Most people should use:

- `APFSAccess_Portable.exe`

Advanced users may also download:

- `APFSAccess-<version>-win-x64-click-run.zip`

The zip contains the extracted app folder, helper scripts, and `README_RUN.txt`. It is useful if you want to inspect or run the app without the single-file portable wrapper.

## Safety Notes

APFS Access has write support, but it is deliberately guarded.

- Encrypted APFS volumes are skipped.
- APFS system, preboot, recovery, VM, sealed, snapshot-heavy, case-sensitive, or otherwise unsupported volumes may be read-only.
- If recovery or validation checks fail, writable mode is blocked and the app falls back to read-only when possible.
- Always eject from the tray before unplugging a drive.
- Keep backups of important APFS drives. This is filesystem software, and backups are still the only real safety net.

## Troubleshooting

If no drive appears:

1. Check the dashboard status and tray icon tooltip.
2. Make sure the app was allowed to run as administrator.
3. Install WinFsp and the Microsoft Visual C++ runtime if prompted.
4. Unplug and replug the APFS drive.
5. Try the dashboard `Fix` action.
6. Right-click the tray icon, choose Quit, then start APFS Access again.

If the drive appears read-only:

- The app could read the volume but did not consider writable mode safe for that volume.
- You can still copy files from APFS to Windows.
- Try the dashboard `Fix` action. It will refresh and remount the drive if writable mode is safe.
- Try another APFS data volume if you still need write access.

If eject does not finish:

- Close Explorer windows, terminals, Office files, previews, and other apps using the APFS drive.
- Click `Eject` again from the dashboard or tray.
- If Windows still holds the drive busy, quit APFS Access from the tray before unplugging.

If Windows SmartScreen warns about the app:

- This is expected for a new unsigned open-source release.
- Choose More info, then Run anyway if you trust the release you downloaded from this repository.

## For Developers

Build the app:

```powershell
pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
```

Run tests:

```powershell
dotnet test APFSAccess.sln -c Debug --no-restore -m:1
ctest --test-dir build/ApfsAccess.ApfsRwEngine -C Debug --output-on-failure
ctest --test-dir build/ApfsAccess.FsHost -C Debug --output-on-failure
```

Main project layout:

- `src/ApfsAccess.Tray` - tray app and user-facing status.
- `src/ApfsAccess.Service` - device discovery and mount orchestration.
- `src/ApfsAccess.Backend.Native` - native backend integration.
- `src-native/ApfsAccess.FsHost` - WinFsp mount host.
- `src-native/ApfsAccess.ApfsRwEngine` - APFS metadata/read-write engine.

Deeper technical notes live in `docs/`.
