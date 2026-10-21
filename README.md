# APFS Access for Windows

APFS Access lets Windows mount Apple APFS drives in File Explorer. Plug in an APFS USB drive, start the app, and supported APFS volumes appear as normal drive letters in This PC.

The app is designed for practical day-to-day use: browse folders, open files, copy files out, and, when the volume passes the built-in safety checks, use normal Explorer file operations such as creating folders, copying files in, renaming, moving, and deleting.

In APFS Access 1.0.6, supported ordinary, unencrypted APFS data volumes mount seamlessly with full read and write support. Drive letters can be customized directly from the dashboard with automatic remounting, and the app checks for updates automatically once weekly.

## Quick Start

1. Go to the [latest release](https://github.com/wcwishson/APFS-Access-For-Windows/releases/latest).
2. Download `APFS Access.exe`.
3. Double-click it.
4. Approve the Windows administrator prompt.
5. If prompted, let APFS Access install its required components.
6. Plug in your APFS drive.
7. Open This PC and use the new APFS drive letter.

The portable launcher automatically unpacks its bundled files, checks for WinFsp and the Microsoft Visual C++ runtime, and starts the tray app.

## What You Should See

APFS Access opens a small dashboard and also runs from the Windows system tray.

- The dashboard groups volumes under their physical drive, partition, and APFS container. Each supported volume gets its own drive letter in This PC.
- Green means healthy read/write.
- Yellow means read-only but usable.
- Orange means mounted but attention may be needed.
- Blue means a file operation or pending writes are still finishing.
- Red means APFS Access found a problem or recovery-blocked state.
- Gray means starting, idle, or no APFS drive is mounted.
- Select a volume to open it, mount or eject it, retry with `Fix`, or read its details. Container actions operate on the volumes in that container.
- `Start with Windows` launches APFS Access automatically after sign-in.
- `Start minimized` keeps the dashboard hidden at startup while leaving the tray icon available.
- `Check for updates` downloads and verifies the latest `APFS Access.exe`; installation happens only after a second confirmation and a safe drive eject.
- Closing the dashboard keeps APFS Access running in the tray.
- Left-click the tray icon to reopen the dashboard.
- Right-click the tray icon to eject APFS drives or quit the app.

When a supported APFS volume is mounted, it appears in This PC with a normal drive letter. Use it from Explorer, file dialogs, terminals, and other Windows apps.

## Everyday Use & Advanced Capabilities

### Common Operations
- **Browse & Open:** Browse APFS folders and open files directly in Windows File Explorer.
- **Full Read/Write Support:** Create folders, copy files in/out, rename, move, and delete on supported APFS data volumes.
- **Custom Drive Letters:** Pick your preferred drive letter (D:, E:, G:) directly from the dashboard; changes apply instantly via auto-remount with in-use safety warnings.
- **Safe Eject & Quit:** Click Eject before unplugging. All pending writes and journal transactions flush cleanly before release.
- **Fix & Refresh:** Use Fix when a drive is safely ejected but still connected, or needs a safe remount into read/write mode.

### Advanced APFS Features
- **Encrypted APFS Volume Unlock:** Register encrypted APFS volumes and click **Unlock…** to enter your passphrase or recovery key. The volume mounts directly into Windows File Explorer, and you can **Lock** it when done.
- **APFS Snapshots:** Open **Volume snapshots** to view historical snapshots, browse them read-only in File Explorer without touching the drive, copy out earlier file versions, or create/delete snapshots.
- **Apple Fusion Drives:** Register multi-tier Fusion drive pairs (SSD + HDD) into unified APFS containers with pooled storage capacity.
- **macOS System & Data Firmlinks:** Use **System Data Browse** to seamlessly navigate macOS Catalina+ split System and Data volumes as a unified filesystem.
- **Volume & Container Management:** Rename volumes, configure storage quotas and reserve space, create/delete volumes, and format or resize containers directly from the dashboard.
- **Case-Sensitive Volumes:** Full support for case-sensitive APFS volumes with Unicode normalization and collision-safe Windows name mapping.

## Automation

Use `--cli` as the portable's first argument for scripts and AI agents. It forwards the normal CLI's arguments, JSON output, and exit code without opening the dashboard. Help and version need no service:

```powershell
& ".\APFS Access.exe" --cli --help
& ".\APFS Access.exe" --cli --version
& ".\APFS Access.exe" --cli list --no-start-service
& ".\APFS Access.exe" --cli status --no-start-service
& ".\APFS Access.exe" --cli mount --device-id "<device-id>" --volume-id "<volume-id>" --mode read-only --no-start-service
& ".\APFS Access.exe" --cli eject --device-id "<device-id>" --volume-id "<volume-id>" --no-start-service
& ".\APFS Access.exe" --cli query --operation-id "<operation-id>" --no-start-service
```

Use IDs returned by `list`. `--no-start-service` requires an existing service; omit it when automatic service startup is wanted. The click-run package's `ApfsAccess.Cli.exe` accepts the same arguments without `--cli`.

Where help lists them, use `--timeout-ms N`, `--dry-run`, or `--human`. Check both JSON and exit code. Query unfinished work by operation ID before retrying; a timeout or cancellation can leave recovery pending.

For a supported APFS image file, `snapshots list` shows its snapshots and
`snapshots browse` opens one by its name or XID in a read-only folder. Copy files
from that folder and press Ctrl+C to close it, or use `--copy-out` to copy file
contents to a new folder and close automatically. Run
`ApfsAccess.Cli.exe snapshots browse --help` for the required image and volume
options. Browsing leaves the image unchanged; it does not enable backup-volume
writes or automatically delete old snapshots.

For image diagnostics, `verify --help` lists the required volume options. Add
`--retained-from-xid START_XID` to check a retained checkpoint chain through the
selected current checkpoint. The JSON report identifies the covered history;
this read-only check does not certify all file contents or repair the image.

## Image Management

For a registered ordinary, unencrypted APFS Data image, open **Volume snapshots**, then **Refresh inventory**. Use **Create**, **Delete selected**, **Browse selected**, or **Copy out selected**; finish with **Close snapshot**. **Recover pending work** handles interrupted changes. CLI equivalents include `snapshot-list` and `snapshots create`, `delete`, or `recover`; use current inventory IDs.

Container mount, unmount, verify, and `Fix` report per-volume results. Supported offline images also offer volume-label and quota/reserve changes, plus volume create, delete, resize, format, or erase. Review the selected volume and plan before confirming. `container-manage plan` and `container-manage apply` select one member; atomic changes across all members are unavailable.

Image management is off by default. Administrators must register the image, configure a permanent `Service.ManagementJournalRoot` outside it, and enable the needed `EnableImageSnapshots`, `EnableImageManagementMutations`, or `EnableImageResizeFormat` options. Keep the management and recovery folders between runs. These options do not enable physical-drive writes.

Availability depends on the selected image and its recorded history. Close its mounts before offline management and refresh inventory after changes. Volume-label changes require intact registration and recovery records. Resize supports specific layouts and sizes; review the result of the selected image's checks before applying a change.

Keep backups of important data and eject mounted volumes before disconnecting their storage.

## Requirements

- Windows 10 or Windows 11, 64-bit.
- Administrator permission when starting the app.
- WinFsp runtime.
- Microsoft Visual C++ Redistributable x64.

`APFS Access.exe` checks the last two requirements for you and can install them automatically. If automatic installation does not work, install them manually and then run APFS Access again:

- [WinFsp](https://winfsp.dev/rel/)
- [Microsoft Visual C++ Redistributable x64](https://aka.ms/vs/17/release/vc_redist.x64.exe)

## Download Choices

Most people should use:

- `APFS Access.exe`

Advanced users may also download:

- `APFSAccess-<version>-win-x64-click-run.zip`

The zip contains the extracted app folder, helper scripts, and `README_RUN.txt`. It is useful if you want to inspect or run the app without the single-file portable wrapper.

Automatic installation is available when you run `APFS Access.exe`. Zip users can use the same dashboard button to open the latest release page and update manually.

## Safety Notes

APFS Access has write support, but it is deliberately guarded.

- A new physical volume starts read-only until write access is enabled through `Fix`, an explicit read/write mount request, or existing configuration. Unsupported layouts remain read-only with an explanation.
- Ordinary unencrypted Data images support admitted case-sensitive layouts. Windows applications may mishandle names differing only in capitalization.
- Registered single-volume, single-key software-encrypted images use Unlock/Lock. Automatic discovery still skips encrypted physical drives; per-file encryption is outside this profile.
- System, sealed, backup, and Fusion layouts have separate requirements; ordinary-image write support does not apply automatically.
- Offline volume-label changes require a registered ordinary image and intact ownership and recovery history. Missing or stale records can prevent a change.
- Resize supports specific layouts and sizes. Requests outside the supported layout are refused.
- Failed validation or pending recovery blocks writes. Keep management files and inspect the current result before retrying.
- Windows sparse, hard-link, and clone controls depend on the provider. Optional `standard-share` supports admitted ordinary images up to 256 MiB, local-only and one session per Windows sign-in. Use `APFS Access.exe --cli standard-share --help`; default WinFsp behavior is unchanged.
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

If mounting fails, select the affected volume and click `Copy info`. Include the full error, your Windows version (`winver`), the WinFsp version, and whether another APFS driver is installed when [reporting the problem](https://github.com/wcwishson/APFS-Access-For-Windows/issues). A mount helper exit and a startup timeout have different causes; the error alone does not mean the disk needs formatting.

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

Prepare the pinned SMBLibrary source described in
[its build instructions](third_party/SMBLibrary/BUILD.md), then build the app:

```powershell
pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64 -SMBLibrarySourceRoot "<path-to-pinned-SMBLibrary-source>"
```

Run tests:

```powershell
dotnet test APFSAccess.sln -c Debug --no-restore -m:1 -p:SMBLibrarySourceRoot="<path-to-pinned-SMBLibrary-source>"
ctest --test-dir build/ApfsAccess.ApfsRwEngine -C Debug --output-on-failure
ctest --test-dir build/ApfsAccess.FsHost -C Debug --output-on-failure
```

Main project layout:

- `src/ApfsAccess.Tray` - tray app and user-facing status.
- `src/ApfsAccess.Service` - device discovery and mount orchestration.
- `src/ApfsAccess.Cli` - structured command-line control for automation.
- `src/ApfsAccess.Backend.Native` - native backend integration.
- `src-native/ApfsAccess.FsHost` - WinFsp mount host.
- `src-native/ApfsAccess.ApfsRwEngine` - APFS metadata/read-write engine.

Deeper technical notes live in `docs/`.
