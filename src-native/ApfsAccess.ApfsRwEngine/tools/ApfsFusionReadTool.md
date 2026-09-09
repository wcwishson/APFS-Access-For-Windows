# Reading a supported pair of Fusion images

`ApfsFusionReadTool` inspects ordinary Windows image files and reads one exactly
selected, unencrypted APFS volume across two members. It supports the narrow
clean-anchor, empty-cache, main-checkpoint layout. It does not establish general
Fusion, writable Fusion, mounted-volume, physical-device or macOS acceptance.

Use `ApfsFusionReadTool --help` for a short reminder. Run `--mode inspect --image
D:\images\main.img` separately for each member. Each response contains an opaque
`identity` string. Copy that complete string into the corresponding binding below;
re-inspect if a member has been replaced. Inspection identifies the host file; it
does not discover or approve the APFS roles, UUIDs, checkpoint or store ranges.

In PowerShell, prepare the complete selection using values established for your
supported image pair:

```powershell
$selection = @(
  '--member-a', 'D:\images\main.img',
  '--member-b', 'D:\images\tier2.img',
  '--identity-a', '<complete main identity from inspect>',
  '--identity-b', '<complete tier2 identity from inspect>',
  '--role-a', 'main', '--role-b', 'tier2',
  '--store-id-a', 'apfs-store:main', '--store-id-b', 'apfs-store:tier2',
  '--store-offset-a', '<main offset in bytes>',
  '--store-offset-b', '<tier2 offset in bytes>',
  '--store-size-a', '<main store size in bytes>',
  '--store-size-b', '<tier2 store size in bytes>',
  '--container-uuid', '<32 lowercase hexadecimal characters>',
  '--fusion-uuid', '<32 lowercase hexadecimal characters>',
  '--checkpoint-xid', '<exact decimal checkpoint>',
  '--role-convention', 'linux-apfs-last-byte-low-bit'
)
& .\ApfsFusionReadTool.exe @selection --mode catalog

$volume = @('--volume-uuid', '<exact UUID from catalog>', '--volume-oid', '<exact OID>')
& .\ApfsFusionReadTool.exe @selection @volume --mode enumerate --directory 2
& .\ApfsFusionReadTool.exe @selection @volume --mode lookup --directory 2 --name 'Café.txt'
```

The `a`/`b` input order may be reversed when each member's identity, role, store ID
and range move together. Store IDs must be distinct. There is no automatic member,
checkpoint or volume fallback. Unknown profiles or inconsistent selections fail.

For file bytes, use `--mode read --inode <OID> --offset <byte offset> --length
<byte count> --binary-stdout`, together with the selection and volume arguments.
For attribute bytes, use `--mode xattr` and add `--xattr com.apple.ResourceFork`
or another exact ASCII attribute name. Unicode file lookup names are supported.
Read stdout is raw binary; capture it with a binary-safe process API such as
Python `subprocess`, or PowerShell 7.4+ native stdout redirection. Older PowerShell
redirection may transcode binary output. JSON modes write newline-terminated JSON.
Diagnostics go to stderr. EOF can produce fewer bytes, including zero bytes.

Always check the process exit code before accepting captured output. A failed or
cancelled command may have emitted a partial prefix, which must be discarded.
Both member leases stay held while read bytes are emitted, including a blocked
pipe. Windows writer, rename and delete admission is excluded until release.

| Control | Default | Maximum |
| --- | ---: | ---: |
| `--length` | Required for reads | 16 MiB |
| `--operation-timeout-ms` | 10,000 | 30,000; minimum 100 |
| `--budget-reads` | 10,000 | 100,000 |
| `--budget-bytes` | 64 MiB | 256 MiB |
| `--budget-records` | 100,000 | 1,000,000 |
| `--budget-material` | 64 MiB | 256 MiB |
| `--repeat` (enumerate only) | 1 | 64 |
| `--interval-ms` (enumerate only) | 0 | 1,000 |

An enumeration result is capped at 1 MiB and total stdout at 64 MiB. The watchdog
requests I/O cancellation at the deadline and forces process termination after
an additional one-second grace interval if cleanup or output is still blocked.
These are application bounds, subject to OS scheduling. Broken/full pipes cannot
produce a successful exit. A launcher can also pass `--cancel-handle <decimal>`
for an explicitly inherited manual-reset Windows event; signaling it cancels
the command. Ctrl+C requests cancellation when a console control event is delivered.

Exit codes: `0` success, `2` invalid options or limits, `3` acquisition/read failure,
`6` cancellation/timeout, `8` output failure. This command has no write mode.

The focused test exporter creates synthetic member images. Run the integration
script with a private D: `--root`, `--tool`, and `--fixture-builder`. Its results
describe these local file-backed fixtures only.
