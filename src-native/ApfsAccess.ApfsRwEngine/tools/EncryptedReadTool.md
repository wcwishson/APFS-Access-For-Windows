# Private encrypted image inspection and exact reads

`ApfsEncryptedReadTool` owns one source lease, credential receive, production
`ApfsEncryptedReadSession::Unlock`, metadata/read operation, and close. It never
creates a persistent unlocked mount. The supported engine profile is software
ONEKEY generation zero with header-bearing virtual filesystem trees. Unknown
crypto classes, hardware-bound profiles, compression and per-file keys remain
explicit refusals. Only ordinary image files on a local fixed drive are admitted. The tool rejects
reserved DOS names and pins every ancestor directory without following reparse
points. It also checks the opened file belongs to a fixed local volume. Paths
through directory symbolic links or junctions must be replaced with direct paths.
There is no physical-device, mount, mutation or credential-in-argument option.

First obtain the public Windows file identity for an **independently known exact
container range**:

```text
ApfsEncryptedReadTool --mode source --image D:\images\sample.img --store-offset 0 --store-size 524288
```

This reports source metadata only. Preserve its `sourceId`. A subsequent operation acquires a new lease
and requires an exact identity match. The source ID contains the observer's
Windows volume/file ID, file size and last-write time plus exact offset/size.
It is a public binding token, not a cryptographic authenticity claim. Each actual
lease also receives a fresh opaque random revision token used internally by the
production session; file times are never treated as that revision.

For a known exact volume OID, `--mode selectors --volume-oid [decimal]
--bag-length includes-header` also requires the image and exact store range.
It reuses the production checkpoint, OMAP, APSB and keybag validation chain to
return public UUID/OID/XID selectors and user UUIDs in a `Locked` JSON result.
It takes no credential and grants no unlock, mount or write authority. Special
keybag object OIDs can be zero; they are taken from validated headers and must
compare exactly. Physical block addresses are never substituted for them.

Launch inspection with public selectors, using a protected parent-created pipe
for stdin (the brackets below stand for public values):

```text
ApfsEncryptedReadTool --mode inspect --image D:\images\sample.img
  --store-offset [decimal] --store-size [decimal] --source-id [sourceId]
  --container-uuid [32hex] --volume-uuid [32hex] --volume-oid [decimal]
  --checkpoint-xid [decimal] --user-uuid [32hex]
  --container-bag-oid [decimal] --container-bag-xid [decimal]
  --volume-bag-oid [decimal] --volume-bag-xid [decimal]
  --bag-length includes-header
```

Supply every identity, checkpoint and bag expectation from independent evidence.
Neither bag OID/XID nor length semantics are guessed from physical addresses.
`--bag-length` accepts only `includes-header` or `entries-only`; the engine still
validates the selected convention. UUIDs are opaque APFS bytes in hex order, not
Windows GUID field ordering. Numeric fields use unsigned decimal with no signs.

Inspection stdout is one JSON object with `mode: inode-metadata`, inode IDs,
sizes and crypto IDs. It contains no file bytes. For an exact binary read use
the same selectors with `--mode read --inode [id] --offset [byte offset]
--length [byte count] --binary-stdout`. Stdout must be redirected to a pipe or
caller-owned file and contains only bytes from production `ReadFile`. The maximum
single read is 1 MiB. No EOF clipping: an over-EOF range fails, a zero-byte read
at EOF succeeds. Byte count and exit status are both part of the caller's result
contract. A failed output write/cancellation can leave a partial caller-owned
destination; do not accept it as a completed read.

`--mode metadata --inode [id]` returns scalar inode facts, including mode, size,
and internal flags. `--mode xattr --inode [id] --xattr [ASCII name]
--binary-stdout` returns the original embedded attribute bytes. Both use the
same protected credential channel, source binding, close and output contract.
Symlinks are metadata only: their bounded filesystem-owned embedded target can
be read as `com.apple.fs.symlink`; file reads and path traversal do not follow
it. Apple's exact reserved root/private-directory entries are validated and
excluded from the user namespace. Nonempty private directories remain refused.

The image read projection admits `INODE_NO_RSRC_FORK` on regular files,
directories and symlinks. It adapts exact bounded data-only xfield framing to
the existing record codec and admits only extent flag `FEXT_CRYPTO_ID_IS_TWEAK`
besides zero. ONEKEY `CRYPTO_SW_ID` is accepted only as a 24-byte no-key zero
state or the observed version-5/minor-0/class-3/revision-1 meta state. Other
classes, wrapped-key lengths and flags remain refused. Historical ENC_ROLLED
alone is supported; active rolling state or OMAP crypto generations are refused.
These are local read profiles; writer and catalog admission is unchanged.

Stderr carries only fixed public JSON states/failure names on a best-effort basis.
Use separate stdout/stderr handles; merged streams are not a binary read result.
All stdout writes are checked and unbuffered, including source metadata. The
operation watchdog remains active through unwinding and final diagnostics.
A blocked diagnostic can cause cancellation; diagnostics may be absent on I/O
failure. Public-option failures before deadline validation use a 30-second bound. `AwaitingCredential`
means the source lease is already held. `Closed` follows key/session destruction
and release of the source. Failure exit also unwinds the owned lease. No state
implies a mount or an unlock that survives the process.

## Protected stdin contract for a managed launcher

1. Create an anonymous byte pipe in the actual parent process with a restrictive
   DACL. The receiver verifies pipe owner=current user and accepts allow ACEs
   only for that user, SYSTEM and the current logon SID. Null, permissive,
   unknown/callback/object ACLs are refused. The ordinary Windows per-user token
   default DACL passed this integration gate; do not assume every service token's
   default DACL will pass. A pipe created by a grandparent/relay is refused.
2. Use `STARTUPINFOEX` with an explicit inherited handle list. Give only the read
   endpoint to the child as stdin, keep only the write endpoint in the parent,
   close the parent's redundant reader immediately, and do not create competing
   readers or expose an endpoint name. The receiver clears inheritance and owns
   closing its input handle. Its checks do not retroactively revoke handles a
   trusted parent already duplicated to another process.
3. Write exactly eight header bytes: ASCII `APC1`, followed by a four-byte unsigned
   little-endian payload length. Write exactly 1..1024 encoded credential bytes,
   then **close every parent writer** to signal EOF. No NUL, newline convention,
   text normalization, BOM, terminator, retry, second frame or trailing byte.
   Choose credential encoding before transport according to independent APFS
   evidence; the native tool consumes bytes and does not guess an encoding.
4. Keep credential bytes in owned secure storage in the launcher too. Avoid
   managed strings, interpolation, environment variables and plaintext files.
   The Python integration harness uses public synthetic vectors only; its
   ordinary Python bytes are not a production managed credential-capture design.
5. Drain stdout/stderr concurrently. `--credential-timeout-ms` defaults to 5000;
   allowed range is 100..30000. The deadline covers header, payload and EOF.
   `--operation-timeout-ms` defaults to 30000, same range. The optional
   `--cancel-handle [unsigned decimal]` is a public inherited manual-reset event
   handle with SYNCHRONIZE and EVENT_QUERY_STATE (0x0001) access, included in the
   explicit handle list. The tool validates manual-reset event type using
   NtQueryEvent; unsupported query behavior, auto-reset events, non-event handles
   and aliases of standard handles are refused before credential acquisition. Signal
   it to request orderly cancellation; continue draining and wait for exact exit.
   The child duplicates the event, closes the inherited handle, and never resets
   or signals the parent's event. CNG calls finish before cancellation is observed
   at the next engine boundary. Console control events also request cancellation.
6. Treat success as one completed inspection/read. For a later mount integration,
   a durable backend owner must retain the same source lease, cancellation token,
   cumulative read budget, attempt budget and session through all reads and drain
   callbacks before `Close`. This command's successful exit cannot be reused as
   a mount capability or cached unlocked key. The current process creates one
   attempt budget and makes one unlock attempt; process restart is not an
   account lockout. A backend supporting retries must retain its budget.

`EncryptedReadTransport.h` provides the move-only credential result and the owned
container-relative source. It contains no APFS parser. The shared
`WindowsImageLease` factors the observer's existing same-handle read/identity/
write-delete-exclusion implementation; observer path admission, error text and
exit code 2 on lease refusal are preserved. Strict ancestor and fixed-volume
checks apply only to the encrypted tool.
The source adapter owns this lease and one cumulative read/materialization
budget for the whole session. Use it through the serialized session, not through
concurrent standalone budget mutations. There is no name-based pipe connection
or arbitrary named endpoint admission in this tool.

## Ownership and exposure limits

The entire bounded input frame, including malformed input and any extra byte,
is read directly into locked `SecureBytes`. Only the validated payload is copied
into a second locked owner. RAII wipes both on every handled receive path. The
credential is explicitly cleared immediately after `Unlock`, and session close
wipes owned keys before success publication. The tool wipes its own returned
plaintext vector on handled success/failure and orderly stack unwinding.

Successful binary stdout is intentionally **caller-owned plaintext**. The tool
cannot wipe the parent's buffers, output files, Windows pipe storage or copies
the parent makes. Locking/wiping covers owned allocations, not CNG internals,
registers, crash dumps, forced termination, power loss, hibernation or OS/admin
compromise. A console-close deadline may terminate a process before unwinding
finishes. No cleanup handler is promised after a forced exit, and this tool
does not modify dump/pagefile/working-set/system policy. Dump inspection and
sleep/resume are later integration gates.

The Windows share-mode lease excludes ordinary existing/new write and delete
handles and file replacement, and all reads stay on the acquired file object.
This is the observer's OS file-lease model, not a claim of authentication against
hostile kernel/storage changes or previously established writable mappings.
Source checksums and UUID checks cannot authenticate malicious or replayed media.
The synthetic gate does not establish real fixture acceptance, hardware
encryption, mounted behavior or service/GUI credential capture.

Exit codes: 0 success; 2 public CLI/selectors; 3 source lease/scope/identity;
4 credential framing/pipe/deadline; 5 production unlock/profile refusal;
6 cancellation; 7 file/metadata read; 8 output; 9 fixed internal failure.

## Maintained focused integration

The CMake patch adds the native tool, reusable transport library, synthetic
fixture executable, and opt-in `EncryptedReadToolIntegration` / `EncryptedReadToolReview` tests. Set
`APFSACCESS_ENCRYPTED_READ_INTEGRATION_ROOT` to a private artifact directory to
register it. The Python harness accepts `--root`, `--tool`, `--fixture-builder`
and `--vectors`; it creates real Windows child pipes and never mounts anything.
The fixture builder reuses the existing public encrypted vectors and
`TestFixtureBuilder`; there is no second APFS parser or test-only unlock path.
Production targets never define `APFSACCESS_CRYPTO_TESTING`.

The review suite requires permission to create a directory symbolic link for its
local-only reparse test; production reading needs no symlink-creation permission.
The observer lease test also accepts `--writer-admission` after a private image
path: expected process exit is 2 with the original observer acquisition message.

Live integration must rebuild C++ engine users together: current Fusion fields
change `NxSuperblock` / checkpoint layouts. Do not mix old frozen541 C++ objects
with new headers. The private review build retains current routing/Fusion and
encrypted-session cleanup sources, reuses frozen third-party C objects only,
and does not extend this single-image tool to encrypted Fusion reads.

## Opt-in real fixture reads

`tests/EncryptedRealFixtureIntegration.py` accepts `--fixtures`, `--root`,
`--tool`, and optional `--baseline-tool` / `--profile`. Keep the acquired images,
pinned licenses/commit/source notes and evidence outside the repository on D:.
The harness checks pinned SHA-256 before and after reading, passes only public
fixture credentials through protected stdin, compares exact independent expected
file bytes and range hashes, and checks wrong credentials, trailing framing,
keybag identity, EOF, root flags and metadata-only symlink handling. Evidence
retains hashes and public selectors/status, not credentials, keys or file bytes.
It exercises the production parser/unlock/read chain on the actual images.
Synthetic framing/generation/refusal vectors remain separate evidence. A real
image read result grants no encrypted writer, physical mount or macOS acceptance.
