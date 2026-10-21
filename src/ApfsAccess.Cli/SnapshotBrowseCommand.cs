using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Ipc;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal sealed record SnapshotBrowseOptions(string Image, string ContainerId, string VolumeOid,
    string SnapshotXid, string? CopyOut, string? SessionDirectory, string? SnapshotName = null,
    bool CloseOnStdin = false);
internal sealed record SnapshotCopyResult(int Files, int Directories, long Bytes);

internal sealed class SnapshotBrowseDependencies
{
    public Func<SnapshotBrowseOptions, CancellationToken, NativeSnapshotBrowseLaunch> Prepare { get; init; }
        = (o, ct) => o.SnapshotName is null
            ? NativeSnapshotBrowseLaunch.Prepare(o.Image, o.ContainerId, o.VolumeOid, o.SnapshotXid, ct)
            : NativeSnapshotBrowseLaunch.PrepareByName(o.Image, o.ContainerId, o.VolumeOid, o.SnapshotName, ct);
    public Func<FsHostSupervisorOptions, CancellationToken, Task<FsHostSupervisorResult>> Supervise { get; init; }
        = (o, ct) => FsHostSupervisor.RunAsync(o, ct);
    public Func<string, JsonElement?> ReadJson { get; init; } = SnapshotBrowseCommand.ReadJson;
    public Func<string, uint, bool> ProbeMount { get; init; } = SnapshotBrowseCommand.ProbeMount;
    public string? HostPath { get; init; }
    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public Func<CancellationToken, Task> WaitForCloseInput { get; init; }
        = token => SnapshotBrowseCommand.WaitForCloseInputAsync(Console.In, token);
    internal bool UseNameSelectorForTest { get; init; }
}

internal static class SnapshotBrowseCommand
{
    internal const string Usage = "snapshots browse --image ABSOLUTE_FILE --container-id APFS_CONTAINER_ID --volume-oid OID (--snapshot-xid XID | --snapshot-name NAME) [--copy-out NEW_DIRECTORY] [--session-dir NEW_DIRECTORY] [--close-on-stdin] [--json]";

    internal static SnapshotBrowseOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] != "browse") throw new ArgumentException(Usage);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var json = false;
        var closeOnStdin = false;
        for (var i = 1; i < args.Length; ++i)
        {
            var flag = args[i];
            if (flag == "--json" && !json) { json = true; continue; }
            if (flag == "--close-on-stdin" && !closeOnStdin) { closeOnStdin = true; continue; }
            if (flag is not ("--image" or "--container-id" or "--volume-oid" or "--snapshot-xid" or "--snapshot-name" or "--copy-out" or "--session-dir") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(flag, args[i]))
                throw new ArgumentException(Usage);
        }
        if (new[] { "--image", "--container-id", "--volume-oid" }.Any(key => !values.ContainsKey(key)) ||
            values.ContainsKey("--snapshot-xid") == values.ContainsKey("--snapshot-name"))
            throw new ArgumentException(Usage);
        var result = new SnapshotBrowseOptions(values["--image"], values["--container-id"], values["--volume-oid"],
            values.GetValueOrDefault("--snapshot-xid", ""), values.GetValueOrDefault("--copy-out"),
            values.GetValueOrDefault("--session-dir"), values.GetValueOrDefault("--snapshot-name"));
        result = result with { CloseOnStdin = closeOnStdin };
        NativeApfsSnapshotReader.ValidateRequest(result.Image, result.ContainerId, result.VolumeOid);
        if (result.SnapshotName is null && (!ulong.TryParse(result.SnapshotXid, NumberStyles.None, CultureInfo.InvariantCulture, out var xid) || xid == 0 ||
            xid.ToString(CultureInfo.InvariantCulture) != result.SnapshotXid))
            throw new ArgumentException("Use a canonical nonzero snapshot XID.");
        if (result.SnapshotName is { } name && (name.Length is 0 or > 255 || name.Any(c => c < 32 || c == 127)))
            throw new ArgumentException("Use an exact snapshot name without control characters.");
        if (result.CopyOut is not null) NativeSnapshotBrowseLaunch.ValidateLocalPath(result.CopyOut);
        if (result.SessionDirectory is not null) NativeSnapshotBrowseLaunch.ValidateLocalPath(result.SessionDirectory);
        return result;
    }

    internal static async Task<int> RunAsync(string[] args, SnapshotBrowseDependencies? dependencies = null,
        CancellationToken cancellationToken = default)
    {
        if (args is ["browse", "--help"] or ["browse", "help"])
        {
            Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 2, command = "snapshots-browse", success = true,
                usage = Usage, description = "Browse an immutable image snapshot. Copy files from the printed mount path, then press Ctrl+C. --copy-out copies file contents to a new folder and closes automatically. --close-on-stdin closes gracefully on the close command or end of input." }));
            return 0;
        }
        var deps = dependencies ?? new();
        var operationId = Guid.NewGuid().ToString("D");
        var exit = 0;
        string? error = null, session = null, mount = null, lifetime = null;
        NativeSnapshotBrowseLaunch? launch = null;
        Task<FsHostSupervisorResult>? supervision = null;
        FsHostSupervisorResult? terminal = null;
        SnapshotCopyResult? copied = null;
        var ready = false;
        var sessionCreated = false;
        using var supervisorStop = new CancellationTokenSource();
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var closeReaderStop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stopping.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            var options = Parse(args);
            stopping.Token.ThrowIfCancellationRequested();
            session = NativeSnapshotBrowseLaunch.ValidateLocalPath(options.SessionDirectory ??
                Path.Combine(Path.GetTempPath(), "ApfsAccess", "SnapshotBrowse", operationId));
            if (Directory.Exists(session) || File.Exists(session)) throw new ArgumentException("The session directory must be new.");
            if (options.CopyOut is not null)
            {
                var destination = NativeSnapshotBrowseLaunch.ValidateLocalPath(options.CopyOut);
                if (Directory.Exists(destination) || File.Exists(destination) || Inside(destination, session) || Inside(session, destination))
                    throw new ArgumentException("Copy-out needs a new directory outside the session directory.");
            }
            var host = deps.HostPath ?? new[] { Path.Combine(AppContext.BaseDirectory, "ApfsAccess.FsHost.exe"),
                Path.Combine(AppContext.BaseDirectory, "native", "ApfsAccess.FsHost.exe") }.FirstOrDefault(File.Exists)
                ?? throw new FileNotFoundException("Package ApfsAccess.FsHost.exe adjacent to the CLI or in its native directory.");
            if (!File.Exists(host)) throw new FileNotFoundException("The packaged snapshot host is missing.");
            NativeSnapshotBrowseLaunch.ValidateLocalPath(host);
            Directory.CreateDirectory(Path.GetDirectoryName(session)!);
            NativeSnapshotBrowseLaunch.ValidateLocalPath(session);
            if (!CreateDirectoryW(session, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
            sessionCreated = true;
            NativeSnapshotBrowseLaunch.ValidateLocalPath(session);
            mount = Path.Combine(session, "mount");
            lifetime = Path.Combine(session, "lifetime");
            var status = Path.Combine(session, "status.json");
            var gate = Path.Combine(session, "startup.gate");
            var gateToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            using (File.Open(lifetime, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { }
            // A fast child must wait on an existing, unauthorized gate until
            // the supervisor replaces it with the exact parent token.
            using (var pending = File.Open(gate, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                pending.Write("pending"u8);
            launch = deps.Prepare(options, stopping.Token);
            // A controlling app owns the input pipe. EOF also closes the session
            // when that app exits, while this CLI retains teardown ownership.
            var closeInput = options.CloseOnStdin
                ? Task.Run(() => deps.WaitForCloseInput(closeReaderStop.Token))
                : Task.Delay(Timeout.Infinite, closeReaderStop.Token);
            var hostArgs = launch.BuildHostArguments(mount, status, lifetime, gate, gateToken, Environment.ProcessId).ToArray();
            if (options.SnapshotName is not null || deps.UseNameSelectorForTest)
            {
                var selector = Array.IndexOf(hostArgs, "--snapshot-xid");
                hostArgs[selector] = "--snapshot-name";
                hostArgs[selector + 1] = launch.Selection.Name;
            }
            var supervisorOptions = new FsHostSupervisorOptions(host, hostArgs, Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
                lifetime, Path.Combine(session, "launch.json"), Path.Combine(session, "supervisor.json"),
                WorkingDirectory: session, StartupGateFile: gate, StartupGateToken: gateToken, MountPoint: mount, StatusFile: status);
            // The supervisor owns process lifetime and orphan containment.
            supervision = deps.Supervise(supervisorOptions, supervisorStop.Token);
            using (var startup = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token))
            {
                startup.CancelAfter(deps.StartupTimeout);
                try
                {
                    while (true)
                    {
                        startup.Token.ThrowIfCancellationRequested();
                        if (closeInput.IsCompleted)
                        {
                            await closeInput.ConfigureAwait(false);
                            throw new OperationCanceledException("Snapshot session closed before mounted readiness.");
                        }
                        if (supervision.IsCompleted) throw new IOException("Snapshot host exited before mounted readiness.");
                        var owner = deps.ReadJson(supervisorOptions.LaunchRecordPath);
                        var state = deps.ReadJson(status);
                        if (owner is {} owned && state is {} current &&
                            TryHostPid(owned, out var pid) && launch.MatchesReadyStatus(current, pid) &&
                            deps.ProbeMount(mount, launch.ExpectedVolumeSerial)) break;
                        await Task.Delay(50, startup.Token).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (!stopping.IsCancellationRequested && !closeInput.IsCompleted)
                { throw new TimeoutException("The exact immutable snapshot did not become mounted and ready."); }
            }
            ready = true;
            File.WriteAllText(Path.Combine(session, "ready.json"), JsonSerializer.Serialize(new {
                operationId, mountPoint = mount, selection = launch.Selection, immutableSnapshot = true, mountedReadinessProven = true,
                copyOut = options.CopyOut }, JsonOptions));
            Console.Error.WriteLine($"Snapshot {launch.Selection.SnapshotXid} ({launch.Selection.Name}) is read-only at {mount}");
            if (options.CopyOut is not null)
            {
                using var copying = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token);
                var copy = CopyOutAsync(mount, options.CopyOut, copying.Token);
                var finished = await Task.WhenAny(copy, supervision, closeInput).ConfigureAwait(false);
                if (finished == supervision || finished == closeInput)
                {
                    copying.Cancel();
                    try { await copy.ConfigureAwait(false); } catch (OperationCanceledException) { }
                    if (finished == closeInput)
                    {
                        await closeInput.ConfigureAwait(false);
                        throw new OperationCanceledException("Snapshot copy was cancelled by its controlling app.");
                    }
                    throw new IOException("Snapshot host exited during copy-out; the destination may be partial.");
                }
                copied = await copy.ConfigureAwait(false);
            }
            else
            {
                Console.Error.WriteLine("Copy files from this directory. Press Ctrl+C to close the snapshot.");
                var stopped = Task.Delay(Timeout.Infinite, stopping.Token);
                var finished = await Task.WhenAny(stopped, supervision, closeInput).ConfigureAwait(false);
                if (finished == supervision)
                    throw new IOException("The snapshot host exited before the browse session was closed.");
                if (finished == closeInput) await closeInput.ConfigureAwait(false);
            }
        }
        catch (ArgumentException ex) { exit = 2; error = ex.Message; }
        catch (FileNotFoundException ex) { exit = 3; error = ex.Message; }
        catch (Win32Exception ex) { exit = 3; error = ex.Message; }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException) { exit = 4; error = ex.Message; }
        catch (Exception ex) { exit = 5; error = ex.Message; }
        finally
        {
            closeReaderStop.Cancel();
            try
            {
                if (lifetime is not null) File.Delete(lifetime);
            }
            catch (Exception ex) { supervisorStop.Cancel(); exit = 5; error = $"Cannot signal snapshot close: {ex.Message}"; }
            if (supervision is not null)
            {
                try
                {
                    // Teardown is deliberately not cancelled by Ctrl+C.
                    terminal = await supervision.ConfigureAwait(false);
                    if (!terminal.Success || !terminal.Evidence.OriginalHostIdentityAbsent || !terminal.Evidence.MountAbsenceProven)
                    { exit = 5; error = "Snapshot teardown was not proven. Retained supervisor evidence identifies any containment owner."; }
                }
                catch (Exception ex) { exit = 5; error = $"Snapshot supervision failed: {ex.Message}"; }
            }
            if (mount is not null && (supervision is null || terminal?.Evidence.MountAbsenceProven == true))
            {
                // Never recursively remove a mount or a partial copy destination.
                try { Directory.Delete(mount, recursive: false); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
            launch?.Dispose();
            Console.CancelKeyPress -= cancel;
        }
        var code = exit switch { 0 => ApfsOperationCodes.OperationSucceeded, 2 => ApfsOperationCodes.InvalidArguments,
            3 => ApfsOperationCodes.ServiceUnavailable, 4 => ApfsOperationCodes.Timeout, _ => ApfsOperationCodes.OperationFailed };
        var result = new { schemaVersion = PipeSchemaVersions.Schema2, command = "snapshots-browse", operationId,
            success = exit == 0, exitCode = exit, code, errorCode = exit == 0 ? null : code, error,
            mountPoint = mount, sessionDirectory = session, mountedReadinessProven = ready, selection = launch?.Selection,
            copyOut = copied, teardownProven = terminal?.Evidence.MountAbsenceProven == true && terminal.Evidence.OriginalHostIdentityAbsent,
            supervisorEvidence = session is null ? null : Path.Combine(session, "supervisor.json") };
        if (sessionCreated && session is not null && Directory.Exists(session))
        {
            try { File.WriteAllText(Path.Combine(session, "result.json"), JsonSerializer.Serialize(result, JsonOptions)); }
            catch (Exception ex) { Console.Error.WriteLine($"Cannot save browse result: {ex.Message}"); }
        }
        Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        return exit;
    }

    internal static async Task WaitForCloseInputAsync(TextReader input, CancellationToken token)
    {
        const string command = "close";
        const string invalid = "Snapshot close input must be 'close' followed by a newline or end of input.";
        var character = new char[1];
        var offset = 0;
        var carriageReturn = false;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            if (await input.ReadAsync(character.AsMemory(), token).ConfigureAwait(false) == 0)
            {
                if (offset is 0 or 5) return;
                throw new ArgumentException(invalid);
            }
            var value = character[0];
            if (value == '\n' && offset == command.Length) return;
            if (!carriageReturn && value == '\r' && offset == command.Length)
            { carriageReturn = true; continue; }
            if (carriageReturn || offset >= command.Length || value != command[offset])
                throw new ArgumentException(invalid);
            ++offset;
        }
    }

    private static bool Inside(string path, string directory)
        => string.Equals(path, directory, StringComparison.OrdinalIgnoreCase) ||
           path.StartsWith(directory.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static bool TryHostPid(JsonElement root, out int pid)
    {
        pid = 0;
        return root.TryGetProperty("supervisionProven", out var supervised) && supervised.ValueKind == JsonValueKind.True &&
            root.TryGetProperty("hostIdentityCaptured", out var captured) && captured.ValueKind == JsonValueKind.True &&
            root.TryGetProperty("hostPid", out var value) && value.TryGetInt32(out pid) && pid > 0;
    }

    internal static JsonElement? ReadJson(string path)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length > 4 * 1024 * 1024) throw new InvalidDataException("Snapshot status exceeds its size bound.");
            using var json = JsonDocument.Parse(file);
            return json.RootElement.Clone();
        }
        catch (Exception ex) when (ex is IOException or JsonException) { return null; }
    }

    internal static bool ProbeMount(string mount, uint expectedSerial)
    {
        using var root = CreateFileW(mount, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        var name = new StringBuilder(128);
        return !root.IsInvalid && GetVolumeInformationByHandleW(root, IntPtr.Zero, 0, out var serial, out _, out var flags,
            name, (uint)name.Capacity) && name.ToString() == "APFS" && (flags & 0x80000) != 0 && serial == expectedSerial;
    }

    internal static async Task<SnapshotCopyResult> CopyOutAsync(string mount, string destination, CancellationToken token)
    {
        destination = NativeSnapshotBrowseLaunch.ValidateLocalPath(destination);
        if (Directory.Exists(destination) || File.Exists(destination) || Inside(destination, mount))
            throw new ArgumentException("Copy-out requires a new destination outside the snapshot mount.");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        NativeSnapshotBrowseLaunch.ValidateLocalPath(destination);
        // CreateDirectoryW gives exclusive ownership, unlike CreateDirectory's
        // existing-directory success. Never merge or overwrite user output.
        if (!CreateDirectoryW(destination, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var pending = new Stack<(string Source, string Target)>();
        pending.Push((mount, destination));
        int files = 0, directories = 1;
        long bytes = 0;
        while (pending.TryPop(out var pair))
        {
            token.ThrowIfCancellationRequested();
            foreach (var entry in Directory.EnumerateFileSystemEntries(pair.Source))
            {
                token.ThrowIfCancellationRequested();
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Copy-out stopped at a link or reparse point; the destination is partial.");
                var target = Path.Combine(pair.Target, Path.GetFileName(entry));
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (!CreateDirectoryW(target, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    ++directories; pending.Push((entry, target));
                }
                else
                {
                    await using var input = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous);
                    await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous);
                    await input.CopyToAsync(output, token).ConfigureAwait(false);
                    await output.FlushAsync(token).ConfigureAwait(false);
                    bytes = checked(bytes + output.Length); ++files;
                }
            }
        }
        return new(files, directories, bytes);
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, IntPtr volume, uint volumeSize,
        out uint serial, out uint maxComponent, out uint flags, StringBuilder filesystem, uint filesystemSize);
}
