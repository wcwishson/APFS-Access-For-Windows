using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli;

internal sealed record SystemDataBrowseOptions(string Image, string ContainerId, string GroupUuid,
    string SystemOid, string DataOid, string CheckpointXid, string? SessionDirectory, string? CopyOut, bool CloseOnStdin);

internal sealed class SystemDataBrowseDependencies
{
    public Func<SystemDataBrowseOptions, CancellationToken, NativeSystemDataBrowseLaunch> Prepare { get; init; }
        = (o, ct) => NativeSystemDataBrowseLaunch.Prepare(o.Image, o.ContainerId, o.GroupUuid, o.SystemOid, o.DataOid, o.CheckpointXid, ct);
    public Func<FsHostSupervisorOptions, CancellationToken, Task<FsHostSupervisorResult>> Supervise { get; init; } = FsHostSupervisor.RunAsync;
    public Func<string, JsonElement?> ReadJson { get; init; } = SnapshotBrowseCommand.ReadJson;
    public Func<string, uint, bool> ProbeMount { get; init; } = SnapshotBrowseCommand.ProbeMount;
    public Func<CancellationToken, Task> WaitForClose { get; init; } = ct => SnapshotBrowseCommand.WaitForCloseInputAsync(Console.In, ct);
    public string? HostPath { get; init; }
    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

internal static class SystemDataBrowseCommand
{
    internal const string Usage = "system-data browse --image ABSOLUTE_FILE --container-id apfs-container:LOWERCASE32HEX --group-uuid LOWERCASE32HEX --system-oid OID --data-oid OID --checkpoint-xid XID [--session-dir NEW_DIRECTORY] [--copy-out NEW_DIRECTORY] [--close-on-stdin] [--json]";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    internal static SystemDataBrowseOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] != "browse") throw new ArgumentException(Usage);
        var values = new Dictionary<string, string>(StringComparer.Ordinal); var close = false; var json = false;
        for (var i = 1; i < args.Length; ++i)
        {
            var flag = args[i];
            if (flag == "--json" && !json) { json = true; continue; }
            if (flag == "--close-on-stdin" && !close) { close = true; continue; }
            if (flag is not ("--image" or "--container-id" or "--group-uuid" or "--system-oid" or "--data-oid" or "--checkpoint-xid" or "--session-dir" or "--copy-out") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(flag, args[i])) throw new ArgumentException(Usage);
        }
        if (new[] { "--image", "--container-id", "--group-uuid", "--system-oid", "--data-oid", "--checkpoint-xid" }.Any(k => !values.ContainsKey(k))) throw new ArgumentException(Usage);
        var o = new SystemDataBrowseOptions(values["--image"], values["--container-id"], values["--group-uuid"], values["--system-oid"], values["--data-oid"],
            values["--checkpoint-xid"], values.GetValueOrDefault("--session-dir"), values.GetValueOrDefault("--copy-out"), close);
        NativeSystemDataBrowseLaunch.ValidateSelection(o.Image, o.ContainerId, o.GroupUuid, o.SystemOid, o.DataOid, o.CheckpointXid);
        if (o.SessionDirectory is not null) NativeSnapshotBrowseLaunch.ValidateLocalPath(o.SessionDirectory);
        if (o.CopyOut is not null) NativeSnapshotBrowseLaunch.ValidateLocalPath(o.CopyOut);
        return o;
    }

    internal static async Task<int> RunAsync(string[] args, SystemDataBrowseDependencies? dependencies = null, CancellationToken token = default)
    {
        if (args is ["browse", "--help"] or ["browse", "help"])
        {
            Console.WriteLine(JsonSerializer.Serialize(new { command = "system-data-browse", success = true, usage = Usage,
                capability = NativeSystemDataBrowseLaunch.Capability, description = "Browse a paired ordinary System/Data image read-only. Native table admission is required. Mac corpus validation remains unverified." }, JsonOptions)); return 0;
        }
        var deps = dependencies ?? new(); var operationId = Guid.NewGuid().ToString("D");
        string? session = null, mount = null, lifetime = null, error = null; var exit = 0; var ready = false; var sessionOwned = false;
        NativeSystemDataBrowseLaunch? launch = null; Task<FsHostSupervisorResult>? supervision = null; FsHostSupervisorResult? terminal = null;
        SnapshotCopyResult? copied = null;
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var supervisorStop = new CancellationTokenSource(); using var inputStop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stopping.Cancel(); }; Console.CancelKeyPress += cancel;
        try
        {
            var o = Parse(args); stopping.Token.ThrowIfCancellationRequested();
            session = NativeSnapshotBrowseLaunch.ValidateLocalPath(o.SessionDirectory ?? Path.Combine(Path.GetTempPath(), "ApfsAccess", "SystemData", operationId));
            if (Directory.Exists(session) || File.Exists(session)) throw new ArgumentException("The System/Data session directory must be new.");
            if (o.CopyOut is not null && (Directory.Exists(o.CopyOut) || File.Exists(o.CopyOut) || Inside(o.CopyOut, session) || Inside(session, o.CopyOut)))
                throw new ArgumentException("Copy-out requires a new directory outside the session.");
            var host = deps.HostPath ?? new[] { Path.Combine(AppContext.BaseDirectory, "ApfsAccess.FsHost.exe"), Path.Combine(AppContext.BaseDirectory, "native", "ApfsAccess.FsHost.exe") }.FirstOrDefault(File.Exists)
                ?? throw new FileNotFoundException("The packaged System/Data native host is missing.");
            NativeSnapshotBrowseLaunch.ValidateLocalPath(host);
            if (!File.Exists(host)) throw new FileNotFoundException("The packaged System/Data native host is missing.");
            Directory.CreateDirectory(Path.GetDirectoryName(session)!); NativeSnapshotBrowseLaunch.ValidateLocalPath(session);
            if (!CreateDirectoryW(session, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error()); sessionOwned = true;
            mount = Path.Combine(session, "mount"); lifetime = Path.Combine(session, "lifetime");
            var status = Path.Combine(session, "status.json"); var gate = Path.Combine(session, "startup.gate");
            var gateToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            using (File.Open(lifetime, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { }
            // The pending file is not authorization; the supervisor supplies
            // the exact token only after establishing the child owner.
            using (var pending = File.Open(gate, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                pending.Write("pending"u8);
            launch = deps.Prepare(o, stopping.Token);
            var close = o.CloseOnStdin ? Task.Run(() => deps.WaitForClose(inputStop.Token)) : Task.Delay(Timeout.Infinite, inputStop.Token);
            var hostArgs = launch.BuildHostArguments(mount, status, lifetime, gate, gateToken, Environment.ProcessId).ToArray();
            var supervisorOptions = new FsHostSupervisorOptions(host, hostArgs, Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
                lifetime, Path.Combine(session, "launch.json"), Path.Combine(session, "supervisor.json"), WorkingDirectory: session,
                StartupGateFile: gate, StartupGateToken: gateToken, MountPoint: mount, StatusFile: status);
            supervision = deps.Supervise(supervisorOptions, supervisorStop.Token);
            using (var startup = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token))
            {
                startup.CancelAfter(deps.StartupTimeout);
                while (true)
                {
                    startup.Token.ThrowIfCancellationRequested();
                    if (close.IsCompleted) { await close.ConfigureAwait(false); throw new OperationCanceledException("System/Data browse closed before readiness."); }
                    if (supervision.IsCompleted) throw new IOException("System/Data native admission refused or its owner exited before readiness.");
                    var owner = deps.ReadJson(supervisorOptions.LaunchRecordPath); var state = deps.ReadJson(status);
                    if (owner is { } owned && state is { } current && TryHostPid(owned, out var pid) && launch.MatchesReadyStatus(current, pid) &&
                        deps.ProbeMount(mount, launch.ExpectedVolumeSerial(current.GetProperty("volumeLabel").GetString()!))) break;
                    await Task.Delay(50, startup.Token).ConfigureAwait(false);
                }
            }
            ready = true;
            File.WriteAllText(Path.Combine(session, "ready.json"), JsonSerializer.Serialize(new { operationId, mountPoint = mount, selection = launch.Selection,
                imageDerivedAdmission = true, capability = NativeSystemDataBrowseLaunch.Capability }, JsonOptions));
            Console.Error.WriteLine($"System/Data is read-only at {mount}");
            if (o.CopyOut is not null)
            {
                using var copying = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token);
                var copy = SnapshotBrowseCommand.CopyOutAsync(mount, o.CopyOut, copying.Token);
                var finished = await Task.WhenAny(copy, supervision, close).ConfigureAwait(false);
                if (finished != copy)
                {
                    copying.Cancel(); try { await copy.ConfigureAwait(false); } catch (OperationCanceledException) { }
                    throw new IOException("System/Data owner closed during copy-out; destination may be partial.");
                }
                copied = await copy.ConfigureAwait(false);
            }
            else
            {
                var finished = await Task.WhenAny(Task.Delay(Timeout.Infinite, stopping.Token), supervision, close).ConfigureAwait(false);
                if (finished == supervision) throw new IOException("System/Data native owner exited before browse close.");
                if (finished == close) await close.ConfigureAwait(false);
            }
        }
        catch (ArgumentException ex) { exit = 2; error = ex.Message; }
        catch (Exception ex) when (ex is FileNotFoundException or Win32Exception) { exit = 3; error = ex.Message; }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException) { exit = 4; error = ex.Message; }
        catch (Exception ex) { exit = 5; error = ex.Message; }
        finally
        {
            inputStop.Cancel();
            try { if (lifetime is not null) File.Delete(lifetime); }
            catch (Exception ex) { supervisorStop.Cancel(); exit = 5; error = "Cannot signal System/Data close: " + ex.Message; }
            if (supervision is not null)
            {
                try
                {
                    terminal = await supervision.ConfigureAwait(false);
                    if (!terminal.Success || !terminal.Evidence.OriginalHostIdentityAbsent || !terminal.Evidence.MountAbsenceProven || terminal.Evidence.ForcedJobTermination)
                    { exit = 5; error = "System/Data teardown did not complete cleanly; retained supervisor evidence identifies the owner."; }
                }
                catch (Exception ex) { exit = 5; error = "System/Data supervision failed: " + ex.Message; }
            }
            if (mount is not null && (supervision is null || terminal?.Evidence.MountAbsenceProven == true))
            { try { Directory.Delete(mount, recursive: false); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
            launch?.Dispose(); Console.CancelKeyPress -= cancel;
        }
        var result = new { schemaVersion = 2, command = "system-data-browse", operationId, success = exit == 0, exitCode = exit, error,
            mountPoint = mount, sessionDirectory = session, nativeAdmissionProven = ready, selection = launch?.Selection, capability = NativeSystemDataBrowseLaunch.Capability,
            copyOut = copied, teardownProven = terminal?.Evidence.MountAbsenceProven == true && terminal.Evidence.OriginalHostIdentityAbsent,
            supervisorEvidence = session is null ? null : Path.Combine(session, "supervisor.json") };
        if (sessionOwned && session is not null)
        { try { File.WriteAllText(Path.Combine(session, "result.json"), JsonSerializer.Serialize(result, JsonOptions)); } catch (Exception ex) { Console.Error.WriteLine("Cannot save System/Data result: " + ex.Message); } }
        Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions)); return exit;
    }
    private static bool Inside(string path, string directory) => string.Equals(path, directory, StringComparison.OrdinalIgnoreCase) || path.StartsWith(directory.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static bool TryHostPid(JsonElement root, out int pid)
    {
        pid = 0; return root.TryGetProperty("supervisionProven", out var proof) && proof.ValueKind == JsonValueKind.True &&
            root.TryGetProperty("hostIdentityCaptured", out var captured) && captured.ValueKind == JsonValueKind.True && root.TryGetProperty("hostPid", out var value) && value.TryGetInt32(out pid) && pid > 0;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
}
