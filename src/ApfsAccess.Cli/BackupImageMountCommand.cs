using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal sealed record BackupImageMountOptions(string Image, string ContainerId, string VolumeOid,
    string JournalDirectory, string SessionDirectory, bool CloseOnStdin);

internal static class BackupImageMountCommand
{
    internal const string Usage = "backup-image mount --image FILE --container-id apfs-container:HEX --volume-oid OID --journal-dir EXISTING_DIRECTORY --session-dir NEW_DIRECTORY [--close-on-stdin] [--json]";
    internal static BackupImageMountOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] != "mount") throw new ArgumentException(Usage);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var close = false; var json = false;
        for (var i = 1; i < args.Length; ++i) {
            var key = args[i];
            if (key == "--close-on-stdin" && !close) { close = true; continue; }
            if (key == "--json" && !json) { json = true; continue; }
            if (key is not ("--image" or "--container-id" or "--volume-oid" or "--journal-dir" or "--session-dir") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(key, args[i]))
                throw new ArgumentException(Usage);
        }
        if (values.Count != 5) throw new ArgumentException(Usage);
        NativeApfsSnapshotReader.ValidateRequest(values["--image"], values["--container-id"], values["--volume-oid"]);
        var journal = NativeSnapshotBrowseLaunch.ValidateLocalPath(values["--journal-dir"]);
        var session = NativeSnapshotBrowseLaunch.ValidateLocalPath(values["--session-dir"]);
        static bool Inside(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith(b.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        if (Inside(session, journal) || Inside(journal, session) || Inside(values["--image"], session))
            throw new ArgumentException("Use separate persistent journal and fresh session directories.");
        return new(values["--image"], values["--container-id"], values["--volume-oid"], journal, session, close);
    }

    internal static async Task<int> RunAsync(string[] args, CancellationToken token = default)
    {
        if (args is ["mount", "--help"] or ["mount", "help"]) {
            Console.WriteLine(JsonSerializer.Serialize(new { command = "backup-image-mount", success = true, usage = Usage,
                profile = "bounded-backup-image-v1", genuineMacCorpus = "unverified", maximumImageBytes = 256L << 20, maximumLiveFileBytes = 8L << 20 }));
            return 0;
        }
        var operationId = Guid.NewGuid().ToString("D");
        string? session = null, mount = null, lifetime = null, failure = null;
        var created = false; var ready = false; var exit = 0;
        NativeBackupImageWriteLaunch? launch = null;
        Task<FsHostSupervisorResult>? supervision = null; FsHostSupervisorResult? terminal = null;
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var closeStop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stopping.Cancel(); };
        Console.CancelKeyPress += cancel;
        try {
            var options = Parse(args); session = options.SessionDirectory;
            if (Directory.Exists(session) || File.Exists(session)) throw new ArgumentException("The session directory must be new.");
            var host = new[] { Path.Combine(AppContext.BaseDirectory, "ApfsAccess.FsHost.exe"),
                Path.Combine(AppContext.BaseDirectory, "native", "ApfsAccess.FsHost.exe") }.FirstOrDefault(File.Exists)
                ?? throw new FileNotFoundException("The packaged native host is missing.");
            NativeSnapshotBrowseLaunch.ValidateLocalPath(host);
            Directory.CreateDirectory(Path.GetDirectoryName(session)!);
            if (!CreateDirectoryW(session, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
            created = true; NativeSnapshotBrowseLaunch.ValidateLocalPath(session);
            mount = Path.Combine(session, "mount"); lifetime = Path.Combine(session, "lifetime");
            var status = Path.Combine(session, "status.json"); var gate = Path.Combine(session, "startup.gate");
            var gateToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            using (File.Open(lifetime, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { }
            using (var pending = File.Open(gate, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) pending.Write("pending"u8);
            launch = NativeBackupImageWriteLaunch.Prepare(options.Image, options.ContainerId, options.VolumeOid, options.JournalDirectory, stopping.Token);
            var arguments = launch.BuildHostArguments(mount, status, lifetime, gate, gateToken, Environment.ProcessId);
            var supervisor = new FsHostSupervisorOptions(host, arguments, Environment.ProcessId.ToString(CultureInfo.InvariantCulture), lifetime,
                Path.Combine(session, "launch.json"), Path.Combine(session, "supervisor.json"), WorkingDirectory: session,
                StartupGateFile: gate, StartupGateToken: gateToken, MountPoint: mount, StatusFile: status);
            var input = options.CloseOnStdin ? Task.Run(() => SnapshotBrowseCommand.WaitForCloseInputAsync(Console.In, closeStop.Token)) : Task.Delay(Timeout.Infinite, closeStop.Token);
            launch.ReleaseForExclusiveStart();
            supervision = FsHostSupervisor.RunAsync(supervisor, CancellationToken.None);
            using (var startup = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token)) {
                startup.CancelAfter(TimeSpan.FromSeconds(45));
                while (true) {
                    startup.Token.ThrowIfCancellationRequested();
                    if (input.IsCompleted) { await input.ConfigureAwait(false); throw new OperationCanceledException("Closed before readiness."); }
                    if (supervision.IsCompleted) throw new IOException("Backup host exited before readiness.");
                    var owner = SnapshotBrowseCommand.ReadJson(supervisor.LaunchRecordPath);
                    var state = SnapshotBrowseCommand.ReadJson(status);
                    if (owner is {} owned && state is {} current && owned.GetProperty("supervisionProven").GetBoolean() &&
                        owned.GetProperty("hostIdentityCaptured").GetBoolean() && owned.TryGetProperty("hostPid", out var pid) &&
                        pid.TryGetInt32(out var id) && launch.MatchesReadyStatus(current, id) && ProbeMount(mount, launch.ExpectedVolumeSerial)) break;
                    await Task.Delay(50, startup.Token).ConfigureAwait(false);
                }
            }
            ready = true;
            File.WriteAllText(Path.Combine(session, "ready.json"), JsonSerializer.Serialize(new {
                operationId, mountPoint = mount, profile = "bounded-backup-image-v1", selection = launch.Selection, mountedReadinessProven = true }));
            Console.Error.WriteLine($"Backup image is writable at {mount}. Press Ctrl+C to close.");
            var finished = await Task.WhenAny(Task.Delay(Timeout.Infinite, stopping.Token), supervision, input).ConfigureAwait(false);
            if (finished == supervision) throw new IOException("Backup host exited before requested close.");
            if (finished == input) await input.ConfigureAwait(false);
        }
        catch (ArgumentException e) { exit = 2; failure = e.Message; }
        catch (Exception e) when (e is OperationCanceledException or TimeoutException) { exit = ready ? 0 : 4; failure = ready ? null : e.Message; }
        catch (Exception e) { exit = 5; failure = e.Message; }
        finally {
            closeStop.Cancel();
            try { if (lifetime is not null) File.Delete(lifetime); } catch (Exception e) { exit = 5; failure = e.Message; }
            if (supervision is not null) {
                try {
                    terminal = await supervision.ConfigureAwait(false);
                    if (!terminal.Success || !terminal.Evidence.OriginalHostIdentityAbsent || !terminal.Evidence.MountAbsenceProven)
                    { exit = 5; failure = "Backup teardown was not proven; retain supervisor evidence."; }
                }
                catch (Exception e) { exit = 5; failure = e.Message; }
            }
            launch?.Dispose(); Console.CancelKeyPress -= cancel;
        }
        var result = new { schemaVersion = 2, command = "backup-image-mount", operationId, success = exit == 0,
            exitCode = exit, error = failure, sessionDirectory = session, mountPoint = mount, selection = launch?.Selection,
            mountedReadinessProven = ready, teardownProven = terminal?.Evidence.OriginalHostIdentityAbsent == true && terminal.Evidence.MountAbsenceProven,
            profile = "bounded-backup-image-v1", genuineMacCorpus = "unverified" };
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        if (created) File.WriteAllText(Path.Combine(session!, "result.json"), json);
        Console.WriteLine(json); return exit;
    }

    private static bool ProbeMount(string mount, uint expected)
    {
        using var handle = CreateFileW(mount, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        var name = new StringBuilder(128);
        return !handle.IsInvalid && GetVolumeInformationByHandleW(handle, IntPtr.Zero, 0, out var serial, out _, out var flags,
            name, 128) && serial == expected && name.ToString() == "APFS" && (flags & 0x80000) == 0;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr label, uint labelSize,
        out uint serial, out uint componentLength, out uint flags, StringBuilder name, uint nameSize);
}
