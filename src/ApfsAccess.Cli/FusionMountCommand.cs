using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal static class FusionMountCommand
{
    internal const string Usage = "fusion mount --selection JSON_FILE --session-dir NEW_DIRECTORY --recovery-dir DIRECTORY [--close-on-stdin]";
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    internal static FusionImageSelection ReadSelection(string path)
    {
        NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is <= 0 or > 65536) throw new ArgumentException("Fusion selection exceeds its bounded profile.");
        using var document = JsonDocument.Parse(file);
        static void Unique(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                { if (!seen.Add(property.Name)) throw new ArgumentException("Duplicate Fusion selector."); Unique(property.Value); }
            }
            else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) Unique(item);
        }
        Unique(document.RootElement);
        var selection = document.RootElement.Deserialize<FusionImageSelection>(Json) ?? throw new ArgumentException("Missing Fusion selection.");
        NativeFusionImageLaunch.ValidateSelection(selection); return selection;
    }

    internal static async Task<int> RunAsync(string[] args, CancellationToken token = default)
    {
        if (args is ["--help"] or ["mount", "--help"]) { Console.WriteLine(Usage); return 0; }
        string? session = null, lifetime = null, error = null; var exit = 0; var ready = false; var sessionOwned = false;
        NativeFusionImageLaunch? launch = null; Task<FsHostSupervisorResult>? supervising = null; FsHostSupervisorResult? terminal = null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var supervisorStop = new CancellationTokenSource(); using var inputStop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stop.Cancel(); }; Console.CancelKeyPress += cancel;
        try
        {
            if (args.Length == 0 || args[0] != "mount") throw new ArgumentException(Usage);
            var values = new Dictionary<string, string>(StringComparer.Ordinal); var closeOnStdin = false;
            for (var i = 1; i < args.Length; ++i)
            {
                var key = args[i];
                if (key == "--close-on-stdin" && !closeOnStdin) { closeOnStdin = true; continue; }
                if (key is not ("--selection" or "--session-dir" or "--recovery-dir") || ++i >= args.Length || !values.TryAdd(key, args[i])) throw new ArgumentException(Usage);
            }
            if (values.Count != 3) throw new ArgumentException(Usage);
            var selection = ReadSelection(values["--selection"]);
            session = NativeSnapshotBrowseLaunch.ValidateLocalPath(values["--session-dir"]);
            var recovery = NativeSnapshotBrowseLaunch.ValidateLocalPath(values["--recovery-dir"]);
            if (Directory.Exists(session) || File.Exists(session) || !Directory.Exists(recovery)) throw new ArgumentException("Use a new session directory and an existing recovery directory.");
            var host = new[] { Path.Combine(AppContext.BaseDirectory, "ApfsAccess.FsHost.exe"), Path.Combine(AppContext.BaseDirectory, "native", "ApfsAccess.FsHost.exe") }.FirstOrDefault(File.Exists)
                ?? throw new FileNotFoundException("The packaged Fusion native host is missing.");
            NativeSnapshotBrowseLaunch.ValidateLocalPath(host);
            launch = NativeFusionImageLaunch.Prepare(selection, stop.Token);
            Directory.CreateDirectory(Path.GetDirectoryName(session)!);
            if (!CreateDirectoryW(session, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error()); sessionOwned = true;
            var mount = Path.Combine(session, "mount"); var status = Path.Combine(session, "status.json");
            var gate = Path.Combine(session, "startup.gate"); var gateToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            lifetime = Path.Combine(session, "lifetime");
            using (File.Open(lifetime, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { }
            using (var pending = File.Open(gate, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) pending.Write("pending"u8);
            var hostArgs = launch.BuildHostArguments(mount, recovery, status, lifetime, gate, gateToken, Environment.ProcessId).ToArray();
            var close = closeOnStdin ? Task.Run(() => SnapshotBrowseCommand.WaitForCloseInputAsync(Console.In, inputStop.Token)) : Task.Delay(Timeout.Infinite, inputStop.Token);
            var options = new FsHostSupervisorOptions(host, hostArgs, Environment.ProcessId.ToString(CultureInfo.InvariantCulture), lifetime,
                Path.Combine(session, "launch.json"), Path.Combine(session, "supervisor.json"), WorkingDirectory: session,
                StartupGateFile: gate, StartupGateToken: gateToken, MountPoint: mount, StatusFile: status);
            launch.ReleaseForNativeOwner();
            supervising = FsHostSupervisor.RunAsync(options, supervisorStop.Token);
            using (var startup = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
            {
                startup.CancelAfter(TimeSpan.FromSeconds(60));
                while (true)
                {
                    startup.Token.ThrowIfCancellationRequested();
                    if (close.IsCompleted) { await close.ConfigureAwait(false); throw new OperationCanceledException("Fusion mount closed before readiness."); }
                    if (supervising.IsCompleted) throw new IOException("Fusion native admission refused or its owner exited before readiness.");
                    var owner = SnapshotBrowseCommand.ReadJson(options.LaunchRecordPath); var current = SnapshotBrowseCommand.ReadJson(status);
                    if (owner is { } owned && current is { } state && owned.TryGetProperty("supervisionProven", out var proof) && proof.ValueKind == JsonValueKind.True &&
                        owned.TryGetProperty("hostIdentityCaptured", out var captured) && captured.ValueKind == JsonValueKind.True &&
                        owned.TryGetProperty("hostPid", out var pid) && pid.TryGetInt32(out var id) && launch.MatchesReadyStatus(state, id) &&
                        ProbeWritableMount(mount, NativeFusionImageLaunch.ExpectedVolumeSerial(state.GetProperty("volumeLabel").GetString()!))) break;
                    await Task.Delay(50, startup.Token).ConfigureAwait(false);
                }
            }
            ready = true;
            File.WriteAllText(Path.Combine(session, "ready.json"), JsonSerializer.Serialize(new { mountPoint = mount, selection = launch.Selection,
                members = launch.Members, nativeAdmissionProven = true, access = "read-write" }, Json));
            Console.Error.WriteLine($"Fusion image volume mounted at {mount}");
            var finished = await Task.WhenAny(Task.Delay(Timeout.Infinite, stop.Token), supervising, close).ConfigureAwait(false);
            if (finished == supervising) throw new IOException("Fusion native owner exited before close.");
            if (finished == close) await close.ConfigureAwait(false);
        }
        catch (ArgumentException e) { exit = 2; error = e.Message; }
        catch (JsonException e) { exit = 2; error = e.Message; }
        catch (OperationCanceledException e) { exit = 4; error = e.Message; }
        catch (Exception e) { exit = 5; error = e.Message; }
        finally
        {
            inputStop.Cancel();
            try { if (lifetime is not null && File.Exists(lifetime)) File.Move(lifetime, lifetime + ".retired"); }
            catch (Exception e) { supervisorStop.Cancel(); exit = 5; error = "Fusion close signal failed: " + e.Message; }
            if (supervising is not null)
            {
                try
                {
                    terminal = await supervising.ConfigureAwait(false);
                    if (!terminal.Success || !terminal.Evidence.OriginalHostIdentityAbsent || !terminal.Evidence.MountAbsenceProven || terminal.Evidence.ForcedJobTermination)
                    { exit = 5; error = "Fusion owner retirement remains unproved; retain the supervisor evidence."; }
                }
                catch (Exception e) { exit = 5; error = "Fusion supervisor failed: " + e.Message; }
            }
            launch?.Dispose(); Console.CancelKeyPress -= cancel;
        }
        var result = new { command = "fusion-mount", success = exit == 0, exitCode = exit, error, sessionDirectory = session,
            nativeAdmissionProven = ready, selection = launch?.Selection,
            teardownProven = terminal?.Evidence.OriginalHostIdentityAbsent == true && terminal.Evidence.MountAbsenceProven,
            supervisorEvidence = session is null ? null : Path.Combine(session, "supervisor.json") };
        if (sessionOwned) File.WriteAllText(Path.Combine(session!, "result.json"), JsonSerializer.Serialize(result, Json));
        Console.WriteLine(JsonSerializer.Serialize(result, Json)); return exit;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
    private static bool ProbeWritableMount(string mount, uint expectedSerial)
    {
        using var root = CreateFileW(mount, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        var name = new StringBuilder(128);
        return !root.IsInvalid && GetVolumeInformationByHandleW(root, IntPtr.Zero, 0, out var serial, out _, out var flags,
            name, (uint)name.Capacity) && name.ToString() == "APFS" && (flags & 0x80000) == 0 && serial == expectedSerial;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr label, uint labelLength,
        out uint serial, out uint componentLength, out uint flags, StringBuilder filesystem, uint filesystemLength);
}
