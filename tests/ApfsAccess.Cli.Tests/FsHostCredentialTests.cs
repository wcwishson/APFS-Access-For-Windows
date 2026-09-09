using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Cli;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli.Tests;

public sealed class FsHostCredentialTests : IDisposable
{
    private readonly IDisposable scope = FsHostSupervisor.InstallSupervisorExecutablePathForTests(
        Path.Combine(Path.GetDirectoryName(typeof(FsHostSupervisor).Assembly.Location)!, "ApfsAccess.Cli.exe"));
    public void Dispose() => scope.Dispose();
    private static string CreateTestDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), "ApfsCredentialTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
    private sealed class CredentialFactAttribute : FactAttribute
    {
        public CredentialFactAttribute() { if (Environment.GetEnvironmentVariable("APFSACCESS_CREDENTIAL_PROBE") is null) Skip = "Run the focused credential probe build gate."; }
    }
    private sealed class CredentialTheoryAttribute : TheoryAttribute
    {
        public CredentialTheoryAttribute() { if (Environment.GetEnvironmentVariable("APFSACCESS_CREDENTIAL_PROBE") is null) Skip = "Run the focused credential probe build gate."; }
    }
    [CredentialTheory]
    [InlineData(1)]
    [InlineData(257)]
    [InlineData(1024)]
    public async Task CredentialNativeReceiverProvesParentAclBytesEofAndHandleIsolation(int size)
    {
        using var excluded = new EventWaitHandle(false, EventResetMode.ManualReset);
        Assert.True(CredentialNative.SetHandleInformation(excluded.SafeWaitHandle.DangerousGetHandle(), 1, 1));
        var (result, probe) = await CredentialRun(Frame(size), "normal", size,
            excluded.SafeWaitHandle.DangerousGetHandle());
        Assert.True(result.Success, result.Evidence.FailureDetails);
        using var json = JsonDocument.Parse(File.ReadAllText(probe));
        var row = json.RootElement;
        Assert.True(row.GetProperty("accepted").GetBoolean()); // Actual native DACL/parent/EOF checks.
        Assert.True(row.GetProperty("exact").GetBoolean());
        Assert.Equal(Environment.ProcessId, row.GetProperty("serverPid").GetInt32());
        Assert.False(row.GetProperty("excludedInherited").GetBoolean());
        Assert.False(row.GetProperty("outputInherited").GetBoolean());
        CredentialTerminal(result);
    }

    [CredentialTheory]
    [InlineData("magic", "InvalidFrame")]
    [InlineData("empty", "InvalidFrame")]
    [InlineData("oversized", "OversizedFrame")]
    [InlineData("truncated-header", "TruncatedFrame")]
    [InlineData("truncated-body", "TruncatedFrame")]
    [InlineData("extra", "InvalidFrame")]
    [InlineData("nul", "InvalidFrame")]
    [InlineData("no-eof", "Timeout")]
    [InlineData("no-input", "Timeout")]
    public async Task CredentialRefusesMalformedInputBeforeCreatingChild(string kind, string reason)
    {
        var frame = Frame(3);
        switch (kind)
        {
            case "magic": frame[0] = 0; break;
            case "empty": frame = Frame(0); break;
            case "oversized": frame = Frame(1025); break;
            case "truncated-header": frame = frame[..4]; break;
            case "truncated-body": frame = frame[..9]; break;
            case "extra": frame = [.. frame, 1]; break;
            case "nul": frame[9] = 0; break;
            case "no-input": frame = []; break;
        }
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var (result, probe) = await CredentialRun(frame, hold: kind is "no-eof" or "no-input");
        Assert.False(result.Success);
        Assert.Contains(reason, result.Evidence.Failure);
        Assert.Null(result.Evidence.HostPid);
        Assert.False(File.Exists(probe));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(8));
    }

    [CredentialFact]
    public async Task CredentialLateCancellationRetainsExactOwnership()
    {
        using var cancellation = new CancellationTokenSource();
        var (result, _) = await CredentialRun(Frame(257), "linger", 257, cancellation: cancellation);
        Assert.False(result.Success);
        Assert.Equal("cancelled", result.Evidence.StopReason);
        Assert.True(result.Evidence.HostIdentityCaptured);
        CredentialTerminal(result);
    }

    [CredentialFact]
    public async Task CredentialChildEarlyExitStillHasExactTerminalProof()
    {
        var (result, _) = await CredentialRun(Frame(257), "early", 257);
        Assert.True(result.Evidence.HostIdentityCaptured);
        CredentialTerminal(result);
    }

    [CredentialFact]
    public async Task CredentialLaunchFailureHasNoChildOrLeakedHandles()
    {
        var (result, _) = await CredentialRun(Frame(257), "missing", 257);
        Assert.False(result.Success);
        Assert.Null(result.Evidence.HostPid);
        Assert.True(result.Evidence.JobClosed);
    }

    [CredentialFact]
    public async Task CredentialFragmentedFrameWaitsForCompleteEof()
    {
        var (result, _) = await CredentialRun(Frame(257), size: 257, fragmented: true);
        Assert.True(result.Success, result.Evidence.FailureDetails);
        CredentialTerminal(result);
    }

    [CredentialFact]
    public async Task CredentialInputCancellationCreatesNoChild()
    {
        using var cancellation = new CancellationTokenSource(100);
        var (result, _) = await CredentialRun([], hold: true, cancellation: cancellation, cancelInput: true);
        Assert.False(result.Success);
        Assert.Equal("cancelled", result.Evidence.StopReason);
        Assert.Null(result.Evidence.HostPid);
    }

    [CredentialFact]
    public async Task CredentialLifetimeLossDuringInputCreatesNoChild()
    {
        var (result, _) = await CredentialRun([], hold: true, endLifetime: true);
        Assert.False(result.Success);
        Assert.Contains("lifetime ended", result.Evidence.Failure);
        Assert.Null(result.Evidence.HostPid);
    }

    [CredentialFact]
    public void CredentialRefusesDiskAndMessagePipeInputs()
    {
        var root = CreateTestDirectory();
        var empty = Path.Combine(root, "empty"); File.WriteAllBytes(empty, []);
        using var disk = File.OpenHandle(empty);
        var raw = disk.DangerousGetHandle(); disk.SetHandleAsInvalid();
        Assert.Contains("PipeRequired", Assert.Throws<IOException>(() => SupervisedCredential.Receive(raw, default, () => {})).Message);
        using var message = new System.IO.Pipes.NamedPipeServerStream(Guid.NewGuid().ToString("N"),
            System.IO.Pipes.PipeDirection.In, 1, System.IO.Pipes.PipeTransmissionMode.Message);
        raw = message.SafePipeHandle.DangerousGetHandle(); message.SafePipeHandle.SetHandleAsInvalid();
        Assert.Contains("PipeRequired", Assert.Throws<IOException>(() => SupervisedCredential.Receive(raw, default, () => {})).Message);
    }

    [CredentialFact]
    public void CredentialBrokenChildPipeRefusesWithoutBlocking()
    {
        Assert.True(CredentialNative.CreatePipe(out var read, out var write, 0, 4096));
        using (var writer = new SafeFileHandle(write, true))
        {
            var bytes = Frame(1024);
            Assert.True(CredentialNative.WriteFile(writer, bytes, (uint)bytes.Length, out _, 0));
            Array.Clear(bytes);
        }
        using var credential = SupervisedCredential.Receive(read, default, () => {});
        credential.CreateChildPipe(); credential.ReleaseLocalReader();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        Assert.Contains("WriteFailure", Assert.Throws<IOException>(() => credential.Send(default, () => {})).Message);
        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(1));
    }

    [CredentialFact]
    public async Task CredentialAssignmentFailureReapsTheExactSuspendedChild()
    {
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        { AssignProcessToJobObjectOverride = () => false });
        var (result, _) = await CredentialRun(Frame(257), size: 257);
        Assert.False(result.Success);
        Assert.True(result.Evidence.HostIdentityCaptured);
        Assert.False(result.Evidence.JobAssigned);
        Assert.False(result.Evidence.Resumed);
        Assert.True(result.Evidence.ExactProcessTerminationAttempted);
        CredentialTerminal(result);
    }

    private static void CredentialTerminal(FsHostSupervisorResult result)
    {
        Assert.True(result.Evidence.OriginalHostIdentityAbsent);
        Assert.True(result.Evidence.MountAbsenceProven);
        Assert.True(result.Evidence.JobClosed);
        Assert.False(result.Evidence.QuarantineRequired);
    }

    private static byte[] Frame(int length)
    {
        var result = new byte[8 + length];
        "APC1"u8.CopyTo(result);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), (uint)length);
        for (var i = 0; i < length; i++) result[8 + i] = (byte)(1 + i % 255);
        return result;
    }

    private async Task<(FsHostSupervisorResult Result, string Probe)> CredentialRun(byte[] frame,
        string mode = "normal", int size = 3, nint excluded = 0, bool hold = false,
        CancellationTokenSource? cancellation = null, bool cancelInput = false, bool endLifetime = false, bool fragmented = false)
    {
        // Explicit test-only executable supplied by the focused native-probe build.
        var native = Environment.GetEnvironmentVariable("APFSACCESS_CREDENTIAL_PROBE");
        Assert.True(native is not null && Path.GetFileName(native) == "CredentialProbe.exe" && File.Exists(native));
        var root = CreateTestDirectory();
        var lifetime = Path.Combine(root, "alive");
        var probe = Path.Combine(root, "probe.json");
        File.WriteAllText(lifetime, "alive");
        var options = new FsHostSupervisorOptions(mode == "missing" ? Path.Combine(root, "absent.exe") : native!,
            [probe, mode, excluded.ToString(), size.ToString()], Environment.ProcessId.ToString(), lifetime,
            Path.Combine(root, "launch.json"), Path.Combine(root, "evidence.json"),
            WorkingDirectory: root, MountPoint: Path.Combine(root, "mount"),
            StartupGateFile: Path.Combine(root, "gate"), StartupGateToken: "synthetic-gate",
            GracefulTimeoutMs: 100, ProcessAbsenceTimeoutMs: 2000, CredentialInput: true);
        Assert.True(CredentialNative.CreatePipe(out var read, out var write, 0, 4096));
        using var writer = new SafeFileHandle(write, true);
        var previous = CredentialNative.GetStdHandle(-10);
        Assert.True(CredentialNative.SetStdHandle(-10, read));
        Task<FsHostSupervisorResult> running;
        try
        {
            if (endLifetime) _ = Task.Run(async () => { await Task.Delay(100); File.Delete(lifetime); });
            if (fragmented)
            {
                _ = Task.Run(async () =>
                {
                    var first = frame[..4]; var rest = frame[4..];
                    CredentialNative.WriteFile(writer, first, (uint)first.Length, out _, 0);
                    await Task.Delay(50);
                    CredentialNative.WriteFile(writer, rest, (uint)rest.Length, out _, 0);
                    Array.Clear(first); Array.Clear(rest); writer.Dispose();
                });
            }
            else if (frame.Length > 0)
                Assert.True(CredentialNative.WriteFile(writer, frame, (uint)frame.Length, out _, 0));
            if (!fragmented) Array.Clear(frame);
            if (!hold && !fragmented) writer.Dispose();
            running = FsHostSupervisor.RunAsync(options, cancellation?.Token ?? default);
        }
        finally { CredentialNative.SetStdHandle(-10, previous); Array.Clear(frame); }
        if (cancellation is not null && !cancelInput)
        {
            var deadline = DateTime.UtcNow.AddSeconds(8);
            while (!File.Exists(probe) && !running.IsCompleted && DateTime.UtcNow < deadline) await Task.Delay(10);
            Assert.True(File.Exists(probe));
            cancellation.Cancel();
        }
        return (await running.WaitAsync(TimeSpan.FromSeconds(15)), probe);
    }

    private static class CredentialNative
    {
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CreatePipe(out nint read, out nint write, nint security, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool WriteFile(SafeFileHandle handle, byte[] buffer, uint count, out uint written, nint overlapped);
        [DllImport("kernel32.dll")] internal static extern nint GetStdHandle(int kind);
        [DllImport("kernel32.dll")] internal static extern bool SetStdHandle(int kind, nint handle);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetHandleInformation(nint handle, uint mask, uint flags);
    }
}
