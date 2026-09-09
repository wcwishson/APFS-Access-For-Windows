namespace ApfsAccess.Backend.Native.Tests;

// A10 runner hardening: real processes, no GUI.
// RED first: these fail against the synchronous ReadToEnd runner.
public sealed class ObserverRunnerHardeningTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StrictUtf8ProtocolPreservesLiteralReplacementAndRejectsMalformedBytes(bool stderr)
    {
        var root = Path.GetTempPath().StartsWith(@"D:\", StringComparison.OrdinalIgnoreCase) ? Path.GetTempPath() : @"D:\Temp";
        var directory = Path.Combine(root, "observer-utf8-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "wire.bin");
        try
        {
            var runner = new ProcessObserverRunner();
            string[] args = stderr ? ["/d", "/c", "type", path, "1>&2"] : ["/d", "/c", "type", path];
            File.WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes("legal~�😀"));
            var result = runner.Run("cmd.exe", args);
            Assert.Equal("legal~�😀", stderr ? result.StandardError : result.StandardOutput);
            File.WriteAllBytes(path, [0xED, 0xA0, 0x80]);
            Assert.Throws<InvalidDataException>(() => runner.Run("cmd.exe", args));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void Runner_DefaultMaxOutputBytes_Is64MB()
    {
        var runner = new ProcessObserverRunner();
        Assert.Equal(64L * 1024 * 1024, runner.MaxOutputBytes);
    }

    [Fact]
    public void HangingProcess_WithShortTimeout_ThrowsTimeoutAndKillsTree()
    {
        var runner = new ProcessObserverRunner { Timeout = TimeSpan.FromSeconds(2) };
        var ping = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "PING.EXE");
        Assert.True(File.Exists(ping), $"Windows ping binary is missing: {ping}");
        var ex = Assert.Throws<TimeoutException>(() =>
            runner.Run(ping, ["-n", "30", "127.0.0.1"]));
        var pid = ParsePid(ex.Message);
        Assert.True(pid > 0, $"Timeout message should carry pid, got: {ex.Message}");
        AssertProcessDead(pid);
    }

    [Fact]
    public void OutputCap_WithTinyLimit_KillsAndThrows()
    {
        var runner = new ProcessObserverRunner
        {
            Timeout = TimeSpan.FromSeconds(20),
            MaxOutputBytes = 1024,
        };
        // Emits ~100k lines to stdout; must trip the 1KB cap.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            runner.Run("cmd.exe", ["/c", "for", "/L", "%i", "in", "(1,1,100000)", "do", "@echo", "line-%i01234567890123456789"]));
        Assert.Contains("MaxOutputBytes", ex.Message);
    }

    [Fact]
    public void ParallelStdoutStderrFlood_CompletesWithoutDeadlock()
    {
        // NOTE: the task spec sketches this with powershell.exe, but Windows
        // PowerShell 5.1 cannot start parented to the test host on this
        // machine ("restricted by your Administrator by policy rule";
        // interactive/cmd-parented spawns of the same binary succeed, so this
        // is an environment policy, not a runner bug). cmd.exe emits the same
        // dual-stream flood and exercises the identical concurrent-drain path:
        // ~20000 lines x2 streams (~400KB) far exceeds the 64KB pipe buffers,
        // so a synchronous ReadToEnd implementation deadlocks here.
        var runner = new ProcessObserverRunner { Timeout = TimeSpan.FromSeconds(60) };
        var result = runner.Run("cmd.exe",
        [
            "/c", "for", "/L", "%i", "in", "(1,1,20000)", "do",
            "@(echo", "out-%i", "&", "echo", "err-%i", "1>&2)",
        ]);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("out-20000", result.StandardOutput);
        Assert.Contains("err-20000", result.StandardError);
    }

    [Fact]
    public void Provenance_PackagedKeepsWritable_OverrideCapsToReadable()
    {
        using var temp = DTempDirectory.Create("provenance");
        var packagedBase = Path.Combine(temp.Path, "pkgbase");
        Directory.CreateDirectory(packagedBase);
        var packagedExe = Path.Combine(packagedBase, "ApfsObserver.exe");
        File.WriteAllBytes(packagedExe, [0x4D, 0x5A]);
        var overrideExe = Path.Combine(temp.Path, "elsewhere.exe");
        File.WriteAllBytes(overrideExe, [0x4D, 0x5A]);

        // Resolve via baseDirectory param: packaged under base, override outside.
        var packagedResolved = NativeApfsObserver.ResolveNativeObserverPath(
            new ApfsAccess.Core.ServiceHostOptions(), packagedBase);
        Assert.Equal(packagedExe, packagedResolved);
        Assert.True(NativeApfsObserver.IsPackagedObserverPath(packagedResolved, packagedBase));

        // Override: file exists but not under packagedBase.
        Assert.False(NativeApfsObserver.IsPackagedObserverPath(overrideExe, packagedBase));

        // Cap logic: packaged keeps Writable, override caps to Readable.
        var writable = new ApfsAccess.Core.ApfsVolumeCapability(
            ApfsAccess.Core.ApfsCapabilityDecision.Writable, [], true);
        var kept = NativeApfsObserver.ApplyObserverProvenanceCap(writable, isPackaged: true);
        Assert.Equal(ApfsAccess.Core.ApfsCapabilityDecision.Writable, kept.Decision);

        var capped = NativeApfsObserver.ApplyObserverProvenanceCap(writable, isPackaged: false);
        Assert.Equal(ApfsAccess.Core.ApfsCapabilityDecision.Readable, capped.Decision);
        Assert.Contains("untrusted-observer-source", capped.Reasons);
        Assert.False(capped.AutoMountAllowed);
    }

    private static int ParsePid(string message)
    {
        // Runner includes "pid <n>" in timeout/overrun messages.
        foreach (var token in message.Split([' ', '=', ':', '(', ')', '[', ']', ',', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Equals("pid", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (int.TryParse(token, out var pid) && pid > 0 && pid < 1_000_000)
            {
                return pid;
            }
        }

        // Fallback: scan for digits.
        var digits = new string(message.Where(char.IsDigit).ToArray());
        return 0;
    }

    private static void AssertProcessDead(int pid)
    {
        for (var i = 0; i < 50; i++)
        {
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(pid);
                if (proc.HasExited)
                {
                    return;
                }
            }
            catch (ArgumentException)
            {
                return;
            }
            catch (InvalidOperationException)
            {
                return;
            }

            Thread.Sleep(100);
        }

        try
        {
            var proc = System.Diagnostics.Process.GetProcessById(pid);
            Assert.True(proc.HasExited, $"Process {pid} is still alive after timeout kill.");
        }
        catch (ArgumentException)
        {
            // Dead = good.
        }
    }
}
