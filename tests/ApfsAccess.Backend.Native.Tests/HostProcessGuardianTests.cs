using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class HostProcessGuardianTests
{
    [Fact]
    public async Task GuardianKeeperOwnsExactHandleAfterCallerDisposesProcess()
    {
        var root = CreateTestDirectory();
        using var child = Process.Start(DedicatedGuardianChild(root))!;
        using var guardian = HostProcessGuardian.Create(child);
        var original = GuardianHandle(guardian, "_processHandle");
        var job = GuardianHandle(guardian, "_job");
        try
        {
            Assert.Equal((uint)child.Id, guardian.ProcessId);
            Assert.Equal(child.StartTime.ToUniversalTime().ToFileTimeUtc(), guardian.CreationTimeFileTimeUtc);
            child.Dispose();
            Assert.False(original.IsClosed);
            Assert.True(guardian.TryTerminate(19));
            Assert.True(guardian.WaitForEmpty(TimeSpan.FromSeconds(5)));
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(original.IsClosed);
            Assert.True(job.IsClosed);
        }
        finally
        {
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GuardianKeeperRetriesFailedTerminationWithoutDroppingOriginalHandles(bool throwOnTermination)
    {
        var root = CreateTestDirectory();
        var fail = 1;
        var attempts = 0;
        var hooks = new HostGuardianCleanupTestHooks
        {
            TerminateJob = (job, code) =>
            {
                Interlocked.Increment(ref attempts);
                if (Volatile.Read(ref fail) == 0) return TerminateTestJob(job, code);
                if (throwOnTermination) throw new IOException("Injected termination failure.");
                return false;
            },
            TerminateProcess = (process, code) => Volatile.Read(ref fail) == 0 && TerminateTestProcess(process, code),
        };
        using var hookScope = new GuardianCleanupHookScope(hooks);
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root), gate);
        var guardian = launch.Guardian!;
        var original = GuardianHandle(guardian, "_processHandle");
        var jobHandle = GuardianHandle(guardian, "_job");
        try
        {
            var started = Stopwatch.StartNew();
            guardian.Dispose();
            Assert.True(started.Elapsed < TimeSpan.FromSeconds(1));
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref attempts) >= 3, TimeSpan.FromSeconds(5)));
            Assert.False(launch.Process.HasExited);
            Assert.False(original.IsClosed);
            Assert.False(jobHandle.IsClosed);
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(guardian.Dispose)));
            Volatile.Write(ref fail, 0);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(launch.Process.WaitForExit(0));
            Assert.True(original.IsClosed);
            Assert.True(jobHandle.IsClosed);
        }
        finally
        {
            Volatile.Write(ref fail, 0);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task GuardianKeeperContinuesRequestedTerminationWithoutCallerDisposal()
    {
        var root = CreateTestDirectory();
        var fail = 1;
        var attempts = 0;
        var exitCodes = new System.Collections.Concurrent.ConcurrentQueue<uint>();
        using var hookScope = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            TerminateJob = (job, code) =>
            {
                Interlocked.Increment(ref attempts);
                exitCodes.Enqueue(code);
                return Volatile.Read(ref fail) == 0 && TerminateTestJob(job, code);
            },
            TerminateProcess = (process, code) => Volatile.Read(ref fail) == 0 && TerminateTestProcess(process, code),
        });
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root), gate);
        var guardian = launch.Guardian!;
        var original = GuardianHandle(guardian, "_processHandle");
        var jobHandle = GuardianHandle(guardian, "_job");
        try
        {
            Assert.False(guardian.TryTerminate(13));
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref attempts) >= 3, TimeSpan.FromSeconds(5)));
            Assert.False(launch.Process.HasExited);
            Assert.False(original.IsClosed);
            Assert.False(jobHandle.IsClosed);
            Volatile.Write(ref fail, 0);
            Assert.True(launch.Process.WaitForExit(5_000));
            Assert.True(guardian.WaitForEmpty(TimeSpan.FromSeconds(5)));
            Assert.All(exitCodes, code => Assert.Equal(13U, code));
            Assert.True(GetTestExitCode((SafeProcessHandle)original, out var actualExitCode));
            Assert.Equal(13U, actualExitCode);
            Assert.False(original.IsClosed);
            Assert.False(jobHandle.IsClosed);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(original.IsClosed);
            Assert.True(jobHandle.IsClosed);
        }
        finally
        {
            Volatile.Write(ref fail, 0);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("present")]
    [InlineData("unknown-identity")]
    [InlineData("identity-exception")]
    [InlineData("nonempty-job")]
    [InlineData("unknown-job")]
    [InlineData("job-exception")]
    [InlineData("unsignaled-handle")]
    public async Task GuardianKeeperRequiresEveryOwnershipProofBeforeReleasingHandles(string unavailableProof)
    {
        var root = CreateTestDirectory();
        var hold = 1;
        var probes = 0;
        var hooks = new HostGuardianCleanupTestHooks
        {
            OriginalHandleSignaled = process =>
                !(Volatile.Read(ref hold) != 0 && unavailableProof == "unsignaled-handle") &&
                WaitForTestProcess(process, 0) == 0,
            OriginalIdentityAbsent = (pid, _) =>
            {
                Interlocked.Increment(ref probes);
                if (Volatile.Read(ref hold) != 0)
                {
                    if (unavailableProof == "present") return false;
                    if (unavailableProof == "unknown-identity") return null;
                    if (unavailableProof == "identity-exception") throw new IOException("Injected enumeration failure.");
                }
                return DedicatedPidAbsent(pid);
            },
            ActiveProcessCount = job =>
            {
                if (Volatile.Read(ref hold) != 0)
                {
                    if (unavailableProof == "nonempty-job") return 1;
                    if (unavailableProof == "unknown-job") return null;
                    if (unavailableProof == "job-exception") throw new IOException("Injected job query failure.");
                }
                return TestJobActiveProcesses(job);
            },
        };
        using var hookScope = new GuardianCleanupHookScope(hooks);
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root), gate);
        var guardian = launch.Guardian!;
        var original = GuardianHandle(guardian, "_processHandle");
        var jobHandle = GuardianHandle(guardian, "_job");
        try
        {
            Assert.True(guardian.TryTerminate(19));
            Assert.True(launch.Process.WaitForExit(5_000));
            Assert.True(SpinWait.SpinUntil(() => TestJobActiveProcesses(jobHandle) == 0 &&
                DedicatedPidAbsent(guardian.ProcessId), TimeSpan.FromSeconds(5)));
            Assert.False(guardian.WaitForEmpty(TimeSpan.FromMilliseconds(30)));
            guardian.Dispose();
            if (unavailableProof != "unsignaled-handle")
                Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref probes) >= 3, TimeSpan.FromSeconds(5)));
            Assert.False(original.IsClosed);
            Assert.False(jobHandle.IsClosed);
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            Volatile.Write(ref hold, 0);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(original.IsClosed);
            Assert.True(jobHandle.IsClosed);
        }
        finally
        {
            Volatile.Write(ref hold, 0);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task GuardianKeeperEnforcesSurvivingDescendantAfterOriginalHostExit()
    {
        var root = CreateTestDirectory();
        var holdJobTermination = 1;
        var attempts = 0;
        using var hookScope = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            TerminateJob = (job, code) =>
            {
                Interlocked.Increment(ref attempts);
                return Volatile.Read(ref holdJobTermination) == 0 && TerminateTestJob(job, code);
            },
        });
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root, descendant: true), gate);
        var guardian = launch.Guardian!;
        var original = (SafeProcessHandle)GuardianHandle(guardian, "_processHandle");
        var jobHandle = GuardianHandle(guardian, "_job");
        try
        {
            Assert.True(SpinWait.SpinUntil(() => File.Exists(Path.Combine(root, "ready.txt")) &&
                TestJobActiveProcesses(jobHandle) >= 2, TimeSpan.FromSeconds(5)));
            var descendantPid = uint.Parse(File.ReadAllText(Path.Combine(root, "ready.txt")),
                System.Globalization.CultureInfo.InvariantCulture);
            Assert.True(TerminateTestProcess(original, 19));
            Assert.True(launch.Process.WaitForExit(5_000));
            Assert.False(guardian.WaitForEmpty(TimeSpan.FromMilliseconds(30)));
            guardian.Dispose();
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref attempts) >= 3, TimeSpan.FromSeconds(5)));
            Assert.True(TestJobActiveProcesses(jobHandle) >= 1);
            Assert.False(original.IsClosed);
            Assert.False(jobHandle.IsClosed);
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            Volatile.Write(ref holdJobTermination, 0);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(DedicatedPidAbsent(guardian.ProcessId));
            Assert.True(SpinWait.SpinUntil(() => DedicatedPidAbsent(descendantPid), TimeSpan.FromSeconds(5)));
            Assert.True(original.IsClosed);
            Assert.True(jobHandle.IsClosed);
        }
        finally
        {
            Volatile.Write(ref holdJobTermination, 0);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GuardianKeeperRetainsTimedOutSuspendedStartupBeforeOrAfterJobAssignment(bool beforeJobAssignment)
    {
        var root = CreateTestDirectory();
        var fail = 1;
        var attempts = 0;
        SafeProcessHandle? original = null;
        SafeHandle? jobHandle = null;
        using var hookScope = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            StartupCleanupTimeout = TimeSpan.FromMilliseconds(30),
            TerminateJob = (job, code) =>
            {
                jobHandle = job;
                return Volatile.Read(ref fail) == 0 && TerminateTestJob(job, code);
            },
            TerminateProcess = (process, code) =>
            {
                original = process;
                Interlocked.Increment(ref attempts);
                return Volatile.Read(ref fail) == 0 && TerminateTestProcess(process, code);
            },
        });
        using var gate = HostStartupGate.Create(root);
        if (!beforeJobAssignment) gate.Dispose();
        uint createdPid = 0;
        try
        {
            var error = Assert.ThrowsAny<Exception>(() => HostProcessGuardian.Start(DedicatedGuardianChild(root), gate, pid =>
            {
                createdPid = pid;
                if (beforeJobAssignment) throw new IOException("Injected pre-assignment failure.");
            }));
            Assert.Contains("cleanup could not", error.ToString());
            Assert.Contains(beforeJobAssignment ? "Injected pre-assignment failure" : "ObjectDisposedException", error.ToString());
            Assert.True(createdPid > 0);
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref attempts) >= 3, TimeSpan.FromSeconds(5)));
            Assert.NotNull(original);
            Assert.False(original!.IsClosed);
            Assert.Equal(258U, WaitForTestProcess(original, 0));
            Assert.False(DedicatedPidAbsent(createdPid));
            Assert.False(File.Exists(Path.Combine(root, "ready.txt")));
            if (!beforeJobAssignment) Assert.False(jobHandle!.IsClosed);
            Volatile.Write(ref fail, 0);
            Assert.True(SpinWait.SpinUntil(() => original.IsClosed && (jobHandle is null || jobHandle.IsClosed),
                TimeSpan.FromSeconds(5)));
            Assert.True(DedicatedPidAbsent(createdPid));
            Assert.False(File.Exists(Path.Combine(root, "ready.txt")));
        }
        finally
        {
            Volatile.Write(ref fail, 0);
            Assert.True(SpinWait.SpinUntil(() => original is null || original.IsClosed, TimeSpan.FromSeconds(5)));
            Directory.Delete(root, recursive: true);
        }
    }

    private static readonly Lazy<string> DedicatedGuardianChildPath = new(BuildDedicatedGuardianChild);

    private static ProcessStartInfo DedicatedGuardianChild(string root, bool descendant = false)
    {
        var path = Environment.GetEnvironmentVariable("APFSACCESS_GUARDIAN_TEST_CHILD");
        if (string.IsNullOrWhiteSpace(path)) path = DedicatedGuardianChildPath.Value;
        Assert.True(File.Exists(path), "The dedicated offline GuardianChild helper executable is missing.");
        var start = new ProcessStartInfo(path!) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root };
        start.ArgumentList.Add("--ready");
        start.ArgumentList.Add(Path.Combine(root, "ready.txt"));
        if (descendant) start.Environment["GUARDIAN_CHILD_DESCENDANT"] = "1";
        return start;
    }

    private static string BuildDedicatedGuardianChild()
    {
        var root = CreateTestDirectory();
        File.WriteAllText(Path.Combine(root, "GuardianChild.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework>
                <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>
              </PropertyGroup>
            </Project>
            """);
        File.WriteAllText(Path.Combine(root, "NuGet.Config"),
            "<configuration><packageSources><clear /></packageSources></configuration>");
        File.WriteAllText(Path.Combine(root, "Program.cs"), """
            using System.Diagnostics;
            if (args.Length == 2 && args[0] == "--descendant") { Thread.Sleep(30_000); return; }
            if (args.Length != 2 || args[0] != "--ready") throw new ArgumentException("Expected --ready path.");
            var readyPid = Environment.ProcessId;
            if (Environment.GetEnvironmentVariable("GUARDIAN_CHILD_DESCENDANT") == "1")
            {
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
                start.Environment.Remove("GUARDIAN_CHILD_DESCENDANT");
                start.ArgumentList.Add("--descendant"); start.ArgumentList.Add(args[1]);
                using var child = Process.Start(start)!;
                readyPid = child.Id;
            }
            File.WriteAllText(args[1] + ".pending", readyPid.ToString());
            File.Move(args[1] + ".pending", args[1]);
            var lifetime = Environment.GetEnvironmentVariable("GUARDIAN_CHILD_GRACEFUL_LIFETIME");
            if (!string.IsNullOrEmpty(lifetime))
            {
                while (File.Exists(lifetime)) Thread.Sleep(10);
                Thread.Sleep(int.Parse(Environment.GetEnvironmentVariable("GUARDIAN_CHILD_GRACEFUL_DELAY_MS") ?? "0"));
                return;
            }
            Thread.Sleep(30_000);
            """);
        var info = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var argument in new[] { "build", "GuardianChild.csproj", "--disable-build-servers", "--artifacts-path",
                     Path.Combine(root, "artifacts"), "--configfile", Path.Combine(root, "NuGet.Config"),
                     "-p:UseSharedCompilation=false", "-p:NuGetAudit=false", "-v:q" })
            info.ArgumentList.Add(argument);
        info.Environment["DOTNET_CLI_HOME"] = Path.Combine(root, "dotnet-home");
        info.Environment["DOTNET_GENERATE_ASPNET_CERTIFICATE"] = "false";
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        info.Environment["NUGET_PACKAGES"] = Path.Combine(root, "packages");
        using var build = Process.Start(info)!;
        var output = build.StandardOutput.ReadToEndAsync();
        var errors = build.StandardError.ReadToEndAsync();
        if (!build.WaitForExit(30_000))
        {
            build.Kill(entireProcessTree: true);
            build.WaitForExit();
            throw new TimeoutException("The dedicated offline guardian helper build timed out.");
        }
        Assert.True(build.ExitCode == 0, output.GetAwaiter().GetResult() + errors.GetAwaiter().GetResult());
        return Path.Combine(root, "artifacts", "bin", "GuardianChild", "debug", "GuardianChild.exe");
    }

    private static SafeHandle GuardianHandle(HostProcessGuardian guardian, string field)
        => Assert.IsAssignableFrom<SafeHandle>(typeof(HostProcessGuardian)
            .GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(guardian));

    private static bool DedicatedPidAbsent(uint pid)
    {
        var processes = Process.GetProcesses();
        try { return processes.All(process => process.Id != pid); }
        finally { foreach (var process in processes) process.Dispose(); }
    }

    private static uint? TestJobActiveProcesses(SafeHandle job)
    {
        var accounting = default(TestJobAccounting);
        return QueryTestJob(job, 1, ref accounting, (uint)Marshal.SizeOf<TestJobAccounting>(), out _)
            ? accounting.ActiveProcesses : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TestJobAccounting
    {
        public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryTestJob(SafeHandle job, uint informationClass, ref TestJobAccounting accounting,
        uint length, out uint returned);

    [DllImport("kernel32.dll", EntryPoint = "TerminateJobObject", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateTestJob(SafeHandle job, uint exitCode);

    [DllImport("kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateTestProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", EntryPoint = "WaitForSingleObject", SetLastError = true)]
    private static extern uint WaitForTestProcess(SafeProcessHandle process, uint timeout);

    [DllImport("kernel32.dll", EntryPoint = "GetExitCodeProcess", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTestExitCode(SafeProcessHandle process, out uint exitCode);

    private sealed class GuardianCleanupHookScope : IDisposable
    {
        private readonly HostGuardianCleanupTestHooks? _previous = HostProcessGuardian.CleanupTestHooks.Value;
        public GuardianCleanupHookScope(HostGuardianCleanupTestHooks hooks) => HostProcessGuardian.CleanupTestHooks.Value = hooks;
        public void Dispose() => HostProcessGuardian.CleanupTestHooks.Value = _previous;
    }

    [Fact]
    public async Task ProbeOperationsRejectNewWorkAfterBackendDisposal()
    {
        using var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = CreateTestPath("evidence.json"),
        });

        backend.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => backend.ProbeDevicesAsync(CancellationToken.None));
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => backend.ProbeVolumesAsync("test-device", CancellationToken.None));
    }

    [Fact]
    public void ClosingGuardianTerminatesLiveHostProcess()
    {
        using var child = StartVeryLongRunningChild();

        Assert.NotNull(child);

        try
        {
            using (HostProcessGuardian.Create(child!))
            {
                Assert.False(child!.HasExited);
            }

            Assert.True(
                child!.WaitForExit(5_000),
                "Closing the guardian should terminate the child before the ping command completes.");
        }
        finally
        {
            try
            {
                if (child is { HasExited: false })
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
                // Cleanup is best effort; the assertion above owns the result.
            }
        }
    }

    [Fact]
    public void WaitForEmptyReturnsOnlyAfterEveryAssignedProcessHasExited()
    {
        using var child = StartVeryLongRunningChild();
        using var guardian = HostProcessGuardian.Create(child);

        try
        {
            Assert.False(guardian.WaitForEmpty(TimeSpan.FromMilliseconds(50)));
            Assert.True(guardian.TryTerminate(1));
            Assert.True(
                guardian.WaitForEmpty(TimeSpan.FromSeconds(5)),
                "The guardian reported a non-empty job after bounded termination.");
            Assert.True(
                child.WaitForExit(0),
                "The job reported empty before the exact assigned process handle was signaled.");
        }
        finally
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
                // Cleanup is best effort; the assertions above own the result.
            }
        }
    }

    [Fact]
    public void SuspendedLaunchAssignsJobBeforeDescendantCanRun()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestDirectory();
        var gate = HostStartupGate.Create(root);
        HostProcessGuardian.LaunchResult? launch = null;
        var beforeCommandIds = SnapshotProcessIds("cmd");
        var gatePath = gate.FilePath;

        try
        {
            var command = "start /b cmd.exe /d /c ping -t 127.0.0.1 & ping -t 127.0.0.1";
            var startInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "CMD.EXE"),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = root,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add(command);

            launch = HostProcessGuardian.Start(startInfo, gate);
            var process = launch.Process;
            var guardian = Assert.IsType<HostProcessGuardian>(launch.Guardian);
            Assert.Equal((uint)process.Id, guardian.ProcessId);
            Assert.True(guardian.CreationTimeFileTimeUtc > 0);

            Assert.True(
                SpinWait.SpinUntil(
                    () => guardian.TryGetActiveProcessCount(out var count) && count >= 3,
                    TimeSpan.FromSeconds(5)),
                "The test host did not create its descendant before the bounded observation window.");

            var descendantIds = SnapshotProcessIds("cmd")
                .Where(processId => !beforeCommandIds.Contains(processId))
                .ToArray();
            Assert.True(
                descendantIds.Length >= 2,
                $"The guarded process tree did not expose a new cmd descendant; active={GetActiveProcessCount(guardian)}, " +
                $"cmd={string.Join(',', SnapshotProcessIds("cmd"))}, conhost={string.Join(',', SnapshotProcessIds("conhost"))}.");

            Assert.True(guardian.TryTerminate(19));
            Assert.True(guardian.WaitForEmpty(TimeSpan.FromSeconds(5)));
            Assert.True(process.WaitForExit(5_000));
            Assert.True(
                SpinWait.SpinUntil(
                    () => descendantIds.All(processId => !IsProcessRunning(processId)),
                    TimeSpan.FromSeconds(5)),
                "A descendant created after the guarded launch remained alive after job termination.");
        }
        finally
        {
            if (launch?.Guardian is { } guardian)
            {
                guardian.TryTerminate(19);
                guardian.WaitForEmpty(TimeSpan.FromSeconds(5));
                guardian.Dispose();
            }

            launch?.Process.Dispose();
            launch?.StartupStderr?.Dispose();
            gate.Dispose();
            TryDeleteFile(gatePath);
            Assert.False(File.Exists(gatePath));
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SuspendedLaunchCapturesStderrWithoutWaitingForPipeEof()
    {
        if (!OperatingSystem.IsWindows()) return;

        var root = CreateTestDirectory();
        using var gate = HostStartupGate.Create(root);
        HostProcessGuardian.LaunchResult? launch = null;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "CMD.EXE"),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = root,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add("echo [FsHost] startup failure 1>&2 & ping -n 4 127.0.0.1 >nul");

            launch = HostProcessGuardian.Start(startInfo, gate);
            Assert.NotNull(launch.StartupStderr);
            await Task.Delay(200);
            var started = Stopwatch.StartNew();
            var detail = await launch.StartupStderr!.GetLastLineAsync();
            Assert.True(started.Elapsed < TimeSpan.FromSeconds(1));
            Assert.Contains("[FsHost] startup failure", detail);
            Assert.False(launch.Process.HasExited);
        }
        finally
        {
            if (launch?.Guardian is { } guardian)
            {
                guardian.TryTerminate(19);
                guardian.WaitForEmpty(TimeSpan.FromSeconds(5));
                guardian.Dispose();
            }
            launch?.StartupStderr?.Dispose();
            launch?.Process.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void SuspendedStartupFailureReapsCreatedProcessBeforeResume()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestDirectory();
        var gate = HostStartupGate.Create(root);
        var gatePath = gate.FilePath;
        gate.Dispose();
        var beforeCommandIds = SnapshotProcessIds("cmd");
        var beforePingIds = SnapshotProcessIds("ping");
        uint? createdProcessId = null;

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "CMD.EXE"),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = root,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add("ping -t 127.0.0.1");

            Assert.Throws<ObjectDisposedException>(() => HostProcessGuardian.Start(
                startInfo,
                gate,
                processId => createdProcessId = processId));
            Assert.True(createdProcessId.HasValue);
            Assert.True(
                SpinWait.SpinUntil(
                    () => !IsProcessRunning(checked((int)createdProcessId.Value)),
                    TimeSpan.FromSeconds(5)),
                "The failed suspended startup did not reap the exact native process it created.");
            Assert.True(
                SpinWait.SpinUntil(
                    () => SnapshotProcessIds("cmd").All(beforeCommandIds.Contains),
                    TimeSpan.FromSeconds(5)),
                "The failed suspended startup left its exact cmd.exe process visible.");
            Assert.True(
                SnapshotProcessIds("ping").All(beforePingIds.Contains),
                "The failed suspended startup ran its payload or left a descendant alive.");
        }
        finally
        {
            TryDeleteFile(gatePath);
            Assert.False(File.Exists(gatePath));
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void LifetimeSentinelDisappearsWhenParentOwnershipEnds()
    {
        var root = Path.Combine(Path.GetTempPath(), "ApfsAccess.Tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(root, "host.alive");
        Directory.CreateDirectory(root);

        try
        {
            using (HostLifetimeSentinel.Create(path))
            {
                Assert.True(File.Exists(path));
            }

            Assert.False(File.Exists(path));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void StartupGateRequiresExplicitAuthorizationAndCleansFailedLaunch()
    {
        var root = Path.Combine(Path.GetTempPath(), "ApfsAccess.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            string failedPath;
            using (var failedGate = HostStartupGate.Create(root))
            {
                failedPath = failedGate.FilePath;
                Assert.True(File.Exists(failedPath));
                Assert.NotEqual(failedGate.AuthorizationToken, File.ReadAllText(failedPath));
            }

            Assert.False(File.Exists(failedPath));

            string authorizedPath;
            string authorizationToken;
            using (var gate = HostStartupGate.Create(root))
            {
                authorizedPath = gate.FilePath;
                authorizationToken = gate.AuthorizationToken;
                gate.Authorize();
            }

            Assert.True(File.Exists(authorizedPath));
            Assert.Equal(authorizationToken, File.ReadAllText(authorizedPath));
            File.Delete(authorizedPath);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FailedStartupAuthorizationClosesGuardianAndReapsChild()
    {
        using var child = StartVeryLongRunningChild();
        Assert.NotNull(child);

        var root = Path.Combine(Path.GetTempPath(), "ApfsAccess.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var gate = HostStartupGate.Create(root);
            gate.Dispose();

            Assert.Throws<ObjectDisposedException>(() => HostProcessGuardian.Create(child!, gate));
            Assert.True(
                child!.WaitForExit(5_000),
                "A failed post-assignment startup authorization must close the job and reap the child.");
        }
        finally
        {
            try
            {
                if (child is { HasExited: false })
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
                // Cleanup is best effort; the assertion above owns the result.
            }

            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void BackendDisposeClosesGuardianAndDeletesAuthorizedStartupGate()
    {
        var root = Path.Combine(Path.GetTempPath(), "ApfsAccess.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var lifetimePath = Path.Combine(root, "host.alive");
        var statusPath = Path.Combine(root, "host.status.json");
        File.WriteAllText(statusPath, "{}");
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        });

        var startupGate = HostStartupGate.Create(root);
        startupGate.Authorize();
        var startupGatePath = startupGate.FilePath;
        startupGate.Dispose();

        var child = StartVeryLongRunningChild();
        Assert.NotNull(child);
        using var observer = Process.GetProcessById(child!.Id);

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var guardian = HostProcessGuardian.Create(child);
            var backendType = typeof(NativeApfsBackend);
            var stateType = backendType.GetNestedType("HostProcessState", BindingFlags.NonPublic);
            Assert.NotNull(stateType);
            var constructor = stateType!.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .SingleOrDefault(candidate => candidate.GetParameters().Length == 8);
            Assert.NotNull(constructor);
            var state = constructor!.Invoke(
            [
                child,
                guardian,
                lifetime,
                lifetimePath,
                startupGatePath,
                statusPath,
                MountAccessMode.ReadOnly,
                "Disabled",
            ]);
            HostTerminalFixture.BindOrdinary(state, child, statusPath);

            var hosts = backendType
                .GetField("_hosts", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(backend)!;
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            backend.Dispose();

            Assert.True(observer.WaitForExit(5_000));
            Assert.False(File.Exists(lifetimePath));
            Assert.False(File.Exists(startupGatePath));
            Assert.False(File.Exists(statusPath));
        }
        finally
        {
            backend.Dispose();
            try
            {
                if (!observer.HasExited)
                {
                    observer.Kill(entireProcessTree: true);
                    observer.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void BackendDisposeRetainsHostOwnershipUntilProcessActuallyExits()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var statusPath = Path.Combine(root, "host.status.json");
        File.WriteAllText(statusPath, "{}");
        var hooks = new HostProcessLifecycleTestHooks
        {
            WaitForExit = (_, _) => false,
            KillProcess = _ => false,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var child = StartReleaseControlledChild(root, out var releasePath);
        using var observer = Process.GetProcessById(child.Id);

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            backend.Dispose();

            Assert.True(
                (bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                "A host whose process exit is unproven must remain reserved after bounded disposal.");
            Assert.False(child.HasExited);
            var retainedState = hosts.GetType().GetProperty("Item")!.GetValue(hosts, ["R:\\"]);
            Assert.NotNull(retainedState);
            Assert.NotNull(retainedState!.GetType().GetProperty("LifetimeSentinel")!.GetValue(retainedState));
            Assert.NotEmpty(Directory.GetFiles(
                Path.Combine(Path.GetTempPath(), "ApfsAccess", "write-diagnostics"),
                "backend-host-exit-unproven-*.json"));

            File.Delete(releasePath);
            Assert.True(observer.WaitForExit(8_000), "The isolated test child did not exit after its independent release.");
            Assert.True(
                SpinWait.SpinUntil(
                    () => !(bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                    TimeSpan.FromSeconds(5)),
                "Retained ownership was not released after the child actually exited.");
        }
        finally
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
                // Cleanup is best effort; the assertions own the result.
            }

            backend.Dispose();
            child.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void BackendDisposeRetainsSignaledHostWhileWindowsStillEnumeratesItsPid()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "enumerated-host.alive");
        var statusPath = Path.Combine(root, "enumerated-host.status.json");
        File.WriteAllText(statusPath, "{}");
        var systemPresence = 1;
        var hooks = new HostProcessLifecycleTestHooks
        {
            ProbeSystemProcessPresence = _ => Volatile.Read(ref systemPresence) != 0,
            ProbeExactProcessHandleExit = _ => null,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "/c", "exit 0" },
        });
        Assert.NotNull(child);
        Assert.True(child!.WaitForExit(5_000));
        Assert.True(child.HasExited);

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            backend.Dispose();

            Assert.True(
                (bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                "A signaled process must stay quarantined while Windows still enumerates its exact PID.");
            Assert.True(IsLifetimeLeaseOwned(lifetime));

            Interlocked.Exchange(ref systemPresence, 0);
            Assert.True(
                SpinWait.SpinUntil(
                    () => !(bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                    TimeSpan.FromSeconds(5)),
                "Retained ownership was not released after independent PID absence was proven.");
            Assert.False(IsLifetimeLeaseOwned(lifetime));
        }
        finally
        {
            Interlocked.Exchange(ref systemPresence, 0);
            backend.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SamePidAndCreationTimeRetainsHostGuardianAndMountReservation()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "same-pid.alive");
        var statusPath = Path.Combine(root, "same-pid.status.json");
        File.WriteAllText(statusPath, "{}");
        var systemPresence = 1;
        long launchCreationTime = 0;
        using var guardianProof = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            OriginalIdentityAbsent = (_, _) => Volatile.Read(ref systemPresence) == 0,
            CurrentProcessCreationTime = _ => launchCreationTime,
        });
        Process? child = null;
        HostProcessGuardian? guardian = null;
        var hooks = new HostProcessLifecycleTestHooks
        {
            ProbeSystemProcessPresence = _ => Volatile.Read(ref systemPresence) != 0,
            ProbeExactProcessHandleExit = _ => true,
            StartProcess = _ => throw new InvalidOperationException("replacement host must not start"),
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var volume = new VolumeInfo(
            VolumeId: "test-device|Main",
            DeviceId: "test-device",
            VolumeName: "Main",
            SupportsReadWrite: false,
            NativeVolumePath: "test-device\\ApfsAccess_Volumes\\Main");
        SeedVolumeCache(backend, volume);

        try
        {
            child = StartLongRunningChild();
            launchCreationTime = child.StartTime.ToFileTimeUtc();
            guardian = HostProcessGuardian.Create(child);
            Assert.True(child.WaitForExit(8_000), "The isolated test child did not exit.");

            SetLifecycleHook(
                hooks,
                "ProbeProcessCreationTime",
                (Func<int, long?>)(_ => launchCreationTime));
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            InvokePrivate(backend, "CleanupExitedHosts_NoLock");

            Assert.True(
                ContainsHost(backend, "R:\\"),
                "A signaled exact handle must not release a host while the same PID and creation time remain enumerated.");
            Assert.True(IsLifetimeLeaseOwned(lifetime));
            Assert.True(IsGuardianHandleOpen(guardian));

            var remount = await backend.MountAsync(
                new MountRequest(volume.VolumeId, 'R', MountAccessMode.ReadOnly),
                CancellationToken.None);
            Assert.False(remount.Success);
            Assert.Equal("MountPointBusy", remount.DiagnosticCode);
        }
        finally
        {
            Interlocked.Exchange(ref systemPresence, 0);
            backend.Dispose();
            try
            {
                if (child is { HasExited: false })
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            guardian?.Dispose();
            child?.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FallbackPidAbsenceCanProveExitAfterPrimaryEnumerationFails()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "fallback-absent.alive");
        var statusPath = Path.Combine(root, "fallback-absent.status.json");
        File.WriteAllText(statusPath, "{}");
        var fallbackCalls = 0;
        var hooks = new HostProcessLifecycleTestHooks
        {
            ProbeSystemProcessPresence = _ => null,
            ProbeFallbackSystemProcessPresence = _ =>
            {
                Interlocked.Increment(ref fallbackCalls);
                return false;
            },
            ProbeExactProcessHandleExit = _ => null,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        using var child = StartExitedChild();

        try
        {
            Assert.True(child.WaitForExit(5_000));
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            InvokePrivate(backend, "CleanupExitedHosts_NoLock");

            Assert.True(fallbackCalls > 0, "The independent fallback process enumeration was not attempted.");
            Assert.False(ContainsHost(backend, "R:\\"));
            Assert.False(IsLifetimeLeaseOwned(lifetime));
        }
        finally
        {
            backend.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void BackendDisposeRetainsSignaledHostWhenSystemPidProbeFails()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "unproven-host.alive");
        var statusPath = Path.Combine(root, "unproven-host.status.json");
        File.WriteAllText(statusPath, "{}");
        var probeSucceeded = 0;
        var hooks = new HostProcessLifecycleTestHooks
        {
            ProbeSystemProcessPresence = _ => Volatile.Read(ref probeSucceeded) == 0 ? null : false,
            ProbeFallbackSystemProcessPresence = _ => null,
            ProbeExactProcessHandleExit = _ => null,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "/c", "exit 0" },
        });
        Assert.NotNull(child);
        Assert.True(child!.WaitForExit(5_000));

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            backend.Dispose();

            Assert.True(
                (bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                "A failed system PID probe must not release host ownership.");
            Assert.True(IsLifetimeLeaseOwned(lifetime));

            Interlocked.Exchange(ref probeSucceeded, 1);
            Assert.True(
                SpinWait.SpinUntil(
                    () => !(bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                    TimeSpan.FromSeconds(5)),
                "Retained ownership was not released after PID absence became provable.");
            Assert.False(IsLifetimeLeaseOwned(lifetime));
        }
        finally
        {
            Interlocked.Exchange(ref probeSucceeded, 1);
            backend.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FailedStartupStopObservesLateProcessExitWithoutAnotherBackendCall()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "late-exit.alive");
        var statusPath = Path.Combine(root, "late-exit.status.json");
        File.WriteAllText(statusPath, "{}");
        var hooks = new HostProcessLifecycleTestHooks
        {
            KillProcess = _ => false,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var child = StartPingChild(8);

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var stopStartedHost = typeof(NativeApfsBackend).GetMethod(
                "StopStartedHostProcessAsync",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(stopStartedHost);

            var stopTask = Assert.IsAssignableFrom<Task>(stopStartedHost!.Invoke(
                backend,
                ["R:\\", state, CancellationToken.None]));
            await stopTask;

            var hosts = GetHosts(backend);
            Assert.True(
                (bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                "An unproven stop must retain the mount slot while the child is alive.");
            Assert.False(child.HasExited);

            using var observer = Process.GetProcessById(child.Id);
            Assert.True(observer.WaitForExit(10_000), "The isolated late-exit child did not exit.");
            Assert.True(
                SpinWait.SpinUntil(
                    () => !(bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                    TimeSpan.FromSeconds(5)),
                "A late child exit must release retained ownership without another backend operation.");
        }
        finally
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            backend.Dispose();
            child.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void GuardianCreationFailureRetainsStartedHostUntilChildExit()
    {
        var root = CreateTestDirectory();
        Process? startedChild = null;
        Process? originalObserver = null;
        var hooks = new HostProcessLifecycleTestHooks
        {
            StartProcess = _ =>
            {
                startedChild = StartLongRunningChild();
                originalObserver = Process.GetProcessById(startedChild.Id);
                return startedChild;
            },
            CreateGuardian = (_, _) => throw new InvalidOperationException("simulated guardian failure"),
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var volume = new VolumeInfo(
            VolumeId: "test-device|Main",
            DeviceId: "test-device",
            VolumeName: "Main",
            SupportsReadWrite: false,
            NativeVolumePath: "test-device\\ApfsAccess_Volumes\\Main");
        SeedAuthoritativeMountTarget(backend, volume);

        try
        {
            var startHost = typeof(NativeApfsBackend).GetMethod(
                "StartHostProcess",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(startHost);

            var invocation = Assert.Throws<TargetInvocationException>(
                () => startHost!.Invoke(backend, [volume, "R:\\", MountAccessMode.ReadOnly, null]));
            var exception = Assert.IsType<InvalidOperationException>(invocation.InnerException);
            Assert.Equal(
                "Unable to establish an OS-level lifetime guardian for the native mount host.",
                exception.Message);
            Assert.Equal("simulated guardian failure", exception.InnerException?.Message);

            Assert.NotNull(startedChild);
            var hosts = GetHosts(backend);
            Assert.True(
                (bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                "A started host must remain reserved when guardian creation fails.");

            var state = hosts.GetType().GetProperty("Item")!.GetValue(hosts, ["R:\\"]);
            Assert.NotNull(state);
            Assert.Null(state!.GetType().GetProperty("Guardian")!.GetValue(state));
            var retainedLifetimePath = (string)state.GetType().GetProperty("LifetimeFilePath")!.GetValue(state)!;

            HostTerminalFixture.BindOrdinary(state, startedChild!, (string)state.GetType().GetProperty("StatusFilePath")!.GetValue(state)!);
            Assert.True(originalObserver!.WaitForExit(8_000), "The isolated startup-failure child did not exit.");
            Assert.True(
                SpinWait.SpinUntil(
                    () => !(bool)hosts.GetType().GetMethod("ContainsKey")!.Invoke(hosts, ["R:\\"])!,
                    TimeSpan.FromSeconds(5)),
                "The guardian-less host was not released after exact child exit.");
            Assert.False(File.Exists(retainedLifetimePath));
        }
        finally
        {
            try
            {
                if (startedChild is { HasExited: false })
                {
                    startedChild.Kill(entireProcessTree: true);
                    startedChild.WaitForExit(2_000);
                }
            }
            catch
            {
                // Cleanup is best effort; the assertions own the result.
            }

            backend.Dispose();
            startedChild?.Dispose();
            originalObserver?.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StartupRegistrationCollisionRetainsMountUntilSupplementalChildExit()
    {
        var root = CreateTestDirectory();
        var startedChildren = new List<Process>();
        var originalObservers = new List<Process>();
        var existingChild = StartReleaseControlledChild(Path.Combine(root, "existing-child"), out var existingRelease);
        using var existingObserver = Process.GetProcessById(existingChild.Id);
        string? supplementalRelease = null;
        var devicePath = Path.Combine(root, "test-device.apfs.img");
        SyntheticApfsTestImage.Create(devicePath, sizeMiB: 4);
        var existingLifetimePath = Path.Combine(root, "existing.alive");
        var existingStatusPath = Path.Combine(root, "existing.status.json");
        File.WriteAllText(existingStatusPath, "{}");
        var hooks = new HostProcessLifecycleTestHooks
        {
            StartProcess = _ =>
            {
                var child = StartReleaseControlledChild(Path.Combine(root, "supplemental-child"), out var release);
                supplementalRelease = release;
                startedChildren.Add(child);
                originalObservers.Add(Process.GetProcessById(child.Id));
                return child;
            },
            CreateGuardian = (_, _) => throw new InvalidOperationException("simulated guardian failure"),
            KillProcess = _ => false,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var volume = new VolumeInfo(
            VolumeId: $"{devicePath}|Main",
            DeviceId: devicePath,
            VolumeName: "Main",
            SupportsReadWrite: false,
            NativeVolumePath: $"{devicePath}\\ApfsAccess_Volumes\\Main");
        SeedVolumeCache(backend, volume);
        SeedAuthoritativeMountTarget(backend, volume);

        try
        {
            var existingLifetime = HostLifetimeSentinel.Create(existingLifetimePath);
            var existingState = CreateHostProcessState(
                existingChild,
                guardian: null,
                existingLifetime,
                existingLifetimePath,
                startupGatePath: string.Empty,
                existingStatusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", existingState])!);

            var startHost = typeof(NativeApfsBackend).GetMethod(
                "StartHostProcess",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(startHost);

            var invocation = Assert.Throws<TargetInvocationException>(
                () => startHost!.Invoke(backend, [
                    volume,
                    "R:\\",
                    MountAccessMode.ReadOnly, null]));
            var exception = Assert.IsType<InvalidOperationException>(invocation.InnerException);
            Assert.Equal(
                "Unable to establish an OS-level lifetime guardian for the native mount host.",
                exception.Message);
            Assert.Equal("simulated guardian failure", exception.InnerException?.Message);
            Assert.Single(startedChildren);

            File.Delete(existingRelease);
            Assert.True(existingObserver.WaitForExit(8_000), "The original host fixture did not exit after release.");
            InvokePrivate(backend, "CleanupExitedHosts_NoLock");
            Assert.False(ContainsHost(backend, "R:\\"));

            Assert.False(originalObservers[0].HasExited);
            var remount = await backend.MountAsync(
                new MountRequest(volume.VolumeId, 'R', MountAccessMode.ReadOnly),
                CancellationToken.None);
            Assert.False(remount.Success);
            Assert.Equal("MountPointBusy", remount.DiagnosticCode);
            Assert.True(
                startedChildren.Count == 1,
                "A retained supplemental startup host must prevent a replacement host from starting.");

            var retainedHosts = typeof(NativeApfsBackend)
                .GetField("_retainedStartupHosts", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(backend)!;
            Assert.Equal(1, (int)retainedHosts.GetType().GetProperty("Count")!.GetValue(retainedHosts)!);

            foreach (var retainedState in (System.Collections.IEnumerable)retainedHosts.GetType().GetProperty("Values")!.GetValue(retainedHosts)!)
                HostTerminalFixture.BindOrdinary(retainedState, startedChildren[0], (string)retainedState.GetType().GetProperty("StatusFilePath")!.GetValue(retainedState)!);
            Assert.NotNull(supplementalRelease);
            File.Delete(supplementalRelease);
            Assert.True(originalObservers[0].WaitForExit(8_000), "The supplemental retained child did not exit.");
            Assert.True(
                SpinWait.SpinUntil(
                    () => (int)retainedHosts.GetType().GetProperty("Count")!.GetValue(retainedHosts)! == 0,
                    TimeSpan.FromSeconds(5)),
                "Supplemental ownership was not released after exact child exit.");
        }
        finally
        {
            try
            {
                foreach (var startedChild in startedChildren)
                {
                    if (!startedChild.HasExited)
                    {
                        startedChild.Kill(entireProcessTree: true);
                        startedChild.WaitForExit(2_000);
                    }
                }

                if (!existingChild.HasExited)
                {
                    existingChild.Kill(entireProcessTree: true);
                    existingChild.WaitForExit(2_000);
                }
            }
            catch
            {
                // Cleanup is best effort; the assertions own the result.
            }

            backend.Dispose();
            foreach (var startedChild in startedChildren)
            {
                startedChild.Dispose();
            }
            foreach (var originalObserver in originalObservers) originalObserver.Dispose();
            existingChild.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ObserverOwnsProcessCleanupAgainstGenericExitedHostCleanup()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "observer-owned.alive");
        var statusPath = Path.Combine(root, "observer-owned.status.json");
        File.WriteAllText(statusPath, "{}");
        using var observerEntered = new ManualResetEventSlim();
        using var allowObserverProof = new ManualResetEventSlim();
        var hooks = new HostProcessLifecycleTestHooks
        {
            WaitForExit = (_, _) => false,
            KillProcess = _ => false,
        };
        SetLifecycleHook(
            hooks,
            "BeforeObserverProof",
            (Action<Process>)(_ =>
            {
                observerEntered.Set();
                allowObserverProof.Wait(TimeSpan.FromSeconds(10));
            }));
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var child = StartVeryLongRunningChild();
        using var exitObserver = Process.GetProcessById(child.Id);

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var stopTask = Assert.IsAssignableFrom<Task>(InvokePrivate(
                backend,
                "StopStartedHostProcessAsync",
                "R:\\",
                state,
                CancellationToken.None));
            await stopTask;
            Assert.True(ContainsHost(backend, "R:\\"));

            child.Kill(entireProcessTree: true);
            Assert.True(exitObserver.WaitForExit(5_000));
            Assert.True(
                observerEntered.Wait(TimeSpan.FromSeconds(5)),
                "The asynchronous observer did not reach its proof boundary.");

            InvokePrivate(backend, "CleanupExitedHosts_NoLock");
            Assert.True(
                ContainsHost(backend, "R:\\"),
                "Generic cleanup must not remove an observer-owned host.");
            Assert.True(IsLifetimeLeaseOwned(lifetime));

            allowObserverProof.Set();
            Assert.True(
                SpinWait.SpinUntil(
                    () => !ContainsHost(backend, "R:\\"),
                    TimeSpan.FromSeconds(5)),
                "The observer did not release ownership after proving process exit.");
        }
        finally
        {
            allowObserverProof.Set();
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            backend.Dispose();
            child.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ObserverUsesExactProcessIdentityWhenPidIsStillEnumerated()
    {
        var root = CreateTestDirectory();
        Process? startedChild = null;
        using var observerEntered = new ManualResetEventSlim();
        using var allowObserverProof = new ManualResetEventSlim();
        var hooks = new HostProcessLifecycleTestHooks
        {
            StartProcess = _ => startedChild = StartLongRunningChild(),
            CreateGuardian = (_, _) => throw new InvalidOperationException("simulated guardian failure"),
            ProbeSystemProcessPresence = _ => true,
        };
        SetLifecycleHook(
            hooks,
            "ProbeProcessCreationTime",
            (Func<int, long?>)(_ => 0L));
        SetLifecycleHook(
            hooks,
            "BeforeObserverProof",
            (Action<Process>)(_ =>
            {
                observerEntered.Set();
                allowObserverProof.Wait(TimeSpan.FromSeconds(10));
            }));
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var volume = new VolumeInfo(
            VolumeId: "test-device|Main",
            DeviceId: "test-device",
            VolumeName: "Main",
            SupportsReadWrite: false,
            NativeVolumePath: "test-device\\ApfsAccess_Volumes\\Main");
        SeedAuthoritativeMountTarget(backend, volume);

        try
        {
            var startHost = typeof(NativeApfsBackend).GetMethod(
                "StartHostProcess",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(startHost);
            var invocation = Assert.Throws<TargetInvocationException>(
                () => startHost!.Invoke(backend, [volume, "R:\\", MountAccessMode.ReadOnly, null]));
            var exception = Assert.IsType<InvalidOperationException>(invocation.InnerException);
            Assert.Equal(
                "Unable to establish an OS-level lifetime guardian for the native mount host.",
                exception.Message);
            Assert.Equal("simulated guardian failure", exception.InnerException?.Message);
            Assert.NotNull(startedChild);

            Assert.True(startedChild!.WaitForExit(10_000));
            Assert.True(
                observerEntered.Wait(TimeSpan.FromSeconds(5)),
                "The observer did not reach the PID-reuse proof boundary.");
            Assert.True(ContainsHost(backend, "R:\\"));

            var originalState = GetHosts(backend).GetType().GetProperty("Item")!.GetValue(GetHosts(backend), ["R:\\"])!;
            HostTerminalFixture.BindOrdinary(originalState, startedChild, (string)originalState.GetType().GetProperty("StatusFilePath")!.GetValue(originalState)!);
            allowObserverProof.Set();
            Assert.True(
                SpinWait.SpinUntil(
                    () => !ContainsHost(backend, "R:\\"),
                    TimeSpan.FromSeconds(5)),
                "A reused PID must not prevent release after the original process handle proves exit.");
        }
        finally
        {
            allowObserverProof.Set();
            try
            {
                if (startedChild is { HasExited: false })
                {
                    startedChild.Kill(entireProcessTree: true);
                    startedChild.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            backend.Dispose();
            startedChild?.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ObserverEscalatesPersistentProofFailureToTerminalRetention()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "terminal.alive");
        var statusPath = Path.Combine(root, "terminal.status.json");
        File.WriteAllText(statusPath, "{}");
        using var terminalDiagnostic = new ManualResetEventSlim();
        var hooks = new HostProcessLifecycleTestHooks
        {
            ProbeSystemProcessPresence = _ => null,
            ProbeFallbackSystemProcessPresence = _ => null,
        };
        SetLifecycleHook(
            hooks,
            "ProbeExactProcessHandleExit",
            (Func<Process, bool?>)(_ => null));
        SetLifecycleHook(
            hooks,
            "OnLifecycleDiagnostic",
            (Action<string>)(stage =>
            {
                if (string.Equals(stage, "host-exit-observer-terminal", StringComparison.Ordinal))
                {
                    terminalDiagnostic.Set();
                }
            }));
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        using var child = StartExitedChild();

        try
        {
            Assert.True(child.WaitForExit(5_000));
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            backend.Dispose();

            Assert.True(
                terminalDiagnostic.Wait(TimeSpan.FromSeconds(10)),
                "Persistent proof failure did not produce a terminal lifecycle diagnostic.");
            Assert.True(ContainsHost(backend, "R:\\"));
            Assert.Equal(0, GetPrivateDictionaryCount(backend, "_hostExitObservers"));
            Assert.True(IsLifetimeLeaseOwned(lifetime));
        }
        finally
        {
            SetLifecycleHook(
                hooks,
                "ProbeExactProcessHandleExit",
                (Func<Process, bool?>)(_ => true));
            hooks.ProbeSystemProcessPresence = _ => false;
            InvokePrivate(backend, "CleanupExitedHosts_NoLock");
            backend.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ObserverBoundsWaitForLiveHostBeforeTerminalRetention()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "live-terminal.alive");
        var statusPath = Path.Combine(root, "live-terminal.status.json");
        File.WriteAllText(statusPath, "{}");
        using var terminalDiagnostic = new ManualResetEventSlim();
        var hooks = new HostProcessLifecycleTestHooks
        {
            WaitForExit = (_, _) => false,
            KillProcess = _ => false,
        };
        SetLifecycleHook(
            hooks,
            "OnLifecycleDiagnostic",
            (Action<string>)(stage =>
            {
                if (string.Equals(stage, "host-exit-observer-terminal", StringComparison.Ordinal))
                {
                    terminalDiagnostic.Set();
                }
            }));
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        using var child = StartVeryLongRunningChild();

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var hosts = GetHosts(backend);
            Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);

            backend.Dispose();

            Assert.True(
                terminalDiagnostic.Wait(TimeSpan.FromSeconds(15)),
                "A live host made the bounded exit observer wait forever.");
            Assert.False(child.HasExited);
            Assert.True(ContainsHost(backend, "R:\\"));
            Assert.Equal(0, GetPrivateDictionaryCount(backend, "_hostExitObservers"));
            Assert.True(IsLifetimeLeaseOwned(lifetime));
        }
        finally
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            Assert.True(
                SpinWait.SpinUntil(
                    () => GetPrivateDictionaryCount(backend, "_hostExitObservers") == 0,
                    TimeSpan.FromSeconds(5)),
                "The observer did not release its bookkeeping after the test child exited.");
            InvokePrivate(backend, "CleanupExitedHosts_NoLock");
            backend.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CanceledStopStillSignalsAndInstallsExitObserver()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "canceled.alive");
        var statusPath = Path.Combine(root, "canceled.status.json");
        File.WriteAllText(statusPath, "{}");
        var hooks = new HostProcessLifecycleTestHooks
        {
            WaitForExit = (_, _) => false,
            KillProcess = _ => false,
        };
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);
        var child = StartVeryLongRunningChild();
        using var exitObserver = Process.GetProcessById(child.Id);

        try
        {
            var lifetime = HostLifetimeSentinel.Create(lifetimePath);
            var state = CreateHostProcessState(
                child,
                guardian: null,
                lifetime,
                lifetimePath,
                startupGatePath: string.Empty,
                statusPath);
            var stopTask = Assert.IsAssignableFrom<Task>(InvokePrivate(
                backend,
                "StopStartedHostProcessAsync",
                "R:\\",
                state,
                new CancellationToken(canceled: true)));
            await stopTask;

            Assert.False(File.Exists(lifetimePath));
            Assert.True(ContainsHost(backend, "R:\\"));
            Assert.True(GetPrivateDictionaryCount(backend, "_hostExitObservers") > 0);

            child.Kill(entireProcessTree: true);
            Assert.True(exitObserver.WaitForExit(5_000));
            Assert.True(
                SpinWait.SpinUntil(
                    () => !ContainsHost(backend, "R:\\"),
                    TimeSpan.FromSeconds(5)),
                "The cancellation path did not retain a reaper until process exit.");
        }
        finally
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    child.WaitForExit(2_000);
                }
            }
            catch
            {
            }

            backend.Dispose();
            child.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTestPath(string fileName)
    {
        return Path.Combine(CreateTestDirectory(), fileName);
    }

    private static string CreateTestDirectory()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "ApfsAccessTests",
            "HostProcessGuardian",
            "tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static object GetHosts(NativeApfsBackend backend)
    {
        return typeof(NativeApfsBackend)
            .GetField("_hosts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
    }

    private static bool ContainsHost(NativeApfsBackend backend, string mountPoint)
        => (bool)GetHosts(backend).GetType().GetMethod("ContainsKey")!.Invoke(
            GetHosts(backend),
            [mountPoint])!;

    private static int GetPrivateDictionaryCount(NativeApfsBackend backend, string fieldName)
    {
        var dictionary = typeof(NativeApfsBackend)
            .GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        return (int)dictionary.GetType().GetProperty("Count")!.GetValue(dictionary)!;
    }

    private static object? InvokePrivate(
        NativeApfsBackend backend,
        string methodName,
        params object?[] arguments)
        => typeof(NativeApfsBackend)
            .GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(backend, arguments);

    private static void SetLifecycleHook<T>(
        HostProcessLifecycleTestHooks hooks,
        string propertyName,
        T value)
    {
        var property = typeof(HostProcessLifecycleTestHooks).GetProperty(
            propertyName,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(property);
        property!.SetValue(hooks, value);
    }

    private static void SeedVolumeCache(NativeApfsBackend backend, VolumeInfo volume)
    {
        var cache = typeof(NativeApfsBackend)
            .GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var tryAdd = cache.GetType().GetMethods()
            .Single(method => method.Name == "TryAdd" && method.GetParameters().Length == 2);
        Assert.True((bool)tryAdd.Invoke(cache, [volume.VolumeId, volume])!);
    }

    private static void SeedAuthoritativeMountTarget(NativeApfsBackend backend, VolumeInfo volume)
    {
        var targetType = typeof(NativeApfsBackend).GetNestedType(
            "VolumeMountTarget",
            BindingFlags.NonPublic);
        Assert.NotNull(targetType);
        var target = targetType!.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Single(constructor => constructor.GetParameters().Length == 3)
            .Invoke([volume.DeviceId, 0UL, null]);
        var targets = typeof(NativeApfsBackend)
            .GetField("_mountTargetsByVolumeId", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var tryAdd = targets.GetType().GetMethods()
            .Single(method => method.Name == "TryAdd" && method.GetParameters().Length == 2);
        Assert.True((bool)tryAdd.Invoke(targets, [volume.VolumeId, target])!);
    }

    private static bool IsLifetimeLeaseOwned(HostLifetimeSentinel lifetime)
        => typeof(HostLifetimeSentinel)
            .GetField("_lease", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(lifetime) is not null;

    private static bool IsGuardianHandleOpen(HostProcessGuardian guardian)
    {
        var job = typeof(HostProcessGuardian)
            .GetField("_job", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(guardian);
        if (job is null)
        {
            return false;
        }

        var isClosed = (bool)job.GetType().GetProperty("IsClosed")!.GetValue(job)!;
        var isInvalid = (bool)job.GetType().GetProperty("IsInvalid")!.GetValue(job)!;
        return !isClosed && !isInvalid;
    }

    private static object CreateHostProcessState(
        Process process,
        HostProcessGuardian? guardian,
        HostLifetimeSentinel? lifetime,
        string lifetimePath,
        string startupGatePath,
        string statusPath,
        bool publishTerminal = true)
    {
        var stateType = typeof(NativeApfsBackend).GetNestedType(
            "HostProcessState",
            BindingFlags.NonPublic);
        Assert.NotNull(stateType);
        var constructor = stateType!.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Single(candidate => candidate.GetParameters().Length == 8);
        var state = constructor.Invoke(
        [
            process,
            guardian,
            lifetime,
            lifetimePath,
            startupGatePath,
            statusPath,
            MountAccessMode.ReadOnly,
            "Disabled",
        ]);
        if (publishTerminal) HostTerminalFixture.BindOrdinary(state, process, statusPath);
        return state;
    }

    private static Process StartLongRunningChild()
        => StartPingChild(8);

    private static Process StartReleaseControlledChild(string root, out string releasePath)
    {
        Directory.CreateDirectory(root);
        releasePath = Path.Combine(root, "independent-child.alive");
        File.WriteAllText(releasePath, "wait for the test's release");
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = releasePath;
        var child = Process.Start(start)!;
        Assert.True(SpinWait.SpinUntil(() => File.Exists(Path.Combine(root, "ready.txt")), TimeSpan.FromSeconds(5)));
        return child;
    }

    private static Process StartVeryLongRunningChild()
        => StartPingChild(30);

    private static Process StartPingChild(int count)
    {
        return Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            ArgumentList =
            {
                "-n",
                count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "127.0.0.1",
            },
        })!;
    }

    private static Process StartExitedChild()
    {
        return Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "/c", "exit 0" },
        })!;
    }

    private static HashSet<int> SnapshotProcessIds(string processName)
    {
        var result = new HashSet<int>();
        foreach (var process in Process.GetProcessesByName(processName))
        {
            result.Add(process.Id);
            process.Dispose();
        }

        return result;
    }

    private static bool IsProcessRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static uint GetActiveProcessCount(HostProcessGuardian guardian)
        => guardian.TryGetActiveProcessCount(out var count) ? count : 0;

    private static void TryDeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        File.Delete(path);
    }
}
