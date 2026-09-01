using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class FsHostSupervisorTests : IDisposable
{
    private readonly string supervisorExecutablePath;
    private readonly string supervisorPayloadPath;
    private readonly IDisposable supervisorExecutableScope;

    public FsHostSupervisorTests()
    {
        var cliDirectory = Path.GetDirectoryName(typeof(FsHostSupervisor).Assembly.Location)!;
        supervisorExecutablePath = Path.Combine(cliDirectory, "ApfsAccess.Cli.exe");
        supervisorPayloadPath = Path.Combine(cliDirectory, "ApfsAccess.Cli.dll");
        Assert.True(File.Exists(supervisorExecutablePath), "The built CLI apphost is missing from the test output.");
        Assert.True(File.Exists(supervisorPayloadPath), "The built CLI payload is missing from the test output.");
        supervisorExecutableScope = FsHostSupervisor.InstallSupervisorExecutablePathForTests(
            supervisorExecutablePath);
    }

    public void Dispose() => supervisorExecutableScope.Dispose();

    [Fact]
    public void EvidenceSerializesExactFileTimeAsString()
    {
        const long fileTime = 134324039887674841;
        var json = JsonSerializer.Serialize(new FsHostSupervisorEvidence
        {
            HostCreationTimeFileTime = fileTime,
        });

        using var document = JsonDocument.Parse(json);
        var value = document.RootElement.GetProperty(nameof(FsHostSupervisorEvidence.HostCreationTimeFileTime));
        Assert.Equal(JsonValueKind.String, value.ValueKind);
        Assert.Equal(fileTime.ToString(), value.GetString());
    }

    [Fact]
    public async Task SupervisorReapsExactCmdChildAndWritesLifecycleEvidence()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var gatePath = Path.Combine(root, "startup.gate");
        var gateToken = "test-token-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(lifetimePath, "alive");
        File.WriteAllText(gatePath, "pending");

        var runTask = Program.Main(
        [
            "supervise-fshost",
            "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            "--host-arg", "/c",
            "--host-arg", "ping.exe",
            "--host-arg", "-n",
            "--host-arg", "30",
            "--host-arg", "127.0.0.1",
            "--owner-pid", Environment.ProcessId.ToString(),
            "--lifetime-file", lifetimePath,
            "--startup-gate-file", gatePath,
            "--startup-gate-token", gateToken,
            "--launch-record", launchPath,
            "--evidence-file", evidencePath,
            "--mount-point", Path.Combine(root, "mount"),
            "--graceful-timeout-ms", "250",
            "--process-absence-timeout-ms", "5000",
        ]);

        try
        {
            using var launch = await WaitForJsonAsync(launchPath, TimeSpan.FromSeconds(5));
            var launchRoot = launch.RootElement;
            var hostPid = launchRoot.GetProperty("hostPid").GetInt32();
            Assert.NotEqual(Environment.ProcessId, hostPid);
            Assert.True(launchRoot.GetProperty("jobAssigned").GetBoolean());
            Assert.True(launchRoot.GetProperty("resumed").GetBoolean());
            Assert.True(launchRoot.GetProperty("startupGateAuthorized").GetBoolean());
            Assert.Equal(
                Path.GetFullPath(supervisorExecutablePath),
                Path.GetFullPath(launchRoot.GetProperty("supervisorExecutable").GetString()!));
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(supervisorExecutablePath))),
                launchRoot.GetProperty("supervisorSha256").GetString());
            Assert.Equal(
                Path.GetFullPath(supervisorPayloadPath),
                Path.GetFullPath(launchRoot.GetProperty("supervisorPayloadPath").GetString()!));
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(supervisorPayloadPath))),
                launchRoot.GetProperty("supervisorPayloadSha256").GetString());
            Assert.Equal(Path.GetFullPath(launchPath), Path.GetFullPath(launchRoot.GetProperty("launchRecordPath").GetString()!));
            Assert.Equal(Path.GetFullPath(evidencePath), Path.GetFullPath(launchRoot.GetProperty("evidenceFile").GetString()!));
            Assert.Equal(gateToken, File.ReadAllText(gatePath));

            File.Delete(lifetimePath);
            Assert.Equal(0, await runTask.WaitAsync(TimeSpan.FromSeconds(15)));

            using var evidence = await WaitForJsonAsync(evidencePath, TimeSpan.FromSeconds(2));
            var rootElement = evidence.RootElement;
            Assert.Equal(hostPid, rootElement.GetProperty("hostPid").GetInt32());
            Assert.True(rootElement.GetProperty("supervisionProven").GetBoolean());
            Assert.True(rootElement.GetProperty("forcedJobTermination").GetBoolean());
            Assert.True(rootElement.GetProperty("hostPidAbsentFromProcessEnumeration").GetBoolean());
            Assert.True(rootElement.GetProperty("hostIdentityCaptured").GetBoolean());
            Assert.Equal("absent", rootElement.GetProperty("hostIdentityState").GetString());
            Assert.True(rootElement.GetProperty("mountAbsentFromDirectProbe").GetBoolean());
            Assert.True(rootElement.GetProperty("jobClosed").GetBoolean());
            Assert.Equal(
                Path.GetFullPath(supervisorExecutablePath),
                Path.GetFullPath(rootElement.GetProperty("supervisorExecutable").GetString()!));
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(supervisorExecutablePath))),
                rootElement.GetProperty("supervisorSha256").GetString());
            Assert.Equal(
                Path.GetFullPath(supervisorPayloadPath),
                Path.GetFullPath(rootElement.GetProperty("supervisorPayloadPath").GetString()!));
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(supervisorPayloadPath))),
                rootElement.GetProperty("supervisorPayloadSha256").GetString());
            Assert.Equal(Path.GetFullPath(launchPath), Path.GetFullPath(rootElement.GetProperty("launchRecordPath").GetString()!));
            Assert.Equal(Path.GetFullPath(evidencePath), Path.GetFullPath(rootElement.GetProperty("evidenceFile").GetString()!));
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            try { await runTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SupervisorReturnsFailureWhenTerminalLaunchRecordCannotBePublished()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        File.WriteAllText(lifetimePath, "alive");

        var runTask = Program.Main(
        [
            "supervise-fshost",
            "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            "--host-arg", "/c",
            "--host-arg", "ping.exe",
            "--host-arg", "-n",
            "--host-arg", "30",
            "--host-arg", "127.0.0.1",
            "--owner-pid", Environment.ProcessId.ToString(),
            "--lifetime-file", lifetimePath,
            "--launch-record", launchPath,
            "--evidence-file", evidencePath,
            "--mount-point", Path.Combine(root, "mount"),
            "--graceful-timeout-ms", "250",
            "--process-absence-timeout-ms", "5000",
        ]);

        try
        {
            using var launch = await WaitForJsonAsync(launchPath, TimeSpan.FromSeconds(5));
            using var launchLock = new FileStream(
                launchPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);

            File.Delete(lifetimePath);
            var exitCode = await runTask.WaitAsync(TimeSpan.FromSeconds(15));

            Assert.NotEqual(0, exitCode);
            using var evidence = await WaitForJsonAsync(evidencePath, TimeSpan.FromSeconds(2));
            Assert.Equal("failed", evidence.RootElement.GetProperty("status").GetString());
            Assert.NotNull(evidence.RootElement.GetProperty("failure").GetString());
            Assert.Equal(1, evidence.RootElement.GetProperty("supervisorExitCode").GetInt32());
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            try { await runTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ProductionSupervisorIgnoresTestOnlyLaunchRecordEnvironmentControls()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        File.WriteAllText(lifetimePath, "alive");

        const string suppressVariable = "APFSACCESS_SUPERVISOR_TEST_SUPPRESS_LAUNCH_RECORD";
        const string delayVariable = "APFSACCESS_SUPERVISOR_TEST_LAUNCH_RECORD_DELAY_MS";
        var previousSuppress = Environment.GetEnvironmentVariable(suppressVariable);
        var previousDelay = Environment.GetEnvironmentVariable(delayVariable);
        Environment.SetEnvironmentVariable(suppressVariable, "1");
        Environment.SetEnvironmentVariable(delayVariable, "2000");

        var runTask = Program.Main(
        [
            "supervise-fshost",
            "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
            "--host-arg", "/c",
            "--host-arg", "exit",
            "--host-arg", "0",
            "--owner-pid", Environment.ProcessId.ToString(),
            "--lifetime-file", lifetimePath,
            "--launch-record", launchPath,
            "--evidence-file", evidencePath,
            "--mount-point", Path.Combine(root, "mount"),
        ]);

        try
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(750);
            while (DateTime.UtcNow < deadline && !File.Exists(launchPath))
            {
                await Task.Delay(25);
            }

            Assert.True(File.Exists(launchPath), "Ambient test controls altered production launch-record publication.");
            await runTask.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            try { await runTask.WaitAsync(TimeSpan.FromSeconds(10)); } catch { }
            Environment.SetEnvironmentVariable(suppressVariable, previousSuppress);
            Environment.SetEnvironmentVariable(delayVariable, previousDelay);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task InlineQuarantineStopsAtCancellationDeadlineWithoutReturningSuccess()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var mountPoint = Path.Combine(root, "mount");
        File.WriteAllText(lifetimePath, "alive");
        Directory.CreateDirectory(mountPoint);

        var probeAllowsAbsenceAt = DateTime.UtcNow.AddSeconds(2.5);
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            StartQuarantineOwnerOverride = () => false,
            MountPointProbeOverride = _ => DateTime.UtcNow >= probeAllowsAbsenceAt
                ? new FsHostMountProbeResult(true, "test-absent", "delayed probe recovery")
                : new FsHostMountProbeResult(false, "test-present", "delayed probe failure"),
        });
        using var cancellation = new CancellationTokenSource();

        var runTask = FsHostSupervisor.RunAsync(
            new FsHostSupervisorOptions(
                HostPath: Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                HostArguments: ["/c", "exit", "0"],
                OwnerPid: Environment.ProcessId.ToString(),
                LifetimeFile: lifetimePath,
                LaunchRecordPath: launchPath,
                EvidenceFile: evidencePath,
                MountPoint: mountPoint,
                GracefulTimeoutMs: 50,
                ProcessAbsenceTimeoutMs: 250,
                OwnerPollIntervalMs: 25),
            cancellation.Token);

        var completed = false;
        try
        {
            await Task.Delay(100);
            cancellation.Cancel();
            completed = await Task.WhenAny(runTask, Task.Delay(1000)) == runTask;
            if (!completed)
            {
                await runTask.WaitAsync(TimeSpan.FromSeconds(6));
            }

            Assert.True(completed, "Inline quarantine ignored cancellation or its bounded deadline.");
            var result = await runTask;
            Assert.NotEqual(0, result.ExitCode);
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            try { await runTask.WaitAsync(TimeSpan.FromSeconds(6)); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void SupervisorIdentityUsesExactApphostAndAdjacentPayloadFallback()
    {
        var root = CreateTestDirectory();
        var apphostPath = Path.Combine(root, "ApfsAccess.Cli.exe");
        var payloadPath = Path.Combine(root, "ApfsAccess.Cli.dll");
        var renamedApphostPath = Path.Combine(root, "renamed.exe");
        File.Copy(Environment.ProcessPath!, apphostPath);
        File.Copy(typeof(FsHostSupervisor).Assembly.Location, payloadPath);
        File.Copy(apphostPath, renamedApphostPath);

        try
        {
            var splitIdentity = FsHostSupervisor.ResolveSupervisorIdentityForTests(apphostPath);
            Assert.Equal(Path.GetFullPath(apphostPath), splitIdentity.ExecutablePath);
            Assert.Equal(Path.GetFullPath(payloadPath), splitIdentity.PayloadPath);

            File.Delete(payloadPath);
            var selfContainedIdentity = FsHostSupervisor.ResolveSupervisorIdentityForTests(apphostPath);
            Assert.Equal(Path.GetFullPath(apphostPath), selfContainedIdentity.ExecutablePath);
            Assert.Equal(Path.GetFullPath(apphostPath), selfContainedIdentity.PayloadPath);

            var mismatch = Assert.Throws<InvalidOperationException>(() =>
                FsHostSupervisor.ResolveSupervisorIdentityForTests(renamedApphostPath));
            Assert.Contains("ApfsAccess.Cli.exe", mismatch.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void QuarantineRecoveryEvidenceRetainsSupervisorIdentity()
    {
        var root = CreateTestDirectory();
        var apphostPath = Path.Combine(root, "ApfsAccess.Cli.exe");
        var payloadPath = Path.Combine(root, "ApfsAccess.Cli.dll");
        var evidencePath = Path.Combine(root, "evidence.json");
        File.Copy(Environment.ProcessPath!, apphostPath);
        File.Copy(typeof(FsHostSupervisor).Assembly.Location, payloadPath);

        try
        {
            var options = new QuarantineOptions(
                JobHandle: 1,
                ProcessHandle: 2,
                HostPid: 123,
                HostCreationTimeFileTime: 456,
                JobAssigned: true,
                MountPoint: Path.Combine(root, "mount"),
                StatusFile: Path.Combine(root, "status.json"),
                EvidenceFile: evidencePath,
                ReadyFile: Path.Combine(root, "ready.txt"),
                ReadyToken: "ready-token",
                ProcessAbsenceTimeoutMs: 1000,
                HandoffToken: "handoff-token",
                TestExcludedHandle: null);

            var evidence = FsHostSupervisor.CreateQuarantineRecoveryEvidenceForTests(options, apphostPath);

            Assert.Equal(Path.GetFullPath(apphostPath), evidence.SupervisorExecutable);
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(apphostPath))),
                evidence.SupervisorSha256);
            Assert.Equal(Path.GetFullPath(payloadPath), evidence.SupervisorPayloadPath);
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(payloadPath))),
                evidence.SupervisorPayloadSha256);
            Assert.Equal(Path.GetFullPath(evidencePath), evidence.EvidenceFile);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void QuarantineRecoveryEvidenceCarriesForwardOfferedRevision()
    {
        var root = CreateTestDirectory();
        var apphostPath = Path.Combine(root, "ApfsAccess.Cli.exe");
        var payloadPath = Path.Combine(root, "ApfsAccess.Cli.dll");
        File.Copy(Environment.ProcessPath!, apphostPath);
        File.Copy(typeof(FsHostSupervisor).Assembly.Location, payloadPath);
        var options = new QuarantineOptions(
            JobHandle: 1,
            ProcessHandle: 2,
            HostPid: 123,
            HostCreationTimeFileTime: 456,
            JobAssigned: true,
            MountPoint: Path.Combine(root, "mount"),
            StatusFile: Path.Combine(root, "status.json"),
            EvidenceFile: Path.Combine(root, "evidence.json"),
            ReadyFile: Path.Combine(root, "ready.txt"),
            ReadyToken: "ready-token",
            ProcessAbsenceTimeoutMs: 1000,
            HandoffToken: "handoff-token",
            TestExcludedHandle: null);

        try
        {
            var method = typeof(FsHostSupervisor).GetMethod(
                "CreateQuarantineRecoveryEvidence",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static,
                binder: null,
                types: [typeof(QuarantineOptions), typeof(string), typeof(long)],
                modifiers: null);
            Assert.NotNull(method);

            var evidence = (FsHostSupervisorEvidence)method.Invoke(null, [options, apphostPath, 17L])!;

            Assert.Equal(17, evidence.EvidenceRevision);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void TestSelfLaunchUsesExactApphostWhenOverrideIsInstalled()
    {
        var method = typeof(FsHostSupervisor).GetMethod(
            "ResolveSelfLaunch",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        var launch = ((string ApplicationPath, string? AssemblyPath))method.Invoke(null, null)!;

        Assert.Equal(Path.GetFullPath(supervisorExecutablePath), Path.GetFullPath(launch.ApplicationPath));
        Assert.Null(launch.AssemblyPath);
    }

    [Fact]
    public void QuarantineAcceptanceRejectsEvidenceWithoutCompleteSupervisorIdentity()
    {
        var root = CreateTestDirectory();
        var evidencePath = Path.Combine(root, "evidence.json");
        const int quarantinePid = 321;
        const string handoffToken = "handoff-token";
        var evidence = new FsHostSupervisorEvidence
        {
            EvidenceWriterPid = quarantinePid,
            EvidenceWriterRole = "quarantine",
            OwnershipHandoffToken = handoffToken,
            OwnershipHandoffState = "accepted",
            QuarantineOwnerHandleInheritanceProven = true,
            QuarantineExcludedHandleInherited = false,
        };
        File.WriteAllText(
            evidencePath,
            JsonSerializer.Serialize(
                evidence,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

        try
        {
            var method = typeof(FsHostSupervisor).GetMethod(
                "TryValidateQuarantineAcceptance",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            Assert.NotNull(method);

            var accepted = (bool)method.Invoke(null, [evidencePath, quarantinePid, handoffToken])!;

            Assert.False(accepted);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StartupFailureLeavesGateUnauthorizedAndWritesFailureEvidence()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var gatePath = Path.Combine(root, "startup.gate");
        File.WriteAllText(lifetimePath, "alive");
        File.WriteAllText(gatePath, "pending");

        try
        {
            var exitCode = await Program.Main(
            [
                "supervise-fshost",
                "--host", Path.Combine(root, "missing-host.exe"),
                "--owner-pid", Environment.ProcessId.ToString(),
                "--lifetime-file", lifetimePath,
                "--startup-gate-file", gatePath,
                "--startup-gate-token", "must-not-be-written",
                "--launch-record", launchPath,
                "--evidence-file", evidencePath,
                "--mount-point", Path.Combine(root, "mount"),
            ]);

            Assert.NotEqual(0, exitCode);
            Assert.Equal("pending", File.ReadAllText(gatePath));
            Assert.False(File.Exists(launchPath));
            using var evidence = await WaitForJsonAsync(evidencePath, TimeSpan.FromSeconds(2));
            var rootElement = evidence.RootElement;
            Assert.False(rootElement.GetProperty("supervisionProven").GetBoolean());
            Assert.False(rootElement.GetProperty("startupGateAuthorized").GetBoolean());
            Assert.Null(rootElement.GetProperty("hostPid").GetString());
            Assert.Contains("CreateProcess", rootElement.GetProperty("failure").GetString(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SupervisorDoesNotPassWhenMountStatusRemainsReady()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var statusPath = Path.Combine(root, "status.json");
        var mountPoint = Path.Combine(root, "mount");
        File.WriteAllText(lifetimePath, "alive");
        File.WriteAllText(statusPath, "{\"mountReady\":true}");
        Directory.CreateDirectory(mountPoint);

        // Force the parent to hand ownership to the durable quarantine owner.
        // The child does not inherit this test hook and must perform its own
        // direct probe and process-identity checks.
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            MountPointProbeOverride = _ => new FsHostMountProbeResult(
                IsAbsent: false,
                ProbeKind: "test-present",
                Detail: "injected parent-side probe failure"),
        });

        try
        {
            var exitCode = await Program.Main(
            [
                "supervise-fshost",
                "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "--host-arg", "/c",
                "--host-arg", "exit",
                "--host-arg", "0",
                "--owner-pid", Environment.ProcessId.ToString(),
                "--lifetime-file", lifetimePath,
                "--status-file", statusPath,
                "--launch-record", launchPath,
                "--evidence-file", evidencePath,
                "--mount-point", mountPoint,
                "--process-absence-timeout-ms", "3000",
            ]);

            Assert.NotEqual(0, exitCode);
            using var evidence = await WaitForJsonAsync(
                evidencePath,
                TimeSpan.FromSeconds(10),
                rootElement =>
                    rootElement.GetProperty("quarantineOwnerStarted").GetBoolean() &&
                    rootElement.GetProperty("jobClosed").GetBoolean() &&
                    rootElement.GetProperty("status").GetString() == "failed");
            var rootElement = evidence.RootElement;
            Assert.Equal("failed", rootElement.GetProperty("status").GetString());
            Assert.True(rootElement.GetProperty("hostPidAbsentFromProcessEnumeration").GetBoolean());
            Assert.False(rootElement.GetProperty("mountAbsentFromStatus").GetBoolean());
            Assert.True(rootElement.GetProperty("mountAbsentFromDirectProbe").GetBoolean());
            Assert.False(rootElement.GetProperty("mountAbsenceProven").GetBoolean());
            Assert.True(rootElement.GetProperty("jobClosed").GetBoolean());
            Assert.Contains("mount", rootElement.GetProperty("failure").GetString(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AssignmentFailureTerminatesUnassignedSuspendedChildAndProvesAbsence()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var gatePath = Path.Combine(root, "startup.gate");
        File.WriteAllText(lifetimePath, "alive");
        File.WriteAllText(gatePath, "pending");

        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            AssignProcessToJobObjectOverride = () => false,
        });

        try
        {
            var exitCode = await Program.Main(
            [
                "supervise-fshost",
                "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "--host-arg", "/c",
                "--host-arg", "ping.exe",
                "--host-arg", "-n",
                "--host-arg", "30",
                "--host-arg", "127.0.0.1",
                "--owner-pid", Environment.ProcessId.ToString(),
                "--lifetime-file", lifetimePath,
                "--startup-gate-file", gatePath,
                "--startup-gate-token", "must-not-be-authorized",
                "--launch-record", launchPath,
                "--evidence-file", evidencePath,
                "--mount-point", Path.Combine(root, "mount"),
                "--process-absence-timeout-ms", "5000",
            ]);

            Assert.NotEqual(0, exitCode);
            using var evidence = await WaitForJsonAsync(evidencePath, TimeSpan.FromSeconds(5));
            var rootElement = evidence.RootElement;
            Assert.False(rootElement.GetProperty("jobAssigned").GetBoolean());
            Assert.False(rootElement.GetProperty("startupGateAuthorized").GetBoolean());
            Assert.Equal("pending", File.ReadAllText(gatePath));
            Assert.True(rootElement.GetProperty("exactProcessTerminationAttempted").GetBoolean());
            Assert.Equal("succeeded", rootElement.GetProperty("exactProcessTerminationResult").GetString());
            Assert.True(rootElement.GetProperty("hostPidAbsentFromProcessEnumeration").GetBoolean());
            Assert.Equal("absent", rootElement.GetProperty("hostIdentityState").GetString());
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            try { await WaitForJsonAsync(evidencePath, TimeSpan.FromSeconds(1)); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ManagedQuarantineInheritsOnlyListedHandlesAndOwnsTerminalEvidence()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var statusPath = Path.Combine(root, "status.json");
        var mountPoint = Path.Combine(root, "mount");
        File.WriteAllText(lifetimePath, "alive");
        File.WriteAllText(statusPath, "{\"mountReady\":true}");
        Directory.CreateDirectory(mountPoint);
        var sentinelPath = Path.Combine(root, "unrelated-inheritable-sentinel.bin");
        using var sentinel = File.OpenHandle(
            sentinelPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.ReadWrite);
        Assert.True(SetHandleInformation(
            sentinel.DangerousGetHandle(),
            HandleFlagInherit,
            HandleFlagInherit));

        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            ExcludedInheritableHandle = sentinel.DangerousGetHandle(),
            MountPointProbeOverride = _ => new FsHostMountProbeResult(
                IsAbsent: false,
                ProbeKind: "test-present",
                Detail: "force managed quarantine handoff"),
        });

        var quarantineOwnerPid = 0;
        try
        {
            var exitCode = await Program.Main(
            [
                "supervise-fshost",
                "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "--host-arg", "/c",
                "--host-arg", "exit",
                "--host-arg", "0",
                "--owner-pid", Environment.ProcessId.ToString(),
                "--lifetime-file", lifetimePath,
                "--status-file", statusPath,
                "--launch-record", launchPath,
                "--evidence-file", evidencePath,
                "--mount-point", mountPoint,
                "--process-absence-timeout-ms", "250",
                "--graceful-timeout-ms", "50",
            ]);

            Assert.NotEqual(0, exitCode);
            using var evidence = await WaitForJsonAsync(
                evidencePath,
                TimeSpan.FromSeconds(10),
                rootElement =>
                    rootElement.GetProperty("evidenceWriterRole").GetString() == "quarantine" &&
                    rootElement.GetProperty("ownershipHandoffState").GetString() == "completed" &&
                    rootElement.GetProperty("quarantineOwnerStarted").GetBoolean() &&
                    rootElement.GetProperty("jobClosed").GetBoolean());
            var rootElement = evidence.RootElement;
            quarantineOwnerPid = rootElement.GetProperty("quarantineOwnerPid").GetInt32();
            var terminalRevision = rootElement.GetProperty("evidenceRevision").GetInt64();
            Assert.True(quarantineOwnerPid > 0);
            Assert.True(rootElement.GetProperty("quarantineOwnerHandleInheritanceProven").GetBoolean());
            Assert.False(rootElement.GetProperty("quarantineExcludedHandleInherited").GetBoolean());
            Assert.True(rootElement.GetProperty("jobClosed").GetBoolean());
            Assert.Equal("failed", rootElement.GetProperty("status").GetString());
            Assert.False(rootElement.GetProperty("mountAbsenceProven").GetBoolean());

            await WaitForProcessAbsenceAsync(quarantineOwnerPid, TimeSpan.FromSeconds(10));
            await Task.Delay(250);
            using var afterParentExit = JsonDocument.Parse(await File.ReadAllTextAsync(evidencePath));
            Assert.Equal("quarantine", afterParentExit.RootElement.GetProperty("evidenceWriterRole").GetString());
            Assert.True(afterParentExit.RootElement.GetProperty("evidenceRevision").GetInt64() >= terminalRevision);
            Assert.Equal("completed", afterParentExit.RootElement.GetProperty("ownershipHandoffState").GetString());
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task SignaledOriginalHandleWithReusedPidReleasesOwnershipSuccessfully()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var mountPoint = Path.Combine(root, "mount");
        File.WriteAllText(lifetimePath, "alive");
        Directory.CreateDirectory(mountPoint);

        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            ObserveProcessIdentityOverride = (_, _) => "reused-pid",
        });

        try
        {
            var exitCode = await Program.Main(
            [
                "supervise-fshost",
                "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "--host-arg", "/c",
                "--host-arg", "exit",
                "--host-arg", "0",
                "--owner-pid", Environment.ProcessId.ToString(),
                "--lifetime-file", lifetimePath,
                "--launch-record", launchPath,
                "--evidence-file", evidencePath,
                "--mount-point", mountPoint,
                "--process-absence-timeout-ms", "3000",
            ]);

            Assert.Equal(0, exitCode);
            using var evidence = await WaitForJsonAsync(evidencePath, TimeSpan.FromSeconds(5));
            var rootElement = evidence.RootElement;
            Assert.True(rootElement.GetProperty("originalHostIdentityAbsent").GetBoolean());
            Assert.True(rootElement.GetProperty("hostPidReused").GetBoolean());
            Assert.False(rootElement.GetProperty("hostPidAbsentFromProcessEnumeration").GetBoolean());
            Assert.Equal("reused-pid", rootElement.GetProperty("hostIdentityState").GetString());
            Assert.True(rootElement.GetProperty("jobClosed").GetBoolean());
            Assert.Equal("stopped", rootElement.GetProperty("status").GetString());
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ManagedQuarantineCanPublishSuccessfulTerminalProofAfterHandoff()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var launchPath = Path.Combine(root, "launch.json");
        var evidencePath = Path.Combine(root, "evidence.json");
        var mountPoint = Path.Combine(root, "mount");
        File.WriteAllText(lifetimePath, "alive");
        Directory.CreateDirectory(mountPoint);

        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            MountPointProbeOverride = _ => new FsHostMountProbeResult(
                IsAbsent: false,
                ProbeKind: "test-present",
                Detail: "force managed quarantine handoff"),
        });

        try
        {
            var exitCode = await Program.Main(
            [
                "supervise-fshost",
                "--host", Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                "--host-arg", "/c",
                "--host-arg", "exit",
                "--host-arg", "0",
                "--owner-pid", Environment.ProcessId.ToString(),
                "--lifetime-file", lifetimePath,
                "--launch-record", launchPath,
                "--evidence-file", evidencePath,
                "--mount-point", mountPoint,
                "--process-absence-timeout-ms", "250",
            ]);

            Assert.NotEqual(0, exitCode);
            using var evidence = await WaitForJsonAsync(
                evidencePath,
                TimeSpan.FromSeconds(10),
                rootElement =>
                    rootElement.GetProperty("ownershipHandoffState").GetString() == "completed" &&
                    rootElement.GetProperty("jobClosed").GetBoolean());
            Assert.Equal("stopped", evidence.RootElement.GetProperty("status").GetString());
            Assert.Null(evidence.RootElement.GetProperty("failure").GetString());
            Assert.True(evidence.RootElement.GetProperty("originalHostIdentityAbsent").GetBoolean());
            Assert.True(evidence.RootElement.GetProperty("mountAbsenceProven").GetBoolean());
        }
        finally
        {
            try { File.Delete(lifetimePath); } catch { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task QuarantineFallsBackToExactProcessTerminationWhenJobTerminationFails()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var evidencePath = Path.Combine(root, "evidence.json");
        var readyPath = Path.Combine(root, "ready.txt");
        var mountPoint = Path.Combine(root, "mount");
        var invalidJobHandlePath = Path.Combine(root, "not-a-job.bin");
        Directory.CreateDirectory(mountPoint);

        var pingPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ping.exe");
        Assert.True(File.Exists(pingPath), $"The system ping executable is missing: {pingPath}");
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = pingPath,
            Arguments = "-n 120 127.0.0.1",
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        Assert.False(child.WaitForExit(500), "The quarantine fallback child exited before the failed job-termination path was exercised.");
        var processHandle = DuplicateCurrentHandle(child.Handle);
        using var sourceJobHandle = File.OpenHandle(
            invalidJobHandlePath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.ReadWrite | FileShare.Delete);
        var notAJobHandle = DuplicateCurrentHandle(sourceJobHandle.DangerousGetHandle());
        const string handoffToken = "adversarial-handoff-token";
        var options = new QuarantineOptions(
            JobHandle: notAJobHandle,
            ProcessHandle: processHandle,
            HostPid: child.Id,
            HostCreationTimeFileTime: 1,
            JobAssigned: true,
            MountPoint: mountPoint,
            StatusFile: null,
            EvidenceFile: evidencePath,
            ReadyFile: readyPath,
            ReadyToken: "ready-token",
            ProcessAbsenceTimeoutMs: 250,
            HandoffToken: handoffToken,
            TestExcludedHandle: null);
        var evidence = FsHostSupervisor.CreateQuarantineRecoveryEvidenceForTests(
            options,
            supervisorExecutablePath);
        evidence.OwnershipHandoffToken = handoffToken;
        evidence.OwnershipHandoffState = "offered";
        File.WriteAllText(
            evidencePath,
            JsonSerializer.Serialize(
                evidence,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

        var runTask = FsHostSupervisor.RunQuarantineAsync(options);
        var completed = await Task.WhenAny(runTask, Task.Delay(1500)) == runTask;
        if (!completed)
        {
            try
            {
                if (!child.HasExited) child.Kill(entireProcessTree: true);
            }
            catch { }

            try { await runTask.WaitAsync(TimeSpan.FromSeconds(6)); } catch { }
        }

        try
        {
            Assert.True(completed, "Quarantine did not fall back from a failed job termination to exact process termination.");
            Assert.Equal(0, await runTask);
        }
        finally
        {
            try
            {
                if (!child.HasExited) child.Kill(entireProcessTree: true);
            }
            catch { }
            sourceJobHandle.Dispose();
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void MissingStatusFileCannotSubstituteForDirectMountAbsence()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var mountPoint = Path.Combine(root, "mount");
        var missingStatus = Path.Combine(root, "missing-status.json");
        Directory.CreateDirectory(mountPoint);

        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            MountPointProbeOverride = _ => new FsHostMountProbeResult(
                IsAbsent: false,
                ProbeKind: "test-present",
                Detail: "injected mount assignment"),
        });

        try
        {
            var proof = FsHostSupervisor.WaitForMountAbsenceForTests(
                mountPoint,
                missingStatus,
                250);

            Assert.False(proof.DirectAbsent);
            Assert.False(proof.StatusAbsent);
            Assert.Equal("missing", proof.StatusResult);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void DirectDirectoryProbeProvesAbsenceWithoutStatusFile()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var mountPoint = Path.Combine(root, "mount");
        Directory.CreateDirectory(mountPoint);

        try
        {
            var proof = FsHostSupervisor.WaitForMountAbsenceForTests(
                mountPoint,
                Path.Combine(root, "missing-status.json"),
                250);

            Assert.True(proof.DirectAbsent);
            Assert.Equal("directory-no-reparse", proof.DirectResult);
            Assert.Equal("missing", proof.StatusResult);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void DirectMountProbeErrorsFailClosed()
    {
        Assert.True(OperatingSystem.IsWindows());
        var root = CreateTestDirectory();
        var mountPoint = Path.Combine(root, "mount");
        Directory.CreateDirectory(mountPoint);

        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            MountPointProbeOverride = _ => throw new InvalidOperationException("injected direct probe failure"),
        });

        try
        {
            var proof = FsHostSupervisor.WaitForMountAbsenceForTests(
                mountPoint,
                statusPath: null,
                250);

            Assert.False(proof.DirectAbsent);
            Assert.Equal("error", proof.DirectResult);
            Assert.Contains("injected direct probe failure", proof.Failure, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void DriveRootMountPointNormalizesToExactDosDeviceName()
    {
        Assert.True(OperatingSystem.IsWindows());
        Assert.Equal("E:", FsHostSupervisor.NormalizeMountPointForTests("e:\\"));
        Assert.Equal("E:", FsHostSupervisor.NormalizeMountPointForTests("e:/"));
        Assert.Equal("E:", FsHostSupervisor.NormalizeMountPointForTests("e:"));
    }

    [Fact]
    public void WaitFailureIsReportedInsteadOfBeingTreatedAsUnsignaled()
    {
        Assert.True(OperatingSystem.IsWindows());
        var error = Assert.Throws<Win32Exception>(() =>
            FsHostSupervisor.ValidateWaitResultForTests(uint.MaxValue, "WaitForSingleObject(test)"));
        Assert.Contains("WaitForSingleObject", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProcessIdentityMismatchIsClassifiedAsPidReuse()
    {
        Assert.True(OperatingSystem.IsWindows());
        Assert.Equal(
            "reused-pid",
            FsHostSupervisor.ObserveProcessIdentityForTests((uint)Environment.ProcessId, 1));
    }

    private static string CreateTestDirectory()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "ApfsAccessTests",
            "FsHostSupervisor",
            "tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static async Task<JsonDocument> WaitForJsonAsync(
        string path,
        TimeSpan timeout,
        Func<JsonElement, bool>? predicate = null)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                try
                {
                    await using var stream = new FileStream(
                        path,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete,
                        bufferSize: 4_096,
                        FileOptions.Asynchronous | FileOptions.SequentialScan);
                    var document = await JsonDocument.ParseAsync(stream);
                    if (predicate is null || predicate(document.RootElement)) return document;
                    document.Dispose();
                }
                catch (JsonException) { }
                catch (IOException) { }
            }

            await Task.Delay(50);
        }

        throw new Xunit.Sdk.XunitException($"Timed out waiting for JSON evidence: {path}");
    }

    private static async Task WaitForProcessAbsenceAsync(int processId, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited)
                {
                    await Task.Delay(50);
                    continue;
                }
            }
            catch (ArgumentException)
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new Xunit.Sdk.XunitException($"Timed out waiting for process PID {processId} to disappear.");
    }

    private const uint HandleFlagInherit = 0x00000001;
    private const uint DuplicateSameAccess = 0x00000002;

    private static nint DuplicateCurrentHandle(nint sourceHandle)
    {
        if (!DuplicateHandle(
                GetCurrentProcess(),
                sourceHandle,
                GetCurrentProcess(),
                out var duplicate,
                0,
                false,
                DuplicateSameAccess))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return duplicate;
    }

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        nint sourceProcessHandle,
        nint sourceHandle,
        nint targetProcessHandle,
        out nint targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(nint handle, uint mask, uint flags);
}
