using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Cli.Tests;

public sealed class FsHostSupervisorDirectoryCrashTests
{
    [Theory]
    [InlineData("bound-directory", true)]
    [InlineData("wrong-pid", false)]
    [InlineData("missing-pid", false)]
    [InlineData("duplicate-pid", false)]
    [InlineData("old-status", false)]
    [InlineData("drive-root", false)]
    public async Task ActualExitedChildRequiresExactBoundDirectoryStatusBeforeStaleReadyCanSettle(string scenario, bool succeeds)
    {
        var basePath = Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT") ?? @"D:\ApfsAccessScratch\SupervisorCrashTests";
        var root = Path.Combine(basePath, "directory-crash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var lifetime = Path.Combine(root, "owner.alive");
        var status = Path.Combine(root, "status.json");
        var release = Path.Combine(root, "release");
        var evidencePath = Path.Combine(root, "evidence.json");
        File.WriteAllText(lifetime, "owned test lifetime");
        var child = Environment.GetEnvironmentVariable("APFSACCESS_SUPERVISOR_CRASH_CHILD") ??
            Path.Combine(AppContext.BaseDirectory, "ApfsAccess.Cli.TestChild.exe");
        Assert.True(File.Exists(child), "The normal SDK test child must be built beside the test assembly.");
        using var supervisorIdentity = FsHostSupervisor.InstallSupervisorExecutablePathForTests(
            Path.Combine(Path.GetDirectoryName(typeof(FsHostSupervisor).Assembly.Location)!, "ApfsAccess.Cli.exe"));
        var mount = scenario == "drive-root" ? "Z:\\" : Path.Combine(root, "mount");
        using var hook = scenario == "drive-root" ? FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            MountPointProbeOverride = _ => new(true, "directory-absent", "No global drive is probed by this negative control."),
        }) : null;
        var running = Program.Main([
            "supervise-fshost", "--host", child,
            "--host-arg", "--probe", "--host-arg", "ready-exit",
            "--host-arg", "--result-path", "--host-arg", status,
            "--host-arg", "--release-path", "--host-arg", release,
            "--host-arg", "--exit-code", "--host-arg", "73",
            "--owner-pid", Environment.ProcessId.ToString(), "--lifetime-file", lifetime,
            "--status-file", status, "--launch-record", Path.Combine(root, "launch.json"),
            "--evidence-file", evidencePath, "--mount-point", mount,
            "--process-absence-timeout-ms", "350", "--owner-poll-interval-ms", "25",
        ]);
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!File.Exists(status))
            {
                Assert.False(running.IsCompleted, "Supervisor exited before the child status control.");
                Assert.True(DateTime.UtcNow < deadline, "Owned child did not publish ready status.");
                await Task.Delay(20);
            }
            var document = JsonNode.Parse(File.ReadAllText(status))!.AsObject();
            var actualPid = document["hostPid"]!.GetValue<int>();
            if (scenario == "wrong-pid") document["hostPid"] = actualPid + 1;
            if (scenario == "missing-pid") document.Remove("hostPid");
            if (scenario is "wrong-pid" or "missing-pid") File.WriteAllText(status, document.ToJsonString());
            if (scenario == "duplicate-pid") File.WriteAllText(status,
                $"{{\"mountReady\":true,\"hostPid\":{actualPid},\"hostPid\":{actualPid}}}");
            if (scenario == "old-status") File.SetLastWriteTimeUtc(status, DateTime.UtcNow.AddMinutes(-2));
            var originalStatus = File.ReadAllBytes(status);
            File.WriteAllText(release, "release exact owned child");
            var code = await running.WaitAsync(TimeSpan.FromSeconds(20));
            var evidence = JsonSerializer.Deserialize<FsHostSupervisorEvidence>(File.ReadAllText(evidencePath),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            Assert.Equal(73, evidence.HostExitCode);
            Assert.True(evidence.OriginalHostIdentityAbsent);
            Assert.True(evidence.HostPidAbsentFromProcessEnumeration);
            Assert.False(evidence.HostPidReused);
            Assert.True(evidence.MountAbsentFromDirectProbe);
            Assert.False(evidence.MountAbsentFromStatus);
            Assert.Equal("ready", evidence.MountStatusProbeResult);
            Assert.Equal(originalStatus, File.ReadAllBytes(status));
            Assert.Equal(succeeds, evidence.StaleReadyStatusDischarged);
            Assert.Equal(succeeds, evidence.MountAbsenceProven);
            Assert.Equal(succeeds ? 0 : 1, code);
            Assert.Equal(succeeds ? "stopped" : "failed", evidence.Status);
            if (succeeds)
            {
                Assert.True(evidence.JobMembersAbsent);
                Assert.True(evidence.JobClosed);
                Assert.False(evidence.ForcedJobTermination);
                Assert.False(evidence.ExactProcessTerminationAttempted);
                Assert.Null(evidence.Failure);
                Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(originalStatus)), evidence.StaleReadyStatusSha256);
            }
            else Assert.Null(evidence.StaleReadyStatusSha256);
        }
        finally
        {
            if (!File.Exists(release)) File.WriteAllText(release, "release on test failure");
            await running.WaitAsync(TimeSpan.FromSeconds(20));
        }
    }
}
