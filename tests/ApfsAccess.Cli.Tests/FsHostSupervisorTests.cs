using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
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

    private static (string Root, string Manifest, string[] Args, FsHostSupervisorEvidence Evidence) CreateCohortFixture(string? firstMount = null, string? secondMount = null)
    {
        var root = CreateTestDirectory();
        var file = Path.Combine(root, "manifest.json");
        var args = WriteCohortManifest(file, firstMount ?? Path.Combine(root, "mount-one"), secondMount ?? Path.Combine(root, "mount-two"));
        var authority = FsHostSupervisor.ReadContainerManifestAuthorityForTests(args)!;
        var evidence = new FsHostSupervisorEvidence { HostArguments = args, ContainerManifestAuthority = authority,
            StatusFile = Path.Combine(root, "status.json"), EvidenceFile = Path.Combine(root, "evidence.json"),
            HostPid = 123, HostCreationTimeFileTime = 134324039887674841 };
        return (root, file, args, evidence);
    }

    private static string[] WriteCohortManifest(string file, string firstMount, string secondMount)
    {
        const string container = "0123456789abcdef0123456789abcdef";
        var volumes = new[]
        {
            new { objectId = 17UL, containerUuid = container, name = "one", mount = firstMount, requestedWrite = true, recoveryIdentity = "rid-one" },
            new { objectId = 23UL, containerUuid = container, name = "two", mount = secondMount, requestedWrite = true, recoveryIdentity = "rid-two" },
        };
        var checksumVolumes = volumes.Select(v => new ApfsAccess.Backend.Native.ContainerManifestVolume(v.objectId, v.containerUuid, v.name, v.mount, v.requestedWrite, v.recoveryIdentity)).ToArray();
        var checksum = ApfsAccess.Backend.Native.ContainerManifestWriter.ComputeManifestSha256(container, "offline-device", 4096, checksumVolumes);
        File.WriteAllText(file, JsonSerializer.Serialize(new { format = "apfs-access-container-manifest", version = 1,
            containerUuid = container, device = "offline-device", deviceOffsetBytes = 4096UL, manifestSha256 = checksum, volumes }));
        return ["--container-manifest", file, "--container-manifest-sha256", checksum];
    }

    private static void WriteCohortStatus(FsHostSupervisorEvidence evidence, bool terminal, bool leaseHeld = true, int? ownerPid = null, long? start = null, bool omitPeer = false)
    {
        var authority = evidence.ContainerManifestAuthority!;
        var peers = terminal ? Array.Empty<object>() : authority.Volumes.Take(omitPeer ? 1 : authority.Volumes.Count).Select(v => (object)new
        {
            objectId = ulong.Parse(v.ObjectId), canonicalId = $"apfs-vol:{authority.ContainerUuid}:{v.ObjectId}",
            mountPoint = v.MountPoint, mounted = true, ready = true, recoveryIdentity = v.RecoveryIdentity,
        }).ToArray();
        File.WriteAllText(evidence.StatusFile!, JsonSerializer.Serialize(new { containerUuid = authority.ContainerUuid,
            ownerPid = ownerPid ?? evidence.HostPid, ownerStartFileTimeUtc = start ?? evidence.HostCreationTimeFileTime,
            leaseHeld, volumes = peers }));
    }

    [Fact]
    public void ManifestCohortAuthorityBindsExactBytesAndAllPeers()
    {
        var fixture = CreateCohortFixture();
        try
        {
            var authority = fixture.Evidence.ContainerManifestAuthority!;
            Assert.Equal(2, authority.Volumes.Count);
            Assert.Equal(["17", "23"], authority.Volumes.Select(v => v.ObjectId));
            Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture.Manifest))), authority.ContentSha256);
            File.AppendAllText(fixture.Manifest, " ");
            Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0));
            Assert.NotEqual(authority.ContentSha256, FsHostSupervisor.ReadContainerManifestAuthorityForTests(fixture.Args)!.ContentSha256);
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Theory]
    [InlineData("E:", "F:")]
    [InlineData("e:\\", "f:/")]
    public void ManifestCohortDriveRootsRetainRawChecksumAndEveryProof(string firstMount, string secondMount)
    {
        var fixture = CreateCohortFixture(firstMount, secondMount);
        var visited = new List<string>();
        var secondPresent = true;
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        { MountPointProbeOverride = mount => { visited.Add(mount); return new(mount != "F:" || !secondPresent, "offline-drive", "injected"); } });
        try
        {
            var authority = fixture.Evidence.ContainerManifestAuthority!;
            Assert.Equal(["E:", "F:"], authority.Volumes.Select(v => v.MountPoint));
            Assert.Equal(fixture.Args[3].ToUpperInvariant(), authority.ManifestSha256);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fixture.Manifest))), authority.ContentSha256);
            WriteCohortStatus(fixture.Evidence, terminal: false);
            var status = JsonNode.Parse(File.ReadAllText(fixture.Evidence.StatusFile!))!;
            status["volumes"]![0]!["mountPoint"] = "e:/";
            status["volumes"]![1]!["mountPoint"] = "f:\\";
            File.WriteAllText(fixture.Evidence.StatusFile!, status.ToJsonString());
            Assert.Equal("ready", FsHostSupervisor.ReadContainerStatusForTests(fixture.Evidence));
            WriteCohortStatus(fixture.Evidence, terminal: true, leaseHeld: false);
            Assert.False(FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0).DirectAbsent);
            Assert.Equal(["E:", "F:"], visited);
            Assert.Equal("present", fixture.Evidence.MountProofs[1].DirectState);
            secondPresent = false;
            visited.Clear();
            var settled = FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0);
            Assert.True(settled.DirectAbsent && settled.StatusAbsent);
            Assert.Equal(["E:", "F:"], visited);
            Assert.Equal(["17", "23"], fixture.Evidence.MountProofs.Select(p => p.ObjectId));
            Assert.Equal(["rid-one", "rid-two"], fixture.Evidence.MountProofs.Select(p => p.RecoveryIdentity));
            var alternateArgs = WriteCohortManifest(fixture.Manifest, firstMount == "E:" ? "e:" : "E:", secondMount);
            var alternate = FsHostSupervisor.ReadContainerManifestAuthorityForTests(alternateArgs)!;
            Assert.Equal(authority.Volumes, alternate.Volumes);
            Assert.NotEqual(authority.ManifestSha256, alternate.ManifestSha256);
            Assert.NotEqual(authority.ContentSha256, alternate.ContentSha256);
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Theory]
    [InlineData("E:", "e:\\directory")]
    [InlineData("E:/directory", "e:\\")]
    [InlineData("E:", "e:/")]
    [InlineData("E:relative", "F:")]
    public void ManifestCohortRejectsDriveDirectoryOverlapAndRelativeDrivePaths(string firstMount, string secondMount)
    {
        var fixture = CreateCohortFixture();
        try
        {
            var args = WriteCohortManifest(fixture.Manifest, firstMount, secondMount);
            Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.ReadContainerManifestAuthorityForTests(args));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ManifestCohortRejectsWrongOrMissingLivePeerMount(bool driveRoots, bool missing)
    {
        var fixture = driveRoots ? CreateCohortFixture("E:", "F:") : CreateCohortFixture();
        try
        {
            WriteCohortStatus(fixture.Evidence, terminal: false);
            var status = JsonNode.Parse(File.ReadAllText(fixture.Evidence.StatusFile!))!;
            var peer = status["volumes"]![1]!.AsObject();
            if (missing) peer.Remove("mountPoint");
            else peer["mountPoint"] = fixture.Evidence.ContainerManifestAuthority!.Volumes[0].MountPoint;
            File.WriteAllText(fixture.Evidence.StatusFile!, status.ToJsonString());
            Assert.Equal("error", FsHostSupervisor.ReadContainerStatusForTests(fixture.Evidence));
            WriteCohortStatus(fixture.Evidence, terminal: true, leaseHeld: false);
            Assert.Equal("absent", FsHostSupervisor.ReadContainerStatusForTests(fixture.Evidence));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Fact]
    public void ManifestCohortDirectWindowsDirectoryProbesRetainBothOriginalMounts()
    {
        var fixture = CreateCohortFixture();
        try
        {
            var authority = fixture.Evidence.ContainerManifestAuthority!;
            Directory.CreateDirectory(authority.Volumes[0].MountPoint);
            WriteCohortStatus(fixture.Evidence, terminal: true, leaseHeld: false);
            var proof = FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0);
            Assert.True(proof.DirectAbsent && proof.StatusAbsent);
            Assert.Equal(authority.Volumes.Select(v => v.MountPoint), fixture.Evidence.MountProofs.Select(p => p.MountPoint));
            Assert.Contains("without a reparse point", fixture.Evidence.MountProofs[0].Detail);
            Assert.Contains("Win32 error", fixture.Evidence.MountProofs[1].Detail);
            Assert.All(fixture.Evidence.MountProofs, p => Assert.Equal("absent", p.DirectState));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Theory]
    [InlineData("--device", "other-device")]
    [InlineData("--mount", "D:\\arbitrary-first-mount")]
    [InlineData("--container-manifest-sha256", "0")]
    public void ManifestCohortRejectsMixedOrDuplicateSelectors(string flag, string value)
    {
        var fixture = CreateCohortFixture();
        try { Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.ReadContainerManifestAuthorityForTests([.. fixture.Args, flag, value])); }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Fact]
    public void ManifestCohortRejectsDuplicateKeysAndChecksumTampering()
    {
        var fixture = CreateCohortFixture();
        try
        {
            var original = File.ReadAllText(fixture.Manifest);
            File.WriteAllText(fixture.Manifest, original.Replace("offline-device", "tampered-device"));
            Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.ReadContainerManifestAuthorityForTests(fixture.Args));
            File.WriteAllText(fixture.Manifest, original.Insert(1, "\"version\":1,"));
            Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.ReadContainerManifestAuthorityForTests(fixture.Args));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Theory]
    [InlineData(124, 134324039887674841, false)]
    [InlineData(123, 134324039887674840, false)]
    [InlineData(123, 134324039887674841, true)]
    public void ManifestCohortRejectsStaleOwnerAndPeerOmission(int pid, long start, bool omitted)
    {
        var fixture = CreateCohortFixture();
        try
        {
            WriteCohortStatus(fixture.Evidence, terminal: !omitted, leaseHeld: omitted, ownerPid: pid, start: start, omitPeer: omitted);
            Assert.Equal("error", FsHostSupervisor.ReadContainerStatusForTests(fixture.Evidence));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Fact]
    public void ManifestCohortStaleReadyOrHeldLeaseCannotSettle()
    {
        var fixture = CreateCohortFixture();
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        { MountPointProbeOverride = _ => new(true, "offline-absent", "injected absent") });
        try
        {
            WriteCohortStatus(fixture.Evidence, terminal: false);
            var ready = FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0);
            Assert.True(ready.DirectAbsent);
            Assert.False(ready.StatusAbsent);
            Assert.Equal("ready", ready.StatusResult);
            WriteCohortStatus(fixture.Evidence, terminal: true);
            Assert.Equal("pending", FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0).StatusResult);
            File.Delete(fixture.Evidence.StatusFile!);
            Assert.Equal("error", FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0).StatusResult);
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Theory]
    [InlineData("bound", true)]
    [InlineData("no-nonce", false)]
    [InlineData("wrong-birth", false)]
    [InlineData("missing-peer", false)]
    [InlineData("wrong-recovery", false)]
    [InlineData("duplicate-owner", false)]
    [InlineData("held-global", false)]
    [InlineData("unknown-alias", false)]
    public async Task ActualCohortChildCrashRequiresBothAliasesAndBoundImmutableStatus(string scenario, bool succeeds)
    {
        var fixture = CreateCohortFixture("Y:", "Z:");
        var lifetime = Path.Combine(fixture.Root, "owner.alive");
        var childReady = Path.Combine(fixture.Root, "child-ready");
        var release = Path.Combine(fixture.Root, "release");
        var script = Path.Combine(fixture.Root, "child.ps1");
        var launch = Path.Combine(fixture.Root, "launch.json");
        File.WriteAllText(lifetime, "alive");
        File.WriteAllText(script, $"$ErrorActionPreference='Stop'\n[IO.File]::WriteAllText('{childReady.Replace("'", "''")}.tmp',[string]$PID)\n" +
            $"[IO.File]::Move('{childReady.Replace("'", "''")}.tmp','{childReady.Replace("'", "''")}')\n" +
            $"$until=[DateTime]::UtcNow.AddSeconds(15)\nwhile(!(Test-Path -LiteralPath '{release.Replace("'", "''")}')){{if([DateTime]::UtcNow -gt $until){{exit 2}};Start-Sleep -Milliseconds 25}}\nexit 73\n");
        var keeper = new TaskCompletionSource<FsHostSupervisorEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            CohortNonceOverride = () => scenario == "no-nonce" ? null : new string('a', 32),
            MountPointProbeOverride = _ => new(true, "offline-absent", "No actual drive is probed by this process contract test."),
            CohortAliasProbeOverride = name => {
                visited.Add(name);
                if (scenario == "unknown-alias") throw new Win32Exception(5);
                return new(!(scenario == "held-global" && name == @"Global\Z:"), "offline-alias", "Injected alias state.");
            },
            StartQuarantineOwnerOverride = () => false,
            CohortKeeperEntered = (e, _, _, _, _) => keeper.TrySetResult(e),
        });
        var options = new FsHostSupervisorOptions(@"C:\Program Files\PowerShell\7\pwsh.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", script, .. fixture.Args],
            Environment.ProcessId.ToString(), lifetime, launch, fixture.Evidence.EvidenceFile,
            StatusFile: fixture.Evidence.StatusFile, GracefulTimeoutMs: 50, ProcessAbsenceTimeoutMs: 250, OwnerPollIntervalMs: 25);
        var running = Task.Run(() => FsHostSupervisor.RunAsync(options));
        FsHostSupervisorEvidence? retained = null;
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(12);
            while (!File.Exists(childReady) || !File.Exists(launch))
            {
                Assert.False(running.IsCompleted);
                Assert.True(DateTime.UtcNow < deadline, "Actual owned PowerShell child did not start.");
                await Task.Delay(20);
            }
            var e = JsonSerializer.Deserialize<FsHostSupervisorEvidence>(File.ReadAllText(launch),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            Assert.Equal(e.HostPid!.Value.ToString(), File.ReadAllText(childReady));
            WriteCohortStatus(e, terminal: false, start: scenario == "wrong-birth" ? e.HostCreationTimeFileTime - 1 : null,
                omitPeer: scenario == "missing-peer");
            if (scenario == "wrong-recovery")
            {
                var status = JsonNode.Parse(File.ReadAllText(e.StatusFile!))!;
                status["volumes"]![1]!["recoveryIdentity"] = "foreign";
                File.WriteAllText(e.StatusFile!, status.ToJsonString());
            }
            if (scenario == "duplicate-owner")
                File.WriteAllText(e.StatusFile!, File.ReadAllText(e.StatusFile!).Replace("\"ownerPid\":", "\"ownerPid\":1,\"ownerPid\":"));
            var original = File.ReadAllBytes(e.StatusFile!);
            File.WriteAllText(release, "release exact original child");
            if (!succeeds)
            {
                retained = await keeper.Task.WaitAsync(TimeSpan.FromSeconds(15));
                Assert.Null(retained.CohortCrashProof);
                Assert.False(retained.JobClosed);
                Assert.False(running.IsCompleted);
                Assert.Equal(original, File.ReadAllBytes(e.StatusFile!));
                // Only the real terminal frame can release the rejected fixture.
                WriteCohortStatus(retained, terminal: true, leaseHeld: false);
            }
            var result = await running.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(succeeds ? 0 : 1, result.ExitCode);
            Assert.True(result.Evidence.OriginalHostIdentityAbsent && result.Evidence.JobMembersAbsent && result.Evidence.JobClosed);
            if (succeeds)
            {
                var proof = Assert.IsType<FsHostCohortCrashProof>(result.Evidence.CohortCrashProof);
                Assert.Equal(new[] { "Y:", @"Global\Y:", "Z:", @"Global\Z:" }.Order(), visited.Order());
                Assert.Equal(2, proof.Aliases.Count);
                Assert.True(proof.OriginalLeaseReleased);
                Assert.Equal(Convert.ToHexString(SHA256.HashData(original)), proof.StatusSha256);
                Assert.Equal(original, File.ReadAllBytes(e.StatusFile!));
                Assert.Equal("ready", result.Evidence.MountStatusProbeResult);
                Assert.False(result.Evidence.MountAbsentFromStatus || result.Evidence.StaleReadyStatusDischarged);
                Assert.False(result.Evidence.ForcedJobTermination || result.Evidence.ExactProcessTerminationAttempted);
            }
        }
        finally
        {
            if (!File.Exists(release)) File.WriteAllText(release, "release on test failure");
            if (retained is null && !running.IsCompleted)
            {
                await Task.WhenAny(running, keeper.Task).WaitAsync(TimeSpan.FromSeconds(20));
                if (keeper.Task.IsCompletedSuccessfully) retained = await keeper.Task;
            }
            if (retained is not null) WriteCohortStatus(retained, terminal: true, leaseHeld: false);
            await running.WaitAsync(TimeSpan.FromSeconds(20));
        }
    }

    [Fact]
    public void ManifestCohortSettlementRequiresEveryMountOriginalHostAndEmptyJob()
    {
        var fixture = CreateCohortFixture();
        var visited = new HashSet<string>();
        var secondPresent = true;
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        { MountPointProbeOverride = mount => { visited.Add(mount); return new(!secondPresent || mount.EndsWith("mount-one"), "offline", "injected"); } });
        try
        {
            WriteCohortStatus(fixture.Evidence, terminal: true, leaseHeld: false);
            var blocked = FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0);
            Assert.False(blocked.DirectAbsent);
            Assert.True(blocked.StatusAbsent);
            Assert.Equal(2, visited.Count);
            secondPresent = false;
            var settled = FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0);
            Assert.True(settled.DirectAbsent && settled.StatusAbsent);
            fixture.Evidence.MountAbsenceProven = true;
            fixture.Evidence.MountAbsentFromStatus = true;
            fixture.Evidence.MountStatusProbeResult = "absent";
            Assert.False(FsHostSupervisor.CanReleaseCohortForTests(fixture.Evidence, 0));
            fixture.Evidence.OriginalHostIdentityAbsent = true;
            Assert.False(FsHostSupervisor.CanReleaseCohortForTests(fixture.Evidence, 1));
            Assert.True(FsHostSupervisor.CanReleaseCohortForTests(fixture.Evidence, 0));
            fixture.Evidence.MountProofs = fixture.Evidence.MountProofs.Take(1).ToArray();
            Assert.False(FsHostSupervisor.CanReleaseCohortForTests(fixture.Evidence, 0));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Fact]
    public void ManifestCohortQuarantineRecoveryRetainsAllMountsAndRejectsSnapshotTamper()
    {
        var fixture = CreateCohortFixture();
        try
        {
            var sealedTarget = FsHostSupervisor.SealCohortHandoffForTests(fixture.Evidence);
            var options = new QuarantineOptions(1, 1, 123, 134324039887674841, true, sealedTarget,
                fixture.Evidence.StatusFile, fixture.Evidence.EvidenceFile, "unused-ready", "unused-token", 250, "unused-handoff", null);
            var recovered = FsHostSupervisor.CreateQuarantineRecoveryEvidenceForTests(options, supervisorExecutablePath);
            Assert.Null(recovered.MountPoint);
            Assert.Equal(2, recovered.ContainerManifestAuthority!.Volumes.Count);
            Assert.Equal(fixture.Evidence.ContainerManifestAuthority!.ContentSha256, recovered.ContainerManifestAuthority.ContentSha256);
            Assert.Equal(fixture.Args, recovered.HostArguments);
            File.AppendAllText(fixture.Evidence.EvidenceFile + ".cohort.json", " ");
            Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.CreateQuarantineRecoveryEvidenceForTests(options, supervisorExecutablePath));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    [Fact]
    public void ManifestCohortFailedRefreshClearsPreviouslySettledProofs()
    {
        var fixture = CreateCohortFixture();
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        { MountPointProbeOverride = _ => new(true, "offline-absent", "injected absent") });
        try
        {
            WriteCohortStatus(fixture.Evidence, terminal: true, leaseHeld: false);
            Assert.True(FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0).StatusAbsent);
            fixture.Evidence.MountAbsenceProven = true;
            fixture.Evidence.MountAbsentFromStatus = true;
            fixture.Evidence.MountStatusProbeResult = "absent";
            fixture.Evidence.OriginalHostIdentityAbsent = true;
            Assert.True(FsHostSupervisor.CanReleaseCohortForTests(fixture.Evidence, 0));
            File.AppendAllText(fixture.Manifest, " ");
            Assert.Throws<InvalidOperationException>(() => FsHostSupervisor.WaitForCohortMountAbsenceForTests(fixture.Evidence, 0));
            Assert.Empty(fixture.Evidence.MountProofs);
            Assert.False(FsHostSupervisor.CanReleaseCohortForTests(fixture.Evidence, 0));
        }
        finally { Directory.Delete(fixture.Root, recursive: true); }
    }

    private sealed record KeeperObservation(FsHostSupervisorEvidence Evidence, WeakReference<SafeHandle> Job,
        WeakReference<SafeHandle> Process, WeakReference<FileStream> Manifest, WeakReference<SafeHandle>? FailedChild);

    private static KeeperObservation ObserveKeeper(FsHostSupervisorEvidence evidence, SafeHandle job,
        SafeHandle process, FileStream manifest, SafeHandle? failedChild)
        => new(evidence, new(job), new(process), new(manifest), failedChild is null ? null : new(failedChild));

    private static void AssertKeeperOwnsLiveResources(KeeperObservation keeper, string manifestPath)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.True(keeper.Job.TryGetTarget(out var job));
        Assert.True(keeper.Process.TryGetTarget(out var process));
        Assert.True(keeper.Manifest.TryGetTarget(out var manifest));
        Assert.False(job.IsClosed);
        Assert.False(process.IsClosed);
        Assert.True(manifest.CanRead);
        Assert.True(GetHandleInformation(job, out _));
        Assert.True(GetHandleInformation(process, out _));
        Assert.True(QueryInformationJobObject(job, 1, out var accounting, (uint)Marshal.SizeOf<JobAccounting>(), out _));
        Assert.Equal(0U, accounting.ActiveProcesses);
        Assert.Equal(0U, WaitForSingleObject(process, 0));
        if (keeper.FailedChild is not null)
        {
            Assert.True(keeper.FailedChild.TryGetTarget(out var child));
            Assert.False(child.IsClosed);
            Assert.True(GetHandleInformation(child, out _));
        }
        Assert.Throws<IOException>(() => { using var write = new FileStream(manifestPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete); });
        Assert.Throws<IOException>(() => File.Move(manifestPath, manifestPath + ".moved"));
    }

    private static void AssertKeeperReleasedResources(KeeperObservation keeper, string manifestPath)
    {
        if (keeper.Job.TryGetTarget(out var job)) Assert.True(job.IsClosed);
        if (keeper.Process.TryGetTarget(out var process)) Assert.True(process.IsClosed);
        if (keeper.Manifest.TryGetTarget(out var manifest)) Assert.False(manifest.CanRead);
        if (keeper.FailedChild?.TryGetTarget(out var child) == true) Assert.True(child.IsClosed);
        using var write = new FileStream(manifestPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManifestCohortFailedHandoffRetainsActualOwnershipPastDeadlineAndCancellation(bool cancel)
    {
        var fixture = CreateCohortFixture();
        var lifetime = Path.Combine(fixture.Root, "host.alive");
        File.WriteAllText(lifetime, "alive");
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource<KeeperObservation>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            StartQuarantineOwnerOverride = () => { if (cancel) cancellation.Cancel(); return false; },
            CohortKeeperEntered = (e, j, p, m, c) =>
            {
                WriteCohortStatus(e, terminal: true, leaseHeld: true);
                entered.TrySetResult(ObserveKeeper(e, j, p, m, c));
            },
        });
        var options = new FsHostSupervisorOptions(Environment.GetEnvironmentVariable("ComSpec")!,
            ["/c", "exit", "0", .. fixture.Args], Environment.ProcessId.ToString(), lifetime,
            Path.Combine(fixture.Root, "launch.json"), fixture.Evidence.EvidenceFile,
            StatusFile: fixture.Evidence.StatusFile, GracefulTimeoutMs: 50, ProcessAbsenceTimeoutMs: 250, OwnerPollIntervalMs: 25);
        var task = Task.Run(() => FsHostSupervisor.RunAsync(options, cancellation.Token));
        KeeperObservation? keeper = null;
        try
        {
            keeper = await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            File.Delete(lifetime);
            await Task.Delay(600);
            Assert.False(task.IsCompleted);
            AssertKeeperOwnsLiveResources(keeper, fixture.Manifest);
            using var retained = await WaitForJsonAsync(fixture.Evidence.EvidenceFile, TimeSpan.FromSeconds(5),
                e => e.GetProperty("cohortKeeperActive").GetBoolean());
            Assert.Equal(Environment.ProcessId, retained.RootElement.GetProperty("cohortKeeperPid").GetInt32());
            Assert.False(retained.RootElement.GetProperty("jobClosed").GetBoolean());
            Assert.Equal("quarantined", retained.RootElement.GetProperty("status").GetString());
            var revision = retained.RootElement.GetProperty("evidenceRevision").GetInt64();
            using var stillServicing = await WaitForJsonAsync(fixture.Evidence.EvidenceFile, TimeSpan.FromSeconds(5),
                e => e.GetProperty("evidenceRevision").GetInt64() > revision);
            Assert.False(task.IsCompleted);
            WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            var result = await task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, result.ExitCode);
            Assert.True(result.Evidence.JobClosed && result.Evidence.JobMembersAbsent && result.Evidence.OriginalHostIdentityAbsent);
            Assert.False(result.Evidence.CohortKeeperActive);
            Assert.NotNull(result.Evidence.CohortKeeperCompletedUtc);
            Assert.Equal(2, result.Evidence.MountProofs.Count);
            AssertKeeperReleasedResources(keeper, fixture.Manifest);
        }
        finally
        {
            if (keeper is not null) WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            await task.WaitAsync(TimeSpan.FromSeconds(10));
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Fact]
    public async Task ManifestCohortUncertainFailedChildRetainsItsExactHandleAndOriginalOwnership()
    {
        var fixture = CreateCohortFixture();
        var lifetime = Path.Combine(fixture.Root, "host.alive");
        File.WriteAllText(lifetime, "alive");
        using var child = Process.Start(new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec")!, "/c exit 0")
            { UseShellExecute = false, CreateNoWindow = true })!;
        var childHandle = child.SafeHandle;
        await child.WaitForExitAsync();
        var uncertainty = 1;
        var entered = new TaskCompletionSource<KeeperObservation>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            StartQuarantineOwnerOverride = () => false,
            FailedQuarantineChildHandle = childHandle,
            WaitForHandleOverride = (_, _, kind) => kind == 3 && Volatile.Read(ref uncertainty) != 0 ? uint.MaxValue : null,
            CohortKeeperEntered = (e, j, p, m, c) =>
            {
                WriteCohortStatus(e, terminal: true, leaseHeld: false);
                entered.TrySetResult(ObserveKeeper(e, j, p, m, c));
            },
        });
        var options = new FsHostSupervisorOptions(Environment.GetEnvironmentVariable("ComSpec")!,
            ["/c", "exit", "0", .. fixture.Args], Environment.ProcessId.ToString(), lifetime,
            Path.Combine(fixture.Root, "launch.json"), fixture.Evidence.EvidenceFile,
            StatusFile: fixture.Evidence.StatusFile, ProcessAbsenceTimeoutMs: 250, OwnerPollIntervalMs: 25);
        var task = Task.Run(() => FsHostSupervisor.RunAsync(options));
        KeeperObservation? keeper = null;
        try
        {
            keeper = await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Task.Delay(600);
            Assert.False(task.IsCompleted);
            Assert.NotNull(keeper.FailedChild);
            AssertKeeperOwnsLiveResources(keeper, fixture.Manifest);
            using var retained = await WaitForJsonAsync(fixture.Evidence.EvidenceFile + ".retained-owner.json", TimeSpan.FromSeconds(5));
            Assert.Equal(Environment.ProcessId, retained.RootElement.GetProperty("cohortKeeperPid").GetInt32());
            Volatile.Write(ref uncertainty, 0);
            var result = await task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(result.Evidence.FailedQuarantineChildAbsent);
            Assert.True(result.Evidence.JobClosed);
            AssertKeeperReleasedResources(keeper, fixture.Manifest);
        }
        finally
        {
            Volatile.Write(ref uncertainty, 0);
            if (keeper is not null) WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            await task.WaitAsync(TimeSpan.FromSeconds(10));
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Fact]
    public async Task ManifestCohortQuarantineCatchRetainsRealInheritedOwnershipUntilProofRestored()
    {
        var fixture = CreateCohortFixture();
        var options = CreateExitedCohortQuarantineOptions(fixture.Evidence, fixture.Root);
        File.WriteAllText(fixture.Evidence.EvidenceFile, "{");
        var entered = new TaskCompletionSource<KeeperObservation>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            CohortKeeperEntered = (e, j, p, m, c) =>
            {
                WriteCohortStatus(e, terminal: true, leaseHeld: true);
                entered.TrySetResult(ObserveKeeper(e, j, p, m, c));
            },
        });
        var task = Task.Run(() => FsHostSupervisor.RunQuarantineAsync(options));
        KeeperObservation? keeper = null;
        try
        {
            keeper = await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Task.Delay(600);
            Assert.False(task.IsCompleted);
            AssertKeeperOwnsLiveResources(keeper, fixture.Manifest);
            Assert.Equal("quarantine-owner-recovery", keeper.Evidence.CohortKeeperReason);
            WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            Assert.Equal(1, await task.WaitAsync(TimeSpan.FromSeconds(5)));
            AssertKeeperReleasedResources(keeper, fixture.Manifest);
            using var final = await WaitForJsonAsync(fixture.Evidence.EvidenceFile, TimeSpan.FromSeconds(5));
            Assert.True(final.RootElement.GetProperty("jobClosed").GetBoolean());
            Assert.False(final.RootElement.GetProperty("cohortKeeperActive").GetBoolean());
            Assert.Equal("completed", final.RootElement.GetProperty("ownershipHandoffState").GetString());
        }
        finally
        {
            if (keeper is not null) WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            await task.WaitAsync(TimeSpan.FromSeconds(10));
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManifestCohortPublicationFailurePreservesAuthenticatedLineage(bool afterReady)
    {
        var fixture = CreateCohortFixture();
        var options = CreateExitedCohortQuarantineOptions(fixture.Evidence, fixture.Root, exitCode: 2);
        var offered = new FsHostSupervisorEvidence
        {
            SupervisorPid = Environment.ProcessId,
            SupervisorExecutable = supervisorExecutablePath,
            SupervisorSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(supervisorExecutablePath))),
            SupervisorPayloadPath = supervisorPayloadPath,
            SupervisorPayloadSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(supervisorPayloadPath))),
            OwnerPid = Environment.ProcessId,
            HostPid = options.HostPid,
            HostParentPid = Environment.ProcessId,
            HostCreationTimeFileTime = options.HostCreationTimeFileTime,
            HostIdentityCaptured = true,
            HostExitCode = fixture.Evidence.HostExitCode,
            HostArguments = fixture.Args,
            ContainerManifestAuthority = fixture.Evidence.ContainerManifestAuthority,
            EvidenceFile = fixture.Evidence.EvidenceFile,
            StatusFile = fixture.Evidence.StatusFile,
            StartedUtc = DateTime.UtcNow,
            JobCreated = true,
            JobAssigned = true,
            OwnershipHandoffToken = options.HandoffToken,
            OwnershipHandoffState = "offered",
            EvidenceRevision = 37,
        };
        Assert.Equal(2, offered.HostExitCode);
        File.WriteAllText(offered.EvidenceFile, JsonSerializer.Serialize(offered,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        var offeredBytes = File.ReadAllBytes(offered.EvidenceFile);
        var failed = 0;
        FsHostSupervisorEvidence? authenticated = null;
        var entered = new TaskCompletionSource<KeeperObservation>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var hooks = FsHostSupervisor.InstallTestHooks(new FsHostSupervisorTestHooks
        {
            BeforeEvidencePublication = evidence =>
            {
                if (evidence.OwnershipHandoffState == "accepted" &&
                    File.Exists(options.ReadyFile) == afterReady &&
                    Interlocked.CompareExchange(ref failed, 1, 0) == 0)
                {
                    authenticated = evidence;
                    throw new UnauthorizedAccessException("Injected transient evidence publication failure.");
                }
            },
            CohortKeeperEntered = (e, j, p, m, c) => entered.TrySetResult(ObserveKeeper(e, j, p, m, c)),
        });
        var task = Task.Run(() => FsHostSupervisor.RunQuarantineAsync(options));
        KeeperObservation? keeper = null;
        try
        {
            keeper = await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var retained = await WaitForJsonAsync(offered.EvidenceFile, TimeSpan.FromSeconds(5),
                e => e.GetProperty("cohortKeeperActive").GetBoolean());
            Assert.Equal(1, Volatile.Read(ref failed));
            Assert.Same(authenticated, keeper.Evidence);
            Assert.Equal(2, keeper.Evidence.HostExitCode);
            Assert.Equal(offered.OwnerPid, keeper.Evidence.OwnerPid);
            Assert.Equal(offered.HostParentPid, keeper.Evidence.HostParentPid);
            Assert.Equal(options.HostPid, keeper.Evidence.HostPid);
            Assert.Equal(options.HostCreationTimeFileTime, keeper.Evidence.HostCreationTimeFileTime);
            Assert.Equal(offered.ContainerManifestAuthority!.ContentSha256,
                keeper.Evidence.ContainerManifestAuthority!.ContentSha256);
            Assert.Equal(options.HandoffToken, keeper.Evidence.OwnershipHandoffToken);
            Assert.Equal("accepted", keeper.Evidence.OwnershipHandoffState);
            Assert.True(keeper.Evidence.QuarantineOwnerStarted);
            Assert.True(keeper.Evidence.QuarantineOwnerHandleInheritanceProven);
            Assert.Equal(Environment.ProcessId, keeper.Evidence.QuarantineOwnerPid);
            Assert.Equal("quarantine", keeper.Evidence.EvidenceWriterRole);
            Assert.True(keeper.Evidence.EvidenceRevision > offered.EvidenceRevision);
            Assert.Equal(2, retained.RootElement.GetProperty("hostExitCode").GetInt32());
            Assert.Equal(Environment.ProcessId, retained.RootElement.GetProperty("quarantineOwnerPid").GetInt32());
            Assert.Equal(options.HandoffToken, retained.RootElement.GetProperty("ownershipHandoffToken").GetString());
            Assert.Equal("accepted", retained.RootElement.GetProperty("ownershipHandoffState").GetString());
            Assert.Contains("UnauthorizedAccessException", keeper.Evidence.FailureDetails);
            Assert.NotEqual(offeredBytes, File.ReadAllBytes(offered.EvidenceFile));
            Assert.Equal(afterReady, File.Exists(options.ReadyFile));
            Assert.False(task.IsCompleted);
            Assert.False(keeper.Evidence.JobClosed);
            Assert.False(File.Exists(offered.StatusFile));
            Assert.Null(keeper.Evidence.CohortCrashProof);
            Assert.Equal("error", FsHostSupervisor.ReadContainerStatusForTests(keeper.Evidence));
            Assert.False(FsHostSupervisor.CanReleaseCohortForTests(keeper.Evidence, 0));
            AssertKeeperOwnsLiveResources(keeper, fixture.Manifest);

            WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            Assert.Equal(1, await task.WaitAsync(TimeSpan.FromSeconds(5)));
            AssertKeeperReleasedResources(keeper, fixture.Manifest);
            using var final = await WaitForJsonAsync(offered.EvidenceFile, TimeSpan.FromSeconds(5));
            Assert.Equal(2, final.RootElement.GetProperty("hostExitCode").GetInt32());
            Assert.Equal(options.HandoffToken, final.RootElement.GetProperty("ownershipHandoffToken").GetString());
            Assert.Equal("completed", final.RootElement.GetProperty("ownershipHandoffState").GetString());
            Assert.True(final.RootElement.GetProperty("jobClosed").GetBoolean());
        }
        finally
        {
            if (keeper is not null) WriteCohortStatus(keeper.Evidence, terminal: true, leaseHeld: false);
            await task.WaitAsync(TimeSpan.FromSeconds(10));
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    private static QuarantineOptions CreateExitedCohortQuarantineOptions(FsHostSupervisorEvidence evidence, string root, int exitCode = 0)
    {
        const System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static;
        using var job = (SafeHandle)typeof(FsHostSupervisor).GetMethod("CreateKillOnCloseJob", flags)!.Invoke(null, null)!;
        var childPath = Path.Combine(Path.GetDirectoryName(typeof(FsHostSupervisorTests).Assembly.Location)!,
            "ApfsAccess.Cli.TestChild.exe");
        string[] arguments = exitCode == 2
            ? ["--invalid-lineage-probe"]
            : ["--result-path", Path.Combine(root, "child.json"), "--sleep-ms", "0"];
        var launch = typeof(FsHostSupervisor).GetMethod("CreateSuspendedChild", flags)!.Invoke(null,
            [childPath, arguments, root, null])!;
        using var process = (SafeHandle)launch.GetType().GetProperty("ProcessHandle")!.GetValue(launch)!;
        using var thread = (SafeHandle)launch.GetType().GetProperty("ThreadHandle")!.GetValue(launch)!;
        evidence.HostPid = checked((int)(uint)launch.GetType().GetProperty("ProcessId")!.GetValue(launch)!);
        evidence.HostCreationTimeFileTime = (long)typeof(FsHostSupervisor).GetMethod("CaptureProcessCreationTime", flags)!.Invoke(null, [process])!;
        Assert.True((bool)typeof(FsHostSupervisor).GetMethod("AssignProcessToJobObject", flags)!.Invoke(null, [job, process])!);
        Assert.NotEqual(uint.MaxValue, ResumeThread(thread));
        Assert.Equal(0U, WaitForSingleObject(process, 5000));
        typeof(FsHostSupervisor).GetMethod("CaptureExitCode", flags)!.Invoke(null, [evidence, process]);
        Assert.Equal(exitCode, evidence.HostExitCode);
        var sealedTarget = FsHostSupervisor.SealCohortHandoffForTests(evidence);
        return new(DuplicateCurrentHandle(job.DangerousGetHandle()), DuplicateCurrentHandle(process.DangerousGetHandle()),
            evidence.HostPid.Value, evidence.HostCreationTimeFileTime.Value, true, sealedTarget, evidence.StatusFile,
            evidence.EvidenceFile, Path.Combine(root, "ready"), "test-ready", 250, "test-handoff", null);
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(SafeHandle handle, out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeHandle handle, uint timeout);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(SafeHandle job, int informationClass,
        out JobAccounting accounting, uint length, out uint returnedLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct JobAccounting
    {
        public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }
}
