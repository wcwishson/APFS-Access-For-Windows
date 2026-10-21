using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Task 2 CLI routing (managed side): `volumes`/`mount`/`eject` operate per
// volume through the container owner. The CLI/service layers are thin pipe
// clients over IApfsBackend, so routing lives in the backend: mount joins a
// live container group (else starts one), eject of one volume never touches
// siblings, and eject of the last volume stops the owner. Fake FsHost shim
// follows HostProcessGuardianTests (StartProcess hook + real ping child).
public sealed partial class ContainerSessionRoutingTests : IDisposable
{
    private const string ContainerHexA = "a9cb92d28b7c4b599eab633c7625f491";

    private readonly List<Process> _children = new();
    private readonly List<NativeApfsBackend> _backends = new();
    private readonly object _sync = new();

    [Fact]
    public async Task Mount_RejectsVolumeAbsentFromLiveManifest_NoSecondRawOwner()
    {
        using var temp = DTempDirectory.Create("container-route-join");
        var launched = new List<string[]>();
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);

        // Seed a live owner for the first volume only.
        backend.StartContainerGroupOwner(new NativeApfsBackend.ContainerMountPlan(ContainerHexA, [planned[0]]));
        Assert.Single(launched);
        var manifestArgument = Array.IndexOf(launched[0], "--container-manifest");
        var checksumArgument = Array.IndexOf(launched[0], "--container-manifest-sha256");
        Assert.True(manifestArgument >= 0 && manifestArgument + 1 < launched[0].Length);
        Assert.True(checksumArgument >= 0 && checksumArgument + 1 < launched[0].Length);
        Assert.Equal(GetContainerManifestPath(backend, ContainerHexA), launched[0][manifestArgument + 1]);
        using (var document = JsonDocument.Parse(File.ReadAllText(launched[0][manifestArgument + 1])))
        {
            Assert.Equal(
                document.RootElement.GetProperty("manifestSha256").GetString(),
                launched[0][checksumArgument + 1]);
        }

        var result = await backend.MountAsync(planned[1].Request, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("ContainerVolumeNotPredeclared", result.DiagnosticCode);
        Assert.Single(launched);
        Assert.Equal(1, GetContainerGroupMemberCount(backend, ContainerHexA));
        var mounts = await backend.GetMountStateAsync(CancellationToken.None);
        Assert.Single(mounts);
    }

    [Fact]
    public async Task Mount_StartsContainerOwnerWhenCanonicalIdentityHasNoOwner()
    {
        using var temp = DTempDirectory.Create("container-route-noowner");
        var launched = new List<string[]>();
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);

        var result = await backend.MountAsync(planned[0].Request, CancellationToken.None);

        // Canonical volumes always use the manifest owner path, including a
        // one-volume container (the fake shim never exposes its drive).
        Assert.False(result.Success);
        Assert.Equal("FsHostStartupTimeout", result.DiagnosticCode);
        PublishTerminalContainerStatus(backend);
        Assert.True(
            SpinWait.SpinUntil(
                () => GetContainerGroupCount(backend) == 0,
                TimeSpan.FromSeconds(10)),
            "Timed-out canonical owner was not reaped after exact exit and namespace absence.");
        Assert.Contains("--container-manifest", launched[0]);
    }

    [Theory]
    [InlineData("R:\\", 101ul, "S:\\")]
    [InlineData("S:\\", 102ul, "R:\\")]
    public async Task Eject_OneVolume_KeepsSiblingsAndOwnerAlive(string targetMount, ulong targetOid, string siblingMount)
    {
        using var temp = DTempDirectory.Create("container-route-ejectone");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        var target = planned.Single(member => member.MountPoint == targetMount);
        var sibling = planned.Single(member => member.MountPoint == siblingMount);

        var detachResponse = RespondToNextControlRequestAsync(
            launched[0], "detach", targetOid, visibility, targetMount, ownerPid);

        var result = await backend.UnmountAsync(targetMount, CancellationToken.None);
        await detachResponse;

        Assert.True(result.Success);
        Assert.True(result.MountRemoved);
        Assert.True(result.ContainerMemberDetached);
        Assert.True(result.PendingDurabilityCleared);
        Assert.False(result.HostOwnershipReleased);
        Assert.Single(launched);
        Assert.Equal(2, GetContainerGroupMemberCount(backend, ContainerHexA));
        Assert.True(IsProcessAlive(ownerPid));
        var mounts = await backend.GetMountStateAsync(CancellationToken.None);
        var remaining = Assert.Single(mounts);
        Assert.Equal(siblingMount, remaining.MountPoint);
        Assert.True(remaining.MountReady);
        Assert.Equal(ownerPid, remaining.HostProcessId);
        using (var owner = Process.GetProcessById(ownerPid))
            Assert.Equal(owner.StartTime.ToUniversalTime().ToFileTimeUtc(), remaining.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(sibling.Volume.DeviceId, remaining.DeviceId);
        Assert.Equal(sibling.Volume.VolumeId, remaining.VolumeId);
        Assert.Equal(sibling.RecoveryIdentity, remaining.RecoveryIdentity);

        var attachResponse = RespondToNextControlRequestAsync(
            launched[0], "attach", targetOid, visibility, targetMount, ownerPid);
        var remounted = await backend.MountAsync(target.Request, CancellationToken.None);
        await attachResponse;

        Assert.True(remounted.Success);
        Assert.Equal("ContainerVolumeReattached", remounted.DiagnosticCode);
        Assert.True(remounted.MountReady);
        Assert.Equal(ownerPid, remounted.HostProcessId);
        Assert.Equal(2, (await backend.GetMountStateAsync(CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Eject_ControlTimeout_ContainsOwnerAndRetainsAllReservationsUntilNamespacesDisappear()
    {
        using var temp = DTempDirectory.Create("container-route-control-timeout");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);

        var result = await backend.UnmountAsync("S:\\", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("ControlResponseTimeout", result.Error, StringComparison.Ordinal);
        Assert.True(
            SpinWait.SpinUntil(() => !IsProcessAlive(ownerPid), TimeSpan.FromSeconds(10)),
            "A timed-out control operation did not contain the shared FsHost owner.");
        Assert.Equal(1, GetContainerGroupCount(backend));
        var reserved = await backend.GetMountStateAsync(CancellationToken.None);
        Assert.Equal(2, reserved.Count);
        Assert.All(reserved, static mount => Assert.False(mount.MountReady));

        var reattach = await backend.MountAsync(planned[1].Request, CancellationToken.None);
        Assert.False(reattach.Success);
        Assert.Equal("ContainerOwnerPoisoned", reattach.DiagnosticCode);
        Assert.Single(launched);

        PublishTerminalContainerStatus(backend);
        visibility["R:\\"] = false;
        Assert.Equal(1, GetContainerGroupCount(backend));
        visibility["S:\\"] = false;
        Assert.True(
            SpinWait.SpinUntil(
                () =>
                {
                    _ = backend.GetMountStateAsync(CancellationToken.None)
                        .GetAwaiter().GetResult();
                    return GetContainerGroupCount(backend) == 0;
                },
                TimeSpan.FromSeconds(10)),
            "Contained owner reservations were not released after exact process and namespace absence.");
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Eject_CancelAfterControlPublication_CompletesNonCancelableDetach()
    {
        using var temp = DTempDirectory.Create("container-route-detach-cancel-published");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility,
            hooks => hooks.ProbeExactProcessHandleExit = process => process.HasExited);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        using var cancellation = new CancellationTokenSource();
        var detachResponse = RespondToNextControlRequestAsync(
            launched[0], "detach", 102, visibility, "S:\\", ownerPid, cancellation);

        var result = await backend.UnmountAsync("S:\\", cancellation.Token);
        await detachResponse;

        Assert.True(cancellation.IsCancellationRequested);
        Assert.True(result.Success, result.Error);
        Assert.True(result.ContainerMemberDetached);
        Assert.True(result.PendingDurabilityCleared);
        Assert.False(result.HostOwnershipReleased);
        Assert.True(IsProcessAlive(ownerPid));
        Assert.Equal(1, GetContainerGroupCount(backend));
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Single(launched);

        PublishTerminalContainerStatus(backend);
        visibility["R:\\"] = false;
        using (var owner = Process.GetProcessById(ownerPid))
        {
            owner.Kill(entireProcessTree: true);
            Assert.True(owner.WaitForExit(5_000));
        }
        Assert.True(
            SpinWait.SpinUntil(
                () =>
                {
                    _ = backend.GetMountStateAsync(CancellationToken.None)
                        .GetAwaiter().GetResult();
                    return GetContainerGroupCount(backend) == 0;
                },
                TimeSpan.FromSeconds(10)),
            "Detached owner was not reaped after exact process and namespace absence.");
    }

    [Fact]
    public async Task Mount_CancelAfterControlPublication_ContainsOwnerAndRetainsReservations()
    {
        using var temp = DTempDirectory.Create("container-route-attach-cancel-published");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        var detachResponse = RespondToNextControlRequestAsync(
            launched[0], "detach", 102, visibility, "S:\\", ownerPid);
        var detached = await backend.UnmountAsync("S:\\", CancellationToken.None);
        Assert.True(detached.Success, detached.Error);
        await detachResponse;

        using var cancellation = new CancellationTokenSource();
        var cancelAfterPublish = CancelOnNextControlRequestAsync(
            launched[0], "attach", 102, cancellation);
        var result = await backend.MountAsync(planned[1].Request, cancellation.Token);
        await cancelAfterPublish;

        Assert.False(result.Success);
        Assert.Equal("ControlCanceledAfterPublish", result.DiagnosticCode);
        Assert.True(
            SpinWait.SpinUntil(() => !IsProcessAlive(ownerPid), TimeSpan.FromSeconds(10)),
            "A canceled published attach did not contain the shared owner.");
        Assert.Equal(1, GetContainerGroupCount(backend));
        Assert.Single(launched);

        PublishTerminalContainerStatus(backend);
        visibility["R:\\"] = false;
        visibility["S:\\"] = false;
        Assert.True(
            SpinWait.SpinUntil(
                () =>
                {
                    _ = backend.GetMountStateAsync(CancellationToken.None)
                        .GetAwaiter().GetResult();
                    return GetContainerGroupCount(backend) == 0;
                },
                TimeSpan.FromSeconds(10)),
            "Canceled attach reservations were not released after complete absence proof.");
    }

    [Fact]
    public async Task UnexpectedOwnerExit_RetainsReservationsUntilAllNamespacesDisappear()
    {
        using var temp = DTempDirectory.Create("container-route-owner-exit-visible");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);

        using (var owner = Process.GetProcessById(ownerPid))
        {
            owner.Kill(entireProcessTree: true);
            Assert.True(owner.WaitForExit(5_000));
        }
        var deadStatus = await backend.GetContainerMountStatusAsync(
            ContainerHexA,
            CancellationToken.None);
        var retained = await backend.GetMountStateAsync(CancellationToken.None);

        Assert.False(deadStatus.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.OwnerNotAlive, deadStatus.UnknownReason);
        Assert.Equal(1, GetContainerGroupCount(backend));
        Assert.Equal(2, retained.Count);
        Assert.All(retained, static mount => Assert.False(mount.MountReady));
        var retry = await backend.MountAsync(planned[0].Request, CancellationToken.None);
        Assert.False(retry.Success);
        Assert.Equal("ContainerOwnerPoisoned", retry.DiagnosticCode);
        Assert.Single(launched);

        PublishTerminalContainerStatus(backend);
        visibility["R:\\"] = false;
        visibility["S:\\"] = false;
        Assert.True(
            SpinWait.SpinUntil(
                () =>
                {
                    _ = backend.GetMountStateAsync(CancellationToken.None)
                        .GetAwaiter().GetResult();
                    return GetContainerGroupCount(backend) == 0;
                },
                TimeSpan.FromSeconds(10)),
            "Exited owner reservations were not released after every namespace disappeared.");
    }

    [Fact]
    public async Task Eject_LastVolume_StopsOwnerAndClearsGroup()
    {
        using var temp = DTempDirectory.Create("container-route-ejectlast");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility,
            hooks => hooks.ProbeExactProcessHandleExit = process =>
            {
                if (!process.HasExited)
                {
                    return false;
                }
                visibility["R:\\"] = false;
                visibility["S:\\"] = false;
                return true;
            });
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        var manifestPath = GetContainerManifestPath(backend, ContainerHexA);
        Assert.True(File.Exists(manifestPath));

        var detachResponse = RespondToNextControlRequestAsync(
            launched[0], "detach", 102, visibility, "S:\\", ownerPid);
        Assert.True((await backend.UnmountAsync("S:\\", CancellationToken.None)).Success);
        await detachResponse;
        var last = await backend.UnmountAsync("R:\\", CancellationToken.None);
        Assert.False(last.ContainerMemberDetached);
        PublishTerminalContainerStatus(backend);
        visibility["R:\\"] = false;

        // Last eject stops the owner (force-stopped shim => legacy
        // not-clean shape with MountRemoved, mirroring UnmountAsync).
        Assert.True(
            SpinWait.SpinUntil(
                () => GetContainerGroupCount(backend) == 0,
                TimeSpan.FromSeconds(10)),
            last.Error ?? "Container owner was not released after exact exit proof.");
        Assert.False(IsProcessAlive(ownerPid));
        Assert.False(File.Exists(manifestPath));
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
    }

    [Fact]
    public async Task StartupTimeout_RetainsOwnerUntilExactExitIsProven()
    {
        using var temp = DTempDirectory.Create("container-route-timeout-retain");
        var launched = new List<string[]>();
        var allowExitProof = false;
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            configureHooks: hooks =>
            {
                hooks.ProbeExactProcessHandleExit = _ => allowExitProof;
                hooks.ProbeSystemProcessPresence = _ => allowExitProof ? false : true;
                hooks.ProbeProcessCreationTime = _ => 0L;
            });
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);

        var results = await backend.MountContainerAsync(
            planned.Select(static member => member.Request).ToArray(),
            CancellationToken.None);

        Assert.All(results, static result => Assert.Equal("FsHostStartupTimeout", result.DiagnosticCode));
        Assert.Equal(1, GetContainerGroupCount(backend));
        var manifestPath = GetContainerManifestPath(backend, ContainerHexA);
        Assert.True(File.Exists(manifestPath));

        PublishTerminalContainerStatus(backend);
        allowExitProof = true;
        Assert.True(
            SpinWait.SpinUntil(
                () => GetContainerGroupCount(backend) == 0,
                TimeSpan.FromSeconds(10)),
            "The exit observer did not release the retained container owner after exact proof became available.");
        Assert.False(File.Exists(manifestPath));
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Startup_MissingOwnedReadyStatusNeverReportsSuccess()
    {
        using var temp = DTempDirectory.Create("container-route-visible-no-status");
        var launched = new List<string[]>();
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        var group = GetContainerGroup(backend, ContainerHexA);
        var status = await backend.GetContainerMountStatusAsync(
            ContainerHexA, CancellationToken.None);
        Assert.False(status.IsKnown);

        var buildResult = typeof(NativeApfsBackend).GetMethod(
            "BuildContainerLaunchSuccessResult",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(buildResult);
        var result = Assert.IsType<MountResult>(buildResult!.Invoke(
            backend,
            [planned[0], group, status]));

        Assert.False(result.Success);
        Assert.Equal("ContainerStatusUnavailable", result.DiagnosticCode);
        Assert.False(result.MountReady);
    }

    [Fact]
    public async Task Startup_OwnedReadyStatusPublishesBothVolumes()
    {
        using var temp = DTempDirectory.Create("container-route-ready-status");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);

        var mountTask = backend.MountContainerAsync(
            planned.Select(static member => member.Request).ToArray(),
            CancellationToken.None);
        Assert.True(
            SpinWait.SpinUntil(
                () => GetContainerGroupCount(backend) == 1 && launched.Count == 1,
                TimeSpan.FromSeconds(5)),
            "Backend did not establish the container owner for the startup probe.");
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        PublishContainerStatus(
            launched[0],
            GetContainerOwnerPid(backend, ContainerHexA),
            visibility);

        var results = await mountTask;

        Assert.Equal(2, results.Count);
        Assert.All(results, static result =>
        {
            Assert.True(result.Success);
            Assert.True(result.MountReady);
            Assert.True(result.IsReadOnly);
            Assert.False(result.WriteEnabled);
        });
        Assert.Equal(2, (await backend.GetMountStateAsync(CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Status_FreshFileReportsPerVolumeStates_StaleFileNeverHealthy()
    {
        using var temp = DTempDirectory.Create("container-route-status");
        var launched = new List<string[]>();
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(
            new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        var statusPath = GetContainerStatusPath(backend, ContainerHexA);

        File.WriteAllText(statusPath, ContainerStatusJson(ownerPid, leaseHeld: true));

        var known = await backend.GetContainerMountStatusAsync(ContainerHexA, CancellationToken.None);
        Assert.True(known.IsKnown);
        Assert.Equal(ownerPid, known.OwnerPid);
        Assert.True(known.LeaseHeld);
        Assert.Equal(2, known.Volumes.Count);
        var mounts = await backend.GetMountStateAsync(CancellationToken.None);
        Assert.Equal(2, mounts.Count);
        Assert.True(mounts.Single(mount => mount.MountPoint == "R:\\").MountReady);
        Assert.False(mounts.Single(mount => mount.MountPoint == "S:\\").MountReady);

        File.Delete(statusPath);
        var unknown = await backend.GetContainerMountStatusAsync(ContainerHexA, CancellationToken.None);
        Assert.False(unknown.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.Missing, unknown.UnknownReason);
        var degraded = await backend.GetMountStateAsync(CancellationToken.None);
        Assert.Equal(2, degraded.Count);
        Assert.All(degraded, static mount => Assert.False(mount.MountReady));
    }

    [Fact]
    public async Task Status_UnknownContainer_IsUnknown()
    {
        using var temp = DTempDirectory.Create("container-route-nogroup");
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")));

        var status = await backend.GetContainerMountStatusAsync(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CancellationToken.None);

        Assert.False(status.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.NoContainerGroup, status.UnknownReason);
    }

    public void Dispose()
    {
        foreach (var backend in _backends)
        {
            try
            {
                backend.Dispose();
            }
            catch
            {
            }
        }

        lock (_sync)
        {
            foreach (var child in _children)
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

                try
                {
                    child.Dispose();
                }
                catch
                {
                }
            }

            _children.Clear();
        }
    }

    private async Task<NativeApfsBackend> CreateProbedBackendAsync(
        DTempDirectory temp,
        string evidence,
        List<string[]>? launched = null,
        ConcurrentDictionary<string, bool>? visibility = null,
        Action<HostProcessLifecycleTestHooks>? configureHooks = null,
        Action<ServiceHostOptions>? configureOptions = null)
    {
        var imagePath = Path.Combine(temp.Path, "fixture.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(imagePath);
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var hooks = new HostProcessLifecycleTestHooks
        {
            StartProcess = psi =>
            {
                launched?.Add(psi.ArgumentList.ToArray());
                return StartPingChild(30);
            },
            IsMountVisible = mountPoint =>
                visibility?.GetValueOrDefault(mountPoint) ?? false,
            QueryDosDevice = (name, _) => visibility?.GetValueOrDefault(name + ":\\") == true
                ? (1u, 0) : (0u, 2),
        };
        configureHooks?.Invoke(hooks);
        var options = new ServiceHostOptions
            {
                BackendMode = "Native",
                NativeAutoDiscoverPhysicalDrives = false,
                NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
                NativeHostStartupTimeoutSeconds = 2,
                NativeHostStopTimeoutSeconds = 2,
                NativeWriteEvidenceStorePath = Path.Combine(temp.Path, "evidence.json"),
            };
        configureOptions?.Invoke(options);
        var backend = new NativeApfsBackend(
            options,
            hooks,
            observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
            observerPathOverride: observerShim);
        _backends.Add(backend);
        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);
        Assert.NotEmpty(volumes);
        return backend;
    }

    private NativeApfsBackend.PlannedVolume[] BuildPlanned(
        NativeApfsBackend backend, string[] letters, MountAccessMode accessMode)
    {
        var volumesField = typeof(NativeApfsBackend)
            .GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend);
        var cached = ((IDictionary)volumesField!)
            .Values.Cast<VolumeInfo>()
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(letters.Length, cached.Length);
        return cached.Select((volume, index) =>
        {
            var target = ReadMountTarget(backend, volume);
            var letter = letters[index][0];
            return new NativeApfsBackend.PlannedVolume(
                new MountRequest(volume.VolumeId, letter, accessMode),
                volume,
                target.DevicePath!,
                target.DeviceOffsetBytes ?? 0,
                target.VolumeObjectId,
                target.RecoveryIdentity,
                $"{char.ToUpperInvariant(letter)}:\\");
        }).ToArray();
    }

    private static (string? DevicePath, ulong? DeviceOffsetBytes, ulong? VolumeObjectId, string? RecoveryIdentity)
        ReadMountTarget(NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var target = method!.Invoke(backend, [volume]);
        Assert.NotNull(target);
        var targetType = target!.GetType();
        return (
            (string?)targetType.GetProperty("DevicePath")!.GetValue(target),
            (ulong?)targetType.GetProperty("DeviceOffsetBytes")!.GetValue(target),
            (ulong?)targetType.GetProperty("VolumeObjectId")!.GetValue(target),
            (string?)targetType.GetProperty("RecoveryIdentity")!.GetValue(target));
    }

    private static object GetContainerGroup(NativeApfsBackend backend, string containerUuid)
    {
        var groups = (IDictionary)typeof(NativeApfsBackend)
            .GetField("_containerGroups", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var group = groups[containerUuid];
        Assert.NotNull(group);
        return group!;
    }

    private static int GetContainerGroupCount(NativeApfsBackend backend)
    {
        var groups = (IDictionary)typeof(NativeApfsBackend)
            .GetField("_containerGroups", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        return groups.Count;
    }

    private static int GetContainerGroupMemberCount(NativeApfsBackend backend, string containerUuid)
    {
        var members = (IDictionary)GetContainerGroup(backend, containerUuid).GetType()
            .GetProperty("Members")!.GetValue(GetContainerGroup(backend, containerUuid))!;
        return members.Count;
    }

    private static int GetContainerOwnerPid(NativeApfsBackend backend, string containerUuid)
    {
        var group = GetContainerGroup(backend, containerUuid);
        var owner = group.GetType().GetProperty("Owner")!.GetValue(group)!;
        var process = (Process)owner.GetType().GetProperty("Process")!.GetValue(owner)!;
        return process.Id;
    }

    private static string GetContainerManifestPath(NativeApfsBackend backend, string containerUuid)
        => (string)GetContainerGroup(backend, containerUuid).GetType()
            .GetProperty("ManifestPath")!.GetValue(GetContainerGroup(backend, containerUuid))!;

    private static string GetContainerStatusPath(NativeApfsBackend backend, string containerUuid)
    {
        var group = GetContainerGroup(backend, containerUuid);
        var owner = group.GetType().GetProperty("Owner")!.GetValue(group)!;
        return (string)owner.GetType().GetProperty("StatusFilePath")!.GetValue(owner)!;
    }

    private static void PublishTerminalContainerStatus(NativeApfsBackend backend)
    {
        var group = GetContainerGroup(backend, ContainerHexA);
        var owner = group.GetType().GetProperty("Owner")!.GetValue(group)!;
        var pid = (int)owner.GetType().GetProperty("ProcessId")!.GetValue(owner)!;
        var creation = (long?)owner.GetType().GetProperty("ProcessCreationTimeFileTimeUtc")!.GetValue(owner);
        Assert.True(pid > 0 && creation > 0);
        File.WriteAllText(GetContainerStatusPath(backend, ContainerHexA), JsonSerializer.Serialize(new
        {
            containerUuid = ContainerHexA, ownerPid = pid, ownerStartFileTimeUtc = creation,
            leaseHeld = false, checkpointXid = 7ul, recoveryRequired = false,
            recoveryVolumeObjectId = (ulong?)null, recoveryReason = string.Empty, volumes = Array.Empty<object>(),
        }));
    }

    private static string ArgumentValue(string[] arguments, string name)
    {
        var index = Array.IndexOf(arguments, name);
        Assert.True(index >= 0 && index + 1 < arguments.Length, $"Missing argument {name}.");
        return arguments[index + 1];
    }

    private static Task RespondToNextControlRequestAsync(
        string[] launchArguments,
        string expectedAction,
        ulong expectedObjectId,
        ConcurrentDictionary<string, bool> visibility,
        string mountPoint,
        int ownerPid,
        CancellationTokenSource? cancelAfterPublication = null,
        Action<JsonObject>? configureStatus = null,
        string? responseCode = null,
        string? responseRequestId = null,
        string responseStatus = "ok",
        bool keepMountVisible = false,
        Action? beforeResponse = null)
    {
        var requestPath = ArgumentValue(launchArguments, "--container-control-file");
        var token = ArgumentValue(launchArguments, "--container-control-token");
        return Task.Factory.StartNew(
            () =>
            {
                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (!File.Exists(requestPath) && DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(1);
                }

                Assert.True(File.Exists(requestPath), "Backend did not publish a container control request.");
                string[] fields;
                while (true)
                {
                    try
                    {
                        fields = File.ReadAllLines(requestPath)
                            .Select(static value => value.TrimEnd('\r')).ToArray();
                        break;
                    }
                    catch (IOException) when (DateTime.UtcNow < deadline)
                    {
                        Thread.Sleep(1);
                    }
                }
                Assert.Equal(5, fields.Length);
                Assert.Equal("APFS-CONTROL/1", fields[0]);
                Assert.Equal(token, fields[2]);
                Assert.Equal(expectedAction, fields[3]);
                Assert.Equal(expectedObjectId.ToString(), fields[4]);

                cancelAfterPublication?.Cancel();
                File.Delete(requestPath);
                visibility[mountPoint] = keepMountVisible || string.Equals(expectedAction, "attach", StringComparison.Ordinal);
                PublishContainerStatus(
                    launchArguments,
                    ownerPid,
                    visibility,
                    configureStatus);
                beforeResponse?.Invoke();
                var responsePath = requestPath + ".response";
                var temporaryResponsePath = responsePath + ".tmp-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(
                    temporaryResponsePath,
                    $"APFS-CONTROL/1\n{responseRequestId ?? fields[1]}\n{responseStatus}\n{responseCode ?? (expectedAction == "attach" ? "Attached" : "Detached")}\n");
                File.Move(temporaryResponsePath, responsePath, overwrite: false);
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
    }

    private static Task CancelOnNextControlRequestAsync(
        string[] launchArguments,
        string expectedAction,
        ulong expectedObjectId,
        CancellationTokenSource cancellation)
    {
        var requestPath = ArgumentValue(launchArguments, "--container-control-file");
        return Task.Factory.StartNew(
            () =>
            {
                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (!File.Exists(requestPath) && DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(1);
                }

                Assert.True(File.Exists(requestPath), "Backend did not publish a container control request.");
                var fields = File.ReadAllLines(requestPath)
                    .Select(static value => value.TrimEnd('\r'))
                    .ToArray();
                Assert.Equal(5, fields.Length);
                Assert.Equal(expectedAction, fields[3]);
                Assert.Equal(expectedObjectId.ToString(), fields[4]);
                cancellation.Cancel();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
    }

    private static void PublishContainerStatus(
        string[] launchArguments,
        int ownerPid,
        ConcurrentDictionary<string, bool> visibility,
        Action<JsonObject>? configureStatus = null)
    {
        var manifestPath = ArgumentValue(launchArguments, "--container-manifest");
        var statusPath = ArgumentValue(launchArguments, "--status-file");
        using var manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var root = manifest.RootElement;
        using var owner = Process.GetProcessById(ownerPid);
        var rows = root.GetProperty("volumes").EnumerateArray()
            .Select(volume =>
            {
                var mount = volume.GetProperty("mount").GetString()!;
                var attached = visibility.GetValueOrDefault(mount);
                return new
                {
                    objectId = volume.GetProperty("objectId").GetUInt64(),
                    canonicalId = $"apfs-vol:{root.GetProperty("containerUuid").GetString()}:{volume.GetProperty("objectId").GetUInt64()}",
                    mounted = attached,
                    ready = attached,
                    writable = false,
                    recoveryActive = false,
                    writeDegraded = false,
                    recoveryReason = string.Empty,
                    recoveryIdentity = volume.GetProperty("recoveryIdentity").GetString() ?? string.Empty,
                    dirtyTransactionCount = 0,
                    inFlightMutationCallbacks = 0,
                    shutdownDrainActive = false,
                    closeCommitDeferred = false,
                    deferredCommitRequested = false,
                    deferredCommitInFlight = false,
                    walRecoveryStateValid = true,
                    walAcceptedSequence = 7ul,
                    walApfsDurableSequence = 7ul,
                    walCleanupSequence = 7ul,
                    payloadSpoolDirtyRangeCount = 0ul,
                    payloadSpoolIndexDirty = false,
                    payloadSpoolRecoveryRequired = false,
                };
            })
            .ToArray();
        var status = new
        {
            containerUuid = root.GetProperty("containerUuid").GetString(),
            ownerPid,
            ownerStartFileTimeUtc = owner.StartTime.ToUniversalTime().ToFileTimeUtc(),
            leaseHeld = true,
            checkpointXid = 7,
            recoveryRequired = false,
            recoveryVolumeObjectId = (ulong?)null,
            recoveryReason = string.Empty,
            volumes = rows,
        };
        var statusNode = JsonSerializer.SerializeToNode(status)!.AsObject();
        configureStatus?.Invoke(statusNode);
        var temporary = statusPath + ".test-tmp";
        File.WriteAllText(temporary, statusNode.ToJsonString());
        File.Move(temporary, statusPath, overwrite: true);
    }

    private static bool IsProcessAlive(int processId)
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

    private static string ContainerStatusJson(int ownerPid, bool leaseHeld)
    {
        using var owner = Process.GetProcessById(ownerPid);
        var ownerStartFileTimeUtc = owner.StartTime.ToUniversalTime().ToFileTimeUtc();
        return $$"""
        {
          "containerUuid": "{{ContainerHexA}}",
          "ownerPid": {{ownerPid}},
          "ownerStartFileTimeUtc": {{ownerStartFileTimeUtc}},
          "leaseHeld": {{(leaseHeld ? "true" : "false")}},
          "checkpointXid": 7,
          "recoveryRequired": false,
          "recoveryVolumeObjectId": null,
          "recoveryReason": "",
          "volumes": [
            {"objectId": 101, "canonicalId": "apfs-vol:{{ContainerHexA}}:101", "mounted": true, "ready": true, "writable": false, "recoveryActive": false, "writeDegraded": false, "recoveryReason": "", "recoveryIdentity": "rec-101"},
            {"objectId": 102, "canonicalId": "apfs-vol:{{ContainerHexA}}:102", "mounted": true, "ready": false, "writable": false, "recoveryActive": false, "writeDegraded": false, "recoveryReason": "", "recoveryIdentity": "rec-102"}
          ]
        }
        """;
    }

    private Process StartPingChild(int count)
    {
        var child = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            ArgumentList =
            {
                "-n",
                count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "127.0.0.1",
            },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        lock (_sync)
        {
            _children.Add(child);
        }

        return child;
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => result;
    }
}
