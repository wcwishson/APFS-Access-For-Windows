using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class ContainerSessionRoutingTests
{
    [Fact]
    public void ContainerMemberDetached_DefaultsToFalseAndPreservesSixFieldAbi()
    {
        Assert.False(new UnmountResult(false, "S:\\", "unproven").ContainerMemberDetached);
        var result = new UnmountResult(true, "S:\\", null, true, true, true);
        Assert.False(result.ContainerMemberDetached);
        var (success, mount, error, removed, released, cleared) = result;
        Assert.True(success && removed && released && cleared);
        Assert.Equal("S:\\", mount);
        Assert.Null(error);
        Assert.NotNull(typeof(UnmountResult).GetConstructor(
            [typeof(bool), typeof(string), typeof(string), typeof(bool), typeof(bool), typeof(bool)]));
        Assert.True((result with { ContainerMemberDetached = true }).ContainerMemberDetached);
    }

    [Theory]
    [InlineData("wrong-ack")]
    [InlineData("already-detached")]
    [InlineData("wrong-request")]
    [InlineData("native-refusal")]
    [InlineData("wrong-target")]
    [InlineData("target-still-mounted")]
    [InlineData("wrong-recovery-identity")]
    [InlineData("wrong-birth")]
    [InlineData("wrong-owner")]
    [InlineData("wrong-container")]
    [InlineData("lease-released")]
    [InlineData("recovery-required")]
    [InlineData("target-degraded")]
    [InlineData("missing-drain")]
    [InlineData("dirty")]
    [InlineData("callbacks")]
    [InlineData("shutdown-drain")]
    [InlineData("accepted-debt")]
    [InlineData("cleanup-debt")]
    [InlineData("deferred-commit")]
    [InlineData("invalid-wal")]
    [InlineData("spool-debt")]
    [InlineData("namespace-present")]
    [InlineData("namespace-unknown")]
    public async Task Eject_RefusesUnprovenContainerMemberDetach(string fault)
    {
        using var temp = DTempDirectory.Create("container-detach-proof");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var namespaceUnknown = false;
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)],
                devicePath: Path.Combine(temp.Path, "fixture.apfs.img")),
            launched,
            visibility,
            hooks => hooks.IsMountVisible = point =>
                Volatile.Read(ref namespaceUnknown) && point == "S:\\"
                    ? throw new IOException("Injected namespace observation failure.")
                    : visibility.GetValueOrDefault(point));
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(new NativeApfsBackend.ContainerMountPlan(ContainerHexA, planned));
        visibility["R:\\"] = true;
        visibility["S:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        var response = RespondToNextControlRequestAsync(
            launched[0], "detach", 102, visibility, "S:\\", ownerPid,
            configureStatus: status => CorruptDetachStatus(status, fault),
            responseCode: fault switch
            {
                "wrong-ack" => "Attached",
                "already-detached" => "AlreadyDetached",
                "native-refusal" => "CommitDrainFailed",
                _ => null,
            },
            responseRequestId: fault == "wrong-request" ? Guid.NewGuid().ToString("N") : null,
            responseStatus: fault == "native-refusal" ? "error" : "ok",
            keepMountVisible: fault == "namespace-present",
            beforeResponse: () => Volatile.Write(ref namespaceUnknown, fault == "namespace-unknown"));

        var result = await backend.UnmountAsync("S:\\", CancellationToken.None);
        await response;
        Volatile.Write(ref namespaceUnknown, false);

        Assert.False(result.Success);
        Assert.False(result.ContainerMemberDetached);
        Assert.False(result.MountRemoved);
        Assert.False(result.PendingDurabilityCleared);
        Assert.False(result.HostOwnershipReleased);
        Assert.Contains("quarantined", result.Error, StringComparison.Ordinal);
        Assert.True(SpinWait.SpinUntil(() => !IsProcessAlive(ownerPid), TimeSpan.FromSeconds(5)));
        Assert.Single(launched);
        Assert.Equal(1, GetContainerGroupCount(backend));
        var reserved = await backend.GetMountStateAsync(CancellationToken.None);
        Assert.Equal(2, reserved.Count);
        Assert.All(reserved, mount => Assert.False(mount.MountReady));
    }

    private static void CorruptDetachStatus(JsonObject status, string fault)
    {
        var volumes = status["volumes"]!.AsArray();
        var target = volumes.Single(row => row!["objectId"]!.GetValue<ulong>() == 102)!.AsObject();
        switch (fault)
        {
            case "wrong-target":
                target["objectId"] = 103ul;
                target["canonicalId"] = $"apfs-vol:{ContainerHexA}:103";
                break;
            case "target-still-mounted":
                target["mounted"] = true;
                target["ready"] = true;
                break;
            case "wrong-recovery-identity": target["recoveryIdentity"] = "replacement"; break;
            case "wrong-birth":
                status["ownerStartFileTimeUtc"] = status["ownerStartFileTimeUtc"]!.GetValue<long>() + 1;
                break;
            case "wrong-owner":
                using (var otherOwner = Process.GetCurrentProcess())
                {
                    status["ownerPid"] = otherOwner.Id;
                    status["ownerStartFileTimeUtc"] = otherOwner.StartTime.ToUniversalTime().ToFileTimeUtc();
                }
                break;
            case "wrong-container":
                var otherContainer = new string('b', 32);
                status["containerUuid"] = otherContainer;
                foreach (var row in volumes)
                    row!["canonicalId"] = $"apfs-vol:{otherContainer}:{row["objectId"]!.GetValue<ulong>()}";
                break;
            case "lease-released": status["leaseHeld"] = false; break;
            case "recovery-required":
                status["recoveryRequired"] = true;
                status["recoveryVolumeObjectId"] = 102ul;
                status["recoveryReason"] = "SessionCommitRecoveryRequired";
                break;
            case "target-degraded": target["writeDegraded"] = true; break;
            case "missing-drain":
                foreach (var key in new[] { "dirtyTransactionCount", "inFlightMutationCallbacks", "shutdownDrainActive",
                    "closeCommitDeferred", "deferredCommitRequested", "deferredCommitInFlight", "walRecoveryStateValid",
                    "walAcceptedSequence", "walApfsDurableSequence", "walCleanupSequence", "payloadSpoolDirtyRangeCount",
                    "payloadSpoolIndexDirty", "payloadSpoolRecoveryRequired" })
                    target.Remove(key);
                break;
            case "dirty": target["dirtyTransactionCount"] = 1; break;
            case "callbacks": target["inFlightMutationCallbacks"] = 1; break;
            case "shutdown-drain": target["shutdownDrainActive"] = true; break;
            case "accepted-debt": target["walAcceptedSequence"] = 8ul; break;
            case "cleanup-debt": target["walCleanupSequence"] = 6ul; break;
            case "deferred-commit": target["deferredCommitRequested"] = true; break;
            case "invalid-wal": target["walRecoveryStateValid"] = false; break;
            case "spool-debt": target["payloadSpoolDirtyRangeCount"] = 1ul; break;
        }
    }
}
