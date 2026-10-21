using System.Globalization;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class MarkedReferenceSpaceWorkflowTests
{
    internal static StatusChangedPayload StatusFor(VerifyScope scope)
    {
        var hex = scope.ContainerId[15..]; var oid = ulong.Parse(scope.VolumeObjectId, CultureInfo.InvariantCulture);
        var size = long.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture);
        var offset = long.Parse(scope.StoreOffsetBytes, CultureInfo.InvariantCulture);
        var volumeId = ApfsTopology.BuildVolumeId(hex, oid); var disk = "apfs-disk:image";
        var graph = new ApfsTopologySnapshot([new(disk, scope.ImagePath, null, size + offset)], [],
            [new("apfs-store:raw", hex, "", scope.ContainerId, offset, size, DiskId: disk)],
            [new(scope.ContainerId, hex, 4096, ["apfs-store:raw"], [volumeId], false, scope.CheckpointXid, [], [], [])],
            [new(volumeId, scope.VolumeUuid, scope.VolumeObjectId, scope.ContainerId, "Marked image", true,
                ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", scope.CheckpointXid)], []);
        var volume = new VolumeInfo(volumeId, scope.ImagePath, "Marked image", true, SupportsNativeWrite: true,
            RecoveryIdentity: "marked-owner", CatalogVolumeId: volumeId, CatalogContainerUuid: hex, CatalogVolumeObjectId: oid,
            CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true,
            CatalogVolumeUuid: scope.VolumeUuid);
        var device = new DeviceInventory(new(scope.ImagePath, "Image", true), [volume], new(1, scope.ImagePath, [disk], graph));
        return WindowsSurfaceFixture.Status() with { ConnectedInventory = [device] };
    }

    internal static VolumeSnapshotWorkflow Workflow(VerifyScope scope, Func<StatusChangedPayload> status) =>
        new(TopologyDashboard.Project(StatusFor(scope)).Single(n => n.Row is not null).Row!, status,
            _ => throw new Exception("Marked read-only accounting cannot dispatch mutation, mount or service work."));

    internal static VerifyScope TemporaryScope()
    {
        var folder = Path.Combine(Path.GetTempPath(), "marked-gui-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder); var path = Path.Combine(folder, "image.apfs");
        using (var stream = File.Create(path)) stream.SetLength(2097152);
        return new(path, "apfs-container:" + new string('a', 32), new string('b', 32), "101", "20", "0", "2097152");
    }

    internal static ApfsMarkedReferenceSpaceResult Unknown() => new(3, false,
        JsonSerializer.SerializeToElement(new { reason = "Known unsupported graph" }));

    [Fact]
    public async Task CurrentScopeIsPassedAndUnknownNeverBecomesZeroOrPolicyBytes()
    {
        var scope = TemporaryScope(); var status = StatusFor(scope); var calls = 0;
        var workflow = Workflow(scope, () => status);
        var client = new MarkedReferenceSpaceClient(true, (request, token) => {
            calls++; token.ThrowIfCancellationRequested();
            Assert.Equal(new ApfsSnapshotAttributionRequest(scope.ImagePath, scope.ContainerId, scope.VolumeUuid,
                scope.VolumeObjectId, scope.CheckpointXid, scope.StoreOffsetBytes, scope.StoreSizeBytes), request);
            return Task.FromResult(Unknown());
        });
        var result = await workflow.ReadMarkedSpaceAsync(client, default);
        Assert.Equal(1, calls); Assert.Same(result, workflow.MarkedSpaceSummary); Assert.False(result.Complete);
        Assert.Contains("Apple purgeable: Unknown", result.Details); Assert.DoesNotContain("0 bytes", result.Details);
        status = StatusFor(scope with { CheckpointXid = "21" });
        _ = workflow.CurrentRow(); Assert.Null(workflow.MarkedSpaceSummary);
    }

    [Fact]
    public async Task ChangedSelectionAfterAcceptedWaitCannotPublishAndBlocksCompetingWork()
    {
        var scope = TemporaryScope(); var status = StatusFor(scope); var workflow = Workflow(scope, () => status);
        var pending = new TaskCompletionSource<ApfsMarkedReferenceSpaceResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new MarkedReferenceSpaceClient(true, (_, _) => pending.Task);
        var run = workflow.ReadMarkedSpaceAsync(client, default);
        Assert.Null(workflow.MarkedSpaceSummary);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.ReadMarkedSpaceAsync(client, default));
        status = StatusFor(scope with { CheckpointXid = "21" });
        pending.SetResult(Unknown());
        await Assert.ThrowsAsync<InvalidOperationException>(() => run);
        Assert.Null(workflow.MarkedSpaceSummary);
    }

    [Fact]
    public async Task UnavailableAndCancelledOperationsCannotPublishOrDispatch()
    {
        var scope = TemporaryScope(); var status = StatusFor(scope); var workflow = Workflow(scope, () => status); var calls = 0;
        var unavailable = new MarkedReferenceSpaceClient(false, (_, _) => { calls++; return Task.FromResult(Unknown()); });
        await Assert.ThrowsAsync<FileNotFoundException>(() => workflow.ReadMarkedSpaceAsync(unavailable, default));
        using var stop = new CancellationTokenSource();
        var pending = new TaskCompletionSource<ApfsMarkedReferenceSpaceResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var available = new MarkedReferenceSpaceClient(true, (_, _) => { calls++; return pending.Task; });
        var run = workflow.ReadMarkedSpaceAsync(available, stop.Token); stop.Cancel();
        Assert.False(run.IsCompleted); pending.SetResult(Unknown());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(1, calls); Assert.Null(workflow.MarkedSpaceSummary);
        status = status with { ConnectedInventory = [] };
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.ReadMarkedSpaceAsync(available, default));
        Assert.Equal(1, calls);
    }
}
