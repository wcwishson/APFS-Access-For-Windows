using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class SnapshotSpaceWorkflowTests
{
    private static StatusChangedPayload Status() => WindowsSurfaceFixture.Status() with {
        ConnectedInventory = [WindowsSurfaceFixture.Inventory(2097152)] };

    private static DriveDashboardRow Row(StatusChangedPayload status) =>
        Assert.Single(TopologyDashboard.Project(status), n => n.Row is not null).Row!;

    private static VolumeSnapshotWorkflow Workflow(Func<StatusChangedPayload> status) => new(Row(status()), status,
        _ => throw new Exception("Space must not dispatch a snapshot service mutation or mount."));

    private static SnapshotSpaceSummary Complete() => new(true,
        "Shared blocks counted once. Apple purgeability and exact deletion savings are unknown.",
        [new("retained", "21", 20480, 4096, 4096, 0)]);

    [Fact]
    public async Task SpaceUsesExactCurrentOfflineScopeWithoutRequiringSnapshotInventory()
    {
        var status = Status(); var workflow = Workflow(() => status); var summary = Complete(); var calls = 0;
        Assert.True(workflow.CanReadSpace); Assert.Null(workflow.Inventory);
        var result = await workflow.ReadSpaceAsync((scope, requireCurrent, token) => {
            calls++; requireCurrent(); token.ThrowIfCancellationRequested();
            Assert.Equal(new VerifyScope(WindowsSurfaceFixture.Image, "apfs-container:" + WindowsSurfaceFixture.Hex,
                WindowsSurfaceFixture.VolumeHex, "101", "90", "0", "2097152"), scope);
            return Task.FromResult(summary);
        }, default);
        Assert.Equal(1, calls); Assert.Same(summary, result); Assert.Same(summary, workflow.SpaceSummary);
        var row = Assert.Single(result.Snapshots);
        Assert.Equal(4096UL, row.SharedWithLiveBytes); Assert.Equal(0UL, row.PotentialReclaimUpperBoundBytes);
        Assert.Contains("exact deletion savings are unknown", result.Details);
    }

    [Fact]
    public async Task UnknownRemainsUnknownWithoutInventedZeroAmounts()
    {
        var status = Status(); var workflow = Workflow(() => status);
        var unknown = new SnapshotSpaceSummary(false, "Snapshot space is unknown. Retained ownership is incomplete.", []);
        var result = await workflow.ReadSpaceAsync((_, current, _) => { current(); return Task.FromResult(unknown); }, default);
        Assert.Same(unknown, result); Assert.False(workflow.SpaceSummary!.Complete);
        Assert.Empty(workflow.SpaceSummary.Snapshots); Assert.Equal(unknown.Summary, workflow.SpaceSummary.Details);
        Assert.DoesNotContain("0 bytes", workflow.SpaceSummary.Details);
    }

    [Theory]
    [InlineData("checkpoint")] [InlineData("window")] [InlineData("recovery")]
    [InlineData("mounted")] [InlineData("disconnected")]
    public async Task DriftDuringObservationCannotPublishAmounts(string kind)
    {
        var status = Status(); var workflow = Workflow(() => status);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.ReadSpaceAsync((_, _, _) => {
            status = Changed(status, kind);
            // The workflow must also enforce postconditions when a dependency omits its callback.
            return Task.FromResult(Complete());
        }, default));
        Assert.Null(workflow.SpaceSummary);
    }

    [Theory]
    [InlineData("checkpoint")] [InlineData("window")] [InlineData("recovery")]
    [InlineData("mounted")] [InlineData("disconnected")]
    public async Task CachedAmountsAreRevokedByCurrentBindingDrift(string kind)
    {
        var status = Status(); var workflow = Workflow(() => status);
        await workflow.ReadSpaceAsync((_, _, _) => Task.FromResult(Complete()), default);
        Assert.NotNull(workflow.SpaceSummary);
        status = Changed(status, kind);
        try { workflow.CurrentRow(); } catch (InvalidOperationException) { }
        Assert.Null(workflow.SpaceSummary);
    }

    [Theory]
    [InlineData("physical")] [InlineData("encrypted")] [InlineData("mounted")]
    public async Task UnsupportedCurrentSourceDoesNotReachClient(string kind)
    {
        var status = Status();
        if (kind == "mounted") status = Changed(status, kind);
        else if (kind == "encrypted")
        {
            var d = status.ConnectedInventory![0];
            status = status with { ConnectedInventory = [d with { Volumes = [d.Volumes[0] with { IsEncrypted = true }] }] };
        }
        else
        {
            var json = System.Text.Json.JsonSerializer.Serialize(status).Replace(
                System.Text.Json.JsonSerializer.Serialize(WindowsSurfaceFixture.Image),
                System.Text.Json.JsonSerializer.Serialize(@"\\.\PhysicalDrive9"), StringComparison.Ordinal);
            status = System.Text.Json.JsonSerializer.Deserialize<StatusChangedPayload>(json)!;
        }
        var workflow = Workflow(() => status); var calls = 0;
        Assert.False(workflow.CanReadSpace);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.ReadSpaceAsync((_, _, _) => {
            calls++; return Task.FromResult(Complete());
        }, default));
        Assert.Equal(0, calls); Assert.Null(workflow.SpaceSummary);
    }

    [Fact]
    public async Task FailedRefreshClearsPreviouslyPublishedAmountsAndReleasesBusyState()
    {
        var status = Status(); var workflow = Workflow(() => status);
        await workflow.ReadSpaceAsync((_, _, _) => Task.FromResult(Complete()), default);
        await Assert.ThrowsAsync<IOException>(() => workflow.ReadSpaceAsync((_, _, _) => throw new IOException("CLI unavailable"), default));
        Assert.Null(workflow.SpaceSummary);
        await workflow.ReadSpaceAsync((_, _, _) => Task.FromResult(Complete()), default);
        Assert.NotNull(workflow.SpaceSummary);
    }

    [Fact]
    public async Task DisconnectRevokesCachedAmountsAndPreventsDispatch()
    {
        var status = Status(); var disconnected = false;
        var workflow = Workflow(() => disconnected ? throw new IOException("Service disconnected") : status);
        await workflow.ReadSpaceAsync((_, _, _) => Task.FromResult(Complete()), default);
        disconnected = true; Assert.False(workflow.CanReadSpace); Assert.Null(workflow.SpaceSummary);
        var calls = 0;
        await Assert.ThrowsAsync<IOException>(() => workflow.ReadSpaceAsync((_, _, _) => { calls++; return Task.FromResult(Complete()); }, default));
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task CancellationPreventsPublicationEvenIfDependencyReturnsASummary(bool beforeStart)
    {
        var status = Status(); var workflow = Workflow(() => status); using var stop = new CancellationTokenSource(); var calls = 0;
        if (beforeStart) stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => workflow.ReadSpaceAsync((_, _, token) => {
            calls++; Assert.Equal(stop.Token, token); stop.Cancel(); return Task.FromResult(Complete());
        }, stop.Token));
        Assert.Equal(beforeStart ? 0 : 1, calls); Assert.Null(workflow.SpaceSummary);
    }

    [Fact]
    public async Task ActiveSpaceReadClearsOldValuesAndBlocksCompetingCommands()
    {
        var status = Status(); var workflow = Workflow(() => status);
        await workflow.ReadSpaceAsync((_, _, _) => Task.FromResult(Complete()), default);
        var pending = new TaskCompletionSource<SnapshotSpaceSummary>(TaskCreationOptions.RunContinuationsAsynchronously);
        var run = workflow.ReadSpaceAsync((_, _, _) => pending.Task, default);
        Assert.Null(workflow.SpaceSummary);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.ReadSpaceAsync((_, _, _) => Task.FromResult(Complete()), default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotList));
        pending.SetResult(Complete()); await run;
        Assert.NotNull(workflow.SpaceSummary);
    }

    [Fact]
    public async Task UnavailableSpaceActionDoesNotInvalidateMountedSnapshotInventory()
    {
        var status = WindowsSurfaceFixture.Status(true);
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r => Task.FromResult(new OperationResultPayload(
            r.OperationId, r.Command, r.Target, ApfsOperationFingerprint.Compute(r), ApfsOperationStates.Succeeded, "ok", true,
            DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, FinalStatus: "snapshot-inventory", MountProof: "present",
            OwnershipProof: "proven", DurabilityProof: "not-applicable", ExpiresAtUtc: r.ExpiresAtUtc,
            SnapshotInventory: new LiveSnapshotInventory(WindowsSurfaceFixture.Hex, WindowsSurfaceFixture.VolumeHex,
                "101", "90", "0", "100000", [new("21", "0", "backup", "249", "17", "230", "8293", "8", "250")]).ToJson())));
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        var inventory = workflow.Inventory; Assert.NotNull(inventory);
        Assert.False(workflow.CanReadSpace);
        Assert.Same(inventory, workflow.Inventory);
    }

    private static StatusChangedPayload Changed(StatusChangedPayload status, string kind)
    {
        var d = status.ConnectedInventory![0];
        return kind switch
        {
            "checkpoint" => status with { ConnectedInventory = [d with { Topology = d.Topology! with { Snapshot = d.Topology.Snapshot with {
                Containers = [d.Topology.Snapshot.Containers[0] with { CheckpointXid = "91" }] } } }] },
            "window" => status with { ConnectedInventory = [d with { Topology = d.Topology! with { Snapshot = d.Topology.Snapshot with {
                Stores = [d.Topology.Snapshot.Stores[0] with { SizeBytes = 1048576 }] } } }] },
            "recovery" => status with { ConnectedInventory = [d with { Volumes = [d.Volumes[0] with { RecoveryIdentity = "new-owner" }] }] },
            "mounted" => status with { MountedVolumes = WindowsSurfaceFixture.Status(true).MountedVolumes },
            _ => status with { ConnectedInventory = [], MountedVolumes = [] }
        };
    }
}
