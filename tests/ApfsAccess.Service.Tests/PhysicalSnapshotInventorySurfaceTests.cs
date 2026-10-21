using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    private const string InventoryPhysicalSource = @"\\.\PhysicalDrive2";
    private static ScenarioBackend PhysicalInventoryBackend() => new()
    {
        ImageDeviceId = InventoryPhysicalSource, ImageVolumeId = InventoryPhysicalSource + "|Main", ImageTopologyXid = "90"
    };
    private static LiveVolumeVerificationScope PhysicalInventoryScope(VolumeInfo volume) => new("raw:gpt-held-window",
        "retained-admitted-raw", volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!,
        volume.CatalogVolumeObjectId!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "91", "8192", "134217728");
    private static MountedVolumeState PhysicalInventoryMount(VolumeInfo volume, LiveVolumeVerificationScope? scope) =>
        HealthyMount() with { DeviceId = InventoryPhysicalSource, VolumeId = volume.VolumeId,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId,
            RecoveryIdentity = volume.RecoveryIdentity, SnapshotInventorySupported = true,
            SnapshotMutationSupported = false, SnapshotRecoverySupported = false,
            VolumeVerificationSupported = scope is not null, VolumeVerificationScope = scope };

    [Fact]
    public async Task PhysicalSnapshotListUsesRetainedScopeAndGateWithNoObserverOrMutationAdmission()
    {
        var backend = PhysicalInventoryBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var device = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == InventoryPhysicalSource);
        var volume = device.Volumes[0]; var scope = PhysicalInventoryScope(volume);
        Assert.False(VerifyScopeDerivation.TryDerive(device, volume).Ok);
        backend.SetMounted(PhysicalInventoryMount(volume, scope));
        backend.SnapshotResults.Enqueue(new(true, "SnapshotInventory", new(scope.ContainerUuid, scope.VolumeUuid,
            scope.VolumeOid, "92", scope.StoreOffsetBytes, scope.StoreSizeBytes, [])));
        backend.SnapshotGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var target = SelectedControlTarget.Create(device, volume);
        var request = CreateRequest(ApfsControlCommands.SnapshotList, target);
        var probes = backend.SnapshotInventoryProbeCalls;
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: (_, _) => throw new InvalidOperationException("No offline raw reader."));
        var reading = executor.ExecuteAsync(request, default);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (backend.SnapshotCalls.Count == 0) await Task.Delay(5, deadline.Token);
        var competitor = worker.WithMountOperationsPausedAsync(_ => Task.FromResult(0), deadline.Token);
        await Task.Delay(30, deadline.Token); Assert.False(competitor.IsCompleted);
        backend.SnapshotGate.SetResult();
        var result = await reading; await competitor;
        Assert.True(result.Success, result.Diagnostic); AssertWireResult(result);
        var call = Assert.Single(backend.SnapshotCalls);
        Assert.Equal(SnapshotControlAction.List, call.Action); Assert.Equal(scope.RequestLines, call.Extras);
        Assert.Equal("8192", result.SnapshotInventory!.Value.GetProperty("storeOffsetBytes").GetString());
        Assert.Equal("92", result.SnapshotInventory!.Value.GetProperty("checkpointXid").GetString());
        Assert.Equal(probes, backend.SnapshotInventoryProbeCalls); Assert.Equal(0, backend.UnmountCalls);
        var create = await executor.ExecuteAsync(CreateRequest(ApfsControlCommands.SnapshotCreate, target) with { SnapshotName = "blocked" }, default);
        var recover = await executor.ExecuteAsync(CreateRequest(ApfsControlCommands.SnapshotRecover, target), default);
        Assert.False(create.Success); Assert.False(recover.Success); Assert.Single(backend.SnapshotCalls);
    }

    [Theory]
    [InlineData("missing-scope")] [InlineData("scope-uuid")] [InlineData("scope-kind")]
    [InlineData("capability")] [InlineData("owner")] [InlineData("no-owner")]
    [InlineData("response-base")] [InlineData("response-size")] [InlineData("response-uuid")]
    [InlineData("response-overflow")] [InlineData("refusal")]
    public async Task PhysicalSnapshotListRefusesWithoutOfflineFallback(string failure)
    {
        var backend = PhysicalInventoryBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var device = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == InventoryPhysicalSource);
        var volume = device.Volumes[0]; var scope = PhysicalInventoryScope(volume);
        var retained = failure switch { "scope-uuid" => scope with { VolumeUuid = new string('f', 32) },
            "scope-kind" => scope with { SourceKind = "retained-image" }, "missing-scope" => null, _ => scope };
        if (failure != "no-owner") backend.SetMounted(PhysicalInventoryMount(volume, retained) with
        {
            SnapshotInventorySupported = failure != "capability", RecoveryIdentity = failure == "owner" ? "replacement" : volume.RecoveryIdentity
        });
        var response = new LiveSnapshotInventory(scope.ContainerUuid, scope.VolumeUuid, scope.VolumeOid, "92", "8192", "134217728", []);
        response = failure switch { "response-base" => response with { StoreOffsetBytes = "0" },
            "response-size" => response with { StoreSizeBytes = "134217729" },
            "response-uuid" => response with { VolumeUuid = new string('f', 32) },
            "response-overflow" => response with { StoreOffsetBytes = ulong.MaxValue.ToString() }, _ => response };
        backend.SnapshotResults.Enqueue(failure == "refusal" ? new(false, "SnapshotPhysicalInventoryOwnerRequired") : new(true, "SnapshotInventory", response));
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: (_, _) => throw new InvalidOperationException("No offline fallback."));
        var result = await executor.ExecuteAsync(CreateRequest(ApfsControlCommands.SnapshotList, SelectedControlTarget.Create(device, volume)), default);
        Assert.False(result.Success); Assert.Null(result.SnapshotInventory); Assert.Equal(0, backend.UnmountCalls);
        Assert.Equal(failure.StartsWith("response-", StringComparison.Ordinal) || failure == "refusal" ? 1 : 0, backend.SnapshotCalls.Count);
        AssertWireResult(result);
    }
}
