using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [SnapshotRecoveryStatusFact]
    public async Task LiveSnapshotRecoverFromActuallyDegradedNativeAcceptedStatusRefusesBeforeDispatch()
    {
        var backend = new SnapshotRecoveryEvidenceBackend(degraded: true); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var inventory = Assert.Single(await worker.GetInventoryAsync(default));
        var target = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.SnapshotRecover, target), default);
        Assert.False(result.Success); Assert.Empty(backend.Calls); AssertWireResult(result);
    }

    [SnapshotRecoveryStatusFact]
    public async Task LiveSnapshotRecoverFromActualNativeAcceptedStatusDispatchesThroughExactServiceTarget()
    {
        var backend = new SnapshotRecoveryEvidenceBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var inventory = Assert.Single(await worker.GetInventoryAsync(default));
        var target = SelectedControlTarget.Create(inventory, inventory.Volumes[0]);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.SnapshotRecover, target), default);
        Assert.True(result.Success, result.Diagnostic); Assert.Equal("snapshot-recovered", result.FinalStatus); AssertWireResult(result);
        Assert.Equal(SnapshotControlAction.Recover, Assert.Single(backend.Calls));
    }

    private sealed class SnapshotRecoveryEvidenceBackend : IApfsBackend, ISnapshotControlBackend
    {
        private readonly DeviceInventory _inventory;
        private readonly MountedVolumeState _mount;
        public List<SnapshotControlAction> Calls { get; } = [];
        public SnapshotRecoveryEvidenceBackend(bool degraded = false)
        {
            var fixture = SnapshotRecoveryFixture.Load(degraded); var native = ContainerStatusReader.Parse(fixture.StatusJson);
            var child = native.Volumes.Single(v => v.ObjectId == 101);
            _inventory = fixture.Inventory(native.ContainerUuid, child.ObjectId, child.RecoveryIdentity);
            var volume = _inventory.Volumes[0];
            _mount = new(volume.VolumeId, "R:\\", child.Writable ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly, DeviceId: fixture.Source,
                RecoveryIdentity: child.RecoveryIdentity, MountReady: child.Ready, HostProcessId: native.OwnerPid,
                RecoveryActive: child.RecoveryActive, RecoveryReason: child.RecoveryReason, CatalogVolumeId: volume.CatalogVolumeId,
                CatalogContainerUuid: native.ContainerUuid, CatalogVolumeObjectId: child.ObjectId, CatalogVolumeUuid: fixture.VolumeUuid,
                SnapshotRecoverySupported: child.SnapshotRecoverySupported, SnapshotInventorySupported: child.SnapshotInventorySupported,
                SnapshotMutationSupported: child.SnapshotMutationSupported);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInfo>>([_inventory.Device]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => Task.FromResult(_inventory.Volumes);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInventory>>([_inventory]);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<MountedVolumeState>>([_mount]);
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => throw new InvalidOperationException("No mount in this contract test.");
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => throw new InvalidOperationException("No unmount in this contract test.");
        public Task<SnapshotControlResult> SendSnapshotControlAsync(string container, ulong oid, SnapshotControlAction action,
            IReadOnlyList<string>? extras, CancellationToken token)
        {
            Assert.Equal(_mount.CatalogContainerUuid, container); Assert.Equal(_mount.CatalogVolumeObjectId, oid);
            Assert.Null(extras); Calls.Add(action); return Task.FromResult(new SnapshotControlResult(true, "SnapshotRecovered"));
        }
    }

    [Fact]
    public async Task LiveSnapshotRecoverUsesExplicitRecoveryCapabilityWithoutCleanMutationSupport()
    {
        var backend = ClosureBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0];
        backend.SetMounted(HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId,
            RecoveryIdentity = volume.RecoveryIdentity, RecoveryActive = true, RecoveryReason = "AcceptedSnapshotDebt",
            AccessMode = MountAccessMode.ReadOnly, SnapshotInventorySupported = false,
            SnapshotMutationSupported = false, SnapshotRecoverySupported = true });
        backend.SnapshotResults.Enqueue(new(true, "SnapshotRecovered"));
        var executor = CreateExecutor(worker);
        var target = SelectedControlTarget.Create(inventory, volume);
        var result = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotRecover) with { Target = target }, default);
        Assert.True(result.Success, result.Diagnostic); Assert.Equal("snapshot-recovered", result.FinalStatus);
        AssertWireResult(result);
        Assert.Equal(SnapshotControlAction.Recover, Assert.Single(backend.SnapshotCalls).Action);
        var create = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotCreate) with { Target = target, SnapshotName = "Blocked" }, default);
        var delete = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotDelete) with { Target = target, SnapshotIdentity = DeleteIdentity }, default);
        Assert.False(create.Success); Assert.False(delete.Success); Assert.Single(backend.SnapshotCalls);
    }

    [Theory]
    [InlineData("capability")]
    [InlineData("source")]
    [InlineData("recovery-identity")]
    [InlineData("observation")]
    public async Task LiveSnapshotRecoverRefusesMissingCapabilityOrStaleExactTarget(string change)
    {
        var backend = ClosureBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0];
        backend.SetMounted(HealthyMount() with { DeviceId = change == "source" ? @"D:\other.apfs" : ClosureImage,
            VolumeId = ClosureVolume, RecoveryIdentity = change == "recovery-identity" ? "other" : volume.RecoveryIdentity,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId,
            SnapshotRecoverySupported = change != "capability" });
        var target = SelectedControlTarget.Create(inventory, volume);
        if (change == "observation") target = target with { ObservationContract = target.ObservationContract + "-stale" };
        var result = await CreateExecutor(worker).ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotRecover) with { Target = target }, default);
        Assert.False(result.Success); Assert.Empty(backend.SnapshotCalls); AssertWireResult(result);
    }

    [Fact]
    public async Task LiveSnapshotListUsesRetainedOwnerAndHoldsMountGateThroughTypedResponse()
    {
        var backend = ClosureBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0]; var scope = VerifyScopeDerivation.TryDerive(inventory, volume).Scope!;
        backend.SetMounted(HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId });
        var live = new LiveSnapshotInventory(scope.ContainerId[15..], scope.VolumeUuid, scope.VolumeObjectId, "91",
            scope.StoreOffsetBytes, scope.StoreSizeBytes, [new("21", "0", "backup", "249", "17", "230", "8293", "8", "250")]);
        backend.SnapshotResults.Enqueue(new(true, "SnapshotInventory", live));
        backend.SnapshotGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: (_, _) => throw new InvalidOperationException("A live list must never open an offline reader."));
        var request = ClosureRequest(ApfsControlCommands.SnapshotList) with { Target = SelectedControlTarget.Create(inventory, volume) };
        var priorProbes = backend.SnapshotInventoryProbeCalls;
        var priorMounts = backend.MountCalls; var priorUnmounts = backend.UnmountCalls;
        var reading = executor.ExecuteAsync(request, default);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (backend.SnapshotCalls.Count == 0) await Task.Delay(5, timeout.Token);
        var refresh = worker.WithMountOperationsPausedAsync(_ => Task.FromResult(0), timeout.Token);
        await Task.Delay(50, timeout.Token); Assert.False(refresh.IsCompleted);
        Assert.Equal(priorProbes, backend.SnapshotInventoryProbeCalls);
        Assert.Equal(priorUnmounts, backend.UnmountCalls); Assert.Equal(priorMounts, backend.MountCalls);
        backend.SnapshotGate.SetResult();
        var result = await reading; await refresh;
        Assert.True(result.Success, result.Diagnostic); Assert.Equal("present", result.MountProof);
        Assert.Equal(SnapshotControlAction.List, Assert.Single(backend.SnapshotCalls).Action);
        Assert.Equal("91", result.SnapshotInventory!.Value.GetProperty("checkpointXid").GetString());
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, 2)).IsValid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LiveSnapshotListRefusesMissingCapabilityOrDifferentSourceWithoutOfflineFallback(bool drift)
    {
        var backend = ClosureBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0]; var scope = VerifyScopeDerivation.TryDerive(inventory, volume).Scope!;
        backend.SetMounted(HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId,
            SnapshotInventorySupported = drift });
        if (drift) backend.SnapshotResults.Enqueue(new(true, "SnapshotInventory", new(scope.ContainerId[15..], new string('d', 32),
            scope.VolumeObjectId, "91", scope.StoreOffsetBytes, scope.StoreSizeBytes, [])));
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: (_, _) => throw new InvalidOperationException("No offline fallback."));
        var result = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotList) with
            { Target = SelectedControlTarget.Create(inventory, volume) }, default);
        Assert.False(result.Success); Assert.Null(result.SnapshotInventory); Assert.Equal(0, backend.UnmountCalls);
        Assert.Equal(drift ? 1 : 0, backend.SnapshotCalls.Count);
    }
}
