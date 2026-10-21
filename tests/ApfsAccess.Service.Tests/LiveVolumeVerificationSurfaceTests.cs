using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LiveVolumeVerifyKeepsOwnerAndUsesNativeScopeWithoutObserver(bool damaged)
    {
        var backend = ClosureBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var device = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = device.Volumes[0];
        var scope = LiveVerificationFixture.Scope(volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!,
            volume.CatalogVolumeObjectId!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        backend.SetMounted(HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId,
            VolumeVerificationSupported = true, VolumeVerificationScope = scope });
        backend.LiveVerificationResults.Enqueue(new(true, "VolumeVerificationReport",
            LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(LiveVerificationFixture.Report(scope, damaged)))));
        backend.LiveVerificationGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var probes = backend.SnapshotInventoryProbeCalls; var mounts = backend.MountCalls; var unmounts = backend.UnmountCalls;
        var request = ClosureRequest(ApfsControlCommands.VolumeVerify) with { Target = SelectedControlTarget.Create(device, volume) };
        var operation = new AgentControlCommandExecutor(worker).ExecuteAsync(request, default);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (backend.LiveVerificationCalls.Count == 0) await Task.Delay(5, deadline.Token);
        var contender = worker.WithMountOperationsPausedAsync(_ => Task.FromResult(0), deadline.Token);
        await Task.Delay(30, deadline.Token); Assert.False(contender.IsCompleted);
        backend.LiveVerificationGate.SetResult();
        var result = await operation; await contender;
        Assert.Equal(!damaged, result.Success); Assert.Equal("present", result.MountProof);
        Assert.NotNull(result.VolumeVerificationReport); Assert.Equal(scope, Assert.Single(backend.LiveVerificationCalls));
        Assert.Equal(probes, backend.SnapshotInventoryProbeCalls);
        Assert.Equal(mounts, backend.MountCalls); Assert.Equal(unmounts, backend.UnmountCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LiveVolumeVerifyRefusesMissingCapabilityOrSourceDriftWithoutOfflineFallback(bool drift)
    {
        var backend = ClosureBackend(); using var worker = CreateWorker(backend);
        await worker.RefreshAsync(false, default);
        var device = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage); var volume = device.Volumes[0];
        var scope = LiveVerificationFixture.Scope(volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!,
            volume.CatalogVolumeObjectId!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        backend.SetMounted(HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeId = volume.CatalogVolumeId, CatalogVolumeObjectId = volume.CatalogVolumeObjectId,
            VolumeVerificationSupported = drift, VolumeVerificationScope = drift ? scope : null });
        var other = scope with { SourceIdentity = "image:replacement-owner" };
        backend.LiveVerificationResults.Enqueue(new(true, "VolumeVerificationReport",
            LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(LiveVerificationFixture.Report(other)))));
        var probes = backend.SnapshotInventoryProbeCalls; var unmounts = backend.UnmountCalls;
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(ClosureRequest(ApfsControlCommands.VolumeVerify) with
            { Target = SelectedControlTarget.Create(device, volume) }, default);
        Assert.False(result.Success); Assert.Null(result.VolumeVerificationReport);
        Assert.Equal(drift ? 1 : 0, backend.LiveVerificationCalls.Count); Assert.Equal(probes, backend.SnapshotInventoryProbeCalls);
        Assert.Equal(unmounts, backend.UnmountCalls); AssertWireResult(result);
    }
}
