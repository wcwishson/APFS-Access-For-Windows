using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    private const string ClosureImage = @"D:\closure-image.apfs";
    private const string ClosureVolume = ClosureImage + "|Main";
    private static ScenarioBackend ClosureBackend() => new()
        { ImageDeviceId = ClosureImage, ImageVolumeId = ClosureVolume, ImageTopologyXid = "90" };
    private static ControlOperationRequestPayload ClosureRequest(string command) => CreateRequest(command, new(ClosureImage, ClosureVolume));
    private static MountedVolumeState ClosureMount() => DegradedMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume };

    [Fact]
    public async Task Fix_OfflineVerifierUsesThePostDrainCheckpoint()
    {
        ScenarioBackend? inner = null;
        inner = new() { ImageDeviceId = ClosureImage, ImageVolumeId = ClosureVolume, ImageTopologyXid = "90",
            AfterUnmountAction = () => inner!.ImageTopologyXid = "91" };
        var original = ClosureMount() with { HostProcessId = 6201,
            HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime };
        inner.SetMounted(original);
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new(true, "Complete", 0, 0, null));
        var liveBackend = new ImageFixBackend(inner, backend, advanceCheckpoints: false);
        using var worker = CreateWorker(liveBackend, TestJournalRoot);
        var volume = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage).Volumes.Single();
        liveBackend.FinalOwner = ImageFixProofOwner(volume, "91");
        var result = await CreateExecutor(worker).ExecuteAsync(ClosureRequest(ApfsControlCommands.Fix), default);
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("91", Assert.Single(backend.VerifyCalls).CheckpointXid);
        Assert.Equal(1, inner.UnmountCalls);
        Assert.Equal(1, inner.MountCalls);
        var live = Assert.Single(liveBackend.LiveCalls);
        Assert.Equal("retained-image", live.SourceKind);
        Assert.Equal("91", live.CheckpointXid);
        Assert.Equal(liveBackend.FinalOwner.VolumeVerificationScope, live);
        Assert.True(Assert.Single(liveBackend.Reports).Complete);
        Assert.True(liveBackend.FinalOwner.HostProcessCreationTimeFileTimeUtc > 0);
        Assert.NotEqual(original.HostProcessId, liveBackend.FinalOwner.HostProcessId);
        Assert.NotEqual(original.HostProcessCreationTimeFileTimeUtc, liveBackend.FinalOwner.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(new[] { "unmount", "offline", "mount", "live" }, liveBackend.Events);
        AssertWireResult(result);

        liveBackend.FinalOwner = liveBackend.FinalOwner with
            { VolumeVerificationSupported = false, VolumeVerificationScope = null };
        backend.Enqueue(new(true, "Complete", 0, 0, null));
        var missingProof = await CreateExecutor(worker).ExecuteAsync(ClosureRequest(ApfsControlCommands.Fix), default);
        Assert.False(missingProof.Success);
        Assert.Equal(ApfsOperationCodes.BlockedRecovery, missingProof.Code);
        Assert.Equal("verification-not-complete", missingProof.FinalStatus);
        Assert.Equal("present", missingProof.MountProof);
        Assert.Equal(ApfsControlModes.ReadWrite, missingProof.EffectiveMode);
        Assert.Equal(2, backend.VerifyCalls.Count);
        Assert.All(backend.VerifyCalls, call => Assert.Equal("91", call.CheckpointXid));
        Assert.Single(liveBackend.LiveCalls);
        AssertWireResult(missingProof);
    }

    [Fact]
    public async Task Fix_PostDrainIdentityReplacementCannotReachVerifierOrRemount()
    {
        ScenarioBackend? inner = null;
        inner = new() { ImageDeviceId = ClosureImage, ImageVolumeId = ClosureVolume, ImageTopologyXid = "90",
            AfterUnmountAction = () => inner!.CurrentRecoveryIdentity = "replacement-image" };
        inner.SetMounted(ClosureMount());
        var backend = new VerifyBackend(inner);
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(ClosureRequest(ApfsControlCommands.Fix), default);
        Assert.False(result.Success); Assert.Contains("identity or topology changed", result.Diagnostic);
        Assert.Empty(backend.VerifyCalls); Assert.Equal(1, inner.UnmountCalls); Assert.Equal(0, inner.MountCalls);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Fix_SiblingSourceOrContainerOwnerBlocksOfflineTools(bool sameContainerOtherSource)
    {
        var inner = ClosureBackend();
        inner.SetMounted(ClosureMount());
        inner.SetMounted(HealthyMount() with { DeviceId = sameContainerOtherSource ? @"D:\other-image.apfs" : ClosureImage,
            VolumeId = "sibling", MountPoint = "Y:\\", CatalogContainerUuid = new string('a', 32) });
        var backend = new VerifyBackend(inner);
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(ClosureRequest(ApfsControlCommands.Fix), default);
        Assert.False(result.Success);
        Assert.Contains("quiesce-required", result.Diagnostic);
        Assert.Empty(backend.VerifyCalls);
        Assert.Equal(0, inner.UnmountCalls);
        Assert.Equal(0, inner.MountCalls);
    }

    [Fact]
    public async Task Fix_UnsafeTeardownDebtPreventsLaterOfflineVerification()
    {
        var inner = ClosureBackend();
        inner.SetMounted(ClosureMount());
        inner.UnmountResponses.Enqueue(new(false, "", "owner retained", true, false, false));
        var backend = new VerifyBackend(inner);
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        var first = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.Fix), default);
        var again = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.Fix), default);
        Assert.False(first.Success); Assert.False(again.Success);
        Assert.Contains("quiesce-unproven", again.Diagnostic);
        Assert.Empty(backend.VerifyCalls);
        Assert.Equal(0, inner.MountCalls);
    }

    [Fact]
    public async Task VolumeVerify_OfflineOnlyAndWireProofRoundTrips()
    {
        var inner = ClosureBackend();
        var backend = new VerifyBackend(inner);
        backend.Enqueue(new(true, "Complete", 0, 0, null));
        using var worker = CreateWorker(backend);
        var executor = CreateExecutor(worker);
        inner.SetMounted(ClosureMount());
        var refused = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.VolumeVerify), default);
        Assert.False(refused.Success); Assert.Empty(backend.VerifyCalls); Assert.Equal(0, inner.UnmountCalls);
        await inner.UnmountAsync(ClosureMount().MountPoint, default);
        var complete = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.VolumeVerify), default);
        Assert.True(complete.Success, complete.Diagnostic);
        AssertWireResult(complete);
    }

    [Fact]
    public async Task SnapshotList_HoldsOfflineGateThroughoutReaderAndBindsObservation()
    {
        var backend = ClosureBackend();
        using var worker = CreateWorker(backend);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: async (scope, ct) =>
        { started.SetResult(); await release.Task.WaitAsync(ct); return SnapshotInventory(scope); });
        var reading = executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotList), default);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var contenderEntered = false;
        var contender = worker.WithMountOperationsPausedAsync(ct => { contenderEntered = true; return Task.FromResult(0); }, default);
        Assert.False(contenderEntered);
        release.SetResult();
        var result = await reading;
        await contender;
        Assert.True(contenderEntered);
        Assert.True(result.Success, result.Diagnostic);
        Assert.NotNull(result.SnapshotInventory);
        AssertWireResult(result);
        Assert.Equal(0, backend.UnmountCalls); Assert.Equal(0, backend.MountCalls);
    }

    [Fact]
    public async Task SnapshotList_InventorySurvivesDurableResultQueryAndReplay()
    {
        var root = Path.Combine(Path.GetTempPath(), "snapshot-result-" + Guid.NewGuid().ToString("N"));
        using var worker = CreateWorker(ClosureBackend());
        var calls = 0;
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: (scope, ct) =>
        { calls++; return Task.FromResult(SnapshotInventory(scope)); });
        var service = new AgentControlOperationService(executor.ExecuteAsync, root);
        AgentControlOperationService? restarted = null;
        try
        {
            var request = ClosureRequest(ApfsControlCommands.SnapshotList);
            var result = await service.ExecuteOrReplayAsync(request);
            Assert.True(result.Success, result.Diagnostic); Assert.NotNull(result.SnapshotInventory);
            AssertWireResult(result);
            await service.StopAsync(default);
            restarted = new AgentControlOperationService((_, _) => throw new InvalidOperationException("Replay must read evidence."), root);
            var queried = restarted.Query(request.OperationId);
            Assert.NotNull(queried); Assert.True(queried.Success, queried.Diagnostic);
            Assert.Equal(result.SnapshotInventory.Value.GetRawText(), queried.SnapshotInventory!.Value.GetRawText());
            var replay = await restarted.ExecuteOrReplayAsync(request);
            Assert.True(replay.Success, replay.Diagnostic); AssertWireResult(replay); Assert.Equal(1, calls);
        }
        finally
        {
            await service.StopAsync(default);
            if (restarted is not null) await restarted.StopAsync(default);
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData("uuid")] [InlineData("checkpoint")] [InlineData("store")]
    public async Task SnapshotList_RefusesDriftedReaderScope(string change)
    {
        var backend = ClosureBackend();
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker, snapshotReader: (scope, ct) => Task.FromResult(
            SnapshotInventory(change switch { "uuid" => scope with { VolumeUuid = new string('d', 32) },
                "checkpoint" => scope with { CheckpointXid = "91" }, _ => scope with { StoreSizeBytes = "4096" } })));
        var result = await executor.ExecuteAsync(ClosureRequest(ApfsControlCommands.SnapshotList), default);
        Assert.False(result.Success); Assert.Null(result.SnapshotInventory); AssertWireResult(result);
    }

    [Fact]
    public async Task ManagementApply_WrongSourceAndOperationLeaveTokenLive()
    {
        var inner = new ScenarioBackend { TopologyCheckpointXid = "90" };
        var backend = new KeeperBackend(inner);
        backend.Enqueue(new(true, 91, ManagementKeeperCodes.Committed, "ok"));
        using var worker = CreateWorker(backend);
        var executor = new AgentControlCommandExecutor(worker, managementJournalRoot: TestJournalRoot);
        var plan = await executor.ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementPlan), default);
        var wrongSource = await executor.ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementApply,
            token: plan.ManagementToken, name: "New", imagePath: @"D:\clone.apfs"), default);
        Assert.False(wrongSource.Success);
        var wrongOperation = await executor.ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementApply,
            ApfsManagementOperations.SetQuotaReserve, token: plan.ManagementToken, quotaBytes: "1", reserveBytes: "0", imagePath: TestImagePath), default);
        Assert.False(wrongOperation.Success); Assert.Empty(backend.KeeperCalls); Assert.Empty(backend.QuotaCalls);
        var correct = await executor.ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementApply,
            token: plan.ManagementToken, name: "New", imagePath: TestImagePath), default);
        Assert.True(correct.Success, correct.Diagnostic); Assert.Single(backend.KeeperCalls);
    }

    [Fact]
    public async Task ManagementPlan_OnlySiblingMountedStillRequiresQuiesce()
    {
        var backend = new ScenarioBackend { TopologyCheckpointXid = "90" };
        backend.SetMounted(HealthyMount() with { VolumeId = "device-1|Archive", MountPoint = "Y:\\", CatalogVolumeObjectId = 102 });
        using var worker = CreateWorker(backend);
        var result = await CreateExecutor(worker).ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementPlan), default);
        Assert.False(result.Success); Assert.Equal("quiesce-required", result.FinalStatus);
        Assert.Null(result.ManagementToken); Assert.Equal(0, backend.UnmountCalls);
    }

    private static JsonElement SnapshotInventory(VerifyScope scope) => JsonSerializer.SerializeToElement(new
    {
        format = "apfs-access-snapshot-inventory", version = 1, readOnly = true,
        source = new { path = scope.ImagePath }, containerUuid = scope.ContainerId[15..], volumeUuid = scope.VolumeUuid,
        volumeOid = scope.VolumeObjectId, checkpointXid = scope.CheckpointXid,
        storeOffsetBytes = scope.StoreOffsetBytes, storeSizeBytes = scope.StoreSizeBytes, snapshots = Array.Empty<object>()
    });

    [Theory]
    [InlineData(ApfsManagementOperations.RenameVolume)]
    [InlineData(ApfsManagementOperations.SetQuotaReserve)]
    public async Task Management_ConfiguredKeeperRequiresVerificationWithoutBurningRefusedApply(string operation)
    {
        var backend = new KeeperBackend(ClosureBackend());
        backend.VerifyResults.Enqueue(new(true, "Complete", 0, 0, null));
        backend.VerifyResults.Enqueue(new(true, "Incomplete", 2, 1, "damaged metadata"));
        backend.VerifyResults.Enqueue(new(true, "Complete", 0, 0, null));
        if (operation == ApfsManagementOperations.RenameVolume)
            backend.Enqueue(new(true, 91, ManagementKeeperCodes.Committed, "kept"));
        else backend.EnqueueQuota(new(true, 91, ManagementKeeperCodes.Committed, "kept"));
        using var worker = CreateWorker(backend, TestJournalRoot);
        var executor = new AgentControlCommandExecutor(worker);
        var planRequest = ClosureRequest(ApfsControlCommands.ManagementPlan) with { ManagementOperation = operation };
        var plan = await executor.ExecuteAsync(planRequest, default);
        Assert.True(plan.Success, plan.Diagnostic);
        var applyRequest = ClosureRequest(ApfsControlCommands.ManagementApply) with
        {
            ManagementOperation = operation, ManagementToken = plan.ManagementToken, ManagementImagePath = ClosureImage,
            ManagementName = operation == ApfsManagementOperations.RenameVolume ? "New name" : null,
            ManagementQuotaBytes = operation == ApfsManagementOperations.SetQuotaReserve ? "65536" : null,
            ManagementReserveBytes = operation == ApfsManagementOperations.SetQuotaReserve ? "20480" : null,
        };
        var refused = await executor.ExecuteAsync(applyRequest, default);
        Assert.False(refused.Success); Assert.Equal("verification-not-complete", refused.FinalStatus);
        Assert.Empty(backend.KeeperCalls); Assert.Empty(backend.QuotaCalls); AssertWireResult(refused);
        var applied = await executor.ExecuteAsync(applyRequest with { OperationId = Guid.NewGuid().ToString("D") }, default);
        Assert.True(applied.Success, applied.Diagnostic); Assert.Equal("91", applied.ManagementObservedXid);
        AssertWireResult(applied);
        if (operation == ApfsManagementOperations.RenameVolume)
        {
            var call = Assert.Single(backend.KeeperCalls);
            Assert.Equal(ClosureImage, call.ImagePath); Assert.Equal("New name", call.NewLabel);
            Assert.Equal("90", call.PreimageXid); Assert.Equal(TestJournalRoot, call.JournalRoot);
        }
        else
        {
            var call = Assert.Single(backend.QuotaCalls);
            Assert.Equal(ClosureImage, call.ImagePath); Assert.Equal("65536", call.QuotaBytes);
            Assert.Equal("20480", call.ReserveBytes); Assert.Equal("90", call.PreimageXid);
            Assert.Equal(TestJournalRoot, call.JournalRoot);
        }
        Assert.Equal(3, backend.VerifyCalls.Count);
        Assert.All(backend.VerifyCalls, scope => Assert.Equal("90", scope.CheckpointXid));
    }

    [Theory]
    [InlineData(ApfsManagementOperations.RenameVolume, false, 91UL)]
    [InlineData(ApfsManagementOperations.RenameVolume, true, 90UL)]
    [InlineData(ApfsManagementOperations.SetQuotaReserve, false, 91UL)]
    [InlineData(ApfsManagementOperations.SetQuotaReserve, true, 90UL)]
    public async Task Management_ContradictoryKeeperCommitNeverClaimsSuccess(string operation, bool committed, ulong xid)
    {
        var backend = new KeeperBackend(new ScenarioBackend { TopologyCheckpointXid = "90" });
        if (operation == ApfsManagementOperations.RenameVolume)
            backend.Enqueue(new(committed, xid, ManagementKeeperCodes.Committed, "bad evidence"));
        else backend.EnqueueQuota(new(committed, xid, ManagementKeeperCodes.Committed, "bad evidence"));
        using var worker = CreateWorker(backend, TestJournalRoot);
        var executor = new AgentControlCommandExecutor(worker);
        var plan = await executor.ExecuteAsync(ManagementRequest(ApfsControlCommands.ManagementPlan, operation), default);
        Assert.True(plan.Success, plan.Diagnostic);
        var request = ManagementRequest(ApfsControlCommands.ManagementApply, operation, token: plan.ManagementToken,
            name: operation == ApfsManagementOperations.RenameVolume ? "New name" : null,
            quotaBytes: operation == ApfsManagementOperations.SetQuotaReserve ? "65536" : null,
            reserveBytes: operation == ApfsManagementOperations.SetQuotaReserve ? "20480" : null, imagePath: TestImagePath);
        var result = await executor.ExecuteAsync(request, default);
        Assert.False(result.Success); Assert.Equal("not-proven", result.FinalStatus);
        Assert.Equal("not-proven", result.DurabilityProof); AssertWireResult(result);
    }

    private static void AssertWireResult(OperationResultPayload result)
    {
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, 2);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid, PipeMessageCodec.Validate(envelope).Diagnostic);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out var decoded));
        Assert.True(PipeMessageCodec.Validate(decoded!).IsValid, PipeMessageCodec.Validate(decoded!).Diagnostic);
    }
}
