using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [Theory]
    [InlineData("success")]
    [InlineData("native-refusal")]
    [InlineData("no-op")]
    [InlineData("dirty")]
    [InlineData("owner")]
    [InlineData("scope")]
    [InlineData("verify-refusal")]
    [InlineData("absent")]
    [InlineData("final-probe-failure")]
    [InlineData("missing-creation")]
    [InlineData("zero-creation")]
    [InlineData("negative-creation")]
    [InlineData("zero-pid")]
    [InlineData("negative-pid")]
    [InlineData("recover-incarnation")]
    [InlineData("recover-zero-creation")]
    [InlineData("recover-negative-creation")]
    [InlineData("verify-incarnation")]
    [InlineData("verify-zero-creation")]
    [InlineData("verify-negative-creation")]
    [InlineData("historical-refusal")]
    [InlineData("other-refusal")]
    public async Task FixRetainedSnapshotRequiresTerminalFreshSameOwnerRwAndLiveVerification(string test)
    {
        var inner = ClosureBackend();
        var backend = new FixSnapshotBackend(inner, test);
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0];
        var scope = LiveVerificationFixture.Scope(volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!,
            volume.CatalogVolumeObjectId!.Value.ToString());
        var mount = HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            RecoveryIdentity = volume.RecoveryIdentity, CatalogContainerUuid = volume.CatalogContainerUuid,
            CatalogVolumeUuid = volume.CatalogVolumeUuid, CatalogVolumeId = volume.CatalogVolumeId,
            CatalogVolumeObjectId = volume.CatalogVolumeObjectId, HostProcessId = 4321,
            HostProcessCreationTimeFileTimeUtc = 123456789, MountReady = true,
            RuntimeWatermarksKnown = true, WalAcceptedSequence = 2, WalApfsDurableSequence = 2, WalCleanupSequence = 2,
            VolumeVerificationSupported = true, VolumeVerificationScope = scope };
        backend.Recovered = mount;
        var initial = mount with { AccessMode = MountAccessMode.ReadOnly, RecoveryActive = true,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback, SnapshotMutationSupported = false,
            SnapshotInventorySupported = false, WalApfsDurableSequence = 0, WalCleanupSequence = 0, DirtyTransactionCount = 1 };
        inner.SetMounted(test switch {
            "missing-creation" => initial with { HostProcessCreationTimeFileTimeUtc = new MountedVolumeState("v", "R:\\", MountAccessMode.ReadOnly).HostProcessCreationTimeFileTimeUtc },
            "zero-creation" => initial with { HostProcessCreationTimeFileTimeUtc = 0 },
            "negative-creation" => initial with { HostProcessCreationTimeFileTimeUtc = -1 },
            "zero-pid" => initial with { HostProcessId = 0 },
            "negative-pid" => initial with { HostProcessId = -1 },
            _ => initial });
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix,
            SelectedControlTarget.Create(inventory, volume)), default);
        var succeeds = test is "success" or "historical-refusal";
        Assert.Equal(succeeds, result.Success);
        AssertWireResult(result);
        Assert.Equal(test is "missing-creation" or "zero-creation" or "negative-creation" or "zero-pid" or "negative-pid" ? 0 : 1, backend.RecoverCalls);
        Assert.Equal(0, inner.UnmountCalls); Assert.Equal(0, inner.MountCalls);
        Assert.Equal(test is "success" or "scope" or "verify-refusal" or "final-probe-failure" or
            "verify-incarnation" or "verify-zero-creation" or "verify-negative-creation" or "historical-refusal" or "other-refusal" ? 1 : 0, backend.VerifyCalls);
        if (test is "historical-refusal" or "other-refusal")
        {
            Assert.NotNull(backend.Verification);
            Assert.Equal("Refused", backend.Verification!.Outcome);
            Assert.False(backend.Verification.Complete);
        }
        if (succeeds)
        {
            Assert.Equal("healthy-rw", result.FinalStatus); Assert.Equal("not-applicable", result.OwnershipProof);
            Assert.Equal("not-applicable", result.DurabilityProof); Assert.Null(result.VolumeVerificationReport);
            Assert.Contains("Whole-volume", result.Diagnostic, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("payload hashes remain unverified", result.Diagnostic);
            if (test == "historical-refusal") Assert.Contains("Generic verification remains Refused", result.Diagnostic);
        }
        if (test is "absent" or "final-probe-failure")
        {
            Assert.Equal(test == "absent" ? "absent" : "not-proven", result.MountProof);
            Assert.Equal(test == "absent" ? "absent" : "not-proven", result.FinalStatus);
            Assert.Null(result.EffectiveMode); Assert.Null(result.RecoveryState);
            Assert.False(result.RecoveryActive); Assert.Equal(0, result.DirtyTransactionCount);
            Assert.Equal("not-proven", result.OwnershipProof); Assert.Equal("not-proven", result.DurabilityProof);
        }
    }

    [Theory]
    [InlineData(true, "none")]
    [InlineData(false, "none")]
    [InlineData(true, "recovery")]
    [InlineData(false, "recovery")]
    [InlineData(true, "container")]
    [InlineData(false, "container")]
    [InlineData(true, "uuid")]
    [InlineData(false, "uuid")]
    [InlineData(true, "oid")]
    [InlineData(false, "oid")]
    [InlineData(true, "catalog-id")]
    [InlineData(false, "catalog-id")]
    [InlineData(true, "device")]
    [InlineData(false, "device")]
    [InlineData(true, "volume")]
    [InlineData(false, "volume")]
    public async Task FixRetainedSnapshotBindsFinalInventoryToVerifiedOwner(bool strongTarget, string change)
    {
        var inner = ClosureBackend();
        var backend = new FixSnapshotBackend(inner, "success");
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0];
        var mount = HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            RecoveryIdentity = volume.RecoveryIdentity, CatalogContainerUuid = volume.CatalogContainerUuid,
            CatalogVolumeUuid = volume.CatalogVolumeUuid, CatalogVolumeId = volume.CatalogVolumeId,
            CatalogVolumeObjectId = volume.CatalogVolumeObjectId, HostProcessId = 4321,
            HostProcessCreationTimeFileTimeUtc = 123456789, MountReady = true,
            RuntimeWatermarksKnown = true, WalAcceptedSequence = 2, WalApfsDurableSequence = 2, WalCleanupSequence = 2,
            VolumeVerificationSupported = true, VolumeVerificationScope = LiveVerificationFixture.Scope(
                volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!, volume.CatalogVolumeObjectId!.Value.ToString()) };
        backend.Recovered = mount;
        inner.SetMounted(mount with { AccessMode = MountAccessMode.ReadOnly, RecoveryActive = true,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback, DirtyTransactionCount = 1 });
        var replacement = change switch {
            "recovery" => volume with { RecoveryIdentity = "replacement-owner" },
            "container" => volume with { CatalogContainerUuid = "cccccccccccccccccccccccccccccccc" },
            "uuid" => volume with { CatalogVolumeUuid = "dddddddddddddddddddddddddddddddd" },
            "oid" => volume with { CatalogVolumeObjectId = volume.CatalogVolumeObjectId + 1 },
            "catalog-id" => volume with { CatalogVolumeId = "replacement-catalog-volume" },
            "device" => volume with { DeviceId = @"D:\replacement.apfs" },
            "volume" => volume with { VolumeId = "replacement-volume" },
            _ => volume };
        backend.InventoryAfterVerification = [inventory with { Volumes = [replacement] }];
        var target = strongTarget ? SelectedControlTarget.Create(inventory, volume) : new ApfsControlTarget(ClosureImage, ClosureVolume);
        var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix, target), default);
        Assert.Same(backend.InventoryAfterVerification, backend.InventoryOverride);
        Assert.Equal(change == "none", result.Success);
        AssertWireResult(result);
        Assert.Equal(1, backend.RecoverCalls); Assert.Equal(1, backend.VerifyCalls);
        Assert.Equal(0, inner.UnmountCalls); Assert.Equal(0, inner.MountCalls);
        if (change != "none")
        {
            Assert.Equal(ApfsOperationCodes.BlockedRecovery, result.Code);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
        }
    }

    [Fact]
    public async Task FixRetainedSnapshotCancellationNeverFallsThroughToRemount()
    {
        var inner = ClosureBackend(); var backend = new FixSnapshotBackend(inner, "cancel");
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0];
        inner.SetMounted(HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            RecoveryIdentity = volume.RecoveryIdentity, CatalogContainerUuid = volume.CatalogContainerUuid,
            CatalogVolumeUuid = volume.CatalogVolumeUuid, CatalogVolumeId = volume.CatalogVolumeId,
            CatalogVolumeObjectId = volume.CatalogVolumeObjectId, HostProcessId = 4321,
            HostProcessCreationTimeFileTimeUtc = 123456789, AccessMode = MountAccessMode.ReadOnly,
            RecoveryActive = true, SnapshotRecoverySupported = true });
        using var cancellation = new CancellationTokenSource();
        var pending = CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix,
            SelectedControlTarget.Create(inventory, volume)), cancellation.Token);
        await backend.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        var result = await pending;
        Assert.False(result.Success); Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
        Assert.Equal(0, inner.UnmountCalls); Assert.Equal(0, inner.MountCalls); Assert.Equal(0, backend.VerifyCalls);
    }

    [Fact]
    public async Task FixRetainedSnapshotLateCancellationAwaitsFinalInventoryCancellationWithoutRemount()
    {
        var inner = ClosureBackend();
        var backend = new FixSnapshotBackend(inner, "success") { GateFinalInventory = true };
        using var worker = CreateWorker(backend, autoMountEnabled: false);
        await worker.RefreshAsync(false, default);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ClosureImage);
        var volume = inventory.Volumes[0];
        var mount = HealthyMount() with { DeviceId = ClosureImage, VolumeId = ClosureVolume,
            RecoveryIdentity = volume.RecoveryIdentity, CatalogContainerUuid = volume.CatalogContainerUuid,
            CatalogVolumeUuid = volume.CatalogVolumeUuid, CatalogVolumeId = volume.CatalogVolumeId,
            CatalogVolumeObjectId = volume.CatalogVolumeObjectId, HostProcessId = 4321,
            HostProcessCreationTimeFileTimeUtc = 123456789, MountReady = true,
            RuntimeWatermarksKnown = true, WalAcceptedSequence = 2, WalApfsDurableSequence = 2, WalCleanupSequence = 2,
            VolumeVerificationSupported = true, VolumeVerificationScope = LiveVerificationFixture.Scope(
                volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!, volume.CatalogVolumeObjectId!.Value.ToString()) };
        backend.Recovered = mount;
        inner.SetMounted(mount with { AccessMode = MountAccessMode.ReadOnly, RecoveryActive = true,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback, DirtyTransactionCount = 1 });
        using var cancellation = new CancellationTokenSource();
        var pending = CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix,
            SelectedControlTarget.Create(inventory, volume)), cancellation.Token);
        try
        {
            await backend.FinalInventoryStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, backend.VerifyCalls);
            Assert.True(backend.Verification?.Complete);
            cancellation.Cancel();
            var completed = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(2)));
            Assert.Same(pending, completed);
            var result = await pending;
            Assert.Equal(cancellation.Token, backend.FinalInventoryToken);
            Assert.True(backend.FinalInventoryCancellationObserved);
            Assert.True(backend.FinalInventoryFinished.Task.IsCompletedSuccessfully);
            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            Assert.Equal("present", result.MountProof);
            Assert.Equal("not-proven", result.OwnershipProof);
            Assert.Equal("not-proven", result.DurabilityProof);
            AssertWireResult(result);
            Assert.Equal(1, backend.RecoverCalls);
            Assert.Equal(0, inner.UnmountCalls); Assert.Equal(0, inner.MountCalls);
        }
        finally
        {
            backend.FinalInventoryRelease.TrySetResult();
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    private sealed class FixSnapshotBackend(ScenarioBackend inner, string test) : IApfsBackend, ISnapshotControlBackend, ILiveVolumeVerificationBackend
    {
        public MountedVolumeState Recovered { get; set; } = null!;
        public int RecoverCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public LiveVolumeVerificationReport? Verification { get; private set; }
        public IReadOnlyList<DeviceInventory>? InventoryAfterVerification { get; set; }
        public IReadOnlyList<DeviceInventory>? InventoryOverride { get; private set; }
        public bool GateFinalInventory { get; init; }
        public CancellationToken FinalInventoryToken { get; private set; }
        public bool FinalInventoryCancellationObserved { get; private set; }
        public TaskCompletionSource FinalInventoryStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FinalInventoryRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FinalInventoryFinished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => inner.ProbeDevicesAsync(token);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => inner.ProbeVolumesAsync(device, token);
        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            if (GateFinalInventory && VerifyCalls != 0)
            {
                FinalInventoryToken = token;
                using var registration = token.Register(() => FinalInventoryRelease.TrySetCanceled(token));
                FinalInventoryStarted.TrySetResult();
                try { await FinalInventoryRelease.Task; }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                { FinalInventoryCancellationObserved = true; throw; }
                finally { FinalInventoryFinished.TrySetResult(); }
            }
            return InventoryOverride is { } inventory ? inventory : await inner.ProbeInventoryAsync(authoritative, token);
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            if (RecoverCalls != 0 && test == "absent")
                return Task.FromResult<IReadOnlyList<MountedVolumeState>>([]);
            if (VerifyCalls != 0 && test == "final-probe-failure")
                throw new IOException("The owner status channel failed after verification.");
            return inner.GetMountStateAsync(token);
        }
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) => inner.MountAsync(request, token);
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => inner.UnmountAsync(point, token);
        public async Task<SnapshotControlResult> SendSnapshotControlAsync(string container, ulong oid, SnapshotControlAction action,
            IReadOnlyList<string>? extras, CancellationToken token)
        {
            Assert.Equal(SnapshotControlAction.Recover, action); RecoverCalls++; Started.SetResult();
            if (test == "cancel") await Task.Delay(Timeout.Infinite, token);
            if (test == "native-refusal") return new(false, "SnapshotRecoveryOwnerRefused");
            if (test == "no-op") return new(true, "SnapshotRecoverNoOp");
            inner.SetMounted(test switch {
                "dirty" => Recovered with { WalCleanupSequence = 0 },
                "owner" => Recovered with { HostProcessId = Recovered.HostProcessId + 1 },
                "recover-incarnation" => Recovered with { HostProcessCreationTimeFileTimeUtc = Recovered.HostProcessCreationTimeFileTimeUtc + 1 },
                "recover-zero-creation" => Recovered with { HostProcessCreationTimeFileTimeUtc = 0 },
                "recover-negative-creation" => Recovered with { HostProcessCreationTimeFileTimeUtc = -1 },
                _ => Recovered });
            return new(true, "SnapshotRecovered");
        }
        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        {
            VerifyCalls++;
            InventoryOverride = InventoryAfterVerification;
            if (test.StartsWith("verify-", StringComparison.Ordinal))
                inner.SetMounted(test switch {
                    "verify-incarnation" => Recovered with { HostProcessCreationTimeFileTimeUtc = Recovered.HostProcessCreationTimeFileTimeUtc + 1 },
                    "verify-zero-creation" => Recovered with { HostProcessCreationTimeFileTimeUtc = 0 },
                    "verify-negative-creation" => Recovered with { HostProcessCreationTimeFileTimeUtc = -1 },
                    _ => Recovered });
            if (test == "verify-refusal") return Task.FromResult(new LiveVolumeVerificationResult(false, "VolumeVerificationOwnerRefused"));
            if (test == "scope") scope = scope with { CheckpointXid = "21" };
            var json = LiveVerificationFixture.Report(scope);
            if (test is "historical-refusal" or "other-refusal")
            {
                json["outcome"] = 3; json["outcomeName"] = "Refused";
                json["coveredFilesystemRecords"] = "0"; json["coveredPhysicalExtents"] = "0";
                json["allocationCensus"] = null; json["coverage"]![12]!["state"] = 4;
                json["repair"]!["refusal"] = 2;
                json["findings"] = System.Text.Json.Nodes.JsonNode.Parse("""
                    [{"code":17,"check":13,"severity":2,"volumeOid":"101","objectId":null,"physicalBlock":null,
                    "checkpointXid":"20","failedSourceOffsetBytes":null,
                    "detail":"VerifierSnapshotReachableBlocksCheckedButHistoricalReferenceOwnershipUnproven"}]
                    """);
                if (test == "other-refusal") json["findings"]![0]!["detail"] = "Another historical ownership refusal";
                json["repair"]!["planId"] = LiveVerificationFixture.PlanId(json);
            }
            var report = LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(json));
            Verification = report;
            return Task.FromResult(new LiveVolumeVerificationResult(true, "VolumeVerificationReport", report));
        }
    }
}
