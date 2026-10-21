using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [Theory]
    [InlineData(@"C:\ApfsManagement")] [InlineData(@"Z:\ApfsManagement")]
    public void ImageRepair_CanonicalLocalManagementRootAdvertisesCapabilityWithoutFilesystemAccess(string root)
    {
        var b = new RepairBackend();
        using var worker = CreateWorker(b, root);
        Assert.True(worker.ImageRepairAvailable);
        Assert.Empty(b.Calls);
    }

    [Fact]
    public async Task ImageRepair_HealthyFixWithUnsupportedRepairRootKeepsNormalManagementAdmissionAndNativeProof()
    {
        var b = new RepairBackend { Repaired = true };
        // Existing management accepts slash-form absolute local roots. The
        // repair profile requires a canonical local root, like its writer.
        var managementRoot = b.Root.Replace('\\', '/');
        using var worker = CreateWorker(b, managementRoot);
        Assert.False(worker.ImageRepairAvailable);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(b.Fix(true), default);
        Assert.True(result.Success, result.Diagnostic); Assert.Equal("healthy-rw", result.FinalStatus);
        Assert.Empty(b.Calls); Assert.Null(result.ImageRepairOffer); Assert.Null(result.ImageRepairReceipt);
        Assert.Equal(new[] { "verify", "mount", "live" }, b.Events); AssertWireResult(result);
    }

    [Fact]
    public async Task ImageRepair_UnsupportedOptionalRepairRootDoesNotBypassPendingManagementAdmission()
    {
        var b = new RepairBackend();
        using (var original = CreateWorker(b, b.Root))
        {
            var executor = new AgentControlCommandExecutor(original); var request = b.Fix(true);
            var offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
            b.ApplyFailure = () => throw new IOException("Accepted lineage still needs native recovery");
            Assert.True((await executor.ExecuteAsync(b.Approve(request, offer), default)).PendingDurability);
        }
        b.Repaired = true;
        using var restarted = CreateWorker(b, b.Root.Replace('\\', '/'));
        Assert.False(restarted.ImageRepairAvailable);
        var refused = await new AgentControlCommandExecutor(restarted).ExecuteAsync(b.Fix(true), default);
        Assert.False(refused.Success); Assert.Equal(0, b.MountCalls); Assert.True(b.Read().Pending);
        Assert.False((await restarted.EnsureMountedAsync(b.VolumeId, default)).Success); AssertWireResult(refused);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(false, true)] [InlineData(true, true)]
    public async Task ImageRepair_OfferAndApprovalBindDerivedSelectionForLegacyAndAdvertisedCallers(bool legacy, bool genericComplete)
    {
        var b = new RepairBackend { GenericComplete = genericComplete }; using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker);
        var request = b.Fix(legacy);
        var offerResult = await executor.ExecuteAsync(request, default);
        Assert.False(offerResult.Success); Assert.Equal(ApfsOperationStates.Failed, offerResult.State);
        Assert.Equal(ApfsOperationCodes.BlockedRecovery, offerResult.Code);
        Assert.True(offerResult.FinalStatus == "repair-confirmation-required", offerResult.Diagnostic);
        var offer = Assert.IsType<ImageRepairOffer>(offerResult.ImageRepairOffer);
        AssertWireResult(offerResult); Assert.False(b.Read().Pending); Assert.Equal(0, b.MountCalls); Assert.Equal(0, b.LiveCalls);
        Assert.Null(Assert.Single(b.Calls).Approval);
        Assert.True(File.Exists(b.Read().JournalPath)); Assert.Equal(0, new FileInfo(b.Read().JournalPath).Length);
        var approval = b.Approve(request, offer);
        var result = await executor.ExecuteAsync(approval, default);
        Assert.True(result.Success, result.Diagnostic); Assert.Equal("healthy-rw", result.FinalStatus); AssertWireResult(result);
        var receipt = Assert.IsType<ImageRepairReceipt>(result.ImageRepairReceipt);
        Assert.Equal(offer, receipt.Binding); Assert.Equal("repaired", receipt.State); Assert.True(receipt.NativePostVerifyComplete);
        Assert.Equal(offer.PlanId, result.ApprovedImageRepairPlanId); Assert.Equal("repaired", b.Read().State);
        Assert.Equal(1, b.MountCalls); Assert.Equal(1, b.LiveCalls); Assert.Equal(3, b.VerifyCalls);
        Assert.Equal(new[] { "verify", "dry", "verify", "dry", "apply", "verify", "mount", "live" }, b.Events);
        var replay = await executor.ExecuteAsync(b.Approve(request, offer), default);
        Assert.False(replay.Success); Assert.Equal(ApfsOperationCodes.OperationConflict, replay.Code);
        Assert.Equal("consumed", replay.ImageRepairReceipt!.State); Assert.Equal(3, b.Calls.Count); AssertWireResult(replay);
    }

    [Fact]
    public async Task ImageRepair_HealthyFixDoesNotPlanAndStillRequiresNativeOwnerProof()
    {
        var b = new RepairBackend { Repaired = true }; using var worker = CreateWorker(b, b.Root);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(b.Fix(true), default);
        Assert.True(result.Success, result.Diagnostic); Assert.Single(b.Calls); Assert.Null(Assert.Single(b.Calls).Approval); Assert.Null(result.ImageRepairOffer);
        Assert.Null(result.ImageRepairReceipt); Assert.Equal(1, b.LiveCalls); AssertWireResult(result);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("device")]
    [InlineData("volume")]
    [InlineData("recovery")]
    [InlineData("scope")]
    public async Task ImageRepair_NormalizedAdvertisedApprovalPreservesOnlyWindowsDeviceSpelling(string fault)
    {
        var b = new RepairBackend(); using var worker = CreateWorker(b,b.Root);
        var executor = new AgentControlCommandExecutor(worker);
        var service = new AgentControlOperationService((request,token)=>executor.ExecuteAsync(request,token),Path.Combine(b.Root,"operations"));
        try
        {
            var request = b.Fix(false);
            var offered = await service.ExecuteOrReplayAsync(request);
            var offer = Assert.IsType<ImageRepairOffer>(offered.ImageRepairOffer);
            Assert.Equal(request.Target!.DeviceId.ToLowerInvariant(),offered.Target!.DeviceId);
            var approval = b.Approve(request,offer);
            approval = fault switch {
                "device" => approval with { Target = approval.Target! with { DeviceId = @"D:\other.apfs" } },
                "volume" => approval with { Target = approval.Target! with { VolumeId = $"apfs-vol:{b.Container}:102" } },
                "recovery" => approval with { Target = approval.Target! with { RecoveryIdentity = "other" } },
                "scope" => approval with { Target = approval.Target! with { ObservationContract = "selected-v1:"+new string('f',64) } },
                _ => approval,
            };
            var result = await service.ExecuteOrReplayAsync(approval);
            AssertWireResult(result);
            Assert.Equal(fault=="none",result.Success);
            Assert.Equal(fault=="none"?1:0,b.ApplyCalls);
            if(fault=="none")Assert.True(result.ImageRepairReceipt!.NativePostVerifyComplete);
        }
        finally { await service.StopAsync(default); }
    }

    [Theory]
    [InlineData("volume")] [InlineData("uuid")] [InlineData("recovery")] [InlineData("source")]
    [InlineData("sha256")] [InlineData("count")] [InlineData("xid")] [InlineData("contract")] [InlineData("unknown")]
    public async Task ImageRepair_StaleApprovalCannotReachConfirmedApply(string change)
    {
        var b = new RepairBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Fix(true);
        var offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
        Assert.NotNull(offer);
        var approval = b.Approve(request, offer);
        switch (change)
        {
            case "volume": approval = approval with { Target = approval.Target! with { VolumeId = $"apfs-vol:{b.Container}:102" } }; break;
            case "uuid": approval = approval with { Target = b.Fix(false).Target! with { VolumeUuid = new string('e', 32) } }; break;
            case "recovery": approval = approval with { Target = approval.Target! with { RecoveryIdentity = "replacement" } }; break;
            case "contract": approval = approval with { Target = b.Fix(false).Target! with { ObservationContract = "selected-v1:" + new string('e', 64) } }; break;
            case "source": b.Source = b.Source + "1"; break;
            case "sha256": b.Sha = new string('e', 64); break;
            case "count": b.Count = "2"; break;
            case "xid": b.Basis.Xid = "8"; break;
            case "unknown": approval = approval with { ApprovedImageRepairPlanId = new string('f', 64) }; break;
        }
        var result = await executor.ExecuteAsync(approval, default);
        Assert.False(result.Success); Assert.Equal(0, b.ApplyCalls); Assert.Equal(0, b.MountCalls);
        Assert.Equal("offered", b.Read().State); AssertWireResult(result);
    }

    [Fact]
    public async Task ImageRepair_ExpiredOfferNeverAcceptsButDoesNotLeaveMountDebt()
    {
        var b = new RepairBackend(); using var worker = CreateWorker(b, b.Root);
        var clock = new RepairClock(DateTimeOffset.UtcNow);
        var executor = new AgentControlCommandExecutor(worker, timeProvider: clock);
        var request = b.Fix(true); var offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
        clock.Now = clock.Now.AddMinutes(3);
        var result = await executor.ExecuteAsync(b.Approve(request, offer) with { ExpiresAtUtc = clock.Now.UtcDateTime.AddMinutes(2) }, default);
        Assert.False(result.Success); Assert.Equal("expired", result.ImageRepairReceipt!.State);
        Assert.False(b.Read().Pending); Assert.Equal(0, b.ApplyCalls); AssertWireResult(result);
    }

    [Theory]
    [InlineData("native-refused")] [InlineData("many-findings")] [InlineData("system")]
    [InlineData("siblings")] [InlineData("fusion")] [InlineData("encrypted")]
    public async Task ImageRepair_UnsupportedFindingsOrProfilesNeverOfferOrApply(string unsupported)
    {
        var b = new RepairBackend { Unsupported = unsupported }; using var worker = CreateWorker(b, b.Root);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(b.Fix(true), default);
        Assert.False(result.Success); Assert.Null(result.ImageRepairOffer); Assert.Equal(0, b.ApplyCalls);
        Assert.Equal(0, b.MountCalls); AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ImageRepair_InterruptedAcceptanceBlocksMountAndRestartReusesOnlyOriginalLineage(bool cancel)
    {
        var b = new RepairBackend(); var request = b.Fix(true); ImageRepairOffer offer;
        using var cancellation = new CancellationTokenSource();
        using (var worker = CreateWorker(b, b.Root))
        {
            var executor = new AgentControlCommandExecutor(worker);
            offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
            b.ApplyFailure = cancel ? () => { cancellation.Cancel(); throw new OperationCanceledException(cancellation.Token); }
                : () => throw new IOException("Injected lost confirmed native reply");
            var result = await executor.ExecuteAsync(b.Approve(request, offer), cancellation.Token);
            Assert.False(result.Success); Assert.True(result.PendingDurability); Assert.Equal("recovery-required", b.Read().State);
            if (cancel) Assert.Equal(ApfsOperationStates.Cancelled, result.State);
            AssertWireResult(result);
            Assert.False((await worker.EnsureMountedAsync(b.VolumeId, default)).Success); Assert.Equal(0, b.MountCalls);
        }
        // This models accepted work before the checkpoint advances. Completed
        // native journal / advanced-CP replay is a separate real runtime gate.
        var original = b.Read(); b.ApplyFailure = null; b.Replay = true;
        using var restarted = CreateWorker(b, b.Root);
        Assert.False((await restarted.EnsureMountedAsync(b.VolumeId, default)).Success);
        var resultAfterRestart = await new AgentControlCommandExecutor(restarted).ExecuteAsync(b.Approve(request, offer), default);
        Assert.True(resultAfterRestart.Success, resultAfterRestart.Diagnostic); AssertWireResult(resultAfterRestart);
        var confirmed = b.Calls.Where(c => c.Approval is not null).ToArray(); Assert.Equal(2, confirmed.Length);
        Assert.Equal(confirmed[0], confirmed[1]); Assert.Equal(original.JournalPath, confirmed[1].JournalPath);
        Assert.Equal(original.EvidenceDirectory, confirmed[1].EvidenceDirectory);
        Assert.Equal(original.AcceptedOperationId, b.Read().AcceptedOperationId);
        Assert.Equal(original.AcceptedFingerprint, b.Read().AcceptedFingerprint);
        Assert.True(resultAfterRestart.ImageRepairReceipt!.Replayed); Assert.False(b.Read().Pending);
    }

    [Fact]
    public async Task ImageRepair_AdvancedCheckpointNativeRefusalPreservesAcceptedOriginalDebt()
    {
        var b = new RepairBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Fix(true);
        var offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
        b.ApplyFailure = () => throw new IOException("Native accepted; reply unavailable");
        var interrupted = await executor.ExecuteAsync(b.Approve(request, offer), default);
        Assert.True(interrupted.PendingDurability); var original = b.Read();
        b.ApplyFailure = null; b.ApplyRefused = true; b.Basis.Xid = "8";
        var refused = await executor.ExecuteAsync(b.Approve(request, offer), default);
        Assert.False(refused.Success); Assert.True(refused.PendingDurability); Assert.Equal("recovery-required", b.Read().State);
        Assert.Equal("RepairRefused", refused.ImageRepairReceipt!.NativeCode); Assert.Equal(0, b.MountCalls);
        Assert.Equal(original.JournalPath, b.Read().JournalPath); Assert.Equal(original.AcceptedFingerprint, b.Read().AcceptedFingerprint);
        Assert.True(new FileInfo(original.JournalPath).Length > 0); AssertWireResult(refused);
    }

    [Theory]
    [InlineData("cancel")] [InlineData("owner")] [InlineData("pid-reuse")] [InlineData("findings")] [InlineData("inventory")]
    public async Task ImageRepair_NativeRepairedReceiptDoesNotRescueFailedTerminalProof(string failure)
    {
        var b = new RepairBackend(); using var worker = CreateWorker(b, b.Root);
        using var cancellation = new CancellationTokenSource();
        var executor = new AgentControlCommandExecutor(worker); var request = b.Fix(true);
        var offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
        b.LiveFailure = failure; if (failure == "cancel") b.AfterLive = cancellation.Cancel;
        var result = await executor.ExecuteAsync(b.Approve(request, offer), cancellation.Token);
        Assert.False(result.Success); Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Equal("repaired", result.ImageRepairReceipt!.State); Assert.True(result.ImageRepairReceipt.NativePostVerifyComplete);
        Assert.Equal(1, b.LiveCalls); AssertWireResult(result);
    }

    [Fact]
    public async Task ImageRepair_IncompleteIntentPreventsNativeApplyAndDirectWorkerMount()
    {
        var b = new RepairBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Fix(true);
        var offer = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
        var incomplete = Path.Combine(b.Root, ImageRepairPersistence.Prefix + offer.PlanId + ".interrupted.tmp");
        await File.WriteAllTextAsync(incomplete, "preserved original interruption");
        var result = await executor.ExecuteAsync(b.Approve(request, offer), default);
        Assert.False(result.Success); Assert.Equal(0, b.ApplyCalls);
        Assert.False((await worker.EnsureMountedAsync(b.VolumeId, default)).Success); Assert.Equal(0, b.MountCalls);
        Assert.Equal("preserved original interruption", await File.ReadAllTextAsync(incomplete));
    }

    private sealed class RepairClock(DateTimeOffset now) : TimeProvider
    { public DateTimeOffset Now = now; public override DateTimeOffset GetUtcNow() => Now; }

    // Mock transport proves service routing/persistence only. No native tool,
    // image bytes, process, drive namespace or real mount is used by these tests.
    private sealed class RepairBackend : IApfsBackend, IVerifyBackend, IImageRepairBackend, ILiveVolumeVerificationBackend
    {
        public readonly TopologyBackend Basis = new();
        public string Root => Basis.Root; public string Image => Basis.Image;
        public string Container => Basis.Container; public string VolumeId => Basis.VolumeId;
        public string Source = "windows-image-v1:" + new string('a', 48) + "0000000000000000" + "0000000000200000" + ":123";
        public string Sha = new('c', 64), Count = "1";
        public bool Repaired, Replay, GenericComplete, ApplyRefused; public int MountCalls, LiveCalls, VerifyCalls, ApplyCalls;
        public string? Unsupported, LiveFailure; public Action? ApplyFailure, AfterLive;
        public readonly List<ImageRepairInvocation> Calls = []; public readonly List<string> Events = [];
        public readonly List<MountedVolumeState> Mounts = [];
        public ImageRepairIntent Read() { using var store = new ImageRepairIntentStore(Root); return Assert.Single(store.ReadAll()); }
        public DeviceInventory Inventory()
        {
            var d = Basis.Inventory(); var t = d.Topology!.Snapshot;
            if (Unsupported == "system") t = t with { Volumes = t.Volumes.Select(v => v with { RoleRaw = 1, Roles = ["system"] }).ToArray() };
            if (Unsupported == "fusion") t = t with { Containers = t.Containers.Select(c => c with { Fusion = true }).ToArray() };
            if (Unsupported == "siblings") t = t with { Containers = t.Containers.Select(c => c with { VolumeIds = [VolumeId, $"apfs-vol:{Container}:102"] }).ToArray() };
            if (Unsupported == "encrypted") d = d with { Volumes = d.Volumes.Select(v => v with { IsEncrypted = true }).ToArray() };
            return d with { Topology = d.Topology with { Snapshot = t } };
        }
        public ControlOperationRequestPayload Fix(bool legacy) => CreateRequest(ApfsControlCommands.Fix,
            legacy ? new(Image, VolumeId) : SelectedControlTarget.Create(Inventory(), Inventory().Volumes.Single()));
        public ControlOperationRequestPayload Approve(ControlOperationRequestPayload initial, ImageRepairOffer offer)
            => initial with { OperationId = Guid.NewGuid().ToString("D"), ExpiresAtUtc = DateTime.UtcNow.AddMinutes(2), ApprovedImageRepairPlanId = offer.PlanId };
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInfo>>([Inventory().Device]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken token) => Task.FromResult(Inventory().Volumes);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
            => Task.FromResult<IReadOnlyList<DeviceInventory>>(LiveCalls != 0 && LiveFailure == "inventory" ? [] : [Inventory()]);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            ImageRepairPersistence.RequireNoPending(Root); MountCalls++; Events.Add("mount");
            var owner = ImageFixProofOwner(Inventory().Volumes[0], Basis.Xid);
            owner = owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { StoreSizeBytes = "2097152" }, MountPoint = request.DriveLetter + ":\\" };
            Mounts.Add(owner);
            return Task.FromResult(new MountResult(true, owner.MountPoint, null, MountAccessMode.ReadWrite, WriteEnabled: true,
                NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite));
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        { Mounts.RemoveAll(m => m.MountPoint == point); return Task.FromResult(new UnmountResult(true, point, null, true, true, true)); }
        public Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken token)
        {
            Assert.Empty(Mounts); VerifyCalls++; Events.Add("verify");
            return Task.FromResult(new ImageVerifyResult(true, Repaired || GenericComplete ? "Complete" : "Incomplete", Repaired || GenericComplete ? 0 : 3,
                Repaired || GenericComplete ? 0 : Unsupported == "many-findings" ? 2 : 1, "MOCK: service proof only"));
        }
        public Task<ImageRepairNativeResult> RunImageRepairAsync(ImageRepairInvocation r, CancellationToken token)
        {
            Assert.Empty(Mounts); Calls.Add(r); Events.Add(r.Approval is null ? "dry" : "apply");
            if (r.Approval is null)
            {
                using var lease = new FileStream(r.JournalPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                Assert.Equal(0, lease.Length); // Matches native dry writer-lease side effect.
            }
            if (r.Approval is not null)
            {
                ApplyCalls++; var durable = Read(); Assert.True(durable.Pending); Assert.NotNull(durable.AcceptedFingerprint);
                Assert.Equal(durable.Offer, r.Approval); Assert.Equal(durable.JournalPath, r.JournalPath); Assert.Equal(durable.EvidenceDirectory, r.EvidenceDirectory);
                if (new FileInfo(r.JournalPath).Length == 0) File.WriteAllText(r.JournalPath, "MOCK accepted original journal; not native RCT2 bytes");
                ApplyFailure?.Invoke(); if (!ApplyRefused) { Repaired = true; Basis.Xid = "8"; }
            }
            var code = r.Approval is null ? Repaired ? "RepairHealthyNoFinding" : Unsupported == "native-refused" ? "RepairRefused" : "RepairNeedsConfirmation" : ApplyRefused ? "RepairRefused" : "RepairedAndVerified";
            var exit = code == "RepairNeedsConfirmation" ? 3 : code == "RepairRefused" ? 4 : 0;
            var report = JsonSerializer.SerializeToElement(new { format = "apfs-access-repair", version = 2, code,
                source = new { identity = Source, sha256 = Sha }, plan = new { expectedCount = Count }, applied = r.Approval is not null,
                replayed = Replay, postVerify = r.Approval is null ? null : new { outcome = 1, findings = 0 } });
            return Task.FromResult(new ImageRepairNativeResult(code, exit, Source, Sha, Replay ? null : Count,
                r.Approval is not null && Replay, r.Approval is not null && !ApplyRefused, report));
        }
        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        {
            LiveCalls++; Events.Add("live");
            if (LiveFailure == "owner") Mounts[0] = Mounts[0] with { HostProcessId = Mounts[0].HostProcessId + 1 };
            if (LiveFailure == "pid-reuse") Mounts[0] = Mounts[0] with { HostProcessCreationTimeFileTimeUtc = Mounts[0].HostProcessCreationTimeFileTimeUtc + 1 };
            AfterLive?.Invoke();
            var json = LiveVerificationFixture.Report(scope, LiveFailure == "findings");
            json["selected"]!["volumeSuperblockXid"] = scope.CheckpointXid;
            json["repair"]!["planId"] = LiveVerificationFixture.PlanId(json);
            return Task.FromResult(new LiveVolumeVerificationResult(true, "VolumeVerificationReport",
                LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(json))));
        }
    }
}
