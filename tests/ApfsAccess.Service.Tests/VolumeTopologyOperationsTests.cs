using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [Theory]
    [InlineData("create", "apply")] [InlineData("delete", "apply")]
    [InlineData("create", "cancel")] [InlineData("delete", "cancel")]
    [InlineData("create", "recover")] [InlineData("delete", "recover")]
    public async Task VolumeTopology_PhysicalTopologyRetainsTypedOriginalThroughConfirmationAndRestart(string kind, string completion)
    {
        var b = new TopologyBackend { Size = 134217728, Offset = 1048576,
            PhysicalBindingHex = ApfsAccess.TestFixtures.PhysicalTopologyBindingFixture.Encode() };
        var request = b.Plan(kind); VolumeTopologyRequest original;
        using (var worker = PhysicalTopologyWorker(b, true))
        {
            var executor = new AgentControlCommandExecutor(worker); var plan = await executor.ExecuteAsync(request, default);
            Assert.True(plan.Success, plan.Diagnostic); original = Assert.Single(b.Calls).Request;
            Assert.Null(original.ImageOptions); Assert.Equal(b.PhysicalBindingHex, original.PhysicalBindingHex);
            Assert.Equal("1048576", original.OffsetBytes); Assert.Equal(VolumePhysicalBinding.Parse(b.PhysicalBindingHex).SourceIdentity, original.SourceIdentity);
            Assert.Equal(b.Image, original.Image); Assert.Equal(kind == "create" ? "20480" : "101", original.VolumeOid);
            if (kind == "create") { Assert.NotEqual(b.Uuid, original.VolumeUuid); Assert.True(Guid.TryParseExact(original.VolumeUuid, "N", out _)); }
            else Assert.Equal(b.Uuid, original.VolumeUuid);
            Assert.Equal(JsonSerializer.Serialize(b.Read().NativeRequest), JsonSerializer.Serialize(original));
            if (completion == "recover")
            {
                b.FailApply = true;
                Assert.False((await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default)).Success);
                Assert.Equal("applying", b.Read().State);
            }
            else
            {
                var result = await executor.ExecuteAsync(b.Confirm(request, completion == "apply" ?
                    ApfsControlCommands.VolumeManagementApply : ApfsControlCommands.VolumeManagementCancel), default);
                Assert.True(result.Success, result.Diagnostic);
                Assert.Equal(completion == "apply" ? "committed" : "cancelled", b.Read().State);
            }
        }
        if (completion == "recover")
        {
            b.RecoverCommitted = true;
            using var restarted = PhysicalTopologyWorker(b, false);
            await restarted.RefreshAsync(false, default);
            Assert.Equal(VolumeTopologyMode.Recover, b.Calls.Last().Mode); Assert.Equal("committed", b.Read().State);
        }
        Assert.All(b.Calls, call => Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(call.Request)));
        Assert.Equal(0, b.MountCalls);
    }

    [Theory]
    [InlineData("create")] [InlineData("delete")]
    public async Task VolumeTopology_PhysicalTopologyStillRequiresOptInAndBoundedWindow(string kind)
    {
        var b = new TopologyBackend { Size = 134217728, Offset = 1048576,
            PhysicalBindingHex = ApfsAccess.TestFixtures.PhysicalTopologyBindingFixture.Encode() };
        using (var disabled = PhysicalTopologyWorker(b, false))
        {
            Assert.False((await new AgentControlCommandExecutor(disabled).ExecuteAsync(b.Plan(kind), default)).Success);
            Assert.Empty(b.Calls);
        }
        b.Size = 536870912; b.PhysicalBindingHex = ApfsAccess.TestFixtures.PhysicalTopologyBindingFixture.Encode(536870912);
        using var large = PhysicalTopologyWorker(b, true);
        Assert.False((await new AgentControlCommandExecutor(large).ExecuteAsync(b.Plan(kind), default)).Success);
        Assert.Empty(b.Calls);
    }

    // The private integration gate supplies this vector from the actual native
    // completed-frame receipt, rather than fabricating a physical capability.
    public async Task VolumeTopology_PhysicalFormatPersistsNativeBindingAndRejectsOtherOperations(string kind, string bindingHex, bool refuseApply)
    {
        var b = new TopologyBackend { Size = 536801280, Offset = 1048576, PhysicalBindingHex = bindingHex, RefuseApply = refuseApply };
        var request = b.Plan("delete") with { Command = ApfsControlCommands.VolumeFormatPlan,
            VolumeManagement = new(kind, Name: "Physical", CaseSensitive: false) };
        using (var disabled = PhysicalTopologyWorker(b, false))
        {
            Assert.False((await new AgentControlCommandExecutor(disabled).ExecuteAsync(request, default)).Success);
            Assert.Empty(b.Calls);
        }
        using var worker = PhysicalTopologyWorker(b, true);
        var executor = new AgentControlCommandExecutor(worker);
        var prepared = await executor.ExecuteAsync(request, default);
        Assert.True(prepared.Success, prepared.Diagnostic);
        var original = Assert.Single(b.Calls).Request;
        Assert.Equal(bindingHex, original.PhysicalBindingHex); Assert.Equal("1048576", original.OffsetBytes);
        Assert.Equal("536801280", original.ImageOptions!.ExpectedBytes); Assert.Equal(original.ImageOptions.ExpectedBytes, original.ImageOptions.TargetBytes);
        var binding = VolumePhysicalBinding.Parse(bindingHex);
        Assert.Equal(ApfsAccess.Backend.Native.NativeApfsVolumeImageManagement.DestinationWal(b.Root,
            original.ImageOptions.NewContainerUuid!, binding.PartitionGuid), original.ImageOptions.NewVolumeWal);
        var result = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default);
        Assert.Equal(!refuseApply, result.Success); Assert.Equal(2, b.Calls.Count);
        Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(b.Calls[1].Request));
        Assert.Equal(refuseApply ? "recovery-required" : "committed", b.Read().State); Assert.Equal(0, b.MountCalls);
        foreach (var operation in new[] { "create", "delete" })
        {
            var other = new TopologyBackend { Size = b.Size, Offset = b.Offset, PhysicalBindingHex = bindingHex };
            using var blocked = PhysicalTopologyWorker(other, true);
            var unsupported = other.Plan(operation == "create" ? "create" : "delete");
            Assert.False((await new AgentControlCommandExecutor(blocked).ExecuteAsync(unsupported, default)).Success);
            Assert.Empty(other.Calls);
        }
    }
    public async Task VolumeTopology_PhysicalResizePersistsWholePartitionAuthority(string kind,string bindingHex,bool refuseApply)
    {
        var b=new TopologyBackend{Size=536801280,Offset=1048576,PhysicalBindingHex=bindingHex,RefuseApply=refuseApply};
        var target=kind=="grow"?"671035392":"402550784";
        var request=b.Plan("delete") with{Command=ApfsControlCommands.VolumeResizePlan,VolumeManagement=new(kind,TargetBytes:target)};
        using var worker=PhysicalTopologyWorker(b,true);var executor=new AgentControlCommandExecutor(worker);
        var prepared=await executor.ExecuteAsync(request,default);Assert.True(prepared.Success,prepared.Diagnostic);
        var original=Assert.Single(b.Calls).Request;Assert.Equal(bindingHex,original.PhysicalBindingHex);
        Assert.Equal("1048576",original.OffsetBytes);Assert.Equal("536801280",original.ImageOptions!.ExpectedBytes);Assert.Equal(target,original.ImageOptions.TargetBytes);
        Assert.Null(original.ImageOptions.NewContainerUuid);Assert.Null(original.ImageOptions.NewVolumeUuid);Assert.Null(original.ImageOptions.NewVolumeWal);
        var applied=await executor.ExecuteAsync(b.Confirm(request,ApfsControlCommands.VolumeManagementApply),default);
        Assert.Equal(!refuseApply,applied.Success);Assert.Equal(2,b.Calls.Count);Assert.Equal(JsonSerializer.Serialize(original),JsonSerializer.Serialize(b.Calls[1].Request));
        Assert.Equal(refuseApply?"recovery-required":"committed",b.Read().State);Assert.Equal(0,b.MountCalls);
    }

    [Fact]
    public async Task VolumeTopology_MalformedNativeObservationDoesNotAdvertiseAvailabilityOrStartMutation()
    {
        var b = new TopologyBackend { BadObservation = true };
        using var worker = CreateWorker(b, b.Root, true, autoMountEnabled: false, autoRemount: false);
        await (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(worker, [CancellationToken.None])!;
        Assert.True(b.ObservationCalls > 0); Assert.Empty(b.Calls); Assert.Equal(0, b.MountCalls);
        var ready = (IReadOnlyList<string>)typeof(ApfsMountWorker).GetField("_volumeManagementReadyImages",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(worker)!;
        Assert.Empty(ready);
    }

    private static ApfsMountWorker PhysicalTopologyWorker(TopologyBackend b, bool enabled) => new(
        Microsoft.Extensions.Logging.Abstractions.NullLogger<ApfsMountWorker>.Instance, b, new FixedMountPolicy(), new RuntimeStatusPublisher(),
        new FixedOptionsMonitor(new ServiceHostOptions { AutoMountEnabled = false, NativeAutoRemountOnReconnect = false,
            EnableNativeWrite = true, WriteBackendMode = "Native", ManagementJournalRoot = b.Root,
            EnablePhysicalVolumeManagement = enabled, EnableImageResizeFormat = true, EnableImageManagementMutations = true }));

    [Theory]
    [InlineData("format", false)] [InlineData("erase", false)]
    [InlineData("format", true)] [InlineData("erase", true)]
    public async Task VolumeTopology_StreamedImageReachesPrepareAndApplyWithExactSavedRequest(string kind, bool refuseApply)
    {
        var b = new TopologyBackend { Size = 536870912, RefuseApply = refuseApply }; var basis = b.Plan("delete");
        var request = basis with { Command = ApfsControlCommands.VolumeFormatPlan, VolumeManagement = new(kind, Name: "Large", CaseSensitive: false) };
        using var worker = CreateWorker(b, b.Root, true); var executor = new AgentControlCommandExecutor(worker);
        var prepared = await executor.ExecuteAsync(request, default); Assert.True(prepared.Success, prepared.Diagnostic);
        var original = Assert.Single(b.Calls).Request;
        Assert.Equal("536870912", original.ImageOptions!.ExpectedBytes); Assert.Equal("536870912", original.ImageOptions.TargetBytes);
        var result = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default);
        Assert.Equal(!refuseApply, result.Success); Assert.Equal(2, b.Calls.Count);
        Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(b.Calls[1].Request));
        Assert.Equal(refuseApply ? "recovery-required" : "committed", b.Read().State);
        Assert.Equal(0, b.MountCalls);
    }
    [Theory]
    [InlineData("create", 0)] [InlineData("delete", 0)]
    [InlineData("format", 4096)] [InlineData("erase", 4096)]
    public async Task VolumeTopology_StreamedImageDoesNotWidenCreateDeleteOrPartitionAdmission(string kind, long offset)
    {
        var b = new TopologyBackend { Size = 536870912, Offset = offset }; var request = b.Plan(kind is "create" ? "create" : "delete");
        if (kind is "format" or "erase") request = request with { Command = ApfsControlCommands.VolumeFormatPlan,
            VolumeManagement = new(kind, Name: "Large", CaseSensitive: false) };
        using var worker = CreateWorker(b, b.Root, true);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(request, default);
        Assert.False(result.Success); Assert.Empty(b.Calls); Assert.Empty(Directory.GetFiles(b.Root, "managed-volume-*.json"));
    }
    [Theory]
    [InlineData("grow")] [InlineData("shrink")] [InlineData("format")] [InlineData("erase")]
    public async Task VolumeTopology_LostPreparedReplyRestartsFromSavedRequestWithoutTokenOrMutationOptIn(string kind)
    {
        var b = new TopologyBackend { FailPrepare = true, RequireTerminalBeforeMount = true }; var basis = b.Plan("delete");
        var format = kind is "format" or "erase";
        var request = basis with { Command = format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            VolumeManagement = format ? new(kind, Name: "Fresh", CaseSensitive: false) : new(kind, TargetBytes: kind == "grow" ? "3145728" : "1048576") };
        using (var worker = CreateWorker(b, b.Root, true))
        {
            var refused = await new AgentControlCommandExecutor(worker).ExecuteAsync(request, default);
            Assert.False(refused.Success); Assert.Equal("preparing", b.Read().State); Assert.Null(b.Read().ConfirmationToken);
            Assert.False((await worker.EnsureMountedAsync(b.VolumeId, default)).Success); Assert.Equal(0, b.MountCalls);
        }
        var original = b.Read().NativeRequest;
        b.RecoverCancelled = true;
        using var restarted = CreateWorker(b, b.Root, false, false);
        await restarted.RefreshAsync(false, default);
        var recovery = b.Calls.Last(); Assert.Equal(VolumeTopologyMode.Recover, recovery.Mode);
        Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(recovery.Request));
        Assert.Equal("cancelled", b.Read().State);
    }
    [Theory]
    [InlineData("grow")] [InlineData("shrink")] [InlineData("format")] [InlineData("erase")]
    public async Task VolumeTopology_ImagePlansPersistOriginalGeometryAndRestartRecoveryUsesSameRequest(string kind)
    {
        var b = new TopologyBackend(); var basis = b.Plan("delete");
        var format = kind is "format" or "erase";
        var request = basis with { Command = format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            VolumeManagement = format ? new(kind, Name: "Fresh", CaseSensitive: false) : new(kind, TargetBytes: kind == "grow" ? "3145728" : "1048576") };
        using (var disabled = CreateWorker(b, b.Root))
        { var refused = await new AgentControlCommandExecutor(disabled).ExecuteAsync(request, default); Assert.False(refused.Success); Assert.Contains("ImageResizeFormatDisabled", refused.Diagnostic); Assert.Empty(b.Calls); }
        using (var worker = CreateWorker(b, b.Root, true))
        {
            var executor = new AgentControlCommandExecutor(worker); var plan = await executor.ExecuteAsync(request, default);
            Assert.True(plan.Success, plan.Diagnostic); AssertWireResult(plan);
            var original = Assert.Single(b.Calls).Request; Assert.Equal("2097152", original.ImageOptions!.ExpectedBytes);
            if (format) { Assert.NotEqual(b.Container, original.ImageOptions.NewContainerUuid); Assert.NotEqual(b.Uuid, original.ImageOptions.NewVolumeUuid);
                Assert.EndsWith("write-ahead.wal", original.ImageOptions.NewVolumeWal); }
            b.FailApply = true; Assert.False((await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default)).Success);
            Assert.Equal("applying", b.Read().State);
        }
        var saved = b.Read().NativeRequest; b.RecoverCommitted = true;
        using var restarted = CreateWorker(b, b.Root);
        await restarted.RefreshAsync(false, default);
        Assert.Equal(VolumeTopologyMode.Recover, b.Calls.Last().Mode);
        Assert.Equal(JsonSerializer.Serialize(saved), JsonSerializer.Serialize(b.Calls.Last().Request)); Assert.Equal("committed", b.Read().State);
    }
    [Fact]
    public async Task VolumeTopology_CreateBindsGeneratedUuidNativeOidOptionsAndPersistsBeforeApply()
    {
        var b = new TopologyBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker);
        var request = b.Plan("create");
        var plan = await executor.ExecuteAsync(request, default);
        Assert.True(plan.Success, plan.Diagnostic); AssertWireResult(plan);
        var prepare = Assert.Single(b.Calls);
        Assert.Equal("20480", prepare.Request.VolumeOid); Assert.NotEqual(b.Uuid, prepare.Request.VolumeUuid);
        Assert.True(Guid.TryParseExact(prepare.Request.VolumeUuid, "N", out var uuid)); Assert.NotEqual(Guid.Empty, uuid);
        Assert.Equal("2", prepare.Request.QuotaBlocks); Assert.Equal("1", prepare.Request.ReserveBlocks);
        var saved = b.Read(); Assert.Equal("prepared", saved.State); Assert.Equal(TopologyBackend.Token, saved.ConfirmationToken);
        var apply = b.Confirm(request, ApfsControlCommands.VolumeManagementApply);
        var complete = await executor.ExecuteAsync(apply, default);
        Assert.True(complete.Success, complete.Diagnostic); AssertWireResult(complete);
        Assert.Equal("committed", b.Read().State);
        Assert.Equal(JsonSerializer.Serialize(prepare.Request), JsonSerializer.Serialize(b.Calls[1].Request));
        var replay = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default);
        Assert.False(replay.Success); Assert.Equal(2, b.Calls.Count);
    }

    [Fact]
    public async Task VolumeTopology_ChangedOptionsIdentityOrUnknownTokenCannotConsumePlan()
    {
        var b = new TopologyBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Plan("create");
        Assert.True((await executor.ExecuteAsync(request, default)).Success);
        var apply = b.Confirm(request, ApfsControlCommands.VolumeManagementApply);
        foreach (var wrong in new[] { apply with { VolumeManagement = apply.VolumeManagement! with { Name = "Changed" } },
            apply with { Target = apply.Target! with { ContainerUuid = new string('d', 32) } },
            apply with { VolumeManagement = apply.VolumeManagement! with { Token = new string('b', 64) } } })
            Assert.False((await executor.ExecuteAsync(wrong, default)).Success);
        Assert.Single(b.Calls); Assert.Equal("prepared", b.Read().State);
        Assert.True((await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementCancel), default)).Success);
        Assert.Equal("cancelled", b.Read().State);
    }

    [Fact]
    public async Task VolumeTopology_ChangedCheckpointRequiresCancelWithOriginalRequest()
    {
        var b = new TopologyBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Plan("delete");
        var plan = await executor.ExecuteAsync(request, default); Assert.True(plan.Success, plan.Diagnostic);
        b.Xid = "8";
        var refused = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default);
        Assert.False(refused.Success); Assert.Single(b.Calls); Assert.Equal("prepared", b.Read().State);
        Assert.True((await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementCancel), default)).Success);
        Assert.Equal("7", b.Calls[1].Request.PreXid);
        Assert.Equal("101", b.Calls[1].Request.VolumeOid); Assert.Equal(b.Uuid, b.Calls[1].Request.VolumeUuid);
    }

    [Fact]
    public async Task VolumeTopology_RestartCancelsPreparedOriginalRequestAndBlocksMountUntilTerminal()
    {
        var b = new TopologyBackend(); var request = b.Plan("delete");
        using (var worker = CreateWorker(b, b.Root))
        {
            var plan = await new AgentControlCommandExecutor(worker).ExecuteAsync(request, default); Assert.True(plan.Success, plan.Diagnostic);
            var mount = await worker.EnsureMountedAsync(b.VolumeId, default);
            Assert.False(mount.Success); Assert.Equal(0, b.MountCalls);
        }
        var original = b.Read().NativeRequest;
        b.Xid = "8"; b.RecoverCommitted = true;
        using var restarted = CreateWorker(b, b.Root);
        await restarted.RefreshAsync(false, default);
        Assert.Equal(VolumeTopologyMode.Cancel, b.Calls[1].Mode); Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(b.Calls[1].Request));
        Assert.Equal("7", b.Calls[1].Request.PreXid); Assert.Equal("cancelled", b.Read().State);
    }

    [Fact]
    public async Task VolumeTopology_AcceptanceInterruptionRetainsTokenOriginalCensusAndRecoveryGuard()
    {
        var b = new TopologyBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Plan("delete");
        var plan = await executor.ExecuteAsync(request, default); Assert.True(plan.Success, plan.Diagnostic);
        b.FailApply = true;
        var result = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default);
        Assert.False(result.Success); Assert.Equal("applying", b.Read().State);
        Assert.Equal(TopologyBackend.Token, b.Read().ConfirmationToken);
        b.RecoverCommitted = false;
        var recovery = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementRecover), default);
        Assert.False(recovery.Success); Assert.Equal("recovery-required", b.Read().State);
        Assert.Equal(TopologyBackend.Token, b.Read().ConfirmationToken);
        b.RecoverCommitted = true;
        Assert.True((await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementRecover), default)).Success);
        Assert.Equal("committed", b.Read().State);
    }

    [Fact]
    public async Task VolumeTopology_SiblingOwnerOrIncompleteVerificationCannotPrepare()
    {
        foreach (var owner in new[] { false, true })
        {
            var b = new TopologyBackend { BadVerify = !owner };
            if (owner) b.Mounts.Add(new("sibling", "X:\\", MountAccessMode.ReadOnly, DeviceId: b.Image));
            using var worker = CreateWorker(b, b.Root);
            var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(b.Plan("delete"), default);
            Assert.False(result.Success); Assert.Empty(b.Calls); Assert.Empty(Directory.GetFiles(b.Root, "managed-volume-*.json"));
        }
    }

    [Fact]
    public async Task VolumeTopology_CorruptIntentPreservedAndMountRefused()
    {
        var b = new TopologyBackend(); var path = Path.Combine(b.Root, "managed-volume-" + Guid.NewGuid().ToString("D") + ".json");
        await File.WriteAllTextAsync(path, "{broken");
        using var worker = CreateWorker(b, b.Root);
        Assert.False((await worker.EnsureMountedAsync(b.VolumeId, default)).Success);
        Assert.Equal(0, b.MountCalls); Assert.Equal("{broken", await File.ReadAllTextAsync(path)); Assert.Empty(b.Calls);
    }

    [Fact]
    public async Task VolumeTopology_OwnPreparedPlanSurvivesRealPollWithoutAdvertisingAnotherPlan()
    {
        var b = new TopologyBackend();
        using var worker = CreateWorker(b, b.Root, true, true, false, false);
        var executor = new AgentControlCommandExecutor(worker);
        var request = b.Plan("create");
        Assert.True((await executor.ExecuteAsync(request, default)).Success);
        var original = JsonSerializer.Serialize(b.Read());
        await (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(worker, [CancellationToken.None])!;
        Assert.Equal(original, JsonSerializer.Serialize(b.Read()));
        var status = ((RuntimeStatusPublisher)typeof(ApfsMountWorker).GetField("_statusPublisher",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(worker)!).Latest;
        Assert.False(status.ManagementJournalRootInspected);
        Assert.Empty(status.VolumeManagementReadyImages!);
        var apply = b.Confirm(request, ApfsControlCommands.VolumeManagementApply);
        Assert.NotEqual(request.OperationId, apply.OperationId);
        Assert.True((await executor.ExecuteAsync(apply, default)).Success);
        Assert.Equal("committed", b.Read().State);
        Assert.Equal(2, b.Calls.Count);
        Assert.Equal(0, b.MountCalls);
    }

    [Fact]
    public async Task VolumeTopology_ForeignPendingIntentCannotUseOwnPreparedPlanException()
    {
        var b = new TopologyBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Plan("create");
        Assert.True((await executor.ExecuteAsync(request, default)).Success);
        var own = b.Read(); var foreignImage = Path.Combine(b.Root, "foreign.apfs");
        var foreign = own with {
            Original = own.Original with { OperationId = Guid.NewGuid().ToString("D"),
                Target = own.Original.Target! with { DeviceId = foreignImage } },
            NativeRequest = own.NativeRequest with { Image = foreignImage },
            ConfirmationToken = new string('c', 64)
        };
        using (var store = new VolumeManagementIntentStore(b.Root)) store.Save(foreign);
        var result = await executor.ExecuteAsync(b.Confirm(request, ApfsControlCommands.VolumeManagementApply), default);
        Assert.False(result.Success);
        Assert.Contains("Another original volume intent", result.Diagnostic);
        Assert.Single(b.Calls);
        using var preserved = new VolumeManagementIntentStore(b.Root);
        Assert.Equal(2, preserved.ReadAll().Count);
        Assert.All(preserved.ReadAll(), r => Assert.Equal("prepared", r.State));
        Assert.Equal(0, b.MountCalls);
    }

    [Fact]
    public async Task VolumeTopology_WrongTokenAndReusedPlanOperationIdCannotConsumeOwnPlan()
    {
        var b = new TopologyBackend(); using var worker = CreateWorker(b, b.Root);
        var executor = new AgentControlCommandExecutor(worker); var request = b.Plan("create");
        var operations = new AgentControlOperationService(executor.ExecuteAsync, Path.Combine(b.Root, "operations"));
        Assert.True((await operations.ExecuteOrReplayAsync(request)).Success);
        var apply = b.Confirm(request, ApfsControlCommands.VolumeManagementApply);
        Assert.False((await operations.ExecuteOrReplayAsync(apply with { VolumeManagement = apply.VolumeManagement! with { Token = new string('c', 64) } })).Success);
        Assert.False((await operations.ExecuteOrReplayAsync(apply with { OperationId = request.OperationId })).Success);
        Assert.Single(b.Calls); Assert.Equal("prepared", b.Read().State);
        Assert.True((await operations.ExecuteOrReplayAsync(apply with { OperationId = Guid.NewGuid().ToString("D") })).Success);
        Assert.Equal("committed", b.Read().State);
    }

    private sealed class TopologyBackend : IApfsBackend, IVerifyBackend, IVolumeTopologyBackend
    {
        public const string Token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        public readonly string Root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT") ?? throw new InvalidOperationException("D test root required."), "topology-" + Guid.NewGuid().ToString("N"));
        public string Image => PhysicalBindingHex is null ? Path.Combine(Root, "image.apfs") : @"\\.\PhysicalDrive2";
        public string? PhysicalBindingHex;
        private string SourceWal => PhysicalBindingHex is null ? Path.Combine(Root, "101.wal") :
            ApfsAccess.Backend.Native.NativeRecoveryStorage.CanonicalWal(Root,
                ApfsAccess.Backend.Native.NativeApfsBackend.BuildRecoveryIdentityFromComponents(
                    VolumePhysicalBinding.Parse(PhysicalBindingHex).PartitionGuid, Container, 101, false)!);
        public string Uuid => new string('b', 32);
        public string Container => new string('a', 32);
        public string VolumeId => ApfsTopology.BuildVolumeId(Container, 101);
        public string Xid = "7";
        public bool FailApply, FailPrepare, RecoverCommitted, RecoverCancelled, RequireTerminalBeforeMount, BadVerify, RefuseApply;
        public long Size = 2097152, Offset;
        public int MountCalls, ObservationCalls;
        public bool BadObservation;
        public readonly List<MountedVolumeState> Mounts = [];
        public readonly List<(VolumeTopologyRequest Request, VolumeTopologyMode Mode)> Calls = [];
        public TopologyBackend() => Directory.CreateDirectory(Root);
        public DeviceInventory Inventory()
        {
            var cid = ApfsTopology.BuildContainerId(Container); var store = "apfs-store:image"; var disk = "apfs-disk:image";
            var v = new VolumeInfo(VolumeId, Image, "Main", true, SupportsNativeWrite: true, RecoveryIdentity: "native-source-test", CatalogVolumeId: VolumeId,
                CatalogContainerUuid: Container, CatalogVolumeUuid: Uuid, CatalogVolumeObjectId: 101,
                CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true);
            var physical = PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(PhysicalBindingHex);
            var topo = new ApfsTopologySnapshot([new(disk, Image, null, physical is null ? Size + Offset : (long)physical.DiskBytes)], [],
                [new(store, Container, "", cid, Offset, physical is null ? Size : (long)physical.PartitionLengthBytes,
                    BlockSizeBytes: physical is null ? null : 4096, TotalBlocks: physical is null ? null : (ulong)Size / 4096, DiskId: disk)],
                [new(cid, Container, 4096, [store], [VolumeId], false, Xid, [], [], [])],
                [new(VolumeId, Uuid, "101", cid, "Main", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", Xid)], []);
            return new(new(Image, "Image", true), [v], new(1, Image, [disk], topo));
        }
        public ControlOperationRequestPayload Plan(string kind)
        {
            var inventory = Inventory();
            return new(Guid.NewGuid().ToString("D"), kind == "create" ? ApfsControlCommands.VolumeCreatePlan : ApfsControlCommands.VolumeDeletePlan,
                kind == "create" ? new(Image, "", ContainerUuid: Container) : SelectedControlTarget.Create(inventory, inventory.Volumes[0]),
                ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: kind == "create" ? new("create", "New", "4097", "1", false) : new("delete"));
        }
        public ControlOperationRequestPayload Confirm(ControlOperationRequestPayload plan, string command) => new(Guid.NewGuid().ToString("D"), command, plan.Target,
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: plan.VolumeManagement! with { Token = Token });
        public VolumeManagementIntent Read() { using var s = new VolumeManagementIntentStore(Root); return Assert.Single(s.ReadAll()); }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInfo>>([Inventory().Device]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken token) => Task.FromResult(Inventory().Volumes);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInventory>>([Inventory()]);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            if (RequireTerminalBeforeMount) Assert.False(Read().Pending);
            MountCalls++; return Task.FromResult(new MountResult(false, "", "test mount stopped", MountAccessMode.ReadOnly));
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => throw new InvalidOperationException("Offline management never silently unmounts siblings.");
        public Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken token) => Task.FromResult(new ImageVerifyResult(true, BadVerify ? "Incomplete" : "Complete", BadVerify ? 1 : 0, BadVerify ? 1 : 0, null));
        public Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, CancellationToken token)
        {
            ++ObservationCalls;
            if (BadObservation) throw new InvalidDataException("Injected malformed native observation.");
            return Task.FromResult(new VolumeTopologyObservation(Image, Offset.ToString(), Size.ToString(),
                PhysicalBindingHex is null ? new string('a', 80) : VolumePhysicalBinding.Parse(PhysicalBindingHex).SourceIdentity,
                Container, Xid, "4096", "20480", Root, [new("101", Uuid, SourceWal)], PhysicalBindingHex));
        }
        public Task<VolumeTopologyResult> RunVolumeTopologyAsync(VolumeTopologyRequest r, VolumeTopologyMode mode, string? confirmation, CancellationToken token)
        {
            Calls.Add((r, mode)); var saved = Read();
            Assert.Equal(JsonSerializer.Serialize(r), JsonSerializer.Serialize(saved.NativeRequest)); // The original request precedes every keeper call.
            Assert.Equal(mode == VolumeTopologyMode.Prepare ? "preparing" : mode is VolumeTopologyMode.Recover or VolumeTopologyMode.Cancel ? saved.State : "applying", saved.State);
            if (mode is VolumeTopologyMode.Apply or VolumeTopologyMode.Cancel) Assert.Equal(Token, saved.ConfirmationToken);
            if (mode == VolumeTopologyMode.Prepare && FailPrepare) throw new IOException("Injected lost prepared helper reply.");
            if (mode == VolumeTopologyMode.Apply && FailApply) throw new IOException("Injected interruption after durable apply intent.");
            var outcome = mode switch { VolumeTopologyMode.Prepare => "prepared", VolumeTopologyMode.Cancel => "cancelled",
                VolumeTopologyMode.Recover => RecoverCancelled ? "cancelled" : RecoverCommitted ? "committed" : "recovery-required", _ => RefuseApply ? "refused" : "committed" };
            var report = JsonSerializer.SerializeToElement(new { schemaVersion = 1, operation = r.ImageOptions is null ? "volume-" + r.Operation : r.Operation, outcome, sourceIdentity = r.SourceIdentity,
                preXid = r.PreXid, postXid = outcome == "committed" ? "8" : "0", containerUuid = r.ContainerUuid, volumeUuid = r.VolumeUuid, volumeOid = r.VolumeOid,
                quotaBlocks = r.QuotaBlocks ?? "0", reserveBlocks = r.ReserveBlocks ?? "0", confirmationToken = outcome == "prepared" ? Token : "",
                expectedBytes = r.ImageOptions?.ExpectedBytes, targetBytes = r.ImageOptions?.TargetBytes,
                newContainerUuid = r.ImageOptions?.NewContainerUuid, newVolumeUuid = r.ImageOptions?.NewVolumeUuid,
                newVolumeOid = r.Operation is "format" or "erase" ? "1024" : "0" });
            return Task.FromResult(new VolumeTopologyResult(outcome, "", r.SourceIdentity, Path.Combine(Root, "native.vmt1"), r.PreXid,
                outcome == "committed" ? "8" : "0", "4096", outcome == "prepared" ? Token : "", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(), report));
        }
    }
}
