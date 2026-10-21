using System.Text;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class ManagedParityWorkflowTests
{
    private static EncryptedImageProfile Profile => new(@"D:\parity.apfs", "windows-file:1:2:4096:4:scope:0:4096", 0, 4096,
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 12, 8, 1, 8, 2, 8,
        "33333333-3333-3333-3333-333333333333", "includes-header");

    private static DriveDashboardRow Row(StatusChangedPayload status) =>
        Assert.Single(TopologyDashboard.Project(status), n => n.Row is not null).Row!;

    private static OperationResultPayload Reply(ControlOperationRequestPayload r, bool mounted = true)
    {
        var status = r.Command switch {
            ApfsControlCommands.RegisterImage => "locked",
            ApfsControlCommands.SnapshotList => "snapshot-inventory",
            ApfsControlCommands.SnapshotCreate => "snapshot-created",
            ApfsControlCommands.SnapshotDelete => "snapshot-deleted",
            ApfsControlCommands.SnapshotRecover => "snapshot-recovered",
            ApfsControlCommands.Mount => "mounted",
            ApfsControlCommands.Eject => "absent",
            _ => throw new InvalidOperationException(r.Command) };
        var inventory = !mounted ? WindowsSurfaceFixture.SnapshotInventory() :
            new LiveSnapshotInventory(WindowsSurfaceFixture.Hex, WindowsSurfaceFixture.VolumeHex, "101", "90", "0", "100000",
                [new("21", "0", "backup", "249", "17", "230", "8293", "8", "250")]).ToJson();
        var result = new OperationResultPayload(r.OperationId, r.Command, r.Target, ApfsOperationFingerprint.Compute(r),
            ApfsOperationStates.Succeeded, "ok", true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
            FinalStatus: status, RequestedMode: r.RequestedMode, EffectiveMode: r.RequestedMode,
            MountProof: r.Command == ApfsControlCommands.Mount ? "present" :
                r.Command == ApfsControlCommands.Eject || !mounted || r.Command == ApfsControlCommands.RegisterImage ? "absent" : "present",
            OwnershipProof: r.Command == ApfsControlCommands.Mount ? "not-applicable" : "proven",
            DurabilityProof: r.Command == ApfsControlCommands.Eject ? "proven" : "not-applicable", ExpiresAtUtc: r.ExpiresAtUtc,
            EncryptionState: r.Command == ApfsControlCommands.RegisterImage ? EncryptedVolumeState.Locked : null,
            SnapshotName: r.SnapshotName, SnapshotIdentity: r.SnapshotIdentity,
            SnapshotInventory: r.Command == ApfsControlCommands.SnapshotList ? inventory : null);
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, r.OperationId, 2));
        Assert.True(validation.IsValid, validation.Diagnostic);
        // Exercise the actual public wire representation rather than object reference identity.
        return JsonSerializer.Deserialize<OperationResultPayload>(JsonSerializer.Serialize(result))!;
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task RegistrationReviewsExactProfileAndDispatchesOnlyWhenApproved(bool approve)
    {
        using var file = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(Profile));
        var profile = EncryptedImageRegistration.ReadProfile(file);
        var calls = new List<ControlOperationRequestPayload>();
        var result = await EncryptedImageRegistration.RunAsync(profile, text => {
            Assert.Contains(Profile.ImagePath, text); Assert.Contains(Profile.VolumeUuid, text); return approve;
        }, request => {
            calls.Add(request);
            Assert.Equal(SelectedControlTarget.ForImage(Profile), request.Target);
            Assert.Equal(ApfsControlCommands.RegisterImage, request.Command);
            Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
            return Task.FromResult(Reply(request));
        });
        Assert.Equal(approve ? 1 : 0, calls.Count);
        Assert.Equal(approve, result is not null);
    }

    [Theory]
    [InlineData("oversize")] [InlineData("duplicate")] [InlineData("secret")] [InlineData("invalid")] [InlineData("array")]
    public void RegistrationRejectsUnboundedOrNonProfileInput(string kind)
    {
        var json = JsonSerializer.Serialize(Profile);
        json = kind switch {
            "oversize" => json + new string(' ', 8193),
            "duplicate" => json.Insert(1, "\"imagePath\":\"D:\\\\other.apfs\","),
            "secret" => json.Insert(1, "\"password\":\"not-a-public-selector\","),
            "array" => "[]",
            _ => "{}" };
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(json));
        Assert.Throws<InvalidDataException>(() => EncryptedImageRegistration.ReadProfile(source));
    }

    [Theory]
    [InlineData("transport")] [InlineData("failed")] [InlineData("mismatch")] [InlineData("pending")]
    public async Task RegistrationNeverClaimsSuccessWithoutMatchingTerminalServiceEvidence(string kind)
    {
        await Assert.ThrowsAnyAsync<IOException>(() => EncryptedImageRegistration.RunAsync(Profile, _ => true, r => {
            if (kind == "transport") throw new IOException("Disconnected");
            var reply = Reply(r);
            return Task.FromResult(kind switch {
                "failed" => reply with { Success = false, State = ApfsOperationStates.Failed, Code = ApfsOperationCodes.OperationFailed },
                "pending" => reply with { State = ApfsOperationStates.InProgress },
                _ => reply with { OperationId = Guid.NewGuid().ToString("D") } });
        }));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task SnapshotRefreshBindsInventoryAndFailedRefreshClearsOldSelection(bool mounted)
    {
        var status = WindowsSurfaceFixture.Status(mounted); var fail = false;
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r =>
            fail ? throw new IOException("Service closed") : Task.FromResult(Reply(r, mounted)));
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        Assert.Equal("backup", Assert.Single(workflow.Inventory!.Entries).Name);
        fail = true;
        await Assert.ThrowsAsync<IOException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotList));
        Assert.Null(workflow.Inventory);
    }

    [Theory]
    [InlineData(ApfsControlCommands.SnapshotCreate)] [InlineData(ApfsControlCommands.SnapshotDelete)]
    [InlineData(ApfsControlCommands.SnapshotRecover)]
    public async Task SnapshotMutationsDispatchExactCurrentIdentityAndInvalidateInventory(string command)
    {
        var status = WindowsSurfaceFixture.Status(true); var requests = new List<ControlOperationRequestPayload>();
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r => { requests.Add(r); return Task.FromResult(Reply(r)); });
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        var entry = Assert.Single(workflow.Inventory!.Entries);
        await workflow.RunAsync(command, command == ApfsControlCommands.SnapshotCreate ? "new backup" : null,
            command == ApfsControlCommands.SnapshotDelete ? entry : null);
        Assert.Equal(2, requests.Count);
        Assert.Equal(command, requests[1].Command);
        Assert.Equal(requests[0].Target, requests[1].Target);
        if (command == ApfsControlCommands.SnapshotDelete) Assert.Equal(entry.DeleteIdentity, requests[1].SnapshotIdentity);
        Assert.Null(workflow.Inventory);
    }

    [Theory]
    [InlineData("pid", true)] [InlineData("creation", true)] [InlineData("capability", true)] [InlineData("unmount", true)]
    [InlineData("pid", false)] [InlineData("creation", false)] [InlineData("capability", false)] [InlineData("unmount", false)]
    public async Task SnapshotOwnerChangeCannotPublishOrReuseOldInventory(string change, bool duringRead)
    {
        var status = WindowsSurfaceFixture.Status(true); var calls = 0;
        void Change() => status = status with { MountedVolumes = change switch {
            "pid" => [status.MountedVolumes![0] with { HostProcessId = 999 }],
            "creation" => [status.MountedVolumes![0] with { HostProcessCreationTimeFileTimeUtc = 999 }],
            "capability" => [status.MountedVolumes![0] with { SnapshotMutationSupported = false }],
            _ => [] } };
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r => {
            calls++; if (duringRead) Change(); return Task.FromResult(Reply(r));
        });
        if (duringRead)
            await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotList));
        else
        {
            await workflow.RunAsync(ApfsControlCommands.SnapshotList);
            var entry = Assert.Single(workflow.Inventory!.Entries);
            Change();
            await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotDelete, entry: entry));
        }
        Assert.Null(workflow.Inventory); Assert.Equal(1, calls);
    }

    [Fact]
    public async Task SnapshotDeleteRequiresAnEntryFromTheLatestSuccessfulRefresh()
    {
        var status = WindowsSurfaceFixture.Status(true); var calls = 0;
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r => { calls++; return Task.FromResult(Reply(r)); });
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        var old = Assert.Single(workflow.Inventory!.Entries);
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotDelete, entry: old));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task SnapshotPendingReadPreventsSecondDispatchAndCannotCacheReplyAfterDisconnect()
    {
        var status = WindowsSurfaceFixture.Status(true); var selected = Row(status);
        var pending = new TaskCompletionSource<OperationResultPayload>(); ControlOperationRequestPayload? request = null;
        var workflow = new VolumeSnapshotWorkflow(selected, () => status, r => { request = r; return pending.Task; });
        var first = workflow.RunAsync(ApfsControlCommands.SnapshotList);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotCreate, "second"));
        status = status with { ConnectedInventory = [], MountedVolumes = [] };
        pending.SetResult(Reply(request!));
        await Assert.ThrowsAsync<InvalidOperationException>(() => first);
        Assert.Null(workflow.Inventory);
    }

    [Theory]
    [InlineData("missing")] [InlineData("other-volume")] [InlineData("fingerprint")]
    public async Task SnapshotInventoryNeedsMatchingCompleteServiceEvidence(string kind)
    {
        var status = WindowsSurfaceFixture.Status();
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r => {
            var reply = Reply(r, false);
            return Task.FromResult(kind switch {
                "missing" => reply with { SnapshotInventory = null },
                "other-volume" => reply with { SnapshotInventory = WindowsSurfaceFixture.SnapshotInventory(new string('c', 32)) },
                _ => reply with { Fingerprint = new string('f', 64) } });
        });
        if (kind == "other-volume")
            await Assert.ThrowsAsync<InvalidDataException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotList));
        else
            await Assert.ThrowsAnyAsync<IOException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotList));
        Assert.Null(workflow.Inventory);
    }

    [Theory]
    [InlineData(ApfsControlCommands.Mount)] [InlineData(ApfsControlCommands.Eject)]
    public async Task SnapshotMountTransitionsUseCurrentPublicRouteAndDiscardInventory(string command)
    {
        var mounted = command == ApfsControlCommands.Eject;
        var status = WindowsSurfaceFixture.Status(mounted); var calls = new List<ControlOperationRequestPayload>();
        var workflow = new VolumeSnapshotWorkflow(Row(status), () => status, r => { calls.Add(r); return Task.FromResult(Reply(r, mounted)); });
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        await workflow.RunAsync(command);
        Assert.Equal(command, calls[1].Command);
        Assert.Null(workflow.Inventory);
    }

    private static StatusChangedPayload ManagementStatus() => WindowsSurfaceFixture.Status() with {
        VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
    private static ControlOperationRequestPayload CreatePlan() => new(Guid.NewGuid().ToString("D"),
        ApfsControlCommands.VolumeCreatePlan, new(WindowsSurfaceFixture.Image, "", ContainerUuid: WindowsSurfaceFixture.Hex),
        ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: new("create", "Data", "4097", "1", false));

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task TopologyConfirmationUsesCurrentCapabilityAndExactServiceToken(bool approve)
    {
        var status = ManagementStatus(); var requests = new List<ControlOperationRequestPayload>();
        await VolumeTopologyWorkflow.RunAsync(CreatePlan(), r => {
            requests.Add(r); return Task.FromResult(VolumeTopologyWorkflowTests.Prepared(r));
        }, _ => approve, () => status);
        Assert.Equal(2, requests.Count);
        Assert.Equal(approve ? ApfsControlCommands.VolumeManagementApply : ApfsControlCommands.VolumeManagementCancel, requests[1].Command);
        Assert.Equal(new string('a', 64), requests[1].VolumeManagement!.Token);
    }

    [Theory]
    [InlineData("capability")] [InlineData("checkpoint")] [InlineData("mounted")] [InlineData("disconnected")]
    public async Task TopologyPlanCannotApplyAfterSelectionOrCapabilityChangesAtConfirmation(string change)
    {
        var status = ManagementStatus(); var requests = new List<ControlOperationRequestPayload>();
        await Assert.ThrowsAsync<InvalidOperationException>(() => VolumeTopologyWorkflow.RunAsync(CreatePlan(), r => {
            requests.Add(r); return Task.FromResult(VolumeTopologyWorkflowTests.Prepared(r));
        }, _ => {
            var d = status.ConnectedInventory![0];
            status = change switch {
                "capability" => status with { ImageManagementMutationsEnabled = false },
                "mounted" => status with { MountedVolumes = WindowsSurfaceFixture.Status(true).MountedVolumes },
                "checkpoint" => status with { ConnectedInventory = [d with { Topology = d.Topology! with {
                    Snapshot = d.Topology.Snapshot with { Containers = [d.Topology.Snapshot.Containers[0] with { CheckpointXid = "91" }] } } }] },
                _ => status with { ConnectedInventory = [], MountedVolumes = [] } };
            return true;
        }, () => status));
        Assert.Equal(2, requests.Count);
        Assert.Equal(ApfsControlCommands.VolumeManagementCancel, requests[1].Command);
        Assert.Equal(new string('a', 64), requests[1].VolumeManagement!.Token);
        Assert.DoesNotContain(requests, r => r.Command == ApfsControlCommands.VolumeManagementApply);
    }

    [Fact]
    public async Task StaleTopologyPlanReportsUnconfirmedCancellationWithoutApplying()
    {
        var status = ManagementStatus(); var requests = new List<ControlOperationRequestPayload>();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => VolumeTopologyWorkflow.RunAsync(CreatePlan(), r => {
            requests.Add(r);
            if (r.Command == ApfsControlCommands.VolumeManagementCancel) throw new IOException("Service closed");
            return Task.FromResult(VolumeTopologyWorkflowTests.Prepared(r));
        }, _ => { status = status with { ImageManagementMutationsEnabled = false }; return true; }, () => status));
        Assert.Contains("Cancellation was not confirmed", error.Message);
        Assert.Equal(2, requests.Count);
        Assert.DoesNotContain(requests, r => r.Command == ApfsControlCommands.VolumeManagementApply);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task TopologyServiceFailureCannotBecomeSuccess(bool afterConfirmation)
    {
        var status = ManagementStatus(); var calls = 0; var confirmations = 0;
        await Assert.ThrowsAsync<IOException>(() => VolumeTopologyWorkflow.RunAsync(CreatePlan(), r => {
            calls++;
            if (!afterConfirmation || calls == 2) throw new IOException("Service closed");
            return Task.FromResult(VolumeTopologyWorkflowTests.Prepared(r));
        }, _ => { confirmations++; return true; }, () => status));
        Assert.Equal(afterConfirmation ? 2 : 1, calls);
        Assert.Equal(afterConfirmation ? 1 : 0, confirmations);
    }

    [Fact]
    public async Task TopologyUnchangedObservationSurvivesNewPollGeneration()
    {
        var status = ManagementStatus(); var calls = 0;
        var result = await VolumeTopologyWorkflow.RunAsync(CreatePlan(), r => {
            calls++; return Task.FromResult(VolumeTopologyWorkflowTests.Prepared(r));
        }, _ => { status = status with { InventoryGeneration = 2,
            ConnectedInventory = [status.ConnectedInventory![0] with { Topology = status.ConnectedInventory[0].Topology! with { Generation = 2 } }] };
            return true;
        }, () => status);
        Assert.True(result.Success); Assert.Equal(2, calls);
    }
}
