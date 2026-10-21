using System.Text.Json;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class VolumeTopologyWorkflowTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ConfirmationSendsExactApplyOrCancelsNativePlan(bool confirm)
    {
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeCreatePlan,
            new(WindowsSurfaceFixture.Image, "", ContainerUuid: WindowsSurfaceFixture.Hex), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: new("create", "Data", "4097", "1", false));
        var calls = new List<ControlOperationRequestPayload>();
        await VolumeTopologyWorkflow.RunAsync(request, r =>
        {
            calls.Add(r);
            return Task.FromResult(Prepared(r));
        }, text => { Assert.Contains("Object: 20480", text); Assert.Contains("Quota: 2 blocks", text); return confirm; });
        Assert.Equal(2, calls.Count);
        Assert.Equal(confirm ? ApfsControlCommands.VolumeManagementApply : ApfsControlCommands.VolumeManagementCancel, calls[1].Command);
        Assert.Equal(request.Target, calls[1].Target);
        Assert.Equal(request.VolumeManagement! with { Token = new string('a', 64) }, calls[1].VolumeManagement);
        Assert.NotEqual(request.OperationId, calls[1].OperationId);
    }
    [Fact]
    public async Task MalformedPlanCannotReachConfirmationOrApply()
    {
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeCreatePlan,
            new(WindowsSurfaceFixture.Image, "", ContainerUuid: WindowsSurfaceFixture.Hex), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: new("create", "Data", "0", "0", true));
        var calls = 0;
        await Assert.ThrowsAsync<IOException>(() => VolumeTopologyWorkflow.RunAsync(request, _ =>
        { calls++; return Task.FromResult(Prepared(request) with { Fingerprint = "changed" }); }, _ => throw new InvalidOperationException("Must never confirm.")));
        Assert.Equal(1, calls);
    }
    internal static OperationResultPayload Prepared(ControlOperationRequestPayload r) => new(r.OperationId, r.Command, r.Target,
        ApfsOperationFingerprint.Compute(r), ApfsOperationStates.Succeeded, "ok", true, DateTime.UtcNow,
        StartedAtUtc: DateTime.UtcNow, CompletedAtUtc: DateTime.UtcNow, ExpiresAtUtc: r.ExpiresAtUtc,
        FinalStatus: r.Command == ApfsControlCommands.VolumeManagementApply ? "volume-management-committed" :
            r.Command == ApfsControlCommands.VolumeManagementCancel ? "volume-management-cancelled" : "volume-management-prepared",
        MountProof: "absent", OwnershipProof: "proven",
        DurabilityProof: r.Command == ApfsControlCommands.VolumeManagementApply ? "proven" : "not-applicable",
        VolumeManagement: r.VolumeManagement, VolumeManagementReport: JsonSerializer.SerializeToElement(new
        {
            schemaVersion = 1, operation = "volume-create", outcome = r.Command == ApfsControlCommands.VolumeManagementApply ? "committed" :
                r.Command == ApfsControlCommands.VolumeManagementCancel ? "cancelled" : "prepared", sourceIdentity = new string('a', 80),
            preXid = "7", containerUuid = WindowsSurfaceFixture.Hex, volumeUuid = WindowsSurfaceFixture.VolumeHex, volumeOid = "20480",
            postXid = "8", quotaBlocks = "2", reserveBlocks = "1", confirmationToken = new string('a', 64)
        }));

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task PreparedTokenCanBeConfirmedAfterPollWithdrawsNewPlanReadiness(bool approve)
    {
        var status = WindowsSurfaceFixture.Status() with { VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeCreatePlan,
            new(WindowsSurfaceFixture.Image, "", ContainerUuid: WindowsSurfaceFixture.Hex), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: new("create", "Data", "4097", "1", false));
        var calls = new List<ControlOperationRequestPayload>();
        var result = await VolumeTopologyWorkflow.RunAsync(request, r => {
            calls.Add(r); return Task.FromResult(Prepared(r));
        }, _ => {
            status = status with { InventoryGeneration = 2, ManagementJournalRootInspected = false, VolumeManagementReadyImages = [] };
            Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status)).CanManageTopologyImage);
            return approve;
        }, () => status);
        Assert.True(result.Success); Assert.Equal(2, calls.Count);
        Assert.Equal(approve ? ApfsControlCommands.VolumeManagementApply : ApfsControlCommands.VolumeManagementCancel, calls[1].Command);
        Assert.Equal(request.VolumeManagement! with { Token = new string('a', 64) }, calls[1].VolumeManagement);
    }

    [Fact]
    public async Task PreparedReplyForAnotherOperationCannotReachConfirmation()
    {
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeCreatePlan,
            new(WindowsSurfaceFixture.Image, "", ContainerUuid: WindowsSurfaceFixture.Hex), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: new("create", "Data", "4097", "1", false));
        var calls = 0; var confirmations = 0;
        await Assert.ThrowsAsync<IOException>(() => VolumeTopologyWorkflow.RunAsync(request, r => {
            calls++; return Task.FromResult(Prepared(r) with { OperationId = Guid.NewGuid().ToString("D") });
        }, _ => { confirmations++; return true; }));
        Assert.Equal(1, calls); Assert.Equal(0, confirmations);
    }
}
