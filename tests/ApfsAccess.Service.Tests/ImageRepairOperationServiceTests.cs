using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class ImageRepairOperationServiceTests
{
    private static ImageRepairOffer Offer() => new(new string('d', 64), DateTime.UtcNow.AddMinutes(2),
        new(@"D:\repair.apfs", "apfs-container:" + new string('a', 32), new string('b', 32), "101", "7", "0", "2097152"),
        "original-recovery", "selected-v1:" + new string('a', 64), new string('b', 64), "0",
        "windows-image-v1:" + new string('a', 48) + "0000000000000000" + "0000000000200000" + ":123", new string('c', 64));

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ImageRepair_AdmissionForwardingDurableReplayAndFingerprintConflictPreserveOpaqueAuthority(bool approve)
    {
        var offer = Offer(); var calls = 0;
        var root = Directory.CreateDirectory(Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!,
            "op-" + Guid.NewGuid().ToString("N")[..8])).FullName;
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.Fix,
            new(offer.Scope.ImagePath, ImageRepairPersistence.VolumeId(offer.Scope)), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2),
            ApprovedImageRepairPlanId: approve ? offer.PlanId : null);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(async (operation, _) =>
        {
            calls++; Assert.Equal(request.ApprovedImageRepairPlanId, operation.ApprovedImageRepairPlanId);
            Assert.Equal(request.Target!.VolumeId, operation.Target!.VolumeId);
            entered.SetResult(); await release.Task;
            var now = DateTime.UtcNow;
            return new(operation.OperationId, operation.Command, operation.Target, null, ApfsOperationStates.Failed,
                ApfsOperationCodes.BlockedRecovery, false, now, now, now, FinalStatus: approve ? "repair-not-complete" : "repair-confirmation-required",
                ExpiresAtUtc: operation.ExpiresAtUtc, ApprovedImageRepairPlanId: operation.ApprovedImageRepairPlanId,
                ImageRepairOffer: approve ? null : offer,
                ImageRepairReceipt: approve ? new(offer.PlanId, "refused", offer, @"D:\journal\original.rct2", @"D:\journal\evidence", "RepairRefused", 4) : null);
        }, root);
        try
        {
            var task = service.ExecuteOrReplayAsync(request);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var running = service.Query(request.OperationId);
            Assert.Equal(request.ApprovedImageRepairPlanId, running.ApprovedImageRepairPlanId);
            Assert.Equal(ApfsOperationFingerprint.Compute(request), running.Fingerprint); Assert.False(running.Success);
            AssertWire(running); release.SetResult();
            var terminal = await task.WaitAsync(TimeSpan.FromSeconds(5)); AssertWire(terminal);
            Assert.Equal(request.ApprovedImageRepairPlanId, terminal.ApprovedImageRepairPlanId);
            if (approve) Assert.Equal(offer, terminal.ImageRepairReceipt!.Binding);
            else Assert.Equal(offer, terminal.ImageRepairOffer);
            Assert.Equal(terminal, await service.ExecuteOrReplayAsync(request)); Assert.Equal(1, calls);
            var conflict = await service.ExecuteOrReplayAsync(request with { ApprovedImageRepairPlanId = new string('e', 64) });
            Assert.Equal(ApfsOperationCodes.OperationConflict, conflict.Code); Assert.Equal(1, calls);
            await service.StopAsync(default);
            var restarted = new AgentControlOperationService((_, _) => throw new InvalidOperationException("Durable replay must not execute again."), root);
            try { Assert.Equal(terminal, await restarted.ExecuteOrReplayAsync(request)); }
            finally { await restarted.StopAsync(default); }
        }
        finally { release.TrySetResult(); await service.StopAsync(default); }
    }

    private static void AssertWire(OperationResultPayload result)
    {
        var check = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, 2));
        Assert.True(check.IsValid, check.Diagnostic);
    }
}
