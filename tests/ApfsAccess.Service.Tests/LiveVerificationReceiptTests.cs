using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class LiveVerificationReceiptTests
{
    [Fact]
    public async Task TypedReportAboveGenericReceiptBoundPersistsAndReplaysAcrossRestart()
    {
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!, "live-receipt-" + Guid.NewGuid().ToString("N"));
        var scope = LiveVerificationFixture.Scope(); var report = LiveVerificationFixture.Report(scope);
        foreach (var coverage in report["coverage"]!.AsArray())
            coverage!["scopeDetail"] = new string('"', 4096);
        report["repair"]!["planId"] = LiveVerificationFixture.PlanId(report);
        var typed = LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(report));
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeVerify,
            new(@"D:\registered.apfs", ApfsTopology.BuildVolumeId(scope.ContainerUuid, 101), RecoveryIdentity: "test-held-recovery", VolumeUuid: scope.VolumeUuid,
                ContainerUuid: scope.ContainerUuid, VolumeObjectId: 101, ObservationContract: "selected-v1:" + new string('a', 64)), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(2));
        var calls = 0;
        var service = new AgentControlOperationService((r, _) =>
        {
            calls++; var now = DateTime.UtcNow;
            return Task.FromResult(new OperationResultPayload(r.OperationId, r.Command, r.Target, ApfsOperationFingerprint.Compute(r),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, now, StartedAtUtc: now, CompletedAtUtc: now,
                ExpiresAtUtc: r.ExpiresAtUtc, FinalStatus: "verified-covered-scope", MountProof: "present", OwnershipProof: "proven",
                DurabilityProof: "not-applicable", VolumeVerificationReport: typed.Json));
        }, root);
        var result = await service.ExecuteOrReplayAsync(request); Assert.True(result.Success, result.Diagnostic); Assert.Equal("verified-covered-scope", result.FinalStatus);
        Assert.True(new FileInfo(result.EvidencePath!).Length > 256 * 1024); Assert.Equal(1, calls);
        await service.StopAsync(default);
        var restarted = new AgentControlOperationService((_, _) => throw new InvalidOperationException("Saved readonly evidence must replay."), root);
        var replay = restarted.Query(request.OperationId)!;
        Assert.True(replay.Success); Assert.Equal(typed.Scope, LiveVolumeVerificationReport.Parse(replay.VolumeVerificationReport!.Value).Scope);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, replay, replay.OperationId, 2)).IsValid);
        await restarted.StopAsync(default);
    }
}
