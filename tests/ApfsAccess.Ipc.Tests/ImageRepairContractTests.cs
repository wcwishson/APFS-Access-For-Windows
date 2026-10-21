using ApfsAccess.Core;
using ApfsAccess.Ipc;
using System.Text.Json.Nodes;

namespace ApfsAccess.Ipc.Tests;

public sealed class ImageRepairContractTests
{
    [Theory]
    [InlineData(@"C:\images\repair.apfs", true)]
    [InlineData(@"Z:\images\repair.apfs", true)]
    [InlineData(@"\\server\share\repair.apfs", false)]
    [InlineData(@"\\?\C:\images\repair.apfs", false)]
    [InlineData(@"\\.\PhysicalDrive0", false)]
    [InlineData(@"C:\images\repair.apfs:stream", false)]
    [InlineData(@"C:\images\..\repair.apfs", false)]
    public void ApprovedRepairSelectorUsesCanonicalLocalSyntax(string path, bool admitted)
    {
        var request = Request(new string('a', 64));
        request = request with { Target = request.Target! with { DeviceId = path } };
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2);
        Assert.Equal(admitted, PipeMessageCodec.Validate(envelope).IsValid);
        if (admitted)
        {
            Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out _, out _, out _));
            Assert.NotEqual(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(request with
            { ApprovedImageRepairPlanId = new string('b', 64) }));
        }
    }

    private static ImageRepairOffer Offer() => new(new string('d', 64), DateTime.UtcNow.AddMinutes(4),
        new(@"D:\repair.apfs", "apfs-container:" + new string('a', 32), new string('b', 32), "101", "7", "0", "2097152"),
        "original-recovery", "selected-v1:" + new string('a', 64), new string('b', 64), "1",
        "windows-image-v1:" + new string('a', 48) + "0000000000000000" + "0000000000200000" + ":123", new string('c', 64));

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void LegacyBareTargetMustBindCanonicalVolumeIdForOfferAndReceipt(bool receipt)
    {
        var offer = Offer();
        var request = Request(receipt ? offer.PlanId : null) with
        { Target = new(offer.Scope.ImagePath, ImageRepairPersistence.VolumeId(offer.Scope)) };
        var result = new OperationResultPayload(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Failed, ApfsOperationCodes.BlockedRecovery, false, DateTime.UtcNow,
            StartedAtUtc: DateTime.UtcNow, CompletedAtUtc: DateTime.UtcNow, ExpiresAtUtc: request.ExpiresAtUtc,
            RequestedMode: request.RequestedMode, FinalStatus: receipt ? "repair-refused" : "repair-confirmation-required",
            ApprovedImageRepairPlanId: request.ApprovedImageRepairPlanId,
            ImageRepairOffer: receipt ? null : offer,
            ImageRepairReceipt: receipt ? new(offer.PlanId, "refused", offer, @"D:\journal\original.rct2", @"D:\journal\evidence", "RepairRefused", 4) : null);
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, 2));
        Assert.True(validation.IsValid, validation.Diagnostic);
        foreach (var wrongId in new[] { "image-volume", $"apfs-vol:{new string('a', 32)}:102", $"apfs-vol:{new string('e', 32)}:101" })
        {
            var wrong = result with { Target = request.Target! with { VolumeId = wrongId } };
            // Recompute the fingerprint too, so rejection proves the proof binding.
            wrong = wrong with { Fingerprint = ApfsOperationFingerprint.ComputeForResult(wrong) };
            Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, wrong, wrong.OperationId, 2)).IsValid);
        }
    }

    private static ControlOperationRequestPayload Request(string? approval = null) => new(Guid.NewGuid().ToString("D"),
        ApfsControlCommands.Fix, new(@"D:\repair.apfs", "apfs-vol:" + new string('a', 32) + ":101"), null,
        DateTime.UtcNow.AddMinutes(2), ApprovedImageRepairPlanId: approval);

    [Fact]
    public void ApprovalIsExactFingerprintMaterialAndEchoRoundTrips()
    {
        var request = Request(new string('a', 64));
        Assert.NotEqual(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(request with { ApprovedImageRepairPlanId = new string('b', 64) }));
        Assert.NotEqual(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(request with { ApprovedImageRepairPlanId = null }));
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out _, out _, out _));
        var result = new OperationResultPayload(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Failed, ApfsOperationCodes.BlockedRecovery, false, DateTime.UtcNow,
            StartedAtUtc: DateTime.UtcNow, CompletedAtUtc: DateTime.UtcNow, ExpiresAtUtc: request.ExpiresAtUtc,
            RequestedMode: request.RequestedMode, FinalStatus: "not-proven", ApprovedImageRepairPlanId: request.ApprovedImageRepairPlanId);
        Assert.Equal(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.ComputeForResult(result));
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, 2)).IsValid);
    }

    [Theory]
    [InlineData("")] [InlineData(" ")] [InlineData("a")] [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void InvalidApprovalIsRejectedRatherThanNormalized(string approval)
    {
        var request = Request(approval);
        Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
    }

    [Theory]
    [InlineData(ApfsControlCommands.Mount)] [InlineData(ApfsControlCommands.Eject)] [InlineData(ApfsControlCommands.VolumeVerify)]
    public void ApprovalCannotBeSmuggledThroughOtherCommands(string command)
    {
        var request = Request(new string('a', 64)) with { Command = command };
        Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
    }

    [Fact]
    public void CallerCannotSupplySourceCountOrJournalAlongsideOpaqueApproval()
    {
        var request = Request(new string('a', 64));
        foreach (var field in new[] { "approvedSourceSha256", "expectedCount", "journalPath", "imageRepairOffer", "imageRepairReceipt", "originalAcceptedOperationId" })
        {
            var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2);
            var payload = Assert.IsType<JsonObject>(envelope.Payload);
            payload[field] = "caller-controlled";
            Assert.False(PipeMessageCodec.Validate(envelope).IsValid);
        }
    }

    [Fact]
    public void ImplicitRecoveryReceiptRequiresCanonicalOriginalAcceptanceAndExactTarget()
    {
        var binding = Offer();
        var request = Request();
        var now = DateTime.UtcNow;
        var receipt = new ImageRepairReceipt(binding.PlanId, "refused", binding,
            @"D:\journal\original.rct2", @"D:\journal\evidence", "RepairRefused", 4);
        var result = new OperationResultPayload(request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request), ApfsOperationStates.Failed, ApfsOperationCodes.BlockedRecovery,
            false, now, now, now, FinalStatus: "repair-not-complete", ExpiresAtUtc: request.ExpiresAtUtc,
            ImageRepairReceipt: receipt);
        bool Valid(OperationResultPayload value) => PipeMessageCodec.Validate(PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult, value, value.OperationId, 2)).IsValid;
        Assert.False(Valid(result));
        result = result with { ImageRepairReceipt = receipt with { OriginalAcceptedOperationId = Guid.NewGuid().ToString("D") } };
        Assert.True(Valid(result));
        Assert.Equal(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.ComputeForResult(result));
        foreach (var invalid in new[] { "", "not-an-operation", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA" })
            Assert.False(Valid(result with { ImageRepairReceipt = result.ImageRepairReceipt! with { OriginalAcceptedOperationId = invalid } }));
        var changed = result with { Target = result.Target! with { VolumeId = "apfs-vol:" + new string('a', 32) + ":102" } };
        changed = changed with { Fingerprint = ApfsOperationFingerprint.ComputeForResult(changed) };
        Assert.False(Valid(changed));
    }
}
