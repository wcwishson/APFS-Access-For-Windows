using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class VolumeTopologyContractTests
{
    [Theory]
    [InlineData("grow")] [InlineData("shrink")] [InlineData("format")] [InlineData("erase")]
    public void ImagePlanOptionsAndCommittedEvidenceBindSelectedIdentityAndCapacity(string kind)
    {
        var format = kind is "format" or "erase";
        var container = new string('a', 32); var volume = new string('b', 32);
        var target = new ApfsControlTarget(@"D:\image.apfs", ApfsAccess.Core.ApfsTopology.BuildVolumeId(container, 101), "original-recovery",
            volume, container, 101, "selected-v1:" + new string('a', 64));
        var options = format ? new VolumeManagementParameters(kind, Name: "Fresh", CaseSensitive: true) :
            new VolumeManagementParameters(kind, TargetBytes: kind == "grow" ? "3145728" : "1048576");
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            target, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: options);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
        var changed = format ? options with { CaseSensitive = false } : options with { TargetBytes = "4194304" };
        Assert.NotEqual(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(request with { VolumeManagement = changed }));
        request = request with { Command = ApfsControlCommands.VolumeManagementApply, VolumeManagement = options with { Token = new string('a', 64) } };
        var report = System.Text.Json.JsonSerializer.SerializeToElement(new { schemaVersion = 1, operation = kind, outcome = "committed",
            sourceIdentity = new string('a', 80), containerUuid = container, volumeUuid = volume, volumeOid = "101", preXid = "7", postXid = "8",
            expectedBytes = "2097152", targetBytes = options.TargetBytes ?? "2097152", newContainerUuid = new string('c', 32), newVolumeUuid = new string('d', 32), newVolumeOid = "1024" });
        var result = new OperationResultPayload(request.OperationId, request.Command, target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, StartedAtUtc: DateTime.UtcNow,
            CompletedAtUtc: DateTime.UtcNow, ExpiresAtUtc: request.ExpiresAtUtc, FinalStatus: "volume-management-committed", MountProof: "absent",
            OwnershipProof: "proven", DurabilityProof: "proven", VolumeManagement: request.VolumeManagement, VolumeManagementReport: report);
        bool Valid(System.Text.Json.JsonElement evidence) => PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult,
            result with { VolumeManagementReport = evidence }, result.OperationId, 2)).IsValid;
        Assert.True(Valid(report));
        foreach (var field in new[] { "operation", "volumeUuid", "postXid", format ? "newVolumeOid" : "targetBytes" })
        {
            var node = System.Text.Json.Nodes.JsonNode.Parse(report.GetRawText())!;
            node[field] = field == "volumeUuid" ? new string('e', 32) : field == "operation" ? "delete" : "7";
            Assert.False(Valid(System.Text.Json.JsonSerializer.SerializeToElement(node)));
        }
    }
    [Fact]
    public void CreateContainerRequestBindsCaseAndEveryOption()
    {
        var r = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeCreatePlan,
            new(@"D:\image.apfs", "", ContainerUuid: new string('a', 32)), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: new("create", "Data", "4097", "0", false));
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, r, r.OperationId, 2);
        var validation = PipeMessageCodec.Validate(envelope); Assert.True(validation.IsValid, validation.Diagnostic);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out _, out _, out _));
        var fingerprint = ApfsOperationFingerprint.Compute(r);
        foreach (var p in new[] { r.VolumeManagement! with { Name = "Other" }, r.VolumeManagement! with { QuotaBytes = "4098" },
            r.VolumeManagement! with { CaseSensitive = true } }) Assert.NotEqual(fingerprint, ApfsOperationFingerprint.Compute(r with { VolumeManagement = p }));
        Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            r with { VolumeManagement = r.VolumeManagement! with { Token = new string('a', 64) } }, r.OperationId, 2)).IsValid);
    }
    [Fact]
    public void MalformedSuccessCannotBecomeACommittedMutation()
    {
        var r = new OperationResultPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeManagementRecover,
            new(@"D:\image.apfs", "", ContainerUuid: new string('a', 32)), null, ApfsOperationStates.Succeeded, "ok", true, DateTime.UtcNow,
            StartedAtUtc: DateTime.UtcNow, CompletedAtUtc: DateTime.UtcNow, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            FinalStatus: "volume-management-committed", MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "proven",
            VolumeManagement: new("create", "Data", "0", "0", false, new string('a', 64)));
        r = r with { Fingerprint = ApfsOperationFingerprint.ComputeForResult(r) };
        Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, r, r.OperationId, 2)).IsValid);
        var malformed = r with { VolumeManagementReport = System.Text.Json.JsonSerializer.SerializeToElement(new { unknown = true }) };
        Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, malformed, r.OperationId, 2)).IsValid);
    }
}
