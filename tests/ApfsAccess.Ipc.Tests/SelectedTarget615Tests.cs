using ApfsAccess.Ipc;
using System.Text.Json.Nodes;
namespace ApfsAccess.Ipc.Tests;
public sealed class SelectedTarget615Tests
{
    private static ApfsControlTarget Target => new("d", "d|same", "recovery", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 201, "selected-v1:" + new string('c', 64));
    [Theory]
    [InlineData("volumeUuid")] [InlineData("containerUuid")] [InlineData("volumeObjectId")] [InlineData("observationContract")] [InlineData("recoveryIdentity")]
    public void AdvertisedIdentityCannotLoseAnyRequiredField(string field)
    {
        var r = new ControlOperationRequestPayload(Guid.NewGuid().ToString(), "mount", Target, "read-only", DateTime.UtcNow.AddSeconds(30));
        var e = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, r, r.OperationId, 2);
        Assert.True(PipeMessageCodec.Validate(e).IsValid);
        e.Payload!["target"]!.AsObject().Remove(field);
        Assert.False(PipeMessageCodec.Validate(e).IsValid);
    }
    [Fact]
    public void CaseVariantDuplicateIdentityCannotShadowTheSelection()
    {
        var r = new ControlOperationRequestPayload(Guid.NewGuid().ToString(), "eject", Target, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(30));
        var e = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, r, r.OperationId, 2);
        var json = PipeMessageCodec.Serialize(e).Replace("\"volumeUuid\":", "\"VolumeUuid\":\"dddddddd-dddd-dddd-dddd-dddddddddddd\",\"volumeUuid\":");
        Assert.False(PipeMessageCodec.TryDeserialize(json, out _));
        Assert.False(PipeMessageCodec.TryDeserializeSyntaxOnly(json, out _));
    }
    [Fact]
    public void UnknownIdentityIsNeverSilentlyIgnored()
    {
        var r = new ControlOperationRequestPayload(Guid.NewGuid().ToString(), "eject", Target, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(30));
        var e = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, r, r.OperationId, 2);
        e.Payload!["target"]!["selectedUuid"] = "different"; Assert.False(PipeMessageCodec.Validate(e).IsValid);
    }
}
