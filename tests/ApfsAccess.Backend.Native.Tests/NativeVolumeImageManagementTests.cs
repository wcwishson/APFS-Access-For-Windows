using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeVolumeImageManagementTests
{
    [Theory]
    [InlineData("536870912", "805306368")] [InlineData("536870912", "1099511627776")]
    public void StreamedCapacityPassesBackendRequestValidation(string before, string after)
    { NativeApfsVolumeImageManagement.ValidateRequest(Request() with { ImageOptions = new(before, after) }); }
    [Theory]
    [InlineData("1099511631872")] [InlineData("536870913")] [InlineData("18446744073709551616")]
    public void StreamedCapacityStillRejectsOversizedUnalignedOrOverflow(string after)
    { Assert.Throws<InvalidDataException>(() => NativeApfsVolumeImageManagement.ValidateRequest(Request() with { ImageOptions = new("536870912", after) })); }
    internal static VolumeTopologyRequest Request(string operation = "grow") => new(operation, @"D:\bounded.apfs", @"D:\private", "0",
        new string('a', 32), new string('b', 32), "201", "7", new string('a', 64) + "0000000000200000", @"D:\spool",
        [new("201", new string('b', 32), @"D:\spool\wal")], ImageOptions: new("2097152", "3145728"));
    internal static string Document(VolumeTopologyRequest r, string outcome, string? source = null) => JsonSerializer.Serialize(new {
        schemaVersion = 1, operation = r.Operation, outcome, error = "", image = r.Image, journal = Path.Combine(r.JournalRoot, "original.vif1"),
        sourceIdentity = source ?? r.SourceIdentity, containerUuid = r.ContainerUuid, volumeUuid = r.VolumeUuid, volumeOid = r.VolumeOid,
        expectedBytes = r.ImageOptions!.ExpectedBytes, targetBytes = r.ImageOptions.TargetBytes, preXid = r.PreXid,
        postXid = outcome == "committed" ? "8" : "0", freeBlocksBefore = "400", freeBlocksAfter = "656", expiresUnixSeconds = "4000000000",
        confirmationToken = outcome == "prepared" ? new string('c', 64) : "", newContainerUuid = r.ImageOptions.NewContainerUuid ?? "",
        newVolumeUuid = r.ImageOptions.NewVolumeUuid ?? "", newVolumeOid = r.Operation is "format" or "erase" ? "1024" : "0",
        newVolumeWal = r.ImageOptions.NewVolumeWal ?? "", name = r.Name ?? "", caseSensitive = r.CaseSensitive ?? false,
        siblingWals = r.SiblingWals.Select(w => new { oid = w.Oid, path = w.Path }) });
    [Fact]
    public void RecoveryKeepsOriginalRequestAndAcceptsSameFileAfterAuthorizedLengthChange()
    {
        var r = Request(); var current = r.SourceIdentity[..64] + "0000000000300000";
        var result = NativeApfsVolumeImageManagement.ParseResult(new(0, Document(r, "committed", current), ""), r, VolumeTopologyMode.Recover);
        Assert.True(result.Committed); Assert.Equal(current, result.SourceIdentity); Assert.Equal("2097152", r.ImageOptions!.ExpectedBytes);
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeImageManagement.ParseResult(new(0, Document(r, "committed", new string('d', 64) + current[64..]), ""), r, VolumeTopologyMode.Recover));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeImageManagement.ParseResult(new(0, Document(r, "committed", current), ""), r, VolumeTopologyMode.Apply));
    }
    [Theory]
    [InlineData("expectedBytes")] [InlineData("targetBytes")] [InlineData("newVolumeOid")]
    [InlineData("sourceIdentity")] [InlineData("preXid")] [InlineData("operation")]
    public void DriftCannotProduceMutationSuccess(string field)
    {
        var r = Request(); var node = JsonNode.Parse(Document(r, "committed"))!; node[field] = "changed";
        Assert.ThrowsAny<Exception>(() => NativeApfsVolumeImageManagement.ParseResult(new(0, node.ToJsonString(), ""), r, VolumeTopologyMode.Apply));
    }
    [Theory]
    [InlineData("committed", 0, VolumeTopologyMode.Prepare)] [InlineData("committed", 1, VolumeTopologyMode.Apply)]
    [InlineData("prepared", 0, VolumeTopologyMode.Apply)] [InlineData("refused", 0, VolumeTopologyMode.Apply)]
    public void FalseSuccessWrongExitAndWrongModeRefuse(string outcome, int exit, VolumeTopologyMode mode)
    { var r = Request(); Assert.Throws<InvalidDataException>(() => NativeApfsVolumeImageManagement.ParseResult(new(exit, Document(r, outcome), ""), r, mode)); }
}
