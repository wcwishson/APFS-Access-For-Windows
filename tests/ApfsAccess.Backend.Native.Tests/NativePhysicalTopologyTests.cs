using System.Globalization;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.TestFixtures;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativePhysicalTopologyTests
{
    internal static string Binding(ulong bytes = 134217728)
        => PhysicalTopologyBindingFixture.Encode(bytes);
    internal static VolumeTopologyRequest Request(string root, string operation, string? bindingHex = null)
    {
        var hex = bindingHex ?? Binding(); var binding = VolumePhysicalBinding.Parse(hex); var container = new string('a', 32);
        var wal = NativeApfsBackend.BuildRecoveryIdentityFromComponents(binding.PartitionGuid, container, 101, false)!;
        return new(operation, @"\\.\PhysicalDrive42", root, binding.BaseOffset.ToString(CultureInfo.InvariantCulture), container,
            operation == "create" ? new string('c', 32) : new string('b', 32), operation == "create" ? "20480" : "101", "7", binding.SourceIdentity,
            root, [new("101", new string('b', 32), NativeRecoveryStorage.CanonicalWal(root, wal))],
            operation == "create" ? "Peer" : null, operation == "create" ? "0" : null,
            operation == "create" ? "0" : null, operation == "create" ? false : null, PhysicalBindingHex: hex);
    }
    [Theory]
    [InlineData("create")] [InlineData("delete")]
    public void TypedPhysicalRequestBindsScopeAndCanonicalOriginalWals(string operation)
    {
        var request = Request(@"D:\private-topology", operation); NativeApfsVolumeManagement.ValidateRequest(request);
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeManagement.ValidateRequest(Request(request.JournalRoot, operation, Binding(268439552))));
        foreach (var changed in new[] {
            request with { OffsetBytes = "0" }, request with { SourceIdentity = new string('a', 80) },
            request with { Image = @"D:\pretend.apfs" }, request with { PhysicalBindingHex = Binding(268439552) },
            request with { SiblingWals = [request.SiblingWals[0] with { Path = @"D:\private-topology\caller.wal" }] } })
            Assert.Throws<InvalidDataException>(() => NativeApfsVolumeManagement.ValidateRequest(changed));
    }
    [Theory]
    [InlineData("create")] [InlineData("delete")]
    public void PhysicalOutcomeRequiresExactInstanceAndOriginalScope(string operation)
    {
        var r = Request(@"D:\private-topology", operation); var binding = VolumePhysicalBinding.Parse(r.PhysicalBindingHex!);
        string Document(string image) => JsonSerializer.Serialize(new {
            schemaVersion = 1, operation = "volume-" + operation, outcome = "committed", error = "", image, sourceIdentity = r.SourceIdentity,
            journal = Path.Combine(r.JournalRoot, "original.vmt1"), containerUuid = r.ContainerUuid, volumeUuid = r.VolumeUuid,
            volumeOid = r.VolumeOid, offsetBytes = r.OffsetBytes, preXid = "7", postXid = "8", blockBytes = "4096",
            freeBlocksBefore = "100", freeBlocksAfter = "92", allocatedBlocks = "8", deferredBlocks = "0", expiresUnixSeconds = "4000000000",
            confirmationToken = "", siblingWals = r.SiblingWals.Select(w => new { oid = w.Oid, path = w.Path }), name = r.Name ?? "",
            quotaBlocks = r.QuotaBlocks ?? "0", reserveBlocks = r.ReserveBlocks ?? "0", caseSensitive = r.CaseSensitive ?? false });
        Assert.True(NativeApfsVolumeManagement.ParseResult(new(0, Document(binding.Instance), ""), r, VolumeTopologyMode.Apply).Committed);
        foreach (var image in new[] { r.Image, binding.Instance + "-OTHER", @"D:\clone.apfs" })
            Assert.Throws<InvalidDataException>(() => NativeApfsVolumeManagement.ParseResult(new(0, Document(image), ""), r, VolumeTopologyMode.Apply));
    }
}
