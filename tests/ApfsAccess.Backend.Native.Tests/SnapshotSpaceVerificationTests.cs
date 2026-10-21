using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class SnapshotSpaceVerificationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "snapshot-space-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "fixture.apfs");
    public SnapshotSpaceVerificationTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[2097152]); }
    public void Dispose() => Directory.Delete(directory, true);
    private ApfsSnapshotAttributionResult Parse(JsonObject value, int exit = 0, CancellationToken token = default)
        => NativeApfsImageVerifier.ParseSnapshotAttribution(value.ToJsonString(), exit,
            SnapshotAttributionTestData.Request(Image), SnapshotAttributionTestData.Identity, token);

    [Fact]
    public void SnapshotMetadataAndPayloadRemainDistinctFromApplePolicy()
    {
        var parsed = Parse(SnapshotAttributionTestData.Read(Image));
        Assert.True(parsed.Complete);
        Assert.Equal("20480", parsed.Report.GetProperty("referencedMetadata").GetProperty("bytes").GetString());
        Assert.Equal("4096", parsed.Report.GetProperty("referencedPayload").GetProperty("bytes").GetString());
        var snapshot = parsed.Report.GetProperty("snapshots")[0];
        Assert.Equal(JsonValueKind.Null, snapshot.GetProperty("applePurgeable").ValueKind);
        Assert.Equal(JsonValueKind.Null, snapshot.GetProperty("reclaimable").ValueKind);
        Assert.Equal("0", snapshot.GetProperty("payload").GetProperty("potentialReclaimUpperBound").GetProperty("bytes").GetString());
    }

    [Theory]
    [InlineData("source")] [InlineData("identity")] [InlineData("scope")] [InlineData("version")]
    [InlineData("writable")] [InlineData("extra")] [InlineData("bytes")]
    [InlineData("live-partition")] [InlineData("reclaim-authority")] [InlineData("purgeability")]
    [InlineData("catalog")] [InlineData("union")] [InlineData("retained-order")] [InlineData("retained-end")]
    [InlineData("duplicate-snapshot")] [InlineData("snapshot-union")] [InlineData("invalid-name")]
    public void ContradictoryOrMismatchedAttributionNeverPublishesComplete(string fault)
    {
        var value = SnapshotAttributionTestData.Read(Image); var row = value["snapshots"]![0]!;
        switch (fault)
        {
            case "source": value["source"]!["path"] = Image + ".other"; break;
            case "identity": value["source"]!["identity"] = "windows-file:1:4:2097152:3"; break;
            case "scope": value["scope"]!["checkpointXid"] = "23"; break;
            case "version": value["version"] = 2; break;
            case "writable": value["readOnly"] = false; break;
            case "extra": value["deletionSafe"] = true; break;
            case "bytes": value["referencedPayload"]!["bytes"] = "4097"; break;
            case "live-partition": row["payload"]!["sharedWithLive"]!["blocks"] = "1"; row["payload"]!["sharedWithLive"]!["bytes"] = "4096"; break;
            case "reclaim-authority": row["payload"]!["potentialReclaimUpperBound"]!["blocks"] = "1"; row["payload"]!["potentialReclaimUpperBound"]!["bytes"] = "4096"; break;
            case "purgeability": row["applePurgeable"] = new JsonObject { ["blocks"] = "1", ["bytes"] = "4096" }; break;
            case "catalog": value["catalogMetadata"]!["blocks"] = "4"; value["catalogMetadata"]!["bytes"] = "16384"; break;
            case "union": value["referencedPayload"]!["blocks"] = "2"; value["referencedPayload"]!["bytes"] = "8192"; break;
            case "retained-order": value["retainedCheckpointXids"]![1] = "20"; break;
            case "retained-end": value["retainedCheckpointXids"]![2] = "23"; break;
            case "duplicate-snapshot": value["snapshots"]!.AsArray().Add(row.DeepClone()); break;
            case "invalid-name": row["name"] = "retained\0hidden"; break;
            default:
                var peer = row.DeepClone(); peer["snapshotXid"] = "22"; peer["name"] = "peer";
                value["snapshots"]!.AsArray().Add(peer); break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(value));
    }

    [Fact]
    public void IncompleteHasNoPartialAccountingAndRequiresItsOwnExit()
    {
        var value = SnapshotAttributionTestData.Unknown(Image);
        Assert.False(Parse(value, 3).Complete);
        Assert.Throws<InvalidDataException>(() => Parse(value));
        value["referencedMetadata"] = new JsonObject { ["blocks"] = "0", ["bytes"] = "0" };
        Assert.Throws<InvalidDataException>(() => Parse(value, 3));
        Assert.Throws<InvalidDataException>(() => Parse(SnapshotAttributionTestData.Read(Image), 3));
    }

    [Theory]
    [InlineData(511, true)]
    [InlineData(512, false)]
    public void CatalogMetadataAndPayloadMustFitDisjointStorage(int catalogBlocks, bool valid)
    {
        var value = SnapshotAttributionTestData.Read(Image);
        value["catalogMetadata"]!["blocks"] = catalogBlocks.ToString(System.Globalization.CultureInfo.InvariantCulture);
        value["catalogMetadata"]!["bytes"] = (catalogBlocks * 4096).ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (valid) Assert.True(Parse(value).Complete);
        else Assert.Throws<InvalidDataException>(() => Parse(value));
    }

    [Fact]
    public void PrecancelledCallerCannotPublishAnExistingCompleteResult()
    {
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => Parse(SnapshotAttributionTestData.Read(Image), token: cancel.Token));
    }

    [Fact]
    public void DuplicateJsonPropertiesAreNotAccepted()
    {
        var json = SnapshotAttributionTestData.Read(Image).ToJsonString();
        json = json.Insert(1, "\"complete\":true,");
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseSnapshotAttribution(json, 0,
            SnapshotAttributionTestData.Request(Image), SnapshotAttributionTestData.Identity));
    }
}
