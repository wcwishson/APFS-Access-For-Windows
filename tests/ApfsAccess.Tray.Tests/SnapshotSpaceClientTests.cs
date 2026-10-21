using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Tray.Tests;

public sealed class SnapshotSpaceClientTests
{
    private static readonly VerifyScope Scope = new(@"D:\Fictional Images\source.apfs",
        "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "101", "22", "0", "2097152");

    private static JsonObject Amount(ulong blocks) => new() { ["blocks"] = blocks.ToString(), ["bytes"] = (blocks * 4096).ToString() };
    private static JsonObject Wire(bool complete = true)
    {
        var report = new JsonObject { ["format"] = "apfs-access-snapshot-space-attribution", ["version"] = 1,
            ["readOnly"] = true, ["complete"] = complete,
            ["source"] = new JsonObject { ["path"] = Scope.ImagePath, ["identity"] = "windows-file:1:2:2097152:3" },
            ["scope"] = new JsonObject { ["containerUuid"] = Scope.ContainerId[15..], ["volumeUuid"] = Scope.VolumeUuid,
                ["volumeOid"] = Scope.VolumeObjectId, ["checkpointXid"] = Scope.CheckpointXid,
                ["storeOffsetBytes"] = Scope.StoreOffsetBytes, ["storeSizeBytes"] = Scope.StoreSizeBytes } };
        if (!complete) report["reason"] = "Retained ownership is incomplete.";
        else
        {
            report["allocationUnitBytes"] = 4096;
            report["referencedMetadata"] = Amount(5); report["referencedPayload"] = Amount(1);
            report["catalogMetadata"] = Amount(14);
            report["snapshots"] = new JsonArray(new JsonObject { ["name"] = "backup", ["snapshotXid"] = "21",
                ["metadata"] = new JsonObject { ["referenced"] = Amount(5) },
                ["payload"] = new JsonObject { ["referenced"] = Amount(1), ["sharedWithLive"] = Amount(1),
                    ["potentialReclaimUpperBound"] = Amount(0) }, ["purgeableMarkedPayload"] = Amount(0),
                ["applePurgeable"] = null, ["reclaimable"] = null });
        }
        return new() { ["schemaVersion"] = 2, ["command"] = "snapshots-space",
            ["operationId"] = "22222222-2222-4222-8222-222222222222", ["success"] = complete,
            ["exitCode"] = complete ? 0 : 3, ["nativeExitCode"] = complete ? 0 : 3,
            ["code"] = complete ? "SnapshotSpaceAttributed" : "SnapshotSpaceUnknown", ["error"] = null,
            ["usage"] = null, ["observation"] = report };
    }

    private static SnapshotSpaceExit Exit(JsonObject wire, int code = 0) => new(code, wire.ToJsonString());

    [Fact]
    public void SharedPayloadIsReportedWithoutClaimingDeletionSavings()
    {
        var summary = SnapshotSpaceClient.Parse(Exit(Wire()), Scope);
        var row = Assert.Single(summary.Snapshots);
        Assert.Equal(20480UL, row.MetadataBytes); Assert.Equal(4096UL, row.PayloadBytes);
        Assert.Equal(4096UL, row.SharedWithLiveBytes); Assert.Equal(0UL, row.PotentialReclaimUpperBoundBytes);
        Assert.Contains("exact deletion savings are unknown", summary.Summary);
    }

    [Fact]
    public void IncompleteObservationHasNoAmounts()
    {
        var summary = SnapshotSpaceClient.Parse(Exit(Wire(false), 3), Scope);
        Assert.False(summary.Complete); Assert.Empty(summary.Snapshots); Assert.Contains("unknown", summary.Summary);
        var forged = Wire(false); forged["observation"]!["referencedMetadata"] = Amount(5);
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(forged, 3), Scope));
    }

    [Theory]
    [InlineData("volumeUuid", "cccccccccccccccccccccccccccccccc")]
    [InlineData("volumeOid", "102")]
    [InlineData("checkpointXid", "23")]
    [InlineData("storeOffsetBytes", "4096")]
    [InlineData("storeSizeBytes", "1048576")]
    public void OtherVolumeOrCheckpointCannotPopulateTheDialog(string field, string value)
    {
        var wire = Wire(); wire["observation"]!["scope"]![field] = value;
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(wire), Scope));
    }

    [Theory]
    [InlineData("applePurgeable")]
    [InlineData("reclaimable")]
    public void InventedPurgeabilityIsRejected(string field)
    {
        var wire = Wire(); wire["observation"]!["snapshots"]![0]![field] = Amount(1);
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(wire), Scope));
    }

    [Fact]
    public void ContradictoryBytesAndSharedReclaimAreRejected()
    {
        var wire = Wire(); wire["observation"]!["snapshots"]![0]!["payload"]!["potentialReclaimUpperBound"] = Amount(1);
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(wire), Scope));
        wire = Wire(); wire["observation"]!["referencedPayload"]!["bytes"] = "4097";
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(wire), Scope));
    }

    [Theory]
    [InlineData(511, true)]
    [InlineData(512, false)]
    public void CatalogAndPayloadStorageCannotOverlap(int catalogBlocks, bool valid)
    {
        var wire = Wire(); wire["observation"]!["catalogMetadata"] = Amount((ulong)catalogBlocks);
        if (valid) Assert.True(SnapshotSpaceClient.Parse(Exit(wire), Scope).Complete);
        else Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(wire), Scope));
    }

    [Fact]
    public void DuplicateKeysAndSuccessDisagreementAreRejected()
    {
        var wire = Wire(); var duplicate = wire.ToJsonString().Replace("\"schemaVersion\":2", "\"schemaVersion\":2,\"schemaVersion\":2");
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(new(0, duplicate), Scope));
        wire["success"] = false;
        Assert.Throws<InvalidDataException>(() => SnapshotSpaceClient.Parse(Exit(wire), Scope));
    }

    [Fact]
    public async Task SelectionChangeDuringObservationDiscardsTheResult()
    {
        var current = true; var checks = 0;
        var client = new SnapshotSpaceClient((_, _) => { current = false; return Task.FromResult(Exit(Wire())); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.RunAsync(Scope, () =>
        { checks++; if (!current) throw new InvalidOperationException("Selection changed"); }, CancellationToken.None));
        Assert.Equal(2, checks);
    }

    [Fact]
    public async Task CancellationAfterAReplyDoesNotPublishAmounts()
    {
        using var cancellation = new CancellationTokenSource();
        var client = new SnapshotSpaceClient((_, _) => { cancellation.Cancel(); return Task.FromResult(Exit(Wire())); });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.RunAsync(Scope, () => { }, cancellation.Token));
    }

    [Fact]
    public void PublicCommandUsesExactArgumentsWithoutAShellOrMount()
    {
        var start = SnapshotSpaceClient.StartInfo(Scope, @"D:\FictionalPackage\ApfsAccess.Cli.exe");
        Assert.False(start.UseShellExecute); Assert.True(start.CreateNoWindow);
        Assert.True(start.RedirectStandardOutput && start.RedirectStandardError);
        Assert.Equal(new[] { "snapshots", "space", "--image", Scope.ImagePath, "--container-id", Scope.ContainerId,
            "--volume-uuid", Scope.VolumeUuid, "--volume-oid", "101", "--checkpoint-xid", "22",
            "--store-offset-bytes", "0", "--store-size-bytes", "2097152", "--json" }, start.ArgumentList);
    }
}
