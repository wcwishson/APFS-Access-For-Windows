using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class LiveSnapshotControlTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static JsonObject Inventory() => JsonNode.Parse(new LiveSnapshotInventory(Container, Volume,
        "101", "18446744073709551615", "0", "1048576",
        [new("9007199254740993", "18446744073709551615", "backup-\"-\u5907\u4efd", "249", "17", "230", "8293", "8", "250")]).ToJson().GetRawText())!.AsObject();

    [Fact]
    public async Task LiveListPublishesBareAuthenticatedRequestAndReadsExactTypedInventory()
    {
        using var dir = DTempDirectory.Create("live-list"); var path = Path.Combine(dir.Path, "control");
        var send = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.SnapshotList,
            101, TimeSpan.FromSeconds(3), default);
        await Respond(path, send, Inventory().ToJsonString(), "snapshot-inventory-json/1", "ok");
        var result = await send;
        Assert.True(result.Success, result.Code); Assert.Equal("SnapshotInventory", result.Code);
        Assert.Equal("18446744073709551615", result.Inventory!.CheckpointXid);
        Assert.Equal("9007199254740993", Assert.Single(result.Inventory.Snapshots).Xid);
        Assert.Contains("\u5907\u4efd", result.Inventory.Snapshots[0].Name);
        Assert.False(File.Exists(path)); Assert.False(File.Exists(path + ".response"));
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("numeric")]
    [InlineData("leading-zero")]
    [InlineData("unknown")]
    [InlineData("over-count")]
    [InlineData("oid")]
    [InlineData("unsorted")]
    [InlineData("uuid")]
    [InlineData("marker")]
    [InlineData("error-data")]
    [InlineData("too-large")]
    public async Task LiveListRefusesMalformedOrOversizedTypedResponse(string failure)
    {
        using var dir = DTempDirectory.Create("live-list-invalid"); var path = Path.Combine(dir.Path, "control");
        var data = Inventory(); var marker = "snapshot-inventory-json/1"; var outcome = "ok";
        switch (failure)
        {
            case "numeric": data["checkpointXid"] = 9007199254740993UL; break;
            case "leading-zero": data["checkpointXid"] = "01"; break;
            case "unknown": data["extra"] = true; break;
            case "over-count": data["snapshots"] = new JsonArray(Enumerable.Range(0, 65).Select(_ => data["snapshots"]![0]!.DeepClone()).ToArray()); break;
            case "oid": data["volumeOid"] = "102"; break;
            case "unsorted": data["snapshots"]!.AsArray().Add(data["snapshots"]![0]!.DeepClone()); break;
            case "uuid": data["snapshots"]![0]!["uuid"] = Volume; break;
            case "marker": marker = "snapshot-inventory-json/2"; break;
            case "error-data": outcome = "error"; break;
        }
        var json = data.ToJsonString();
        if (failure == "duplicate") json = json.Replace("\"version\":1", "\"version\":1,\"version\":1", StringComparison.Ordinal);
        if (failure == "too-large") json += new string(' ', LiveSnapshotInventory.MaximumResponseBytes);
        var send = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.SnapshotList,
            101, TimeSpan.FromSeconds(3), default);
        await Respond(path, send, json, marker, outcome);
        var result = await send;
        Assert.False(result.Success); Assert.Equal("ControlResponseInvalid", result.Code); Assert.Null(result.Inventory);
    }

    [Fact]
    public async Task LegacyErrorStaysFourLinesAndCannotSupplyInventory()
    {
        using var dir = DTempDirectory.Create("live-list-legacy"); var path = Path.Combine(dir.Path, "control");
        var send = ContainerControlChannel.SendAsync(path, new string('a', 64), ContainerControlAction.SnapshotList,
            101, TimeSpan.FromSeconds(3), default);
        await Respond(path, send, null, "", "error");
        var result = await send;
        Assert.False(result.Success); Assert.Equal("SnapshotRuntimeOwnerNotReady", result.Code); Assert.Null(result.Inventory);
        await Assert.ThrowsAsync<ArgumentException>(() => ContainerControlChannel.SendAsync(path, new string('a', 64),
            ContainerControlAction.SnapshotList, 101, TimeSpan.FromSeconds(1), default, ["extra"]));
    }

    [Fact]
    public void SnapshotLaunchIsDefaultOffAndRestrictedToCanonicalOrdinaryManifestImages()
    {
        var options = new ServiceHostOptions { WriteBackendMode = "Native" };
        var volume = new VolumeInfo("main", @"D:\image.apfs", "Main", true);
        var manifest = new WrittenContainerManifest("unused", "unused", Container, volume.DeviceId, 0,
            [new(101, Container, "Main", "R:\\", true, "recovery")]);
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume, true));
        options.EnableImageSnapshots = true;
        Assert.True(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume, true));
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume, false));
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest with { Device = @"\\.\PhysicalDrive2" }, volume, true));
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest with { DeviceOffsetBytes = 4096 }, volume, true));
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume with { IsEncrypted = true }, true));
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume with { WriteUnsupportedFeatures = ["FusionBacked"] }, true));
        options.NativeWriteRequireCanonicalCommit = false;
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume, true));
        options.NativeWriteRequireCanonicalCommit = true; options.WriteBackendMode = "Overlay";
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume, true));
    }

    [Fact]
    public void StatusDoesNotInferCapabilitiesAndRejectsNonBooleanOrContradictoryClaims()
    {
        var root = JsonNode.Parse("""
            {"containerUuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ownerPid":123,"ownerStartFileTimeUtc":42,
             "leaseHeld":true,"checkpointXid":"90","recoveryRequired":false,"recoveryVolumeObjectId":null,"recoveryReason":"",
             "volumes":[{"objectId":"101","canonicalId":"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101","mounted":true,
              "ready":true,"writable":true,"recoveryActive":false,"writeDegraded":false,"recoveryReason":"","recoveryIdentity":"rec"}]}
            """)!.AsObject();
        var legacy = Assert.Single(ContainerStatusReader.Parse(root.ToJsonString()).Volumes);
        Assert.False(legacy.SnapshotInventorySupported); Assert.False(legacy.SnapshotMutationSupported);
        Assert.False(legacy.SnapshotRecoverySupported);
        var row = root["volumes"]![0]!;
        row["snapshotInventorySupported"] = true; row["snapshotMutationSupported"] = true;
        Assert.True(Assert.Single(ContainerStatusReader.Parse(root.ToJsonString()).Volumes).SnapshotMutationSupported);
        row["snapshotInventorySupported"] = "true";
        Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(root.ToJsonString()));
        row["snapshotInventorySupported"] = false;
        Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(root.ToJsonString()));
    }

    [Fact]
    public void RecoveryStatusIsIndependentOfCleanMutationButRequiresRetainedOwnerProof()
    {
        var root = JsonNode.Parse("""
            {"containerUuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ownerPid":123,"ownerStartFileTimeUtc":42,
             "leaseHeld":true,"checkpointXid":"90","recoveryRequired":false,"recoveryVolumeObjectId":null,"recoveryReason":"",
             "volumes":[{"objectId":"101","canonicalId":"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101","mounted":true,
              "ready":true,"writable":false,"recoveryActive":true,"writeDegraded":true,"recoveryReason":"AcceptedSnapshotDebt",
              "recoveryIdentity":"rec","snapshotInventorySupported":false,"snapshotMutationSupported":false,"snapshotRecoverySupported":true}]}
            """)!;
        var volume = Assert.Single(ContainerStatusReader.Parse(root.ToJsonString()).Volumes);
        Assert.True(volume.SnapshotRecoverySupported); Assert.False(volume.SnapshotMutationSupported);
        foreach (var change in new[] { "type", "lease", "mounted", "ready", "checkpoint", "container-recovery" })
        {
            var malformed = root.DeepClone(); var child = malformed["volumes"]![0]!;
            switch (change)
            {
                case "type": child["snapshotRecoverySupported"] = "true"; break;
                case "lease": malformed["leaseHeld"] = false; break;
                case "mounted": child["mounted"] = false; child["ready"] = false; break;
                case "ready": child["ready"] = false; break;
                case "checkpoint": malformed["checkpointXid"] = "0"; break;
                default: malformed["recoveryRequired"] = true; malformed["recoveryVolumeObjectId"] = "101";
                    malformed["recoveryReason"] = "OwnerLatched"; break;
            }
            Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(malformed.ToJsonString()));
        }
    }

    private static async Task Respond(string path, Task<ContainerControlResult> pending, string? json, string marker, string outcome)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!File.Exists(path) && !pending.IsCompleted) await Task.Delay(5, timeout.Token);
        var lines = await File.ReadAllLinesAsync(path, timeout.Token);
        Assert.Equal(5, lines.Length); Assert.Equal("snapshot-list", lines[3]); Assert.Equal("101", lines[4]);
        var response = $"APFS-CONTROL/1\n{lines[1]}\n{outcome}\n" +
            (json is null ? "SnapshotRuntimeOwnerNotReady\n" : $"SnapshotInventory\n{marker}\n{json}\n");
        await File.WriteAllTextAsync(path + ".tmp", response, new UTF8Encoding(false), timeout.Token);
        File.Move(path + ".tmp", path + ".response");
    }
}
