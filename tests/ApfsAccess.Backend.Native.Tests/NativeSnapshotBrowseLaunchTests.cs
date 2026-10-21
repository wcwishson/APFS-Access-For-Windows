using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeSnapshotBrowseLaunchTests : IDisposable
{
    private const string Container = "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private readonly string directory = Path.Combine(Path.GetTempPath(), "snapshot-browse-launch-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "source with spaces.raw");

    public NativeSnapshotBrowseLaunchTests()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Image, Enumerable.Range(0, 8192).Select(i => (byte)i).ToArray());
    }

    public void Dispose() => Directory.Delete(directory, recursive: true);

    [Fact]
    public void SourceLeaseExcludesWritersAndReplacementDuringInventoryAndUntilDisposal()
    {
        var observed = false;
        var launch = NativeSnapshotBrowseLaunch.Prepare(Image, Container, "101", "11", (image, container, oid, _) =>
        {
            observed = true;
            Assert.Equal(Image, image);
            Assert.Equal(Container, container);
            Assert.Equal("101", oid);
            AssertPinned();
            return Element(Inventory());
        });
        try
        {
            Assert.True(observed);
            AssertPinned();
            Assert.Equal(Hash(), launch.Selection.SourceSha256);
        }
        finally { launch.Dispose(); }
        launch.Dispose();
        AssertReleased();
    }

    [Fact]
    public void AnExistingWriterPreventsInventoryAndLeavesItsHandleUsable()
    {
        using (var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
        {
            Assert.Throws<IOException>(() => NativeSnapshotBrowseLaunch.Prepare(Image, Container, "101", "11",
                (_, _, _, _) => throw new InvalidOperationException("Inventory must not execute with an existing writer.")));
            writer.WriteByte(42);
        }
        AssertReleased();
    }

    [Fact]
    public void SelectionRetainsExactSourceScopeAndSelectedRootRatherThanFirstSnapshot()
    {
        var evidence = Inventory();
        using var launch = Prepare(evidence);
        var selected = launch.Selection;
        Assert.Equal(Image, selected.Image);
        Assert.Equal(8192, selected.SourceSizeBytes);
        Assert.Equal(Hash(), selected.SourceSha256);
        Assert.Equal(new string('a', 32), selected.ContainerUuid);
        Assert.Equal(new string('b', 32), selected.VolumeUuid);
        Assert.Equal("101", selected.VolumeOid);
        Assert.Equal("20", selected.CheckpointXid);
        Assert.Equal("4096", selected.StoreOffsetBytes);
        Assert.Equal("4096", selected.StoreSizeBytes);
        Assert.Equal("11", selected.SnapshotXid);
        Assert.Equal("second backup", selected.Name);
        Assert.Equal(evidence["snapshots"]![1]!.ToJsonString(), selected.Snapshot.GetRawText());
        evidence["snapshots"]![1]!["rootOid"] = "99";
        Assert.Equal("14", selected.Snapshot.GetProperty("rootOid").GetString());
    }

    [Theory]
    [InlineData("source-path")]
    [InlineData("source-hash")]
    [InlineData("source-size")]
    [InlineData("partial-hash")]
    [InlineData("source-kind")]
    [InlineData("container")]
    [InlineData("volume-oid")]
    [InlineData("volume-id")]
    [InlineData("read-write")]
    [InlineData("store-offset")]
    [InlineData("store-size")]
    [InlineData("missing-xid")]
    [InlineData("duplicate-xid")]
    [InlineData("future-xid")]
    [InlineData("superblockPhysicalBlock")]
    [InlineData("omapPhysicalBlock")]
    [InlineData("omapTreePhysicalBlock")]
    [InlineData("rootOid")]
    [InlineData("rootPhysicalBlock")]
    [InlineData("extentrefPhysicalBlock")]
    public void UnboundOrIncompleteInventoryIsRefusedAndReleasesSource(string mutation)
    {
        var node = Inventory();
        switch (mutation)
        {
            case "source-path": node["source"]!["path"] = Path.Combine(directory, "other.raw"); break;
            case "source-hash": node["source"]!["sha256"] = new string('0', 64); break;
            case "source-size": node["source"]!["sizeBytes"] = 4096; break;
            case "partial-hash": node["source"]!["hashScope"] = "prefix"; break;
            case "source-kind": node["source"]!["kind"] = "physical"; break;
            case "container": node["containerUuid"] = new string('c', 32); break;
            case "volume-oid": node["volumeOid"] = "102"; break;
            case "volume-id": node["volumeId"] = "apfs-vol:" + new string('a', 32) + ":102"; break;
            case "read-write": node["readOnly"] = false; break;
            case "store-offset": node["storeOffsetBytes"] = "8193"; break;
            case "store-size": node["storeSizeBytes"] = "4097"; break;
            case "missing-xid": node["snapshots"]![1]!["xid"] = "12"; break;
            case "duplicate-xid": node["snapshots"]![0]!["xid"] = "11"; break;
            case "future-xid": node["checkpointXid"] = "10"; break;
            default: node["snapshots"]![1]!.AsObject().Remove(mutation); break;
        }
        if (mutation == "missing-xid") Assert.Throws<ArgumentException>(() => Prepare(node));
        else Assert.Throws<InvalidDataException>(() => Prepare(node));
        AssertReleased();
    }

    [Theory]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("+11")]
    [InlineData(" 11")]
    [InlineData("18446744073709551616")]
    [InlineData("backup")]
    public void InvalidXidNeverReadsInventory(string xid)
    {
        Assert.Throws<ArgumentException>(() => NativeSnapshotBrowseLaunch.Prepare(Image, Container, "101", xid,
            (_, _, _, _) => throw new InvalidOperationException("Inventory must not execute.")));
        AssertReleased();
    }

    [Fact]
    public void MaximumU64XidAndOidRemainExactInHostArguments()
    {
        const string maximum = "18446744073709551615";
        var node = Inventory();
        node["volumeOid"] = maximum;
        node["volumeId"] = "apfs-vol:" + new string('a', 32) + ":" + maximum;
        node["checkpointXid"] = maximum;
        node["snapshots"]![1]!["xid"] = maximum;
        using var launch = NativeSnapshotBrowseLaunch.Prepare(Image, Container, maximum, maximum, (_, _, _, _) => Element(node));
        var args = Arguments(launch);
        Assert.Equal(maximum, Value(args, "--snapshot-xid"));
        Assert.Equal(maximum, Value(args, "--volume-oid"));
    }

    [Fact]
    public void ArgumentsSelectImmutableSnapshotAndCarrySupervisionWithoutAWriteWindow()
    {
        using var launch = Prepare();
        var args = Arguments(launch);
        Assert.Equal(Image, Value(args, "--device"));
        Assert.Equal("4096", Value(args, "--device-offset"));
        Assert.Equal(new string('a', 32), Value(args, "--container-id"));
        Assert.Equal("101", Value(args, "--volume-oid"));
        Assert.Equal("11", Value(args, "--snapshot-xid"));
        Assert.Single(args, a => a == "--readonly");
        Assert.Equal("Disabled", Value(args, "--write-backend"));
        Assert.Equal("1234", Value(args, "--parent-pid"));
        Assert.Equal(Token, Value(args, "--startup-gate-token"));
        foreach (var (flag, name) in new[] { ("--mount", "mount"), ("--status-file", "status.json"),
                     ("--lifetime-file", "lifetime"), ("--startup-gate-file", "startup.gate") })
            Assert.Equal(Path.Combine(directory, name), Value(args, flag));
        Assert.DoesNotContain("--readwrite", args);
        Assert.DoesNotContain("--snapshot-name", args);
        Assert.DoesNotContain("--enable-image-snapshots", args);
        Assert.DoesNotContain("--allow-raw-physical-write", args);
    }

    [Theory]
    [InlineData(0, Token)]
    [InlineData(-1, Token)]
    [InlineData(1234, "")]
    [InlineData(1234, "abcd")]
    [InlineData(1234, "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public void MissingSupervisionAuthorityCannotProduceHostArguments(int pid, string token)
    {
        using var launch = Prepare();
        Assert.Throws<ArgumentException>(() => Arguments(launch, pid, token));
    }

    [Theory]
    [InlineData("hostPid", "1235")]
    [InlineData("mountReady", "false")]
    [InlineData("immutableSnapshot", "false")]
    [InlineData("explicitReadOnly", "false")]
    [InlineData("writeBackend", "\"Native\"")]
    [InlineData("snapshotContainerId", "\"cccccccccccccccccccccccccccccccc\"")]
    [InlineData("snapshotVolumeOid", "102")]
    [InlineData("snapshotVolumeOid", "\"101\"")]
    [InlineData("snapshotXid", "\"10\"")]
    [InlineData("snapshotName", "\"first backup\"")]
    [InlineData("hostPid", "null")]
    [InlineData("mountReady", "\"true\"")]
    public void StaleUnreadyOrMalformedStatusCannotAuthorizeBrowse(string field, string json)
    {
        using var launch = Prepare();
        var status = ReadyStatus();
        status[field] = JsonNode.Parse(json);
        Assert.False(launch.MatchesReadyStatus(Element(status), 1234));
        Assert.True(launch.MatchesReadyStatus(Element(ReadyStatus()), 1234));
    }

    [Fact]
    public void MissingStatusFieldsOrInvalidHostPidCannotAuthorizeBrowse()
    {
        using var launch = Prepare();
        foreach (var key in ReadyStatus().Select(p => p.Key).ToArray())
        {
            var status = ReadyStatus(); status.Remove(key);
            Assert.False(launch.MatchesReadyStatus(Element(status), 1234));
        }
        Assert.False(launch.MatchesReadyStatus(JsonSerializer.SerializeToElement(new { }), 1234));
        Assert.False(launch.MatchesReadyStatus(Element(ReadyStatus()), 0));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CancellationAndReaderFailureReleaseAllPins(bool cancel)
    {
        using var cancellation = new CancellationTokenSource();
        NativeSnapshotBrowseLaunch Action() => NativeSnapshotBrowseLaunch.Prepare(Image, Container, "101", "11", (_, _, _, ct) =>
        {
            AssertPinned();
            if (!cancel) throw new IOException("Injected observer failure.");
            cancellation.Cancel();
            Assert.True(ct.IsCancellationRequested);
            return Element(Inventory());
        }, cancellation.Token);
        if (cancel) Assert.Throws<OperationCanceledException>(Action);
        else Assert.Throws<IOException>(Action);
        AssertReleased();
    }

    [Fact]
    public void DisposedLaunchCannotBuildArgumentsOrAcceptReadyStatus()
    {
        var launch = Prepare(); launch.Dispose();
        Assert.Throws<ObjectDisposedException>(() => Arguments(launch));
        Assert.Throws<ObjectDisposedException>(() => launch.MatchesReadyStatus(Element(ReadyStatus()), 1234));
    }

    [Theory]
    [InlineData("relative")]
    [InlineData(@"D:relative")]
    [InlineData(@"\rooted")]
    [InlineData(@"\\server\share\folder")]
    [InlineData(@"\\?\D:\folder")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"D:\folder\..\child")]
    [InlineData(@"D:\folder\.\child")]
    [InlineData(@"D:\folder:stream")]
    [InlineData(@"D:\folder.\child")]
    [InlineData(@"D:\folder \child")]
    [InlineData(@"D:\folder\\child")]
    public void InvalidOutputPathsCannotProduceArguments(string path)
    {
        using var launch = Prepare();
        var valid = Path.Combine(directory, "valid");
        for (var i = 0; i < 4; ++i)
        {
            var paths = new[] { valid, valid, valid, valid }; paths[i] = path;
            Assert.Throws<ArgumentException>(() => launch.BuildHostArguments(paths[0], paths[1], paths[2], paths[3], Token, 1234));
        }
    }

    [Theory]
    [InlineData(@"C:\ApfsAccessSnapshotTests\new session")]
    [InlineData(@"D:\ApfsAccessSnapshotTests\new session")]
    public void OrdinaryAbsoluteOutputPathsAreNotRestrictedToTheScratchDrive(string path)
        => Assert.Equal(Path.GetFullPath(path), NativeSnapshotBrowseLaunch.ValidateLocalPath(path));

    private NativeSnapshotBrowseLaunch Prepare(JsonObject? node = null)
        => NativeSnapshotBrowseLaunch.Prepare(Image, Container, "101", "11", (_, _, _, _) => Element(node ?? Inventory()));

    private IReadOnlyList<string> Arguments(NativeSnapshotBrowseLaunch launch, int pid = 1234, string token = Token)
        => launch.BuildHostArguments(Path.Combine(directory, "mount"), Path.Combine(directory, "status.json"),
            Path.Combine(directory, "lifetime"), Path.Combine(directory, "startup.gate"), token, pid);

    private static string Value(IReadOnlyList<string> args, string flag)
    {
        Assert.Single(args, a => a == flag);
        return args[Array.IndexOf(args.ToArray(), flag) + 1];
    }

    private void AssertPinned()
    {
        using var reader = File.Open(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.Equal(8192, reader.Length);
        Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete); });
        Assert.Throws<IOException>(() => File.Move(Image, Image + ".moved"));
        Assert.Throws<IOException>(() => File.Delete(Image));
        var replacement = Path.Combine(directory, "replacement.raw");
        File.WriteAllBytes(replacement, [9, 8, 7]);
        Assert.Throws<IOException>(() => File.Replace(replacement, Image, null));
        Assert.True(File.Exists(replacement));
        Assert.Throws<IOException>(() => Directory.Move(directory, directory + "-moved"));
    }

    private void AssertReleased()
    {
        using (var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None)) Assert.Equal(8192, writer.Length);
        File.Move(Image, Image + ".moved"); File.Move(Image + ".moved", Image);
        Directory.Move(directory, directory + "-moved"); Directory.Move(directory + "-moved", directory);
    }

    private string Hash() { using var file = File.OpenRead(Image); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static JsonElement Element(JsonObject node) => JsonSerializer.SerializeToElement(node);
    private JsonObject Inventory() => JsonSerializer.SerializeToNode(new {
        format = "apfs-access-snapshot-inventory", version = 1, readOnly = true,
        source = new { kind = "image", path = Image, sizeBytes = 8192, hashScope = "full", sha256 = Hash() },
        containerUuid = new string('a', 32), volumeUuid = new string('b', 32),
        volumeId = "apfs-vol:" + new string('a', 32) + ":101", volumeOid = "101", checkpointXid = "20",
        storeOffsetBytes = "4096", storeSizeBytes = "4096",
        snapshots = new[] { new { xid = "10", name = "first backup", createTimeNs = "0", superblockPhysicalBlock = "1",
            omapPhysicalBlock = "2", omapTreePhysicalBlock = "3", rootOid = "4", rootPhysicalBlock = "5", extentrefPhysicalBlock = "6" },
            new { xid = "11", name = "second backup", createTimeNs = "0", superblockPhysicalBlock = "11",
            omapPhysicalBlock = "12", omapTreePhysicalBlock = "13", rootOid = "14", rootPhysicalBlock = "15", extentrefPhysicalBlock = "16" } }
    })!.AsObject();

    private static JsonObject ReadyStatus() => JsonSerializer.SerializeToNode(new {
        hostPid = 1234, mountReady = true, immutableSnapshot = true, explicitReadOnly = true, writeBackend = "Disabled",
        snapshotContainerId = new string('a', 32), snapshotVolumeOid = 101UL, snapshotXid = "11", snapshotName = "second backup"
    })!.AsObject();
}
