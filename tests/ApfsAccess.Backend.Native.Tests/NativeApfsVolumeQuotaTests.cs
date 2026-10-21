using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Managed keeper transport over the offline quota tool: strict JSON plan
// binding, exact tool-vector checks, native confirm-token flow, bounded
// recovery, and replacement detection. The native planner is proven by
// VolumeQuotaReserveTests (1175 checks); these gates pin the contract
// between the plan the service confirms and the bytes on disk.
public sealed class NativeApfsVolumeQuotaTests
{
    private const string ContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string VolumeHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static ApfsVolumeQuotaRequest Base(string image, string root)
        => new(image, ContainerHex, VolumeHex, "101", "90", "1048576", "524288",
            ["102", "103"], root);

    private static string PlanJson(
        string xid = "90", string oid = "101", string quota = "256", string reserve = "128",
        string blockBytes = "4096", string confirm = null!, string oids = "101,102,103")
    {
        confirm ??= new string('c', 64);
        var volumes = string.Join(",", oids.Split(',').Select(oid =>
            $"{{\"oid\":{oid},\"charged\":10,\"quota\":0,\"reserve\":0}}"));
        return $"{{\"operation\":20,\"xid\":{xid},\"oid\":{oid},\"quotaBlocks\":{quota}," +
            $"\"reserveBlocks\":{reserve},\"blockBytes\":{blockBytes},\"freeBlocks\":1000000," +
            $"\"confirm\":\"{confirm}\",\"volumes\":[{volumes}]}}";
    }

    [Fact]
    public void ValidateRequest_PinsIdentityLimitsSiblingsAndRoots()
    {
        using var temp = DTempDirectory.Create("quota-validate");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[4096]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        NativeApfsVolumeQuota.ValidateRequest(Base(image, root));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { ContainerUuid = new string('0', 32) }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { PreimageXid = "0" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { QuotaBytes = "01" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { ReserveBytes = "x" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { SiblingOids = ["101"] }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { SiblingOids = ["102", "102"] }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { SiblingOids = ["0"] }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { JournalRoot = Path.Combine(temp.Path, "missing") }));
        var unc = Base(image, root) with { Image = @"\\server\share\image.apfs.img" };
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(unc));
        var otherDrive = Base(image, root) with { Image = @"E:\image.apfs.img", JournalRoot = @"E:\" };
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeQuota.ValidateRequest(otherDrive));
        NativeApfsVolumeQuota.ValidateRequest(Base(image, root) with { QuotaBytes = "0", ReserveBytes = "0", SiblingOids = [] });
    }

    [Theory]
    [InlineData("1048576", 4096UL, 256UL)]
    [InlineData("1", 4096UL, 1UL)]
    [InlineData("4096", 4096UL, 1UL)]
    [InlineData("4097", 4096UL, 2UL)]
    [InlineData("0", 4096UL, 0UL)]
    public void ToBlocks_RoundsUpExactByteLimits(string bytes, ulong blockBytes, ulong blocks)
        => Assert.Equal(blocks, NativeApfsVolumeQuota.ToBlocks(bytes, blockBytes));

    [Fact]
    public void ParsePlan_AcceptsExactBinding()
    {
        using var temp = DTempDirectory.Create("quota-parse");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[4096]);
        var request = Base(image, temp.Path);
        var plan = NativeApfsVolumeQuota.ParsePlan(PlanJson(), request, "256", "128");
        Assert.Equal(90UL, plan.PreimageXid);
        Assert.Equal(101UL, plan.TargetOid);
        Assert.Equal(4096UL, plan.BlockBytes);
        Assert.Equal(new string('c', 64), plan.ConfirmToken);
        Assert.Equal([101UL, 102UL, 103UL], plan.VolumeOids);
    }

    [Theory]
    [InlineData("91")]
    [InlineData("102")]
    public void ParsePlan_RejectsIdentityDrift(string field)
    {
        using var temp = DTempDirectory.Create("quota-parse-drift");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[4096]);
        var request = Base(image, temp.Path);
        var json = field == "91" ? PlanJson(xid: "91") : PlanJson(oid: "102");
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(json, request, "256", "128"));
    }

    [Fact]
    public void ParsePlan_RejectsShapeViolations()
    {
        using var temp = DTempDirectory.Create("quota-parse-shape");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[4096]);
        var request = Base(image, temp.Path);
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(PlanJson(quota: "257"), request, "256", "128"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(PlanJson(blockBytes: "0"), request, "256", "128"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(PlanJson(confirm: "short"), request, "256", "128"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(PlanJson(oids: "101,102"), request, "256", "128"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(PlanJson().TrimEnd('}') + ",\"extra\":1}", request, "256", "128"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan("not json", request, "256", "128"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParsePlan(PlanJson() + "\n" + PlanJson(), request, "256", "128"));
    }

    [Fact]
    public void ParseDurable_AcceptsExactCommit()
    {
        Assert.Equal(91UL, NativeApfsVolumeQuota.ParseDurable(
            "{\"durable\":true,\"checkpointXid\":91,\"cleanupSequence\":5}"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParseDurable(
            "{\"durable\":false,\"checkpointXid\":91,\"cleanupSequence\":5}"));
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeQuota.ParseDurable(
            "{\"durable\":true,\"checkpointXid\":91}"));
    }

    [Fact]
    public async Task SetQuotaReserveAsync_FullFlow_CommitsWithExactVectors()
    {
        using var temp = DTempDirectory.Create("quota-invoke");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeQuotaReserveImageTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var journalDir = NativeApfsVolumeQuota.JournalDirFor(root, image);
        string Wal(ulong oid) => Path.Combine(journalDir, $"{oid}.wal");
        var token = new string('c', 64);
        var runner = new ScriptRunner(
            new ObserverRunResult(0, PlanJson(quota: "0", reserve: "0", blockBytes: "4096", confirm: new string('a', 64)) + "\n", string.Empty),
            new ObserverRunResult(0, PlanJson(confirm: token) + "\n", string.Empty),
            new ObserverRunResult(0, "{\"durable\":true,\"checkpointXid\":91,\"cleanupSequence\":5}\n", string.Empty));
        var keeper = new NativeApfsVolumeQuota(runner, tool, root);

        var result = await keeper.SetQuotaReserveAsync(new ManagementKeeperQuotaRequest(
            image, ContainerHex, VolumeHex, "101", "90", "1048576", "524288",
            ["102", "103"], root));

        Assert.Equal(3, runner.AllArguments.Count);
        var probe = new List<string> { "--image", image, "--offset", "0", "--container", ContainerHex,
            "--volume", VolumeHex, "--oid", "101", "--xid", "90",
            "--quota-blocks", "0", "--reserve-blocks", "0",
            "--wal", $"101={Wal(101)}", "--wal", $"102={Wal(102)}", "--wal", $"103={Wal(103)}",
            "--dry-run" };
        Assert.Equal(probe, runner.AllArguments[0]);
        var bind = new List<string>(probe);
        bind[13] = "256";
        bind[15] = "128";
        Assert.Equal(bind, runner.AllArguments[1]);
        var commit = new List<string>(bind) { "--commit", "--confirm", token };
        commit.Remove("--dry-run");
        Assert.Equal(commit, runner.AllArguments[2]);
        Assert.True(result.Committed);
        Assert.Equal(ManagementKeeperCodes.Committed, result.Code);
        Assert.Equal(91UL, result.CommittedXid);
    }

    [Fact]
    public async Task SetQuotaReserveAsync_StaleProbe_MapsToDrift()
    {
        using var temp = DTempDirectory.Create("quota-stale");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeQuotaReserveImageTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(
            new ObserverRunResult(1, string.Empty, "REFUSED exact container/XID mismatch\n"));
        var keeper = new NativeApfsVolumeQuota(runner, tool, root);

        var result = await keeper.SetQuotaReserveAsync(new ManagementKeeperQuotaRequest(
            image, ContainerHex, VolumeHex, "101", "90", "1048576", "524288", ["102"], root));

        Assert.False(result.Committed);
        Assert.Equal(ManagementKeeperCodes.StalePreimage, result.Code);
        Assert.Single(runner.AllArguments);
    }

    [Fact]
    public async Task SetQuotaReserveAsync_ConflictRecoversThenReportsStale()
    {
        using var temp = DTempDirectory.Create("quota-recover");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeQuotaReserveImageTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(
            new ObserverRunResult(1, string.Empty, "REFUSED conflicting accepted session\n"),
            new ObserverRunResult(0, PlanJson(quota: "0", reserve: "0", blockBytes: "4096", oids: "101,102") + "\n", string.Empty),
            new ObserverRunResult(0, "{\"durable\":true,\"checkpointXid\":91,\"cleanupSequence\":5}\n", string.Empty));
        var keeper = new NativeApfsVolumeQuota(runner, tool, root);

        var result = await keeper.SetQuotaReserveAsync(new ManagementKeeperQuotaRequest(
            image, ContainerHex, VolumeHex, "101", "90", "1048576", "524288", ["102"], root));

        Assert.False(result.Committed);
        Assert.Equal(ManagementKeeperCodes.StalePreimage, result.Code);
        Assert.Equal(3, runner.AllArguments.Count);
        Assert.Contains("--recover", runner.AllArguments[1]);
        Assert.Contains("--recover", runner.AllArguments[2]);
        Assert.DoesNotContain("--recover", runner.AllArguments[0]);
    }

    [Fact]
    public async Task SetQuotaReserveAsync_UnrecoverableConflict_Refuses()
    {
        using var temp = DTempDirectory.Create("quota-norecover");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeQuotaReserveImageTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(
            new ObserverRunResult(1, string.Empty, "REFUSED conflicting accepted session\n"),
            new ObserverRunResult(1, string.Empty, "REFUSED WAL intent changed\n"));
        var keeper = new NativeApfsVolumeQuota(runner, tool, root);

        var result = await keeper.SetQuotaReserveAsync(new ManagementKeeperQuotaRequest(
            image, ContainerHex, VolumeHex, "101", "90", "1048576", "524288", ["102"], root));

        Assert.False(result.Committed);
        Assert.Equal(ManagementKeeperCodes.Refused, result.Code);
        Assert.Equal(2, runner.AllArguments.Count);
    }

    [Fact]
    public async Task SetQuotaReserveAsync_UsageError_Throws()
    {
        using var temp = DTempDirectory.Create("quota-usage");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeQuotaReserveImageTool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(new ObserverRunResult(2, string.Empty, "usage\n"));
        var keeper = new NativeApfsVolumeQuota(runner, tool, root);

        await Assert.ThrowsAsync<NativeQuotaExitException>(() => keeper.SetQuotaReserveAsync(
            new ManagementKeeperQuotaRequest(image, ContainerHex, VolumeHex, "101", "90",
                "1048576", "524288", ["102"], root)));
    }

    [Fact]
    public async Task SetQuotaReserveAsync_MissingTool_ThrowsBeforeContact()
    {
        using var temp = DTempDirectory.Create("quota-notool");
        var image = Path.Combine(temp.Path, "image.apfs.img");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var keeper = new NativeApfsVolumeQuota(new ScriptRunner(),
            Path.Combine(temp.Path, "VolumeQuotaReserveImageTool.exe"), root);

        await Assert.ThrowsAsync<FileNotFoundException>(() => keeper.SetQuotaReserveAsync(
            new ManagementKeeperQuotaRequest(image, ContainerHex, VolumeHex, "101", "90",
                "1048576", "524288", ["102"], root)));
    }

    private sealed class ScriptRunner(params ObserverRunResult[] results) : IObserverRunner
    {
        private readonly Queue<ObserverRunResult> queue = new(results);
        public List<IReadOnlyList<string>> AllArguments { get; } = [];
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            AllArguments.Add(arguments.ToArray());
            return queue.Dequeue();
        }
    }

    [Fact]
    public async Task SetQuotaReserveAsync_RealTool_VerifiesIdentityEndToEnd()
    {
        // Real-binary proof through the managed transport: the vector this
        // transport builds must satisfy the real quota tool argument
        // contract, and a wrong identity must fail closed with bytes
        // unchanged. A full commit is NOT proven here (same parser-grade
        // fixture limit as the rename keeper); planner commits are proven
        // by VolumeQuotaReserveTests on native fixtures.
        var tool = Environment.GetEnvironmentVariable("APFSACCESS_QUOTA_TEST_TOOL");
        Assert.True(File.Exists(tool), "Explicit APFSACCESS_QUOTA_TEST_TOOL input is required; historical private binaries are not selected implicitly.");
        using var temp = DTempDirectory.Create("quota-realtool");
        var disk = Path.Combine(temp.Path, "keeper.apfs.img");
        var image = Path.Combine(temp.Path, "container.img");
        var containerGuid = Guid.Parse("a9cb92d2-8b7c-4b59-9eab-633c7625f491");
        var volumeGuid = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
        static string RawHex(Guid value) => Convert.ToHexStringLower(value.ToByteArray());
        var volumeHex = RawHex(volumeGuid);
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(disk, new CatalogFixtureSpec(
            SizeMiB: 16,
            Partitions:
            [
                new CatalogPartitionSpec(
                    ContainerUuid: containerGuid,
                    Xid: 7,
                    Volumes: [new CatalogVolumeSpec(Name: "Data", VolumeUuid: volumeGuid, ObjectId: 101)]),
            ]));
        var partition = Assert.Single(fixture.Partitions);
        using (var source = new FileStream(disk, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var target = new FileStream(image, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            source.Seek(partition.StartByte, SeekOrigin.Begin);
            var remaining = partition.SizeBytes;
            var buffer = new byte[1048576];
            while (remaining > 0)
            {
                var want = (int)Math.Min(buffer.Length, remaining);
                var got = await source.ReadAsync(buffer.AsMemory(0, want));
                Assert.True(got > 0, "Partition slice truncated.");
                await target.WriteAsync(buffer.AsMemory(0, got));
                remaining -= got;
            }
        }

        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var keeper = new NativeApfsVolumeQuota(new ProcessObserverRunner(), tool, root);
        var preHash = NativeApfsVolumeRepair.HashFile(image, CancellationToken.None);

        // Wrong container identity fails closed before any mutation. The
        // quota tool merges container and generation mismatches into one
        // check, so both map to StalePreimage: the caller re-observes,
        // which disambiguates drift from a wrong file, and the detail
        // preserves the native reason.
        var wrong = await keeper.SetQuotaReserveAsync(new ManagementKeeperQuotaRequest(
            image,
            RawHex(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff")),
            volumeHex,
            "101",
            partition.CheckpointXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "1048576",
            "524288",
            [],
            root));
        Assert.False(wrong.Committed);
        Assert.Equal(ManagementKeeperCodes.StalePreimage, wrong.Code);
        Assert.Equal(preHash, NativeApfsVolumeRepair.HashFile(image, CancellationToken.None));
    }
}
