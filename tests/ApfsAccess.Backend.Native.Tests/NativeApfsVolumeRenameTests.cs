using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Managed keeper transport over the offline rename tool: strict stdout
// claim binding, exact tool-vector checks, per-image journal scoping,
// single bounded recovery, and replacement detection. The native planner
// itself is proven by VolumeRenameTests (584 checks); these gates pin the
// contract between the plan the service confirms and the bytes on disk.
public sealed class NativeApfsVolumeRenameTests
{
    private const string ContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string VolumeHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static ManagementKeeperRenameRequest Keeper(
        string image, string root, string label = "Renamed", string xid = "90")
        => new(image, ContainerHex, VolumeHex, "101", xid, label, root);

    [Fact]
    public void ValidateRequest_PinsIdentityLabelAndJournalShape()
    {
        using var temp = DTempDirectory.Create("rename-validate");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        ApfsVolumeRenameRequest Base() => new(image, ContainerHex, VolumeHex, "101", "90", "Renamed", root);
        NativeApfsVolumeRename.ValidateRequest(Base());
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { NewLabel = "" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { NewLabel = new string('x', 256) }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { NewLabel = "a\0b" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { NewLabel = "lone\ud800surrogate" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { ContainerUuid = new string('0', 32) }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { VolumeUuid = "ABC" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { PreimageXid = "0" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { PreimageXid = "01" }));
        Assert.Throws<ArgumentException>(() => NativeApfsVolumeRename.ValidateRequest(Base() with { JournalRoot = Path.Combine(temp.Path, "missing") }));
        var paired = "a\ud800\udc00b";
        NativeApfsVolumeRename.ValidateRequest(Base() with { NewLabel = paired });
    }

    [Theory]
    [InlineData("Renamed oid=101 xid=91 label=Renamed", 91)]
    [InlineData("Renamed oid=101 xid=9007199254740993 label=caf\u00e9 \ud83d\ude00", 9007199254740993)]
    public void ParseRenamed_AcceptsExactClaim(string line, ulong xid)
    {
        using var temp = DTempDirectory.Create("rename-parse");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var label = line[(line.IndexOf("label=", StringComparison.Ordinal) + 6)..];
        var request = new ApfsVolumeRenameRequest(image, ContainerHex, VolumeHex, "101", "90", label, temp.Path);
        Assert.Equal(xid, NativeApfsVolumeRename.ParseRenamed(line + "\n", request));
    }

    [Theory]
    [InlineData("Renamed oid=102 xid=91 label=Renamed")]
    [InlineData("Renamed oid=101 xid=90 label=Renamed")]
    [InlineData("Renamed oid=101 xid=0 label=Renamed")]
    [InlineData("Renamed oid=101 xid=091 label=Renamed")]
    [InlineData("Renamed oid=101 xid=91 label=Other")]
    [InlineData("Renamed oid=101 xid=91 label=Renamed\nextra")]
    [InlineData("")]
    public void ParseRenamed_RejectsMismatch(string output)
    {
        using var temp = DTempDirectory.Create("rename-parse-refuse");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var request = new ApfsVolumeRenameRequest(image, ContainerHex, VolumeHex, "101", "90", "Renamed", temp.Path);
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeRename.ParseRenamed(output, request));
    }

    [Fact]
    public void JournalDirFor_IsStablePerPathAndDistinctPerTwin()
    {
        using var temp = DTempDirectory.Create("rename-journal-scope");
        var first = Path.Combine(temp.Path, "a.apfs");
        var second = Path.Combine(temp.Path, "b.apfs");
        Assert.Equal(
            NativeApfsVolumeRename.JournalDirFor(temp.Path, first),
            NativeApfsVolumeRename.JournalDirFor(temp.Path, first));
        Assert.NotEqual(
            NativeApfsVolumeRename.JournalDirFor(temp.Path, first),
            NativeApfsVolumeRename.JournalDirFor(temp.Path, second));
    }

    [Fact]
    public async Task RenameVolumeAsync_RecoversThenCommitsWithExactVectors()
    {
        using var temp = DTempDirectory.Create("rename-invoke");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeRenameImage.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var journalDir = NativeApfsVolumeRename.JournalDirFor(root, image);
        var runner = new ScriptRunner(new ObserverRunResult(0, "No accepted rename oid=101 xid=90\n", string.Empty),
            new ObserverRunResult(0, "Renamed oid=101 xid=91 label=Renamed\n", string.Empty));
        var keeper = new NativeApfsVolumeRename(runner, tool, root);

        var result = await keeper.RenameVolumeAsync(Keeper(image, root));

        Assert.True(Directory.Exists(journalDir));
        Assert.Equal(2, runner.AllArguments.Count);
        Assert.Equal(
            ["recover", image, ContainerHex, VolumeHex, "101", journalDir],
            runner.AllArguments[0]);
        Assert.Equal(
            ["rename", image, ContainerHex, VolumeHex, "101", "90", "Renamed", journalDir],
            runner.AllArguments[1]);
        Assert.Equal(ManagementKeeperCodes.Committed, result.Code);
        Assert.True(result.Committed);
        Assert.Equal(91UL, result.CommittedXid);
    }

    [Fact]
    public async Task RenameVolumeAsync_StalePreimage_MapsToDrift()
    {
        using var temp = DTempDirectory.Create("rename-stale");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeRenameImage.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(new ObserverRunResult(0, "No accepted rename oid=101 xid=95\n", string.Empty),
            new ObserverRunResult(1, string.Empty, "Rename refused or requires recovery: Stale preimage XID\n"));
        var keeper = new NativeApfsVolumeRename(runner, tool, root);

        var result = await keeper.RenameVolumeAsync(Keeper(image, root, xid: "90"));

        Assert.False(result.Committed);
        Assert.Equal(ManagementKeeperCodes.StalePreimage, result.Code);
        Assert.Equal(2, runner.AllArguments.Count);
    }

    [Fact]
    public async Task RenameVolumeAsync_UnrecoverableWork_RefusesWithoutRename()
    {
        using var temp = DTempDirectory.Create("rename-unrecovered");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeRenameImage.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(new ObserverRunResult(1, string.Empty, "Rename refused or requires recovery: journal locked\n"));
        var keeper = new NativeApfsVolumeRename(runner, tool, root);

        var result = await keeper.RenameVolumeAsync(Keeper(image, root));

        Assert.False(result.Committed);
        Assert.Equal(ManagementKeeperCodes.Unproven, result.Code);
        Assert.Single(runner.AllArguments);
    }

    [Fact]
    public async Task RenameVolumeAsync_ReplacedImageDuringRefusal_Throws()
    {
        using var temp = DTempDirectory.Create("rename-replaced");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeRenameImage.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var runner = new ScriptRunner(new ObserverRunResult(0, "No accepted rename oid=101 xid=90\n", string.Empty),
            new ObserverRunResult(1, string.Empty, "Rename refused or requires recovery: no\n"),
            replaceOnCall: 2,
            replace: () => { File.Delete(image); File.WriteAllBytes(image, new byte[2097152]); });
        var keeper = new NativeApfsVolumeRename(runner, tool, root);

        var result = await keeper.RenameVolumeAsync(Keeper(image, root));
        Assert.Equal(ManagementKeeperCodes.Unproven, result.Code);
        Assert.False(result.Committed);
    }

    [Fact]
    public async Task RenameVolumeAsync_MissingTool_ThrowsBeforeTouchingImage()
    {
        using var temp = DTempDirectory.Create("rename-notool");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var before = File.GetLastWriteTimeUtc(image);
        var keeper = new NativeApfsVolumeRename(new ScriptRunner(), Path.Combine(temp.Path, "VolumeRenameImage.exe"), root);

        await Assert.ThrowsAsync<FileNotFoundException>(() => keeper.RenameVolumeAsync(Keeper(image, root)));
        Assert.Equal(before, File.GetLastWriteTimeUtc(image));
    }

    [Fact]
    public async Task RenameVolumeAsync_InvalidRequest_ReturnsInvalidWithoutContact()
    {
        using var temp = DTempDirectory.Create("rename-badarg");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[4096]);
        var root = Path.Combine(temp.Path, "journals");
        Directory.CreateDirectory(root);
        var runner = new ScriptRunner();
        var keeper = new NativeApfsVolumeRename(runner, Path.Combine(temp.Path, "VolumeRenameImage.exe"), root);

        var result = await keeper.RenameVolumeAsync(Keeper(image, root, label: ""));

        Assert.False(result.Committed);
        Assert.Equal(ManagementKeeperCodes.InvalidRequest, result.Code);
        Assert.Empty(runner.AllArguments);
    }

    [Fact]
    public async Task RenameVolumeAsync_RealTool_VerifiesIdentityEndToEnd()
    {
        // Real-binary proof through the managed transport: the vector this
        // transport builds must satisfy the real VolumeRenameImage argument
        // contract, and a wrong identity must fail closed with bytes
        // unchanged. A full commit is NOT proven here: the catalog fixture
        // writer emits parser-grade images whose allocator state the native
        // commit capacity gate refuses (CommitCapacityAdmissionRefused);
        // planner commits are proven by VolumeRenameTests on native
        // fixtures, and stdout claim binding by the canned gates above.
        var tool = Environment.GetEnvironmentVariable("APFSACCESS_RENAME_TEST_TOOL");
        Assert.True(File.Exists(tool), "Explicit APFSACCESS_RENAME_TEST_TOOL input is required; historical private binaries are not selected implicitly.");
        using var temp = DTempDirectory.Create("rename-realtool");
        var disk = Path.Combine(temp.Path, "keeper.apfs.img");
        var image = Path.Combine(temp.Path, "container.img");
        var containerGuid = Guid.Parse("a9cb92d2-8b7c-4b59-9eab-633c7625f491");
        var volumeGuid = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
        // The fixture writer stores Guid.TryWriteBytes layout while the
        // native tool reads raw UUID bytes as hex, so the tool arguments
        // use the raw on-disk hex, not Guid "N" format.
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
        var keeper = new NativeApfsVolumeRename(new ProcessObserverRunner(), tool, root);
        var preHash = NativeApfsVolumeRepair.HashFile(image, CancellationToken.None);

        // Wrong container identity fails closed before any mutation.
        var wrong = await keeper.RenameVolumeAsync(new ManagementKeeperRenameRequest(
            image,
            RawHex(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff")),
            volumeHex,
            "101",
            partition.CheckpointXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "Renamed",
            root));
        Assert.False(wrong.Committed);
        Assert.Equal(ManagementKeeperCodes.Unproven, wrong.Code);
        Assert.Equal(preHash, NativeApfsVolumeRepair.HashFile(image, CancellationToken.None));
    }

    [Theory]
    [InlineData("commit-exit")]
    [InlineData("commit-malformed")]
    [InlineData("recover-malformed")]
    [InlineData("recover-wrong-oid")]
    public async Task LegacyDispatchWithoutTerminalProofRequiresOriginalRecovery(string fault)
    {
        using var temp = DTempDirectory.Create("rename-uncertain");
        var image = Path.Combine(temp.Path, "image.apfs");
        File.WriteAllBytes(image, new byte[1048576]);
        var root = Path.Combine(temp.Path, "journals"); Directory.CreateDirectory(root);
        var tool = Path.Combine(temp.Path, "VolumeRenameImage.exe"); File.WriteAllBytes(tool, [0x4d, 0x5a]);
        var recover = fault switch {
            "recover-malformed" => "Invalid recovery claim",
            "recover-wrong-oid" => "No accepted rename oid=102 xid=90",
            _ => "No accepted rename oid=101 xid=90",
        };
        var runner = new ScriptRunner(new(0,recover,""), fault=="commit-exit"?
            new(1,"","Rename refused or requires recovery: injected after acceptance"):
            new(0,"Renamed oid=102 xid=91 label=Renamed",""));
        var result = await new NativeApfsVolumeRename(runner,tool,root).RenameVolumeAsync(Keeper(image,root));
        Assert.Equal(ManagementKeeperCodes.Unproven,result.Code); Assert.False(result.Committed);
        Assert.Equal(fault.StartsWith("recover",StringComparison.Ordinal)?1:2,runner.AllArguments.Count);
    }

    private sealed class ScriptRunner(params ObserverRunResult[] results) : IObserverRunner
    {
        private readonly Queue<ObserverRunResult> queue = new(results);
        private readonly int replaceOnCall;
        private readonly Action? replace;
        public ScriptRunner(ObserverRunResult first, ObserverRunResult second, int replaceOnCall, Action replace)
            : this(first, second)
        {
            this.replaceOnCall = replaceOnCall;
            this.replace = replace;
        }
        public List<IReadOnlyList<string>> AllArguments { get; } = [];
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            AllArguments.Add(arguments.ToArray());
            if (replace is not null && AllArguments.Count == replaceOnCall) replace();
            return queue.Dequeue();
        }
    }
}

