using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeVolumeManagementTests
{
    [Theory]
    [InlineData("prepared", 0, VolumeTopologyMode.Apply)]
    [InlineData("committed", 0, VolumeTopologyMode.Prepare)]
    [InlineData("committed", 1, VolumeTopologyMode.Apply)]
    [InlineData("refused", 0, VolumeTopologyMode.Apply)]
    public void RejectsFalseMutationSuccessAndWrongMode(string outcome, int exit, VolumeTopologyMode mode)
    {
        var r = Request(@"D:\unit.apfs", @"D:\private", "create");
        var wire = Document(r, outcome);
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeManagement.ParseResult(new(exit, wire, ""), r, mode));
    }

    [Theory]
    [InlineData("sourceIdentity")]
    [InlineData("preXid")]
    [InlineData("name")]
    [InlineData("siblingWals")]
    public void RejectsNativeBindingDrift(string field)
    {
        var r = Request(@"D:\unit.apfs", @"D:\private", "create");
        var node = System.Text.Json.Nodes.JsonNode.Parse(Document(r, "prepared"))!.AsObject();
        if (field == "siblingWals") node[field] = new System.Text.Json.Nodes.JsonArray();
        else node[field] = field == "preXid" ? "8" : "changed";
        Assert.Throws<InvalidDataException>(() => NativeApfsVolumeManagement.ParseResult(new(0, node.ToJsonString(), ""), r, VolumeTopologyMode.Prepare));
    }

    [NativeKeeperTheory]
    [InlineData("create")]
    [InlineData("delete")]
    public void RealBinary_CommitsAndRecoversUsingOriginalRequestAfterProcessExit(string operation)
    {
        var r = RealRequest(operation);
        var tool = Environment.GetEnvironmentVariable("APFSACCESS_VMT_TOOL")!;
        var keeper = new NativeApfsVolumeManagement(new ProcessObserverRunner(), tool, r.JournalRoot, r.SpoolRoot);
        var preimage = Hash(r.Image);
        var plan = keeper.Execute(r, VolumeTopologyMode.Prepare, null, default);
        Assert.Equal("prepared", plan.Outcome); Assert.Equal(preimage, Hash(r.Image));
        Save(r, "prepare", plan);
        // Execute uses a separate helper process per invocation and a fresh transport here.
        var apply = new NativeApfsVolumeManagement(new ProcessObserverRunner(), tool, r.JournalRoot, r.SpoolRoot)
            .Execute(r, VolumeTopologyMode.Apply, plan.ConfirmationToken, default);
        Assert.True(apply.Committed, apply.Error); Assert.Equal("8", apply.PostXid); Assert.NotEqual(preimage, Hash(r.Image)); Save(r, "apply", apply);
        var committedHash = Hash(r.Image);
        var recovered = new NativeApfsVolumeManagement(new ProcessObserverRunner(), tool, r.JournalRoot, r.SpoolRoot)
            .Execute(r, VolumeTopologyMode.Recover, null, default);
        Assert.True(recovered.Committed, recovered.Error); Assert.Equal(committedHash, Hash(r.Image)); Save(r, "recover", recovered);
        var replay = keeper.Execute(r, VolumeTopologyMode.Apply, plan.ConfirmationToken, default);
        Assert.Equal("refused", replay.Outcome); Assert.Equal("VolumeManagementConfirmationConsumed", replay.Error);
        Assert.Equal(committedHash, Hash(r.Image)); Save(r, "replay", replay);
    }

    [NativeKeeperTheory]
    [InlineData("create")]
    [InlineData("delete")]
    public void RealBinary_CancelIsByteIdenticalAndSourceReplacementCannotApply(string operation)
    {
        var r = RealRequest(operation); var tool = Environment.GetEnvironmentVariable("APFSACCESS_VMT_TOOL")!;
        var keeper = new NativeApfsVolumeManagement(new ProcessObserverRunner(), tool, r.JournalRoot, r.SpoolRoot);
        var hash = Hash(r.Image);
        var plan = keeper.Execute(r, VolumeTopologyMode.Prepare, null, default);
        Assert.Equal("prepared", plan.Outcome);
        var cancelled = keeper.Execute(r, VolumeTopologyMode.Cancel, plan.ConfirmationToken, default);
        Assert.Equal("cancelled", cancelled.Outcome); Assert.Equal(hash, Hash(r.Image)); Save(r, "cancel", cancelled);
        var again = keeper.Execute(r, VolumeTopologyMode.Prepare, null, default); Assert.Equal("prepared", again.Outcome);
        File.Move(r.Image, r.Image + ".original"); File.Copy(r.Image + ".original", r.Image);
        Assert.Throws<InvalidDataException>(() => keeper.Execute(r, VolumeTopologyMode.Apply, again.ConfirmationToken, default));
        Assert.Equal(hash, Hash(r.Image));
    }

    private static VolumeTopologyRequest RealRequest(string operation)
    {
        var baseRoot = Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT") ?? throw new InvalidOperationException("D scratch required.");
        var root = Path.Combine(baseRoot, "real-vmt-" + operation + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var fixtureRoot = Environment.GetEnvironmentVariable("APFSACCESS_VMT_FIXTURES")!;
        var image = Path.Combine(root, "image.apfs"); File.Copy(Path.Combine(fixtureRoot, "run-final", "cancel", "image.apfs"), image);
        using var refDoc = JsonDocument.Parse(File.ReadAllText(Path.Combine(fixtureRoot, "cli-final", operation == "create" ? "document-1.json" : "document-5.json")));
        var reference = refDoc.RootElement;
        var container = reference.GetProperty("containerUuid").GetString()!;
        var observer = Path.Combine(Path.GetDirectoryName(Environment.GetEnvironmentVariable("APFSACCESS_VMT_TOOL"))!, "ApfsObserver.exe");
        var reader = new NativeApfsSnapshotReader(new ProcessObserverRunner(), observer);
        var census = new[] { "101", "102" }.Select(oid =>
        {
            var observed = reader.Read(image, ApfsTopology.BuildContainerId(container), oid);
            var originalWal = Path.Combine(fixtureRoot, "run-final", "cancel", oid + ".wal");
            Assert.True(File.Exists(originalWal), "The retained fixture must supply every sibling WAL.");
            var wal = Path.Combine(root, oid + ".wal");
            File.Copy(originalWal, wal);
            return new VolumeTopologyWal(oid, observed.GetProperty("volumeUuid").GetString()!, wal);
        }).ToArray();
        // The next OID is from the native fixture's retained prepare document, never a product caller.
        var oid = reference.GetProperty("volumeOid").GetString()!;
        var request = new VolumeTopologyRequest(operation, image, root, "0", container,
            operation == "create" ? Guid.NewGuid().ToString("N") : census.Single(w => w.Oid == oid).VolumeUuid,
            oid, "7", NativeApfsVolumeManagement.SourceIdentity(image, "0"), root, census,
            operation == "create" ? "Managed transport data" : null, operation == "create" ? "64" : null,
            operation == "create" ? "16" : null, operation == "create" ? false : null);
        File.WriteAllText(Path.Combine(root, "original-request.json"), JsonSerializer.Serialize(request));
        return request;
    }
    private static void Save(VolumeTopologyRequest r, string stage, VolumeTopologyResult result) => File.WriteAllText(Path.Combine(r.JournalRoot, stage + ".json"), result.Report.GetRawText());
    private static string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static VolumeTopologyRequest Request(string image, string root, string operation) => new(operation, image, root, "0", new string('a', 32), new string('b', 32), "20480", "7", new string('a', 80), root,
        [new("101", new string('c', 32), @"D:\private\101.wal")], "Data", "64", "16", false);
    private static string Document(VolumeTopologyRequest r, string outcome) => JsonSerializer.Serialize(new
    {
        schemaVersion = 1, operation = "volume-" + r.Operation, outcome, error = "", image = r.Image, sourceIdentity = r.SourceIdentity,
        journal = Path.Combine(r.JournalRoot, "native.vmt1"), containerUuid = r.ContainerUuid, volumeUuid = r.VolumeUuid, volumeOid = r.VolumeOid,
        offsetBytes = r.OffsetBytes, preXid = r.PreXid, postXid = "8", blockBytes = "4096", freeBlocksBefore = "100", freeBlocksAfter = "92", allocatedBlocks = "8", deferredBlocks = "0",
        expiresUnixSeconds = "1791430000", confirmationToken = outcome == "prepared" ? new string('a', 64) : "", siblingWals = r.SiblingWals.Select(w => new { oid = w.Oid, path = w.Path }),
        name = r.Name, quotaBlocks = r.QuotaBlocks, reserveBlocks = r.ReserveBlocks, caseSensitive = r.CaseSensitive
    });
}

public sealed class NativeKeeperTheoryAttribute : TheoryAttribute
{
    public NativeKeeperTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_VMT_TOOL") is null || Environment.GetEnvironmentVariable("APFSACCESS_VMT_FIXTURES") is null)
            Skip = "Real-binary keeper tests require the released native test slot and explicit helper/fixture paths.";
    }
}
