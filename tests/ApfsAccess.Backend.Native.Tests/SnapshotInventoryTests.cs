using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class SnapshotInventoryTests : IDisposable
{
    private static string Fixtures => Environment.GetEnvironmentVariable("APFS_SNAPSHOT_FIXTURES")!;
    private readonly string directory = Path.Combine(Path.GetTempPath().StartsWith(@"D:\", StringComparison.OrdinalIgnoreCase) ? Path.GetTempPath() : @"D:\Temp", "snapshot-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "literal~�.raw");
    public SnapshotInventoryTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[4096]); }
    public void Dispose() => Directory.Delete(directory, true);
    private const string Container = "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private JsonObject Evidence() => System.Text.Json.JsonSerializer.SerializeToNode(new {
        format = "apfs-access-snapshot-inventory", version = 1, readOnly = true,
        source = new { kind = "image", path = Image, sizeBytes = 4096, hashScope = "full", sha256 = Hash(Image) },
        containerUuid = new string('a', 32), volumeUuid = new string('b', 32),
        volumeId = "apfs-vol:" + new string('a', 32) + ":101", volumeOid = "101", checkpointXid = "20",
        storeOffsetBytes = "0", storeSizeBytes = "4096",
        snapshots = new[] { "backup", "second" }.Select((name, i) => new {
            xid = (10 + i).ToString(), name, createTimeNs = "0", superblockPhysicalBlock = "1",
            omapPhysicalBlock = "2", omapTreePhysicalBlock = "3", rootOid = "4", rootPhysicalBlock = "5", extentrefPhysicalBlock = "6"
        }).ToArray()
    })!.AsObject();
    private System.Text.Json.JsonElement Parse(JsonObject node) => NativeApfsSnapshotReader.ParseInventory(node.ToJsonString(), Image, Container, "101", 4096, Hash(Image));

    [SnapshotIntegrationTheory]
    [Trait("Category", "SnapshotIntegrationGate")]
    [InlineData("one", 1)]
    [InlineData("two", 2)]
    [InlineData("empty", 0)]
    public void NativeIntegrationGateInventory(string fixture, int count)
    {
        var binary = Path.Combine(Fixtures, "ApfsObserver.exe");
        ValidateProvenance();
        var staged = StagedPackagedObserver.Stage(binary, "snapshot-495-" + fixture);
        var image = Path.Combine(Fixtures, fixture + ".raw");
        var before = Hash(image);
        var result = new NativeApfsSnapshotReader(new ProcessObserverRunner(), staged).Read(image, Container, "101");
        Assert.Equal(count, result.GetProperty("snapshots").GetArrayLength());
        Assert.Equal(before, result.GetProperty("source").GetProperty("sha256").GetString());
        Assert.Equal(before, Hash(image));
    }

    [SnapshotIntegrationFact]
    [Trait("Category", "SnapshotIntegrationGate")]
    public void NativeIntegrationGateRefusalNeverReturnsPartialInventory()
    {
        ValidateProvenance();
        var staged = StagedPackagedObserver.Stage(Path.Combine(Fixtures, "ApfsObserver.exe"), "snapshot-495-refusal");
        var reader = new NativeApfsSnapshotReader(new ProcessObserverRunner(), staged);
        var image = Path.Combine(Fixtures, "bad.raw"); var before = Hash(image);
        Assert.Throws<InvalidDataException>(() => reader.Read(image, Container, "101"));
        Assert.Equal(before, Hash(image));
        Assert.Throws<InvalidDataException>(() => reader.Read(Path.Combine(Fixtures, "one.raw"), Container, "102"));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("+1")]
    [InlineData(" 1")]
    [InlineData("18446744073709551616")]
    [InlineData("١")]
    public void RejectsInvalidIdentifiers(string value)
    {
        var node = Evidence(); node["snapshots"]![0]!["xid"] = value;
        Assert.Throws<InvalidDataException>(() => Parse(node));
    }

    [Theory]
    [InlineData("readOnly")]
    [InlineData("containerUuid")]
    [InlineData("volumeOid")]
    [InlineData("volumeId")]
    [InlineData("source")]
    [InlineData("hash")]
    [InlineData("duplicateXid")]
    [InlineData("duplicateName")]
    [InlineData("duplicateUuid")]
    [InlineData("numericOid")]
    [InlineData("missingRoot")]
    [InlineData("unknownWriteFlag")]
    public void RejectsContradictoryOrIncompleteEvidence(string mutation)
    {
        var node = Evidence();
        switch (mutation)
        {
            case "readOnly": node["readOnly"] = false; break;
            case "containerUuid": node[mutation] = new string('c', 32); break;
            case "volumeOid": node[mutation] = "102"; break;
            case "volumeId": node[mutation] = "apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:102"; break;
            case "source": node["source"]!["path"] = "D:\\wrong.raw"; break;
            case "hash": node["source"]!["sha256"] = new string('0', 64); break;
            case "duplicateXid": node["snapshots"]![1]!["xid"] = "10"; break;
            case "duplicateName": node["snapshots"]![1]!["name"] = "backup"; break;
            case "duplicateUuid": foreach (var s in node["snapshots"]!.AsArray()) s!["uuid"] = new string('c', 32); break;
            case "numericOid": node["volumeOid"] = 101; break;
            case "missingRoot": node["snapshots"]![0]!.AsObject().Remove("rootOid"); break;
            case "unknownWriteFlag": node["writeEnabled"] = true; break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(node));
    }

    [Theory]
    [InlineData("trailing")]
    [InlineData("duplicateProperty")]
    [InlineData("surrogate")]
    [InlineData("literalSurrogate")]
    public void RejectsMalformedJson(string kind)
    {
        var json = Evidence().ToJsonString();
        json = kind switch { "trailing" => json + "{}", "duplicateProperty" => json.Replace("\"readOnly\":true", "\"readOnly\":true,\"readOnly\":false"), "literalSurrogate" => json.Replace("backup", "\uD800"), _ => json.Replace("backup", "\\uD800") };
        Assert.Throws<InvalidDataException>(() => NativeApfsSnapshotReader.ParseInventory(json, Image, Container, "101", 4096, Hash(Image)));
    }

    [Fact]
    public void PreservesUnicodeAndMaximumU64WithoutRounding()
    {
        var node = Evidence(); node["snapshots"]![0]!["name"] = "备份😀é~�";
        node["snapshots"]![0]!["xid"] = "18446744073709551615";
        var parsed = Parse(node);
        Assert.Equal("备份😀é~�", parsed.GetProperty("snapshots")[0].GetProperty("name").GetString());
        Assert.Equal("18446744073709551615", parsed.GetProperty("snapshots")[0].GetProperty("xid").GetString());
    }

    [Fact]
    public void ReaderPreservesNamesArgumentsAndHashAgreement()
    {
        var runner = new SyntheticRunner(Evidence().ToJsonString());
        var reader = new NativeApfsSnapshotReader(runner, Image);
        Assert.Equal(2, reader.Read(Image, Container, "101").GetProperty("snapshots").GetArrayLength());
        Assert.Equal(new[] { "--image", Image, "--mode", "snapshots", "--container-uuid", Container[15..], "--volume-oid", "101" }, runner.Arguments);
        var bad = Evidence(); bad["source"]!["sha256"] = new string('0', 64);
        Assert.Throws<InvalidDataException>(() => new NativeApfsSnapshotReader(new SyntheticRunner(bad.ToJsonString()), Image).Read(Image, Container, "101"));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.Read(Image, Container, "101", cancelled.Token));
    }

    private sealed class SyntheticRunner(string json) : IObserverRunner
    {
        public IReadOnlyList<string>? Arguments { get; private set; }
        public ObserverRunResult Run(string path, IReadOnlyList<string> arguments)
        { Arguments = arguments; return new(0, json, ""); }
    }

    private static void ValidateProvenance()
    {
        // Caller supplies a JSON object mapping each required filename to its SHA-256.
        var hashes = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(Environment.GetEnvironmentVariable("APFS_SNAPSHOT_PROVENANCE")!))!;
        foreach (var name in new[] { "ApfsObserver.exe", "one.raw", "two.raw", "empty.raw", "bad.raw" })
            Assert.Equal(hashes[name].ToLowerInvariant(), Hash(Path.Combine(Fixtures, name)));
    }
}

internal static class SnapshotIntegrationInputs
{
    internal static string? Missing => !File.Exists(Environment.GetEnvironmentVariable("APFS_SNAPSHOT_PROVENANCE")) ||
        new[] { "ApfsObserver.exe", "one.raw", "two.raw", "empty.raw", "bad.raw" }.Any(name => !File.Exists(Path.Combine(Environment.GetEnvironmentVariable("APFS_SNAPSHOT_FIXTURES") ?? "", name)))
        ? "Snapshot integration gate requires APFS_SNAPSHOT_FIXTURES and APFS_SNAPSHOT_PROVENANCE (filename-to-SHA256 JSON)." : null;
}
public sealed class SnapshotIntegrationFactAttribute : FactAttribute
{ public SnapshotIntegrationFactAttribute() { Skip = SnapshotIntegrationInputs.Missing; } }
public sealed class SnapshotIntegrationTheoryAttribute : TheoryAttribute
{ public SnapshotIntegrationTheoryAttribute() { Skip = SnapshotIntegrationInputs.Missing; } }
