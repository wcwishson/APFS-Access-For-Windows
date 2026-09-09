using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class SnapshotCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath().StartsWith(@"D:\", StringComparison.OrdinalIgnoreCase) ? Path.GetTempPath() : @"D:\Temp", "snapshot-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "literal~�.raw");
    public SnapshotCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, [1, 2, 3]); }
    public void Dispose() => Directory.Delete(directory, true);
    private string[] Args => ["list", "--image", Image, "--container-id", "apfs-container:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--volume-oid", "101"];
    private static (int Exit, JsonElement Json) Run(string[] args, Func<string, string, string, JsonElement>? read = null)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); var exit = SnapshotCommand.Run(args, read); return (exit, JsonDocument.Parse(output.ToString()).RootElement.Clone()); }
        finally { Console.SetOut(previous); }
    }
    [Theory]
    [InlineData("--json")]
    [InlineData("--image")]
    [InlineData("--container-id")]
    [InlineData("--volume-oid")]
    [InlineData("--write")]
    public void RejectsExtraDuplicateFlags(string flag)
    {
        var result = Run([..Args, "--json", flag, "value"], (_, _, _) => throw new Exception("Must not execute"));
        Assert.Equal(2, result.Exit); Assert.False(result.Json.GetProperty("success").GetBoolean());
    }
    [Theory]
    [InlineData("\\\\.\\PhysicalDrive0")]
    [InlineData("\\\\server\\share\\image.raw")]
    [InlineData("D:\\image.raw:stream")]
    [InlineData("relative.raw")]
    [InlineData("D:\\folder\\..\\image.raw")]
    public void RefusesNonLocalOrAliasPaths(string path)
    { var args = Args; args[2] = path; Assert.Equal(2, Run(args).Exit); }
    [Theory]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("18446744073709551616")]
    [InlineData("１")]
    public void RejectsNoncanonicalOid(string oid)
    { var args = Args; args[6] = oid; Assert.Equal(2, Run(args).Exit); }
    [Theory]
    [InlineData("apfs-container:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("apfs-container:00000000000000000000000000000000")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void RejectsContainerAliases(string id)
    { var args = Args; args[4] = id; Assert.Equal(2, Run(args).Exit); }
    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void StableFailureEnvelope(int exit)
    {
        var result = Run(Args, (_, _, _) => throw (exit switch { 3 => new FileNotFoundException("Missing observer"), 4 => new TimeoutException("Timeout"), _ => new InvalidDataException("Native refusal") }));
        Assert.Equal(exit, result.Exit); Assert.Equal(exit, result.Json.GetProperty("exitCode").GetInt32());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("inventory").ValueKind);
        Assert.Equal(result.Json.GetProperty("code").GetString(), result.Json.GetProperty("errorCode").GetString());
    }
    [Fact]
    public void HelpAndMissingSelectors()
    {
        Assert.Contains("snapshots list", Run(["--help"]).Json.GetProperty("usage").GetString());
        Assert.Equal(2, Run(["list"]).Exit);
        Assert.Equal(2, Run(["create"]).Exit);
    }
    [Fact]
    public async Task RegistrationReportsReadOnlyInventory()
    {
        var previous = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); Assert.Equal(0, await Program.RunForTestAsync(["capabilities"])); }
        finally { Console.SetOut(previous); }
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Contains(json.RootElement.GetProperty("commands").EnumerateArray(), x => x.GetString() == "snapshots");
        Assert.Equal("read-only-local-image", json.RootElement.GetProperty("snapshotInventory").GetString());
    }
    [Fact]
    public void SyntheticDefaultAndJsonOutputPreserveLegalPath()
    {
        foreach (var args in new[] { Args, [..Args, "--json"] })
        {
            var result = Run(args, (image, _, _) => { Assert.Equal(Image, image); return JsonSerializer.SerializeToElement(new { readOnly = true }); });
            Assert.Equal(0, result.Exit);
            Assert.True(result.Json.GetProperty("inventory").GetProperty("readOnly").GetBoolean());
        }
        Assert.Equal(4, Run(Args, (_, _, _) => throw new OperationCanceledException()).Exit);
        Assert.Equal(5, Run(Args, (_, _, _) => throw new InvalidDataException("Malformed UTF-8")).Exit);
    }

    [SnapshotIntegrationFact]
    [Trait("Category", "SnapshotIntegrationGate")]
    public void NativeIntegrationGatePackagedObserverDefaultAndJsonOutput()
    {
        var fixtures = Environment.GetEnvironmentVariable("APFS_SNAPSHOT_FIXTURES")!;
        var hashes = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(Environment.GetEnvironmentVariable("APFS_SNAPSHOT_PROVENANCE")!))!;
        foreach (var name in new[] { "ApfsObserver.exe", "one.raw" })
        {
            using var stream = File.OpenRead(Path.Combine(fixtures, name));
            Assert.Equal(hashes[name].ToLowerInvariant(), Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(stream)));
        }
        var binary = Path.Combine(fixtures, "ApfsObserver.exe");
        var directory = Path.Combine(AppContext.BaseDirectory, "native"); Directory.CreateDirectory(directory);
        File.Copy(binary, Path.Combine(directory, "ApfsObserver.exe"), true);
        var realArgs = Args; realArgs[2] = Path.Combine(fixtures, "one.raw");
        try
        {
        foreach (var args in new[] { realArgs, [..realArgs, "--json"] })
        {
            var result = Run(args); Assert.Equal(0, result.Exit);
            Assert.Equal("101", result.Json.GetProperty("inventory").GetProperty("volumeOid").GetString());
            Assert.Single(result.Json.GetProperty("inventory").GetProperty("snapshots").EnumerateArray());
        }
        }
        finally { File.Delete(Path.Combine(directory, "ApfsObserver.exe")); }
    }
}

public sealed class SnapshotIntegrationFactAttribute : FactAttribute
{
    public SnapshotIntegrationFactAttribute()
    {
        if (!File.Exists(Environment.GetEnvironmentVariable("APFS_SNAPSHOT_PROVENANCE")) ||
            new[] { "ApfsObserver.exe", "one.raw" }.Any(name => !File.Exists(Path.Combine(Environment.GetEnvironmentVariable("APFS_SNAPSHOT_FIXTURES") ?? "", name))))
            Skip = "Snapshot integration gate requires APFS_SNAPSHOT_FIXTURES and APFS_SNAPSHOT_PROVENANCE (filename-to-SHA256 JSON).";
    }
}
