using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Backend.Native.Tests;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class SnapshotSpaceCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "snapshot-space-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "fixture.apfs");
    private string[] Args => ["space", "--image", Image, "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-uuid", new string('b', 32), "--volume-oid", "101", "--checkpoint-xid", "22",
        "--store-offset-bytes", "0", "--store-size-bytes", "2097152"];
    public SnapshotSpaceCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[2097152]); }
    public void Dispose() => Directory.Delete(directory, true);

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void CompleteAndUnknownKeepTheirDistinctTerminalStatus(bool unknown)
    {
        var (exit, json) = Run(Args, (request, _) => NativeApfsImageVerifier.ParseSnapshotAttribution(
            (unknown ? SnapshotAttributionTestData.Unknown(Image) : SnapshotAttributionTestData.Read(Image)).ToJsonString(),
            unknown ? 3 : 0, request, SnapshotAttributionTestData.Identity));
        Assert.Equal(unknown ? 3 : 0, exit);
        Assert.Equal(!unknown, json.GetProperty("success").GetBoolean());
        Assert.Equal(unknown ? "SnapshotSpaceUnknown" : "SnapshotSpaceAttributed", json.GetProperty("code").GetString());
        Assert.Equal(!unknown, json.GetProperty("observation").GetProperty("complete").GetBoolean());
    }

    [Theory]
    [InlineData("--json")] [InlineData("--volume-oid")] [InlineData("--snapshot-xid")]
    [InlineData("--device")] [InlineData("--require-whole-volume")] [InlineData("--write")]
    public void DuplicatesAndUnsupportedFlagsNeverDispatch(string extra)
    {
        var called = false;
        var args = extra == "--json" ? new[] { "--json", "--json" } : new[] { extra, "101" };
        var result = Run([.. Args, .. args], (_, _) => { called = true; throw new InvalidOperationException(); });
        Assert.Equal(2, result.Exit); Assert.False(called);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("observation").ValueKind);
    }

    [Fact]
    public void CancellationAfterNativeResultDoesNotPublishTheObservation()
    {
        using var cancel = new CancellationTokenSource();
        var result = Run(Args, (request, _) => {
            var observation = NativeApfsImageVerifier.ParseSnapshotAttribution(
                SnapshotAttributionTestData.Read(Image).ToJsonString(), 0, request, SnapshotAttributionTestData.Identity);
            cancel.Cancel(); return observation;
        }, cancel.Token);
        Assert.Equal(4, result.Exit);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("observation").ValueKind);
    }

    [Fact]
    public void NativeProcessFailureCannotPublishCompleteLookingStdout()
    {
        var result = Run(Args, (_, _) => throw new NativeVerificationExitException(99, "native failure"));
        Assert.Equal(5, result.Exit);
        Assert.Equal(99, result.Json.GetProperty("nativeExitCode").GetInt32());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("observation").ValueKind);
    }

    [Fact]
    public void InconsistentTerminalCannotBecomeASuccess()
    {
        var result = Run(Args, (_, _) => new(99, true, JsonSerializer.SerializeToElement(new { complete = true })));
        Assert.Equal(5, result.Exit);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("observation").ValueKind);
    }

    private static (int Exit, JsonElement Json) Run(string[] args,
        Func<ApfsSnapshotAttributionRequest, CancellationToken, ApfsSnapshotAttributionResult> read, CancellationToken token = default)
    {
        var previous = Console.Out;
        using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var exit = SnapshotSpaceCommand.Run(args, read, token);
            using var document = JsonDocument.Parse(output.ToString());
            return (exit, document.RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }
}
