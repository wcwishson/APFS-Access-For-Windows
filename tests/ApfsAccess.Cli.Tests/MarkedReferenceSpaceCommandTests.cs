using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class MarkedReferenceSpaceCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "marked-cli-" + Guid.NewGuid().ToString("N"));
    public MarkedReferenceSpaceCommandTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Path.Combine(directory, "image"), new byte[32768]); }
    public void Dispose() => Directory.Delete(directory, true);
    private string[] Args => ["--image", Path.Combine(directory, "image"), "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-uuid", new string('b', 32), "--volume-oid", "101", "--checkpoint-xid", "20", "--store-offset-bytes", "0", "--store-size-bytes", "32768"];
    private static (int Exit, JsonElement Json) Run(string[] args, Func<ApfsSnapshotAttributionRequest, CancellationToken, ApfsMarkedReferenceSpaceResult> action)
    {
        var old = Console.Out; using var text = new StringWriter(); Console.SetOut(text);
        try { var code = MarkedReferenceSpaceCommand.Run(args, action); using var document = JsonDocument.Parse(text.ToString()); return (code, document.RootElement.Clone()); }
        finally { Console.SetOut(old); }
    }
    [Fact] public void InvalidBroaderSelectorsAreRejectedBeforeCallingNative()
    {
        foreach (var flags in new[] { new[] { "--retained-from-xid", "1" }, ["--require-whole-volume"], ["--credential-stdin"], ["--volume-oid", "102"] })
            Assert.Equal(2, Run([.. Args, .. flags], (_, _) => throw new Exception("must not launch")).Exit);
    }
    [Fact] public void CancellationAndInconsistentTerminalsHaveNoObservation()
    {
        var result = Run(Args, (_, _) => throw new OperationCanceledException()); Assert.Equal(12, result.Exit);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("observation").ValueKind);
        result = Run(Args, (_, _) => new(0, false, JsonSerializer.SerializeToElement(new { complete = false }))); Assert.Equal(5, result.Exit);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("observation").ValueKind);
        result = Run(Args, (_, _) => new(3, false, JsonSerializer.SerializeToElement(new { complete = false, reason = "bounded-refusal" })));
        Assert.Equal(3, result.Exit); Assert.False(result.Json.GetProperty("success").GetBoolean());
    }
}
