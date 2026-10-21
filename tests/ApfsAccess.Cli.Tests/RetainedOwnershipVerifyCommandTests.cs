using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Backend.Native.Tests;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class RetainedOwnershipVerifyCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "retained-accounting-cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image.apfs");
    public RetainedOwnershipVerifyCommandTests()
    { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[2097152]); }
    public void Dispose() => Directory.Delete(directory, true);

    private string[] Args(string fixture = "ordinary") => ["--image", Image, "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-uuid", new string(fixture == "wrong-volume" ? 'c' : 'b', 32), "--volume-oid", "101",
        "--checkpoint-xid", fixture == "snapshot" ? "22" : "31", "--store-offset-bytes", "0", "--store-size-bytes", "2097152",
        .. (fixture == "ordinary-default" ? Array.Empty<string>() : new[] { "--account-retained-ownership" })];

    private static (int Exit, JsonElement Json) Run(string[] args,
        Func<ApfsImageVerificationRequest, CancellationToken, ApfsImageVerificationResult> verify, CancellationToken token = default)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var exit = VerifyCommand.Run(args, verify, token);
            using var json = JsonDocument.Parse(output.ToString()); return (exit, json.RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }

    private string Wire(string fixture = "ordinary")
    {
        var json = RetainedOwnershipNativeReports.Read(fixture);
        using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
        RetainedOwnershipNativeReports.MoveSource(json, Image, NativeApfsImageVerifier.ReadIdentity(handle));
        return json.ToJsonString();
    }

    [Theory]
    [InlineData("ordinary", 0, "RetainedAllocationOwnershipVerified")]
    [InlineData("snapshot", 0, "RetainedAllocationOwnershipVerified")]
    [InlineData("orphan", 3, "VerificationIncomplete")]
    [InlineData("wrong-volume", 4, "VerificationRefused")]
    [InlineData("ordinary-default", 0, "CurrentMetadataSubsetVerified")]
    public void RealNativeJsonTraversesPublicCommandAndHeldSourceDecoder(string fixture, int exit, string code)
    {
        var calls = 0;
        var result = Run(Args(fixture), (request, token) => new NativeApfsImageVerifier(new Runner((arguments, cancellation) => {
            calls++; Assert.Equal(token, cancellation);
            Assert.Equal(fixture != "ordinary-default", request.AccountRetainedOwnership);
            Assert.Equal(fixture == "ordinary-default" ? 0 : 1, arguments.Count(a => a == "--account-retained-ownership"));
            Assert.Contains("verify", arguments); Assert.DoesNotContain("verify-history", arguments);
            Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
            return new(exit, Wire(fixture), "");
        }), Image).Verify(request, token));
        Assert.Equal(1, calls); Assert.Equal(exit, result.Exit);
        Assert.Equal(code, result.Json.GetProperty("code").GetString());
        Assert.Equal(exit, result.Json.GetProperty("nativeExitCode").GetInt32());
        Assert.Equal(exit == 0, result.Json.GetProperty("success").GetBoolean());
        var verification = result.Json.GetProperty("verification");
        Assert.False(verification.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(verification.GetProperty("payloadContentHashesVerified").GetBoolean());
        if (fixture is "ordinary" or "snapshot")
            Assert.Contains("does not certify file contents or reclaimable space", result.Json.GetProperty("message").GetString());
        if (fixture == "orphan") Assert.Contains(verification.GetProperty("findings").EnumerateArray(), f => f.GetProperty("code").GetInt32() == 26);
    }

    [Theory]
    [InlineData("duplicate")] [InlineData("history")] [InlineData("report")]
    public void DuplicateAndConflictingAccountingFlagsNeverReachObserver(string kind)
    {
        string[] extra = kind switch { "duplicate" => ["--account-retained-ownership"],
            "history" => ["--retained-from-xid", "20"], _ => ["--verification-report", @"D:\absent-report.json", "--expected-manifest", @"D:\absent-manifest.json"] };
        var result = Run([.. Args(), .. extra], (_, _) => throw new Exception("Arguments must fail before observer dispatch."));
        Assert.Equal(2, result.Exit); Assert.Equal("InvalidArguments", result.Json.GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
    }

    [Theory]
    [InlineData(2)] [InlineData(99)] [InlineData(-1)]
    public void NativeFailureWithCompleteLookingJsonNeverPublishesReport(int nativeExit)
    {
        var result = Run(Args(), (request, token) => new NativeApfsImageVerifier(
            new Runner((_, _) => new(nativeExit, Wire(), "injected native failure")), Image).Verify(request, token));
        Assert.Equal(5, result.Exit); Assert.Equal("NativeVerificationFailed", result.Json.GetProperty("code").GetString());
        Assert.Equal(nativeExit, result.Json.GetProperty("nativeExitCode").GetInt32());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
    }

    [Theory]
    [InlineData("truncated")] [InlineData("wrong-identity")] [InlineData("legacy")] [InlineData("partial-ownership")]
    public void ProtocolFailureNeverPublishesCompleteOrPartialAccounting(string kind)
    {
        var result = Run(Args(), (request, token) => new NativeApfsImageVerifier(new Runner((_, _) => {
            var node = JsonNode.Parse(Wire(kind == "legacy" ? "ordinary-default" : kind == "partial-ownership" ? "orphan" : "ordinary"))!;
            if (kind == "wrong-identity") node["source"]!["identity"] = "windows-file:1:2:2097152:3";
            if (kind == "partial-ownership") node["retainedOwnership"] = RetainedOwnershipNativeReports.Read()["retainedOwnership"]!.DeepClone();
            return new(kind == "partial-ownership" ? 3 : 0, kind == "truncated" ? "{\"version\":4" : node.ToJsonString(), "");
        }), Image).Verify(request, token));
        Assert.Equal(5, result.Exit); Assert.Equal("InvalidVerificationOutput", result.Json.GetProperty("code").GetString());
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
    }

    [Fact]
    public void CancellationAfterAssignedCompleteResultStillClearsAccountingPayload()
    {
        using var cancel = new CancellationTokenSource();
        var result = Run(Args(), (request, token) => {
            var completed = new NativeApfsImageVerifier(new Runner((_, _) => new(0, Wire(), "")), Image).Verify(request, token);
            cancel.Cancel(); return completed;
        }, cancel.Token);
        Assert.Equal(12, result.Exit); Assert.Equal("VerificationCancelled", result.Json.GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
    }

    [Fact]
    public void PublicHelpDescribesOptInAndUnknownTotals()
    {
        var result = Run(["--help"], (_, _) => throw new Exception("Help cannot start observer."));
        Assert.Equal(0, result.Exit);
        Assert.Contains("--account-retained-ownership", result.Json.GetProperty("usage").GetString());
        Assert.Contains("Snapshot totals and purgeable bytes remain unknown", result.Json.GetProperty("description").GetString());
    }

    private sealed class Runner(Func<IReadOnlyList<string>, CancellationToken, ObserverRunResult> run) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => run(arguments, default);
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments, CancellationToken token = default) => run(arguments, token);
    }
}
