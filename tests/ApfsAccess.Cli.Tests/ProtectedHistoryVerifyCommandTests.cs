using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class ProtectedHistoryVerifyCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(@"D:\ApfsAccessScratch\WindowsClosure\protected-history-cli-20261015",
        "cli-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image.raw");
    private string[] Args => ["--image", Image, "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-uuid", new string('b', 32), "--volume-oid", "101", "--checkpoint-xid", "20",
        "--store-offset-bytes", "0", "--store-size-bytes", "2097152"];
    private string[] HistoryArgs => [.. Args, "--retained-from-xid", "7", "--json"];
    public ProtectedHistoryVerifyCommandTests()
    {
        Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[2097152]);
    }
    public void Dispose() => Directory.Delete(directory, true);

    private static JsonObject Evidence(ApfsImageVerificationRequest request, string identity, int outcome = 1, int legacyVersion = 2)
    {
        var history = request.RetainedFromXid is not null;
        var node = ExpectedPayloadTestData.Report();
        node["format"] = history ? "apfs-access-protected-history-verification" : "apfs-access-verification";
        node["version"] = history ? 1 : legacyVersion;
        node["source"] = JsonSerializer.SerializeToNode(new { kind = "image", path = request.Image, identity, lease = "windows-read-deny-write-delete" });
        var scope = node["requestedScope"]!.AsObject(); scope.Remove("sourceIdentity"); scope.Remove("sourceKind");
        foreach (var key in new[] { "maxReads", "maxReadBytes", "maxRecords", "maxRecordBytes" }) scope[key] = node["limits"]![key]!.DeepClone();
        scope["requireWholeVolume"] = request.RequireWholeVolume; scope["requirePayloadContentHashes"] = request.RequirePayloadContentHashes;
        var selected = node["selected"]!.AsObject();
        foreach (var property in selected["scope"]!.AsObject())
            if (property.Key is not ("sourceIdentity" or "sourceKind")) selected[property.Key] = property.Value!.DeepClone();
        selected.Remove("scope");
        foreach (var key in new[] { "limits", "elapsedMs", "requireWholeVolume", "requirePayloadContentHashes" }) node.Remove(key);
        if (history || legacyVersion != 3)
        {
            node.Remove("observePayloadContent"); node.Remove("payloadInventory"); node["coverage"]!.AsArray().RemoveAt(20);
        }
        else { scope["maxPayloadLogicalBytes"] = "268435456"; scope["maxPayloadEntries"] = "1024"; }
        if (history)
        {
            node.Remove("repair"); scope["retainedFromXid"] = request.RetainedFromXid;
            node["coverage"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {
                check = 22, implemented = true, required = true, state = 2, scopeDetail = "Requested protected chain"
            }));
            node["requestedHistory"] = new JsonObject {
                ["fromXid"] = request.RetainedFromXid, ["endpoint"] = selected.DeepClone(),
                ["chainXids"] = new JsonArray("7", "20"),
                ["checkpoints"] = new JsonArray(new JsonObject { ["checkpointXid"] = "7",
                    ["metadataRanges"] = new JsonArray(new JsonObject { ["physicalBlock"] = "0", ["blockCount"] = "2" }),
                    ["payloadRanges"] = new JsonArray(new JsonObject { ["physicalBlock"] = "2", ["blockCount"] = "1" }) })
            };
        }
        else if (legacyVersion == 1)
        {
            node.Remove("allocationCensus"); node["coverage"]!.AsArray().RemoveAt(19); node["coverage"]!.AsArray().RemoveAt(18);
        }
        if (outcome != 1)
        {
            node["outcome"] = outcome; node["outcomeName"] = ((ApfsVerificationOutcome)outcome).ToString();
            node["coveredFilesystemRecords"] = "0"; node["coveredPhysicalExtents"] = "0";
            node["allocationCensus"] = null; node["requestedHistory"] = null;
            node["coverage"]![20]!["state"] = outcome == 3 ? 4 : 3;
            node["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {
                code = outcome == 3 ? 2 : 7, severity = outcome == 3 ? 2 : 3, check = 22,
                volumeOid = "101", objectId = (string?)null, physicalBlock = (string?)null,
                checkpointXid = "7", failedSourceOffsetBytes = (string?)null, detail = "Requested chain did not pass"
            }));
        }
        if (!history) node["repair"]!["planId"] = NativeApfsImageVerifier.BuildPlanId(JsonSerializer.SerializeToElement(node));
        return node;
    }

    private (int Exit, JsonElement Json) Run(string[] args, Func<ApfsImageVerificationRequest, CancellationToken, ApfsImageVerificationResult> verify,
        CancellationToken token = default)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output); var exit = VerifyCommand.Run(args, verify, token);
            using var document = JsonDocument.Parse(output.ToString()); return (exit, document.RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }

    [Theory]
    [InlineData(1, 0, "RequestedProtectedHistoryAndCurrentMetadataVerified")]
    [InlineData(2, 3, "VerificationIncomplete")] [InlineData(3, 4, "VerificationRefused")]
    public void CliRunsManagedVerifierThroughHeldImageRunner(int outcome, int exit, string code)
    {
        var calls = 0;
        var result = Run(HistoryArgs, (request, token) => {
            Assert.Equal("7", request.RetainedFromXid); Assert.False(request.RequireWholeVolume); Assert.False(request.RequirePayloadContentHashes);
            var runner = new Runner((args, runnerToken) => {
                calls++; Assert.Equal(token, runnerToken); Assert.Equal("verify-history", args[3]);
                Assert.Equal(new[] { "--retained-from-xid", "7" }, args.TakeLast(2));
                Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
                using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
                return new(exit, Evidence(request, NativeApfsImageVerifier.ReadIdentity(handle), outcome).ToJsonString(), "");
            });
            return new NativeApfsImageVerifier(runner, Image).Verify(request, token);
        });
        Assert.Equal(1, calls); Assert.Equal(exit, result.Exit); Assert.Equal(code, result.Json.GetProperty("code").GetString());
        Assert.Equal(exit, result.Json.GetProperty("nativeExitCode").GetInt32()); Assert.Equal(exit == 0, result.Json.GetProperty("success").GetBoolean());
        var report = result.Json.GetProperty("verification");
        Assert.False(report.TryGetProperty("repair", out _));
        Assert.Equal(outcome == 1 ? JsonValueKind.Object : JsonValueKind.Null, report.GetProperty("requestedHistory").ValueKind);
        if (outcome == 1) Assert.Equal("Only the requested protected checkpoint chain and covered current metadata passed verification.", result.Json.GetProperty("message").GetString());
    }

    [Theory]
    [InlineData("--require-whole-volume")] [InlineData("--require-payload-content-hashes")]
    [InlineData("--expected-manifest")] [InlineData("--verification-report")]
    [InlineData("--retained-from-xid")] [InlineData("--device-id")] [InlineData("--mode")]
    public void ConflictingOrUnrelatedOptionsAreRejectedBeforeRunner(string flag)
    {
        var args = flag is "--require-whole-volume" or "--require-payload-content-hashes" ?
            new[] { flag } : new[] { flag, flag == "--retained-from-xid" ? "7" : Path.Combine(directory, "absent.json") };
        AssertInvalid([.. HistoryArgs, .. args]);
    }

    [Theory]
    [InlineData("")] [InlineData("0")] [InlineData("07")] [InlineData("+7")] [InlineData("-7")]
    [InlineData(" 7")] [InlineData("7.0")] [InlineData("18446744073709551616")] [InlineData("20")] [InlineData("21")]
    public void NoncanonicalOrNonhistoricalStartNeverLaunches(string start) => AssertInvalid([.. Args, "--retained-from-xid", start]);

    [Fact]
    public void MissingValueAndOfflineCombinationsNeverLaunch()
    {
        AssertInvalid([.. Args, "--retained-from-xid"]);
        AssertInvalid([.. Args, "--retained-from-xid", "--json"]);
        AssertInvalid(["--verification-report", Path.Combine(directory, "report.json"), "--expected-manifest",
            Path.Combine(directory, "manifest.json"), "--retained-from-xid", "7"]);
        for (var index = 0; index < Args.Length; index += 2)
            AssertInvalid([.. Args[..index], .. Args[(index + 2)..], "--retained-from-xid", "7"]);
    }

    [Theory]
    [InlineData("relative.raw")] [InlineData(@"\\.\PhysicalDrive0")] [InlineData(@"\\server\share\image.raw")]
    [InlineData(@"D:\image.raw:stream")] [InlineData(@"D:\folder\..\image.raw")]
    public void HistoryKeepsLocalImageAdmission(string path)
    { var args = HistoryArgs; args[1] = path; AssertInvalid(args); }

    private void AssertInvalid(string[] args)
    {
        var calls = 0;
        var result = Run(args, (_, _) => { calls++; throw new InvalidOperationException("Must not execute"); });
        Assert.Equal(0, calls); Assert.Equal(2, result.Exit); Assert.Equal("InvalidArguments", result.Json.GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
    }

    [Theory]
    [InlineData("downgrade", 5)] [InlineData("partial", 5)] [InlineData("exitMismatch", 5)] [InlineData("sourceMismatch", 5)]
    [InlineData("nativeExit", 5)] [InlineData("timeout", 6)] [InlineData("cancel", 12)]
    public void RunnerProtocolAndTransportFailuresPublishNoReport(string failure, int exit)
    {
        using var cancellation = new CancellationTokenSource();
        var result = Run(HistoryArgs, (request, token) => {
            var runner = new Runner((_, _) => {
                if (failure == "timeout") throw new TimeoutException();
                if (failure == "cancel") cancellation.Cancel();
                using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
                var source = failure == "sourceMismatch" ? "wrong-source" : NativeApfsImageVerifier.ReadIdentity(handle);
                var wire = Evidence(failure == "downgrade" ? request with { RetainedFromXid = null } : request, source).ToJsonString();
                return new(failure == "nativeExit" ? 2 : failure == "exitMismatch" ? 3 : 0, failure == "partial" ? wire[..^1] : wire, "failure");
            });
            return new NativeApfsImageVerifier(runner, Image).Verify(request, token);
        }, cancellation.Token);
        Assert.Equal(exit, result.Exit); Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
        using var after = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void AbsentOptionPreservesLegacyReportsThroughRunner(int version)
    {
        string? wire = null;
        var result = Run(Args, (request, token) => {
            Assert.Null(request.RetainedFromXid);
            return new NativeApfsImageVerifier(new Runner((args, _) => {
                Assert.Equal("verify", args[3]); Assert.DoesNotContain("--retained-from-xid", args);
                using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
                wire = Evidence(request, NativeApfsImageVerifier.ReadIdentity(handle), legacyVersion: version).ToJsonString();
                return new(0, wire, "");
            }), Image).Verify(request, token);
        });
        Assert.Equal(0, result.Exit); Assert.Equal("CurrentMetadataSubsetVerified", result.Json.GetProperty("code").GetString());
        using var expected = JsonDocument.Parse(wire!);
        Assert.True(JsonElement.DeepEquals(expected.RootElement, result.Json.GetProperty("verification")));
        Assert.False(result.Json.GetProperty("verification").TryGetProperty("requestedHistory", out _));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void MalformedHistoryMetadataDoesNotBecomePublicSuccess(bool emptyPayload)
    {
        var calls = 0;
        var result = Run(HistoryArgs, (request, token) => new NativeApfsImageVerifier(new Runner((_, _) => {
            calls++;
            using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
            var node = Evidence(request, NativeApfsImageVerifier.ReadIdentity(handle));
            node["requestedHistory"]!["checkpoints"]![0]!["metadataRanges"] = new JsonArray();
            if (emptyPayload) node["requestedHistory"]!["checkpoints"]![0]!["payloadRanges"] = new JsonArray();
            return new(0, node.ToJsonString(), "");
        }), Image).Verify(request, token));
        Assert.Equal(1, calls);
        Assert.Equal(5, result.Exit);
        Assert.Equal("InvalidVerificationOutput", result.Json.GetProperty("code").GetString());
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
    }

    [Fact]
    public void CompleteHistoryWithEmptyPayloadStillPublishesSuccess()
    {
        var result = Run(HistoryArgs, (request, token) => new NativeApfsImageVerifier(new Runner((_, _) => {
            using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
            var node = Evidence(request, NativeApfsImageVerifier.ReadIdentity(handle));
            node["requestedHistory"]!["checkpoints"]![0]!["payloadRanges"] = new JsonArray();
            return new(0, node.ToJsonString(), "");
        }), Image).Verify(request, token));
        Assert.Equal(0, result.Exit);
        Assert.Equal("RequestedProtectedHistoryAndCurrentMetadataVerified", result.Json.GetProperty("code").GetString());
    }

    [Fact]
    public void LegacyBroaderFlagsAndHistoryHelpRemainAvailable()
    {
        var request = VerifyCommand.ParseArguments([.. Args, "--require-whole-volume", "--require-payload-content-hashes"]);
        Assert.Null(request.RetainedFromXid); Assert.True(request.RequireWholeVolume); Assert.True(request.RequirePayloadContentHashes);
        var help = Run(["--help"], (_, _) => throw new InvalidOperationException("Must not execute"));
        Assert.Equal(0, help.Exit); Assert.Contains("--retained-from-xid START_XID", help.Json.GetProperty("usage").GetString());
        Assert.Contains("Full historical reachability", help.Json.GetProperty("description").GetString());
    }

    private sealed class Runner(Func<IReadOnlyList<string>, CancellationToken, ObserverRunResult> run) : IObserverRunner
    {
        public ObserverRunResult Run(string path, IReadOnlyList<string> args) => run(args, default);
        public ObserverRunResult Run(string path, IReadOnlyList<string> args, CancellationToken token)
        { token.ThrowIfCancellationRequested(); var result = run(args, token); token.ThrowIfCancellationRequested(); return result; }
    }
}
