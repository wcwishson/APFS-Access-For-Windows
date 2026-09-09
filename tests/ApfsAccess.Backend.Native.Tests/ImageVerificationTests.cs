using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ImageVerificationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "image-verification-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "literal~�.raw");
    private const string Identity = "windows-file:1:2:4096:3";
    private ApfsImageVerificationRequest Request => new(Image, "apfs-container:" + new string('a', 32), new string('b', 32), "101", "20", "0", "4096");
    public ImageVerificationTests() { Directory.CreateDirectory(directory); File.WriteAllBytes(Image, new byte[4096]); }
    public void Dispose() => Directory.Delete(directory, true);

    private JsonObject Evidence(int outcome = 1, bool whole = false, bool hashes = false)
    {
        var node = JsonSerializer.SerializeToNode(new {
            format = "apfs-access-verification", version = 1, readOnly = true,
            source = new { kind = "image", path = Image, identity = Identity, lease = "windows-read-deny-write-delete" },
            requestedScope = new { containerUuid = new string('a', 32), volumeUuid = new string('b', 32), volumeOid = "101", checkpointXid = "20",
                storeOffsetBytes = "0", storeSizeBytes = "4096", maxReads = "65536", maxReadBytes = "268435456", maxRecords = "1000000", maxRecordBytes = "268435456",
                requireWholeVolume = whole, requirePayloadContentHashes = hashes },
            selected = new { containerUuid = new string('a', 32), volumeUuid = new string('b', 32), volumeOid = "101", checkpointXid = "20",
                storeOffsetBytes = "0", storeSizeBytes = "4096", checkpointPhysicalBlock = "12", volumeSuperblockPhysicalBlock = "4", volumeSuperblockXid = "20", rootOid = "8293", rootPhysicalBlock = "7" },
            outcome, outcomeName = ((ApfsVerificationOutcome)outcome).ToString(), wholeVolumeVerified = false, payloadContentHashesVerified = false,
            sourceReads = "62", sourceReadBytes = "241760", coveredFilesystemRecords = outcome == 1 ? "5" : "0", coveredPhysicalExtents = outcome == 1 ? "1" : "0",
            findings = Array.Empty<object>(),
            coverage = Enumerable.Range(1,18).Select(check => new { check, implemented = check <= 11 || check >= 17,
                required = check <= 11 || check >= 17 || (check is 12 or 13 && whole) || (check == 14 && (whole || hashes)),
                state = check is 15 or 16 ? 4 : check is 12 or 13 or 14 ? 1 : 2, scopeDetail = "Declared subset; gaps remain visible." }).ToArray(),
            repair = new { planId = "", refusal = outcome == 1 ? 1 : 2, nextActionableCandidate = (object?)null }
        })!.AsObject();
        if (outcome != 1)
        {
            var check = whole ? 12 : hashes ? 14 : 1;
            node["coverage"]![check - 1]!["state"] = outcome == 3 ? 4 : whole || hashes ? 1 : 3;
            node["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {
                code = whole || hashes ? 18 : outcome == 3 ? 2 : 6, severity = outcome == 3 ? 2 : 3, check,
                volumeOid = (string?)null, objectId = "18446744073709551615", physicalBlock = (string?)null,
                checkpointXid = "20", failedSourceOffsetBytes = (string?)null, detail = "Synthetic finding 😀"
            }));
            if (outcome == 3) node["selected"] = null;
        }
        Bind(node); return node;
    }
    private static void Bind(JsonObject node) => node["repair"]!["planId"] = NativeApfsImageVerifier.BuildPlanId(JsonSerializer.SerializeToElement(node));
    private ApfsImageVerificationResult Parse(JsonObject node, int exit = 0, ApfsImageVerificationRequest? request = null)
        => NativeApfsImageVerifier.ParseReport(node.ToJsonString(), exit, request ?? Request, Identity);

    [Theory]
    [InlineData(1, 0)] [InlineData(2, 3)] [InlineData(3, 4)]
    public void TypedOutcomesPreserveEveryCoverageAndUint64String(int outcome, int exit)
    {
        var result = Parse(Evidence(outcome), exit);
        Assert.Equal((ApfsVerificationOutcome)outcome, result.Outcome); Assert.Equal(exit, result.NativeExitCode);
        Assert.Equal(18, result.Report.GetProperty("coverage").GetArrayLength());
        Assert.False(result.Report.GetProperty("wholeVolumeVerified").GetBoolean());
        if (outcome != 1) Assert.Equal("18446744073709551615", result.Report.GetProperty("findings")[0].GetProperty("objectId").GetString());
    }
    [Theory]
    [InlineData(true, false)] [InlineData(false, true)] [InlineData(true, true)]
    public void RequestedBroaderCoverageRemainsIncomplete(bool whole, bool hashes)
    { Assert.Equal(ApfsVerificationOutcome.Incomplete, Parse(Evidence(2, whole, hashes), 3, Request with { RequireWholeVolume = whole, RequirePayloadContentHashes = hashes }).Outcome); }

    [Theory]
    [InlineData("version")] [InlineData("outcome")] [InlineData("selected")] [InlineData("scope")] [InlineData("source")]
    [InlineData("missingCoverage")] [InlineData("duplicateCoverage")] [InlineData("implemented")] [InlineData("required")]
    [InlineData("missingFinding")] [InlineData("overflow")] [InlineData("numeric64")] [InlineData("whole")]
    [InlineData("extra")] [InlineData("plan")] [InlineData("limit")] [InlineData("nullString")]
    public void TamperedOrInconsistentOutputIsNeverAResult(string mutation)
    {
        var node = Evidence();
        switch (mutation)
        {
            case "version": node["version"] = 2; break;
            case "outcome": node["outcome"] = 2; break;
            case "selected": node["selected"]!["volumeOid"] = "102"; break;
            case "scope": node["requestedScope"]!["checkpointXid"] = "21"; break;
            case "source": node["source"]!["identity"] = "windows-file:1:3:4096:3"; break;
            case "missingCoverage": node["coverage"]!.AsArray().RemoveAt(0); break;
            case "duplicateCoverage": node["coverage"]![1]!["check"] = 1; break;
            case "implemented": node["coverage"]![11]!["implemented"] = true; break;
            case "required": node["coverage"]![0]!["required"] = false; break;
            case "missingFinding": node["coverage"]![0]!["state"] = 3; break;
            case "overflow": node["sourceReads"] = "18446744073709551616"; break;
            case "numeric64": node["sourceReads"] = 62; break;
            case "whole": node["wholeVolumeVerified"] = true; break;
            case "extra": node["unexpected"] = true; break;
            case "plan": node["repair"]!["planId"] = "tampered"; break;
            case "limit": node["requestedScope"]!["maxReads"] = "65537"; break;
            case "nullString": node["coverage"]![0]!["scopeDetail"] = null; break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(node));
        if (mutation is not ("nullString" or "plan")) { Bind(node); Assert.Throws<InvalidDataException>(() => Parse(node)); }
    }
    [Fact]
    public void DuplicateTruncatedMalformedAndOversizedOutputFails()
    {
        var json = Evidence().ToJsonString();
        foreach (var bad in new[] { json[..^1], json.Replace("\"version\":1", "\"version\":1,\"version\":1"), json + "{}", "\ud800" })
            Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(bad, 0, Request, Identity));
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(new string(' ', NativeApfsImageVerifier.MaxReportBytes + 1), 0, Request, Identity));
        Assert.Throws<InvalidDataException>(() => Parse(Evidence(), 3));
        Assert.Throws<InvalidDataException>(() => Parse(Evidence(), 2));
    }
    [Theory]
    [InlineData("0")] [InlineData("01")] [InlineData("+1")] [InlineData("18446744073709551616")] [InlineData("１")]
    public void NoncanonicalExactSelectorsAreRejected(string value)
    {
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { VolumeOid = value }));
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { CheckpointXid = value }));
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { StoreSizeBytes = value }));
    }
    [Fact]
    public void StoreOverflowAndUuidAliasesAreRejected()
    {
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { StoreOffsetBytes = "18446744073709551615" }));
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { VolumeUuid = new string('0',32) }));
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { VolumeUuid = new string('B',32) }));
    }

    private sealed class Runner(Func<IReadOnlyList<string>, ObserverRunResult> run) : IObserverRunner
    { public ObserverRunResult Run(string path, IReadOnlyList<string> arguments) => run(arguments); }
    [Theory]
    [InlineData(1, 0)] [InlineData(2, 3)] [InlineData(3, 4)]
    public void ReaderUsesExactArgumentsAndHeldIdentity(int outcome, int exit)
    {
        var runner = new Runner(args => {
            Assert.Equal(new[] { "--image", Image, "--mode", "verify", "--container-uuid", new string('a',32), "--volume-uuid", new string('b',32),
                "--volume-oid", "101", "--checkpoint-xid", "20", "--store-offset-bytes", "0", "--store-size-bytes", "4096" }, args);
            Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
            using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
            var node = Evidence(outcome); node["source"]!["identity"] = NativeApfsImageVerifier.ReadIdentity(handle); Bind(node);
            return new(exit, node.ToJsonString(), "");
        });
        Assert.Equal(exit, new NativeApfsImageVerifier(runner, Image).Verify(Request).NativeExitCode);
    }
    [Theory]
    [InlineData(0)] [InlineData(3)] [InlineData(4)]
    public void SharedTransportReturnsExitWithoutInterpretingIt(int exit)
    {
        var result = new ProcessObserverRunner().Run("cmd.exe", ["/d", "/c", "exit", exit.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
        Assert.Equal(exit, result.ExitCode);
    }
    [Theory]
    [InlineData(2)] [InlineData(1)] [InlineData(99)]
    public void OtherNativeExitsCannotBecomeResults(int exit)
    {
        var verifier = new NativeApfsImageVerifier(new Runner(_ => new(exit, Evidence().ToJsonString(), "native failure")), Image);
        Assert.Equal(exit, Assert.Throws<NativeVerificationExitException>(() => verifier.Verify(Request)).NativeExitCode);
    }
    [Fact]
    public void CancellationAndTransportErrorsRemainFailures()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        var verifier = new NativeApfsImageVerifier(new Runner(_ => throw new Exception("Must not execute")), Image);
        Assert.Throws<OperationCanceledException>(() => verifier.Verify(Request, cts.Token));
        foreach (var error in new Exception[] { new TimeoutException(), new InvalidDataException(), new IOException() })
            Assert.Throws(error.GetType(), () => new NativeApfsImageVerifier(new Runner(_ => throw error), Image).Verify(Request));
    }

    [VerificationIntegrationFact]
    [Trait("Category", "VerificationIntegrationGate")]
    public void OptionalPrivateObserverHealthyAndCorruptIntegration()
    {
        var observer = Environment.GetEnvironmentVariable("APFS_VERIFY_TEST_OBSERVER")!;
        foreach (var pair in new[] { ("APFS_VERIFY_TEST_HEALTHY", 0), ("APFS_VERIFY_TEST_CORRUPT", 3) })
        {
            var original = Environment.GetEnvironmentVariable(pair.Item1)!;
            var image = Path.Combine(directory, pair.Item1 + ".apfs"); File.Copy(original, image);
            var before = System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(image));
            var request = Request with { Image = image, StoreSizeBytes = "2097152" };
            var result = new NativeApfsImageVerifier(new ProcessObserverRunner { Timeout = TimeSpan.FromSeconds(20) }, observer).Verify(request);
            Assert.Equal(pair.Item2, result.NativeExitCode);
            Assert.Equal(18, result.Report.GetProperty("coverage").GetArrayLength());
            var results = Environment.GetEnvironmentVariable("APFS_VERIFY_TEST_RESULTS");
            if (results is not null) File.WriteAllText(Path.Combine(results, pair.Item1 + ".json"), result.Report.GetRawText());
            Assert.Equal(before, System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(image)));
        }
    }
}
public sealed class VerificationIntegrationFactAttribute : FactAttribute
{
    public VerificationIntegrationFactAttribute()
    {
        if (new[] { "APFS_VERIFY_TEST_OBSERVER", "APFS_VERIFY_TEST_HEALTHY", "APFS_VERIFY_TEST_CORRUPT" }.Any(key => !File.Exists(Environment.GetEnvironmentVariable(key))))
            Skip = "Optional private observer integration requires APFS_VERIFY_TEST_OBSERVER, APFS_VERIFY_TEST_HEALTHY and APFS_VERIFY_TEST_CORRUPT regular fixture paths.";
    }
}
