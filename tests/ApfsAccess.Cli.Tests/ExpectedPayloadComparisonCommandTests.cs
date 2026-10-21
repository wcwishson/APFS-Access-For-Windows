using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Cli.Tests;

public sealed class ExpectedPayloadComparisonCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "expected-payload-cli-" + Guid.NewGuid().ToString("N"));
    private string ManifestPath => Path.Combine(directory, "expected.json");
    private string ReportPath => Path.Combine(directory, "observed.json");
    private string ImagePath => Path.Combine(directory, "unread-image.raw");
    public ExpectedPayloadComparisonCommandTests()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(ManifestPath, ExpectedPayloadTestData.Manifest().ToJsonString(), new UTF8Encoding(false));
        File.WriteAllText(ReportPath, ExpectedPayloadTestData.Report().ToJsonString(), new UTF8Encoding(false));
        File.WriteAllBytes(ImagePath, new byte[4096]);
    }
    public void Dispose() => Directory.Delete(directory, true);
    private string[] OfflineArgs => ["--verification-report", ReportPath, "--expected-manifest", ManifestPath, "--json"];
    private string[] ImageArgs => ["--image", ImagePath, "--container-id", "apfs-container:" + new string('a', 32),
        "--volume-uuid", new string('b', 32), "--volume-oid", "101", "--checkpoint-xid", "20",
        "--store-offset-bytes", "0", "--store-size-bytes", "4096"];

    private static (int Exit, JsonElement Json) Run(string[] args,
        Func<ApfsImageVerificationRequest, CancellationToken, ApfsImageVerificationResult>? verify = null)
    {
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output);
            var exit = VerifyCommand.Run(args, verify ?? ((_, _) => throw new Exception("Offline route launched an observer")));
            return (exit, JsonDocument.Parse(output.ToString()).RootElement.Clone());
        }
        finally { Console.SetOut(previous); }
    }

    [Fact]
    public async Task ActualProgramOfflineRouteMatchesWithoutObserverSourceOrService()
    {
        File.Delete(ImagePath);
        var previous = Console.Out; using var output = new StringWriter();
        try
        {
            Console.SetOut(output); Assert.Equal(0, await Program.RunForTestAsync(["verify", ..OfflineArgs]));
            using var doc = JsonDocument.Parse(output.ToString()); var root = doc.RootElement;
            var comparison = root.GetProperty("expectedPayloadComparison");
            Assert.Equal("MatchingProvidedManifest", comparison.GetProperty("outcome").GetString());
            Assert.Equal(2, comparison.GetProperty("matchedEntryCount").GetInt32());
            Assert.Equal(64, comparison.GetProperty("manifestSha256").GetString()!.Length);
            Assert.True(comparison.GetProperty("completeInventoryCoverage").GetBoolean());
            Assert.Equal(JsonValueKind.Null, root.GetProperty("nativeExitCode").ValueKind);
            Assert.Equal("MatchingProvidedManifest", root.GetProperty("code").GetString());
            var provenance = root.GetProperty("verificationReportInput");
            Assert.Equal("caller-supplied-report-file", provenance.GetProperty("source").GetString());
            Assert.False(provenance.GetProperty("liveSourceRechecked").GetBoolean());
            Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(ReportPath))),
                provenance.GetProperty("sha256").GetString());
            var report = root.GetProperty("verification");
            Assert.False(report.GetProperty("wholeVolumeVerified").GetBoolean());
            Assert.False(report.GetProperty("payloadContentHashesVerified").GetBoolean());
            Assert.Equal("NotSupplied", report.GetProperty("payloadInventory").GetProperty("expectedComparison").GetString());
            var evidence = Environment.GetEnvironmentVariable("APFSACCESS_EXPECTED_COMPARE_EVIDENCE");
            if (!string.IsNullOrEmpty(evidence))
            {
                Directory.CreateDirectory(evidence);
                File.Copy(ManifestPath, Path.Combine(evidence, "expected.json"), true);
                File.Copy(ReportPath, Path.Combine(evidence, "observed.json"), true);
                File.WriteAllText(Path.Combine(evidence, "program-route-result.json"), output.ToString());
            }
        }
        finally { Console.SetOut(previous); }
    }

    [Theory]
    [InlineData("hash", 3, "Mismatch")] [InlineData("size", 3, "Mismatch")]
    [InlineData("missing", 3, "Mismatch")] [InlineData("extra", 3, "Mismatch")]
    [InlineData("owner", 4, "Refused")] [InlineData("checkpoint", 4, "Refused")]
    public void OfflineMismatchOrScopeRefusalCannotPublishSuccess(string change, int exit, string outcome)
    {
        var manifest = ExpectedPayloadTestData.Manifest();
        switch (change)
        {
            case "hash": manifest["entries"]![0]!["expectedSha256"] = new string('1', 64); break;
            case "size": manifest["entries"]![0]!["logicalSizeBytes"] = "4"; break;
            case "missing": manifest["entries"]!.AsArray().Add(ExpectedPayloadTestData.Expected("file-data", "999", "999", null, "0", ExpectedPayloadTestData.EmptyDigest)); break;
            case "extra": manifest["entries"]!.AsArray().RemoveAt(1); break;
            case "owner": manifest["scope"]!["sourceIdentity"] = "image:another-held-owner"; break;
            case "checkpoint": manifest["scope"]!["checkpointXid"] = "21"; break;
        }
        File.WriteAllText(ManifestPath, manifest.ToJsonString());
        var result = Run(OfflineArgs); Assert.Equal(exit, result.Exit); Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal(outcome, result.Json.GetProperty("expectedPayloadComparison").GetProperty("outcome").GetString());
        Assert.False(result.Json.GetProperty("verification").GetProperty("payloadContentHashesVerified").GetBoolean());
    }

    [Theory]
    [InlineData("duplicate")] [InlineData("unknown")] [InlineData("oversize")] [InlineData("malformed")]
    [InlineData("forged-verified")] [InlineData("report-oversize")] [InlineData("wrong-format")]
    public void InvalidInputsDiscardBothReports(string change)
    {
        switch (change)
        {
            case "duplicate":
                var manifest = ExpectedPayloadTestData.Manifest(); manifest["entries"]!.AsArray().Add(manifest["entries"]![0]!.DeepClone());
                File.WriteAllText(ManifestPath, manifest.ToJsonString()); break;
            case "unknown": File.WriteAllText(ManifestPath, ExpectedPayloadTestData.Manifest().ToJsonString().Replace("\"version\":1", "\"version\":1,\"extra\":true")); break;
            case "oversize": File.WriteAllBytes(ManifestPath, new byte[ExpectedPayloadManifest.MaximumManifestBytes + 1]); break;
            case "malformed": File.WriteAllText(ManifestPath, "{"); break;
            case "forged-verified":
                var report = ExpectedPayloadTestData.Report(); report["payloadContentHashesVerified"] = true;
                File.WriteAllText(ReportPath, report.ToJsonString()); break;
            case "report-oversize": File.WriteAllBytes(ReportPath, new byte[LiveVolumeVerificationReport.MaximumResponseBytes + 1]); break;
            case "wrong-format": File.WriteAllText(ReportPath, "{\"verification\":" + ExpectedPayloadTestData.Report().ToJsonString() + "}"); break;
        }
        var result = Run(OfflineArgs); Assert.Equal(5, result.Exit);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("verification").ValueKind);
        Assert.Equal(JsonValueKind.Null, result.Json.GetProperty("expectedPayloadComparison").ValueKind);
    }

    [Fact]
    public void LegacyReportRetainsNativeMeaningButComparisonIsIncomplete()
    {
        var report = ExpectedPayloadTestData.Report(); report["version"] = 1;
        report.Remove("observePayloadContent"); report.Remove("payloadInventory");
        report["limits"]!.AsObject().Remove("maxPayloadLogicalBytes"); report["limits"]!.AsObject().Remove("maxPayloadEntries");
        report["coverage"]!.AsArray().RemoveAt(20); ExpectedPayloadTestData.Bind(report);
        File.WriteAllText(ReportPath, report.ToJsonString());
        var result = Run(OfflineArgs); Assert.Equal(3, result.Exit);
        Assert.Equal("Complete", result.Json.GetProperty("verification").GetProperty("outcomeName").GetString());
        Assert.Equal("Incomplete", result.Json.GetProperty("expectedPayloadComparison").GetProperty("outcome").GetString());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void OfflineIncompleteEnumerationOrReadRemainsIncomplete(bool enumerationIncomplete)
    {
        File.WriteAllText(ReportPath, ExpectedPayloadTestData.PartialReport(enumerationIncomplete).ToJsonString());
        var result = Run(OfflineArgs); Assert.Equal(3, result.Exit);
        var comparison = result.Json.GetProperty("expectedPayloadComparison");
        Assert.Equal("Incomplete", comparison.GetProperty("outcome").GetString());
        Assert.False(comparison.GetProperty("completeInventoryCoverage").GetBoolean());
        Assert.Equal(0, comparison.GetProperty("comparedEntryCount").GetInt32());
    }

    [Fact]
    public void UppercaseExpectedHexWorksThroughOfflineCli()
    {
        var manifest = ExpectedPayloadTestData.Manifest();
        foreach (var row in manifest["entries"]!.AsArray())
            row!["expectedSha256"] = row["expectedSha256"]!.GetValue<string>().ToUpperInvariant();
        File.WriteAllText(ManifestPath, manifest.ToJsonString());
        var result = Run(OfflineArgs);
        Assert.Equal(0, result.Exit);
        Assert.True(result.Json.GetProperty("expectedPayloadComparison").GetProperty("matchingProvidedManifest").GetBoolean());
    }

    [Fact]
    public void CompleteMatchingInventoryDoesNotOverrideIncompleteNativeMetadataReport()
    {
        var report = ExpectedPayloadTestData.Report();
        report["outcome"] = 2; report["outcomeName"] = "Incomplete"; report["allocationCensus"] = null;
        report["coveredFilesystemRecords"] = "0"; report["coveredPhysicalExtents"] = "0"; report["repair"]!["refusal"] = 2;
        report["findings"] = new JsonArray(new JsonObject { ["code"] = 18, ["severity"] = 3, ["check"] = 12,
            ["volumeOid"] = "101", ["objectId"] = null, ["physicalBlock"] = null, ["checkpointXid"] = "20",
            ["failedSourceOffsetBytes"] = null, ["detail"] = "Whole-volume coverage unavailable" });
        ExpectedPayloadTestData.Bind(report); File.WriteAllText(ReportPath, report.ToJsonString());
        var result = Run(OfflineArgs);
        Assert.Equal(3, result.Exit); Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.Equal("VerificationIncomplete", result.Json.GetProperty("code").GetString());
        Assert.Equal("Incomplete", result.Json.GetProperty("verification").GetProperty("outcomeName").GetString());
        var comparison = result.Json.GetProperty("expectedPayloadComparison");
        Assert.Equal("MatchingProvidedManifest", comparison.GetProperty("outcome").GetString());
        Assert.True(comparison.GetProperty("completeInventoryCoverage").GetBoolean());
        Assert.False(result.Json.GetProperty("verification").GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(result.Json.GetProperty("verification").GetProperty("payloadContentHashesVerified").GetBoolean());
    }

    [Fact]
    public void ImageResultComparisonKeepsNativeExitAndHeldManifestLease()
    {
        var manifest = ExpectedPayloadTestData.Manifest(); manifest["scope"]!["sourceKind"] = "image";
        manifest["scope"]!["storeSizeBytes"] = "4096"; File.WriteAllText(ManifestPath, manifest.ToJsonString());
        var observation = ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report()).PayloadInventory;
        var report = JsonSerializer.SerializeToElement(new { source = new { kind = "image", identity = "image:opaque-held-owner" },
            requestedScope = new { containerUuid = new string('a',32), volumeUuid = new string('b',32), volumeOid = "101",
                checkpointXid = "20", storeOffsetBytes = "0", storeSizeBytes = "4096" },
            wholeVolumeVerified = false, payloadContentHashesVerified = false, payloadInventory = observation });
        var result = Run([..ImageArgs, "--expected-manifest", ManifestPath], (_, _) =>
        {
            Assert.Throws<IOException>(() => File.Open(ManifestPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Move(ManifestPath, ManifestPath + ".moved"));
            return new ApfsImageVerificationResult(0, ApfsVerificationOutcome.Complete, report, observation);
        });
        Assert.Equal(0, result.Exit); Assert.Equal(0, result.Json.GetProperty("nativeExitCode").GetInt32());
        Assert.True(result.Json.GetProperty("expectedPayloadComparison").GetProperty("matchingProvidedManifest").GetBoolean());
    }

    [Fact]
    public void ProvidedManifestCannotOverrideNativeRequireHashesRefusal()
    {
        var manifest = ExpectedPayloadTestData.Manifest(); manifest["scope"]!["sourceKind"] = "image";
        manifest["scope"]!["storeSizeBytes"] = "4096"; File.WriteAllText(ManifestPath, manifest.ToJsonString());
        var observation = ExpectedPayloadTestData.ParseReport(ExpectedPayloadTestData.Report()).PayloadInventory;
        var report = JsonSerializer.SerializeToElement(new { source = new { kind = "image", identity = "image:opaque-held-owner" },
            requestedScope = new { containerUuid = new string('a',32), volumeUuid = new string('b',32), volumeOid = "101",
                checkpointXid = "20", storeOffsetBytes = "0", storeSizeBytes = "4096" },
            wholeVolumeVerified = false, payloadContentHashesVerified = false });
        var result = Run([..ImageArgs, "--expected-manifest", ManifestPath, "--require-payload-content-hashes"], (request, _) =>
        {
            Assert.True(request.RequirePayloadContentHashes);
            return new ApfsImageVerificationResult(3, ApfsVerificationOutcome.Incomplete, report, observation);
        });
        Assert.Equal(3, result.Exit); Assert.Equal(3, result.Json.GetProperty("nativeExitCode").GetInt32());
        Assert.False(result.Json.GetProperty("success").GetBoolean());
        Assert.True(result.Json.GetProperty("expectedPayloadComparison").GetProperty("matchingProvidedManifest").GetBoolean());
    }

    [Theory]
    [InlineData("no-manifest")] [InlineData("two-manifests")] [InlineData("mixed-source")]
    [InlineData("native-switch")] [InlineData("missing-value")]
    public void OptionCombinationsAreExplicitAndUnambiguous(string change)
    {
        string[] args = change switch
        {
            "no-manifest" => ["--verification-report", ReportPath],
            "two-manifests" => [..OfflineArgs, "--expected-manifest", ManifestPath],
            "mixed-source" => [..OfflineArgs, ..ImageArgs],
            "native-switch" => [..OfflineArgs, "--require-payload-content-hashes"],
            _ => [..ImageArgs, "--expected-manifest"]
        };
        Assert.Equal(2, Run(args).Exit);
    }

    [Fact]
    public void DefaultWireHasNoExpectationFieldAndHelpDocumentsTrustAndBounds()
    {
        var report = JsonSerializer.SerializeToElement(new { wholeVolumeVerified = false, payloadContentHashesVerified = false });
        var result = Run(ImageArgs, (_, _) => new ApfsImageVerificationResult(0, ApfsVerificationOutcome.Complete, report));
        Assert.Equal(0, result.Exit); Assert.False(result.Json.TryGetProperty("expectedPayloadComparison", out _));
        var help = Run(["--help"]).Json;
        Assert.Contains("--expected-manifest", help.GetProperty("usage").GetString());
        Assert.Contains("without authenticating", help.GetProperty("description").GetString());
        Assert.Contains("1 MiB", help.GetProperty("description").GetString());
    }
}
