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

    private JsonObject Evidence(int outcome = 1, bool whole = false, bool hashes = false, int version = 1)
    {
        var node = JsonSerializer.SerializeToNode(new {
            format = "apfs-access-verification", version, readOnly = true,
            source = new { kind = "image", path = Image, identity = Identity, lease = "windows-read-deny-write-delete" },
            requestedScope = new { containerUuid = new string('a', 32), volumeUuid = new string('b', 32), volumeOid = "101", checkpointXid = "20",
                storeOffsetBytes = "0", storeSizeBytes = "4096", maxReads = "65536", maxReadBytes = "268435456", maxRecords = "1000000", maxRecordBytes = "268435456",
                requireWholeVolume = whole, requirePayloadContentHashes = hashes },
            selected = new { containerUuid = new string('a', 32), volumeUuid = new string('b', 32), volumeOid = "101", checkpointXid = "20",
                storeOffsetBytes = "0", storeSizeBytes = "4096", checkpointPhysicalBlock = "12", volumeSuperblockPhysicalBlock = "4", volumeSuperblockXid = "20", rootOid = "8293", rootPhysicalBlock = "7" },
            outcome, outcomeName = ((ApfsVerificationOutcome)outcome).ToString(), wholeVolumeVerified = false, payloadContentHashesVerified = false,
            sourceReads = "62", sourceReadBytes = "241760", coveredFilesystemRecords = outcome == 1 ? "5" : "0", coveredPhysicalExtents = outcome == 1 ? "1" : "0",
            findings = Array.Empty<object>(),
            coverage = Enumerable.Range(1,version == 1 ? 18 : 20).Select(check => new { check, implemented = check <= 11 || check >= 17,
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
        if (version == 2)
        {
            node["requestedScope"]!["storeSizeBytes"] = "2097152";
            if (node["selected"] is not null) node["selected"]!["storeSizeBytes"] = "2097152";
            node["allocationCensus"] = outcome == 1 ? JsonSerializer.SerializeToNode(new {
                blockSizeBytes = "4096", containerBlockCount = "512", currentMetadataBlocks = "17", currentPayloadBlocks = "1",
                unattributedMainBlocks = "4", unattributedInternalBlocks = "1",
                unattributedMainRanges = new[] { new { physicalBlock = "221", blockCount = "1" }, new { physicalBlock = "223", blockCount = "2" }, new { physicalBlock = "250", blockCount = "1" } },
                unattributedInternalRanges = new[] { new { physicalBlock = "100", blockCount = "1" } }
            }) : null;
        }
        Bind(node); return node;
    }
    private static void Bind(JsonObject node) => node["repair"]!["planId"] = NativeApfsImageVerifier.BuildPlanId(JsonSerializer.SerializeToElement(node));
    private ApfsImageVerificationResult Parse(JsonObject node, int exit = 0, ApfsImageVerificationRequest? request = null)
        => NativeApfsImageVerifier.ParseReport(node.ToJsonString(), exit, request ?? (node["version"]!.GetValue<int>() == 2 ? Request with { StoreSizeBytes = "2097152" } : Request), Identity);

    private JsonObject PayloadEvidence(int outcome = 1)
        => PayloadObservationFixture.Upgrade(Evidence(outcome, version: 2), live: false);
    private ApfsImageVerificationResult ParsePayload(JsonObject node, int exit = 0)
        => Parse(node, exit, Request with { StoreSizeBytes = "2097152" });

    [Fact]
    public void PayloadObservationParsesExactCurrentRowsWithoutExpectedAuthority()
    {
        var result = ParsePayload(PayloadEvidence());
        Assert.Equal(ApfsVerificationOutcome.Complete, result.Outcome);
        Assert.Equal(21, result.Report.GetProperty("coverage").GetArrayLength());
        var payload = result.Report.GetProperty("payloadInventory");
        Assert.Equal("NotSupplied", payload.GetProperty("expectedComparison").GetString());
        Assert.Equal("9007199254740993", payload.GetProperty("entries")[0].GetProperty("inodeOid").GetString());
        Assert.False(result.Report.GetProperty("payloadContentHashesVerified").GetBoolean());
        Assert.NotNull(result.PayloadInventory);
        Assert.Equal("18446744073709551615", result.PayloadInventory.Entries[0].StreamOid);
        Assert.All(result.PayloadInventory.Entries, entry => Assert.Null(entry.ExpectedSha256));
    }

    [Theory]
    [InlineData("ReadFailure")] [InlineData("BudgetExceeded")] [InlineData("Unsupported")]
    public void PayloadObservationPreservesPartialAndEarlyRefusalWithoutCompleteHash(string status)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.Fail(node, status);
        Assert.Equal(status == "Unsupported" ? ApfsVerificationOutcome.Refused : ApfsVerificationOutcome.Incomplete,
            ParsePayload(node, status == "Unsupported" ? 4 : 3).Outcome);
        var early = PayloadEvidence(3);
        Assert.Equal(ApfsVerificationOutcome.Refused, ParsePayload(early, 4).Outcome);
    }

    [Fact]
    public void PayloadObservationBroaderExpectationStillReportsIncomplete()
    {
        var node = PayloadObservationFixture.Upgrade(Evidence(2, hashes: true, version: 2), live: false);
        node["payloadInventory"] = PayloadObservationFixture.Inventory(); node["coverage"]![20]!["state"] = 2;
        PayloadObservationFixture.Bind(node);
        Assert.Equal(ApfsVerificationOutcome.Incomplete, Parse(node, 3, Request with {
            StoreSizeBytes = "2097152", RequirePayloadContentHashes = true }).Outcome);
    }

    [Fact]
    public void PayloadObservationCanonicalBytesBindRequestBoundsAndUtf8ButExcludeObservedHashes()
    {
        var node = PayloadEvidence(); var id = node["repair"]!["planId"]!.GetValue<string>();
        Assert.StartsWith("apfs-verifier-refusal-v2|", id);
        Assert.Contains("1:19:2684354564:1024", id);
        Assert.Equal(id, NativeApfsImageVerifier.BuildPlanId(JsonSerializer.SerializeToElement(node)));
        node["payloadInventory"]!["entries"]![0]!["observedSha256"] = new string('a', 64);
        Assert.Equal(id, ParsePayload(node).Report.GetProperty("repair").GetProperty("planId").GetString());
        PayloadObservationFixture.Fail(node, "ReadFailure");
        node["findings"]![0]!["detail"] = "\u00e9"; PayloadObservationFixture.Bind(node);
        Assert.Contains("2:\u00e9", ParsePayload(node, 3).Report.GetProperty("repair").GetProperty("planId").GetString());
    }

    [Theory]
    [MemberData(nameof(PayloadObservationFixture.PartialInvalidCases), MemberType = typeof(PayloadObservationFixture))]
    public void PayloadObservationRejectsContradictoryPartialReports(string mutation)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.Fail(node, "ReadFailure");
        PayloadObservationFixture.MutatePartial(node, mutation);
        Assert.Throws<InvalidDataException>(() => ParsePayload(node, 3));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void PayloadObservationAcceptsExactBoundsAndEmptyAdmittedCensus(bool empty)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.AtBounds(node, empty);
        Assert.Equal(ApfsVerificationOutcome.Complete, ParsePayload(node).Outcome);
    }

    [Fact]
    public void PayloadObservationUsesNativeUtf8NameOrder()
    {
        var node = PayloadEvidence(); PayloadObservationFixture.UnicodeNames(node);
        Assert.Equal("\uE000", ParsePayload(node).PayloadInventory!.Entries[1].NameUtf8);
    }

    [Theory]
    [MemberData(nameof(PayloadObservationFixture.InvalidCases), MemberType = typeof(PayloadObservationFixture))]
    public void PayloadObservationRejectsForgedInventory(string mutation)
    {
        var node = PayloadEvidence(); PayloadObservationFixture.Mutate(node, mutation);
        Assert.Throws<InvalidDataException>(() => ParsePayload(node));
    }

    [Fact]
    public void PayloadObservationRejectsDuplicatePropertiesSemanticExitsAndOversizedUtf8()
    {
        var node = PayloadEvidence(); var json = node.ToJsonString();
        foreach (var bad in PayloadObservationFixture.DuplicateProperties(json))
            Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(bad, 0,
                Request with { StoreSizeBytes = "2097152" }, Identity));
        Assert.Throws<InvalidDataException>(() => ParsePayload(node, 3));
        node["coverage"]![0]!["scopeDetail"] = new string('x', NativeApfsImageVerifier.MaxReportBytes);
        Assert.Throws<InvalidDataException>(() => ParsePayload(node));
    }

    [Theory]
    [InlineData(1, 18)] [InlineData(2, 20)]
    public void PayloadObservationLegacyParsesKeepOriginalCoverageAndPlanBytes(int version, int checks)
    {
        var node = Evidence(version: version); var plan = node["repair"]!["planId"]!.GetValue<string>();
        Assert.StartsWith("apfs-verifier-refusal-v1|", plan);
        Assert.Equal(checks, Parse(node).Report.GetProperty("coverage").GetArrayLength());
        Assert.Null(Parse(node).PayloadInventory);
        node["payloadInventory"] = PayloadObservationFixture.Inventory();
        Assert.Throws<InvalidDataException>(() => Parse(node));
    }

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
    [InlineData(1, 0)] [InlineData(2, 3)] [InlineData(3, 4)]
    public void Version2OutcomesPreserveCensusAndExplicitGaps(int outcome, int exit)
    {
        var result = Parse(Evidence(outcome, version: 2), exit);
        Assert.Equal(20, result.Report.GetProperty("coverage").GetArrayLength());
        Assert.Equal(outcome == 1 ? JsonValueKind.Object : JsonValueKind.Null, result.Report.GetProperty("allocationCensus").ValueKind);
        Assert.False(result.Report.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.Equal(JsonValueKind.Null, result.Report.GetProperty("repair").GetProperty("nextActionableCandidate").ValueKind);
        if (outcome == 1) Assert.Equal("4", result.Report.GetProperty("allocationCensus").GetProperty("unattributedMainBlocks").GetString());
    }
    [Theory]
    [InlineData(23)] [InlineData(24)]
    public void NewCensusCorruptionCodesRequireTheirExactCheck(int code)
    {
        var node = Evidence(2, version: 2);
        node["coverage"]![0]!["state"] = 2; node["coverage"]![18]!["state"] = 3;
        node["findings"]![0]!["code"] = code; node["findings"]![0]!["check"] = 19; Bind(node);
        Assert.Equal(ApfsVerificationOutcome.Incomplete, Parse(node, 3).Outcome);
        node["findings"]![0]!["check"] = 20; node["coverage"]![19]!["state"] = 3; Bind(node);
        Assert.Throws<InvalidDataException>(() => Parse(node, 3));
    }
    [Fact]
    public void Version2SnapshotRefusalPreservesReachabilityWithoutHistoricalHealth()
    {
        var node = Evidence(3, version: 2);
        node["coverage"]![0]!["state"] = 2; node["coverage"]![12]!["state"] = 4;
        node["findings"]![0]!["check"] = 13; node["findings"]![0]!["code"] = 17; Bind(node);
        Assert.Equal(ApfsVerificationOutcome.Refused, Parse(node, 4).Outcome);
        node["coverage"]![12]!["state"] = 2; Bind(node);
        Assert.Throws<InvalidDataException>(() => Parse(node, 4));
    }
    [Theory]
    [InlineData(1)] [InlineData(2)]
    public void LateQuotaFailureCannotPublishCountsOrCensus(int version)
    {
        var node = Evidence(2, version: version);
        node["coverage"]![0]!["state"] = 2; node["coverage"]![9]!["state"] = 3;
        node["findings"]![0]!["code"] = 15; node["findings"]![0]!["check"] = 10; Bind(node);
        Assert.Equal(ApfsVerificationOutcome.Incomplete, Parse(node, 3).Outcome);
        node["coveredFilesystemRecords"] = "5";
        Assert.Throws<InvalidDataException>(() => Parse(node, 3));
        node["coveredFilesystemRecords"] = "0";
        if (version == 2) { node["allocationCensus"] = Evidence(version: 2)["allocationCensus"]!.DeepClone(); Assert.Throws<InvalidDataException>(() => Parse(node, 3)); }
    }
    [Theory]
    [InlineData("null")] [InlineData("missing")] [InlineData("extra")] [InlineData("numeric")] [InlineData("leadingZero")]
    [InlineData("overflow")] [InlineData("zeroLength")] [InlineData("rangeOverflow")] [InlineData("outside")]
    [InlineData("overlap")] [InlineData("adjacent")] [InlineData("unsorted")] [InlineData("crossPool")]
    [InlineData("wrongCount")] [InlineData("emptyNonzero")] [InlineData("sumOverflow")] [InlineData("totalOutside")]
    [InlineData("zeroUnit")] [InlineData("unknownUnit")] [InlineData("zeroCapacity")] [InlineData("storeBounds")]
    [InlineData("selectedBounds")] [InlineData("arrayType")] [InlineData("rangeExtra")] [InlineData("unknownCheck")]
    [InlineData("unknownState")] [InlineData("unknownCode")] [InlineData("missingCheck")]
    public void InvalidVersion2CensusAndCoverageNeverBecomeHealthy(string mutation)
    {
        var node = Evidence(version: 2); var census = node["allocationCensus"]!;
        var ranges = census["unattributedMainRanges"]!;
        switch (mutation)
        {
            case "null": node["allocationCensus"] = null; break;
            case "missing": node.Remove("allocationCensus"); break;
            case "extra": census["reclaimableBlocks"] = "4"; break;
            case "numeric": census["currentMetadataBlocks"] = 17; break;
            case "leadingZero": ranges[0]!["physicalBlock"] = "0221"; break;
            case "overflow": census["unattributedMainBlocks"] = "18446744073709551616"; break;
            case "zeroLength": ranges[0]!["blockCount"] = "0"; break;
            case "rangeOverflow": ranges[0]!["blockCount"] = "18446744073709551615"; break;
            case "outside": ranges[2]!["physicalBlock"] = "512"; break;
            case "overlap": ranges[1]!["physicalBlock"] = "221"; break;
            case "adjacent": ranges[1]!["physicalBlock"] = "222"; break;
            case "unsorted": ranges[2]!["physicalBlock"] = "200"; break;
            case "crossPool": census["unattributedInternalRanges"]![0]!["physicalBlock"] = "223"; break;
            case "wrongCount": census["unattributedMainBlocks"] = "3"; break;
            case "emptyNonzero": ranges.AsArray().Clear(); break;
            case "sumOverflow": census["currentMetadataBlocks"] = "18446744073709551615"; break;
            case "totalOutside": census["currentMetadataBlocks"] = "512"; break;
            case "zeroUnit": census["blockSizeBytes"] = "0"; break;
            case "unknownUnit": census["blockSizeBytes"] = "4097"; break;
            case "zeroCapacity": census["containerBlockCount"] = "0"; break;
            case "storeBounds": census["containerBlockCount"] = "513"; break;
            case "selectedBounds": node["selected"]!["rootPhysicalBlock"] = "512"; break;
            case "arrayType": census["unattributedMainRanges"] = new JsonObject(); break;
            case "rangeExtra": ranges[0]!["reclaim"] = true; break;
            case "unknownCheck": node["coverage"]![19]!["check"] = 21; break;
            case "unknownState": node["coverage"]![19]!["state"] = 6; break;
            case "unknownCode": node["findings"]!.AsArray().Add(Evidence(2)["findings"]![0]!.DeepClone()); node["findings"]![0]!["code"] = 25; break;
            case "missingCheck": node["coverage"]!.AsArray().RemoveAt(19); break;
        }
        Bind(node); Assert.Throws<InvalidDataException>(() => Parse(node));
    }
    [Fact]
    public void Version2ZeroResidualAnd8192ByteBlocksRemainOnlySubsetProof()
    {
        var node = Evidence(version: 2); var census = node["allocationCensus"]!;
        census["blockSizeBytes"] = "8192"; census["containerBlockCount"] = "256";
        census["unattributedMainBlocks"] = "0"; census["unattributedInternalBlocks"] = "0";
        census["unattributedMainRanges"]!.AsArray().Clear(); census["unattributedInternalRanges"]!.AsArray().Clear();
        Assert.False(Parse(node).Report.GetProperty("wholeVolumeVerified").GetBoolean());
        node["wholeVolumeVerified"] = true; Assert.Throws<InvalidDataException>(() => Parse(node));
    }
    [Fact]
    public void Version1CannotSmuggleVersion2ChecksCodesOrCensus()
    {
        var node = Evidence(); node["allocationCensus"] = null;
        Assert.Throws<InvalidDataException>(() => Parse(node));
        node = Evidence(); node["coverage"]![17]!["check"] = 19; Bind(node);
        Assert.Throws<InvalidDataException>(() => Parse(node));
        node = Evidence(2); node["findings"]![0]!["code"] = 23; Bind(node);
        Assert.Throws<InvalidDataException>(() => Parse(node, 3));
    }
    [Fact]
    public void Version2DuplicateCensusPropertiesAndTruncationAreRejected()
    {
        var json = Evidence(version: 2).ToJsonString();
        var request = Request with { StoreSizeBytes = "2097152" };
        foreach (var bad in new[] { json[..^1], json.Replace("\"blockCount\":\"1\"", "\"blockCount\":\"1\",\"blockCount\":\"1\""),
            json.Replace("\"allocationCensus\":", "\"allocationCensus\":null,\"allocationCensus\":") })
            Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(bad, 0, request, Identity));
    }
    [Theory]
    [InlineData("source")] [InlineData("path")] [InlineData("containerUuid")] [InlineData("volumeUuid")]
    [InlineData("volumeOid")] [InlineData("checkpointXid")] [InlineData("storeOffsetBytes")] [InlineData("storeSizeBytes")]
    [InlineData("plan")] [InlineData("repair")] [InlineData("historical")] [InlineData("implemented")]
    public void Version2StillBindsExactSourceAndScopeAndRefusesRepair(string field)
    {
        var node = Evidence(version: 2);
        if (field == "source") node["source"]!["identity"] = "windows-file:1:3:4096:3";
        else if (field == "path") node["source"]!["path"] = Image + ".other";
        else if (field == "plan") node["repair"]!["planId"] = "unbound";
        else if (field == "repair") node["repair"]!["nextActionableCandidate"] = new JsonObject();
        else if (field == "historical") node["coverage"]![12]!["state"] = 2;
        else if (field == "implemented") node["coverage"]![18]!["implemented"] = false;
        else node["selected"]![field] = field.EndsWith("Uuid", StringComparison.Ordinal) ? new string('c', 32) : "21";
        if (field != "plan") Bind(node);
        Assert.Throws<InvalidDataException>(() => Parse(node));
    }
    [Theory]
    [InlineData(true, false)] [InlineData(false, true)] [InlineData(true, true)]
    public void Version2BroaderRequestsNeverPublishCensus(bool whole, bool hashes)
    {
        var request = Request with { StoreSizeBytes = "2097152", RequireWholeVolume = whole, RequirePayloadContentHashes = hashes };
        var result = Parse(Evidence(2, whole, hashes, 2), 3, request);
        Assert.Equal(JsonValueKind.Null, result.Report.GetProperty("allocationCensus").ValueKind);
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
            Assert.Equal(3, result.Report.GetProperty("version").GetInt32());
            Assert.Equal(21, result.Report.GetProperty("coverage").GetArrayLength());
            Assert.True(result.Report.GetProperty("observePayloadContent").GetBoolean());
            Assert.False(result.Report.GetProperty("payloadContentHashesVerified").GetBoolean());
            Assert.Equal("NotSupplied", result.Report.GetProperty("payloadInventory").GetProperty("expectedComparison").GetString());
            Assert.Equal(pair.Item2 == 0 ? JsonValueKind.Object : JsonValueKind.Null, result.Report.GetProperty("allocationCensus").ValueKind);
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
