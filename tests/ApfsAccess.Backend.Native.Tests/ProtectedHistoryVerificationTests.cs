using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ProtectedHistoryVerificationTests : IDisposable
{
    private readonly string directory = Path.Combine(@"D:\ApfsAccessScratch\WindowsClosure\protected-history-cli-20261015",
        "backend-" + Guid.NewGuid().ToString("N"));
    private string Image => Path.Combine(directory, "image.raw");
    private const string Identity = "windows-file:1:2:2097152:3";
    private ApfsImageVerificationRequest Request => new(Image, "apfs-container:" + new string('a', 32),
        new string('b', 32), "101", "20", "0", "2097152", RetainedFromXid: "7");

    public ProtectedHistoryVerificationTests()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Image, new byte[2097152]);
    }
    public void Dispose() => Directory.Delete(directory, true);

    private JsonObject Evidence(int outcome = 1, int code = 7, bool selected = true)
    {
        var node = LiveVerificationFixture.Report();
        node["format"] = "apfs-access-protected-history-verification";
        foreach (var key in new[] { "limits", "requireWholeVolume", "requirePayloadContentHashes", "elapsedMs", "repair" }) node.Remove(key);
        node["source"] = JsonSerializer.SerializeToNode(new {
            kind = "image", path = Image, identity = Identity, lease = "windows-read-deny-write-delete"
        });
        var scope = node["requestedScope"]!.AsObject();
        scope.Remove("sourceKind"); scope.Remove("sourceIdentity");
        scope["maxReads"] = "65536"; scope["maxReadBytes"] = "268435456";
        scope["maxRecords"] = "1000000"; scope["maxRecordBytes"] = "268435456";
        scope["requireWholeVolume"] = false; scope["requirePayloadContentHashes"] = false;
        scope["retainedFromXid"] = "7";
        var identityScope = node["selected"]!["scope"]!.AsObject();
        var endpoint = node["selected"]!.AsObject();
        foreach (var property in identityScope)
            if (property.Key is not ("sourceKind" or "sourceIdentity")) endpoint[property.Key] = property.Value!.DeepClone();
        endpoint.Remove("scope");
        node["coverage"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {
            check = 22, implemented = true, required = true, state = 2, scopeDetail = "Only the requested protected chain"
        }));
        node["requestedHistory"] = new JsonObject {
            ["fromXid"] = "7", ["endpoint"] = endpoint.DeepClone(),
            ["chainXids"] = new JsonArray("7", "11", "20"),
            ["checkpoints"] = new JsonArray(
                new JsonObject { ["checkpointXid"] = "7", ["metadataRanges"] = Ranges((0, 2), (5, 1)), ["payloadRanges"] = Ranges((2, 2)) },
                new JsonObject { ["checkpointXid"] = "11", ["metadataRanges"] = Ranges((0, 2)), ["payloadRanges"] = Ranges((2, 4)) })
        };
        if (outcome != 1)
        {
            node["outcome"] = outcome; node["outcomeName"] = ((ApfsVerificationOutcome)outcome).ToString();
            node["coveredFilesystemRecords"] = "0"; node["coveredPhysicalExtents"] = "0";
            node["allocationCensus"] = null; node["requestedHistory"] = null;
            node["coverage"]![20]!["state"] = outcome == 3 ? 4 : code is 3 or 4 or 5 or 18 ? 1 : 3;
            node["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {
                code, severity = outcome == 3 ? 2 : 3, check = 22, volumeOid = "101", objectId = (string?)null,
                physicalBlock = (string?)null, checkpointXid = "11", failedSourceOffsetBytes = (string?)null,
                detail = "Requested protected chain could not be verified"
            }));
            if (!selected) node["selected"] = null;
        }
        return node;
    }

    private static JsonArray Ranges(params (int Start, int Count)[] ranges) => new(ranges.Select(range =>
        JsonSerializer.SerializeToNode(new { physicalBlock = range.Start.ToString(System.Globalization.CultureInfo.InvariantCulture),
            blockCount = range.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) })).ToArray());
    private ApfsImageVerificationResult Parse(JsonObject node, int exit = 0)
        => NativeApfsImageVerifier.ParseReport(node.ToJsonString(), exit, Request, Identity);

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void RejectsCompleteHistoryWithoutMetadata(bool emptyPayload)
    {
        var node = Evidence();
        node["requestedHistory"]!["checkpoints"]![0]!["metadataRanges"] = new JsonArray();
        if (emptyPayload) node["requestedHistory"]!["checkpoints"]![0]!["payloadRanges"] = new JsonArray();
        Assert.Throws<InvalidDataException>(() => Parse(node));
    }

    [Fact]
    public void CompleteHistoryKeepsEmptyPayload()
    {
        var node = Evidence();
        foreach (var checkpoint in node["requestedHistory"]!["checkpoints"]!.AsArray())
            checkpoint!["payloadRanges"] = new JsonArray();
        Assert.Equal(ApfsVerificationOutcome.Complete, Parse(node).Outcome);
    }

    [Fact]
    public void CompletePublishesOnlyRequestedNonconsecutiveChainAndCurrentSubset()
    {
        var node = Evidence();
        // Object property order is not identity, including the endpoint field order.
        var endpoint = node["requestedHistory"]!["endpoint"]!.AsObject();
        var root = endpoint["rootOid"]!.DeepClone(); endpoint.Remove("rootOid"); endpoint["rootOid"] = root;
        var result = Parse(node);
        Assert.Equal(ApfsVerificationOutcome.Complete, result.Outcome);
        Assert.Null(result.PayloadInventory);
        Assert.False(result.Report.TryGetProperty("repair", out _));
        Assert.False(result.Report.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(result.Report.GetProperty("payloadContentHashesVerified").GetBoolean());
        Assert.Equal(new[] { "7", "11", "20" }, result.Report.GetProperty("requestedHistory").GetProperty("chainXids").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(Enumerable.Range(1, 20).Append(22), result.Report.GetProperty("coverage").EnumerateArray().Select(x => x.GetProperty("check").GetInt32()));
        Assert.Equal(1, result.Report.GetProperty("coverage")[11].GetProperty("state").GetInt32());
        Assert.Equal(1, result.Report.GetProperty("coverage")[12].GetProperty("state").GetInt32());
    }

    [Fact]
    public void Uint64ChainAndGeometryBoundaryDoNotLosePrecision()
    {
        const string start = "9007199254740993", end = "18446744073709551615";
        var request = Request with { RetainedFromXid = start, CheckpointXid = end };
        var node = Evidence(); var history = node["requestedHistory"]!;
        node["requestedScope"]!["retainedFromXid"] = start; node["requestedScope"]!["checkpointXid"] = end;
        node["selected"]!["checkpointXid"] = end; history["endpoint"]!["checkpointXid"] = end;
        history["fromXid"] = start; history["chainXids"] = new JsonArray(start, end);
        history["checkpoints"] = new JsonArray(new JsonObject { ["checkpointXid"] = start,
            ["metadataRanges"] = Ranges((511, 1)), ["payloadRanges"] = new JsonArray() });
        var result = NativeApfsImageVerifier.ParseReport(node.ToJsonString(), 0, request, Identity);
        Assert.Equal(end, result.Report.GetProperty("requestedHistory").GetProperty("chainXids")[1].GetString());
        node["allocationCensus"]!["blockSizeBytes"] = "8192";
        node["allocationCensus"]!["containerBlockCount"] = "256";
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(node.ToJsonString(), 0, request, Identity));
        history["checkpoints"]![0]!["metadataRanges"] = Ranges((255, 1));
        Assert.Equal(ApfsVerificationOutcome.Complete,
            NativeApfsImageVerifier.ParseReport(node.ToJsonString(), 0, request, Identity).Outcome);
    }

    [Theory]
    [InlineData(2, 3, 7)] [InlineData(2, 3, 3)] [InlineData(2, 3, 4)] [InlineData(2, 3, 5)]
    [InlineData(3, 4, 1)] [InlineData(3, 4, 2)] [InlineData(3, 4, 8)]
    public void FailuresPreserveFindingsAndNeverPublishHistory(int outcome, int exit, int code)
    {
        var result = Parse(Evidence(outcome, code, selected: outcome != 3), exit);
        Assert.Equal((ApfsVerificationOutcome)outcome, result.Outcome);
        Assert.Equal(JsonValueKind.Null, result.Report.GetProperty("requestedHistory").ValueKind);
        Assert.Equal(JsonValueKind.Null, result.Report.GetProperty("allocationCensus").ValueKind);
        Assert.Equal("0", result.Report.GetProperty("coveredFilesystemRecords").GetString());
    }

    [Theory]
    [InlineData("nullHistory")] [InlineData("missingHistory")] [InlineData("extraHistory")] [InlineData("fromMismatch")]
    [InlineData("endpoint")] [InlineData("endpointExtra")] [InlineData("endpointMissing")] [InlineData("chainStart")]
    [InlineData("chainEnd")] [InlineData("chainOrder")] [InlineData("chainDuplicate")] [InlineData("chainNumeric")]
    [InlineData("chainLeadingZero")] [InlineData("chainOverflow")] [InlineData("chainShort")] [InlineData("chainType")]
    [InlineData("checkpointCount")] [InlineData("checkpointOrder")] [InlineData("checkpointExtra")] [InlineData("checkpointEndpoint")]
    [InlineData("rangeExtra")] [InlineData("rangeType")] [InlineData("rangeZero")] [InlineData("rangeOverflow")]
    [InlineData("rangeOutside")] [InlineData("rangeOverlap")] [InlineData("rangeAdjacent")] [InlineData("rangeOrder")]
    [InlineData("rangeNumeric")] [InlineData("rangeLeadingZero")] [InlineData("crossKindOverlap")] [InlineData("payloadOverlap")]
    [InlineData("payloadOutside")] [InlineData("repair")] [InlineData("observe")] [InlineData("inventory")]
    [InlineData("scopeExtra")] [InlineData("scopeStart")] [InlineData("scopeWhole")] [InlineData("scopeHashes")]
    [InlineData("format")] [InlineData("version")] [InlineData("selected")] [InlineData("sourceIdentity")]
    [InlineData("sourcePath")] [InlineData("sourceKind")] [InlineData("lease")] [InlineData("readBudget")]
    [InlineData("coverage21")] [InlineData("coverageMissing")] [InlineData("coverageDuplicate")] [InlineData("coverageUnknown")]
    [InlineData("historyUnimplemented")] [InlineData("historyNotRequired")] [InlineData("historyUnproven")]
    [InlineData("historicalVerified")] [InlineData("allocationVerified")] [InlineData("wholeVerified")] [InlineData("hashesVerified")]
    public void MalformedOrForgedSuccessIsRejected(string mutation)
    {
        var node = Evidence(); var history = node["requestedHistory"]!;
        var chain = history["chainXids"]!; var checkpoints = history["checkpoints"]!;
        var ranges = checkpoints[0]!["metadataRanges"]!;
        switch (mutation)
        {
            case "nullHistory": node["requestedHistory"] = null; break;
            case "missingHistory": node.Remove("requestedHistory"); break;
            case "extraHistory": history["reclaimable"] = true; break;
            case "fromMismatch": history["fromXid"] = "8"; break;
            case "endpoint": history["endpoint"]!["rootOid"] = "999"; break;
            case "endpointExtra": history["endpoint"]!["repair"] = true; break;
            case "endpointMissing": history["endpoint"]!.AsObject().Remove("rootOid"); break;
            case "chainStart": chain[0] = "6"; break;
            case "chainEnd": chain[2] = "21"; break;
            case "chainOrder": chain[1] = "21"; break;
            case "chainDuplicate": chain[1] = "7"; break;
            case "chainNumeric": chain[1] = 11; break;
            case "chainLeadingZero": chain[1] = "011"; break;
            case "chainOverflow": chain[1] = "18446744073709551616"; break;
            case "chainShort": history["chainXids"] = new JsonArray("20"); history["checkpoints"] = new JsonArray(); break;
            case "chainType": history["chainXids"] = new JsonObject(); break;
            case "checkpointCount": checkpoints.AsArray().RemoveAt(1); break;
            case "checkpointOrder": checkpoints[0]!["checkpointXid"] = "11"; break;
            case "checkpointExtra": checkpoints[0]!["rootOid"] = "99"; break;
            case "checkpointEndpoint": checkpoints[1]!["checkpointXid"] = "20"; break;
            case "rangeExtra": ranges[0]!["reclaimable"] = true; break;
            case "rangeType": checkpoints[0]!["metadataRanges"] = new JsonObject(); break;
            case "rangeZero": ranges[0]!["blockCount"] = "0"; break;
            case "rangeOverflow": ranges[0]!["blockCount"] = "18446744073709551615"; break;
            case "rangeOutside": ranges[1]!["physicalBlock"] = "512"; break;
            case "rangeOverlap": ranges[1]!["physicalBlock"] = "1"; break;
            case "rangeAdjacent": ranges[1]!["physicalBlock"] = "2"; break;
            case "rangeOrder": ranges[0]!["physicalBlock"] = "8"; break;
            case "rangeNumeric": ranges[0]!["blockCount"] = 2; break;
            case "rangeLeadingZero": ranges[0]!["physicalBlock"] = "00"; break;
            case "crossKindOverlap": checkpoints[0]!["payloadRanges"]![0]!["physicalBlock"] = "1"; break;
            case "payloadOverlap": checkpoints[0]!["payloadRanges"]!.AsArray().Add(Ranges((3, 1))[0]!.DeepClone()); break;
            case "payloadOutside": checkpoints[0]!["payloadRanges"]![0]!["physicalBlock"] = "512"; break;
            case "repair": node["repair"] = new JsonObject(); break;
            case "observe": node["observePayloadContent"] = false; break;
            case "inventory": node["payloadInventory"] = null; break;
            case "scopeExtra": node["requestedScope"]!["maxPayloadEntries"] = "1024"; break;
            case "scopeStart": node["requestedScope"]!["retainedFromXid"] = "8"; break;
            case "scopeWhole": node["requestedScope"]!["requireWholeVolume"] = true; break;
            case "scopeHashes": node["requestedScope"]!["requirePayloadContentHashes"] = true; break;
            case "format": node["format"] = "apfs-access-verification"; break;
            case "version": node["version"] = 2; break;
            case "selected": node["selected"] = null; break;
            case "sourceIdentity": node["source"]!["identity"] = "windows-file:other"; break;
            case "sourcePath": node["source"]!["path"] = Image + ".other"; break;
            case "sourceKind": node["source"]!["kind"] = "device"; break;
            case "lease": node["source"]!["lease"] = "none"; break;
            case "readBudget": node["sourceReads"] = "65537"; break;
            case "coverage21": node["coverage"]![20]!["check"] = 21; break;
            case "coverageMissing": node["coverage"]!.AsArray().RemoveAt(20); break;
            case "coverageDuplicate": node["coverage"]![20]!["check"] = 20; break;
            case "coverageUnknown": node["coverage"]![20]!["check"] = 23; break;
            case "historyUnimplemented": node["coverage"]![20]!["implemented"] = false; break;
            case "historyNotRequired": node["coverage"]![20]!["required"] = false; break;
            case "historyUnproven": node["coverage"]![20]!["state"] = 1; break;
            case "historicalVerified": node["coverage"]![12]!["state"] = 2; break;
            case "allocationVerified": node["coverage"]![11]!["state"] = 2; break;
            case "wholeVerified": node["wholeVolumeVerified"] = true; break;
            case "hashesVerified": node["payloadContentHashesVerified"] = true; break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(node));
    }

    [Theory]
    [InlineData("history")] [InlineData("census")] [InlineData("records")] [InlineData("extents")]
    [InlineData("verified22")] [InlineData("finding21")] [InlineData("findingUnknown")] [InlineData("codeUnknown")]
    public void PartialResultsCannotPublishSuccessEvidence(string mutation)
    {
        var node = Evidence(2);
        switch (mutation)
        {
            case "history": node["requestedHistory"] = Evidence()["requestedHistory"]!.DeepClone(); break;
            case "census": node["allocationCensus"] = Evidence()["allocationCensus"]!.DeepClone(); break;
            case "records": node["coveredFilesystemRecords"] = "1"; break;
            case "extents": node["coveredPhysicalExtents"] = "1"; break;
            case "verified22": node["coverage"]![20]!["state"] = 2; break;
            case "finding21": node["findings"]![0]!["check"] = 21; break;
            case "findingUnknown": node["findings"]![0]!["check"] = 23; break;
            case "codeUnknown": node["findings"]![0]!["code"] = 26; break;
        }
        Assert.Throws<InvalidDataException>(() => Parse(node, 3));
    }

    [Fact]
    public void FullHistoricalReachabilityStaysUnprovenOnRefusal()
    {
        var node = Evidence(3, 2); node["coverage"]![12]!["state"] = 4;
        node["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {
            code = 17, severity = 2, check = 13, volumeOid = (string?)null, objectId = (string?)null,
            physicalBlock = (string?)null, checkpointXid = (string?)null,
            failedSourceOffsetBytes = (string?)null, detail = "Full history remains unproven"
        }));
        Assert.Throws<InvalidDataException>(() => Parse(node, 4));
    }

    [Fact]
    public void DuplicateFieldsTruncationAndExitMismatchAreRejected()
    {
        var json = Evidence().ToJsonString();
        foreach (var key in new[] { "format", "retainedFromXid", "fromXid", "endpoint", "chainXids", "checkpoints",
            "checkpointXid", "metadataRanges", "physicalBlock", "blockCount", "check", "identity" })
        {
            using var document = JsonDocument.Parse(json);
            // Insert the identical property twice at its first occurrence, preserving valid JSON.
            var token = "\"" + key + "\":"; var start = json.IndexOf(token, StringComparison.Ordinal);
            // Values are obtained structurally below; no parsing of JSON values by delimiters.
            var value = Find(document.RootElement, key);
            var duplicate = json.Insert(start, token + value.GetRawText() + ",");
            Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(duplicate, 0, Request, Identity));
        }
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(json[..^1], 0, Request, Identity));
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(json + json, 0, Request, Identity));
        Assert.Throws<InvalidDataException>(() => Parse(Evidence(), 3));
        Assert.Throws<InvalidDataException>(() => Parse(Evidence(3, 2), 0));
    }

    private static JsonElement Find(JsonElement node, string key)
    {
        if (node.ValueKind == JsonValueKind.Object)
            foreach (var property in node.EnumerateObject())
            {
                if (property.Name == key) return property.Value;
                var found = Find(property.Value, key); if (found.ValueKind != JsonValueKind.Undefined) return found;
            }
        if (node.ValueKind == JsonValueKind.Array)
            foreach (var child in node.EnumerateArray())
            { var found = Find(child, key); if (found.ValueKind != JsonValueKind.Undefined) return found; }
        return default;
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void AbsentOptionKeepsLegacyWireAndRejectsHistoryDowngrade(int version)
    {
        var request = Request with { RetainedFromXid = null };
        var node = Evidence(); node["format"] = "apfs-access-verification"; node["version"] = version == 1 ? 1 : 2;
        node.Remove("requestedHistory"); node["requestedScope"]!.AsObject().Remove("retainedFromXid");
        node["coverage"]!.AsArray().RemoveAt(20);
        if (version == 1)
        {
            node.Remove("allocationCensus"); node["coverage"]!.AsArray().RemoveAt(19); node["coverage"]!.AsArray().RemoveAt(18);
        }
        node["repair"] = new JsonObject { ["planId"] = "", ["refusal"] = 1, ["nextActionableCandidate"] = null };
        node["repair"]!["planId"] = NativeApfsImageVerifier.BuildPlanId(JsonSerializer.SerializeToElement(node));
        if (version == 3) node = PayloadObservationFixture.Upgrade(node, live: false);
        var runner = new Runner((args, _) => {
            Assert.Equal("verify", args[3]); Assert.DoesNotContain("--retained-from-xid", args);
            using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
            node["source"]!["identity"] = NativeApfsImageVerifier.ReadIdentity(handle);
            node["repair"]!["planId"] = NativeApfsImageVerifier.BuildPlanId(JsonSerializer.SerializeToElement(node));
            return new(0, node.ToJsonString(), "");
        });
        var result = new NativeApfsImageVerifier(runner, Image).Verify(request);
        Assert.Equal(node.ToJsonString(), result.Report.GetRawText());
        Assert.Equal(version, result.Report.GetProperty("version").GetInt32());
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(node.ToJsonString(), 0, Request,
            node["source"]!["identity"]!.GetValue<string>()));
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseReport(Evidence().ToJsonString(), 0, request, Identity));
    }

    [Theory]
    [InlineData("")] [InlineData("0")] [InlineData("07")] [InlineData("+7")] [InlineData("-7")]
    [InlineData("7.0")] [InlineData(" 7")] [InlineData("18446744073709551616")] [InlineData("20")] [InlineData("21")]
    public void InvalidStartIsRejectedBeforeRunner(string start)
    {
        var runner = new Runner((_, _) => throw new InvalidOperationException("Must not execute"));
        Assert.Throws<ArgumentException>(() => new NativeApfsImageVerifier(runner, Image).Verify(Request with { RetainedFromXid = start }));
    }

    [Fact]
    public void HistoryCannotRequestBroaderCoverage()
    {
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { RequireWholeVolume = true }));
        Assert.Throws<ArgumentException>(() => NativeApfsImageVerifier.ValidateRequest(Request with { RequirePayloadContentHashes = true }));
        NativeApfsImageVerifier.ValidateRequest(Request);
    }

    [Theory]
    [InlineData(1, 0, 7)] [InlineData(2, 3, 7)] [InlineData(3, 4, 2)]
    public void RunnerUsesExactScopeHeldLeaseAndCancellation(int outcome, int exit, int code)
    {
        using var cancellation = new CancellationTokenSource();
        var runner = new Runner((args, token) => {
            Assert.Equal(cancellation.Token, token);
            Assert.Equal(new[] { "--image", Image, "--mode", "verify-history", "--container-uuid", new string('a', 32),
                "--volume-uuid", new string('b', 32), "--volume-oid", "101", "--checkpoint-xid", "20",
                "--store-offset-bytes", "0", "--store-size-bytes", "2097152", "--retained-from-xid", "7" }, args);
            Assert.Throws<IOException>(() => { using var writer = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
            Assert.Throws<IOException>(() => File.Move(Image, Image + ".moved"));
            using var handle = File.OpenHandle(Image, FileMode.Open, FileAccess.Read, FileShare.Read);
            var node = Evidence(outcome, code); node["source"]!["identity"] = NativeApfsImageVerifier.ReadIdentity(handle);
            return new(exit, node.ToJsonString(), "");
        });
        Assert.Equal(exit, new NativeApfsImageVerifier(runner, Image).Verify(Request, cancellation.Token).NativeExitCode);
        using var after = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    [Theory]
    [InlineData("cancel")] [InlineData("timeout")] [InlineData("nativeExit")] [InlineData("sourceMismatch")]
    public void RunnerFailuresReleaseTheImageLease(string failure)
    {
        using var cancellation = new CancellationTokenSource();
        var runner = new Runner((_, _) => {
            if (failure == "cancel") cancellation.Cancel();
            if (failure == "timeout") throw new TimeoutException();
            return new(failure == "nativeExit" ? 2 : 0, Evidence().ToJsonString(), "failure");
        });
        var verifier = new NativeApfsImageVerifier(runner, Image);
        var expected = failure switch { "cancel" => typeof(OperationCanceledException), "timeout" => typeof(TimeoutException),
            "nativeExit" => typeof(NativeVerificationExitException), _ => typeof(InvalidDataException) };
        Assert.Throws(expected, () => verifier.Verify(Request, cancellation.Token));
        using var after = File.Open(Image, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    private sealed class Runner(Func<IReadOnlyList<string>, CancellationToken, ObserverRunResult> run) : IObserverRunner
    {
        public ObserverRunResult Run(string path, IReadOnlyList<string> arguments) => run(arguments, default);
        public ObserverRunResult Run(string path, IReadOnlyList<string> arguments, CancellationToken token)
        { token.ThrowIfCancellationRequested(); var result = run(arguments, token); token.ThrowIfCancellationRequested(); return result; }
    }
}
