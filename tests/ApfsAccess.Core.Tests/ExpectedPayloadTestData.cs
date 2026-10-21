using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

internal static class ExpectedPayloadTestData
{
    // SHA-256 of the independent, known input ASCII "abc". Never derive expectations from observations.
    internal const string AbcDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    internal const string EmptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    internal static JsonObject Scope() => new()
    {
        ["sourceIdentity"] = "image:opaque-held-owner", ["sourceKind"] = "retained-image",
        ["containerUuid"] = new string('a', 32), ["volumeUuid"] = new string('b', 32),
        ["volumeOid"] = "101", ["checkpointXid"] = "20", ["storeOffsetBytes"] = "0", ["storeSizeBytes"] = "2097152"
    };
    internal static JsonObject Manifest() => new()
    {
        ["format"] = "apfs-access-expected-payload-manifest", ["version"] = 1,
        ["expectedSource"] = "Original external input: ASCII abc and an empty attribute; caller supplied",
        ["algorithm"] = "SHA256", ["coverage"] = ExpectedPayloadManifest.Coverage, ["scope"] = Scope(),
        ["entries"] = new JsonArray(Expected("file-data", "9007199254740993", "18446744073709551615", null, "3", AbcDigest),
            Expected("xattr", "9007199254740993", "0", "com.apple.Empty", "0", EmptyDigest))
    };
    internal static JsonObject Expected(string kind, string inode, string stream, string? name, string size, string digest) => new()
    {
        ["kind"] = kind, ["inodeOid"] = inode, ["streamOid"] = stream, ["nameUtf8"] = name,
        ["logicalSizeBytes"] = size, ["expectedSha256"] = digest
    };
    internal static JsonObject Report()
    {
        var report = JsonSerializer.SerializeToNode(new
        {
            format = "apfs-access-live-volume-verification", version = 2, readOnly = true, requestedScope = Scope(),
            limits = new { maxReads = "65536", maxReadBytes = "268435456", maxRecords = "1000000", maxRecordBytes = "268435456",
                maxSessions = 100, maxElapsedMs = "5000", timeLimitKind = "cooperative-read-boundaries",
                maxPayloadLogicalBytes = "268435456", maxPayloadEntries = "1024" },
            requireWholeVolume = false, requirePayloadContentHashes = false, elapsedMs = "2", observePayloadContent = true,
            selected = new { scope = Scope(), checkpointPhysicalBlock = "19", volumeSuperblockPhysicalBlock = "4",
                volumeSuperblockXid = "20", rootOid = "8293", rootPhysicalBlock = "8" },
            outcome = 1, outcomeName = "Complete", wholeVolumeVerified = false, payloadContentHashesVerified = false,
            sourceReads = "94", sourceReadBytes = "372832", coveredFilesystemRecords = "5", coveredPhysicalExtents = "1",
            allocationCensus = new { blockSizeBytes = "4096", containerBlockCount = "512", currentMetadataBlocks = "23",
                currentPayloadBlocks = "1", unattributedMainBlocks = "0", unattributedInternalBlocks = "0",
                unattributedMainRanges = Array.Empty<object>(), unattributedInternalRanges = Array.Empty<object>() },
            findings = Array.Empty<object>(),
            coverage = Enumerable.Range(1, 21).Select(check => new { check, implemented = check <= 11 || check >= 17,
                required = check <= 11 || check >= 17, state = check is 15 or 16 ? 4 : check is >= 12 and <= 14 ? 1 : 2,
                scopeDetail = "Covered current metadata or observed payload" }).ToArray(),
            repair = new { planId = "", refusal = 1, nextActionableCandidate = (string?)null }
        })!.AsObject();
        report["payloadInventory"] = new JsonObject
        {
            ["scopeKind"] = "selected-current-volume", ["algorithm"] = "SHA256", ["enumerationComplete"] = true,
            ["readComplete"] = true, ["hashesObserved"] = true, ["expectedComparison"] = "NotSupplied",
            ["maxLogicalBytes"] = "268435456", ["maxEntries"] = "1024", ["entryCount"] = "2", ["logicalBytesRead"] = "3",
            ["entries"] = new JsonArray(Observed("file-data", "18446744073709551615", null, "3", AbcDigest),
                Observed("xattr", "0", "com.apple.Empty", "0", EmptyDigest))
        };
        Bind(report); return report;
    }
    private static JsonObject Observed(string kind, string stream, string? name, string size, string digest) => new()
    {
        ["kind"] = kind, ["inodeOid"] = "9007199254740993", ["streamOid"] = stream, ["nameUtf8"] = name,
        ["logicalSizeBytes"] = size, ["logicalBytesRead"] = size, ["readOutcome"] = "Complete",
        ["observedSha256"] = digest, ["expectedSha256"] = null
    };
    internal static void Bind(JsonObject report)
    {
        using var document = JsonDocument.Parse(report.ToJsonString()); var root = document.RootElement;
        var id = new StringBuilder(root.GetProperty("version").GetInt32() == 2 ? "apfs-verifier-refusal-v2|" : "apfs-verifier-refusal-v1|");
        void Add(string text) => id.Append(Encoding.UTF8.GetByteCount(text).ToString(CultureInfo.InvariantCulture)).Append(':').Append(text);
        void Fields(JsonElement obj, string names)
        {
            foreach (var name in names.Split(' '))
            {
                var value = obj.GetProperty(name);
                Add(value.ValueKind switch { JsonValueKind.String => value.GetString()!, JsonValueKind.Null => "unknown",
                    JsonValueKind.True => "1", JsonValueKind.False => "0", _ => value.GetRawText() });
            }
        }
        const string exact = "storeOffsetBytes storeSizeBytes containerUuid volumeUuid volumeOid checkpointXid";
        Fields(root.GetProperty("requestedScope"), "sourceIdentity " + exact); Add("1");
        Fields(root.GetProperty("selected").GetProperty("scope"), exact);
        Fields(root.GetProperty("selected"), "checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
        Fields(root.GetProperty("limits"), "maxReads maxReadBytes maxRecords maxRecordBytes");
        Fields(root, "requireWholeVolume requirePayloadContentHashes");
        if (root.GetProperty("version").GetInt32() == 2)
        { Fields(root, "observePayloadContent"); Fields(root.GetProperty("limits"), "maxPayloadLogicalBytes maxPayloadEntries"); }
        Fields(root, "outcome"); Fields(root.GetProperty("repair"), "refusal");
        var findings = root.GetProperty("findings"); Add(findings.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var item in findings.EnumerateArray()) Fields(item, "check code severity volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
        var coverage = root.GetProperty("coverage"); Add(coverage.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var item in coverage.EnumerateArray()) Fields(item, "check implemented required state");
        report["repair"]!["planId"] = id.ToString();
    }
    internal static JsonObject PartialReport(bool enumerationIncomplete)
    {
        var report = Report(); var p = report["payloadInventory"]!;
        report["outcome"] = 2; report["outcomeName"] = "Incomplete"; report["allocationCensus"] = null;
        report["coveredFilesystemRecords"] = "0"; report["coveredPhysicalExtents"] = "0";
        report["repair"]!["refusal"] = 2; report["coverage"]![20]!["state"] = 1;
        p["readComplete"] = false; p["hashesObserved"] = false;
        if (enumerationIncomplete)
        {
            p["enumerationComplete"] = false; p["entries"] = new JsonArray(); p["entryCount"] = "0"; p["logicalBytesRead"] = "0";
        }
        else
        {
            p["entries"]![0]!["readOutcome"] = "ReadFailure"; p["entries"]![0]!["observedSha256"] = null;
            p["entries"]![0]!["logicalBytesRead"] = "1"; p["logicalBytesRead"] = "1";
        }
        report["findings"] = new JsonArray(new JsonObject
        {
            ["code"] = enumerationIncomplete ? 4 : 3, ["severity"] = 3, ["check"] = 21,
            ["volumeOid"] = "101", ["objectId"] = null, ["physicalBlock"] = null, ["checkpointXid"] = "20",
            ["failedSourceOffsetBytes"] = null, ["detail"] = "Payload observation incomplete"
        });
        Bind(report); return report;
    }
    internal static ExpectedPayloadManifest Parse(JsonObject manifest)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(manifest.ToJsonString()));
        return ExpectedPayloadManifest.Parse(ExpectedPayloadInput.Read(stream, ExpectedPayloadManifest.MaximumManifestBytes));
    }
    internal static LiveVolumeVerificationReport ParseReport(JsonObject report) =>
        LiveVolumeVerificationReport.Parse(JsonSerializer.SerializeToElement(report));
}
