using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

internal static class LiveVerificationFixture
{
    public static LiveVolumeVerificationScope Scope(string container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        string volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", string oid = "101") =>
        new("image:test-held-owner", "retained-image", container, volume, oid, "20", "0", "2097152");
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static JsonObject Report(LiveVolumeVerificationScope? scope = null, bool damaged = false)
    {
        scope ??= Scope();
        var data = JsonSerializer.SerializeToNode(new
        {
            format = "apfs-access-live-volume-verification", version = 1, readOnly = true, requestedScope = scope,
            limits = new { maxReads = "65536", maxReadBytes = "268435456", maxRecords = "1000000", maxRecordBytes = "268435456",
                maxSessions = 100, maxElapsedMs = "5000", timeLimitKind = "cooperative-read-boundaries" },
            requireWholeVolume = false, requirePayloadContentHashes = false, elapsedMs = "2",
            selected = new { scope, checkpointPhysicalBlock = "19", volumeSuperblockPhysicalBlock = "4",
                volumeSuperblockXid = "20", rootOid = "8293", rootPhysicalBlock = "8" },
            outcome = damaged ? 2 : 1, outcomeName = damaged ? "Incomplete" : "Complete",
            wholeVolumeVerified = false, payloadContentHashesVerified = false, sourceReads = "94", sourceReadBytes = "372832",
            coveredFilesystemRecords = damaged ? "0" : "5", coveredPhysicalExtents = damaged ? "0" : "1",
            allocationCensus = damaged ? null : new { blockSizeBytes = "4096", containerBlockCount = "512", currentMetadataBlocks = "23",
                currentPayloadBlocks = "1", unattributedMainBlocks = "0", unattributedInternalBlocks = "0",
                unattributedMainRanges = Array.Empty<object>(), unattributedInternalRanges = Array.Empty<object>() },
            findings = damaged ? new[] { new { code = 6, severity = 3, check = 5, volumeOid = scope.VolumeOid,
                objectId = (string?)null, physicalBlock = (string?)null, checkpointXid = scope.CheckpointXid,
                failedSourceOffsetBytes = (string?)null, detail = "checksum mismatch" } } : [],
            coverage = Enumerable.Range(1, 20).Select(check => new { check, implemented = check <= 11 || check >= 17,
                required = check <= 11 || check >= 17,
                state = damaged && check == 5 ? 3 : check is 15 or 16 ? 4 : check is >= 12 and <= 14 ? 1 : damaged ? 1 : 2,
                scopeDetail = "covered metadata" }).ToArray(),
            repair = new { planId = "", refusal = damaged ? 2 : 1, nextActionableCandidate = (string?)null }
        }, Options)!.AsObject();
        data["repair"]!["planId"] = PlanId(data);
        return data;
    }

    // Native length-prefixed refusal contract; this fixture never authorizes repair.
    internal static string PlanId(JsonObject node)
    {
        using var document = JsonDocument.Parse(node.ToJsonString()); var root = document.RootElement;
        var builder = new StringBuilder("apfs-verifier-refusal-v1|");
        void Add(string value) => builder.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value);
        void Fields(JsonElement obj, string names)
        {
            foreach (var name in names.Split(' '))
            {
                var value = obj.GetProperty(name);
                Add(value.ValueKind switch { JsonValueKind.String => value.GetString()!, JsonValueKind.Null => "unknown",
                    JsonValueKind.True => "1", JsonValueKind.False => "0", _ => value.GetRawText() });
            }
        }
        const string keys = "storeOffsetBytes storeSizeBytes containerUuid volumeUuid volumeOid checkpointXid";
        Fields(root.GetProperty("requestedScope"), "sourceIdentity " + keys); Add("1");
        Fields(root.GetProperty("selected").GetProperty("scope"), keys);
        Fields(root.GetProperty("selected"), "checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
        Fields(root.GetProperty("limits"), "maxReads maxReadBytes maxRecords maxRecordBytes");
        Fields(root, "requireWholeVolume requirePayloadContentHashes outcome"); Fields(root.GetProperty("repair"), "refusal");
        var findings = root.GetProperty("findings"); Add(findings.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var value in findings.EnumerateArray()) Fields(value, "check code severity volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
        var coverage = root.GetProperty("coverage"); Add(coverage.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var value in coverage.EnumerateArray()) Fields(value, "check implemented required state");
        return builder.ToString();
    }

    public static JsonElement Element(JsonNode node) => JsonSerializer.SerializeToElement(node);
}
