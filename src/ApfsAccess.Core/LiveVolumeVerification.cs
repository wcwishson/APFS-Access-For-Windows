using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Core;

public sealed record LiveVolumeVerificationScope(string SourceIdentity, string SourceKind,
    string ContainerUuid, string VolumeUuid, string VolumeOid, string CheckpointXid,
    string StoreOffsetBytes, string StoreSizeBytes)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyList<string> RequestLines => [ContainerUuid, VolumeUuid, CheckpointXid,
        StoreOffsetBytes, StoreSizeBytes, SourceIdentity];

    public static LiveVolumeVerificationScope Parse(JsonElement value)
    {
        VerificationWire.Object(value, "sourceIdentity sourceKind containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes");
        var identity = VerificationWire.Text(value, "sourceIdentity", 192);
        VerificationWire.Require(identity.Length > 0 && identity.All(c => c is >= '!' and <= '~'));
        var kind = VerificationWire.Text(value, "sourceKind");
        VerificationWire.Require(kind is "retained-image" or "retained-admitted-raw");
        var container = VerificationWire.Text(value, "containerUuid");
        var volume = VerificationWire.Text(value, "volumeUuid");
        VerificationWire.Require(VerificationWire.Uuid(container) && VerificationWire.Uuid(volume));
        VerificationWire.Number(value, "volumeOid", false); VerificationWire.Number(value, "checkpointXid", false);
        var offset = VerificationWire.Number(value, "storeOffsetBytes");
        var size = VerificationWire.Number(value, "storeSizeBytes", false);
        VerificationWire.Require(size <= ulong.MaxValue - offset);
        return new(identity, kind, container, volume, value.GetProperty("volumeOid").GetString()!,
            value.GetProperty("checkpointXid").GetString()!, value.GetProperty("storeOffsetBytes").GetString()!,
            value.GetProperty("storeSizeBytes").GetString()!);
    }
}

public sealed record LiveVolumeVerificationReport(LiveVolumeVerificationScope Scope, string Outcome,
    int FindingCount, JsonElement Json)
{
    public const int MaximumResponseBytes = 1024 * 1024;
    public bool Complete => Outcome == "Complete" && FindingCount == 0;
    public CurrentPayloadInventory? PayloadInventory { get; init; }

    public static LiveVolumeVerificationReport Parse(JsonElement root)
    {
        try
        {
            VerificationWire.Require(Encoding.UTF8.GetByteCount(root.GetRawText()) <= MaximumResponseBytes);
            var version = VerificationWire.Enum(root, "version", 2);
            var observation = version == 2;
            VerificationWire.Object(root, "format version readOnly requestedScope limits requireWholeVolume requirePayloadContentHashes elapsedMs selected outcome outcomeName wholeVolumeVerified payloadContentHashesVerified sourceReads sourceReadBytes coveredFilesystemRecords coveredPhysicalExtents allocationCensus findings coverage repair" +
                (observation ? " observePayloadContent payloadInventory" : ""));
            VerificationWire.Require(VerificationWire.Text(root, "format") == "apfs-access-live-volume-verification" &&
                root.GetProperty("readOnly").GetBoolean() &&
                !root.GetProperty("requireWholeVolume").GetBoolean() && !root.GetProperty("requirePayloadContentHashes").GetBoolean() &&
                !root.GetProperty("wholeVolumeVerified").GetBoolean() && !root.GetProperty("payloadContentHashesVerified").GetBoolean());
            VerificationWire.Require(!observation || root.GetProperty("observePayloadContent").GetBoolean());
            var scope = LiveVolumeVerificationScope.Parse(root.GetProperty("requestedScope"));
            var limits = root.GetProperty("limits");
            VerificationWire.Object(limits, "maxReads maxReadBytes maxRecords maxRecordBytes maxSessions maxElapsedMs timeLimitKind" +
                (observation ? " maxPayloadLogicalBytes maxPayloadEntries" : ""));
            if (observation) VerificationWire.Require(VerificationWire.Number(limits, "maxPayloadLogicalBytes") == CurrentPayloadInventory.MaximumLogicalBytes &&
                VerificationWire.Number(limits, "maxPayloadEntries") == CurrentPayloadInventory.MaximumEntries);
            VerificationWire.Require(VerificationWire.Number(limits, "maxReads") == 65536 &&
                VerificationWire.Number(limits, "maxReadBytes") == 268435456 &&
                VerificationWire.Number(limits, "maxRecords") == 1000000 &&
                VerificationWire.Number(limits, "maxRecordBytes") == 268435456 &&
                VerificationWire.Enum(limits, "maxSessions", 100) == 100 &&
                VerificationWire.Number(limits, "maxElapsedMs") == 5000 &&
                VerificationWire.Text(limits, "timeLimitKind") == "cooperative-read-boundaries" &&
                VerificationWire.Number(root, "elapsedMs") <= 5000);
            var outcome = VerificationWire.Enum(root, "outcome", 3);
            var name = outcome == 1 ? "Complete" : outcome == 2 ? "Incomplete" : "Refused";
            VerificationWire.Require(VerificationWire.Text(root, "outcomeName") == name);
            var selected = root.GetProperty("selected");
            if (selected.ValueKind != JsonValueKind.Null)
            {
                VerificationWire.Object(selected, "scope checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
                VerificationWire.Require(LiveVolumeVerificationScope.Parse(selected.GetProperty("scope")) == scope);
                foreach (var key in "checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock".Split(' '))
                    VerificationWire.Number(selected, key, false);
                VerificationWire.Require(VerificationWire.Number(selected, "volumeSuperblockXid", false) <=
                    ulong.Parse(scope.CheckpointXid, CultureInfo.InvariantCulture));
            }
            VerificationWire.Require(outcome != 1 || selected.ValueKind == JsonValueKind.Object);
            VerificationWire.Require(VerificationWire.Number(root, "sourceReads") <= 65536 &&
                VerificationWire.Number(root, "sourceReadBytes") <= 268435456);
            var records = VerificationWire.Number(root, "coveredFilesystemRecords");
            var extents = VerificationWire.Number(root, "coveredPhysicalExtents");
            VerificationWire.Require(records <= 1000000 && extents <= 1000000 && (outcome == 1 || records == 0 && extents == 0));
            var coverage = root.GetProperty("coverage");
            var checkCount = observation ? 21 : 20;
            VerificationWire.Require(coverage.ValueKind == JsonValueKind.Array && coverage.GetArrayLength() == checkCount);
            var states = new Dictionary<int, int>();
            foreach (var entry in coverage.EnumerateArray())
            {
                VerificationWire.Object(entry, "check implemented required state scopeDetail");
                var check = VerificationWire.Enum(entry, "check", checkCount); var state = VerificationWire.Enum(entry, "state", 5);
                VerificationWire.Require(states.TryAdd(check, state));
                VerificationWire.Text(entry, "scopeDetail");
                var implemented = check <= 11 || check >= 17;
                VerificationWire.Require(entry.GetProperty("implemented").GetBoolean() == implemented &&
                    entry.GetProperty("required").GetBoolean() == implemented && (!implemented || state != 5));
                if (check is 12 or 14) VerificationWire.Require(state == 1);
                if (check == 13) VerificationWire.Require(state == 1 || outcome == 3 && state == 4);
                if (check is 15 or 16) VerificationWire.Require(state == 4);
                if (outcome == 1 && implemented) VerificationWire.Require(state == 2);
            }
            var findings = root.GetProperty("findings");
            VerificationWire.Require(findings.ValueKind == JsonValueKind.Array && findings.GetArrayLength() <= 64 &&
                (outcome == 1 ? findings.GetArrayLength() == 0 : findings.GetArrayLength() > 0));
            var findingChecks = new HashSet<int>();
            foreach (var finding in findings.EnumerateArray())
            {
                VerificationWire.Object(finding, "code severity check volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
                var code = VerificationWire.Enum(finding, "code", observation ? 25 : 24); var severity = VerificationWire.Enum(finding, "severity", 3);
                var check = VerificationWire.Enum(finding, "check", checkCount); findingChecks.Add(check);
                if (code is 23 or 24) VerificationWire.Require(check == 19);
                if (code == 25) VerificationWire.Require(check == 7);
                if (code == 17) VerificationWire.Require(check == 13);
                var refused = code is 1 or 2 or 8 or 17 or 19 or 20;
                var state = refused ? 4 : code is 3 or 4 or 5 or 18 ? 1 : 3;
                VerificationWire.Require((outcome == 3) == refused && states[check] == state && severity == (refused ? 2 : 3));
                foreach (var key in "volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes".Split(' '))
                    if (finding.GetProperty(key).ValueKind != JsonValueKind.Null) VerificationWire.Number(finding, key);
                VerificationWire.Text(finding, "detail");
            }
            foreach (var (check, state) in states)
                if (state == 3 || state == 4 && check is not (15 or 16)) VerificationWire.Require(findingChecks.Contains(check));
            ValidateCensus(root.GetProperty("allocationCensus"), selected, scope, outcome);
            var payload = observation ? CurrentPayloadInventory.Parse(root.GetProperty("payloadInventory"), outcome,
                states[21], selected.ValueKind == JsonValueKind.Object, findings) : null;
            var repair = root.GetProperty("repair");
            VerificationWire.Object(repair, "planId refusal nextActionableCandidate");
            VerificationWire.Require(VerificationWire.Enum(repair, "refusal", 2) == (outcome == 1 ? 1 : 2) &&
                repair.GetProperty("nextActionableCandidate").ValueKind == JsonValueKind.Null &&
                VerificationWire.Text(repair, "planId", 65536) == BuildPlanId(root));
            return new(scope, name, findings.GetArrayLength(), root.Clone()) { PayloadInventory = payload };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or KeyNotFoundException)
        { throw new InvalidDataException("Invalid retained-source volume verification report.", ex); }
    }

    private static void ValidateCensus(JsonElement census, JsonElement selected, LiveVolumeVerificationScope scope, int outcome)
    {
        if (outcome != 1) { VerificationWire.Require(census.ValueKind == JsonValueKind.Null); return; }
        VerificationWire.Object(census, "blockSizeBytes containerBlockCount currentMetadataBlocks currentPayloadBlocks unattributedMainBlocks unattributedInternalBlocks unattributedMainRanges unattributedInternalRanges");
        var block = VerificationWire.Number(census, "blockSizeBytes", false);
        var capacity = VerificationWire.Number(census, "containerBlockCount", false);
        VerificationWire.Require(block is >= 4096 and <= 65536 && (block & (block - 1)) == 0 &&
            capacity <= ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture) / block);
        var metadata = VerificationWire.Number(census, "currentMetadataBlocks", false);
        var payload = VerificationWire.Number(census, "currentPayloadBlocks");
        var main = VerificationWire.Number(census, "unattributedMainBlocks");
        var internalBlocks = VerificationWire.Number(census, "unattributedInternalBlocks");
        VerificationWire.Require(checked(metadata + payload + main + internalBlocks) <= capacity);
        List<(ulong Start, ulong End)> Ranges(string key, ulong count)
        {
            var array = census.GetProperty(key);
            VerificationWire.Require(array.ValueKind == JsonValueKind.Array && array.GetArrayLength() <= 8192);
            var ranges = new List<(ulong, ulong)>(); ulong sum = 0, end = 0;
            foreach (var range in array.EnumerateArray())
            {
                VerificationWire.Object(range, "physicalBlock blockCount");
                var start = VerificationWire.Number(range, "physicalBlock"); var size = VerificationWire.Number(range, "blockCount", false);
                VerificationWire.Require(start < capacity && size <= capacity - start && (ranges.Count == 0 || start > end));
                end = checked(start + size); sum = checked(sum + size); ranges.Add((start, end));
            }
            VerificationWire.Require(sum == count); return ranges;
        }
        var a = Ranges("unattributedMainRanges", main); var b = Ranges("unattributedInternalRanges", internalBlocks);
        int i = 0, j = 0;
        while (i < a.Count && j < b.Count)
        {
            VerificationWire.Require(a[i].End <= b[j].Start || b[j].End <= a[i].Start);
            if (a[i].End <= b[j].Start) ++i; else ++j;
        }
        foreach (var key in "checkpointPhysicalBlock volumeSuperblockPhysicalBlock rootPhysicalBlock".Split(' '))
            VerificationWire.Require(VerificationWire.Number(selected, key, false) < capacity);
    }

    private static string BuildPlanId(JsonElement root)
    {
        var observation = root.GetProperty("version").GetInt32() == 2;
        var id = new StringBuilder(observation ? "apfs-verifier-refusal-v2|" : "apfs-verifier-refusal-v1|");
        void Field(string value) => id.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value);
        void Value(JsonElement obj, string key)
        {
            var value = obj.GetProperty(key);
            Field(value.ValueKind switch { JsonValueKind.String => value.GetString()!, JsonValueKind.True => "1",
                JsonValueKind.False => "0", JsonValueKind.Null => "unknown", _ => value.GetRawText() });
        }
        void Values(JsonElement obj, string keys) { foreach (var key in keys.Split(' ')) Value(obj, key); }
        const string exact = "storeOffsetBytes storeSizeBytes containerUuid volumeUuid volumeOid checkpointXid";
        Value(root.GetProperty("requestedScope"), "sourceIdentity"); Values(root.GetProperty("requestedScope"), exact);
        var selected = root.GetProperty("selected"); Field(selected.ValueKind == JsonValueKind.Null ? "0" : "1");
        if (selected.ValueKind != JsonValueKind.Null)
        {
            Values(selected.GetProperty("scope"), exact);
            Values(selected, "checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
        }
        Values(root.GetProperty("limits"), "maxReads maxReadBytes maxRecords maxRecordBytes");
        Values(root, "requireWholeVolume requirePayloadContentHashes");
        if (observation)
        {
            Value(root, "observePayloadContent");
            Values(root.GetProperty("limits"), "maxPayloadLogicalBytes maxPayloadEntries");
        }
        Value(root, "outcome"); Value(root.GetProperty("repair"), "refusal");
        var findings = root.GetProperty("findings"); Field(findings.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var finding in findings.EnumerateArray()) Values(finding, "check code severity volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
        var coverage = root.GetProperty("coverage"); Field(coverage.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var entry in coverage.EnumerateArray()) Values(entry, "check implemented required state");
        return id.ToString();
    }
}

internal static class VerificationWire
{
    internal static bool Uuid(string value) => value.Length == 32 && value.All(char.IsAsciiHexDigitLower) && value.Any(c => c != '0');
    internal static void Object(JsonElement value, string fields)
    {
        Require(value.ValueKind == JsonValueKind.Object);
        var expected = fields.Split(' ').ToHashSet(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) Require(expected.Remove(property.Name));
        Require(expected.Count == 0);
    }
    internal static string Text(JsonElement value, string key, int limit = 4096)
    {
        var text = value.GetProperty(key).GetString();
        Require(text is not null && new UTF8Encoding(false, true).GetByteCount(text) <= limit); return text!;
    }
    internal static ulong Number(JsonElement value, string key, bool zero = true)
    {
        var text = Text(value, key);
        Require(ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number) &&
            (zero || number > 0) && number.ToString(CultureInfo.InvariantCulture) == text); return number;
    }
    internal static int Enum(JsonElement value, string key, int max)
    { var number = value.GetProperty(key).GetInt32(); Require(number is >= 1 && number <= max); return number; }
    internal static void Require(bool condition)
    { if (!condition) throw new InvalidDataException("Invalid retained-source volume verification contract."); }
}

public sealed record LiveVolumeVerificationResult(bool Success, string Code, LiveVolumeVerificationReport? Report = null);

public interface ILiveVolumeVerificationBackend
{
    Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token);

    Task<LiveVolumeVerificationResult> VerifyLiveVolumeMetadataAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        => VerifyLiveVolumeAsync(scope, token);
}
