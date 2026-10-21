using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

/// <summary>Exact image scope. No default volume or checkpoint selection is permitted.</summary>
public sealed record ApfsImageVerificationRequest(string Image, string ContainerId, string VolumeUuid,
    string VolumeOid, string CheckpointXid, string StoreOffsetBytes, string StoreSizeBytes,
    bool RequireWholeVolume = false, bool RequirePayloadContentHashes = false, string? RetainedFromXid = null,
    bool AccountRetainedOwnership = false);

public enum ApfsVerificationOutcome { Complete = 1, Incomplete = 2, Refused = 3 }

/// <summary>
/// Complete means only the declared covered current metadata subset passed. The validated native
/// report preserves all coverage, findings and decimal uint64 strings. It is not repair authorization.
/// With RetainedFromXid, Complete also covers only the requested protected checkpoint chain.
/// </summary>
public sealed class ApfsImageVerificationResult
{
    internal ApfsImageVerificationResult(int nativeExitCode, ApfsVerificationOutcome outcome, JsonElement report,
        CurrentPayloadInventory? payloadInventory = null)
    { NativeExitCode = nativeExitCode; Outcome = outcome; Report = report; PayloadInventory = payloadInventory; }
    public int NativeExitCode { get; }
    public ApfsVerificationOutcome Outcome { get; }
    public JsonElement Report { get; }
    public CurrentPayloadInventory? PayloadInventory { get; }
}

public sealed class NativeVerificationExitException(int exitCode, string diagnostic)
    : IOException($"Native verification failed (exit {exitCode}): {diagnostic}")
{
    public int NativeExitCode { get; } = exitCode;
}

/// <summary>Read-only regular image verification through the bounded packaged observer transport.</summary>
public sealed partial class NativeApfsImageVerifier
{
    internal const int MaxReportBytes = 64 * 1024 * 1024;
    private readonly IObserverRunner runner;
    private readonly string? observerPath;
    public NativeApfsImageVerifier() : this(new ProcessObserverRunner(), NativeApfsSnapshotReader.ResolvePackagedObserver()) { }
    internal NativeApfsImageVerifier(IObserverRunner runner, string? observerPath)
    { this.runner = runner; this.observerPath = observerPath; }

    public static void ValidateRequest(ApfsImageVerificationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        NativeApfsSnapshotReader.ValidateRequest(request.Image, request.ContainerId, request.VolumeOid);
        if (!IsHex(request.VolumeUuid) || !NativeApfsSnapshotReader.IsU64(request.CheckpointXid, false) ||
            !NativeApfsSnapshotReader.IsU64(request.StoreOffsetBytes) || !NativeApfsSnapshotReader.IsU64(request.StoreSizeBytes, false))
            throw new ArgumentException("Use a nonzero lowercase hex32 volume UUID and canonical decimal uint64 XID, offset and size; XID and size must be nonzero.");
        if (request.RetainedFromXid is not null &&
            (!NativeApfsSnapshotReader.IsU64(request.RetainedFromXid, false) ||
             ulong.Parse(request.RetainedFromXid, CultureInfo.InvariantCulture) >= ulong.Parse(request.CheckpointXid, CultureInfo.InvariantCulture) ||
             request.RequireWholeVolume || request.RequirePayloadContentHashes || request.AccountRetainedOwnership))
            throw new ArgumentException("Protected history requires a canonical nonzero retained start XID before the selected checkpoint, without whole-volume or payload-content-hash requirements.");
        var size = (ulong)new FileInfo(request.Image).Length;
        var offset = ulong.Parse(request.StoreOffsetBytes, CultureInfo.InvariantCulture);
        if (offset > size || ulong.Parse(request.StoreSizeBytes, CultureInfo.InvariantCulture) > size - offset)
            throw new ArgumentException("The exact store window must fit inside the image.");
    }

    public ApfsImageVerificationResult Verify(ApfsImageVerificationRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRequest(request);
        if (observerPath is null) throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath);
        // Keep the exact image leased across launch, validation and final identity recheck.
        // No full-image or payload hash is claimed by this protocol.
        using var source = File.OpenHandle(request.Image, FileMode.Open, FileAccess.Read, FileShare.Read);
        NativeApfsSnapshotReader.ValidateIdentity(source, request.Image);
        var identity = ReadIdentity(source);
        var arguments = new List<string> { "--image", request.Image, "--mode", request.RetainedFromXid is null ? "verify" : "verify-history",
            "--container-uuid", request.ContainerId[15..], "--volume-uuid", request.VolumeUuid,
            "--volume-oid", request.VolumeOid, "--checkpoint-xid", request.CheckpointXid,
            "--store-offset-bytes", request.StoreOffsetBytes, "--store-size-bytes", request.StoreSizeBytes };
        if (request.RequireWholeVolume) arguments.Add("--require-whole-volume");
        if (request.RequirePayloadContentHashes) arguments.Add("--require-payload-content-hashes");
        if (request.RetainedFromXid is not null) arguments.AddRange(["--retained-from-xid", request.RetainedFromXid]);
        if (request.AccountRetainedOwnership) arguments.Add("--account-retained-ownership");
        var wire = runner.Run(observerPath, arguments, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3 or 4)) throw new NativeVerificationExitException(wire.ExitCode, wire.StandardError);
        var result = ParseReport(wire.StandardOutput, wire.ExitCode, request, identity);
        if (identity != ReadIdentity(source)) throw new InvalidDataException("Image identity changed during verification.");
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    internal static string ReadIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("Cannot establish image file identity.");
        return FormattableString.Invariant($"windows-file:{info.VolumeSerial}:{Join(info.IndexHigh, info.IndexLow)}:{Join(info.SizeHigh, info.SizeLow)}:{Join(info.WriteHigh, info.WriteLow)}");
    }
    private static ulong Join(uint high, uint low) => ((ulong)high << 32) | low;
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);

    internal static ApfsImageVerificationResult ParseReport(string json, int exitCode, ApfsImageVerificationRequest request, string identity)
    {
        try
        {
            Require(new UTF8Encoding(false, true).GetByteCount(json) <= MaxReportBytes);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var history = request.RetainedFromXid is not null;
            var version = EnumNumber(root, "version", 4);
            var accounting = version == 4;
            Require(accounting == request.AccountRetainedOwnership && (!accounting || !history));
            var observation = !history && (version == 3 || accounting && root.TryGetProperty("observePayloadContent", out _));
            Require(!history || version == 1);
            Object(root, "format version readOnly source requestedScope selected outcome outcomeName wholeVolumeVerified payloadContentHashesVerified sourceReads sourceReadBytes coveredFilesystemRecords coveredPhysicalExtents findings coverage" +
                (history ? " allocationCensus requestedHistory" : " repair" + (version >= 2 ? " allocationCensus" : "")) +
                (observation ? " observePayloadContent payloadInventory" : "") + (accounting ? " retainedOwnership" : ""));
            Require(Text(root, "format") == (history ? "apfs-access-protected-history-verification" : "apfs-access-verification") && Bool(root, "readOnly"));
            Require(!observation || Bool(root, "observePayloadContent"));
            var outcome = EnumNumber(root, "outcome", 3);
            Require(exitCode == (outcome == 1 ? 0 : outcome == 2 ? 3 : 4) &&
                Text(root, "outcomeName") == ((ApfsVerificationOutcome)outcome).ToString());
            Require(!Bool(root, "wholeVolumeVerified") && !Bool(root, "payloadContentHashesVerified"));
            var source = root.GetProperty("source"); Object(source, "kind path identity lease");
            Require(Text(source, "kind") == "image" && Text(source, "path") == request.Image &&
                Text(source, "identity") == identity && Text(source, "lease") == "windows-read-deny-write-delete");
            var scope = root.GetProperty("requestedScope");
            Object(scope, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes maxReads maxReadBytes maxRecords maxRecordBytes requireWholeVolume requirePayloadContentHashes" +
                (history ? " retainedFromXid" : "") + (observation ? " maxPayloadLogicalBytes maxPayloadEntries" : "") +
                (accounting ? " accountRetainedOwnership" : ""));
            if (accounting) Require(Bool(scope, "accountRetainedOwnership"));
            if (observation) Require(Number(scope, "maxPayloadLogicalBytes") == CurrentPayloadInventory.MaximumLogicalBytes &&
                Number(scope, "maxPayloadEntries") == CurrentPayloadInventory.MaximumEntries);
            Exact(scope, request);
            if (history)
                Require(Text(scope, "retainedFromXid") == request.RetainedFromXid &&
                    Number(scope, "retainedFromXid", false) < Number(scope, "checkpointXid", false) &&
                    !request.RequireWholeVolume && !request.RequirePayloadContentHashes);
            Require(Number(scope, "maxReads") == 65536 && Number(scope, "maxReadBytes") == 268435456 &&
                Number(scope, "maxRecords") == 1000000 && Number(scope, "maxRecordBytes") == 268435456 &&
                Bool(scope, "requireWholeVolume") == request.RequireWholeVolume &&
                Bool(scope, "requirePayloadContentHashes") == request.RequirePayloadContentHashes);
            var selected = root.GetProperty("selected");
            if (selected.ValueKind != JsonValueKind.Null)
            {
                Object(selected, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
                Exact(selected, request);
                foreach (var key in "checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock".Split(' ')) Number(selected, key, false);
                Require(Number(selected, "volumeSuperblockXid", false) <= Number(scope, "checkpointXid", false));
            }
            Require(outcome != 1 || selected.ValueKind == JsonValueKind.Object);
            Require(Number(root, "sourceReads") <= Number(scope, "maxReads") && Number(root, "sourceReadBytes") <= Number(scope, "maxReadBytes"));
            var records = Number(root, "coveredFilesystemRecords"); var extents = Number(root, "coveredPhysicalExtents");
            Require(outcome == 1 || (records == 0 && extents == 0));
            Require(records <= Number(scope, "maxRecords") && extents <= Number(scope, "maxRecords"));
            var checkCount = history || observation ? 21 : version == 1 ? 18 : 20;
            var maxCheck = history ? 22 : checkCount;
            var coverage = root.GetProperty("coverage"); Require(coverage.ValueKind == JsonValueKind.Array && coverage.GetArrayLength() == checkCount);
            var states = new Dictionary<int, int>();
            foreach (var entry in coverage.EnumerateArray())
            {
                Object(entry, "check implemented required state scopeDetail");
                var check = EnumNumber(entry, "check", maxCheck); var state = EnumNumber(entry, "state", 5);
                Require(!history || check != 21);
                Require(states.TryAdd(check, state)); Text(entry, "scopeDetail");
                var implemented = check <= 11 || check >= 17 || accounting && check is 12 or 13;
                var required = implemented || (check is 12 or 13 && request.RequireWholeVolume) ||
                    (check == 14 && (request.RequireWholeVolume || request.RequirePayloadContentHashes));
                Require(Bool(entry, "implemented") == implemented && Bool(entry, "required") == required);
                if (check == 14 || check == 12 && !accounting || (check == 13 && (history || version == 1))) Require(state == 1);
                if (check == 13 && !accounting && !history && version >= 2) Require(state == 1 || (outcome == 3 && state == 4));
                if (check == 22) Require((state == 2) == (outcome == 1));
                if (check is 15 or 16) Require(state == 4);
                if (outcome == 1 && required) Require(state == 2);
                Require(!required || state != 5);
            }
            var findings = root.GetProperty("findings"); Require(findings.ValueKind == JsonValueKind.Array);
            Require((ulong)findings.GetArrayLength() <= Number(scope, "maxRecords"));
            Require(outcome == 1 ? findings.GetArrayLength() == 0 : findings.GetArrayLength() > 0);
            var findingChecks = new HashSet<int>();
            foreach (var finding in findings.EnumerateArray())
            {
                Object(finding, "code severity check volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
                var code = EnumNumber(finding, "code", accounting ? 27 : history || observation ? 25 : version == 1 ? 22 : 24); var severity = EnumNumber(finding, "severity", 3);
                var check = EnumNumber(finding, "check", maxCheck);
                Require(!history || check != 21);
                findingChecks.Add(check);
                if (code is 23 or 24) Require(check == 19);
                if (code == 25) Require(check == 7);
                if (code == 17 && (history || version >= 2)) Require(check == 13);
                if (code == 26) Require(accounting && check == 12);
                if (code == 27) Require(accounting && check == 13);
                var refused = code is 1 or 2 or 8 or 17 or 19 or 20;
                var expectedState = refused ? 4 : code is 3 or 4 or 5 or 18 ? 1 : 3;
                Require((outcome == 3) == refused && states[check] == expectedState && (refused ? severity == 2 : severity == 3));
                foreach (var key in "volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes".Split(' '))
                    if (finding.GetProperty(key).ValueKind != JsonValueKind.Null) Number(finding, key);
                Text(finding, "detail");
            }
            foreach (var (check, state) in states)
                if (state == 3 || (state == 4 && check is not (15 or 16))) Require(findingChecks.Contains(check));
            if (history || version >= 2) ValidateCensus(root, scope, outcome);
            if (history) ValidateHistory(root, scope, outcome);
            if (accounting) ValidateRetainedOwnership(root, scope, outcome);
            var payload = observation ? CurrentPayloadInventory.Parse(root.GetProperty("payloadInventory"), outcome,
                states[21], selected.ValueKind == JsonValueKind.Object, findings, retainedAccounting: accounting) : null;
            if (!history)
            {
                var repair = root.GetProperty("repair"); Object(repair, "planId refusal nextActionableCandidate");
                Require(EnumNumber(repair, "refusal", 2) == (outcome == 1 ? 1 : 2) && repair.GetProperty("nextActionableCandidate").ValueKind == JsonValueKind.Null);
                Require(Text(repair, "planId") == BuildPlanId(root));
            }
            return new(exitCode, (ApfsVerificationOutcome)outcome, root.Clone(), payload);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or KeyNotFoundException)
        { throw new InvalidDataException("Native observer returned invalid or mismatched verification output.", ex); }
    }

    private static void ValidateCensus(JsonElement root, JsonElement scope, int outcome)
    {
        var census = root.GetProperty("allocationCensus");
        // Publish observations only after all covered checks succeed.
        if (outcome != 1) { Require(census.ValueKind == JsonValueKind.Null); return; }
        Object(census, "blockSizeBytes containerBlockCount currentMetadataBlocks currentPayloadBlocks unattributedMainBlocks unattributedInternalBlocks unattributedMainRanges unattributedInternalRanges");
        var blockSize = Number(census, "blockSizeBytes", false);
        Require(blockSize is >= 4096 and <= 65536 && (blockSize & (blockSize - 1)) == 0);
        var capacity = Number(census, "containerBlockCount", false);
        Require(capacity <= Number(scope, "storeSizeBytes", false) / blockSize);
        // No physical unit is inferred from an image size or a 4096-byte default.
        var metadata = Number(census, "currentMetadataBlocks", false);
        var payload = Number(census, "currentPayloadBlocks");
        var main = Number(census, "unattributedMainBlocks");
        var internalCount = Number(census, "unattributedInternalBlocks");
        var total = checked(metadata + payload + main + internalCount);
        Require(total <= capacity);
        var mainRanges = census.GetProperty("unattributedMainRanges");
        var internalRanges = census.GetProperty("unattributedInternalRanges");
        Require(mainRanges.ValueKind == JsonValueKind.Array && internalRanges.ValueKind == JsonValueKind.Array);
        Require((ulong)mainRanges.GetArrayLength() + (ulong)internalRanges.GetArrayLength() <= Number(scope, "maxRecords"));
        Require(ValidateRanges(mainRanges, capacity) == main && ValidateRanges(internalRanges, capacity) == internalCount);
        // The internal pool is excluded from main residuals. Both lists use
        // container-relative physical blocks, so cross-list overlaps are invalid.
        RequireDisjoint(mainRanges, internalRanges);
        var selected = root.GetProperty("selected");
        foreach (var key in "checkpointPhysicalBlock volumeSuperblockPhysicalBlock rootPhysicalBlock".Split(' '))
            Require(Number(selected, key, false) < capacity);
    }

    private static ulong ValidateRanges(JsonElement ranges, ulong capacity)
    {
        Require(ranges.ValueKind == JsonValueKind.Array);
        ulong end = 0, sum = 0; var first = true;
        foreach (var range in ranges.EnumerateArray())
        {
            Object(range, "physicalBlock blockCount");
            var start = Number(range, "physicalBlock"); var count = Number(range, "blockCount", false);
            // Adjacent intervals must already have been coalesced by the native verifier.
            Require(start < capacity && count <= capacity - start && (first || start > end));
            end = checked(start + count); sum = checked(sum + count); first = false;
        }
        return sum;
    }

    private static void RequireDisjoint(JsonElement leftRanges, JsonElement rightRanges)
    {
        var left = leftRanges.EnumerateArray(); var right = rightRanges.EnumerateArray();
        var hasLeft = left.MoveNext(); var hasRight = right.MoveNext();
        while (hasLeft && hasRight)
        {
            var a = Number(left.Current, "physicalBlock"); var b = Number(right.Current, "physicalBlock");
            var ae = checked(a + Number(left.Current, "blockCount", false));
            var be = checked(b + Number(right.Current, "blockCount", false));
            Require(ae <= b || be <= a);
            if (ae <= b) hasLeft = left.MoveNext(); else hasRight = right.MoveNext();
        }
    }

    private static void ValidateHistory(JsonElement root, JsonElement scope, int outcome)
    {
        var history = root.GetProperty("requestedHistory");
        if (outcome != 1) { Require(history.ValueKind == JsonValueKind.Null); return; }
        Object(history, "fromXid endpoint chainXids checkpoints");
        Require(Text(history, "fromXid") == Text(scope, "retainedFromXid"));
        var selected = root.GetProperty("selected");
        var endpoint = history.GetProperty("endpoint");
        Object(endpoint, string.Join(' ', selected.EnumerateObject().Select(p => p.Name)));
        foreach (var property in selected.EnumerateObject()) Require(Text(endpoint, property.Name) == property.Value.GetString());

        var chain = history.GetProperty("chainXids"); var checkpoints = history.GetProperty("checkpoints");
        Require(chain.ValueKind == JsonValueKind.Array && checkpoints.ValueKind == JsonValueKind.Array);
        Require(chain.GetArrayLength() >= 2 && checkpoints.GetArrayLength() == chain.GetArrayLength() - 1);
        Require((ulong)chain.GetArrayLength() <= Number(scope, "maxRecords"));
        Require(chain[0].GetString() == Text(history, "fromXid") && chain[chain.GetArrayLength() - 1].GetString() == Text(scope, "checkpointXid"));
        ulong previous = 0;
        foreach (var item in chain.EnumerateArray())
        {
            var xid = item.GetString(); Require(NativeApfsSnapshotReader.IsU64(xid, false));
            var current = ulong.Parse(xid!, CultureInfo.InvariantCulture);
            Require(current > previous); previous = current;
        }
        var capacity = Number(root.GetProperty("allocationCensus"), "containerBlockCount", false);
        ulong rangeCount = 0; var index = 0;
        foreach (var checkpoint in checkpoints.EnumerateArray())
        {
            Object(checkpoint, "checkpointXid metadataRanges payloadRanges");
            Require(Text(checkpoint, "checkpointXid") == chain[index++].GetString());
            var metadata = checkpoint.GetProperty("metadataRanges"); var payload = checkpoint.GetProperty("payloadRanges");
            Require(ValidateRanges(metadata, capacity) > 0); ValidateRanges(payload, capacity);
            RequireDisjoint(metadata, payload);
            rangeCount = checked(rangeCount + (ulong)metadata.GetArrayLength() + (ulong)payload.GetArrayLength());
            Require(rangeCount <= Number(scope, "maxRecords"));
        }
    }

    // Legacy bytes stay unchanged. The v2 binding adds only the observation request/bounds,
    // never observed hashes or authority to repair or reclaim allocations.
    internal static string BuildPlanId(JsonElement root)
    {
        var version = root.GetProperty("version").GetInt32();
        var accounting = version == 4;
        var observation = version == 3 || accounting && root.TryGetProperty("observePayloadContent", out _);
        var id = new StringBuilder(accounting ? "apfs-verifier-refusal-ownership-v1|" :
            observation ? "apfs-verifier-refusal-v2|" : "apfs-verifier-refusal-v1|");
        void Field(string value) => id.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append(':').Append(value);
        void Value(JsonElement obj, string key)
        {
            var value = obj.GetProperty(key);
            Field(value.ValueKind switch { JsonValueKind.String => value.GetString()!, JsonValueKind.True => "1",
                JsonValueKind.False => "0", JsonValueKind.Null => "unknown", _ => value.GetRawText() });
        }
        void Values(JsonElement obj, string keys) { foreach (var key in keys.Split(' ')) Value(obj, key); }
        const string exact = "storeOffsetBytes storeSizeBytes containerUuid volumeUuid volumeOid checkpointXid";
        Value(root.GetProperty("source"), "identity"); Values(root.GetProperty("requestedScope"), exact);
        var selected = root.GetProperty("selected"); Field(selected.ValueKind == JsonValueKind.Null ? "0" : "1");
        if (selected.ValueKind != JsonValueKind.Null) Values(selected, exact + " checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
        Values(root.GetProperty("requestedScope"), "maxReads maxReadBytes maxRecords maxRecordBytes requireWholeVolume requirePayloadContentHashes");
        if (accounting) Value(root.GetProperty("requestedScope"), "accountRetainedOwnership");
        if (observation)
        {
            Value(root, "observePayloadContent");
            Values(root.GetProperty("requestedScope"), "maxPayloadLogicalBytes maxPayloadEntries");
        }
        Value(root, "outcome"); Value(root.GetProperty("repair"), "refusal");
        var findings = root.GetProperty("findings"); Field(findings.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var finding in findings.EnumerateArray()) Values(finding, "check code severity volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
        var coverage = root.GetProperty("coverage"); Field(coverage.GetArrayLength().ToString(CultureInfo.InvariantCulture));
        foreach (var entry in coverage.EnumerateArray()) Values(entry, "check implemented required state");
        return id.ToString();
    }
    private static void Exact(JsonElement obj, ApfsImageVerificationRequest request)
    {
        Require(Text(obj, "containerUuid") == request.ContainerId[15..] && Text(obj, "volumeUuid") == request.VolumeUuid &&
            Text(obj, "volumeOid") == request.VolumeOid && Text(obj, "checkpointXid") == request.CheckpointXid &&
            Text(obj, "storeOffsetBytes") == request.StoreOffsetBytes && Text(obj, "storeSizeBytes") == request.StoreSizeBytes);
        Require(IsHex(Text(obj, "containerUuid")) && IsHex(Text(obj, "volumeUuid")));
        Number(obj, "volumeOid", false); Number(obj, "checkpointXid", false); Number(obj, "storeOffsetBytes"); Number(obj, "storeSizeBytes", false);
    }
    private static bool IsHex(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigitLower) && value.Any(c => c != '0');
    private static string Text(JsonElement obj, string key)
    { var text = obj.GetProperty(key).GetString(); Require(text is not null); _ = new UTF8Encoding(false, true).GetByteCount(text!); return text!; }
    private static bool Bool(JsonElement obj, string key) => obj.GetProperty(key).GetBoolean();
    private static ulong Number(JsonElement obj, string key, bool zero = true)
    { var text = Text(obj, key); Require(NativeApfsSnapshotReader.IsU64(text, zero)); return ulong.Parse(text, CultureInfo.InvariantCulture); }
    private static int EnumNumber(JsonElement obj, string key, int max)
    { var value = obj.GetProperty(key).GetInt32(); Require(value >= 1 && value <= max); return value; }
    private static void Object(JsonElement obj, string fields)
    {
        Require(obj.ValueKind == JsonValueKind.Object);
        var expected = fields.Split(' ').ToHashSet(StringComparer.Ordinal);
        foreach (var property in obj.EnumerateObject()) Require(expected.Remove(property.Name));
        Require(expected.Count == 0);
    }
    private static void Require(bool condition)
    { if (!condition) throw new InvalidDataException("Native observer returned invalid or mismatched verification output."); }
}
