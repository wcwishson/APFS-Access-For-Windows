using System.Text;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

public sealed record ApfsMarkedReferenceViewSpace(string Xid, bool Current, string Name,
    ulong MarkedRegularInodes, ulong WantOnlyRegularInodes, ulong LiteralRecordBytes, ulong FilePayloadBytes,
    ulong SharedWithCurrentBytes, ulong AbsentFromCurrentBytes, ulong SharedWithOtherSnapshotsBytes,
    ulong UniqueInMarkedInventoryBytes);

public sealed record ApfsMarkedReferenceSpaceResult(int NativeExitCode, bool Complete, JsonElement Report)
{
    public IReadOnlyList<ApfsMarkedReferenceViewSpace> PhysicalViews { get; init; } = [];
}

public sealed partial class NativeApfsImageVerifier
{
    public ApfsMarkedReferenceSpaceResult ObserveMarkedReferenceSpace(ApfsSnapshotAttributionRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateSnapshotAttributionRequest(request); cancellationToken.ThrowIfCancellationRequested();
        if (observerPath is null) throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath);
        using var source = File.OpenHandle(request.Image, FileMode.Open, FileAccess.Read, FileShare.Read);
        NativeApfsSnapshotReader.ValidateIdentity(source, request.Image); var identity = ReadIdentity(source);
        string[] arguments = ["--image", request.Image, "--mode", "marked-reference-space",
            "--container-uuid", request.ContainerId[15..], "--volume-uuid", request.VolumeUuid,
            "--volume-oid", request.VolumeOid, "--checkpoint-xid", request.CheckpointXid,
            "--store-offset-bytes", request.StoreOffsetBytes, "--store-size-bytes", request.StoreSizeBytes];
        var wire = runner.Run(observerPath, arguments, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3)) throw new NativeVerificationExitException(wire.ExitCode, wire.StandardError);
        var result = ParseMarkedReferenceSpace(wire.StandardOutput, wire.ExitCode, request, identity, cancellationToken);
        NativeApfsSnapshotReader.ValidateIdentity(source, request.Image);
        if (identity != ReadIdentity(source)) throw new InvalidDataException("Image identity changed during marked reference accounting.");
        cancellationToken.ThrowIfCancellationRequested(); return result;
    }

    internal static ApfsMarkedReferenceSpaceResult ParseMarkedReferenceSpace(string json, int exitCode,
        ApfsSnapshotAttributionRequest request, string identity, CancellationToken token = default)
    {
        try
        {
            token.ThrowIfCancellationRequested(); Require(new UTF8Encoding(false, true).GetByteCount(json) <= MaxReportBytes);
            using var document = JsonDocument.Parse(json); var root = document.RootElement; var complete = Bool(root, "complete");
            Object(root, "format version readOnly complete source scope" + (complete ?
                " allocationUnitBytes namespaceAndDirectory7ReferencesVerified catalogMetadataAndPayloadAllocationVerified hiddenOwnersComplete retainedCheckpointHistoryVerified recordMeaning filePayloadMeaning literalRecordUnion filePayloadUnion views snapshotAllocationChargeBytes applePurgeableBytes reclaimableBytes" : " reason"));
            Require(Text(root, "format") == "apfs-access-marked-reference-space" && root.GetProperty("version").GetInt32() == 1 &&
                Bool(root, "readOnly") && exitCode == (complete ? 0 : 3));
            var source = root.GetProperty("source"); Object(source, "path identity");
            Require(Text(source, "path") == request.Image && Text(source, "identity") == identity);
            var scope = root.GetProperty("scope"); Object(scope, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes");
            Exact(scope, request.ExactScope);
            if (!complete) { var reason = Text(root, "reason"); Require(reason.Length is > 0 and <= 65535 && !reason.Contains('\0')); return new(exitCode, false, root.Clone()); }
            var unit = root.GetProperty("allocationUnitBytes").GetUInt32(); var size = Number(scope, "storeSizeBytes", false);
            Require(unit is >= 4096 and <= 65536 && (unit & (unit - 1)) == 0 && size % unit == 0 && Number(scope, "storeOffsetBytes") % unit == 0 &&
                Bool(root, "namespaceAndDirectory7ReferencesVerified") && Bool(root, "catalogMetadataAndPayloadAllocationVerified") &&
                !Bool(root, "hiddenOwnersComplete") && !Bool(root, "retainedCheckpointHistoryVerified") &&
                Text(root, "recordMeaning") == "literal-is-purgeable-private-stream-file-extent-union" &&
                Text(root, "filePayloadMeaning") == "literal-is-purgeable-file-and-external-attribute-physical-union");
            foreach (var name in new[] { "snapshotAllocationChargeBytes", "applePurgeableBytes", "reclaimableBytes" }) Require(root.GetProperty(name).ValueKind == JsonValueKind.Null);
            var capacity = size / unit; var math = new ProfileSetMath(token); var all = new List<ProfileSpan>();
            ulong Amount(JsonElement parent, string name) => AttributionAmount(parent.GetProperty(name), capacity, unit);
            var views = root.GetProperty("views"); Require(views.ValueKind == JsonValueKind.Array && views.GetArrayLength() is > 0 and <= 1000000);
            ulong previous = 0, literalMax = 0, literalSum = 0; var names = new HashSet<string>(StringComparer.Ordinal); var index = 0;
            var physical = new List<(JsonElement Row, List<ProfileSpan> Ranges)>();
            foreach (var row in views.EnumerateArray())
            {
                math.Tick(); Object(row, "viewXid current name markedRegularInodes wantOnlyRegularInodes literalRecordPayload filePayload filePayloadRanges");
                var current = ++index == views.GetArrayLength(); var xid = Number(row, "viewXid", false); var name = row.GetProperty("name").GetString();
                Require(Bool(row, "current") == current && xid <= Number(scope, "checkpointXid", false) &&
                    (current ? xid == Number(scope, "checkpointXid", false) && name == "" :
                        xid > previous && !string.IsNullOrEmpty(name) && !name.Contains('\0') && Encoding.UTF8.GetByteCount(name) <= 65535 && names.Add(name)));
                previous = xid; var marked = Number(row, "markedRegularInodes"); var wants = Number(row, "wantOnlyRegularInodes");
                Require(marked <= 1000000 && wants <= 1000000 - marked);
                var literal = Amount(row, "literalRecordPayload"); var full = Amount(row, "filePayload");
                Require(literal <= full && (marked > 0 || full == 0));
                var ranges = row.GetProperty("filePayloadRanges"); Require(ranges.ValueKind == JsonValueKind.Array && ranges.GetArrayLength() <= 1000000 - all.Count);
                var spans = new List<ProfileSpan>();
                foreach (var range in ranges.EnumerateArray())
                {
                    math.Tick(); Object(range, "physicalBlock blockCount"); var start = Number(range, "physicalBlock"); var count = Number(range, "blockCount", false);
                    Require(start < capacity && count <= capacity - start && (spans.Count == 0 || start > spans[^1].End)); spans.Add(new(start, checked(start + count)));
                }
                Require(math.Count(spans) == full); all.AddRange(spans);
                physical.Add((row, spans));
                literalMax = Math.Max(literalMax, literal); literalSum += Math.Min(literal, capacity - literalSum);
            }
            var union = math.Count(math.Union(all)); var literalUnion = Amount(root, "literalRecordUnion");
            Require(Amount(root, "filePayloadUnion") == union && literalUnion >= literalMax && literalUnion <= literalSum && literalUnion <= union);
            var measures = new List<ApfsMarkedReferenceViewSpace>(); var live = physical[^1].Ranges;
            for (var i = 0; i < physical.Count; ++i)
            {
                math.Tick(); var (row, ranges) = physical[i]; var current = i + 1 == physical.Count;
                var otherRanges = new List<ProfileSpan>();
                for (var j = 0; j + 1 < physical.Count; ++j)
                {
                    // Empty views also consume work; a large empty inventory
                    // must not bypass the shared bound in a quadratic scan.
                    math.Tick(); if (j == i) continue;
                    math.Tick(physical[j].Ranges.Count); otherRanges.AddRange(physical[j].Ranges);
                }
                var others = math.Union(otherRanges);
                var count = math.Count(ranges);
                var absent = current ? 0 : math.Count(math.Difference(ranges, live));
                var unique = math.Count(math.Difference(ranges, math.Union(others.Concat(current ? [] : live))));
                measures.Add(new(Text(row, "viewXid"), current, Text(row, "name"), Number(row, "markedRegularInodes"),
                    Number(row, "wantOnlyRegularInodes"), checked(Amount(row, "literalRecordPayload") * unit), checked(count * unit),
                    current ? 0 : checked((count - absent) * unit), checked(absent * unit),
                    checked((count - math.Count(math.Difference(ranges, others))) * unit), checked(unique * unit)));
            }
            token.ThrowIfCancellationRequested(); return new(exitCode, true, root.Clone()) { PhysicalViews = measures.AsReadOnly() };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or EncoderFallbackException)
        { throw new InvalidDataException("Invalid marked-reference accounting document.", ex); }
    }
}
