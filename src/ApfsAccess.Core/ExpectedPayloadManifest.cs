using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Core;

public sealed record ExpectedPayloadScope(string SourceIdentity, string SourceKind, string ContainerUuid,
    string VolumeUuid, string VolumeOid, string CheckpointXid, string StoreOffsetBytes, string StoreSizeBytes)
{
    internal static ExpectedPayloadScope Parse(JsonElement value)
    {
        VerificationWire.Object(value, "sourceIdentity sourceKind containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes");
        var identity = VerificationWire.Text(value, "sourceIdentity", 192);
        var kind = VerificationWire.Text(value, "sourceKind");
        VerificationWire.Require(identity.Length > 0 && identity.All(c => c is >= '!' and <= '~') &&
            kind is "image" or "retained-image" or "retained-admitted-raw");
        VerificationWire.Require(VerificationWire.Uuid(VerificationWire.Text(value, "containerUuid")) &&
            VerificationWire.Uuid(VerificationWire.Text(value, "volumeUuid")));
        VerificationWire.Number(value, "volumeOid", false); VerificationWire.Number(value, "checkpointXid", false);
        var offset = VerificationWire.Number(value, "storeOffsetBytes");
        VerificationWire.Require(VerificationWire.Number(value, "storeSizeBytes", false) <= ulong.MaxValue - offset);
        return new(identity, kind, value.GetProperty("containerUuid").GetString()!, value.GetProperty("volumeUuid").GetString()!,
            value.GetProperty("volumeOid").GetString()!, value.GetProperty("checkpointXid").GetString()!,
            value.GetProperty("storeOffsetBytes").GetString()!, value.GetProperty("storeSizeBytes").GetString()!);
    }
}

public sealed record ExpectedPayloadEntry(string Kind, string InodeOid, string StreamOid, string? NameUtf8,
    string LogicalSizeBytes, string ExpectedSha256);
public sealed record ExpectedPayloadMismatch(string Code, string? Kind = null, string? InodeOid = null,
    string? StreamOid = null, string? NameUtf8 = null, string? ExpectedSizeBytes = null,
    string? ObservedSizeBytes = null, string? ExpectedSha256 = null, string? ObservedSha256 = null);
public sealed record ExpectedPayloadComparison(string Format, int Version, string Outcome,
    bool MatchingProvidedManifest, string ExpectedSource, string Trust, string ManifestSha256,
    ExpectedPayloadScope Scope, ExpectedPayloadScope ObservedScope, string Coverage,
    int ExpectedEntryCount, int ObservedEntryCount, int ComparedEntryCount, int MatchedEntryCount,
    bool CompleteInventoryCoverage, IReadOnlyList<ExpectedPayloadMismatch> Mismatches);

/// <summary>Caller-provided expectations, with no authentication or native verification authority.</summary>
public sealed class ExpectedPayloadManifest
{
    public const int MaximumManifestBytes = 1024 * 1024;
    public const int MaximumNameUtf8Bytes = 4096;
    public const string Coverage = "complete-current-payload-inventory";
    public string ExpectedSource { get; }
    public string ManifestSha256 { get; }
    public ExpectedPayloadScope Scope { get; }
    public IReadOnlyList<ExpectedPayloadEntry> Entries { get; }

    private ExpectedPayloadManifest(string expectedSource, string sha256, ExpectedPayloadScope scope,
        IReadOnlyList<ExpectedPayloadEntry> entries)
    { ExpectedSource = expectedSource; ManifestSha256 = sha256; Scope = scope; Entries = entries; }

    public static ExpectedPayloadManifest Parse(ExpectedPayloadInput input)
    {
        try
        {
            VerificationWire.Require(input.ByteCount <= MaximumManifestBytes);
            using var document = input.ParseDocument(); var root = document.RootElement;
            VerificationWire.Require(Encoding.UTF8.GetByteCount(root.GetRawText()) <= MaximumManifestBytes);
            VerificationWire.Object(root, "format version expectedSource algorithm coverage scope entries");
            VerificationWire.Require(VerificationWire.Text(root, "format") == "apfs-access-expected-payload-manifest" &&
                VerificationWire.Enum(root, "version", 1) == 1 && VerificationWire.Text(root, "algorithm") == "SHA256" &&
                VerificationWire.Text(root, "coverage") == Coverage);
            var source = VerificationWire.Text(root, "expectedSource", 1024);
            VerificationWire.Require(!string.IsNullOrWhiteSpace(source) && !source.Any(char.IsControl));
            var scope = ExpectedPayloadScope.Parse(root.GetProperty("scope"));
            var array = root.GetProperty("entries");
            VerificationWire.Require(array.ValueKind == JsonValueKind.Array && array.GetArrayLength() <= (int)CurrentPayloadInventory.MaximumEntries);
            var entries = new List<ExpectedPayloadEntry>();
            var identities = new HashSet<(string, string, string?)>(); ulong total = 0;
            foreach (var row in array.EnumerateArray())
            {
                VerificationWire.Object(row, "kind inodeOid streamOid nameUtf8 logicalSizeBytes expectedSha256");
                var kind = VerificationWire.Text(row, "kind");
                VerificationWire.Require(kind is "file-data" or "xattr");
                VerificationWire.Number(row, "inodeOid", false); VerificationWire.Number(row, "streamOid", kind == "xattr");
                var inode = row.GetProperty("inodeOid").GetString()!;
                string? name = null;
                if (kind == "file-data") VerificationWire.Require(row.GetProperty("nameUtf8").ValueKind == JsonValueKind.Null);
                else
                {
                    name = VerificationWire.Text(row, "nameUtf8", MaximumNameUtf8Bytes);
                    VerificationWire.Require(name.Length > 0 && !name.Contains('\0'));
                }
                // A second stream for one file inode or one exact attribute name is an ambiguous alias.
                VerificationWire.Require(identities.Add((kind, inode, name)));
                var size = VerificationWire.Number(row, "logicalSizeBytes");
                VerificationWire.Require(size <= CurrentPayloadInventory.MaximumLogicalBytes - total); total += size;
                var digest = VerificationWire.Text(row, "expectedSha256", 64);
                VerificationWire.Require(digest.Length == 64 && digest.All(char.IsAsciiHexDigit));
                entries.Add(new(kind, inode, row.GetProperty("streamOid").GetString()!, name,
                    row.GetProperty("logicalSizeBytes").GetString()!, digest.ToLowerInvariant()));
            }
            entries.Sort((a, b) => CompareKeys(Key(a), Key(b)));
            return new(source, input.Sha256, scope, entries.AsReadOnly());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or KeyNotFoundException)
        { throw new InvalidDataException("Invalid expected payload manifest.", ex); }
    }

    public ExpectedPayloadComparison Compare(LiveVolumeVerificationReport report)
    {
        // Reparse the bound wire report rather than trusting replaceable public record properties.
        var bound = LiveVolumeVerificationReport.Parse(report.Json);
        var s = bound.Scope;
        return Compare(new(s.SourceIdentity, s.SourceKind, s.ContainerUuid, s.VolumeUuid, s.VolumeOid,
            s.CheckpointXid, s.StoreOffsetBytes, s.StoreSizeBytes), bound.PayloadInventory);
    }

    /// <summary>The caller must supply scope and inventory from the same already validated report.</summary>
    public ExpectedPayloadComparison Compare(ExpectedPayloadScope observedScope, CurrentPayloadInventory? inventory)
    {
        var issues = new List<ExpectedPayloadMismatch>(); var compared = 0; var matched = 0; var complete = false;
        if (Scope != observedScope) issues.Add(new("ScopeMismatch"));
        else if (inventory is null) issues.Add(new("PayloadObservationNotSupplied"));
        else if (!inventory.EnumerationComplete || !inventory.ReadComplete || !inventory.HashesObserved)
            issues.Add(new("PayloadInventoryIncomplete"));
        else
        {
            VerificationWire.Require(inventory.Entries.Count <= (int)CurrentPayloadInventory.MaximumEntries);
            // Validate complete typed inventories too; callers cannot promote a partial or forged record.
            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            var wire = JsonSerializer.SerializeToElement(inventory, options);
            using var empty = JsonDocument.Parse("[]");
            inventory = CurrentPayloadInventory.Parse(wire, 1, 2, true, empty.RootElement);
            var observed = inventory.Entries.ToDictionary(e => (e.Kind, e.InodeOid, e.StreamOid, e.NameUtf8));
            foreach (var expected in Entries)
            {
                if (!observed.Remove(Key(expected), out var actual))
                { issues.Add(Issue("ExpectedEntryMissing", expected)); continue; }
                compared++;
                var sameSize = expected.LogicalSizeBytes == actual.LogicalSizeBytes;
                var sameHash = expected.ExpectedSha256 == actual.ObservedSha256;
                if (sameSize && sameHash) matched++;
                else issues.Add(new(sameSize ? "HashMismatch" : sameHash ? "SizeMismatch" : "SizeAndHashMismatch",
                    expected.Kind, expected.InodeOid, expected.StreamOid, expected.NameUtf8,
                    expected.LogicalSizeBytes, actual.LogicalSizeBytes, expected.ExpectedSha256, actual.ObservedSha256));
            }
            foreach (var actual in observed.Values.OrderBy(e => (e.Kind, e.InodeOid, e.StreamOid, e.NameUtf8), KeyComparer.Instance))
                issues.Add(new("UnexpectedObservedEntry", actual.Kind, actual.InodeOid, actual.StreamOid, actual.NameUtf8,
                    ObservedSizeBytes: actual.LogicalSizeBytes, ObservedSha256: actual.ObservedSha256));
            complete = compared == Entries.Count && observed.Count == 0;
        }
        var success = complete && issues.Count == 0;
        var outcome = success ? "MatchingProvidedManifest" : issues.Any(e => e.Code == "ScopeMismatch") ? "Refused" :
            issues.Any(e => e.Code is "PayloadObservationNotSupplied" or "PayloadInventoryIncomplete") ? "Incomplete" : "Mismatch";
        return new("apfs-access-expected-payload-comparison", 1, outcome, success, ExpectedSource,
            "caller-supplied; origin and independence not authenticated", ManifestSha256, Scope, observedScope, Coverage,
            Entries.Count, inventory?.Entries.Count ?? 0, compared, matched, complete, issues.AsReadOnly());
    }

    private static ExpectedPayloadMismatch Issue(string code, ExpectedPayloadEntry entry) =>
        new(code, entry.Kind, entry.InodeOid, entry.StreamOid, entry.NameUtf8, entry.LogicalSizeBytes,
            ExpectedSha256: entry.ExpectedSha256);
    private static (string Kind, string Inode, string Stream, string? Name) Key(ExpectedPayloadEntry entry) =>
        (entry.Kind, entry.InodeOid, entry.StreamOid, entry.NameUtf8);
    private static int CompareKeys((string Kind, string Inode, string Stream, string? Name) a,
        (string Kind, string Inode, string Stream, string? Name) b)
    {
        var order = string.CompareOrdinal(a.Kind, b.Kind);
        if (order == 0) order = ulong.Parse(a.Inode, CultureInfo.InvariantCulture).CompareTo(ulong.Parse(b.Inode, CultureInfo.InvariantCulture));
        if (order == 0) order = ulong.Parse(a.Stream, CultureInfo.InvariantCulture).CompareTo(ulong.Parse(b.Stream, CultureInfo.InvariantCulture));
        return order == 0 ? Encoding.UTF8.GetBytes(a.Name ?? "").AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b.Name ?? "")) : order;
    }
    private sealed class KeyComparer : IComparer<(string, string, string, string?)>
    {
        internal static readonly KeyComparer Instance = new();
        public int Compare((string, string, string, string?) x, (string, string, string, string?) y) => CompareKeys(x, y);
    }
}
