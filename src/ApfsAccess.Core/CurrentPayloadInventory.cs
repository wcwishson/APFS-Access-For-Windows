using System.Text;
using System.Text.Json;

namespace ApfsAccess.Core;

public sealed record CurrentPayloadEntry(string Kind, string InodeOid, string StreamOid, string? NameUtf8,
    string LogicalSizeBytes, string LogicalBytesRead, string ReadOutcome, string? ObservedSha256, string? ExpectedSha256);

/// <summary>Bounded observations of current logical bytes, without an expected-content baseline.</summary>
public sealed record CurrentPayloadInventory(string ScopeKind, string Algorithm, bool EnumerationComplete,
    bool ReadComplete, bool HashesObserved, string ExpectedComparison, string MaxLogicalBytes, string MaxEntries,
    string EntryCount, string LogicalBytesRead, IReadOnlyList<CurrentPayloadEntry> Entries)
{
    public const ulong MaximumLogicalBytes = 256 * 1024 * 1024;
    public const ulong MaximumEntries = 1024;
    private const string EmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public static CurrentPayloadInventory Parse(JsonElement value, int outcome, int observationState,
        bool selected, JsonElement findings, bool retainedAccounting = false)
    {
        VerificationWire.Object(value, "scopeKind algorithm enumerationComplete readComplete hashesObserved expectedComparison maxLogicalBytes maxEntries entryCount logicalBytesRead entries");
        VerificationWire.Require(VerificationWire.Text(value, "scopeKind") == "selected-current-volume" &&
            VerificationWire.Text(value, "algorithm") == "SHA256" &&
            VerificationWire.Text(value, "expectedComparison") == "NotSupplied" &&
            VerificationWire.Number(value, "maxLogicalBytes") == MaximumLogicalBytes &&
            VerificationWire.Number(value, "maxEntries") == MaximumEntries);
        var enumerated = value.GetProperty("enumerationComplete").GetBoolean();
        var read = value.GetProperty("readComplete").GetBoolean();
        var hashed = value.GetProperty("hashesObserved").GetBoolean();
        var count = VerificationWire.Number(value, "entryCount");
        var bytes = VerificationWire.Number(value, "logicalBytesRead");
        var array = value.GetProperty("entries");
        VerificationWire.Require(array.ValueKind == JsonValueKind.Array && count <= MaximumEntries &&
            count == (ulong)array.GetArrayLength() && bytes <= MaximumLogicalBytes && read == hashed &&
            (!enumerated || selected) && (enumerated || count == 0 && bytes == 0 && !read));
        var entries = new List<CurrentPayloadEntry>((int)count);
        var keys = new HashSet<(string, ulong, ulong, string?)>();
        var files = new HashSet<ulong>(); var attributes = new HashSet<(ulong, string)>();
        (string Kind, ulong Inode, ulong Stream, string? Name)? previous = null;
        ulong sizeSum = 0, readSum = 0; var allComplete = true;
        var failureCodes = findings.EnumerateArray().Where(f => f.GetProperty("check").GetInt32() == 21)
            .Select(f => f.GetProperty("code").GetInt32()).ToHashSet();
        foreach (var row in array.EnumerateArray())
        {
            VerificationWire.Object(row, "kind inodeOid streamOid nameUtf8 logicalSizeBytes logicalBytesRead readOutcome observedSha256 expectedSha256");
            var kind = VerificationWire.Text(row, "kind");
            var inode = VerificationWire.Number(row, "inodeOid", false);
            var stream = VerificationWire.Number(row, "streamOid", kind == "xattr");
            VerificationWire.Require(kind is "file-data" or "xattr");
            string? name = null;
            if (kind == "file-data")
                VerificationWire.Require(row.GetProperty("nameUtf8").ValueKind == JsonValueKind.Null && files.Add(inode));
            else
            {
                name = VerificationWire.Text(row, "nameUtf8");
                VerificationWire.Require(name.Length > 0 && !name.Contains('\0') && attributes.Add((inode, name)));
            }
            var key = (kind, inode, stream, name);
            VerificationWire.Require(keys.Add(key) && (previous is null || Compare(previous.Value, key) < 0));
            previous = key;
            var size = VerificationWire.Number(row, "logicalSizeBytes");
            var fed = VerificationWire.Number(row, "logicalBytesRead");
            VerificationWire.Require(size <= MaximumLogicalBytes - sizeSum && fed <= size);
            sizeSum += size; readSum = checked(readSum + fed);
            var status = VerificationWire.Text(row, "readOutcome");
            VerificationWire.Require(status is "Complete" or "NotRead" or "ReadFailure" or "BudgetExceeded" or "Unsupported");
            VerificationWire.Require(row.GetProperty("expectedSha256").ValueKind == JsonValueKind.Null);
            string? digest = null;
            if (status == "Complete")
            {
                digest = VerificationWire.Text(row, "observedSha256", 64);
                VerificationWire.Require(fed == size && digest.Length == 64 && digest.All(char.IsAsciiHexDigitLower) &&
                    (size != 0 || digest == EmptySha256));
            }
            else
            {
                allComplete = false;
                VerificationWire.Require(row.GetProperty("observedSha256").ValueKind == JsonValueKind.Null &&
                    (status is not ("NotRead" or "Unsupported") || fed == 0));
                var code = status == "ReadFailure" ? 3 : status == "BudgetExceeded" ? 4 : status == "Unsupported" ? 8 : 0;
                VerificationWire.Require(code == 0 || failureCodes.Contains(code));
            }
            entries.Add(new(kind, row.GetProperty("inodeOid").GetString()!, row.GetProperty("streamOid").GetString()!, name,
                row.GetProperty("logicalSizeBytes").GetString()!, row.GetProperty("logicalBytesRead").GetString()!, status, digest, null));
        }
        var complete = enumerated && allComplete;
        VerificationWire.Require(readSum == bytes && read == complete && (observationState == 2) == complete &&
            observationState is >= 1 and <= 4 && (outcome != 1 || complete));
        // Broader missing expected/historical coverage may coexist with completed observations.
        // Admission or payload failures cannot publish an apparently completed inventory.
        if (enumerated && outcome != 1)
            foreach (var finding in findings.EnumerateArray())
            {
                var check = finding.GetProperty("check").GetInt32();
                var code = finding.GetProperty("code").GetInt32();
                // A v4 caller has separately validated current graph coverage.
                // An older checkpoint or orphan fault does not erase completed
                // current-byte observations. Legacy callers keep their rules.
                var separateAccountingFailure = retainedAccounting && outcome == 2 &&
                    (code == 26 && check == 12 || code == 27 && check == 13 ||
                        code is 3 or 4 or 5 or 6 or 7 && check is 12 or 13);
                VerificationWire.Require(check == 21 && !complete ||
                    code == 18 && check is 12 or 13 or 14 || separateAccountingFailure);
            }
        return new("selected-current-volume", "SHA256", enumerated, read, hashed, "NotSupplied",
            value.GetProperty("maxLogicalBytes").GetString()!, value.GetProperty("maxEntries").GetString()!,
            value.GetProperty("entryCount").GetString()!, value.GetProperty("logicalBytesRead").GetString()!, entries.AsReadOnly());
    }

    private static int Compare((string Kind, ulong Inode, ulong Stream, string? Name) a,
        (string Kind, ulong Inode, ulong Stream, string? Name) b)
    {
        var order = string.CompareOrdinal(a.Kind, b.Kind);
        if (order == 0) order = a.Inode.CompareTo(b.Inode);
        if (order == 0) order = a.Stream.CompareTo(b.Stream);
        // Native names are UTF-8 byte strings; UTF-16 ordinal ordering differs for supplementary characters.
        return order == 0 ? Encoding.UTF8.GetBytes(a.Name ?? "").AsSpan().SequenceCompareTo(
            Encoding.UTF8.GetBytes(b.Name ?? "")) : order;
    }
}
