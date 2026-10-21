using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Core;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageRepairOffer(string PlanId, DateTime ExpiresAtUtc, VerifyScope Scope,
    string RecoveryIdentity, string ObservationContract, string CohortDigest, string ExpectedCount,
    string SourceIdentity, string SourceSha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageRepairReceipt(string PlanId, string State, ImageRepairOffer Binding,
    string JournalPath, string EvidenceDirectory, string? NativeCode = null, int? NativeExitCode = null,
    bool Replayed = false, bool NativePostVerifyComplete = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OriginalAcceptedOperationId = null);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageRepairIntent(ImageRepairOffer Offer, string Nonce, string JournalRoot,
    string JournalPath, string EvidenceDirectory, string State = "offered", string? AcceptedOperationId = null,
    string? AcceptedFingerprint = null, ImageRepairReceipt? Receipt = null, JsonElement? NativeReport = null)
{
    [JsonIgnore] public bool Pending => State is "applying" or "recovery-required";
}

public sealed record ImageRepairInvocation(VerifyScope Scope, string JournalRoot, string JournalPath,
    string EvidenceDirectory, ImageRepairOffer? Approval = null);

public sealed record ImageRepairNativeResult(string Code, int NativeExitCode, string? SourceIdentity,
    string? SourceSha256, string? ExpectedCount, bool Replayed, bool NativePostVerifyComplete, JsonElement Report);

public interface IImageRepairBackend
{
    Task<ImageRepairNativeResult> RunImageRepairAsync(ImageRepairInvocation request, CancellationToken token);
}

// Shared by the service's durable writer and the backend's mount admission.
// This reads our intent envelope only; RCT2 and APFS remain native-owned.
public static class ImageRepairPersistence
{
    public const string Prefix = "managed-image-repair-";
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Frame(int Schema, string Digest, string Payload);

    public static bool Hex(string? value, int length = 64) => value is not null && value.Length == length && value.All(char.IsAsciiHexDigitLower);
    public static bool LocalPath(string? value)
    {
        try { return value is not null && VolumeTopologyProfile.LocalPath(value) &&
            string.Equals(Path.GetFullPath(value), value, StringComparison.OrdinalIgnoreCase); }
        catch (Exception error) when (error is ArgumentException or IOException or NotSupportedException) { return false; }
    }
    public static bool DPath(string? value) => LocalPath(value);
    private static bool Text(string? value, int max = 512) => !string.IsNullOrWhiteSpace(value) && value.Length <= max && !value.Any(char.IsControl);

    public static bool ValidOffer(ImageRepairOffer? offer)
    {
        if (offer is null || !Hex(offer.PlanId) || offer.Scope is not { } scope || !LocalPath(scope.ImagePath) ||
            scope.ContainerId is not { } container || !container.StartsWith("apfs-container:", StringComparison.Ordinal) || !VolumeTopologyProfile.Uuid(container[15..]) ||
            !VolumeTopologyProfile.Uuid(scope.VolumeUuid) || !VolumeTopologyProfile.Number(scope.VolumeObjectId, false) ||
            !VolumeTopologyProfile.Number(scope.CheckpointXid, false) || scope.StoreOffsetBytes != "0" ||
            !VolumeTopologyProfile.Number(scope.StoreSizeBytes, false) || !VolumeTopologyProfile.IsBounded(scope) ||
            offer.ExpiresAtUtc == default || offer.ExpiresAtUtc.Kind != DateTimeKind.Utc || !Text(offer.RecoveryIdentity) ||
            offer.ObservationContract is not { } contract || !contract.StartsWith("selected-v1:", StringComparison.Ordinal) || !Hex(contract[12..]) ||
            !Hex(offer.CohortDigest) || !VolumeTopologyProfile.Number(offer.ExpectedCount) || !Hex(offer.SourceSha256)) return false;
        const string prefix = "windows-image-v1:";
        var identity = offer.SourceIdentity;
        return identity is not null && identity.StartsWith(prefix, StringComparison.Ordinal) && identity.Length > prefix.Length + 81 &&
            Hex(identity.Substring(prefix.Length, 80), 80) && identity[prefix.Length + 80] == ':' &&
            VolumeTopologyProfile.Number(identity[(prefix.Length + 81)..]) &&
            identity.Substring(prefix.Length + 48, 16) == "0000000000000000" &&
            identity.Substring(prefix.Length + 64, 16) == ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture).ToString("x16", CultureInfo.InvariantCulture);
    }

    public static bool ValidReceipt(ImageRepairReceipt? receipt) => receipt is not null && ValidOffer(receipt.Binding) &&
        receipt.PlanId == receipt.Binding.PlanId && LocalPath(receipt.JournalPath) && LocalPath(receipt.EvidenceDirectory) &&
        receipt.State is "applying" or "recovery-required" or "repaired" or "refused" or "expired" or "consumed" &&
        (receipt.NativeCode is null || receipt.NativeCode is "RepairedAndVerified" or "RepairHealthyNoFinding" or "RepairNeedsConfirmation" or "RepairRefused") &&
        (receipt.NativeExitCode is null or 0 or 3 or 4) &&
        (receipt.OriginalAcceptedOperationId is null || Guid.TryParseExact(receipt.OriginalAcceptedOperationId, "D", out var acceptedId) &&
            acceptedId.ToString("D") == receipt.OriginalAcceptedOperationId) &&
        (!receipt.Replayed || receipt.NativeCode == "RepairedAndVerified") &&
        (receipt.State != "repaired" || receipt.NativeCode == "RepairedAndVerified" && receipt.NativeExitCode == 0 && receipt.NativePostVerifyComplete);

    public static ImageRepairIntent Create(ImageRepairOffer binding, string root, string nonce)
    {
        var lineage = Path.Combine(root, "repair-lineage-" + nonce);
        var record = new ImageRepairIntent(binding with { PlanId = "" }, nonce, root,
            Path.Combine(lineage, "original.rct2"), Path.Combine(lineage, "evidence"));
        record = record with { Offer = record.Offer with { PlanId = Commitment(record) } };
        Validate(record, root);
        return record;
    }

    public static string Commitment(ImageRepairIntent intent) => Hash(JsonSerializer.Serialize(new
    {
        binding = intent.Offer with { PlanId = "" }, intent.Nonce, intent.JournalRoot, intent.JournalPath, intent.EvidenceDirectory,
    }, Json));

    public static void Validate(ImageRepairIntent record, string root)
    {
        var directory = Path.Combine(root, "repair-lineage-" + record.Nonce);
        if (!LocalPath(root) || !ValidOffer(record.Offer) || !Hex(record.Nonce, 32) || record.JournalRoot != root ||
            record.JournalPath != Path.Combine(directory, "original.rct2") || record.EvidenceDirectory != Path.Combine(directory, "evidence") ||
            record.Offer.PlanId != Commitment(record) || record.State is not ("offered" or "applying" or "recovery-required" or "repaired" or "refused" or "expired"))
            throw new InvalidDataException("ImageRepairOriginalBindingInvalid");
        var accepted = record.AcceptedOperationId is not null || record.AcceptedFingerprint is not null;
        if (accepted && (!Guid.TryParseExact(record.AcceptedOperationId, "D", out var id) || id.ToString("D") != record.AcceptedOperationId ||
            record.AcceptedFingerprint is not { } fingerprint || !fingerprint.StartsWith("sha256:", StringComparison.Ordinal) || !Hex(fingerprint[7..])) ||
            record.Pending && !accepted || record.State == "offered" && accepted)
            throw new InvalidDataException("ImageRepairAcceptedLineageInvalid");
        if (record.Receipt is not null && (!ValidReceipt(record.Receipt) || record.Receipt.Binding != record.Offer ||
            record.Receipt.OriginalAcceptedOperationId is not null && record.Receipt.OriginalAcceptedOperationId != record.AcceptedOperationId ||
            record.Receipt.State != record.State || record.Receipt.JournalPath != record.JournalPath || record.Receipt.EvidenceDirectory != record.EvidenceDirectory) ||
            record.State == "repaired" && (record.Receipt is not { NativePostVerifyComplete: true } || record.NativeReport is null))
            throw new InvalidDataException("ImageRepairReceiptInvalid");
    }

    public static byte[] Encode(ImageRepairIntent intent)
    {
        Validate(intent, intent.JournalRoot);
        var payload = JsonSerializer.Serialize(intent, Json);
        return JsonSerializer.SerializeToUtf8Bytes(new Frame(1, Hash(payload), payload), Json);
    }

    public static ImageRepairIntent Read(string path, string root)
        => ReadCore(path, root, null);

    public static ImageRepairIntent ReadVerified(string path, string root, byte[] expectedBytes)
    {
        ArgumentNullException.ThrowIfNull(expectedBytes);
        return ReadCore(path, root, expectedBytes);
    }

    private static ImageRepairIntent ReadCore(string path, string root, byte[]? expectedBytes)
    {
        var roots = new List<SafeFileHandle>();
        try
        {
            if (!LocalPath(root) || !LocalPath(path) || !string.Equals(Path.GetDirectoryName(path), root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("ImageRepairIntentRootInvalid");
            // Hold the whole directory chain against rename/deletion, then open
            // the file itself without following a final reparse point.
            PinDirectories(root, roots);
            using var handle = OpenPinned(path, directory: false);
            using var input = new FileStream(handle, FileAccess.Read);
            const int maximum = 256 * 1024;
            if (input.Length > maximum)
                throw new InvalidDataException("ImageRepairIntentFileInvalid");
            var bounded = new byte[maximum + 1];
            var count = 0;
            while (count < bounded.Length)
            {
                var read = input.Read(bounded, count, bounded.Length - count);
                if (read == 0) break;
                count += read;
            }
            if (count > maximum) throw new InvalidDataException("ImageRepairIntentFileInvalid");
            var bytes = bounded.AsSpan(0, count).ToArray();
            if (expectedBytes is not null && !bytes.AsSpan().SequenceEqual(expectedBytes))
                throw new IOException("ImageRepairIntentDurableReadbackFailed");
            RequireUniqueFields(bytes);
            var frame = JsonSerializer.Deserialize<Frame>(bytes, Json) ?? throw new InvalidDataException("ImageRepairIntentMissing");
            if (frame.Schema != 1 || frame.Digest != Hash(frame.Payload)) throw new InvalidDataException("ImageRepairIntentCorrupt");
            RequireUniqueFields(Encoding.UTF8.GetBytes(frame.Payload));
            var record = JsonSerializer.Deserialize<ImageRepairIntent>(frame.Payload, Json) ?? throw new InvalidDataException("ImageRepairOriginalMissing");
            Validate(record, root);
            if (!string.Equals(path, PathFor(root, record.Offer.PlanId), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("ImageRepairIntentFilenameChanged");
            return record;
        }
        catch (JsonException error) { throw new InvalidDataException("ImageRepairIntentSchemaInvalid", error); }
        finally { foreach (var lease in roots) lease.Dispose(); }
    }

    public static IReadOnlyList<ImageRepairIntent> ReadAll(string root)
    {
        var files = Directory.EnumerateFileSystemEntries(root, Prefix + "*").Take(1025).ToArray();
        if (files.Length > 1024 || files.Any(p => !p.EndsWith(".json", StringComparison.Ordinal)))
            throw new InvalidDataException("ImageRepairIncompleteIntentPreserved");
        var records = files.Select(p => Read(p, root)).ToArray();
        if (records.Where(r => r.Pending).GroupBy(r => r.Offer.Scope.ImagePath, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            throw new InvalidDataException("ImageRepairConflictingAcceptedLineage");
        return records;
    }

    public static void RequireNoPending(string? root, string? allowedOriginalPlanId = null)
    {
        if (root is null) return;
        if (ReadAll(root).Any(r => r.Pending && r.Offer.PlanId != allowedOriginalPlanId))
            throw new IOException("ImageRepairAcceptedLineageRequiresReconciliation");
    }

    // Native dry planning can leave an empty writer-lease file. Only native
    // parses RCT2; this check establishes absence of any accepted bytes while
    // denying replacement, writes, reparse traversal and directory retargeting.
    public static bool JournalUnaccepted(string path, string root)
    {
        var directory = Path.GetDirectoryName(path);
        if (!LocalPath(root) || !LocalPath(path) || directory is null || Path.GetFileName(path) != "original.rct2" ||
            !string.Equals(Path.GetDirectoryName(directory), root, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(directory).StartsWith("repair-lineage-", StringComparison.Ordinal) ||
            !Hex(Path.GetFileName(directory)[15..], 32)) throw new InvalidDataException("ImageRepairJournalOriginalPathInvalid");
        var leases = new List<SafeFileHandle>();
        try
        {
            PinDirectories(directory, leases);
            try
            {
                using var file = OpenPinned(path, directory: false);
                using var input = new FileStream(file, FileAccess.Read);
                return input.Length == 0;
            }
            catch (IOException error) when (error.InnerException is Win32Exception { NativeErrorCode: 2 }) { return true; }
        }
        finally { foreach (var lease in leases) lease.Dispose(); }
    }

    public static string PathFor(string root, string planId) => Hex(planId)
        ? Path.Combine(root, Prefix + planId + ".json") : throw new InvalidDataException("ImageRepairPlanIdInvalid");
    public static string VolumeId(VerifyScope scope) => $"apfs-vol:{scope.ContainerId[15..]}:{scope.VolumeObjectId}";
    public static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    private static void PinDirectories(string root, List<SafeFileHandle> leases)
    {
        RequireFixedFileSystem(root);
        var directories = new List<string>();
        for (var dir = new DirectoryInfo(root); dir is not null; dir = dir.Parent) directories.Add(dir.FullName);
        foreach (var dir in directories.AsEnumerable().Reverse()) leases.Add(OpenPinned(dir, directory: true));
    }
    public static void RequireFixedFileSystem(string path)
    {
        if (!LocalPath(path) || new DriveInfo(Path.GetPathRoot(path)!).DriveType != DriveType.Fixed)
            throw new IOException("ImageRepairFixedLocalFileSystemRequired");
    }
    private static SafeFileHandle OpenPinned(string path, bool directory)
    {
        var handle = CreateFile(@"\\?\" + path, directory ? 0x80u : 0x80000000u, directory ? 3u : 1u, IntPtr.Zero, 3,
            0x00200000u | (directory ? 0x02000000u : 0x08000000u), IntPtr.Zero);
        if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException("ImageRepairIntentLeaseFailed", new Win32Exception(error)); }
        if (!GetFileInformationByHandle(handle, out var info) ||
            (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 ||
            !directory && info.Links != 1 ||
            ((info.Attributes & (uint)FileAttributes.Directory) != 0) != directory)
        { handle.Dispose(); throw new InvalidDataException("ImageRepairIntentAliasOrKindInvalid"); }
        return handle;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    private static void RequireUniqueFields(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        void Visit(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var fields = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in value.EnumerateObject())
                { if (!fields.Add(p.Name)) throw new InvalidDataException("ImageRepairDuplicateField"); Visit(p.Value); }
            }
            else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Visit(item);
        }
        Visit(document.RootElement);
    }
}
