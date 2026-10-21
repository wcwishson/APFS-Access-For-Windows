using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

// This is a pinned request, not evidence that its APFS group/table was accepted.
// Only the native image-derived producer may admit the namespace.
public sealed record SystemDataBrowseSelection(string Image, long SourceSizeBytes, string SourceSha256,
    string ContainerUuid, string GroupUuid, string SystemOid, string DataOid, string CheckpointXid);

public sealed class NativeSystemDataBrowseLaunch : IDisposable
{
    public const long MaximumImageBytes = 512L * 1024 * 1024;
    private FileStream? source;
    private readonly List<SafeFileHandle> ancestors = [];
    private FileIdentity identity;
    public SystemDataBrowseSelection Selection { get; private set; } = null!;
    public static object Capability => new { route = "system-data browse", access = "read-only",
        authority = "canonical-System-table", nativeAdmission = "required", genuineMacCorpus = "unverified",
        unifiedMutations = false, encrypted = false, snapshots = false, partitionlessSingleImage = true,
        maximumImageBytes = MaximumImageBytes, requiresPackagedNativeHost = true, serviceMount = false };

    private NativeSystemDataBrowseLaunch() { }

    public static void ValidateSelection(string image, string containerId, string groupUuid,
        string systemOid, string dataOid, string checkpointXid)
    {
        NativeApfsSnapshotReader.ValidateRequest(image, containerId, systemOid);
        if (string.IsNullOrEmpty(groupUuid) || groupUuid.Length != 32 || groupUuid.All(c => c == '0') ||
            groupUuid.Any(c => c is not (>= 'a' and <= 'f' or >= '0' and <= '9')) ||
            !NativeApfsSnapshotReader.IsU64(dataOid, false) || !NativeApfsSnapshotReader.IsU64(checkpointXid, false) || systemOid == dataOid)
            throw new ArgumentException("Select an exact nonzero lowercase group UUID, distinct volume OIDs and current checkpoint XID.");
        if (image.Length > 4096 || image.Split(['\\', '/']).Length > 256)
            throw new ArgumentException("The local image path exceeds the bounded System/Data profile.");
    }

    public static NativeSystemDataBrowseLaunch Prepare(string image, string containerId, string groupUuid,
        string systemOid, string dataOid, string checkpointXid, CancellationToken token = default)
    {
        ValidateSelection(image, containerId, groupUuid, systemOid, dataOid, checkpointXid);
        var owner = new NativeSystemDataBrowseLaunch();
        try
        {
            token.ThrowIfCancellationRequested();
            for (var directory = new FileInfo(image).Directory; directory is not null; directory = directory.Parent)
            {
                var handle = CreateFileW(directory.FullName, 0x80000000, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
                owner.ancestors.Add(handle);
                var info = Identity(handle);
                if ((info.Attributes & 0x410) != 0x10) throw new IOException("The image's directory chain is not ordinary and pinned.");
            }
            owner.source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
            NativeApfsSnapshotReader.ValidateIdentity(owner.source.SafeFileHandle, image);
            owner.identity = Identity(owner.source.SafeFileHandle);
            if ((owner.identity.Attributes & 0x450) != 0 || owner.source.Length is <= 0 or > MaximumImageBytes)
                throw new ArgumentException("System/Data browse requires a nonempty ordinary image of at most 512 MiB.");
            var hash = Convert.ToHexStringLower(SHA256.HashDataAsync(owner.source, token).GetAwaiter().GetResult());
            owner.Selection = new(image, owner.source.Length, hash, containerId[15..], groupUuid, systemOid, dataOid, checkpointXid);
            owner.RequireSource(); token.ThrowIfCancellationRequested(); return owner;
        }
        catch { owner.Dispose(); throw; }
    }

    public IReadOnlyList<string> BuildHostArguments(string mount, string status, string lifetime,
        string startupGate, string startupToken, int parentPid)
    {
        RequireSource();
        foreach (var item in new[] { mount, status, lifetime, startupGate }) NativeSnapshotBrowseLaunch.ValidateLocalPath(item);
        if (parentPid <= 0 || startupToken.Length != 64 || startupToken.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Invalid supervised System/Data startup authority.");
        return ["--system-data-image", "--device", Selection.Image, "--device-offset", "0",
            "--container-id", Selection.ContainerUuid, "--volume-oid", Selection.SystemOid,
            "--system-data-group", Selection.GroupUuid, "--system-data-data-oid", Selection.DataOid,
            "--system-data-checkpoint-xid", Selection.CheckpointXid, "--readonly", "--write-backend", "Disabled",
            "--mount", mount, "--parent-pid", parentPid.ToString(CultureInfo.InvariantCulture), "--lifetime-file", lifetime,
            "--startup-gate-file", startupGate, "--startup-gate-token", startupToken, "--status-file", status];
    }

    public bool MatchesReadyStatus(JsonElement status, int hostPid)
    {
        RequireSource();
        try
        {
            if (status.ValueKind != JsonValueKind.Object || status.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != status.EnumerateObject().Count()) return false;
            var label = status.GetProperty("volumeLabel").GetString();
            if (label is null || label.Length > 256 || label.Contains('\0')) return false;
            return hostPid > 0 && status.GetProperty("hostPid").GetInt32() == hostPid && status.GetProperty("mountReady").ValueKind == JsonValueKind.True &&
                status.GetProperty("systemDataRoute").GetString() == "ImageTableReadOnly" &&
                status.GetProperty("systemDataAuthority").GetString() == "CanonicalSystemTable" &&
                status.GetProperty("systemDataWritable").ValueKind == JsonValueKind.False &&
                status.GetProperty("systemDataGenuineMacCorpus").GetString() == "Unverified" &&
                status.GetProperty("explicitReadOnly").ValueKind == JsonValueKind.True && status.GetProperty("writeBackend").GetString() == "Disabled" &&
                status.GetProperty("systemDataCheckpointXid").GetString() == Selection.CheckpointXid &&
                status.GetProperty("systemDataSystemOid").GetString() == Selection.SystemOid &&
                status.GetProperty("systemDataDataOid").GetString() == Selection.DataOid &&
                status.GetProperty("systemDataGroup").GetString() == Selection.GroupUuid &&
                status.GetProperty("snapshotContainerId").GetString() == Selection.ContainerUuid &&
                status.GetProperty("systemDataPairs").GetUInt32() is > 0 and <= 1024 &&
                status.GetProperty("walAcceptedSequence").GetUInt64() == 0 && status.GetProperty("walApfsDurableSequence").GetUInt64() == 0 &&
                status.GetProperty("walCleanupSequence").GetUInt64() == 0;
        }
        catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException) { return false; }
    }

    // Existing FsHost serial for zero-offset/no-recovery-identity ordinary image
    // modes; the canonical System label is supplied by the admitted native view.
    public uint ExpectedVolumeSerial(string systemLabel)
    {
        RequireSource();
        if (systemLabel.Length > 256 || systemLabel.Contains('\0')) throw new ArgumentException("Invalid native System label.");
        uint hash = 2166136261;
        foreach (var c in Selection.Image) { hash = unchecked((hash ^ (c & 255u)) * 16777619); hash = unchecked((hash ^ ((uint)c >> 8)) * 16777619); }
        hash = unchecked((hash ^ '|') * 16777619);
        foreach (var c in systemLabel) { hash = unchecked((hash ^ (c & 255u)) * 16777619); hash = unchecked((hash ^ ((uint)c >> 8)) * 16777619); }
        for (var i = 0; i < 8; ++i) hash = unchecked(hash * 16777619);
        return hash == 0 ? 1 : hash;
    }

    public void RequireSource()
    {
        ObjectDisposedException.ThrowIf(source is null, this);
        NativeApfsSnapshotReader.ValidateIdentity(source.SafeFileHandle, Selection.Image);
        if (Identity(source.SafeFileHandle) != identity || source.Length != Selection.SourceSizeBytes)
            throw new IOException("The pinned System/Data image identity changed.");
    }

    public void Dispose()
    {
        source?.Dispose(); source = null;
        foreach (var handle in ancestors) handle.Dispose(); ancestors.Clear();
    }
    private readonly record struct FileIdentity(uint Attributes, ulong Creation, ulong Write, uint Volume, ulong Size, ulong FileId);
    private static FileIdentity Identity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var value)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new(value.Attributes, ((ulong)value.CreateHigh << 32) | value.CreateLow, ((ulong)value.WriteHigh << 32) | value.WriteLow,
            value.Volume, ((ulong)value.SizeHigh << 32) | value.SizeLow, ((ulong)value.IndexHigh << 32) | value.IndexLow);
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
}
