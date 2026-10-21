using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

public sealed record SnapshotBrowseSelection(
    string Image, long SourceSizeBytes, string SourceSha256, string ContainerUuid,
    string VolumeUuid, string VolumeOid, string CheckpointXid, string StoreOffsetBytes,
    string StoreSizeBytes, string SnapshotXid, string Name, JsonElement Snapshot);

// Keep this owner alive until the supervisor proves teardown. The immutable
// source binds the observer's complete root identity to the host's XID lookup.
public sealed class NativeSnapshotBrowseLaunch : IDisposable
{
    private readonly List<SafeFileHandle> ancestors = [];
    private FileStream? source;
    public SnapshotBrowseSelection Selection { get; private set; } = null!;

    private NativeSnapshotBrowseLaunch() { }

    public static NativeSnapshotBrowseLaunch Prepare(string image, string containerId,
        string volumeOid, string snapshotXid, CancellationToken token = default)
        => Prepare(image, containerId, volumeOid, snapshotXid,
            (path, container, oid, ct) => new NativeApfsSnapshotReader().Read(path, container, oid, ct), token);

    public static NativeSnapshotBrowseLaunch PrepareByName(string image, string containerId,
        string volumeOid, string snapshotName, CancellationToken token = default)
        => PrepareSelection(image, containerId, volumeOid, null, snapshotName,
            (path, container, oid, ct) => new NativeApfsSnapshotReader().Read(path, container, oid, ct), token);

    internal static NativeSnapshotBrowseLaunch Prepare(string image, string containerId,
        string volumeOid, string snapshotXid,
        Func<string, string, string, CancellationToken, JsonElement> read, CancellationToken token = default)
        => PrepareSelection(image, containerId, volumeOid, snapshotXid, null, read, token);

    private static NativeSnapshotBrowseLaunch PrepareSelection(string image, string containerId,
        string volumeOid, string? snapshotXid, string? snapshotName,
        Func<string, string, string, CancellationToken, JsonElement> read, CancellationToken token)
    {
        if (snapshotName is null && !NativeApfsSnapshotReader.IsU64(snapshotXid, false))
            throw new ArgumentException("Use a canonical nonzero snapshot XID.");
        if (snapshotName is not null && (snapshotName.Length is 0 or > 255 || snapshotName.Any(c => c < 32 || c == 127)))
            throw new ArgumentException("Use an exact snapshot name without control characters.");
        NativeApfsSnapshotReader.ValidateRequest(image, containerId, volumeOid);
        var owner = new NativeSnapshotBrowseLaunch();
        try
        {
            token.ThrowIfCancellationRequested();
            owner.ancestors.AddRange(PinAncestors(image));
            owner.source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
            NativeApfsSnapshotReader.ValidateIdentity(owner.source.SafeFileHandle, image);
            RequireAttributes(owner.source.SafeFileHandle, directory: false);
            var hash = Convert.ToHexStringLower(SHA256.HashDataAsync(owner.source, token).GetAwaiter().GetResult());
            var observed = read(image, containerId, volumeOid, token);
            // Apply the existing strict wire parser even to injected readers.
            var inventory = NativeApfsSnapshotReader.ParseInventory(observed.GetRawText(), image,
                containerId, volumeOid, owner.source.Length, hash);
            var matches = inventory.GetProperty("snapshots").EnumerateArray()
                .Where(item => snapshotName is null ? item.GetProperty("xid").GetString() == snapshotXid :
                    item.GetProperty("name").GetString() == snapshotName).ToArray();
            if (matches.Length != 1) throw new ArgumentException("The exact snapshot is absent or ambiguous.");
            snapshotXid = matches[0].GetProperty("xid").GetString()!;
            string Text(string key) => inventory.GetProperty(key).GetString()!;
            if (ulong.Parse(snapshotXid, CultureInfo.InvariantCulture) > ulong.Parse(Text("checkpointXid"), CultureInfo.InvariantCulture))
                throw new InvalidDataException("Snapshot XID is newer than its observed checkpoint.");
            owner.Selection = new(image, owner.source.Length, hash, Text("containerUuid"), Text("volumeUuid"),
                Text("volumeOid"), Text("checkpointXid"), Text("storeOffsetBytes"), Text("storeSizeBytes"),
                snapshotXid, matches[0].GetProperty("name").GetString()!, matches[0].Clone());
            NativeApfsSnapshotReader.ValidateIdentity(owner.source.SafeFileHandle, image);
            token.ThrowIfCancellationRequested();
            return owner;
        }
        catch { owner.Dispose(); throw; }
    }

    public IReadOnlyList<string> BuildHostArguments(string mount, string status, string lifetime,
        string startupGate, string startupToken, int parentPid)
    {
        ObjectDisposedException.ThrowIf(source is null, this);
        foreach (var path in new[] { mount, status, lifetime, startupGate }) ValidateLocalPath(path);
        if (parentPid <= 0 || startupToken.Length != 64 || startupToken.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Invalid supervised snapshot startup authority.");
        return ["--device", Selection.Image, "--device-offset", Selection.StoreOffsetBytes,
            "--container-id", Selection.ContainerUuid, "--volume-oid", Selection.VolumeOid,
            "--snapshot-xid", Selection.SnapshotXid, "--readonly", "--write-backend", "Disabled",
            "--mount", mount, "--parent-pid", parentPid.ToString(CultureInfo.InvariantCulture),
            "--lifetime-file", lifetime, "--startup-gate-file", startupGate,
            "--startup-gate-token", startupToken, "--status-file", status];
    }

    public bool MatchesReadyStatus(JsonElement status, int hostPid)
    {
        ObjectDisposedException.ThrowIf(source is null, this);
        try
        {
            return hostPid > 0 && status.GetProperty("hostPid").GetInt32() == hostPid &&
                status.GetProperty("mountReady").GetBoolean() && status.GetProperty("immutableSnapshot").GetBoolean() &&
                status.GetProperty("explicitReadOnly").GetBoolean() &&
                status.GetProperty("writeBackend").GetString() == "Disabled" &&
                status.GetProperty("snapshotContainerId").GetString() == Selection.ContainerUuid &&
                status.GetProperty("snapshotVolumeOid").GetUInt64().ToString(CultureInfo.InvariantCulture) == Selection.VolumeOid &&
                status.GetProperty("snapshotXid").GetString() == Selection.SnapshotXid &&
                status.GetProperty("snapshotName").GetString() == Selection.Name;
        }
        catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        { return false; }
    }

    // This is the host's public snapshot serial, not an APFS disk parser.
    public uint ExpectedVolumeSerial
    {
        get
        {
            uint hash = 2166136261;
            foreach (var c in $"apfs-snapshot:{Selection.ContainerUuid}:{Selection.VolumeOid}:{Selection.SnapshotXid}")
            {
                hash = unchecked((hash ^ (c & 255u)) * 16777619);
                hash = unchecked((hash ^ ((uint)c >> 8)) * 16777619);
            }
            return hash == 0 ? 1 : hash;
        }
    }

    public static string ValidateLocalPath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Length < 4 || !char.IsAsciiLetter(path[0]) ||
            path[1] != ':' || path[2] is not ('\\' or '/') || path[2..].Contains(':') || path.Contains('\0') ||
            path[3..].Split(['\\', '/']).Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new ArgumentException("Use an absolute ordinary local path without aliases or streams.");
        var full = Path.GetFullPath(path);
        for (var current = full; current is not null; current = Path.GetDirectoryName(current))
            if ((Directory.Exists(current) || File.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Snapshot session and copy-out paths cannot contain reparse points.");
        return full;
    }

    internal static List<SafeFileHandle> PinAncestors(string image)
    {
        var pins = new List<SafeFileHandle>();
        try
        {
            for (var directory = new FileInfo(image).Directory; directory is not null; directory = directory.Parent)
            {
                var pin = CreateFileW(directory.FullName, 0x80000000, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                if (pin.IsInvalid) { pin.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot pin the image's directories."); }
                pins.Add(pin);
                RequireAttributes(pin, directory: true);
            }
            return pins;
        }
        catch { foreach (var pin in pins) pin.Dispose(); throw; }
    }

    internal static void RequireAttributes(SafeFileHandle handle, bool directory)
    {
        if (!GetFileInformationByHandleEx(handle, 9, out var attributes, 8))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((attributes.Attributes & 0x440) != 0 || ((attributes.Attributes & 0x10) != 0) != directory)
            throw new ArgumentException("The source and its directories must be ordinary local filesystem objects.");
    }

    public void Dispose()
    {
        source?.Dispose(); source = null;
        foreach (var pin in ancestors) pin.Dispose();
        ancestors.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTag { public uint Attributes; public uint ReparseTag; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out AttributeTag data, uint size);
}
