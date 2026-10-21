using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

public sealed record BackupImageWriteSelection(string Image, long SizeBytes, string SourceSha256,
    string FileIdentity, string ContainerUuid, string VolumeUuid, string VolumeOid,
    string CheckpointXid, int SnapshotCount, string RecoveryIdentity, string JournalRoot,
    string? PhysicalBinding = null, string? PhysicalSourceIdentity = null, ulong StoreOffsetBytes = 0);

// Observation selects an exact source. Only the native complete backup graph
// admission under the exclusive writer lease grants write authority.
public sealed partial class NativeBackupImageWriteLaunch : IDisposable
{
    private FileStream? source;
    private readonly List<SafeFileHandle> pins = [];
    private bool disposed, released;
    public BackupImageWriteSelection Selection { get; private set; } = null!;
    private NativeBackupImageWriteLaunch() { }

    public static NativeBackupImageWriteLaunch Prepare(string image, string containerId,
        string volumeOid, string journalRoot, CancellationToken token = default)
        => Prepare(image, containerId, volumeOid, journalRoot,
            (path, container, oid, ct) => new NativeApfsSnapshotReader().Read(path, container, oid, ct), token);

    internal static NativeBackupImageWriteLaunch Prepare(string image, string containerId,
        string volumeOid, string journalRoot,
        Func<string, string, string, CancellationToken, JsonElement> read, CancellationToken token = default)
    {
        NativeApfsSnapshotReader.ValidateRequest(image, containerId, volumeOid);
        journalRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(journalRoot);
        if (!Directory.Exists(journalRoot)) throw new ArgumentException("Create the persistent private journal directory first.");
        var owner = new NativeBackupImageWriteLaunch();
        try
        {
            token.ThrowIfCancellationRequested();
            owner.pins.AddRange(NativeSnapshotBrowseLaunch.PinAncestors(image));
            owner.pins.AddRange(NativeSnapshotBrowseLaunch.PinAncestors(Path.Combine(journalRoot, "journal")));
            owner.source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
            NativeApfsSnapshotReader.ValidateIdentity(owner.source.SafeFileHandle, image);
            NativeSnapshotBrowseLaunch.RequireAttributes(owner.source.SafeFileHandle, false);
            var size = owner.source.Length;
            if (size <= 0 || size > 256L * 1024 * 1024 || size % 4096 != 0)
                throw new ArgumentException("The backup writer supports whole regular images up to 256 MiB.");
            var identity = ReadFileIdentity(owner.source.SafeFileHandle, size);
            var hash = Convert.ToHexStringLower(SHA256.HashDataAsync(owner.source, token).GetAwaiter().GetResult());
            var inventory = NativeApfsSnapshotReader.ParseInventory(read(image, containerId, volumeOid, token).GetRawText(),
                image, containerId, volumeOid, size, hash);
            string Text(string key) => inventory.GetProperty(key).GetString()!;
            var count = inventory.GetProperty("snapshots").GetArrayLength();
            if (Text("storeOffsetBytes") != "0" || Text("storeSizeBytes") != size.ToString(CultureInfo.InvariantCulture) || count is < 1 or > 64)
                throw new ArgumentException("The backup writer requires one supported whole-image snapshot graph.");
            var creation = File.GetCreationTimeUtc(image).ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
            var binding = SHA256.HashData(Encoding.UTF8.GetBytes($"backup-image-v1|{identity}|{creation}|{Text("containerUuid")}|{Text("volumeUuid")}|{volumeOid}"));
            var recovery = "apfs-recovery-v1-" + Convert.ToBase64String(binding).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            owner.Selection = new(image, size, hash, identity, Text("containerUuid"), Text("volumeUuid"),
                volumeOid, Text("checkpointXid"), count, recovery, journalRoot);
            NativeApfsSnapshotReader.ValidateIdentity(owner.source.SafeFileHandle, image);
            if (ReadFileIdentity(owner.source.SafeFileHandle, size) != identity) throw new IOException("Backup source identity changed.");
            token.ThrowIfCancellationRequested();
            return owner;
        }
        catch { owner.Dispose(); throw; }
    }

    public IReadOnlyList<string> BuildHostArguments(string mount, string status, string lifetime,
        string gate, string token, int parentPid)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var driveRoot = mount.Length == 3 && char.IsAsciiLetter(mount[0]) && mount[1] == ':' && mount[2] == '\\';
        if (!driveRoot) NativeSnapshotBrowseLaunch.ValidateLocalPath(mount);
        foreach (var path in new[] { status, lifetime, gate }) NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
        if (parentPid <= 0 || token.Length is not (32 or 64) || token.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Invalid supervisor authority.");
        var s = Selection;
        if (s.PhysicalBinding is not null) return BuildHeldHostArguments(mount, status, lifetime, gate, token, parentPid);
        return ["--enable-backup-image-writes", "--device", s.Image, "--device-offset", "0",
            "--container-id", s.ContainerUuid, "--volume-oid", s.VolumeOid,
            "--backup-volume-uuid", s.VolumeUuid, "--backup-checkpoint-xid", s.CheckpointXid,
            "--backup-source-sha256", s.SourceSha256, "--backup-file-identity", s.FileIdentity,
            "--backup-journal-root", s.JournalRoot, "--management-journal-directory", s.JournalRoot,
            "--recovery-identity", s.RecoveryIdentity, "--readwrite", "--write-backend", "Native",
            "--write-safety-level", "Strict", "--write-max-dirty-transactions", "1",
            "--write-recovery-policy", "FailClosed", "--write-crash-replay-mode", "ReplayIfSafe",
            "--allow-legacy-scaffold-for-fixtures", "false", "--write-require-canonical-commit", "true",
            "--write-integrity-check-on-mount", "true", "--mount", mount,
            "--parent-pid", parentPid.ToString(CultureInfo.InvariantCulture), "--lifetime-file", lifetime,
            "--startup-gate-file", gate, "--startup-gate-token", token, "--status-file", status];
    }

    // Normal app discovery already owns its canonical recovery namespace. Bind
    // that namespace only after the held source and fresh inventory agree.
    internal void BindDiscoveredSelection(ApfsAccess.Core.VolumeInfo volume)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var expected = volume.BackupImageWrite;
        var selected = Selection;
        if (released || expected is null || !ApfsAccess.Core.BackupImageMountPolicy.HasCandidate(volume) ||
            selected.Image != volume.DeviceId || selected.SizeBytes != (long)expected.StoreSizeBytes ||
            !ApfsAccess.Core.TopologyAdmission.SameUuid(selected.ContainerUuid, expected.ContainerUuid) ||
            !ApfsAccess.Core.TopologyAdmission.SameUuid(selected.VolumeUuid, expected.VolumeUuid) ||
            selected.VolumeOid != expected.VolumeObjectId.ToString(CultureInfo.InvariantCulture) ||
            selected.CheckpointXid != expected.CheckpointXid.ToString(CultureInfo.InvariantCulture))
            throw new IOException("BackupImageAppObservedSourceChanged");
        Selection = selected with { RecoveryIdentity = volume.RecoveryIdentity! };
    }

    public void ReleaseForExclusiveStart()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (released) throw new InvalidOperationException("The source handoff is one-shot.");
        source?.Dispose(); source = null; released = true;
    }

    public bool MatchesReadyStatus(JsonElement status, int hostPid)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        try
        {
            static bool Unique(JsonElement value) => value.ValueKind == JsonValueKind.Object &&
                value.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() == value.EnumerateObject().Count();
            if (!Unique(status)) return false;
            if (Selection.PhysicalBinding is not null) return MatchesHeldReadyStatus(status, hostPid);
            var b = status.GetProperty("backupImageWriter"); var s = Selection;
            if (!Unique(b) || status.GetProperty("walAcceptedSequence").GetUInt64() != status.GetProperty("walCleanupSequence").GetUInt64() ||
                status.GetProperty("walAcceptedSequence").GetUInt64() != status.GetProperty("walApfsDurableSequence").GetUInt64()) return false;
            return released && hostPid > 0 && status.GetProperty("hostPid").GetInt32() == hostPid &&
                status.GetProperty("mountReady").GetBoolean() && b.GetProperty("nativeWriteEnabled").GetBoolean() &&
                !b.GetProperty("writeDegraded").GetBoolean() && !status.GetProperty("recoveryActive").GetBoolean() &&
                status.GetProperty("writeBackend").GetString() == "Native" &&
                b.GetProperty("profile").GetString() == "bounded-backup-image-v1" && b.GetProperty("roleRaw").GetInt32() == 384 &&
                b.GetProperty("volumeOid").GetUInt64().ToString(CultureInfo.InvariantCulture) == s.VolumeOid &&
                b.GetProperty("volumeUuid").GetString() == s.VolumeUuid &&
                b.GetProperty("admittedCheckpointXid").GetUInt64().ToString(CultureInfo.InvariantCulture) == s.CheckpointXid &&
                b.GetProperty("sourceSha256").GetString() == s.SourceSha256 && b.GetProperty("fileIdentity").GetString() == s.FileIdentity;
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException) { return false; }
    }

    public uint ExpectedVolumeSerial
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            uint hash = 2166136261;
            foreach (var c in Selection.RecoveryIdentity) {
                hash = unchecked((hash ^ (c & 255u)) * 16777619);
                hash = unchecked((hash ^ ((uint)c >> 8)) * 16777619);
            }
            return hash == 0 ? 1 : hash;
        }
    }

    private static string ReadFileIdentity(SafeFileHandle handle, long size)
    {
        if (!GetFileInformationByHandleEx(handle, 18, out var id, 24)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return id.Volume.ToString("x16", CultureInfo.InvariantCulture) + Convert.ToHexStringLower(id.Id) +
            "0000000000000000" + size.ToString("x16", CultureInfo.InvariantCulture);
    }
    public void Dispose()
    {
        source?.Dispose(); source = null; foreach (var pin in pins) pin.Dispose(); pins.Clear(); disposed = true;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdentity { public ulong Volume; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Id; }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out FileIdentity data, uint size);
}
