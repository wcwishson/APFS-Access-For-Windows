using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FusionImageMemberSelection(string Path, string Role, string StoreId, ulong StoreOffset, ulong StoreSize);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FusionImageSelection(string ContainerUuid, string FusionUuid, string VolumeUuid,
    ulong VolumeOid, ulong CheckpointXid, FusionImageMemberSelection[] Members);
public sealed record FusionImageSelectedMember(FusionImageMemberSelection Selection, string Identity);

// Captures selectors, never APFS write authority. The native owner must reacquire
// the exact pair and prove allocation, namespace and original-journal ownership.
public sealed class NativeFusionImageLaunch : IDisposable
{
    private readonly List<SafeFileHandle> sources = [];
    private readonly List<SafeFileHandle> ancestors = [];
    private bool released, disposed;
    private readonly FusionImageSelection selection;
    public FusionImageSelection Selection => selection with { Members = [.. selection.Members] };
    public IReadOnlyList<FusionImageSelectedMember> Members { get; private set; } = [];
    private NativeFusionImageLaunch(FusionImageSelection selection) => this.selection = selection;

    public static void ValidateSelection(FusionImageSelection selection)
    {
        static bool Uuid(string? s) => s is { Length: 32 } && s.Any(c => c != '0') && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
        if (!Uuid(selection.ContainerUuid) || !Uuid(selection.FusionUuid) || !Uuid(selection.VolumeUuid) ||
            selection.VolumeOid == 0 || selection.CheckpointXid == 0 || selection.Members is not { Length: 2 })
            throw new ArgumentException("Select one exact Fusion container, volume, checkpoint and two members.");
        foreach (var member in selection.Members)
        {
            if (member is null) throw new ArgumentException("A Fusion member is missing.");
            if (NativeSnapshotBrowseLaunch.ValidateLocalPath(member.Path) != member.Path || member.Path.Length > 4096 || member.Path.Split('\\').Length > 256)
                throw new ArgumentException("Use canonical bounded Fusion member paths.");
            if (member.Role is not ("main" or "tier2") || member.StoreId is not { Length: > 0 and <= 256 } ||
                member.StoreId.Any(c => c is < ' ' or > '~') || member.StoreSize == 0 ||
                member.StoreOffset > long.MaxValue || member.StoreSize > (ulong)long.MaxValue - member.StoreOffset ||
                member.StoreOffset % 4096 != 0 || member.StoreSize % 4096 != 0)
                throw new ArgumentException("Fusion members require exact roles, store IDs and aligned bounded windows.");
        }
        var a = selection.Members[0]; var b = selection.Members[1];
        if (a.Role == b.Role || a.StoreId == b.StoreId || string.Equals(a.Path, b.Path, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Fusion requires distinct members, roles and store IDs.");
    }

    public static NativeFusionImageLaunch Prepare(FusionImageSelection selection, CancellationToken token = default)
    {
        ValidateSelection(selection);
        // Do not retain the caller's mutable member array.
        var owner = new NativeFusionImageLaunch(selection with { Members = [.. selection.Members] });
        try
        {
            var selected = new List<FusionImageSelectedMember>();
            foreach (var member in owner.Selection.Members)
            {
                token.ThrowIfCancellationRequested();
                for (var directory = new FileInfo(member.Path).Directory; directory is not null; directory = directory.Parent)
                {
                    var ancestor = CreateFileW(directory.FullName, 0x80000000, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    if (ancestor.IsInvalid) { ancestor.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
                    owner.ancestors.Add(ancestor);
                    if (!GetFileInformationByHandle(ancestor, out var info) || (info.Attributes & 0x410) != 0x10)
                        throw new IOException("Fusion image ancestors must be ordinary pinned directories.");
                }
                var handle = File.OpenHandle(member.Path, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
                owner.sources.Add(handle);
                var identity = Capture(handle, out var size);
                if (member.StoreOffset + member.StoreSize > size) throw new IOException("Fusion store window exceeds its selected member.");
                selected.Add(new(member, identity));
            }
            if (selected[0].Identity.Split(':').Take(2).SequenceEqual(selected[1].Identity.Split(':').Take(2)))
                throw new IOException("Both Fusion paths name the same file identity.");
            owner.Members = selected.AsReadOnly(); token.ThrowIfCancellationRequested(); return owner;
        }
        catch { owner.Dispose(); throw; }
    }

    public IReadOnlyList<string> BuildHostArguments(string mount, string recovery, string status, string lifetime,
        string gate, string gateToken, int parentPid)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (released) throw new InvalidOperationException("Fusion launch was already handed to the native owner.");
        foreach (var path in new[] { mount, recovery, status, lifetime, gate }) NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
        if (!Directory.Exists(recovery) || parentPid <= 0 || gateToken.Length is not (32 or 64) || gateToken.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("An existing recovery directory and authenticated startup are required.");
        var args = new List<string> { "--fusion-images", "--readwrite", "--write-backend", "Disabled", "--fusion-write-root", recovery,
            "--container-id", Selection.ContainerUuid, "--volume-oid", Number(Selection.VolumeOid),
            "--fusion-uuid", Selection.FusionUuid, "--fusion-volume-uuid", Selection.VolumeUuid,
            "--fusion-checkpoint-xid", Number(Selection.CheckpointXid), "--fusion-role-convention", "linux-apfs-last-byte-low-bit",
            "--mount", mount, "--status-file", status, "--lifetime-file", lifetime,
            "--parent-pid", parentPid.ToString(CultureInfo.InvariantCulture), "--startup-gate-file", gate, "--startup-gate-token", gateToken };
        for (var i = 0; i < 2; ++i)
        {
            var m = Members[i];
            if (Capture(sources[i], out _) != m.Identity) throw new IOException("Fusion member changed before launch.");
            foreach (var field in new[] { ("member", m.Selection.Path), ("identity", m.Identity), ("role", m.Selection.Role),
                ("store-id", m.Selection.StoreId), ("store-offset", Number(m.Selection.StoreOffset)), ("store-size", Number(m.Selection.StoreSize)) })
            { args.Add("--fusion-" + field.Item1 + (i == 0 ? "-a" : "-b")); args.Add(field.Item2); }
        }
        return args;
    }

    // Read leases cannot coexist with the native exclusive writers. The exact
    // FILE_ID_INFO/time/size selectors bridge this handoff; native rejects drift.
    public void ReleaseForNativeOwner()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (released) throw new InvalidOperationException("Fusion pair already released.");
        for (var i = 0; i < 2; ++i) if (Capture(sources[i], out _) != Members[i].Identity) throw new IOException("Fusion member changed during handoff.");
        released = true; foreach (var source in sources) source.Dispose(); sources.Clear();
    }

    public bool MatchesReadyStatus(JsonElement status, int hostPid)
        => MatchesBoundStatus(status, hostPid, terminal: false);

    internal bool MatchesTerminalStatus(JsonElement status, int hostPid)
        => MatchesBoundStatus(status, hostPid, terminal: true);

    private bool MatchesBoundStatus(JsonElement status, int hostPid, bool terminal)
    {
        try
        {
            if (!released || disposed || hostPid <= 0 || status.GetProperty("hostPid").GetInt32() != hostPid ||
                status.GetProperty("mountReady").GetBoolean() == terminal || status.GetProperty("fusionWritable").GetBoolean() == terminal ||
                status.GetProperty("fusionHealth").GetString() != (terminal ? "StoppedReadOnly" : "ReadWrite") || status.GetProperty("fusionMissingMemberMask").GetUInt32() != 0 ||
                status.GetProperty("fusionContainerUuid").GetString() != Selection.ContainerUuid || status.GetProperty("fusionVolumeOid").GetString() != Number(Selection.VolumeOid) ||
                status.GetProperty("fusionCheckpointXid").GetUInt64() < Selection.CheckpointXid) return false;
            var chosen = status.GetProperty("fusionSelection");
            if (chosen.GetProperty("uuid").GetString() != Selection.FusionUuid || chosen.GetProperty("volume-uuid").GetString() != Selection.VolumeUuid ||
                chosen.GetProperty("checkpoint-xid").GetString() != Number(Selection.CheckpointXid) || chosen.GetProperty("role-convention").GetString() != "linux-apfs-last-byte-low-bit") return false;
            var water = status.GetProperty("fusionAcceptedSequence").GetUInt64();
            if (status.GetProperty("fusionDurableSequence").GetUInt64() != water || status.GetProperty("fusionCleanupSequence").GetUInt64() != water) return false;
            var members = status.GetProperty("fusionMembers"); if (members.GetArrayLength() != 2) return false;
            for (var i = 0; i < 2; ++i)
            {
                var m = Members[i]; var actual = members[m.Selection.Role == "main" ? 0 : 1];
                if (actual.GetProperty("member").GetString() != m.Selection.Path || actual.GetProperty("identity").GetString() != m.Identity ||
                    actual.GetProperty("role").GetString() != m.Selection.Role || actual.GetProperty("store-id").GetString() != m.Selection.StoreId ||
                    actual.GetProperty("store-offset").GetString() != Number(m.Selection.StoreOffset) || actual.GetProperty("store-size").GetString() != Number(m.Selection.StoreSize) ||
                    actual.GetProperty("state").GetString() != (terminal ? "ReleasedOrNotAdmitted" : "HeldExclusive")) return false;
            }
            return true;
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException) { return false; }
    }

    public static uint ExpectedVolumeSerial(string label)
    {
        uint hash = unchecked((2166136261u ^ '|') * 16777619);
        foreach (var c in label) { hash = unchecked((hash ^ (c & 255u)) * 16777619); hash = unchecked((hash ^ ((uint)c >> 8)) * 16777619); }
        for (var i = 0; i < 8; ++i) hash = unchecked(hash * 16777619);
        return hash == 0 ? 1 : hash;
    }
    private static string Number(ulong value) => value.ToString(CultureInfo.InvariantCulture);
    private static string Capture(SafeFileHandle handle, out ulong size)
    {
        if (!GetFileInformationByHandle(handle, out var info) || (info.Attributes & 0x450) != 0 ||
            !GetFileInformationByHandleEx(handle, 18, out var id, (uint)Marshal.SizeOf<FileIdInfo>())) throw new IOException("Exact Fusion regular-file identity unavailable.");
        size = ((ulong)info.SizeHigh << 32) | info.SizeLow;
        return string.Join(':', Number(id.Volume), Convert.ToHexStringLower(id.Id), Number(size),
            Number(((ulong)info.CreateHigh << 32) | info.CreateLow), Number(((ulong)info.WriteHigh << 32) | info.WriteLow));
    }
    public void Dispose()
    {
        disposed = true; foreach (var h in sources) h.Dispose(); sources.Clear();
        foreach (var h in ancestors) h.Dispose(); ancestors.Clear();
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    { public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [StructLayout(LayoutKind.Sequential)] private struct FileIdInfo
    { public ulong Volume; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Id; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfoNative info);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out FileIdInfo info, uint size);
}
