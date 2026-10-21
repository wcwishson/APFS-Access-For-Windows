using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

internal static class NativeOrdinaryImageOwnership
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    internal sealed record Binding(string ContainerUuid, string VolumeUuid, string Oid, string RecoveryIdentity, string Wal);
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    internal sealed record Record(string Image, string Locator, string JournalRoot, string SpoolRoot, string RecoveryRoot,
        bool FreshCopy, string? CopiedFrom, string? OriginalDigest, IReadOnlyList<Binding> LaunchBindings);
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Frame(int Schema, string Digest, string Payload);

    internal static void RegisterFreshCopy(OrdinaryManagementImageRegistration registration, string root, string spool, string recovery)
    {
        Roots(root, spool, recovery);
        if (!VolumeTopologyProfile.LocalPath(registration.SourceImage) || !VolumeTopologyProfile.LocalPath(registration.DestinationImage) ||
            Same(registration.SourceImage, registration.DestinationImage)) throw new IOException("Fresh ordinary image requires separate exact local paths.");
        if (File.Exists(registration.DestinationImage))
        {
            var existing = Read(root, registration.DestinationImage, "0");
            if (!existing.FreshCopy || !Same(existing.CopiedFrom!, registration.SourceImage) || !Same(existing.SpoolRoot, spool) || !Same(existing.RecoveryRoot, recovery))
                throw new IOException("Existing image has no matching fresh registration provenance.");
            return;
        }
        NativeApfsSnapshotReader.ValidateLocalFile(registration.SourceImage);
        NativeApfsVolumeRename.ValidateJournalRoot(Path.GetDirectoryName(registration.DestinationImage)!);
        using var source = new FileStream(registration.SourceImage, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (source.Length is < 1048576 or > 268435456 || source.Length % 4096 != 0) throw new IOException("Fresh registration requires a whole ordinary image of 1-256 MiB.");
        using var destination = new FileStream(registration.DestinationImage, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536, FileOptions.WriteThrough);
        string digest;
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536]; int read;
            while ((read = source.Read(buffer)) != 0) { destination.Write(buffer, 0, read); hash.AppendData(buffer, 0, read); }
            destination.Flush(true); digest = Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        using var readback = new FileStream(registration.DestinationImage, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (readback.Length != source.Length || Convert.ToHexStringLower(SHA256.HashData(readback)) != digest)
            throw new IOException("Fresh ordinary image flushed copy readback failed.");
        var identity = NativeApfsVolumeManagement.SourceIdentity(destination.SafeFileHandle, registration.DestinationImage, "0");
        Save(new(registration.DestinationImage, identity[..64], root, spool, recovery, true, registration.SourceImage, digest, []));
    }
    internal static Record CaptureLaunch(ProcessStartInfo start, string root, string image, string offset, IReadOnlyList<VolumeInfo> volumes)
    {
        var spool = start.Environment.TryGetValue("APFSACCESS_SPOOL_ROOT", out var configuredSpool) && configuredSpool is not null ? configuredSpool : throw new IOException("Explicit original spool root is required.");
        var recovery = start.Environment.TryGetValue("APFSACCESS_RECOVERY_ROOT", out var configuredRecovery) && configuredRecovery is not null ? configuredRecovery : throw new IOException("Explicit stable recovery root is required.");
        Roots(root, spool, recovery);
        var locator = NativeApfsVolumeManagement.SourceIdentity(image, offset, false)[..64];
        var path = PathFor(root, locator);
        var record = File.Exists(path) ? Read(root, image, offset) : new Record(image, locator, root, spool, recovery, false, null, null, []);
        if (!Same(record.SpoolRoot, spool) || !Same(record.RecoveryRoot, recovery)) throw new IOException("Original ordinary image launch roots changed.");
        var bindings = record.LaunchBindings.ToList();
        foreach (var volume in volumes)
        {
            if (volume.RegisteredImage is not null || !VolumeTopologyProfile.Uuid(volume.CatalogContainerUuid) ||
                !VolumeTopologyProfile.Uuid(volume.CatalogVolumeUuid) || volume.CatalogVolumeObjectId is not > 0 || volume.RecoveryIdentity is null)
                throw new IOException("Original ordinary image launch lacks exact writable catalog identity.");
            var binding = new Binding(volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!, volume.CatalogVolumeObjectId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                volume.RecoveryIdentity, NativeRecoveryStorage.CanonicalWal(spool, volume.RecoveryIdentity));
            var prior = bindings.Where(b => b.ContainerUuid == binding.ContainerUuid && b.Oid == binding.Oid).ToArray();
            if (prior.Length > 1 || prior.Length == 1 && prior[0] != binding) throw new IOException("Original ordinary image launch binding drift.");
            if (prior.Length == 0) bindings.Add(binding);
        }
        if (bindings.Count > 100) throw new IOException("Ordinary image launch history exceeds its census bound.");
        record = record with { LaunchBindings = bindings.ToArray() };
        Save(record);
        start.Environment["APFSACCESS_SPOOL_ROOT"] = spool;
        start.Environment["APFSACCESS_RECOVERY_ROOT"] = recovery;
        return record;
    }
    internal static IReadOnlyList<Binding> RequireCensus(string root, string image, string offset, string spool, string recovery, string container, IReadOnlyList<VolumeTopologyWal> census)
    {
        var record = Read(root, image, offset);
        if (!record.FreshCopy || !Same(record.SpoolRoot, spool) || !Same(record.RecoveryRoot, recovery))
            throw new IOException("OrdinaryImageHistoricalOwnershipUnproved");
        var original = new List<Binding>();
        foreach (var wal in census)
        {
            var bindings = record.LaunchBindings.Where(b => b.ContainerUuid == container && b.Oid == wal.Oid && b.VolumeUuid == wal.VolumeUuid && Same(b.Wal, wal.Path)).ToArray();
            if (bindings.Length != 1 || !File.Exists(wal.Path)) throw new IOException("OrdinaryImageOriginalSiblingWalMissing");
            NativeApfsSnapshotReader.ValidateLocalFile(wal.Path);
            if (!Same(NativeRecoveryStorage.CanonicalWal(record.SpoolRoot, bindings[0].RecoveryIdentity), wal.Path))
                throw new IOException("OrdinaryImageOriginalSiblingWalChanged");
            original.Add(bindings[0]);
        }
        return original;
    }
    internal static Record Read(string root, string image, string offset)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        var locator = NativeApfsVolumeManagement.SourceIdentity(image, offset, false)[..64];
        return ReadBoundRecord(root, image, locator);
    }
    private static Record ReadBoundRecord(string root, string image, string locator)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        var path = PathFor(root, locator);
        if (!File.Exists(path)) throw new IOException("OrdinaryImageOriginalLaunchOwnershipMissing");
        NativeApfsSnapshotReader.ValidateLocalFile(path);
        if (new FileInfo(path).Length > 256 * 1024) throw new IOException("Ordinary image ownership frame exceeds its bound.");
        var frame = JsonSerializer.Deserialize<Frame>(File.ReadAllBytes(path), Json) ?? throw new IOException("Missing original launch ownership.");
        if (frame.Schema != 1 || Hash(frame.Payload) != frame.Digest) throw new IOException("Corrupt original launch ownership.");
        var record = JsonSerializer.Deserialize<Record>(frame.Payload, Json) ?? throw new IOException("Missing original launch ownership.");
        if (record.Locator != locator || !Same(record.Image, image) || !Same(record.JournalRoot, root) || record.LaunchBindings.Count > 100 ||
            record.FreshCopy && (record.OriginalDigest is not { Length: 64 } || !record.OriginalDigest.All(char.IsAsciiHexDigitLower) || !VolumeTopologyProfile.LocalPath(record.CopiedFrom)))
            throw new IOException("Original launch ownership binding changed.");
        Roots(record.JournalRoot, record.SpoolRoot, record.RecoveryRoot);
        return record;
    }

    // Preserve the original file identity without requesting data access that
    // would conflict with FsHost's exclusive writer. Reuse checks this handle,
    // including renamed or delete-pending sources, rather than reopening data.
    internal sealed class RetainedLaunch : IDisposable
    {
        private readonly SafeFileHandle _identityHandle;
        private readonly string _identity;
        private readonly string _offset;
        internal Record Record { get; }

        internal RetainedLaunch(Record record, string offset)
        {
            Record = record;
            _offset = offset;
            _identityHandle = CreateFile(@"\\?\" + Path.GetFullPath(record.Image), 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            try
            {
                if (_identityHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                _identity = NativeApfsVolumeManagement.SourceIdentity(_identityHandle, record.Image, offset, false);
                if (_identity[..64] != record.Locator) throw new IOException("OrdinaryImageLaunchSourceChanged");
            }
            catch { _identityHandle.Dispose(); throw; }
        }

        internal void RequireRegistration(OrdinaryManagementImageRegistration registration, string root, string spool, string recovery)
        {
            Roots(root, spool, recovery);
            if (_offset != "0" || !Record.FreshCopy || !Same(Record.Image, registration.DestinationImage) ||
                !Same(Record.CopiedFrom!, registration.SourceImage) || !Same(Record.JournalRoot, root) ||
                !Same(Record.SpoolRoot, spool) || !Same(Record.RecoveryRoot, recovery))
                throw new IOException("OrdinaryImageRetainedRegistrationChanged");
            RequireBinding();
        }

        internal void RequireBinding()
        {
            if (_identityHandle.IsClosed || !GetFileInformationByHandleEx(_identityHandle, 1, out var standard, (uint)Marshal.SizeOf<StandardInfo>()) ||
                standard.DeletePending || standard.Directory)
                throw new IOException("OrdinaryImageRetainedSourceChanged");
            try
            {
                if (NativeApfsVolumeManagement.SourceIdentity(_identityHandle, Record.Image, _offset, false) != _identity)
                    throw new IOException("OrdinaryImageRetainedSourceChanged");
            }
            catch (ArgumentException error) { throw new IOException("OrdinaryImageRetainedSourceChanged", error); }
            var persisted = ReadBoundRecord(Record.JournalRoot, Record.Image, Record.Locator);
            if (JsonSerializer.Serialize(persisted, Json) != JsonSerializer.Serialize(Record, Json))
                throw new IOException("OrdinaryImageRetainedLaunchBindingChanged");
        }

        public void Dispose() => _identityHandle.Dispose();
    }
    private static void Save(Record record)
    {
        var path = PathFor(record.JournalRoot, record.Locator);
        var payload = JsonSerializer.Serialize(record, Json);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new Frame(1, Hash(payload), payload), Json);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { output.Write(bytes); output.Flush(true); }
        if (!MoveFileEx("\\\\?\\" + Path.GetFullPath(temporary), "\\\\?\\" + Path.GetFullPath(path), 9)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes)) throw new IOException("Original launch ownership durable readback failed.");
    }
    private static void Roots(params string[] roots) { foreach (var root in roots) NativeApfsVolumeManagement.ValidateStoreRoot(root); }
    private static string PathFor(string root, string locator) => Path.Combine(root, "ordinary-image-" + locator + ".json");
    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));
    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool MoveFileEx(string source, string destination, uint flags);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [StructLayout(LayoutKind.Sequential)]
    private struct StandardInfo
    {
        public long AllocationSize, EndOfFile;
        public uint Links;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
    }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out StandardInfo info, uint size);
}
