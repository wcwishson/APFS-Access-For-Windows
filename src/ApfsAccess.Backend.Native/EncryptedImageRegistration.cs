using ApfsAccess.Core;
using ApfsAccess.Cli;
using Microsoft.Win32.SafeHandles;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IEncryptedImageBackend
{
    private sealed record RegisteredImage(EncryptedImageProfile Profile, SafeFileHandle? Lease,
        NativeEncryptedImageWriteLaunch? WriteLease = null);
    private readonly ConcurrentDictionary<string, RegisteredImage> _encryptedImages = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, EncryptedVolumeState> _encryptionStates = new(StringComparer.OrdinalIgnoreCase);
    public async Task RegisterEncryptedImageAsync(EncryptedImageProfile profile, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        if (!profile.IsValid()) throw new InvalidOperationException("Invalid encrypted image selectors.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (_encryptedImages.Count >= 16 || _encryptedImages.Values.Any(r =>
                r.Profile.ContainerUuid == profile.ContainerUuid || r.Profile.SourceId == profile.SourceId ||
                string.Equals(r.Profile.ImagePath,profile.ImagePath,StringComparison.OrdinalIgnoreCase)) ||
                _volumeCache.Values.Any(v => v.VolumeId == profile.VolumeId || TopologyAdmission.SameUuid(v.CatalogContainerUuid,profile.ContainerUuid) ||
                    string.Equals(v.DeviceId,profile.ImagePath,StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Encrypted image identity is already registered or conflicts.");
            if (new DriveInfo(Path.GetPathRoot(profile.ImagePath)!).DriveType != DriveType.Fixed ||
                (File.GetAttributes(profile.ImagePath) & (FileAttributes.Directory|FileAttributes.ReparsePoint|FileAttributes.Device)) != 0)
                throw new InvalidOperationException("A local regular image is required.");
            if (profile.Writable)
            {
                if (!_options.EnableNativeWrite || string.IsNullOrWhiteSpace(_options.ManagementJournalRoot))
                    throw new InvalidOperationException("Explicit encrypted writing requires enabled native writes and durable external recovery storage.");
                var pin = NativeEncryptedImageWriteLaunch.Prepare(profile, token);
                try
                {
                    _ = pin.RecoveryDirectory(_options.ManagementJournalRoot);
                    if (!_encryptedImages.TryAdd(profile.VolumeId, new(profile, null, pin)))
                        throw new InvalidOperationException("Duplicate encrypted image.");
                    _volumeCache[profile.VolumeId] = RegisteredVolume(profile);
                    pin = null!;
                    return;
                }
                finally { pin?.Dispose(); }
            }
            var lease = File.OpenHandle(profile.ImagePath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
            try
            {
                if (ScopedImageIdentity(lease,profile) != profile.SourceId || (ulong)RandomAccess.GetLength(lease) < profile.StoreOffset+profile.StoreSize)
                    throw new InvalidOperationException("Encrypted image member identity or bounds differ.");
                if (!_encryptedImages.TryAdd(profile.VolumeId,new(profile,lease))) throw new InvalidOperationException("Duplicate encrypted image.");
                // Initial display defaults to Locked; the worker commits later state
                // only if registration still owns its command generation.
                _volumeCache[profile.VolumeId] = RegisteredVolume(profile);
                lease = null!;
            }
            finally { lease?.Dispose(); }
        }
        finally { _gate.Release(); }
    }
    private VolumeInfo RegisteredVolume(EncryptedImageProfile p) => new(p.VolumeId,p.ImagePath,"Encrypted image",p.Writable,
        IsEncrypted:true,SupportsExplorerMount:true,SupportsNativeWrite:p.Writable,RecoveryIdentity:p.Contract,CatalogVolumeId:p.VolumeId,
        CatalogContainerUuid:p.ContainerUuid,CatalogVolumeObjectId:p.VolumeObjectId,CatalogDecision:ApfsCapabilityDecision.Locked,
        CatalogReasons:[p.Writable ? "registered-encrypted-image-explicit-writer" : "registered-encrypted-image-read-only"],CatalogAutoMountAllowed:false,CatalogVolumeUuid:p.VolumeUuid,
        RegisteredImage:p,EncryptionState:RegisteredState(p.VolumeId));
    private EncryptedVolumeState RegisteredState(string id)
    {
        var state=_encryptionStates.GetValueOrDefault(id,EncryptedVolumeState.Locked);
        var mounts=_mounts.Values.Where(m=>m.VolumeId==id).Concat(_encryptedWriteSessions.Values.Where(s=>s.VolumeId==id).Select(s=>s.ReadState())).ToArray();
        return state==EncryptedVolumeState.Unlocked && (mounts.Length!=1 || !mounts[0].MountReady || mounts[0].RecoveryActive)
            ? EncryptedVolumeState.Failed : state;
    }
    public void SetEncryptionState(string volumeId, EncryptedVolumeState state)
    {
        if (_encryptedImages.ContainsKey(volumeId)) _encryptionStates[volumeId] = state;
    }
    public async Task<MountResult> UnlockEncryptedImageAsync(MountRequest request, EncryptedImageProfile profile,
        SupervisedCredential credential, CancellationToken token)
    {
        if (profile.Writable) return await UnlockWritableEncryptedImageAsync(request, profile, credential, token).ConfigureAwait(false);
        if (request.AccessMode != MountAccessMode.ReadOnly || request.VolumeId != profile.VolumeId ||
            !_encryptedImages.TryGetValue(request.VolumeId,out var registered) || registered.Profile != profile ||
            registered.Lease is null || ScopedImageIdentity(registered.Lease,profile) != profile.SourceId) throw new InvalidOperationException("Encrypted image identity changed.");
        return await MountCoreAsync(request,token,credential).ConfigureAwait(false);
    }
    private static string ScopedImageIdentity(SafeFileHandle handle,EncryptedImageProfile profile)
        => ImageIdentity(handle)+$":scope:{profile.StoreOffset}:{profile.StoreSize}";
    internal static string ImageIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle,out var i) || (i.Attributes & 0x450) != 0)
            throw new InvalidOperationException("Regular image identity unavailable.");
        return $"windows-file:{i.Serial}:{((ulong)i.IndexHigh<<32)|i.IndexLow}:{((ulong)i.SizeHigh<<32)|i.SizeLow}:{((ulong)i.WriteHigh<<32)|i.WriteLow}";
    }
    [StructLayout(LayoutKind.Sequential)] private struct ImageFileInformation
    {
        public uint Attributes,CreateLow,CreateHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Serial,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle h,out ImageFileInformation info);
}
