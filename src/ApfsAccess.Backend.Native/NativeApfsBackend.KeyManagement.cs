using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IImageKeyManagementBackend, IImageKeyManagementObserver
{
    public async Task<ImageKeyManagementReceipt> ManageImageKeysAsync(ImageKeyManagementRequest request,
        SupervisedCredentialSet credentials, CancellationToken cancellation)
    {
        using (credentials)
        using (AcquireLifecycleOperationLease())
        using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellation, _disposeCts.Token))
        {
            if (!request.IsValid() || !_options.EnableNativeWrite || string.IsNullOrWhiteSpace(_options.ManagementJournalRoot) ||
                string.IsNullOrWhiteSpace(_nativeFsHostPath))
                throw new InvalidOperationException("Native image writing and protected recovery storage are required.");
            await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                await _encryptedWriteGate.WaitAsync(linked.Token).ConfigureAwait(false);
                try
                {
                    var endpoint = request.Expected;
                    bool SameSource(string path, string? container) => string.Equals(path, endpoint.ImagePath, StringComparison.OrdinalIgnoreCase) ||
                        TopologyAdmission.SameUuid(container, endpoint.ContainerUuid);
                    if (_mounts.Values.Any(m => SameSource(m.DeviceId, m.CatalogContainerUuid)) ||
                        _encryptedWriteSessions.Values.Any(s => SameSource(s.ReadState().DeviceId, s.ReadState().CatalogContainerUuid)))
                        throw new IOException("Lock or eject the image and wait for its owner to close before changing keys.");
                    var registrations = _encryptedImages.Where(r => SameSource(r.Value.Profile.ImagePath, r.Value.Profile.ContainerUuid)).ToArray();
                    if (registrations.Any(r => endpoint.Mode != ImageEncryptionMode.SoftwareOneKeyGenerationZero ||
                        (r.Value.Profile with { Writable = true }) != endpoint.ToWritableEncryptedProfile()))
                        throw new IOException("Registered image selectors changed. Refresh the image before changing keys.");
                    // Retire only this exact idle registration. No stale selector or read
                    // handle survives a switch or an interrupted maintenance run.
                    foreach (var row in registrations)
                    {
                        if (!_encryptedImages.TryRemove(row)) throw new IOException("Image registration changed.");
                        row.Value.Lease?.Dispose(); row.Value.WriteLease?.Dispose();
                        _encryptionStates.TryRemove(row.Key, out _); _volumeCache.TryRemove(row.Key, out _);
                    }
                    var tool = Path.Combine(Path.GetDirectoryName(_nativeFsHostPath)!, "ApfsAccess.ApfsImageKeyManagementTool.exe");
                    var backend = new NativeImageKeyManagementBackend(tool, _options.ManagementJournalRoot,
                        Path.Combine(_options.ManagementJournalRoot, "key-operations"));
                    var receipt = await backend.ManageImageKeysAsync(request, credentials, linked.Token).ConfigureAwait(false);
                    if (receipt.After.Mode == ImageEncryptionMode.SoftwareOneKeyGenerationZero)
                    {
                        var profile = receipt.After.ToWritableEncryptedProfile();
                        var pin = NativeEncryptedImageWriteLaunch.Prepare(profile, CancellationToken.None);
                        try
                        {
                            _ = pin.RecoveryDirectory(_options.ManagementJournalRoot);
                            if (!_encryptedImages.TryAdd(profile.VolumeId, new(profile, null, pin)))
                                throw new IOException("The completed image requires a fresh registration.");
                            pin = null!;
                            _encryptionStates[profile.VolumeId] = EncryptedVolumeState.Locked;
                            _volumeCache[profile.VolumeId] = RegisteredVolume(profile);
                        }
                        finally { pin?.Dispose(); }
                    }
                    return receipt;
                }
                finally { _encryptedWriteGate.Release(); }
            }
            finally { _gate.Release(); }
        }
    }
}
