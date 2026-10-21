using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class ApfsMountWorker
{
    private string? _volumeJournalRoot;
    private readonly HashSet<string> _freshVolumePlans = new(StringComparer.Ordinal);
    private IReadOnlyList<string> _volumeManagementReadyImages = [];

    private bool ImageMutationRootReady(string image)
        => !VolumeTopologyProfile.LocalPath(image) || TryInspectManagementRoot();

    private bool TryInspectManagementRoot()
    {
        try
        {
            using var store = OpenVolumeIntentStore();
            if (store.ReadAll().Any(r => r.Pending)) return false;
            ApfsAccess.Backend.Native.NativeManagementJournalAdmission.RequireClearRoot(_volumeJournalRoot, _backend is ApfsAccess.Backend.Native.NativeApfsBackend);
            return true;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException) { return false; }
    }

    private async Task ObserveVolumeManagementAvailabilityAsync(IReadOnlyList<DeviceInventory> inventory, CancellationToken ct)
    {
        var ready = new List<string>();
        if (ConfiguredManagementJournalRoot is not null && _backend is IVolumeTopologyBackend backend)
        {
            var mounts = await _backend.GetMountStateAsync(ct).ConfigureAwait(false);
            foreach (var d in inventory.Where(TopologyAdmission.Validate))
            {
                var v = d.Volumes.FirstOrDefault();
                if (v is null || d.Volumes.Any(v => v.IsEncrypted || v.RegisteredImage is not null || !CatalogMountPolicy.AllowsOrdinaryMount(v)) ||
                    mounts.Any(m => string.Equals(m.DeviceId, d.Device.DeviceId, StringComparison.OrdinalIgnoreCase)) ||
                    HasUnsafeOfflineTeardown(d) || VolumeIntentBlocks(d.Device.DeviceId)) continue;
                var physical = VolumePhysicalBinding.IsDevicePath(v.DeviceId);
                var operation = physical && !ImageResizeFormatEnabled ? "create" : "format";
                var scope = VolumeTopologyProfile.DeriveManagementScope(d, v, operation).Scope;
                if (scope is null || !(VolumeTopologyProfile.LocalPath(scope.ImagePath) && (VolumeTopologyProfile.IsBounded(scope) || ImageResizeFormatEnabled &&
                    ImageManagementMutationsEnabled && VolumeTopologyProfile.IsStreamedImage(scope, "format")) ||
                    PhysicalVolumeManagementEnabled && ImageManagementMutationsEnabled &&
                    (VolumeTopologyProfile.IsPhysicalTopology(scope, "create") || ImageResizeFormatEnabled && VolumeTopologyProfile.IsPhysicalFormat(scope, "format")))) continue;
                try { _ = await backend.ObserveVolumeTopologyAsync(scope, d, operation, ct).ConfigureAwait(false); ready.Add(scope.ImagePath); }
                catch (OperationCanceledException) { throw; }
                catch (Exception e) when (e is IOException or InvalidDataException or ArgumentException or System.Text.Json.JsonException) { }
            }
        }
        _volumeManagementReadyImages = ready;
    }
    internal IVolumeTopologyBackend VolumeTopologyBackend => _backend as IVolumeTopologyBackend ??
        throw new IOException("Volume management keeper is unavailable.");
    internal bool ImageResizeFormatEnabled => _optionsMonitor.CurrentValue.EnableImageResizeFormat;
    internal bool ImageManagementMutationsEnabled => _optionsMonitor.CurrentValue.EnableImageManagementMutations;
    internal bool PhysicalVolumeManagementEnabled => _optionsMonitor.CurrentValue.EnablePhysicalVolumeManagement;
    internal void RequireNativeKeeperAdmission(VerifyScope scope)
    {
        if (_backend is ApfsAccess.Backend.Native.NativeApfsBackend)
            ApfsAccess.Backend.Native.NativeManagementJournalAdmission.RequireImage(ConfiguredManagementJournalRoot, scope.ImagePath, scope.StoreOffsetBytes);
    }

    internal VolumeManagementIntentStore OpenVolumeIntentStore()
    {
        var root = ConfiguredManagementJournalRoot;
        if (_volumeJournalRoot is not null && !string.Equals(root, _volumeJournalRoot, StringComparison.OrdinalIgnoreCase))
            throw new IOException("ManagementJournalRoot changed while this service owns volume intents.");
        if (root is null) throw new IOException("ManagementJournalRoot is not configured.");
        _volumeJournalRoot = root;
        return new(root);
    }

    internal void RememberVolumePlan(string token) => _freshVolumePlans.Add(token);

    internal bool VolumeIntentBlocks(string image)
    {
        if (!VolumeTopologyProfile.LocalPath(image) && !VolumePhysicalBinding.IsDevicePath(image)) return false;
        if (ConfiguredManagementJournalRoot is null && _volumeJournalRoot is null) return false;
        try
        {
            using var store = OpenVolumeIntentStore();
            if (store.ReadAll().Any(r => r.Pending && (string.Equals(r.NativeRequest.Image, image, StringComparison.OrdinalIgnoreCase) ||
                r.NativeRequest.PhysicalBindingHex is not null && VolumePhysicalBinding.IsDevicePath(image)))) return true;
            ApfsAccess.Backend.Native.NativeManagementJournalAdmission.RequireClearRoot(_volumeJournalRoot, _backend is ApfsAccess.Backend.Native.NativeApfsBackend);
            return false;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        { return true; }
    }

    private async Task ReconcileVolumeIntentsAsync(CancellationToken token)
    {
        if (ConfiguredManagementJournalRoot is null && _volumeJournalRoot is null) return;
        using var notifications = new DeferredNotifications(this);
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            token.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _shutdownRequested) != 0)
                throw new OfflineImageOperationException(ApfsOperationCodes.ServiceUnavailable, "Service shutdown has started.");
            var invalidated = false;
            try
            {
                using var store = OpenVolumeIntentStore();
                var pending = store.ReadAll().Where(r => r.Pending).ToArray();
                if (pending.Length == 0)
                {
                    // Native journals are proved against the held source at native
                    // startup. Managed pending/corrupt evidence must still invalidate.
                    ApfsAccess.Backend.Native.NativeManagementJournalAdmission.RequireClearRoot(_volumeJournalRoot,
                        _backend is ApfsAccess.Backend.Native.NativeApfsBackend);
                    token.ThrowIfCancellationRequested();
                    return;
                }
                ++_mountOperationGeneration;
                invalidated = true;
                foreach (var intent in pending)
                {
                    if (intent.State == "prepared" && intent.Result is { } plan &&
                        _freshVolumePlans.Contains(plan.ConfirmationToken) && plan.ExpiresUnixSeconds > DateTimeOffset.UtcNow.ToUnixTimeSeconds()) continue;
                    await RequireVolumeSourceQuiescedAsync(intent.NativeRequest, token).ConfigureAwait(false);
                    var mode = intent.State == "prepared" ? VolumeTopologyMode.Cancel : VolumeTopologyMode.Recover;
                    if (mode == VolumeTopologyMode.Cancel) store.Save(intent with { State = "applying" });
                    var result = await VolumeTopologyBackend.RunVolumeTopologyAsync(intent.NativeRequest, mode,
                        mode == VolumeTopologyMode.Cancel ? intent.ConfirmationToken : null, token).ConfigureAwait(false);
                    store.Save(intent with { State = TerminalIntentState(result, mode), Result = result });
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                if (!invalidated) ++_mountOperationGeneration;
                _logger.LogWarning("Volume management recovery remains blocked: {Reason}", e.Message);
            }
        }
        finally { _mountOperationLock.Release(); }
    }

    internal static string TerminalIntentState(VolumeTopologyResult result, VolumeTopologyMode mode) =>
        result.Outcome is "committed" or "cancelled" ? result.Outcome :
        mode is VolumeTopologyMode.Cancel or VolumeTopologyMode.Apply && result.Outcome == "refused" && result.Error is "VolumeManagementConfirmationExpired" or "VolumeImageConfirmationExpired"
            ? "cancelled" : "recovery-required";

    internal async Task RequireVolumeImageQuiescedAsync(string image, string container, CancellationToken ct)
    {
        var mounts = await _backend.GetMountStateAsync(ct).ConfigureAwait(false);
        if (mounts.Any(m => string.Equals(m.DeviceId, image, StringComparison.OrdinalIgnoreCase) ||
            TopologyAdmission.SameUuid(m.CatalogContainerUuid, container)))
            throw new OfflineImageOperationException(ApfsOperationCodes.UnsafeOwnership, "quiesce-required: Unmount every sibling before volume management.");
    }

    internal async Task RequireVolumeSourceQuiescedAsync(VolumeTopologyRequest original, CancellationToken ct)
    {
        await RequireVolumeImageQuiescedAsync(original.Image, original.ContainerUuid, ct).ConfigureAwait(false);
        if (original.PhysicalBindingHex is not null && original.ImageOptions?.NewContainerUuid is { } destination)
            await RequireVolumeImageQuiescedAsync(original.Image, destination, ct).ConfigureAwait(false);
    }

    internal async Task<(DeviceInventory Device, VerifyScope Scope)> ObserveVolumeManagementScopeAsync(
        ApfsControlTarget target, bool create, CancellationToken ct, string? imageOperation = null)
    {
        var inventory = await GetInventoryAsync(ct).ConfigureAwait(false);
        var devices = inventory.Where(d => string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0]))
            throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "Selected image topology is not uniquely admitted.");
        var device = devices[0];
        var members = device.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, target.ContainerUuid)).ToArray();
        if (members.Length == 0 || members.Any(v => v.IsEncrypted || v.RegisteredImage is not null || !CatalogMountPolicy.AllowsOrdinaryMount(v)))
            throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "Only ordinary unencrypted nonempty image containers are supported.");
        if (HasUnsafeOfflineTeardown(device)) throw new OfflineImageOperationException(ApfsOperationCodes.UnsafeOwnership, "Sibling recovery debt remains.");
        var selected = create ? members[0] : members.SingleOrDefault(v => SelectedControlTarget.Matches([device], target) && v.VolumeId == target.VolumeId);
        if (selected is null) throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "Selected volume identity changed.");
        var derived = VolumeTopologyProfile.DeriveManagementScope(device, selected, imageOperation ?? (create ? "create" : "delete"));
        var physical = VolumePhysicalBinding.IsDevicePath(selected.DeviceId);
        var operation = imageOperation ?? (create ? "create" : "delete");
        if (!derived.Ok || derived.Scope is null || !(physical ? PhysicalVolumeManagementEnabled &&
            VolumeTopologyProfile.IsPhysicalManagement(derived.Scope, operation) : VolumeTopologyProfile.IsBounded(derived.Scope) ||
            imageOperation is not null && VolumeTopologyProfile.IsStreamedImage(derived.Scope, imageOperation)))
            throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments,
                "Volume management requires an admitted offline source: create/delete up to 256 MiB, streamed image and held physical operations within their native profiles. " + derived.Detail);
        await RequireVolumeImageQuiescedAsync(derived.Scope.ImagePath, selected.CatalogContainerUuid!, ct).ConfigureAwait(false);
        foreach (var sibling in members)
        {
            if (physical)
            {
                var physicalSibling = VolumeTopologyProfile.DeriveManagementScope(device, sibling, operation);
                if (physicalSibling.Scope is not { } s || s.CheckpointXid != derived.Scope.CheckpointXid ||
                    s.StoreOffsetBytes != derived.Scope.StoreOffsetBytes || s.StoreSizeBytes != derived.Scope.StoreSizeBytes)
                    throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery, "Physical sibling scope changed.");
                // Native observation/prepare/apply verifies every canonical sibling
                // while retaining the qualified physical window and original WALs.
                continue;
            }
            var scope = VerifyScopeDerivation.TryDerive(device, sibling);
            var verified = scope.Scope is null ? null : await VerifyImageAsync(scope.Scope, ct).ConfigureAwait(false);
            if (!scope.Ok || verified is not { Supported: true, Outcome: "Complete", NativeExitCode: 0, FindingCount: 0 })
                throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery, "Complete read-only verification is required for every current sibling.");
        }
        return (device, derived.Scope);
    }
}

public sealed partial class AgentControlCommandExecutor
{
    private async Task<OperationResultPayload> ExecuteVolumeManagementAsync(ControlOperationRequestPayload request,
        DateTime requested, DateTime started, CancellationToken ct)
    {
        if (!VolumeManagementParameters.Valid(request.Command, request.VolumeManagement) || request.Target is null)
            throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "Invalid volume management request.");
        var p = request.VolumeManagement!;
        if ((VolumeManagementParameters.IsPlan(request.Command) || request.Command == ApfsControlCommands.VolumeManagementApply) && !_worker.ImageManagementMutationsEnabled)
            throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "ImageManagementMutationsDisabled: source-held runtime admission and actual original-WAL keeper evidence are required.");
        if (VolumeManagementParameters.IsImageKind(p.Kind) && (VolumeManagementParameters.IsPlan(request.Command) || request.Command == ApfsControlCommands.VolumeManagementApply) && !_worker.ImageResizeFormatEnabled)
            throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "ImageResizeFormatDisabled: repaired native keeper evidence and explicit service opt-in are required.");
        using var store = _worker.OpenVolumeIntentStore();
        var records = store.ReadAll();
        VolumeManagementIntent intent;
        VolumeTopologyResult result;
        if (VolumeManagementParameters.IsPlan(request.Command))
        {
            ApfsAccess.Backend.Native.NativeManagementJournalAdmission.RequireClearRoot(_worker.ConfiguredManagementJournalRoot, true);
            if (records.Any(r => r.Pending && string.Equals(r.NativeRequest.Image, request.Target.DeviceId, StringComparison.OrdinalIgnoreCase)))
                throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery, "An original volume intent must be reconciled before another plan.");
            var (device, scope) = await _worker.ObserveVolumeManagementScopeAsync(request.Target, p.Kind == "create", ct,
                imageOperation: VolumeManagementParameters.IsImageKind(p.Kind) ? p.Kind : null).ConfigureAwait(false);
            var observed = await _worker.VolumeTopologyBackend.ObserveVolumeTopologyAsync(scope, device, p.Kind, ct).ConfigureAwait(false);
            var siblings = device.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, observed.ContainerUuid)).ToArray();
            if (siblings.Length != observed.Volumes.Count || siblings.Any(v => observed.Volumes.Count(w =>
                TopologyAdmission.SameUuid(v.CatalogVolumeUuid, w.VolumeUuid) && v.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture) == w.Oid) != 1) ||
                observed.Image != scope.ImagePath || observed.CheckpointXid != scope.CheckpointXid || observed.OffsetBytes != scope.StoreOffsetBytes)
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "Native identity or complete sibling census changed.");
            var native = new VolumeTopologyRequest(p.Kind, scope.ImagePath, _worker.ConfiguredManagementJournalRoot!,
                scope.StoreOffsetBytes, observed.ContainerUuid, p.Kind == "create" ? Guid.NewGuid().ToString("N") : scope.VolumeUuid,
                p.Kind == "create" ? observed.NextOid : scope.VolumeObjectId, scope.CheckpointXid, observed.SourceIdentity,
                observed.SpoolRoot, observed.Volumes, p.Name,
                p.QuotaBytes is null ? null : VolumeTopologyProfile.Blocks(p.QuotaBytes, observed.BlockBytes),
                p.ReserveBytes is null ? null : VolumeTopologyProfile.Blocks(p.ReserveBytes, observed.BlockBytes), p.CaseSensitive,
                PhysicalBindingHex: observed.PhysicalBindingHex);
            if (VolumeManagementParameters.IsImageKind(p.Kind))
            {
                var physical = observed.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(observed.PhysicalBindingHex);
                if (!(physical is null ? VolumeTopologyProfile.IsStreamedImage(scope, p.Kind) : _worker.PhysicalVolumeManagementEnabled &&
                    VolumeTopologyProfile.IsPhysicalManagement(scope, p.Kind)) || observed.BlockBytes != "4096" || observed.StoreSizeBytes != scope.StoreSizeBytes)
                    throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "Resize/format require whole ordinary 4 KiB images of 1 MiB-1 TiB and native profile proof.");
                var format = p.Kind is "format" or "erase";
                var size = p.TargetBytes ?? observed.StoreSizeBytes;
                if (physical is null ? !VolumeTopologyProfile.IsStreamedImage(scope with { StoreSizeBytes = size }, p.Kind) :
                    !VolumeTopologyProfile.IsPhysicalManagement(scope with { StoreSizeBytes = size },p.Kind) ||
                    (format ? size != observed.StoreSizeBytes :
                        !physical.AllowsResizeTarget(ulong.Parse(size, System.Globalization.CultureInfo.InvariantCulture))))
                    throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "Target capacity is outside the aligned streamed image profile.");
                if (!format && (p.Kind == "grow" ? ulong.Parse(size) <= ulong.Parse(observed.StoreSizeBytes) : ulong.Parse(size) >= ulong.Parse(observed.StoreSizeBytes)))
                    throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "Resize direction must match the observed capacity.");
                var newContainer = format ? Guid.NewGuid().ToString("N") : null;
                var newVolume = format ? Guid.NewGuid().ToString("N") : null;
                var newWal = format ? ApfsAccess.Backend.Native.NativeApfsVolumeImageManagement.DestinationWal(observed.SpoolRoot, newContainer!, physical?.PartitionGuid) : null;
                native = native with { ImageOptions = new(observed.StoreSizeBytes, size, newContainer, newVolume, newWal) };
            }
            intent = new(request, native, "preparing");
            store.Save(intent);
            result = await _worker.VolumeTopologyBackend.RunVolumeTopologyAsync(native, VolumeTopologyMode.Prepare, null, ct).ConfigureAwait(false);
            var journalPresent = result.SourceIdentity == native.SourceIdentity &&
                string.Equals(Path.GetDirectoryName(result.Journal), native.JournalRoot, StringComparison.OrdinalIgnoreCase) && File.Exists(result.Journal);
            intent = intent with { State = result.Outcome == "prepared" ? "prepared" : result.Outcome == "refused" && !journalPresent ? "refused" : "recovery-required", Result = result,
                ConfirmationToken = result.Outcome == "prepared" ? result.ConfirmationToken : null };
            store.Save(intent);
            if (result.Outcome == "prepared") _worker.RememberVolumePlan(result.ConfirmationToken);
        }
        else
        {
            intent = records.SingleOrDefault(r => r.ConfirmationToken == p.Token) ??
                throw new OfflineImageOperationException(ApfsOperationCodes.InvalidArguments, "Unknown or consumed native confirmation token.");
            if (intent.Original.Target != request.Target || intent.Original.VolumeManagement != p with { Token = null })
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "The original target or create options changed.");
            if (!intent.Pending) throw new OfflineImageOperationException(ApfsOperationCodes.OperationConflict, "The volume intent is already terminal.");
            await _worker.RequireVolumeSourceQuiescedAsync(intent.NativeRequest, ct).ConfigureAwait(false);
            var mode = request.Command switch { ApfsControlCommands.VolumeManagementApply => VolumeTopologyMode.Apply,
                ApfsControlCommands.VolumeManagementCancel => VolumeTopologyMode.Cancel, _ => VolumeTopologyMode.Recover };
            if (mode == VolumeTopologyMode.Apply)
            {
                if (records.Any(r => r.Pending && r.Original.OperationId != intent.Original.OperationId))
                    throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery, "Another original volume intent must be reconciled before applying this plan.");
                if (intent.State != "prepared") throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery, "Accepted volume intent requires recovery.");
                var (_, scope) = await _worker.ObserveVolumeManagementScopeAsync(request.Target, p.Kind == "create", ct,
                    imageOperation: intent.NativeRequest.ImageOptions is null ? null : intent.NativeRequest.Operation).ConfigureAwait(false);
                if (scope.CheckpointXid != intent.NativeRequest.PreXid)
                    throw new OfflineImageOperationException(ApfsOperationCodes.OperationConflict, "Checkpoint changed; cancel the original intent before planning again.");
            }
            store.Save(intent with { State = "applying" });
            result = await _worker.VolumeTopologyBackend.RunVolumeTopologyAsync(intent.NativeRequest, mode,
                mode is VolumeTopologyMode.Apply or VolumeTopologyMode.Cancel ? p.Token : null, ct).ConfigureAwait(false);
            intent = intent with { State = ApfsMountWorker.TerminalIntentState(result, mode), Result = result };
            store.Save(intent);
        }
        var prepared = result.Outcome == "prepared";
        var committed = result.Committed;
        var cancelled = result.Outcome == "cancelled";
        var ok = prepared || committed || cancelled && request.Command != ApfsControlCommands.VolumeManagementApply;
        return BuildResult(request, requested, started, ok, ok ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
            "volume-management-" + result.Outcome, mountProof: "absent", ownershipProof: "proven",
            durabilityProof: committed ? "proven" : prepared || cancelled ? "not-applicable" : "not-proven",
            pendingDurability: intent.Pending && !prepared, diagnostic: result.Error) with { VolumeManagementReport = result.Report };
    }
}
