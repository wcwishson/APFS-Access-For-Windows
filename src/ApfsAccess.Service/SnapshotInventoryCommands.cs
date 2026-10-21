using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private static Task<JsonElement> ReadSnapshotInventoryAsync(VerifyScope scope, CancellationToken token)
        => Task.Run(() => new NativeApfsSnapshotReader().Read(scope.ImagePath, scope.ContainerId,
            scope.VolumeObjectId, token), token);

    private async Task<OperationResultPayload> ExecuteSnapshotListAsync(ControlOperationRequestPayload request,
        DateTime requestedAtUtc, DateTime startedAtUtc, CancellationToken token)
    {
        if (request.Target is null || request.SnapshotName is not null || request.SnapshotIdentity is not null)
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.InvalidArguments,
                "invalid", diagnostic: "Snapshot inventory requires an exact volume target and no mutation parameters.");
        var live = await _worker.TryReadLiveSnapshotInventoryAsync(request.Target, token).ConfigureAwait(false);
        if (live is {} liveInventory)
            return BuildResult(request, requestedAtUtc, startedAtUtc, true, ApfsOperationCodes.OperationSucceeded,
                "snapshot-inventory", mountProof: "present", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: "Snapshot inventory from the retained canonical owner.") with { SnapshotInventory = liveInventory };
        var inventory = await _worker.WithOfflineVolumeAsync(request.Target, false, async (scope, ct) =>
        {
            var result = await _snapshotReader(scope, ct).ConfigureAwait(false);
            // The reader validates hash, schema and file lease. Also bind its observation
            // to the admitted volume UUID, checkpoint and store window.
            if (!TopologyAdmission.SameUuid(result.GetProperty("volumeUuid").GetString(), scope.VolumeUuid) ||
                result.GetProperty("containerUuid").GetString() != scope.ContainerId[15..] ||
                result.GetProperty("volumeOid").GetString() != scope.VolumeObjectId ||
                result.GetProperty("checkpointXid").GetString() != scope.CheckpointXid ||
                result.GetProperty("storeOffsetBytes").GetString() != scope.StoreOffsetBytes ||
                result.GetProperty("storeSizeBytes").GetString() != scope.StoreSizeBytes ||
                !string.Equals(result.GetProperty("source").GetProperty("path").GetString(), scope.ImagePath,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Snapshot inventory no longer matches the selected observation. Refresh before acting.");
            return result.Clone();
        }, token).ConfigureAwait(false);
        return BuildResult(request, requestedAtUtc, startedAtUtc, true, ApfsOperationCodes.OperationSucceeded,
            "snapshot-inventory", mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
            diagnostic: "Read-only snapshot inventory from the exact offline image.") with { SnapshotInventory = inventory };
    }
}

public sealed partial class ApfsMountWorker
{
    public Task<JsonElement?> TryReadLiveSnapshotInventoryAsync(ApfsControlTarget target, CancellationToken token)
        => WithMountOperationsPausedAsync<JsonElement?>(async ct =>
        {
            var mounts = await _backend.GetMountStateAsync(ct).ConfigureAwait(false);
            var owners = mounts.Where(m => string.Equals(m.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                TopologyAdmission.SameUuid(m.CatalogContainerUuid, target.ContainerUuid)).ToArray();
            if (owners.Length == 0)
            {
                if (target.DeviceId.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
                    target.DeviceId.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase))
                    throw new OfflineImageOperationException(ApfsOperationCodes.ServiceUnavailable,
                        "SnapshotRuntimeOwnerNotReady: Physical inventory requires its retained owner.");
                return null;
            }
            // Use the admitted source scope while its retained owner is live. Listing must
            // not run an observer against a newly opened image or quiesce that owner.
            var inventory = _admittedDiscovery?.Inventory;
            if (inventory is null || !SelectedControlTarget.Matches(inventory, target))
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "Refresh the selected snapshot identity before listing.");
            var device = inventory.Single(d => string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase));
            var volume = device.Volumes.Single(v => v.VolumeId == target.VolumeId);
            var scope = VerifyScopeDerivation.TryDerive(device, volume);
            var exact = owners.Where(m => SelectedControlTarget.MatchesMount(target, m)).ToArray();
            var retained = exact.Length == 1 ? exact[0].VolumeVerificationScope : null;
            var physical = retained?.SourceKind == "retained-admitted-raw";
            var physicalScopeOk = physical && retained is not null && exact[0].VolumeVerificationSupported &&
                exact[0].AccessMode == MountAccessMode.ReadWrite && !exact[0].RecoveryActive &&
                TopologyAdmission.SameUuid(retained.ContainerUuid, volume.CatalogContainerUuid) &&
                TopologyAdmission.SameUuid(retained.VolumeUuid, volume.CatalogVolumeUuid) &&
                retained.VolumeOid == volume.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if ((physical ? !physicalScopeOk : !scope.Ok || scope.Scope is null || scope.Scope.StoreOffsetBytes != "0") ||
                !CatalogMountPolicy.AllowsOrdinaryMount(volume) || volume.IsEncrypted || volume.RegisteredImage is not null ||
                exact.Length != 1 || !exact[0].SnapshotInventorySupported)
                throw new OfflineImageOperationException(ApfsOperationCodes.ServiceUnavailable,
                    "SnapshotRuntimeOwnerNotReady: The exact retained owner does not support live inventory.");
            var result = await SendSnapshotControlAsync(physical ? retained!.ContainerUuid : scope.Scope!.ContainerId[15..],
                volume.CatalogVolumeObjectId!.Value, SnapshotControlAction.List, physical ? retained!.RequestLines : null, ct).ConfigureAwait(false);
            if (!result.Success || result.Code != "SnapshotInventory" || result.Inventory is null ||
                !(physical ? result.Inventory.MatchesScope(retained!) : result.Inventory.MatchesScope(scope.Scope!)))
                throw new OfflineImageOperationException(ApfsOperationCodes.OperationFailed,
                    $"Live snapshot inventory was not proved: {result.Code}.");
            // Revalidate typed data even for injected backends; only the host supplies
            // the current checkpoint, which may have advanced since discovery.
            return LiveSnapshotInventory.Parse(result.Inventory.ToJson()).ToJson();
        }, token);
}
