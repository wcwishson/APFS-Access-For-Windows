using System.Globalization;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

// Client batch evidence only. Each Fix still requires the existing service authority.
public sealed class ContainerFixProof
{
    private static readonly JsonSerializerOptions WireOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private sealed record Owner(int Pid, long Created, string MountPoint, MountAccessMode Mode, LiveVolumeVerificationScope? Scope);
    private readonly Owner?[] owners;
    private readonly Owner?[] acknowledgedOwners;
    private readonly VerifyScope?[] imageScopes;
    private readonly MountedVolumeDisplay?[] mounts;
    private string? sourceIdentity;
    public IReadOnlyList<VolumeInfo> Volumes { get; }
    public IReadOnlyList<ApfsControlTarget> Targets { get; }
    private bool Image => VolumeTopologyProfile.LocalPath(Targets[0].DeviceId);

    private ContainerFixProof(VolumeInfo[] volumes, ApfsControlTarget[] targets, Owner?[] owners,
        VerifyScope?[] imageScopes, MountedVolumeDisplay?[] mounts)
    {
        Volumes = Array.AsReadOnly(volumes); Targets = Array.AsReadOnly(targets);
        this.owners = owners; this.imageScopes = imageScopes; this.mounts = mounts;
        acknowledgedOwners = new Owner?[owners.Length];
        sourceIdentity = owners.FirstOrDefault(o => o?.Scope is not null)?.Scope?.SourceIdentity;
    }

    private static InvalidOperationException Changed(string detail) => new($"Container Fix stopped: {detail} Refresh before retrying.");

    public static ContainerFixProof CaptureForContainer(StatusChangedPayload status, string deviceId, string containerUuid)
    {
        RequireBounded(status);
        var devices = status.ConnectedInventory!.Where(d => string.Equals(d.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || devices[0].Topology is null || !TopologyAdmission.Validate(devices[0]))
            throw Changed("The selected source topology is unavailable or ambiguous.");
        return Capture(status, devices[0].Volumes.Where(v => ApfsTopology.MatchesContainerUuid(containerUuid, v.CatalogContainerUuid))
            .Select(v => SelectedControlTarget.Create(devices[0], v)).ToArray());
    }

    public static ContainerFixProof Capture(StatusChangedPayload status, IReadOnlyList<ApfsControlTarget> targets)
    {
        RequireBounded(status);
        if (targets.Count is 0 or > TopologyGraphIndex.Limit || targets.Any(t => t is null) ||
            targets.Select(t => t.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != targets.Count)
            throw Changed("Every original member needs a unique target.");
        var deviceId = targets[0].DeviceId; var containerUuid = targets[0].ContainerUuid;
        if (targets.Any(t => !string.Equals(t.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
            !TopologyAdmission.SameUuid(t.ContainerUuid, containerUuid))) throw Changed("Select one original source and container.");
        var inventory = status.ConnectedInventory!;
        var devices = inventory.Where(d => string.Equals(d.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || !devices[0].Device.IsConnected || devices[0].Topology is null || !TopologyAdmission.Validate(devices[0]) ||
            inventory.Where(d => !ReferenceEquals(d, devices[0])).Any(d =>
                d.Volumes.Any(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, containerUuid)) ||
                d.Topology?.Snapshot.Containers.Any(c => TopologyAdmission.SameUuid(c.Uuid, containerUuid)) == true))
            throw Changed("The original source is missing, replaced or ambiguous.");
        var device = devices[0];
        var volumes = device.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, containerUuid)).ToArray();
        var containers = device.Topology!.Snapshot.Containers.Where(c => TopologyAdmission.SameUuid(c.Uuid, containerUuid)).ToArray();
        var selected = targets.Select(t => volumes.SingleOrDefault(v => v.VolumeId == t.VolumeId)).ToArray();
        var wanted = selected.Select(v => v?.CatalogVolumeId).ToHashSet(StringComparer.Ordinal);
        if (selected.Any(v => v is null) || wanted.Count != targets.Count || volumes.Length != targets.Count || containers.Length != 1 ||
            containers[0].VolumeIds.Count != targets.Count || !wanted.SetEquals(containers[0].VolumeIds) ||
            !wanted.SetEquals(device.Topology.Snapshot.Volumes.Where(v => v.ContainerId == containers[0].Id).Select(v => v.Id)))
            throw Changed("Original container membership changed.");
        var owners = new List<Owner?>(); var scopes = new List<VerifyScope?>(); var mounts = new List<MountedVolumeDisplay?>();
        for (var i = 0; i < targets.Count; ++i)
        {
            var volume = selected[i]!;
            if (targets[i] != SelectedControlTarget.Create(device, volume) || !SelectedControlTarget.Matches(inventory, targets[i]) ||
                !CatalogMountPolicy.AllowsOrdinaryMount(volume) || volume.IsEncrypted || volume.RegisteredImage is not null)
                throw Changed("A member identity or capability changed.");
            var scope = VerifyScopeDerivation.TryDerive(device, volume).Scope;
            if (VolumeTopologyProfile.LocalPath(deviceId) && scope is null) throw Changed("An exact original image scope is required.");
            var candidates = (status.MountedVolumes ?? []).Where(m => string.Equals(m.VolumeId, volume.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                TopologyAdmission.SameUuid(m.CatalogVolumeUuid, volume.CatalogVolumeUuid)).ToArray();
            Owner? owner = null; MountedVolumeDisplay? mount = null;
            if (candidates.Length > 0)
            {
                if (candidates.Length != 1 || !MatchesOwner(candidates[0], volume) ||
                    candidates[0].RecoveryIdentity != volume.RecoveryIdentity || !candidates[0].HasRuntimeStatus ||
                    candidates[0].HostProcessId <= 0 || candidates[0].HostProcessCreationTimeFileTimeUtc <= 0)
                    throw Changed("A retained owner is missing, duplicated or replaced.");
                mount = candidates[0];
                if (mount.VolumeVerificationScope is { } retained)
                {
                    try { _ = LiveVolumeVerificationScope.Parse(JsonSerializer.SerializeToElement(retained, WireOptions)); }
                    catch (InvalidDataException) { throw Changed("The retained source scope is malformed."); }
                    if (!TopologyAdmission.SameUuid(retained.ContainerUuid, volume.CatalogContainerUuid) ||
                        !TopologyAdmission.SameUuid(retained.VolumeUuid, volume.CatalogVolumeUuid) ||
                        retained.VolumeOid != volume.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture))
                        throw Changed("A retained scope names a different member.");
                }
                if (VolumeTopologyProfile.LocalPath(deviceId) && (mount.VolumeVerificationScope is not { SourceKind: "retained-image" } held ||
                    held.StoreOffsetBytes != scope!.StoreOffsetBytes || held.StoreSizeBytes != scope.StoreSizeBytes))
                    throw Changed("The retained original image source or window is unproven.");
                owner = new(mount.HostProcessId, mount.HostProcessCreationTimeFileTimeUtc, mount.MountPoint, mount.AccessMode, mount.VolumeVerificationScope);
            }
            owners.Add(owner); scopes.Add(scope); mounts.Add(mount);
        }
        if ((status.MountedVolumes ?? []).Any(m =>
            (string.Equals(m.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) || TopologyAdmission.SameUuid(m.CatalogContainerUuid, containerUuid)) &&
            !volumes.Any(v => MatchesOwner(m, v)))) throw Changed("A foreign source owner is present.");
        if (owners.Where(o => o?.Scope is not null).Select(o => (o!.Scope!.SourceIdentity, o.Scope.SourceKind,
            o.Scope.StoreOffsetBytes, o.Scope.StoreSizeBytes)).Distinct().Count() > 1) throw Changed("Member sources disagree.");
        return new(selected.Select(v => v!).ToArray(), targets.ToArray(), owners.ToArray(), scopes.ToArray(), mounts.ToArray());
    }

    private static void RequireBounded(StatusChangedPayload status)
    {
        var count = status.MountedVolumes?.Count ?? 0;
        if (status.InventoryGeneration is not > 0 || status.ConnectedInventory is null ||
            count > TopologyGraphIndex.Limit || status.ConnectedInventory.Count > TopologyGraphIndex.Limit ||
            status.MountedVolumes?.Any(m => m is null || !TopologyGraphIndex.Text(m.VolumeId)) == true)
            throw Changed("Current bounded topology is required.");
        long graphCount = 0;
        foreach (var d in status.ConnectedInventory)
        {
            if (d?.Device is null || d.Volumes is null || !TopologyGraphIndex.Text(d.Device.DeviceId) ||
                (count += d.Volumes.Count) > TopologyGraphIndex.Limit ||
                d.Volumes.Any(v => v is null || !TopologyGraphIndex.Text(v.VolumeId) || !TopologyGraphIndex.Text(v.DeviceId)))
                throw Changed("Current bounded topology is required.");
            if (d.Topology?.Snapshot is { } t)
            {
                graphCount += (long)(t.Disks?.Count ?? 0) + (t.Partitions?.Count ?? 0) + (t.Stores?.Count ?? 0) +
                    (t.Containers?.Count ?? 0) + (t.Volumes?.Count ?? 0) + (t.Groups?.Count ?? 0);
                if (graphCount > TopologyGraphIndex.Limit) throw Changed("Current bounded topology is required.");
            }
        }
    }

    private static bool MatchesOwner(MountedVolumeDisplay m, VolumeInfo v) =>
        string.Equals(m.DeviceId, v.DeviceId, StringComparison.OrdinalIgnoreCase) && m.VolumeId == v.VolumeId &&
        m.CatalogVolumeId == v.CatalogVolumeId && TopologyAdmission.SameUuid(m.CatalogContainerUuid, v.CatalogContainerUuid) &&
        m.CatalogVolumeObjectId == v.CatalogVolumeObjectId && TopologyAdmission.SameUuid(m.CatalogVolumeUuid, v.CatalogVolumeUuid) &&
        m.RecoveryIdentity == v.RecoveryIdentity;

    public bool IsHealthy(int index) => Healthy(mounts[index]);
    public bool NeedsFix(int index) => mounts[index] is not { } m ? Image && imageScopes[index] is not null : !Healthy(m) && !Busy(m);
    private static bool Busy(MountedVolumeDisplay m) => m.PendingDurability || m.WalAcceptedSequence > m.WalApfsDurableSequence ||
        m.DirtyTransactionCount > 0 || m.ShutdownDrainActive || m.InFlightMutationCallbacks > 0;
    private static bool Healthy(MountedVolumeDisplay? m) => m is { HasRuntimeStatus: true, State: RuntimeState.MountedRw,
        MountReady: true, WriteEnabled: true, AccessMode: MountAccessMode.ReadWrite, RecoveryActive: false } && !Busy(m) &&
        m.NativeWriteSafetyState is not (NativeWriteSafetyState.RecoveryBlocked or NativeWriteSafetyState.ReadOnlyFallback);

    public static bool HasHealthyOwner(StatusChangedPayload status, ApfsControlTarget target)
    {
        var matches = (status.MountedVolumes ?? []).Where(m => string.Equals(m.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase)).ToArray();
        return matches.Length == 1 && string.Equals(matches[0].DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) &&
            matches[0].RecoveryIdentity == target.RecoveryIdentity && matches[0].CatalogVolumeObjectId == target.VolumeObjectId &&
            TopologyAdmission.SameUuid(matches[0].CatalogContainerUuid, target.ContainerUuid) &&
            TopologyAdmission.SameUuid(matches[0].CatalogVolumeUuid, target.VolumeUuid) && Healthy(matches[0]);
    }

    private void RequireOriginal(ContainerFixProof after)
    {
        if (!Targets.SequenceEqual(after.Targets)) throw Changed("Source, UUID, recovery identity or capability was replaced.");
        for (var i = 0; i < Targets.Count; ++i)
            if (imageScopes[i] is { } scope && (after.imageScopes[i] is not { } fresh ||
                (fresh with { CheckpointXid = scope.CheckpointXid }) != scope)) throw Changed("The original image scope changed.");
        if (sourceIdentity is not null && after.sourceIdentity is not null && sourceIdentity != after.sourceIdentity)
            throw Changed("The original retained source was replaced.");
    }

    public ContainerFixProof Revalidate(StatusChangedPayload status)
    {
        var fresh = Capture(status, Targets); RequireOriginal(fresh);
        if (!owners.SequenceEqual(fresh.owners) || !imageScopes.SequenceEqual(fresh.imageScopes))
            throw Changed("A retained owner or current scope changed between operations.");
        fresh.sourceIdentity = sourceIdentity ?? fresh.sourceIdentity;
        Array.Copy(acknowledgedOwners, fresh.acknowledgedOwners, owners.Length);
        return fresh;
    }

    public void AcknowledgeHealthy(int index)
    {
        if (!IsHealthy(index) || owners[index] is null) throw Changed("The acknowledged member has no current healthy owner.");
        acknowledgedOwners[index] = owners[index];
    }

    public void RevalidateForCompletion(StatusChangedPayload status)
    {
        var fresh = Capture(status, Targets); RequireOriginal(fresh);
        for (var i = 0; i < owners.Length; ++i)
        {
            var member = $"Final cohort member '{Volumes[i].VolumeName}' ({Volumes[i].VolumeId})";
            if (!fresh.IsHealthy(i) || fresh.owners[i] is not { } current)
                throw Changed(member + " is absent or unhealthy.");
            if (owners[i] != current || imageScopes[i] != fresh.imageScopes[i])
                throw Changed(member + " has a changed current owner or scope.");
            // Later image work may advance checkpoints, but cannot rebind acknowledged owners.
            if (acknowledgedOwners[i] is not { } acknowledged || acknowledged.Pid != current.Pid ||
                acknowledged.Created != current.Created || acknowledged.MountPoint != current.MountPoint || acknowledged.Mode != current.Mode)
                throw Changed(member + " no longer has its acknowledged owner.");
        }
    }

    public void RevalidateForApproval(StatusChangedPayload status)
    {
        var fresh = Capture(status, Targets); RequireOriginal(fresh);
        // The plan may drain original owners; it cannot replace them while awaiting approval.
        for (var i = 0; i < owners.Length; ++i)
            if (fresh.owners[i] is not null && fresh.owners[i] != owners[i]) throw Changed("A retained owner changed while awaiting confirmation.");
    }

    public ContainerFixProof AfterCompletedFix(StatusChangedPayload status, int selected, out bool canContinue, out string? stopReason)
    {
        var after = Capture(status, Targets); RequireOriginal(after);
        if (!after.IsHealthy(selected) || after.owners[selected] is not { } selectedOwner)
            throw Changed("The acknowledged Fix has no current healthy owner.");
        Array.Copy(acknowledgedOwners, after.acknowledgedOwners, owners.Length);
        after.AcknowledgeHealthy(selected);
        stopReason = null;
        for (var i = 0; i < owners.Length; ++i)
        {
            if (owners[i] == after.owners[i]) continue;
            // No current Fix receipt binds a replacement physical cohort. Keep the
            // acknowledged child result, but do not adopt those peers for later Fix.
            if (!Image && (i != selected || owners[i] is not { } old || old.Pid != selectedOwner.Pid ||
                old.Created != selectedOwner.Created || old.MountPoint != selectedOwner.MountPoint))
                stopReason = "The service completed the selected Fix, but the physical owner cohort changed. Refresh before Fixing remaining members.";
            if (Image && i != selected && after.owners[i] is { } peer &&
                (peer.Pid != selectedOwner.Pid || peer.Created != selectedOwner.Created || peer.Scope?.SourceIdentity != selectedOwner.Scope?.SourceIdentity))
                stopReason = "The service completed the selected Fix, but an unrelated peer owner replaced the original cohort. Refresh before Fixing remaining members.";
        }
        canContinue = stopReason is null;
        after.sourceIdentity = sourceIdentity ?? after.sourceIdentity;
        return after;
    }

    public static void ValidateReply(ControlOperationRequestPayload request, OperationResultPayload result)
    {
        if (request.Command != ApfsControlCommands.Fix || result.OperationId != request.OperationId || result.Command != request.Command ||
            !ContainerVerificationProof.SameReplyTarget(result.Target, request.Target) || result.Fingerprint != ApfsOperationFingerprint.Compute(request) ||
            result.ExpiresAtUtc != request.ExpiresAtUtc || result.RequestedMode != request.RequestedMode ||
            result.ApprovedImageRepairPlanId != request.ApprovedImageRepairPlanId ||
            !PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, PipeSchemaVersions.Schema2)).IsValid)
            throw Changed("The service returned mismatched or invalid Fix evidence.");
    }
}
