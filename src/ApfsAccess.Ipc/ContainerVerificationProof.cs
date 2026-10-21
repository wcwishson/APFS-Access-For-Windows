using System.Globalization;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

// Client-side evidence for a batch of existing VolumeVerify requests, not a wire contract.
public sealed class ContainerVerificationProof
{
    public const string Scope = "Per-volume current metadata only; whole-container integrity, whole-volume integrity, historical integrity and payload hashes are not verified.";
    private static readonly JsonSerializerOptions WireOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private sealed record Owner(int Pid, long Created, string MountPoint, MountAccessMode Mode,
        LiveVolumeVerificationScope Scope);
    private sealed record Member(ApfsControlTarget Target, Owner? Owner, VerifyScope? OfflineScope);
    private readonly Member[] _members;
    public IReadOnlyList<VolumeInfo> Volumes { get; }
    public IReadOnlyList<ApfsControlTarget> Targets { get; }

    private ContainerVerificationProof(Member[] members, VolumeInfo[] volumes)
    {
        _members = members;
        Volumes = Array.AsReadOnly(volumes);
        Targets = Array.AsReadOnly(members.Select(m => m.Target).ToArray());
    }

    private static InvalidOperationException Changed(string detail)
        => new($"Verify volumes unavailable: {detail} Refresh before acting.");

    public static ContainerVerificationProof CaptureForContainer(StatusChangedPayload current, string deviceId, string containerUuid)
    {
        RequireBounded(current);
        var devices = current.ConnectedInventory!.Where(d =>
            string.Equals(d.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || devices[0].Topology is null || !TopologyAdmission.Validate(devices[0]))
            throw Changed("The selected source topology is unavailable or ambiguous.");
        var device = devices[0];
        var targets = device.Volumes.Where(v => ApfsTopology.MatchesContainerUuid(containerUuid, v.CatalogContainerUuid))
            .Select(v => SelectedControlTarget.Create(device, v)).ToArray();
        return Capture(current, targets);
    }

    public static ContainerVerificationProof Capture(StatusChangedPayload current, IReadOnlyList<ApfsControlTarget> targets)
    {
        RequireBounded(current);
        if (targets.Count is 0 or > TopologyGraphIndex.Limit || targets.Any(t => t is null) ||
            targets.Select(t => t.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != targets.Count)
            throw Changed("Every member needs a unique eligible per-volume target and current topology.");
        var inventory = current.ConnectedInventory!;
        var deviceId = targets[0].DeviceId;
        var containerUuid = targets[0].ContainerUuid;
        if (targets.Any(t => !string.Equals(t.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
                !TopologyAdmission.SameUuid(t.ContainerUuid, containerUuid)))
            throw Changed("Members must name one source and container.");
        var devices = inventory.Where(d => string.Equals(d.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || devices[0].Topology is null || !TopologyAdmission.Validate(devices[0]))
            throw Changed("The selected source topology is unavailable or ambiguous.");
        var device = devices[0];
        if (inventory.Where(d => !ReferenceEquals(d, device)).Any(d =>
            d.Volumes.Any(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, containerUuid)) ||
            d.Topology?.Snapshot.Containers.Any(c => TopologyAdmission.SameUuid(c.Uuid, containerUuid)) == true))
            throw Changed("The container identity is advertised by multiple sources.");
        var containers = device.Topology!.Snapshot.Containers.Where(c => TopologyAdmission.SameUuid(c.Uuid, containerUuid)).ToArray();
        if (containers.Length != 1) throw Changed("The container identity is ambiguous.");
        var container = containers[0];
        var volumes = device.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, containerUuid)).ToArray();
        var catalog = device.Topology.Snapshot.Volumes.Where(v => v.ContainerId == container.Id).ToArray();
        var selected = targets.Select(t => volumes.SingleOrDefault(v => v.VolumeId == t.VolumeId)).ToArray();
        if (selected.Any(v => v is null)) throw Changed("A selected member is missing or duplicated.");
        var wanted = selected.Select(v => v!.CatalogVolumeId).ToHashSet(StringComparer.Ordinal);
        if (wanted.Count != targets.Count || volumes.Length != targets.Count || catalog.Length != targets.Count ||
            container.VolumeIds.Count != targets.Count || !wanted.SetEquals(container.VolumeIds) ||
            !wanted.SetEquals(catalog.Select(v => v.Id)) || !wanted.SetEquals(volumes.Select(v => v.CatalogVolumeId)))
            throw Changed("The entire selected container membership must match current topology.");
        var result = new List<Member>();
        for (var i = 0; i < targets.Count; i++)
        {
            var target = targets[i];
            var volume = selected[i]!;
            if (target != SelectedControlTarget.Create(device, volume) || !SelectedControlTarget.Matches(inventory, target) ||
                volume.RegisteredImage is not null || volume.IsEncrypted)
                throw Changed("A selected routing identity or verification capability is ambiguous.");
            var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeVerify,
                target, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(90));
            if (!PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
                request, request.OperationId, PipeSchemaVersions.Schema2)).IsValid)
                throw Changed("A selected routing target cannot form a valid VolumeVerify request.");
            // Count routing owners before matching full identity, including stale owners.
            var owners = (current.MountedVolumes ?? []).Where(m =>
                string.Equals(m.VolumeId, volume.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                TopologyAdmission.SameUuid(m.CatalogVolumeUuid, volume.CatalogVolumeUuid)).ToArray();
            Owner? owner = null;
            VerifyScope? offline = null;
            if (owners.Length != 0)
            {
                if (owners.Length != 1 || !MatchesOwner(owners[0], volume) ||
                    owners[0] is not { HasRuntimeStatus: true, HostProcessId: > 0, VolumeVerificationSupported: true,
                        VolumeVerificationScope: { } scope } || !CatalogMountPolicy.AllowsOrdinaryMount(volume))
                    throw Changed("A retained verification owner is missing, stale or duplicated.");
                if (!TopologyAdmission.SameUuid(scope.ContainerUuid, volume.CatalogContainerUuid) ||
                    !TopologyAdmission.SameUuid(scope.VolumeUuid, volume.CatalogVolumeUuid) ||
                    scope.VolumeOid != volume.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture))
                    throw Changed("The retained verification capability names a different volume.");
                try { _ = LiveVolumeVerificationScope.Parse(JsonSerializer.SerializeToElement(scope, WireOptions)); }
                catch (InvalidDataException) { throw Changed("The retained verification scope is malformed."); }
                owner = new(owners[0].HostProcessId, owners[0].HostProcessCreationTimeFileTimeUtc,
                    owners[0].MountPoint, owners[0].AccessMode, scope);
            }
            else
            {
                var derived = VerifyScopeDerivation.TryDerive(device, volume);
                if (!derived.Ok || (current.MountedVolumes ?? []).Any(m =>
                    string.Equals(m.DeviceId, volume.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                    TopologyAdmission.SameUuid(m.CatalogContainerUuid, volume.CatalogContainerUuid)))
                    throw Changed("An offline member has a source owner or lacks an exact verification scope.");
                offline = derived.Scope;
            }
            result.Add(new(target, owner, offline));
        }
        if ((current.MountedVolumes ?? []).Any(m => TopologyAdmission.SameUuid(m.CatalogContainerUuid, containerUuid) &&
            !volumes.Any(v => MatchesOwner(m, v))))
            throw Changed("The container has a stale or mixed-source owner.");
        if (result.Where(m => m.Owner is not null).Select(m => m.Owner!.Scope)
            .Select(s => (s.SourceIdentity, s.SourceKind, s.StoreOffsetBytes, s.StoreSizeBytes)).Distinct().Count() > 1)
            throw Changed("Live members advertise conflicting retained sources or store windows.");
        return new(result.ToArray(), selected.Select(v => v!).ToArray());
    }

    public void Revalidate(StatusChangedPayload current)
    {
        var fresh = Capture(current, Targets);
        if (!fresh._members.SequenceEqual(_members))
            throw Changed("A member observation, retained owner or verification scope changed.");
    }

    private static bool MatchesOwner(MountedVolumeDisplay m, VolumeInfo v) =>
        string.Equals(m.DeviceId, v.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(m.VolumeId, v.VolumeId, StringComparison.Ordinal) &&
        string.Equals(m.CatalogVolumeId, v.CatalogVolumeId, StringComparison.Ordinal) &&
        string.Equals(m.CatalogContainerUuid, v.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
        m.CatalogVolumeObjectId == v.CatalogVolumeObjectId &&
        string.Equals(m.CatalogVolumeUuid, v.CatalogVolumeUuid, StringComparison.OrdinalIgnoreCase) &&
        m.RecoveryIdentity == v.RecoveryIdentity;

    private static void RequireBounded(StatusChangedPayload s)
    {
        var count = s.MountedVolumes?.Count ?? 0;
        if (s.InventoryGeneration is not > 0 || s.ConnectedInventory is null ||
            count > TopologyGraphIndex.Limit || s.ConnectedInventory.Count > TopologyGraphIndex.Limit ||
            s.MountedVolumes?.Any(v => v is null || !TopologyGraphIndex.Text(v.VolumeId)) == true)
            throw Changed("Current bounded topology is required.");
        long graphCount = 0;
        foreach (var d in s.ConnectedInventory)
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

    public static void ValidateReply(ControlOperationRequestPayload request, OperationResultPayload result)
    {
        if (result.OperationId != request.OperationId || result.Command != ApfsControlCommands.VolumeVerify ||
            !SameReplyTarget(result.Target, request.Target) || result.Fingerprint != ApfsOperationFingerprint.Compute(request))
            throw new InvalidOperationException("Service returned a mismatched verification result. Refresh to confirm the child outcome.");
    }

    public static void RequireVerifiedReply(ControlOperationRequestPayload request, OperationResultPayload result)
    {
        ValidateReply(request, result);
        if (result.State != ApfsOperationStates.Succeeded || !result.Success)
            throw new InvalidOperationException(result.Diagnostic ?? $"Verification did not complete ({result.State}, {result.Code}).");
    }

    internal static bool SameReplyTarget(ApfsControlTarget? actual, ApfsControlTarget? expected)
        => actual is not null && expected is not null &&
            string.Equals(actual.DeviceId, expected.DeviceId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(actual.VolumeId, expected.VolumeId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(actual.ContainerUuid, expected.ContainerUuid, StringComparison.OrdinalIgnoreCase) &&
            actual with { DeviceId = expected.DeviceId, VolumeId = expected.VolumeId,
                ContainerUuid = expected.ContainerUuid } == expected;
}
