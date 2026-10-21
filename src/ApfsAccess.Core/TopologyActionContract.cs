namespace ApfsAccess.Core;

public enum ApfsTopologyAction
{
    Details,
    Rescan,
    EjectDevice,
    MemberHealth,
    Open,
    Mount,
    Unmount,
    Unlock,
    Lock,
    Repair,
    Verify,
    SnapshotCreate,
    SnapshotDelete,
    SnapshotRecover,
    Manage,
    ManagementPlan,
    ManagementApply,
}

public enum ApfsActionAvailability
{
    Available,
    Unavailable,
    Refused,
}

public sealed record ApfsActionCapability(
    ApfsTopologyAction Action,
    ApfsActionAvailability Availability,
    string? Code,
    string Reason)
{
    public bool IsAvailable => Availability == ApfsActionAvailability.Available;
}

public static class ApfsTopologyActionContract
{
    public const string LiveVerifyUnavailable = "live-verify-unavailable";
    public const string LiveRepairUnavailable = "live-repair-unavailable";
    public const string LiveContainerManagementUnavailable = "live-container-management-unavailable";
    public const string RuntimeOwnerUnproven = "runtime-owner-unproven";
    public const string SnapshotRuntimeOwnerUnproven = "snapshot-runtime-owner-unproven";
    public const string SnapshotIdentityRequired = "snapshot-identity-required";
    public const string GuiManagementUnavailable = "gui-management-unavailable";

    public static ApfsActionCapability Available(ApfsTopologyAction action, string reason = "Available.")
        => new(action, ApfsActionAvailability.Available, null, reason);

    public static ApfsActionCapability Unavailable(ApfsTopologyAction action, string reason)
        => new(action, ApfsActionAvailability.Unavailable, null, reason);

    public static ApfsActionCapability Unavailable(ApfsTopologyAction action, string code, string reason)
        => new(action, ApfsActionAvailability.Unavailable, code, reason);

    public static ApfsActionCapability Refused(ApfsTopologyAction action, string code, string reason)
        => new(action, ApfsActionAvailability.Refused, code, reason);

    public static IReadOnlyList<ApfsActionCapability> ForVolume(
        bool canOpen,
        bool isMounted,
        bool canMount,
        bool canUnmount,
        bool canUnlock,
        bool canLock,
        bool canRepair,
        bool canCreateSnapshot,
        bool runtimeOwnerProven,
        bool registeredImage,
        bool canVerifyOffline = false,
        bool canManageOffline = false,
        bool hasSnapshotIdentity = false,
        bool canRecoverSnapshots = false)
    {
        var repair = canRepair
            ? runtimeOwnerProven
                ? Available(ApfsTopologyAction.Repair, "The service has a proven runtime owner for this volume.")
                : Refused(ApfsTopologyAction.Repair, RuntimeOwnerUnproven,
                    "Repair is unavailable until the service proves the runtime owner and public WAL authority.")
            : Unavailable(ApfsTopologyAction.Repair, isMounted ? "The current volume state does not allow repair." : "The volume is not mounted.");
        var snapshot = canCreateSnapshot
            ? runtimeOwnerProven
                ? Available(ApfsTopologyAction.SnapshotCreate, "The mounted owner session can receive snapshot control.")
                : Refused(ApfsTopologyAction.SnapshotCreate, SnapshotRuntimeOwnerUnproven,
                    "Snapshot control is unavailable until the service proves the mounted runtime owner.")
            : Unavailable(ApfsTopologyAction.SnapshotCreate, "Snapshot control requires a mounted, fully identified volume.");

        return
        [
            Available(ApfsTopologyAction.Details),
            canOpen ? Available(ApfsTopologyAction.Open) : Unavailable(ApfsTopologyAction.Open, "The volume is not mounted."),
            canMount ? Available(ApfsTopologyAction.Mount) : Unavailable(ApfsTopologyAction.Mount, "Mount is blocked by the current capability or identity state."),
            canUnmount ? Available(ApfsTopologyAction.Unmount) : Unavailable(ApfsTopologyAction.Unmount, "The volume is not mounted."),
            canUnlock ? Available(ApfsTopologyAction.Unlock) : Unavailable(ApfsTopologyAction.Unlock, "The encrypted volume is not waiting for unlock."),
            canLock ? Available(ApfsTopologyAction.Lock) : Unavailable(ApfsTopologyAction.Lock, "The encrypted volume is not ready to lock."),
            repair,
            canVerifyOffline ? Available(ApfsTopologyAction.Verify, "Verify covered metadata in the selected offline image through the service.") :
                Refused(ApfsTopologyAction.Verify, LiveVerifyUnavailable,
                    "Offline verification requires a complete single-store image scope and every image volume unmounted."),
            snapshot,
            snapshot.IsAvailable && hasSnapshotIdentity ? Available(ApfsTopologyAction.SnapshotDelete) :
                Unavailable(ApfsTopologyAction.SnapshotDelete, SnapshotIdentityRequired,
                    "Delete requires the exact snapshot identity from the snapshot inventory and a writable owner."),
            canRecoverSnapshots && runtimeOwnerProven ? Available(ApfsTopologyAction.SnapshotRecover) :
                Unavailable(ApfsTopologyAction.SnapshotRecover, SnapshotRuntimeOwnerUnproven,
                    "Recover requires the exact mounted volume's owner and journal authority."),
            canManageOffline && !registeredImage
                ? Available(ApfsTopologyAction.Manage, "Review and confirm an offline rename or quota/reserve plan through the service.")
                : Refused(ApfsTopologyAction.Manage, GuiManagementUnavailable,
                    "Management requires an eligible unencrypted offline image and a configured native keeper."),
        ];
    }

    public static IReadOnlyList<ApfsActionCapability> ForContainer(
        bool canMount,
        bool canUnmount,
        bool canRepair)
        =>
        [
            Available(ApfsTopologyAction.Details),
            Available(ApfsTopologyAction.MemberHealth),
            canMount ? Available(ApfsTopologyAction.Mount) : Unavailable(ApfsTopologyAction.Mount, "No eligible unmounted member is available."),
            canUnmount ? Available(ApfsTopologyAction.Unmount) : Unavailable(ApfsTopologyAction.Unmount, "No mounted member is available for container unmount."),
            canRepair ? Refused(ApfsTopologyAction.Repair, LiveRepairUnavailable,
                "An unbound atomic container repair is unavailable. Use the identity-bound per-volume container-fix workflow when admitted.")
                : Unavailable(ApfsTopologyAction.Repair, "No mounted member is currently repairable."),
            Refused(ApfsTopologyAction.Verify, LiveVerifyUnavailable,
                "An unbound whole-container verification is unavailable. Use container-verify for an admitted batch of exact per-volume metadata requests."),
            Refused(ApfsTopologyAction.Manage, LiveContainerManagementUnavailable,
                "An unbound atomic container change is unavailable. Select an admitted offline member for its service-backed management plan."),
        ];

    // Presentation of a client's admitted member operations, not service authority.
    // Existing owner/keeper proofs must still be revalidated before every dispatch.
    public static IReadOnlyList<ApfsActionCapability> ForBoundMemberBatch(DeviceInventory observed,
        string expectedCheckpointXid, IReadOnlyDictionary<string, string> memberContracts,
        bool verificationAdmitted, bool fixAdmitted)
    {
        RequireBoundMembers(observed, expectedCheckpointXid, memberContracts);
        return
        [
            verificationAdmitted ? Available(ApfsTopologyAction.Verify,
                "Verify the complete bound member set with sequential per-volume current-metadata requests; global, historical and payload integrity are outside this batch.")
                : Unavailable(ApfsTopologyAction.Verify, "The bound members lack complete current verification admission."),
            fixAdmitted ? Available(ApfsTopologyAction.Repair,
                "Run existing per-volume Fix workflows for the bound members needing repair, with each service authority and confirmation rechecked.")
                : Unavailable(ApfsTopologyAction.Repair, "No bound member currently has admitted Fix work."),
            Refused(ApfsTopologyAction.Manage, LiveContainerManagementUnavailable,
                "This batch grants no atomic management operation. Select an admitted offline member for a leaf plan."),
        ];
    }

    public static IReadOnlyList<ApfsActionCapability> ForBoundOfflineMember(DeviceInventory observed,
        string expectedCheckpointXid, IReadOnlyDictionary<string, string> memberContracts,
        string selectedVolumeId, bool managementAdmitted)
    {
        var members = RequireBoundMembers(observed, expectedCheckpointXid, memberContracts);
        var selected = members.SingleOrDefault(v => v.VolumeId == selectedVolumeId)
            ?? throw new InvalidOperationException("Select one member of the complete bound container.");
        var eligible = managementAdmitted && !selected.IsEncrypted && selected.RegisteredImage is null &&
            selected.RegisteredFusion is null && CatalogMountPolicy.AllowsOrdinaryMount(selected);
        return
        [
            eligible ? Available(ApfsTopologyAction.Manage,
                "Review a service-backed rename or quota/reserve plan for this exact offline member; its siblings and observation remain bound.")
                : Unavailable(ApfsTopologyAction.Manage, GuiManagementUnavailable,
                    "The selected bound member lacks current offline management admission."),
        ];
    }

    private static VolumeInfo[] RequireBoundMembers(DeviceInventory observed, string expectedCheckpointXid,
        IReadOnlyDictionary<string, string> memberContracts)
    {
        static InvalidOperationException Changed() => new("The complete source, checkpoint and member observation contracts must still match. Refresh before acting.");
        if (!ulong.TryParse(expectedCheckpointXid, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var xid) || xid == 0 ||
            xid.ToString(System.Globalization.CultureInfo.InvariantCulture) != expectedCheckpointXid ||
            !TopologyAdmission.Validate(observed) || observed.Topology is null ||
            memberContracts is null || memberContracts.Count is 0 or > TopologyGraphIndex.Limit ||
            memberContracts.Any(p => !TopologyGraphIndex.Text(p.Key) || !TopologyGraphIndex.Text(p.Value)))
            throw Changed();
        var members = observed.Volumes.Where(v => memberContracts.ContainsKey(v.VolumeId)).ToArray();
        if (members.Length != memberContracts.Count || members.Length == 0 ||
            !members.Select(v => v.VolumeId).ToHashSet(StringComparer.Ordinal).SetEquals(memberContracts.Keys)) throw Changed();
        var uuid = members[0].CatalogContainerUuid;
        var containers = observed.Topology.Snapshot.Containers.Where(c => TopologyAdmission.SameUuid(c.Uuid, uuid)).ToArray();
        if (containers.Length != 1 || containers[0].CheckpointXid != expectedCheckpointXid ||
            members.Any(v => !TopologyAdmission.SameUuid(v.CatalogContainerUuid, uuid)) ||
            observed.Volumes.Count(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, uuid)) != members.Length)
            throw Changed();
        var catalogIds = members.Select(v => v.CatalogVolumeId).ToHashSet(StringComparer.Ordinal);
        var container = containers[0];
        if (catalogIds.Count != members.Length || container.VolumeIds.Count != members.Length ||
            !catalogIds.SetEquals(container.VolumeIds) || !catalogIds.SetEquals(observed.Topology.Snapshot.Volumes
                .Where(v => v.ContainerId == container.Id).Select(v => v.Id)) ||
            members.Any(v => TopologyAdmission.Contract(observed, v) != memberContracts[v.VolumeId]))
            throw Changed();
        return members;
    }

    public static IReadOnlyList<ApfsActionCapability> ForCli()
        =>
        [
            Available(ApfsTopologyAction.ManagementPlan, "Issues a service-backed, single-use management plan."),
            Available(ApfsTopologyAction.ManagementApply, "Applies a matching service-backed management plan."),
            Available(ApfsTopologyAction.Verify,
                "volume-verify checks an admitted volume scope; container-verify batches exact current member requests and reports their bounded metadata coverage."),
            Refused(ApfsTopologyAction.Repair, LiveRepairUnavailable,
                "An unbound repair is unavailable. Use admitted volume Fix or container-fix member workflows with their runtime/WAL or confirmed image-repair authority."),
            Refused(ApfsTopologyAction.Manage, LiveContainerManagementUnavailable,
                "An unbound atomic container change is unavailable. container-manage plan/apply selects one exact admitted offline member."),
        ];

    public static ApfsActionCapability Find(
        IReadOnlyList<ApfsActionCapability>? actions,
        ApfsTopologyAction action)
        => actions?.FirstOrDefault(candidate => candidate.Action == action)
            ?? Unavailable(action, "Capability information is unavailable; refresh before acting.");
}
