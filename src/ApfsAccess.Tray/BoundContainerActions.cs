using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal static class BoundContainerActions
{
    // Call only after the existing complete membership and owner proof succeeds.
    internal static ApfsActionCapability Require(StatusChangedPayload status,IReadOnlyList<ApfsControlTarget> targets,
        ApfsTopologyAction action,string? selectedOfflineMember=null)
    {
        if(targets.Count==0)throw new InvalidOperationException("A complete bound member set is required.");
        var source=(status.ConnectedInventory??[]).Single(d=>string.Equals(d.Device.DeviceId,targets[0].DeviceId,StringComparison.OrdinalIgnoreCase));
        var container=source.Topology!.Snapshot.Containers.Single(c=>TopologyAdmission.SameUuid(c.Uuid,targets[0].ContainerUuid));
        var contracts=targets.ToDictionary(t=>t.VolumeId,t=>t.ObservationContract??throw new InvalidOperationException("A current member contract is required."),StringComparer.Ordinal);
        var actions=action==ApfsTopologyAction.Manage
            ?ApfsTopologyActionContract.ForBoundOfflineMember(source,container.CheckpointXid!,contracts,
                selectedOfflineMember??throw new InvalidOperationException("Select one offline member."),true)
            :ApfsTopologyActionContract.ForBoundMemberBatch(source,container.CheckpointXid!,contracts,
                action==ApfsTopologyAction.Verify,action==ApfsTopologyAction.Repair);
        var capability=ApfsTopologyActionContract.Find(actions,action);
        if(!capability.IsAvailable)throw new InvalidOperationException(capability.Reason);
        return capability;
    }
}
