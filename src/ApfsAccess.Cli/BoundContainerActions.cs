using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class BoundContainerActions
{
    internal static ApfsActionCapability RequireBatch(StatusChangedPayload status,IReadOnlyList<ApfsControlTarget> targets,
        ApfsTopologyAction action)
    {
        var (source,xid,contracts)=Binding(status,targets);
        var capability=ApfsTopologyActionContract.Find(ApfsTopologyActionContract.ForBoundMemberBatch(source,xid,contracts,
            action==ApfsTopologyAction.Verify,action==ApfsTopologyAction.Repair),action);
        if(!capability.IsAvailable)throw new InvalidOperationException(capability.Reason);
        return capability;
    }

    internal static ApfsActionCapability RequireOfflineMember(StatusChangedPayload status,ApfsControlTarget selected,
        IReadOnlyList<DeviceInventory> latestInventory)
    {
        var proof=ContainerVerificationProof.CaptureForContainer(status,selected.DeviceId,selected.ContainerUuid!);
        if(!proof.Targets.Contains(selected)||!status.ManagementJournalRootInspected||
            (status.MountedVolumes??[]).Any(m=>string.Equals(m.DeviceId,selected.DeviceId,StringComparison.OrdinalIgnoreCase)||
                TopologyAdmission.SameUuid(m.CatalogContainerUuid,selected.ContainerUuid)))
            throw new InvalidOperationException("The selected offline member or inspected management keeper changed.");
        var (source,xid,contracts)=Binding(status,proof.Targets);
        var current=latestInventory.Where(d=>string.Equals(d.Device.DeviceId,selected.DeviceId,StringComparison.OrdinalIgnoreCase)).ToArray();
        if(current.Length!=1||!SelectedControlTarget.Matches(latestInventory,selected)||latestInventory.Any(d=>
            !string.Equals(d.Device.DeviceId,selected.DeviceId,StringComparison.OrdinalIgnoreCase)&&
            d.Topology?.Snapshot.Containers.Any(c=>TopologyAdmission.SameUuid(c.Uuid,selected.ContainerUuid))==true))
            throw new InvalidOperationException("The current inventory no longer has one bound source.");
        var volume=proof.Volumes.Single(v=>v.VolumeId==selected.VolumeId);
        var admitted=VerifyScopeDerivation.TryDerive(source,volume).Ok;
        var capability=ApfsTopologyActionContract.Find(ApfsTopologyActionContract.ForBoundOfflineMember(current[0],xid,contracts,
            selected.VolumeId,admitted),ApfsTopologyAction.Manage);
        if(!capability.IsAvailable)throw new InvalidOperationException(capability.Reason);
        return capability;
    }

    private static (DeviceInventory Source,string Xid,Dictionary<string,string> Contracts) Binding(
        StatusChangedPayload status,IReadOnlyList<ApfsControlTarget> targets)
    {
        if(targets.Count==0)throw new InvalidOperationException("A complete bound member set is required.");
        var source=(status.ConnectedInventory??[]).Single(d=>string.Equals(d.Device.DeviceId,targets[0].DeviceId,StringComparison.OrdinalIgnoreCase));
        var container=source.Topology!.Snapshot.Containers.Single(c=>TopologyAdmission.SameUuid(c.Uuid,targets[0].ContainerUuid));
        return (source,container.CheckpointXid!,targets.ToDictionary(t=>t.VolumeId,
            t=>t.ObservationContract??throw new InvalidOperationException("A current member contract is required."),StringComparer.Ordinal));
    }
}
