using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Backend.Native;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal sealed class SystemDataBrowseWorkflow : IDisposable
{
    private readonly NativeSystemDataBrowseLaunch context;
    private readonly Action<SystemDataBrowseSelection> requireOffline;
    internal SystemDataBrowseSelection Selection => context.Selection;

    internal SystemDataBrowseWorkflow(NativeSystemDataBrowseLaunch held,Action<SystemDataBrowseSelection> validate)
    { context=held; requireOffline=validate; RequireCurrent(); }

    internal static SystemDataBrowseSelection ReadSelection(Stream stream)
    {
        using var bytes=new MemoryStream();var buffer=new byte[4096];int n;
        while((n=stream.Read(buffer))!=0){if(bytes.Length+n>16384)throw new InvalidDataException("System/Data selectors exceed 16 KiB.");bytes.Write(buffer,0,n);}
        using var doc=JsonDocument.Parse(bytes.ToArray());
        var names=doc.RootElement.EnumerateObject().Select(p=>p.Name).ToArray();
        if(names.Length!=8 || names.Distinct(StringComparer.Ordinal).Count()!=8)
            throw new InvalidDataException("Select the exact System/Data source and pair context.");
        var selection=doc.RootElement.Deserialize<SystemDataBrowseSelection>(new JsonSerializerOptions{
            PropertyNamingPolicy=JsonNamingPolicy.CamelCase,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow})
            ??throw new InvalidDataException("System/Data selectors are missing.");
        Validate(selection);return selection;
    }

    internal static void Validate(SystemDataBrowseSelection selection)
    {
        NativeSystemDataBrowseLaunch.ValidateSelection(selection.Image,"apfs-container:"+selection.ContainerUuid,
            selection.GroupUuid,selection.SystemOid,selection.DataOid,selection.CheckpointXid);
        if(selection.SourceSizeBytes is <=0 or >NativeSystemDataBrowseLaunch.MaximumImageBytes ||
            selection.SourceSha256 is not {Length:64} || selection.SourceSha256.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidDataException("The exact source size and SHA-256 are required.");
    }

    internal static async Task<NativeSystemDataBrowseLaunch> HoldAsync(SystemDataBrowseSelection selection,CancellationToken token)
    {
        Validate(selection);
        var held=await Task.Run(()=>NativeSystemDataBrowseLaunch.Prepare(selection.Image,"apfs-container:"+selection.ContainerUuid,
            selection.GroupUuid,selection.SystemOid,selection.DataOid,selection.CheckpointXid,token),token).ConfigureAwait(false);
        if(held.Selection!=selection){held.Dispose();throw new InvalidDataException("The selected System/Data image bytes or pair context changed.");}
        return held;
    }

    internal void RequireCurrent(){requireOffline(Selection);context.RequireSource();}

    internal static void RequireOffline(StatusChangedPayload? status,bool connected,SystemDataBrowseSelection selected)
    {
        if(!connected || status is null)throw new InvalidOperationException("Reconnect to the service before browsing the selected pair.");
        static bool Same(string? a,string b)=>string.Equals(a,b,StringComparison.OrdinalIgnoreCase);
        if((status.MountedVolumes??[]).Any(m=>Same(m.DeviceId,selected.Image) && !string.IsNullOrWhiteSpace(m.MountPoint)))
            throw new InvalidOperationException("Unmount every volume on the selected image before System/Data browsing.");
        var devices=(status.ConnectedInventory??[]).Where(d=>Same(d.Device.DeviceId,selected.Image)).ToArray();
        if(devices.Length>1 || devices.Any(d=>!d.Device.IsConnected || !ApfsAccess.Core.TopologyAdmission.Validate(d)))
            throw new InvalidOperationException("The selected image inventory is stale or ambiguous.");
        foreach(var device in devices)
        {
            if(device.Topology is { } topology && !topology.Snapshot.Containers.Any(c=>
                ApfsAccess.Core.TopologyAdmission.SameUuid(c.Uuid,selected.ContainerUuid)&&c.CheckpointXid==selected.CheckpointXid))
                throw new InvalidOperationException("The selected System/Data checkpoint changed. Refresh the pair context.");
        }
    }

    public void Dispose()=>context.Dispose();
}
