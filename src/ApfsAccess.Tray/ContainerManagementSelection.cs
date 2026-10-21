using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal sealed class ContainerManagementSelection
{
    private readonly ContainerVerificationProof membership;
    internal IReadOnlyList<DriveDashboardRow> Rows {get;}
    internal ApfsActionCapability Capability {get;}
    private ContainerManagementSelection(StatusChangedPayload status,IReadOnlyList<DriveDashboardRow> rows)
    {
        if(!DriveDashboardPresenter.ContainerManageAvailable(rows))throw new InvalidOperationException("No eligible offline volume is available for management.");
        membership=ContainerVerificationProof.CaptureForContainer(status,rows[0].DeviceId!,rows[0].CatalogContainerUuid!);
        var expected=membership.Targets.Select(t=>t.VolumeId).ToHashSet(StringComparer.Ordinal);
        var supplied=rows.Select(r=>r.VolumeId).ToHashSet(StringComparer.Ordinal);
        if(supplied.Count!=rows.Count || !supplied.SetEquals(expected))
            throw new InvalidOperationException("The complete current container membership is required.");
        Rows=Array.AsReadOnly(rows.ToArray());
        var member=Resolve(status,Rows.First(r=>r.CanManageOffline).VolumeId);
        Capability=BoundContainerActions.Require(status,membership.Targets,ApfsTopologyAction.Manage,member.VolumeId);
    }
    internal static ContainerManagementSelection Capture(StatusChangedPayload status,IReadOnlyList<DriveDashboardRow> rows)=>new(status,rows);
    internal DriveDashboardRow Resolve(StatusChangedPayload status,string volumeId)
    {
        membership.Revalidate(status);
        var old=Rows.SingleOrDefault(r=>r.VolumeId==volumeId)??throw new InvalidOperationException("Select a current container member.");
        var current=DriveDashboardPresenter.BuildRows(status).Where(r=>DriveDashboardPresenter.RowIdentity(r)==DriveDashboardPresenter.RowIdentity(old)).ToArray();
        if(current.Length!=1 || !current[0].CanManageOffline || current[0].IsMounted ||
            current[0].RecoveryIdentity!=old.RecoveryIdentity || current[0].SnapshotScope!=old.SnapshotScope)
            throw new InvalidOperationException("The selected management volume changed. Refresh before acting.");
        _ = BoundContainerActions.Require(status, membership.Targets, ApfsTopologyAction.Manage, volumeId);
        return current[0];
    }
}

internal sealed class ContainerManagementDialog : Form
{
    private sealed record Choice(DriveDashboardRow Row)
    {public override string ToString()=>$"{Row.VolumeName} | OID {Row.CatalogVolumeObjectId} | {Row.CatalogVolumeUuid}";}
    private readonly ComboBox volume=new(){Dock=DockStyle.Fill,DropDownStyle=ComboBoxStyle.DropDownList};
    internal string? SelectedVolumeId=>(volume.SelectedItem as Choice)?.Row.VolumeId;
    internal ContainerManagementDialog(ContainerManagementSelection selected)
    {
        Text="Manage offline container volume";AutoScaleMode=AutoScaleMode.Dpi;StartPosition=FormStartPosition.CenterParent;
        Size=new(660,260);MinimumSize=new(480,240);MinimizeBox=MaximizeBox=false;
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(12),RowCount=3,ColumnCount=1};
        layout.ColumnStyles.Add(new(SizeType.Percent,100));layout.RowStyles.Add(new(SizeType.Percent,100));
        layout.RowStyles.Add(new(SizeType.AutoSize));layout.RowStyles.Add(new(SizeType.AutoSize));
        var row=selected.Rows[0];layout.Controls.Add(new TextBox{Dock=DockStyle.Fill,ReadOnly=true,Multiline=true,ScrollBars=ScrollBars.Vertical,
            Text=$"Image: {row.DeviceId}\r\nContainer: {row.CatalogContainerUuid}"},0,0);
        foreach(var member in selected.Rows.Where(r=>r.CanManageOffline))volume.Items.Add(new Choice(member));
        volume.SelectedIndex=0;layout.Controls.Add(volume,0,1);
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,WrapContents=true,FlowDirection=FlowDirection.RightToLeft};
        var cancel=new Button{Text="Cancel",AutoSize=true,DialogResult=DialogResult.Cancel};
        var manage=new Button{Text="Manage selected volume",AutoSize=true,DialogResult=DialogResult.OK};
        buttons.Controls.Add(cancel);buttons.Controls.Add(manage);layout.Controls.Add(buttons,0,2);Controls.Add(layout);AcceptButton=manage;CancelButton=cancel;
    }
}
