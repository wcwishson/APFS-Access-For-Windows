using ApfsAccess.Backend.Native;

namespace ApfsAccess.Tray;

internal sealed class SystemDataBrowseDialog : Form
{
    private readonly SystemDataBrowseWorkflow workflow;
    private readonly SystemDataBrowseClient client;
    private readonly Action<string> open;
    private readonly DialogPendingOperation lifetime=new();
    private readonly TextBox scope=new(){Dock=DockStyle.Fill,ReadOnly=true,Multiline=true,WordWrap=false,ScrollBars=ScrollBars.Both};
    private readonly TextBox result=new(){Dock=DockStyle.Fill,ReadOnly=true,Multiline=true,ScrollBars=ScrollBars.Vertical};
    private readonly TextBox destination=new(){Dock=DockStyle.Fill,AccessibleName="New copy destination"};
    private readonly Button browse=new(){Text="Browse read-only",AutoSize=true};
    private readonly Button copy=new(){Text="Copy out",AutoSize=true};
    private readonly Button choose=new(){Text="Destination...",AutoSize=true};
    private readonly Button close=new(){Text="Close",AutoSize=true};
    private readonly Label status=new(){Text="Ready",AutoSize=true,Dock=DockStyle.Fill};
    private readonly System.Windows.Forms.Timer watch=new(){Interval=1000};
    private CancellationTokenSource? operation;
    private bool closeAfterOperation;
    private bool closureUnconfirmed;
    internal Task? Pending=>lifetime.Pending;

    internal SystemDataBrowseDialog(SystemDataBrowseWorkflow selected,Action<string> openPath,SystemDataBrowseClient? browseClient=null)
    {
        workflow=selected;open=openPath;client=browseClient??new();
        Text="System/Data image";StartPosition=FormStartPosition.CenterParent;AutoScaleMode=AutoScaleMode.Dpi;
        Size=new(860,570);MinimumSize=new(600,420);Font=new("Segoe UI",9);MinimizeBox=false;
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(12),ColumnCount=1,RowCount=4};
        layout.ColumnStyles.Add(new(SizeType.Percent,100));layout.RowStyles.Add(new(SizeType.Percent,100));
        layout.RowStyles.Add(new(SizeType.AutoSize));layout.RowStyles.Add(new(SizeType.AutoSize));layout.RowStyles.Add(new(SizeType.AutoSize));
        var tabs=new TabControl{Dock=DockStyle.Fill};var context=new TabPage("Pair context");context.Controls.Add(scope);
        var outcome=new TabPage("Result");outcome.Controls.Add(result);tabs.TabPages.AddRange([context,outcome]);layout.Controls.Add(tabs,0,0);
        var target=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,AutoSize=true};
        target.ColumnStyles.Add(new(SizeType.Percent,100));target.ColumnStyles.Add(new(SizeType.AutoSize));
        target.Controls.Add(destination,0,0);target.Controls.Add(choose,1,0);layout.Controls.Add(target,0,1);
        var commands=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,WrapContents=true};
        commands.Controls.AddRange([browse,copy,close]);layout.Controls.Add(commands,0,2);layout.Controls.Add(status,0,3);Controls.Add(layout);
        layout.SizeChanged+=(_,_)=>status.MaximumSize=new(Math.Max(100,layout.ClientSize.Width-layout.Padding.Horizontal),0);
        var s=workflow.Selection;
        scope.Text=$"Image: {s.Image}\r\nSize: {s.SourceSizeBytes} bytes\r\nSHA-256: {s.SourceSha256}\r\n"+
            $"Container: {s.ContainerUuid}\r\nGroup: {s.GroupUuid}\r\nSystem OID: {s.SystemOid}\r\nData OID: {s.DataOid}\r\nCheckpoint XID: {s.CheckpointXid}\r\n\r\n"+
            "Access: Read-only\r\nAuthority: Canonical System table; native admission required\r\nGenuine Mac corpus: Unverified\r\nUnified mutations: Unsupported\r\nEncrypted and snapshot views: Unsupported";
        browse.Click+=async(_,_)=>await RunAsync(false);copy.Click+=async(_,_)=>await RunAsync(true);
        choose.Click+=(_,_)=>{using var picker=new FolderBrowserDialog{Description="Copy destination parent",UseDescriptionForTitle=true};
            if(picker.ShowDialog(this)==DialogResult.OK)destination.Text=Path.Combine(picker.SelectedPath,"SystemData-"+s.CheckpointXid+"-"+Guid.NewGuid().ToString("N")[..8]);};
        destination.TextChanged+=(_,_)=>UpdateAvailability();
        close.Click+=(_,_)=>{if(operation is null)Close();else{closeAfterOperation=true;operation.Cancel();status.Text="Closing; waiting for native teardown...";}};
        FormClosing+=(_,e)=>{if(operation is not null){e.Cancel=true;closeAfterOperation=true;operation.Cancel();status.Text="Closing; waiting for native teardown...";}};
        watch.Tick+=(_,_)=>RevalidateSelection();Shown+=(_,_)=>watch.Start();UpdateAvailability();
    }

    internal void RevalidateSelection()
    {
        if(!lifetime.ViewAttached)return;
        try{workflow.RequireCurrent();}
        catch(Exception ex){operation?.Cancel();result.Clear();status.Text=ex.Message;browse.Enabled=copy.Enabled=false;}
    }

    private void UpdateAvailability()
    {
        if(!lifetime.ViewAttached)return;
        browse.Enabled=operation is null&&client.Available&&!closureUnconfirmed;
        copy.Enabled=browse.Enabled&&!string.IsNullOrWhiteSpace(destination.Text);
        choose.Enabled=destination.Enabled=operation is null;
        if(!client.Available)status.Text="The packaged System/Data CLI is unavailable.";
        try{workflow.RequireCurrent();}catch(Exception ex){browse.Enabled=copy.Enabled=false;status.Text=ex.Message;}
    }

    internal async Task RunAsync(bool copying)
    {
        if(operation is not null||!lifetime.ViewAttached||closureUnconfirmed)return;
        using var stop=new CancellationTokenSource();operation=stop;result.Clear();UpdateAvailability();close.Text="Cancel";
        var s=workflow.Selection;var target=copying?destination.Text:null;var mayClose=true;
        void Current()
        {
            if(!lifetime.ViewAttached||IsDisposed||Disposing||Owner is {IsDisposed:true}||Owner is {Disposing:true})
                throw new OperationCanceledException("The System/Data view is closed.",stop.Token);
            workflow.RequireCurrent();
        }
        try
        {
            Current();status.Text=copying?"Copying System/Data...":"Opening System/Data read-only...";
            var request=new SystemDataBrowseRequest(s,Path.Combine(Path.GetTempPath(),"ApfsAccess","SystemDataGui",Guid.NewGuid().ToString("N")),target);
            var pending=client.RunAsync(request,path=>{Current();status.Text="Browsing read-only; native owner active.";open(path);},Current,stop.Token);
            lifetime.Observe(pending);var completed=await pending.ConfigureAwait(true);Current();stop.Token.ThrowIfCancellationRequested();
            lifetime.UpdateView(()=>{result.Text=completed.Destination is null?"Browse closed. Native teardown confirmed.\r\nEvidence: "+completed.Evidence:
                $"Copied {completed.Files} files, {completed.Directories} directories, {completed.Bytes} bytes.\r\nDestination: {completed.Destination}\r\nNative teardown confirmed.\r\nEvidence: {completed.Evidence}";
                status.Text=completed.Destination is null?"Closed; native teardown confirmed.":"Copy complete; native teardown confirmed.";});
        }
        catch(SystemDataBrowseException ex){mayClose=ex.TeardownConfirmed;closureUnconfirmed=!ex.TeardownConfirmed;
            lifetime.UpdateView(()=>{result.Clear();status.Text=ex.Message+(copying?" Copy destination may be partial.":"");});}
        catch(OperationCanceledException ex){lifetime.UpdateView(()=>{result.Clear();status.Text=ex.Message;});}
        catch(Exception ex){lifetime.UpdateView(()=>{result.Clear();status.Text=ex.Message+(copying?" Copy destination may be partial.":"");});}
        finally
        {
            operation=null;
            lifetime.UpdateView(()=>{close.Text="Close";UpdateAvailability();if(closeAfterOperation&&mayClose)Close();});
        }
    }

    protected override void Dispose(bool disposing)
    {
        if(disposing){lifetime.Detach(()=>operation?.Cancel());watch.Dispose();workflow.Dispose();}
        base.Dispose(disposing);
    }
}
