using ApfsAccess.Backend.Native;

namespace ApfsAccess.Tray;

internal sealed class ProfileVerificationDialog : Form
{
    private sealed record VerificationMode(string Label,bool Snapshots,bool Retained)
    {public override string ToString()=>Label;}
    private VerificationMode SelectedMode=>(VerificationMode)mode.SelectedItem!;
    private readonly ProfileVerificationClient client;
    private readonly ProfileVerificationSelection selection;
    private readonly DriveDashboardRow? encryptedRow;
    private readonly Action requireCurrent;
    private readonly bool dark;
    private readonly string selectionScope;
    private readonly Button verify=new(){Text="Verify",AutoSize=true};
    private readonly Button close=new(){Text="Close",AutoSize=true};
    private readonly Label status=new(){Text="Ready",Dock=DockStyle.Fill,AutoEllipsis=true,TextAlign=ContentAlignment.MiddleLeft};
    private readonly TextBox scope=new(){ReadOnly=true,Multiline=true,Dock=DockStyle.Fill,ScrollBars=ScrollBars.Both,WordWrap=false};
    private readonly DataGridView coverage=Grid(),findings=Grid();
    private readonly ComboBox mode=new(){DropDownStyle=ComboBoxStyle.DropDownList,Width=220};
    private readonly NumericUpDown fromXid=new(){Minimum=1,Maximum=ulong.MaxValue,Width=180};
    private CancellationTokenSource? operation;
    private bool closeAfterCancel;
    private bool hasResult;
    private readonly DialogPendingOperation lifetime=new();
    private readonly System.Windows.Forms.Timer selectionWatch=new(){Interval=1000};

    internal ProfileVerificationDialog(ProfileVerificationSelection selected,DriveDashboardRow? row,Action validate,
        bool isDark,ProfileVerificationClient? verificationClient=null)
    {
        selection=selected;encryptedRow=row;requireCurrent=validate;dark=isDark;client=verificationClient??new();
        Text="Verify image profile";StartPosition=FormStartPosition.CenterParent;AutoScaleMode=AutoScaleMode.Dpi;
        Size=new(860,620);MinimumSize=new(620,420);MinimizeBox=false;MaximizeBox=true;Font=new("Segoe UI",9);
        var theme=dark?DashboardTheme.Dark:DashboardTheme.Light;BackColor=theme.WindowBackground;ForeColor=theme.TextPrimary;
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=4,Padding=new(12)};
        layout.ColumnStyles.Add(new(SizeType.Percent,100));
        layout.RowStyles.Add(new(SizeType.AutoSize));layout.RowStyles.Add(new(SizeType.Percent,100));layout.RowStyles.Add(new(SizeType.Absolute,30));layout.RowStyles.Add(new(SizeType.AutoSize));
        mode.Items.Add(new VerificationMode("Current metadata",false,false));
        var endpoint=ulong.Parse(selection.Request.CheckpointXid,System.Globalization.CultureInfo.InvariantCulture);
        if(endpoint>1){mode.Items.Add(new VerificationMode("Retained checkpoint chain",false,true));fromXid.Maximum=endpoint-1;fromXid.Value=endpoint-1;}
        mode.Items.Add(new VerificationMode("Visible snapshots",true,false));
        if(endpoint>1)mode.Items.Add(new VerificationMode("Retained snapshot graphs",true,true));
        mode.SelectedIndex=0;fromXid.Visible=false;
        var fromLabel=new Label{Text="From XID",AutoSize=true,Visible=false,Margin=new(10,6,3,0)};
        var selector=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,WrapContents=true,Margin=new(0,0,0,8)};
        selector.Controls.Add(mode);selector.Controls.Add(fromLabel);selector.Controls.Add(fromXid);
        var tabs=new TabControl{Dock=DockStyle.Fill};
        foreach(var pair in new[]{("Scope",(Control)scope),("Coverage",(Control)coverage),("Findings",(Control)findings)})
        {var page=new TabPage(pair.Item1){Padding=new(8),BackColor=theme.WindowBackground};page.Controls.Add(pair.Item2);tabs.TabPages.Add(page);}
        var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,FlowDirection=FlowDirection.RightToLeft,WrapContents=false};
        buttons.Controls.Add(close);buttons.Controls.Add(verify);layout.Controls.Add(selector,0,0);layout.Controls.Add(tabs,0,1);layout.Controls.Add(status,0,2);layout.Controls.Add(buttons,0,3);Controls.Add(layout);
        var r=selection.Request;
        scope.Text=$"{r.Profile}\r\nContainer {r.ContainerId}\r\nVolume {r.VolumeUuid} / OID {r.VolumeOid} / XID {r.CheckpointXid}\r\n"+
            $"Main: {r.Image}\r\n{r.ExpectedMainIdentity??selection.WritableRegistration?.SourceId}\r\nOffset {r.StoreOffsetBytes}, size {r.StoreSizeBytes} bytes\r\n"+
            (r.Tier2Image is null?"":$"Tier2: {r.Tier2Image}\r\n{r.ExpectedTier2Identity}\r\nOffset {r.Tier2OffsetBytes}, size {r.Tier2SizeBytes} bytes\r\nFusion {r.FusionUuid}\r\n")+
            "\r\nSnapshot allocation charge: Unknown\r\nApple purgeable: Unknown\r\nReclaimable: Unknown";
        selectionScope=scope.Text;
        mode.SelectedIndexChanged+=(_,_)=>{fromXid.Visible=fromLabel.Visible=SelectedMode.Retained;ClearResult();};
        fromXid.ValueChanged+=(_,_)=>ClearResult();
        verify.Enabled=client.Available;if(!client.Available)status.Text="Packaged current-profile observer unavailable.";
        verify.Click+=async(_,_)=>await RunAsync();
        close.Click+=(_,_)=>{if(operation is null)Close();else{closeAfterCancel=true;operation.Cancel();status.Text="Cancelling...";}};
        FormClosing+=(_,e)=>{if(operation is not null){e.Cancel=true;closeAfterCancel=true;operation.Cancel();}};
        AcceptButton=verify;CancelButton=close;
        Shown+=(_,_)=>{DashboardTheme.ApplyImmersiveDarkMode(Handle,dark);selectionWatch.Start();};
        selectionWatch.Tick+=(_,_)=>{if(hasResult||operation is not null)RevalidateDisplayedSelection();};
        Disposed+=(_,_)=>selectionWatch.Dispose();
        foreach(var button in new[]{verify,close})
        {button.FlatStyle=FlatStyle.Flat;button.BackColor=theme.ButtonBackground;button.ForeColor=theme.ButtonText;button.FlatAppearance.BorderColor=theme.ButtonBorder;}
        foreach(var control in new Control[]{scope,coverage,findings}){control.BackColor=theme.DetailsBackground;control.ForeColor=theme.DetailsText;}
    }

    private static DataGridView Grid()
    {
        var grid=new DataGridView{Dock=DockStyle.Fill,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,
            AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.AllCells,
            ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.AutoSize,
            RowHeadersVisible=false,SelectionMode=DataGridViewSelectionMode.FullRowSelect,
            DefaultCellStyle=new(){WrapMode=DataGridViewTriState.True}};
        void Columns()
        {
            if(!grid.IsHandleCreated||grid.DataSource is null||grid.Disposing)return;
            foreach(DataGridViewColumn column in grid.Columns)
            {
                if(column.DataGridView!=grid)continue;
                var wide=column.Name is "Scope" or "Detail";
                column.MinimumWidth=wide?Math.Max(180,grid.Font.Height*12):
                    Math.Max(56,TextRenderer.MeasureText(column.HeaderText,grid.Font).Width+16);
                column.FillWeight=wide?3:1;
            }
        }
        grid.DataBindingComplete+=(_,_)=>Columns();grid.FontChanged+=(_,_)=>Columns();grid.HandleCreated+=(_,_)=>Columns();
        return grid;
    }

    internal void ClearResult()
    {
        if(!lifetime.ViewAttached)return;
        hasResult=false;
        coverage.DataSource=null;findings.DataSource=null;scope.Text=selectionScope;
        status.Text=client.Available?"Ready":"Packaged current-profile observer unavailable.";
    }

    internal void RevalidateDisplayedSelection()
    {
        if(!lifetime.ViewAttached)return;
        try{requireCurrent();}
        catch(Exception ex){operation?.Cancel();DisplayFailure(ex);}
    }

    internal void DisplayFailure(Exception error)
    {
        if(!lifetime.ViewAttached)return;
        ClearResult();
        status.Text=error is OperationCanceledException?"Cancelled":error.Message;
        if(error is not OperationCanceledException)scope.AppendText("\r\n\r\n"+error.Message);
    }

    internal void DisplayResult(ProfileVerificationDisplay result,bool retained)
    {
        if(!lifetime.ViewAttached)return;
        scope.Text=result.Scope+"\r\n\r\n"+result.Policy;
        coverage.DataSource=result.Report.GetProperty("coverage").EnumerateArray().Select(c=>new{
            Check=c.GetProperty("check").GetInt32(),Implemented=c.GetProperty("implemented").GetBoolean(),
            Required=c.GetProperty("required").GetBoolean(),State=StateName(c.GetProperty("state").GetInt32()),Scope=c.GetProperty("scopeDetail").GetString()}).ToList();
        findings.DataSource=result.Report.GetProperty("findings").EnumerateArray().Select(f=>new{
            Code=f.GetProperty("code").GetInt32(),Severity=f.GetProperty("severity").GetInt32() switch{1=>"Information",2=>"Warning",_=>"Error"},Check=f.GetProperty("check").GetInt32(),
            Detail=f.GetProperty("detail").GetString(),Volume=f.GetProperty("volumeOid").ToString(),
            Object=f.GetProperty("objectId").ToString(),Block=f.GetProperty("physicalBlock").ToString(),Xid=f.GetProperty("checkpointXid").ToString(),
            ReadOffset=f.GetProperty("failedSourceOffsetBytes").ToString()}).ToList();
        var snapshots=result.Report.GetProperty("format").GetString()=="apfs-access-visible-snapshot-profile-verification";
        status.Text=$"{result.Outcome}: {(snapshots?"visible snapshot graph":retained?"requested checkpoint chain":"current profile scope")}";
        hasResult=true;
    }

    private async Task RunAsync()
    {
        if(operation is not null||!lifetime.ViewAttached)return;
        ClearResult();
        using var stop=new CancellationTokenSource();
        operation=stop;verify.Enabled=false;mode.Enabled=fromXid.Enabled=false;close.Text="Cancel";
        var requestedMode=SelectedMode;var retained=requestedMode.Retained;
        var requestedFrom=fromXid.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        void ValidateViewSelection()
        {
            if(!lifetime.ViewAttached||IsDisposed||Disposing||Owner is {IsDisposed:true}||Owner is {Disposing:true})
                throw new OperationCanceledException("The verification view is closed.",stop.Token);
            requireCurrent();
        }
        try
        {
            ValidateViewSelection();
            using var credential=encryptedRow is null?null:EncryptedPasswordPrompt.Show(this,encryptedRow,dark);
            if(encryptedRow is not null && credential is null){status.Text="Cancelled";return;}
            status.Text="Verifying...";
            var pending=requestedMode.Snapshots?
                client.RunVisibleSnapshotsAsync(selection,retained?requestedFrom:null,credential,ValidateViewSelection,stop.Token):retained?
                client.RunRetainedAsync(selection,requestedFrom,credential,ValidateViewSelection,stop.Token):
                client.RunAsync(selection,credential,ValidateViewSelection,stop.Token);
            lifetime.Observe(pending);
            var result=await pending;
            ValidateViewSelection();stop.Token.ThrowIfCancellationRequested();
            lifetime.UpdateView(()=>DisplayResult(result,retained));
        }
        catch(Exception ex){lifetime.UpdateView(()=>DisplayFailure(ex));}
        finally
        {
            operation=null;
            lifetime.UpdateView(()=>{verify.Enabled=client.Available;mode.Enabled=fromXid.Enabled=true;close.Text="Close";
                if(closeAfterCancel)Close();});
        }
    }
    protected override void Dispose(bool disposing)
    {
        if(disposing){lifetime.Detach(()=>operation?.Cancel());selectionWatch.Dispose();}
        base.Dispose(disposing);
    }
    private static string StateName(int state)=>state switch
    {1=>"Unproven",2=>"Verified",3=>"Inconsistent",4=>"Unsupported",5=>"Not requested",_=>state.ToString(System.Globalization.CultureInfo.InvariantCulture)};
}
