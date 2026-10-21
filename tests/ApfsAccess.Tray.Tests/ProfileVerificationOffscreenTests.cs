using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Forms;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Tray.Tests;

public sealed class ProfileVerificationOffscreenTests
{
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    private static ApfsCurrentProfileVerificationRequest Request()=>new("fusion-clean-cache",
        @"D:\Private APFS fixtures\main image with a representative long name.apfs",
        "apfs-container:"+new string('a',32),new string('b',32),"101","7","0","131072",
        @"D:\Private APFS fixtures\tier2 image with a representative long name.apfs","0","32768",new string('c',32),
        "linux-apfs-last-byte-low-bit"){
            ExpectedMainIdentity="windows-file:1:2:131072:3",ExpectedTier2Identity="windows-file:1:4:32768:3"};

    private static ProfileVerificationClient Client(bool available=true)=>new(available,
        (_,_,_)=>throw new InvalidOperationException("Offscreen rendering cannot launch native work."));

    private static ProfileVerificationDisplay Current(ApfsCurrentProfileVerificationRequest request)
    {
        var value=ProfileVerificationTests.Report(request);
        foreach(var row in value["coverage"]!.AsArray())
            row!["scopeDetail"]="Canonical checksum, exact source and generation, complete separator routing, namespace links, stream owners and allocation checks; Apple policy amounts remain unknown.";
        var result=NativeApfsImageVerifier.ValidateCurrentProfileReport(value.ToJsonString(),0,request,
            request.ExpectedMainIdentity!,request.ExpectedTier2Identity);
        return new(result.Outcome,result.Report);
    }

    private static void Sta(Action action)
    {
        Exception? failure=null;
        var thread=new Thread(()=>{try{action();}catch(Exception ex){failure=ex;}});
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure is not null)ExceptionDispatchInfo.Capture(failure).Throw();
    }

    [Fact]
    public void RealFormInvalidatesPublishedRowsAndModeChangesCannotRetainOldSuccess()
    {
        Sta(()=>{
            var request=Request();var current=true;
            using var form=new ProfileVerificationDialog(new(request),null,
                ()=>{if(!current)throw new InvalidOperationException("The selected image is no longer locked and offline.");},false,Client());
            var grids=Descendants(form).OfType<DataGridView>().ToArray();
            var selector=Descendants(form).OfType<ComboBox>().Single();
            var text=Descendants(form).OfType<TextBox>().Single(t=>t.Multiline);
            form.DisplayResult(Current(request),false);
            Assert.NotNull(grids[0].DataSource);Assert.Contains("Covered volumes",text.Text);
            selector.SelectedIndex=1;
            Assert.All(grids,g=>Assert.Null(g.DataSource));Assert.DoesNotContain("Covered volumes",text.Text);
            form.DisplayResult(Current(request),false);current=false;form.RevalidateDisplayedSelection();
            Assert.All(grids,g=>Assert.Null(g.DataSource));Assert.Contains("offline",text.Text);
            Assert.DoesNotContain("Covered volumes",text.Text);
            Assert.False(form.Visible);
        });
    }

    private static IEnumerable<Control> Descendants(Control parent)
    {
        foreach(Control child in parent.Controls)
        {
            yield return child;
            foreach(var nested in Descendants(child))yield return nested;
        }
    }

    private sealed record BoundsRow(string Path,string Type,string Text,Rectangle Bounds,Size Preferred,
        bool WithinParent,bool? TextFits,bool IntentionalEllipsis,bool Scrollable);
    private sealed record OverlapRow(string Parent,string First,string Second,Rectangle Intersection);
    private sealed record RenderRow(string State,int RequestedDpi,int ActualDeviceDpi,string DpiMethod,
        Size LogicalSize,int Tab,string Bitmap,int ShownEvents,int ActivatedEvents,bool Visible,
        bool ForegroundUnchanged,int NonBackgroundPixels,BoundsRow[] Bounds,OverlapRow[] Overlaps,string[] Errors);

    // Invoked explicitly by the private visual gate after Root allocates its slot.
    // It constructs the production form and does not enter a desktop message loop.
    public static void RenderOffscreen(string outputFolder)
    {
        var output=Path.GetFullPath(outputFolder);
        if(!output.StartsWith(@"D:\ApfsAccessScratch\",StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Offscreen artifacts require the private D: evidence root.");
        if(Directory.Exists(output))throw new IOException("Preserve existing offscreen evidence.");
        var rows=new List<RenderRow>();
        Sta(()=>{
            Directory.CreateDirectory(output);
            var main=Path.Combine(output,"synthetic main image with a representative long name.bin");
            var tier=Path.Combine(output,"synthetic tier2 image with a representative long name.bin");
            using(var file=File.Create(main))file.SetLength(131072);
            using(var file=File.Create(tier))file.SetLength(32768);
            var bound=NativeApfsImageVerifier.CaptureCurrentProfileBindings(Request() with{
                Image=main,Tier2Image=tier,ExpectedMainIdentity=null,ExpectedTier2Identity=null});
            foreach(var dpi in new[]{96,144,192})
            foreach(var state in new[]{"ready","current","history","refused","stale","cancelled","unavailable"})
            {
                var request=bound;var current=true;var shown=0;var activated=0;
                using var form=new ProfileVerificationDialog(new(request),null,
                    ()=>{if(!current)throw new InvalidOperationException("The registered image changed. Lock the writable image and keep it offline before verifying again.");},
                    dpi==192,Client(state!="unavailable"));
                var foreground=GetForegroundWindow();
                using var host=new Panel();form.TopLevel=false;host.Controls.Add(form);
                form.ShowInTaskbar=false;form.Shown+=(_,_)=>++shown;form.Activated+=(_,_)=>++activated;
                var selector=Descendants(form).OfType<ComboBox>().Single();
                if(state=="history")
                {
                    selector.SelectedIndex=1;
                    Descendants(form).OfType<NumericUpDown>().Single().Value=5;
                    var history=ProfileVerificationTests.History(request);
                    var parsed=NativeApfsImageVerifier.ValidateRetainedProfileReport(history.Report.GetRawText(),0,new(request,"5"),
                        request.ExpectedMainIdentity!,request.ExpectedTier2Identity);
                    form.DisplayResult(new(parsed.Outcome,parsed.Report),true);
                }
                else if(state is "current" or "stale")form.DisplayResult(Current(request),false);
                else if(state=="refused")
                {
                    var value=ProfileVerificationTests.Report(request);
                    value["outcome"]=(int)ApfsVerificationOutcome.Refused;value["outcomeName"]="Refused";value["selected"]=null;value["counts"]=null;
                    foreach(var row in value["coverage"]!.AsArray())if(row!["required"]!.GetValue<bool>())
                        row["state"]=row["check"]!.GetValue<int>()==16?4:1;
                    value["findings"]=JsonSerializer.SerializeToNode(new[]{new{code=20,severity=2,check=16,volumeOid="101",objectId=(string?)null,
                        physicalBlock=(string?)null,checkpointXid="7",failedSourceOffsetBytes=(string?)null,
                        detail="Fusion member identity or exact selected generation is unavailable. No complete accounting was produced."}});
                    var parsed=NativeApfsImageVerifier.ValidateCurrentProfileReport(value.ToJsonString(),4,request,
                        request.ExpectedMainIdentity!,request.ExpectedTier2Identity);
                    form.DisplayResult(new(parsed.Outcome,parsed.Report),false);
                }
                else if(state=="cancelled")form.DisplayFailure(new OperationCanceledException());
                if(state=="stale"){current=false;form.RevalidateDisplayedSelection();}
                var tabs=Descendants(form).OfType<TabControl>().Single();
                var pages=state is "current" or "history"?new[]{0,1}:state=="refused"?new[]{2}:new[]{0};
                var scale=dpi/96f;
                form.AutoScaleMode=AutoScaleMode.None;
                _=form.Handle;
                form.BindingContext=new BindingContext();
                form.Scale(new SizeF(scale,scale));
                using var font=new Font(form.Font.FontFamily,9*dpi/(float)form.DeviceDpi,FontStyle.Regular,GraphicsUnit.Point);
                form.Font=font;
                foreach(var control in Descendants(form))_=control.Handle;
                var sizes=state is "current" or "history" or "refused"?new[]{new Size(860,620),new Size(620,420)}:new[]{new Size(860,620)};
                foreach(var logicalSize in sizes)
                foreach(var page in pages)
                {
                    form.Size=new((int)(logicalSize.Width*scale),(int)(logicalSize.Height*scale));host.Size=form.Size;
                    tabs.SelectedIndex=page;form.PerformLayout();
                    foreach(var control in Descendants(form).Reverse())control.PerformLayout();
                    var bitmap=Path.Combine(output,$"{state}-{dpi}-{logicalSize.Width}x{logicalSize.Height}-tab{page}.png");
                    var painted=0;
                    using(var image=new Bitmap(form.Width,form.Height))
                    {
                        image.SetResolution(dpi,dpi);form.DrawToBitmap(image,new Rectangle(Point.Empty,image.Size));
                        var background=form.BackColor.ToArgb();
                        for(var y=40;y<image.Height-40;y+=4)for(var x=20;x<image.Width-20;x+=4)
                            if(image.GetPixel(x,y).ToArgb()!=background)++painted;
                        image.Save(bitmap,ImageFormat.Png);
                    }
                    var bounds=new List<BoundsRow>();var overlaps=new List<OverlapRow>();var errors=new List<string>();
                    Inspect(form,"Form",page,selector.SelectedIndex==1,bounds,overlaps,errors);
                    if(form.Visible||shown!=0||activated!=0)errors.Add("The form was shown or activated.");
                    var foregroundUnchanged=foreground==GetForegroundWindow();
                    if(!foregroundUnchanged)errors.Add("Foreground window changed during offscreen rendering.");
                    if(painted<300)errors.Add("Native child controls were not painted.");
                    rows.Add(new(state,dpi,form.DeviceDpi,"Control.Scale from 96-DPI design plus font normalization to actual DeviceDpi; hidden production form, no monitor transition",
                        logicalSize,page,bitmap,shown,activated,form.Visible,foregroundUnchanged,painted,bounds.ToArray(),overlaps.ToArray(),errors.ToArray()));
                }
            }
        });
        File.WriteAllText(Path.Combine(output,"layout.json"),JsonSerializer.Serialize(new{
            format="apfs-access-profile-verification-offscreen-layout",version=1,screenAutomation=false,showOrActivate=false,
            settingsWrites=false,deviceActions=false,functionalPublicRouteGate=false,syntheticRegularFileBytes=163840,
            productionFormAssembly=typeof(ProfileVerificationDialog).Assembly.Location,
            nativeDrawToBitmapLimitation="Hidden native combo/edit interiors may omit text; managed values and measured bounds are recorded separately. No substitute renderer.",
            rows},new JsonSerializerOptions{WriteIndented=true}));
        Assert.All(rows,row=>Assert.Empty(row.Errors));
    }

    private static void Inspect(Control parent,string path,int selectedTab,bool retained,List<BoundsRow> rows,
        List<OverlapRow> overlaps,List<string> errors)
    {
        var children=parent.Controls.Cast<Control>().Where(c=>
            (parent is not TabControl tabs||ReferenceEquals(c,tabs.SelectedTab))&&
            (retained||c is not NumericUpDown&&!(c is Label label&&label.Text=="From XID"))).ToArray();
        for(var i=0;i<children.Length;++i)
        {
            var child=children[i];var name=path+"/"+child.GetType().Name+"["+i+"]";
            var contained=parent.ClientRectangle.Contains(child.Bounds);
            var scrollable=child is TextBox or DataGridView;
            bool? fits=null;var ellipsis=child is Label{AutoEllipsis:true};
            if(child is Button or Label)
            {
                var preferred=TextRenderer.MeasureText(child.Text,child.Font,Size.Empty,TextFormatFlags.SingleLine|TextFormatFlags.NoPadding);
                fits=preferred.Width<=child.ClientSize.Width&&preferred.Height<=child.ClientSize.Height;
                if(fits==false&&!ellipsis)errors.Add(name+": fixed text does not fit.");
            }
            if(child is ComboBox or NumericUpDown)
            {
                var measured=TextRenderer.MeasureText(child.Text,child.Font,Size.Empty,TextFormatFlags.SingleLine|TextFormatFlags.NoPadding);
                fits=measured.Width<=child.ClientSize.Width-20&&measured.Height<=child.ClientSize.Height;
                if(fits==false)errors.Add(name+": selector text does not fit.");
            }
            if(!contained&&child is not TabPage)errors.Add(name+": bounds leave the parent client area.");
            rows.Add(new(name,child.GetType().Name,child.Text,child.Bounds,child.GetPreferredSize(Size.Empty),contained,fits,ellipsis,scrollable));
            if(child is DataGridView grid)
            {
                foreach(DataGridViewColumn column in grid.Columns)
                {
                    var box=grid.GetCellDisplayRectangle(column.Index,-1,false);
                    if(box.Width<=0||box.Height<=0)box=new(1+grid.Columns.Cast<DataGridViewColumn>().Take(column.Index).Sum(c=>c.Width),
                        1,column.Width,grid.ColumnHeadersHeight);
                    var measured=TextRenderer.MeasureText(column.HeaderText,grid.ColumnHeadersDefaultCellStyle.Font??grid.Font,
                        new Size(Math.Max(1,box.Width-8),int.MaxValue),TextFormatFlags.WordBreak|TextFormatFlags.NoPadding|TextFormatFlags.NoPrefix);
                    rows.Add(new(name+"/Header/"+column.Name,"GridHeader",column.HeaderText,box,measured,true,
                        measured.Width<=box.Width&&measured.Height<=box.Height,false,true));
                }
                foreach(DataGridViewRow row in grid.Rows)foreach(DataGridViewCell cell in row.Cells)
                {
                    var box=grid.GetCellDisplayRectangle(cell.ColumnIndex,cell.RowIndex,false);
                    if(box.Width<=0||box.Height<=0)box=new(1+grid.Columns.Cast<DataGridViewColumn>().Take(cell.ColumnIndex).Sum(c=>c.Width),
                        1+grid.ColumnHeadersHeight+grid.Rows.Cast<DataGridViewRow>().Take(cell.RowIndex).Sum(r=>r.Height),
                        grid.Columns[cell.ColumnIndex].Width,row.Height);
                    var text=cell.FormattedValue?.ToString()??"";
                    var measured=cell is DataGridViewCheckBoxCell?cell.PreferredSize:
                        TextRenderer.MeasureText(text,cell.InheritedStyle.Font??grid.Font,new Size(Math.Max(1,box.Width-8),int.MaxValue),
                            TextFormatFlags.WordBreak|TextFormatFlags.NoPadding|TextFormatFlags.NoPrefix);
                    rows.Add(new(name+"/Cell/"+cell.RowIndex+"/"+cell.ColumnIndex,cell.GetType().Name,text,box,measured,true,
                        cell is DataGridViewCheckBoxCell?null:measured.Width<=box.Width&&measured.Height<=box.Height,false,true));
                }
            }
            for(var j=i+1;j<children.Length;++j)
            {
                var intersection=Rectangle.Intersect(child.Bounds,children[j].Bounds);
                if(intersection.Width>0&&intersection.Height>0)
                {overlaps.Add(new(path,name,children[j].GetType().Name+"["+j+"]",intersection));errors.Add(path+": sibling controls overlap.");}
            }
            if(child is not TextBox and not DataGridView and not NumericUpDown and not ComboBox)
                Inspect(child,name,selectedTab,retained,rows,overlaps,errors);
        }
    }
}
