using System.Diagnostics;

namespace ApfsAccess.Tray;

public sealed partial class TrayApplicationContext
{
    private void AddSystemDataBrowseMenu(ContextMenuStrip menu)
    {
        menu.Items.Add(new ToolStripMenuItem("Browse System/Data image...",null,async(_,_)=>
        {
            try
            {
                using var picker=new OpenFileDialog{Title="Exact System/Data pair context",Filter="Pair context (*.json)|*.json",CheckFileExists=true,Multiselect=false};
                if(picker.ShowDialog(_dashboard)!=DialogResult.OK)return;
                ApfsAccess.Backend.Native.SystemDataBrowseSelection selected;
                using(var source=File.OpenRead(picker.FileName))selected=SystemDataBrowseWorkflow.ReadSelection(source);
                void Current(ApfsAccess.Backend.Native.SystemDataBrowseSelection s)=>SystemDataBrowseWorkflow.RequireOffline(_latestStatus,_serviceConnected,s);
                Current(selected);
                using var held=await SystemDataBrowseWorkflow.HoldAsync(selected,_shutdownCts.Token).ConfigureAwait(true);
                if(_dashboard.IsDisposed||_dashboard.Disposing||_shutdownCts.IsCancellationRequested)return;
                using var workflow=new SystemDataBrowseWorkflow(held,Current);
                using var dialog=new SystemDataBrowseDialog(workflow,path=>Process.Start(new ProcessStartInfo("explorer.exe",path){UseShellExecute=true}));
                dialog.ShowDialog(_dashboard);
            }
            catch(Exception ex){if(!_dashboard.IsDisposed&&!_dashboard.Disposing)_dashboard.SetFooter(ex.Message);}
        }));
    }
}
