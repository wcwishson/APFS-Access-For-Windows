namespace ApfsAccess.Tray;

public sealed partial class TrayApplicationContext
{
    private void AddProfileVerificationMenu(ContextMenuStrip menu)
    {
        var item=new ToolStripMenuItem("Verify Fusion image profile...",null,(_,_)=>
        {
            try
            {
                using var picker=new OpenFileDialog{Title="Current Fusion image selectors",Filter="Profile selectors (*.json)|*.json",CheckFileExists=true,Multiselect=false};
                if(picker.ShowDialog(_dashboard)!=DialogResult.OK)return;
                using var stream=File.OpenRead(picker.FileName);var selected=ProfileVerificationSelection.ReadFusion(stream);
                using var dialog=new ProfileVerificationDialog(selected,null,selected.RequireCurrentSources,_dashboard.IsDarkMode);
                dialog.ShowDialog(_dashboard);
            }
            catch(Exception ex){_dashboard.SetFooter(ex.Message);}
        });
        menu.Items.Add(item);
    }

    private Task VerifySelectedProfileAsync(DriveDashboardRow selected)
    {
        void Current()=>DriveDashboardPresenter.RequireCurrentProfileRow(
            _latestStatus??throw new InvalidOperationException("Service status is unavailable."),selected,_serviceConnected);
        Current();var profile=selected.RegisteredFusion is { } fusion?ProfileVerificationSelection.Registered(fusion):
            ProfileVerificationSelection.Registered(selected.RegisteredImage!);
        void BoundCurrent(){Current();if(selected.RegisteredFusion is not null)profile.RequireCurrentSources();}
        using var dialog=new ProfileVerificationDialog(profile,selected.RegisteredImage is null?null:selected,BoundCurrent,_dashboard.IsDarkMode);
        dialog.ShowDialog(_dashboard);return Task.CompletedTask;
    }
}
