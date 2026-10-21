using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed partial class TrayApplicationContext
{
    private ToolStripMenuItem? _registerFusionItem;
    private void AddFusionRegistrationMenu(ContextMenuStrip menu)
    {
        _registerFusionItem = new("Register Fusion image pair...", null, async (_, _) => {
            try { await RegisterFusionImageAsync().ConfigureAwait(true); }
            catch (Exception e) { _dashboard?.SetFooter(e.Message); }
        }) { Enabled = false };
        menu.Items.Add(_registerFusionItem);
    }
    private async Task RegisterFusionImageAsync()
    {
        if (!_serviceConnected) throw new IOException("Reconnect to the service before registering an image pair.");
        using var picker = new OpenFileDialog { Title = "Register Fusion image pair", Filter = "Fusion selector profiles (*.json)|*.json", CheckFileExists = true };
        if (picker.ShowDialog(_dashboard) != DialogResult.OK) return;
        using var source = File.OpenRead(picker.FileName);
        var profile = FusionImageRegistration.ReadProfile(source);
        var request = FusionImageRegistration.CreateRequest(profile);
        if (!_serviceConnected) throw new IOException("Service disconnected before registration.");
        var reply = await SendControlRequestAsync(request, null).ConfigureAwait(true);
        ControlOperationReply.RequireSuccess(request, reply);
        await TrySendRefreshAsync(false).ConfigureAwait(true);
        _dashboard?.SetFooter(reply.Diagnostic ?? "Fusion pair registered.");
    }
}
