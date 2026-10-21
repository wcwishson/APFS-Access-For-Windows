using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed partial class TrayApplicationContext
{
    private void AddImageKeyManagementMenu(ContextMenuStrip menu)
    {
        var keys = new ToolStripMenuItem("Image encryption");
        foreach (var (title, action) in new[]
        {
            ("Change image password...", ImageKeyManagementAction.ChangePassword),
            ("Rotate image key...", ImageKeyManagementAction.RotateVolumeKey),
            ("Encrypt image...", ImageKeyManagementAction.Encrypt),
            ("Decrypt image...", ImageKeyManagementAction.Decrypt)
        })
        {
            keys.DropDownItems.Add(new ToolStripMenuItem(title, null, async (_, _) =>
            {
                try { await ManageImageKeysAsync(action).ConfigureAwait(true); }
                catch (OperationCanceledException) { }
                catch { if (!_dashboard.IsDisposed) _dashboard.SetFooter("Image key management did not finish. Refresh the image status."); }
            }));
        }
        menu.Items.Add(keys);
    }

    private async Task ManageImageKeysAsync(ImageKeyManagementAction action)
    {
        if (!_serviceConnected || _shutdownCts.IsCancellationRequested)
            throw new IOException("The service is unavailable.");
        using var picker = new OpenFileDialog { Title = "Image endpoint or writable profile", Filter = "Image selectors (*.json)|*.json",
            CheckFileExists = true, Multiselect = false };
        if (picker.ShowDialog(_dashboard) != DialogResult.OK) return;
        ImageKeyManagementEndpoint selected;
        using (var input = File.OpenRead(picker.FileName)) selected = ImageKeyManagementSelection.Read(input);
        using var observation = CancellationTokenSource.CreateLinkedTokenSource(_shutdownCts.Token);
        observation.CancelAfter(TimeSpan.FromSeconds(30));
        selected = await ImageKeyManagementControlClient.ObserveAsync(selected, observation.Token).ConfigureAwait(true);
        if (_dashboard.IsDisposed || _shutdownCts.IsCancellationRequested) return;
        var request = new ImageKeyManagementRequest(Guid.NewGuid().ToString("D"), action, selected);
        if (!request.IsValid()) throw new IOException("This action does not match the current image encryption mode.");
        var latest = selected;
        using var dialog = new ImageKeyManagementDialog(Path.GetFileName(selected.ImagePath), selected, action,
            async (operation, credentials, cancellation) =>
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellation, _shutdownCts.Token);
                var result = await ImageKeyManagementControlClient.ManageAsync(operation, credentials, linked.Token).ConfigureAwait(false);
                if (!result.Success || result.KeyManagementReceipt is not { } receipt || !receipt.Proves(operation))
                    throw new IOException("The operation lacks a complete native receipt.");
                latest = receipt.After;
                return receipt;
            }, async cancellation =>
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellation, _shutdownCts.Token);
                return await ImageKeyManagementControlClient.ObserveAsync(latest, linked.Token).ConfigureAwait(false);
            }, _dashboard.IsDarkMode);
        dialog.ShowDialog(_dashboard);
        if (!_dashboard.IsDisposed && dialog.Receipt is { } completed)
            _dashboard.SetFooter($"Image key operation completed at checkpoint {completed.After.CheckpointXid}.");
    }
}
