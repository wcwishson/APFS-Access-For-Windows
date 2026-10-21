using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

internal sealed class ImageKeyManagementDialog : Form
{
    private readonly ImageKeyManagementRequest request;
    private readonly Func<ImageKeyManagementRequest, SupervisedCredentialSet, CancellationToken, Task<ImageKeyManagementReceipt>> execute;
    private readonly Func<CancellationToken, Task<ImageKeyManagementEndpoint>> refresh;
    private readonly SecureKeyManagementInput first, next, confirmation;
    private readonly CheckBox confirmed;
    private readonly Button apply, cancel;
    private readonly Label status;
    private readonly ImageKeyManagementDialogLifetime lifetime = new();
    private bool busy, closing, endpointChanged;
    internal ImageKeyManagementReceipt? Receipt { get; private set; }

    internal ImageKeyManagementDialog(string volumeName, ImageKeyManagementEndpoint endpoint, ImageKeyManagementAction action,
        Func<ImageKeyManagementRequest, SupervisedCredentialSet, CancellationToken, Task<ImageKeyManagementReceipt>> execute,
        Func<CancellationToken, Task<ImageKeyManagementEndpoint>> refresh, bool dark = false)
    {
        request = new(Guid.NewGuid().ToString("D"), action, endpoint);
        if (!request.IsValid() || action == ImageKeyManagementAction.Observe) throw new ArgumentException("A current image endpoint and mutation are required.");
        this.execute = execute; this.refresh = refresh;
        var title = action switch
        {
            ImageKeyManagementAction.ChangePassword => "Change password",
            ImageKeyManagementAction.RotateVolumeKey => "Rotate volume key",
            ImageKeyManagementAction.Encrypt => "Encrypt image",
            _ => "Decrypt image"
        };
        var theme = dark ? DashboardTheme.Dark : DashboardTheme.Light;
        Text = title; StartPosition = FormStartPosition.CenterParent; AutoScaleMode = AutoScaleMode.Dpi;
        MinimizeBox = MaximizeBox = false; MinimumSize = new(460, 380); Size = new(600, 540);
        Font = new("Segoe UI", 10); BackColor = theme.WindowBackground; ForeColor = theme.TextPrimary;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoScroll = true, Padding = new(16) };
        layout.SizeChanged += (_, _) =>
        {
            var width = Math.Max(120, layout.ClientSize.Width - layout.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth);
            foreach (var label in layout.Controls.OfType<Label>()) label.MaximumSize = new(width, 0);
        };
        void Add(Control control) { control.Dock = DockStyle.Top; control.Margin = new(0, 0, 0, 9); layout.Controls.Add(control); }
        Add(new Label { AutoSize = true, MaximumSize = new(540, 0), Text = $"{volumeName}\n{endpoint.ImagePath}\n{endpoint.VolumeUuid}\nCheckpoint {endpoint.CheckpointXid}" });
        first = new(theme); next = new(theme); confirmation = new(theme);
        var two = request.CredentialCount == 2;
        Add(new Label { AutoSize = true, Text = action == ImageKeyManagementAction.Encrypt ? "New password" : "Current password" });
        first.AccessibleName = action == ImageKeyManagementAction.Encrypt ? "New password" : "Current password"; Add(first);
        if (two) { Add(new Label { AutoSize = true, Text = "New password" }); next.AccessibleName = "New password"; Add(next); }
        if (action != ImageKeyManagementAction.Decrypt)
        {
            Add(new Label { AutoSize = true, Text = "Confirm new password" }); confirmation.AccessibleName = "Confirm new password"; Add(confirmation);
        }
        confirmed = new() { AutoSize = true, Text = $"Confirm {title.ToLowerInvariant()} for this image" }; Add(confirmed);
        status = new() { AutoSize = true, MaximumSize = new(540, 0), ForeColor = theme.TextPrimary }; Add(status);
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        cancel = new() { AutoSize = true, Text = "Cancel" }; apply = new() { AutoSize = true, Text = title, Enabled = false };
        buttons.Controls.Add(cancel); buttons.Controls.Add(apply); Add(buttons); Controls.Add(layout);
        confirmed.CheckedChanged += (_, _) => apply.Enabled = confirmed.Checked && !busy && !endpointChanged;
        apply.Click += async (_, _) => await RunAsync();
        cancel.Click += (_, _) => { if (busy) { closing = true; lifetime.Cancel(); status.Text = "Cancelling..."; } else Close(); };
        FormClosing += (_, e) => { if (busy) { e.Cancel = true; closing = true; lifetime.Cancel(); status.Text = "Cancelling..."; } };
        Shown += (_, _) => { DashboardTheme.ApplyImmersiveDarkMode(Handle, dark); first.Focus(); };
        AcceptButton = apply; CancelButton = cancel;
    }

    private async Task RunAsync()
    {
        if (!lifetime.CanUpdateView || busy || !confirmed.Checked || endpointChanged) return;
        SupervisedCredentialSet? credentials = null;
        try
        {
            using var repeat = request.Action == ImageKeyManagementAction.Decrypt ? null : SupervisedCredential.FromSecureString(confirmation.Secret);
            var initial = SupervisedCredential.FromSecureString(first.Secret);
            SupervisedCredential? replacement = null;
            try
            {
                if (request.CredentialCount == 2) replacement = SupervisedCredential.FromSecureString(next.Secret);
                if (repeat is not null && !(replacement ?? initial).ContentEquals(repeat))
                { status.Text = "New passwords do not match."; return; }
                credentials = SupervisedCredentialSet.Own(initial, replacement); initial = null!; replacement = null;
            }
            finally { initial?.Dispose(); replacement?.Dispose(); }
        }
        catch { status.Text = "Enter a valid password in each field."; return; }
        if (credentials is null) return;
        using (credentials)
        {
            busy = true; apply.Enabled = confirmed.Enabled = first.Enabled = next.Enabled = confirmation.Enabled = false;
            first.ClearSecret(); next.ClearSecret(); confirmation.ClearSecret(); status.Text = "Working...";
            try
            {
                var result = await lifetime.Start(token => execute(request, credentials, token));
                if (!result.Proves(request)) throw new InvalidOperationException("Incomplete image operation receipt.");
                if (!lifetime.CanUpdateView) return;
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var current = await refresh(deadline.Token);
                if (current != result.After) throw new InvalidOperationException("Image endpoint changed after completion.");
                lifetime.UpdateView(() => Receipt = result);
            }
            catch (OperationCanceledException) { lifetime.UpdateView(() => status.Text = "Operation cancelled. Refresh the image status."); }
            catch { lifetime.UpdateView(() => status.Text = "Operation did not finish. Refresh the image status."); }
            finally
            {
                busy = false;
                lifetime.UpdateView(() => { endpointChanged = true; confirmed.Checked = false; cancel.Text = "Close"; cancel.Enabled = true; });
            }
        }
        lifetime.UpdateView(() => { if (Receipt is not null) { DialogResult = DialogResult.OK; Close(); } else if (closing) Close(); });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { lifetime.Detach(); first.Dispose(); next.Dispose(); confirmation.Dispose(); }
        base.Dispose(disposing);
    }
}
