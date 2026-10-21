using System.Security;
using ApfsAccess.Cli;

namespace ApfsAccess.Tray;

internal static class EncryptedPasswordPrompt
{
    internal static SupervisedCredential? Show(IWin32Window owner, DriveDashboardRow row, bool isDarkMode = false)
    {
        var theme = isDarkMode ? DashboardTheme.Dark : DashboardTheme.Light;
        var caption = row.RegisteredImage?.Writable == true ? "Unlock read/write" : "Unlock read-only";
        using var form = new Form
        {
            Text = caption,
            StartPosition = FormStartPosition.CenterParent,
            AutoScaleMode = AutoScaleMode.Dpi,
            MinimizeBox = false,
            MaximizeBox = false,
            MinimumSize = new(360, 220),
            Size = new(520, 240),
            Font = new("Segoe UI", 10),
            BackColor = theme.WindowBackground,
            ForeColor = theme.TextPrimary,
        };
        DashboardTheme.ApplyImmersiveDarkMode(form.Handle, isDarkMode);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new(16),
            BackColor = theme.WindowBackground,
        };
        layout.RowStyles.Add(new(SizeType.AutoSize));
        layout.RowStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.AutoSize));

        var label = new Label
        {
            Text = $"{row.VolumeName}\n{row.CatalogVolumeUuid}",
            AutoSize = true,
            Dock = DockStyle.Fill,
            ForeColor = theme.TextPrimary,
        };
        using var password = new SecureInput(isDarkMode)
        {
            Dock = DockStyle.Fill,
            TabStop = true,
            AccessibleName = "Volume password",
        };
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            BackColor = theme.WindowBackground,
        };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var unlock = new Button { Text = caption, AutoSize = true, DialogResult = DialogResult.OK };
        if (isDarkMode)
        {
            cancel.FlatStyle = FlatStyle.Flat;
            cancel.FlatAppearance.BorderColor = theme.ButtonBorder;
            cancel.BackColor = theme.ButtonBackground;
            cancel.ForeColor = theme.ButtonText;
            unlock.FlatStyle = FlatStyle.Flat;
            unlock.FlatAppearance.BorderColor = theme.ButtonBorder;
            unlock.BackColor = theme.ButtonBackground;
            unlock.ForeColor = theme.ButtonText;
        }
        else
        {
            cancel.UseVisualStyleBackColor = true;
            unlock.UseVisualStyleBackColor = true;
        }

        buttons.Controls.Add(cancel);
        buttons.Controls.Add(unlock);
        layout.Controls.Add(label);
        layout.Controls.Add(password);
        layout.Controls.Add(buttons);
        form.Controls.Add(layout);
        form.AcceptButton = unlock;
        form.CancelButton = cancel;
        form.Shown += (_, _) => password.Focus();
        return form.ShowDialog(owner) == DialogResult.OK ? SupervisedCredential.FromSecureString(password.Secret) : null;
    }

    // No password Text property, clipboard, undo buffer, or accessible value.
    private sealed class SecureInput : Control
    {
        private readonly bool _isDarkMode;
        internal SecureString Secret { get; } = new();

        public SecureInput(bool isDarkMode = false)
        {
            _isDarkMode = isDarkMode;
            SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.Selectable, true);
            BackColor = isDarkMode ? Color.FromArgb(18, 19, 22) : Color.White;
            ForeColor = isDarkMode ? Color.FromArgb(240, 242, 245) : Color.Black;
        }

        protected override void OnKeyPress(KeyPressEventArgs e)
        {
            e.Handled = true;
            if (e.KeyChar == '\b')
            {
                if (Secret.Length > 0) Secret.RemoveAt(Secret.Length - 1);
            }
            else if (!char.IsControl(e.KeyChar) && Secret.Length < 1024)
            {
                Secret.AppendChar(e.KeyChar);
            }
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var borderColor = Focused
                ? Color.DodgerBlue
                : (_isDarkMode ? Color.FromArgb(64, 68, 78) : Color.Gray);
            ControlPaint.DrawBorder(e.Graphics, ClientRectangle, borderColor, ButtonBorderStyle.Solid);
            TextRenderer.DrawText(e.Graphics, new string('●', Math.Min(Secret.Length, 64)), Font, ClientRectangle, ForeColor, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
        protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }
        protected override void Dispose(bool disposing) { if (disposing) Secret.Dispose(); base.Dispose(disposing); }
    }
}
