using System.Security;

namespace ApfsAccess.Tray;

internal sealed class SecureKeyManagementInput : Control
{
    private readonly DashboardTheme theme;
    private bool selected;
    private readonly ToolTip interaction = new();
    internal SecureString Secret { get; } = new();

    internal SecureKeyManagementInput(DashboardTheme theme)
    {
        this.theme = theme;
        SetStyle(ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.Selectable, true);
        BackColor = theme.WindowBackground;
        ForeColor = theme.TextPrimary;
        MinimumSize = new(120, 32);
        AccessibleRole = AccessibleRole.Text;
        AccessibleDescription = "Typed password input. Ctrl+A selects all; Backspace removes the last character. Paste and cursor editing are unavailable.";
        interaction.SetToolTip(this, "Typed input only. Paste and cursor editing are unavailable.");
        TabStop = true;
    }

    internal void ClearSecret() { Secret.Clear(); selected = false; Invalidate(); }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Control && e.KeyCode == Keys.A) { selected = true; e.SuppressKeyPress = true; Invalidate(); }
        else if (e.Control || e.KeyCode == Keys.Delete)
        {
            if (e.KeyCode == Keys.Delete && selected) ClearSecret();
            e.SuppressKeyPress = true;
        }
        base.OnKeyDown(e);
    }

    protected override void OnKeyPress(KeyPressEventArgs e)
    {
        e.Handled = true;
        if (e.KeyChar == '\b')
        {
            if (selected) ClearSecret();
            else if (Secret.Length > 0) Secret.RemoveAt(Secret.Length - 1);
        }
        else if (!char.IsControl(e.KeyChar))
        {
            if (selected) ClearSecret();
            if (Secret.Length < 1024) Secret.AppendChar(e.KeyChar);
        }
        selected = false;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        ControlPaint.DrawBorder(e.Graphics, ClientRectangle, Focused ? Color.DodgerBlue : theme.ButtonBorder, ButtonBorderStyle.Solid);
        var area = Rectangle.Inflate(ClientRectangle, -7, -1);
        if (selected && Secret.Length > 0) e.Graphics.FillRectangle(SystemBrushes.Highlight, area);
        TextRenderer.DrawText(e.Graphics, new string('*', Math.Min(Secret.Length, 64)), Font, area,
            selected ? SystemColors.HighlightText : ForeColor, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); selected = false; Invalidate(); }
    protected override void Dispose(bool disposing) { if (disposing) { interaction.Dispose(); Secret.Dispose(); } base.Dispose(disposing); }
}
