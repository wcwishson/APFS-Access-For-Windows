using System.Globalization;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal sealed class VolumeCreateDialog : Form
{
    private readonly TextBox _name = new() { Name = "VolumeName", Dock = DockStyle.Fill, MaxLength = 255 };
    private readonly NumericUpDown _quota = new() { Name = "QuotaBytes", Dock = DockStyle.Fill, Maximum = ulong.MaxValue };
    private readonly NumericUpDown _reserve = new() { Name = "ReserveBytes", Dock = DockStyle.Fill, Maximum = ulong.MaxValue };
    private readonly CheckBox _case = new() { Name = "CaseSensitive", Text = "Case sensitive", AutoSize = true, Checked = true };
    public VolumeManagementParameters Parameters => new("create", _name.Text, _quota.Value.ToString(CultureInfo.InvariantCulture),
        _reserve.Value.ToString(CultureInfo.InvariantCulture), _case.Checked);
    public VolumeCreateDialog(string image, string container)
    {
        Text = "Create image volume"; StartPosition = FormStartPosition.CenterParent; AutoScaleMode = AutoScaleMode.Dpi;
        Size = new(560, 370); MinimumSize = new(440, 320); MinimizeBox = MaximizeBox = false;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(16), ColumnCount = 2, RowCount = 6, AutoScroll = true };
        layout.ColumnStyles.Add(new(SizeType.AutoSize)); layout.ColumnStyles.Add(new(SizeType.Percent, 100));
        var identity = new TextBox { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, Text = $"Image: {image}\r\nContainer: {container}", ScrollBars = ScrollBars.Vertical };
        layout.Controls.Add(identity, 0, 0); layout.SetColumnSpan(identity, 2); layout.RowStyles.Add(new(SizeType.Percent, 100));
        void Field(string title, Control control, int row)
        { layout.Controls.Add(new Label { Text = title, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new(0, 8, 12, 8) }, 0, row); layout.Controls.Add(control, 1, row); layout.RowStyles.Add(new(SizeType.AutoSize)); }
        Field("Name", _name, 1); Field("Quota (bytes)", _quota, 2); Field("Reserve (bytes)", _reserve, 3);
        layout.Controls.Add(_case, 1, 4); layout.RowStyles.Add(new(SizeType.AutoSize));
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var review = new Button { Name = "ReviewPlan", Text = "Review plan", AutoSize = true };
        review.Click += (_, _) => { if (VolumeManagementParameters.Valid(ApfsControlCommands.VolumeCreatePlan, Parameters)) DialogResult = DialogResult.OK; else _name.Focus(); };
        buttons.Controls.Add(cancel); buttons.Controls.Add(review); layout.Controls.Add(buttons, 0, 5); layout.SetColumnSpan(buttons, 2); layout.RowStyles.Add(new(SizeType.AutoSize));
        AcceptButton = review; CancelButton = cancel; Controls.Add(layout);
    }
}
