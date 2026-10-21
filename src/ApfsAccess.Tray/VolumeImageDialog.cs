using System.Globalization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal sealed class VolumeImageDialog : Form
{
    private readonly RadioButton _first = new() { Text = "Grow", AutoSize = true, Checked = true };
    private readonly RadioButton _second = new() { Text = "Shrink", AutoSize = true };
    private readonly NumericUpDown _size = new() { Name = "TargetBytes", Minimum = 1048576, Maximum = VolumeTopologyProfile.MaximumStreamedImageBytes, Increment = 4096, Dock = DockStyle.Fill };
    private readonly TextBox _name = new() { Name = "VolumeName", MaxLength = 255, Dock = DockStyle.Fill };
    private readonly CheckBox _case = new() { Name = "CaseSensitive", Text = "Case sensitive", Checked = true, AutoSize = true };
    private readonly bool _format;
    public VolumeManagementParameters Parameters => _format
        ? new(_first.Checked ? "format" : "erase", Name: _name.Text, CaseSensitive: _case.Checked)
        : new(_first.Checked ? "grow" : "shrink", TargetBytes: _size.Value.ToString(CultureInfo.InvariantCulture));
    public VolumeImageDialog(DriveDashboardRow row, bool format)
    {
        _format = format; Text = format ? "Format image container" : "Resize image container";
        StartPosition = FormStartPosition.CenterParent; AutoScaleMode = AutoScaleMode.Dpi;
        Size = new(560, 340); MinimumSize = new(440, 300); MinimizeBox = MaximizeBox = false;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(16), ColumnCount = 2, RowCount = 5, AutoScroll = true };
        layout.ColumnStyles.Add(new(SizeType.AutoSize)); layout.ColumnStyles.Add(new(SizeType.Percent, 100));
        var identity = new TextBox { ReadOnly = true, Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical,
            Text = $"Image: {row.DeviceId}\r\nContainer: {row.CatalogContainerUuid}\r\nCapacity: {row.SnapshotScope?.StoreSizeBytes} bytes" };
        layout.Controls.Add(identity, 0, 0); layout.SetColumnSpan(identity, 2); layout.RowStyles.Add(new(SizeType.Percent, 100));
        var modes = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true }; modes.Controls.Add(_first); modes.Controls.Add(_second);
        if (format) { _first.Text = "Format"; _second.Text = "Erase free space"; }
        _first.Enabled = row.CanPlanImageOperation(format ? "format" : "grow");
        _second.Enabled = row.CanPlanImageOperation(format ? "erase" : "shrink");
        if (!_first.Enabled && _second.Enabled) _second.Checked = true;
        layout.Controls.Add(modes, 0, 1); layout.SetColumnSpan(modes, 2); layout.RowStyles.Add(new(SizeType.AutoSize));
        layout.Controls.Add(new Label { Text = format ? "New volume name" : "New capacity (bytes)", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        layout.Controls.Add(format ? _name : _size, 1, 2); layout.RowStyles.Add(new(SizeType.AutoSize));
        if (!format && decimal.TryParse(row.SnapshotScope?.StoreSizeBytes, NumberStyles.None, CultureInfo.InvariantCulture, out var capacity)) _size.Value = Math.Clamp(capacity, _size.Minimum, _size.Maximum);
        if (format) layout.Controls.Add(_case, 1, 3); layout.RowStyles.Add(new(SizeType.AutoSize));
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var review = new Button { Name = "ReviewPlan", Text = "Review plan", AutoSize = true };
        review.Click += (_, _) => { if (row.CanPlanImageOperation(Parameters.Kind) &&
            VolumeManagementParameters.Valid(format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan, Parameters)) DialogResult = DialogResult.OK; };
        buttons.Controls.Add(cancel); buttons.Controls.Add(review); layout.Controls.Add(buttons, 0, 4); layout.SetColumnSpan(buttons, 2);
        layout.RowStyles.Add(new(SizeType.AutoSize)); AcceptButton = review; CancelButton = cancel; Controls.Add(layout);
    }
}
