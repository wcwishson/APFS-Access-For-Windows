using System.Globalization;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal sealed class VolumeManagementDialog : Form
{
    private readonly ComboBox _operation = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly TextBox _name = new() { Dock = DockStyle.Fill, MaxLength = 255 };
    private readonly NumericUpDown _quota = new() { Dock = DockStyle.Fill, Maximum = ulong.MaxValue, DecimalPlaces = 0 };
    private readonly NumericUpDown _reserve = new() { Dock = DockStyle.Fill, Maximum = ulong.MaxValue, DecimalPlaces = 0 };

    public string Operation => _operation.SelectedIndex == 0 ? ApfsManagementOperations.RenameVolume : ApfsManagementOperations.SetQuotaReserve;
    public string? NewName => _operation.SelectedIndex == 0 ? _name.Text : null;
    public string? QuotaBytes => _operation.SelectedIndex == 1 ? _quota.Value.ToString(CultureInfo.InvariantCulture) : null;
    public string? ReserveBytes => _operation.SelectedIndex == 1 ? _reserve.Value.ToString(CultureInfo.InvariantCulture) : null;

    public VolumeManagementDialog(DriveDashboardRow row)
    {
        Text = "Manage volume";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        MinimumSize = new Size(460, 320);
        Size = new Size(580, 380);
        MinimizeBox = false;
        MaximizeBox = false;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 6,
            Padding = new Padding(16), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var identity = new TextBox { ReadOnly = true, Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical,
            Text = $"{row.VolumeName}\r\nImage: {row.DeviceId}\r\nContainer: {row.CatalogContainerUuid}\r\nVolume: {row.CatalogVolumeUuid}\r\nObject: {row.CatalogVolumeObjectId}" };
        layout.Controls.Add(identity, 0, 0);
        layout.SetColumnSpan(identity, 2);
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _operation.Items.AddRange(["Rename", "Quota and reserve"]);
        _name.Text = row.VolumeName;
        var space = row.CatalogSpace;
        var knownLimits = space is not null && space.Volume.VolumeId == row.CatalogVolumeId &&
            space.Volume.ObjectId == row.CatalogVolumeObjectId &&
            space.ContainerId.StartsWith("apfs-container:", StringComparison.Ordinal) &&
            ApfsAccess.Core.TopologyAdmission.SameUuid(space.ContainerId[15..], row.CatalogContainerUuid);
        _quota.Value = knownLimits ? space!.Volume.Quota?.Bytes ?? 0 : 0;
        _reserve.Value = knownLimits ? space!.Volume.Reserve?.Bytes ?? 0 : 0;
        var quotaEntered = knownLimits;
        var reserveEntered = knownLimits;
        _quota.ValueChanged += (_, _) => quotaEntered = true;
        _reserve.ValueChanged += (_, _) => reserveEntered = true;
        _quota.TextChanged += (_, _) => quotaEntered = true;
        _reserve.TextChanged += (_, _) => reserveEntered = true;
        void AddField(string label, Control control, int index)
        {
            layout.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 8, 12, 8) }, 0, index);
            layout.Controls.Add(control, 1, index);
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }
        AddField("Operation", _operation, 1);
        AddField("Name", _name, 2);
        AddField("Quota (bytes)", _quota, 3);
        AddField("Reserve (bytes)", _reserve, 4);
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var plan = new Button { Text = "Review plan", AutoSize = true };
        plan.Click += (_, _) =>
        {
            if (Operation == ApfsManagementOperations.RenameVolume && (string.IsNullOrWhiteSpace(NewName) || NewName.Any(c => c is '\0' or '\r' or '\n')))
            { _name.Focus(); return; }
            if (Operation == ApfsManagementOperations.SetQuotaReserve && (!quotaEntered || !reserveEntered))
            { (!_quota.Enabled || quotaEntered ? _reserve : _quota).Focus(); return; }
            DialogResult = DialogResult.OK;
        };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(plan);
        layout.Controls.Add(buttons, 0, 5);
        layout.SetColumnSpan(buttons, 2);
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _operation.SelectedIndexChanged += (_, _) =>
        {
            _name.Enabled = _operation.SelectedIndex == 0;
            _quota.Enabled = _reserve.Enabled = _operation.SelectedIndex == 1;
        };
        _operation.SelectedIndex = 0;
        AcceptButton = plan;
        CancelButton = cancel;
        Controls.Add(layout);
    }
}
