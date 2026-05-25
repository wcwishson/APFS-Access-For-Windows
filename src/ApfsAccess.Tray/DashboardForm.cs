using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed class DashboardForm : Form
{
    private readonly Func<string?, Task> _openAsync;
    private readonly Func<string?, Task> _ejectAsync;
    private readonly Func<string?, Task> _fixAsync;
    private readonly Label _summaryLabel;
    private readonly FlowLayoutPanel _rowsPanel;
    private readonly List<Button> _actionButtons = [];
    private string? _renderedDashboardKey;
    private bool _allowClose;

    public DashboardForm(
        Func<string?, Task> openAsync,
        Func<string?, Task> ejectAsync,
        Func<string?, Task> fixAsync)
    {
        _openAsync = openAsync ?? throw new ArgumentNullException(nameof(openAsync));
        _ejectAsync = ejectAsync ?? throw new ArgumentNullException(nameof(ejectAsync));
        _fixAsync = fixAsync ?? throw new ArgumentNullException(nameof(fixAsync));

        Text = "APFS Access";
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        MinimumSize = new Size(900, 540);
        Size = new Size(980, 620);
        BackColor = Color.FromArgb(248, 250, 252);
        Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(18),
            BackColor = BackColor,
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        Controls.Add(root);

        _summaryLabel = new Label
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            Font = new Font(Font, FontStyle.Bold),
            ForeColor = Color.FromArgb(31, 41, 55),
            Margin = new Padding(0, 0, 0, 14),
            Text = "Starting APFS Access...",
        };
        root.Controls.Add(_summaryLabel, 0, 0);

        _rowsPanel = new FlowLayoutPanel
        {
            AutoScroll = true,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            BackColor = BackColor,
            Margin = new Padding(0),
        };
        root.Controls.Add(_rowsPanel, 0, 1);

        ApplyStatus(new StatusChangedPayload(
            State: ApfsAccess.Core.RuntimeState.Starting,
            MountPoints: Array.Empty<string>(),
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>()));
    }

    public void ApplyStatus(StatusChangedPayload payload)
    {
        if (IsDisposed)
        {
            return;
        }

        var rows = DriveDashboardPresenter.BuildRows(payload);
        var summary = DriveDashboardPresenter.BuildSummary(payload);
        var key = BuildDashboardKey(summary, rows);
        if (string.Equals(_renderedDashboardKey, key, StringComparison.Ordinal))
        {
            return;
        }

        _summaryLabel.Text = summary;
        RenderRows(rows);
        _renderedDashboardKey = key;
    }

    public void SetFooter(string message)
    {
        _ = message;
    }

    public void SetActionsEnabled(bool enabled)
    {
        foreach (var button in _actionButtons)
        {
            button.Enabled = enabled && button.Tag is true;
        }
    }

    public void ShowDashboard()
    {
        if (IsDisposed)
        {
            return;
        }

        if (!Visible)
        {
            Show();
        }

        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Activate();
    }

    public void AllowCloseForApplicationExit()
    {
        _allowClose = true;
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_allowClose && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnFormClosing(e);
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        ResizeRows();
    }

    private void RenderRows(IReadOnlyList<DriveDashboardRow> rows)
    {
        if (_rowsPanel is null)
        {
            return;
        }

        _rowsPanel.SuspendLayout();
        try
        {
            _actionButtons.Clear();
            _rowsPanel.Controls.Clear();

            foreach (var row in rows)
            {
                _rowsPanel.Controls.Add(BuildRow(row));
            }

            ResizeRows();
        }
        finally
        {
            _rowsPanel.ResumeLayout();
        }
    }

    private static string BuildDashboardKey(string summary, IReadOnlyList<DriveDashboardRow> rows)
    {
        return string.Join(
            "\u001f",
            new[] { summary }.Concat(rows.Select(BuildRowKey)));
    }

    private static string BuildRowKey(DriveDashboardRow row)
        => string.Join(
            "\u001e",
            row.VolumeId,
            row.DeviceName,
            row.VolumeName,
            row.MountPoint,
            row.MountPath,
            row.State,
            row.Palette,
            row.StateText,
            row.Summary,
            row.CanOpen,
            row.CanEject,
            row.CanFix);

    private Control BuildRow(DriveDashboardRow row)
    {
        var container = new Panel
        {
            Height = 1,
            Margin = new Padding(0, 0, 0, 10),
            BackColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle,
        };

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            Padding = new Padding(0),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 8F));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        container.Controls.Add(layout);

        layout.Controls.Add(new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = ToColor(row.Palette),
            Margin = new Padding(0),
        }, 0, 0);

        var textPanel = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Padding = new Padding(14, 12, 14, 12),
        };
        textPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        textPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        textPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        textPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(textPanel, 1, 0);

        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            Font = new Font(Font, FontStyle.Bold),
            ForeColor = Color.FromArgb(17, 24, 39),
            Text = row.DeviceName,
        }, 0, 0);
        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            ForeColor = Color.FromArgb(55, 65, 81),
            Text = BuildVolumeLine(row),
        }, 0, 1);
        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            ForeColor = ToColor(row.Palette),
            Text = row.StateText,
        }, 0, 2);
        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            ForeColor = Color.FromArgb(75, 85, 99),
            Text = row.Summary,
        }, 0, 3);

        var buttonsPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Top,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(0, 10, 12, 10),
            Margin = new Padding(0, 0, 0, 0),
        };
        layout.Controls.Add(buttonsPanel, 2, 0);

        buttonsPanel.Controls.Add(BuildActionButton("Open", row.CanOpen, () => RunActionAsync(
            "Opening drive...",
            () => _openAsync(row.MountPath))));
        buttonsPanel.Controls.Add(BuildActionButton("Eject", row.CanEject, () => RunActionAsync(
            "Ejecting APFS drive...",
            () => _ejectAsync(row.VolumeId))));
        buttonsPanel.Controls.Add(BuildActionButton("Fix", row.CanFix, () => RunActionAsync(
            "Refreshing APFS drive...",
            () => _fixAsync(row.VolumeId))));
        buttonsPanel.Controls.Add(BuildActionButton("Details", true, () =>
        {
            ShowDetails(row);
            return Task.CompletedTask;
        }));

        return container;
    }

    private Button BuildActionButton(string text, bool enabled, Func<Task> action)
    {
        var button = new Button
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Margin = new Padding(4, 0, 0, 6),
            Padding = new Padding(12, 5, 12, 5),
            Text = text,
            Enabled = enabled,
            Tag = enabled,
            UseVisualStyleBackColor = true,
        };
        button.Click += async (_, _) => await action().ConfigureAwait(true);
        _actionButtons.Add(button);
        return button;
    }

    private async Task RunActionAsync(string workingMessage, Func<Task> action)
    {
        SetFooter(workingMessage);
        SetActionsEnabled(false);
        try
        {
            await action().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetFooter(ex.Message);
            MessageBox.Show(this, ex.Message, "APFS Access", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            SetActionsEnabled(true);
        }
    }

    private void ShowDetails(DriveDashboardRow row)
    {
        var lines = row.Details.ToList();
        if (row.FixGuidance.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Fix guidance:");
            lines.AddRange(row.FixGuidance.Select(static guidance => "- " + guidance));
        }

        MessageBox.Show(
            this,
            string.Join(Environment.NewLine, lines),
            $"{row.DeviceName} details",
            MessageBoxButtons.OK,
            row.State == DriveDashboardState.Problem ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
    }

    private void ResizeRows()
    {
        if (_rowsPanel is null)
        {
            return;
        }

        var width = Math.Max(320, _rowsPanel.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4);
        foreach (Control control in _rowsPanel.Controls)
        {
            control.Width = width;
            ResizeRowContent(control);
        }
    }

    private static void ResizeRowContent(Control root)
    {
        var layout = root.Controls.OfType<TableLayoutPanel>().FirstOrDefault();
        var textPanel = EnumerateControls(root).OfType<TableLayoutPanel>().FirstOrDefault(static panel => panel.RowCount == 4);
        var buttonsPanel = EnumerateControls(root).OfType<FlowLayoutPanel>().FirstOrDefault();

        if (layout is not null)
        {
            layout.Width = root.ClientSize.Width;
        }

        var buttonWidth = buttonsPanel?.GetPreferredSize(Size.Empty).Width ?? 0;
        var textWidth = Math.Max(180, root.ClientSize.Width - 8 - buttonWidth - 34);
        foreach (var label in EnumerateControls(root).OfType<Label>())
        {
            if (label.MaximumSize.Width != textWidth)
            {
                label.MaximumSize = new Size(textWidth, 0);
            }
        }

        var textHeight = textPanel?.Padding.Vertical ?? 0;
        if (textPanel is not null)
        {
            foreach (var label in textPanel.Controls.OfType<Label>())
            {
                textHeight += MeasureWrappedLabelHeight(label, textWidth) + label.Margin.Vertical;
            }
        }

        var buttonHeight = buttonsPanel?.GetPreferredSize(Size.Empty).Height ?? 0;
        root.Height = Math.Max(1, Math.Max(textHeight, buttonHeight) + 4);
        root.PerformLayout();
    }

    private static int MeasureWrappedLabelHeight(Label label, int textWidth)
    {
        if (string.IsNullOrEmpty(label.Text))
        {
            return label.Font.Height;
        }

        var measured = TextRenderer.MeasureText(
            label.Text,
            label.Font,
            new Size(textWidth, int.MaxValue),
            TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
        return Math.Max(label.Font.Height, measured.Height);
    }

    private static IEnumerable<Control> EnumerateControls(Control root)
    {
        foreach (Control control in root.Controls)
        {
            yield return control;

            foreach (var child in EnumerateControls(control))
            {
                yield return child;
            }
        }
    }

    private static string BuildVolumeLine(DriveDashboardRow row)
    {
        var volume = string.IsNullOrWhiteSpace(row.VolumeName) ? "APFS volume" : row.VolumeName;
        return string.IsNullOrWhiteSpace(row.MountPoint)
            ? volume
            : $"{volume} ({row.MountPoint})";
    }

    private static Color ToColor(DashboardPalette palette)
        => palette switch
        {
            DashboardPalette.Green => Color.FromArgb(34, 139, 84),
            DashboardPalette.Yellow => Color.FromArgb(214, 158, 46),
            DashboardPalette.Orange => Color.FromArgb(221, 107, 32),
            DashboardPalette.Red => Color.FromArgb(197, 48, 48),
            _ => Color.FromArgb(113, 128, 150),
        };
}
