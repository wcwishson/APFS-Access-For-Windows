using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed class DashboardForm : Form
{
    private readonly Func<string?, Task> _openAsync;
    private readonly Func<string?, Task> _ejectAsync;
    private readonly Func<string?, Task> _fixAsync;
    private readonly Func<bool, Task>? _setStartWithWindowsAsync;
    private readonly Func<bool, Task>? _setStartMinimizedAsync;
    private readonly Label _summaryLabel;
    private readonly FlowLayoutPanel _rowsPanel;
    private readonly List<Button> _actionButtons = [];
    private readonly List<RenderedDashboardRow> _renderedRows = [];
    private CheckBox? _startWithWindowsCheckBox;
    private CheckBox? _startMinimizedCheckBox;
    private string? _renderedDashboardKey;
    private string? _renderedSummary;
    private bool _allowClose;
    private bool _actionsEnabled = true;
    private bool _updatingStartupPreferences;

    private sealed record RenderedDashboardRow(string Identity, Control Control, IReadOnlyList<Button> Buttons);

    public DashboardForm(
        Func<string?, Task> openAsync,
        Func<string?, Task> ejectAsync,
        Func<string?, Task> fixAsync,
        StartupPreferences? startupPreferences = null,
        Func<bool, Task>? setStartWithWindowsAsync = null,
        Func<bool, Task>? setStartMinimizedAsync = null)
    {
        _openAsync = openAsync ?? throw new ArgumentNullException(nameof(openAsync));
        _ejectAsync = ejectAsync ?? throw new ArgumentNullException(nameof(ejectAsync));
        _fixAsync = fixAsync ?? throw new ArgumentNullException(nameof(fixAsync));
        _setStartWithWindowsAsync = setStartWithWindowsAsync;
        _setStartMinimizedAsync = setStartMinimizedAsync;
        startupPreferences ??= new StartupPreferences(StartWithWindows: false, StartMinimized: false);

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
            RowCount = 3,
            Padding = new Padding(18),
            BackColor = BackColor,
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
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

        root.Controls.Add(BuildStartupPreferencesPanel(startupPreferences), 0, 2);

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
        var key = BuildDashboardKey(rows);
        var summaryChanged = !string.Equals(_renderedSummary, summary, StringComparison.Ordinal);
        if (string.Equals(_renderedDashboardKey, key, StringComparison.Ordinal))
        {
            if (summaryChanged)
            {
                _summaryLabel.Text = summary;
            }

            UpdateRenderedRows(rows);
            _renderedDashboardKey = key;
            _renderedSummary = summary;
            return;
        }

        if (summaryChanged)
        {
            _summaryLabel.Text = summary;
        }

        ReconcileRows(rows);

        _renderedDashboardKey = key;
        _renderedSummary = summary;
    }

    public void SetFooter(string message)
    {
        _ = message;
    }

    public void SetActionsEnabled(bool enabled)
    {
        _actionsEnabled = enabled;
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

    private void ReconcileRows(IReadOnlyList<DriveDashboardRow> rows)
    {
        if (_rowsPanel is null)
        {
            return;
        }

        _rowsPanel.SuspendLayout();
        try
        {
            _actionButtons.Clear();
            var currentRows = _renderedRows.ToDictionary(static row => row.Identity, StringComparer.Ordinal);
            var nextRows = new List<RenderedDashboardRow>(rows.Count);

            foreach (var row in rows)
            {
                var identity = BuildRowIdentity(row);
                if (currentRows.TryGetValue(identity, out var existing) &&
                    existing.Control is not null)
                {
                    UpdateRow(existing.Control, row);
                    nextRows.Add(existing);
                    _actionButtons.AddRange(existing.Buttons);
                }
                else
                {
                    if (existing is not null)
                    {
                        var existingControl = existing.Control;
                        ArgumentNullException.ThrowIfNull(existingControl);
                        _rowsPanel.Controls.Remove(existingControl);
                        existingControl.Dispose();
                    }

                    var buttons = new List<Button>();
                    var newControl = BuildRow(row, buttons);
                    nextRows.Add(new RenderedDashboardRow(identity, newControl, buttons));
                    _actionButtons.AddRange(buttons);
                }
            }

            var nextIdentitySet = nextRows
                .Select(static row => row.Identity)
                .ToHashSet(StringComparer.Ordinal);
            foreach (var oldRow in _renderedRows)
            {
                if (!nextIdentitySet.Contains(oldRow.Identity))
                {
                    _rowsPanel.Controls.Remove(oldRow.Control);
                    oldRow.Control.Dispose();
                }
            }

            for (var index = 0; index < nextRows.Count; ++index)
            {
                var control = nextRows[index].Control;
                if (!_rowsPanel.Controls.Contains(control))
                {
                    _rowsPanel.Controls.Add(control);
                }

                _rowsPanel.Controls.SetChildIndex(control, index);
            }

            _renderedRows.Clear();
            _renderedRows.AddRange(nextRows);
            ResizeRows();
        }
        finally
        {
            _rowsPanel.ResumeLayout();
        }
    }

    private void UpdateRenderedRows(IReadOnlyList<DriveDashboardRow> rows)
    {
        if (_rowsPanel is null)
        {
            return;
        }

        var currentRows = _renderedRows.ToDictionary(static row => row.Identity, StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var identity = BuildRowIdentity(row);
            if (currentRows.TryGetValue(identity, out var existing))
            {
                UpdateRow(existing.Control, row);
            }
        }
    }

    private static string BuildDashboardKey(IReadOnlyList<DriveDashboardRow> rows)
    {
        return string.Join("\u001f", rows.Select(BuildRowIdentity));
    }

    private static string BuildRowIdentity(DriveDashboardRow row)
        => string.IsNullOrWhiteSpace(row.VolumeId) ? "idle" : row.VolumeId;

    private void UpdateRow(Control root, DriveDashboardRow row)
    {
        if (root.Controls.Count == 0 ||
            root.Controls[0] is not TableLayoutPanel layout ||
            layout.Controls.Count < 3)
        {
            return;
        }

        if (layout.Controls[0] is Control palette)
        {
            palette.BackColor = ToColor(row.Palette);
        }

        if (layout.Controls[1] is TableLayoutPanel textPanel)
        {
            var labels = textPanel.Controls.OfType<Label>().ToArray();
            if (labels.Length >= 4)
            {
                labels[0].Text = row.DeviceName;
                labels[1].Text = BuildVolumeLine(row);
                labels[2].ForeColor = ToColor(row.Palette);
                labels[2].Text = row.StateText;
                labels[3].Text = row.Summary;
            }
        }

        if (layout.Controls[2] is FlowLayoutPanel buttonsPanel)
        {
            var buttons = buttonsPanel.Controls.OfType<Button>().ToArray();
            if (buttons.Length >= 4)
            {
                buttons[0].Tag = row.CanOpen;
                buttons[0].Enabled = _actionsEnabled && row.CanOpen;
                buttons[1].Tag = row.CanEject;
                buttons[1].Enabled = _actionsEnabled && row.CanEject;
                buttons[2].Tag = row.CanFix;
                buttons[2].Enabled = _actionsEnabled && row.CanFix;
                buttons[3].Tag = true;
                buttons[3].Enabled = _actionsEnabled;
            }
        }

        ResizeRowContent(root);
    }

    private Control BuildRow(DriveDashboardRow row, List<Button> actionButtons)
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

        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Open", row.CanOpen, () => RunActionAsync(
            "Opening drive...",
            () => _openAsync(row.MountPath))));
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Eject", row.CanEject, () => RunActionAsync(
            "Ejecting APFS drive...",
            () => _ejectAsync(row.VolumeId))));
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Fix", row.CanFix, () => RunActionAsync(
            "Refreshing APFS drive...",
            () => _fixAsync(row.VolumeId))));
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Details", true, () =>
        {
            ShowDetails(row);
            return Task.CompletedTask;
        }));

        return container;
    }

    private Control BuildStartupPreferencesPanel(StartupPreferences startupPreferences)
    {
        var panel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            Margin = new Padding(0, 8, 0, 0),
            Padding = new Padding(0),
            BackColor = BackColor,
        };

        _startWithWindowsCheckBox = BuildStartupCheckBox(
            "Start the program with Windows",
            startupPreferences.StartWithWindows,
            _setStartWithWindowsAsync);
        _startMinimizedCheckBox = BuildStartupCheckBox(
            "Start minimized",
            startupPreferences.StartMinimized,
            _setStartMinimizedAsync);

        panel.Controls.Add(_startWithWindowsCheckBox);
        panel.Controls.Add(_startMinimizedCheckBox);
        return panel;
    }

    private CheckBox BuildStartupCheckBox(string text, bool isChecked, Func<bool, Task>? action)
    {
        var checkBox = new CheckBox
        {
            AutoSize = true,
            Checked = isChecked,
            Margin = new Padding(0, 0, 22, 8),
            Text = text,
            UseVisualStyleBackColor = true,
        };

        checkBox.CheckedChanged += async (_, _) =>
        {
            if (_updatingStartupPreferences)
            {
                return;
            }

            await RunStartupPreferenceActionAsync(checkBox, action).ConfigureAwait(true);
        };

        return checkBox;
    }

    private async Task RunStartupPreferenceActionAsync(CheckBox checkBox, Func<bool, Task>? action)
    {
        if (action is null)
        {
            return;
        }

        var requestedValue = checkBox.Checked;
        checkBox.Enabled = false;
        try
        {
            await action(requestedValue).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _updatingStartupPreferences = true;
            try
            {
                checkBox.Checked = !requestedValue;
            }
            finally
            {
                _updatingStartupPreferences = false;
            }

            MessageBox.Show(this, ex.Message, "APFS Access", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            checkBox.Enabled = true;
        }
    }

    private Button BuildActionButton(List<Button> actionButtons, string text, bool enabled, Func<Task> action)
    {
        var button = new Button
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Margin = new Padding(4, 0, 0, 6),
            Padding = new Padding(12, 5, 12, 5),
            Text = text,
            Enabled = _actionsEnabled && enabled,
            Tag = enabled,
            UseVisualStyleBackColor = true,
        };
        button.Click += async (_, _) => await action().ConfigureAwait(true);
        actionButtons.Add(button);
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
            DashboardPalette.Blue => Color.FromArgb(49, 130, 206),
            DashboardPalette.Yellow => Color.FromArgb(214, 158, 46),
            DashboardPalette.Orange => Color.FromArgb(221, 107, 32),
            DashboardPalette.Red => Color.FromArgb(197, 48, 48),
            _ => Color.FromArgb(113, 128, 150),
        };
}
