using System.Drawing.Drawing2D;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed class DashboardForm : Form
{
    internal bool IsDarkMode=>_currentTheme.IsDark;
    private readonly Func<string?, Task> _openAsync;
    private readonly Func<string?, Task> _ejectAsync;
    private readonly Func<string?, Task> _fixAsync;
    private readonly Action<string> _copyText;
    private readonly Func<bool, Task>? _setStartWithWindowsAsync;
    private readonly Func<bool, Task>? _setStartMinimizedAsync;
    private readonly Func<Task>? _checkForUpdatesAsync;
    private readonly Func<string, string, Task>? _mountContainerAsync;
    private readonly Func<string, string, Task>? _unmountContainerAsync;
    private readonly Func<string, Task>? _ejectDeviceAsync;
    private readonly Func<IReadOnlyList<DriveDashboardRow>, Task>? _fixContainerAsync;
    private readonly Func<ContainerVolumeVerification, Task>? _verifyContainerAsync;
    private ContainerVolumeVerification? _selectedContainerVerification;
    private readonly Func<DriveDashboardRow, string, Task>? _setDriveLetterAsync;
    private readonly Label _summaryLabel;
    private readonly ProgressBar _activityBar;
    private readonly FlowLayoutPanel _rowsPanel;
    private readonly TreeView _topologyTree;
    private readonly TableLayoutPanel _topologyLayout;
    private readonly Panel _detailContainer;
    private readonly Panel _detailsTopPanel;
    private readonly FlowLayoutPanel _memberPanel;
    private bool _adjustingMemberPanelHeight;
    private readonly SplitContainer _contentSplit;
    private readonly Label _nodeDetails;
    private readonly ApfsStorageBarControl _storageBar;
    private bool _storageBarActive;
    private readonly ContextMenuStrip _treeContextMenu;
    private readonly Button _copyDetailsButton;
    private readonly Button _copyJsonButton;
    private readonly Button _memberButton;
    private readonly Button _containerMountButton;
    private readonly Button _containerUnmountButton;
    private readonly Button _deviceEjectButton;
    private readonly Button _containerFixButton;
    private readonly Button _containerVerifyButton;
    private readonly Button _containerManageButton;
    private readonly Button _containerCreateButton;
    private readonly Button _memberHealthButton;
    private readonly Button _volumeSnapshotsButton;
    private readonly Button _volumeManageButton;
    private readonly Button _volumeVerifyButton;
    private readonly Button _profileVerifyButton;
    private readonly Func<DriveDashboardRow,Task>? _verifyProfileAsync;
    private readonly Func<DriveDashboardRow, Task>? _verifyVolumeAsync;
    private readonly Func<DriveDashboardRow, Task>? _manageVolumeAsync;
    private readonly Func<DriveDashboardRow, Task>? _snapshotsVolumeAsync;
    private readonly Func<string, string, Task>? _createVolumeAsync;
    private readonly Func<DriveDashboardRow, Task>? _deleteVolumeAsync;
    private readonly Button _volumeDeleteButton;
    private readonly Button _imageResizeButton;
    private readonly Button _imageFormatButton;
    private readonly Func<DriveDashboardRow, Task>? _resizeImageAsync;
    private readonly Func<DriveDashboardRow, Task>? _formatImageAsync;
    private Button? _rescanDevicesButton;
    private Button? _registerImageButton;
    private bool _imageRegistrationAvailable;
    private readonly Func<Task>? _registerImageAsync;
    private string? _selectedContainerDeviceId;
    private string? _selectedContainerUuid;
    private string? _selectedDeviceId;
    private IReadOnlyList<DriveDashboardRow>? _selectedContainerRows;
    private readonly ComboBox _members;
    private bool _refreshingTree;
    private string? _detailsNodeId;
    private sealed record MemberChoice(string Id, string Text)
    {
        public override string ToString() => Text;
    }
    private readonly List<Button> _actionButtons = [];
    private readonly List<RenderedDashboardRow> _renderedRows = [];
    public const string GitHubProjectUrl = "https://github.com/wcwishson/APFS-Access-For-Windows";
    private CheckBox? _startWithWindowsCheckBox;
    private CheckBox? _startMinimizedCheckBox;
    private Button? _updateButton;
    private Button? _gitHubButton;
    private Label? _updateStatusLabel;
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    internal Action? OpenGitHubPageOverride { get; set; }
    private string? _renderedSummary;
    private bool _allowClose;
    private bool _actionsEnabled = true;
    private bool _updatingStartupPreferences;

    private sealed record RenderedDashboardRow(string Identity, Control Control, IReadOnlyList<Button> Buttons);
    private readonly Func<DriveDashboardRow, Task>? _mountVolumeAsync;
    private readonly Func<DriveDashboardRow, Task>? _ejectVolumeAsync;
    private readonly Func<DriveDashboardRow, Task>? _fixVolumeAsync;
    private readonly Func<DriveDashboardRow, Task>? _encryptionVolumeAsync;

    private AppThemeMode _themeMode = AppThemeMode.System;
    private DashboardTheme _currentTheme = DashboardTheme.Light;
    private readonly Func<AppThemeMode, Task>? _setThemeModeAsync;
    private readonly TableLayoutPanel _rootPanel;
    private readonly TableLayoutPanel _summaryHeaderPanel;
    private readonly Panel _detailsContainer;
    private readonly Panel _detailsScroll;
    private readonly FlowLayoutPanel _inspectorToolbar;
    private readonly Label _inspectorTitle;
    private FlowLayoutPanel? _bottomPanel;
    private Label? _themeLabel;
    private ComboBox? _themeComboBox;

    public AppThemeMode ThemeMode => _themeMode;
    public DashboardTheme CurrentTheme => _currentTheme;

    public DashboardForm(
        Func<string?, Task> openAsync,
        Func<string?, Task> ejectAsync,
        Func<string?, Task> fixAsync,
        StartupPreferences? startupPreferences = null,
        Func<bool, Task>? setStartWithWindowsAsync = null,
        Func<bool, Task>? setStartMinimizedAsync = null,
        Func<Task>? checkForUpdatesAsync = null,
        Func<DriveDashboardRow, string, Task>? setDriveLetterAsync = null,
        Func<DriveDashboardRow, Task>? mountVolumeAsync = null,
        Func<Task>? rescanAsync = null,
        Func<DriveDashboardRow, Task>? ejectVolumeAsync = null,
        Func<DriveDashboardRow, Task>? fixVolumeAsync = null,
        Func<DriveDashboardRow, Task>? encryptionVolumeAsync = null,
        Func<string, string, Task>? mountContainerAsync = null,
        Func<string, string, Task>? unmountContainerAsync = null,
        Func<string, Task>? ejectDeviceAsync = null,
        Func<IReadOnlyList<DriveDashboardRow>, Task>? fixContainerAsync = null,
        Func<AppThemeMode, Task>? setThemeModeAsync = null,
        Func<DriveDashboardRow, Task>? verifyVolumeAsync = null,
        Func<DriveDashboardRow, Task>? manageVolumeAsync = null,
        Func<DriveDashboardRow, Task>? snapshotsVolumeAsync = null,
        Func<string, string, Task>? createVolumeAsync = null,
        Func<DriveDashboardRow, Task>? deleteVolumeAsync = null,
        Func<DriveDashboardRow, Task>? resizeImageAsync = null,
        Func<DriveDashboardRow, Task>? formatImageAsync = null,
        Func<ContainerVolumeVerification, Task>? verifyContainerAsync = null,
        Func<Task>? registerImageAsync = null,
        Func<DriveDashboardRow,Task>? verifyProfileAsync = null,
        Action<string>? copyText = null)
    {
        _openAsync = openAsync ?? throw new ArgumentNullException(nameof(openAsync));
        _ejectAsync = ejectAsync ?? throw new ArgumentNullException(nameof(ejectAsync));
        _fixAsync = fixAsync ?? throw new ArgumentNullException(nameof(fixAsync));
        _copyText = copyText ?? Clipboard.SetText;
        _setStartWithWindowsAsync = setStartWithWindowsAsync;
        _setStartMinimizedAsync = setStartMinimizedAsync;
        _checkForUpdatesAsync = checkForUpdatesAsync;
        _setDriveLetterAsync = setDriveLetterAsync;
        _mountVolumeAsync = mountVolumeAsync;
        _ejectVolumeAsync = ejectVolumeAsync;
        _fixVolumeAsync = fixVolumeAsync;
        _encryptionVolumeAsync = encryptionVolumeAsync;
        _mountContainerAsync = mountContainerAsync;
        _unmountContainerAsync = unmountContainerAsync;
        _ejectDeviceAsync = ejectDeviceAsync;
        _fixContainerAsync = fixContainerAsync;
        _verifyContainerAsync = verifyContainerAsync;
        _registerImageAsync = registerImageAsync;
        _verifyProfileAsync = verifyProfileAsync;
        _verifyVolumeAsync = verifyVolumeAsync;
        _manageVolumeAsync = manageVolumeAsync;
        _snapshotsVolumeAsync = snapshotsVolumeAsync;
        _createVolumeAsync = createVolumeAsync;
        _deleteVolumeAsync = deleteVolumeAsync;
        _resizeImageAsync = resizeImageAsync; _formatImageAsync = formatImageAsync;
        startupPreferences ??= new StartupPreferences(StartWithWindows: false, StartMinimized: false);
        _setThemeModeAsync = setThemeModeAsync;
        _themeMode = startupPreferences.ThemeMode;
        _currentTheme = DashboardTheme.Resolve(_themeMode);

        Text = "APFS Access";
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        var screen = Screen.PrimaryScreen;
        var workArea = screen?.WorkingArea ?? new Rectangle(0, 0, 1920, 1080);
        var targetWidth = Math.Min(ScaleDpi(1140), (int)(workArea.Width * 0.92f));
        var targetHeight = Math.Min(ScaleDpi(740), (int)(workArea.Height * 0.88f));
        Size = new Size(targetWidth, targetHeight);
        MinimumSize = new Size(ScaleDpi(360), ScaleDpi(280));
        BackColor = _currentTheme.WindowBackground;
        Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);


        _rootPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(ScaleDpi(16)),
            BackColor = BackColor,
        };
        _rootPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _rootPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        _rootPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(_rootPanel);
        _rootPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

        _summaryHeaderPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Margin = new Padding(0, 0, 0, ScaleDpi(10)),
            Padding = new Padding(0),
            BackColor = BackColor,
        };
        _summaryHeaderPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _summaryHeaderPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _summaryLabel = new Label
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            Font = new Font(Font, FontStyle.Bold),
            ForeColor = _currentTheme.TextPrimary,
            Margin = new Padding(0, 0, 0, ScaleDpi(6)),
            Text = "Starting APFS Access...",
        };
        _summaryHeaderPanel.Controls.Add(_summaryLabel, 0, 0);

        _activityBar = new ProgressBar
        {
            Dock = DockStyle.Top,
            Height = Math.Max(3, ScaleDpi(3)),
            Style = ProgressBarStyle.Blocks,
            MarqueeAnimationSpeed = 0,
            Visible = false,
            ForeColor = Color.FromArgb(14, 165, 233),
            Margin = new Padding(0),
        };
        _summaryHeaderPanel.Controls.Add(_activityBar, 0, 1);
        _rootPanel.Controls.Add(_summaryHeaderPanel, 0, 0);

        _rowsPanel = new FlowLayoutPanel
        {
            AutoScroll = true,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            BackColor = BackColor,
            Margin = new Padding(0),
        };

        _topologyLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 2,
            BackColor = BackColor,
        };
        _topologyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30F));
        _topologyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70F));
        _topologyLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        _topologyLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 0F));

        _treeContextMenu = new ContextMenuStrip();
        _treeContextMenu.Renderer = _currentTheme.IsDark ? new DarkToolStripRenderer() : new ToolStripProfessionalRenderer();
        _treeContextMenu.Opening += (_, _) => PopulateContextMenu();

        _topologyTree = new TreeView
        {
            Dock = DockStyle.Fill,
            HideSelection = false,
            ShowNodeToolTips = false,
            AccessibleName = "APFS topology",
            TabIndex = 0,
            ItemHeight = Math.Max(26, ScaleDpi(26)),
            Font = new Font("Segoe UI", 9.5F, FontStyle.Regular),
            ContextMenuStrip = _treeContextMenu,
            BackColor = _currentTheme.TreeViewBackground,
            ForeColor = _currentTheme.TreeViewText,
            LineColor = _currentTheme.TreeViewLineColor,
        };
        _topologyTree.MouseDown += (s, e) =>
        {
            if (e.Button == MouseButtons.Right)
            {
                var hit = _topologyTree.HitTest(e.Location);
                if (hit.Node is not null)
                {
                    _topologyTree.SelectedNode = hit.Node;
                }
                PopulateContextMenu();
            }
        };

        void StyleToolbarButton(Button btn)
        {
            btn.AutoSize = true;
            btn.Margin = new Padding(0, 0, ScaleDpi(6), ScaleDpi(6));
            btn.Padding = new Padding(ScaleDpi(8), ScaleDpi(3), ScaleDpi(8), ScaleDpi(3));
            StyleButtonByTheme(btn);
        }

        _storageBar = new ApfsStorageBarControl
        {
            Dock = DockStyle.Top,
            Visible = false,
            Margin = new Padding(0, ScaleDpi(4), 0, ScaleDpi(8)),
            IsDarkMode = _currentTheme.IsDark,
            BackColor = BackColor,
        };

        _memberButton = new Button { Text = "Go to member / container", Enabled = false };
        StyleToolbarButton(_memberButton);

        _containerMountButton = new Button { Text = "Mount container", Enabled = false, Visible = false };
        StyleToolbarButton(_containerMountButton);
        _containerMountButton.Click += (_, _) => RunContainerActionAsync(_mountContainerAsync, "Mounting container...");

        _containerUnmountButton = new Button { Text = "Unmount container", Enabled = false, Visible = false };
        StyleToolbarButton(_containerUnmountButton);
        _containerUnmountButton.Click += (_, _) => RunContainerActionAsync(_unmountContainerAsync, "Unmounting container...");

        _deviceEjectButton = new Button { Text = "Eject device", Enabled = false, Visible = false };
        StyleToolbarButton(_deviceEjectButton);
        _deviceEjectButton.Click += (_, _) => RunDeviceActionAsync();

        _containerFixButton = new Button { Text = "Fix container", Enabled = false, Visible = false };
        StyleToolbarButton(_containerFixButton);
        _containerFixButton.Click += (_, _) => RunFixContainerActionAsync();

        _containerVerifyButton = new Button { Text = "Verify volumes", Enabled = false, Visible = false,
            AccessibleDescription = DriveDashboardPresenter.ContainerUnavailableActionReason("container-verify") };
        StyleToolbarButton(_containerVerifyButton);
        _containerVerifyButton.Click += (_, _) => RunVerifyContainerActionAsync();

        _containerManageButton = new Button { Text = "Manage offline volume", Enabled = false, Visible = false,
            AccessibleDescription = "Select an offline container member for rename or quota/reserve." };
        StyleToolbarButton(_containerManageButton);
        _containerManageButton.Click+=(_,_)=>RunContainerManagement();
        _containerCreateButton = new Button { Text = "Create image volume", Enabled = false, Visible = false,
            AccessibleDescription = "Requires a bounded offline image and native management observation with a configured durable journal root." };
        StyleToolbarButton(_containerCreateButton);
        _containerCreateButton.Click += (_, _) => RunContainerActionAsync(_createVolumeAsync, "Planning image volume...");

        _volumeSnapshotsButton = new Button { Text = "Volume snapshots", Enabled = false, Visible = false,
            AccessibleDescription = DriveDashboardPresenter.VolumeUnavailableActionReason("snapshots") };
        StyleToolbarButton(_volumeSnapshotsButton);
        _volumeSnapshotsButton.Click += (_, _) => RunOfflineSelectedAction(_snapshotsVolumeAsync, "Opening snapshots...");

        _volumeManageButton = new Button { Text = "Manage volume", Enabled = false, Visible = false,
            AccessibleDescription = DriveDashboardPresenter.VolumeUnavailableActionReason("manage") };
        StyleToolbarButton(_volumeManageButton);
        _volumeManageButton.Click += (_, _) => RunOfflineSelectedAction(_manageVolumeAsync, "Managing volume...");

        _volumeVerifyButton = new Button { Text = "Verify volume", Enabled = false, Visible = false };
        StyleToolbarButton(_volumeVerifyButton);
        _volumeVerifyButton.Click += (_, _) => RunOfflineSelectedAction(_verifyVolumeAsync, "Verifying volume...");
        _profileVerifyButton=new Button{Text="Verify current profile",Enabled=false,Visible=false};
        StyleToolbarButton(_profileVerifyButton);
        _profileVerifyButton.Click+=(_,_)=>RunOfflineSelectedAction(_verifyProfileAsync,"Verifying current profile...");
        _volumeDeleteButton = new Button { Text = "Delete image volume", Enabled = false, Visible = false,
            AccessibleDescription = "Requires a bounded offline image and native management observation with a configured durable journal root." };
        StyleToolbarButton(_volumeDeleteButton);
        _volumeDeleteButton.Click += (_, _) => RunOfflineSelectedAction(_deleteVolumeAsync, "Planning volume deletion...");
        _imageResizeButton = new Button { Text = "Resize image container", Enabled = false, Visible = false };
        StyleToolbarButton(_imageResizeButton);
        _imageResizeButton.Click += (_, _) => RunOfflineSelectedAction(_resizeImageAsync, "Planning image resize...");
        _imageFormatButton = new Button { Text = "Format image container", Enabled = false, Visible = false };
        StyleToolbarButton(_imageFormatButton);
        _imageFormatButton.Click += (_, _) => RunOfflineSelectedAction(_formatImageAsync, "Planning image format...");

        _memberHealthButton = new Button { Text = "Member health", Enabled = true, Visible = false,
            AccessibleDescription = "Inspect APFS member health and container binding" };
        StyleToolbarButton(_memberHealthButton);
        _memberHealthButton.Click += (_, _) => ShowMemberHealth();

        _members = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            AccessibleName = "Member identity",
            Width = ScaleDpi(220),
            FlatStyle = FlatStyle.Flat,
            Margin = new Padding(0, 0, ScaleDpi(6), ScaleDpi(6)),
            DrawMode = DrawMode.OwnerDrawFixed,
            BackColor = _currentTheme.DropdownBackground,
            ForeColor = _currentTheme.DropdownText,
        };
        _members.ItemHeight = Math.Max(20, ScaleDpi(20));
        _members.DrawItem += (s, e) =>
        {
            if (e.Index < 0 || e.Index >= _members.Items.Count) return;
            var isDark = _currentTheme.IsDark;
            var isSelected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
            var bg = isSelected ? (isDark ? Color.FromArgb(58, 62, 72) : SystemColors.Highlight) : (isDark ? _currentTheme.DropdownBackground : Color.White);
            var fg = isSelected ? (isDark ? Color.White : SystemColors.HighlightText) : (isDark ? _currentTheme.DropdownText : SystemColors.WindowText);
            using var brush = new SolidBrush(bg);
            e.Graphics.FillRectangle(brush, e.Bounds);
            var text = _members.Items[e.Index]?.ToString() ?? "";
            TextRenderer.DrawText(e.Graphics, text, e.Font ?? _members.Font, e.Bounds, fg, TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
        };

        _memberPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = false,
            WrapContents = true,
            BackColor = BackColor,
            Padding = new Padding(0),
            Margin = new Padding(0),
        };
        _memberPanel.Controls.Add(_members);
        _memberPanel.Controls.Add(_memberButton);
        if (mountContainerAsync is not null)
            _memberPanel.Controls.Add(_containerMountButton);
        if (unmountContainerAsync is not null)
            _memberPanel.Controls.Add(_containerUnmountButton);
        if (ejectDeviceAsync is not null)
            _memberPanel.Controls.Add(_deviceEjectButton);
        if (fixContainerAsync is not null)
            _memberPanel.Controls.Add(_containerFixButton);
        _memberPanel.Controls.Add(_containerVerifyButton);
        _memberPanel.Controls.Add(_containerManageButton);
        _memberPanel.Controls.Add(_imageResizeButton); _memberPanel.Controls.Add(_imageFormatButton);
        _memberPanel.Controls.Add(_containerCreateButton);
        _memberPanel.Controls.Add(_volumeSnapshotsButton);
        _memberPanel.Controls.Add(_volumeManageButton);
        _memberPanel.Controls.Add(_volumeVerifyButton);
        _memberPanel.Controls.Add(_profileVerifyButton);
        _memberPanel.Controls.Add(_volumeDeleteButton);
        _memberPanel.Controls.Add(_memberHealthButton);

        if (rescanAsync is not null)
        {
            _rescanDevicesButton = BuildActionButton(_actionButtons, "Rescan devices", true,
                () => RunActionAsync("Refreshing inventory...", rescanAsync));
            StyleToolbarButton(_rescanDevicesButton);
            _memberPanel.Controls.Add(_rescanDevicesButton);
        }

        _memberButton.Click += (_, _) => NavigateMember();
        _topologyTree.NodeMouseDoubleClick += (_, _) => NavigateMember();
        _topologyTree.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { NavigateMember(); e.Handled = true; } };

        _nodeDetails = new Label
        {
            AutoSize = true,
            Dock = DockStyle.Top,
            AccessibleName = "Selected node details",
            Font = new Font("Consolas", 8.75F, FontStyle.Regular, GraphicsUnit.Point),
            ForeColor = _currentTheme.DetailsText,
            BackColor = _currentTheme.DetailsBackground,
        };
        _detailsScroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = _currentTheme.DetailsBackground, Padding = new Padding(ScaleDpi(6)) };
        _detailsScroll.Controls.Add(_nodeDetails);
        _detailsScroll.SizeChanged += (_, _) => _nodeDetails.MaximumSize = new Size(Math.Max(80, _detailsScroll.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - ScaleDpi(16)), 0);

        _inspectorToolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
            Padding = new Padding(0, ScaleDpi(4), 0, ScaleDpi(4)),
            Margin = new Padding(0),
            BackColor = BackColor,
        };

        _inspectorTitle = new Label
        {
            Text = "INSPECTOR & DIAGNOSTICS",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold, GraphicsUnit.Point),
            ForeColor = _currentTheme.TextMuted,
            AutoSize = true,
            Margin = new Padding(0, ScaleDpi(5), ScaleDpi(8), ScaleDpi(4)),
        };
        _copyDetailsButton = new Button
        {
            Text = "Copy info",
            AutoSize = true,
            Margin = new Padding(0, 0, ScaleDpi(4), 0),
            Padding = new Padding(ScaleDpi(8), ScaleDpi(2), ScaleDpi(8), ScaleDpi(2)),
            Font = new Font("Segoe UI", 8F),
        };
        StyleToolbarButton(_copyDetailsButton);
        _copyDetailsButton.Click += (_, _) => CopyDetailsToClipboard();

        _copyJsonButton = new Button
        {
            Text = "Copy JSON",
            AutoSize = true,
            Margin = new Padding(0, 0, ScaleDpi(4), 0),
            Padding = new Padding(ScaleDpi(8), ScaleDpi(2), ScaleDpi(8), ScaleDpi(2)),
            Font = new Font("Segoe UI", 8F),
        };
        StyleToolbarButton(_copyJsonButton);
        _copyJsonButton.Click += (_, _) => CopyJsonToClipboard();

        _inspectorToolbar.Controls.Add(_inspectorTitle);
        _inspectorToolbar.Controls.Add(_copyDetailsButton);
        _inspectorToolbar.Controls.Add(_copyJsonButton);

        _detailsContainer = new Panel
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(0),
            Padding = new Padding(0),
            BackColor = BackColor,
        };
        _detailsContainer.Controls.Add(_inspectorToolbar);
        _detailsContainer.Controls.Add(_detailsScroll);
        _detailsScroll.BringToFront();

        _detailContainer = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = BackColor,
            Padding = new Padding(ScaleDpi(8), 0, 0, 0),
        };

        _detailsTopPanel = new Panel
        {
            Dock = DockStyle.Top,
            AutoSize = false,
            BackColor = BackColor,
            Padding = new Padding(0),
            Margin = new Padding(0),
        };
        _detailsTopPanel.Controls.Add(_memberPanel);
        _detailsTopPanel.Controls.Add(_storageBar);
        _storageBar.BringToFront();

        _contentSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = Math.Max(6, ScaleDpi(8)),
            Panel1MinSize = ScaleDpi(60),
            Panel2MinSize = ScaleDpi(60),
            BackColor = _currentTheme.SplitterColor,
            IsSplitterFixed = true,
        };
        _contentSplit.Panel1.BackColor = BackColor;
        _contentSplit.Panel1.Controls.Add(_rowsPanel);
        _contentSplit.Panel2.BackColor = BackColor;
        _contentSplit.Panel2.Controls.Add(_detailsContainer);

        _contentSplit.MouseMove += (_, e) =>
        {
            var isOverSplitter = e.Y >= _contentSplit.SplitterDistance && e.Y <= _contentSplit.SplitterDistance + _contentSplit.SplitterWidth;
            if (_isDraggingContentSplit)
            {
                var delta = e.Y - _dragStartY;
                var newDist = _dragStartDistance + delta;
                var totalAvailable = _contentSplit.ClientSize.Height - _contentSplit.SplitterWidth;
                var min = _contentSplit.Panel1MinSize;
                var max = Math.Max(min, totalAvailable - _contentSplit.Panel2MinSize);
                newDist = Math.Clamp(newDist, min, max);
                if (_contentSplit.SplitterDistance != newDist)
                {
                    SafeSetSplitterDistance(_contentSplit, newDist);
                    _userAdjustedContentSplit = true;
                    _contentSplit.Invalidate();
                }
            }
            else
            {
                _contentSplit.Cursor = isOverSplitter ? Cursors.HSplit : Cursors.Default;
            }
        };

        _contentSplit.MouseDown += (_, e) =>
        {
            if (e.Button == MouseButtons.Left &&
                e.Y >= _contentSplit.SplitterDistance &&
                e.Y <= _contentSplit.SplitterDistance + _contentSplit.SplitterWidth)
            {
                _isDraggingContentSplit = true;
                _dragStartY = e.Y;
                _dragStartDistance = _contentSplit.SplitterDistance;
                _contentSplit.Capture = true;
                _contentSplit.Invalidate();
            }
        };

        _contentSplit.MouseUp += (_, e) =>
        {
            if (_isDraggingContentSplit)
            {
                _isDraggingContentSplit = false;
                _contentSplit.Capture = false;
                _contentSplit.Invalidate();
            }
        };

        _contentSplit.MouseLeave += (_, _) =>
        {
            if (!_isDraggingContentSplit)
            {
                _contentSplit.Cursor = Cursors.Default;
            }
        };

        _contentSplit.DoubleClick += (_, _) =>
        {
            _userAdjustedContentSplit = false;
            AdjustContentSplitDistance();
            _contentSplit.Invalidate();
        };

        _contentSplit.Paint += (_, e) =>
        {
            if (_contentSplit.Panel1Collapsed || _contentSplit.Panel2Collapsed) return;
            var splitterRect = new Rectangle(0, _contentSplit.SplitterDistance, _contentSplit.ClientSize.Width, _contentSplit.SplitterWidth);
            using var bgBrush = new SolidBrush(_currentTheme.WindowBackground);
            e.Graphics.FillRectangle(bgBrush, splitterRect);

            using var linePen = new Pen(_currentTheme.SplitterColor, 1F);
            var midY = splitterRect.Top + (splitterRect.Height / 2);
            e.Graphics.DrawLine(linePen, 0, midY, splitterRect.Width, midY);

            var gripWidth = ScaleDpi(36);
            var gripHeight = Math.Max(3, ScaleDpi(4));
            var gripRect = new Rectangle(
                (splitterRect.Width - gripWidth) / 2,
                splitterRect.Top + (splitterRect.Height - gripHeight) / 2,
                gripWidth,
                gripHeight);

            var handleColor = _isDraggingContentSplit
                ? (_currentTheme.IsDark ? Color.FromArgb(130, 140, 160) : Color.FromArgb(100, 116, 139))
                : (_currentTheme.IsDark ? Color.FromArgb(70, 75, 88) : Color.FromArgb(190, 198, 210));
            using var gripBrush = new SolidBrush(handleColor);
            using var gripPath = CreateRoundedRectanglePath(gripRect, ScaleDpi(2));
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            e.Graphics.FillPath(gripBrush, gripPath);
        };

        _detailContainer.Controls.Add(_contentSplit);
        _detailContainer.Controls.Add(_detailsTopPanel);
        _detailsTopPanel.BringToFront();

        _detailContainer.SizeChanged += (_, _) => AdjustMemberPanelHeight();
        _contentSplit.SizeChanged += (_, _) => { if (!_resizing && !_adjustingContentSplit) AdjustContentSplitDistance(); };


        _topologyLayout.Controls.Add(_topologyTree, 0, 0);
        _topologyLayout.Controls.Add(_detailContainer, 1, 0);
        _topologyLayout.SizeChanged += (_, _) => { if (!_resizing) ResizeTopology(); };
        _rowsPanel.SizeChanged += (_, _) => { if (!_resizing && !_adjustingContentSplit) ResizeRows(); };
        _topologyTree.AfterSelect += (_, _) => { if (!_refreshingTree) ShowSelectedNode(); };
        _rootPanel.Controls.Add(_topologyLayout, 0, 1);

        Load += (_, _) =>
        {
            try
            {
                ResizeTopology();
            }
            catch
            {
            }
            AdjustMemberPanelHeight();
            ResizeRows();
            AdjustContentSplitDistance();
        };

        _rootPanel.Controls.Add(BuildStartupPreferencesPanel(startupPreferences), 0, 2);

        ApplyStatus(new StatusChangedPayload(
            State: ApfsAccess.Core.RuntimeState.Starting,
            MountPoints: Array.Empty<string>(),
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>()));
    }

    private long? _inventoryGeneration;
    private StatusChangedPayload? _lastAppliedStatus;
    private ApfsAccess.Core.ApfsTopologySnapshot? _lastTopology;
    private bool _resizing;
    private bool _treeInitiallyExpanded;
    private bool _adjustingContentSplit;
    private bool _userAdjustedContentSplit;
    private bool _isDraggingContentSplit;
    private int _dragStartY;
    private int _dragStartDistance;

    // Display refreshes skip statuses that render identically to the last
    // applied one (the service republishes every poll interval with a fresh
    // timestamp). Comparison is structural over the whole payload except the
    // timestamp, so any real change still rebuilds immediately.
    internal static bool IsDisplayEqual(StatusChangedPayload a, StatusChangedPayload b)
    {
        if (ReferenceEquals(a, b)) return true;
        var left = System.Text.Json.JsonSerializer.Serialize(a with { TimestampUtc = b.TimestampUtc });
        var right = System.Text.Json.JsonSerializer.Serialize(b);
        return string.Equals(left, right, StringComparison.Ordinal);
    }

    public void ApplyStatus(StatusChangedPayload payload)
        => ApplyTopologyStatus(payload, null);

    // Ordinary status delivery projects the inventory observations carried by this payload.
    public void ApplyTopologyStatus(StatusChangedPayload payload, ApfsAccess.Core.ApfsTopologySnapshot? topology)
    {
        if (IsDisposed)
        {
            return;
        }

        if (payload.InventoryGeneration is {} generation && _inventoryGeneration is {} previous && generation < previous) return;
        _inventoryGeneration = payload.InventoryGeneration;
        if (_lastAppliedStatus is {} applied && IsDisplayEqual(applied, payload)) return;
        _lastAppliedStatus = payload;
        _lastTopology = topology;
        var nodes = TopologyDashboard.Project(payload, topology);
        _refreshingTree = true;
        try { TopologyTreeRefresh.Apply(_topologyTree, nodes); }
        finally { _refreshingTree = false; }
        if (!_treeInitiallyExpanded && _topologyTree.Nodes.Cast<TreeNode>().Any(n => n.Nodes.Count > 0))
        {
            _treeInitiallyExpanded = true;
            _topologyTree.ExpandAll();
        }
        ShowSelectedNode();
        var summary = TopologyStatusProjection.IsBounded(payload) ? DriveDashboardPresenter.BuildSummary(payload) : "Details unavailable";
        if (_renderedSummary != summary) _summaryLabel.Text = summary;
        _renderedSummary = summary;
    }

    public void SetFooter(string message)
    {
        _summaryLabel.Text = message;
    }

    private void ShowSelectedNode()
    {
        if (_topologyTree.SelectedNode?.Tag is not TopologyDashboardNode node) return;
        var details = _detailsNodeId == node.Id ? node.Details : (!string.IsNullOrWhiteSpace(node.Details) ? node.Details : node.Text);
        if(node.Row is { } profileRow && DriveDashboardPresenter.ProfileVerificationUnavailableReason(profileRow) is { } profileReason)
            details+="\r\n\r\nCurrent profile verification: "+profileReason;
        if (_nodeDetails.Text != details) _nodeDetails.Text = details;
        var members = node.MemberIds ?? [];
        var choices = members.Select((id, index) => new MemberChoice(id,
            $"Member {index + 1} · " + ((_topologyTree.Nodes.Find(id, true).FirstOrDefault()?.Tag as TopologyDashboardNode)?.Text ?? "Unavailable"))).ToArray();
        if (!_members.Items.Cast<MemberChoice>().SequenceEqual(choices))
        {
            var selected = (_members.SelectedItem as MemberChoice)?.Id;
            _members.Items.Clear();
            _members.Items.AddRange(choices.Cast<object>().ToArray());
            if (choices.FirstOrDefault(c => c.Id == selected) is {} retained) _members.SelectedItem = retained;
            else if (_members.Items.Count > 0) _members.SelectedIndex = 0;
        }
        _members.DropDownWidth = Math.Min(ScaleDpi(900), Math.Max(_members.Width,
            choices.Select(c => TextRenderer.MeasureText(c.Text, _members.Font).Width + ScaleDpi(32)).DefaultIfEmpty(0).Max()));
        _members.Visible = members.Count > 0;
        _memberButton.Enabled = node.ReferenceId is not null || members.Count > 0 || _topologyTree.SelectedNode.Nodes.Count > 0;
        _memberButton.Visible = _memberButton.Enabled;
        ReconcileContainerButtons(_topologyTree.SelectedNode);
        _memberHealthButton.Text = "Member health";
        ReconcileRows(node.Row is {} row ? new[] { row } : []);
        UpdateStorageBar(_topologyTree.SelectedNode);
        if (_contentSplit is not null)
        {
            var hasRows = node.Row is not null;
            if (_contentSplit.Panel1Collapsed != !hasRows)
            {
                _contentSplit.Panel1Collapsed = !hasRows;
            }
            if (hasRows)
            {
                AdjustContentSplitDistance();
            }
        }
        AdjustMemberPanelHeight();
    }

    private void ReconcileContainerButtons(TreeNode? selected)
    {
        _selectedContainerDeviceId = null;
        _selectedContainerUuid = null;
        _selectedDeviceId = null;
        _selectedContainerRows = null;
        _selectedContainerVerification = null;
        var canMount = false;
        var canUnmount = false;
        var canEjectDevice = false;
        var canFix = false;
        var containerSelected = false;
        var isDeviceNode = selected?.Tag is TopologyDashboardNode devNode &&
            devNode.Row is null &&
            (devNode.Id.StartsWith("apfs-disk:", StringComparison.Ordinal) ||
             devNode.Id.StartsWith("inventory-device:", StringComparison.Ordinal));

        if (selected is not null)
        {
            var rows = CollectDescendantRows(selected);
            if (DriveDashboardPresenter.TryResolveContainerTarget(rows, out var deviceId, out var containerUuid))
            {
                containerSelected = true;
                canMount = _mountContainerAsync is not null && DriveDashboardPresenter.ContainerMountAvailable(rows);
                canUnmount = _unmountContainerAsync is not null && DriveDashboardPresenter.ContainerUnmountAvailable(rows);
                canFix = _fixContainerAsync is not null && DriveDashboardPresenter.ContainerFixAvailable(rows);
                _selectedContainerDeviceId = deviceId;
                _selectedContainerUuid = containerUuid;
                _selectedContainerRows = rows;
            }

            if (isDeviceNode && DriveDashboardPresenter.TryResolveDeviceTarget(rows, out var deviceOnlyId))
            {
                canEjectDevice = _ejectDeviceAsync is not null && DriveDashboardPresenter.DeviceEjectAvailable(rows);
                if (canEjectDevice)
                {
                    _selectedDeviceId = deviceOnlyId;
                }
            }
        }

        var isPartitionOrStore = false;
        var volumeSelected = false;
        if (selected?.Tag is TopologyDashboardNode node)
        {
            if (node.Id.StartsWith("apfs-part:", StringComparison.Ordinal) ||
                node.Id.StartsWith("apfs-store:", StringComparison.Ordinal) ||
                node.Id.StartsWith("registered-store:", StringComparison.Ordinal))
            {
                isPartitionOrStore = true;
            }
            if (node.Row is not null || node.Id.StartsWith("apfs-vol:", StringComparison.Ordinal) || node.Id.StartsWith("inventory-volume:", StringComparison.Ordinal))
            {
                volumeSelected = true;
            }
        }

        _containerMountButton.Enabled = _actionsEnabled && canMount;
        _containerMountButton.Visible = canMount;
        _containerUnmountButton.Enabled = _actionsEnabled && canUnmount;
        _containerUnmountButton.Visible = canUnmount;
        _deviceEjectButton.Enabled = _actionsEnabled && canEjectDevice;
        _deviceEjectButton.Visible = canEjectDevice;
        var fixReason = "No current bound member needs admitted Fix work.";
        if (canFix && _lastAppliedStatus is { } fixStatus && _selectedContainerRows is { } fixRows)
        {
            try { fixReason = ContainerFixFlow.Capture(fixStatus, fixRows).Capability.Reason; }
            catch (InvalidOperationException ex) { canFix = false; fixReason = ex.Message; }
        }
        _containerFixButton.AccessibleDescription = fixReason;
        _containerFixButton.Enabled = _actionsEnabled && canFix;
        _containerFixButton.Visible = canFix;
        var verifyContainerSelected = containerSelected && selected?.Tag is TopologyDashboardNode verifyNode &&
            IsContainerNode(verifyNode);
        var verifyReason = DriveDashboardPresenter.ContainerUnavailableActionReason("container-verify");
        if (verifyContainerSelected && _lastAppliedStatus is { } status && _selectedContainerRows is { } verifyRows)
            ContainerVolumeVerification.TryCapture(status, verifyRows, out _selectedContainerVerification, out verifyReason);
        _containerVerifyButton.Visible = verifyContainerSelected;
        _containerVerifyButton.Enabled = _actionsEnabled && _verifyContainerAsync is not null && _selectedContainerVerification is not null;
        _containerVerifyButton.AccessibleDescription = verifyReason;
        _containerManageButton.Visible = containerSelected;
        var canManage = false;
        var managementReason = DriveDashboardPresenter.ContainerUnavailableActionReason("container-manage");
        if (_lastAppliedStatus is { } managementStatus && _selectedContainerRows is { } managementRows &&
            DriveDashboardPresenter.ContainerManageAvailable(managementRows))
        {
            try { var selection = ContainerManagementSelection.Capture(managementStatus, managementRows);
                canManage = selection.Capability.IsAvailable; managementReason = selection.Capability.Reason; }
            catch (InvalidOperationException ex) { managementReason = ex.Message; }
        }
        _containerManageButton.AccessibleDescription = managementReason;
        _containerManageButton.Enabled = _actionsEnabled && _manageVolumeAsync is not null && canManage;
        _memberHealthButton.Visible = isPartitionOrStore;
        _volumeSnapshotsButton.Visible = volumeSelected;
        _volumeManageButton.Visible = volumeSelected;
        var selectedRow = (selected?.Tag as TopologyDashboardNode)?.Row;
        _volumeSnapshotsButton.Enabled = _actionsEnabled && _snapshotsVolumeAsync is not null &&
            selectedRow is { } snapshotRow && (snapshotRow.CanVerifyOffline || snapshotRow.CanListSnapshots || snapshotRow.CanRecoverSnapshots);
        _volumeManageButton.Enabled = _actionsEnabled && _manageVolumeAsync is not null && selectedRow?.CanManageOffline == true;
        _volumeVerifyButton.Visible = volumeSelected;
        _volumeVerifyButton.Enabled = _actionsEnabled && _verifyVolumeAsync is not null && selectedRow is { } verifyRow && (verifyRow.CanVerifyOffline || verifyRow.CanVerifyLive);
        _profileVerifyButton.Visible=volumeSelected && (selectedRow?.RegisteredImage is not null || selectedRow?.RegisteredFusion is not null);
        _profileVerifyButton.Enabled=_actionsEnabled && _verifyProfileAsync is not null && selectedRow is not null && DriveDashboardPresenter.CanVerifyCurrentProfile(selectedRow);
        var profileReason=selectedRow is null?null:DriveDashboardPresenter.ProfileVerificationUnavailableReason(selectedRow);
        _profileVerifyButton.AccessibleDescription=profileReason;
        _profileVerifyButton.Text=profileReason is null?"Verify current profile":selectedRow?.RegisteredFusion is not null?"Unmount pair to verify":"Lock image to verify";
        _volumeDeleteButton.Visible = volumeSelected;
        _volumeDeleteButton.Enabled = _actionsEnabled && _deleteVolumeAsync is not null && selectedRow?.CanManageTopologyImage == true;
        _imageResizeButton.Visible = _imageFormatButton.Visible = volumeSelected;
        _imageResizeButton.Enabled = _actionsEnabled && _resizeImageAsync is not null && selectedRow?.CanResizeImage == true;
        _imageFormatButton.Enabled = _actionsEnabled && _formatImageAsync is not null && selectedRow?.CanFormatImage == true;
        _containerCreateButton.Visible = containerSelected;
        _containerCreateButton.Enabled = _actionsEnabled && _createVolumeAsync is not null && containerSelected &&
            _selectedContainerRows is { Count: > 0 } members && members.All(r => r.CanManageTopologyImage);
        if (_rescanDevicesButton is not null)
        {
            _rescanDevicesButton.Text = isDeviceNode ? "Rescan device" : "Rescan devices";
        }
    }

    private static IReadOnlyList<DriveDashboardRow> CollectDescendantRows(TreeNode node)
    {
        var rows = new List<DriveDashboardRow>();
        void Visit(TreeNode current)
        {
            if (current.Tag is TopologyDashboardNode model && model.Row is {} row) rows.Add(row);
            foreach (TreeNode child in current.Nodes) Visit(child);
        }

        Visit(node);
        return rows;
    }

    private static bool IsContainerNode(TopologyDashboardNode node)
    {
        var id = node.Id;
        if (id.StartsWith('['))
        {
            try { id = System.Text.Json.JsonSerializer.Deserialize<string[]>(id)?.LastOrDefault() ?? string.Empty; }
            catch (System.Text.Json.JsonException) { return false; }
        }
        return node.Row is null && (id.StartsWith("apfs-container:", StringComparison.Ordinal) ||
            id.StartsWith("registered-container:", StringComparison.Ordinal));
    }

    private void RunOfflineSelectedAction(Func<DriveDashboardRow, Task>? action, string message)
    {
        if (action is null || _topologyTree.SelectedNode?.Tag is not TopologyDashboardNode { Row: { } row }) return;
        _ = RunActionAsync(message, () => action(row));
    }

    private void RunContainerManagement()
    {
        if(!_containerManageButton.Enabled||_lastAppliedStatus is null||_selectedContainerRows is null||_manageVolumeAsync is null)return;
        try
        {
            var selected=ContainerManagementSelection.Capture(_lastAppliedStatus,_selectedContainerRows);
            using var picker=new ContainerManagementDialog(selected);
            if(picker.ShowDialog(this)!=DialogResult.OK||picker.SelectedVolumeId is not { } id)return;
            DispatchContainerManagement(selected,id);
        }
        catch(Exception ex){SetFooter(ex.Message);}
    }

    internal void DispatchContainerManagement(ContainerManagementSelection selected,string volumeId)
    {
        if(_lastAppliedStatus is null||_manageVolumeAsync is null)throw new InvalidOperationException("Current management status is unavailable.");
        var row=selected.Resolve(_lastAppliedStatus,volumeId);
        _=RunActionAsync("Managing selected offline volume...",()=>_manageVolumeAsync(row));
    }

    private void RunContainerActionAsync(Func<string, string, Task>? action, string workingMessage)
    {
        if (_selectedContainerDeviceId is not {} deviceId ||
            _selectedContainerUuid is not {} containerUuid || action is null) return;
        _ = RunActionAsync(workingMessage, () => action(deviceId, containerUuid));
    }

    private void RunDeviceActionAsync()
    {
        if (_selectedDeviceId is not {} deviceId || _ejectDeviceAsync is null) return;
        _ = RunActionAsync("Ejecting device...", () => _ejectDeviceAsync(deviceId));
    }

    private void RunFixContainerActionAsync()
    {
        if (_selectedContainerRows is not {} rows || _fixContainerAsync is null) return;
        _ = RunActionAsync("Fixing container...", () => _fixContainerAsync(rows));
    }

    private void RunVerifyContainerActionAsync()
    {
        if (!_containerVerifyButton.Enabled || _selectedContainerVerification is not { } selection || _verifyContainerAsync is null) return;
        _ = RunActionAsync("Verifying volume metadata...", () => _verifyContainerAsync(selection));
    }

    private void NavigateMember()
    {
        if (_topologyTree.SelectedNode?.Tag is not TopologyDashboardNode node) return;
        var targetId = node.ReferenceId ?? (node.MemberIds?.Count > 0 ? (_members.SelectedItem as MemberChoice)?.Id : null);
        var target = targetId is {} id ? _topologyTree.Nodes.Find(id, true).FirstOrDefault()
            : _topologyTree.SelectedNode.Nodes.Cast<TreeNode>().FirstOrDefault();
        if (target is null) return;
        _topologyTree.SelectedNode = target;
        target.EnsureVisible();
        _topologyTree.Focus();
    }

    private void ShowMemberHealth()
    {
        if (_topologyTree.SelectedNode?.Tag is not TopologyDashboardNode node) return;
        var healthText = DriveDashboardPresenter.FormatMemberHealth(node);
        if (_nodeDetails.Text == healthText)
        {
            _detailsNodeId = node.Id;
            _nodeDetails.Text = node.Details;
            _memberHealthButton.Text = "Member health";
        }
        else
        {
            _detailsNodeId = node.Id;
            _nodeDetails.Text = healthText;
            _memberHealthButton.Text = "Node details";
        }
    }

    private void CopyDetailsToClipboard()
    {
        if (string.IsNullOrWhiteSpace(_nodeDetails.Text)) return;
        try
        {
            _copyText(_nodeDetails.Text);
            SetFooter("Copied node details to clipboard.");
        }
        catch (Exception ex)
        {
            SetFooter($"Clipboard copy failed: {ex.Message}");
        }
    }

    private void CopyJsonToClipboard()
    {
        if (_topologyTree.SelectedNode?.Tag is not TopologyDashboardNode node) return;
        try
        {
            object payloadToSerialize = node.Row is { } r ? (object)r : node;
            var json = System.Text.Json.JsonSerializer.Serialize(payloadToSerialize, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            _copyText(json);
            SetFooter("Copied JSON diagnostics to clipboard.");
        }
        catch (Exception ex)
        {
            SetFooter($"JSON copy failed: {ex.Message}");
        }
    }

    private void UpdateStorageBar(TreeNode? selectedNode)
    {
        if (_storageBar is null) return;
        if (selectedNode?.Tag is not TopologyDashboardNode node)
        {
            _storageBarActive = false;
            _storageBar.Visible = false;
            return;
        }

        if (_lastAppliedStatus is not { } status)
        {
            _storageBarActive = false;
            _storageBar.Visible = false;
            return;
        }

        var activeTopology = _lastTopology
            ?? status.ConnectedInventory?.FirstOrDefault(d => d.Topology?.Snapshot is not null)?.Topology?.Snapshot;

        var colors = new[]
        {
            Color.FromArgb(14, 165, 233),   // Sky blue
            Color.FromArgb(139, 92, 246),  // Purple
            Color.FromArgb(16, 185, 129),  // Emerald green
            Color.FromArgb(245, 158, 11),  // Amber
            Color.FromArgb(244, 63, 94),   // Rose
            Color.FromArgb(6, 182, 212),   // Cyan
            Color.FromArgb(236, 72, 153),  // Pink
        };

        // 1. DISK node
        if (node.Id.StartsWith("apfs-disk:", StringComparison.Ordinal) ||
            node.Id.StartsWith("inventory-device:", StringComparison.Ordinal))
        {
            var disk = activeTopology?.Disks.FirstOrDefault(d => d.Id == node.Id || node.Id.EndsWith(d.DeviceIdentifier, StringComparison.OrdinalIgnoreCase))
                ?? activeTopology?.Disks.FirstOrDefault();

            if (disk is not null && disk.SizeBytes > 0)
            {
                var partitions = activeTopology?.Partitions.Where(p => p.DiskId == disk.Id).OrderBy(p => p.Index).ToList() ?? [];
                var segments = new List<ApfsStorageBarControl.Segment>();
                long partitionedBytes = 0;
                int cIdx = 0;
                foreach (var part in partitions)
                {
                    var segName = $"Partition {part.Index} ({part.Usage})";
                    segments.Add(new ApfsStorageBarControl.Segment(segName, part.SizeBytes, colors[cIdx % colors.Length]));
                    partitionedBytes += part.SizeBytes;
                    cIdx++;
                }

                var unallocated = Math.Max(0, disk.SizeBytes - partitionedBytes);
                _storageBar.SetStorage(disk.SizeBytes, unallocated, segments, $"Disk {disk.DeviceIdentifier} Physical Layout");
                _storageBarActive = true;
                _storageBar.Visible = true;
                return;
            }
        }

        // 2. GPT PARTITION node
        if (node.Id.StartsWith("apfs-part:", StringComparison.Ordinal))
        {
            var part = activeTopology?.Partitions.FirstOrDefault(p => p.Id == node.Id);
            if (part is not null && part.SizeBytes > 0)
            {
                var store = activeTopology?.Stores.FirstOrDefault(s => s.PartitionId == part.Id);
                var container = store is not null ? activeTopology?.Containers.FirstOrDefault(c => c.Id == store.ContainerId) : null;
                if (container?.SharedSpace is { } shared && shared.Total.Bytes > 0)
                {
                    var segments = new List<ApfsStorageBarControl.Segment>();
                    int idx = 0;
                    foreach (var v in shared.Volumes)
                    {
                        var vName = activeTopology?.Volumes.FirstOrDefault(x => x.Id == v.VolumeId)?.Name ?? $"Volume {v.ObjectId}";
                        segments.Add(new ApfsStorageBarControl.Segment(vName, (long)v.Allocated.Bytes, colors[idx % colors.Length]));
                        idx++;
                    }

                    var unallocatedInPartition = Math.Max(0, part.SizeBytes - (long)shared.Total.Bytes);
                    var freeBytes = (long)shared.Free.Bytes + unallocatedInPartition;
                    _storageBar.SetStorage(part.SizeBytes, freeBytes, segments, $"GPT Partition {part.Index} Storage ({part.Usage})");
                }
                else
                {
                    var partSegment = new ApfsStorageBarControl.Segment($"Partition {part.Index} ({part.Usage})", part.SizeBytes, colors[0]);
                    _storageBar.SetStorage(part.SizeBytes, 0, [partSegment], $"GPT Partition {part.Index} Storage");
                }

                _storageBarActive = true;
                _storageBar.Visible = true;
                return;
            }
        }

        // 3. APFS STORE node
        if (node.Id.StartsWith("apfs-store:", StringComparison.Ordinal) ||
            node.Id.StartsWith("registered-store:", StringComparison.Ordinal))
        {
            var store = activeTopology?.Stores.FirstOrDefault(s => s.Id == node.Id);
            var storeSize = store?.SizeBytes ?? 0;
            if (storeSize > 0)
            {
                var storeSegment = new ApfsStorageBarControl.Segment("Store Capacity", storeSize, colors[0]);
                _storageBar.SetStorage(storeSize, 0, [storeSegment], "APFS Store Slice Storage");
                _storageBarActive = true;
                _storageBar.Visible = true;
                return;
            }
        }

        // 4. APFS CONTAINER node
        var containerId = node.ReferenceId ?? node.Id;
        if (containerId.StartsWith("apfs-container:", StringComparison.Ordinal) ||
            containerId.StartsWith("registered-container:", StringComparison.Ordinal))
        {
            var container = activeTopology?.Containers.FirstOrDefault(c => c.Id == containerId)
                ?? activeTopology?.Containers.FirstOrDefault();

            if (container?.SharedSpace is { } shared && shared.Total.Bytes > 0)
            {
                var total = (long)shared.Total.Bytes;
                var free = (long)shared.Free.Bytes;
                var segments = new List<ApfsStorageBarControl.Segment>();
                int idx = 0;
                foreach (var v in shared.Volumes)
                {
                    var volName = activeTopology?.Volumes.FirstOrDefault(x => x.Id == v.VolumeId)?.Name ?? $"Volume {v.ObjectId}";
                    segments.Add(new ApfsStorageBarControl.Segment(volName, (long)v.Allocated.Bytes, colors[idx % colors.Length]));
                    idx++;
                }

                var title = container.Fusion ? "Fusion Container Storage Pool" : "Shared APFS Container Storage Pool";
                _storageBar.SetStorage(total, free, segments, title);
                _storageBarActive = true;
                _storageBar.Visible = true;
                return;
            }
        }

        // 5. APFS VOLUME node
        if (node.Id.StartsWith("apfs-vol:", StringComparison.Ordinal) ||
            node.Id.StartsWith("inventory-volume:", StringComparison.Ordinal) ||
            node.Row is not null)
        {
            var vol = activeTopology?.Volumes.FirstOrDefault(v => v.Id == node.Id || node.Id.EndsWith(":" + v.ObjectId, StringComparison.Ordinal))
                ?? activeTopology?.Volumes.FirstOrDefault(v => v.Id == node.Row?.CatalogVolumeId);

            var container = vol is not null
                ? activeTopology?.Containers.FirstOrDefault(c => c.Id == vol.ContainerId)
                : activeTopology?.Containers.FirstOrDefault();

            if (container?.SharedSpace is { } shared && shared.Total.Bytes > 0)
            {
                var volName = vol?.Name ?? node.Row?.VolumeName ?? "Volume";
                var volSpace = shared.Volumes.FirstOrDefault(sp =>
                    (vol is not null && (sp.VolumeId == vol.Id || sp.ObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture) == vol.ObjectId)) ||
                    (node.Row?.CatalogVolumeObjectId is { } oid && sp.ObjectId == oid));

                var segments = new List<ApfsStorageBarControl.Segment>();
                if (volSpace is not null)
                {
                    segments.Add(new ApfsStorageBarControl.Segment($"{volName} (Selected)", (long)volSpace.Allocated.Bytes, Color.FromArgb(14, 165, 233)));
                }

                int sibIdx = 1;
                foreach (var sibling in shared.Volumes)
                {
                    if (volSpace is not null && sibling.ObjectId == volSpace.ObjectId) continue;
                    var sibName = activeTopology?.Volumes.FirstOrDefault(x => x.Id == sibling.VolumeId)?.Name ?? $"Volume {sibling.ObjectId}";
                    segments.Add(new ApfsStorageBarControl.Segment(sibName, (long)sibling.Allocated.Bytes, colors[sibIdx % colors.Length]));
                    sibIdx++;
                }

                var title = $"Volume \"{volName}\" Storage Allocation";
                _storageBar.SetStorage((long)shared.Total.Bytes, (long)shared.Free.Bytes, segments, title);
                _storageBarActive = true;
                _storageBar.Visible = true;
                return;
            }
            else if (status.MountedVolumes?.FirstOrDefault(m => m.VolumeId == node.Row?.VolumeId)?.CatalogSpace is { } catSpace && catSpace.ContainerTotal.Bytes > 0)
            {
                var volName = node.Row?.VolumeName ?? "Volume";
                var segments = new List<ApfsStorageBarControl.Segment>
                {
                    new ApfsStorageBarControl.Segment($"{volName} (Selected)", (long)catSpace.Volume.Allocated.Bytes, Color.FromArgb(14, 165, 233))
                };
                var title = $"Volume \"{volName}\" Storage Allocation";
                _storageBar.SetStorage((long)catSpace.ContainerTotal.Bytes, (long)catSpace.ContainerFree.Bytes, segments, title);
                _storageBarActive = true;
                _storageBar.Visible = true;
                return;
            }
        }

        _storageBarActive = false;
        _storageBar.Visible = false;
    }

    private void PopulateContextMenu()
    {
        _treeContextMenu.Items.Clear();
        var selected = _topologyTree.SelectedNode;
        if (selected?.Tag is not TopologyDashboardNode node)
        {
            var expandAllItem = new ToolStripMenuItem("Expand all nodes", null, (_, _) => _topologyTree.ExpandAll());
            var collapseAllItem = new ToolStripMenuItem("Collapse all nodes", null, (_, _) => _topologyTree.CollapseAll());
            _treeContextMenu.Items.Add(expandAllItem);
            _treeContextMenu.Items.Add(collapseAllItem);
            return;
        }

        if (node.Row is { } row)
        {
            var openItem = new ToolStripMenuItem($"Open {row.VolumeName} in Explorer", null, async (_, _) =>
            {
                if (row.CanOpen && _actionsEnabled)
                    await RunActionAsync("Opening drive...", () => _openAsync(row.MountPath)).ConfigureAwait(true);
            }) { Enabled = _actionsEnabled && row.CanOpen };
            _treeContextMenu.Items.Add(openItem);

            var ejectItem = new ToolStripMenuItem($"Eject {row.VolumeName}", null, async (_, _) =>
            {
                if (row.CanEject && _actionsEnabled)
                    await RunActionAsync("Ejecting APFS drive...", () =>
                        _ejectVolumeAsync is not null ? _ejectVolumeAsync(row) : _ejectAsync(row.VolumeId)).ConfigureAwait(true);
            }) { Enabled = _actionsEnabled && row.CanEject };
            _treeContextMenu.Items.Add(ejectItem);

            var canAct = CanAct(row);
            var actText = ActionText(row);
            var fixItem = new ToolStripMenuItem($"{actText} {row.VolumeName}", null, async (_, _) =>
            {
                if (canAct && _actionsEnabled)
                {
                    await RunActionAsync("Refreshing APFS drive...", () =>
                    {
                        if (row.RegisteredImage is not null) return _encryptionVolumeAsync?.Invoke(row) ?? Task.CompletedTask;
                        return row.IsMounted ? (_fixVolumeAsync is not null ? _fixVolumeAsync(row) : _fixAsync(row.VolumeId)) :
                            _mountVolumeAsync?.Invoke(row) ?? Task.CompletedTask;
                    }).ConfigureAwait(true);
                }
            }) { Enabled = _actionsEnabled && canAct };
            _treeContextMenu.Items.Add(fixItem);
            if (CanFixOffline(row))
                _treeContextMenu.Items.Add(new ToolStripMenuItem($"Fix {row.VolumeName}", null, async (_, _) =>
                    await RunActionAsync("Checking image...", () => _fixVolumeAsync!(row)).ConfigureAwait(true))
                    { Enabled = _actionsEnabled });

            _treeContextMenu.Items.Add(new ToolStripMenuItem("Verify volume", null, async (_, _) =>
                await RunActionAsync("Verifying volume...", () => _verifyVolumeAsync!(row)).ConfigureAwait(true))
                { Enabled = _actionsEnabled && (row.CanVerifyOffline || row.CanVerifyLive) && _verifyVolumeAsync is not null });
            _treeContextMenu.Items.Add(new ToolStripMenuItem("Manage volume...", null, async (_, _) =>
                await RunActionAsync("Managing volume...", () => _manageVolumeAsync!(row)).ConfigureAwait(true))
                { Enabled = _actionsEnabled && row.CanManageOffline && _manageVolumeAsync is not null });
            _treeContextMenu.Items.Add(new ToolStripMenuItem("Volume snapshots...", null, async (_, _) =>
                await RunActionAsync("Opening snapshots...", () => _snapshotsVolumeAsync!(row)).ConfigureAwait(true))
                { Enabled = _actionsEnabled && _snapshotsVolumeAsync is not null && (row.CanVerifyOffline || row.CanListSnapshots || row.CanRecoverSnapshots) });
            _treeContextMenu.Items.Add(new ToolStripMenuItem("Delete image volume...", null, async (_, _) =>
                await RunActionAsync("Planning volume deletion...", () => _deleteVolumeAsync!(row)).ConfigureAwait(true))
                { Enabled = _actionsEnabled && _deleteVolumeAsync is not null && row.CanManageTopologyImage });
            _treeContextMenu.Items.Add(new ToolStripMenuItem("Resize image container...", null, async (_, _) =>
                await RunActionAsync("Planning image resize...", () => _resizeImageAsync!(row)).ConfigureAwait(true))
                { Enabled = _actionsEnabled && _resizeImageAsync is not null && row.CanResizeImage });
            _treeContextMenu.Items.Add(new ToolStripMenuItem("Format image container...", null, async (_, _) =>
                await RunActionAsync("Planning image format...", () => _formatImageAsync!(row)).ConfigureAwait(true))
                { Enabled = _actionsEnabled && _formatImageAsync is not null && row.CanFormatImage });

            if (_setDriveLetterAsync is not null && row.DriveLetterPreference?.CanEdit == true)
            {
                var letterItem = new ToolStripMenuItem("Preferred drive letter…", null, async (_, _) =>
                {
                    if (_actionsEnabled) await ChooseDriveLetterAsync(row).ConfigureAwait(true);
                }) { Enabled = _actionsEnabled };
                _treeContextMenu.Items.Add(letterItem);
            }

            _treeContextMenu.Items.Add(new ToolStripSeparator());

            if (!string.IsNullOrWhiteSpace(row.CatalogVolumeUuid))
            {
                _treeContextMenu.Items.Add(new ToolStripMenuItem("Copy Volume UUID", null, (_, _) =>
                {
                    try { _copyText(row.CatalogVolumeUuid); SetFooter($"Copied volume UUID: {row.CatalogVolumeUuid}"); } catch { }
                }));
            }

            if (!string.IsNullOrWhiteSpace(row.MountPath))
            {
                _treeContextMenu.Items.Add(new ToolStripMenuItem("Copy Mount Path", null, (_, _) =>
                {
                    try { _copyText(row.MountPath); SetFooter($"Copied mount path: {row.MountPath}"); } catch { }
                }));
            }
        }
        else if (_selectedContainerDeviceId is not null && _selectedContainerUuid is not null)
        {
            if (_mountContainerAsync is not null)
            {
                var mountItem = new ToolStripMenuItem("Mount Container", null, (_, _) =>
                    RunContainerActionAsync(_mountContainerAsync, "Mounting container..."))
                { Enabled = _actionsEnabled && _containerMountButton.Enabled };
                _treeContextMenu.Items.Add(mountItem);
            }

            if (_unmountContainerAsync is not null)
            {
                var unmountItem = new ToolStripMenuItem("Unmount Container", null, (_, _) =>
                    RunContainerActionAsync(_unmountContainerAsync, "Unmounting container..."))
                { Enabled = _actionsEnabled && _containerUnmountButton.Enabled };
                _treeContextMenu.Items.Add(unmountItem);
            }

            if (_fixContainerAsync is not null)
            {
                var fixItem = new ToolStripMenuItem("Fix Container", null, (_, _) => RunFixContainerActionAsync())
                { Enabled = _actionsEnabled && _containerFixButton.Enabled };
                _treeContextMenu.Items.Add(fixItem);
            }

            if (IsContainerNode(node))
                _treeContextMenu.Items.Add(new ToolStripMenuItem("Verify volumes", null, (_, _) => RunVerifyContainerActionAsync())
                { Enabled = _containerVerifyButton.Enabled, ToolTipText = _containerVerifyButton.AccessibleDescription });

            _treeContextMenu.Items.Add(new ToolStripSeparator());

            _treeContextMenu.Items.Add(new ToolStripMenuItem("Create image volume...", null, (_, _) =>
                RunContainerActionAsync(_createVolumeAsync, "Planning image volume...")) { Enabled = _containerCreateButton.Enabled });
            if (!string.IsNullOrWhiteSpace(_selectedContainerUuid))
            {
                _treeContextMenu.Items.Add(new ToolStripMenuItem("Copy Container UUID", null, (_, _) =>
                {
                    try { _copyText(_selectedContainerUuid); SetFooter($"Copied container UUID: {_selectedContainerUuid}"); } catch { }
                }));
            }
        }
        else if (_selectedDeviceId is not null)
        {
            if (_ejectDeviceAsync is not null)
            {
                var ejectItem = new ToolStripMenuItem("Eject Physical Device", null, (_, _) => RunDeviceActionAsync())
                { Enabled = _actionsEnabled && _deviceEjectButton.Enabled };
                _treeContextMenu.Items.Add(ejectItem);
            }

            if (_rescanDevicesButton is not null)
            {
                var rescanItem = new ToolStripMenuItem(_rescanDevicesButton.Text, null, (_, _) =>
                    _rescanDevicesButton.PerformClick())
                { Enabled = _actionsEnabled };
                _treeContextMenu.Items.Add(rescanItem);
            }

            _treeContextMenu.Items.Add(new ToolStripSeparator());

            _treeContextMenu.Items.Add(new ToolStripMenuItem("Copy Device ID", null, (_, _) =>
            {
                try { _copyText(_selectedDeviceId); SetFooter($"Copied device ID: {_selectedDeviceId}"); } catch { }
            }));
        }

        _treeContextMenu.Items.Add(new ToolStripMenuItem("Copy Node Details", null, (_, _) => CopyDetailsToClipboard()));
        _treeContextMenu.Items.Add(new ToolStripSeparator());
        _treeContextMenu.Items.Add(new ToolStripMenuItem("Expand all nodes", null, (_, _) => _topologyTree.ExpandAll()));
        _treeContextMenu.Items.Add(new ToolStripMenuItem("Collapse all nodes", null, (_, _) => _topologyTree.CollapseAll()));
    }


    private void AdjustMemberPanelHeight()
    {
        if (_adjustingMemberPanelHeight) return;
        if (_memberPanel is null || _memberPanel.IsDisposed) return;
        if (_detailsTopPanel is null || _detailsTopPanel.IsDisposed) return;

        _adjustingMemberPanelHeight = true;
        try
        {
            var availWidth = _memberPanel.ClientSize.Width;
            if (availWidth <= 0 && _detailContainer is not null)
            {
                availWidth = _detailContainer.ClientSize.Width - _detailContainer.Padding.Horizontal;
            }
            if (availWidth <= 0 && _detailsTopPanel.Width > 0)
            {
                availWidth = _detailsTopPanel.Width;
            }
            if (availWidth <= 0)
            {
                availWidth = 400;
            }

            var pref = _memberPanel.GetPreferredSize(new Size(availWidth, 0));
            var minFlowHeight = ScaleDpi(28);
            var flowHeight = Math.Max(minFlowHeight, pref.Height);

            var barHeight = (_storageBarActive && _storageBar is not null) ? _storageBar.Height : 0;
            var totalHeight = barHeight + flowHeight;

            _detailsTopPanel.SuspendLayout();
            _memberPanel.SuspendLayout();
            try
            {
                if (_memberPanel.Height != flowHeight)
                {
                    _memberPanel.Height = flowHeight;
                }
                if (_detailsTopPanel.Height != totalHeight)
                {
                    _detailsTopPanel.Height = totalHeight;
                }
            }
            finally
            {
                _memberPanel.ResumeLayout(true);
                _detailsTopPanel.ResumeLayout(true);
            }

            _memberPanel.PerformLayout();
            _detailsTopPanel.PerformLayout();
            _detailContainer?.PerformLayout();
        }
        finally
        {
            _adjustingMemberPanelHeight = false;
        }
    }

    private static void SafeSetSplitterDistance(SplitContainer split, int desiredDistance)
    {
        try
        {
            if (split.Width <= 0 || split.Height <= 0) return;
            var total = split.Orientation == Orientation.Vertical ? split.Width : split.Height;
            if (total <= 0) return;
            var max = total - split.Panel2MinSize - split.SplitterWidth;
            var min = split.Panel1MinSize;
            if (max > min)
            {
                var clamped = Math.Clamp(desiredDistance, min, max);
                if (split.SplitterDistance != clamped)
                {
                    split.SplitterDistance = clamped;
                }
            }
        }
        catch
        {
        }
    }

    private static GraphicsPath CreateRoundedRectanglePath(Rectangle rect, int radius)
    {
        var path = new GraphicsPath();
        if (radius <= 0 || rect.Width <= 0 || rect.Height <= 0)
        {
            path.AddRectangle(rect);
            return path;
        }

        var diameter = Math.Min(radius * 2, Math.Min(rect.Width, rect.Height));
        var arc = new Rectangle(rect.Location, new Size(diameter, diameter));
        path.AddArc(arc, 180, 90);
        arc.X = rect.Right - diameter;
        path.AddArc(arc, 270, 90);
        arc.Y = rect.Bottom - diameter;
        path.AddArc(arc, 0, 90);
        arc.X = rect.Left;
        path.AddArc(arc, 90, 90);
        path.CloseFigure();
        return path;
    }

    private void AdjustContentSplitDistance()
    {
        if (_adjustingContentSplit || _contentSplit is null || _rowsPanel is null || _contentSplit.Panel1Collapsed)
        {
            return;
        }

        var totalAvailable = _contentSplit.ClientSize.Height - _contentSplit.SplitterWidth;
        if (totalAvailable <= 0) return;

        var minInspectorHeight = Math.Max(ScaleDpi(90), (int)(totalAvailable * 0.25f));
        var maxPanel1Height = Math.Max(_contentSplit.Panel1MinSize, totalAvailable - minInspectorHeight);

        if (_userAdjustedContentSplit)
        {
            var clamped = Math.Clamp(_contentSplit.SplitterDistance, _contentSplit.Panel1MinSize, maxPanel1Height);
            if (_contentSplit.SplitterDistance != clamped)
            {
                SafeSetSplitterDistance(_contentSplit, clamped);
            }
            return;
        }

        _adjustingContentSplit = true;
        try
        {
            if (_rowsPanel.Controls.Count == 0)
            {
                return;
            }

            int requiredHeight = _rowsPanel.Padding.Vertical;
            foreach (Control c in _rowsPanel.Controls)
            {
                requiredHeight += c.Height + c.Margin.Vertical;
            }
            requiredHeight += ScaleDpi(6);

            var targetDistance = Math.Min(requiredHeight, maxPanel1Height);
            targetDistance = Math.Max(targetDistance, _contentSplit.Panel1MinSize);

            SafeSetSplitterDistance(_contentSplit, targetDistance);
        }
        finally
        {
            _adjustingContentSplit = false;
        }
    }

    private void ResizeTopology()
    {
        if (_topologyLayout is null || _detailContainer is null || _topologyTree is null) return;
        var narrow = _topologyLayout.ClientSize.Width < ScaleDpi(750);
        _topologyLayout.SuspendLayout();
        _topologyLayout.SetCellPosition(_detailContainer, narrow ? new TableLayoutPanelCellPosition(0, 1) : new TableLayoutPanelCellPosition(1, 0));
        _topologyLayout.SetColumnSpan(_topologyTree, narrow ? 2 : 1);
        _topologyLayout.SetColumnSpan(_detailContainer, narrow ? 2 : 1);
        _topologyLayout.RowStyles[0] = new RowStyle(SizeType.Percent, narrow ? 42F : 100F);
        _topologyLayout.RowStyles[1] = new RowStyle(narrow ? SizeType.Percent : SizeType.Absolute, narrow ? 58F : 0F);
        _topologyLayout.ColumnStyles[0] = new ColumnStyle(SizeType.Percent, narrow ? 100F : 30F);
        _topologyLayout.ColumnStyles[1] = new ColumnStyle(narrow ? SizeType.Absolute : SizeType.Percent, narrow ? 0F : 70F);
        _topologyLayout.ResumeLayout();
        AdjustMemberPanelHeight();
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);
        SuspendLayout();
        try
        {
            if (_topologyTree is not null)
            {
                _topologyTree.ItemHeight = Math.Max(26, ScaleDpi(26));
            }
            if (_contentSplit is not null)
            {
                _contentSplit.SplitterWidth = Math.Max(4, ScaleDpi(6));
                _contentSplit.Panel1MinSize = ScaleDpi(60);
                _contentSplit.Panel2MinSize = ScaleDpi(60);
            }
            ResizeTopology();
            ResizeRows();
            AdjustMemberPanelHeight();
        }
        finally
        {
            ResumeLayout(true);
        }
    }

    private int ScaleDpi(int value) => ScaleDpi(value, DeviceDpi);
    private static int ScaleDpi(int value, int dpi) => (int)Math.Round(value * (dpi / 96f));

    public void SetActionsEnabled(bool enabled)
    {
        _actionsEnabled = enabled;
        if (_activityBar is not null)
        {
            _activityBar.Visible = !enabled;
            _activityBar.Style = !enabled ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
            _activityBar.MarqueeAnimationSpeed = !enabled ? 30 : 0;
        }
        foreach (var button in EnumerateControls(this).OfType<Button>().Where(button => button.Tag is bool))
        {
            button.Enabled = enabled && button.Tag is true;
            StyleButtonByTheme(button);
        }
        ReconcileContainerButtons(_topologyTree.SelectedNode);
        SetImageRegistrationAvailable(_imageRegistrationAvailable);
    }

    public void SetImageRegistrationAvailable(bool available)
    {
        _imageRegistrationAvailable = available;
        if (_registerImageButton is not null)
            _registerImageButton.Enabled = _actionsEnabled && available && _registerImageAsync is not null;
    }

    public void SetUpdateStatus(string message, string buttonText, bool enabled)
    {
        if (IsDisposed)
        {
            return;
        }

        if (_updateStatusLabel is not null)
        {
            _updateStatusLabel.Text = message;
        }

        if (_updateButton is not null)
        {
            _updateButton.Text = buttonText;
            _updateButton.Enabled = enabled && _checkForUpdatesAsync is not null;
        }
    }

    public void ShowDashboard()
    {
        if (IsDisposed)
        {
            return;
        }

        if (_topologyTree.Nodes.Cast<TreeNode>().Any(n => n.Nodes.Count > 0))
        {
            _treeInitiallyExpanded = true;
            _topologyTree.ExpandAll();
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
        if (!_resizing) ResizeRows();
    }

    protected override void OnResizeBegin(EventArgs e)
    {
        base.OnResizeBegin(e);
        _resizing = true;
    }

    protected override void OnResizeEnd(EventArgs e)
    {
        _resizing = false;
        ResizeRows();
        base.OnResizeEnd(e);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
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
        => DriveDashboardPresenter.RowIdentity(row);

    private void UpdateRow(Control root, DriveDashboardRow row)
    {
        root.Tag = row;
        if (root.Controls.Count == 0 ||
            root.Controls[0] is not TableLayoutPanel layout ||
            layout.Controls.Count < 3)
        {
            return;
        }

        if (layout.Controls[0] is Control palette)
        {
            palette.BackColor = ToColor(row.Palette, _currentTheme.IsDark);
        }

        if (layout.Controls[1] is TableLayoutPanel textPanel)
        {
            var labels = textPanel.Controls.OfType<Label>().ToArray();
            if (labels.Length >= 4)
            {
                labels[0].ForeColor = _currentTheme.TextPrimary;
                labels[0].Text = row.DeviceName;
                labels[1].ForeColor = _currentTheme.TextSecondary;
                labels[1].Text = BuildVolumeLine(row);
                labels[2].ForeColor = ToColor(row.Palette, _currentTheme.IsDark);
                labels[2].Text = row.StateText;
                labels[3].ForeColor = _currentTheme.TextMuted;
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
                buttons[0].Visible = row.CanOpen;
                buttons[1].Tag = row.CanEject;
                buttons[1].Enabled = _actionsEnabled && row.CanEject;
                buttons[1].Visible = row.CanEject;
                var canAct = CanAct(row);
                buttons[2].Text = ActionText(row);
                buttons[2].Tag = canAct;
                buttons[2].Enabled = _actionsEnabled && canAct;
                buttons[2].Visible = canAct;
                var canFixOffline = CanFixOffline(row);
                buttons[3].Text = canFixOffline ? "Fix" : string.Empty;
                buttons[3].Tag = canFixOffline;
                buttons[3].Enabled = _actionsEnabled && canFixOffline;
                buttons[3].Visible = canFixOffline;
                if (buttons.Length >= 5)
                {
                    var canEdit = _setDriveLetterAsync is not null && row.DriveLetterPreference?.CanEdit == true;
                    buttons[4].Tag = canEdit;
                    buttons[4].Enabled = _actionsEnabled && canEdit;
                    buttons[4].Visible = canEdit;
                }
            }
        }

        ResizeRowContent(root);
    }

    private bool CanAct(DriveDashboardRow row) => row.RegisteredImage is not null ? _encryptionVolumeAsync is not null && (row.CanUnlock || row.CanLock) :
        row.IsMounted ? row.CanFix : _mountVolumeAsync is not null && row.CanMount;
    private bool CanFixOffline(DriveDashboardRow row) => !row.IsMounted && _fixVolumeAsync is not null &&
        DriveDashboardPresenter.CanFixVolume(row);
    private static string ActionText(DriveDashboardRow row) => row.RegisteredImage is not null ? row.IsMounted ? "Lock" : "Unlock…" :
        row.IsMounted ? "Fix" : row.CanMountBackupReadWrite ? "Mount backup read/write" : row.CanInspectReadOnly ? "Inspect read-only" : "Mount";

    private Control BuildRow(DriveDashboardRow row, List<Button> actionButtons)
    {
        var container = new Panel
        {
            Height = 1,
            Margin = new Padding(0, 0, 0, ScaleDpi(6)),
            BackColor = _currentTheme.CardBackground,
            BorderStyle = BorderStyle.FixedSingle,
        };

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            Padding = new Padding(0),
            BackColor = _currentTheme.CardBackground,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, (float)ScaleDpi(8)));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        container.Controls.Add(layout);

        layout.Controls.Add(new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = ToColor(row.Palette, _currentTheme.IsDark),
            Margin = new Padding(0),
        }, 0, 0);

        var textPanel = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Padding = new Padding(ScaleDpi(14), ScaleDpi(8), ScaleDpi(14), ScaleDpi(8)),
            BackColor = _currentTheme.CardBackground,
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
            ForeColor = _currentTheme.TextPrimary,
            Text = row.DeviceName,
        }, 0, 0);
        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            ForeColor = _currentTheme.TextSecondary,
            Text = BuildVolumeLine(row),
        }, 0, 1);
        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            ForeColor = ToColor(row.Palette, _currentTheme.IsDark),
            Text = row.StateText,
        }, 0, 2);
        textPanel.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(0, 0),
            Dock = DockStyle.Fill,
            ForeColor = _currentTheme.TextMuted,
            Text = row.Summary,
        }, 0, 3);

        var buttonsPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Top,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(0, ScaleDpi(6), ScaleDpi(10), ScaleDpi(6)),
            Margin = new Padding(0),
            BackColor = _currentTheme.CardBackground,
        };
        layout.Controls.Add(buttonsPanel, 2, 0);

        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Open", row.CanOpen, () => RunActionAsync(
            "Opening drive...",
            () => _openAsync(((DriveDashboardRow)container.Tag!).MountPath))));
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Eject", row.CanEject, () => RunActionAsync(
            "Ejecting APFS drive...",
            () => _ejectVolumeAsync is not null ? _ejectVolumeAsync((DriveDashboardRow)container.Tag!) : _ejectAsync(((DriveDashboardRow)container.Tag!).VolumeId))));
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, ActionText(row),
            CanAct(row), () => RunActionAsync(
            "Refreshing APFS drive...",
            () => {
                var current = (DriveDashboardRow)container.Tag!;
                if (current.RegisteredImage is not null) return _encryptionVolumeAsync?.Invoke(current) ?? Task.CompletedTask;
                return current.IsMounted ? (_fixVolumeAsync is not null ? _fixVolumeAsync(current) : _fixAsync(current.VolumeId)) :
                    _mountVolumeAsync?.Invoke(current) ?? Task.CompletedTask;
            })));
        container.Tag = row;
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, CanFixOffline(row) ? "Fix" : string.Empty,
            CanFixOffline(row), () => RunActionAsync("Checking image...", () => _fixVolumeAsync!((DriveDashboardRow)container.Tag!))));
        buttonsPanel.Controls.Add(BuildActionButton(actionButtons, "Drive letter…",
            _setDriveLetterAsync is not null && row.DriveLetterPreference?.CanEdit == true,
            () => ChooseDriveLetterAsync((DriveDashboardRow)container.Tag!)));
        return container;
    }

    private async Task ChooseDriveLetterAsync(DriveDashboardRow row)
    {
        if (_setDriveLetterAsync is null || row.DriveLetterPreference is not { CanEdit: true } preference) return;
        using var dialog = new Form
        {
            Text = "Preferred drive letter",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MinimizeBox = false,
            MaximizeBox = false,
            ShowInTaskbar = false,
            AutoScaleMode = AutoScaleMode.Dpi,
            Font = Font,
            BackColor = _currentTheme.WindowBackground,
            ForeColor = _currentTheme.TextPrimary,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(ScaleDpi(520), ScaleDpi(250)),
        };
        DashboardTheme.ApplyImmersiveDarkMode(dialog.Handle, _currentTheme.IsDark);

        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(ScaleDpi(20), ScaleDpi(18), ScaleDpi(20), ScaleDpi(18)),
            AutoScroll = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = _currentTheme.WindowBackground,
        };

        var titleText = string.IsNullOrWhiteSpace(preference.VolumeUuid)
            ? row.VolumeName
            : $"{row.VolumeName} — {preference.VolumeUuid}";
        panel.Controls.Add(new Label
        {
            Text = titleText,
            Font = new Font(Font, FontStyle.Bold),
            AutoSize = true,
            ForeColor = _currentTheme.TextPrimary,
            Margin = new Padding(0, 0, 0, ScaleDpi(8)),
        });

        var prefText = preference.Text.EndsWith('.') ? preference.Text : preference.Text + ".";
        panel.Controls.Add(new Label
        {
            Text = prefText,
            AutoSize = true,
            ForeColor = _currentTheme.TextSecondary,
            Margin = new Padding(0, 0, 0, ScaleDpi(4)),
        });

        panel.Controls.Add(new Label
        {
            Text = "Remounts automatically when saved (or offers to queue if currently in use).",
            AutoSize = true,
            ForeColor = _currentTheme.TextMuted,
            Margin = new Padding(0, 0, 0, ScaleDpi(16)),
        });

        var chooser = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            AccessibleName = "Preferred drive letter",
            Width = ScaleDpi(120),
            BackColor = _currentTheme.DropdownBackground,
            ForeColor = _currentTheme.DropdownText,
            Margin = new Padding(0, 0, 0, ScaleDpi(18)),
        };
        var occupied = GetOccupiedDriveLetters(row);
        var allowedCandidates = preference.AllowedLetters
            .Where(c => !occupied.Contains(char.ToUpperInvariant(c)))
            .Select(c => (object)$"{char.ToUpperInvariant(c)}:")
            .ToArray();
        chooser.Items.AddRange(allowedCandidates);
        var targetLetter = (preference.PreferredLetter ?? preference.ActualLetter) + ":";
        chooser.SelectedItem = targetLetter;
        if (chooser.SelectedIndex < 0 && chooser.Items.Count > 0) chooser.SelectedIndex = 0;
        panel.Controls.Add(chooser);

        var actions = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = _currentTheme.WindowBackground,
            Margin = new Padding(0, ScaleDpi(4), 0, 0),
        };
        var save = new Button
        {
            Text = "Save",
            DialogResult = DialogResult.OK,
            Enabled = chooser.Items.Count > 0,
            AutoSize = true,
            Padding = new Padding(ScaleDpi(16), ScaleDpi(6), ScaleDpi(16), ScaleDpi(6)),
            Margin = new Padding(0, 0, ScaleDpi(10), 0),
        };
        var cancel = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            Padding = new Padding(ScaleDpi(16), ScaleDpi(6), ScaleDpi(16), ScaleDpi(6)),
            Margin = new Padding(0),
        };
        StyleButtonByTheme(save);
        StyleButtonByTheme(cancel);
        actions.Controls.Add(save);
        actions.Controls.Add(cancel);
        panel.Controls.Add(actions);

        dialog.Controls.Add(panel);
        dialog.AcceptButton = save;
        dialog.CancelButton = cancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && chooser.SelectedItem is string selected)
            await SaveDriveLetterPreferenceAsync(row, selected[..1]).ConfigureAwait(true);
    }

    internal Task SaveDriveLetterPreferenceAsync(DriveDashboardRow row, string letter)
        => _setDriveLetterAsync is null ? Task.CompletedTask : RunActionAsync("Saving preferred letter…", () => _setDriveLetterAsync(row, letter));

    internal static HashSet<char> GetOccupiedDriveLetters(DriveDashboardRow? currentRow, Func<string[]>? getLogicalDrives = null)
    {
        var occupied = new HashSet<char>();
        char currentLetter = '\0';
        if (!string.IsNullOrWhiteSpace(currentRow?.MountPoint))
        {
            var trimmed = currentRow.MountPoint.Trim();
            if (trimmed.Length >= 2 && trimmed[1] == ':' && char.IsAsciiLetter(trimmed[0]))
            {
                currentLetter = char.ToUpperInvariant(trimmed[0]);
            }
        }

        var drives = getLogicalDrives is not null ? getLogicalDrives() : Environment.GetLogicalDrives();
        foreach (var drive in drives)
        {
            if (!string.IsNullOrWhiteSpace(drive) && char.IsAsciiLetter(drive[0]))
            {
                var letter = char.ToUpperInvariant(drive[0]);
                if (letter != currentLetter)
                {
                    occupied.Add(letter);
                }
            }
        }
        return occupied;
    }

    private Control BuildStartupPreferencesPanel(StartupPreferences startupPreferences)
    {
        _bottomPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            Margin = new Padding(0, ScaleDpi(8), 0, 0),
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

        _bottomPanel.Controls.Add(_startWithWindowsCheckBox);
        _bottomPanel.Controls.Add(_startMinimizedCheckBox);
        if (_registerImageAsync is not null)
        {
            _registerImageButton = new Button { Text = "Register encrypted image...", AutoSize = true, Enabled = false,
                Margin = new Padding(ScaleDpi(8), 0, ScaleDpi(8), 0) };
            StyleButtonByTheme(_registerImageButton);
            _registerImageButton.Click += async (_, _) => await RunActionAsync("Registering image...", _registerImageAsync).ConfigureAwait(true);
            _bottomPanel.Controls.Add(_registerImageButton);
        }

        _themeLabel = new Label
        {
            Text = "Theme:",
            AutoSize = true,
            ForeColor = _currentTheme.TextSecondary,
            BackColor = BackColor,
            Margin = new Padding(ScaleDpi(4), ScaleDpi(6), ScaleDpi(4), ScaleDpi(8)),
        };
        _themeComboBox = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            AccessibleName = "Color theme",
            Width = ScaleDpi(125),
            FlatStyle = FlatStyle.Flat,
            Margin = new Padding(0, ScaleDpi(2), ScaleDpi(12), ScaleDpi(8)),
            DrawMode = DrawMode.OwnerDrawFixed,
            BackColor = _currentTheme.DropdownBackground,
            ForeColor = _currentTheme.DropdownText,
        };
        _themeComboBox.Items.AddRange(["Follow Windows", "Light", "Dark"]);
        _themeComboBox.SelectedIndex = (int)_themeMode;
        _themeComboBox.ItemHeight = Math.Max(20, ScaleDpi(20));
        _themeComboBox.DrawItem += (s, e) =>
        {
            if (e.Index < 0 || e.Index >= _themeComboBox.Items.Count) return;
            var isDark = _currentTheme.IsDark;
            var isSelected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
            var bg = isSelected ? (isDark ? Color.FromArgb(58, 62, 72) : SystemColors.Highlight) : (isDark ? _currentTheme.DropdownBackground : Color.White);
            var fg = isSelected ? (isDark ? Color.White : SystemColors.HighlightText) : (isDark ? _currentTheme.DropdownText : SystemColors.WindowText);
            using var brush = new SolidBrush(bg);
            e.Graphics.FillRectangle(brush, e.Bounds);
            var text = _themeComboBox.Items[e.Index]?.ToString() ?? "";
            TextRenderer.DrawText(e.Graphics, text, e.Font ?? _themeComboBox.Font, e.Bounds, fg, TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
        };
        _themeComboBox.SelectedIndexChanged += async (_, _) =>
        {
            var newMode = (AppThemeMode)_themeComboBox.SelectedIndex;
            if (newMode != _themeMode)
            {
                await SetThemeModeAsync(newMode).ConfigureAwait(true);
            }
        };

        _bottomPanel.Controls.Add(_themeLabel);
        _bottomPanel.Controls.Add(_themeComboBox);

        _updateButton = new Button
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Enabled = _checkForUpdatesAsync is not null,
            Margin = new Padding(0, 0, ScaleDpi(8), ScaleDpi(8)),
            Padding = new Padding(ScaleDpi(12), ScaleDpi(5), ScaleDpi(12), ScaleDpi(5)),
            Text = "Check for updates",
        };
        StyleButtonByTheme(_updateButton);
        _updateButton.Click += async (_, _) => await RunUpdateActionAsync().ConfigureAwait(true);
        _bottomPanel.Controls.Add(_updateButton);

        _gitHubButton = new Button
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            AccessibleName = "Open GitHub page",
            Margin = new Padding(0, 0, ScaleDpi(12), ScaleDpi(8)),
            Padding = new Padding(ScaleDpi(12), ScaleDpi(5), ScaleDpi(12), ScaleDpi(5)),
            Text = "GitHub",
        };
        StyleButtonByTheme(_gitHubButton);
        _gitHubButton.Click += (_, _) => OpenGitHubPage();
        _bottomPanel.Controls.Add(_gitHubButton);

        _updateStatusLabel = new Label
        {
            AutoSize = true,
            ForeColor = _currentTheme.TextSecondary,
            BackColor = BackColor,
            Margin = new Padding(0, ScaleDpi(7), 0, ScaleDpi(8)),
            Text = string.Empty,
        };
        _bottomPanel.Controls.Add(_updateStatusLabel);
        return _bottomPanel;
    }

    internal void OpenGitHubPage()
    {
        if (OpenGitHubPageOverride is not null)
        {
            OpenGitHubPageOverride();
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = GitHubProjectUrl,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "APFS Access", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async Task RunUpdateActionAsync()
    {
        if (_checkForUpdatesAsync is null || _updateButton is null || !_updateButton.Enabled)
        {
            return;
        }

        _updateButton.Enabled = false;
        try
        {
            await _checkForUpdatesAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetUpdateStatus(ex.Message, "Check for updates", enabled: true);
            MessageBox.Show(this, ex.Message, "APFS Access", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private CheckBox BuildStartupCheckBox(string text, bool isChecked, Func<bool, Task>? action)
    {
        var checkBox = new CheckBox
        {
            AutoSize = true,
            Checked = isChecked,
            Margin = new Padding(0, 0, ScaleDpi(22), ScaleDpi(8)),
            Text = text,
            ForeColor = _currentTheme.CheckBoxText,
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
            Margin = new Padding(ScaleDpi(4), 0, 0, ScaleDpi(4)),
            Padding = new Padding(ScaleDpi(12), ScaleDpi(4), ScaleDpi(12), ScaleDpi(4)),
            Text = text,
            Enabled = _actionsEnabled && enabled,
            Visible = enabled,
            Tag = enabled,
        };
        StyleButtonByTheme(button);
        button.Click += async (_, _) => { if (_actionsEnabled && button.Tag is true) await action().ConfigureAwait(true); };
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
            if (_summaryLabel.Text == workingMessage && _renderedSummary is { } summary)
            {
                SetFooter(summary);
            }
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



    private void ResizeRows()
    {
        if (_rowsPanel is null)
        {
            return;
        }

        _rowsPanel.SuspendLayout();
        try
        {
            var width = Math.Max(100, _rowsPanel.ClientSize.Width - ScaleDpi(4));
            foreach (Control control in _rowsPanel.Controls)
            {
                control.Width = width;
                ResizeRowContent(control);
            }
        }
        finally
        {
            _rowsPanel.ResumeLayout(true);
        }

        if (!_userAdjustedContentSplit)
        {
            AdjustContentSplitDistance();
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

        var stacked = root.ClientSize.Width < ScaleDpi(360, root.DeviceDpi);
        if (layout is not null && buttonsPanel is not null && textPanel is not null)
        {
            layout.SuspendLayout();
            if (stacked)
            {
                layout.ColumnCount = 2;
                layout.RowCount = 2;
                layout.ColumnStyles.Clear();
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, (float)ScaleDpi(8, root.DeviceDpi)));
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
                layout.RowStyles.Clear();
                layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                layout.SetCellPosition(textPanel, new TableLayoutPanelCellPosition(1, 0));
                layout.SetCellPosition(buttonsPanel, new TableLayoutPanelCellPosition(1, 1));
                layout.SetColumnSpan(textPanel, 1);
                layout.SetColumnSpan(buttonsPanel, 1);
                buttonsPanel.FlowDirection = FlowDirection.LeftToRight;
                buttonsPanel.WrapContents = true;
                buttonsPanel.MaximumSize = new Size(Math.Max(80, root.ClientSize.Width - 16), 0);
            }
            else
            {
                layout.ColumnCount = 3;
                layout.RowCount = 1;
                layout.ColumnStyles.Clear();
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, (float)ScaleDpi(8, root.DeviceDpi)));
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                layout.RowStyles.Clear();
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
                layout.SetCellPosition(textPanel, new TableLayoutPanelCellPosition(1, 0));
                layout.SetCellPosition(buttonsPanel, new TableLayoutPanelCellPosition(2, 0));
                layout.SetColumnSpan(textPanel, 1);
                layout.SetColumnSpan(buttonsPanel, 1);
                buttonsPanel.FlowDirection = FlowDirection.TopDown;
                buttonsPanel.WrapContents = false;
                buttonsPanel.MaximumSize = Size.Empty;
            }
            layout.ResumeLayout(true);
        }

        var buttonWidth = stacked ? 0 : buttonsPanel?.GetPreferredSize(Size.Empty).Width ?? 0;
        var textWidth = Math.Max(80, root.ClientSize.Width - ScaleDpi(8, root.DeviceDpi) - buttonWidth - ScaleDpi(34, root.DeviceDpi));
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

        var buttonHeight = stacked
            ? (buttonsPanel?.GetPreferredSize(new Size(Math.Max(80, root.ClientSize.Width - 16), 0)).Height ?? 0)
            : (buttonsPanel?.GetPreferredSize(Size.Empty).Height ?? 0);
        root.Height = Math.Max(1, (stacked ? textHeight + buttonHeight : Math.Max(textHeight, buttonHeight)) + ScaleDpi(4, root.DeviceDpi));
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

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        DashboardTheme.ApplyImmersiveDarkMode(Handle, _currentTheme.IsDark);
        if (_topologyTree is not null && _topologyTree.IsHandleCreated)
        {
            DashboardTheme.ApplyWindowTheme(_topologyTree.Handle, _currentTheme.IsDark);
        }
    }

    private const int WM_SETTINGCHANGE = 0x001A;
    private const int WM_ENTERSIZEMOVE = 0x0231;
    private const int WM_EXITSIZEMOVE = 0x0232;

    protected override void WndProc(ref Message m)
    {
        switch (m.Msg)
        {
            case WM_ENTERSIZEMOVE:
                _resizing = true;
                break;
            case WM_EXITSIZEMOVE:
                _resizing = false;
                ResizeTopology();
                ResizeRows();
                AdjustMemberPanelHeight();
                break;
            case WM_SETTINGCHANGE when _themeMode == AppThemeMode.System:
                ApplyTheme(AppThemeMode.System);
                break;
        }

        base.WndProc(ref m);
    }

    public async Task SetThemeModeAsync(AppThemeMode mode)
    {
        SetThemeMode(mode);
        if (_setThemeModeAsync is not null)
        {
            try
            {
                await _setThemeModeAsync(mode).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "APFS Access", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }

    public void SetThemeMode(AppThemeMode mode)
    {
        _themeMode = mode;
        if (_themeComboBox is not null && _themeComboBox.SelectedIndex != (int)mode)
        {
            _themeComboBox.SelectedIndex = (int)mode;
        }
        ApplyTheme(mode);
    }

    public void ApplyTheme(AppThemeMode mode)
    {
        _themeMode = mode;
        _currentTheme = DashboardTheme.Resolve(mode);
        var isDark = _currentTheme.IsDark;

        BackColor = _currentTheme.WindowBackground;

        if (IsHandleCreated)
        {
            DashboardTheme.ApplyImmersiveDarkMode(Handle, isDark);
        }

        if (_rootPanel is not null) _rootPanel.BackColor = _currentTheme.WindowBackground;
        if (_summaryHeaderPanel is not null) _summaryHeaderPanel.BackColor = _currentTheme.WindowBackground;
        if (_summaryLabel is not null) _summaryLabel.ForeColor = _currentTheme.TextPrimary;
        if (_rowsPanel is not null) _rowsPanel.BackColor = _currentTheme.WindowBackground;
        if (_topologyLayout is not null) _topologyLayout.BackColor = _currentTheme.WindowBackground;
        if (_memberPanel is not null) _memberPanel.BackColor = _currentTheme.WindowBackground;
        if (_detailContainer is not null) _detailContainer.BackColor = _currentTheme.WindowBackground;
        if (_detailsTopPanel is not null) _detailsTopPanel.BackColor = _currentTheme.WindowBackground;
        if (_detailsContainer is not null) _detailsContainer.BackColor = _currentTheme.WindowBackground;
        if (_inspectorToolbar is not null) _inspectorToolbar.BackColor = _currentTheme.WindowBackground;
        if (_inspectorTitle is not null) _inspectorTitle.ForeColor = _currentTheme.TextMuted;
        if (_detailsScroll is not null) _detailsScroll.BackColor = _currentTheme.DetailsBackground;
        if (_nodeDetails is not null)
        {
            _nodeDetails.BackColor = _currentTheme.DetailsBackground;
            _nodeDetails.ForeColor = _currentTheme.DetailsText;
        }
        if (_contentSplit is not null)
        {
            _contentSplit.BackColor = _currentTheme.SplitterColor;
            _contentSplit.Panel1.BackColor = _currentTheme.WindowBackground;
            _contentSplit.Panel2.BackColor = _currentTheme.WindowBackground;
        }
        if (_storageBar is not null)
        {
            _storageBar.IsDarkMode = isDark;
            _storageBar.BackColor = _currentTheme.WindowBackground;
            _storageBar.Invalidate();
        }
        if (_bottomPanel is not null) _bottomPanel.BackColor = _currentTheme.WindowBackground;
        if (_themeLabel is not null)
        {
            _themeLabel.ForeColor = _currentTheme.TextSecondary;
            _themeLabel.BackColor = _currentTheme.WindowBackground;
        }
        if (_themeComboBox is not null)
        {
            _themeComboBox.BackColor = _currentTheme.DropdownBackground;
            _themeComboBox.ForeColor = _currentTheme.DropdownText;
            _themeComboBox.Invalidate();
        }
        if (_members is not null)
        {
            _members.BackColor = _currentTheme.DropdownBackground;
            _members.ForeColor = _currentTheme.DropdownText;
            _members.Invalidate();
        }
        if (_startWithWindowsCheckBox is not null) _startWithWindowsCheckBox.ForeColor = _currentTheme.CheckBoxText;
        if (_startMinimizedCheckBox is not null) _startMinimizedCheckBox.ForeColor = _currentTheme.CheckBoxText;
        if (_updateStatusLabel is not null)
        {
            _updateStatusLabel.ForeColor = _currentTheme.TextSecondary;
            _updateStatusLabel.BackColor = _currentTheme.WindowBackground;
        }
        if (_treeContextMenu is not null)
        {
            _treeContextMenu.Renderer = isDark ? new DarkToolStripRenderer() : new ToolStripProfessionalRenderer();
        }

        if (_topologyTree is not null)
        {
            if (_topologyTree.IsHandleCreated)
            {
                DashboardTheme.ApplyWindowTheme(_topologyTree.Handle, isDark);
            }
            _topologyTree.BackColor = _currentTheme.TreeViewBackground;
            _topologyTree.ForeColor = _currentTheme.TreeViewText;
            _topologyTree.LineColor = _currentTheme.TreeViewLineColor;
            TopologyTreeRefresh.ReapplyColors(_topologyTree);
        }

        foreach (var button in EnumerateControls(this).OfType<Button>())
        {
            StyleButtonByTheme(button);
        }

        if (_rowsPanel is not null)
        {
            foreach (Control card in _rowsPanel.Controls)
            {
                ApplyThemeToRowCard(card);
            }
        }

        Invalidate(true);
    }

    private void ApplyThemeToRowCard(Control card)
    {
        card.BackColor = _currentTheme.CardBackground;
        if (card.Controls.Count == 0 || card.Controls[0] is not TableLayoutPanel layout || layout.Controls.Count < 3)
            return;

        layout.BackColor = _currentTheme.CardBackground;

        var row = card.Tag as DriveDashboardRow;
        if (row is not null && layout.Controls[0] is Control palette)
        {
            palette.BackColor = ToColor(row.Palette, _currentTheme.IsDark);
        }

        if (layout.Controls[1] is TableLayoutPanel textPanel)
        {
            textPanel.BackColor = _currentTheme.CardBackground;
            var labels = textPanel.Controls.OfType<Label>().ToArray();
            if (labels.Length >= 4)
            {
                labels[0].ForeColor = _currentTheme.TextPrimary;
                labels[1].ForeColor = _currentTheme.TextSecondary;
                if (row is not null)
                {
                    labels[2].ForeColor = ToColor(row.Palette, _currentTheme.IsDark);
                }
                labels[3].ForeColor = _currentTheme.TextMuted;
            }
        }

        if (layout.Controls[2] is FlowLayoutPanel buttonsPanel)
        {
            buttonsPanel.BackColor = _currentTheme.CardBackground;
            foreach (var btn in buttonsPanel.Controls.OfType<Button>())
            {
                StyleButtonByTheme(btn);
            }
        }
    }

    private readonly HashSet<Button> _styledButtons = [];

    private void StyleButtonByTheme(Button btn)
    {
        if (_styledButtons.Add(btn))
        {
            btn.EnabledChanged += (_, _) =>
            {
                StyleButtonByTheme(btn);
                btn.Invalidate();
            };
            btn.Paint += (sender, e) =>
            {
                if (sender is Button b && !b.Enabled && _currentTheme.IsDark)
                {
                    using var backBrush = new SolidBrush(_currentTheme.ButtonDisabledBackground);
                    e.Graphics.FillRectangle(backBrush, b.ClientRectangle);

                    using var borderPen = new Pen(_currentTheme.ButtonDisabledBorder);
                    e.Graphics.DrawRectangle(borderPen, 0, 0, Math.Max(0, b.Width - 1), Math.Max(0, b.Height - 1));

                    var flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
                    TextRenderer.DrawText(e.Graphics, b.Text, b.Font, b.ClientRectangle, _currentTheme.ButtonDisabledText, flags);
                }
            };
        }

        if (_currentTheme.IsDark)
        {
            btn.FlatStyle = FlatStyle.Flat;
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = btn.Enabled ? _currentTheme.ButtonBorder : _currentTheme.ButtonDisabledBorder;
            btn.BackColor = btn.Enabled ? _currentTheme.ButtonBackground : _currentTheme.ButtonDisabledBackground;
            btn.ForeColor = btn.Enabled ? _currentTheme.ButtonText : _currentTheme.ButtonDisabledText;
            btn.FlatAppearance.MouseOverBackColor = _currentTheme.ButtonHover;
            btn.FlatAppearance.MouseDownBackColor = _currentTheme.ButtonPressed;
        }
        else
        {
            btn.FlatStyle = FlatStyle.System;
            btn.UseVisualStyleBackColor = true;
            btn.ForeColor = SystemColors.ControlText;
            btn.BackColor = SystemColors.Control;
        }
    }

    private Color ToColor(DashboardPalette palette) => ToColor(palette, _currentTheme.IsDark);

    private static Color ToColor(DashboardPalette palette, bool isDark)
    {
        if (isDark)
        {
            return palette switch
            {
                DashboardPalette.Green => Color.FromArgb(74, 222, 128),
                DashboardPalette.Blue => Color.FromArgb(96, 165, 250),
                DashboardPalette.Yellow => Color.FromArgb(250, 204, 21),
                DashboardPalette.Orange => Color.FromArgb(251, 146, 60),
                DashboardPalette.Red => Color.FromArgb(248, 113, 113),
                _ => Color.FromArgb(148, 163, 184),
            };
        }

        return palette switch
        {
            DashboardPalette.Green => Color.FromArgb(34, 139, 84),
            DashboardPalette.Blue => Color.FromArgb(49, 130, 206),
            DashboardPalette.Yellow => Color.FromArgb(214, 158, 46),
            DashboardPalette.Orange => Color.FromArgb(221, 107, 32),
            DashboardPalette.Red => Color.FromArgb(197, 48, 48),
            _ => Color.FromArgb(113, 128, 150),
        };
    }
}
