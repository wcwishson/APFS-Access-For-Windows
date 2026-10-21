using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

internal sealed class VolumeSnapshotDialog : Form
{
    private readonly VolumeSnapshotWorkflow _workflow;
    private readonly SnapshotBrowseClient _browseClient;
    private readonly SnapshotSpaceClient _spaceClient;
    private readonly MarkedReferenceSpaceClient _markedSpaceClient;
    private readonly MarkedOwnerSpaceClient _ownerSpaceClient;
    private MarkedReferenceSpaceSummary? _shownOwnerSpace;
    private readonly TabPage _ownerPage = new("Owner attribution");
    private readonly TextBox _ownerDetails = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical };
    private readonly Button _owners = new() { Text = "Observe owners", AutoSize = true };
    private readonly CheckBox _includeRetained = new() { Text = "Retained checkpoints", AutoSize = true };
    private readonly NumericUpDown _ownerFrom = new() { Minimum = 1, Maximum = ulong.MaxValue, Width = 160, Value = 1, Enabled = false };
    private readonly Action<string> _openSnapshot;
    private SnapshotInventoryView? _shownInventory;
    private SnapshotSpaceSummary? _shownSpace;
    private MarkedReferenceSpaceSummary? _shownMarkedSpace;
    private readonly TabControl _views = new() { Dock = DockStyle.Fill };
    private readonly TabPage _spacePage = new("Space details");
    private readonly TabPage _markedSpacePage = new("Marked-file space");
    private readonly TextBox _markedSpaceDetails = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
        ScrollBars = ScrollBars.Vertical, WordWrap = true };
    private readonly TextBox _spaceDetails = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
        ScrollBars = ScrollBars.Vertical, WordWrap = true };
    private readonly DataGridView _grid = new() { Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
        AllowUserToDeleteRows = false, MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        RowHeadersVisible = false, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill };
    private readonly TextBox _name = new() { Width = 220, MaxLength = 255 };
    private readonly Label _status = new() { AutoSize = true, Dock = DockStyle.Fill };
    private readonly Button _read = new() { Text = "Refresh inventory", AutoSize = true };
    private readonly Button _create = new() { Text = "Create", AutoSize = true };
    private readonly Button _delete = new() { Text = "Delete selected", AutoSize = true };
    private readonly Button _recover = new() { Text = "Recover pending work", AutoSize = true };
    private readonly Button _mount = new() { Text = "Mount current volume", AutoSize = true };
    private readonly Button _unmount = new() { Text = "Unmount current volume", AutoSize = true };
    private readonly Button _browse = new() { Text = "Browse selected", AutoSize = true };
    private readonly Button _space = new() { Text = "Space details", AutoSize = true };
    private readonly Button _markedSpace = new() { Text = "Marked-file space", AutoSize = true };
    private readonly Button _copy = new() { Text = "Copy out selected", AutoSize = true };
    private readonly Button _stop = new() { Text = "Close snapshot", AutoSize = true, Enabled = false };
    private readonly Button _choose = new() { Text = "Destination...", AutoSize = true };
    private readonly TextBox _destination = new() { Width = 280, AccessibleName = "New copy destination" };
    private readonly System.Windows.Forms.Timer _refresh = new() { Interval = 1000 };
    private bool _busy;
    private bool _closeAfterOperation;
    private bool _keepBrowseResult;
    private CancellationTokenSource? _browseStop;
    private readonly DialogPendingOperation _lifetime = new();

    public VolumeSnapshotDialog(VolumeSnapshotWorkflow workflow, Action<string> openSnapshot, SnapshotBrowseClient? browseClient = null,
        SnapshotSpaceClient? spaceClient = null, MarkedReferenceSpaceClient? markedSpaceClient = null, MarkedOwnerSpaceClient? ownerSpaceClient = null)
    {
        _workflow = workflow;
        _openSnapshot = openSnapshot;
        _browseClient = browseClient ?? new();
        _spaceClient = spaceClient ?? new();
        _markedSpaceClient = markedSpaceClient ?? new();
        _ownerSpaceClient = ownerSpaceClient ?? new();
        var row = workflow.CurrentRow();
        Text = $"Snapshots: {row.VolumeName}";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = new Size(860, 530);
        MinimumSize = new Size(480, 330);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(12) };
        layout.RowStyles.Add(new(SizeType.AutoSize));
        layout.RowStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.AutoSize));
        layout.RowStyles.Add(new(SizeType.AutoSize));
        layout.RowStyles.Add(new(SizeType.AutoSize));
        layout.Controls.Add(new TextBox { ReadOnly = true, Dock = DockStyle.Fill,
            Text = $"{row.DeviceId} | {row.CatalogContainerUuid} | OID {row.CatalogVolumeObjectId}" }, 0, 0);
        _grid.Columns.Add("name", "Name");
        _grid.Columns.Add("xid", "Snapshot XID");
        _grid.Columns.Add("created", "Created (ns)");
        var snapshotsPage = new TabPage("Snapshots");
        snapshotsPage.Controls.Add(_grid); _spacePage.Controls.Add(_spaceDetails);
        _markedSpacePage.Controls.Add(_markedSpaceDetails);
        _views.TabPages.AddRange([snapshotsPage, _spacePage, _markedSpacePage]);
        var ownerLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        ownerLayout.RowStyles.Add(new(SizeType.AutoSize)); ownerLayout.RowStyles.Add(new(SizeType.Percent,100));
        var ownerSelectors = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        ownerSelectors.Controls.AddRange([_owners, _includeRetained, new Label { Text = "From XID", AutoSize = true, Margin = new Padding(3,6,3,0) }, _ownerFrom]);
        ownerLayout.Controls.Add(ownerSelectors,0,0); ownerLayout.Controls.Add(_ownerDetails,0,1); _ownerPage.Controls.Add(ownerLayout); _views.TabPages.Add(_ownerPage);
        var endpoint = ulong.Parse(row.SnapshotScope?.CheckpointXid ?? "1", System.Globalization.CultureInfo.InvariantCulture);
        _ownerFrom.Maximum = Math.Max(1m, endpoint - 1m); _ownerFrom.Value = _ownerFrom.Maximum;
        _includeRetained.CheckedChanged += (_, _) => { _workflow.InvalidateOwnerSpace(); UpdateAvailability(); };
        _ownerFrom.ValueChanged += (_, _) => { _workflow.InvalidateOwnerSpace(); UpdateAvailability(); };
        _owners.Click += async (_, _) => await ReadOwnerSpaceAsync();
        layout.Controls.Add(_views, 0, 1);
        var commands = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        commands.Controls.AddRange([_read, _space, _markedSpace, _mount, _unmount, _name, _create, _delete, _recover]);
        layout.Controls.Add(commands, 0, 2);
        var browsing = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        browsing.Controls.AddRange([_browse, _destination, _choose, _copy, _stop]);
        layout.Controls.Add(browsing, 0, 3);
        layout.Controls.Add(_status, 0, 4);
        layout.SizeChanged += (_, _) => _status.MaximumSize = new Size(Math.Max(80, layout.ClientSize.Width - layout.Padding.Horizontal), 0);
        Controls.Add(layout);
        _read.Click += async (_, _) => await RunAsync(ApfsControlCommands.SnapshotList);
        _space.Click += async (_, _) => await ReadSpaceAsync();
        _markedSpace.Click += async (_, _) => await ReadMarkedSpaceAsync();
        _create.Click += async (_, _) => await RunAsync(ApfsControlCommands.SnapshotCreate, _name.Text);
        _recover.Click += async (_, _) => await RunAsync(ApfsControlCommands.SnapshotRecover);
        _mount.Click += async (_, _) => await RunAsync(ApfsControlCommands.Mount);
        _unmount.Click += async (_, _) => await RunAsync(ApfsControlCommands.Eject);
        _browse.Click += async (_, _) => await BrowseAsync(false);
        _copy.Click += async (_, _) => await BrowseAsync(true);
        _stop.Click += (_, _) => { _browseStop?.Cancel(); _stop.Enabled = false; _status.Text = "Waiting for the snapshot operation to stop..."; };
        _destination.TextChanged += (_, _) => UpdateAvailability();
        _choose.Click += (_, _) =>
        {
            using var picker = new FolderBrowserDialog { Description = "Choose the parent folder for a new snapshot copy", UseDescriptionForTitle = true };
            if (picker.ShowDialog(this) == DialogResult.OK)
                _destination.Text = Path.Combine(picker.SelectedPath, "Snapshot-" + (_grid.CurrentRow?.Tag as SnapshotInventoryEntry)?.Xid);
        };
        _delete.Click += async (_, _) =>
        {
            try
            {
                if (_grid.CurrentRow?.Tag is not SnapshotInventoryEntry snapshot) return;
                var selected = _workflow.CurrentRow();
                if (MessageBox.Show(this, $"Delete snapshot '{snapshot.Name}' (XID {snapshot.Xid})?\r\n" +
                    $"Volume: {selected.CatalogVolumeUuid}\r\nContainer: {selected.CatalogContainerUuid}\r\n" +
                    $"Object: {selected.CatalogVolumeObjectId}\r\nIdentity: {string.Join(", ", snapshot.DeleteIdentity)}",
                    "Confirm snapshot deletion", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) == DialogResult.OK)
                    await RunAsync(ApfsControlCommands.SnapshotDelete, entry: snapshot);
            }
            catch (InvalidOperationException ex) { _status.Text = ex.Message; UpdateAvailability(); }
        };
        _grid.SelectionChanged += (_, _) => UpdateAvailability();
        _name.TextChanged += (_, _) => UpdateAvailability();
        _refresh.Tick += (_, _) => UpdateAvailability();
        UpdateAvailability();
        _refresh.Start();
        FormClosing += (_, e) =>
        {
            if (!_busy) return;
            e.Cancel = true; _closeAfterOperation = true; _browseStop?.Cancel();
            _status.Text = "Waiting for the current operation to close...";
        };
    }

    private void ShowInventory(SnapshotInventoryView view)
    {
        _shownInventory = view;
        _grid.Rows.Clear();
        foreach (var entry in view.Entries)
            _grid.Rows[_grid.Rows.Add(entry.Name, entry.Xid, entry.CreateTimeNs)].Tag = entry;
        _status.Text = $"{view.Entries.Count} snapshot(s), observed at checkpoint {view.CheckpointXid}.";
    }

    private async Task RunAsync(string command, string? name = null, SnapshotInventoryEntry? entry = null)
    {
        if (_busy || !_lifetime.ViewAttached) return;
        _keepBrowseResult = false;
        _busy = true;
        UpdateAvailability();
        _status.Text = "Waiting for service...";
        var finished = false;
        try
        {
            var pending = _workflow.RunAsync(command, name, entry);
            _lifetime.Observe(pending);
            UpdateAvailability();
            var result = await pending.ConfigureAwait(true);
            finished = true;
            _lifetime.UpdateView(() => {
            if (command == ApfsControlCommands.SnapshotList)
            {
                ShowInventory(_workflow.Inventory!);
            }
            else
            {
                _status.Text = result.Diagnostic ?? result.FinalStatus;
            }
            });
        }
        catch (Exception ex)
        {
            _lifetime.UpdateView(() => _status.Text = ex.Message);
        }
        finally { _busy = false; _lifetime.UpdateView(() => { UpdateAvailability(); if (_closeAfterOperation && finished) Close(); }); }
    }

    private async Task BrowseAsync(bool copy)
    {
        if (_busy || !_lifetime.ViewAttached || _grid.CurrentRow?.Tag is not SnapshotInventoryEntry entry) return;
        _keepBrowseResult = false;
        _busy = true;
        var closureConfirmed = false;
        using var stop = new CancellationTokenSource(); _browseStop = stop;
        _stop.Text = copy ? "Cancel copy" : "Close snapshot";
        _status.Text = copy ? "Copying snapshot; waiting for native readiness..." : "Opening snapshot; waiting for native readiness...";
        UpdateAvailability();
        try
        {
            var pending = _workflow.BrowseAsync(entry, copy ? _destination.Text.Trim() : null, _browseClient, path =>
            {
                _lifetime.UpdateView(() => {
                _status.Text = $"Read-only snapshot {entry.Xid}: {path}";
                _openSnapshot(path);
                });
            }, stop.Token);
            _lifetime.Observe(pending);
            var result = await pending.ConfigureAwait(true);
            closureConfirmed = true;
            _lifetime.UpdateView(() => {
            _status.Text = copy ? $"Copied {result.Files} files, {result.Directories} folders, {result.Bytes} bytes to {result.CopyDestination}. Snapshot closed." :
                "Snapshot closed; teardown confirmed.";
            });
        }
        catch (OperationCanceledException) { _lifetime.UpdateView(() => _status.Text = "Snapshot operation cancelled. No successful closure result published."); }
        catch (Exception ex) { _lifetime.UpdateView(() => _status.Text = ex.Message); }
        finally
        {
            _browseStop = null; _busy = false; _keepBrowseResult = true;
            _lifetime.UpdateView(() => { UpdateAvailability(); if (_closeAfterOperation && closureConfirmed) Close(); });
            _closeAfterOperation = false;
        }
    }

    private async Task ReadSpaceAsync()
    {
        if (_busy || !_lifetime.ViewAttached) return;
        _keepBrowseResult = false; _busy = true;
        using var stop = new CancellationTokenSource(); _browseStop = stop;
        _stop.Text = "Cancel observation";
        _status.Text = "Reading snapshot space...";
        var finished = false;
        try
        {
            var pending = _workflow.ReadSpaceAsync(_spaceClient.RunAsync, stop.Token);
            _lifetime.Observe(pending);
            UpdateAvailability();
            var result = await pending.ConfigureAwait(true);
            finished = true;
            _lifetime.UpdateView(() => {
            _shownSpace = result; _spaceDetails.Text = result.Details;
            _views.SelectedTab = _spacePage;
            _status.Text = result.Complete ? "Snapshot space observed." : "Snapshot space is unknown.";
            });
        }
        catch (OperationCanceledException) { _lifetime.UpdateView(() => _status.Text = "Snapshot space observation cancelled; no amounts published."); }
        catch (Exception ex) { _lifetime.UpdateView(() => _status.Text = ex.Message); }
        finally
        {
            _browseStop = null; _busy = false; _keepBrowseResult = !finished;
            _lifetime.UpdateView(() => { UpdateAvailability(); if (_closeAfterOperation && finished) Close(); });
            _closeAfterOperation = false;
        }
    }

    private void UpdateAvailability()
    {
        if (!_lifetime.ViewAttached) return;
        try
        {
            var row = _workflow.CurrentRow();
            if (!ReferenceEquals(_shownInventory, _workflow.Inventory))
            { _shownInventory = null; _grid.Rows.Clear(); }
            if (!ReferenceEquals(_shownSpace, _workflow.SpaceSummary))
            { _shownSpace = _workflow.SpaceSummary; _spaceDetails.Text = _shownSpace?.Details ?? ""; }
            if (!ReferenceEquals(_shownMarkedSpace, _workflow.MarkedSpaceSummary))
            { _shownMarkedSpace = _workflow.MarkedSpaceSummary; _markedSpaceDetails.Text = _shownMarkedSpace?.Details ?? ""; }
            if (!ReferenceEquals(_shownOwnerSpace, _workflow.OwnerSpaceSummary))
            { _shownOwnerSpace = _workflow.OwnerSpaceSummary; _ownerDetails.Text = _shownOwnerSpace?.Details ?? ""; }
            _read.Enabled = !_busy && (row.CanVerifyOffline || row.CanListSnapshots);
            _space.Enabled = !_busy && _workflow.CanReadSpace;
            _space.AccessibleDescription = _space.Enabled ? null : "Snapshot space requires the current offline image scope.";
            _markedSpace.Enabled = !_busy && _workflow.CanReadSpace && _markedSpaceClient.Available;
            _markedSpace.AccessibleDescription = _markedSpace.Enabled ? null :
                "Marked-file space requires a current offline ordinary image and the packaged observer.";
            _owners.Enabled = !_busy && _workflow.CanReadSpace && _ownerSpaceClient.Available;
            _includeRetained.Enabled = !_busy && _owners.Enabled && ulong.Parse(row.SnapshotScope?.CheckpointXid ?? "1", System.Globalization.CultureInfo.InvariantCulture) > 1;
            _ownerFrom.Enabled = _includeRetained.Enabled && _includeRetained.Checked;
            _create.Enabled = !_busy && row.CanMutateSnapshots && !string.IsNullOrWhiteSpace(_name.Text);
            _delete.Enabled = !_busy && row.CanMutateSnapshots && _grid.CurrentRow?.Tag is SnapshotInventoryEntry;
            _recover.Enabled = !_busy && row.CanRecoverSnapshots;
            _create.AccessibleDescription = _delete.AccessibleDescription = _recover.AccessibleDescription =
                row.CanRecoverSnapshots ? null : "SnapshotRuntimeOwnerNotReady: Native snapshot runtime enrollment is unavailable.";
            _mount.Enabled = !_busy && row.CanMount;
            _mount.Text = row.CanMountBackupReadWrite ? "Mount backup read/write" : "Mount current volume";
            _unmount.Enabled = !_busy && row.IsMounted && row.CanEject;
            var canBrowse = !_busy && _workflow.CanBrowse(_grid.CurrentRow?.Tag as SnapshotInventoryEntry);
            _browse.Enabled = canBrowse;
            _copy.Enabled = canBrowse && !string.IsNullOrWhiteSpace(_destination.Text);
            _destination.Enabled = _choose.Enabled = !_busy && row.CanVerifyOffline;
            _stop.Enabled = _browseStop is { IsCancellationRequested: false };
            _browse.AccessibleDescription = _copy.AccessibleDescription = canBrowse ? null :
                "A fresh selected snapshot of an offline ordinary image is required. Physical snapshot browsing is unavailable.";
        }
        catch (InvalidOperationException ex)
        {
            _shownInventory = null; _grid.Rows.Clear();
            _read.Enabled = _create.Enabled = _delete.Enabled = _recover.Enabled = _mount.Enabled = _unmount.Enabled = false;
            _browse.Enabled = _copy.Enabled = _choose.Enabled = _destination.Enabled = false;
            _space.Enabled = false; _shownSpace = null; _spaceDetails.Clear();
            _markedSpace.Enabled = false; _shownMarkedSpace = null; _markedSpaceDetails.Clear();
            _owners.Enabled = _includeRetained.Enabled = _ownerFrom.Enabled = false; _shownOwnerSpace = null; _ownerDetails.Clear();
            _stop.Enabled = _browseStop is { IsCancellationRequested: false };
            if (!_keepBrowseResult) _status.Text = ex.Message;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _lifetime.Detach(() => _browseStop?.Cancel()); _refresh.Dispose(); }
        base.Dispose(disposing);
    }

    private async Task ReadMarkedSpaceAsync()
    {
        if (_busy || !_lifetime.ViewAttached) return;
        _keepBrowseResult = false; _busy = true;
        using var stop = new CancellationTokenSource(); _browseStop = stop;
        _stop.Text = "Cancel observation"; _status.Text = "Reading marked-file space...";
        var finished = false;
        try
        {
            var pending = _workflow.ReadMarkedSpaceAsync(_markedSpaceClient, stop.Token);
            _lifetime.Observe(pending); UpdateAvailability();
            var result = await pending.ConfigureAwait(true); finished = true;
            _lifetime.UpdateView(() => {
                _shownMarkedSpace = result; _markedSpaceDetails.Text = result.Details;
                _views.SelectedTab = _markedSpacePage;
                _status.Text = result.Complete ? "Marked-file physical space observed." : "Marked-file space is unknown.";
            });
        }
        catch (OperationCanceledException) { _lifetime.UpdateView(() => _status.Text = "Marked-file observation cancelled; no amounts published."); }
        catch (Exception ex) { _lifetime.UpdateView(() => _status.Text = ex.Message); }
        finally
        {
            _browseStop = null; _busy = false; _keepBrowseResult = !finished;
            _lifetime.UpdateView(() => { UpdateAvailability(); if (_closeAfterOperation && finished) Close(); });
            _closeAfterOperation = false;
        }
    }

    private async Task ReadOwnerSpaceAsync()
    {
        if (_busy || !_lifetime.ViewAttached) return;
        var from = _includeRetained.Checked ? _ownerFrom.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : null;
        _keepBrowseResult = false; _busy = true;
        using var stop = new CancellationTokenSource(); _browseStop = stop;
        _stop.Text = "Cancel observation"; _status.Text = "Reading marked owners..."; var finished = false;
        try {
            var pending = _workflow.ReadOwnerSpaceAsync(_ownerSpaceClient, from, stop.Token);
            _lifetime.Observe(pending); UpdateAvailability(); var result = await pending.ConfigureAwait(true); finished = true;
            _lifetime.UpdateView(() => { _shownOwnerSpace = result; _ownerDetails.Text = result.Details; _views.SelectedTab = _ownerPage;
                _status.Text = result.Complete ? "Marked owners observed." : "Marked owner accounting is unknown."; });
        }
        catch (OperationCanceledException) { _lifetime.UpdateView(() => _status.Text = "Marked-owner observation cancelled; no amounts published."); }
        catch (Exception error) { _lifetime.UpdateView(() => _status.Text = error.Message); }
        finally {
            _browseStop = null; _busy = false; _keepBrowseResult = !finished;
            _lifetime.UpdateView(() => { UpdateAvailability(); if (_closeAfterOperation && finished) Close(); }); _closeAfterOperation = false;
        }
    }
}
