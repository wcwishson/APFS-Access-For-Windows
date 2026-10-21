using ApfsAccess.Core;
using ApfsAccess.Ipc;
using System.Text.Json;

namespace ApfsAccess.Tray;

public sealed class VolumeSnapshotWorkflow(DriveDashboardRow selected, Func<StatusChangedPayload> latestStatus,
    Func<ControlOperationRequestPayload, Task<OperationResultPayload>> send)
{
    private string? _inventoryBinding;
    private string? _spaceBinding;
    private string? _markedSpaceBinding;
    private string? _ownerSpaceBinding;
    private bool _busy;
    public SnapshotInventoryView? Inventory { get; private set; }
    public SnapshotSpaceSummary? SpaceSummary { get; private set; }
    public MarkedReferenceSpaceSummary? MarkedSpaceSummary { get; private set; }
    public MarkedReferenceSpaceSummary? OwnerSpaceSummary { get; private set; }

    public DriveDashboardRow CurrentRow()
    {
        try { return Resolve(latestStatus()); }
        catch { Invalidate(); throw; }
    }

    private DriveDashboardRow Resolve(StatusChangedPayload status)
    {
        try
        {
            var matches = TopologyDashboard.Project(status).Where(n => n.Row is not null).Select(n => n.Row!)
                .Where(r => DriveDashboardPresenter.RowIdentity(r) == DriveDashboardPresenter.RowIdentity(selected) &&
                    r.RecoveryIdentity == selected.RecoveryIdentity).ToArray();
            if (matches.Length != 1) throw new InvalidOperationException("Snapshot volume identity changed. Refresh before acting.");
            var row = matches[0];
            if (Inventory is not null && _inventoryBinding != Binding(row, status)) Invalidate();
            if (SpaceSummary is not null && _spaceBinding != Binding(row, status)) Invalidate();
            if (MarkedSpaceSummary is not null && _markedSpaceBinding != Binding(row, status)) Invalidate();
            if (OwnerSpaceSummary is not null && _ownerSpaceBinding != Binding(row, status)) Invalidate();
            return row;
        }
        catch { Invalidate(); throw; }
    }

    public void Invalidate() { Inventory = null; _inventoryBinding = null; SpaceSummary = null; _spaceBinding = null;
        MarkedSpaceSummary = null; _markedSpaceBinding = null; InvalidateOwnerSpace(); }
    internal void InvalidateOwnerSpace() { OwnerSpaceSummary = null; _ownerSpaceBinding = null; }

    internal bool CanReadSpace
    {
        get
        {
            try { SpaceTarget(); return true; }
            catch (Exception ex) when (ex is InvalidOperationException or IOException) { return false; }
        }
    }

    private (VerifyScope Scope, string Binding) SpaceTarget()
    {
        StatusChangedPayload status;
        DriveDashboardRow row;
        try
        {
            status = latestStatus(); row = Resolve(status);
        }
        catch { Invalidate(); throw; }
        if (!row.CanVerifyOffline || row.IsMounted || row.SnapshotScope is not { } scope)
            throw new InvalidOperationException("Snapshot space requires the current offline image scope. Physical sources are unavailable.");
        return (scope, Binding(row, status));
    }

    internal async Task<SnapshotSpaceSummary> ReadSpaceAsync(
        Func<VerifyScope, Action, CancellationToken, Task<SnapshotSpaceSummary>> observe, CancellationToken token)
    {
        if (_busy) throw new InvalidOperationException("A snapshot operation is already running.");
        _busy = true;
        SpaceSummary = null; _spaceBinding = null;
        try
        {
            token.ThrowIfCancellationRequested();
            var target = SpaceTarget();
            void RequireCurrent()
            {
                if (SpaceTarget() != target)
                    throw new InvalidOperationException("Snapshot source or capability changed during space observation. Refresh before acting.");
            }
            RequireCurrent();
            var result = await observe(target.Scope, RequireCurrent, token).ConfigureAwait(true);
            RequireCurrent(); token.ThrowIfCancellationRequested();
            SpaceSummary = result; _spaceBinding = target.Binding;
            return result;
        }
        catch { Invalidate(); throw; }
        finally { _busy = false; }
    }

    internal bool CanBrowse(SnapshotInventoryEntry? entry)
    {
        try { PrepareBrowse(entry, null, Path.Combine(Path.GetTempPath(), "ApfsAccess", "SnapshotBrowse", Guid.NewGuid().ToString("N"))); return true; }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or IOException) { return false; }
    }

    internal async Task<MarkedReferenceSpaceSummary> ReadMarkedSpaceAsync(MarkedReferenceSpaceClient client, CancellationToken token)
    {
        if (_busy) throw new InvalidOperationException("A snapshot operation is already running.");
        _busy = true; MarkedSpaceSummary = null; _markedSpaceBinding = null;
        try
        {
            token.ThrowIfCancellationRequested(); var target = SpaceTarget();
            void RequireCurrent()
            {
                if (SpaceTarget() != target)
                    throw new InvalidOperationException("Marked-file source or capability changed during observation. Refresh before acting.");
            }
            var result = await client.RunAsync(target.Scope, RequireCurrent, token).ConfigureAwait(true);
            RequireCurrent(); token.ThrowIfCancellationRequested();
            MarkedSpaceSummary = result; _markedSpaceBinding = target.Binding; return result;
        }
        catch { Invalidate(); throw; }
        finally { _busy = false; }
    }

    internal async Task<MarkedReferenceSpaceSummary> ReadOwnerSpaceAsync(MarkedOwnerSpaceClient client, string? from, CancellationToken token)
    {
        if (_busy) throw new InvalidOperationException("A snapshot operation is already running.");
        _busy = true; InvalidateOwnerSpace();
        try {
            token.ThrowIfCancellationRequested(); var target = SpaceTarget();
            void Current() { if (SpaceTarget() != target) throw new InvalidOperationException("Marked-owner selection changed. Refresh before acting."); }
            var result = await client.RunAsync(target.Scope, from, Current, token).ConfigureAwait(true);
            Current(); token.ThrowIfCancellationRequested(); OwnerSpaceSummary = result; _ownerSpaceBinding = target.Binding; return result;
        }
        catch { Invalidate(); throw; }
        finally { _busy = false; }
    }

    internal SnapshotBrowseRequest PrepareBrowse(SnapshotInventoryEntry? entry, string? copyOut, string sessionDirectory)
    {
        var row = CurrentRow();
        if (!row.CanVerifyOffline || !row.CanFix || row.SnapshotScope is not { StoreOffsetBytes: "0" } scope || row.IsMounted ||
            Inventory is null || entry is null || !Inventory.Entries.Any(e => ReferenceEquals(e, entry)))
            throw new InvalidOperationException("Select a snapshot from fresh inventory of an ordinary offline image. Physical snapshot browsing is unavailable.");
        if (copyOut is not null)
        {
            static string Normal(string path) => path.Replace('/', '\\').TrimEnd('\\');
            var path = Normal(copyOut); var session = Normal(sessionDirectory);
            if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' || path[2..].Contains(':') ||
                path.Any(c => c < 32 || c is '<' or '>' or '"' or '|' or '?' or '*') ||
                path[3..].Split('\\').Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')) ||
                string.Equals(path, session, StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(session + "\\", StringComparison.OrdinalIgnoreCase) || session.StartsWith(path + "\\", StringComparison.OrdinalIgnoreCase) ||
                Directory.Exists(copyOut) || File.Exists(copyOut))
                throw new InvalidOperationException("Copy-out requires a new absolute local directory outside the snapshot session.");
        }
        try
        {
            var inventory = Inventory.ImageInventory ?? throw new InvalidDataException("Refresh the complete image snapshot inventory before browsing.");
            var source = inventory.GetProperty("source");
            var size = source.GetProperty("sizeBytes").GetInt64(); var hash = source.GetProperty("sha256").GetString();
            if (source.GetProperty("kind").GetString() != "image" || source.GetProperty("hashScope").GetString() != "full" ||
                !string.Equals(source.GetProperty("path").GetString(), scope.ImagePath, StringComparison.OrdinalIgnoreCase) ||
                size <= 0 || hash is not { Length: 64 } || hash.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
                inventory.GetProperty("storeOffsetBytes").GetString() != scope.StoreOffsetBytes ||
                inventory.GetProperty("storeSizeBytes").GetString() != scope.StoreSizeBytes ||
                Inventory.CheckpointXid != scope.CheckpointXid || entry.NativeIdentity is null ||
                !ulong.TryParse(scope.StoreSizeBytes, out var window) || window > (ulong)size ||
                ulong.Parse(entry.Xid, System.Globalization.CultureInfo.InvariantCulture) > ulong.Parse(scope.CheckpointXid, System.Globalization.CultureInfo.InvariantCulture))
                throw new InvalidDataException("Snapshot image identity or source window changed. Refresh before browsing.");
            return new(scope, entry, size, hash, sessionDirectory, copyOut);
        }
        catch (Exception ex) when (ex is KeyNotFoundException or JsonException or InvalidOperationException or FormatException)
        { throw new InvalidDataException("Complete image snapshot identity is unavailable. Refresh before browsing.", ex); }
    }

    internal async Task<SnapshotBrowseResult> BrowseAsync(SnapshotInventoryEntry entry, string? copyOut,
        SnapshotBrowseClient client, Action<string> ready, CancellationToken token, string? sessionDirectory = null)
    {
        if (_busy) throw new InvalidOperationException("A snapshot operation is already running.");
        _busy = true;
        var inventory = Inventory;
        try
        {
            var request = PrepareBrowse(entry, copyOut, sessionDirectory ??
                Path.Combine(Path.GetTempPath(), "ApfsAccess", "SnapshotBrowse", Guid.NewGuid().ToString("N")));
            void RequireCurrent()
            {
                var current = PrepareBrowse(entry, copyOut, request.SessionDirectory);
                if (!ReferenceEquals(inventory, Inventory) || current.Scope != request.Scope ||
                    current.SourceSizeBytes != request.SourceSizeBytes || current.SourceSha256 != request.SourceSha256)
                    throw new InvalidOperationException("Snapshot selection changed. Closing the snapshot session.");
            }
            return await client.RunAsync(request, ready, RequireCurrent, token).ConfigureAwait(true);
        }
        catch { Invalidate(); throw; }
        finally { _busy = false; }
    }

    private static string Binding(DriveDashboardRow row, StatusChangedPayload status) => System.Text.Json.JsonSerializer.Serialize(new object?[] {
        DriveDashboardPresenter.RowIdentity(row), row.RecoveryIdentity, row.IsMounted, row.SnapshotScope,
        row.SnapshotRuntimeAuthority, row.CanListSnapshots, row.CanMutateSnapshots, row.CanRecoverSnapshots, row.CanVerifyOffline,
        (status.ConnectedInventory ?? []).Where(d => string.Equals(d.Device.DeviceId, row.DeviceId, StringComparison.OrdinalIgnoreCase))
            .SelectMany(d => d.Volumes.Where(v => string.Equals(v.VolumeId, row.VolumeId, StringComparison.OrdinalIgnoreCase))
                .Select(v => SelectedControlTarget.Create(d, v))).ToArray(),
        (status.MountedVolumes ?? []).Where(m => string.Equals(m.DeviceId, row.DeviceId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(m.VolumeId, row.VolumeId, StringComparison.OrdinalIgnoreCase)).Select(m =>
                new { m.HostProcessId, m.HostProcessCreationTimeFileTimeUtc, m.RecoveryIdentity, m.MountPoint,
                    m.AccessMode, m.MountReady, m.RecoveryActive }).ToArray() });

    public async Task<OperationResultPayload> RunAsync(string command, string? name = null, SnapshotInventoryEntry? entry = null)
    {
        if (_busy) throw new InvalidOperationException("A snapshot operation is already running.");
        _busy = true;
        try
        {
            var status = latestStatus();
            var row = Resolve(status);
            var binding = Binding(row, status);
            if (command == ApfsControlCommands.SnapshotDelete &&
                (Inventory is null || !Inventory.Entries.Any(e => ReferenceEquals(e, entry))))
                throw new InvalidOperationException("Refresh inventory and select a current snapshot before deleting.");
            var request = command is ApfsControlCommands.Mount or ApfsControlCommands.Eject
                ? DriveDashboardPresenter.CreateSelectedRequest(status, row, command)
                : DriveDashboardPresenter.CreateSnapshotRequest(status, row, command, name, entry?.DeleteIdentity);
            Invalidate();
            var result = await send(request).ConfigureAwait(true);
            ControlOperationReply.RequireSuccess(request, result);
            if (command == ApfsControlCommands.SnapshotList)
            {
                var latest = latestStatus();
                var current = Resolve(latest);
                if (Binding(current, latest) != binding)
                    throw new InvalidOperationException("Snapshot source or owner changed while reading inventory. Refresh before acting.");
                Inventory = SnapshotInventoryView.Parse(result.SnapshotInventory ?? throw new IOException("Missing snapshot inventory."), current);
                _inventoryBinding = binding;
            }
            return result;
        }
        catch { Invalidate(); throw; }
        finally { _busy = false; }
    }
}
