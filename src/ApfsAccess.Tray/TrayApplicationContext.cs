using System.Collections.Concurrent;
using System.Diagnostics;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed record EjectMenuDescriptor(string Text, string? VolumeId);

public sealed class TrayApplicationContext : ApplicationContext
{
    private static readonly TimeSpan ServiceStartThrottle = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan EjectRequestTimeout = TimeSpan.FromSeconds(130);
    private static readonly object DiagnosticLogSync = new();
    private static readonly string[] ExplicitCanonicalGateRecoveryReasons =
    [
        "CanonicalStateNotLoaded",
        "NativeWriteNotReady",
        "WriteDeviceNotAllowed",
        "CommitPathNotReady",
        "CanonicalCommitNotReady",
        "FixtureCompatibilityPathActive",
        "ScaffoldCommitBlobActive",
    ];
    private static readonly string[] HighPriorityReplayRecoveryReasons =
    [
        "IntegrityMissingAllocationMap",
        "ReplayCheckpointPendingWindow",
        "ReplayCheckpointNotPendingWindow",
        "ReplayCanonicalCandidateMissing",
    ];

    private readonly SynchronizationContext _uiContext;
    private readonly Control _uiInvoker = new();
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _ejectItem;
    private readonly List<Icon> _ownedIcons = [];
    private readonly Dictionary<RuntimeState, Icon> _iconByState;
    private readonly HashSet<string> _shownWarnings = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<AckPayload>> _pendingAcks = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _statusPeerSync = new();

    private PipePeer? _statusPeer;
    private bool _exitRequested;
    private DateTime _lastServiceStartAttemptUtc = DateTime.MinValue;

    public TrayApplicationContext()
    {
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _ = _uiInvoker.Handle;

        _iconByState = LoadIcons();

        var menu = new ContextMenuStrip();
        _ejectItem = new ToolStripMenuItem("Eject APFS drives");
        _ejectItem.Click += OnEjectClicked;
        _ejectItem.Enabled = false;
        menu.Items.Add(_ejectItem);
        menu.Items.Add(new ToolStripSeparator());

        var quitItem = new ToolStripMenuItem("Quit");
        quitItem.Click += OnQuitClicked;
        menu.Items.Add(quitItem);

        _notifyIcon = new NotifyIcon
        {
            Visible = true,
            Text = "APFS Access: starting",
            Icon = _iconByState[RuntimeState.Starting],
            ContextMenuStrip = menu,
        };

        _notifyIcon.MouseClick += OnNotifyIconMouseClick;

        TryStartServiceProcessIfMissing();
        _ = Task.Run(() => RunStatusListenerAsync(_shutdownCts.Token));
    }

    private void OnNotifyIconMouseClick(object? sender, MouseEventArgs e)
    {
        _ = sender;
        if (e.Button == MouseButtons.Left)
        {
            // Required behavior: left-click does nothing.
            return;
        }
    }

    private async void OnQuitClicked(object? sender, EventArgs e)
    {
        _ = sender;
        _ = e;
        await RequestQuitAndExitAsync().ConfigureAwait(false);
    }

    private async void OnEjectClicked(object? sender, EventArgs e)
    {
        _ = e;
        var volumeId = sender is ToolStripMenuItem { Tag: string taggedVolumeId } &&
                       !string.IsNullOrWhiteSpace(taggedVolumeId)
            ? taggedVolumeId
            : null;
        LogDiagnostic($"Eject click received. volumeId='{volumeId ?? "<all>"}'");
        await RequestEjectAsync(volumeId).ConfigureAwait(false);
    }

    private async Task RequestEjectAsync(string? volumeId)
    {
        PostToUi(() => _ejectItem.Enabled = false);
        var (success, message) = await TrySendEjectAsync(volumeId).ConfigureAwait(false);
        LogDiagnostic($"Eject request completed. success={success}; message='{message ?? string.Empty}'");
        PostToUi(() =>
        {
            _ejectItem.Enabled = true;
            _notifyIcon.ShowBalloonTip(
                5000,
                success ? "APFS Access" : "APFS Access Notice",
                string.IsNullOrWhiteSpace(message) ? (success ? "APFS drives ejected." : "Eject failed.") : message,
                success ? ToolTipIcon.Info : ToolTipIcon.Warning);
        });
    }

    private async Task RequestQuitAndExitAsync()
    {
        if (_exitRequested)
        {
            return;
        }

        _exitRequested = true;
        await TrySendQuitAsync().ConfigureAwait(false);

        PostToUi(() =>
        {
            _notifyIcon.Visible = false;
            ExitThread();
        });
    }

    private async Task RunStatusListenerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TryStartServiceProcessIfMissing();

            try
            {
                await using var peer = await NamedPipeMessageClient
                    .ConnectAsync(ApfsPipeConstants.PipeName, timeoutMilliseconds: 1500, cancellationToken)
                    .ConfigureAwait(false);

                try
                {
                    if (!await TryPrimeStatusFromServiceAsync(peer, cancellationToken).ConfigureAwait(false))
                    {
                        continue;
                    }

                    SetStatusPeer(peer);

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var message = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                        if (message is null)
                        {
                            break;
                        }

                        if (message.Type == ApfsMessageTypes.StatusChanged &&
                            PipeMessageCodec.TryGetPayload<StatusChangedPayload>(message, out var status) &&
                            status is not null)
                        {
                            PostToUi(() => UpdateUi(status));
                        }
                        else if (message.Type == ApfsMessageTypes.Ack)
                        {
                            CompletePendingAck(message);
                        }
                    }
                }
                finally
                {
                    ClearStatusPeer(peer);
                    CompleteAllPendingAcks("The APFS Access service connection closed before it answered.");
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (TimeoutException)
            {
                PostToUi(SetDisconnectedUi);
                TryStartServiceProcessIfMissing();
            }
            catch (IOException)
            {
                PostToUi(SetDisconnectedUi);
                TryStartServiceProcessIfMissing();
            }
            catch
            {
                PostToUi(SetDisconnectedUi);
                TryStartServiceProcessIfMissing();
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private void TryStartServiceProcessIfMissing()
    {
        if (_exitRequested)
        {
            return;
        }

        var nowUtc = DateTime.UtcNow;
        if (nowUtc - _lastServiceStartAttemptUtc < ServiceStartThrottle)
        {
            return;
        }

        _lastServiceStartAttemptUtc = nowUtc;

        var serviceCandidates = GetServiceExeCandidates().ToArray();
        try
        {
            var runningServices = Process.GetProcessesByName("ApfsAccess.Service");
            if (runningServices.Any(process =>
                    IsCurrentServiceExecutablePath(TryGetProcessExecutablePath(process), serviceCandidates)))
            {
                DisposeProcesses(runningServices);
                return;
            }

            var knownStaleServices = runningServices
                .Where(process => !string.IsNullOrWhiteSpace(TryGetProcessExecutablePath(process)))
                .ToArray();
            if (knownStaleServices.Length > 0)
            {
                LogDiagnostic(
                    $"Found {knownStaleServices.Length} stale service process(es) from another payload; requesting clean shutdown before starting current service.");
                if (!TrySendQuitAsync().GetAwaiter().GetResult())
                {
                    LogDiagnostic("Stale service shutdown request was not acknowledged; delaying service replacement.");
                    DisposeProcesses(runningServices);
                    return;
                }

                WaitForProcessesToExit(knownStaleServices, TimeSpan.FromSeconds(12));
                DisposeProcesses(runningServices);

                runningServices = Process.GetProcessesByName("ApfsAccess.Service");
                if (runningServices.Any(process =>
                        IsCurrentServiceExecutablePath(TryGetProcessExecutablePath(process), serviceCandidates)))
                {
                    DisposeProcesses(runningServices);
                    return;
                }

                if (runningServices.Length > 0)
                {
                    LogDiagnostic("Stale service process is still running after shutdown request; current service start postponed.");
                    DisposeProcesses(runningServices);
                    return;
                }
            }

            DisposeProcesses(runningServices);
        }
        catch
        {
            // If process enumeration fails, continue and attempt process start by path.
        }

        foreach (var candidate in serviceCandidates)
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            try
            {
                var workingDirectory = Path.GetDirectoryName(candidate) ?? AppContext.BaseDirectory;
                Process.Start(new ProcessStartInfo
                {
                    FileName = candidate,
                    WorkingDirectory = workingDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                });
                return;
            }
            catch
            {
                // Try next candidate.
            }
        }
    }

    private static IEnumerable<string> GetServiceExeCandidates()
    {
        var baseDir = AppContext.BaseDirectory;

        // Combined click-run publish bundle.
        yield return Path.Combine(baseDir, "ApfsAccess.Service.exe");

        // Legacy split publish layout.
        yield return Path.GetFullPath(Path.Combine(baseDir, "..", "service", "ApfsAccess.Service.exe"));
    }

    private static bool IsCurrentServiceExecutablePath(string? executablePath, IEnumerable<string> serviceExeCandidates)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return false;
        }

        string normalizedExecutablePath;
        try
        {
            normalizedExecutablePath = Path.GetFullPath(executablePath);
        }
        catch
        {
            normalizedExecutablePath = executablePath.Trim();
        }

        foreach (var candidate in serviceExeCandidates)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            string normalizedCandidate;
            try
            {
                normalizedCandidate = Path.GetFullPath(candidate);
            }
            catch
            {
                normalizedCandidate = candidate.Trim();
            }

            if (string.Equals(normalizedExecutablePath, normalizedCandidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? TryGetProcessExecutablePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static void WaitForProcessesToExit(IEnumerable<Process> processes, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        foreach (var process in processes)
        {
            try
            {
                if (process.HasExited)
                {
                    continue;
                }

                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero)
                {
                    return;
                }

                process.WaitForExit((int)Math.Min(remaining.TotalMilliseconds, int.MaxValue));
            }
            catch
            {
                // Best-effort replacement guard; startup retry loop will try again.
            }
        }
    }

    private static void DisposeProcesses(IEnumerable<Process> processes)
    {
        foreach (var process in processes)
        {
            try
            {
                process.Dispose();
            }
            catch
            {
                // Ignore process disposal failures.
            }
        }
    }

    private async Task<bool> TrySendQuitAsync()
    {
        var requestId = Guid.NewGuid().ToString("N");

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await using var peer = await NamedPipeMessageClient
                .ConnectAsync(ApfsPipeConstants.PipeName, timeoutMilliseconds: 1000, timeoutCts.Token)
                .ConfigureAwait(false);

            var quitMessage = PipeMessageCodec.Create(
                ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload(Environment.UserName, DateTime.UtcNow),
                requestId
            );

            await peer.SendAsync(quitMessage, timeoutCts.Token).ConfigureAwait(false);

            while (!timeoutCts.Token.IsCancellationRequested)
            {
                var response = await peer.ReadMessageAsync(timeoutCts.Token).ConfigureAwait(false);
                if (response is null)
                {
                    break;
                }

                if (!string.Equals(response.Type, ApfsMessageTypes.Ack, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!string.Equals(response.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return PipeMessageCodec.TryGetPayload<AckPayload>(response, out var ack) && ack?.Success == true;
            }
        }
        catch
        {
            // Timeout fallback behavior: tray should still exit.
        }

        return false;
    }

    private async Task<bool> TryPrimeStatusFromServiceAsync(PipePeer peer, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var message = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (message is null)
            {
                return false;
            }

            if (message.Type != ApfsMessageTypes.StatusChanged)
            {
                continue;
            }

            if (!PipeMessageCodec.TryGetPayload<StatusChangedPayload>(message, out var status) || status is null)
            {
                continue;
            }

            PostToUi(() => UpdateUi(status));
            return true;
        }

        return false;
    }

    private async Task<(bool Success, string? Message)> TrySendEjectAsync(string? volumeId = null)
    {
        var statusPeer = GetStatusPeer();
        if (statusPeer is not null)
        {
            try
            {
                return await TrySendEjectOnStatusChannelAsync(statusPeer, volumeId).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
                LogDiagnostic($"Status-channel eject failed before ACK wait; falling back to transient pipe. {ex.GetType().Name}: {ex.Message}");
            }
        }

        return await TrySendEjectOnTransientPipeAsync(volumeId).ConfigureAwait(false);
    }

    private async Task<(bool Success, string? Message)> TrySendEjectOnStatusChannelAsync(PipePeer peer, string? volumeId)
    {
        var requestId = Guid.NewGuid().ToString("N");
        var pending = new TaskCompletionSource<AckPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingAcks.TryAdd(requestId, pending))
        {
            return (false, "Could not request eject: duplicate request id.");
        }

        using var timeoutCts = new CancellationTokenSource(EjectRequestTimeout);
        try
        {
            var ejectMessage = PipeMessageCodec.Create(
                ApfsMessageTypes.EjectRequested,
                new EjectRequestedPayload(Environment.UserName, DateTime.UtcNow, volumeId),
                requestId
            );

            LogDiagnostic($"Sending eject over status channel. requestId={requestId}; volumeId='{volumeId ?? "<all>"}'");
            await peer.SendAsync(ejectMessage, timeoutCts.Token).ConfigureAwait(false);
            var ack = await pending.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
            return (ack.Success, ack.Message);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            LogDiagnostic($"Timed out waiting for status-channel eject ACK. requestId={requestId}");
            return (false, "Timed out waiting for APFS Access to eject drives.");
        }
        finally
        {
            _pendingAcks.TryRemove(requestId, out _);
        }
    }

    private async Task<(bool Success, string? Message)> TrySendEjectOnTransientPipeAsync(string? volumeId = null)
    {
        var requestId = Guid.NewGuid().ToString("N");

        using var timeoutCts = new CancellationTokenSource(EjectRequestTimeout);
        try
        {
            await using var peer = await NamedPipeMessageClient
                .ConnectAsync(ApfsPipeConstants.PipeName, timeoutMilliseconds: 1000, timeoutCts.Token)
                .ConfigureAwait(false);

            var ejectMessage = PipeMessageCodec.Create(
                ApfsMessageTypes.EjectRequested,
                new EjectRequestedPayload(Environment.UserName, DateTime.UtcNow, volumeId),
                requestId
            );

            LogDiagnostic($"Sending eject over transient pipe. requestId={requestId}; volumeId='{volumeId ?? "<all>"}'");
            await peer.SendAsync(ejectMessage, timeoutCts.Token).ConfigureAwait(false);

            while (!timeoutCts.Token.IsCancellationRequested)
            {
                var response = await peer.ReadMessageAsync(timeoutCts.Token).ConfigureAwait(false);
                if (response is null)
                {
                    break;
                }

                if (!string.Equals(response.Type, ApfsMessageTypes.Ack, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(response.RequestId, requestId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (PipeMessageCodec.TryGetPayload<AckPayload>(response, out var ack) && ack is not null)
                {
                    LogDiagnostic($"Transient eject ACK received. requestId={requestId}; success={ack.Success}; message='{ack.Message ?? string.Empty}'");
                    return (ack.Success, ack.Message);
                }

                return (false, "The service returned an unreadable eject response.");
            }
        }
        catch (Exception ex)
        {
            LogDiagnostic($"Transient eject request failed. requestId={requestId}; {ex.GetType().Name}: {ex.Message}");
            return (false, $"Could not request eject: {ex.Message}");
        }

        LogDiagnostic($"Timed out waiting for transient eject ACK. requestId={requestId}");
        return (false, "Timed out waiting for APFS Access to eject drives.");
    }

    private void CompletePendingAck(PipeEnvelope message)
    {
        if (string.IsNullOrWhiteSpace(message.RequestId) ||
            !_pendingAcks.TryRemove(message.RequestId, out var pending))
        {
            return;
        }

        if (PipeMessageCodec.TryGetPayload<AckPayload>(message, out var ack) && ack is not null)
        {
            LogDiagnostic($"Status-channel ACK received. requestId={message.RequestId}; success={ack.Success}; message='{ack.Message ?? string.Empty}'");
            pending.TrySetResult(ack);
            return;
        }

        pending.TrySetResult(new AckPayload(false, "The service returned an unreadable eject response."));
    }

    private void CompleteAllPendingAcks(string message)
    {
        foreach (var requestId in _pendingAcks.Keys.ToArray())
        {
            if (_pendingAcks.TryRemove(requestId, out var pending))
            {
                pending.TrySetResult(new AckPayload(false, message));
            }
        }
    }

    private PipePeer? GetStatusPeer()
    {
        lock (_statusPeerSync)
        {
            return _statusPeer;
        }
    }

    private void SetStatusPeer(PipePeer peer)
    {
        lock (_statusPeerSync)
        {
            _statusPeer = peer;
        }

        LogDiagnostic("Status pipe connected.");
    }

    private void ClearStatusPeer(PipePeer peer)
    {
        lock (_statusPeerSync)
        {
            if (ReferenceEquals(_statusPeer, peer))
            {
                _statusPeer = null;
            }
        }

        LogDiagnostic("Status pipe disconnected.");
    }

    private void SetDisconnectedUi()
    {
        _notifyIcon.Icon = _iconByState[RuntimeState.Error];
        _notifyIcon.Text = "APFS Access: service disconnected";
    }

    private void UpdateUi(StatusChangedPayload payload)
    {
        if (!_iconByState.TryGetValue(payload.State, out var icon))
        {
            icon = _iconByState[RuntimeState.Idle];
        }

        _notifyIcon.Icon = icon;

        var text = BuildNotifyIconText(payload);

        if (text.Length > 63)
        {
            text = text[..63];
        }

        _notifyIcon.Text = text;
        UpdateEjectMenu(payload);
        ShowWarnings(payload);
    }

    private void UpdateEjectMenu(StatusChangedPayload payload)
    {
        var descriptors = BuildEjectMenuDescriptors(payload);
        _ejectItem.DropDownItems.Clear();
        _ejectItem.Tag = null;
        _ejectItem.Enabled = descriptors.Count > 0;

        if (descriptors.Count == 0)
        {
            _ejectItem.Text = "Eject APFS drives";
            return;
        }

        if (descriptors.Count == 1)
        {
            var descriptor = descriptors[0];
            _ejectItem.Text = descriptor.Text;
            _ejectItem.Tag = descriptor.VolumeId;
            return;
        }

        _ejectItem.Text = $"Eject APFS drives ({descriptors.Count})";
        foreach (var descriptor in descriptors)
        {
            var child = new ToolStripMenuItem(descriptor.Text)
            {
                Tag = descriptor.VolumeId,
            };
            child.Click += OnEjectClicked;
            _ejectItem.DropDownItems.Add(child);
        }
    }

    private static string BuildNotifyIconText(StatusChangedPayload payload)
    {
        var text = payload.State switch
        {
            RuntimeState.MountedRw => $"APFS Access: mounted RW ({payload.MountPoints.Count})",
            RuntimeState.MountedRo => $"APFS Access: mounted RO ({payload.MountPoints.Count})",
            RuntimeState.Error => "APFS Access: error",
            RuntimeState.Starting => "APFS Access: starting",
            RuntimeState.Stopping => "APFS Access: stopping",
            _ => "APFS Access: idle",
        };

        var warningCount = (payload.Warnings?.Count ?? 0) + (payload.CompatibilityWarnings?.Count ?? 0);
        if (warningCount > 0 && payload.State is not RuntimeState.Error)
        {
            text = $"{text} [warn:{warningCount}]";
        }

        var primaryRecoveryReason = SelectPrimaryRecoveryReason(payload);
        if ((payload.RecoveryActive || payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked) &&
            payload.State is not RuntimeState.Error)
        {
            text = string.IsNullOrWhiteSpace(primaryRecoveryReason)
                ? $"{text} [recovery]"
                : $"{text} [recovery:{primaryRecoveryReason}]";
        }

        if (payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked &&
            payload.State is not RuntimeState.Error)
        {
            text = $"{text} [rw:blocked]";
        }

        if (payload.DirtyTransactionCount > 0 && payload.State is not RuntimeState.Error)
        {
            text = $"{text} [dirty:{payload.DirtyTransactionCount}]";
        }

        if (payload.ShutdownDrainActive && payload.State is not RuntimeState.Error)
        {
            text = $"{text} [drain]";
        }

        if (payload.InFlightMutationCallbacks > 0 && payload.State is not RuntimeState.Error)
        {
            text = $"{text} [mut:{payload.InFlightMutationCallbacks}]";
        }

        return text;
    }

    private static IReadOnlyList<EjectMenuDescriptor> BuildEjectMenuDescriptors(StatusChangedPayload payload)
    {
        if (payload.MountedVolumes is { Count: > 0 })
        {
            return payload.MountedVolumes
                .Where(static volume => !string.IsNullOrWhiteSpace(volume.MountPoint))
                .OrderBy(static volume => NormalizeDriveLabel(volume.MountPoint), StringComparer.OrdinalIgnoreCase)
                .Select(static volume => new EjectMenuDescriptor(
                    BuildEjectMenuText(volume),
                    volume.VolumeId))
                .ToArray();
        }

        return (payload.MountPoints ?? Array.Empty<string>())
            .Where(static mountPoint => !string.IsNullOrWhiteSpace(mountPoint))
            .OrderBy(static mountPoint => NormalizeDriveLabel(mountPoint), StringComparer.OrdinalIgnoreCase)
            .Select(static mountPoint => new EjectMenuDescriptor(
                $"Eject APFS drive {NormalizeDriveLabel(mountPoint)}",
                null))
            .ToArray();
    }

    private static string BuildEjectMenuText(MountedVolumeDisplay volume)
    {
        var deviceName = !string.IsNullOrWhiteSpace(volume.DeviceDisplayName)
            ? volume.DeviceDisplayName.Trim()
            : !string.IsNullOrWhiteSpace(volume.DeviceId)
                ? volume.DeviceId.Trim()
                : "APFS drive";
        var drive = NormalizeDriveLabel(volume.MountPoint);
        var volumeName = !string.IsNullOrWhiteSpace(volume.VolumeName)
            ? volume.VolumeName.Trim()
            : "APFS";

        return $"Eject {deviceName} ({drive}, {volumeName})";
    }

    private static string NormalizeDriveLabel(string? mountPoint)
    {
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            return "?";
        }

        var trimmed = mountPoint.Trim();
        if (trimmed.Length >= 2 && trimmed[1] == ':')
        {
            return $"{char.ToUpperInvariant(trimmed[0])}:";
        }

        return trimmed.TrimEnd('\\');
    }

    private static void LogDiagnostic(string message)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ApfsAccess");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "tray-diagnostics.log");
            var line = $"{DateTimeOffset.Now:O} [pid:{Environment.ProcessId}] {message}{Environment.NewLine}";
            lock (DiagnosticLogSync)
            {
                File.AppendAllText(logPath, line);
            }
        }
        catch
        {
            // Diagnostics must never affect tray behavior.
        }
    }

    private void ShowWarnings(StatusChangedPayload payload)
    {
        var warnings = (payload.Warnings ?? Array.Empty<string>())
            .Concat(payload.CompatibilityWarnings ?? Array.Empty<string>())
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static x => GetWarningPriority(x))
            .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        ShowWarnings(warnings);
    }

    private void ShowWarnings(IReadOnlyList<string> warnings)
    {
        if (warnings.Count == 0)
        {
            return;
        }

        foreach (var warning in warnings)
        {
            if (string.IsNullOrWhiteSpace(warning))
            {
                continue;
            }

            if (!_shownWarnings.Add(warning))
            {
                continue;
            }

            var message = warning.Length > 220 ? warning[..220] : warning;
            _notifyIcon.ShowBalloonTip(6000, "APFS Access Notice", message, ToolTipIcon.Warning);
        }
    }

    private static string? SelectPrimaryRecoveryReason(StatusChangedPayload payload)
    {
        var candidates = new List<string>();

        if (!string.IsNullOrWhiteSpace(payload.RecoveryReason))
        {
            candidates.Add(payload.RecoveryReason.Trim());
        }

        if (payload.NativeWriteDiagnostics is { Count: > 0 })
        {
            candidates.AddRange(
                payload.NativeWriteDiagnostics
                    .Select(static x => x.RecoveryReason)
                    .Where(static x => !string.IsNullOrWhiteSpace(x))
                    .Select(static x => x!.Trim()));
        }

        foreach (var warning in (payload.CompatibilityWarnings ?? Array.Empty<string>())
                     .Concat(payload.Warnings ?? Array.Empty<string>()))
        {
            var parsed = TryExtractReasonTokenFromWarning(warning);
            if (!string.IsNullOrWhiteSpace(parsed))
            {
                candidates.Add(parsed);
            }
        }

        return candidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static x => GetRecoveryReasonPriority(x))
            .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    private static int GetWarningPriority(string warning)
    {
        var reason = TryExtractReasonTokenFromWarning(warning);
        if (!string.IsNullOrWhiteSpace(reason))
        {
            return GetRecoveryReasonPriority(reason);
        }

        return int.MaxValue;
    }

    private static int GetRecoveryReasonPriority(string? recoveryReason)
    {
        if (string.IsNullOrWhiteSpace(recoveryReason))
        {
            return int.MaxValue;
        }

        var normalized = recoveryReason.Trim();
        if (ExplicitCanonicalGateRecoveryReasons.Any(x => string.Equals(x, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return 0;
        }

        if (HighPriorityReplayRecoveryReasons.Any(x => string.Equals(x, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return 1;
        }

        if (string.Equals(normalized, "CanonicalPathNotActive", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        return 3;
    }

    private static string? TryExtractReasonTokenFromWarning(string? warning)
    {
        if (string.IsNullOrWhiteSpace(warning))
        {
            return null;
        }

        var text = warning.AsSpan();
        const string marker = "reason=";
        var index = warning.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        var cursor = index + marker.Length;
        while (cursor < text.Length && char.IsWhiteSpace(text[cursor]))
        {
            cursor++;
        }

        var start = cursor;
        while (cursor < text.Length)
        {
            var ch = text[cursor];
            if (char.IsLetterOrDigit(ch) || ch == '_')
            {
                cursor++;
                continue;
            }
            break;
        }

        if (cursor <= start)
        {
            return null;
        }

        return warning[start..cursor];
    }

    private Dictionary<RuntimeState, Icon> LoadIcons()
    {
        var outputDir = AppContext.BaseDirectory;
        var iconDir = Path.Combine(outputDir, "assets", "icons");

        Icon Load(string fileName, Icon fallback)
        {
            var path = Path.Combine(iconDir, fileName);
            if (!File.Exists(path))
            {
                return fallback;
            }

            using var fs = File.OpenRead(path);
            var icon = new Icon(fs);
            _ownedIcons.Add(icon);
            return icon;
        }

        return new Dictionary<RuntimeState, Icon>
        {
            [RuntimeState.Starting] = Load("tray_idle.ico", SystemIcons.Application),
            [RuntimeState.Idle] = Load("tray_idle.ico", SystemIcons.Application),
            [RuntimeState.MountedRw] = Load("tray_mounted_rw.ico", SystemIcons.Shield),
            [RuntimeState.MountedRo] = Load("tray_mounted_ro.ico", SystemIcons.Shield),
            [RuntimeState.Error] = Load("tray_error.ico", SystemIcons.Error),
            [RuntimeState.Stopping] = Load("tray_idle.ico", SystemIcons.Application),
        };
    }

    private void PostToUi(Action action)
    {
        if (_uiInvoker.IsDisposed)
        {
            action();
            return;
        }

        if (_uiInvoker.IsHandleCreated)
        {
            _uiInvoker.BeginInvoke(action);
            return;
        }

        _uiContext.Post(_ => action(), null);
    }

    protected override void ExitThreadCore()
    {
        _shutdownCts.Cancel();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();

        foreach (var icon in _ownedIcons)
        {
            icon.Dispose();
        }

        _shutdownCts.Dispose();
        _uiInvoker.Dispose();
        base.ExitThreadCore();
    }
}
