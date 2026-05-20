using System.Diagnostics;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed class TrayApplicationContext : ApplicationContext
{
    private static readonly TimeSpan ServiceStartThrottle = TimeSpan.FromSeconds(4);
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
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _ejectItem;
    private readonly List<Icon> _ownedIcons = [];
    private readonly Dictionary<RuntimeState, Icon> _iconByState;
    private readonly HashSet<string> _shownWarnings = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _shutdownCts = new();

    private bool _exitRequested;
    private DateTime _lastServiceStartAttemptUtc = DateTime.MinValue;

    public TrayApplicationContext()
    {
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

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
        _ = sender;
        _ = e;
        await RequestEjectAsync().ConfigureAwait(false);
    }

    private async Task RequestEjectAsync()
    {
        PostToUi(() => _ejectItem.Enabled = false);
        var (success, message) = await TrySendEjectAsync().ConfigureAwait(false);
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

        try
        {
            if (Process.GetProcessesByName("ApfsAccess.Service").Length > 0)
            {
                return;
            }
        }
        catch
        {
            // If process enumeration fails, continue and attempt process start by path.
        }

        foreach (var candidate in GetServiceExeCandidates())
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

    private async Task<(bool Success, string? Message)> TrySendEjectAsync()
    {
        var requestId = Guid.NewGuid().ToString("N");

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            await using var peer = await NamedPipeMessageClient
                .ConnectAsync(ApfsPipeConstants.PipeName, timeoutMilliseconds: 1000, timeoutCts.Token)
                .ConfigureAwait(false);

            var ejectMessage = PipeMessageCodec.Create(
                ApfsMessageTypes.EjectRequested,
                new EjectRequestedPayload(Environment.UserName, DateTime.UtcNow),
                requestId
            );

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
                    return (ack.Success, ack.Message);
                }

                return (false, "The service returned an unreadable eject response.");
            }
        }
        catch (Exception ex)
        {
            return (false, $"Could not request eject: {ex.Message}");
        }

        return (false, "Timed out waiting for APFS Access to eject drives.");
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
        _ejectItem.Enabled = payload.MountPoints.Count > 0;
        ShowWarnings(payload);
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
        base.ExitThreadCore();
    }
}
