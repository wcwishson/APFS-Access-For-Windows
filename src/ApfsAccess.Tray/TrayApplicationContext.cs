using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed record EjectMenuDescriptor(string Text, string? VolumeId);

public sealed class TrayApplicationContext : ApplicationContext
{
    private static readonly TimeSpan ServiceStartThrottle = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan EjectRequestTimeout = TimeSpan.FromSeconds(130);
    private static readonly TimeSpan FixRequestTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan UpdateShutdownTimeout = TimeSpan.FromSeconds(150);
    private static readonly Uri LatestReleasePage = new("https://github.com/wcwishson/APFS-Access-For-Windows/releases/latest");
    private static readonly object DiagnosticLogSync = new();

    private readonly SynchronizationContext _uiContext;
    private readonly Control _uiInvoker = new();
    private readonly NotifyIcon _notifyIcon;
    private readonly DashboardForm _dashboard;
    private readonly StartupSettingsManager _startupSettingsManager;
    private readonly GitHubReleaseUpdateClient _updateClient = new();
    private readonly ToolStripMenuItem _ejectItem;
    private readonly List<Icon> _ownedIcons = [];
    private readonly Dictionary<RuntimeState, Icon> _iconByState;
    private readonly HashSet<string> _shownWarnings = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<AckPayload>> _pendingAcks = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _statusPeerSync = new();
    private string? _ejectMenuSignature;
    private AppUpdateDownload? _readyUpdate;

private PipePeer? _statusPeer;
    private StatusChangedPayload? _latestStatus;
    private DriveDashboardState? _lastStatusBalloonState;
    private int _exitRequested;
    private int _updateHandoffActive;
    private DateTime _lastServiceStartAttemptUtc = DateTime.MinValue;
    private readonly DateTime _trayStartedUtc;

    public TrayApplicationContext()
    {
        _trayStartedUtc = DateTime.UtcNow;
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _ = _uiInvoker.Handle;

        _iconByState = LoadIcons();

        var menu = new ContextMenuStrip();
        var showItem = new ToolStripMenuItem("Show APFS Access");
        showItem.Click += (_, _) => ShowDashboard();
        menu.Items.Add(showItem);
        menu.Items.Add(new ToolStripSeparator());

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

        _startupSettingsManager = StartupSettingsManager.CreateDefault();
        var startupPreferences = _startupSettingsManager.Load();
        _dashboard = new DashboardForm(
            OpenMountPointAsync,
            RequestEjectAsync,
            RequestFixAsync,
            startupPreferences,
            SetStartWithWindowsAsync,
            SetStartMinimizedAsync,
            HandleUpdateButtonAsync);
if (!startupPreferences.StartMinimized)
        {
            _dashboard.Show();
        }

        HandleIntentionalQuitMarker();
        TryStartServiceProcessIfMissing();
        _ = Task.Run(() => RunStatusListenerAsync(_shutdownCts.Token));
        UpdateReceiptPublisher.TryWriteCurrentProcessPhase("ready");
    }

    private void OnNotifyIconMouseClick(object? sender, MouseEventArgs e)
    {
        _ = sender;
        if (e.Button == MouseButtons.Left)
        {
            ShowDashboard();
            return;
        }
    }

    private void ShowDashboard()
    {
        _dashboard.ShowDashboard();
        if (_latestStatus is not null)
        {
            _dashboard.ApplyStatus(_latestStatus);
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
        PostToUi(() =>
        {
            _ejectItem.Enabled = false;
            _dashboard.SetActionsEnabled(false);
            _dashboard.SetFooter("Ejecting APFS drive...");
        });
        var (success, message) = await TrySendEjectAsync(volumeId).ConfigureAwait(false);
        LogDiagnostic($"Eject request completed. success={success}; message='{message ?? string.Empty}'");
        PostToUi(() =>
        {
            _ejectItem.Enabled = true;
            _dashboard.SetActionsEnabled(true);
            _dashboard.SetFooter(string.IsNullOrWhiteSpace(message)
                ? (success ? "APFS drive ejected." : "Eject failed.")
                : message);
            _notifyIcon.ShowBalloonTip(
                5000,
                SelectActionFeedbackTitle(success, volumeId),
                string.IsNullOrWhiteSpace(message) ? (success ? "APFS drives ejected." : "Eject failed.") : message,
                SelectActionFeedbackIcon(success, volumeId));
        });
    }

    private async Task RequestFixAsync(string? volumeId)
    {
        PostToUi(() =>
        {
            _dashboard.SetActionsEnabled(false);
            _dashboard.SetFooter("Refreshing APFS drive...");
        });
        var (success, message) = await TrySendFixAsync(volumeId).ConfigureAwait(false);
        LogDiagnostic($"Fix refresh request completed. success={success}; message='{message ?? string.Empty}'");
        PostToUi(() =>
        {
            _dashboard.SetActionsEnabled(true);
            _dashboard.SetFooter(string.IsNullOrWhiteSpace(message)
                ? (success ? "Refresh requested. APFS Access will remount the drive if it is safe." : "Could not refresh APFS drives.")
                : message);
            _notifyIcon.ShowBalloonTip(
                5000,
                SelectActionFeedbackTitle(success, volumeId),
                string.IsNullOrWhiteSpace(message)
                    ? (success ? "APFS drives refreshed." : "Could not refresh APFS drives.")
                    : message,
                SelectActionFeedbackIcon(success, volumeId));
        });
    }

    private Task SetStartWithWindowsAsync(bool enabled)
    {
        _startupSettingsManager.SetStartWithWindows(enabled);
        return Task.CompletedTask;
    }

    private Task SetStartMinimizedAsync(bool enabled)
    {
        _startupSettingsManager.SetStartMinimized(enabled);
        return Task.CompletedTask;
    }

    private async Task HandleUpdateButtonAsync()
    {
        if (_readyUpdate is not null)
        {
            await InstallReadyUpdateAsync(_readyUpdate).ConfigureAwait(true);
            return;
        }

        if (!TryResolveInstalledLauncherPath(out var launcherPath))
        {
            _dashboard.SetUpdateStatus(
                "Automatic install is available when running APFS Access.exe.",
                "Check for updates",
                enabled: true);
            var open = MessageBox.Show(
                _dashboard,
                "This copy was started from the extracted zip. Download APFS Access.exe from the latest release page to update.",
                "APFS Access",
                MessageBoxButtons.OKCancel,
                MessageBoxIcon.Information);
            if (open == DialogResult.OK)
            {
                Process.Start(new ProcessStartInfo { FileName = LatestReleasePage.AbsoluteUri, UseShellExecute = true });
            }
            return;
        }

        _dashboard.SetUpdateStatus("Checking GitHub and downloading any available update...", "Checking...", enabled: false);
        var progress = new Progress<AppUpdateProgress>(value =>
            _dashboard.SetUpdateStatus($"Downloading update: {value.Percentage}%", "Checking...", enabled: false));

        var currentVersion = typeof(TrayApplicationContext).Assembly.GetName().Version ?? new Version(1, 0, 5);
        var result = await _updateClient.CheckAndDownloadAsync(
            launcherPath,
            currentVersion,
            progress,
            _shutdownCts.Token).ConfigureAwait(true);

        switch (result.Decision)
        {
            case AppUpdateDecision.UpToDate:
                _dashboard.SetUpdateStatus("APFS Access is up to date.", "Check for updates", enabled: true);
                break;
            case AppUpdateDecision.Ready when result.Download is not null:
                _readyUpdate = result.Download;
                _dashboard.SetUpdateStatus(
                    $"Version {result.Download.Release.Version.ToString(3)} is downloaded and verified.",
                    "Install update",
                    enabled: true);
                break;
            default:
                _dashboard.SetUpdateStatus(
                    result.Error ?? "The update could not be downloaded.",
                    "Check for updates",
                    enabled: true);
                break;
        }
    }

    private async Task InstallReadyUpdateAsync(AppUpdateDownload download)
    {
        var updaterPath = Path.Combine(AppContext.BaseDirectory, "ApfsAccess.Updater.exe");
        if (!File.Exists(updaterPath) ||
            !File.Exists(download.ReadyPath) ||
            !TryResolveInstalledLauncherPath(out var launcherPath) ||
            !string.Equals(launcherPath, download.LauncherPath, StringComparison.OrdinalIgnoreCase))
        {
            _readyUpdate = null;
            _dashboard.SetUpdateStatus(
                "The verified update is no longer available. Check again.",
                "Check for updates",
                enabled: true);
            return;
        }

        var choice = MessageBox.Show(
            _dashboard,
            "APFS Access will safely eject its mounted drives, install the downloaded update, and restart. Continue?",
            "Install APFS Access update",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2);
        if (choice != DialogResult.Yes)
        {
            _dashboard.SetUpdateStatus(
                $"Version {download.Release.Version.ToString(3)} is ready to install.",
                "Install update",
                enabled: true);
            return;
        }

        Interlocked.Exchange(ref _updateHandoffActive, 1);
        _dashboard.SetActionsEnabled(false);
        _dashboard.SetUpdateStatus("Safely ejecting APFS drives...", "Installing...", enabled: false);

        var shutdown = await RequestVerifiedShutdownForUpdateAsync().ConfigureAwait(true);
        if (!IsCompleteShutdownProof(shutdown))
        {
            Interlocked.Exchange(ref _updateHandoffActive, 0);
            _dashboard.SetActionsEnabled(true);
            _dashboard.SetUpdateStatus(
                shutdown?.Diagnostic ?? "APFS Access could not safely release every mounted drive.",
                "Install update",
                enabled: true);
            MessageBox.Show(
                _dashboard,
                "The update was not installed because APFS Access could not verify a clean drive shutdown. Close files using the APFS drive and try again.",
                "APFS Access",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var manifestPath = WriteUpdateManifest(download);
        var startInfo = new ProcessStartInfo
        {
            FileName = updaterPath,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--apply");
        startInfo.ArgumentList.Add(manifestPath);
        _ = Process.Start(startInfo) ?? throw new InvalidOperationException("The update installer could not be started.");

        Interlocked.Exchange(ref _exitRequested, 1);
        ExitTrayForShutdown();
    }

    private async Task<ServiceStoppingPayload?> RequestVerifiedShutdownForUpdateAsync()
    {
        var requestId = Guid.NewGuid().ToString("N");
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_shutdownCts.Token);
        timeoutCts.CancelAfter(UpdateShutdownTimeout);

        try
        {
            await using var peer = await NamedPipeMessageClient
                .ConnectAsync(ApfsPipeConstants.PipeName, timeoutMilliseconds: 1500, timeoutCts.Token)
                .ConfigureAwait(false);
            await peer.SendAsync(
                PipeMessageCodec.Create(
                    ApfsMessageTypes.QuitRequested,
                    new QuitRequestedPayload(Environment.UserName, DateTime.UtcNow),
                    requestId),
                timeoutCts.Token).ConfigureAwait(false);

            var acknowledged = false;
            while (!timeoutCts.Token.IsCancellationRequested)
            {
                var message = await peer.ReadMessageAsync(timeoutCts.Token).ConfigureAwait(false);
                if (message is null)
                {
                    return null;
                }

                if (message.Type == ApfsMessageTypes.Ack &&
                    string.Equals(message.RequestId, requestId, StringComparison.OrdinalIgnoreCase) &&
                    PipeMessageCodec.TryGetPayload<AckPayload>(message, out var ack))
                {
                    acknowledged = ack?.Success == true;
                    continue;
                }

                if (acknowledged &&
                    message.Type == ApfsMessageTypes.ServiceStopping &&
                    PipeMessageCodec.TryGetPayload<ServiceStoppingPayload>(message, out var stopping))
                {
                    return stopping;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException)
        {
            LogDiagnostic($"Update shutdown handoff failed: {ex.Message}");
        }

        return null;
    }

    private static bool IsCompleteShutdownProof(ServiceStoppingPayload? payload)
        => payload is
        {
            CleanupCompleted: true,
            HostOwnershipReleased: true,
            PendingDurabilityCleared: true,
            RemainingMountPoints.Count: 0,
        };

    private static bool TryResolveInstalledLauncherPath(out string launcherPath)
    {
        launcherPath = string.Empty;
        var value = Environment.GetEnvironmentVariable("APFSACCESS_LAUNCHER_PATH");
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
        {
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(value);
            if (!File.Exists(fullPath) ||
                !string.Equals(Path.GetFileName(fullPath), "APFS Access.exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            launcherPath = fullPath;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string WriteUpdateManifest(AppUpdateDownload download)
    {
        using var process = Process.GetCurrentProcess();
        var directory = Path.GetDirectoryName(download.LauncherPath)!;
        var id = Guid.NewGuid().ToString("N");
        var manifestPath = Path.Combine(directory, $".APFS.Access.update.{id}.json");
        var manifest = new UpdateHandoffManifest(
            process.Id,
            process.StartTime.ToUniversalTime().Ticks,
            download.LauncherPath,
            download.ReadyPath,
            Path.Combine(directory, $".APFS.Access.update.{id}.backup"),
            Path.Combine(directory, $".APFS.Access.update.{id}.receipt.json"),
            download.CurrentSha256,
            download.Release.Sha256,
            download.Release.Version.ToString(3),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        File.WriteAllText(
            manifestPath,
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        return manifestPath;
    }

    private sealed record UpdateHandoffManifest(
        int OldTrayProcessId,
        long OldTrayStartTimeUtcTicks,
        string LauncherPath,
        string ReadyPath,
        string BackupPath,
        string ReceiptPath,
        string CurrentSha256,
        string ExpectedSha256,
        string ExpectedVersion,
        string Token);

    private static Task OpenMountPointAsync(string? mountPoint)
    {
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            return Task.CompletedTask;
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = mountPoint,
            UseShellExecute = true,
        });

        return Task.CompletedTask;
    }

    private async Task RequestQuitAndExitAsync()
    {
        if (Interlocked.Exchange(ref _exitRequested, 1) != 0)
        {
            return;
        }

        var acknowledged = await TrySendQuitAsync().ConfigureAwait(false);
        var serviceRunning = IsServiceProcessRunningOrUnknown();
        if (!ShouldCompleteQuit(acknowledged, serviceRunning))
        {
            LogDiagnostic("Quit request was not acknowledged and the APFS Access service is still running; keeping the tray available for retry.");
            Interlocked.Exchange(ref _exitRequested, 0);
            return;
        }

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

                        if (message.Type == ApfsMessageTypes.ServiceStopping &&
                            PipeMessageCodec.TryGetPayload<ServiceStoppingPayload>(message, out _))
                        {
                            HandleServiceStopping();
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
        if (Volatile.Read(ref _exitRequested) != 0 ||
            Volatile.Read(ref _updateHandoffActive) != 0)
        {
            return;
        }

        HandleIntentionalQuitMarker();
        if (Volatile.Read(ref _exitRequested) != 0)
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

                QuitRequestMarker.ClearMarker();
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
                    Environment =
                    {
                        ["TEMP"] = Environment.GetEnvironmentVariable("TEMP") ?? Path.GetTempPath(),
                        ["TMP"] = Environment.GetEnvironmentVariable("TMP") ?? Path.GetTempPath(),
                        ["APFSACCESS_SPOOL_ROOT"] = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? string.Empty,
                        ["APFSACCESS_RUNTIME_ROOT"] = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT") ?? string.Empty,
                        ["APFSACCESS_TRACE_MOVES"] = Environment.GetEnvironmentVariable("APFSACCESS_TRACE_MOVES") ?? string.Empty,
                        ["APFSACCESS_PERF_COUNTERS"] = Environment.GetEnvironmentVariable("APFSACCESS_PERF_COUNTERS") ?? string.Empty,
                        ["APFSACCESS_TRACE_COMMITS"] = Environment.GetEnvironmentVariable("APFSACCESS_TRACE_COMMITS") ?? string.Empty,
                        ["APFSACCESS_TRACE_READS"] = Environment.GetEnvironmentVariable("APFSACCESS_TRACE_READS") ?? string.Empty,
                        ["APFSACCESS_DEFER_CLOSE_COMMITS"] = Environment.GetEnvironmentVariable("APFSACCESS_DEFER_CLOSE_COMMITS") ?? string.Empty,
                        ["APFSACCESS_DISABLE_CONTENT_WRITEBACK"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CONTENT_WRITEBACK") ?? string.Empty,
                        ["APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE"] = Environment.GetEnvironmentVariable("APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE") ?? string.Empty,
                        ["APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE") ?? string.Empty,
                        ["APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE") ?? string.Empty,
                        ["APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK"] = Environment.GetEnvironmentVariable("APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK") ?? string.Empty,
                        ["APFSACCESS_DISABLE_NAMESPACE_WRITEBACK"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_NAMESPACE_WRITEBACK") ?? string.Empty,
                        ["APFSACCESS_DISABLE_ASYNC_BLOCK_IO"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_ASYNC_BLOCK_IO") ?? string.Empty,
                        ["APFSACCESS_ASYNC_BLOCK_IO_DEPTH"] = Environment.GetEnvironmentVariable("APFSACCESS_ASYNC_BLOCK_IO_DEPTH") ?? string.Empty,
                        ["APFSACCESS_CHECKPOINT_DELTA_SHADOW"] = Environment.GetEnvironmentVariable("APFSACCESS_CHECKPOINT_DELTA_SHADOW") ?? string.Empty,
                        ["APFSACCESS_STRICT_COMMIT_VERIFY"] = Environment.GetEnvironmentVariable("APFSACCESS_STRICT_COMMIT_VERIFY") ?? string.Empty,
                        ["APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE") ?? string.Empty,
                        ["APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE") ?? string.Empty,
                        ["APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX") ?? string.Empty,
                        ["APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE") ?? string.Empty,
                        ["APFSACCESS_DISABLE_INDEX_DELTA"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_INDEX_DELTA") ?? string.Empty,
                    },
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
            // The caller verifies service exit before allowing the tray to close.
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

            if (message.Type == ApfsMessageTypes.ServiceStopping &&
                PipeMessageCodec.TryGetPayload<ServiceStoppingPayload>(message, out _))
            {
                HandleServiceStopping();
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

    private static bool ShouldCompleteQuit(bool acknowledged, bool serviceRunning)
        => acknowledged || !serviceRunning;

    private static bool IsServiceProcessRunningOrUnknown()
    {
        Process[] processes;
        try
        {
            processes = Process.GetProcessesByName("ApfsAccess.Service");
        }
        catch
        {
            return true;
        }

        try
        {
            return processes.Length > 0;
        }
        finally
        {
            DisposeProcesses(processes);
        }
    }

private void HandleServiceStopping()
    {
        if (Volatile.Read(ref _updateHandoffActive) != 0)
        {
            LogDiagnostic("Service stopping notification received during update handoff; waiting for the dedicated shutdown proof.");
            return;
        }

        if (Interlocked.Exchange(ref _exitRequested, 1) != 0)
        {
            return;
        }

        LogDiagnostic("Service notified the tray that it is stopping; exiting tray.");
        ExitTrayForShutdown();
    }

    private void HandleIntentionalQuitMarker()
    {
        if (Volatile.Read(ref _exitRequested) != 0)
        {
            return;
        }

        var markerTimestampUtc = QuitRequestMarker.TryReadMarkerTimestampUtc();
        if (markerTimestampUtc is null)
        {
            return;
        }

        if (QuitRequestMarker.ShouldHonorMarker(markerTimestampUtc.Value, _trayStartedUtc))
        {
            LogDiagnostic($"Intentional quit marker found (written {markerTimestampUtc.Value:O}); exiting tray without restarting the service.");
            if (Interlocked.Exchange(ref _exitRequested, 1) != 0)
            {
                return;
            }

            ExitTrayForShutdown();
            return;
        }

        LogDiagnostic("Ignoring stale quit marker from a previous tray session.");
        QuitRequestMarker.ClearMarker();
    }

    private void ExitTrayForShutdown()
    {
        try
        {
            _shutdownCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        PostToUi(() =>
        {
            _notifyIcon.Visible = false;
            ExitThread();
        });
    }

    private async Task<(bool Success, string? Message)> TrySendEjectAsync(string? volumeId = null)
        => await TrySendRequestAsync(
            ApfsMessageTypes.EjectRequested,
            new EjectRequestedPayload(Environment.UserName, DateTime.UtcNow, volumeId),
            EjectRequestTimeout,
            $"volumeId='{volumeId ?? "<all>"}'",
            "Timed out waiting for APFS Access to eject drives.")
            .ConfigureAwait(false);

    private async Task<(bool Success, string? Message)> TrySendRefreshAsync(bool clearUserEjectedVolumes, string? volumeId = null)
        => await TrySendRequestAsync(
            ApfsMessageTypes.RefreshRequested,
            new RefreshRequestedPayload(Environment.UserName, DateTime.UtcNow, clearUserEjectedVolumes, volumeId),
            FixRequestTimeout,
            $"clearUserEjectedVolumes={clearUserEjectedVolumes}; volumeId='{volumeId ?? "<all>"}'",
            "Timed out waiting for APFS Access to refresh drives.")
            .ConfigureAwait(false);

    private async Task<(bool Success, string? Message)> TrySendFixAsync(string? volumeId = null)
        => await TrySendRequestAsync(
            ApfsMessageTypes.FixRequested,
            new FixRequestedPayload(Environment.UserName, DateTime.UtcNow, volumeId),
            FixRequestTimeout,
            $"volumeId='{volumeId ?? "<all>"}'",
            "Timed out waiting for APFS Access to fix drives.")
            .ConfigureAwait(false);

    private async Task<(bool Success, string? Message)> TrySendRequestAsync(
        string messageType,
        object payload,
        TimeSpan timeout,
        string diagnosticDetail,
        string timeoutMessage)
    {
        var statusPeer = GetStatusPeer();
        if (statusPeer is not null)
        {
            try
            {
                return await TrySendRequestOnStatusChannelAsync(statusPeer, messageType, payload, timeout, diagnosticDetail, timeoutMessage)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
                LogDiagnostic($"Status-channel {messageType} failed before ACK wait; falling back to transient pipe. {ex.GetType().Name}: {ex.Message}");
            }
        }

        return await TrySendRequestOnTransientPipeAsync(messageType, payload, timeout, diagnosticDetail, timeoutMessage)
            .ConfigureAwait(false);
    }

    private async Task<(bool Success, string? Message)> TrySendRequestOnStatusChannelAsync(
        PipePeer peer,
        string messageType,
        object payload,
        TimeSpan timeout,
        string diagnosticDetail,
        string timeoutMessage)
    {
        var requestId = Guid.NewGuid().ToString("N");
        var pending = new TaskCompletionSource<AckPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingAcks.TryAdd(requestId, pending))
        {
            return (false, "Could not contact APFS Access: duplicate request id.");
        }

        using var timeoutCts = new CancellationTokenSource(timeout);
        try
        {
            var message = PipeMessageCodec.Create(messageType, payload, requestId);

            LogDiagnostic($"Sending {messageType} over status channel. requestId={requestId}; {diagnosticDetail}");
            await peer.SendAsync(message, timeoutCts.Token).ConfigureAwait(false);
            var ack = await pending.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
            return (ack.Success, ack.Message);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            LogDiagnostic($"Timed out waiting for status-channel {messageType} ACK. requestId={requestId}");
            return (false, timeoutMessage);
        }
        finally
        {
            _pendingAcks.TryRemove(requestId, out _);
        }
    }

    private async Task<(bool Success, string? Message)> TrySendRequestOnTransientPipeAsync(
        string messageType,
        object payload,
        TimeSpan timeout,
        string diagnosticDetail,
        string timeoutMessage)
    {
        var requestId = Guid.NewGuid().ToString("N");

        using var timeoutCts = new CancellationTokenSource(timeout);
        try
        {
            await using var peer = await NamedPipeMessageClient
                .ConnectAsync(ApfsPipeConstants.PipeName, timeoutMilliseconds: 1000, timeoutCts.Token)
                .ConfigureAwait(false);

            var message = PipeMessageCodec.Create(messageType, payload, requestId);

            LogDiagnostic($"Sending {messageType} over transient pipe. requestId={requestId}; {diagnosticDetail}");
            await peer.SendAsync(message, timeoutCts.Token).ConfigureAwait(false);

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
                    LogDiagnostic($"Transient {messageType} ACK received. requestId={requestId}; success={ack.Success}; message='{ack.Message ?? string.Empty}'");
                    return (ack.Success, ack.Message);
                }

                return (false, "The service returned an unreadable response.");
            }
        }
        catch (Exception ex)
        {
            LogDiagnostic($"Transient {messageType} request failed. requestId={requestId}; {ex.GetType().Name}: {ex.Message}");
            return (false, $"Could not contact APFS Access: {ex.Message}");
        }

        LogDiagnostic($"Timed out waiting for transient {messageType} ACK. requestId={requestId}");
        return (false, timeoutMessage);
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

        pending.TrySetResult(new AckPayload(false, "The service returned an unreadable response."));
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
        _ejectMenuSignature = null;
        ResetEjectMenu(_ejectItem);
        var disconnected = new StatusChangedPayload(
            State: RuntimeState.Error,
            MountPoints: Array.Empty<string>(),
            LastError: "APFS Access service is disconnected.",
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["APFS Access service is disconnected."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>());
        _latestStatus = disconnected;
        _lastStatusBalloonState = SelectBalloonState(disconnected);
        _dashboard.ApplyStatus(disconnected);
    }

    private void UpdateUi(StatusChangedPayload payload)
    {
        _latestStatus = payload;
        var previousBalloonState = _lastStatusBalloonState;
        var rows = DriveDashboardPresenter.BuildRows(payload);
        var currentBalloonState = SelectBalloonStateFromRows(payload, rows);
        if (!_iconByState.TryGetValue(SelectNotifyIconStateForState(currentBalloonState, payload.State), out var icon))
        {
            icon = _iconByState[RuntimeState.Idle];
        }

        _notifyIcon.Icon = icon;

        var text = BuildNotifyIconTextForState(payload, currentBalloonState);

        if (text.Length > 63)
        {
            text = text[..63];
        }

        _notifyIcon.Text = text;
        UpdateEjectMenu(payload);
        _dashboard.ApplyStatus(payload);
        if (currentBalloonState == DriveDashboardState.HealthyReadWrite)
        {
            _shownWarnings.Clear();
        }
        ShowWarnings(payload, BuildStatusBalloonWarnings(payload, currentBalloonState), currentBalloonState);
        ShowHealthTransition(payload, previousBalloonState, currentBalloonState);
        _lastStatusBalloonState = currentBalloonState;
    }

    private void UpdateEjectMenu(StatusChangedPayload payload)
    {
        var descriptors = BuildEjectMenuDescriptors(payload);
        var signature = BuildEjectMenuSignature(descriptors);
        if (string.Equals(_ejectMenuSignature, signature, StringComparison.Ordinal))
        {
            return;
        }

        _ejectMenuSignature = signature;
        _ejectItem.DropDownItems.Clear();
        _ejectItem.Tag = null;
        _ejectItem.Enabled = descriptors.Count > 0;

        if (descriptors.Count == 0)
        {
            ResetEjectMenu(_ejectItem);
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

    private static void ResetEjectMenu(ToolStripMenuItem ejectItem)
    {
        ejectItem.DropDownItems.Clear();
        ejectItem.Tag = null;
        ejectItem.Text = "Eject APFS drives";
        ejectItem.Enabled = false;
    }

    private static string BuildEjectMenuSignature(IReadOnlyList<EjectMenuDescriptor> descriptors)
        => string.Join(
            "\u001f",
            descriptors.Select(static descriptor =>
                $"{descriptor.VolumeId ?? string.Empty}\u001e{descriptor.Text}"));

    private static string BuildNotifyIconText(StatusChangedPayload payload)
        => BuildNotifyIconTextForState(payload, SelectBalloonState(payload));

    private static string BuildNotifyIconTextForState(StatusChangedPayload payload, DriveDashboardState effectiveState)
    {
        var text = payload.State switch
        {
            RuntimeState.MountedRw => $"APFS Access: mounted read/write ({payload.MountPoints.Count})",
            RuntimeState.MountedRo => $"APFS Access: mounted read-only ({payload.MountPoints.Count})",
            RuntimeState.Error => "APFS Access: error",
            RuntimeState.Starting => "APFS Access: starting",
            RuntimeState.Stopping => "APFS Access: stopping",
            _ => "APFS Access: idle",
        };

        var nonWarningMountedState = IsNonWarningMountedState(effectiveState);
        var warningCount = nonWarningMountedState
            ? 0
            : (payload.Warnings?.Count ?? 0) + (payload.CompatibilityWarnings?.Count ?? 0);
        if (warningCount > 0 && payload.State is not RuntimeState.Error)
        {
            text = $"{text} [warn:{warningCount}]";
        }

        var primaryRecoveryReason = SelectPrimaryRecoveryReason(payload);
        if (!nonWarningMountedState &&
            (payload.RecoveryActive || payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked) &&
            payload.State is not RuntimeState.Error)
        {
            text = string.IsNullOrWhiteSpace(primaryRecoveryReason)
                ? $"{text} [recovery]"
                : $"{text} [recovery:{primaryRecoveryReason}]";
        }

        if (!nonWarningMountedState &&
            payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked &&
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
        var balloonState = SelectBalloonState(payload);
        ShowWarnings(payload, BuildStatusBalloonWarnings(payload, balloonState), balloonState);
    }

    private static IReadOnlyList<string> BuildStatusBalloonWarnings(StatusChangedPayload payload)
        => BuildStatusBalloonWarnings(payload, SelectBalloonState(payload));

    private static IReadOnlyList<string> BuildStatusBalloonWarnings(
        StatusChangedPayload payload,
        DriveDashboardState balloonState)
    {
        var warnings = (payload.Warnings ?? Array.Empty<string>())
            .Concat(payload.CompatibilityWarnings ?? Array.Empty<string>())
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Where(static x => !IsHealthyMountNotice(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static x => GetWarningPriority(x))
            .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return IsNonWarningMountedState(balloonState)
            ? Array.Empty<string>()
            : warnings;
    }

    private void ShowWarnings(
        StatusChangedPayload payload,
        IReadOnlyList<string> warnings,
        DriveDashboardState balloonState)
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
            _notifyIcon.ShowBalloonTip(
                6000,
                SelectBalloonTitle(balloonState),
                message,
                SelectBalloonIcon(balloonState));
        }
    }

    private void ShowHealthTransition(
        StatusChangedPayload payload,
        DriveDashboardState? previousState,
        DriveDashboardState currentState)
    {
        if (!ShouldShowHealthTransitionBalloon(previousState, currentState))
        {
            return;
        }

        _notifyIcon.ShowBalloonTip(
            4000,
            SelectBalloonTitle(currentState),
            BuildHealthTransitionBalloonMessage(payload),
            SelectBalloonIcon(currentState));
    }

    private static bool ShouldShowHealthTransitionBalloon(
        DriveDashboardState? previousState,
        DriveDashboardState currentState)
        => currentState == DriveDashboardState.HealthyReadWrite &&
           (previousState is DriveDashboardState.Problem or
               DriveDashboardState.ReadOnly or
               DriveDashboardState.Attention);

    private static string BuildHealthTransitionBalloonMessage(StatusChangedPayload payload)
    {
        if (payload.MountedVolumes is { Count: 1 })
        {
            var volume = payload.MountedVolumes[0];
            var drive = NormalizeDriveLabel(volume.MountPoint);
            var volumeName = string.IsNullOrWhiteSpace(volume.VolumeName)
                ? "APFS"
                : volume.VolumeName.Trim();
            return $"{drive} ({volumeName}) is mounted with full read/write access.";
        }

        if (payload.MountPoints.Count == 1)
        {
            return $"{NormalizeDriveLabel(payload.MountPoints[0])} is mounted with full read/write access.";
        }

        var count = payload.MountedVolumes?.Count > 0
            ? payload.MountedVolumes.Count
            : payload.MountPoints.Count;
        return count == 1
            ? "APFS drive is mounted with full read/write access."
            : $"{count} APFS drives are mounted with full read/write access.";
    }

    private static ToolTipIcon SelectBalloonIcon(StatusChangedPayload payload)
        => SelectBalloonIcon(SelectBalloonState(payload));

    private static RuntimeState SelectNotifyIconState(StatusChangedPayload payload)
        => SelectNotifyIconStateForState(SelectBalloonState(payload), payload.State);

    private static RuntimeState SelectNotifyIconStateForState(DriveDashboardState state, RuntimeState fallbackState)
        => state switch
        {
            DriveDashboardState.Problem => RuntimeState.Error,
            DriveDashboardState.ReadOnly or DriveDashboardState.Attention => RuntimeState.MountedRo,
            DriveDashboardState.HealthyReadWrite or DriveDashboardState.FinishingWrites => RuntimeState.MountedRw,
            _ => fallbackState,
        };

    private string SelectActionBalloonTitle(bool success)
    {
        if (!success && _latestStatus is { } latestStatus)
        {
            return SelectBalloonTitle(SelectBalloonState(latestStatus));
        }

        if (_latestStatus is { } currentStatus)
        {
            return SelectBalloonTitle(SelectBalloonState(currentStatus));
        }

        return success ? "APFS Access" : "APFS Access Problem";
    }

    private ToolTipIcon SelectActionBalloonIcon(bool success)
    {
        if (!success && _latestStatus is { } latestStatus)
        {
            return SelectBalloonIcon(SelectBalloonState(latestStatus));
        }

        if (_latestStatus is { } currentStatus)
        {
            return SelectBalloonIcon(SelectBalloonState(currentStatus));
        }

        return success ? ToolTipIcon.Info : ToolTipIcon.Error;
    }

    private string SelectActionFeedbackTitle(bool success, string? volumeId)
    {
        var state = SelectActionFeedbackState(volumeId);
        if (state.HasValue)
        {
            return SelectBalloonTitle(state.Value);
        }

        return success ? "APFS Access" : "APFS Access Problem";
    }

    private ToolTipIcon SelectActionFeedbackIcon(bool success, string? volumeId)
    {
        var state = SelectActionFeedbackState(volumeId);
        if (state.HasValue)
        {
            return SelectBalloonIcon(state.Value);
        }

        return success ? ToolTipIcon.Info : ToolTipIcon.Error;
    }

    private DriveDashboardState? SelectActionFeedbackState(string? volumeId)
    {
        if (_latestStatus is not { } latestStatus)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return SelectBalloonState(latestStatus);
        }

        var rows = DriveDashboardPresenter.BuildRows(latestStatus);
        var matchingRow = rows.FirstOrDefault(candidate =>
            string.Equals(candidate.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase));
        if (matchingRow is not null)
        {
            return matchingRow.State;
        }

        return SelectBalloonState(latestStatus);
    }

    private static DriveDashboardState SelectBalloonState(StatusChangedPayload payload)
    {
        var rows = DriveDashboardPresenter.BuildRows(payload);
        return SelectBalloonStateFromRows(payload, rows);
    }

    private static DriveDashboardState SelectBalloonStateFromRows(
        StatusChangedPayload payload,
        IReadOnlyList<DriveDashboardRow> rows)
    {
        if (payload.MountedVolumes is { Count: > 0 })
        {
            var mountedStates = rows
                .Where(static row => row.State != DriveDashboardState.Idle)
                .Select(static row => row.State)
                .ToArray();
            if (mountedStates.Length > 0)
            {
                return mountedStates.Max();
            }
        }

        if (payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked ||
            payload.RecoveryActive)
        {
            return DriveDashboardState.Problem;
        }

        if (payload.DirtyTransactionCount > 0 ||
            payload.ShutdownDrainActive)
        {
            return DriveDashboardState.FinishingWrites;
        }

        if (payload.State == RuntimeState.MountedRw)
        {
            return DriveDashboardState.HealthyReadWrite;
        }

        if (payload.State == RuntimeState.MountedRo ||
            payload.NativeWriteSafetyState == NativeWriteSafetyState.ReadOnlyFallback ||
            ((payload.MountPoints?.Count ?? 0) > 0 && !payload.WriteEnabled))
        {
            return DriveDashboardState.ReadOnly;
        }

        if (HasWarningSignals(payload) ||
            payload.State is RuntimeState.Starting or RuntimeState.Stopping)
        {
            return DriveDashboardState.Attention;
        }

        return DriveDashboardState.Idle;
    }

    private static bool HasWarningSignals(StatusChangedPayload payload)
        => (payload.Warnings ?? Array.Empty<string>()).Any(static warning => !string.IsNullOrWhiteSpace(warning)) ||
           (payload.CompatibilityWarnings ?? Array.Empty<string>()).Any(static warning => !string.IsNullOrWhiteSpace(warning)) ||
           payload.NativeWriteDiagnostics is { Count: > 0 };

    private static bool IsHealthyMountNotice(string warning)
        => warning.Contains("mounted", StringComparison.OrdinalIgnoreCase) &&
           warning.Contains("native write enabled", StringComparison.OrdinalIgnoreCase);

    private static ToolTipIcon SelectBalloonIcon(DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.Problem => ToolTipIcon.Error,
            DriveDashboardState.ReadOnly or DriveDashboardState.Attention => ToolTipIcon.Warning,
            DriveDashboardState.FinishingWrites => ToolTipIcon.Info,
            DriveDashboardState.HealthyReadWrite => ToolTipIcon.Info,
            _ => ToolTipIcon.Info,
        };

    private static bool IsNonWarningMountedState(DriveDashboardState state)
        => state is DriveDashboardState.HealthyReadWrite or DriveDashboardState.FinishingWrites;

    private static string SelectBalloonTitle(DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.Problem => "APFS Access Problem",
            DriveDashboardState.ReadOnly => "APFS Access Read-only",
            DriveDashboardState.Attention => "APFS Access Notice",
            DriveDashboardState.FinishingWrites => "APFS Access Finishing Writes",
            DriveDashboardState.HealthyReadWrite => "APFS Access Healthy",
            _ => "APFS Access",
        };

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
            var parsed = NativeWriteRecoveryReasons.TryExtractReasonToken(warning);
            if (!string.IsNullOrWhiteSpace(parsed))
            {
                candidates.Add(parsed);
            }
        }

        return candidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static x => NativeWriteRecoveryReasons.GetPriority(x))
            .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    private static int GetWarningPriority(string warning)
    {
        var reason = NativeWriteRecoveryReasons.TryExtractReasonToken(warning);
        if (!string.IsNullOrWhiteSpace(reason))
        {
            return NativeWriteRecoveryReasons.GetPriority(reason);
        }

        return int.MaxValue;
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
        _dashboard.AllowCloseForApplicationExit();
        _dashboard.Close();
        _dashboard.Dispose();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _updateClient.Dispose();

        foreach (var icon in _ownedIcons)
        {
            icon.Dispose();
        }

        _shutdownCts.Dispose();
        _uiInvoker.Dispose();
        base.ExitThreadCore();
    }
}
