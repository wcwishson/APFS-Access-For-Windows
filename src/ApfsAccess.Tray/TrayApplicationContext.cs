using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed record EjectMenuDescriptor(string Text, string? VolumeId, DriveDashboardRow? Row = null);

public sealed partial class TrayApplicationContext : ApplicationContext
{
    public static readonly TimeSpan WeeklyUpdateCheckInterval = TimeSpan.FromDays(7);
    private static readonly TimeSpan AutoUpdateStartupDelay = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan AutoUpdatePollInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan ServiceStartThrottle = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan EjectRequestTimeout = TimeSpan.FromSeconds(130);
    private static readonly TimeSpan FixRequestTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan UpdateShutdownTimeout = TimeSpan.FromSeconds(150);
    private static readonly Uri LatestReleasePage = new("https://github.com/wcwishson/APFS-Access-For-Windows/releases/latest");
    private static readonly object DiagnosticLogSync = new();

    private sealed record QueuedDriveLetterRemount(
        string DeviceId,
        string VolumeId,
        string? ContainerUuid,
        string VolumeName,
        string TargetLetter);

    private readonly SynchronizationContext _uiContext;
    private readonly Control _uiInvoker = new();
    private readonly NotifyIcon _notifyIcon;
    private readonly DashboardForm _dashboard;
    private readonly StartupSettingsManager _startupSettingsManager;
    private readonly GitHubReleaseUpdateClient _updateClient = new();
    private readonly ToolStripMenuItem _ejectItem;
    private readonly ToolStripMenuItem? _fixItem;
    private readonly ToolStripMenuItem? _mountItem;
    private readonly ToolStripMenuItem _verifyItem;
    private readonly ToolStripMenuItem _manageItem;
    private readonly ToolStripMenuItem _snapshotsItem;
    private readonly ToolStripMenuItem _createVolumeItem;
    private readonly ToolStripMenuItem _deleteVolumeItem;
    private readonly ToolStripMenuItem _registerImageItem;
    private bool _serviceConnected;
    private readonly ToolStripMenuItem _themeFollowWindowsItem;
    private readonly ToolStripMenuItem _themeLightItem;
    private readonly ToolStripMenuItem _themeDarkItem;
    private readonly List<Icon> _ownedIcons = [];
    private readonly Dictionary<RuntimeState, Icon> _iconByState;
    private readonly HashSet<string> _shownWarnings = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<AckPayload>> _pendingAcks = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, QueuedDriveLetterRemount> _queuedDriveLetterRemounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _statusPeerSync = new();
    private string? _ejectMenuSignature;
    private AppUpdateDownload? _readyUpdate;
    private int _updateCheckInFlight;
    private int _queuedRemountInFlight;

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

        _startupSettingsManager = StartupSettingsManager.CreateDefault();
        var startupPreferences = _startupSettingsManager.Load();
        var initialTheme = DashboardTheme.Resolve(startupPreferences.ThemeMode);

        var menu = new ContextMenuStrip();
        menu.Renderer = initialTheme.IsDark ? new DarkToolStripRenderer() : new ToolStripProfessionalRenderer();
        var showItem = new ToolStripMenuItem("Show APFS Access");
        showItem.Click += (_, _) => ShowDashboard();
        menu.Items.Add(showItem);
        menu.Items.Add(new ToolStripSeparator());

        _ejectItem = new ToolStripMenuItem("Eject APFS drives");
        _ejectItem.Click += OnEjectClicked;
        _ejectItem.Enabled = false;
        menu.Items.Add(_ejectItem);
        _fixItem = new ToolStripMenuItem("Fix APFS volume") { Enabled = false };
        _mountItem = new ToolStripMenuItem("Mount APFS volume") { Enabled = false };
        menu.Items.Add(_fixItem); menu.Items.Add(_mountItem);
        _verifyItem = new ToolStripMenuItem("Verify image volume") { Enabled = false };
        _manageItem = new ToolStripMenuItem("Manage image volume") { Enabled = false };
        menu.Items.Add(_verifyItem); menu.Items.Add(_manageItem);
        _snapshotsItem = new ToolStripMenuItem("Volume snapshots") { Enabled = false };
        menu.Items.Add(_snapshotsItem);
        _createVolumeItem = new ToolStripMenuItem("Create image volume") { Enabled = false };
        _deleteVolumeItem = new ToolStripMenuItem("Delete image volume") { Enabled = false };
        menu.Items.Add(_createVolumeItem); menu.Items.Add(_deleteVolumeItem);
        _registerImageItem = new ToolStripMenuItem("Register encrypted image...", null, async (_, _) =>
        {
            try { await RegisterEncryptedImageAsync().ConfigureAwait(true); }
            catch (Exception ex) { _dashboard?.SetFooter(ex.Message); }
        }) { Enabled = false };
        menu.Items.Add(_registerImageItem);
        AddFusionRegistrationMenu(menu);
        AddProfileVerificationMenu(menu);
        AddImageKeyManagementMenu(menu);
        AddSystemDataBrowseMenu(menu);
        menu.Items.Add(new ToolStripSeparator());

        var themeMenu = new ToolStripMenuItem("Theme");
        _themeFollowWindowsItem = new ToolStripMenuItem("Follow Windows", null, async (_, _) => await SetThemeModeAsync(AppThemeMode.System).ConfigureAwait(false));
        _themeLightItem = new ToolStripMenuItem("Light", null, async (_, _) => await SetThemeModeAsync(AppThemeMode.Light).ConfigureAwait(false));
        _themeDarkItem = new ToolStripMenuItem("Dark", null, async (_, _) => await SetThemeModeAsync(AppThemeMode.Dark).ConfigureAwait(false));
        themeMenu.DropDownItems.Add(_themeFollowWindowsItem);
        themeMenu.DropDownItems.Add(_themeLightItem);
        themeMenu.DropDownItems.Add(_themeDarkItem);
        UpdateThemeMenuChecks(startupPreferences.ThemeMode);
        menu.Items.Add(themeMenu);
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

        _dashboard = new DashboardForm(
            OpenMountPointAsync,
            RequestEjectAsync,
            RequestFixAsync,
            startupPreferences,
            SetStartWithWindowsAsync,
            SetStartMinimizedAsync,
            HandleUpdateButtonAsync,
            SetDriveLetterPreferenceAsync,
            MountConnectedVolumeAsync,
            async () => {
                var result = await TrySendRefreshAsync(false).ConfigureAwait(true);
                if (!result.Success) throw new InvalidOperationException(result.Message ?? "Inventory refresh failed.");
                _dashboard?.SetFooter(result.Message ?? "Inventory refreshed.");
            },             row => SendSelectedVolumeAsync(row, ApfsControlCommands.Eject),
            row => SendSelectedVolumeAsync(row, ApfsControlCommands.Fix),
            row => SendSelectedVolumeAsync(row, row.IsMounted ? ApfsControlCommands.Lock : ApfsControlCommands.Unlock),
            (deviceId, containerUuid) => SendContainerAsync(
                ResolveContainerRows(deviceId, containerUuid), ApfsControlCommands.ContainerMount),
            (deviceId, containerUuid) => SendContainerAsync(
                ResolveContainerRows(deviceId, containerUuid), ApfsControlCommands.ContainerUnmount),
            EjectDeviceAsync,
            rows => FixContainerAsync(rows),
            SetThemeModeAsync,
            VerifySelectedVolumeAsync,
            ManageSelectedVolumeAsync,
            ShowSelectedSnapshotsAsync, CreateImageVolumeAsync, DeleteImageVolumeAsync, ResizeImageAsync, FormatImageAsync,
            VerifyContainerVolumesAsync, RegisterEncryptedImageAsync, VerifySelectedProfileAsync);
        if (!startupPreferences.StartMinimized)
        {
            _dashboard.Show();
        }

        HandleIntentionalQuitMarker();
        TryStartServiceProcessIfMissing();
        _ = Task.Run(() => RunStatusListenerAsync(_shutdownCts.Token));
        _ = Task.Run(() => RunWeeklyUpdateCheckLoopAsync(_shutdownCts.Token));
        _ = Task.Run(() => RunQueuedRemountWatchLoopAsync(_shutdownCts.Token));
        UpdateReceiptPublisher.TryWriteCurrentProcessPhase("ready");
    }

    private void OnNotifyIconMouseClick(object? sender, MouseEventArgs e)
    {
        _ = sender;
        HandleNotifyIconClick(e.Button, ShowDashboard);
    }

    internal static void HandleNotifyIconClick(MouseButtons button, Action showDashboard)
    {
        if (button == MouseButtons.Left) showDashboard();
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
        if (sender is ToolStripMenuItem { Tag: DriveDashboardRow selected })
        {
            try { await SendSelectedVolumeAsync(selected, ApfsControlCommands.Eject).ConfigureAwait(false); }
            catch (Exception ex) { PostToUi(() => _dashboard.SetFooter(ex.Message)); }
            return;
        }
        // A parent menu without a selected row is not a volume action.
        if (sender is ToolStripMenuItem { HasDropDownItems: true }) return;
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

    private void UpdateThemeMenuChecks(AppThemeMode mode)
    {
        if (_themeFollowWindowsItem is not null) _themeFollowWindowsItem.Checked = mode == AppThemeMode.System;
        if (_themeLightItem is not null) _themeLightItem.Checked = mode == AppThemeMode.Light;
        if (_themeDarkItem is not null) _themeDarkItem.Checked = mode == AppThemeMode.Dark;
    }

    private Task SetThemeModeAsync(AppThemeMode mode)
    {
        _startupSettingsManager.SetThemeMode(mode);
        PostToUi(() =>
        {
            UpdateThemeMenuChecks(mode);
            var resolved = DashboardTheme.Resolve(mode);
            if (_notifyIcon.ContextMenuStrip is not null)
            {
                _notifyIcon.ContextMenuStrip.Renderer = resolved.IsDark ? new DarkToolStripRenderer() : new ToolStripProfessionalRenderer();
            }
            _dashboard.SetThemeMode(mode);
        });
        return Task.CompletedTask;
    }

    public static bool IsWeeklyUpdateCheckDue(DateTimeOffset? lastCheckUtc, DateTimeOffset nowUtc)
        => lastCheckUtc is null || (nowUtc - lastCheckUtc.Value) >= WeeklyUpdateCheckInterval;

    private async Task RunWeeklyUpdateCheckLoopAsync(CancellationToken cancellationToken)
    {
        if (string.Equals(
                Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_AUTO_UPDATE_CHECK"),
                "1",
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            await Task.Delay(AutoUpdateStartupDelay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        while (!cancellationToken.IsCancellationRequested && Volatile.Read(ref _exitRequested) == 0)
        {
            try
            {
                if (_readyUpdate is null &&
                    IsWeeklyUpdateCheckDue(_startupSettingsManager.GetLastAutoUpdateCheckUtc(), DateTimeOffset.UtcNow))
                {
                    await TryRunAutomaticUpdateCheckAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                LogDiagnostic($"Weekly automatic update check failed: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                await Task.Delay(AutoUpdatePollInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task TryRunAutomaticUpdateCheckAsync(CancellationToken cancellationToken)
    {
        if (!TryResolveInstalledLauncherPath(out var launcherPath))
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _updateCheckInFlight, 1, 0) != 0)
        {
            return;
        }

        try
        {
            var currentVersion = typeof(TrayApplicationContext).Assembly.GetName().Version ?? new Version(1, 0, 6);
            var result = await _updateClient.CheckAndDownloadAsync(
                launcherPath,
                currentVersion,
                progress: null,
                cancellationToken).ConfigureAwait(false);

            switch (result.Decision)
            {
                case AppUpdateDecision.UpToDate:
                    _startupSettingsManager.SetLastAutoUpdateCheckUtc(DateTimeOffset.UtcNow);
                    break;
                case AppUpdateDecision.Ready when result.Download is not null:
                    _startupSettingsManager.SetLastAutoUpdateCheckUtc(DateTimeOffset.UtcNow);
                    var download = result.Download;
                    PostToUi(() =>
                    {
                        _readyUpdate = download;
                        _dashboard.SetUpdateStatus(
                            $"Version {download.Release.Version.ToString(3)} is downloaded and verified.",
                            "Install update",
                            enabled: true);
                        _notifyIcon.ShowBalloonTip(
                            5000,
                            "APFS Access Update Ready",
                            $"Version {download.Release.Version.ToString(3)} is downloaded and ready to install.",
                            ToolTipIcon.Info);
                    });
                    break;
            }
        }
        finally
        {
            Interlocked.Exchange(ref _updateCheckInFlight, 0);
        }
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

        if (Interlocked.CompareExchange(ref _updateCheckInFlight, 1, 0) != 0)
        {
            return;
        }

        try
        {
            _dashboard.SetUpdateStatus("Checking GitHub and downloading any available update...", "Checking...", enabled: false);
            var progress = new Progress<AppUpdateProgress>(value =>
                _dashboard.SetUpdateStatus($"Downloading update: {value.Percentage}%", "Checking...", enabled: false));

            var currentVersion = typeof(TrayApplicationContext).Assembly.GetName().Version ?? new Version(1, 0, 6);
            var result = await _updateClient.CheckAndDownloadAsync(
                launcherPath,
                currentVersion,
                progress,
                _shutdownCts.Token).ConfigureAwait(true);

            switch (result.Decision)
            {
                case AppUpdateDecision.UpToDate:
                    _startupSettingsManager.SetLastAutoUpdateCheckUtc(DateTimeOffset.UtcNow);
                    _dashboard.SetUpdateStatus("APFS Access is up to date.", "Check for updates", enabled: true);
                    break;
                case AppUpdateDecision.Ready when result.Download is not null:
                    _startupSettingsManager.SetLastAutoUpdateCheckUtc(DateTimeOffset.UtcNow);
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
        finally
        {
            Interlocked.Exchange(ref _updateCheckInFlight, 0);
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
                if (!TrySendQuitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult())
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

    private async Task<bool> TrySendQuitAsync(TimeSpan? timeout = null)
    {
        var (success, message) = await TrySendRequestAsync(
            ApfsMessageTypes.QuitRequested,
            new QuitRequestedPayload(Environment.UserName, DateTime.UtcNow),
            timeout ?? UpdateShutdownTimeout,
            "application shutdown",
            "Timed out waiting for APFS Access to quit.")
            .ConfigureAwait(false);
        LogDiagnostic($"Quit request completed. success={success}; message='{message ?? string.Empty}'");
        return success;
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

        Interlocked.Exchange(ref _exitRequested, 1);

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

    internal Func<DriveDashboardRow, string, string, Task<bool>>? PromptDriveLetterInUseOverride { get; set; }

    private async Task SetDriveLetterPreferenceAsync(DriveDashboardRow row, string letter)
    {
        if (row.DeviceId is null || row.DriveLetterPreference is not { CanEdit: true, VolumeUuid: not null } preference)
            throw new InvalidOperationException("Volume identity is unavailable. Refresh and try again.");
        if (string.IsNullOrWhiteSpace(letter))
            throw new InvalidOperationException("Choose a valid drive letter A-Z.");

        var normalizedLetter = char.ToUpperInvariant(letter.Trim()[0]).ToString();
        var currentStatus = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var queueKey = GetDriveLetterQueueKey(row.DeviceId, row.VolumeId);

        if (row.IsMounted && string.Equals(preference.ActualLetter, normalizedLetter, StringComparison.OrdinalIgnoreCase))
        {
            await SaveDriveLetterPreferenceToServiceAsync(row, normalizedLetter).ConfigureAwait(false);
            _queuedDriveLetterRemounts.TryRemove(queueKey, out _);
            PostToUi(() => _dashboard?.SetFooter($"Preferred drive letter {normalizedLetter}: saved for {row.VolumeName}."));
            return;
        }

        if (TryDetectVolumeOrContainerInUse(currentStatus, row, out var inUseReason))
        {
            var queueRemount = await ConfirmQueueRemountWhenInUseAsync(
                row,
                normalizedLetter,
                inUseReason ?? $"'{row.VolumeName}' is currently in use.").ConfigureAwait(false);
            if (!queueRemount)
            {
                PostToUi(() => _dashboard?.SetFooter("Drive letter change cancelled."));
                return;
            }

            await SaveDriveLetterPreferenceToServiceAsync(row, normalizedLetter).ConfigureAwait(false);
            _queuedDriveLetterRemounts[queueKey] = new QueuedDriveLetterRemount(
                row.DeviceId,
                row.VolumeId,
                row.CatalogContainerUuid,
                row.VolumeName,
                normalizedLetter);
            PostToUi(() => _dashboard?.SetFooter(
                $"Preferred drive letter {normalizedLetter}: saved for {row.VolumeName}. Remount queued until the volume is no longer in use."));
            return;
        }

        var previousLetter = preference.PreferredLetter ?? preference.ActualLetter;
        await SaveDriveLetterPreferenceToServiceAsync(row, normalizedLetter).ConfigureAwait(false);
        _queuedDriveLetterRemounts.TryRemove(queueKey, out _);

        PostToUi(() => _dashboard?.SetFooter($"Remounting {row.VolumeName} as {normalizedLetter}:…"));
        await ExecuteDriveLetterRemountAsync(
            row,
            normalizedLetter,
            previousLetter,
            allowInUsePrompt: true).ConfigureAwait(false);
    }

    private async Task<bool> SaveDriveLetterPreferenceToServiceAsync(
        DriveDashboardRow row,
        string letter,
        bool throwOnFailure = true)
    {
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var freshRow = FindMatchingRow(current, row) ?? row;
        var result = await TrySendRequestAsync(
            ApfsMessageTypes.DriveLetterPreferenceRequested,
            DriveDashboardPresenter.CreatePreferenceRequest(current, freshRow, letter),
            TimeSpan.FromSeconds(15),
            "Save preferred drive letter",
            "Preference request timed out; refresh before retrying.").ConfigureAwait(false);
        if (!result.Success && throwOnFailure)
            throw new InvalidOperationException(result.Message ?? "Could not save the preferred letter.");
        return result.Success;
    }

    private async Task<bool> ExecuteDriveLetterRemountAsync(
        DriveDashboardRow row,
        string targetLetter,
        string? previousLetter,
        bool allowInUsePrompt)
    {
        var queueKey = GetDriveLetterQueueKey(row.DeviceId!, row.VolumeId);
        var current = _latestStatus;
        var freshRow = current is null ? row : (FindMatchingRow(current, row) ?? row);

        if (freshRow.IsMounted)
        {
            var ejectResult = await TrySendEjectAsync(freshRow.VolumeId).ConfigureAwait(false);
            if (!ejectResult.Success)
            {
                if (!allowInUsePrompt)
                {
                    return false;
                }

                var queueRemount = await ConfirmQueueRemountWhenInUseAsync(
                    freshRow,
                    targetLetter,
                    ejectResult.Message ?? $"'{freshRow.VolumeName}' is currently in use and could not be unmounted immediately.").ConfigureAwait(false);
                if (queueRemount)
                {
                    _queuedDriveLetterRemounts[queueKey] = new QueuedDriveLetterRemount(
                        freshRow.DeviceId!,
                        freshRow.VolumeId,
                        freshRow.CatalogContainerUuid,
                        freshRow.VolumeName,
                        targetLetter);
                    PostToUi(() => _dashboard?.SetFooter(
                        $"Preferred drive letter {targetLetter}: saved for {freshRow.VolumeName}. Remount queued until the volume is no longer in use."));
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(previousLetter) &&
                    !string.Equals(previousLetter, targetLetter, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        await SaveDriveLetterPreferenceToServiceAsync(freshRow, previousLetter, throwOnFailure: false).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        LogDiagnostic($"Best-effort rollback of preferred drive letter failed: {ex.Message}");
                    }
                }

                PostToUi(() => _dashboard?.SetFooter("Drive letter change cancelled."));
                return false;
            }
        }

        var mountResult = await TrySendRefreshAsync(clearUserEjectedVolumes: true, volumeId: freshRow.VolumeId).ConfigureAwait(false);
        if (!mountResult.Success && current is not null)
        {
            var mountedSiblings = GetMountedContainerRows(_latestStatus ?? current, freshRow)
                .Where(r => !string.Equals(r.VolumeId, freshRow.VolumeId, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (mountedSiblings.Length > 0)
            {
                var allSiblingsUnmounted = true;
                foreach (var sibling in mountedSiblings)
                {
                    var siblingEject = await TrySendEjectAsync(sibling.VolumeId).ConfigureAwait(false);
                    if (!siblingEject.Success)
                    {
                        allSiblingsUnmounted = false;
                        break;
                    }
                }

                if (allSiblingsUnmounted)
                {
                    mountResult = await TrySendRefreshAsync(clearUserEjectedVolumes: true, volumeId: freshRow.VolumeId).ConfigureAwait(false);
                }
            }
        }

        if (!mountResult.Success)
        {
            if (allowInUsePrompt)
            {
                throw new InvalidOperationException(
                    mountResult.Message ?? $"Preferred drive letter {targetLetter}: was saved, but automatic remount failed.");
            }

            return false;
        }

        _queuedDriveLetterRemounts.TryRemove(queueKey, out _);
        PostToUi(() => _dashboard?.SetFooter($"Remounted {freshRow.VolumeName} on {targetLetter}:."));
        return true;
    }

    internal static bool TryDetectVolumeOrContainerInUse(
        StatusChangedPayload status,
        DriveDashboardRow targetRow,
        out string? reason,
        Func<IReadOnlyList<string>, string?>? hostMountPointInUseDetector = null)
    {
        reason = null;
        var mountedRows = GetMountedContainerRows(status, targetRow);
        if (mountedRows.Count == 0 && !targetRow.IsMounted)
        {
            return false;
        }

        if (targetRow.State == DriveDashboardState.FinishingWrites ||
            mountedRows.Any(r => r.State == DriveDashboardState.FinishingWrites))
        {
            reason = $"'{targetRow.VolumeName}' is currently finishing pending writes.";
            return true;
        }

        var mountedDisplays = (status.MountedVolumes ?? [])
            .Where(m => string.Equals(m.DeviceId, targetRow.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(m.VolumeId, targetRow.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                 (!string.IsNullOrWhiteSpace(targetRow.CatalogContainerUuid) &&
                  string.Equals(m.CatalogContainerUuid, targetRow.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase))))
            .ToArray();

        if (mountedDisplays.Any(m => m.InFlightMutationCallbacks > 0) ||
            (mountedDisplays.Length == 0 && status.InFlightMutationCallbacks > 0))
        {
            reason = $"'{targetRow.VolumeName}' has active file operations in progress.";
            return true;
        }

        if (mountedDisplays.Any(m => m.DirtyTransactionCount > 0) ||
            (mountedDisplays.Length == 0 && status.DirtyTransactionCount > 0))
        {
            reason = $"'{targetRow.VolumeName}' has uncommitted filesystem changes being flushed.";
            return true;
        }

        if (mountedDisplays.Any(m => m.ShutdownDrainActive || m.RecoveryActive) ||
            (mountedDisplays.Length == 0 && (status.ShutdownDrainActive || status.RecoveryActive)))
        {
            reason = $"'{targetRow.VolumeName}' is currently draining or recovering.";
            return true;
        }

        var mountPoints = mountedRows
            .Select(static r => r.MountPoint)
            .Append(targetRow.MountPoint)
            .Where(static mp => !string.IsNullOrWhiteSpace(mp))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (mountPoints.Length > 0)
        {
            var detector = hostMountPointInUseDetector ?? DetectHostMountPointsInUse;
            var hostReason = detector(mountPoints);
            if (!string.IsNullOrWhiteSpace(hostReason))
            {
                reason = hostReason;
                return true;
            }
        }

        return false;
    }

    private static string? DetectHostMountPointsInUse(IReadOnlyList<string> mountPoints)
    {
        var roots = mountPoints
            .Select(NormalizeDriveRoot)
            .Where(static r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (roots.Length == 0)
        {
            return null;
        }

        try
        {
            var shellType = Type.GetTypeFromProgID("Shell.Application");
            if (shellType is not null)
            {
                dynamic? shell = Activator.CreateInstance(shellType);
                if (shell is not null)
                {
                    dynamic windows = shell.Windows();
                    int count = (int)windows.Count;
                    for (var i = 0; i < count; i++)
                    {
                        try
                        {
                            dynamic? win = windows.Item(i);
                            if (win is null) continue;
                            string? locationUrl = win.LocationURL as string;
                            if (!string.IsNullOrWhiteSpace(locationUrl))
                            {
                                foreach (var root in roots)
                                {
                                    var fileUriPrefix = $"file:///{root[0]}:/";
                                    if (locationUrl.StartsWith(fileUriPrefix, StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(locationUrl, $"file:///{root[0]}:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        return $"File Explorer is currently open on {root}.";
                                    }
                                }
                            }
                        }
                        catch
                        {
                            // Ignore individual COM window inspection errors.
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore Shell.Application COM errors.
        }

        var currentPid = Environment.ProcessId;
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == currentPid) continue;
                var fileName = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(fileName)) continue;
                foreach (var root in roots)
                {
                    if (fileName.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        return $"Process '{process.ProcessName}' is currently running from {root}.";
                    }
                }
            }
            catch
            {
                // Access denied on system/elevated processes is expected.
            }
            finally
            {
                process.Dispose();
            }
        }

        return null;
    }

    private static string NormalizeDriveRoot(string? mountPoint)
    {
        if (string.IsNullOrWhiteSpace(mountPoint)) return string.Empty;
        var trimmed = mountPoint.Trim();
        if (trimmed.Length >= 2 && trimmed[1] == ':' && char.IsAsciiLetter(trimmed[0]))
        {
            return $"{char.ToUpperInvariant(trimmed[0])}:\\";
        }

        return string.Empty;
    }

    private static IReadOnlyList<DriveDashboardRow> GetMountedContainerRows(StatusChangedPayload status, DriveDashboardRow targetRow)
    {
        var rows = DriveDashboardPresenter.BuildRows(status);
        return rows
            .Where(r => r.IsMounted &&
                !string.IsNullOrWhiteSpace(r.VolumeId) &&
                string.Equals(r.DeviceId, targetRow.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(r.VolumeId, targetRow.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                 (!string.IsNullOrWhiteSpace(targetRow.CatalogContainerUuid) &&
                  string.Equals(r.CatalogContainerUuid, targetRow.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase))))
            .ToArray();
    }

    private static DriveDashboardRow? FindMatchingRow(StatusChangedPayload status, DriveDashboardRow targetRow)
        => TopologyDashboard.Project(status)
            .Select(static n => n.Row)
            .Where(static r => r is not null)
            .Select(static r => r!)
            .FirstOrDefault(r =>
                string.Equals(r.DeviceId, targetRow.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(r.VolumeId, targetRow.VolumeId, StringComparison.OrdinalIgnoreCase));

    private static string GetDriveLetterQueueKey(string deviceId, string volumeId)
        => $"{deviceId.Trim()}|{volumeId.Trim()}";

    private Task<bool> ConfirmQueueRemountWhenInUseAsync(DriveDashboardRow row, string targetLetter, string inUseReason)
    {
        if (PromptDriveLetterInUseOverride is { } overridePrompt)
        {
            return overridePrompt(row, targetLetter, inUseReason);
        }

        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _uiContext.Post(_ =>
        {
            try
            {
                if (_shutdownCts.IsCancellationRequested || _dashboard.IsDisposed)
                {
                    completion.TrySetResult(false);
                    return;
                }

                completion.TrySetResult(ShowDriveLetterInUseDialog(row, targetLetter, inUseReason));
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
            }
        }, null);
        return completion.Task;
    }

    private bool ShowDriveLetterInUseDialog(DriveDashboardRow row, string targetLetter, string inUseReason)
    {
        var theme = _dashboard.CurrentTheme;
        using var dialog = new Form
        {
            Text = "Volume Currently in Use",
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = theme.WindowBackground,
            ForeColor = theme.TextPrimary,
            Font = _dashboard.Font,
            Padding = new Padding(16),
        };

        var panel = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = theme.WindowBackground,
            Margin = new Padding(0),
            Padding = new Padding(8),
        };

        panel.Controls.Add(new Label
        {
            Text = $"{row.VolumeName} is currently in use",
            Font = new Font(_dashboard.Font, FontStyle.Bold),
            AutoSize = true,
            ForeColor = theme.TextPrimary,
            Margin = new Padding(0, 0, 0, 8),
        });

        panel.Controls.Add(new Label
        {
            Text = $"{inUseReason}\n\nCannot remount '{row.VolumeName}' to {targetLetter}: right now.\nWould you like to queue a remount so it switches to {targetLetter}: automatically as soon as it is no longer in use, or cancel?",
            AutoSize = true,
            MaximumSize = new Size(440, 0),
            ForeColor = theme.TextSecondary,
            Margin = new Padding(0, 0, 0, 16),
        });

        var actions = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = theme.WindowBackground,
            Margin = new Padding(0),
        };

        var queueButton = new Button
        {
            Text = "Queue Remount",
            DialogResult = DialogResult.Yes,
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            BackColor = theme.ButtonBackground,
            ForeColor = theme.ButtonText,
            Padding = new Padding(14, 6, 14, 6),
            Margin = new Padding(0, 0, 10, 0),
        };
        queueButton.FlatAppearance.BorderColor = theme.ButtonBorder;

        var cancelButton = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            BackColor = theme.ButtonBackground,
            ForeColor = theme.ButtonText,
            Padding = new Padding(14, 6, 14, 6),
            Margin = new Padding(0),
        };
        cancelButton.FlatAppearance.BorderColor = theme.ButtonBorder;

        actions.Controls.Add(queueButton);
        actions.Controls.Add(cancelButton);
        panel.Controls.Add(actions);
        dialog.Controls.Add(panel);
        dialog.AcceptButton = queueButton;
        dialog.CancelButton = cancelButton;

        return dialog.ShowDialog(_dashboard) == DialogResult.Yes;
    }

    private async Task RunQueuedRemountWatchLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
                if (!_queuedDriveLetterRemounts.IsEmpty && _latestStatus is { } status)
                {
                    await TryProcessQueuedDriveLetterRemountsAsync(status).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            LogDiagnostic($"Queued remount watch loop stopped: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task TryProcessQueuedDriveLetterRemountsAsync(StatusChangedPayload status)
    {
        if (_queuedDriveLetterRemounts.IsEmpty ||
            Interlocked.CompareExchange(ref _queuedRemountInFlight, 1, 0) != 0)
        {
            return;
        }

        try
        {
            foreach (var pair in _queuedDriveLetterRemounts.ToArray())
            {
                var queued = pair.Value;
                var rows = DriveDashboardPresenter.BuildRows(status);
                var row = rows.FirstOrDefault(r =>
                    string.Equals(r.DeviceId, queued.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.VolumeId, queued.VolumeId, StringComparison.OrdinalIgnoreCase));
                if (row is null)
                {
                    _queuedDriveLetterRemounts.TryRemove(pair.Key, out _);
                    continue;
                }

                if (row.IsMounted &&
                    string.Equals(row.DriveLetterPreference?.ActualLetter, queued.TargetLetter, StringComparison.OrdinalIgnoreCase))
                {
                    _queuedDriveLetterRemounts.TryRemove(pair.Key, out _);
                    continue;
                }

                if (TryDetectVolumeOrContainerInUse(status, row, out _))
                {
                    continue;
                }

                PostToUi(() => _dashboard?.SetFooter($"Volume '{queued.VolumeName}' is no longer in use. Remounting on {queued.TargetLetter}:…"));
                await ExecuteDriveLetterRemountAsync(
                    row,
                    queued.TargetLetter,
                    previousLetter: null,
                    allowInUsePrompt: false).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            LogDiagnostic($"Queued drive letter remount attempt failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _queuedRemountInFlight, 0);
        }
    }

    private Task MountConnectedVolumeAsync(DriveDashboardRow row) => SendSelectedVolumeAsync(row, ApfsControlCommands.Mount);

    private async Task SendSelectedVolumeAsync(DriveDashboardRow row, string command)
    {
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable. Refresh first.");
        var request = DriveDashboardPresenter.CreateSelectedRequest(current, row, command);
        using var credential = command == ApfsControlCommands.Unlock ? EncryptedPasswordPrompt.Show(_dashboard!, row, _dashboard?.CurrentTheme.IsDark ?? false) : null;
        if (command == ApfsControlCommands.Unlock && credential is null) return;
        if (command == ApfsControlCommands.Fix)
        {
            var result = await ImageRepairFixFlow.ExecuteAsync(request,
                value => SendControlRequestAsync(value, null, allowImageRepairOffer: true), ConfirmImageRepairAsync).ConfigureAwait(false);
            PostToUi(() => _dashboard?.SetFooter(result is null ? "Repair confirmation declined. No repair was approved." :
                result.Diagnostic ?? "Fix completed."));
            return;
        }
        await SendControlRequestAsync(request, credential).ConfigureAwait(false);
    }

    private Task<bool> ConfirmImageRepairAsync(ImageRepairOffer offer)
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _uiContext.Post(_ =>
        {
            try
            {
                if (_shutdownCts.IsCancellationRequested || _dashboard.IsDisposed) { completion.TrySetResult(false); return; }
                var answer = MessageBox.Show(_dashboard, ImageRepairFixFlow.ConfirmationText(offer), "Review APFS image repair",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                completion.TrySetResult(answer == DialogResult.Yes);
            }
            catch (Exception ex) { completion.TrySetException(ex); }
        }, null);
        return completion.Task;
    }

    private Task SendContainerAsync(IReadOnlyList<DriveDashboardRow> rows, string command)
    {
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable. Refresh first.");
        var request = DriveDashboardPresenter.CreateContainerRequest(current, rows, command);
        return SendControlRequestAsync(request, null);
    }

    public Task MountContainerAsync(string deviceId, string containerUuid)
        => SendContainerAsync(ResolveContainerRows(deviceId, containerUuid), ApfsControlCommands.ContainerMount);

    public Task UnmountContainerAsync(string deviceId, string containerUuid)
        => SendContainerAsync(ResolveContainerRows(deviceId, containerUuid), ApfsControlCommands.ContainerUnmount);

    public Task EjectDeviceAsync(string deviceId)
    {
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable. Refresh first.");
        var rows = DriveDashboardPresenter.BuildRows(current)
            .Where(r => string.Equals(r.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(r.VolumeId))
            .ToArray();
        var request = DriveDashboardPresenter.CreateDeviceRequest(current, rows);
        return SendControlRequestAsync(request, null);
    }

    public async Task FixContainerAsync(IReadOnlyList<DriveDashboardRow> rows)
    {
        var flow = ContainerFixFlow.Capture(_latestStatus ?? throw new InvalidOperationException("Service status is unavailable."), rows);
        var report = await flow.RunAsync(() => _latestStatus ?? throw new InvalidOperationException("Service status is unavailable."),
            request => SendControlRequestAsync(request, null, allowImageRepairOffer: true), ConfirmImageRepairAsync, _shutdownCts.Token).ConfigureAwait(true);
        _dashboard.SetFooter(report.Summary);
    }

    private IReadOnlyList<DriveDashboardRow> ResolveContainerRows(string deviceId, string containerUuid)
    {
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable. Refresh first.");
        var rows = DriveDashboardPresenter.BuildRows(current)
            .Where(r => string.Equals(r.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                ApfsTopology.MatchesContainerUuid(containerUuid, r.CatalogContainerUuid))
            .ToArray();
        if (rows.Length == 0) throw new InvalidOperationException("Selected container has no volumes. Refresh before acting.");
        return rows;
    }

    private async Task<OperationResultPayload> SendControlRequestAsync(ControlOperationRequestPayload request, ApfsAccess.Cli.SupervisedCredential? credential,
        bool allowImageRepairOffer = false)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_shutdownCts.Token);
        timeout.CancelAfter(ControlRequestTimeout(request.Command));
        try
        {
            await using var peer = await AgentControlClient.ConnectAsync(
                ApfsPipeConstants.PipeName, 1000, timeout.Token).ConfigureAwait(false);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request,
                request.OperationId, PipeSchemaVersions.Schema2), timeout.Token).ConfigureAwait(false);
            if (credential is not null) await EncryptedCredentialTransport.SendAsync(request.OperationId, credential, timeout.Token).ConfigureAwait(false);
            while (true)
            {
                var response = await peer.ReadMessageAsync(timeout.Token).ConfigureAwait(false)
                    ?? throw new IOException("Service connection closed. Refresh to check the operation result.");
                if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != request.OperationId) continue;
                if (!PipeMessageCodec.Validate(response).IsValid ||
                    !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) || result is null ||
                    result.OperationId != request.OperationId || result.Command != request.Command ||
                    !string.Equals(result.Target?.DeviceId, request.Target?.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(result.Target?.VolumeId, request.Target?.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                    result.Target?.VolumeUuid != request.Target?.VolumeUuid ||
                    result.Target?.ContainerUuid != request.Target?.ContainerUuid ||
                    result.Target?.VolumeObjectId != request.Target?.VolumeObjectId ||
                    result.Target?.ObservationContract != request.Target?.ObservationContract ||
                    result.Target?.RecoveryIdentity != request.Target?.RecoveryIdentity ||
                    result.ApprovedImageRepairPlanId != request.ApprovedImageRepairPlanId ||
                    result.RequestedMode != request.RequestedMode ||
                    result.Fingerprint != ApfsOperationFingerprint.Compute(request))
                    throw new IOException("Service returned an invalid operation result. Refresh before retrying.");
                if (result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
                {
                    await Task.Delay(250, timeout.Token).ConfigureAwait(false);
                    await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery,
                        new OperationResultQueryPayload(request.OperationId), request.OperationId, PipeSchemaVersions.Schema2), timeout.Token).ConfigureAwait(false);
                    continue;
                }
                if (!result.Success && !(allowImageRepairOffer && result.ImageRepairOffer is not null))
                    throw new InvalidOperationException(result.Diagnostic ?? "Selected operation failed.");
                return result;
            }
        }
        catch (OperationCanceledException)
        {
            // Closing a pipe does not cancel an idempotent service operation.
            // Deliver explicit cancellation with its own short, bounded transport.
            using var cancelDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await using var peer = await AgentControlClient.ConnectAsync(ApfsPipeConstants.PipeName, 1000, cancelDeadline.Token).ConfigureAwait(false);
                await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.CancellationRequest,
                    new OperationCancellationRequestPayload(request.OperationId), request.OperationId, PipeSchemaVersions.Schema2), cancelDeadline.Token).ConfigureAwait(false);
                while ((await peer.ReadMessageAsync(cancelDeadline.Token).ConfigureAwait(false)) is {} response)
                    if (response.Type == ApfsMessageTypes.OperationResult && response.RequestId == request.OperationId) break;
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidOperationException) { }
            throw new InvalidOperationException("Operation cancelled or timed out. Refresh to confirm the result before retrying.");
        }
    }

    private static TimeSpan ControlRequestTimeout(string command)
        => command switch
        {
            ApfsControlCommands.DeviceEject or
            ApfsControlCommands.Eject or
            ApfsControlCommands.ContainerUnmount => EjectRequestTimeout,
            _ => FixRequestTimeout,
        };

    private async Task VerifySelectedVolumeAsync(DriveDashboardRow selected)
    {
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var result = await SendControlRequestAsync(DriveDashboardPresenter.CreateSelectedRequest(current, selected,
            ApfsControlCommands.VolumeVerify), null).ConfigureAwait(true);
        _dashboard.SetFooter(result.Diagnostic ?? "Covered metadata verified.");
    }

    private async Task VerifyContainerVolumesAsync(ContainerVolumeVerification selection)
    {
        var report = await selection.RunAsync(
            () => _latestStatus ?? throw new InvalidOperationException("Service status is unavailable. Refresh first."),
            request => SendControlRequestAsync(request, null)).ConfigureAwait(true);
        _dashboard.SetFooter(report.Summary);
        MessageBox.Show(_dashboard, report.Details, "Verify volumes", MessageBoxButtons.OK,
            report.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }

    private async Task ManageSelectedVolumeAsync(DriveDashboardRow selected)
    {
        using var dialog = new VolumeManagementDialog(selected);
        if (dialog.ShowDialog(_dashboard) != DialogResult.OK) return;
        var current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var plan = await SendControlRequestAsync(DriveDashboardPresenter.CreateManagementPlanRequest(current,
            selected, dialog.Operation), null).ConfigureAwait(true);
        if (string.IsNullOrWhiteSpace(plan.ManagementToken) || string.IsNullOrWhiteSpace(plan.ManagementPlanId) ||
            string.IsNullOrWhiteSpace(plan.ManagementObservedXid))
            throw new IOException("Service returned no complete management plan.");
        var change = dialog.Operation == ApfsManagementOperations.RenameVolume ? $"Name: {dialog.NewName}" :
            $"Quota: {dialog.QuotaBytes} bytes\r\nReserve: {dialog.ReserveBytes} bytes";
        if (MessageBox.Show(_dashboard,
            $"Image: {selected.DeviceId}\r\nContainer: {selected.CatalogContainerUuid}\r\nVolume: {selected.CatalogVolumeUuid}\r\nObject: {selected.CatalogVolumeObjectId}\r\nCheckpoint: {plan.ManagementObservedXid}\r\n{change}\r\n\r\nApply this plan?",
            "Confirm volume change", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
        current = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var result = await SendControlRequestAsync(DriveDashboardPresenter.CreateManagementApplyRequest(current,
            selected, dialog.Operation, plan.ManagementToken, dialog.NewName, dialog.QuotaBytes, dialog.ReserveBytes,
            selected.DeviceId), null).ConfigureAwait(true);
        _dashboard.SetFooter(result.Diagnostic ?? "Volume change applied.");
    }

    private async Task CreateImageVolumeAsync(string deviceId, string containerUuid)
    {
        var rows = ResolveContainerRows(deviceId, containerUuid);
        if (rows.Count == 0 || rows.Any(r => !r.CanManageTopologyImage)) throw new InvalidOperationException("Offline volume management observation is unavailable.");
        using var dialog = new VolumeCreateDialog(deviceId, containerUuid);
        if (dialog.ShowDialog(_dashboard) != DialogResult.OK) return;
        var target = new ApfsControlTarget(deviceId, "", ContainerUuid: containerUuid);
        await RunVolumeTopologyPlanAsync(new(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeCreatePlan, target,
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80), VolumeManagement: dialog.Parameters)).ConfigureAwait(true);
    }

    private async Task DeleteImageVolumeAsync(DriveDashboardRow selected)
    {
        var status = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var current = TopologyDashboard.Project(status).SingleOrDefault(n => n.Row is not null &&
            DriveDashboardPresenter.RowIdentity(n.Row) == DriveDashboardPresenter.RowIdentity(selected))?.Row;
        if (current?.CanManageTopologyImage != true) throw new InvalidOperationException("Offline volume management observation is unavailable.");
        var device = status.ConnectedInventory!.Single(d => d.Device.DeviceId == current.DeviceId);
        var volume = device.Volumes.Single(v => v.VolumeId == current.VolumeId);
        await RunVolumeTopologyPlanAsync(new(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeDeletePlan,
            SelectedControlTarget.Create(device, volume), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: new("delete"))).ConfigureAwait(true);
    }

    private Task ResizeImageAsync(DriveDashboardRow row) => ChangeImageAsync(row, false);
    private Task FormatImageAsync(DriveDashboardRow row) => ChangeImageAsync(row, true);
    private async Task ChangeImageAsync(DriveDashboardRow selected, bool format)
    {
        var status = _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.");
        var current = TopologyDashboard.Project(status).SingleOrDefault(n => n.Row is not null &&
            DriveDashboardPresenter.RowIdentity(n.Row) == DriveDashboardPresenter.RowIdentity(selected))?.Row;
        if (current is null || !(format ? current.CanFormatImage : current.CanResizeImage))
            throw new InvalidOperationException("Image resize/format is unavailable or not enabled.");
        using var dialog = new VolumeImageDialog(current, format);
        if (dialog.ShowDialog(_dashboard) != DialogResult.OK) return;
        var device = status.ConnectedInventory!.Single(d => d.Device.DeviceId == current.DeviceId);
        var volume = device.Volumes.Single(v => v.VolumeId == current.VolumeId);
        await RunVolumeTopologyPlanAsync(new(Guid.NewGuid().ToString("D"),
            format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            SelectedControlTarget.Create(device, volume), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80),
            VolumeManagement: dialog.Parameters)).ConfigureAwait(true);
    }
    private async Task RunVolumeTopologyPlanAsync(ControlOperationRequestPayload request)
    {
        var result = await VolumeTopologyWorkflow.RunAsync(request, r => SendControlRequestAsync(r, null), text =>
            MessageBox.Show(_dashboard, text, "Confirm image volume change", MessageBoxButtons.OKCancel,
                request.VolumeManagement!.Kind is "delete" or "format" or "erase" ? MessageBoxIcon.Warning : MessageBoxIcon.Question) == DialogResult.OK,
            () => _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.")).ConfigureAwait(true);
        _dashboard.SetFooter(result.FinalStatus ?? result.Diagnostic ?? "Volume management completed.");
    }

    private Task ShowSelectedSnapshotsAsync(DriveDashboardRow selected)
    {
        var workflow = new VolumeSnapshotWorkflow(selected,
            () => _serviceConnected ? _latestStatus ?? throw new InvalidOperationException("Service status is unavailable.") :
                throw new InvalidOperationException("Service is disconnected. Reconnect before acting on snapshots."),
            request => SendControlRequestAsync(request, null));
        using var dialog = new VolumeSnapshotDialog(workflow, path =>
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true }));
        dialog.ShowDialog(_dashboard);
        return Task.CompletedTask;
    }

    private async Task RegisterEncryptedImageAsync()
    {
        if (!_serviceConnected) throw new IOException("Service is disconnected. Reconnect before registering an image.");
        using var picker = new OpenFileDialog { Title = "Register encrypted image", Filter = "Image selector profiles (*.json)|*.json",
            CheckFileExists = true, Multiselect = false };
        if (picker.ShowDialog(_dashboard) != DialogResult.OK) return;
        EncryptedImageProfile profile;
        using (var source = File.OpenRead(picker.FileName)) profile = EncryptedImageRegistration.ReadProfile(source);
        var result = await EncryptedImageRegistration.RunAsync(profile,
            text => MessageBox.Show(_dashboard, text, "Review encrypted image", MessageBoxButtons.OKCancel,
                MessageBoxIcon.Question) == DialogResult.OK,
            request => _serviceConnected ? SendControlRequestAsync(request, null) :
                throw new IOException("Service is disconnected. Reconnect before registering an image.")).ConfigureAwait(true);
        _dashboard.SetFooter(result is null ? "Image registration cancelled." : result.Diagnostic ?? "Encrypted image registered.");
    }

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
                    if (ack.Status is not null && !IsOlderStatus(_latestStatus, ack.Status))
                    {
                        _latestStatus = ack.Status;
                        PostToUi(() => UpdateUi(ack.Status));
                    }
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
            if (ack.Status is not null && !IsOlderStatus(_latestStatus, ack.Status))
            {
                _latestStatus = ack.Status;
                PostToUi(() => UpdateUi(ack.Status));
            }
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
        _serviceConnected = false;
        _registerImageItem.Enabled = false;
        if (_registerFusionItem is not null) _registerFusionItem.Enabled = false;
        _dashboard.SetImageRegistrationAvailable(false);
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

    internal static bool IsOlderStatus(StatusChangedPayload? current, StatusChangedPayload incoming)
        => current?.InventoryGeneration is {} previous && incoming.InventoryGeneration is {} next && next < previous;

    private void UpdateUi(StatusChangedPayload payload)
    {
        if (IsOlderStatus(_latestStatus, payload)) return;
        _serviceConnected = true;
        _registerImageItem.Enabled = true;
        if (_registerFusionItem is not null) _registerFusionItem.Enabled = true;
        _dashboard.SetImageRegistrationAvailable(true);
        if (!TopologyStatusProjection.IsBounded(payload))
            payload = new(RuntimeState.Error, [], "Details unavailable", DateTime.UtcNow, [], false, []);
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
        UpdateSelectedActionMenu(_fixItem, payload, ApfsControlCommands.Fix);
        UpdateSelectedActionMenu(_mountItem, payload, ApfsControlCommands.Mount);
        UpdateOfflineActionMenus(payload);
        _dashboard.ApplyStatus(payload);
        if (currentBalloonState == DriveDashboardState.HealthyReadWrite)
        {
            _shownWarnings.Clear();
        }
        ShowWarnings(payload, BuildStatusBalloonWarnings(payload, currentBalloonState), currentBalloonState);
        ShowHealthTransition(payload, previousBalloonState, currentBalloonState);
        _lastStatusBalloonState = currentBalloonState;
        if (!_queuedDriveLetterRemounts.IsEmpty)
        {
            _ = Task.Run(() => TryProcessQueuedDriveLetterRemountsAsync(payload));
        }
    }

    private void UpdateOfflineActionMenus(StatusChangedPayload status)
    {
        _verifyItem.DropDownItems.Clear();
        _manageItem.DropDownItems.Clear();
        _snapshotsItem.DropDownItems.Clear();
        _createVolumeItem.DropDownItems.Clear();
        _deleteVolumeItem.DropDownItems.Clear();
        var rows = TopologyDashboard.Project(status).Where(n => n.Row is not null).Select(n => n.Row!).ToArray();
        foreach (var row in rows)
        {
            var label = $"{row.VolumeName} ({row.DeviceName}, {row.CatalogVolumeUuid})";
            if (row.CanVerifyOffline || row.CanVerifyLive)
                _verifyItem.DropDownItems.Add(new ToolStripMenuItem(label, null, async (_, _) =>
                {
                    try { await VerifySelectedVolumeAsync(row).ConfigureAwait(true); }
                    catch (Exception ex) { _dashboard.SetFooter(ex.Message); }
                }) { Tag = row });
            if (row.CanManageOffline)
                _manageItem.DropDownItems.Add(new ToolStripMenuItem(label, null, async (_, _) =>
                {
                    try { await ManageSelectedVolumeAsync(row).ConfigureAwait(true); }
                    catch (Exception ex) { _dashboard.SetFooter(ex.Message); }
                }) { Tag = row });
            if (row.CanVerifyOffline || row.CanListSnapshots || row.CanRecoverSnapshots)
                _snapshotsItem.DropDownItems.Add(new ToolStripMenuItem(label, null, async (_, _) =>
                {
                    try { await ShowSelectedSnapshotsAsync(row).ConfigureAwait(true); }
                    catch (Exception ex) { _dashboard.SetFooter(ex.Message); }
                }) { Tag = row });
            if (row.CanManageTopologyImage)
                _deleteVolumeItem.DropDownItems.Add(new ToolStripMenuItem(label, null, async (_, _) =>
                {
                    try { await DeleteImageVolumeAsync(row).ConfigureAwait(true); }
                    catch (Exception ex) { _dashboard.SetFooter(ex.Message); }
                }) { Tag = row });
            if (row.CanResizeImage)
                _manageItem.DropDownItems.Add(new ToolStripMenuItem("Resize container: " + label, null, async (_, _) =>
                { try { await ResizeImageAsync(row).ConfigureAwait(true); } catch (Exception ex) { _dashboard.SetFooter(ex.Message); } }));
            if (row.CanFormatImage)
                _manageItem.DropDownItems.Add(new ToolStripMenuItem("Format container: " + label, null, async (_, _) =>
                { try { await FormatImageAsync(row).ConfigureAwait(true); } catch (Exception ex) { _dashboard.SetFooter(ex.Message); } }));
        }
        foreach (var group in rows.GroupBy(r => (r.DeviceId, r.CatalogContainerUuid)).Where(g => g.All(r => r.CanManageTopologyImage)))
        {
            var first = group.First();
            _createVolumeItem.DropDownItems.Add(new ToolStripMenuItem($"{first.DeviceName} ({first.CatalogContainerUuid})", null, async (_, _) =>
            {
                try { await CreateImageVolumeAsync(first.DeviceId!, first.CatalogContainerUuid!).ConfigureAwait(true); }
                catch (Exception ex) { _dashboard.SetFooter(ex.Message); }
            }));
        }
        _verifyItem.Enabled = _verifyItem.HasDropDownItems;
        _manageItem.Enabled = _manageItem.HasDropDownItems;
        _snapshotsItem.Enabled = _snapshotsItem.HasDropDownItems;
        _createVolumeItem.Enabled = _createVolumeItem.HasDropDownItems;
        _deleteVolumeItem.Enabled = _deleteVolumeItem.HasDropDownItems;
    }

    private void UpdateSelectedActionMenu(ToolStripMenuItem? menu, StatusChangedPayload status, string command)
    {
        if (menu is null) return;
        var rows = SelectedActionRows(status, command);
        var signature = JsonSerializer.Serialize(rows);
        if (menu.Tag is string previous && previous == signature) return;
        foreach (var item in menu.DropDownItems.Cast<ToolStripItem>().ToArray()) { menu.DropDownItems.Remove(item); item.Dispose(); }
        menu.Tag = signature;
        foreach (var row in rows) menu.DropDownItems.Add(CreateSelectedActionItem(row, command, SendSelectedVolumeAsync,
            ex => PostToUi(() => _dashboard.SetFooter(ex.Message))));
        menu.Enabled = rows.Length > 0;
    }

    internal static DriveDashboardRow[] SelectedActionRows(StatusChangedPayload status, string command)
        => TopologyDashboard.Project(status).Where(n => n.Row is not null).Select(n => n.Row!)
            .Where(r => command == ApfsControlCommands.Fix ? DriveDashboardPresenter.CanFixVolume(r) :
                r.CanMount).ToArray();

    internal static ToolStripMenuItem CreateSelectedActionItem(DriveDashboardRow row, string command,
        Func<DriveDashboardRow, string, Task> send, Action<Exception> failed)
    {
        var label = command == ApfsControlCommands.Fix ? "Fix" : command == ApfsControlCommands.Eject ? "Eject" :
            row.CanMountBackupReadWrite ? "Mount backup read/write" : row.CanInspectReadOnly ? "Inspect read-only" : "Mount";
        var item = new ToolStripMenuItem($"{label} {row.DeviceName} ({row.MountPoint}, {row.VolumeName})") { Tag = row };
        item.Click += async (sender, _) => {
            if (sender is not ToolStripMenuItem { Tag: DriveDashboardRow selected }) return;
            try { await send(selected, command).ConfigureAwait(false); }
            catch (Exception ex) { failed(ex); }
        };
        return item;
    }

    private void UpdateEjectMenu(StatusChangedPayload payload)
    {
        var descriptors = BuildEjectMenuDescriptors(payload);
        var signature = BuildEjectMenuSignature(descriptors) + System.Text.Json.JsonSerializer.Serialize(descriptors.Select(d => d.Row));
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
            _ejectItem.Tag = (object?)descriptor.Row ?? descriptor.VolumeId;
            return;
        }

        _ejectItem.Text = $"Eject APFS drives ({descriptors.Count})";
        foreach (var descriptor in descriptors)
        {
            var child = descriptor.Row is {} selected
                ? CreateSelectedActionItem(selected, ApfsControlCommands.Eject, SendSelectedVolumeAsync,
                    ex => PostToUi(() => _dashboard.SetFooter(ex.Message)))
                : new ToolStripMenuItem(descriptor.Text) { Tag = descriptor.VolumeId };
            if (descriptor.Row is null) child.Click += OnEjectClicked;
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
        if (payload.InventoryGeneration is not null || payload.ConnectedInventory?.Any(d => d.Topology is not null) == true)
        {
            return TopologyDashboard.Project(payload).Where(n => n.Row?.CanEject == true)
                .Select(n => n.Row!).OrderBy(r => r.MountPoint, StringComparer.OrdinalIgnoreCase)
                .Select(r => new EjectMenuDescriptor($"Eject {r.DeviceName} ({r.MountPoint}, {r.VolumeName})", r.VolumeId, r)).ToArray();
        }
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
                .Where(static row => row.IsMounted)
                .Select(static row => row.State)
                .ToArray();
            if (mountedStates.Length > 0)
            {
                return mountedStates.Max();
            }
        }

        if (payload.ConnectedInventory is not null && !rows.Any(r => r.IsMounted) && payload.State == RuntimeState.Idle)
            return DriveDashboardState.Idle;

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
