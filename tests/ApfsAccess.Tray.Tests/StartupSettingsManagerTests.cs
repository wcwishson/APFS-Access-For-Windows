using System.Windows.Forms;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class StartupSettingsManagerTests
{
    [Fact]
    public void SetStartWithWindows_WritesCurrentUserRunCommandForLauncher()
    {
        var registry = new FakeStartupRegistry();
        var shortcut = new FakeStartupShortcut();
        var settingsPath = Path.Combine(Path.GetTempPath(), "ApfsAccessTrayTests", Guid.NewGuid().ToString("N"), "settings.json");
        var manager = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);

        manager.SetStartWithWindows(true);

        Assert.Equal("\"D:\\Apps\\APFS Access.exe\"", registry.Value);
        Assert.False(shortcut.Exists());
        Assert.True(manager.Load().StartWithWindows);
    }

    [Fact]
    public void SetStartWithWindows_FallsBackToStartupShortcutWhenRegistryWriteIsBlocked()
    {
        var registry = new FakeStartupRegistry
        {
            ThrowOnSet = true,
        };
        var shortcut = new FakeStartupShortcut();
        var settingsPath = Path.Combine(Path.GetTempPath(), "ApfsAccessTrayTests", Guid.NewGuid().ToString("N"), "settings.json");
        var manager = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);

        manager.SetStartWithWindows(true);

        Assert.Null(registry.Value);
        Assert.True(shortcut.Exists());
        Assert.Equal(@"D:\Apps\APFS Access.exe", shortcut.TargetPath);
        Assert.True(manager.Load().StartWithWindows);
    }

    [Fact]
    public void SetStartWithWindowsFalse_RemovesRegistryValueAndFallbackShortcut()
    {
        var registry = new FakeStartupRegistry();
        var shortcut = new FakeStartupShortcut();
        var settingsPath = Path.Combine(Path.GetTempPath(), "ApfsAccessTrayTests", Guid.NewGuid().ToString("N"), "settings.json");
        var manager = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);

        manager.SetStartWithWindows(true);
        shortcut.Create(@"D:\Apps\APFS Access.exe");

        manager.SetStartWithWindows(false);

        Assert.Null(registry.Value);
        Assert.False(shortcut.Exists());
        Assert.False(manager.Load().StartWithWindows);
    }

    [Fact]
    public void SetStartMinimized_PersistsPreferenceToSettingsFile()
    {
        var registry = new FakeStartupRegistry();
        var shortcut = new FakeStartupShortcut();
        var settingsPath = Path.Combine(Path.GetTempPath(), "ApfsAccessTrayTests", Guid.NewGuid().ToString("N"), "settings.json");
        var manager = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);

        manager.SetStartMinimized(true);

        var reloaded = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);
        Assert.True(reloaded.Load().StartMinimized);
    }

    [Fact]
    public void SetLastAutoUpdateCheckUtc_PersistsAndEvaluatesWeeklySchedule()
    {
        var registry = new FakeStartupRegistry();
        var shortcut = new FakeStartupShortcut();
        var settingsPath = Path.Combine(Path.GetTempPath(), "ApfsAccessTrayTests", Guid.NewGuid().ToString("N"), "settings.json");
        var manager = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);

        var now = new DateTimeOffset(2026, 10, 21, 2, 0, 0, TimeSpan.Zero);
        Assert.Null(manager.GetLastAutoUpdateCheckUtc());
        Assert.True(TrayApplicationContext.IsWeeklyUpdateCheckDue(manager.GetLastAutoUpdateCheckUtc(), now));

        manager.SetLastAutoUpdateCheckUtc(now);

        var reloaded = new StartupSettingsManager(
            registry,
            settingsPath,
            () => @"D:\Apps\APFS Access.exe",
            shortcut);
        Assert.Equal(now, reloaded.GetLastAutoUpdateCheckUtc());
        Assert.False(TrayApplicationContext.IsWeeklyUpdateCheckDue(reloaded.GetLastAutoUpdateCheckUtc(), now.AddDays(6)));
        Assert.True(TrayApplicationContext.IsWeeklyUpdateCheckDue(reloaded.GetLastAutoUpdateCheckUtc(), now.AddDays(7)));
    }

    [Fact]
    public void GitHubButton_AppearsRightOfUpdateButtonAndOpensProjectUrl()
    {
        using var form = new DashboardForm(
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            new StartupPreferences(false, false, AppThemeMode.Dark),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            () => Task.CompletedTask);

        var opened = false;
        form.OpenGitHubPageOverride = () => opened = true;

        var buttons = FindAllButtons(form);
        var updateButton = Assert.Single(buttons, b => b.Text == "Check for updates");
        var gitHubButton = Assert.Single(buttons, b => b.Text == "GitHub");
        Assert.Same(updateButton.Parent, gitHubButton.Parent);
        var parentControls = updateButton.Parent!.Controls;
        Assert.Equal(parentControls.IndexOf(updateButton) + 1, parentControls.IndexOf(gitHubButton));

        typeof(Control)
            .GetMethod("OnClick", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .Invoke(gitHubButton, [EventArgs.Empty]);
        Assert.True(opened);
    }

    [Fact]
    public void TryDetectVolumeOrContainerInUse_DetectsActiveWritesAndHostHandles()
    {
        var row = new DriveDashboardRow(
            VolumeId: "vol-1",
            DeviceName: "PhysicalDrive2",
            VolumeName: "WorkAPFS",
            MountPoint: "E:",
            MountPath: @"E:\",
            State: DriveDashboardState.HealthyReadWrite,
            Palette: DashboardPalette.Green,
            StateText: "Mounted (read-write)",
            Summary: "Ready",
            CanOpen: true,
            CanEject: true,
            CanFix: false,
            Details: [],
            FixGuidance: [],
            CatalogVolumeId: "vol-1",
            CatalogContainerUuid: "11111111-2222-3333-4444-555555555555",
            DeviceId: @"\\.\PhysicalDrive2",
            IsMounted: true);

        var idleStatus = new StatusChangedPayload(
            State: ApfsAccess.Core.RuntimeState.MountedRw,
            MountPoints: ["E:"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: [],
            WriteEnabled: true,
            CompatibilityWarnings: []);

        Assert.False(TrayApplicationContext.TryDetectVolumeOrContainerInUse(
            idleStatus,
            row,
            out var idleReason,
            _ => null));
        Assert.Null(idleReason);

        Assert.True(TrayApplicationContext.TryDetectVolumeOrContainerInUse(
            idleStatus,
            row,
            out var explorerReason,
            _ => @"File Explorer is currently open on E:\."));
        Assert.Equal(@"File Explorer is currently open on E:\.", explorerReason);

        var activeWriteStatus = idleStatus with { InFlightMutationCallbacks = 2 };
        Assert.True(TrayApplicationContext.TryDetectVolumeOrContainerInUse(
            activeWriteStatus,
            row,
            out var writeReason,
            _ => null));
        Assert.Contains("active file operations", writeReason, StringComparison.OrdinalIgnoreCase);
    }

    private static List<Button> FindAllButtons(Control root)
    {
        var result = new List<Button>();
        foreach (Control child in root.Controls)
        {
            if (child is Button button)
            {
                result.Add(button);
            }
            result.AddRange(FindAllButtons(child));
        }
        return result;
    }

    private sealed class FakeStartupRegistry : IStartupRegistry
    {
        public string? Value { get; private set; }
        public bool ThrowOnSet { get; init; }

        public string? GetCurrentUserRunValue(string name)
        {
            Assert.Equal("APFS Access", name);
            return Value;
        }

        public void SetCurrentUserRunValue(string name, string value)
        {
            Assert.Equal("APFS Access", name);
            if (ThrowOnSet)
            {
                throw new UnauthorizedAccessException("Registry write blocked.");
            }

            Value = value;
        }

        public void DeleteCurrentUserRunValue(string name)
        {
            Assert.Equal("APFS Access", name);
            Value = null;
        }
    }

    private sealed class FakeStartupShortcut : IStartupShortcut
    {
        public string? TargetPath { get; private set; }

        public bool Exists()
            => !string.IsNullOrWhiteSpace(TargetPath);

        public void Create(string launcherPath)
            => TargetPath = launcherPath;

        public void Delete()
            => TargetPath = null;
    }
}
