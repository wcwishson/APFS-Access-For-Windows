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
