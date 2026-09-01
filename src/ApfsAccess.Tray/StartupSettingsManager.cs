using System.Text.Json;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;

namespace ApfsAccess.Tray;

public sealed record StartupPreferences(bool StartWithWindows, bool StartMinimized);

public interface IStartupRegistry
{
    string? GetCurrentUserRunValue(string name);
    void SetCurrentUserRunValue(string name, string value);
    void DeleteCurrentUserRunValue(string name);
}

public interface IStartupShortcut
{
    bool Exists();
    void Create(string launcherPath);
    void Delete();
}

public sealed class WindowsStartupRegistry : IStartupRegistry
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public string? GetCurrentUserRunValue(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
        return key?.GetValue(name) as string;
    }

    public void SetCurrentUserRunValue(string name, string value)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
        key.SetValue(name, value, RegistryValueKind.String);
    }

    public void DeleteCurrentUserRunValue(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
        key?.DeleteValue(name, throwOnMissingValue: false);
    }
}

public sealed class WindowsStartupShortcut : IStartupShortcut
{
    private readonly string _shortcutPath;

    public WindowsStartupShortcut(string shortcutPath)
    {
        _shortcutPath = string.IsNullOrWhiteSpace(shortcutPath)
            ? throw new ArgumentException("Shortcut path is required.", nameof(shortcutPath))
            : shortcutPath;
    }

    public static WindowsStartupShortcut CreateDefault()
        => new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            "APFS Access.lnk"));

    public bool Exists()
        => File.Exists(_shortcutPath);

    public void Create(string launcherPath)
    {
        var directory = Path.GetDirectoryName(_shortcutPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new InvalidOperationException("Windows shortcut support is unavailable.");
        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(shellType)
                ?? throw new InvalidOperationException("Could not create Windows shortcut helper.");
            shortcut = shellType.InvokeMember(
                "CreateShortcut",
                System.Reflection.BindingFlags.InvokeMethod,
                binder: null,
                target: shell,
                args: [_shortcutPath]);

            if (shortcut is null)
            {
                throw new InvalidOperationException("Could not create Windows startup shortcut.");
            }

            var shortcutType = shortcut.GetType();
            shortcutType.InvokeMember("TargetPath", System.Reflection.BindingFlags.SetProperty, null, shortcut, [launcherPath]);
            shortcutType.InvokeMember(
                "WorkingDirectory",
                System.Reflection.BindingFlags.SetProperty,
                null,
                shortcut,
                [Path.GetDirectoryName(launcherPath) ?? AppContext.BaseDirectory]);
            shortcutType.InvokeMember("Description", System.Reflection.BindingFlags.SetProperty, null, shortcut, ["APFS Access"]);
            shortcutType.InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, shortcut, []);
        }
        finally
        {
            ReleaseComObject(shortcut);
            ReleaseComObject(shell);
        }
    }

    public void Delete()
    {
        if (File.Exists(_shortcutPath))
        {
            File.Delete(_shortcutPath);
        }
    }

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            Marshal.FinalReleaseComObject(value);
        }
    }
}

public sealed class StartupSettingsManager
{
    private const string RunValueName = "APFS Access";
    private readonly IStartupRegistry _registry;
    private readonly IStartupShortcut _shortcut;
    private readonly string _settingsPath;
    private readonly Func<string> _resolveLauncherPath;

    public StartupSettingsManager(
        IStartupRegistry registry,
        string settingsPath,
        Func<string> resolveLauncherPath,
        IStartupShortcut? shortcut = null)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _shortcut = shortcut ?? NoopStartupShortcut.Instance;
        _settingsPath = string.IsNullOrWhiteSpace(settingsPath)
            ? throw new ArgumentException("Settings path is required.", nameof(settingsPath))
            : settingsPath;
        _resolveLauncherPath = resolveLauncherPath ?? throw new ArgumentNullException(nameof(resolveLauncherPath));
    }

    public static StartupSettingsManager CreateDefault()
        => new(
            new WindowsStartupRegistry(),
            GetDefaultSettingsPath(),
            ResolveLauncherPath,
            WindowsStartupShortcut.CreateDefault());

    public StartupPreferences Load()
    {
        var persisted = LoadPersistedSettings();
        var startupCommand = TryGetStartupCommand();
        return new StartupPreferences(
            StartWithWindows: !string.IsNullOrWhiteSpace(startupCommand) || SafeShortcutExists(),
            StartMinimized: persisted.StartMinimized);
    }

    public void SetStartWithWindows(bool enabled)
    {
        if (enabled)
        {
            var launcherPath = _resolveLauncherPath();
            try
            {
                _registry.SetCurrentUserRunValue(RunValueName, QuotePath(launcherPath));
                _shortcut.Delete();
            }
            catch (Exception ex) when (IsRegistryAccessFailure(ex))
            {
                _shortcut.Create(launcherPath);
            }

            return;
        }

        _registry.DeleteCurrentUserRunValue(RunValueName);
        _shortcut.Delete();
    }

    public void SetStartMinimized(bool enabled)
    {
        var settings = LoadPersistedSettings() with
        {
            StartMinimized = enabled,
        };
        SavePersistedSettings(settings);
    }

    private static string GetDefaultSettingsPath()
        => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ApfsAccess",
            "tray-settings.json");

    private static string ResolveLauncherPath()
    {
        var launcherPath = Environment.GetEnvironmentVariable("APFSACCESS_LAUNCHER_PATH");
        if (!string.IsNullOrWhiteSpace(launcherPath) && File.Exists(launcherPath))
        {
            return Path.GetFullPath(launcherPath);
        }

        foreach (var directory in EnumerateParentDirectories(AppContext.BaseDirectory, maxDepth: 8))
        {
            var candidate = Path.Combine(directory, "APFS Access.exe");
            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        return Environment.ProcessPath ?? Application.ExecutablePath;
    }

    private static IEnumerable<string> EnumerateParentDirectories(string startDirectory, int maxDepth)
    {
        var directory = new DirectoryInfo(startDirectory);
        for (var depth = 0; depth <= maxDepth && directory is not null; ++depth, directory = directory.Parent)
        {
            yield return directory.FullName;
        }
    }

    private static string QuotePath(string path)
        => $"\"{path.Trim().Trim('"')}\"";

    private string? TryGetStartupCommand()
    {
        try
        {
            return _registry.GetCurrentUserRunValue(RunValueName);
        }
        catch (Exception ex) when (IsRegistryAccessFailure(ex))
        {
            return null;
        }
    }

    private bool SafeShortcutExists()
    {
        try
        {
            return _shortcut.Exists();
        }
        catch
        {
            return false;
        }
    }

    private static bool IsRegistryAccessFailure(Exception ex)
        => ex is UnauthorizedAccessException or SecurityException or IOException;

    private PersistedStartupSettings LoadPersistedSettings()
    {
        try
        {
            if (!File.Exists(_settingsPath))
            {
                return new PersistedStartupSettings();
            }

            var json = File.ReadAllText(_settingsPath);
            return JsonSerializer.Deserialize<PersistedStartupSettings>(json) ?? new PersistedStartupSettings();
        }
        catch
        {
            return new PersistedStartupSettings();
        }
    }

    private void SavePersistedSettings(PersistedStartupSettings settings)
    {
        var directory = Path.GetDirectoryName(_settingsPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(
            _settingsPath,
            JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
    }

    private sealed record PersistedStartupSettings
    {
        public bool StartMinimized { get; init; }
    }

    private sealed class NoopStartupShortcut : IStartupShortcut
    {
        public static readonly NoopStartupShortcut Instance = new();

        public bool Exists()
            => false;

        public void Create(string launcherPath)
            => _ = launcherPath;

        public void Delete()
        {
        }
    }
}
