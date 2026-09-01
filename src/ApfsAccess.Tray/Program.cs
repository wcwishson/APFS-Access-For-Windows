namespace ApfsAccess.Tray;

using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;

public static class Program
{
    private const string ElevatedEnvironmentArgument = "--apfsaccess-elevated-environment";

    private static readonly string[] PropagatedEnvironmentKeys =
    [
        "APFSACCESS_PORTABLE_ROOT",
        "APFSACCESS_RUNTIME_ROOT",
        "APFSACCESS_SPOOL_ROOT",
        "TEMP",
        "TMP",
        "APFSACCESS_TRACE_MOVES",
        "APFSACCESS_PERF_COUNTERS",
        "APFSACCESS_TRACE_COMMITS",
        "APFSACCESS_TRACE_READS",
        "APFSACCESS_DEFER_CLOSE_COMMITS",
        "APFSACCESS_DISABLE_CONTENT_WRITEBACK",
        "APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE",
        "APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE",
        "APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE",
        "APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK",
        "APFSACCESS_DISABLE_NAMESPACE_WRITEBACK",
        "APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        "APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        "APFSACCESS_CHECKPOINT_DELTA_SHADOW",
        "APFSACCESS_STRICT_COMMIT_VERIFY",
        "APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE",
        "APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE",
        "APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX",
        "APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE",
        "APFSACCESS_DISABLE_INDEX_DELTA",
        UpdateReceiptPublisher.TokenEnvironmentKey,
        UpdateReceiptPublisher.VersionEnvironmentKey,
        UpdateReceiptPublisher.ReceiptPathEnvironmentKey,
    ];

    [STAThread]
    private static void Main(string[] args)
    {
        ApplyElevatedEnvironment(args);

        if (ShouldRelaunchElevated())
        {
            RelaunchElevated();
            return;
        }

        ConfigurePortableRuntimeEnvironment();
        UpdateReceiptPublisher.TryWriteCurrentProcessPhase("launched");
        ApplicationConfiguration.Initialize();
        using var context = new TrayApplicationContext();
        Application.Run(context);
    }

    private static bool ShouldRelaunchElevated()
    {
        if (string.Equals(
                Environment.GetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED"),
                "1",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return !principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void RelaunchElevated()
    {
        var selfPath = Environment.ProcessPath ?? Application.ExecutablePath;
        var environmentFile = WriteElevatedEnvironmentFile();
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = selfPath,
                Arguments = $"{ElevatedEnvironmentArgument} \"{environmentFile}\"",
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = true,
                Verb = "runas",
            });
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            TryDeleteElevatedEnvironmentFile(environmentFile);
            MessageBox.Show(
                "Administrator permission is required so APFS Access can read APFS USB drives and mount them in This PC.",
                "APFS Access",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
    }

    private static string WriteElevatedEnvironmentFile()
    {
        var runtimeRoot = ResolveRuntimeRoot();
        Directory.CreateDirectory(runtimeRoot);
        var path = Path.Combine(
            runtimeRoot,
            $"elevation-environment-{Guid.NewGuid():N}.json");
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in PropagatedEnvironmentKeys)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(value))
            {
                values[key] = value;
            }
        }

        File.WriteAllText(path, JsonSerializer.Serialize(values));
        return path;
    }

    private static void ApplyElevatedEnvironment(string[] args)
    {
        for (var index = 0; index + 1 < args.Length; index++)
        {
            if (!string.Equals(args[index], ElevatedEnvironmentArgument, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var path = args[index + 1];
            if (!IsElevatedEnvironmentFile(path))
            {
                return;
            }
            try
            {
                var values = JsonSerializer.Deserialize<Dictionary<string, string>>(
                    File.ReadAllText(path));
                if (values is not null)
                {
                    foreach (var entry in values)
                    {
                        if (PropagatedEnvironmentKeys.Contains(entry.Key, StringComparer.OrdinalIgnoreCase))
                        {
                            Environment.SetEnvironmentVariable(entry.Key, entry.Value);
                        }
                    }
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (JsonException)
            {
            }
            finally
            {
                TryDeleteElevatedEnvironmentFile(path);
            }
            return;
        }
    }

    private static void TryDeleteElevatedEnvironmentFile(string path)
    {
        if (!IsElevatedEnvironmentFile(path))
        {
            return;
        }

        try
        {
            File.Delete(path);
        }
        catch
        {
        }
    }

    private static bool IsElevatedEnvironmentFile(string path)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);
        const string prefix = "elevation-environment-";
        return Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase) &&
               fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
               Guid.TryParseExact(fileName[prefix.Length..], "N", out _);
    }

    private static void ConfigurePortableRuntimeEnvironment()
    {
        var runtimeRoot = ResolveRuntimeRoot();
        var tempRoot = Path.Combine(runtimeRoot, "temp");
        var spoolRoot = Path.Combine(runtimeRoot, "payload-spool");

        Directory.CreateDirectory(tempRoot);
        Directory.CreateDirectory(spoolRoot);

        Environment.SetEnvironmentVariable("TEMP", tempRoot);
        Environment.SetEnvironmentVariable("TMP", tempRoot);
        Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", spoolRoot);
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_TRACE_MOVES");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_PERF_COUNTERS");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_TRACE_COMMITS");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_TRACE_READS");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DEFER_CLOSE_COMMITS");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CONTENT_WRITEBACK");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_NAMESPACE_WRITEBACK");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_ASYNC_BLOCK_IO");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_ASYNC_BLOCK_IO_DEPTH");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_CHECKPOINT_DELTA_SHADOW");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_STRICT_COMMIT_VERIFY");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE");
        PreserveOptionalDiagnosticEnvironment("APFSACCESS_DISABLE_INDEX_DELTA");
    }

    private static void PreserveOptionalDiagnosticEnvironment(string key)
    {
        var value = Environment.GetEnvironmentVariable(key);
        if (!string.IsNullOrWhiteSpace(value))
        {
            Environment.SetEnvironmentVariable(key, value);
        }
    }

    private static string ResolvePortableRoot()
    {
        var overrideRoot = Environment.GetEnvironmentVariable("APFSACCESS_PORTABLE_ROOT");
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            return Path.GetFullPath(overrideRoot);
        }

        var baseDirectory = new DirectoryInfo(AppContext.BaseDirectory);
        if (baseDirectory.Name.StartsWith("payload-", StringComparison.OrdinalIgnoreCase) &&
            baseDirectory.Parent is not null)
        {
            return baseDirectory.Parent.FullName;
        }

        return Path.Combine(AppContext.BaseDirectory, ".apfsaccess-portable");
    }

    private static string ResolveRuntimeRoot()
    {
        var overrideRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            return Path.GetFullPath(overrideRoot);
        }

        var portableRoot = ResolvePortableRoot();
        if (LooksLikeCloudSyncedPath(portableRoot))
        {
            var driveRoot = Path.GetPathRoot(portableRoot);
            if (!string.IsNullOrWhiteSpace(driveRoot))
            {
                return Path.Combine(driveRoot, "ApfsAccessScratch", "AppRuntime");
            }
        }

        return Path.Combine(portableRoot, "runtime");
    }

    private static bool LooksLikeCloudSyncedPath(string path)
    {
        return path.Contains("SynologyDrive", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Dropbox", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Google Drive", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("iCloudDrive", StringComparison.OrdinalIgnoreCase);
    }
}
