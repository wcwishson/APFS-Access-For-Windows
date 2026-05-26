using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ApfsAccess.Bootstrap;

internal static class Program
{
    private const string EmbeddedPayloadResourceName = "ApfsAccess.Bootstrap.Payload.click-run.zip";
    private const string AdjacentPayloadFileName = "click-run-payload.zip";
    private const string LauncherDisplayName = "APFS Access Portable";
    private const string InstallModeArgument = "--install-prereqs";
    private const string VcRedistDirectUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
    private const string WinFspListingUrl = "https://winfsp.dev/rel/";

    private static readonly IReadOnlyList<PrerequisiteSpec> RequiredPrerequisites =
    [
        new(
            Key: "winfsp",
            DisplayName: "WinFsp runtime",
            WingetId: "WinFsp.WinFsp",
            ManualUrl: "https://winfsp.dev/rel/",
            IsInstalled: IsWinFspInstalled),
        new(
            Key: "vcredist",
            DisplayName: "Microsoft Visual C++ Redistributable x64",
            WingetId: "Microsoft.VCRedist.2015+.x64",
            ManualUrl: VcRedistDirectUrl,
            IsInstalled: IsVcRuntimeInstalled),
    ];

    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        try
        {
            if (args.Any(a => string.Equals(a, InstallModeArgument, StringComparison.OrdinalIgnoreCase)))
            {
                return RunInstallerMode();
            }

            EnsurePrerequisitesInteractive();

            var payloadBytes = LoadPayloadBytes();
            var extractionDirectory = ExtractPayload(payloadBytes);
            LaunchTray(extractionDirectory);
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 1;
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
            return 1;
        }
    }

    private static int RunInstallerMode()
    {
        if (!IsAdministrator())
        {
            ShowError("Administrator permission is required to install prerequisites.");
            return 2;
        }

        return InstallMissingPrerequisitesWithUi() ? 0 : 3;
    }

    private static void EnsurePrerequisitesInteractive()
    {
        var missing = GetMissingPrerequisites();
        if (missing.Count == 0)
        {
            return;
        }

        var prompt = new StringBuilder();
        prompt.AppendLine("APFS Access needs these components before it can run:");
        prompt.AppendLine();
        foreach (var item in missing)
        {
            prompt.AppendLine($"- {item.DisplayName}");
        }

        prompt.AppendLine();
        prompt.Append("Install them automatically now?");

        var choice = MessageBox.Show(
            prompt.ToString(),
            LauncherDisplayName,
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button1);

        if (choice != DialogResult.Yes)
        {
            throw new OperationCanceledException("Prerequisite installation was canceled.");
        }

        var installSucceeded = IsAdministrator()
            ? InstallMissingPrerequisitesWithUi()
            : RunElevatedInstaller() == 0;

        var remaining = GetMissingPrerequisites();
        if (installSucceeded && remaining.Count == 0)
        {
            return;
        }

        ShowManualGuidance(remaining.Count > 0 ? remaining : missing);
        throw new InvalidOperationException("Required prerequisites are still missing.");
    }

    private static int RunElevatedInstaller()
    {
        MessageBox.Show(
            "Windows will now request administrator permission so APFS Access can install required components automatically.",
            LauncherDisplayName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);

        var selfPath = Environment.ProcessPath ?? Application.ExecutablePath;
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = selfPath,
                Arguments = InstallModeArgument,
                UseShellExecute = true,
                Verb = "runas",
            });

            if (process is null)
            {
                return 1;
            }

            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException("Administrator permission prompt was canceled.", ex);
        }
    }

    private static bool InstallMissingPrerequisitesWithUi()
    {
        var missing = GetMissingPrerequisites();
        if (missing.Count == 0)
        {
            return true;
        }

        MessageBox.Show(
            "APFS Access is installing required components now. This may take a few minutes.",
            LauncherDisplayName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);

        var wingetAvailable = IsWingetAvailable();
        foreach (var prerequisite in missing)
        {
            if (SafeIsInstalled(prerequisite))
            {
                continue;
            }

            var installed = wingetAvailable && InstallViaWinget(prerequisite);
            if (!installed)
            {
                installed = InstallViaFallbackDownload(prerequisite);
            }

            if (!installed || !SafeIsInstalled(prerequisite))
            {
                return false;
            }
        }

        MessageBox.Show(
            "Setup finished. APFS Access will start now.",
            LauncherDisplayName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);

        return true;
    }

    private static bool InstallViaWinget(PrerequisiteSpec prerequisite)
    {
        if (string.IsNullOrWhiteSpace(prerequisite.WingetId))
        {
            return false;
        }

        var args =
            $"install --id \"{prerequisite.WingetId}\" -e --source winget " +
            "--accept-package-agreements --accept-source-agreements --silent --disable-interactivity";

        var exitCode = RunProcess("winget", args, timeout: TimeSpan.FromMinutes(10));
        return IsAcceptableInstallerExitCode(exitCode);
    }

    private static bool InstallViaFallbackDownload(PrerequisiteSpec prerequisite)
    {
        try
        {
            return prerequisite.Key switch
            {
                "winfsp" => InstallWinFspFromDirectDownload(),
                "vcredist" => InstallVcRedistFromDirectDownload(),
                _ => false,
            };
        }
        catch
        {
            return false;
        }
    }

    private static bool InstallWinFspFromDirectDownload()
    {
        var winfspUrl = ResolveWinFspInstallerUrl();
        if (string.IsNullOrWhiteSpace(winfspUrl))
        {
            return false;
        }

        var msiPath = DownloadToTempFile(winfspUrl, "winfsp.msi");
        var exitCode = RunProcess("msiexec.exe", $"/i \"{msiPath}\" /passive /norestart", timeout: TimeSpan.FromMinutes(10));
        return IsAcceptableInstallerExitCode(exitCode);
    }

    private static bool InstallVcRedistFromDirectDownload()
    {
        var exePath = DownloadToTempFile(VcRedistDirectUrl, "vc_redist.x64.exe");
        var exitCode = RunProcess(exePath, "/install /passive /norestart", timeout: TimeSpan.FromMinutes(10));
        return IsAcceptableInstallerExitCode(exitCode) || exitCode == 1638;
    }

    private static string? ResolveWinFspInstallerUrl()
    {
        using var client = CreateHttpClient();
        var html = client.GetStringAsync(WinFspListingUrl).GetAwaiter().GetResult();
        var match = Regex.Match(
            html,
            @"https://github\.com/winfsp/winfsp/releases/download/[^""']+\.msi",
            RegexOptions.IgnoreCase);

        return match.Success ? match.Value : null;
    }

    private static string DownloadToTempFile(string url, string fileName)
    {
        var downloadRoot = Path.Combine(ResolvePortableRoot(), "downloads");
        Directory.CreateDirectory(downloadRoot);

        var destination = Path.Combine(downloadRoot, fileName);
        using var client = CreateHttpClient();
        using var response = client.GetAsync(url).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();

        using var sourceStream = response.Content.ReadAsStream();
        using var destinationStream = File.Create(destination);
        sourceStream.CopyTo(destinationStream);
        return destination;
    }

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(5),
        };

        client.DefaultRequestHeaders.UserAgent.ParseAdd("APFSAccessPortable/1.0");
        return client;
    }

    private static int RunProcess(string fileName, string arguments, TimeSpan timeout)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
        });

        if (process is null)
        {
            return -1;
        }

        if (!process.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort.
            }

            return -1;
        }

        return process.ExitCode;
    }

    private static bool IsAcceptableInstallerExitCode(int exitCode)
    {
        return exitCode is 0 or 1641 or 3010;
    }

    private static bool IsWingetAvailable()
    {
        try
        {
            return RunProcess("winget", "--version", timeout: TimeSpan.FromSeconds(20)) == 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsAdministrator()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static List<PrerequisiteSpec> GetMissingPrerequisites()
    {
        var missing = new List<PrerequisiteSpec>();
        foreach (var prerequisite in RequiredPrerequisites)
        {
            if (!SafeIsInstalled(prerequisite))
            {
                missing.Add(prerequisite);
            }
        }

        return missing;
    }

    private static bool SafeIsInstalled(PrerequisiteSpec prerequisite)
    {
        try
        {
            return prerequisite.IsInstalled();
        }
        catch
        {
            return false;
        }
    }

    private static bool IsWinFspInstalled()
    {
        using var serviceKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinFsp.Launcher");
        if (serviceKey is not null)
        {
            return true;
        }

        var programFilesPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinFsp", "bin", "launchctl-x64.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WinFsp", "bin", "launchctl-x64.exe"),
        };

        return programFilesPaths.Any(File.Exists);
    }

    private static bool IsVcRuntimeInstalled()
    {
        using var key64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(@"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64");

        if (key64 is null)
        {
            return false;
        }

        return (key64.GetValue("Installed") as int?) == 1;
    }

    private static void ShowManualGuidance(IReadOnlyList<PrerequisiteSpec> missing)
    {
        if (missing.Count == 0)
        {
            return;
        }

        foreach (var prerequisite in missing)
        {
            TryOpenUrl(prerequisite.ManualUrl);
        }

        var message = new StringBuilder();
        message.AppendLine("APFS Access could not complete automatic setup.");
        message.AppendLine("Official download pages were opened in your browser.");
        message.AppendLine();
        message.AppendLine("Please install these components, then run APFSAccess_Portable.exe again:");
        foreach (var prerequisite in missing)
        {
            message.AppendLine($"- {prerequisite.DisplayName}");
        }

        MessageBox.Show(
            message.ToString(),
            LauncherDisplayName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
    }

    private static void TryOpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true,
            });
        }
        catch
        {
            // No-op.
        }
    }

    private static byte[] LoadPayloadBytes()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var embeddedStream = assembly.GetManifestResourceStream(EmbeddedPayloadResourceName);
        if (embeddedStream is not null)
        {
            using var memory = new MemoryStream();
            embeddedStream.CopyTo(memory);
            return memory.ToArray();
        }

        var adjacentPayloadPath = Path.Combine(AppContext.BaseDirectory, AdjacentPayloadFileName);
        if (File.Exists(adjacentPayloadPath))
        {
            return File.ReadAllBytes(adjacentPayloadPath);
        }

        throw new InvalidOperationException(
            "Portable payload is missing. Rebuild with build/publish.ps1 so the launcher embeds the click-run package."
        );
    }

    private static string ExtractPayload(byte[] payloadBytes)
    {
        var payloadHash = ComputeSha256(payloadBytes)[..16];
        var rootPath = ResolvePortableRoot();
        var targetPath = Path.Combine(rootPath, $"payload-{payloadHash}");
        var markerPath = Path.Combine(targetPath, ".payload.sha256");
        var trayPath = Path.Combine(targetPath, "ApfsAccess.Tray.exe");

        Directory.CreateDirectory(rootPath);

        if (File.Exists(markerPath) &&
            File.Exists(trayPath) &&
            string.Equals(File.ReadAllText(markerPath).Trim(), payloadHash, StringComparison.OrdinalIgnoreCase))
        {
            return targetPath;
        }

        var stagingPath = Path.Combine(rootPath, $"staging-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingPath);

        try
        {
            using var memory = new MemoryStream(payloadBytes);
            using var archive = new ZipArchive(memory, ZipArchiveMode.Read, leaveOpen: false);
            archive.ExtractToDirectory(stagingPath, overwriteFiles: true);
            File.WriteAllText(Path.Combine(stagingPath, ".payload.sha256"), payloadHash, Encoding.UTF8);

            if (Directory.Exists(targetPath))
            {
                Directory.Delete(targetPath, recursive: true);
            }

            Directory.Move(stagingPath, targetPath);
            return targetPath;
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                try
                {
                    Directory.Delete(stagingPath, recursive: true);
                }
                catch
                {
                    // Keep original exception.
                }
            }

            throw;
        }
    }

    private static string ResolvePortableRoot()
    {
        var overrideRoot = Environment.GetEnvironmentVariable("APFSACCESS_PORTABLE_ROOT");
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            return Path.GetFullPath(overrideRoot);
        }

        var launcherPath = Environment.ProcessPath ?? Application.ExecutablePath;
        var launcherDirectory = string.IsNullOrWhiteSpace(launcherPath)
            ? null
            : Path.GetDirectoryName(launcherPath);
        if (!string.IsNullOrWhiteSpace(launcherDirectory) && Directory.Exists(launcherDirectory))
        {
            return Path.Combine(launcherDirectory, ".apfsaccess-portable");
        }

        var baseDirectory = AppContext.BaseDirectory;
        if (!string.IsNullOrWhiteSpace(baseDirectory) && Directory.Exists(baseDirectory))
        {
            return Path.Combine(baseDirectory, ".apfsaccess-portable");
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ApfsAccessPortable"
        );
    }

    private static void LaunchTray(string extractionDirectory)
    {
        var trayPath = Path.Combine(extractionDirectory, "ApfsAccess.Tray.exe");
        if (!File.Exists(trayPath))
        {
            throw new FileNotFoundException($"Tray executable not found at '{trayPath}'.");
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = trayPath,
            WorkingDirectory = extractionDirectory,
            UseShellExecute = true,
        });
    }

    private static string ComputeSha256(byte[] bytes)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }

    private static void ShowError(string detail)
    {
        MessageBox.Show(
            detail,
            LauncherDisplayName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Error
        );
    }

    private sealed record PrerequisiteSpec(
        string Key,
        string DisplayName,
        string WingetId,
        string ManualUrl,
        Func<bool> IsInstalled);
}
