using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace ApfsAccess.Bootstrap;

internal static class Program
{
    private const string EmbeddedPayloadResourceName = "ApfsAccess.Bootstrap.Payload.click-run.zip";
    private const string AdjacentPayloadFileName = "click-run-payload.zip";
    private const string LauncherDisplayName = "APFS Access Portable";
    private const string InstallModeArgument = "--install-prereqs";
    private const int RestartRequiredExitCode = 4;
    private const string VcRedistDirectUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
    private const string WinFspDirectUrl = "https://github.com/winfsp/winfsp/releases/download/v2.2B4/winfsp-2.2.26215.msi";
    private const string WinFspDirectSha256 = "2ECB5C89405488A95BBD8A01875E02C48534FD37BBDFD84488F7590464D65944";
    private const int MinimumWinFspMajor = 2;
    private const int MinimumWinFspMinor = 2;
    private const int MinimumWinFspBuild = 26215;
    private static bool _restartRequired;

    private static readonly IReadOnlyList<PrerequisiteSpec> RequiredPrerequisites =
    [
        new(
            Key: "winfsp",
            DisplayName: "WinFsp filesystem runtime update",
            WingetId: string.Empty,
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

            var extractionDirectory = ShouldUseAdjacentClickRunDirectory()
                ? ResolveAdjacentClickRunDirectory()
                : null;
            if (string.IsNullOrWhiteSpace(extractionDirectory))
            {
                var payloadBytes = LoadPayloadBytes();
                extractionDirectory = ExtractPayload(payloadBytes);
            }

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

        var installed = InstallMissingPrerequisitesWithUi();
        return _restartRequired ? RestartRequiredExitCode : installed ? 0 : 3;
    }

    private static void EnsurePrerequisitesInteractive()
    {
        var missing = GetMissingPrerequisites();
        if (_restartRequired)
        {
            ShowWinFspRestartRequired();
            throw new OperationCanceledException("Windows must restart before APFS Access can run.");
        }
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

        bool installSucceeded;
        if (IsAdministrator())
        {
            installSucceeded = InstallMissingPrerequisitesWithUi();
            if (_restartRequired)
            {
                throw new OperationCanceledException("Windows must restart before APFS Access can run.");
            }
        }
        else
        {
            var installerExitCode = RunElevatedInstaller();
            if (installerExitCode == RestartRequiredExitCode)
            {
                throw new OperationCanceledException("Windows must restart before APFS Access can run.");
            }
            installSucceeded = installerExitCode == 0;
        }

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
        if (_restartRequired)
        {
            ShowWinFspRestartRequired();
            return false;
        }
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

        if (_restartRequired)
        {
            ShowWinFspRestartRequired();
            return false;
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
        return RecordInstallerExitCode(exitCode);
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
        var msiPath = DownloadToTempFile(WinFspDirectUrl, "winfsp-2.2.26215.msi");
        var downloadedHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(msiPath)));
        if (!string.Equals(downloadedHash, WinFspDirectSha256, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var exitCode = RunProcess(
            "msiexec.exe",
            BuildWinFspInstallerArguments(msiPath),
            timeout: TimeSpan.FromMinutes(10));
        var installed = RecordInstallerExitCode(exitCode);
        _restartRequired |= WinFspInstallRequiresRestart(exitCode);
        return installed;
    }

    private static bool InstallVcRedistFromDirectDownload()
    {
        var exePath = DownloadToTempFile(VcRedistDirectUrl, "vc_redist.x64.exe");
        var exitCode = RunProcess(exePath, "/install /passive /norestart", timeout: TimeSpan.FromMinutes(10));
        return RecordInstallerExitCode(exitCode) || exitCode == 1638;
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

    private static string BuildWinFspInstallerArguments(string msiPath)
        => $"/i \"{msiPath}\" /passive /norestart MSIRESTARTMANAGERCONTROL=Disable REBOOT=ReallySuppress";

    private static bool WinFspInstallRequiresRestart(int exitCode)
        => IsAcceptableInstallerExitCode(exitCode);

    private static bool IsRestartRequiredInstallerExitCode(int exitCode)
    {
        return exitCode is 1641 or 3010;
    }

    private static bool RecordInstallerExitCode(int exitCode)
    {
        _restartRequired |= IsRestartRequiredInstallerExitCode(exitCode);
        return IsAcceptableInstallerExitCode(exitCode);
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
        var binDirectories = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinFsp", "bin"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WinFsp", "bin"),
        };

        var bootUtc = CurrentBootUtc();
        foreach (var binDirectory in binDirectories)
        {
            var dllPath = Path.Combine(binDirectory, "winfsp-x64.dll");
            var driverPath = Path.Combine(binDirectory, "winfsp-x64.sys");
            var dllCreationUtc = File.Exists(dllPath)
                ? File.GetCreationTimeUtc(dllPath)
                : DateTime.MinValue;
            var driverCreationUtc = File.Exists(driverPath)
                ? File.GetCreationTimeUtc(driverPath)
                : DateTime.MinValue;
            if (RequiresRestartForWinFspRuntimeFileTimes(
                    dllCreationUtc,
                    driverCreationUtc,
                    bootUtc))
            {
                _restartRequired = true;
                return true;
            }
        }

        foreach (var binDirectory in binDirectories)
        {
            var dllPath = Path.Combine(binDirectory, "winfsp-x64.dll");
            var driverPath = Path.Combine(binDirectory, "winfsp-x64.sys");
            if (!TryReadWinFspFileVersion(dllPath, out var dllVersion) ||
                !TryReadWinFspFileVersion(driverPath, out var driverVersion) ||
                !IsMatchingSupportedWinFspFileVersions(
                    dllVersion.Major,
                    dllVersion.Minor,
                    dllVersion.Build,
                    dllVersion.Revision,
                    driverVersion.Major,
                    driverVersion.Minor,
                    driverVersion.Build,
                    driverVersion.Revision) ||
                !IsActiveWinFspServiceVersionCompatible(
                    dllPath,
                    dllVersion.Major,
                    dllVersion.Minor))
            {
                continue;
            }

            if (RequiresRestartForWinFspRuntimeFileTimes(
                    File.GetCreationTimeUtc(dllPath),
                    File.GetCreationTimeUtc(driverPath),
                    bootUtc))
            {
                _restartRequired = true;
                return true;
            }

            return true;
        }

        return false;
    }

    private static bool TryReadWinFspFileVersion(string path, out WinFspFileVersion version)
    {
        version = default;
        if (!File.Exists(path))
        {
            return false;
        }

        var fileVersion = FileVersionInfo.GetVersionInfo(path);
        version = new WinFspFileVersion(
            fileVersion.FileMajorPart,
            fileVersion.FileMinorPart,
            fileVersion.FileBuildPart,
            fileVersion.FilePrivatePart);
        return true;
    }

    private static bool IsMatchingSupportedWinFspFileVersions(
        int dllMajor,
        int dllMinor,
        int dllBuild,
        int dllRevision,
        int driverMajor,
        int driverMinor,
        int driverBuild,
        int driverRevision)
    {
        if (dllMajor != driverMajor ||
            dllMinor != driverMinor ||
            dllBuild != driverBuild ||
            dllRevision != driverRevision)
        {
            return false;
        }

        return IsSupportedWinFspVersion(
            dllMajor,
            dllMinor,
            dllBuild);
    }

    private static bool IsActiveWinFspServiceVersionCompatible(
        string dllPath,
        int expectedMajor,
        int expectedMinor)
    {
        nint module = 0;
        try
        {
            module = NativeLibrary.Load(dllPath);
            var export = NativeLibrary.GetExport(module, "FspFsctlServiceVersion");
            var serviceVersion = Marshal.GetDelegateForFunctionPointer<FspFsctlServiceVersionDelegate>(export);
            var status = serviceVersion(out var encodedVersion);
            if (status < 0)
            {
                return false;
            }

            var activeMajor = (int)(encodedVersion >> 16);
            var activeMinor = (int)(encodedVersion & 0xffffu);
            return activeMajor == expectedMajor && activeMinor == expectedMinor;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (module != 0)
            {
                NativeLibrary.Free(module);
            }
        }
    }

    private static bool IsSupportedWinFspVersion(int major, int minor, int build)
        => major > MinimumWinFspMajor ||
           major == MinimumWinFspMajor &&
           (minor > MinimumWinFspMinor ||
            minor == MinimumWinFspMinor && build >= MinimumWinFspBuild);

    private static DateTime CurrentBootUtc()
        => DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

    private static bool RequiresRestartForWinFspRuntimeFileTimes(
        DateTime dllCreationUtc,
        DateTime driverCreationUtc,
        DateTime bootUtc)
        => dllCreationUtc >= bootUtc || driverCreationUtc >= bootUtc;

    private static void ShowWinFspRestartRequired()
    {
        MessageBox.Show(
            "WinFsp was installed or updated after Windows started. Restart Windows once before APFS Access mounts a drive. The app will not reinstall WinFsp while this restart is pending.",
            LauncherDisplayName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
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
        message.AppendLine("Please install these components, then run APFS Access.exe again:");
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

    private static bool ShouldUseAdjacentClickRunDirectory()
        => string.Equals(
            Environment.GetEnvironmentVariable("APFSACCESS_USE_ADJACENT_CLICK_RUN"),
            "1",
            StringComparison.OrdinalIgnoreCase);

    private static string? ResolveAdjacentClickRunDirectory()
    {
        var launcherPath = Environment.ProcessPath ?? Application.ExecutablePath;
        var launcherDirectory = string.IsNullOrWhiteSpace(launcherPath)
            ? AppContext.BaseDirectory
            : Path.GetDirectoryName(launcherPath);
        if (string.IsNullOrWhiteSpace(launcherDirectory))
        {
            return null;
        }

        var candidates = new[]
        {
            Path.Combine(launcherDirectory, "artifacts", "publish", "click-run"),
            Path.Combine(launcherDirectory, "click-run"),
        };

        foreach (var candidate in candidates)
        {
            var trayPath = Path.Combine(candidate, "ApfsAccess.Tray.exe");
            if (File.Exists(trayPath))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string ExtractPayload(byte[] payloadBytes)
    {
        var payloadHash = ComputeSha256(payloadBytes)[..16];
        Exception? lastError = null;
        foreach (var rootPath in ResolvePortableRootCandidates())
        {
            try
            {
                var existingPayload = TryFindExistingPayloadDirectory(rootPath, payloadHash);
                if (!string.IsNullOrWhiteSpace(existingPayload))
                {
                    return existingPayload;
                }

                return ExtractPayloadToRoot(payloadBytes, payloadHash, rootPath);
            }
            catch (Exception ex) when (IsRecoverableExtractionError(ex))
            {
                lastError = ex;
            }
        }

        throw new InvalidOperationException("APFS Access could not prepare its portable app files.", lastError);
    }

    private static string ExtractPayloadToRoot(byte[] payloadBytes, string payloadHash, string rootPath)
    {
        Directory.CreateDirectory(rootPath);

        var targetPath = Path.Combine(rootPath, $"payload-{payloadHash}");
        var stagingPath = Path.Combine(rootPath, $"staging-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingPath);

        try
        {
            using var memory = new MemoryStream(payloadBytes);
            using var archive = new ZipArchive(memory, ZipArchiveMode.Read, leaveOpen: false);
            archive.ExtractToDirectory(stagingPath, overwriteFiles: true);
            File.WriteAllText(Path.Combine(stagingPath, ".payload.sha256"), payloadHash, Encoding.UTF8);

            var finalPath = Directory.Exists(targetPath)
                ? Path.Combine(rootPath, $"payload-{payloadHash}-{Guid.NewGuid():N}")
                : targetPath;
            Directory.Move(stagingPath, finalPath);
            return finalPath;
        }
        finally
        {
            DeleteDirectoryBestEffort(stagingPath);
        }
    }

    private static string? TryFindExistingPayloadDirectory(string rootPath, string payloadHash)
    {
        if (!Directory.Exists(rootPath))
        {
            return null;
        }

        foreach (var candidate in Directory.EnumerateDirectories(rootPath, $"payload-{payloadHash}*"))
        {
            var markerPath = Path.Combine(candidate, ".payload.sha256");
            var trayPath = Path.Combine(candidate, "ApfsAccess.Tray.exe");
            if (File.Exists(markerPath) &&
                File.Exists(trayPath) &&
                string.Equals(File.ReadAllText(markerPath).Trim(), payloadHash, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        return null;
    }

    private static IEnumerable<string> ResolvePortableRootCandidates()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in new[]
        {
            ResolvePortableRoot(),
            ResolveDriveScratchPortableRoot(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ApfsAccessPortable"),
        })
        {
            if (!string.IsNullOrWhiteSpace(candidate) && seen.Add(candidate))
            {
                yield return candidate;
            }
        }
    }

    private static string? ResolveDriveScratchPortableRoot()
    {
        var launcherPath = Environment.ProcessPath ?? Application.ExecutablePath;
        var launcherDirectory = string.IsNullOrWhiteSpace(launcherPath)
            ? AppContext.BaseDirectory
            : Path.GetDirectoryName(launcherPath);
        if (string.IsNullOrWhiteSpace(launcherDirectory))
        {
            return null;
        }

        var root = Path.GetPathRoot(launcherDirectory);
        return string.IsNullOrWhiteSpace(root)
            ? null
            : Path.Combine(root, "ApfsAccessScratch", "PortablePayload");
    }

    private static bool IsRecoverableExtractionError(Exception ex)
        => ex is IOException or UnauthorizedAccessException or InvalidDataException;

    private static void DeleteDirectoryBestEffort(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // Best effort cleanup; a later launch can use another staging folder.
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
        ConfigureRuntimeScratchEnvironment();

        var trayPath = Path.Combine(extractionDirectory, "ApfsAccess.Tray.exe");
        if (!File.Exists(trayPath))
        {
            throw new FileNotFoundException($"Tray executable not found at '{trayPath}'.");
        }

        var psi = new ProcessStartInfo
        {
            FileName = trayPath,
            WorkingDirectory = extractionDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.Environment["TEMP"] = Environment.GetEnvironmentVariable("TEMP") ?? Path.GetTempPath();
        psi.Environment["TMP"] = Environment.GetEnvironmentVariable("TMP") ?? Path.GetTempPath();
        psi.Environment["APFSACCESS_SPOOL_ROOT"] = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? string.Empty;
        psi.Environment["APFSACCESS_RUNTIME_ROOT"] = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT") ?? string.Empty;
        psi.Environment["APFSACCESS_TRACE_MOVES"] = Environment.GetEnvironmentVariable("APFSACCESS_TRACE_MOVES") ?? string.Empty;
        psi.Environment["APFSACCESS_PERF_COUNTERS"] = Environment.GetEnvironmentVariable("APFSACCESS_PERF_COUNTERS") ?? string.Empty;
        psi.Environment["APFSACCESS_TRACE_COMMITS"] = Environment.GetEnvironmentVariable("APFSACCESS_TRACE_COMMITS") ?? string.Empty;
        psi.Environment["APFSACCESS_TRACE_READS"] = Environment.GetEnvironmentVariable("APFSACCESS_TRACE_READS") ?? string.Empty;
        psi.Environment["APFSACCESS_DEFER_CLOSE_COMMITS"] = Environment.GetEnvironmentVariable("APFSACCESS_DEFER_CLOSE_COMMITS") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_CONTENT_WRITEBACK"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CONTENT_WRITEBACK") ?? string.Empty;
        psi.Environment["APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE"] = Environment.GetEnvironmentVariable("APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE") ?? string.Empty;
        psi.Environment["APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK"] = Environment.GetEnvironmentVariable("APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_NAMESPACE_WRITEBACK"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_NAMESPACE_WRITEBACK") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_ASYNC_BLOCK_IO"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_ASYNC_BLOCK_IO") ?? string.Empty;
        psi.Environment["APFSACCESS_ASYNC_BLOCK_IO_DEPTH"] = Environment.GetEnvironmentVariable("APFSACCESS_ASYNC_BLOCK_IO_DEPTH") ?? string.Empty;
        psi.Environment["APFSACCESS_CHECKPOINT_DELTA_SHADOW"] = Environment.GetEnvironmentVariable("APFSACCESS_CHECKPOINT_DELTA_SHADOW") ?? string.Empty;
        psi.Environment["APFSACCESS_STRICT_COMMIT_VERIFY"] = Environment.GetEnvironmentVariable("APFSACCESS_STRICT_COMMIT_VERIFY") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE") ?? string.Empty;
        psi.Environment["APFSACCESS_DISABLE_INDEX_DELTA"] = Environment.GetEnvironmentVariable("APFSACCESS_DISABLE_INDEX_DELTA") ?? string.Empty;
        psi.Environment["APFSACCESS_LAUNCHER_PATH"] = Environment.ProcessPath ?? Application.ExecutablePath;
        psi.Environment["APFSACCESS_UPDATE_TOKEN"] = Environment.GetEnvironmentVariable("APFSACCESS_UPDATE_TOKEN") ?? string.Empty;
        psi.Environment["APFSACCESS_UPDATE_EXPECTED_VERSION"] = Environment.GetEnvironmentVariable("APFSACCESS_UPDATE_EXPECTED_VERSION") ?? string.Empty;
        psi.Environment["APFSACCESS_UPDATE_RECEIPT_PATH"] = Environment.GetEnvironmentVariable("APFSACCESS_UPDATE_RECEIPT_PATH") ?? string.Empty;

        Process.Start(psi);
    }

    private static void ConfigureRuntimeScratchEnvironment()
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

    private readonly record struct WinFspFileVersion(int Major, int Minor, int Build, int Revision);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int FspFsctlServiceVersionDelegate(out uint version);
}
