using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli.Tests;

public sealed class PackagedServiceLauncherTests
{
    private static readonly string ArtifactRoot = Path.Combine(
        Path.GetTempPath(),
        "ApfsAccessTests",
        "PackagedServiceLauncher");

    [Fact]
    public async Task ChildReceivesSanitizedRuntimeEnvironmentAndPreservesBenignValues()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("environment");
        var packageRoot = Path.Combine(root, "package");
        CopyTestChildPackage(packageRoot);
        var resultPath = Path.Combine(root, "environment.json");
        var startupHookMarker = Path.Combine(root, "startup-hook.txt");
        var hostileNames = new[]
        {
            "DOTNET_STARTUP_HOOKS",
            "DOTNET_ADDITIONAL_DEPS",
            "DOTNET_SHARED_STORE",
            "DOTNET_ROOT_X64",
            "DOTNET_ROOT(x86)",
            "DOTNET_ROLL_FORWARD",
            "CORECLR_ENABLE_PROFILING",
            "CORECLR_PROFILER_PATH",
            "COR_ENABLE_PROFILING",
            "COR_PROFILER",
            "COMPlus_ReadyToRunExcludeList",
        };
        var startInfo = CreateProbeStartInfo(packageRoot, "environment", resultPath);
        startInfo.Environment["DOTNET_STARTUP_HOOKS"] = typeof(StartupHook).Assembly.Location;
        startInfo.Environment["DOTNET_ADDITIONAL_DEPS"] = Path.Combine(packageRoot, "ApfsAccess.Cli.TestChild.deps.json");
        startInfo.Environment["DOTNET_SHARED_STORE"] = packageRoot;
        startInfo.Environment["DOTNET_ROOT_X64"] = packageRoot;
        startInfo.Environment["DOTNET_ROOT(x86)"] = packageRoot;
        startInfo.Environment["DOTNET_ROLL_FORWARD"] = "LatestMajor";
        startInfo.Environment["CORECLR_ENABLE_PROFILING"] = "0";
        startInfo.Environment["CORECLR_PROFILER_PATH"] = Path.Combine(root, "profiler.dll");
        startInfo.Environment["COR_ENABLE_PROFILING"] = "0";
        startInfo.Environment["COR_PROFILER"] = "{11111111-1111-1111-1111-111111111111}";
        startInfo.Environment["COMPlus_ReadyToRunExcludeList"] = "ApfsAccess.Service";
        startInfo.Environment["APFSACCESS_TEST_STARTUP_HOOK_MARKER"] = startupHookMarker;
        startInfo.Environment["APFSACCESS_TRACE_MOVES"] = "1";
        startInfo.Environment["PACKAGED_SERVICE_BENIGN"] = "preserved";
        startInfo.Environment["PATH"] = root;
        startInfo.Environment["PATHEXT"] = ".HOSTILE";
        startInfo.Environment["COMSPEC"] = Path.Combine(root, "hostile.exe");

        Process? child = null;
        try
        {
            child = Process.GetProcessById(PackagedServiceLauncher.Start(startInfo));
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
            Assert.Equal(0, child.ExitCode);
            Assert.False(File.Exists(startupHookMarker));

            using var result = JsonDocument.Parse(await File.ReadAllTextAsync(resultPath));
            foreach (var hostileName in hostileNames)
            {
                Assert.Equal(JsonValueKind.Null, result.RootElement.GetProperty(hostileName).ValueKind);
            }

            Assert.Equal(JsonValueKind.Null, result.RootElement.GetProperty("APFSACCESS_TEST_STARTUP_HOOK_MARKER").ValueKind);
            Assert.Equal("1", result.RootElement.GetProperty("APFSACCESS_TRACE_MOVES").GetString());
            Assert.Equal(JsonValueKind.Null, result.RootElement.GetProperty("PACKAGED_SERVICE_BENIGN").ValueKind);
            Assert.NotEqual(root, result.RootElement.GetProperty("PATH").GetString());
            Assert.NotEqual(".HOSTILE", result.RootElement.GetProperty("PATHEXT").GetString());
            Assert.NotEqual(Path.Combine(root, "hostile.exe"), result.RootElement.GetProperty("COMSPEC").GetString());
        }
        finally
        {
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5_000);
            }

            child?.Dispose();
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public async Task ServiceLikeChildSurvivesSoleOwnerJobCloseWhileOrdinaryChildDies()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("breakaway");
        var pwshPath = GetPowerShellPath();
        var packageRoot = Path.Combine(root, "package");
        CopyTestChildPackage(packageRoot);
        var servicePath = Path.Combine(packageRoot, "ApfsAccess.Cli.TestChild.exe");
        var readyPath = Path.Combine(root, "ready.json");
        var serviceLaunchPath = readyPath + ".service-launch";
        var serviceAcceptedPath = readyPath + ".service-accepted";
        var ordinaryChildScriptPath = Path.Combine(root, "ordinary-child.ps1");
        var cliAssemblyPath = typeof(PackagedServiceLauncher).Assembly.Location;
        var jobName = $@"Local\ApfsAccess.Cli.ServiceBreakaway.{Guid.NewGuid():N}";
        var ordinaryChildScript = $$"""
            $ErrorActionPreference = 'Stop'
            $assembly = [Reflection.Assembly]::LoadFrom('{{PowerShellLiteral(cliAssemblyPath)}}')
            $transport = $assembly.GetType('ApfsAccess.Cli.CliElevationTransport', $true)
            $open = $transport.GetMethod('OpenJob', [Reflection.BindingFlags]'Static,NonPublic')
            $job = $open.Invoke($null, @('{{PowerShellLiteral(jobName)}}'))
            $jobType = $job.GetType()
            $null = $jobType.GetMethod('AssignCurrentProcess').Invoke($job, @())
            $null = $jobType.GetMethod('Dispose').Invoke($job, @())

            $launcher = $assembly.GetType('ApfsAccess.Cli.PackagedServiceLauncher', $true)
            $start = $launcher.GetMethod('Start', [Reflection.BindingFlags]'Static,NonPublic')
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = '{{PowerShellLiteral(servicePath)}}'
            $startInfo.WorkingDirectory = '{{PowerShellLiteral(packageRoot)}}'
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.ArgumentList.Add('--probe')
            $startInfo.ArgumentList.Add('service')
            $startInfo.ArgumentList.Add('--result-path')
            $startInfo.ArgumentList.Add('{{PowerShellLiteral(readyPath)}}.service')
            $startInfo.ArgumentList.Add('--accepted-path')
            $startInfo.ArgumentList.Add('{{PowerShellLiteral(serviceAcceptedPath)}}')
            $servicePid = [int]$start.Invoke($null, @($startInfo))
            $service = [Diagnostics.Process]::GetProcessById($servicePid)
            $serviceEvidence = [ordered]@{
                processId = $servicePid
                startTimeUtcTicks = $service.StartTime.ToUniversalTime().Ticks
                imagePath = $service.MainModule.FileName
            }
            $serviceTemporary = '{{PowerShellLiteral(serviceLaunchPath)}}.tmp'
            [IO.File]::WriteAllText($serviceTemporary, ($serviceEvidence | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
            [IO.File]::Move($serviceTemporary, '{{PowerShellLiteral(serviceLaunchPath)}}')
            $self = [Diagnostics.Process]::GetCurrentProcess()
            $evidence = [ordered]@{
                ordinaryProcessId = $PID
                ordinaryStartTimeUtcTicks = $self.StartTime.ToUniversalTime().Ticks
                ordinaryImagePath = $self.MainModule.FileName
                serviceProcessId = $servicePid
                serviceStartTimeUtcTicks = $service.StartTime.ToUniversalTime().Ticks
                serviceImagePath = $service.MainModule.FileName
            }
            $temporary = '{{PowerShellLiteral(readyPath)}}.tmp'
            [IO.File]::WriteAllText($temporary, ($evidence | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
            [IO.File]::Move($temporary, '{{PowerShellLiteral(readyPath)}}')
            while ($true) { Start-Sleep -Milliseconds 100 }
            """;

        await File.WriteAllTextAsync(ordinaryChildScriptPath, ordinaryChildScript, new UTF8Encoding(false));
        using var job = CliElevationTransport.CreateJob(jobName);
        using var ordinaryOwner = StartPowerShellFile(pwshPath, ordinaryChildScriptPath);
        ProcessEvidence? ordinary = null;
        ProcessEvidence? service = null;
        try
        {
            await WaitForFileAsync(readyPath, ordinaryOwner, TimeSpan.FromSeconds(15));
            using (var ready = JsonDocument.Parse(await File.ReadAllTextAsync(readyPath)))
            {
                ordinary = ReadProcessEvidence(ready.RootElement, "ordinary");
                service = ReadProcessEvidence(ready.RootElement, "service");
            }
            await File.WriteAllTextAsync(serviceAcceptedPath, "accepted", new UTF8Encoding(false));

            Assert.True(IsExactProcessRunning(ordinary), "The ordinary job child was not running before owner close.");
            Assert.True(IsExactProcessRunning(service), "The Service-like child was not running before owner close.");

            job.Dispose();

            await WaitForExactAbsenceAsync(ordinary, TimeSpan.FromSeconds(5));
            await Task.Delay(500);
            Assert.True(
                IsExactProcessRunning(service),
                "The explicitly launched Service-like child remained in the CLI kill-on-close job.");
        }
        finally
        {
            job.Dispose();
            if (!ordinaryOwner.HasExited)
            {
                ordinaryOwner.Kill(entireProcessTree: true);
                ordinaryOwner.WaitForExit(5_000);
            }

            service ??= TryReadProcessEvidence(serviceLaunchPath);
            TryKillExactProcessTree(service);
            TryKillExactProcessTree(ordinary);
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public async Task ExistingRuntimeConfigCannotBeReplacedUntilLaunchedChildExits()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("package-lease");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(packageRoot);
        CopyCliPackage(packageRoot);
        var executablePath = Path.Combine(packageRoot, "ApfsAccess.Cli.exe");
        var dependencyPath = Path.Combine(packageRoot, "ApfsAccess.Cli.runtimeconfig.json");
        var movedDependencyPath = dependencyPath + ".replacement";
        var startInfo = new ProcessStartInfo(executablePath)
        {
            WorkingDirectory = packageRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("status");
        startInfo.ArgumentList.Add("--pipe-name");
        startInfo.ArgumentList.Add("ApfsAccess.Cli.PackageLease." + Guid.NewGuid().ToString("N"));
        startInfo.ArgumentList.Add("--no-start-service");
        startInfo.ArgumentList.Add("--timeout-ms");
        startInfo.ArgumentList.Add("3000");

        Process? child = null;
        try
        {
            var processId = PackagedServiceLauncher.Start(startInfo);
            child = Process.GetProcessById(processId);
            Assert.False(child.HasExited);

            _ = Assert.Throws<IOException>(() => File.Move(dependencyPath, movedDependencyPath));
            Assert.True(File.Exists(dependencyPath));
            Assert.False(File.Exists(movedDependencyPath));

            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            File.Move(dependencyPath, movedDependencyPath);
            Assert.True(File.Exists(movedDependencyPath));
        }
        finally
        {
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5_000);
            }

            child?.Dispose();
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public async Task ProvisionalStartupDisposalTerminatesTheExactUnreadyChild()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("provisional-startup");
        var packageRoot = Path.Combine(root, "package");
        CopyTestChildPackage(packageRoot);
        var resultPath = Path.Combine(root, "child.json");
        var startInfo = new ProcessStartInfo(Path.Combine(packageRoot, "ApfsAccess.Cli.TestChild.exe"))
        {
            WorkingDirectory = packageRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--result-path");
        startInfo.ArgumentList.Add(resultPath);
        startInfo.ArgumentList.Add("--sleep-ms");
        startInfo.ArgumentList.Add("5000");

        PackagedServiceStartup? startup = null;
        Process? child = null;
        ProcessEvidence? evidence = null;
        try
        {
            startup = PackagedServiceLauncher.StartOwned(startInfo);
            child = Process.GetProcessById(startup.Started.ProcessId);
            await WaitForFileAsync(resultPath, child, TimeSpan.FromSeconds(10));
            evidence = new ProcessEvidence(
                startup.Started.ProcessId,
                startup.Started.StartTimeUtcTicks,
                startup.Started.ImagePath);
            Assert.True(IsExactProcessRunning(evidence));

            startup.Dispose();
            startup = null;

            await WaitForExactAbsenceAsync(evidence, TimeSpan.FromSeconds(5));
        }
        finally
        {
            startup?.Dispose();
            child?.Dispose();
            TryKillExactProcessTree(evidence);
            DeleteDirectoryAndVerify(root);
        }
    }

    [Fact]
    public async Task DevelopmentRuntimeConfigCannotBeCreatedOrReplacedWhileChildRuns()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("development-runtimeconfig");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(packageRoot);
        CopyCliPackage(packageRoot);
        var executablePath = Path.Combine(packageRoot, "ApfsAccess.Cli.exe");
        var developmentRuntimeConfig = Path.Combine(packageRoot, "ApfsAccess.Cli.runtimeconfig.dev.json");
        var replacementPath = developmentRuntimeConfig + ".replacement";
        var startInfo = new ProcessStartInfo(executablePath)
        {
            WorkingDirectory = packageRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("status");
        startInfo.ArgumentList.Add("--pipe-name");
        startInfo.ArgumentList.Add("ApfsAccess.Cli.DevRuntimeConfig." + Guid.NewGuid().ToString("N"));
        startInfo.ArgumentList.Add("--no-start-service");
        startInfo.ArgumentList.Add("--timeout-ms");
        startInfo.ArgumentList.Add("5000");

        Process? child = null;
        try
        {
            child = Process.GetProcessById(PackagedServiceLauncher.Start(startInfo));
            Assert.False(child.HasExited);

            _ = Assert.Throws<IOException>(() => new FileStream(
                developmentRuntimeConfig,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None).Dispose());
            _ = Assert.Throws<IOException>(() => File.Move(developmentRuntimeConfig, replacementPath));
            _ = Assert.Throws<IOException>(() => File.WriteAllText(developmentRuntimeConfig, "hostile"));

            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(3, child.ExitCode);

            await using (var created = new FileStream(
                developmentRuntimeConfig,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None))
            {
                await created.WriteAsync("hostile"u8.ToArray());
            }

            Assert.Equal("hostile", await File.ReadAllTextAsync(developmentRuntimeConfig));
        }
        finally
        {
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5_000);
            }

            child?.Dispose();
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public async Task GrandchildCannotInheritOrExtendPackageLocks()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("grandchild-lock");
        var packageRoot = Path.Combine(root, "package");
        CopyTestChildPackage(packageRoot);
        var dependencyPath = Path.Combine(packageRoot, "ApfsAccess.Cli.TestChild.runtimeconfig.json");
        var movedDependencyPath = dependencyPath + ".replacement";
        var readyPath = Path.Combine(root, "ready.json");
        var releasePath = Path.Combine(root, "release.txt");
        var startInfo = CreateProbeStartInfo(packageRoot, "grandchild", readyPath);
        startInfo.ArgumentList.Add("--release-path");
        startInfo.ArgumentList.Add(releasePath);

        Process? child = null;
        ProcessEvidence? grandchild = null;
        try
        {
            child = Process.GetProcessById(PackagedServiceLauncher.Start(startInfo));
            await WaitForFileAsync(readyPath, child, TimeSpan.FromSeconds(15));
            grandchild = TryReadProcessEvidence(readyPath);
            Assert.NotNull(grandchild);
            using var ready = JsonDocument.Parse(await File.ReadAllTextAsync(readyPath));
            Assert.True(ready.RootElement.GetProperty("inheritedSentinel").GetBoolean());

            Assert.True(IsExactProcessRunning(grandchild));
            _ = Assert.Throws<IOException>(() => File.Move(dependencyPath, movedDependencyPath));

            await File.WriteAllTextAsync(releasePath, "release");
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            await WaitForExactAbsenceAsync(grandchild, TimeSpan.FromSeconds(5));

            File.Move(dependencyPath, movedDependencyPath);
            Assert.True(File.Exists(movedDependencyPath));
        }
        finally
        {
            TryKillExactProcessTree(grandchild);
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5_000);
            }

            child?.Dispose();
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public void ManagedServiceApphostWithoutStableAdjacentCompanionsIsRejectedBeforeLaunch()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("incomplete-package");
        var source = Path.Combine(Path.GetDirectoryName(typeof(Program).Assembly.Location)!, "ApfsAccess.Cli.exe");
        var servicePath = Path.Combine(root, "ApfsAccess.Service.exe");
        File.Copy(source, servicePath);
        var startInfo = new ProcessStartInfo(servicePath)
        {
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("version");

        try
        {
            _ = Assert.Throws<CliElevationValidationException>(() => PackagedServiceLauncher.Start(startInfo));
        }
        finally
        {
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public void PackageLeaseCapturesCanonicalHashFileIdAndStableCompanionIdentities()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("identity");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(packageRoot);
        CopyCliPackage(packageRoot);
        var executablePath = Path.Combine(packageRoot, "ApfsAccess.Cli.exe");
        var leaseType = typeof(Program).Assembly.GetType("ApfsAccess.Cli.PackagedServicePackageLease");

        try
        {
            Assert.NotNull(leaseType);
            var acquire = leaseType!.GetMethod("Acquire", BindingFlags.Static | BindingFlags.NonPublic);
            Assert.NotNull(acquire);
            using var lease = Assert.IsAssignableFrom<IDisposable>(acquire!.Invoke(null, new object[] { executablePath }));
            var identity = leaseType.GetProperty("Identity", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(lease);
            Assert.NotNull(identity);
            var identityType = identity!.GetType();
            var appHost = identityType.GetProperty("AppHost")!.GetValue(identity)!;
            var appHostType = appHost.GetType();
            Assert.Equal(Path.GetFullPath(executablePath), (string?)appHostType.GetProperty("CanonicalPath")!.GetValue(appHost), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(new FileInfo(executablePath).Length, appHostType.GetProperty("Length")!.GetValue(appHost));
            Assert.Equal(
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executablePath))),
                appHostType.GetProperty("Sha256")!.GetValue(appHost));
            Assert.False(string.IsNullOrWhiteSpace((string?)appHostType.GetProperty("LaunchIdentity")!.GetValue(appHost)));

            var companions = Assert.IsAssignableFrom<System.Collections.IEnumerable>(
                identityType.GetProperty("Companions")!.GetValue(identity));
            var companionNames = companions.Cast<object>()
                .Select(item => Path.GetFileName((string)item.GetType().GetProperty("CanonicalPath")!.GetValue(item)!))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains("ApfsAccess.Cli.dll", companionNames);
            Assert.Contains("ApfsAccess.Cli.deps.json", companionNames);
            Assert.Contains("ApfsAccess.Cli.runtimeconfig.json", companionNames);
            Assert.Contains("ApfsAccess.Core.dll", companionNames);
            Assert.Contains("ApfsAccess.Ipc.dll", companionNames);
        }
        finally
        {
            TryDeleteDirectory(root);
        }
    }

    [Fact]
    public void PackageLeaseRejectsAWriterThatPredatesValidation()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("preexisting-writer");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(packageRoot);
        CopyCliPackage(packageRoot);
        var executablePath = Path.Combine(packageRoot, "ApfsAccess.Cli.exe");

        try
        {
            using var writer = new FileStream(
                executablePath,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.ReadWrite | FileShare.Delete);

            _ = Assert.Throws<IOException>(() => PackagedServicePackageLease.Acquire(executablePath));
        }
        finally
        {
            DeleteDirectoryAndVerify(root);
        }
    }

    [Fact]
    public void PackageLeaseRevalidatesEveryUnchangedLaunchIdentity()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("revalidate");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(packageRoot);
        CopyCliPackage(packageRoot);

        try
        {
            using var lease = PackagedServicePackageLease.Acquire(
                Path.Combine(packageRoot, "ApfsAccess.Cli.exe"));
            lease.Revalidate();
        }
        finally
        {
            DeleteDirectoryAndVerify(root);
        }
    }

    [Fact]
    public void LeaseCleanupAttemptsEveryDisposeAndReportsAllFailures()
    {
        var first = new TrackingDisposable(throws: false);
        var failing = new TrackingDisposable(throws: true);
        var last = new TrackingDisposable(throws: false);

        var error = Assert.Throws<AggregateException>(() =>
            PackagedServicePackageLease.DisposeAllForTest([first, failing, last]));

        Assert.True(first.Disposed);
        Assert.True(failing.Disposed);
        Assert.True(last.Disposed);
        Assert.Single(error.InnerExceptions);
    }

    [Fact]
    public async Task ExplicitHandleListDoesNotInheritUnrelatedInheritableHandle()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = CreateTestRoot("handle-isolation");
        var packageRoot = Path.Combine(root, "package");
        CopyTestChildPackage(packageRoot);
        var resultPath = Path.Combine(root, "sentinel.json");
        using var sentinel = File.OpenHandle(
            Path.Combine(root, "sentinel.bin"),
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.ReadWrite | FileShare.Delete);
        Assert.True(SetHandleInformation(sentinel, HandleFlagInherit, HandleFlagInherit));
        var sentinelValue = sentinel.DangerousGetHandle().ToInt64();
        var sentinelPath = Path.GetFullPath(Path.Combine(root, "sentinel.bin"));
        var startInfo = CreateProbeStartInfo(packageRoot, "handle", resultPath);
        startInfo.ArgumentList.Add("--handle");
        startInfo.ArgumentList.Add(sentinelValue.ToString(System.Globalization.CultureInfo.InvariantCulture));
        startInfo.ArgumentList.Add("--expected-path");
        startInfo.ArgumentList.Add(sentinelPath);

        Process? child = null;
        try
        {
            var processId = PackagedServiceLauncher.Start(startInfo);
            child = Process.GetProcessById(processId);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(0, child.ExitCode);
            using var result = JsonDocument.Parse(await File.ReadAllTextAsync(resultPath));
            Assert.False(result.RootElement.GetProperty("inheritedSentinel").GetBoolean());
        }
        finally
        {
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(5_000);
            }

            child?.Dispose();
            TryDeleteDirectory(root);
        }
    }

    private static string GetPowerShellPath()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "PowerShell",
            "7",
            "pwsh.exe");
        Assert.True(File.Exists(path), $"PowerShell 7 was not found at '{path}'.");
        return path;
    }

    private static string CreateTestRoot(string purpose)
    {
        var path = Path.Combine(ArtifactRoot, purpose + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static ProcessStartInfo CreateProbeStartInfo(string packageRoot, string probe, string resultPath)
    {
        var startInfo = new ProcessStartInfo(Path.Combine(packageRoot, "ApfsAccess.Cli.TestChild.exe"))
        {
            WorkingDirectory = packageRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--probe");
        startInfo.ArgumentList.Add(probe);
        startInfo.ArgumentList.Add("--result-path");
        startInfo.ArgumentList.Add(resultPath);
        return startInfo;
    }

    private static Process StartPowerShellFile(string pwshPath, string scriptPath)
    {
        var startInfo = new ProcessStartInfo(pwshPath)
        {
            WorkingDirectory = Path.GetDirectoryName(scriptPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(scriptPath);
        return Process.Start(startInfo)
           ?? throw new InvalidOperationException("Could not start the PowerShell test helper.");
    }

    private static string PowerShellLiteral(string value)
        => value.Replace("'", "''", StringComparison.Ordinal);

    private static async Task WaitForFileAsync(string path, Process owner, TimeSpan timeout)
    {
        var deadline = Stopwatch.GetTimestamp() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (File.Exists(path))
            {
                return;
            }

            if (owner.HasExited)
            {
                throw new Xunit.Sdk.XunitException($"The job owner exited before publishing readiness ({owner.ExitCode}).");
            }

            await Task.Delay(25);
        }

        throw new TimeoutException($"Timed out waiting for '{path}'.");
    }

    private static ProcessEvidence ReadProcessEvidence(JsonElement root, string prefix)
        => new(
            root.GetProperty(prefix + "ProcessId").GetInt32(),
            root.GetProperty(prefix + "StartTimeUtcTicks").GetInt64(),
            root.GetProperty(prefix + "ImagePath").GetString()!);

    private static bool IsExactProcessRunning(ProcessEvidence evidence)
    {
        try
        {
            using var process = Process.GetProcessById(evidence.ProcessId);
            return !process.HasExited &&
                   process.StartTime.ToUniversalTime().Ticks == evidence.StartTimeUtcTicks &&
                   string.Equals(process.MainModule?.FileName, evidence.ImagePath, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
        {
            return false;
        }
    }

    private static async Task WaitForExactAbsenceAsync(ProcessEvidence evidence, TimeSpan timeout)
    {
        var deadline = Stopwatch.GetTimestamp() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (!IsExactProcessRunning(evidence))
            {
                return;
            }

            await Task.Delay(25);
        }

        Assert.False(IsExactProcessRunning(evidence), $"Process {evidence.ProcessId} remained alive.");
    }

    private static void TryKillExactProcessTree(ProcessEvidence? evidence)
    {
        if (evidence is null || !IsExactProcessRunning(evidence))
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(evidence.ProcessId);
            if (process.StartTime.ToUniversalTime().Ticks != evidence.StartTimeUtcTicks ||
                !string.Equals(process.MainModule?.FileName, evidence.ImagePath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            process.Kill(entireProcessTree: true);
            if (!process.WaitForExit(5_000))
            {
                throw new TimeoutException($"Process {evidence.ProcessId} did not exit during test cleanup.");
            }

            Assert.False(IsExactProcessRunning(evidence), $"Process {evidence.ProcessId} remained after cleanup.");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
        {
            if (IsExactProcessRunning(evidence))
            {
                throw;
            }
        }
    }

    private static ProcessEvidence? TryReadProcessEvidence(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            return new ProcessEvidence(
                document.RootElement.GetProperty("processId").GetInt32(),
                document.RootElement.GetProperty("startTimeUtcTicks").GetInt64(),
                document.RootElement.GetProperty("imagePath").GetString()!);
        }
        catch (Exception ex) when (
            ex is FileNotFoundException or DirectoryNotFoundException or IOException or JsonException)
        {
            return null;
        }
    }

    private static void CopyCliPackage(string destination)
    {
        var source = Path.GetDirectoryName(typeof(Program).Assembly.Location)!;
        foreach (var file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), overwrite: false);
        }

        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.exe")));
        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.dll")));
        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.deps.json")));
        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.runtimeconfig.json")));
    }

    private static void CopyTestChildPackage(string destination)
    {
        Directory.CreateDirectory(destination);
        var source = Path.GetDirectoryName(typeof(Program).Assembly.Location)!;
        foreach (var file in Directory.EnumerateFiles(source, "ApfsAccess.Cli.TestChild*"))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), overwrite: false);
        }

        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.TestChild.exe")));
        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.TestChild.dll")));
        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.TestChild.deps.json")));
        Assert.True(File.Exists(Path.Combine(destination, "ApfsAccess.Cli.TestChild.runtimeconfig.json")));
    }

    private static void TryDeleteDirectory(string path)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                Assert.False(Directory.Exists(path), $"Test directory remained after cleanup: {path}");
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                lastError = ex;
                Thread.Sleep(25);
            }
        }

        throw new IOException($"Test directory could not be removed after bounded cleanup: {path}", lastError);
    }

    private static void DeleteDirectoryAndVerify(string path)
    {
        Directory.Delete(path, recursive: true);
        Assert.False(Directory.Exists(path), $"Test directory remained after cleanup: {path}");
    }

    private sealed class TrackingDisposable(bool throws) : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
            if (throws)
            {
                throw new IOException("Injected lease cleanup failure.");
            }
        }
    }

    private sealed record ProcessEvidence(int ProcessId, long StartTimeUtcTicks, string ImagePath);

    private const uint HandleFlagInherit = 0x00000001;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(
        SafeHandle handle,
        uint mask,
        uint flags);
}
