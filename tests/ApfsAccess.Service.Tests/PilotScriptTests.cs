using System.Diagnostics;
using System.Text.Json;

namespace ApfsAccess.Service.Tests;

public sealed class PilotScriptTests
{
    [Fact]
    public void UpdateWriteEvidence_AcceptsCommaSeparatedScenarioList_FromFileInvocation()
    {
        using var temp = TempDirectory.Create();
        var storePath = Path.Combine(temp.Path, "write-evidence.json");
        var profileId = @"raw::\\.\physicaldrive999::main";
        var volumeId = @"\\.\PhysicalDrive999|Main";

        var result = RunPowerShellScript(
            "update_write_evidence.ps1",
            "-ProfileId", profileId,
            "-VolumeId", volumeId,
            "-Scenario", "CrashFault,HardwarePilot,PowerLossVerified",
            "-Count", "2",
            "-EvidenceStorePath", storePath);

        Assert.True(
            result.ExitCode == 0,
            $"create_test_image.ps1 failed with exit code {result.ExitCode}.{Environment.NewLine}{result.Stdout}{Environment.NewLine}{result.Stderr}");
        using var document = JsonDocument.Parse(File.ReadAllText(storePath));
        var profile = document.RootElement.GetProperty("profiles").GetProperty(profileId);
        var volume = document.RootElement.GetProperty("volumes").GetProperty(volumeId);

        Assert.Equal(2, profile.GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal(2, profile.GetProperty("hardwarePilotPasses").GetInt32());
        Assert.True(profile.GetProperty("powerLossPassVerified").GetBoolean());
        Assert.Equal(2, volume.GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal(2, volume.GetProperty("hardwarePilotPasses").GetInt32());
        Assert.True(volume.GetProperty("powerLossPassVerified").GetBoolean());
    }

    [Fact]
    public void ImportValidationReport_PreservesCountersAcrossMultipleRows()
    {
        using var temp = TempDirectory.Create();
        var reportPath = Path.Combine(temp.Path, "validation-report.json");
        var storePath = Path.Combine(temp.Path, "write-evidence.json");
        var profileId = @"raw::\\.\physicaldrive999::main";
        var volumeId = @"\\.\PhysicalDrive999|Main";

        var reportJson = $$"""
        {
          "results": [
            {
              "profileId": "{{JsonEncodedText(profileId)}}",
              "volumeId": "{{JsonEncodedText(volumeId)}}",
              "scenario": "CrashFault",
              "passed": true,
              "count": 3,
              "validatedUtc": "2026-05-06T00:00:00Z"
            },
            {
              "profileId": "{{JsonEncodedText(profileId)}}",
              "volumeId": "{{JsonEncodedText(volumeId)}}",
              "scenario": "HardwarePilot",
              "passed": true,
              "count": 1,
              "validatedUtc": "2026-05-06T00:00:00Z"
            },
            {
              "profileId": "{{JsonEncodedText(profileId)}}",
              "volumeId": "{{JsonEncodedText(volumeId)}}",
              "scenario": "PowerLossVerified",
              "passed": true,
              "count": 1,
              "validatedUtc": "2026-05-06T00:00:00Z"
            },
            {
              "profileId": "{{JsonEncodedText(profileId)}}",
              "volumeId": "{{JsonEncodedText(volumeId)}}",
              "scenario": "HotUnplug",
              "passed": false,
              "count": 9,
              "validatedUtc": "2026-05-06T00:00:00Z"
            }
          ]
        }
        """;
        File.WriteAllText(reportPath, reportJson);

        var result = RunPowerShellScript(
            "import_validation_report.ps1",
            "-ReportPath", reportPath,
            "-EvidenceStorePath", storePath);

        Assert.True(
            result.ExitCode == 0,
            $"create_test_image.ps1 failed with exit code {result.ExitCode}.{Environment.NewLine}{result.Stdout}{Environment.NewLine}{result.Stderr}");
        using var document = JsonDocument.Parse(File.ReadAllText(storePath));
        var profile = document.RootElement.GetProperty("profiles").GetProperty(profileId);
        var volume = document.RootElement.GetProperty("volumes").GetProperty(volumeId);

        Assert.Equal(3, profile.GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal(1, profile.GetProperty("hardwarePilotPasses").GetInt32());
        Assert.Equal(0, profile.GetProperty("hotUnplugPasses").GetInt32());
        Assert.True(profile.GetProperty("powerLossPassVerified").GetBoolean());
        Assert.Equal(3, volume.GetProperty("crashFaultPasses").GetInt32());
        Assert.Equal(1, volume.GetProperty("hardwarePilotPasses").GetInt32());
        Assert.True(volume.GetProperty("powerLossPassVerified").GetBoolean());
    }

    [Fact]
    public void EvaluateWritePromotion_EmitsFailClosedJson_WhenDefaultConfigBlocksProfile()
    {
        using var temp = TempDirectory.Create();
        var storePath = Path.Combine(temp.Path, "write-evidence.json");
        var profileId = @"raw::\\.\physicaldrive999::main";
        var storeJson = $$"""
        {
          "profiles": {
            "{{JsonEncodedText(profileId)}}": {
              "crashFaultPasses": 1,
              "crashStageMatrixPasses": 1,
              "hardwarePilotPasses": 3,
              "hotUnplugPasses": 1,
              "macOsValidationPasses": 2,
              "macOsConsistencyPasses": 2,
              "powerLossReplayPasses": 1,
              "powerLossPassVerified": true,
              "lastValidatedUtc": "2026-05-06T00:00:00Z",
              "lastValidationProfileId": "{{JsonEncodedText(profileId)}}"
            }
          },
          "volumes": {}
        }
        """;
        File.WriteAllText(storePath, storeJson);

        var result = RunPowerShellScript(
            "evaluate_write_promotion.ps1",
            "-AppSettingsPath", Path.Combine(RepoRoot, "src", "ApfsAccess.Service", "appsettings.json"),
            "-EvidenceStorePath", storePath,
            "-ProfileId", profileId,
            "-AsJson");

        Assert.Equal(0, result.ExitCode);
        using var document = JsonDocument.Parse(result.Stdout);
        var first = document.RootElement.GetProperty("results")[0];
        var reasons = first.GetProperty("configReasons").EnumerateArray().Select(x => x.GetString()).ToArray();

        Assert.False(first.GetProperty("eligible").GetBoolean());
        Assert.Single(reasons);
        Assert.Contains("HardwarePilotAllowListMissing", reasons);
    }

    [Fact]
    public void EvaluateWritePromotion_UsesThirtyDayFreshnessDefault_WhenConfigOmitsMaxAge()
    {
        using var temp = TempDirectory.Create();
        var appSettingsPath = Path.Combine(temp.Path, "appsettings.json");
        var storePath = Path.Combine(temp.Path, "write-evidence.json");
        var profileId = @"raw::\\.\physicaldrive999::main";
        var staleUtc = DateTime.UtcNow.AddDays(-31).ToString("O");

        var appSettingsJson = """
        {
          "Service": {
            "BackendMode": "Mock",
            "EnableNativeWrite": false,
            "WriteRolloutChannel": "Disabled",
            "WriteBackendMode": "Disabled",
            "NativeWriteAllowRawPhysicalDevices": false,
            "NativeWritePromotionPolicy": "ScaffoldOnly"
          }
        }
        """;
        var storeJson = $$"""
        {
          "profiles": {
            "{{JsonEncodedText(profileId)}}": {
              "crashFaultPasses": 1,
              "crashStageMatrixPasses": 1,
              "hardwarePilotPasses": 3,
              "hotUnplugPasses": 1,
              "macOsValidationPasses": 2,
              "macOsConsistencyPasses": 2,
              "powerLossReplayPasses": 1,
              "powerLossPassVerified": true,
              "lastValidatedUtc": "{{staleUtc}}",
              "lastValidationProfileId": "{{JsonEncodedText(profileId)}}"
            }
          },
          "volumes": {}
        }
        """;
        File.WriteAllText(appSettingsPath, appSettingsJson);
        File.WriteAllText(storePath, storeJson);

        var result = RunPowerShellScript(
            "evaluate_write_promotion.ps1",
            "-AppSettingsPath", appSettingsPath,
            "-EvidenceStorePath", storePath,
            "-ProfileId", profileId,
            "-AsJson");

        Assert.Equal(0, result.ExitCode);
        using var document = JsonDocument.Parse(result.Stdout);
        var first = document.RootElement.GetProperty("results")[0];
        var reasons = first.GetProperty("reasons").EnumerateArray().Select(x => x.GetString()).ToArray();

        Assert.Contains("ValidationEvidenceStale", reasons);
        Assert.True(first.GetProperty("metrics").GetProperty("stale").GetBoolean());
    }

    [Fact]
    public void CreateTestImage_CreatesImageAndRefusesOverwrite()
    {
        using var temp = TempDirectory.Create();
        var imagePath = Path.Combine(temp.Path, "safe-smoke.apfs.img");

        var result = RunPowerShellScript(
            "create_test_image.ps1",
            "-Path", imagePath,
            "-SizeMiB", "4",
            "-AsJson");

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(imagePath));
        Assert.Equal(4L * 1024L * 1024L, new FileInfo(imagePath).Length);
        using (var document = JsonDocument.Parse(result.Stdout))
        {
            Assert.Equal(Path.GetFullPath(imagePath), document.RootElement.GetProperty("imagePath").GetString());
            Assert.False(document.RootElement.GetProperty("macOsCompatible").GetBoolean());
        }

        var overwrite = RunPowerShellScript(
            "create_test_image.ps1",
            "-Path", imagePath,
            "-SizeMiB", "4");

        Assert.NotEqual(0, overwrite.ExitCode);
        Assert.Contains("Refusing to overwrite existing file", overwrite.Stdout + overwrite.Stderr);
    }

    [Fact]
    public void RunPilotValidation_DefaultsToReadOnlyPhysicalValidation()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_pilot_validation.ps1"));

        Assert.Contains("[bool]$UseBootstrapEvidence = $false", script);
        Assert.Contains("[switch]$AllowDestructiveWriteSmoke", script);
        Assert.Contains("[switch]$KeepMounted", script);
        Assert.Contains("$service.EnableNativeWrite = [bool]$AllowDestructiveWriteSmoke", script);
        Assert.Contains("$service.NativeWriteAllowRawPhysicalDevices = [bool]$AllowDestructiveWriteSmoke", script);
        Assert.Contains("$service.NativeWriteCrashReplayMode = if ($AllowDestructiveWriteSmoke) { \"ReplayIfSafe\" } else { \"FailClosed\" }", script);
        Assert.Contains("Read-only validation mode is active. The script will not write to the APFS volume.", script);
    }

    [Fact]
    public void PhysicalRwValidation_RecordsBenchmarkMetricsForPerformancePhases()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("function Measure-Phase", script);
        Assert.Contains("elapsedMs", script);
        Assert.Contains("megabytesPerSecond", script);
        Assert.Contains("filesPerSecond", script);
        Assert.Contains("sha256MismatchCount", script);
        Assert.Contains("statusBefore", script);
        Assert.Contains("statusAfter", script);
        Assert.Contains("Add-BenchmarkMetric -Results $results -Name \"copy-read-hash\"", script);
        Assert.Contains("Add-BenchmarkMetric -Results $results -Name \"direct-apfs-write\"", script);
        Assert.Contains("Add-BenchmarkMetric -Results $results -Name \"recursive-copy\"", script);
        Assert.Contains("Add-BenchmarkMetric -Results $results -Name \"storm-create-copy\"", script);
        Assert.Contains("Add-BenchmarkMetric -Results $results -Name \"large-file-roundtrip\"", script);
        Assert.Contains("$Results.benchmarks += $metric", script);
    }

    [Fact]
    public void PhysicalRwValidation_IncludesExplorerWorkflowIntegrityMode()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("[ValidateSet(\"Smoke\", \"Storm\", \"ExplorerWorkflow\", \"VerifyManifest\", \"Performance\")]", script);
        Assert.Contains("Invoke-ExplorerWorkflow", script);
        Assert.Contains("explorer-format-copy-hash", script);
        Assert.Contains("explorer-rename-move-cut-paste", script);
        Assert.Contains("explorer-recycle-delete-restore", script);
        Assert.Contains("explorer-final-hash-sweep", script);
        Assert.Contains("Get-FileHash -Algorithm SHA256", script);
        Assert.Contains("edge-4095.png", script);
        Assert.Contains("edge-4096.docx", script);
        Assert.Contains("edge-4097.xlsx", script);
        Assert.Contains("installer.exe", script);
        Assert.Contains("unicodeFolder", script);
        Assert.Contains("recycle-move-to-bin", script);
        Assert.Contains("recycle-restore", script);
        Assert.Contains("recycle-delete-metadata", script);
        Assert.Contains("explorer-many-small-files", script);
        Assert.Contains("explorer-long-name", script);
        Assert.Contains("explorer-large-file-roundtrip", script);
    }

    [Fact]
    public void PhysicalRwValidation_IncludesPerformanceMode()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("[ValidateSet(\"Smoke\", \"Storm\", \"ExplorerWorkflow\", \"VerifyManifest\", \"Performance\")]", script);
        Assert.Contains("function Invoke-PerformanceBenchmark", script);
        Assert.Contains("[int]$SmallFileBytes = 16KB", script);
        Assert.Contains("[int]$SmallFileHashSampleCount = 100", script);
        Assert.Contains("if ($RequestedFileCount -eq 180) { 1000 }", script);
        Assert.Contains("if ($RequestedLargeFileBytes -eq 64MB) { [UInt64]1GB }", script);
        Assert.Contains("-Name \"large-copy-in\"", script);
        Assert.Contains("-Name \"large-copy-back\"", script);
        Assert.Contains("-Name \"small-copy-in\"", script);
        Assert.Contains("-Name \"small-copy-back\"", script);
        Assert.Contains("-Name \"small-internal-move\"", script);
        Assert.Contains("-Name \"small-move-out-and-back\"", script);
        Assert.Contains("-Name \"directory-enumeration\"", script);
        Assert.Contains("-Name \"delete-tree\"", script);
        Assert.Contains("Assert-SampledSmallFiles", script);
        Assert.Contains("Performance mode requires -StatusFile", script);
        Assert.Contains("elseif ($Mode -eq \"Performance\")", script);
    }

    [Fact]
    public void PhysicalRwValidation_CleansGeneratedExplorerTreeWithRetry()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("function Remove-GeneratedApfsTree", script);
        Assert.DoesNotContain("Remove-Item -LiteralPath $Path -Recurse -Force", script);
        Assert.DoesNotContain("Remove-Item -LiteralPath $apfsRoot -Recurse -Force", script);
        Assert.Contains("function Get-GeneratedApfsEntries", script);
        Assert.Contains("function Test-GeneratedDirectoryPath", script);
        Assert.Contains("Where-Object { -not (Test-GeneratedDirectoryPath -ItemPath $_) }", script);
        Assert.Contains("Where-Object { Test-GeneratedDirectoryPath -ItemPath $_ }", script);
        Assert.Contains("Sort-Object Length, { $_ } -Descending", script);
        Assert.Contains("function Test-GeneratedDirectoryOpenable", script);
        Assert.Contains("[System.IO.Directory]::EnumerateFileSystemEntries($ItemPath)", script);
        Assert.Contains("if (-not (Test-GeneratedDirectoryOpenable -ItemPath $Path))", script);
        Assert.Contains("[System.IO.Directory]::Delete($ItemPath, $false)", script);
        Assert.Contains("Assert-HostStatusReady -Path $StatusFilePath", script);
        Assert.Contains("Remove-GeneratedApfsTree -Path $apfsRoot -MountRoot $NormalizedMountRoot", script);
        Assert.Contains("Timed out cleaning generated APFS test root", script);
    }

    [Fact]
    public void PhysicalRwValidation_WaitsForCleanNativeStatusBetweenExplorerOperations()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("[int]$TimeoutSeconds = 20", script);
        Assert.Contains("[int]$PollMilliseconds = 100", script);
        Assert.Contains("$deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))", script);
        Assert.Contains("Start-Sleep -Milliseconds $pollDelay", script);
        Assert.Contains("-and $lastStatus.dirtyTransactionCount -eq 0", script);
    }

    [Fact]
    public void PhysicalRwValidation_WaitsForExplorerDeleteVisibility()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("function Wait-PathDeleted", script);
        Assert.Contains("Timed out waiting for deleted path to disappear", script);
        Assert.Contains("Wait-PathDeleted -Path $deleteFile -StatusFilePath $StatusFilePath", script);
        Assert.Contains("Wait-PathDeleted -Path $deleteDir -StatusFilePath $StatusFilePath", script);
        Assert.DoesNotContain("Deleted directory still exists", script);
        Assert.DoesNotContain("Deleted file still exists", script);
    }

    [Fact]
    public void PhysicalRwValidation_ScriptParses()
    {
        var scriptPath = Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1");
        var command =
            "$errors = $null; " +
            $"[System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath '{scriptPath}' -Raw), [ref]$errors) | Out-Null; " +
            "if ($errors -and $errors.Count -gt 0) { $errors | ConvertTo-Json -Compress; exit 1 }";

        var result = RunPowerShellCommand(command);

        Assert.True(
            result.ExitCode == 0,
            $"run_physical_rw_validation.ps1 has PowerShell parse errors.{Environment.NewLine}{result.Stdout}{Environment.NewLine}{result.Stderr}");
    }

    [Fact]
    public void PhysicalRwValidation_CaseOnlyRenameUsesCaseSensitiveEntryCheck()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_physical_rw_validation.ps1"));

        Assert.Contains("function Assert-ExplorerCaseOnlyRename", script);
        Assert.Contains("[switch]$CaseOnlyRename", script);
        Assert.Contains("$_.Name -ceq $DestinationLeaf", script);
        Assert.Contains("$_.Name -ceq $SourceLeaf", script);
        Assert.Contains("-CaseOnlyRename", script);

        var caseOnlyRenameStart = script.IndexOf("-Name \"case-only-rename\"", StringComparison.Ordinal);
        Assert.True(caseOnlyRenameStart >= 0, "The Explorer workflow should include a case-only rename operation.");
        var caseOnlyRenameEnd = script.IndexOf("Add-TrackedExplorerFile -Path $caseRenamed", caseOnlyRenameStart, StringComparison.Ordinal);
        Assert.True(caseOnlyRenameEnd > caseOnlyRenameStart, "The case-only rename operation block should be locatable.");
        var caseOnlyRenameBlock = script[caseOnlyRenameStart..caseOnlyRenameEnd];
        Assert.Contains("-CaseOnlyRename", caseOnlyRenameBlock);
        Assert.DoesNotContain("-SourceRemoved", caseOnlyRenameBlock);
    }

    [Fact]
    public void RunPilotValidation_KeepMountedLeavesSuccessfulMountAvailableForExplorer()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_pilot_validation.ps1"));

        Assert.Contains("keepMounted = [bool]$KeepMounted", script);
        Assert.Contains("if ($KeepMounted -and $summary.status -eq \"Complete\")", script);
        Assert.Contains("APFS Access processes were left running so the mounted APFS drive remains visible in Explorer.", script);
        Assert.Contains("Stop-ApfsProcesses", script);
    }

    [Fact]
    public void TrayStartup_DoesNotRequestDuplicateRefreshAfterInitialStatus()
    {
        var traySource = File.ReadAllText(Path.Combine(RepoRoot, "src", "ApfsAccess.Tray", "TrayApplicationContext.cs"));

        Assert.DoesNotContain("RequestStartupRefreshOnceAsync", traySource);
        Assert.DoesNotContain("ClearUserEjectedVolumes: true", traySource);
    }

    [Fact]
    public void TrayPipeHost_CoalescesStatusBroadcastBursts()
    {
        var serviceSource = File.ReadAllText(Path.Combine(RepoRoot, "src", "ApfsAccess.Service", "TrayPipeHostService.cs"));

        Assert.Contains("_pendingBroadcast = payload", serviceSource);
        Assert.Contains("_broadcastPumpActive", serviceSource);
        Assert.Contains("BroadcastLatestStatusAsync", serviceSource);
        Assert.DoesNotContain("_ = BroadcastStatusAsync(payload)", serviceSource);
    }

    [Fact]
    public void RunPilotValidation_WaitsForActualDriveLetterMount()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_pilot_validation.ps1"));

        Assert.Contains("if ($mountPoints.Count -gt 0)", script);
        Assert.DoesNotContain("if ($null -ne $lastStatus) {\r\n        return $lastStatus", script);
        Assert.Contains("Timed out waiting for a mounted APFS volume with a drive letter", script);
    }

    [Fact]
    public void RunPilotValidation_InvokesNativeProbeWithNamedParameters()
    {
        var script = File.ReadAllText(Path.Combine(RepoRoot, "scripts", "run_pilot_validation.ps1"));

        Assert.DoesNotContain("& $ProbeScriptPath @arguments", script);
        Assert.Contains("& $ProbeScriptPath -DeviceId $DeviceId.Trim() -AsJson", script);
        Assert.Contains("& $ProbeScriptPath -MaxPhysicalDriveIndex ([Math]::Max(0, $MaxPhysicalDriveIndex)) -AsJson", script);
    }

    [Fact]
    public void EvaluateWritePromotion_AllowsEmptyAllowListUnderStrictMode()
    {
        using var temp = TempDirectory.Create();
        var appSettingsPath = Path.Combine(temp.Path, "appsettings.json");
        var profileId = @"raw::\\.\physicaldrive999::main";
        File.WriteAllText(
            appSettingsPath,
            """
            {
              "Service": {
                "EnableNativeWrite": false,
                "WriteRolloutChannel": "Disabled",
                "WriteBackendMode": "Disabled",
                "NativeWriteAllowRawPhysicalDevices": false,
                "NativeWritePromotionPolicy": "ScaffoldOnly",
                "NativeWriteHardwarePilotDeviceAllowList": []
              }
            }
            """);

        var result = RunPowerShellCommand(
            "Set-StrictMode -Version Latest; " +
            $"& '{Path.Combine(RepoRoot, "scripts", "evaluate_write_promotion.ps1")}' " +
            $"-AppSettingsPath '{appSettingsPath}' " +
            $"-ProfileId '{profileId}' " +
            "-AsJson");

        Assert.Equal(0, result.ExitCode);
        using var document = JsonDocument.Parse(result.Stdout);
        Assert.False(document.RootElement.GetProperty("results")[0].GetProperty("allowListConfigured").GetBoolean());
    }

    [Fact]
    public void SilentLauncher_Block_IsIncludedInPublishScript()
    {
        var publishScript = File.ReadAllText(Path.Combine(RepoRoot, "build", "publish.ps1"));

        Assert.Contains("Run_APFS_Access_Silent.vbs", publishScript);
        Assert.Contains("shell.Run \"\"\"\" & trayPath & \"\"\"\", 0, False", publishScript);
    }

    [Fact]
    public void PublishScript_ExcludesValidationFeedbackFromPortablePayload()
    {
        var publishScript = File.ReadAllText(Path.Combine(RepoRoot, "build", "publish.ps1"));

        Assert.Contains("click-run-portable-payload", publishScript);
        Assert.Contains("\"pilot-feedback\"", publishScript);
        Assert.Contains("$portablePayloadExcludes -notcontains $_.Name", publishScript);
    }

    [Fact]
    public void AppSettings_DefaultToNativePilotWriteWithSafetyGates()
    {
        var appSettingsPath = Path.Combine(RepoRoot, "src", "ApfsAccess.Service", "appsettings.json");
        using var document = JsonDocument.Parse(File.ReadAllText(appSettingsPath));
        var service = document.RootElement.GetProperty("Service");

        Assert.Equal("Native", service.GetProperty("BackendMode").GetString());
        Assert.True(service.GetProperty("NativeAutoDiscoverPhysicalDrives").GetBoolean());
        Assert.Empty(service.GetProperty("NativeDeviceCandidates").EnumerateArray());
        Assert.True(service.GetProperty("EnableNativeWrite").GetBoolean());
        Assert.Equal("Pilot", service.GetProperty("WriteRolloutChannel").GetString());
        Assert.Equal("Native", service.GetProperty("WriteBackendMode").GetString());
        Assert.True(service.GetProperty("NativeWriteAllowRawPhysicalDevices").GetBoolean());
        Assert.Equal("PilotHardware", service.GetProperty("NativeWritePromotionPolicy").GetString());
        Assert.Empty(service.GetProperty("NativeWriteHardwarePilotDeviceAllowList").EnumerateArray());
    }

    [Fact]
    public void GitIgnore_CoversGeneratedAndPrivateValidationArtifacts()
    {
        var gitIgnorePath = Path.Combine(RepoRoot, ".gitignore");
        var gitIgnore = File.ReadAllText(gitIgnorePath);

        Assert.Contains("artifacts/", gitIgnore);
        Assert.Contains("APFSAccess_Portable.exe", gitIgnore);
        Assert.Contains("**/bin/", gitIgnore);
        Assert.Contains("**/obj/", gitIgnore);
        Assert.Contains("*.log", gitIgnore);
        Assert.Contains("physical-usb-tests/", gitIgnore);
    }

    private static ScriptResult RunPowerShellScript(string scriptName, params string[] arguments)
    {
        var pwsh = FindPowerShell();
        Assert.False(string.IsNullOrWhiteSpace(pwsh), "pwsh must be available to run pilot script regression tests.");

        var scriptPath = Path.Combine(RepoRoot, "scripts", scriptName);
        var startInfo = new ProcessStartInfo(pwsh!)
        {
            WorkingDirectory = RepoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(scriptPath);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start pwsh.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), $"Timed out running {scriptName}.");
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();

        return new ScriptResult(process.ExitCode, stdout, stderr);
    }

    private static ScriptResult RunPowerShellCommand(string command)
    {
        var pwsh = FindPowerShell();
        Assert.False(string.IsNullOrWhiteSpace(pwsh), "pwsh must be available to run pilot script regression tests.");

        var startInfo = new ProcessStartInfo(pwsh!)
        {
            WorkingDirectory = RepoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(command);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start pwsh.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "Timed out running PowerShell command.");
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();

        return new ScriptResult(process.ExitCode, stdout, stderr);
    }

    private static string? FindPowerShell()
    {
        var candidates = new[] { "pwsh.exe", "pwsh" };
        foreach (var candidate in candidates)
        {
            try
            {
                var startInfo = new ProcessStartInfo(candidate, "-NoProfile -Command $PSVersionTable.PSVersion.ToString()")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                };
                using var process = Process.Start(startInfo);
                if (process is null)
                {
                    continue;
                }

                if (process.WaitForExit(5_000) && process.ExitCode == 0)
                {
                    return candidate;
                }
            }
            catch
            {
                // Try the next candidate.
            }
        }

        return null;
    }

    private static string RepoRoot => LazyRepoRoot.Value;

    private static readonly Lazy<string> LazyRepoRoot = new(() =>
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "scripts")) &&
                File.Exists(Path.Combine(current.FullName, "APFSAccess.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate repository root.");
    });

    private static string JsonEncodedText(string value) => JsonSerializer.Serialize(value)[1..^1];

    private sealed record ScriptResult(int ExitCode, string Stdout, string Stderr);

    private sealed class TempDirectory : IDisposable
    {
        private TempDirectory(string path) => Path = path;

        public string Path { get; }

        public static TempDirectory Create()
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "apfsaccess-script-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TempDirectory(path);
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
