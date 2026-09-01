using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.ComponentModel;
using ApfsAccess.Updater;
using Xunit.Sdk;

namespace ApfsAccess.Updater.Tests;

public sealed class UpdateReplacementEngineTests
{
    [Fact]
    public async Task ApplyAsync_RejectsMissingManifest()
    {
        using var workspace = new TestWorkspace();
        var runtime = new FakeProcessRuntime();

        var result = await CreateEngine(runtime).ApplyAsync(
            Path.Combine(workspace.Root, "missing.json"),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
        Assert.Equal(0, runtime.StartCalls);
    }

    [Theory]
    [InlineData(nameof(UpdateManifest.LauncherPath))]
    [InlineData(nameof(UpdateManifest.ReadyPath))]
    [InlineData(nameof(UpdateManifest.BackupPath))]
    [InlineData(nameof(UpdateManifest.ReceiptPath))]
    public async Task ApplyAsync_RejectsRelativeManifestPaths(string propertyName)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        manifest = propertyName switch
        {
            nameof(UpdateManifest.LauncherPath) => manifest with { LauncherPath = "APFS Access.exe" },
            nameof(UpdateManifest.ReadyPath) => manifest with { ReadyPath = "update.ready" },
            nameof(UpdateManifest.BackupPath) => manifest with { BackupPath = "old.backup" },
            nameof(UpdateManifest.ReceiptPath) => manifest with { ReceiptPath = "ready.json" },
            _ => throw new ArgumentOutOfRangeException(nameof(propertyName)),
        };

        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_RejectsNonCanonicalManifestPath()
    {
        using var workspace = new TestWorkspace();
        var manifestPath = workspace.WriteManifest(workspace.CreateManifest());
        var aliasedPath = Path.Combine(workspace.Root, ".", Path.GetFileName(manifestPath));

        var result = await CreateEngine().ApplyAsync(aliasedPath, CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_RejectsPathsFromDifferentDirectories()
    {
        using var workspace = new TestWorkspace();
        var otherDirectory = Path.Combine(workspace.Root, "other");
        Directory.CreateDirectory(otherDirectory);
        var manifest = workspace.CreateManifest() with
        {
            ReceiptPath = Path.Combine(otherDirectory, "ready.json"),
        };

        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_RejectsLauncherAndReadyPathAliasing()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        manifest = manifest with { ReadyPath = manifest.LauncherPath.ToUpperInvariant() };

        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Theory]
    [InlineData("ABC", ValidHash, ValidVersion, ValidToken)]
    [InlineData(ValidHash, "xyz", ValidVersion, ValidToken)]
    [InlineData(ValidHash, ValidHash, "v1.0.5", ValidToken)]
    [InlineData(ValidHash, ValidHash, ValidVersion, "short-token")]
    public async Task ApplyAsync_RejectsMalformedHashesVersionOrToken(
        string currentHash,
        string expectedHash,
        string expectedVersion,
        string token)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest() with
        {
            CurrentSha256 = currentHash,
            ExpectedSha256 = expectedHash,
            ExpectedVersion = expectedVersion,
            Token = token,
        };

        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_RejectsAbsentReadyFile()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        File.Delete(manifest.ReadyPath);

        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_DoesNotWaitForReusedOldProcessId()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime
        {
            CurrentProcess = new UpdateProcessIdentity(
                manifest.OldTrayProcessId,
                manifest.OldTrayStartTimeUtcTicks + 1),
        };
        var timing = new FakeTiming();

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.NotEqual(UpdateExitCode.OldProcessTimeout, result);
        Assert.Equal(0, timing.OldProcessDelayCalls);
        Assert.DoesNotContain(
            new UpdateProcessIdentity(
                manifest.OldTrayProcessId,
                manifest.OldTrayStartTimeUtcTicks + 1),
            runtime.Terminated);
    }

    [Fact]
    public async Task ApplyAsync_TreatsMissingOldProcessAsAlreadyExited()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming();

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.NotEqual(UpdateExitCode.OldProcessTimeout, result);
        Assert.Equal(0, timing.OldProcessDelayCalls);
    }

    [Fact]
    public async Task ApplyAsync_ReturnsBoundedFailureWhenExactOldProcessDoesNotExit()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime
        {
            CurrentProcess = new UpdateProcessIdentity(
                manifest.OldTrayProcessId,
                manifest.OldTrayStartTimeUtcTicks),
        };
        var timing = new FakeTiming();

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.OldProcessTimeout, result);
        Assert.InRange(timing.DelayCalls, 1, 100);
        Assert.Empty(runtime.Terminated);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
    }

    [Fact]
    public async Task ApplyAsync_ReplacesLauncherAndDeletesBackupOnlyAfterExactReadyReceipt()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var manifestPath = workspace.WriteManifest(manifest);
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () =>
            {
                Assert.True(File.Exists(manifest.BackupPath));
                Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
                WriteReceipt(manifest, runtime.CurrentProcess!.Value);
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            manifestPath,
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.Success, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.ReadyPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.False(File.Exists(manifestPath));
        Assert.False(File.Exists(manifest.ReceiptPath));
        var launch = Assert.Single(runtime.Starts);
        Assert.Equal(manifest.LauncherPath, launch.ExecutablePath);
        Assert.Equal(manifest.Token, launch.Environment["APFSACCESS_UPDATE_TOKEN"]);
        Assert.Equal(manifest.ExpectedVersion, launch.Environment["APFSACCESS_UPDATE_EXPECTED_VERSION"]);
        Assert.Equal(manifest.ReceiptPath, launch.Environment["APFSACCESS_UPDATE_RECEIPT_PATH"]);
        Assert.Empty(runtime.Terminated);
    }

    [Fact]
    public async Task ApplyAsync_AcceptsReadyReceiptFromTrayStartedByBootstrap()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var manifestPath = workspace.WriteManifest(manifest);
        var runtime = new FakeProcessRuntime();
        var trayProcess = new UpdateProcessIdentity(9123, 638923683000000000);
        var timing = new FakeTiming
        {
            OnDelay = () =>
            {
                runtime.CurrentProcess = trayProcess;
                WriteReceipt(manifest, trayProcess);
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            manifestPath,
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.Success, result);
        Assert.Equal(trayProcess, runtime.CurrentProcess);
        Assert.False(File.Exists(manifest.BackupPath));
    }

    [Fact]
    public async Task ApplyAsync_RejectsReadyHashChangeBeforeBackup()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var timing = new FakeTiming
        {
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeReplacement)
                {
                    File.WriteAllText(manifest.ReadyPath, "changed after validation");
                }
            },
        };

        var result = await CreateEngine(timing: timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Equal("changed after validation", File.ReadAllText(manifest.ReadyPath));
        Assert.False(File.Exists(manifest.BackupPath));
    }

    [Fact]
    public async Task ApplyAsync_FailsClosedWhenLauncherIsLocked()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        using var lockedLauncher = new FileStream(
            manifest.LauncherPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);

        var timing = new FakeTiming();
        var result = await CreateEngine(timing: timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.ReadyPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Contains(UpdateCheckpoint.BeforeReplacement, timing.Checkpoints);
    }

    [Fact]
    public async Task ApplyAsync_RestoresAndRelaunchesOldLauncherOnInstalledHashMismatch()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.AfterReadyInstalled)
                {
                    File.WriteAllText(manifest.LauncherPath, "tampered installed launcher");
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
        var relaunch = Assert.Single(runtime.Starts);
        Assert.Equal(manifest.LauncherPath, relaunch.ExecutablePath);
        Assert.Empty(relaunch.Environment);
    }

    [Fact]
    public async Task ApplyAsync_RestoresAndRelaunchesOldLauncherWhenNewLaunchFails()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime { StartFailuresRemaining = 1 };

        var result = await CreateEngine(runtime).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReadinessFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Equal(2, runtime.Starts.Count);
        Assert.Empty(runtime.Starts[1].Environment);
    }

    [Fact]
    public async Task ApplyAsync_TerminatesExactNewProcessThenRestoresAndRelaunchesOnReceiptTimeout()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming();

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReadinessFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
        Assert.Equal(2, runtime.Starts.Count);
        Assert.InRange(timing.DelayCalls, 1, 500);
    }

    [Theory]
    [InlineData("token")]
    [InlineData("version")]
    [InlineData("phase")]
    [InlineData("processId")]
    [InlineData("processStartTime")]
    public async Task ApplyAsync_RejectsReceiptThatDoesNotMatchExactReadyLaunch(string mismatch)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () =>
            {
                var launched = runtime.CurrentProcess!.Value;
                WriteReceipt(
                    manifest,
                    launched,
                    token: mismatch == "token" ? new string('C', 64) : manifest.Token,
                    version: mismatch == "version" ? "1.0.6" : manifest.ExpectedVersion,
                    phase: mismatch == "phase" ? "launched" : "ready",
                    processId: mismatch == "processId" ? launched.ProcessId + 1 : launched.ProcessId,
                    processStartTimeUtcTicks: mismatch == "processStartTime"
                        ? launched.StartTimeUtcTicks + 1
                        : launched.StartTimeUtcTicks);
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReadinessFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
        Assert.Equal(2, runtime.Starts.Count);
    }

    [Fact]
    public async Task ApplyAsync_DoesNotTerminateReusedNewProcessIdDuringRollback()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => runtime.CurrentProcess = runtime.NewProcessIdentity with
            {
                StartTimeUtcTicks = runtime.NewProcessIdentity.StartTimeUtcTicks + 1,
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReadinessFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Empty(runtime.Terminated);
        Assert.Equal(2, runtime.Starts.Count);
    }

    [Fact]
    public async Task ApplyAsync_RejectsReceiptWithNonExactFieldNames()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () =>
            {
                var launched = runtime.CurrentProcess!.Value;
                File.WriteAllText(manifest.ReceiptPath, JsonSerializer.Serialize(new
                {
                    Token = manifest.Token,
                    ExpectedVersion = manifest.ExpectedVersion,
                    Phase = "ready",
                    ProcessId = launched.ProcessId,
                    ProcessStartTimeUtcTicks = launched.StartTimeUtcTicks,
                }));
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReadinessFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
    }

    [Fact]
    public async Task ApplyAsync_ReturnsRollbackFailureWhenExactNewProcessCannotBeTerminated()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime { AllowTermination = false };

        var result = await CreateEngine(runtime).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.RollbackFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.True(File.Exists(manifest.BackupPath));
        Assert.Single(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_LeavesCandidateAndCorruptBackupUntouchedWithoutTerminatingNewProcess()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var corruptBackup = Encoding.UTF8.GetBytes("corrupt backup");
        var timing = new FakeTiming
        {
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.AfterReadyInstalled)
                {
                    File.WriteAllBytes(manifest.BackupPath, corruptBackup);
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.RollbackFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Equal(corruptBackup, File.ReadAllBytes(manifest.BackupPath));
        Assert.False(File.Exists(manifest.ReadyPath));
        Assert.Empty(runtime.Terminated);
        Assert.Single(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_PreservesCandidateAndVerifiedBackupWhenCandidateHoldingMoveFails()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        FileStream? candidateLock = null;
        var timing = new FakeTiming
        {
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeCandidateHold)
                {
                    candidateLock = new FileStream(
                        manifest.LauncherPath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read);
                }
            },
        };

        int result;
        try
        {
            result = await CreateEngine(runtime, timing).ApplyAsync(
                workspace.WriteManifest(manifest),
                CancellationToken.None);
        }
        finally
        {
            candidateLock?.Dispose();
        }

        Assert.NotNull(candidateLock);
        Assert.Equal(UpdateExitCode.RollbackFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.BackupPath));
        Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
        Assert.Single(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_RestoresHeldCandidateWhenVerifiedBackupMoveFails()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        FileStream? backupLock = null;
        string? heldCandidatePath = null;
        var timing = new FakeTiming
        {
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeBackupRestore)
                {
                    heldCandidatePath = Assert.Single(Directory.GetFiles(
                        workspace.Root,
                        ".APFS.Access.update.failed.*.hold"));
                    Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(heldCandidatePath));
                    backupLock = new FileStream(
                        manifest.BackupPath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read);
                }
            },
        };

        int result;
        try
        {
            result = await CreateEngine(runtime, timing).ApplyAsync(
                workspace.WriteManifest(manifest),
                CancellationToken.None);
        }
        finally
        {
            backupLock?.Dispose();
        }

        Assert.NotNull(heldCandidatePath);
        Assert.NotNull(backupLock);
        Assert.Equal(UpdateExitCode.RollbackFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.BackupPath));
        Assert.False(File.Exists(heldCandidatePath));
        Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
        Assert.Single(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_RejectsAlternateDataStreamPath()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var adsPath = manifest.LauncherPath + ":ready";
        try
        {
            File.WriteAllBytes(adsPath, workspace.ReadyBytes);
        }
        catch (Exception ex) when (FixtureCreationWasRefused(ex))
        {
            throw SkipException.ForSkip($"Windows refused the D:-rooted ADS fixture: {ex.Message}");
        }

        manifest = manifest with { ReadyPath = adsPath };
        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_RejectsHardLinkAliasOfLauncher()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var hardLinkPath = Path.Combine(workspace.Root, "APFS Access.hardlink.ready");
        if (!NativeTestMethods.CreateHardLink(hardLinkPath, manifest.LauncherPath, 0))
        {
            throw SkipException.ForSkip(
                $"Windows refused the D:-rooted hard-link fixture with error {Marshal.GetLastWin32Error()}.");
        }

        manifest = manifest with
        {
            ReadyPath = hardLinkPath,
            ExpectedSha256 = manifest.CurrentSha256,
        };
        var result = await CreateEngine().ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Fact]
    public async Task ApplyAsync_RejectsFileReparsePoint()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var linkPath = Path.Combine(workspace.Root, "APFS Access.reparse.ready");
        try
        {
            File.CreateSymbolicLink(linkPath, manifest.ReadyPath);
        }
        catch (Exception ex) when (FixtureCreationWasRefused(ex))
        {
            throw SkipException.ForSkip($"Windows refused the D:-rooted file reparse fixture: {ex.Message}");
        }

        try
        {
            manifest = manifest with { ReadyPath = linkPath };
            var result = await CreateEngine().ApplyAsync(
                workspace.WriteManifest(manifest),
                CancellationToken.None);

            Assert.Equal(UpdateExitCode.InvalidManifest, result);
        }
        finally
        {
            File.Delete(linkPath);
        }
    }

    [Fact]
    public async Task ApplyAsync_RejectsContainingDirectoryReparsePoint()
    {
        using var workspace = new TestWorkspace();
        var realManifest = workspace.CreateManifest();
        var linkDirectory = Path.Combine(workspace.Root, "directory-alias");
        try
        {
            Directory.CreateSymbolicLink(linkDirectory, workspace.Root);
        }
        catch (Exception ex) when (FixtureCreationWasRefused(ex))
        {
            throw SkipException.ForSkip($"Windows refused the D:-rooted directory reparse fixture: {ex.Message}");
        }

        try
        {
            var manifest = realManifest with
            {
                LauncherPath = Path.Combine(linkDirectory, Path.GetFileName(realManifest.LauncherPath)),
                ReadyPath = Path.Combine(linkDirectory, Path.GetFileName(realManifest.ReadyPath)),
                BackupPath = Path.Combine(linkDirectory, Path.GetFileName(realManifest.BackupPath)),
                ReceiptPath = Path.Combine(linkDirectory, Path.GetFileName(realManifest.ReceiptPath)),
            };
            var realManifestPath = workspace.WriteManifest(manifest);
            var aliasManifestPath = Path.Combine(linkDirectory, Path.GetFileName(realManifestPath));

            var result = await CreateEngine().ApplyAsync(aliasManifestPath, CancellationToken.None);

            Assert.Equal(UpdateExitCode.InvalidManifest, result);
        }
        finally
        {
            Directory.Delete(linkDirectory);
        }
    }

    [Fact]
    public async Task ApplyAsync_RejectsShortNameFinalPathAlias()
    {
        using var workspace = new TestWorkspace();
        var realManifest = workspace.CreateManifest();
        var shortRoot = GetShortPathOrSkip(workspace.Root);
        var manifest = realManifest with
        {
            LauncherPath = Path.Combine(shortRoot, Path.GetFileName(realManifest.LauncherPath)),
            ReadyPath = Path.Combine(shortRoot, Path.GetFileName(realManifest.ReadyPath)),
            BackupPath = Path.Combine(shortRoot, Path.GetFileName(realManifest.BackupPath)),
            ReceiptPath = Path.Combine(shortRoot, Path.GetFileName(realManifest.ReceiptPath)),
        };
        var realManifestPath = workspace.WriteManifest(manifest);
        var shortManifestPath = Path.Combine(shortRoot, Path.GetFileName(realManifestPath));

        var result = await CreateEngine().ApplyAsync(shortManifestPath, CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Theory]
    [InlineData("manifest")]
    [InlineData("directory")]
    [InlineData("launcher")]
    [InlineData("ready")]
    public async Task ApplyAsync_RejectsOwnerMismatchForEveryExistingUpdateObject(string objectName)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var manifestPath = workspace.WriteManifest(manifest);
        var mismatchPath = objectName switch
        {
            "manifest" => manifestPath,
            "directory" => workspace.Root,
            "launcher" => manifest.LauncherPath,
            "ready" => manifest.ReadyPath,
            _ => throw new ArgumentOutOfRangeException(nameof(objectName)),
        };
        var inspector = new OwnerMismatchPathInspector(mismatchPath);

        var result = await CreateEngine(pathInspector: inspector).ApplyAsync(
            manifestPath,
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidManifest, result);
    }

    [Theory]
    [InlineData("launcher")]
    [InlineData("ready")]
    public async Task ApplyAsync_RejectsFileSwapAfterInitialValidation(string objectName)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var manifestPath = workspace.WriteManifest(manifest);
        var runtime = new FakeProcessRuntime();
        var approvedPath = objectName == "launcher" ? manifest.LauncherPath : manifest.ReadyPath;
        var approvedBytes = objectName == "launcher" ? workspace.CurrentBytes : workspace.ReadyBytes;
        var displacedPath = approvedPath + ".approved";
        var replacementPath = approvedPath + ".replacement";
        File.WriteAllBytes(replacementPath, approvedBytes);
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeReplacement)
                {
                    File.Move(approvedPath, displacedPath);
                    File.Move(replacementPath, approvedPath);
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            manifestPath,
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.Equal(approvedBytes, File.ReadAllBytes(approvedPath));
        Assert.Equal(approvedBytes, File.ReadAllBytes(displacedPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Empty(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_RejectsContainingDirectorySwapAfterInitialValidation()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var manifestPath = workspace.WriteManifest(manifest);
        var approvedRoot = workspace.Root + ".approved";
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint != UpdateCheckpoint.BeforeReplacement)
                {
                    return;
                }

                Directory.Move(workspace.Root, approvedRoot);
                Directory.CreateDirectory(workspace.Root);
                foreach (var fileName in new[]
                         {
                             Path.GetFileName(manifestPath),
                             Path.GetFileName(manifest.LauncherPath),
                             Path.GetFileName(manifest.ReadyPath),
                         })
                {
                    File.Copy(
                        Path.Combine(approvedRoot, fileName),
                        Path.Combine(workspace.Root, fileName));
                }
            },
        };

        try
        {
            var result = await CreateEngine(runtime, timing).ApplyAsync(
                manifestPath,
                CancellationToken.None);

            Assert.Equal(UpdateExitCode.ReplacementFailed, result);
            Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
            Assert.False(File.Exists(manifest.BackupPath));
            Assert.Empty(runtime.Starts);
        }
        finally
        {
            if (Directory.Exists(approvedRoot))
            {
                Directory.Delete(approvedRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task ApplyAsync_RejectsHardLinkSwapAfterInitialValidation()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var displacedPath = manifest.ReadyPath + ".approved";
        var sourcePath = Path.Combine(workspace.Root, "hard-link-source.ready");
        var aliasPath = Path.Combine(workspace.Root, "hard-link-alias.ready");
        File.WriteAllBytes(sourcePath, workspace.ReadyBytes);
        if (!NativeTestMethods.CreateHardLink(aliasPath, sourcePath, 0))
        {
            throw SkipException.ForSkip(
                $"Windows refused the D:-rooted transition hard-link fixture with error {Marshal.GetLastWin32Error()}.");
        }

        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeReplacement)
                {
                    File.Move(manifest.ReadyPath, displacedPath);
                    File.Move(aliasPath, manifest.ReadyPath);
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.ReadyPath));
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(displacedPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Empty(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_RejectsReparseSwapAfterInitialValidation()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var displacedPath = manifest.ReadyPath + ".approved";
        var targetPath = Path.Combine(workspace.Root, "reparse-target.ready");
        var linkPath = Path.Combine(workspace.Root, "reparse-alias.ready");
        File.WriteAllBytes(targetPath, workspace.ReadyBytes);
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
        }
        catch (Exception ex) when (FixtureCreationWasRefused(ex))
        {
            throw SkipException.ForSkip(
                $"Windows refused the D:-rooted transition reparse fixture: {ex.Message}");
        }

        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeReplacement)
                {
                    File.Move(manifest.ReadyPath, displacedPath);
                    File.Move(linkPath, manifest.ReadyPath);
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.ReadyPath));
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(displacedPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Empty(runtime.Starts);
    }

    [Theory]
    [InlineData("directory")]
    [InlineData("launcher")]
    [InlineData("ready")]
    public async Task ApplyAsync_RejectsOwnerChangeAfterInitialValidation(string objectName)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var targetPath = objectName switch
        {
            "directory" => workspace.Root,
            "launcher" => manifest.LauncherPath,
            "ready" => manifest.ReadyPath,
            _ => throw new ArgumentOutOfRangeException(nameof(objectName)),
        };
        var inspector = new TransitionOwnerMismatchPathInspector(targetPath);
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == UpdateCheckpoint.BeforeReplacement)
                {
                    inspector.MismatchEnabled = true;
                }
            },
        };

        var result = await CreateEngine(runtime, timing, inspector).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReplacementFailed, result);
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Empty(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_HeldTransitionHandlesPreventSwapBeforeRename()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var displacedPath = manifest.LauncherPath + ".displaced";
        var replacementPath = manifest.LauncherPath + ".replacement";
        File.WriteAllBytes(replacementPath, workspace.CurrentBytes);
        var runtime = new FakeProcessRuntime();
        var swapAttempted = false;
        var swapRefused = false;
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (!string.Equals(
                        checkpoint.ToString(),
                        "AfterTransitionHandlesOpened",
                        StringComparison.Ordinal))
                {
                    return;
                }

                swapAttempted = true;
                try
                {
                    File.Move(manifest.LauncherPath, displacedPath);
                    File.Move(replacementPath, manifest.LauncherPath);
                }
                catch (IOException)
                {
                    swapRefused = true;
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.Success, result);
        Assert.True(swapAttempted);
        Assert.True(swapRefused);
        Assert.False(File.Exists(displacedPath));
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
    }

    [Fact]
    public async Task ApplyAsync_TimesOutFailClosedWhenOldProcessObservationIsUnknown()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime { ObservationIsUnknown = true };
        var timing = new FakeTiming();

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.OldProcessTimeout, result);
        Assert.InRange(timing.OldProcessDelayCalls, 1, 100);
        Assert.Empty(runtime.Starts);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
    }

    [Fact]
    public async Task ApplyAsync_LeavesCandidateAndBackupUntouchedWhenNewProcessObservationIsUnknown()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => runtime.ObservationIsUnknown = true,
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.RollbackFailed, result);
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.BackupPath));
        Assert.Empty(runtime.Terminated);
        Assert.Single(runtime.Starts);
    }

    [Fact]
    public async Task ApplyAsync_FreezesRestoredLayoutWhenOldRelaunchObservationIsUnknown()
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime
        {
            ObservationOverride = expected => expected == FakeProcessRuntime.OldRelaunchProcessIdentity
                ? UpdateProcessObservation.Unknown
                : null,
        };

        var result = await CreateEngine(runtime).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.RollbackFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
        var heldCandidate = Assert.Single(Directory.GetFiles(
            workspace.Root,
            ".APFS.Access.update.failed.*.hold"));
        Assert.Equal(workspace.ReadyBytes, File.ReadAllBytes(heldCandidate));
        Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
        Assert.DoesNotContain(FakeProcessRuntime.OldRelaunchProcessIdentity, runtime.Terminated);
        Assert.Equal(2, runtime.Starts.Count);
        Assert.Contains(
            "rollback could not restore and relaunch",
            File.ReadAllText(Path.Combine(workspace.Root, "apfs-access-update-diagnostic.txt")),
            StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("afterReceiptParsed")]
    [InlineData("beforeCommit")]
    public async Task ApplyAsync_RollsBackWhenReadyProcessExitsAtLivenessBoundary(
        string boundary)
    {
        using var workspace = new TestWorkspace();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var exitCheckpoint = boundary switch
        {
            "afterReceiptParsed" => UpdateCheckpoint.AfterReceiptParsed,
            "beforeCommit" => UpdateCheckpoint.BeforeCommit,
            _ => throw new ArgumentOutOfRangeException(nameof(boundary)),
        };
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == exitCheckpoint)
                {
                    runtime.CurrentProcess = null;
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            CancellationToken.None);

        Assert.Equal(UpdateExitCode.ReadinessFailed, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Empty(runtime.Terminated);
        Assert.Equal(2, runtime.Starts.Count);
    }

    [Theory]
    [InlineData("AfterBackupCreated", false)]
    [InlineData("AfterReadyInstalled", false)]
    [InlineData("AfterLaunch", true)]
    [InlineData("AfterReceiptParsed", true)]
    [InlineData("AfterReadiness", true)]
    [InlineData("BeforeCommit", true)]
    public async Task ApplyAsync_CancellationAtPostBackupBoundaryRollsBack(
        string checkpointName,
        bool newProcessWasLaunched)
    {
        using var workspace = new TestWorkspace();
        using var cancellation = new CancellationTokenSource();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var cancellationCheckpoint = Enum.Parse<UpdateCheckpoint>(checkpointName);
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
            OnCheckpoint = checkpoint =>
            {
                if (checkpoint == cancellationCheckpoint)
                {
                    cancellation.Cancel();
                }
            },
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            cancellation.Token);

        Assert.Equal(UpdateExitCode.Cancelled, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));

        if (newProcessWasLaunched)
        {
            Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
            Assert.Equal(2, runtime.Starts.Count);
        }
        else
        {
            Assert.Empty(runtime.Terminated);
            var relaunch = Assert.Single(runtime.Starts);
            Assert.Empty(relaunch.Environment);
        }
    }

    [Fact]
    public async Task ApplyAsync_CancellationDuringFinalObservationRollsBackBeforeCommit()
    {
        using var workspace = new TestWorkspace();
        using var cancellation = new CancellationTokenSource();
        var manifest = workspace.CreateManifest();
        var runtime = new FakeProcessRuntime();
        var timing = new FakeTiming
        {
            OnDelay = () => WriteReceipt(manifest, runtime.CurrentProcess!.Value),
        };
        runtime.OnObserve = expected =>
        {
            if (expected == runtime.NewProcessIdentity &&
                timing.Checkpoints.Contains(UpdateCheckpoint.BeforeCommit))
            {
                cancellation.Cancel();
            }
        };

        var result = await CreateEngine(runtime, timing).ApplyAsync(
            workspace.WriteManifest(manifest),
            cancellation.Token);

        Assert.Equal(UpdateExitCode.Cancelled, result);
        Assert.Equal(workspace.CurrentBytes, File.ReadAllBytes(manifest.LauncherPath));
        Assert.False(File.Exists(manifest.BackupPath));
        Assert.Contains(runtime.NewProcessIdentity, runtime.Terminated);
        Assert.Equal(2, runtime.Starts.Count);
    }

    [Theory]
    [MemberData(nameof(InvalidArguments))]
    public async Task Program_RejectsArgumentsOtherThanOneApplyManifestPair(string[] args)
    {
        var result = await Program.RunAsync(args, CancellationToken.None);

        Assert.Equal(UpdateExitCode.InvalidArguments, result);
    }

    public static TheoryData<string[]> InvalidArguments => new()
    {
        Array.Empty<string>(),
        new[] { "--apply" },
        new[] { "manifest.json" },
        new[] { "--other", "manifest.json" },
        new[] { "--apply", "one.json", "two.json" },
    };

    private const string ValidHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string ValidVersion = "1.0.5";
    private const string ValidToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    private static UpdateReplacementEngine CreateEngine(
        FakeProcessRuntime? runtime = null,
        FakeTiming? timing = null,
        IUpdatePathIdentityInspector? pathInspector = null)
        => new(
            runtime ?? new FakeProcessRuntime(),
            timing ?? new FakeTiming(),
            pathInspector ?? new WindowsUpdatePathIdentityInspector());

    private static bool FixtureCreationWasRefused(Exception ex)
        => ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException or NotSupportedException;

    private static string GetShortPathOrSkip(string path)
    {
        var buffer = new StringBuilder(32_768);
        var length = NativeTestMethods.GetShortPathName(path, buffer, buffer.Capacity);
        if (length == 0 || length >= buffer.Capacity)
        {
            throw SkipException.ForSkip(
                $"Windows refused the D:-rooted short-name fixture with error {Marshal.GetLastWin32Error()}.");
        }

        var shortPath = buffer.ToString();
        if (string.Equals(shortPath, path, StringComparison.OrdinalIgnoreCase))
        {
            throw SkipException.ForSkip("Windows did not expose an 8.3 alias for the D:-rooted fixture.");
        }

        return shortPath;
    }

    private static void WriteReceipt(
        UpdateManifest manifest,
        UpdateProcessIdentity identity,
        string? token = null,
        string? version = null,
        string phase = "ready",
        int? processId = null,
        long? processStartTimeUtcTicks = null)
    {
        File.WriteAllText(manifest.ReceiptPath, JsonSerializer.Serialize(new
        {
            token = token ?? manifest.Token,
            expectedVersion = version ?? manifest.ExpectedVersion,
            phase,
            processId = processId ?? identity.ProcessId,
            processStartTimeUtcTicks = processStartTimeUtcTicks ?? identity.StartTimeUtcTicks,
        }));
    }

    private sealed class FakeProcessRuntime : IUpdateProcessRuntime
    {
        public static UpdateProcessIdentity OldRelaunchProcessIdentity { get; } =
            new(8124, 638923682000000000);

        public UpdateProcessIdentity? CurrentProcess { get; set; }
        public UpdateProcessIdentity NewProcessIdentity { get; } = new(8123, 638923681000000000);
        public int StartFailuresRemaining { get; set; }
        public bool AllowTermination { get; set; } = true;
        public bool ObservationIsUnknown { get; set; }
        public Action<UpdateProcessIdentity>? OnObserve { get; set; }
        public Func<UpdateProcessIdentity, UpdateProcessObservation?>? ObservationOverride { get; init; }
        public List<StartAttempt> Starts { get; } = [];
        public List<UpdateProcessIdentity> Terminated { get; } = [];

        public int StartCalls => Starts.Count;

        public UpdateProcessObservation Observe(UpdateProcessIdentity expected)
        {
            OnObserve?.Invoke(expected);
            var overridden = ObservationOverride?.Invoke(expected);
            if (overridden.HasValue)
            {
                return overridden.Value;
            }

            if (ObservationIsUnknown)
            {
                return UpdateProcessObservation.Unknown;
            }

            if (!CurrentProcess.HasValue || CurrentProcess.Value.ProcessId != expected.ProcessId)
            {
                return UpdateProcessObservation.Absent;
            }

            return CurrentProcess.Value == expected
                ? UpdateProcessObservation.Matching
                : UpdateProcessObservation.Mismatched;
        }

        public UpdateProcessIdentity Start(
            string executablePath,
            string workingDirectory,
            IReadOnlyDictionary<string, string> environment)
        {
            Starts.Add(new StartAttempt(
                executablePath,
                workingDirectory,
                new Dictionary<string, string>(environment)));
            if (StartFailuresRemaining > 0)
            {
                StartFailuresRemaining--;
                throw new InvalidOperationException("Configured launch failure.");
            }

            var identity = Starts.Count == 1
                ? NewProcessIdentity
                : OldRelaunchProcessIdentity;
            CurrentProcess = identity;
            return identity;
        }

        public bool TryTerminateExact(UpdateProcessIdentity identity)
        {
            if (CurrentProcess != identity)
            {
                return false;
            }

            if (!AllowTermination)
            {
                return false;
            }

            Terminated.Add(identity);
            CurrentProcess = null;
            return true;
        }

        public sealed record StartAttempt(
            string ExecutablePath,
            string WorkingDirectory,
            IReadOnlyDictionary<string, string> Environment);
    }

    private sealed class FakeTiming : IUpdateTiming
    {
        public int DelayCalls { get; private set; }
        public int OldProcessDelayCalls { get; private set; }
        public Action? OnDelay { get; init; }
        public Action<UpdateCheckpoint>? OnCheckpoint { get; init; }
        public List<UpdateCheckpoint> Checkpoints { get; } = [];

        public Task DelayAsync(UpdateWaitKind waitKind, TimeSpan delay, CancellationToken token)
        {
            DelayCalls++;
            if (waitKind == UpdateWaitKind.OldProcess)
            {
                OldProcessDelayCalls++;
            }
            OnDelay?.Invoke();
            return Task.CompletedTask;
        }

        public Task CheckpointAsync(UpdateCheckpoint checkpoint, CancellationToken token)
        {
            Checkpoints.Add(checkpoint);
            OnCheckpoint?.Invoke(checkpoint);
            return Task.CompletedTask;
        }
    }

    private sealed class OwnerMismatchPathInspector(string mismatchPath) : IUpdatePathIdentityInspector
    {
        private readonly WindowsUpdatePathIdentityInspector _inner = new();

        public UpdatePathIdentity InspectExisting(string path)
        {
            var identity = _inner.InspectExisting(path);
            return string.Equals(path, mismatchPath, StringComparison.OrdinalIgnoreCase)
                ? identity with { OwnerMatchesCurrentUser = false }
                : identity;
        }

        public IUpdateFileTransition OpenTransition(
            string directoryPath,
            string launcherPath,
            string readyPath)
            => _inner.OpenTransition(directoryPath, launcherPath, readyPath);
    }

    private sealed class TransitionOwnerMismatchPathInspector(string mismatchPath) : IUpdatePathIdentityInspector
    {
        private readonly WindowsUpdatePathIdentityInspector _inner = new();

        public bool MismatchEnabled { get; set; }

        public UpdatePathIdentity InspectExisting(string path)
        {
            var identity = _inner.InspectExisting(path);
            return MismatchEnabled && string.Equals(path, mismatchPath, StringComparison.OrdinalIgnoreCase)
                ? identity with { OwnerMatchesCurrentUser = false }
                : identity;
        }

        public IUpdateFileTransition OpenTransition(
            string directoryPath,
            string launcherPath,
            string readyPath)
            => new OwnerMismatchTransition(
                _inner.OpenTransition(directoryPath, launcherPath, readyPath),
                MismatchEnabled,
                mismatchPath,
                directoryPath,
                launcherPath,
                readyPath);

        private sealed class OwnerMismatchTransition(
            IUpdateFileTransition inner,
            bool mismatchEnabled,
            string mismatchPath,
            string directoryPath,
            string launcherPath,
            string readyPath) : IUpdateFileTransition
        {
            public UpdatePathIdentity DirectoryIdentity => MaybeMismatch(
                inner.DirectoryIdentity,
                directoryPath);

            public UpdatePathIdentity LauncherIdentity => MaybeMismatch(
                inner.LauncherIdentity,
                launcherPath);

            public UpdatePathIdentity ReadyIdentity => MaybeMismatch(
                inner.ReadyIdentity,
                readyPath);

            public bool LauncherHashMatches(string expected)
                => inner.LauncherHashMatches(expected);

            public bool ReadyHashMatches(string expected)
                => inner.ReadyHashMatches(expected);

            public void RenameLauncherTo(string destinationPath)
                => inner.RenameLauncherTo(destinationPath);

            public void RenameReadyTo(string destinationPath)
                => inner.RenameReadyTo(destinationPath);

            public void Dispose()
                => inner.Dispose();

            private UpdatePathIdentity MaybeMismatch(UpdatePathIdentity identity, string path)
                => mismatchEnabled && string.Equals(path, mismatchPath, StringComparison.OrdinalIgnoreCase)
                    ? identity with { OwnerMatchesCurrentUser = false }
                    : identity;
        }
    }

    private static class NativeTestMethods
    {
        [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateHardLink(string newFileName, string existingFileName, nint securityAttributes);

        [DllImport("kernel32.dll", EntryPoint = "GetShortPathNameW", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern uint GetShortPathName(string longPath, StringBuilder shortPath, int bufferLength);
    }

    private sealed class TestWorkspace : IDisposable
    {
        public TestWorkspace()
        {
            Root = Path.Combine(
                @"D:\ApfsAccessScratch\TestRuns\ApfsAccess.Updater.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }
        public byte[] CurrentBytes { get; } = Encoding.UTF8.GetBytes("current launcher");
        public byte[] ReadyBytes { get; } = Encoding.UTF8.GetBytes("ready launcher");

        public UpdateManifest CreateManifest()
        {
            var launcherPath = CreateFile("APFS Access.exe", CurrentBytes);
            var readyPath = CreateFile("APFS Access.update.ready", ReadyBytes);
            return new UpdateManifest(
                OldTrayProcessId: 4123,
                OldTrayStartTimeUtcTicks: 638923680000000000,
                LauncherPath: launcherPath,
                ReadyPath: readyPath,
                BackupPath: Path.Combine(Root, "APFS Access.update.backup"),
                ReceiptPath: Path.Combine(Root, "APFS Access.update.receipt.json"),
                CurrentSha256: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(CurrentBytes)),
                ExpectedSha256: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ReadyBytes)),
                ExpectedVersion: ValidVersion,
                Token: ValidToken);
        }

        public string WriteManifest(UpdateManifest manifest)
        {
            var path = Path.Combine(Root, "APFS Access.update.manifest.json");
            File.WriteAllText(path, JsonSerializer.Serialize(manifest, JsonOptions));
            return path;
        }

        private string CreateFile(string fileName, byte[] content)
        {
            var path = Path.Combine(Root, fileName);
            File.WriteAllBytes(path, content);
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }

        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    }
}
