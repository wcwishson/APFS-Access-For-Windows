using System.Diagnostics;
using System.ComponentModel;
using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Updater;

public sealed class UpdateReplacementEngine
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(100);
    private const int OldProcessPollLimit = 50;
    private const int ReadinessPollLimit = 200;

    private readonly IUpdateProcessRuntime _processRuntime;
    private readonly IUpdateTiming _timing;
    private readonly IUpdatePathIdentityInspector _pathInspector;

    public UpdateReplacementEngine()
        : this(
            new SystemUpdateProcessRuntime(),
            new SystemUpdateTiming(),
            new WindowsUpdatePathIdentityInspector())
    {
    }

    internal UpdateReplacementEngine(
        IUpdateProcessRuntime processRuntime,
        IUpdateTiming timing)
        : this(processRuntime, timing, new WindowsUpdatePathIdentityInspector())
    {
    }

    internal UpdateReplacementEngine(
        IUpdateProcessRuntime processRuntime,
        IUpdateTiming timing,
        IUpdatePathIdentityInspector pathInspector)
    {
        _processRuntime = processRuntime;
        _timing = timing;
        _pathInspector = pathInspector;
    }

    public async Task<int> ApplyAsync(string manifestPath, CancellationToken token)
    {
        if (!TryLoadManifest(manifestPath, out var approvedUpdate))
        {
            WriteDiagnostic(manifestPath, "The update manifest was rejected.");
            return UpdateExitCode.InvalidManifest;
        }

        var manifest = approvedUpdate.Manifest;

        try
        {
            if (!await WaitForOldProcessExitAsync(manifest, token))
            {
                WriteDiagnostic(manifestPath, "The previous tray process did not exit before the timeout.");
                return UpdateExitCode.OldProcessTimeout;
            }

            token.ThrowIfCancellationRequested();
            await _timing.CheckpointAsync(UpdateCheckpoint.BeforeReplacement, token);
            using var transition = _pathInspector.OpenTransition(
                Path.GetDirectoryName(manifest.LauncherPath)!,
                manifest.LauncherPath,
                manifest.ReadyPath);
            if (!TransitionMatchesApproval(approvedUpdate, transition) ||
                FileSystemEntryExists(manifest.BackupPath) ||
                FileSystemEntryExists(manifest.ReceiptPath))
            {
                WriteDiagnostic(manifestPath, "The launcher or staged update changed before replacement.");
                return UpdateExitCode.ReplacementFailed;
            }

            await ForwardCheckpointAsync(UpdateCheckpoint.AfterTransitionHandlesOpened, token);

            return await ReplaceAndRelaunchAsync(manifestPath, manifest, transition, token);
        }
        catch (OperationCanceledException)
        {
            WriteDiagnostic(manifestPath, "The update was canceled before replacement.");
            return UpdateExitCode.Cancelled;
        }
        catch (Exception ex) when (IsExpectedUpdateFailure(ex))
        {
            WriteDiagnostic(manifestPath, "The launcher could not be replaced.");
            return UpdateExitCode.ReplacementFailed;
        }
    }

    private async Task<int> ReplaceAndRelaunchAsync(
        string manifestPath,
        UpdateManifest manifest,
        IUpdateFileTransition transition,
        CancellationToken token)
    {
        var backupCreated = false;
        var committed = false;
        UpdateProcessIdentity? launchedProcess = null;
        var failureCode = UpdateExitCode.ReplacementFailed;

        try
        {
            if (!transition.LauncherHashMatches(manifest.CurrentSha256) ||
                !transition.ReadyHashMatches(manifest.ExpectedSha256))
            {
                throw new InvalidDataException("A launcher hash changed before replacement.");
            }

            transition.RenameLauncherTo(manifest.BackupPath);
            backupCreated = true;
            await ForwardCheckpointAsync(UpdateCheckpoint.AfterBackupCreated, token);
            if (!transition.LauncherHashMatches(manifest.CurrentSha256))
            {
                throw new InvalidDataException("The backup hash changed during replacement.");
            }

            transition.RenameReadyTo(manifest.LauncherPath);
            if (!transition.ReadyHashMatches(manifest.ExpectedSha256))
            {
                throw new InvalidDataException("The installed launcher hash changed during replacement.");
            }
            transition.Dispose();
            await ForwardCheckpointAsync(UpdateCheckpoint.AfterReadyInstalled, token);
            RequireHash(manifest.LauncherPath, manifest.ExpectedSha256);

            failureCode = UpdateExitCode.ReadinessFailed;
            var bootstrapProcess = _processRuntime.Start(
                manifest.LauncherPath,
                Path.GetDirectoryName(manifest.LauncherPath)!,
                BuildLaunchEnvironment(manifest));
            launchedProcess = bootstrapProcess;
            await ForwardCheckpointAsync(UpdateCheckpoint.AfterLaunch, token);

            var readiness = await WaitForReadinessAsync(manifest, bootstrapProcess, token);
            launchedProcess = readiness.Process ?? bootstrapProcess;
            if (!readiness.Ready)
            {
                throw new ReadinessException();
            }
            await ForwardCheckpointAsync(UpdateCheckpoint.AfterReadiness, token);

            RequireHash(manifest.BackupPath, manifest.CurrentSha256);
            RequireHash(manifest.LauncherPath, manifest.ExpectedSha256);
            await ForwardCheckpointAsync(UpdateCheckpoint.BeforeCommit, token);
            if (_processRuntime.Observe(launchedProcess.Value) != UpdateProcessObservation.Matching)
            {
                throw new ReadinessException();
            }
            token.ThrowIfCancellationRequested();

            File.Delete(manifest.BackupPath);
            committed = true;
            DeleteBestEffort(manifest.ReceiptPath);
            DeleteBestEffort(manifestPath);
            return UpdateExitCode.Success;
        }
        catch (OperationCanceledException)
        {
            failureCode = UpdateExitCode.Cancelled;
        }
        catch (ReadinessException)
        {
            failureCode = UpdateExitCode.ReadinessFailed;
        }
        catch (Exception ex) when (IsExpectedUpdateFailure(ex))
        {
            // The failure code records whether replacement or relaunch had begun.
        }
        finally
        {
            transition.Dispose();
        }

        if (backupCreated && !committed)
        {
            if (!await TryRestoreAndRelaunchOldAsync(manifest, launchedProcess))
            {
                WriteDiagnostic(manifestPath, "Update rollback could not restore and relaunch the previous launcher.");
                return UpdateExitCode.RollbackFailed;
            }
        }

        WriteDiagnostic(
            manifestPath,
            failureCode == UpdateExitCode.ReadinessFailed
                ? "The revised launcher did not produce a matching ready receipt; the previous launcher was restored."
                : "The update failed after backup; the previous launcher was restored.");
        return failureCode;
    }

    private bool TryLoadManifest(string manifestPath, out ApprovedUpdate approvedUpdate)
    {
        approvedUpdate = null!;
        try
        {
            if (!IsCanonicalAbsolutePath(manifestPath) ||
                HasAlternateDataStreamSyntax(manifestPath) ||
                !File.Exists(manifestPath) ||
                !ValidateManifestEnvelope(manifestPath))
            {
                return false;
            }

            var manifest = JsonSerializer.Deserialize<UpdateManifest>(
                File.ReadAllText(manifestPath),
                JsonOptions)!;
            return manifest is not null &&
                   TryValidateManifest(manifestPath, manifest, out approvedUpdate);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException or Win32Exception or JsonException)
        {
            return false;
        }
    }

    private bool TryValidateManifest(
        string manifestPath,
        UpdateManifest manifest,
        out ApprovedUpdate approvedUpdate)
    {
        approvedUpdate = null!;
        if (manifest.OldTrayProcessId <= 0 ||
            manifest.OldTrayStartTimeUtcTicks <= 0 ||
            !IsSha256(manifest.CurrentSha256) ||
            !IsSha256(manifest.ExpectedSha256) ||
            !IsStrictVersion(manifest.ExpectedVersion) ||
            !IsToken(manifest.Token))
        {
            return false;
        }

        var paths = new[]
        {
            manifestPath,
            manifest.LauncherPath,
            manifest.ReadyPath,
            manifest.BackupPath,
            manifest.ReceiptPath,
        };
        if (paths.Any(path => !IsCanonicalAbsolutePath(path) || HasAlternateDataStreamSyntax(path)) ||
            paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length)
        {
            return false;
        }

        var directory = Path.GetDirectoryName(manifestPath);
        if (string.IsNullOrWhiteSpace(directory) ||
            paths.Skip(1).Any(path => !string.Equals(
                Path.GetDirectoryName(path),
                directory,
                StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (!TryValidateExistingPathSet(
                directory,
                manifestPath,
                manifest.LauncherPath,
                manifest.ReadyPath,
                out var directoryIdentity,
                out var launcherIdentity,
                out var readyIdentity) ||
            !File.Exists(manifest.LauncherPath) ||
            !File.Exists(manifest.ReadyPath) ||
            FileSystemEntryExists(manifest.BackupPath) ||
            FileSystemEntryExists(manifest.ReceiptPath) ||
            !HashMatches(manifest.LauncherPath, manifest.CurrentSha256) ||
            !HashMatches(manifest.ReadyPath, manifest.ExpectedSha256))
        {
            return false;
        }

        approvedUpdate = new ApprovedUpdate(
            manifest,
            directoryIdentity,
            launcherIdentity,
            readyIdentity);
        return true;
    }

    private bool ValidateManifestEnvelope(string manifestPath)
    {
        var directory = Path.GetDirectoryName(manifestPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return false;
        }

        var directoryIdentity = _pathInspector.InspectExisting(directory);
        var manifestIdentity = _pathInspector.InspectExisting(manifestPath);
        return ExistingPathMatches(directory, directoryIdentity, expectDirectory: true) &&
               ExistingPathMatches(manifestPath, manifestIdentity, expectDirectory: false) &&
               string.Equals(
                   Path.GetDirectoryName(manifestIdentity.FinalPath),
                   directoryIdentity.FinalPath,
                   StringComparison.OrdinalIgnoreCase);
    }

    private bool TryValidateExistingPathSet(
        string directory,
        string manifestPath,
        string launcherPath,
        string readyPath,
        out UpdatePathIdentity directoryIdentity,
        out UpdatePathIdentity launcherIdentity,
        out UpdatePathIdentity readyIdentity)
    {
        var inspectedDirectoryIdentity = _pathInspector.InspectExisting(directory);
        directoryIdentity = inspectedDirectoryIdentity;
        launcherIdentity = null!;
        readyIdentity = null!;
        if (!ExistingPathMatches(directory, inspectedDirectoryIdentity, expectDirectory: true))
        {
            return false;
        }

        var paths = new[] { manifestPath, launcherPath, readyPath };
        var identities = paths.Select(_pathInspector.InspectExisting).ToArray();
        if (identities.Where((identity, index) =>
                !ExistingPathMatches(paths[index], identity, expectDirectory: false) ||
                identity.LinkCount != 1 ||
                !string.Equals(
                    Path.GetDirectoryName(identity.FinalPath),
                    inspectedDirectoryIdentity.FinalPath,
                    StringComparison.OrdinalIgnoreCase)).Any())
        {
            return false;
        }

        if (identities.Select(identity => identity.FileIdentity).Distinct().Count() != identities.Length)
        {
            return false;
        }

        launcherIdentity = identities[1];
        readyIdentity = identities[2];
        return true;
    }

    private static bool ExistingPathMatches(
        string suppliedPath,
        UpdatePathIdentity identity,
        bool expectDirectory)
        => identity.IsDirectory == expectDirectory &&
           !identity.IsReparsePoint &&
           identity.OwnerMatchesCurrentUser &&
           string.Equals(identity.FinalPath, suppliedPath, StringComparison.OrdinalIgnoreCase);

    private static bool TransitionMatchesApproval(
        ApprovedUpdate approvedUpdate,
        IUpdateFileTransition transition)
        => transition.DirectoryIdentity == approvedUpdate.DirectoryIdentity &&
           transition.LauncherIdentity == approvedUpdate.LauncherIdentity &&
           transition.ReadyIdentity == approvedUpdate.ReadyIdentity;

    private async Task<bool> WaitForOldProcessExitAsync(
        UpdateManifest manifest,
        CancellationToken token)
    {
        var expected = new UpdateProcessIdentity(
            manifest.OldTrayProcessId,
            manifest.OldTrayStartTimeUtcTicks);

        for (var poll = 0; poll < OldProcessPollLimit; poll++)
        {
            var observation = _processRuntime.Observe(expected);
            if (observation is UpdateProcessObservation.Absent or UpdateProcessObservation.Mismatched)
            {
                return true;
            }

            await _timing.DelayAsync(UpdateWaitKind.OldProcess, PollInterval, token);
        }

        return _processRuntime.Observe(expected) is
            UpdateProcessObservation.Absent or UpdateProcessObservation.Mismatched;
    }

    private async Task<UpdateReadinessResult> WaitForReadinessAsync(
        UpdateManifest manifest,
        UpdateProcessIdentity bootstrapProcess,
        CancellationToken token)
    {
        UpdateProcessIdentity? receiptProcess = null;
        for (var poll = 0; poll < ReadinessPollLimit; poll++)
        {
            if (TryReadReceipt(manifest, out var receipt))
            {
                var candidate = new UpdateProcessIdentity(
                    receipt.ProcessId,
                    receipt.ProcessStartTimeUtcTicks);
                if (_processRuntime.Observe(candidate) == UpdateProcessObservation.Matching)
                {
                    receiptProcess = candidate;
                    if (string.Equals(receipt.Phase, "ready", StringComparison.Ordinal))
                    {
                        await ForwardCheckpointAsync(UpdateCheckpoint.AfterReceiptParsed, token);
                        return new UpdateReadinessResult(Ready: true, Process: candidate);
                    }
                }
            }

            if (receiptProcess is null &&
                _processRuntime.Observe(bootstrapProcess) == UpdateProcessObservation.Unknown)
            {
                return new UpdateReadinessResult(Ready: false, Process: null);
            }

            await _timing.DelayAsync(UpdateWaitKind.Readiness, PollInterval, token);
        }

        if (TryReadReceipt(manifest, out var finalReceipt))
        {
            var finalProcess = new UpdateProcessIdentity(
                finalReceipt.ProcessId,
                finalReceipt.ProcessStartTimeUtcTicks);
            if (_processRuntime.Observe(finalProcess) == UpdateProcessObservation.Matching)
            {
                receiptProcess = finalProcess;
                if (string.Equals(finalReceipt.Phase, "ready", StringComparison.Ordinal))
                {
                    await ForwardCheckpointAsync(UpdateCheckpoint.AfterReceiptParsed, token);
                    return new UpdateReadinessResult(Ready: true, Process: finalProcess);
                }
            }
        }

        return new UpdateReadinessResult(Ready: false, Process: receiptProcess);
    }

    private static bool TryReadReceipt(UpdateManifest manifest, out UpdateReceipt receipt)
    {
        receipt = null!;
        try
        {
            if (!File.Exists(manifest.ReceiptPath))
            {
                return false;
            }

            var parsed = JsonSerializer.Deserialize<UpdateReceipt>(
                File.ReadAllText(manifest.ReceiptPath),
                JsonOptions);
            if (parsed is null ||
                !string.Equals(parsed.Token, manifest.Token, StringComparison.Ordinal) ||
                !string.Equals(parsed.ExpectedVersion, manifest.ExpectedVersion, StringComparison.Ordinal) ||
                (parsed.Phase != "launched" && parsed.Phase != "ready") ||
                parsed.ProcessId <= 0 ||
                parsed.ProcessStartTimeUtcTicks <= 0)
            {
                return false;
            }

            receipt = parsed;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private async Task ForwardCheckpointAsync(
        UpdateCheckpoint checkpoint,
        CancellationToken token)
    {
        await _timing.CheckpointAsync(checkpoint, token);
        token.ThrowIfCancellationRequested();
    }

    private async Task<bool> TryRestoreAndRelaunchOldAsync(
        UpdateManifest manifest,
        UpdateProcessIdentity? launchedProcess)
    {
        string? heldCandidatePath = null;

        try
        {
            if (!File.Exists(manifest.BackupPath) ||
                !HashMatches(manifest.BackupPath, manifest.CurrentSha256))
            {
                return false;
            }

            if (launchedProcess.HasValue)
            {
                var observation = _processRuntime.Observe(launchedProcess.Value);
                if (observation == UpdateProcessObservation.Unknown)
                {
                    return false;
                }

                if (observation == UpdateProcessObservation.Matching &&
                    (!_processRuntime.TryTerminateExact(launchedProcess.Value) ||
                     _processRuntime.Observe(launchedProcess.Value) is
                         UpdateProcessObservation.Matching or UpdateProcessObservation.Unknown))
                {
                    return false;
                }
            }

            if (File.Exists(manifest.LauncherPath))
            {
                await _timing.CheckpointAsync(
                    UpdateCheckpoint.BeforeCandidateHold,
                    CancellationToken.None);
                heldCandidatePath = CreateFailedCandidatePath(manifest.LauncherPath);
                File.Move(manifest.LauncherPath, heldCandidatePath);
            }

            RequireHash(manifest.BackupPath, manifest.CurrentSha256);
            await _timing.CheckpointAsync(
                UpdateCheckpoint.BeforeBackupRestore,
                CancellationToken.None);
            File.Move(manifest.BackupPath, manifest.LauncherPath);
            RequireHash(manifest.LauncherPath, manifest.CurrentSha256);
            var oldProcess = _processRuntime.Start(
                manifest.LauncherPath,
                Path.GetDirectoryName(manifest.LauncherPath)!,
                EmptyEnvironment);

            var oldObservation = _processRuntime.Observe(oldProcess);
            if (oldObservation == UpdateProcessObservation.Unknown)
            {
                return false;
            }

            if (oldObservation != UpdateProcessObservation.Matching)
            {
                RestorePreRollbackLayout(manifest, heldCandidatePath);
                return false;
            }

            if (heldCandidatePath is not null)
            {
                DeleteBestEffort(heldCandidatePath);
            }

            return true;
        }
        catch (Exception ex) when (IsExpectedUpdateFailure(ex))
        {
            RestorePreRollbackLayout(manifest, heldCandidatePath);
            return false;
        }
    }

    private static string CreateFailedCandidatePath(string launcherPath)
    {
        var directory = Path.GetDirectoryName(launcherPath)!;
        string path;
        do
        {
            path = Path.Combine(
                directory,
                $".APFS.Access.update.failed.{Guid.NewGuid():N}.hold");
        }
        while (File.Exists(path));

        return path;
    }

    private static void RestorePreRollbackLayout(
        UpdateManifest manifest,
        string? heldCandidatePath)
    {
        try
        {
            if (File.Exists(manifest.LauncherPath) && !File.Exists(manifest.BackupPath))
            {
                File.Move(manifest.LauncherPath, manifest.BackupPath);
            }

            if (heldCandidatePath is not null &&
                File.Exists(heldCandidatePath) &&
                !File.Exists(manifest.LauncherPath))
            {
                File.Move(heldCandidatePath, manifest.LauncherPath);
            }
        }
        catch (Exception ex) when (IsExpectedUpdateFailure(ex))
        {
            // Preserve whatever recovery objects remain; do not delete either one.
        }
    }

    private static IReadOnlyDictionary<string, string> BuildLaunchEnvironment(UpdateManifest manifest)
        => new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["APFSACCESS_UPDATE_TOKEN"] = manifest.Token,
            ["APFSACCESS_UPDATE_EXPECTED_VERSION"] = manifest.ExpectedVersion,
            ["APFSACCESS_UPDATE_RECEIPT_PATH"] = manifest.ReceiptPath,
        };

    private static bool IsCanonicalAbsolutePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        try
        {
            return string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static bool HasAlternateDataStreamSyntax(string path)
    {
        var root = Path.GetPathRoot(path);
        return string.IsNullOrEmpty(root) || path.AsSpan(root.Length).Contains(':');
    }

    private static bool FileSystemEntryExists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static bool IsSha256(string? value)
        => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static bool IsToken(string? value)
        => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static bool IsStrictVersion(string? value)
    {
        var components = value?.Split('.');
        return components is { Length: 3 } && components.All(component =>
            component.Length > 0 &&
            (component.Length == 1 || component[0] != '0') &&
            int.TryParse(component, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    private static bool HashMatches(string path, string expected)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireHash(string path, string expected)
    {
        if (!HashMatches(path, expected))
        {
            throw new InvalidDataException("A launcher hash changed during replacement.");
        }
    }

    private static bool IsExpectedUpdateFailure(Exception ex)
        => ex is IOException or UnauthorizedAccessException or
           InvalidDataException or InvalidOperationException or
           System.Security.SecurityException or System.ComponentModel.Win32Exception;

    private static void DeleteBestEffort(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The update has committed; stale handoff metadata is token-bound and harmless.
        }
    }

    private static void WriteDiagnostic(string manifestPath, string message)
    {
        foreach (var directory in DiagnosticDirectories(manifestPath))
        {
            try
            {
                Directory.CreateDirectory(directory);
                File.WriteAllText(
                    Path.Combine(directory, "apfs-access-update-diagnostic.txt"),
                    $"{DateTime.UtcNow:O} {message}{Environment.NewLine}");
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // Try the next bounded diagnostic location.
            }
        }
    }

    private static IEnumerable<string> DiagnosticDirectories(string manifestPath)
    {
        var runtimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        if (IsCanonicalAbsolutePath(runtimeRoot))
        {
            yield return runtimeRoot!;
        }

        if (IsCanonicalAbsolutePath(manifestPath))
        {
            var manifestDirectory = Path.GetDirectoryName(manifestPath);
            if (!string.IsNullOrWhiteSpace(manifestDirectory) &&
                string.Equals(Path.GetPathRoot(manifestDirectory), @"D:\", StringComparison.OrdinalIgnoreCase))
            {
                yield return manifestDirectory;
            }
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
    };

    private static readonly IReadOnlyDictionary<string, string> EmptyEnvironment =
        new Dictionary<string, string>();

    private sealed record ApprovedUpdate(
        UpdateManifest Manifest,
        UpdatePathIdentity DirectoryIdentity,
        UpdatePathIdentity LauncherIdentity,
        UpdatePathIdentity ReadyIdentity);

    private sealed record UpdateReceipt(
        string Token,
        string ExpectedVersion,
        string Phase,
        int ProcessId,
        long ProcessStartTimeUtcTicks);

    private readonly record struct UpdateReadinessResult(bool Ready, UpdateProcessIdentity? Process);

    private sealed class ReadinessException : Exception;
}

internal static class UpdateExitCode
{
    public const int Success = 0;
    public const int InvalidArguments = 2;
    public const int InvalidManifest = 10;
    public const int OldProcessTimeout = 20;
    public const int ReplacementFailed = 30;
    public const int ReadinessFailed = 40;
    public const int RollbackFailed = 50;
    public const int Cancelled = 60;
}

internal readonly record struct UpdateProcessIdentity(int ProcessId, long StartTimeUtcTicks);

internal interface IUpdateProcessRuntime
{
    UpdateProcessObservation Observe(UpdateProcessIdentity expected);

    UpdateProcessIdentity Start(
        string executablePath,
        string workingDirectory,
        IReadOnlyDictionary<string, string> environment);

    bool TryTerminateExact(UpdateProcessIdentity identity);
}

internal enum UpdateProcessObservation
{
    Absent,
    Matching,
    Mismatched,
    Unknown,
}

internal interface IUpdateTiming
{
    Task DelayAsync(UpdateWaitKind waitKind, TimeSpan delay, CancellationToken token);

    Task CheckpointAsync(UpdateCheckpoint checkpoint, CancellationToken token);
}

internal readonly record struct UpdateFileIdentity(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh);

internal sealed record UpdatePathIdentity(
    string FinalPath,
    UpdateFileIdentity FileIdentity,
    uint LinkCount,
    bool IsDirectory,
    bool IsReparsePoint,
    bool OwnerMatchesCurrentUser);

internal interface IUpdatePathIdentityInspector
{
    UpdatePathIdentity InspectExisting(string path);

    IUpdateFileTransition OpenTransition(
        string directoryPath,
        string launcherPath,
        string readyPath);
}

internal interface IUpdateFileTransition : IDisposable
{
    UpdatePathIdentity DirectoryIdentity { get; }

    UpdatePathIdentity LauncherIdentity { get; }

    UpdatePathIdentity ReadyIdentity { get; }

    bool LauncherHashMatches(string expected);

    bool ReadyHashMatches(string expected);

    void RenameLauncherTo(string destinationPath);

    void RenameReadyTo(string destinationPath);
}

internal sealed class WindowsUpdatePathIdentityInspector : IUpdatePathIdentityInspector
{
    public UpdatePathIdentity InspectExisting(string path)
    {
        using var handle = OpenHandle(
            path,
            NativeMethods.FileReadAttributes | NativeMethods.ReadControl,
            NativeMethods.FileShareRead | NativeMethods.FileShareWrite | NativeMethods.FileShareDelete);
        return InspectHandle(handle);
    }

    public IUpdateFileTransition OpenTransition(
        string directoryPath,
        string launcherPath,
        string readyPath)
        => WindowsUpdateFileTransition.Open(directoryPath, launcherPath, readyPath);

    private static SafeFileHandle OpenHandle(string path, uint desiredAccess, uint shareMode)
    {
        var handle = NativeMethods.CreateFile(
            path,
            desiredAccess,
            shareMode,
            0,
            NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagOpenReparsePoint,
            0);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(
                error,
                "Could not open an update path for identity validation.");
        }

        return handle;
    }

    private static UpdatePathIdentity InspectHandle(SafeFileHandle handle)
    {
        if (!NativeMethods.GetFileInformationByHandle(handle, out var information))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not read an update path identity.");
        }

        return new UpdatePathIdentity(
            GetFinalPath(handle),
            new UpdateFileIdentity(
                information.VolumeSerialNumber,
                information.FileIndexLow,
                information.FileIndexHigh),
            information.NumberOfLinks,
            IsDirectory: (information.FileAttributes & (uint)FileAttributes.Directory) != 0,
            IsReparsePoint: (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0,
            OwnerMatchesCurrentUser: IsOwnedByCurrentUser(handle));
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32_768)
        {
            var buffer = new StringBuilder(capacity);
            var length = NativeMethods.GetFinalPathNameByHandle(
                handle,
                buffer,
                buffer.Capacity,
                NativeMethods.VolumeNameDos);
            if (length == 0)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not resolve an update path to its final path.");
            }

            if (length < buffer.Capacity)
            {
                return NormalizeFinalPath(buffer.ToString());
            }

            capacity = checked((int)length + 1);
        }

        throw new InvalidDataException("An update path exceeded the supported final-path length.");
    }

    private static string NormalizeFinalPath(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return Path.GetFullPath(@"\\" + path[8..]);
        }

        return Path.GetFullPath(
            path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path);
    }

    private static bool IsOwnedByCurrentUser(SafeFileHandle handle)
    {
        var result = NativeMethods.GetSecurityInfo(
            handle,
            NativeMethods.SeFileObject,
            NativeMethods.OwnerSecurityInformation,
            out var ownerPointer,
            0,
            0,
            0,
            out var securityDescriptor);
        if (result != NativeMethods.ErrorSuccess)
        {
            throw new Win32Exception(
                checked((int)result),
                "Could not read the owner of an update path handle.");
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            var owner = ownerPointer == 0 ? null : new SecurityIdentifier(ownerPointer);
            return identity.User is not null && owner is not null && identity.User.Equals(owner);
        }
        finally
        {
            if (securityDescriptor != 0)
            {
                _ = NativeMethods.LocalFree(securityDescriptor);
            }
        }
    }

    private static bool HashMatches(SafeFileHandle handle, string expected)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long offset = 0;
            while (true)
            {
                var read = RandomAccess.Read(handle, buffer.AsSpan(0, 64 * 1024), offset);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
                offset += read;
            }

            return string.Equals(
                Convert.ToHexString(hash.GetHashAndReset()),
                expected,
                StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void RenameHandle(
        SafeFileHandle handle,
        string destinationPath,
        string verifiedDirectoryPath)
    {
        if (!string.Equals(
                Path.GetDirectoryName(destinationPath),
                verifiedDirectoryPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("A handle-bound rename left the verified update directory.");
        }

        var destinationBytes = Encoding.Unicode.GetBytes(destinationPath);
        var rootDirectoryOffset = IntPtr.Size == 8 ? 8 : 4;
        var fileNameLengthOffset = rootDirectoryOffset + IntPtr.Size;
        var fileNameOffset = fileNameLengthOffset + sizeof(uint);
        var bufferSize = checked(fileNameOffset + destinationBytes.Length + sizeof(char));
        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            Marshal.Copy(new byte[bufferSize], 0, buffer, bufferSize);
            Marshal.WriteInt32(buffer, 0, 0);
            Marshal.WriteIntPtr(buffer, rootDirectoryOffset, 0);
            Marshal.WriteInt32(buffer, fileNameLengthOffset, destinationBytes.Length);
            Marshal.Copy(
                destinationBytes,
                0,
                IntPtr.Add(buffer, fileNameOffset),
                destinationBytes.Length);
            if (!NativeMethods.SetFileInformationByHandle(
                    handle,
                    NativeMethods.FileRenameInfo,
                    buffer,
                    checked((uint)bufferSize)))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "A handle-bound launcher rename failed.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private sealed class WindowsUpdateFileTransition : IUpdateFileTransition
    {
        private readonly SafeFileHandle _directoryHandle;
        private readonly SafeFileHandle _launcherHandle;
        private readonly SafeFileHandle _readyHandle;

        private WindowsUpdateFileTransition(
            SafeFileHandle directoryHandle,
            SafeFileHandle launcherHandle,
            SafeFileHandle readyHandle)
        {
            _directoryHandle = directoryHandle;
            _launcherHandle = launcherHandle;
            _readyHandle = readyHandle;
            DirectoryIdentity = InspectHandle(directoryHandle);
            LauncherIdentity = InspectHandle(launcherHandle);
            ReadyIdentity = InspectHandle(readyHandle);
        }

        public UpdatePathIdentity DirectoryIdentity { get; }

        public UpdatePathIdentity LauncherIdentity { get; }

        public UpdatePathIdentity ReadyIdentity { get; }

        public static WindowsUpdateFileTransition Open(
            string directoryPath,
            string launcherPath,
            string readyPath)
        {
            SafeFileHandle? directoryHandle = null;
            SafeFileHandle? launcherHandle = null;
            SafeFileHandle? readyHandle = null;
            try
            {
                directoryHandle = OpenHandle(
                    directoryPath,
                    NativeMethods.FileReadAttributes | NativeMethods.ReadControl,
                    NativeMethods.FileShareRead | NativeMethods.FileShareWrite);
                launcherHandle = OpenHandle(
                    launcherPath,
                    NativeMethods.FileReadData | NativeMethods.FileReadAttributes |
                    NativeMethods.ReadControl | NativeMethods.Delete,
                    NativeMethods.FileShareRead);
                readyHandle = OpenHandle(
                    readyPath,
                    NativeMethods.FileReadData | NativeMethods.FileReadAttributes |
                    NativeMethods.ReadControl | NativeMethods.Delete,
                    NativeMethods.FileShareRead);
                return new WindowsUpdateFileTransition(
                    directoryHandle,
                    launcherHandle,
                    readyHandle);
            }
            catch
            {
                readyHandle?.Dispose();
                launcherHandle?.Dispose();
                directoryHandle?.Dispose();
                throw;
            }
        }

        public bool LauncherHashMatches(string expected)
            => HashMatches(_launcherHandle, expected);

        public bool ReadyHashMatches(string expected)
            => HashMatches(_readyHandle, expected);

        public void RenameLauncherTo(string destinationPath)
            => RenameHandle(_launcherHandle, destinationPath, DirectoryIdentity.FinalPath);

        public void RenameReadyTo(string destinationPath)
            => RenameHandle(_readyHandle, destinationPath, DirectoryIdentity.FinalPath);

        public void Dispose()
        {
            _readyHandle.Dispose();
            _launcherHandle.Dispose();
            _directoryHandle.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private static class NativeMethods
    {
        internal const uint FileReadAttributes = 0x00000080;
        internal const uint FileReadData = 0x00000001;
        internal const uint Delete = 0x00010000;
        internal const uint ReadControl = 0x00020000;
        internal const uint FileShareRead = 0x00000001;
        internal const uint FileShareWrite = 0x00000002;
        internal const uint FileShareDelete = 0x00000004;
        internal const uint OpenExisting = 3;
        internal const uint FileFlagBackupSemantics = 0x02000000;
        internal const uint FileFlagOpenReparsePoint = 0x00200000;
        internal const uint VolumeNameDos = 0;
        internal const uint ErrorSuccess = 0;
        internal const uint SeFileObject = 1;
        internal const uint OwnerSecurityInformation = 0x00000001;
        internal const int FileRenameInfo = 3;

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            nint securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            nint templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder path,
            int pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int fileInformationClass,
            nint fileInformation,
            uint bufferSize);

        [DllImport("advapi32.dll")]
        internal static extern uint GetSecurityInfo(
            SafeFileHandle handle,
            uint objectType,
            uint securityInfo,
            out nint owner,
            nint group,
            nint dacl,
            nint sacl,
            out nint securityDescriptor);

        [DllImport("kernel32.dll")]
        internal static extern nint LocalFree(nint memory);
    }
}

internal enum UpdateWaitKind
{
    OldProcess,
    Readiness,
}

internal enum UpdateCheckpoint
{
    BeforeReplacement,
    AfterTransitionHandlesOpened,
    AfterBackupCreated,
    AfterReadyInstalled,
    AfterLaunch,
    BeforeCandidateHold,
    BeforeBackupRestore,
    AfterReceiptParsed,
    AfterReadiness,
    BeforeCommit,
}

internal sealed class SystemUpdateTiming : IUpdateTiming
{
    public Task DelayAsync(UpdateWaitKind waitKind, TimeSpan delay, CancellationToken token)
        => Task.Delay(delay, token);

    public Task CheckpointAsync(UpdateCheckpoint checkpoint, CancellationToken token)
        => Task.CompletedTask;
}

internal sealed class SystemUpdateProcessRuntime : IUpdateProcessRuntime
{
    public UpdateProcessObservation Observe(UpdateProcessIdentity expected)
    {
        Process process;
        try
        {
            process = Process.GetProcessById(expected.ProcessId);
        }
        catch (ArgumentException)
        {
            return UpdateProcessObservation.Absent;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return UpdateProcessObservation.Unknown;
        }

        using (process)
        {
            try
            {
                var actual = new UpdateProcessIdentity(
                    process.Id,
                    process.StartTime.ToUniversalTime().Ticks);
                return actual == expected
                    ? UpdateProcessObservation.Matching
                    : UpdateProcessObservation.Mismatched;
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
            {
                return UpdateProcessObservation.Unknown;
            }
        }
    }

    public UpdateProcessIdentity Start(
        string executablePath,
        string workingDirectory,
        IReadOnlyDictionary<string, string> environment)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var (name, value) in environment)
        {
            startInfo.Environment[name] = value;
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The launcher process did not start.");
        return new UpdateProcessIdentity(process.Id, process.StartTime.ToUniversalTime().Ticks);
    }

    public bool TryTerminateExact(UpdateProcessIdentity identity)
    {
        try
        {
            using var process = Process.GetProcessById(identity.ProcessId);
            if (process.StartTime.ToUniversalTime().Ticks != identity.StartTimeUtcTicks)
            {
                return false;
            }

            process.Kill(entireProcessTree: false);
            return process.WaitForExit(milliseconds: 5_000);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
