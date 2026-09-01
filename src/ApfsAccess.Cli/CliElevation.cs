using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal sealed record CliElevationFileIdentity(
    string CanonicalPath,
    long Length,
    string Sha256,
    string LaunchIdentity);

internal sealed record CliElevationPackageIdentity(
    CliElevationFileIdentity AppHost,
    CliElevationFileIdentity Payload);

internal sealed record CliElevationProcessIdentity(
    int ProcessId,
    long StartTimeUtcTicks,
    string ImagePath);

internal sealed record CliElevationObservedProcess(
    bool Exists,
    CliElevationProcessIdentity? Identity)
{
    public static CliElevationObservedProcess Absent { get; } = new(false, null);
}

internal sealed record CliElevationContract(
    int SchemaVersion,
    string Token,
    string Command,
    string ArgumentsSha256,
    int ParentPid,
    long ParentStartTimeUtcTicks,
    CliElevationPackageIdentity Package,
    DateTimeOffset CreatedAtUtc,
    string? ChannelName = null,
    string? JobName = null,
    DateTimeOffset? OperationDeadlineUtc = null);

internal sealed record CliElevationResultEnvelope(
    int SchemaVersion,
    string Token,
    string Command,
    string ArgumentsSha256,
    int ParentPid,
    long ParentStartTimeUtcTicks,
    int ChildPid,
    long ChildStartTimeUtcTicks,
    string ChildPath,
    long ChildLength,
    string ChildSha256,
    string ChildLaunchIdentity,
    string PayloadPath,
    long PayloadLength,
    string PayloadSha256,
    string PayloadLaunchIdentity,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    string Stdout,
    string StdoutSha256,
    int ExitCode);

internal sealed record CliElevationParentResult(
    int ExitCode,
    string? Stdout,
    string? ErrorCode,
    string? Message);

internal sealed record CliElevationPublicArguments(
    string[] Arguments,
    bool ElevationRequested);

internal interface ICliElevationProcess : IDisposable
{
    CliElevationProcessIdentity Identity { get; }
    bool HasExited { get; }
    int? ExitCode { get; }
    CliElevationObservedProcess ObserveIdentity();
    Task WaitForExitAsync(CancellationToken cancellationToken);
    Task<bool> TerminateTreeAndProveExitAsync(TimeSpan timeout);
}

internal sealed class CliElevationPackageLease : IDisposable
{
    private readonly IDisposable? _appHostLease;
    private readonly IDisposable? _payloadLease;

    internal CliElevationPackageLease(
        CliElevationPackageIdentity identity,
        IDisposable? appHostLease = null,
        IDisposable? payloadLease = null)
    {
        Identity = identity;
        _appHostLease = appHostLease;
        _payloadLease = payloadLease;
    }

    internal CliElevationPackageIdentity Identity { get; }

    public void Dispose()
    {
        List<Exception>? failures = null;
        try
        {
            _payloadLease?.Dispose();
        }
        catch (Exception ex)
        {
            (failures ??= []).Add(ex);
        }

        try
        {
            _appHostLease?.Dispose();
        }
        catch (Exception ex)
        {
            (failures ??= []).Add(ex);
        }

        if (failures is not null)
        {
            throw new AggregateException("One or more APFS Access CLI package leases could not be released.", failures);
        }
    }
}

internal sealed class CliElevationTestHooks
{
    public Func<bool>? IsAdministrator { get; init; }
    public Func<CliElevationPackageLease>? AcquirePackageLease { get; init; }
    public Func<CliElevationPackageIdentity>? CaptureCurrentPackageIdentity { get; init; }
    public Func<string>? TokenFactory { get; init; }
    public Func<ProcessStartInfo, CliElevationContract, Task<ICliElevationProcess>>? StartElevatedProcessAsync { get; init; }
    public Func<int, long, CliElevationObservedProcess>? ObserveProcessIdentity { get; init; }
    public Func<string, CliElevationProcessIdentity>? CaptureCurrentProcessIdentity { get; init; }
    public Func<DateTimeOffset>? UtcNow { get; init; }
    public Func<CliElevationContract, ICliElevationServerChannel>? CreateServerChannel { get; init; }
    public Func<CliElevationContract, ICliElevationClientChannel>? CreateClientChannel { get; init; }
    public Func<string, ICliElevationJob>? CreateJob { get; init; }
    public Func<string, ICliElevationJob>? OpenJob { get; init; }
}

internal sealed class CliElevationValidationException(string message) : Exception(message);

internal sealed class CliElevationUnsafeOwnershipException(string message, Exception? innerException = null)
    : Exception(message, innerException);

internal static class CliElevation
{
    internal const int ContractSchemaVersion = 3;
    internal const int ResultSchemaVersion = 2;
    internal const string InternalChildMarker = "--apfs-cli-elevation-child";

    private const int InvalidArguments = 2;
    private const int Timeout = 4;
    private const int OperationFailed = 5;
    private const int ElevationFailed = 6;
    private const int UnsafeOwnership = 10;
    private const int ErrorCancelled = 1223;
    private const int CleanupTimeoutMs = 5_000;
    private const string InternalMarkerPrefix = "--apfs-cli-elevation-";
    private const string ChannelNamePrefix = "ApfsAccess.Cli.Elevation.";
    private const string JobNamePrefix = @"Local\ApfsAccess.Cli.Elevation.";
    private static readonly AsyncLocal<CliElevationTestHooks?> TestHooks = new();

    internal static JsonSerializerOptions SerializerOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
    };

    internal static IDisposable InstallTestHooks(CliElevationTestHooks hooks)
    {
        ArgumentNullException.ThrowIfNull(hooks);
        var previous = TestHooks.Value;
        TestHooks.Value = hooks;
        return new TestHookScope(previous);
    }

    internal static bool IsInternalChildInvocation(IReadOnlyList<string> args)
        => args.Count > 0 && string.Equals(args[0], InternalChildMarker, StringComparison.Ordinal);

    internal static CliElevationPublicArguments ParsePublicArguments(string[] args)
    {
        var elevationRequested = false;
        var result = new List<string>(args.Length);
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (argument.StartsWith(InternalMarkerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new CliElevationValidationException("Internal elevation markers cannot be supplied as public arguments.");
            }

            if (string.Equals(argument, "--elevate", StringComparison.OrdinalIgnoreCase))
            {
                if (elevationRequested)
                {
                    throw new CliElevationValidationException("Option '--elevate' may only be supplied once.");
                }

                elevationRequested = true;
                continue;
            }

            result.Add(argument);
            if (OptionRequiresValue(argument) && index + 1 < args.Length)
            {
                var value = args[++index];
                if (value.StartsWith(InternalMarkerPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    throw new CliElevationValidationException("Internal elevation markers cannot be supplied as public arguments.");
                }

                result.Add(value);
            }
        }

        return new CliElevationPublicArguments(result.ToArray(), elevationRequested);
    }

    internal static bool IsAdministrator()
    {
        if (TestHooks.Value?.IsAdministrator is { } test)
        {
            return test();
        }

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    internal static async Task<CliElevationParentResult> RunParentAsync(
        string[] publicArguments,
        TimeSpan timeout)
    {
        CliElevationPackageLease? packageLease = null;
        ICliElevationProcess? child = null;
        ICliElevationServerChannel? channel = null;
        ICliElevationJob? job = null;
        var jobOwnershipEstablished = false;
        try
        {
            packageLease = AcquirePackageLease();
            var package = packageLease.Identity;
            var parent = CaptureCurrentProcessIdentity(package.AppHost.CanonicalPath);
            var token = CreateToken();
            ValidateToken(token);
            var createdAt = UtcNow();

            var contract = new CliElevationContract(
                ContractSchemaVersion,
                token,
                ExtractCommand(publicArguments),
                ComputeArgumentsSha256(publicArguments),
                parent.ProcessId,
                parent.StartTimeUtcTicks,
                package,
                createdAt,
                ChannelNamePrefix + token,
                JobNamePrefix + token,
                createdAt.Add(timeout));
            ValidateContract(contract, publicArguments);
            channel = CreateServerChannel(contract);
            job = CreateJob(contract.JobName!);
            var startInfo = CreateStartInfo(contract, publicArguments);
            var deadline = CreateMonotonicDeadline(contract.OperationDeadlineUtc!.Value);
            var startTask = StartElevatedProcessAsync(startInfo, contract);
            var startResult = await WaitForTaskAsync(startTask, deadline).ConfigureAwait(false);
            if (!startResult.Completed)
            {
                var graceDeadline = Stopwatch.GetTimestamp() + ToStopwatchTicks(TimeSpan.FromMilliseconds(CleanupTimeoutMs));
                startResult = await WaitForTaskAsync(startTask, graceDeadline).ConfigureAwait(false);
                if (!startResult.Completed)
                {
                    RetainPackageLeaseUntilLaunchCompletes(startTask, packageLease);
                    packageLease = null;
                    return Failure(
                        UnsafeOwnership,
                        ApfsOperationCodes.UnsafeOwnership,
                        "The UAC launch did not complete within the bounded ownership window; authorization was revoked and child absence is unproven.");
                }

                child = await AwaitStartedProcessAsync(startTask).ConfigureAwait(false);
                return await TimeoutAfterCleanupAsync(child, package, job, jobOwnershipEstablished).ConfigureAwait(false);
            }

            child = await AwaitStartedProcessAsync(startTask).ConfigureAwait(false);
            try
            {
                ValidateStartedProcess(child.Identity, package.AppHost);
            }
            catch (CliElevationValidationException ex)
            {
                return await FailureAfterCleanupAsync(
                    child,
                    package,
                    job,
                    jobOwnershipEstablished,
                    UnsafeOwnership,
                    ApfsOperationCodes.UnsafeOwnership,
                    ex.Message).ConfigureAwait(false);
            }

            if (channel is null || job is null)
            {
                return await FailureAfterCleanupAsync(
                    child,
                    package,
                    job,
                    jobOwnershipEstablished,
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    "The elevated child did not establish an authenticated result channel.").ConfigureAwait(false);
            }

            await channel.WaitForExactPeerAsync(child.Identity.ProcessId, GetRequiredRemaining(deadline)).ConfigureAwait(false);
            var hello = await channel.ReadAsync(GetRequiredRemaining(deadline)).ConfigureAwait(false);
            ValidateHello(hello, contract, child.Identity, package, channel.PeerProcessId);
            if (!job.ContainsOnlyProcess(child.Identity.ProcessId))
            {
                return await FailureAfterCleanupAsync(
                    child,
                    package,
                    job,
                    jobOwnershipEstablished,
                    UnsafeOwnership,
                    ApfsOperationCodes.UnsafeOwnership,
                    "The elevated child did not establish exclusive ownership in the token-specific process job.").ConfigureAwait(false);
            }

            jobOwnershipEstablished = true;
            await channel.WriteAsync(
                new CliElevationWireMessage(
                    CliElevationTransport.WireSchemaVersion,
                    CliElevationTransport.AuthorizationMessage,
                    contract.Token,
                    Authorized: true,
                    OperationDeadlineUtc: contract.OperationDeadlineUtc),
                GetRequiredRemaining(deadline)).ConfigureAwait(false);

            var resultMessage = await channel.ReadAsync(GetRequiredRemaining(deadline)).ConfigureAwait(false);
            if (resultMessage.SchemaVersion != CliElevationTransport.WireSchemaVersion ||
                !string.Equals(resultMessage.Type, CliElevationTransport.ResultMessage, StringComparison.Ordinal) ||
                !FixedEquals(resultMessage.Token, contract.Token) ||
                resultMessage.OperationDeadlineUtc != contract.OperationDeadlineUtc ||
                resultMessage.Result is null)
            {
                return await FailureAfterCleanupAsync(
                    child,
                    package,
                    job,
                    jobOwnershipEstablished,
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    "The elevated child published a malformed authenticated result message.").ConfigureAwait(false);
            }

            var exitResult = await WaitForProcessAsync(child, deadline).ConfigureAwait(false);
            if (!exitResult)
            {
                return await TimeoutAfterCleanupAsync(child, package, job, jobOwnershipEstablished).ConfigureAwait(false);
            }

            var currentPackage = CaptureCurrentPackageIdentity();
            if (!PackageMatches(package, currentPackage))
            {
                return await FailureAfterCleanupAsync(
                    child,
                    package,
                    job,
                    jobOwnershipEstablished,
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    "The CLI package changed during elevation.").ConfigureAwait(false);
            }

            var actualExitCode = child.ExitCode
                ?? throw new CliElevationValidationException("The elevated child exit code is unavailable.");
            var requireJsonOutput = !publicArguments.Contains("--human", StringComparer.OrdinalIgnoreCase);
            var envelope = ValidateResultEnvelope(
                contract,
                child.Identity,
                actualExitCode,
                currentPackage,
                JsonSerializer.Serialize(resultMessage.Result, SerializerOptions),
                requireJsonOutput);
            return new CliElevationParentResult(envelope.ExitCode, envelope.Stdout, null, null);
        }
        catch (Win32Exception ex) when (child is null && ex.NativeErrorCode == ErrorCancelled)
        {
            return Failure(ElevationFailed, ApfsOperationCodes.ElevationFailed, "The UAC elevation request was cancelled.");
        }
        catch (CliElevationUnsafeOwnershipException ex)
        {
            return Failure(UnsafeOwnership, ApfsOperationCodes.UnsafeOwnership, ex.Message);
        }
        catch (CliElevationValidationException ex)
        {
            var exitCode = child is null ? ElevationFailed : OperationFailed;
            var code = child is null ? ApfsOperationCodes.ElevationFailed : ApfsOperationCodes.OperationFailed;
            return child is null
                ? Failure(exitCode, code, ex.Message)
                : await FailureAfterCleanupAsync(
                    child,
                    packageLease?.Identity,
                    job,
                    jobOwnershipEstablished,
                    exitCode,
                    code,
                    ex.Message).ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException ex)
        {
            var exitCode = child is null ? ElevationFailed : OperationFailed;
            var code = child is null ? ApfsOperationCodes.ElevationFailed : ApfsOperationCodes.OperationFailed;
            return child is null
                ? Failure(exitCode, code, ex.Message)
                : await FailureAfterCleanupAsync(
                    child,
                    packageLease?.Identity,
                    job,
                    jobOwnershipEstablished,
                    exitCode,
                    code,
                    ex.Message).ConfigureAwait(false);
        }
        catch (Win32Exception ex)
        {
            var exitCode = child is null ? ElevationFailed : OperationFailed;
            var code = child is null ? ApfsOperationCodes.ElevationFailed : ApfsOperationCodes.OperationFailed;
            return child is null
                ? Failure(exitCode, code, ex.Message)
                : await FailureAfterCleanupAsync(
                    child,
                    packageLease?.Identity,
                    job,
                    jobOwnershipEstablished,
                    exitCode,
                    code,
                    ex.Message).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return child is null
                ? Failure(UnsafeOwnership, ApfsOperationCodes.UnsafeOwnership, "The UAC launch exceeded its bounded authorization window.")
                : await TimeoutAfterCleanupAsync(
                    child,
                    packageLease?.Identity,
                    job,
                    jobOwnershipEstablished).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return child is null
                ? Failure(UnsafeOwnership, ApfsOperationCodes.UnsafeOwnership, "The UAC launch exceeded its bounded authorization window.")
                : await TimeoutAfterCleanupAsync(
                    child,
                    packageLease?.Identity,
                    job,
                    jobOwnershipEstablished).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return child is null
                ? Failure(OperationFailed, ApfsOperationCodes.OperationFailed, ex.Message)
                : await FailureAfterCleanupAsync(
                    child,
                    packageLease?.Identity,
                    job,
                    jobOwnershipEstablished,
                    OperationFailed,
                    ApfsOperationCodes.OperationFailed,
                    ex.Message).ConfigureAwait(false);
        }
        finally
        {
            child?.Dispose();
            job?.Dispose();
            if (channel is not null)
            {
                await channel.DisposeAsync().ConfigureAwait(false);
            }
            packageLease?.Dispose();
        }
    }

    internal static async Task<int> RunInternalChildAsync(
        string[] args,
        Func<string[], DateTimeOffset, Task<int>> executePublicAsync)
    {
        CliElevationContract? contract = null;
        try
        {
            var parsed = ParseInternalChildArguments(args);
            contract = parsed.Contract;
            ValidateContract(contract, parsed.PublicArguments);
            if (!IsAdministrator())
            {
                throw new CliElevationValidationException("The internal elevation child is not running with administrator integrity.");
            }

            using var packageLease = AcquirePackageLease();
            if (!PackageMatches(contract.Package, packageLease.Identity))
            {
                throw new CliElevationValidationException("The elevated CLI package does not match the parent launch identity.");
            }

            var observedParent = ObserveProcessIdentity(contract.ParentPid, contract.ParentStartTimeUtcTicks);
            if (!observedParent.Exists ||
                observedParent.Identity is null ||
                !ProcessMatches(
                    observedParent.Identity,
                    new CliElevationProcessIdentity(
                        contract.ParentPid,
                        contract.ParentStartTimeUtcTicks,
                        contract.Package.AppHost.CanonicalPath)))
            {
                throw new CliElevationValidationException("The elevation parent identity is absent or mismatched.");
            }

            var authorizationRemaining = GetOperationRemaining(contract);
            using (var assignmentJob = OpenJob(contract.JobName!))
            {
                assignmentJob.AssignCurrentProcess();
            }

            var child = CaptureCurrentProcessIdentity(packageLease.Identity.AppHost.CanonicalPath);
            await using var channel = CreateClientChannel(contract);
            await channel.ConnectToExactServerAsync(contract.ParentPid, authorizationRemaining).ConfigureAwait(false);
            await channel.WriteAsync(
                new CliElevationWireMessage(
                    CliElevationTransport.WireSchemaVersion,
                    CliElevationTransport.HelloMessage,
                    contract.Token,
                    child,
                    packageLease.Identity,
                    OperationDeadlineUtc: contract.OperationDeadlineUtc),
                GetOperationRemaining(contract)).ConfigureAwait(false);
            var authorization = await channel.ReadAsync(GetOperationRemaining(contract)).ConfigureAwait(false);
            if (authorization.SchemaVersion != CliElevationTransport.WireSchemaVersion ||
                !string.Equals(authorization.Type, CliElevationTransport.AuthorizationMessage, StringComparison.Ordinal) ||
                !FixedEquals(authorization.Token, contract.Token) ||
                !authorization.Authorized ||
                authorization.OperationDeadlineUtc != contract.OperationDeadlineUtc ||
                channel.PeerProcessId != contract.ParentPid)
            {
                throw new CliElevationValidationException("The elevated child did not receive exact-parent startup authorization.");
            }

            var operationDeadlineUtc = contract.OperationDeadlineUtc!.Value;
            _ = GetOperationRemaining(contract);
            var startedAt = UtcNow();
            var originalOutput = Console.Out;
            using var writer = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            int exitCode;
            Console.SetOut(writer);
            try
            {
                exitCode = await executePublicAsync(parsed.PublicArguments, operationDeadlineUtc).ConfigureAwait(false);
            }
            finally
            {
                Console.SetOut(originalOutput);
            }

            var completedAt = UtcNow();
            var stdout = writer.ToString();
            var envelope = new CliElevationResultEnvelope(
                ResultSchemaVersion,
                contract.Token,
                contract.Command,
                contract.ArgumentsSha256,
                contract.ParentPid,
                contract.ParentStartTimeUtcTicks,
                child.ProcessId,
                child.StartTimeUtcTicks,
                packageLease.Identity.AppHost.CanonicalPath,
                packageLease.Identity.AppHost.Length,
                packageLease.Identity.AppHost.Sha256,
                packageLease.Identity.AppHost.LaunchIdentity,
                packageLease.Identity.Payload.CanonicalPath,
                packageLease.Identity.Payload.Length,
                packageLease.Identity.Payload.Sha256,
                packageLease.Identity.Payload.LaunchIdentity,
                startedAt,
                completedAt,
                stdout,
                ComputeSha256(stdout),
                exitCode);
            await channel.WriteAsync(
                new CliElevationWireMessage(
                    CliElevationTransport.WireSchemaVersion,
                    CliElevationTransport.ResultMessage,
                    contract.Token,
                    Result: envelope,
                    OperationDeadlineUtc: operationDeadlineUtc),
                GetOperationRemaining(contract)).ConfigureAwait(false);
            return exitCode;
        }
        catch (CliElevationValidationException ex) when (contract is null)
        {
            WriteInvalidInternalInvocation(ex.Message);
            return InvalidArguments;
        }
        catch
        {
            return ElevationFailed;
        }
    }

    internal static string ComputeArgumentsSha256(IReadOnlyList<string> arguments)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (var argument in arguments)
        {
            var bytes = Encoding.UTF8.GetBytes(argument);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    internal static string ComputeSha256(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    internal static CliElevationResultEnvelope ValidateResultEnvelopeForTests(
        CliElevationContract contract,
        CliElevationProcessIdentity child,
        int actualExitCode,
        CliElevationPackageIdentity currentPackage,
        string resultText)
        => ValidateResultEnvelope(contract, child, actualExitCode, currentPackage, resultText, requireJsonOutput: true);

    internal static void ValidatePackagedPathsForTests(
        string processPath,
        string assemblyPath,
        string canonicalProcessPath,
        string canonicalAssemblyPath)
        => ValidatePackagedPaths(processPath, assemblyPath, canonicalProcessPath, canonicalAssemblyPath);

    private static CliElevationResultEnvelope ValidateResultEnvelope(
        CliElevationContract contract,
        CliElevationProcessIdentity child,
        int actualExitCode,
        CliElevationPackageIdentity currentPackage,
        string resultText,
        bool requireJsonOutput)
    {
        CliElevationResultEnvelope envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<CliElevationResultEnvelope>(resultText, SerializerOptions)
                ?? throw new CliElevationValidationException("The elevated result envelope is empty.");
        }
        catch (CliElevationValidationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw new CliElevationValidationException($"The elevated result envelope is malformed: {ex.Message}");
        }

        if (envelope.SchemaVersion != ResultSchemaVersion ||
            !FixedEquals(envelope.Token, contract.Token) ||
            !string.Equals(envelope.Command, contract.Command, StringComparison.Ordinal) ||
            !FixedEquals(envelope.ArgumentsSha256, contract.ArgumentsSha256) ||
            envelope.ParentPid != contract.ParentPid ||
            envelope.ParentStartTimeUtcTicks != contract.ParentStartTimeUtcTicks)
        {
            throw new CliElevationValidationException("The elevated result envelope is not bound to the parent request.");
        }

        if (!PackageMatches(contract.Package, currentPackage))
        {
            throw new CliElevationValidationException("The CLI package identity changed before result acceptance.");
        }

        var envelopePackage = new CliElevationPackageIdentity(
            new CliElevationFileIdentity(
                envelope.ChildPath,
                envelope.ChildLength,
                envelope.ChildSha256,
                envelope.ChildLaunchIdentity),
            new CliElevationFileIdentity(
                envelope.PayloadPath,
                envelope.PayloadLength,
                envelope.PayloadSha256,
                envelope.PayloadLaunchIdentity));
        if (!PackageMatches(contract.Package, envelopePackage) ||
            envelope.ChildPid != child.ProcessId ||
            envelope.ChildStartTimeUtcTicks != child.StartTimeUtcTicks ||
            !string.Equals(envelope.ChildPath, child.ImagePath, StringComparison.OrdinalIgnoreCase) ||
            envelope.ExitCode != actualExitCode)
        {
            throw new CliElevationValidationException("The elevated child or package identity is mismatched.");
        }

        if (envelope.StartedAtUtc < contract.CreatedAtUtc ||
            envelope.StartedAtUtc.UtcDateTime.Ticks < child.StartTimeUtcTicks ||
            envelope.CompletedAtUtc < envelope.StartedAtUtc ||
            envelope.CompletedAtUtc > contract.OperationDeadlineUtc)
        {
            throw new CliElevationValidationException("The elevated result timestamps are stale or unordered.");
        }

        if (!FixedEquals(envelope.StdoutSha256, ComputeSha256(envelope.Stdout)))
        {
            throw new CliElevationValidationException("The elevated stdout digest is mismatched.");
        }

        if (requireJsonOutput)
        {
            try
            {
                using var output = JsonDocument.Parse(envelope.Stdout);
                if (output.RootElement.ValueKind != JsonValueKind.Object ||
                    !output.RootElement.TryGetProperty("exitCode", out var outputExitCode) ||
                    outputExitCode.ValueKind != JsonValueKind.Number ||
                    !outputExitCode.TryGetInt32(out var parsedExitCode) ||
                    parsedExitCode != envelope.ExitCode)
                {
                    throw new CliElevationValidationException("The elevated stdout JSON does not match the result exit code.");
                }
            }
            catch (CliElevationValidationException)
            {
                throw;
            }
            catch (JsonException ex)
            {
                throw new CliElevationValidationException($"The elevated stdout is not valid JSON: {ex.Message}");
            }
        }

        return envelope;
    }

    private static async Task<CliElevationParentResult> TimeoutAfterCleanupAsync(
        ICliElevationProcess child,
        CliElevationPackageIdentity? package,
        ICliElevationJob? job,
        bool jobOwnershipEstablished)
    {
        var absenceProven = await StopExactChildTreeAsync(
            child,
            package,
            job,
            jobOwnershipEstablished).ConfigureAwait(false);
        return absenceProven
            ? Failure(Timeout, ApfsOperationCodes.Timeout, "The elevated CLI command exceeded its bounded timeout.")
            : Failure(
                UnsafeOwnership,
                ApfsOperationCodes.UnsafeOwnership,
                "The elevated child identity changed or its absence could not be proven; cleanup was refused.");
    }

    private static async Task<bool> StopExactChildTreeAsync(
        ICliElevationProcess child,
        CliElevationPackageIdentity? package,
        ICliElevationJob? job,
        bool jobOwnershipEstablished)
    {
        if (package is null)
        {
            return false;
        }

        if (!jobOwnershipEstablished)
        {
            if (child.HasExited)
            {
                return true;
            }

            CliElevationObservedProcess observed;
            try
            {
                observed = TestHooks.Value?.ObserveProcessIdentity is { } observe
                    ? observe(child.Identity.ProcessId, child.Identity.StartTimeUtcTicks)
                    : child.ObserveIdentity();
            }
            catch
            {
                return false;
            }

            if (!observed.Exists)
            {
                return true;
            }

            if (observed.Identity is null ||
                !ProcessMatches(child.Identity, observed.Identity) ||
                !string.Equals(observed.Identity.ImagePath, package.AppHost.CanonicalPath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (job is null || !job.ContainsOnlyProcess(child.Identity.ProcessId))
            {
                return await child.TerminateTreeAndProveExitAsync(
                    TimeSpan.FromMilliseconds(CleanupTimeoutMs)).ConfigureAwait(false);
            }
        }

        return job is not null &&
               await job.TerminateAndProveEmptyAsync(TimeSpan.FromMilliseconds(CleanupTimeoutMs)).ConfigureAwait(false);
    }

    private static async Task<CliElevationParentResult> FailureAfterCleanupAsync(
        ICliElevationProcess child,
        CliElevationPackageIdentity? package,
        ICliElevationJob? job,
        bool jobOwnershipEstablished,
        int exitCode,
        string code,
        string message)
    {
        var absenceProven = await StopExactChildTreeAsync(
            child,
            package,
            job,
            jobOwnershipEstablished).ConfigureAwait(false);
        return absenceProven
            ? Failure(exitCode, code, message)
            : Failure(
                UnsafeOwnership,
                ApfsOperationCodes.UnsafeOwnership,
                $"{message} Exact elevated process-tree absence could not be proven.");
    }

    private static void ValidateHello(
        CliElevationWireMessage hello,
        CliElevationContract contract,
        CliElevationProcessIdentity child,
        CliElevationPackageIdentity package,
        int? peerProcessId)
    {
        if (hello.SchemaVersion != CliElevationTransport.WireSchemaVersion ||
            !string.Equals(hello.Type, CliElevationTransport.HelloMessage, StringComparison.Ordinal) ||
            !FixedEquals(hello.Token, contract.Token) ||
            hello.Process is null ||
            hello.Package is null ||
            hello.OperationDeadlineUtc != contract.OperationDeadlineUtc ||
            peerProcessId != child.ProcessId ||
            !ProcessMatches(hello.Process, child) ||
            !PackageMatches(hello.Package, package))
        {
            throw new CliElevationValidationException("The elevation IPC peer is not the exact launched child/package identity.");
        }
    }

    private static TimeSpan GetRequiredRemaining(long deadline)
    {
        var remaining = GetRemaining(deadline);
        return remaining > TimeSpan.Zero
            ? remaining
            : throw new TimeoutException("The elevation authorization deadline has expired.");
    }

    private static TimeSpan GetOperationRemaining(CliElevationContract contract)
    {
        var remaining = contract.OperationDeadlineUtc!.Value - UtcNow();
        return remaining > TimeSpan.Zero
            ? remaining
            : throw new TimeoutException("The elevated operation deadline has expired.");
    }

    private static ICliElevationServerChannel? CreateServerChannel(CliElevationContract contract)
    {
        if (TestHooks.Value is { } hooks)
        {
            return hooks.CreateServerChannel?.Invoke(contract);
        }

        return CliElevationTransport.CreateServer(contract.ChannelName!);
    }

    private static ICliElevationClientChannel CreateClientChannel(CliElevationContract contract)
        => TestHooks.Value?.CreateClientChannel?.Invoke(contract) ??
           CliElevationTransport.CreateClient(contract.ChannelName!);

    private static ICliElevationJob? CreateJob(string jobName)
    {
        if (TestHooks.Value is { } hooks)
        {
            return hooks.CreateJob?.Invoke(jobName);
        }

        return CliElevationTransport.CreateJob(jobName);
    }

    private static ICliElevationJob OpenJob(string jobName)
        => TestHooks.Value?.OpenJob?.Invoke(jobName) ?? CliElevationTransport.OpenJob(jobName);

    private static void RetainPackageLeaseUntilLaunchCompletes(
        Task<ICliElevationProcess> startTask,
        CliElevationPackageLease packageLease)
        => _ = RetainPackageLeaseUntilLaunchCompletesCoreAsync(startTask, packageLease);

    private static async Task RetainPackageLeaseUntilLaunchCompletesCoreAsync(
        Task<ICliElevationProcess> startTask,
        CliElevationPackageLease packageLease)
    {
        using (packageLease)
        {
            try
            {
                using var process = await startTask.ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }

    private static ProcessStartInfo CreateStartInfo(
        CliElevationContract contract,
        IReadOnlyList<string> publicArguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = contract.Package.AppHost.CanonicalPath,
            WorkingDirectory = Path.GetDirectoryName(contract.Package.AppHost.CanonicalPath) ?? AppContext.BaseDirectory,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add(InternalChildMarker);
        startInfo.ArgumentList.Add(ToBase64Url(JsonSerializer.SerializeToUtf8Bytes(contract, SerializerOptions)));
        startInfo.ArgumentList.Add("--");
        foreach (var argument in publicArguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static (CliElevationContract Contract, string[] PublicArguments) ParseInternalChildArguments(string[] args)
    {
        if (args.Length < 3 ||
            !string.Equals(args[0], InternalChildMarker, StringComparison.Ordinal) ||
            !string.Equals(args[2], "--", StringComparison.Ordinal))
        {
            throw new CliElevationValidationException("The internal elevation child contract is incomplete.");
        }

        CliElevationContract contract;
        try
        {
            contract = JsonSerializer.Deserialize<CliElevationContract>(FromBase64Url(args[1]), SerializerOptions)
                ?? throw new CliElevationValidationException("The internal elevation child contract is empty.");
        }
        catch (CliElevationValidationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or NotSupportedException)
        {
            throw new CliElevationValidationException($"The internal elevation child contract is malformed: {ex.Message}");
        }

        return (contract, args[3..]);
    }

    private static void ValidateContract(CliElevationContract contract, IReadOnlyList<string> publicArguments)
    {
        if (contract.SchemaVersion != ContractSchemaVersion)
        {
            throw new CliElevationValidationException("The internal elevation contract schema is unsupported.");
        }

        ValidateToken(contract.Token);
        var expectedChannelName = ChannelNamePrefix + contract.Token;
        var expectedJobName = JobNamePrefix + contract.Token;
        if (!string.Equals(contract.ChannelName, expectedChannelName, StringComparison.Ordinal) ||
            !string.Equals(contract.JobName, expectedJobName, StringComparison.Ordinal) ||
            contract.OperationDeadlineUtc is null ||
            contract.OperationDeadlineUtc <= contract.CreatedAtUtc ||
            contract.OperationDeadlineUtc > contract.CreatedAtUtc.AddMinutes(5))
        {
            throw new CliElevationValidationException("The internal elevation IPC/authorization contract is invalid.");
        }

        if (!FixedEquals(contract.ArgumentsSha256, ComputeArgumentsSha256(publicArguments)) ||
            !string.Equals(contract.Command, ExtractCommand(publicArguments), StringComparison.Ordinal))
        {
            throw new CliElevationValidationException("The internal elevation arguments do not match the parent digest.");
        }

        if (publicArguments.Any(static argument =>
                argument.StartsWith(InternalMarkerPrefix, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(argument, "--elevate", StringComparison.OrdinalIgnoreCase)))
        {
            throw new CliElevationValidationException("Recursive elevation markers are not permitted.");
        }

        ValidatePackageIdentity(contract.Package);
    }

    private static CliElevationPackageLease AcquirePackageLease()
        => TestHooks.Value?.AcquirePackageLease?.Invoke() ?? AcquireProductionPackageLease();

    private static CliElevationPackageIdentity CaptureCurrentPackageIdentity()
    {
        if (TestHooks.Value?.CaptureCurrentPackageIdentity is { } capture)
        {
            return capture();
        }

        using var lease = AcquireProductionPackageLease();
        return lease.Identity;
    }

    private static CliElevationPackageLease AcquireProductionPackageLease()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new CliElevationValidationException("Explicit CLI elevation is supported only by the packaged Windows apphost.");
        }

        var processPath = Environment.ProcessPath;
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        if (string.IsNullOrWhiteSpace(processPath) || string.IsNullOrWhiteSpace(assemblyPath))
        {
            throw new CliElevationValidationException("The packaged CLI identity is unavailable.");
        }

        FileStream? appHost = null;
        FileStream? payload = null;
        try
        {
            appHost = OpenIdentityLease(processPath);
            var canonicalProcessPath = GetCanonicalPath(appHost.SafeFileHandle);
            var expectedPayloadPath = Path.Combine(
                Path.GetDirectoryName(canonicalProcessPath) ?? throw new CliElevationValidationException("The CLI apphost directory is unavailable."),
                "ApfsAccess.Cli.dll");
            payload = OpenIdentityLease(expectedPayloadPath);
            var canonicalPayloadPath = GetCanonicalPath(payload.SafeFileHandle);
            ValidatePackagedPaths(processPath, assemblyPath, canonicalProcessPath, canonicalPayloadPath);

            var identity = new CliElevationPackageIdentity(
                CaptureFileIdentity(appHost, canonicalProcessPath),
                CaptureFileIdentity(payload, canonicalPayloadPath));
            ValidatePackageIdentity(identity);
            return new CliElevationPackageLease(identity, appHost, payload);
        }
        catch
        {
            payload?.Dispose();
            appHost?.Dispose();
            throw;
        }
    }

    private static void ValidatePackagedPaths(
        string processPath,
        string assemblyPath,
        string canonicalProcessPath,
        string canonicalAssemblyPath)
    {
        var fullProcessPath = Path.GetFullPath(processPath);
        var fullAssemblyPath = Path.GetFullPath(assemblyPath);
        if (!string.Equals(Path.GetFileName(fullProcessPath), "ApfsAccess.Cli.exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(fullProcessPath, canonicalProcessPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new CliElevationValidationException("Explicit elevation requires the exact, non-aliased ApfsAccess.Cli.exe apphost.");
        }

        var expectedPayloadPath = Path.Combine(
            Path.GetDirectoryName(canonicalProcessPath) ?? string.Empty,
            "ApfsAccess.Cli.dll");
        if (!string.Equals(fullAssemblyPath, expectedPayloadPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(fullAssemblyPath, canonicalAssemblyPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new CliElevationValidationException("Explicit elevation requires the exact adjacent ApfsAccess.Cli.dll payload.");
        }
    }

    private static void ValidatePackageIdentity(CliElevationPackageIdentity package)
    {
        if (!string.Equals(Path.GetFileName(package.AppHost.CanonicalPath), "ApfsAccess.Cli.exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(package.Payload.CanonicalPath), "ApfsAccess.Cli.dll", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetDirectoryName(package.AppHost.CanonicalPath),
                Path.GetDirectoryName(package.Payload.CanonicalPath),
                StringComparison.OrdinalIgnoreCase) ||
            package.AppHost.Length <= 0 ||
            package.Payload.Length <= 0 ||
            !IsSha256(package.AppHost.Sha256) ||
            !IsSha256(package.Payload.Sha256) ||
            string.IsNullOrWhiteSpace(package.AppHost.LaunchIdentity) ||
            string.IsNullOrWhiteSpace(package.Payload.LaunchIdentity))
        {
            throw new CliElevationValidationException("The packaged CLI apphost/payload identity is incomplete.");
        }
    }

    private static FileStream OpenIdentityLease(string path)
        => new(
            Path.GetFullPath(path),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);

    private static CliElevationFileIdentity CaptureFileIdentity(FileStream stream, string canonicalPath)
    {
        stream.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(stream));
        stream.Position = 0;
        if (!NativeMethods.GetFileInformationByHandle(stream.SafeFileHandle, out var information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not capture the immutable file identity for '{canonicalPath}'.");
        }

        if (information.NumberOfLinks != 1)
        {
            throw new CliElevationValidationException($"The CLI package file '{canonicalPath}' is hard-linked and cannot be elevated unambiguously.");
        }

        var launchIdentity = $"{information.VolumeSerialNumber:X8}:{information.FileIndexHigh:X8}{information.FileIndexLow:X8}";
        return new CliElevationFileIdentity(canonicalPath, stream.Length, sha256, launchIdentity);
    }

    private static string GetCanonicalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32_768)
        {
            var builder = new StringBuilder(capacity);
            var length = NativeMethods.GetFinalPathNameByHandle(handle, builder, builder.Capacity, 0);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve a canonical CLI package path.");
            }

            if (length < builder.Capacity)
            {
                var path = builder.ToString();
                if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return @"\\" + path[8..];
                }

                return path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path;
            }

            capacity = checked((int)length + 1);
        }

        throw new CliElevationValidationException("The canonical CLI package path is too long.");
    }

    private static Task<ICliElevationProcess> StartElevatedProcessAsync(
        ProcessStartInfo startInfo,
        CliElevationContract contract)
    {
        if (TestHooks.Value?.StartElevatedProcessAsync is { } start)
        {
            return start(startInfo, contract);
        }

        return Task.Run<ICliElevationProcess>(() =>
        {
            var process = Process.Start(startInfo)
                ?? throw new Win32Exception("ShellExecute did not return an elevated CLI process.");
            try
            {
                return new ProductionElevationProcess(process);
            }
            catch (Exception ex)
            {
                process.Dispose();
                throw new CliElevationUnsafeOwnershipException(
                    "ShellExecute returned a process whose exact elevated identity could not be captured.",
                    ex);
            }
        });
    }

    private static async Task<ICliElevationProcess> AwaitStartedProcessAsync(Task<ICliElevationProcess> startTask)
    {
        try
        {
            return await startTask.ConfigureAwait(false);
        }
        catch (Win32Exception)
        {
            throw;
        }
        catch (CliElevationUnsafeOwnershipException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new Win32Exception(ex.HResult, $"The elevated CLI process could not be launched: {ex.Message}");
        }
    }

    private static async Task<(bool Completed, T? Result)> WaitForTaskAsync<T>(Task<T> task, long deadline)
    {
        var remaining = GetRemaining(deadline);
        if (remaining <= TimeSpan.Zero)
        {
            return (task.IsCompleted, task.IsCompletedSuccessfully ? task.Result : default);
        }

        var completed = await Task.WhenAny(task, Task.Delay(remaining)).ConfigureAwait(false);
        return (ReferenceEquals(completed, task), task.IsCompletedSuccessfully ? task.Result : default);
    }

    private static async Task<bool> WaitForProcessAsync(ICliElevationProcess process, long deadline)
    {
        if (process.HasExited)
        {
            return true;
        }

        var remaining = GetRemaining(deadline);
        if (remaining <= TimeSpan.Zero)
        {
            return false;
        }

        using var cts = new CancellationTokenSource(remaining);
        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return process.HasExited;
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return false;
        }
    }

    private static CliElevationProcessIdentity CaptureCurrentProcessIdentity(string expectedPath)
    {
        if (TestHooks.Value?.CaptureCurrentProcessIdentity is { } capture)
        {
            return capture(expectedPath);
        }

        using var process = Process.GetCurrentProcess();
        var identity = CaptureProcessIdentity(process);
        if (!string.Equals(identity.ImagePath, expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new CliElevationValidationException("The current CLI process path does not match the packaged apphost identity.");
        }

        return identity;
    }

    private static CliElevationObservedProcess ObserveProcessIdentity(int processId, long expectedStartTimeUtcTicks)
    {
        if (TestHooks.Value?.ObserveProcessIdentity is { } observe)
        {
            return observe(processId, expectedStartTimeUtcTicks);
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            return new CliElevationObservedProcess(true, CaptureProcessIdentity(process));
        }
        catch (ArgumentException)
        {
            return CliElevationObservedProcess.Absent;
        }
        catch (InvalidOperationException)
        {
            return CliElevationObservedProcess.Absent;
        }
        catch (Win32Exception)
        {
            return new CliElevationObservedProcess(true, null);
        }
    }

    private static CliElevationProcessIdentity CaptureProcessIdentity(Process process)
    {
        var imagePath = QueryProcessImagePath(process);
        var startTime = process.StartTime.ToUniversalTime().Ticks;
        return new CliElevationProcessIdentity(process.Id, startTime, Path.GetFullPath(imagePath));
    }

    private static string QueryProcessImagePath(Process process)
    {
        var capacity = 1024;
        while (capacity <= 32_768)
        {
            var builder = new StringBuilder(capacity);
            var size = builder.Capacity;
            if (NativeMethods.QueryFullProcessImageName(process.Handle, 0, builder, ref size))
            {
                return builder.ToString();
            }

            var error = Marshal.GetLastWin32Error();
            if (error != 122)
            {
                throw new Win32Exception(error, $"Could not query process {process.Id} image identity.");
            }

            capacity *= 2;
        }

        throw new CliElevationValidationException("The elevated process image path is too long.");
    }

    private static void ValidateStartedProcess(
        CliElevationProcessIdentity child,
        CliElevationFileIdentity appHost)
    {
        if (child.ProcessId <= 0 ||
            child.StartTimeUtcTicks <= 0 ||
            !string.Equals(child.ImagePath, appHost.CanonicalPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new CliElevationValidationException("ShellExecute returned a child with the wrong apphost identity.");
        }
    }

    private static bool PackageMatches(CliElevationPackageIdentity left, CliElevationPackageIdentity right)
        => FileMatches(left.AppHost, right.AppHost) && FileMatches(left.Payload, right.Payload);

    private static bool FileMatches(CliElevationFileIdentity left, CliElevationFileIdentity right)
        => string.Equals(left.CanonicalPath, right.CanonicalPath, StringComparison.OrdinalIgnoreCase) &&
           left.Length == right.Length &&
           FixedEquals(left.Sha256, right.Sha256) &&
           string.Equals(left.LaunchIdentity, right.LaunchIdentity, StringComparison.Ordinal);

    private static bool ProcessMatches(CliElevationProcessIdentity left, CliElevationProcessIdentity right)
        => left.ProcessId == right.ProcessId &&
           left.StartTimeUtcTicks == right.StartTimeUtcTicks &&
           string.Equals(left.ImagePath, right.ImagePath, StringComparison.OrdinalIgnoreCase);

    private static string CreateToken()
        => TestHooks.Value?.TokenFactory?.Invoke() ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    private static void ValidateToken(string token)
    {
        if (token.Length != 64 || !token.All(static character => Uri.IsHexDigit(character)))
        {
            throw new CliElevationValidationException("The internal elevation token is invalid.");
        }
    }

    private static string ExtractCommand(IReadOnlyList<string> arguments)
    {
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (string.Equals(argument, "--version", StringComparison.OrdinalIgnoreCase))
            {
                return "version";
            }

            if (string.Equals(argument, "--help", StringComparison.OrdinalIgnoreCase))
            {
                return "help";
            }

            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                return argument.ToLowerInvariant();
            }

            if (OptionRequiresValue(argument))
            {
                index++;
            }
        }

        return "status";
    }

    private static bool OptionRequiresValue(string argument)
        => argument.ToLowerInvariant() is
            "--device-id" or "--volume-id" or "--operation-id" or
            "--recovery-identity" or "--mode" or "--requested-mode" or
            "--timeout-ms" or "--pipe-name";

    private static void WriteInvalidInternalInvocation(string message)
    {
        var response = new
        {
            schemaVersion = 2,
            command = "status",
            operationId = Guid.NewGuid().ToString("D"),
            success = false,
            exitCode = InvalidArguments,
            code = ApfsOperationCodes.InvalidArguments,
            resultCode = ApfsOperationCodes.InvalidArguments,
            errorCode = ApfsOperationCodes.InvalidArguments,
            message,
            error = message,
        };
        Console.WriteLine(JsonSerializer.Serialize(response, SerializerOptions));
    }

    private static CliElevationParentResult Failure(int exitCode, string code, string message)
        => new(exitCode, null, code, message);

    private static DateTimeOffset UtcNow()
        => TestHooks.Value?.UtcNow?.Invoke() ?? DateTimeOffset.UtcNow;

    private static bool IsSha256(string value)
        => value.Length == 64 && value.All(static character => Uri.IsHexDigit(character));

    private static bool FixedEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length &&
               CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static long ToStopwatchTicks(TimeSpan timeout)
        => Math.Max(1, checked((long)Math.Ceiling(timeout.TotalSeconds * Stopwatch.Frequency)));

    private static long CreateMonotonicDeadline(DateTimeOffset operationDeadlineUtc)
    {
        var remaining = operationDeadlineUtc - UtcNow();
        return remaining <= TimeSpan.Zero
            ? Stopwatch.GetTimestamp()
            : checked(Stopwatch.GetTimestamp() + ToStopwatchTicks(remaining));
    }

    private static TimeSpan GetRemaining(long deadline)
    {
        var ticks = deadline - Stopwatch.GetTimestamp();
        return ticks <= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds((double)ticks / Stopwatch.Frequency);
    }

    private static string ToBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '=');
        return Convert.FromBase64String(base64);
    }

    private sealed class ProductionElevationProcess : ICliElevationProcess
    {
        private readonly Process _process;

        internal ProductionElevationProcess(Process process)
        {
            _process = process;
            Identity = CaptureProcessIdentity(process);
        }

        public CliElevationProcessIdentity Identity { get; }
        public bool HasExited
        {
            get
            {
                try
                {
                    return _process.HasExited;
                }
                catch (InvalidOperationException)
                {
                    return true;
                }
            }
        }

        public int? ExitCode => HasExited ? _process.ExitCode : null;

        public CliElevationObservedProcess ObserveIdentity()
        {
            if (HasExited)
            {
                return CliElevationObservedProcess.Absent;
            }

            try
            {
                return new CliElevationObservedProcess(true, CaptureProcessIdentity(_process));
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
            {
                return new CliElevationObservedProcess(true, null);
            }
        }

        public Task WaitForExitAsync(CancellationToken cancellationToken)
            => _process.WaitForExitAsync(cancellationToken);

        public async Task<bool> TerminateTreeAndProveExitAsync(TimeSpan timeout)
        {
            if (HasExited)
            {
                return true;
            }

            var observed = ObserveIdentity();
            if (!observed.Exists)
            {
                return true;
            }

            if (observed.Identity is null || !ProcessMatches(Identity, observed.Identity))
            {
                return false;
            }

            try
            {
                _process.Kill(entireProcessTree: true);
                using var timeoutCts = new CancellationTokenSource(timeout);
                await _process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                return HasExited;
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or OperationCanceledException)
            {
                return HasExited;
            }
        }

        public void Dispose() => _process.Dispose();
    }

    private sealed class TestHookScope(CliElevationTestHooks? previous) : IDisposable
    {
        public void Dispose() => TestHooks.Value = previous;
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
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder filePath,
            int filePathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            IntPtr process,
            int flags,
            StringBuilder executableName,
            ref int size);
    }
}
