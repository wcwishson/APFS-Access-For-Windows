using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class CliElevationTests
{
    [Fact]
    public void PackageLeaseCleanupAttemptsBothHandlesWhenTheFirstDisposeFails()
    {
        var appHost = new TrackingThrowingDisposable(throws: false);
        var payload = new TrackingThrowingDisposable(throws: true);
        var identity = new CliElevationFileIdentity("C:\\test.exe", 1, "AA", "file-id");
        var lease = new CliElevationPackageLease(
            new CliElevationPackageIdentity(identity, identity),
            appHost,
            payload);

        var error = Assert.Throws<AggregateException>(() => lease.Dispose());

        Assert.True(payload.Disposed);
        Assert.True(appHost.Disposed);
        Assert.Single(error.InnerExceptions);
    }

    private static readonly CliElevationPackageIdentity Package = new(
        new CliElevationFileIdentity(
            @"C:\Program Files\APFS Access\ApfsAccess.Cli.exe",
            101,
            new string('A', 64),
            "00000001:0000000000000001"),
        new CliElevationFileIdentity(
            @"C:\Program Files\APFS Access\ApfsAccess.Cli.dll",
            202,
            new string('B', 64),
            "00000001:0000000000000002"));

    [Fact]
    public async Task ElevatePreservesEveryArgumentAndRemovesOnlyPublicMarker()
    {
        var publicArguments = new[]
        {
            "status",
            "--pipe-name", "pipe with spaces \"and quotes\" trailing\\",
            "--elevate",
            "--require-admin",
            "--timeout-ms", "1000",
        };
        var expectedChildArguments = publicArguments.Where(static value => value != "--elevate").ToArray();
        CliElevationContract? launchedContract = null;
        ProcessStartInfo? launchedStartInfo = null;
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, processId: 4101, startTimeUtcTicks: 638920000000000001);

        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            CaptureCurrentPackageIdentity = static () => Package,
            TokenFactory = static () => new string('1', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (startInfo, contract) =>
            {
                launchedStartInfo = startInfo;
                launchedContract = contract;
                return Task.FromResult<ICliElevationProcess>(process);
            },
            ObserveProcessIdentity = (_, _) => CliElevationObservedProcess.Absent,
            CreateServerChannel = contract => new TestServerChannel(
                contract,
                () => process,
                (_, child) => CreateValidEnvelope(contract, child.Identity, 0)),
            CreateJob = name => new TestElevationJob(name, () => process, terminateProof: true),
        });

        var result = await InvokeAsync(publicArguments);

        Assert.Equal(0, result.ExitCode);
        Assert.NotNull(launchedStartInfo);
        Assert.Equal("runas", launchedStartInfo!.Verb);
        Assert.True(launchedStartInfo.UseShellExecute);
        Assert.Equal(Package.AppHost.CanonicalPath, launchedStartInfo.FileName);
        Assert.Equal(CliElevation.InternalChildMarker, launchedStartInfo.ArgumentList[0]);
        Assert.Equal("--", launchedStartInfo.ArgumentList[2]);
        Assert.Equal(expectedChildArguments, launchedStartInfo.ArgumentList.Skip(3));
    }

    [Fact]
    public async Task AlreadyElevatedExecutesInProcessWithoutRecursion()
    {
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => true,
            StartElevatedProcessAsync = static (_, _) => throw new Xunit.Sdk.XunitException("Elevation must not recurse."),
        });

        var result = await InvokeAsync("version", "--elevate", "--require-admin");

        Assert.Equal(0, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.True(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("version", json.RootElement.GetProperty("command").GetString());
    }

    [Theory]
    [InlineData("--apfs-cli-elevation-child")]
    [InlineData("--apfs-cli-elevation-token")]
    [InlineData("--apfs-cli-elevation-result")]
    public async Task PublicArgumentsRejectInternalOrRecursiveMarkers(string marker)
    {
        var result = await InvokeAsync("version", marker, "injected");

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task MalformedInternalChildInvocationIsRejectedAsStableJson()
    {
        var result = await InvokeAsync(CliElevation.InternalChildMarker, "injected");

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(ApfsOperationCodes.InvalidArguments, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public void ElevateMarkerUsedAsAnOptionValueIsPreserved()
    {
        var parsed = CliElevation.ParsePublicArguments(["status", "--pipe-name", "--elevate"]);

        Assert.False(parsed.ElevationRequested);
        Assert.Equal(new[] { "status", "--pipe-name", "--elevate" }, parsed.Arguments);
    }

    [Fact]
    public async Task DuplicateElevateMarkersAreRejected()
    {
        var result = await InvokeAsync("version", "--elevate", "--elevate");

        Assert.Equal(2, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task UacCancellationUsesStableElevationFailure()
    {
        using var scope = InstallParentHooks(
            static (_, _) => Task.FromException<ICliElevationProcess>(new Win32Exception(1223)));

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(6, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.ElevationFailed, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task CancellationErrorAfterChildCreationStillProvesCleanup()
    {
        var process = TestElevationProcess.Running(Package.AppHost.CanonicalPath, 4115, 638920000000000015);
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            TokenFactory = static () => new string('9', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (_, _) => Task.FromResult<ICliElevationProcess>(process),
            ObserveProcessIdentity = (_, _) => new CliElevationObservedProcess(true, process.Identity),
            CreateServerChannel = _ => new FaultingServerChannel(new Win32Exception(1223)),
            CreateJob = name => new TestElevationJob(name, () => process, terminateProof: true),
        });

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(5, result.ExitCode);
        Assert.True(process.KillTreeCalled);
    }

    [Fact]
    public async Task InvalidStartedProcessEvidenceStillRunsBoundedExactCleanup()
    {
        var process = TestElevationProcess.Running(
            Package.AppHost.CanonicalPath,
            processId: 4116,
            startTimeUtcTicks: 0);
        using var scope = InstallParentHooks(
            (_, _) => Task.FromResult<ICliElevationProcess>(process),
            observe: (_, _) => process.ObserveIdentity());

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(10, result.ExitCode);
        Assert.True(process.KillTreeCalled);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task NonExclusiveElevationJobStillCleansTheExactLaunchedChild()
    {
        var process = TestElevationProcess.Running(
            Package.AppHost.CanonicalPath,
            processId: 4117,
            startTimeUtcTicks: 638920000000000017);
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            CaptureCurrentPackageIdentity = static () => Package,
            TokenFactory = static () => new string('8', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (_, _) => Task.FromResult<ICliElevationProcess>(process),
            ObserveProcessIdentity = (_, _) => process.ObserveIdentity(),
            CreateServerChannel = contract => new TestServerChannel(
                contract,
                () => process,
                (_, _) => null),
            CreateJob = name => new TestElevationJob(
                name,
                () => process,
                terminateProof: true,
                containsOnly: static () => false),
        });

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(10, result.ExitCode);
        Assert.True(process.KillTreeCalled);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task ShellLaunchFailureUsesStableElevationFailure()
    {
        using var scope = InstallParentHooks(
            static (_, _) => Task.FromException<ICliElevationProcess>(new Win32Exception(2)));

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(6, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.ElevationFailed, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task LateShellLaunchRetainsPackageLeaseUntilTheLaunchResolves()
    {
        var leaseDisposed = false;
        var launch = new TaskCompletionSource<ICliElevationProcess>(TaskCreationOptions.RunContinuationsAsynchronously);
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4110, 638920000000000010);
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = () => new CliElevationPackageLease(
                Package,
                new CallbackDisposable(() => leaseDisposed = true)),
            TokenFactory = static () => new string('4', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (_, _) => launch.Task,
            ObserveProcessIdentity = (_, _) => CliElevationObservedProcess.Absent,
        });

        try
        {
            var result = await CliElevation.RunParentAsync(["version"], TimeSpan.FromMilliseconds(1));

            Assert.Equal(10, result.ExitCode);
            Assert.False(leaseDisposed);
        }
        finally
        {
            launch.TrySetResult(process);
            await Task.Delay(100);
        }

        Assert.True(leaseDisposed);
    }

    [Fact]
    public async Task MissingResultEnvelopeNeverClaimsSuccess()
    {
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4107, 638920000000000007);
        using var scope = InstallParentHooks(
            (_, _) => Task.FromResult<ICliElevationProcess>(process));

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(5, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.OperationFailed, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task SelfAuthoredResultEnvelopeIsNotAcceptedAsChildEvidence()
    {
        CliElevationContract? launchedContract = null;
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4111, 638920000000000011);
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            CaptureCurrentPackageIdentity = static () => Package,
            TokenFactory = static () => new string('5', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (_, contract) =>
            {
                launchedContract = contract;
                return Task.FromResult<ICliElevationProcess>(process);
            },
            ObserveProcessIdentity = (_, _) => CliElevationObservedProcess.Absent,
        });

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(5, result.ExitCode);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.OperationFailed, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task SameUserPipeWriterWithWrongOsPeerPidIsNeverAuthorized()
    {
        var process = TestElevationProcess.Running(Package.AppHost.CanonicalPath, 4114, 638920000000000014);
        var hostileChannel = new WrongPeerServerChannel(process.Identity.ProcessId + 1);
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            TokenFactory = static () => new string('8', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (_, _) => Task.FromResult<ICliElevationProcess>(process),
            ObserveProcessIdentity = (_, _) => new CliElevationObservedProcess(true, process.Identity),
            CreateServerChannel = _ => hostileChannel,
            CreateJob = name => new TestElevationJob(name, () => process, terminateProof: true),
        });

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(5, result.ExitCode);
        Assert.False(hostileChannel.AuthorizationSent);
        Assert.True(process.KillTreeCalled);
    }

    [Fact]
    public async Task ReplayedResultEnvelopeIsNotAcceptedForANewLaunch()
    {
        CliElevationContract? launchedContract = null;
        CliElevationResultEnvelope? replayedEnvelope = null;
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4113, 638920000000000013);
        using var scope = CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            CaptureCurrentPackageIdentity = static () => Package,
            TokenFactory = static () => new string('6', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = (_, contract) =>
            {
                launchedContract = contract;
                return Task.FromResult<ICliElevationProcess>(process);
            },
            ObserveProcessIdentity = (_, _) => CliElevationObservedProcess.Absent,
            CreateServerChannel = contract => new TestServerChannel(
                contract,
                () => process,
                (_, child) => replayedEnvelope ??= CreateValidEnvelope(launchedContract!, child.Identity, 0)),
            CreateJob = name => new TestElevationJob(name, () => process, terminateProof: true),
        });

        var first = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");
        var replay = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(5, replay.ExitCode);
        using var json = JsonDocument.Parse(replay.Output);
        Assert.Equal(ApfsOperationCodes.OperationFailed, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task ElevationContractDoesNotExposeAFileResultPath()
    {
        CliElevationContract? launchedContract = null;
        using var scope = InstallParentHooks((_, contract) =>
        {
            launchedContract = contract;
            return Task.FromException<ICliElevationProcess>(new Win32Exception(2));
        });

        _ = await InvokeAsync("version", "--elevate", "--timeout-ms", "1000");

        Assert.NotNull(launchedContract);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(launchedContract, CliElevation.SerializerOptions));
        Assert.False(json.RootElement.TryGetProperty("resultPath", out _));
    }

    [Fact]
    public async Task InternalChildNeverExecutesWithoutExactParentAuthorization()
    {
        var contract = CreateIpcContract();
        var client = new TestClientChannel(
            contract.ParentPid,
            new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.AuthorizationMessage,
                contract.Token,
                Authorized: false,
                OperationDeadlineUtc: contract.OperationDeadlineUtc));
        var executed = false;
        using var scope = InstallChildHooks(contract, client);

        var exitCode = await CliElevation.RunInternalChildAsync(
            CreateInternalArguments(contract, "version"),
            (_, _) =>
            {
                executed = true;
                return Task.FromResult(0);
            });

        Assert.Equal(6, exitCode);
        Assert.False(executed);
        Assert.DoesNotContain(client.Writes, message => message.Type == CliElevationTransport.ResultMessage);
    }

    [Fact]
    public async Task InternalChildPublishesResultOnlyAfterExactParentAuthorization()
    {
        var contract = CreateIpcContract();
        var client = new TestClientChannel(
            contract.ParentPid,
            new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.AuthorizationMessage,
                contract.Token,
                Authorized: true,
                OperationDeadlineUtc: contract.OperationDeadlineUtc));
        using var scope = InstallChildHooks(contract, client);

        var exitCode = await CliElevation.RunInternalChildAsync(
            CreateInternalArguments(contract, "version"),
            (_, _) =>
            {
                Console.WriteLine("{\"schemaVersion\":2,\"command\":\"version\",\"success\":true,\"exitCode\":0}");
                return Task.FromResult(0);
            });

        Assert.Equal(0, exitCode);
        Assert.Collection(
            client.Writes,
            hello => Assert.Equal(CliElevationTransport.HelloMessage, hello.Type),
            result =>
            {
                Assert.Equal(CliElevationTransport.ResultMessage, result.Type);
                Assert.NotNull(result.Result);
                Assert.Equal(0, result.Result!.ExitCode);
            });
    }

    [Fact]
    public async Task DelayedAuthorizationPreservesTheParentDeadlineInTheServiceRequest()
    {
        const string deviceId = @"\\.\PhysicalDrive91";
        const string volumeId = @"\\.\PhysicalDrive91|Main";
        const string operationId = "29bc9680-2568-4b41-a759-b894c692f861";
        var pipeName = $"ApfsAccess.Cli.Elevation.Deadline.{Guid.NewGuid():N}";
        var publicArguments = new[]
        {
            "mount",
            "--device-id", deviceId,
            "--volume-id", volumeId,
            "--mode", ApfsControlModes.ReadWrite,
            "--operation-id", operationId,
            "--pipe-name", pipeName,
            "--no-start-service",
            "--timeout-ms", "2000",
        };
        var createdAt = DateTimeOffset.UtcNow;
        var contract = CreateIpcContract(publicArguments, createdAt, createdAt.AddSeconds(2));
        var client = new TestClientChannel(
            contract.ParentPid,
            new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.AuthorizationMessage,
                contract.Token,
                Authorized: true,
                OperationDeadlineUtc: contract.OperationDeadlineUtc),
            authorizationDelay: TimeSpan.FromMilliseconds(650));
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var serverTask = CaptureMutationRequestAsync(pipeName, serverCancellation.Token);
        using var scope = InstallChildHooks(contract, client);

        var exitCode = await CliElevation.RunInternalChildAsync(
            CreateInternalArguments(contract, publicArguments),
            static (publicArgs, operationDeadlineUtc) =>
                Program.RunForTestWithAuthenticatedOperationDeadlineAsync(publicArgs, operationDeadlineUtc));
        var issued = await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, exitCode);
        Assert.Equal(contract.OperationDeadlineUtc!.Value.UtcDateTime, issued.ExpiresAtUtc);
    }

    [Fact]
    public async Task AuthorizationThatArrivesAfterTheParentDeadlineNeverExecutesTheCommand()
    {
        var createdAt = DateTimeOffset.UtcNow;
        var contract = CreateIpcContract(["version"], createdAt, createdAt.AddMilliseconds(300));
        var client = new TestClientChannel(
            contract.ParentPid,
            new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.AuthorizationMessage,
                contract.Token,
                Authorized: true,
                OperationDeadlineUtc: contract.OperationDeadlineUtc),
            authorizationDelay: TimeSpan.FromMilliseconds(450));
        var executed = false;
        using var scope = InstallChildHooks(contract, client);

        var exitCode = await CliElevation.RunInternalChildAsync(
            CreateInternalArguments(contract, "version"),
            (_, _) =>
            {
                executed = true;
                Console.WriteLine("{\"schemaVersion\":2,\"command\":\"version\",\"success\":true,\"exitCode\":0}");
                return Task.FromResult(0);
            });

        Assert.Equal(6, exitCode);
        Assert.False(executed);
    }

    [Fact]
    public async Task InternalChildRejectsAnAuthenticatedDeadlineSubstitution()
    {
        var contract = CreateIpcContract();
        var client = new TestClientChannel(
            contract.ParentPid,
            new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.AuthorizationMessage,
                contract.Token,
                Authorized: true,
                OperationDeadlineUtc: contract.OperationDeadlineUtc!.Value.AddMilliseconds(1)));
        var executed = false;
        using var scope = InstallChildHooks(contract, client);

        var exitCode = await CliElevation.RunInternalChildAsync(
            CreateInternalArguments(contract, "version"),
            (_, _) =>
            {
                executed = true;
                return Task.FromResult(0);
            });

        Assert.Equal(6, exitCode);
        Assert.False(executed);
    }

    [Fact]
    public async Task InternalChildDisposesTheAssignmentJobBeforeExecutingTheCommand()
    {
        var contract = CreateIpcContract();
        var assignmentJob = new TrackingElevationJob(contract.JobName!);
        var disposedBeforeAuthorization = false;
        var client = new TestClientChannel(
            contract.ParentPid,
            new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.AuthorizationMessage,
                contract.Token,
                Authorized: true,
                OperationDeadlineUtc: contract.OperationDeadlineUtc),
            onConnect: () => disposedBeforeAuthorization = assignmentJob.Disposed);
        var disposedBeforeExecution = false;
        using var scope = InstallChildHooks(contract, client, assignmentJob);

        var exitCode = await CliElevation.RunInternalChildAsync(
            CreateInternalArguments(contract, "version"),
            (_, _) =>
            {
                disposedBeforeExecution = assignmentJob.Disposed;
                Console.WriteLine("{\"schemaVersion\":2,\"command\":\"version\",\"success\":true,\"exitCode\":0}");
                return Task.FromResult(0);
            });

        Assert.Equal(0, exitCode);
        Assert.True(disposedBeforeAuthorization);
        Assert.True(disposedBeforeExecution);
    }

    [Fact]
    public async Task TimeoutTerminatesOnlyTheMatchingElevatedChildTree()
    {
        var process = TestElevationProcess.Running(Package.AppHost.CanonicalPath, processId: 4102, startTimeUtcTicks: 638920000000000002);
        using var scope = InstallParentHooks(
            (_, _) => Task.FromResult<ICliElevationProcess>(process),
            observe: (_, _) => new CliElevationObservedProcess(true, process.Identity));

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "250");

        Assert.Equal(4, result.ExitCode);
        Assert.True(process.KillTreeCalled);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.Timeout, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task TimeoutRefusesCleanupWhenChildIdentityChanged()
    {
        var process = TestElevationProcess.Running(Package.AppHost.CanonicalPath, processId: 4103, startTimeUtcTicks: 638920000000000003);
        var replaced = process.Identity with { StartTimeUtcTicks = process.Identity.StartTimeUtcTicks + 1 };
        using var scope = InstallParentHooks(
            (_, _) => Task.FromResult<ICliElevationProcess>(process),
            observe: (_, _) => new CliElevationObservedProcess(true, replaced));

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "250");

        Assert.Equal(10, result.ExitCode);
        Assert.False(process.KillTreeCalled);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task TimeoutRequiresPostKillProofOfWholeTreeAbsence()
    {
        var process = TestElevationProcess.Running(Package.AppHost.CanonicalPath, processId: 4112, startTimeUtcTicks: 638920000000000012);
        using var scope = InstallParentHooks(
            (_, _) => Task.FromResult<ICliElevationProcess>(process),
            observe: (_, _) => new CliElevationObservedProcess(true, process.Identity),
            terminateProof: false);

        var result = await InvokeAsync("version", "--elevate", "--timeout-ms", "250");

        Assert.Equal(10, result.ExitCode);
        Assert.True(process.KillTreeCalled);
        using var json = JsonDocument.Parse(result.Output);
        Assert.Equal(ApfsOperationCodes.UnsafeOwnership, json.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task ClosingTheSoleOwnerOnAbruptParentDeathTerminatesTheExactWholeProcessTree()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var pwshPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "PowerShell",
            "7",
            "pwsh.exe");
        Assert.True(File.Exists(pwshPath), $"PowerShell 7 was not found at '{pwshPath}'.");

        var root = Path.Combine(Path.GetTempPath(), "ApfsAccess.Cli.ParentCrash", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var readyPath = Path.Combine(root, "tree-ready.json");
        var cliAssemblyPath = typeof(CliElevation).Assembly.Location;
        var jobName = $@"Local\ApfsAccess.Cli.Elevation.ParentCrash.{Guid.NewGuid():N}";
        var descendantScript = "while ($true) { Start-Sleep -Milliseconds 100 }";
        var childScript = $$"""
            $ErrorActionPreference = 'Stop'
            $assembly = [Reflection.Assembly]::LoadFrom('{{PowerShellLiteral(cliAssemblyPath)}}')
            $transport = $assembly.GetType('ApfsAccess.Cli.CliElevationTransport', $true)
            $open = $transport.GetMethod('OpenJob', [Reflection.BindingFlags]'Static,NonPublic')
            $job = $open.Invoke($null, @('{{PowerShellLiteral(jobName)}}'))
            $jobType = $job.GetType()
            $null = $jobType.GetMethod('AssignCurrentProcess').Invoke($job, @())
            $null = $jobType.GetMethod('Dispose').Invoke($job, @())
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = '{{PowerShellLiteral(pwshPath)}}'
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.ArgumentList.Add('-NoLogo')
            $startInfo.ArgumentList.Add('-NoProfile')
            $startInfo.ArgumentList.Add('-NonInteractive')
            $startInfo.ArgumentList.Add('-EncodedCommand')
            $startInfo.ArgumentList.Add('{{EncodePowerShell(descendantScript)}}')
            $descendant = [Diagnostics.Process]::Start($startInfo)
            $self = [Diagnostics.Process]::GetCurrentProcess()
            $descendant.Refresh()
            $evidence = [ordered]@{
                childPid = $PID
                childStartTimeUtcTicks = $self.StartTime.ToUniversalTime().Ticks
                childPath = $self.MainModule.FileName
                descendantPid = $descendant.Id
                descendantStartTimeUtcTicks = $descendant.StartTime.ToUniversalTime().Ticks
                descendantPath = $descendant.MainModule.FileName
            }
            $temporary = '{{PowerShellLiteral(readyPath)}}.tmp'
            [IO.File]::WriteAllText($temporary, ($evidence | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
            [IO.File]::Move($temporary, '{{PowerShellLiteral(readyPath)}}')
            while ($true) { Start-Sleep -Milliseconds 100 }
            """;
        var ownerScript = $$"""
            $ErrorActionPreference = 'Stop'
            $assembly = [Reflection.Assembly]::LoadFrom('{{PowerShellLiteral(cliAssemblyPath)}}')
            $transport = $assembly.GetType('ApfsAccess.Cli.CliElevationTransport', $true)
            $create = $transport.GetMethod('CreateJob', [Reflection.BindingFlags]'Static,NonPublic')
            $job = $create.Invoke($null, @('{{PowerShellLiteral(jobName)}}'))
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = '{{PowerShellLiteral(pwshPath)}}'
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.ArgumentList.Add('-NoLogo')
            $startInfo.ArgumentList.Add('-NoProfile')
            $startInfo.ArgumentList.Add('-NonInteractive')
            $startInfo.ArgumentList.Add('-EncodedCommand')
            $startInfo.ArgumentList.Add('{{EncodePowerShell(childScript)}}')
            $child = [Diagnostics.Process]::Start($startInfo)
            while ($true) { Start-Sleep -Milliseconds 100 }
            """;
        using var owner = StartPowerShell(pwshPath, ownerScript);
        ProcessEvidence? child = null;
        ProcessEvidence? descendant = null;
        try
        {
            await WaitForFileAsync(readyPath, owner, TimeSpan.FromSeconds(10));
            using (var ready = JsonDocument.Parse(await File.ReadAllTextAsync(readyPath)))
            {
                child = ReadProcessEvidence(ready.RootElement, "child");
                descendant = ReadProcessEvidence(ready.RootElement, "descendant");
            }

            Assert.Equal(ExactProcessState.Matching, ObserveExactProcess(child));
            Assert.Equal(ExactProcessState.Matching, ObserveExactProcess(descendant));

            owner.Kill(entireProcessTree: false);
            await owner.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));

            await WaitForExactAbsenceAsync(child, descendant, TimeSpan.FromSeconds(5));
        }
        finally
        {
            TryKillExactProcessTree(child);
            TryKillExactProcessTree(descendant);
            if (!owner.HasExited)
            {
                owner.Kill(entireProcessTree: true);
                owner.WaitForExit(5_000);
            }

            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    [Fact]
    public void ResultValidationRejectsMalformedStaleAndMismatchedEnvelopes()
    {
        var contract = CreateContract();
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4104, 638920000000000004);
        var valid = CreateValidResult(contract, process.Identity, 0);

        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, process.Identity, 0, Package, "{"));

        var stale = JsonSerializer.Deserialize<CliElevationResultEnvelope>(valid, CliElevation.SerializerOptions)! with
        {
            StartedAtUtc = contract.CreatedAtUtc.AddSeconds(-1),
        };
        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, process.Identity, 0, Package, JsonSerializer.Serialize(stale, CliElevation.SerializerOptions)));

        var mismatched = JsonSerializer.Deserialize<CliElevationResultEnvelope>(valid, CliElevation.SerializerOptions)! with
        {
            Token = new string('9', 64),
        };
        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, process.Identity, 0, Package, JsonSerializer.Serialize(mismatched, CliElevation.SerializerOptions)));
    }

    [Fact]
    public void ResultValidationRejectsPackageMutationAliasAndWrongChildIdentity()
    {
        var contract = CreateContract();
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4105, 638920000000000005);
        var valid = CreateValidResult(contract, process.Identity, 0);

        var mutatedPackage = Package with
        {
            Payload = Package.Payload with { Sha256 = new string('C', 64) },
        };
        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, process.Identity, 0, mutatedPackage, valid));

        var aliasedPackage = Package with
        {
            AppHost = Package.AppHost with { CanonicalPath = @"C:\Alias\ApfsAccess.Cli.exe" },
        };
        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, process.Identity, 0, aliasedPackage, valid));

        var wrongChild = process.Identity with { ProcessId = process.Identity.ProcessId + 1 };
        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, wrongChild, 0, Package, valid));
    }

    [Fact]
    public void ResultValidationRejectsOutputTampering()
    {
        var contract = CreateContract();
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4106, 638920000000000006);
        var valid = JsonSerializer.Deserialize<CliElevationResultEnvelope>(
            CreateValidResult(contract, process.Identity, 0),
            CliElevation.SerializerOptions)! with
        {
            Stdout = "{\"schemaVersion\":2,\"exitCode\":5}",
        };

        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(
                contract,
                process.Identity,
                0,
                Package,
                JsonSerializer.Serialize(valid, CliElevation.SerializerOptions)));
    }

    [Fact]
    public void ResultValidationBindsTheActualChildExitCode()
    {
        var contract = CreateContract();
        var process = TestElevationProcess.Exited(Package.AppHost.CanonicalPath, 4108, 638920000000000008);
        var result = CreateValidResult(contract, process.Identity, 0);

        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidateResultEnvelopeForTests(contract, process.Identity, 5, Package, result));
    }

    [Fact]
    public void PackagedPathValidationRejectsFrameworkHostAndAliases()
    {
        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidatePackagedPathsForTests(
                @"C:\Program Files\dotnet\dotnet.exe",
                @"C:\Program Files\APFS Access\ApfsAccess.Cli.dll",
                @"C:\Program Files\dotnet\dotnet.exe",
                @"C:\Program Files\APFS Access\ApfsAccess.Cli.dll"));

        Assert.Throws<CliElevationValidationException>(() =>
            CliElevation.ValidatePackagedPathsForTests(
                Package.AppHost.CanonicalPath,
                Package.Payload.CanonicalPath,
                @"C:\Alias\ApfsAccess.Cli.exe",
                Package.Payload.CanonicalPath));
    }

    private static IDisposable InstallParentHooks(
        Func<ProcessStartInfo, CliElevationContract, Task<ICliElevationProcess>> start,
        Func<int, long, CliElevationObservedProcess>? observe = null,
        bool terminateProof = true)
    {
        ICliElevationProcess? launchedProcess = null;
        CliElevationContract? launchedContract = null;
        return CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => false,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            CaptureCurrentPackageIdentity = static () => Package,
            TokenFactory = static () => new string('2', 64),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000000,
                path),
            StartElevatedProcessAsync = async (startInfo, contract) =>
            {
                launchedContract = contract;
                launchedProcess = await start(startInfo, contract);
                return launchedProcess;
            },
            ObserveProcessIdentity = observe ?? ((_, _) => CliElevationObservedProcess.Absent),
            CreateServerChannel = contract => new TestServerChannel(
                contract,
                () => launchedProcess,
                (_, _) => null),
            CreateJob = name => new TestElevationJob(
                name,
                () => launchedProcess,
                terminateProof,
                containsOnly: () =>
                {
                    if (observe is null || launchedProcess is null)
                    {
                        return true;
                    }

                    var observed = observe(
                        launchedProcess.Identity.ProcessId,
                        launchedProcess.Identity.StartTimeUtcTicks);
                    return observed.Exists && observed.Identity == launchedProcess.Identity;
                }),
        });
    }

    private static CliElevationContract CreateContract()
    {
        var token = new string('3', 64);
        return new(
            CliElevation.ContractSchemaVersion,
            token,
            "version",
            CliElevation.ComputeArgumentsSha256(["version"]),
            4000,
            638920000000000000,
            Package,
            new DateTimeOffset(2026, 8, 28, 1, 0, 0, TimeSpan.Zero));
    }

    private static CliElevationContract CreateIpcContract()
        => CreateIpcContract(["version"], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(30));

    private static CliElevationContract CreateIpcContract(
        string[] publicArguments,
        DateTimeOffset createdAt,
        DateTimeOffset operationDeadlineUtc)
    {
        var token = new string('7', 64);
        return new CliElevationContract(
            CliElevation.ContractSchemaVersion,
            token,
            publicArguments[0],
            CliElevation.ComputeArgumentsSha256(publicArguments),
            4000,
            638920000000000000,
            Package,
            createdAt,
            $"ApfsAccess.Cli.Elevation.{token}",
            $@"Local\ApfsAccess.Cli.Elevation.{token}",
            operationDeadlineUtc);
    }

    private static IDisposable InstallChildHooks(
        CliElevationContract contract,
        TestClientChannel client,
        ICliElevationJob? assignmentJob = null)
        => CliElevation.InstallTestHooks(new CliElevationTestHooks
        {
            IsAdministrator = static () => true,
            AcquirePackageLease = static () => new CliElevationPackageLease(Package),
            ObserveProcessIdentity = (pid, ticks) => new CliElevationObservedProcess(
                true,
                new CliElevationProcessIdentity(pid, ticks, Package.AppHost.CanonicalPath)),
            CaptureCurrentProcessIdentity = static path => new CliElevationProcessIdentity(
                Environment.ProcessId,
                638920000000000099,
                path),
            CreateClientChannel = _ => client,
            OpenJob = name => assignmentJob ?? new TestElevationJob(name, static () => null, terminateProof: true),
        });

    private static async Task<ControlOperationRequestPayload> CaptureMutationRequestAsync(
        string pipeName,
        CancellationToken cancellationToken)
    {
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync(cancellationToken);
        await using var peer = new PipePeer(server);
        var status = new StatusChangedPayload(
            RuntimeState.MountedRo,
            Array.Empty<string>(),
            null,
            DateTime.UtcNow,
            Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes: Array.Empty<MountedVolumeDisplay>());
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), cancellationToken);
        var request = await peer.ReadMessageAsync(cancellationToken)
            ?? throw new Xunit.Sdk.XunitException("The deadline test service received EOF before the mutation request.");
        Assert.Equal(ApfsMessageTypes.ControlOperationRequest, request.Type);
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(request, out var issued));
        Assert.NotNull(issued);
        var requestedAt = DateTime.UtcNow;
        var result = new OperationResultPayload(
            issued!.OperationId,
            issued.Command,
            issued.Target,
            Fingerprint: ApfsOperationFingerprint.Compute(issued),
            State: ApfsOperationStates.Succeeded,
            Code: ApfsOperationCodes.OperationSucceeded,
            Success: true,
            RequestedAtUtc: requestedAt,
            StartedAtUtc: requestedAt.AddMilliseconds(1),
            CompletedAtUtc: requestedAt.AddMilliseconds(2),
            FinalStatus: "healthy-rw",
            RequestedMode: issued.RequestedMode,
            EffectiveMode: issued.RequestedMode,
            RecoveryState: "clean",
            RecoveryActive: false,
            DirtyTransactionCount: 0,
            PendingDurability: false,
            MountProof: "present",
            OwnershipProof: "not-applicable",
            DurabilityProof: "not-applicable",
            ExpiresAtUtc: issued.ExpiresAtUtc);
        await peer.SendAsync(
            PipeMessageCodec.Create(
                ApfsMessageTypes.OperationResult,
                result,
                issued.OperationId,
                PipeSchemaVersions.Schema2),
            cancellationToken);
        return issued;
    }

    private static Process StartPowerShell(string pwshPath, string script)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = pwshPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(EncodePowerShell(script));
        return Process.Start(startInfo)
            ?? throw new Xunit.Sdk.XunitException("Could not start the isolated PowerShell 7 parent-crash helper.");
    }

    private static string EncodePowerShell(string script)
        => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

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
                var stdout = await owner.StandardOutput.ReadToEndAsync();
                var stderr = await owner.StandardError.ReadToEndAsync();
                throw new Xunit.Sdk.XunitException(
                    $"The parent-crash helper exited before publishing process evidence. stdout={stdout} stderr={stderr}");
            }

            await Task.Delay(25);
        }

        throw new Xunit.Sdk.XunitException("The parent-crash helper did not publish process evidence within 10 seconds.");
    }

    private static ProcessEvidence ReadProcessEvidence(JsonElement root, string prefix)
        => new(
            root.GetProperty($"{prefix}Pid").GetInt32(),
            root.GetProperty($"{prefix}StartTimeUtcTicks").GetInt64(),
            root.GetProperty($"{prefix}Path").GetString()
                ?? throw new Xunit.Sdk.XunitException($"The {prefix} path evidence is missing."));

    private static async Task WaitForExactAbsenceAsync(
        ProcessEvidence child,
        ProcessEvidence descendant,
        TimeSpan timeout)
    {
        var deadline = Stopwatch.GetTimestamp() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (ObserveExactProcess(child) == ExactProcessState.Absent &&
                ObserveExactProcess(descendant) == ExactProcessState.Absent)
            {
                return;
            }

            await Task.Delay(25);
        }

        Assert.Equal(ExactProcessState.Absent, ObserveExactProcess(child));
        Assert.Equal(ExactProcessState.Absent, ObserveExactProcess(descendant));
    }

    private static ExactProcessState ObserveExactProcess(ProcessEvidence? evidence)
    {
        if (evidence is null)
        {
            return ExactProcessState.Absent;
        }

        try
        {
            using var process = Process.GetProcessById(evidence.ProcessId);
            if (process.HasExited)
            {
                return ExactProcessState.Absent;
            }

            var startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks;
            var path = process.MainModule?.FileName;
            return startTimeUtcTicks == evidence.StartTimeUtcTicks &&
                   string.Equals(path, evidence.ImagePath, StringComparison.OrdinalIgnoreCase)
                ? ExactProcessState.Matching
                : ExactProcessState.Absent;
        }
        catch (ArgumentException)
        {
            return ExactProcessState.Absent;
        }
        catch (InvalidOperationException)
        {
            return ExactProcessState.Absent;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return ExactProcessState.Indeterminate;
        }
    }

    private static void TryKillExactProcessTree(ProcessEvidence? evidence)
    {
        if (evidence is null || ObserveExactProcess(evidence) != ExactProcessState.Matching)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(evidence.ProcessId);
            if (process.StartTime.ToUniversalTime().Ticks != evidence.StartTimeUtcTicks)
            {
                return;
            }

            process.Kill(entireProcessTree: true);
            process.WaitForExit(5_000);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
    }

    private static string[] CreateInternalArguments(CliElevationContract contract, params string[] publicArguments)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(contract, CliElevation.SerializerOptions);
        var encoded = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return [CliElevation.InternalChildMarker, encoded, "--", .. publicArguments];
    }

    private static string CreateValidResult(
        CliElevationContract contract,
        CliElevationProcessIdentity process,
        int exitCode)
        => JsonSerializer.Serialize(
            CreateValidEnvelope(contract, process, exitCode),
            CliElevation.SerializerOptions);

    private static CliElevationResultEnvelope CreateValidEnvelope(
        CliElevationContract contract,
        CliElevationProcessIdentity process,
        int exitCode)
    {
        var stdout = $"{{\"schemaVersion\":2,\"command\":\"{contract.Command}\",\"success\":true,\"exitCode\":{exitCode}}}{Environment.NewLine}";
        return new CliElevationResultEnvelope(
            CliElevation.ResultSchemaVersion,
            contract.Token,
            contract.Command,
            contract.ArgumentsSha256,
            contract.ParentPid,
            contract.ParentStartTimeUtcTicks,
            process.ProcessId,
            process.StartTimeUtcTicks,
            Package.AppHost.CanonicalPath,
            Package.AppHost.Length,
            Package.AppHost.Sha256,
            Package.AppHost.LaunchIdentity,
            Package.Payload.CanonicalPath,
            Package.Payload.Length,
            Package.Payload.Sha256,
            Package.Payload.LaunchIdentity,
            contract.CreatedAtUtc,
            contract.CreatedAtUtc.AddMilliseconds(10),
            stdout,
            CliElevation.ComputeSha256(stdout),
            exitCode);
    }

    private static async Task<(int ExitCode, string Output)> InvokeAsync(params string[] args)
    {
        var original = Console.Out;
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        Console.SetOut(writer);
        try
        {
            return (await Program.RunForTestAsync(args), writer.ToString());
        }
        finally
        {
            Console.SetOut(original);
        }
    }

    private sealed class TestElevationProcess : ICliElevationProcess
    {
        private readonly TaskCompletionSource<bool> _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private TestElevationProcess(CliElevationProcessIdentity identity, bool exited)
        {
            Identity = identity;
            if (exited)
            {
                _exit.TrySetResult(true);
            }
        }

        public CliElevationProcessIdentity Identity { get; }
        public bool HasExited => _exit.Task.IsCompleted;
        public int? ExitCode => HasExited ? 0 : null;
        public bool KillTreeCalled { get; private set; }

        public CliElevationObservedProcess ObserveIdentity()
            => HasExited
                ? CliElevationObservedProcess.Absent
                : new CliElevationObservedProcess(true, Identity);

        public static TestElevationProcess Exited(string path, int processId, long startTimeUtcTicks)
            => new(new CliElevationProcessIdentity(processId, startTimeUtcTicks, path), exited: true);

        public static TestElevationProcess Running(string path, int processId, long startTimeUtcTicks)
            => new(new CliElevationProcessIdentity(processId, startTimeUtcTicks, path), exited: false);

        public Task WaitForExitAsync(CancellationToken cancellationToken)
            => _exit.Task.WaitAsync(cancellationToken);

        public Task<bool> TerminateTreeAndProveExitAsync(TimeSpan timeout)
        {
            KillTreeCalled = true;
            _exit.TrySetResult(true);
            return Task.FromResult(true);
        }

        public void Dispose()
        {
        }
    }

    private sealed class CallbackDisposable(Action callback) : IDisposable
    {
        public void Dispose() => callback();
    }

    private sealed class TrackingThrowingDisposable(bool throws) : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
            if (throws)
            {
                throw new IOException("Injected elevation lease cleanup failure.");
            }
        }
    }

    private sealed class TestServerChannel(
        CliElevationContract contract,
        Func<ICliElevationProcess?> process,
        Func<CliElevationContract, ICliElevationProcess, CliElevationResultEnvelope?> resultFactory)
        : ICliElevationServerChannel
    {
        private int _readCount;

        public int? PeerProcessId { get; private set; }

        public Task WaitForExactPeerAsync(int expectedProcessId, TimeSpan timeout)
        {
            var child = process() ?? throw new InvalidOperationException("The test child is unavailable.");
            PeerProcessId = child.Identity.ProcessId;
            if (PeerProcessId != expectedProcessId)
            {
                throw new CliElevationValidationException("The test peer process is mismatched.");
            }

            return Task.CompletedTask;
        }

        public Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout)
        {
            var child = process() ?? throw new InvalidOperationException("The test child is unavailable.");
            if (_readCount++ == 0)
            {
                return Task.FromResult(new CliElevationWireMessage(
                    CliElevationTransport.WireSchemaVersion,
                    CliElevationTransport.HelloMessage,
                    contract.Token,
                    child.Identity,
                    Package,
                    OperationDeadlineUtc: contract.OperationDeadlineUtc));
            }

            var result = resultFactory(contract, child);
            if (result is null)
            {
                throw child.HasExited
                    ? new EndOfStreamException("The test child did not publish a result.")
                    : new TimeoutException("The test child exceeded its result deadline.");
            }
            return Task.FromResult(new CliElevationWireMessage(
                CliElevationTransport.WireSchemaVersion,
                CliElevationTransport.ResultMessage,
                contract.Token,
                Result: result,
                OperationDeadlineUtc: contract.OperationDeadlineUtc));
        }

        public Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout)
        {
            Assert.Equal(CliElevationTransport.AuthorizationMessage, message.Type);
            Assert.True(message.Authorized);
            Assert.Equal(contract.OperationDeadlineUtc, message.OperationDeadlineUtc);
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class TestClientChannel(
        int peerProcessId,
        CliElevationWireMessage authorization,
        TimeSpan? authorizationDelay = null,
        Action? onConnect = null) : ICliElevationClientChannel
    {
        public int? PeerProcessId { get; private set; }
        public List<CliElevationWireMessage> Writes { get; } = [];

        public Task ConnectToExactServerAsync(int expectedProcessId, TimeSpan timeout)
        {
            onConnect?.Invoke();
            PeerProcessId = peerProcessId;
            if (PeerProcessId != expectedProcessId)
            {
                throw new CliElevationValidationException("The test server process is mismatched.");
            }

            return Task.CompletedTask;
        }

        public async Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout)
        {
            if (authorizationDelay > TimeSpan.Zero)
            {
                await Task.Delay(authorizationDelay.Value);
            }

            return authorization;
        }

        public Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout)
        {
            Writes.Add(message);
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class WrongPeerServerChannel(int peerProcessId) : ICliElevationServerChannel
    {
        public int? PeerProcessId => peerProcessId;
        public bool AuthorizationSent { get; private set; }

        public Task WaitForExactPeerAsync(int expectedProcessId, TimeSpan timeout)
            => throw new CliElevationValidationException("The observed pipe peer is not the launched child.");

        public Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout)
            => throw new InvalidOperationException("A wrong peer must never be read.");

        public Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout)
        {
            AuthorizationSent = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FaultingServerChannel(Exception exception) : ICliElevationServerChannel
    {
        public int? PeerProcessId => null;

        public Task WaitForExactPeerAsync(int expectedProcessId, TimeSpan timeout)
            => Task.FromException(exception);

        public Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout)
            => Task.FromException<CliElevationWireMessage>(exception);

        public Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout)
            => Task.FromException(exception);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class TestElevationJob(
        string name,
        Func<ICliElevationProcess?> process,
        bool terminateProof,
        Func<bool>? containsOnly = null) : ICliElevationJob
    {
        public string Name => name;

        public void AssignCurrentProcess()
        {
        }

        public bool ContainsOnlyProcess(int processId)
            => process()?.Identity.ProcessId == processId && (containsOnly?.Invoke() ?? true);

        public async Task<bool> TerminateAndProveEmptyAsync(TimeSpan timeout)
        {
            var child = process();
            if (child is not null && !child.HasExited)
            {
                _ = await child.TerminateTreeAndProveExitAsync(timeout);
            }

            return terminateProof;
        }

        public void Dispose()
        {
        }
    }

    private sealed class TrackingElevationJob(string name) : ICliElevationJob
    {
        public string Name => name;
        public bool Disposed { get; private set; }

        public void AssignCurrentProcess()
        {
            Assert.False(Disposed);
        }

        public bool ContainsOnlyProcess(int processId) => !Disposed;

        public Task<bool> TerminateAndProveEmptyAsync(TimeSpan timeout)
            => Task.FromResult(false);

        public void Dispose() => Disposed = true;
    }

    private sealed record ProcessEvidence(int ProcessId, long StartTimeUtcTicks, string ImagePath);

    private enum ExactProcessState
    {
        Absent,
        Matching,
        Indeterminate,
    }
}
