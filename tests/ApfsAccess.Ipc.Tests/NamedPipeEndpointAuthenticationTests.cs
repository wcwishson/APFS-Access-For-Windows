using System.IO.Pipes;
using System.Runtime.Versioning;

namespace ApfsAccess.Ipc.Tests;

[Collection("Production pipe authentication")]
[SupportedOSPlatform("windows")]
public sealed class NamedPipeEndpointAuthenticationTests
{
    private const string UserSid = "S-1-5-21-100-200-300-1001";
    private const int SessionId = 7;

    [Fact]
    public void ProductionPolicy_CannotBeBypassedWithPipeNameCasing()
    {
        Assert.True(NamedPipeEndpointAuthentication.IsRequired(
            ApfsPipeConstants.PipeName.ToUpperInvariant()));
        Assert.True(NamedPipeEndpointAuthentication.IsRequired(
            ApfsPipeConstants.PipeName.ToLowerInvariant()));
    }

    [Fact]
    public async Task ProductionClient_RejectsSquattedServerWithRealWindowsHandles()
    {
        Assert.True(OperatingSystem.IsWindows());

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var squatter = new NamedPipeServerStream(
            ApfsPipeConstants.PipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var connected = squatter.WaitForConnectionAsync(cancellation.Token);

        PipePeer? peer = null;
        var exception = await Record.ExceptionAsync(async () =>
        {
            peer = await NamedPipeMessageClient.ConnectAsync(
                ApfsPipeConstants.PipeName,
                timeoutMilliseconds: 2000,
                cancellation.Token);
        });

        await connected;
        if (peer is not null)
        {
            await peer.DisposeAsync();
        }

        Assert.IsType<UnauthorizedAccessException>(exception);
    }

    [Fact]
    public async Task ProductionServer_RejectsUnauthorizedClientBeforeHandlerWithRealWindowsHandles()
    {
        Assert.True(OperatingSystem.IsWindows());

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handlerCalled = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new NamedPipeMessageServer(ApfsPipeConstants.PipeName);
        var serverTask = server.RunAsync((_, _) =>
        {
            handlerCalled.TrySetResult();
            return Task.CompletedTask;
        }, cancellation.Token);
        try
        {
            await using var client = new NamedPipeClientStream(
                ".",
                ApfsPipeConstants.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);
            await client.ConnectAsync(2000, cancellation.Token);
            await Task.Delay(250, cancellation.Token);

            Assert.False(handlerCalled.Task.IsCompleted);
        }
        finally
        {
            await cancellation.CancelAsync();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task WindowsIdentitySource_ObservesExactPipeProcessIdsWithRealWindowsHandles()
    {
        Assert.True(OperatingSystem.IsWindows());

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var pipeName = $"ApfsAccess.PipeIdentity.{Guid.NewGuid():N}";
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        var connected = server.WaitForConnectionAsync(cancellation.Token);
        await client.ConnectAsync(2000, cancellation.Token);
        await connected;

        Assert.Equal(
            Environment.ProcessId,
            WindowsPipeEndpointIdentitySource.Instance.GetClientProcessId(server));
        Assert.Equal(
            Environment.ProcessId,
            WindowsPipeEndpointIdentitySource.Instance.GetServerProcessId(client));

        var identity = WindowsPipeEndpointIdentitySource.Instance.GetCurrentProcessIdentity();
        Assert.Equal(Environment.ProcessId, identity.ProcessId);
        Assert.Equal(
            System.Diagnostics.Process.GetCurrentProcess().SessionId,
            identity.SessionId);
        Assert.StartsWith("S-1-", identity.UserSid, StringComparison.Ordinal);
        Assert.True(identity.IntegrityRid >= PipeIntegrityLevels.Low);
        Assert.Equal(
            Path.GetFullPath(Environment.ProcessPath!),
            identity.ImagePath,
            ignoreCase: true);
    }

    [Fact]
    public void SimulatedServicePolicy_AcceptsPackagedNonAdminTrayAndCli()
    {
        var combinedService = Identity(
            100,
            PipeIntegrityLevels.High,
            @"D:\Package\ApfsAccess.Service.exe");
        var tray = Identity(
            200,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Tray.exe");
        var cli = Identity(
            201,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Cli.exe");
        var splitService = combinedService with
        {
            ImagePath = @"D:\Package\service\ApfsAccess.Service.exe",
        };
        var splitTray = tray with
        {
            ImagePath = @"D:\Package\tray\ApfsAccess.Tray.exe",
        };
        var splitCli = cli with
        {
            ImagePath = @"D:\Package\cli\ApfsAccess.Cli.exe",
        };

        NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(combinedService, tray);
        NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(combinedService, cli);
        NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(splitService, tray);
        NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(splitService, splitTray);
        NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(splitService, splitCli);
    }

    [Fact]
    public void SimulatedServicePolicy_RejectsUnauthorizedControlClients()
    {
        foreach (var (service, client) in UnauthorizedControlClients())
        {
            Assert.Throws<UnauthorizedAccessException>(
                () => NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(service, client));
        }
    }

    [Fact]
    public void SimulatedClientPolicy_AcceptsHighIntegrityServiceInSupportedLayouts()
    {
        var tray = Identity(
            200,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Tray.exe");
        var cli = Identity(
            201,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Cli.exe");
        var combinedService = Identity(
            100,
            PipeIntegrityLevels.High,
            @"D:\Package\ApfsAccess.Service.exe");
        var splitService = combinedService with
        {
            ImagePath = @"D:\Package\service\ApfsAccess.Service.exe",
        };
        var splitTray = tray with
        {
            ImagePath = @"D:\Package\tray\ApfsAccess.Tray.exe",
        };
        var splitCli = cli with
        {
            ImagePath = @"D:\Package\cli\ApfsAccess.Cli.exe",
        };

        NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(tray, combinedService);
        NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(tray, splitService);
        NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(cli, combinedService);
        NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(splitTray, splitService);
        NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(splitCli, splitService);
    }

    [Fact]
    public void SimulatedPolicy_RejectsLocalSystemSessionZeroServiceUnderPerUserDeploymentContract()
    {
        var tray = Identity(
            200,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Tray.exe");
        var systemService = new PipeEndpointProcessIdentity(
            100,
            "S-1-5-18",
            SessionId: 0,
            PipeIntegrityLevels.High,
            @"D:\Package\ApfsAccess.Service.exe");

        Assert.Throws<UnauthorizedAccessException>(
            () => NamedPipeEndpointAuthenticationPolicy.ValidateClientForService(systemService, tray));
        Assert.Throws<UnauthorizedAccessException>(
            () => NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(tray, systemService));
    }

    [Fact]
    public void SimulatedClientPolicy_RejectsUnauthorizedOrSquattedServers()
    {
        foreach (var (client, service) in UnauthorizedServiceEndpoints())
        {
            Assert.Throws<UnauthorizedAccessException>(
                () => NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient(client, service));
        }
    }

    private static IReadOnlyList<(PipeEndpointProcessIdentity Service, PipeEndpointProcessIdentity Client)>
        UnauthorizedControlClients()
    {
        var service = Identity(
            100,
            PipeIntegrityLevels.High,
            @"D:\Package\ApfsAccess.Service.exe");
        var tray = Identity(
            200,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Tray.exe");
        return
        [
            (service, tray with { ProcessId = service.ProcessId }),
            (service, tray with { UserSid = "S-1-5-21-100-200-300-2002" }),
            (service, tray with { SessionId = SessionId + 1 }),
            (service, tray with { ImagePath = @"D:\Other\ApfsAccess.Tray.exe" }),
            (service, tray with { ImagePath = @"D:\Package\Untrusted.exe" }),
            (service, tray with { IntegrityRid = PipeIntegrityLevels.Low }),
        ];
    }

    private static IReadOnlyList<(PipeEndpointProcessIdentity Client, PipeEndpointProcessIdentity Service)>
        UnauthorizedServiceEndpoints()
    {
        var client = Identity(
            200,
            PipeIntegrityLevels.Medium,
            @"D:\Package\ApfsAccess.Tray.exe");
        var service = Identity(
            100,
            PipeIntegrityLevels.High,
            @"D:\Package\ApfsAccess.Service.exe");
        return
        [
            (client, service with { ProcessId = client.ProcessId }),
            (client, service with { UserSid = "S-1-5-21-100-200-300-2002" }),
            (client, service with { SessionId = SessionId + 1 }),
            (client, service with { ImagePath = @"D:\Other\ApfsAccess.Service.exe" }),
            (client, service with { ImagePath = @"D:\Package\Squatter.exe" }),
            (client, service with { IntegrityRid = PipeIntegrityLevels.Medium }),
            (client, service with { IntegrityRid = PipeIntegrityLevels.Low }),
        ];
    }

    private static PipeEndpointProcessIdentity Identity(
        int processId,
        int integrityRid,
        string imagePath)
        => new(processId, UserSid, SessionId, integrityRid, imagePath);
}

[CollectionDefinition("Production pipe authentication", DisableParallelization = true)]
public sealed class ProductionPipeAuthenticationCollection;
