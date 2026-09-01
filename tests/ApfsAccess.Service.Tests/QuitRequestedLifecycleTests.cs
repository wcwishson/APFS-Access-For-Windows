using System.IO.Pipes;
using System.Reflection;
using System.Text;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

[Collection("QuitMarkerEnvIsolation")]
public sealed class QuitRequestedLifecycleTests
{
    [Fact]
    public async Task MalformedPipeFrame_ReturnsStableErrorInsteadOfDisconnect()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = new ApfsMountWorker(
            NullLogger<ApfsMountWorker>.Instance,
            new NoopBackend(),
            new NoopMountPolicy(),
            statusPublisher,
            new FixedOptionsMonitor(new ServiceHostOptions()));
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            statusPublisher,
            worker,
            new RecordingApplicationLifetime());
        var pair = await ConnectedPipePair.CreateAsync(
            $"ApfsAccess.Malformed.{Guid.NewGuid():N}",
            cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);

        Assert.Equal(
            ApfsMessageTypes.StatusChanged,
            (await clientPeer.ReadMessageAsync(cancellation.Token))!.Type);

        await pair.Client.WriteAsync(
            Encoding.UTF8.GetBytes("{not-json}\n"),
            cancellation.Token);
        await pair.Client.FlushAsync(cancellation.Token);

        var response = await clientPeer.ReadMessageAsync(cancellation.Token);
        Assert.NotNull(response);
        Assert.Equal(ApfsMessageTypes.Ack, response!.Type);
        Assert.True(PipeMessageCodec.TryGetPayload<AckPayload>(response, out var payload));
        Assert.False(payload!.Success);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, payload.Code);

        await cancellation.CancelAsync();
        await clientPeer.DisposeAsync();
        await handler;
        await serverPeer.DisposeAsync();
    }

    [Fact]
    public async Task QuitRequested_AcknowledgesThenNotifiesAllClientsBeforeStopping()
    {
        var pipePrefix = $"ApfsAccess.Quit.{Guid.NewGuid():N}";
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var lifetime = new RecordingApplicationLifetime();
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = new ApfsMountWorker(
            NullLogger<ApfsMountWorker>.Instance,
            new NoopBackend(),
            new NoopMountPolicy(),
            statusPublisher,
            new FixedOptionsMonitor(new ServiceHostOptions()));
        await using var durableHost = DurableTrayPipeHost.Create(statusPublisher, worker, lifetime);
        var service = durableHost.Service;

        var statusPair = await ConnectedPipePair.CreateAsync($"{pipePrefix}.status", cancellation.Token);
        var controlPair = await ConnectedPipePair.CreateAsync($"{pipePrefix}.control", cancellation.Token);
        var statusServerPeer = new PipePeer(statusPair.Server);
        var controlServerPeer = new PipePeer(controlPair.Server);
        var statusClientPeer = new PipePeer(statusPair.Client);
        var controlClientPeer = new PipePeer(controlPair.Client);

        var statusHandler = InvokeHandleClient(service, statusServerPeer, cancellation.Token);
        var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

        Assert.Equal(ApfsMessageTypes.StatusChanged, (await statusClientPeer.ReadMessageAsync(cancellation.Token))!.Type);
        Assert.Equal(ApfsMessageTypes.StatusChanged, (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

        var statusMessages = new List<string>();
        var statusReadTask = Task.Run(async () =>
        {
            while (!cancellation.IsCancellationRequested)
            {
                var next = await statusClientPeer.ReadMessageAsync(cancellation.Token);
                if (next is null)
                {
                    break;
                }

                statusMessages.Add(next.Type);
                if (next.Type == ApfsMessageTypes.ServiceStopping)
                {
                    break;
                }
            }
        });

        var quit = PipeMessageCodec.Create(
            ApfsMessageTypes.QuitRequested,
            new QuitRequestedPayload("test", DateTime.UtcNow),
            requestId: "quit-1");
        await controlClientPeer.SendAsync(quit, cancellation.Token);

        var ack = await controlClientPeer.ReadMessageAsync(cancellation.Token);
        Assert.NotNull(ack);
        Assert.Equal(ApfsMessageTypes.Ack, ack!.Type);
        Assert.Equal("quit-1", ack.RequestId);
        Assert.True(PipeMessageCodec.TryGetPayload<AckPayload>(ack, out var ackPayload));
        Assert.True(ackPayload!.Success);
        Assert.Equal("Shutdown requested.", ackPayload.Message);

        var controlStopping = await controlClientPeer.ReadMessageAsync(cancellation.Token);
        Assert.Equal(ApfsMessageTypes.ServiceStopping, controlStopping!.Type);
        await statusReadTask.WaitAsync(cancellation.Token);
        Assert.Contains(ApfsMessageTypes.ServiceStopping, statusMessages);
        await lifetime.StopRequestedSignal.Task.WaitAsync(cancellation.Token);
        Assert.True(lifetime.StopRequested);

        await cancellation.CancelAsync();
        await statusClientPeer.DisposeAsync();
        await controlClientPeer.DisposeAsync();
        await Task.WhenAll(statusHandler, controlHandler);
        await statusServerPeer.DisposeAsync();
        await controlServerPeer.DisposeAsync();
    }

    [Fact]
    public async Task QuitRequested_WaitsForUnmountBeforeNotifyingServiceStopping()
    {
        var runtimeRoot = Path.Combine(
            Path.GetTempPath(),
            "ApfsAccessTests",
            "QuitRequestedLifecycle",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var previousRuntimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);

        try
        {
            var pipePrefix = $"ApfsAccess.QuitUnmountOrder.{Guid.NewGuid():N}";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var lifetime = new RecordingApplicationLifetime();
            var statusPublisher = new RuntimeStatusPublisher();
            var backend = new BlockingUnmountBackend();
            var worker = new ApfsMountWorker(
                NullLogger<ApfsMountWorker>.Instance,
                backend,
                new NoopMountPolicy(),
                statusPublisher,
                new FixedOptionsMonitor(new ServiceHostOptions()));
            await using var durableHost = DurableTrayPipeHost.Create(
                statusPublisher,
                worker,
                lifetime,
                runtimeRoot);
            var service = durableHost.Service;

            var controlPair = await ConnectedPipePair.CreateAsync(
                $"{pipePrefix}.control",
                cancellation.Token);
            var controlServerPeer = new PipePeer(controlPair.Server);
            var controlClientPeer = new PipePeer(controlPair.Client);
            var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

            var quit = PipeMessageCodec.Create(
                ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload("test", DateTime.UtcNow),
                requestId: "quit-unmount-order-1");
            await controlClientPeer.SendAsync(quit, cancellation.Token);

            var unmountObserved = await Task.WhenAny(
                backend.UnmountStarted.Task,
                Task.Delay(TimeSpan.FromSeconds(2), cancellation.Token));
            Assert.Same(backend.UnmountStarted.Task, unmountObserved);

            var firstResponseTask = controlClientPeer.ReadMessageAsync(cancellation.Token);
            var responseBeforeUnmount = await Task.WhenAny(
                firstResponseTask,
                Task.Delay(TimeSpan.FromMilliseconds(250), cancellation.Token));
            Assert.NotSame(firstResponseTask, responseBeforeUnmount);

            backend.AllowUnmount.TrySetResult();
            var ack = await firstResponseTask;
            Assert.NotNull(ack);
            Assert.Equal(ApfsMessageTypes.Ack, ack!.Type);
            Assert.True(IsSuccessAck(ack));

            var stopping = await controlClientPeer.ReadMessageAsync(cancellation.Token);
            Assert.NotNull(stopping);
            Assert.Equal(ApfsMessageTypes.ServiceStopping, stopping!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ServiceStoppingPayload>(stopping, out var stoppingPayload));
            Assert.NotNull(stoppingPayload);
            Assert.True(stoppingPayload!.CleanupCompleted);
            Assert.True(stoppingPayload.HostOwnershipReleased);
            Assert.True(stoppingPayload.PendingDurabilityCleared);
            Assert.Empty(stoppingPayload.RemainingMountPoints!);

            await lifetime.StopRequestedSignal.Task.WaitAsync(cancellation.Token);
            Assert.True(lifetime.StopRequested);

            await cancellation.CancelAsync();
            await controlClientPeer.DisposeAsync();
            await Task.WhenAll(controlHandler);
            await controlServerPeer.DisposeAsync();
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", previousRuntimeRoot);
            try
            {
                Directory.Delete(runtimeRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task QuitRequested_NonReadingPeerCannotBlockTheQuit()
    {
        var pipePrefix = $"ApfsAccess.QuitBlock.{Guid.NewGuid():N}";
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var lifetime = new RecordingApplicationLifetime();
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = new ApfsMountWorker(
            NullLogger<ApfsMountWorker>.Instance,
            new NoopBackend(),
            new NoopMountPolicy(),
            statusPublisher,
            new FixedOptionsMonitor(new ServiceHostOptions()));
        await using var durableHost = DurableTrayPipeHost.Create(statusPublisher, worker, lifetime);
        var service = durableHost.Service;

        var statusPair = await ConnectedPipePair.CreateAsync($"{pipePrefix}.status", cancellation.Token);
        var controlPair = await ConnectedPipePair.CreateAsync($"{pipePrefix}.control", cancellation.Token);
        var statusServerPeer = new PipePeer(statusPair.Server);
        var controlServerPeer = new PipePeer(controlPair.Server);
        var statusClientPeer = new PipePeer(statusPair.Client);
        var controlClientPeer = new PipePeer(controlPair.Client);

        var statusHandler = InvokeHandleClient(service, statusServerPeer, cancellation.Token);
        var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

        Assert.Equal(ApfsMessageTypes.StatusChanged, (await statusClientPeer.ReadMessageAsync(cancellation.Token))!.Type);
        Assert.Equal(ApfsMessageTypes.StatusChanged, (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

        var quit = PipeMessageCodec.Create(
            ApfsMessageTypes.QuitRequested,
            new QuitRequestedPayload("test", DateTime.UtcNow),
            requestId: "quit-block-1");
        await controlClientPeer.SendAsync(quit, cancellation.Token);

        var ack = await controlClientPeer.ReadMessageAsync(cancellation.Token);
        Assert.NotNull(ack);
        Assert.Equal(ApfsMessageTypes.Ack, ack!.Type);

        var controlStopping = await controlClientPeer.ReadMessageAsync(cancellation.Token);
        Assert.Equal(ApfsMessageTypes.ServiceStopping, controlStopping!.Type);

        await lifetime.StopRequestedSignal.Task.WaitAsync(cancellation.Token);
        Assert.True(lifetime.StopRequested);

        await cancellation.CancelAsync();
        await statusClientPeer.DisposeAsync();
        await controlClientPeer.DisposeAsync();
        await Task.WhenAll(statusHandler, controlHandler);
        await statusServerPeer.DisposeAsync();
        await controlServerPeer.DisposeAsync();
    }

    [Fact]
    public async Task QuitRequested_PersistsDurableQuitMarkerBeforeAcknowledging()
    {
        var runtimeRoot = Path.Combine(
            Path.GetTempPath(),
            "apfsaccess-quit-lifecycle-tests",
            Guid.NewGuid().ToString("N"));
        var previousRuntimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);
        try
        {
            var startedUtc = DateTime.UtcNow;
            var pipePrefix = $"ApfsAccess.QuitMarker.{Guid.NewGuid():N}";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var lifetime = new RecordingApplicationLifetime();
            var statusPublisher = new RuntimeStatusPublisher();
            var worker = new ApfsMountWorker(
                NullLogger<ApfsMountWorker>.Instance,
                new NoopBackend(),
                new NoopMountPolicy(),
                statusPublisher,
                new FixedOptionsMonitor(new ServiceHostOptions()));
            await using var durableHost = DurableTrayPipeHost.Create(
                statusPublisher,
                worker,
                lifetime,
                runtimeRoot);
            var service = durableHost.Service;

            var controlPair = await ConnectedPipePair.CreateAsync($"{pipePrefix}.control", cancellation.Token);
            var controlServerPeer = new PipePeer(controlPair.Server);
            var controlClientPeer = new PipePeer(controlPair.Client);
            var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

            var quit = PipeMessageCodec.Create(
                ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload("test", DateTime.UtcNow),
                requestId: "quit-marker-1");
            await controlClientPeer.SendAsync(quit, cancellation.Token);

            var ack = await controlClientPeer.ReadMessageAsync(cancellation.Token);
            Assert.NotNull(ack);
            Assert.Equal(ApfsMessageTypes.Ack, ack!.Type);
            Assert.True(IsSuccessAck(ack));

            var markerTimestampUtc = QuitRequestMarker.TryReadMarkerTimestampUtc();
            Assert.NotNull(markerTimestampUtc);
            Assert.True(markerTimestampUtc >= startedUtc);
            Assert.True(QuitRequestMarker.ShouldHonorMarker(markerTimestampUtc.Value, startedUtc));

            await lifetime.StopRequestedSignal.Task.WaitAsync(cancellation.Token);
            Assert.True(QuitRequestMarker.TryReadMarkerTimestampUtc() is not null);

            await cancellation.CancelAsync();
            await controlClientPeer.DisposeAsync();
            await Task.WhenAll(controlHandler);
            await controlServerPeer.DisposeAsync();
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", previousRuntimeRoot);
            try
            {
                Directory.Delete(runtimeRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task QuitRequested_DroppedConnectionBeforeAckCannotBlockTheQuit()
    {
        var runtimeRoot = Path.Combine(
            Path.GetTempPath(),
            "apfsaccess-quit-dropped-tests",
            Guid.NewGuid().ToString("N"));
        var previousRuntimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);
        try
        {
            var pipePrefix = $"ApfsAccess.QuitDropped.{Guid.NewGuid():N}";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var lifetime = new RecordingApplicationLifetime();
            var statusPublisher = new RuntimeStatusPublisher();
            var worker = new ApfsMountWorker(
                NullLogger<ApfsMountWorker>.Instance,
                new NoopBackend(),
                new NoopMountPolicy(),
                statusPublisher,
                new FixedOptionsMonitor(new ServiceHostOptions()));
            await using var durableHost = DurableTrayPipeHost.Create(
                statusPublisher,
                worker,
                lifetime,
                runtimeRoot);
            var service = durableHost.Service;

            var controlPair = await ConnectedPipePair.CreateAsync(
                $"{pipePrefix}.control",
                cancellation.Token,
                64);
            var controlServerPeer = new PipePeer(controlPair.Server);
            var controlClientPeer = new PipePeer(controlPair.Client);
            var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

            var quit = PipeMessageCodec.Create(
                ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload("test", DateTime.UtcNow),
                requestId: "quit-dropped-1");
            await controlClientPeer.SendAsync(quit, cancellation.Token);
            await controlClientPeer.DisposeAsync();

            await lifetime.StopRequestedSignal.Task.WaitAsync(TimeSpan.FromSeconds(8));
            Assert.True(lifetime.StopRequested);

            await cancellation.CancelAsync();
            await Task.WhenAll(controlHandler);
            await controlServerPeer.DisposeAsync();
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", previousRuntimeRoot);
            try
            {
                Directory.Delete(runtimeRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task QuitRequested_NonReadingQuitRequesterCannotBlockTheQuit()
    {
        var runtimeRoot = Path.Combine(
            Path.GetTempPath(),
            "apfsaccess-quit-backpressure-tests",
            Guid.NewGuid().ToString("N"));
        var previousRuntimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);
        try
        {
            var pipePrefix = $"ApfsAccess.QuitBackpressure.{Guid.NewGuid():N}";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var lifetime = new RecordingApplicationLifetime();
            var statusPublisher = new RuntimeStatusPublisher();
            var worker = new ApfsMountWorker(
                NullLogger<ApfsMountWorker>.Instance,
                new NoopBackend(),
                new NoopMountPolicy(),
                statusPublisher,
                new FixedOptionsMonitor(new ServiceHostOptions()));
            await using var durableHost = DurableTrayPipeHost.Create(
                statusPublisher,
                worker,
                lifetime,
                runtimeRoot);
            var service = durableHost.Service;

            var controlPair = await ConnectedPipePair.CreateAsync(
                $"{pipePrefix}.control",
                cancellation.Token,
                64);
            var controlServerPeer = new PipePeer(controlPair.Server);
            var controlClientPeer = new PipePeer(controlPair.Client);
            var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

            var quit = PipeMessageCodec.Create(
                ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload("test", DateTime.UtcNow),
                requestId: "quit-backpressure-1");
            await controlClientPeer.SendAsync(quit, cancellation.Token);

            await lifetime.StopRequestedSignal.Task.WaitAsync(TimeSpan.FromSeconds(8));
            Assert.True(lifetime.StopRequested);

            await cancellation.CancelAsync();
            await controlClientPeer.DisposeAsync();
            await Task.WhenAll(controlHandler);
            await controlServerPeer.DisposeAsync();
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", previousRuntimeRoot);
            try
            {
                Directory.Delete(runtimeRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task QuitRequested_UnwritableMarkerReportsFailureButStillStops()
    {
        var runtimeRoot = Path.Combine(
            Path.GetTempPath(),
            "apfsaccess-quit-marker-failure-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        File.WriteAllText(Path.Combine(runtimeRoot, "temp"), "blocking file");
        var previousRuntimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", runtimeRoot);
        try
        {
            var pipePrefix = $"ApfsAccess.QuitMarkerFail.{Guid.NewGuid():N}";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var lifetime = new RecordingApplicationLifetime();
            var statusPublisher = new RuntimeStatusPublisher();
            var worker = new ApfsMountWorker(
                NullLogger<ApfsMountWorker>.Instance,
                new NoopBackend(),
                new NoopMountPolicy(),
                statusPublisher,
                new FixedOptionsMonitor(new ServiceHostOptions()));
            await using var durableHost = DurableTrayPipeHost.Create(
                statusPublisher,
                worker,
                lifetime,
                runtimeRoot);
            var service = durableHost.Service;

            var controlPair = await ConnectedPipePair.CreateAsync($"{pipePrefix}.control", cancellation.Token);
            var controlServerPeer = new PipePeer(controlPair.Server);
            var controlClientPeer = new PipePeer(controlPair.Client);
            var controlHandler = InvokeHandleClient(service, controlServerPeer, cancellation.Token);

            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await controlClientPeer.ReadMessageAsync(cancellation.Token))!.Type);

            var quit = PipeMessageCodec.Create(
                ApfsMessageTypes.QuitRequested,
                new QuitRequestedPayload("test", DateTime.UtcNow),
                requestId: "quit-marker-fail-1");
            await controlClientPeer.SendAsync(quit, cancellation.Token);

            var ack = await controlClientPeer.ReadMessageAsync(cancellation.Token);
            Assert.NotNull(ack);
            Assert.Equal(ApfsMessageTypes.Ack, ack!.Type);
            Assert.Equal("quit-marker-fail-1", ack.RequestId);
            Assert.True(PipeMessageCodec.TryGetPayload<AckPayload>(ack, out var ackPayload));
            Assert.False(ackPayload!.Success, "An unwritable quit marker must never be acknowledged as success.");
            Assert.Contains("marker", ackPayload.Message ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            Assert.Null(QuitRequestMarker.TryReadMarkerTimestampUtc());

            await lifetime.StopRequestedSignal.Task.WaitAsync(cancellation.Token);
            Assert.True(lifetime.StopRequested);

            await cancellation.CancelAsync();
            await controlClientPeer.DisposeAsync();
            await Task.WhenAll(controlHandler);
            await controlServerPeer.DisposeAsync();
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT", previousRuntimeRoot);
            try
            {
                Directory.Delete(runtimeRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    private static bool IsSuccessAck(PipeEnvelope ack)
        => PipeMessageCodec.TryGetPayload<AckPayload>(ack, out var ackPayload) &&
           ackPayload is { Success: true };

    private static Task InvokeHandleClient(
        TrayPipeHostService service,
        PipePeer peer,
        CancellationToken cancellationToken)
    {
        var method = typeof(TrayPipeHostService).GetMethod(
            "HandleClientAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<Task>(method!.Invoke(service, [peer, cancellationToken]));
    }

    private sealed class DurableTrayPipeHost : IAsyncDisposable
    {
        private readonly AgentControlOperationService _operationService;
        private readonly string _runtimeRoot;
        private readonly bool _ownsRuntimeRoot;

        private DurableTrayPipeHost(
            RuntimeStatusPublisher statusPublisher,
            ApfsMountWorker worker,
            IHostApplicationLifetime lifetime,
            string runtimeRoot,
            bool ownsRuntimeRoot)
        {
            _runtimeRoot = runtimeRoot;
            _ownsRuntimeRoot = ownsRuntimeRoot;
            var markerPath = Path.Combine(runtimeRoot, "temp", "ApfsAccess", "quit-requested");
            var executor = new AgentControlCommandExecutor(
                worker,
                timestampUtc => QuitRequestMarker.WriteMarker(timestampUtc, markerPath));
            _operationService = new AgentControlOperationService(
                executor.ExecuteAsync,
                Path.Combine(runtimeRoot, "agent-operations"));
            Service = new TrayPipeHostService(
                NullLogger<TrayPipeHostService>.Instance,
                statusPublisher,
                worker,
                lifetime,
                _operationService);
        }

        internal TrayPipeHostService Service { get; }

        internal static DurableTrayPipeHost Create(
            RuntimeStatusPublisher statusPublisher,
            ApfsMountWorker worker,
            IHostApplicationLifetime lifetime,
            string? runtimeRoot = null)
        {
            var ownsRuntimeRoot = string.IsNullOrWhiteSpace(runtimeRoot);
            runtimeRoot ??= Path.Combine(
                Path.GetTempPath(),
                "apfsaccess-quit-lifecycle-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(runtimeRoot);
            return new DurableTrayPipeHost(
                statusPublisher,
                worker,
                lifetime,
                runtimeRoot,
                ownsRuntimeRoot);
        }

        public async ValueTask DisposeAsync()
        {
            await _operationService.StopAsync(CancellationToken.None);
            if (!_ownsRuntimeRoot)
            {
                return;
            }

            try
            {
                Directory.Delete(_runtimeRoot, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private sealed class ConnectedPipePair : IAsyncDisposable
    {
        private ConnectedPipePair(NamedPipeServerStream server, NamedPipeClientStream client)
        {
            Server = server;
            Client = client;
        }

        public NamedPipeServerStream Server { get; }

        public NamedPipeClientStream Client { get; }

        public static async Task<ConnectedPipePair> CreateAsync(
            string pipeName,
            CancellationToken cancellationToken,
            int outBufferSize = 0)
        {
            var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                4096,
                outBufferSize);
            var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);
            try
            {
                var connectTask = client.ConnectAsync(2000, cancellationToken);
                await server.WaitForConnectionAsync(cancellationToken);
                await connectTask;
                return new ConnectedPipePair(server, client);
            }
            catch
            {
                await client.DisposeAsync();
                await server.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await Server.DisposeAsync();
        }
    }

    private sealed class RecordingApplicationLifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public bool StopRequested { get; private set; }

        public TaskCompletionSource StopRequestedSignal { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void StopApplication()
        {
            StopRequested = true;
            StopRequestedSignal.TrySetResult();
        }
    }

    private sealed class NoopBackend : IApfsBackend
    {
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>(Array.Empty<DeviceInfo>());

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Array.Empty<MountedVolumeState>());
    }

    private sealed class BlockingUnmountBackend : IApfsBackend
    {
        private int _mounted = 1;

        public TaskCompletionSource UnmountStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource AllowUnmount { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>(Array.Empty<DeviceInfo>());

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public async Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
        {
            UnmountStarted.TrySetResult();
            await AllowUnmount.Task.WaitAsync(cancellationToken);
            Interlocked.Exchange(ref _mounted, 0);
            return new UnmountResult(
                Success: true,
                MountPoint: mountPoint,
                Error: null,
                MountRemoved: true,
                HostOwnershipReleased: true,
                PendingDurabilityCleared: true);
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<MountedVolumeState> mounts = Volatile.Read(ref _mounted) == 0
                ? Array.Empty<MountedVolumeState>()
                :
                [new MountedVolumeState(
                    VolumeId: "device|volume",
                    MountPoint: @"E:\",
                    AccessMode: MountAccessMode.ReadWrite,
                    VolumeName: "Test volume")];
            return Task.FromResult(mounts);
        }
    }

    private sealed class NoopMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters) => 'Z';

        public bool ShouldAutoMount(VolumeInfo volume) => false;
    }

    private sealed class FixedOptionsMonitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;

        public ServiceHostOptions Get(string? name) => options;

        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
}
