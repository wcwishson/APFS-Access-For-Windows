using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ApfsAccess.Ipc;

public sealed class NamedPipeMessageServer
{
    private static readonly TimeSpan ActiveClientDrainTimeout = TimeSpan.FromSeconds(2);
    private readonly string _pipeName;
    private readonly bool _requiresEndpointAuthentication;

    public NamedPipeMessageServer(string pipeName)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName)
            ? throw new ArgumentException("Pipe name cannot be null or whitespace.", nameof(pipeName))
            : pipeName;
        _requiresEndpointAuthentication = NamedPipeEndpointAuthentication.IsRequired(_pipeName);
    }

    public async Task RunAsync(Func<PipePeer, CancellationToken, Task> clientHandler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientHandler);

        var activeClients = new ConcurrentDictionary<int, Task>();
        var clientCounter = 0;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var serverStream = CreateServerStream();

                try
                {
                    await serverStream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    serverStream.Dispose();
                    throw;
                }

                if (_requiresEndpointAuthentication)
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        serverStream.Dispose();
                        throw new PlatformNotSupportedException(
                            "The production APFS Access pipe requires Windows endpoint authentication.");
                    }

                    try
                    {
                        NamedPipeEndpointAuthentication.AuthenticateClient(serverStream);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        serverStream.Dispose();
                        continue;
                    }
                }

                var clientId = Interlocked.Increment(ref clientCounter);
                var peer = new PipePeer(serverStream);
                var task = AcceptedPipeClientOwner.Start(
                    peer,
                    clientHandler,
                    cancellationToken,
                    ActiveClientDrainTimeout);

                activeClients[clientId] = task;
                _ = task.ContinueWith(
                    _ =>
                    {
                        activeClients.TryRemove(clientId, out Task? removedTask);
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default
                );
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during shutdown.
        }

        var activeClientTasks = activeClients.Values.ToArray();
        if (activeClientTasks.Length == 0)
        {
            return;
        }

        var activeClientDrain = Task.WhenAll(activeClientTasks);
        try
        {
            await activeClientDrain
                .WaitAsync(ActiveClientDrainTimeout)
                .ConfigureAwait(false);
        }
        catch (TimeoutException exception)
        {
            _ = activeClientDrain.ContinueWith(
                completed => _ = completed.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw new TimeoutException(
                $"Timed out waiting for {activeClientTasks.Length} active pipe client(s) to finish cleanup.",
                exception);
        }
    }

    private NamedPipeServerStream CreateServerStream()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new NamedPipeServerStream(
                _pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }

        // The service is commonly elevated while the tray and CLI run with a
        // standard token. The default pipe ACL follows the elevated creator
        // and can deny that same user's non-elevated client.
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddRule(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl);
        AddRule(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl);
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is not null)
        {
            security.SetOwner(identity.User);
            AddRule(security, identity.User, PipeAccessRights.FullControl);
        }

        return NamedPipeServerStreamAcl.Create(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            security,
            HandleInheritability.None,
            (PipeAccessRights)0);
    }

    [SupportedOSPlatform("windows")]
    private static void AddRule(
        PipeSecurity security,
        SecurityIdentifier identity,
        PipeAccessRights rights)
    {
        security.AddAccessRule(new PipeAccessRule(identity, rights, AccessControlType.Allow));
    }
}

internal static class AcceptedPipeClientOwner
{
    internal static Task Start(
        PipePeer peer,
        Func<PipePeer, CancellationToken, Task> clientHandler,
        CancellationToken handlerCancellationToken,
        TimeSpan cleanupTimeout,
        Func<Func<Task>, CancellationToken, Task>? taskStarter = null)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(clientHandler);
        taskStarter ??= static (work, schedulingToken) => Task.Run(work, schedulingToken);

        return taskStarter(async () =>
        {
            try
            {
                await clientHandler(peer, handlerCancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (handlerCancellationToken.IsCancellationRequested)
            {
                // Expected during shutdown.
            }
            finally
            {
                await peer.DisposeAsync(cleanupTimeout).ConfigureAwait(false);
            }
        }, CancellationToken.None);
    }
}
