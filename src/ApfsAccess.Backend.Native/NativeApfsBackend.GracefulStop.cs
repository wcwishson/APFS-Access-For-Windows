using System.Diagnostics;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public interface IGracefulShutdownBackend
{
    // Cancellation bounds acquisition; once signaled, the exact owner retains its drain.
    Task<UnmountResult> UnmountForShutdownAsync(string mountPoint, CancellationToken cancellationToken);
}

public sealed partial class NativeApfsBackend : IGracefulShutdownBackend
{
    public Task<UnmountResult> UnmountForShutdownAsync(string mountPoint, CancellationToken cancellationToken)
        => UnmountAsync(mountPoint, cancellationToken);

    private Task<HostStopResult> StopMountedHostProcessAsync(HostProcessState host, CancellationToken cancellationToken)
    {
        // Set before signaling: observers and disposal share this exact owner's decision.
        Volatile.Write(ref host.GracefulStopRequested, 1);
        return StopHostProcessAsync(host, cancellationToken);
    }

    private async Task<HostStopResult> WaitForGracefulHostStopAsync(HostProcessState host)
    {
        TrySignalHostStop(host);
        var observationWindow = GetLifecycleShutdownTimeout();
        var observation = Stopwatch.StartNew();
        while (!TryProveProcessExited(host, out _) || !IsHostGuardianSettled(host))
        {
            if (observation.Elapsed >= observationWindow)
            {
                WriteLifecycleDiagnostic("host-graceful-drain-pending", host.TrackedMountPoint, host,
                    "The graceful observation window elapsed; the original owner and pending durability remain retained. No forced stop was requested.");
                observation.Restart();
            }
            // Native may hold its metadata lock during a long commit, so neither a
            // stale status nor an unchanged watermark can prove a dead process.
            await Task.Delay(100).ConfigureAwait(false);
        }
        // The exit observer can remove the terminal sidecar during resource cleanup.
        lock (_disposeFinalizationSync) return CaptureHostStopResult(host);
    }
}
