using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

// One keeper spans credential handoff, graceful cancellation and exact child
// retirement. An unretired child keeps its source registration reserved.
public sealed partial class NativeImageKeyManagementBackend : IImageKeyManagementBackend, IImageKeyManagementObserver
{
    private static readonly ConcurrentDictionary<string, Reservation> active = new(StringComparer.Ordinal);
    private static readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() }
    };
    private readonly string toolPath, recoveryRoot, operationRoot;
    public NativeImageKeyManagementBackend(string toolPath, string recoveryRoot, string operationRoot)
    {
        this.toolPath = NativeSnapshotBrowseLaunch.ValidateLocalPath(toolPath);
        this.recoveryRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(recoveryRoot);
        this.operationRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(operationRoot);
    }

    public async Task<ImageKeyManagementReceipt> ManageImageKeysAsync(ImageKeyManagementRequest request,
        SupervisedCredentialSet credentials, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        using (credentials)
        {
            if (!OperatingSystem.IsWindows() || !request.IsValid() || request.Action == ImageKeyManagementAction.Observe ||
                credentials.Count != request.CredentialCount)
                throw new ArgumentException("An exact image request and credential exchange are required.");
            var reservation = new Reservation(request.Expected.SourceId);
            if (!active.TryAdd(reservation.Identity, reservation)) throw new IOException("This image still has an owned key-management operation.");
            try
            {
                reservation.Launch = NativeImageKeyManagementLaunch.Prepare(request, recoveryRoot, operationRoot, cancellation);
                reservation.Executable = reservation.Launch.PinExecutable(toolPath, cancellation);
                using var startup = HostStartupGate.Create(reservation.Launch.OperationDirectory);
                reservation.Lifetime = HostLifetimeSentinel.Create(Path.Combine(reservation.Launch.OperationDirectory, "lifetime"));
                var info = new ProcessStartInfo(toolPath) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = reservation.Launch.OperationDirectory };
                foreach (var argument in reservation.Launch.Arguments(reservation.Lifetime.FilePath, startup)) info.ArgumentList.Add(argument);
                cancellation.ThrowIfCancellationRequested(); credentials.CreateChildPipe();
                reservation.Child = HostProcessGuardian.StartWithCredential(info, startup, credentials.Reader);
                if (reservation.Child.Guardian is null) throw new IOException("Exact native process ownership is required.");
                using var cancel = cancellation.Register(() => reservation.Lifetime.Dispose());
                using var exchange = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                exchange.CancelAfter(TimeSpan.FromSeconds(10));
                credentials.ReleaseLocalReader();
                await Task.Run(() => credentials.Send(exchange.Token, () =>
                {
                    reservation.Launch.RequireUnchanged();
                    if (reservation.Child.Guardian.TryObserveProcessExit(out _)) throw new IOException("Native credential admission ended.");
                }), CancellationToken.None).ConfigureAwait(false);
                if (!await reservation.WaitRetiredAsync(TimeSpan.FromMinutes(5), cancellation).ConfigureAwait(false))
                    throw new IOException("Key-management owner retirement remains pending.");
                reservation.Launch.RequireUnchanged();
                var receipt = reservation.ReadReceipt(request);
                await reservation.ReleaseAsync().ConfigureAwait(false);
                return receipt;
            }
            catch
            {
                reservation.Lifetime?.Dispose();
                if (reservation.Child is null || await reservation.WaitRetiredAsync(TimeSpan.FromSeconds(30), CancellationToken.None).ConfigureAwait(false))
                    await reservation.ReleaseAsync().ConfigureAwait(false);
                else reservation.KeepUntilRetired();
                throw;
            }
        }
    }

    private sealed partial class Reservation(string identity)
    {
        internal readonly string Identity = identity;
        internal NativeImageKeyManagementLaunch? Launch;
        internal SafeFileHandle? Executable;
        internal HostLifetimeSentinel? Lifetime;
        internal HostProcessGuardian.LaunchResult? Child;
        private int? exitCode;

        internal async Task<bool> WaitRetiredAsync(TimeSpan timeout, CancellationToken cancellation)
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < timeout)
            {
                if (cancellation.IsCancellationRequested) Lifetime?.Dispose();
                var guardian = Child?.Guardian;
                if (guardian is not null && guardian.TryObserveProcessExit(out var result) &&
                    guardian.TryGetActiveProcessCount(out var count) && count == 0)
                { exitCode = result; return true; }
                await Task.Delay(25, CancellationToken.None).ConfigureAwait(false);
            }
            return false;
        }

        internal ImageKeyManagementReceipt ReadReceipt(ImageKeyManagementRequest request)
        {
            var guardian = Child?.Guardian ?? throw new IOException("Native owner identity is unavailable.");
            if (exitCode != 0)
            {
                var failure = new IOException("Native key management did not finish. Refresh the image endpoint before retrying.");
                failure.Data["NativeExitCode"] = exitCode; throw failure;
            }
            using var file = Launch!.OpenReceipt();
            if (file.Length is <= 0 or > 16384) throw new IOException("Key-management receipt is incomplete.");
            var envelope = JsonSerializer.Deserialize<Envelope>(file, json);
            if (envelope is null || envelope.SchemaVersion != 1 || envelope.HostPid != guardian.ProcessId ||
                envelope.HostCreationTimeFileTimeUtc != guardian.CreationTimeFileTimeUtc ||
                envelope.Receipt is null || !envelope.Receipt.Proves(request))
                throw new IOException("Key-management receipt does not match this exact native owner and image request.");
            Launch.RequireUnchanged(); return envelope.Receipt;
        }

        internal void KeepUntilRetired()
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!await WaitRetiredAsync(TimeSpan.FromSeconds(30), CancellationToken.None).ConfigureAwait(false)) { }
                    await ReleaseAsync().ConfigureAwait(false);
                }
                catch { /* Keep this reservation and all original recovery storage. */ }
            });
        }

        internal async Task ReleaseAsync()
        {
            Lifetime?.Dispose();
            if (Child?.Guardian is { } guardian)
            {
                guardian.Dispose();
                await guardian.OwnershipReleased.ConfigureAwait(false);
            }
            Child?.StartupStderr?.Dispose(); Child?.Process.Dispose(); Executable?.Dispose(); Launch?.Dispose();
            active.TryRemove(new KeyValuePair<string, Reservation>(Identity, this));
        }
    }
    private sealed record Envelope(int SchemaVersion, uint HostPid, long HostCreationTimeFileTimeUtc, ImageKeyManagementReceipt Receipt);
}
