using System.Diagnostics;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeImageKeyManagementBackend
{
    public async Task<ImageKeyManagementReceipt> ObserveImageKeysAsync(ImageKeyManagementRequest request,
        CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows() || !request.IsValid() || request.Action != ImageKeyManagementAction.Observe)
            throw new ArgumentException("An exact image observation request is required.");
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
            cancellation.ThrowIfCancellationRequested();
            reservation.Child = HostProcessGuardian.Start(info, startup);
            if (reservation.Child.Guardian is null) throw new IOException("Exact native process ownership is required.");
            using var cancel = cancellation.Register(() => reservation.Lifetime.Dispose());
            if (!await reservation.WaitRetiredAsync(TimeSpan.FromMinutes(5), cancellation).ConfigureAwait(false))
                throw new IOException("Image observation owner retirement remains pending.");
            reservation.Launch.RequireUnchanged();
            var receipt = reservation.ReadObservation(request);
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

    private sealed partial class Reservation
    {
        internal ImageKeyManagementReceipt ReadObservation(ImageKeyManagementRequest request)
        {
            var guardian = Child?.Guardian ?? throw new IOException("Native owner identity is unavailable.");
            if (exitCode != 0) throw ObservationFailure(request, guardian);
            using var file = Launch!.OpenReceipt();
            if (file.Length is <= 0 or > 16384) throw new IOException("Image observation receipt is incomplete.");
            var envelope = JsonSerializer.Deserialize<ObservationEnvelope>(file, json);
            if (envelope is null || envelope.SchemaVersion != 1 || envelope.HostPid != guardian.ProcessId ||
                envelope.HostCreationTimeFileTimeUtc != guardian.CreationTimeFileTimeUtc ||
                envelope.ObservationId != request.OperationId || envelope.Endpoint is null)
                throw new IOException("Image observation differs from its exact native owner.");
            var receipt = new ImageKeyManagementReceipt(request.OperationId, ImageKeyManagementAction.Observe,
                request.Expected, envelope.Endpoint, envelope.AcceptedSequence, envelope.DurableSequence,
                envelope.CleanedSequence, true, envelope.OwnerClosed);
            if (!receipt.Proves(request)) throw new IOException("Image observation lacks a clean current endpoint.");
            Launch.RequireUnchanged(); return receipt;
        }
    }

    private sealed record ObservationEnvelope(int SchemaVersion, uint HostPid, long HostCreationTimeFileTimeUtc,
        string ObservationId, ImageKeyManagementEndpoint Endpoint, ulong AcceptedSequence,
        ulong DurableSequence, ulong CleanedSequence, bool OwnerClosed);
}
