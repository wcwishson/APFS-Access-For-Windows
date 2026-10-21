using System.Globalization;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

public sealed record MarkedReferenceSpaceSummary(bool Complete, string Details);

public sealed class MarkedReferenceSpaceClient
{
    private readonly Func<ApfsSnapshotAttributionRequest, CancellationToken, Task<ApfsMarkedReferenceSpaceResult>> observe;
    public bool Available { get; }

    public MarkedReferenceSpaceClient()
    {
        var verifier = new NativeApfsImageVerifier();
        Available = verifier.CurrentProfileObserverAvailable;
        observe = (request, token) => Task.Run(() => verifier.ObserveMarkedReferenceSpace(request, token), token);
    }

    internal MarkedReferenceSpaceClient(bool available,
        Func<ApfsSnapshotAttributionRequest, CancellationToken, Task<ApfsMarkedReferenceSpaceResult>> observation)
    { Available = available; observe = observation; }

    public async Task<MarkedReferenceSpaceSummary> RunAsync(VerifyScope scope, Action requireCurrent, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); requireCurrent();
        if (!Available) throw new FileNotFoundException("The packaged marked-file observer is unavailable.");
        var request = new ApfsSnapshotAttributionRequest(scope.ImagePath, scope.ContainerId, scope.VolumeUuid,
            scope.VolumeObjectId, scope.CheckpointXid, scope.StoreOffsetBytes, scope.StoreSizeBytes);
        NativeApfsImageVerifier.ValidateSnapshotAttributionRequest(request);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var result = await observe(request, deadline.Token).ConfigureAwait(true);
        deadline.Token.ThrowIfCancellationRequested(); requireCurrent(); token.ThrowIfCancellationRequested();
        if (result.NativeExitCode != (result.Complete ? 0 : 3) || result.Complete != (result.PhysicalViews.Count > 0))
            throw new InvalidDataException("Marked-file observation has an inconsistent terminal result.");
        if (!result.Complete)
            return new(false, "Marked-file space: Unknown\r\n" + result.Report.GetProperty("reason").GetString() + Policy);
        var root = result.Report;
        var text = $"Marked-file physical payload: {root.GetProperty("filePayloadUnion").GetProperty("bytes").GetString()} bytes\r\n" +
            $"Literal private-stream records: {root.GetProperty("literalRecordUnion").GetProperty("bytes").GetString()} bytes\r\n" +
            "File payload includes owned external attributes. Physical overlap is counted once.\r\n" +
            "Scope: current and visible marked-file inventories; no hidden-owner or retained-checkpoint census.\r\n" +
            $"Image: {scope.ImagePath}\r\n{root.GetProperty("source").GetProperty("identity").GetString()}\r\n" +
            $"Container {scope.ContainerId}\r\nVolume {scope.VolumeUuid} / OID {scope.VolumeObjectId} / XID {scope.CheckpointXid}\r\n";
        foreach (var view in result.PhysicalViews)
        {
            string Bytes(ulong value) => value.ToString(CultureInfo.InvariantCulture);
            text += $"\r\n{(view.Current ? "Current" : view.Name)} / XID {view.Xid}\r\n" +
                $"  IS_PURGEABLE files: {view.MarkedRegularInodes}; WANT-only files: {view.WantOnlyRegularInodes}\r\n" +
                $"  File payload: {Bytes(view.FilePayloadBytes)} bytes; literal records: {Bytes(view.LiteralRecordBytes)} bytes\r\n";
            if (!view.Current) text += $"  Shared with current marked files: {Bytes(view.SharedWithCurrentBytes)} bytes; absent from current marked files: {Bytes(view.AbsentFromCurrentBytes)} bytes\r\n";
            text += $"  Shared with {(view.Current ? "snapshots" : "other snapshots")}: {Bytes(view.SharedWithOtherSnapshotsBytes)} bytes\r\n" +
                $"  Unique within visible marked-file inventory: {Bytes(view.UniqueInMarkedInventoryBytes)} bytes\r\n";
        }
        return new(true, text + "\r\nUnmarked files, peers and historical owners may share these blocks. Unique marked bytes are not deletion savings." + Policy);
    }

    private const string Policy = "\r\n\r\nSnapshot allocation charge: Unknown\r\nApple purgeable: Unknown\r\nReclaimable: Unknown";
}
