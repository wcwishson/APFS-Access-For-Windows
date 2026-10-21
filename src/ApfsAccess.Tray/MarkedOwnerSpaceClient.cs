using System.Text;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

public sealed class MarkedOwnerSpaceClient
{
    private readonly Func<ApfsMarkedOwnerSpaceRequest, CancellationToken, Task<ApfsMarkedOwnerSpaceResult>> observe;
    public bool Available { get; }
    public MarkedOwnerSpaceClient()
    {
        var verifier = new NativeApfsImageVerifier(); Available = verifier.CurrentProfileObserverAvailable;
        observe = (request, token) => Task.Run(() => verifier.ObserveMarkedOwnerSpace(request, token), token);
    }
    internal MarkedOwnerSpaceClient(bool available, Func<ApfsMarkedOwnerSpaceRequest, CancellationToken, Task<ApfsMarkedOwnerSpaceResult>> run)
    { Available = available; observe = run; }
    public async Task<MarkedReferenceSpaceSummary> RunAsync(VerifyScope scope, string? from, Action current, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); current();
        if (!Available) throw new FileNotFoundException("The marked-owner observer is unavailable.");
        var request = new ApfsMarkedOwnerSpaceRequest(new(scope.ImagePath, scope.ContainerId, scope.VolumeUuid,
            scope.VolumeObjectId, scope.CheckpointXid, scope.StoreOffsetBytes, scope.StoreSizeBytes), from);
        NativeApfsImageVerifier.ValidateMarkedOwnerSpaceRequest(request);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token); stop.CancelAfter(TimeSpan.FromSeconds(75));
        var result = await observe(request, stop.Token).ConfigureAwait(true); stop.Token.ThrowIfCancellationRequested(); current();
        if (result.NativeExitCode != (result.Complete ? 0 : 3)) throw new InvalidDataException("Inconsistent marked-owner result.");
        if (!result.Complete) return new(false, "Marked owner accounting: Unknown\r\n" + result.Report.GetProperty("reason").GetString() + Policy);
        var r = result.Report; var marked = r.GetProperty("marked");
        var text = new StringBuilder($"Image: {scope.ImagePath}\r\n{marked.GetProperty("source").GetProperty("identity").GetString()}\r\n" +
            $"Container {scope.ContainerId}\r\nVolume {scope.VolumeUuid} / OID {scope.VolumeObjectId} / XID {scope.CheckpointXid}\r\n" +
            $"Protected checkpoint chain: {string.Join(", ", r.GetProperty("checkpointXids").EnumerateArray().Select(v => v.GetString()))}\r\n" +
            $"Catalog metadata: {r.GetProperty("catalogMetadata").GetProperty("bytes").GetString()} bytes; visible payload union: {r.GetProperty("visiblePayloadUnion").GetProperty("bytes").GetString()} bytes\r\n" +
            "Protection: explicit retained checkpoints and visible peers. Hidden-owner census: Not verified.\r\n");
        var i = 0;
        foreach (var view in r.GetProperty("views").EnumerateArray()) {
            var info = marked.GetProperty("views")[i++]; var live = info.GetProperty("current").GetBoolean();
            string Bytes(JsonElement parent, string field) => parent.GetProperty(field).GetProperty("bytes").GetString()!;
            text.Append($"\r\n{(live ? "Current" : info.GetProperty("name").GetString())} / XID {info.GetProperty("viewXid").GetString()}\r\n");
            foreach (var field in new[] { "metadata", "markedPayload" }) {
                var a = view.GetProperty(field);
                if (live && field == "metadata") {
                    text.Append($"  Complete current view metadata: {Bytes(a,"referenced")} bytes; shared with snapshots {Bytes(a,"sharedWithOtherSnapshots")} bytes; retained/peer protected {Bytes(a,"retainedOrPeerProtected")} bytes\r\n");
                    continue;
                }
                var label = field == "metadata" ? "View metadata" : "Marked-file data";
                text.Append($"  {label}: referenced {Bytes(a,"referenced")} bytes; shared with {(live ? "unmarked current owners" : "all current owners")} {Bytes(a,"sharedWithLive")} bytes; absent {Bytes(a,"absentFromLive")} bytes\r\n" +
                    $"  Shared with other snapshots {Bytes(a,"sharedWithOtherSnapshots")} bytes; unique in all-visible inventory {Bytes(a,"uniqueInVisibleInventory")} bytes\r\n" +
                    $"  Retained/peer protected {Bytes(a,"retainedOrPeerProtected")} bytes; potential release upper bound {Bytes(a,"potentialReclaimUpperBound")} bytes\r\n");
            }
            text.Append($"  Marked data shared with same-view unmarked owners: {Bytes(view,"sharedWithUnmarkedInView")} bytes\r\n");
        }
        text.Append("\r\nMetadata is the complete view footprint, not a per-marked-file charge. Upper bounds are not deletion permission or exact savings.");
        return new(true, text.ToString() + Policy);
    }
    private const string Policy = "\r\n\r\nSnapshot allocation charge: Unknown\r\nApple purgeable: Unknown\r\nReclaimable: Unknown";
}
