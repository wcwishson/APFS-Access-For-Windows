using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

public sealed record ProfileVerificationSelection(ApfsCurrentProfileVerificationRequest Request)
{
    internal EncryptedImageProfile? WritableRegistration {get;private init;}
    internal FusionImageProfile? FusionRegistration {get;private init;}
    internal static ApfsCurrentProfileVerificationRequest RegisteredRequest(EncryptedImageProfile profile) =>
        new("encrypted-onekey-generation-zero",profile.ImagePath,
            "apfs-container:"+Guid.Parse(profile.ContainerUuid).ToString("N"),Guid.Parse(profile.VolumeUuid).ToString("N"),
            profile.VolumeObjectId.ToString(CultureInfo.InvariantCulture),profile.CheckpointXid.ToString(CultureInfo.InvariantCulture),
            profile.StoreOffset.ToString(CultureInfo.InvariantCulture),profile.StoreSize.ToString(CultureInfo.InvariantCulture));

    public static ProfileVerificationSelection Registered(EncryptedImageProfile profile)
    {
        if(!profile.IsValid())throw new InvalidDataException("The registered encrypted selectors are unavailable.");
        var request=RegisteredRequest(profile);
        if(profile.Writable)return new(request){WritableRegistration=profile};
        var suffix=FormattableString.Invariant($":scope:{profile.StoreOffset}:{profile.StoreSize}");
        request=request with {ExpectedMainIdentity=profile.SourceId[..^suffix.Length]};
        return new(NativeApfsImageVerifier.CaptureCurrentProfileBindings(request));
    }

    public static ProfileVerificationSelection Registered(FusionImageProfile profile)
    {
        using var held=HoldRegisteredFusion(profile);
        var main=profile.Members.Single(m=>m.Role=="main");
        var tier=profile.Members.Single(m=>m.Role=="tier2");
        var request=new ApfsCurrentProfileVerificationRequest("fusion-clean-cache",main.Path,
            "apfs-container:"+profile.ContainerUuid,profile.VolumeUuid,
            profile.VolumeOid.ToString(CultureInfo.InvariantCulture),profile.CheckpointXid.ToString(CultureInfo.InvariantCulture),
            main.StoreOffset.ToString(CultureInfo.InvariantCulture),main.StoreSize.ToString(CultureInfo.InvariantCulture),tier.Path,
            tier.StoreOffset.ToString(CultureInfo.InvariantCulture),tier.StoreSize.ToString(CultureInfo.InvariantCulture),
            profile.FusionUuid,"linux-apfs-last-byte-low-bit");
        return new(NativeApfsImageVerifier.CaptureCurrentProfileBindings(request)){FusionRegistration=profile.Snapshot()};
    }

    internal static NativeFusionImageLaunch HoldRegisteredFusion(FusionImageProfile profile,CancellationToken token=default)
    {
        if(!profile.IsValid() || profile.Members.Any(m=>m.Identity is null))
            throw new InvalidDataException("The registered Fusion pair identities are unavailable.");
        var held=NativeFusionImageLaunch.Prepare(new(profile.ContainerUuid,profile.FusionUuid,profile.VolumeUuid,
            profile.VolumeOid,profile.CheckpointXid,profile.Members.Select(m=>
                new FusionImageMemberSelection(m.Path,m.Role,m.StoreId,m.StoreOffset,m.StoreSize)).ToArray()),token);
        try
        {
            foreach(var member in held.Members)
                if(member.Identity!=profile.Members.Single(m=>m.Role==member.Selection.Role).Identity)
                    throw new InvalidDataException("A registered Fusion member changed. Register the current pair before verification.");
            return held;
        }
        catch{held.Dispose();throw;}
    }

    public void RequireCurrentSources()
    {
        if(FusionRegistration is { } profile)
        {using var held=HoldRegisteredFusion(profile);}
        if(Request.ExpectedMainIdentity is null || Request.Profile=="fusion-clean-cache" && Request.ExpectedTier2Identity is null)
            throw new InvalidDataException("The exact profile source identities are unavailable.");
        _=NativeApfsImageVerifier.CaptureCurrentProfileBindings(Request);
    }

    public static ProfileVerificationSelection ReadFusion(Stream stream)
    {
        var bytes=new byte[16385];var count=0;
        while(count<bytes.Length){var n=stream.Read(bytes,count,bytes.Length-count);if(n==0)break;count+=n;}
        if(count is < 2 or >16384)throw new InvalidDataException("Profile selector exceeds its size bound.");
        try
        {
            using var doc=JsonDocument.Parse(bytes.AsMemory(0,count));var root=doc.RootElement;
            var names=root.EnumerateObject().Select(p=>p.Name).ToArray();
            if(names.Length!=3 || !names.ToHashSet(StringComparer.Ordinal).SetEquals(["format","version","request"]) ||
                root.GetProperty("format").GetString()!="apfs-access-current-profile-selection" || root.GetProperty("version").GetInt32()!=1)
                throw new InvalidDataException("Unsupported profile selector.");
            var value=root.GetProperty("request");var fields=value.EnumerateObject().Select(p=>p.Name).ToArray();
            if(fields.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=fields.Length)throw new InvalidDataException("Duplicate profile selector.");
            var request=value.Deserialize<ApfsCurrentProfileVerificationRequest>(new JsonSerializerOptions{
                PropertyNamingPolicy=JsonNamingPolicy.CamelCase,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow});
            if(request is null || request.Profile!="fusion-clean-cache" || request.RequireWholeVolume || request.RequirePayloadContentHashes ||
                request.AccountRetainedOwnership || request.RetainedFromXid is not null)
                throw new InvalidDataException("Select the supported current Fusion image profile.");
            return new(NativeApfsImageVerifier.CaptureCurrentProfileBindings(request));
        }
        catch(Exception ex)when(ex is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        {throw new InvalidDataException("Invalid exact profile selectors.",ex);}
    }
}

public sealed record ProfileVerificationDisplay(ApfsVerificationOutcome Outcome,JsonElement Report)
{
    public string Scope
    {
        get
        {
            var r=Report;var scope=r.GetProperty("requestedScope");
            var members=string.Join("\r\n",r.GetProperty("source").GetProperty("stores").EnumerateArray().Select(s=>
                $"{s.GetProperty("role").GetString()}: {s.GetProperty("label").GetString()}\r\n  {s.GetProperty("id").GetString()}\r\n  Offset {s.GetProperty("offsetBytes").GetString()}, size {s.GetProperty("sizeBytes").GetString()} bytes"));
            if(r.GetProperty("format").GetString()=="apfs-access-visible-snapshot-profile-verification")
                return VisibleSnapshotScope(r,scope,members);
            var retained=r.GetProperty("format").GetString()=="apfs-access-retained-profile-verification";
            var counts=r.GetProperty(retained?"history":"counts");
            var observed=retained?(counts.ValueKind==JsonValueKind.Null?"Requested retained chain: Unavailable":
                $"From XID: {r.GetProperty("fromXid").GetString()}\r\nCheckpoint chain: {string.Join(", ",counts.GetProperty("chainXids").EnumerateArray().Select(x=>x.GetString()))}\r\n"+
                $"Canonical historical namespaces: Verified\r\nAllocation unit: {counts.GetProperty("allocationUnitBytes").GetInt32()} bytes\r\nSnapshot owner scope: {counts.GetProperty("snapshotOwnerScope").GetString()}"):
                counts.ValueKind==JsonValueKind.Null?"Current graph counts: Unavailable":
                $"Covered volumes: {counts.GetProperty("volumeCount").GetString()}\r\nFilesystem records: {counts.GetProperty("filesystemRecords").GetString()}\r\n"+
                $"Physical extent records: {counts.GetProperty("physicalExtentRecords").GetString()}\r\nCurrent metadata dependency blocks: {counts.GetProperty("metadataDependencyBlocks").GetString()}\r\n"+
                $"Metadata count scope: {counts.GetProperty("metadataCountScope").GetString()}\r\nAllocation unit: {counts.GetProperty("allocationUnitBytes").GetInt32()} bytes";
            return $"{r.GetProperty("profile").GetString()}\r\nContainer {scope.GetProperty("containerUuid").GetString()}\r\n"+
                $"Volume {scope.GetProperty("volumeUuid").GetString()} / OID {scope.GetProperty("volumeOid").GetString()} / XID {scope.GetProperty("checkpointXid").GetString()}\r\n"+
                r.GetProperty("source").GetProperty("coordinateSystem").GetString()+"\r\n"+members+"\r\n\r\n"+observed+
                "\r\nWhole volume: Not verified\r\nRetained ownership: Not verified\r\nPayload content hashes: Not verified";
        }
    }
    private static string VisibleSnapshotScope(JsonElement r,JsonElement scope,string members)
    {
        var graph=r.GetProperty("graph");var attribution=r.GetProperty("attribution");
        var text=$"{r.GetProperty("profile").GetString()}\r\nContainer {scope.GetProperty("containerUuid").GetString()}\r\n"+
            $"Volume {scope.GetProperty("volumeUuid").GetString()} / OID {scope.GetProperty("volumeOid").GetString()} / XID {scope.GetProperty("checkpointXid").GetString()}\r\n"+
            r.GetProperty("source").GetProperty("coordinateSystem").GetString()+"\r\n"+members+"\r\n\r\n";
        if(graph.ValueKind==JsonValueKind.Null)return text+"Visible snapshot graph: Unavailable";
        text+=$"Checkpoint chain: {string.Join(", ",graph.GetProperty("chainXids").EnumerateArray().Select(x=>x.GetString()))}\r\n"+
            "Visible snapshot namespaces: Verified\r\nProtection scope: Explicit parents and visible peers\r\n"+
            "Hidden owners: Not verified\r\nWhole volume: Not verified\r\nPayload content hashes: Not verified\r\n";
        foreach(var row in attribution.GetProperty("snapshots").EnumerateArray())
        {
            text+=$"\r\nSnapshot {row.GetProperty("name").GetString()} / XID {row.GetProperty("snapshotXid").GetString()}\r\n";
            foreach(var field in new[]{"metadata","payload"})
            {
                var a=row.GetProperty(field);
                string Bytes(string key)=>a.GetProperty(key).GetProperty("bytes").GetString()!;
                text+=$"  {field}: referenced {Bytes("referenced")}; shared with live {Bytes("sharedWithLive")}; absent from live {Bytes("absentFromLive")} bytes\r\n"+
                    $"  Shared with other snapshots {Bytes("sharedWithOtherSnapshots")}; unique in visible inventory {Bytes("uniqueInVisibleInventory")} bytes\r\n"+
                    $"  Protected by parents/peers {Bytes("retainedOrPeerProtected")}; potential release upper bound {Bytes("potentialReclaimUpperBound")} bytes\r\n";
            }
            text+=$"  Saved filesystem allocation counter: {row.GetProperty("declaredFilesystemAllocation").GetProperty("bytes").GetString()} bytes at descriptor XID\r\n";
        }
        return text;
    }
    public string Policy => "Snapshot allocation charge: Unknown\r\nApple purgeable: Unknown\r\nReclaimable: Unknown";
}

public sealed class ProfileVerificationClient
{
    private readonly Func<ApfsCurrentProfileVerificationRequest,SupervisedCredential?,CancellationToken,Task<ApfsCurrentProfileVerificationResult>> run;
    private readonly Func<ApfsRetainedProfileVerificationRequest,SupervisedCredential?,CancellationToken,Task<ApfsRetainedProfileVerificationResult>> runHistory;
    private readonly Func<ApfsVisibleSnapshotProfileRequest,SupervisedCredential?,CancellationToken,Task<ApfsVisibleSnapshotProfileResult>> runSnapshots;
    public bool Available {get;}
    public ProfileVerificationClient()
    {
        var verifier=new NativeApfsImageVerifier();Available=verifier.CurrentProfileObserverAvailable;
        run=(request,credential,token)=>Task.Run(()=>verifier.VerifyCurrentProfile(request,credential,token),token);
        runHistory=(request,credential,token)=>Task.Run(()=>verifier.VerifyRetainedProfile(request,credential,token),token);
        runSnapshots=(request,credential,token)=>Task.Run(()=>verifier.VerifyVisibleSnapshotProfile(request,credential,token),token);
    }
    internal ProfileVerificationClient(bool available,Func<ApfsCurrentProfileVerificationRequest,SupervisedCredential?,CancellationToken,Task<ApfsCurrentProfileVerificationResult>> verify,
        Func<ApfsRetainedProfileVerificationRequest,SupervisedCredential?,CancellationToken,Task<ApfsRetainedProfileVerificationResult>>? historyVerify=null,
        Func<ApfsVisibleSnapshotProfileRequest,SupervisedCredential?,CancellationToken,Task<ApfsVisibleSnapshotProfileResult>>? snapshotVerify=null)
    {Available=available;run=verify;runHistory=historyVerify??((_,_,_)=>throw new NotSupportedException("Retained profile verification is unavailable."));
        runSnapshots=snapshotVerify??((_,_,_)=>throw new NotSupportedException("Visible snapshot verification is unavailable."));}

    private sealed class BoundSelection : IDisposable
    {
        private NativeEncryptedImageWriteLaunch? registration;
        private NativeFusionImageLaunch? fusionRegistration;
        private IDisposable? sources;
        public ApfsCurrentProfileVerificationRequest Request {get;}
        public BoundSelection(ProfileVerificationSelection selected,SupervisedCredential? credential,CancellationToken token)
        {
            try
            {
                var request=selected.Request;
                if((request.Profile=="fusion-clean-cache")== (credential is not null))throw new ArgumentException("Only encrypted image verification requires a credential.");
                var writable=selected.WritableRegistration;
                if(writable is not null && request!=ProfileVerificationSelection.RegisteredRequest(writable))
                    throw new InvalidDataException("The registered writable image selection changed.");
                registration=writable is null?null:NativeEncryptedImageWriteLaunch.Prepare(writable,token);
                if(selected.FusionRegistration is { } fusion)
                {
                    fusionRegistration=ProfileVerificationSelection.HoldRegisteredFusion(fusion,token);
                    if(ProfileVerificationSelection.Registered(fusion).Request!=request)
                        throw new InvalidDataException("The registered Fusion profile selection changed.");
                }
                if(registration is not null)
                    request=NativeApfsImageVerifier.CaptureCurrentProfileBindings(request with {ExpectedMainIdentity=registration.CaptureReadOnlyVerificationIdentity()});
                if(request.ExpectedMainIdentity is null || (request.Profile=="fusion-clean-cache" && request.ExpectedTier2Identity is null))
                    throw new InvalidDataException("Current profile member identities are missing.");
                sources=NativeApfsImageVerifier.HoldCurrentProfileSources(request);Request=request;
            }
            catch{Dispose();throw;}
        }
        public void RequireUnchanged()=>registration?.RequireUnchanged();
        public void Dispose(){sources?.Dispose();sources=null;fusionRegistration?.Dispose();fusionRegistration=null;registration?.Dispose();registration=null;}
    }
    public async Task<ProfileVerificationDisplay> RunAsync(ProfileVerificationSelection selected,SupervisedCredential? credential,
        Action requireCurrent,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();requireCurrent();
        if(!Available)throw new FileNotFoundException("The packaged current-profile observer is unavailable.");
        using var held=new BoundSelection(selected,credential,token);var request=held.Request;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var result=await run(request,credential,deadline.Token).ConfigureAwait(true);
        deadline.Token.ThrowIfCancellationRequested();
        var checkedResult=NativeApfsImageVerifier.ValidateCurrentProfileReport(result.Report.GetRawText(),result.NativeExitCode,request,
            request.ExpectedMainIdentity!,request.ExpectedTier2Identity,deadline.Token);
        if(result.Outcome!=checkedResult.Outcome)throw new InvalidDataException("Inconsistent current profile terminal result.");
        held.RequireUnchanged();
        requireCurrent();token.ThrowIfCancellationRequested();return new(checkedResult.Outcome,checkedResult.Report);
    }

    public async Task<ProfileVerificationDisplay> RunRetainedAsync(ProfileVerificationSelection selected,string fromXid,SupervisedCredential? credential,
        Action requireCurrent,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();requireCurrent();
        if(!Available)throw new FileNotFoundException("The packaged current-profile observer is unavailable.");
        NativeApfsImageVerifier.ValidateRetainedProfileRequest(new(selected.Request,fromXid));
        using var held=new BoundSelection(selected,credential,token);var request=new ApfsRetainedProfileVerificationRequest(held.Request,fromXid);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var result=await runHistory(request,credential,deadline.Token).ConfigureAwait(true);
        deadline.Token.ThrowIfCancellationRequested();
        var checkedResult=NativeApfsImageVerifier.ValidateRetainedProfileReport(result.Report.GetRawText(),result.NativeExitCode,request,
            held.Request.ExpectedMainIdentity!,held.Request.ExpectedTier2Identity,deadline.Token);
        if(result.Outcome!=checkedResult.Outcome)throw new InvalidDataException("Inconsistent retained profile terminal result.");
        held.RequireUnchanged();requireCurrent();token.ThrowIfCancellationRequested();return new(checkedResult.Outcome,checkedResult.Report);
    }

    public async Task<ProfileVerificationDisplay> RunVisibleSnapshotsAsync(ProfileVerificationSelection selected,string? fromXid,SupervisedCredential? credential,
        Action requireCurrent,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();requireCurrent();
        if(!Available)throw new FileNotFoundException("The packaged current-profile observer is unavailable.");
        NativeApfsImageVerifier.ValidateVisibleSnapshotProfileRequest(new(selected.Request,fromXid));
        using var held=new BoundSelection(selected,credential,token);var request=new ApfsVisibleSnapshotProfileRequest(held.Request,fromXid);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var result=await runSnapshots(request,credential,deadline.Token).ConfigureAwait(true);
        deadline.Token.ThrowIfCancellationRequested();
        var checkedResult=NativeApfsImageVerifier.ValidateVisibleSnapshotProfileReport(result.Report.GetRawText(),result.NativeExitCode,request,
            held.Request.ExpectedMainIdentity!,held.Request.ExpectedTier2Identity,deadline.Token);
        if(result.Outcome!=checkedResult.Outcome)throw new InvalidDataException("Inconsistent visible snapshot terminal result.");
        held.RequireUnchanged();requireCurrent();token.ThrowIfCancellationRequested();return new(checkedResult.Outcome,checkedResult.Report);
    }
}
