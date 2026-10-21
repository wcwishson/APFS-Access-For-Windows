using System.Globalization;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Backend.Native;

public sealed record ApfsRetainedProfileVerificationRequest(ApfsCurrentProfileVerificationRequest Endpoint,string FromXid);
public sealed record ApfsRetainedProfileVerificationResult(int NativeExitCode,ApfsVerificationOutcome Outcome,JsonElement Report);

public sealed partial class NativeApfsImageVerifier
{
    private const ulong ProfileHistoryTier2ByteAddress=0x4000000000000000UL;
    public static void ValidateRetainedProfileRequest(ApfsRetainedProfileVerificationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);ValidateCurrentProfileRequest(request.Endpoint);
        if(request.Endpoint.RetainedFromXid is not null || !NativeApfsSnapshotReader.IsU64(request.FromXid,false) ||
            ulong.Parse(request.FromXid,CultureInfo.InvariantCulture)>=ulong.Parse(request.Endpoint.CheckpointXid,CultureInfo.InvariantCulture))
            throw new ArgumentException("Select an explicit earlier retained checkpoint XID.");
    }

    public ApfsRetainedProfileVerificationResult VerifyRetainedProfile(ApfsRetainedProfileVerificationRequest request,
        SupervisedCredential? credential=null,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();ValidateRetainedProfileRequest(request);var q=request.Endpoint;
        if(q.Fusion==(credential is not null))throw new ArgumentException("Only encrypted verification requires a supervised credential pipe.");
        if(observerPath is null)throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath);using var held=new CurrentProfileSources(q);
        var args=new List<string>{"--mode","verify-profile-history","--verification-profile",q.Profile,q.Fusion?"--store-a":"--image",q.Image,
            "--expected-main-identity",held.MainId,"--container-uuid",q.ContainerId[15..],"--volume-uuid",q.VolumeUuid,"--volume-oid",q.VolumeOid,
            "--checkpoint-xid",q.CheckpointXid,"--store-offset-bytes",q.StoreOffsetBytes,"--store-size-bytes",q.StoreSizeBytes,
            "--retained-from-xid",request.FromXid};
        if(q.Fusion)args.AddRange(["--store-b",q.Tier2Image!,"--expected-tier2-identity",held.TierId!,"--tier2-offset-bytes",q.Tier2OffsetBytes!,
            "--tier2-size-bytes",q.Tier2SizeBytes!,"--fusion-uuid",q.FusionUuid!,"--fusion-role-convention",q.FusionRoleConvention!]);
        else args.Add("--credential-stdin");
        if(q.RequireWholeVolume)args.Add("--require-whole-volume");
        if(q.RequirePayloadContentHashes)args.Add("--require-payload-content-hashes");
        if(q.AccountRetainedOwnership)args.Add("--account-retained-ownership");
        var wire=credential is null?runner.Run(observerPath,args,token):runner.RunWithCredential(observerPath,args,credential,token);
        token.ThrowIfCancellationRequested();
        if(wire.ExitCode is not(0 or 3 or 4))throw new NativeVerificationExitException(wire.ExitCode,wire.StandardError);
        var result=ValidateRetainedProfileReport(wire.StandardOutput,wire.ExitCode,request,held.MainId,held.TierId,token);
        held.RequireUnchanged();token.ThrowIfCancellationRequested();return result;
    }

    public static ApfsRetainedProfileVerificationResult ValidateRetainedProfileReport(string json,int exitCode,
        ApfsRetainedProfileVerificationRequest request,string mainId,string? tierId,CancellationToken token=default)
    {
        try
        {
            token.ThrowIfCancellationRequested();ValidateRetainedProfileRequest(request);var q=request.Endpoint;
            Require(new UTF8Encoding(false,true).GetByteCount(json)<=MaxReportBytes &&
                (q.ExpectedMainIdentity is null||q.ExpectedMainIdentity==mainId) && (q.ExpectedTier2Identity is null||q.ExpectedTier2Identity==tierId) &&
                (!q.Fusion||tierId is not null&&tierId!=mainId));
            using var doc=JsonDocument.Parse(json);var root=doc.RootElement;
            Object(root,"format version readOnly profile source requestedScope fromXid selected outcome outcomeName wholeVolumeVerified retainedOwnershipComplete payloadContentHashesVerified historicalNamespaceVerified sourceReads sourceReadBytes history snapshotAllocationChargeBytes applePurgeableBytes reclaimableBytes findings coverage");
            Require(Text(root,"format")=="apfs-access-retained-profile-verification"&&root.GetProperty("version").GetInt32()==1&&Bool(root,"readOnly")&&Text(root,"profile")==q.Profile&&
                Text(root,"fromXid")==request.FromXid&&!Bool(root,"wholeVolumeVerified")&&!Bool(root,"retainedOwnershipComplete")&&!Bool(root,"payloadContentHashesVerified"));
            foreach(var field in new[]{"snapshotAllocationChargeBytes","applePurgeableBytes","reclaimableBytes"})Require(root.GetProperty(field).ValueKind==JsonValueKind.Null);
            var outcome=EnumNumber(root,"outcome",3);var complete=outcome==1;
            Require(exitCode==(complete?0:outcome==2?3:4)&&Text(root,"outcomeName")==((ApfsVerificationOutcome)outcome).ToString());
            var source=root.GetProperty("source");Object(source,"identity coordinateSystem stores");
            var identity=q.Fusion?mainId+":fusion:"+q.FusionUuid+":"+tierId:mainId+":scope:"+q.StoreOffsetBytes+":"+q.StoreSizeBytes;
            Require(Text(source,"identity")==identity&&Text(source,"coordinateSystem")== (q.Fusion?"member-image-relative":"container-relative"));
            var stores=source.GetProperty("stores");Require(stores.ValueKind==JsonValueKind.Array&&stores.GetArrayLength()==(q.Fusion?2:1));
            var sizes=new ulong[stores.GetArrayLength()];var offsets=new ulong[sizes.Length];
            for(var i=0;i<sizes.Length;++i)
            {
                var store=stores[i];Object(store,"role id label offsetBytes sizeBytes");
                Require(Text(store,"role")== (q.Fusion?(i==0?"main":"tier2"):"container")&&Text(store,"id")== (q.Fusion?(i==0?mainId:tierId):identity)&&
                    Text(store,"label")== (i==0?q.Image:q.Tier2Image)&&Text(store,"offsetBytes")== (i==0?q.WireScope.StoreOffsetBytes:q.Tier2OffsetBytes)&&
                    Text(store,"sizeBytes")== (i==0?q.StoreSizeBytes:q.Tier2SizeBytes));
                sizes[i]=Number(store,"sizeBytes",false);offsets[i]=Number(store,"offsetBytes");
                Require(offsets[i]<=ulong.MaxValue-sizes[i]&&offsets[i]%4096==0&&sizes[i]%4096==0);
            }
            var scope=root.GetProperty("requestedScope");
            Object(scope,"containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes maxReads maxReadBytes maxRecords maxRecordBytes requireWholeVolume requirePayloadContentHashes observePayloadContent accountRetainedOwnership retainedFromXid");
            Exact(scope,q.WireScope);
            Require(Number(scope,"maxReads")==65536&&Number(scope,"maxReadBytes")==268435456&&Number(scope,"maxRecords")==1000000&&Number(scope,"maxRecordBytes")==268435456&&
                Bool(scope,"requireWholeVolume")==q.RequireWholeVolume&&Bool(scope,"requirePayloadContentHashes")==q.RequirePayloadContentHashes&&
                !Bool(scope,"observePayloadContent")&&Bool(scope,"accountRetainedOwnership")==q.AccountRetainedOwnership&&scope.GetProperty("retainedFromXid").ValueKind==JsonValueKind.Null&&
                Number(root,"sourceReads")<=65536&&Number(root,"sourceReadBytes")<=268435456);
            var findings=root.GetProperty("findings");Require(findings.ValueKind==JsonValueKind.Array&&findings.GetArrayLength()<=1000000&&complete==(findings.GetArrayLength()==0));
            foreach(var finding in findings.EnumerateArray())
            {
                token.ThrowIfCancellationRequested();Object(finding,"code severity check volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
                EnumNumber(finding,"code",27);EnumNumber(finding,"check",22);Require(EnumNumber(finding,"severity",3)==(outcome==3?2:3));
                foreach(var field in new[]{"volumeOid","objectId","physicalBlock","checkpointXid","failedSourceOffsetBytes"})
                    if(finding.GetProperty(field).ValueKind!=JsonValueKind.Null)Number(finding,field);
                ProfileText(finding,"detail");
            }
            var coverage=root.GetProperty("coverage");Require(coverage.ValueKind==JsonValueKind.Array&&coverage.GetArrayLength()==1);
            var covered=coverage[0];Object(covered,"check implemented required state scopeDetail");
            Require(EnumNumber(covered,"check",22)==22&&Bool(covered,"implemented")&&Bool(covered,"required")&&EnumNumber(covered,"state",5)==(complete?2:outcome==3?4:3));ProfileText(covered,"scopeDetail");
            var selected=root.GetProperty("selected");var history=root.GetProperty("history");
            if(!complete)
                Require(selected.ValueKind==JsonValueKind.Null&&history.ValueKind==JsonValueKind.Null&&root.GetProperty("historicalNamespaceVerified").ValueKind==JsonValueKind.Null);
            else
            {
                Require(!q.RequireWholeVolume&&!q.RequirePayloadContentHashes&&!q.AccountRetainedOwnership&&Bool(root,"historicalNamespaceVerified")&&
                    Number(root,"sourceReads",false)>0&&Number(root,"sourceReadBytes",false)>0);
                Object(history,"allocationUnitBytes snapshotOwnerScope chainXids checkpoints");
                var bs=history.GetProperty("allocationUnitBytes").GetUInt32();Require(bs>=4096&&bs<=65536&&(bs&(bs-1))==0&&
                    Text(history,"snapshotOwnerScope")=="canonical-empty-inventories-only"&&sizes.All(v=>v%bs==0)&&offsets.All(v=>v%bs==0));
                var capacity=checked(sizes[0]/bs+(q.Fusion?sizes[1]/bs:0));
                bool Address(ulong block,ulong count=1)=>count>0&&(block<sizes[0]/bs?count<=sizes[0]/bs-block:
                    q.Fusion&&block>=ProfileHistoryTier2ByteAddress/bs&&block-ProfileHistoryTier2ByteAddress/bs<sizes[1]/bs&&count<=sizes[1]/bs-(block-ProfileHistoryTier2ByteAddress/bs));
                Object(selected,"containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");Exact(selected,q.WireScope);
                Require(Number(selected,"checkpointPhysicalBlock",false)<sizes[0]/bs&&Address(Number(selected,"volumeSuperblockPhysicalBlock",false))&&
                    Address(Number(selected,"rootPhysicalBlock",false))&&Number(selected,"rootOid",false)>0&&Number(selected,"volumeSuperblockXid",false)<=ulong.Parse(q.CheckpointXid,CultureInfo.InvariantCulture));
                var chain=history.GetProperty("chainXids");var checkpoints=history.GetProperty("checkpoints");
                Require(chain.ValueKind==JsonValueKind.Array&&chain.GetArrayLength() is >=2 and <=1000000&&checkpoints.ValueKind==JsonValueKind.Array&&checkpoints.GetArrayLength()==chain.GetArrayLength());
                ulong previousXid=0;long rangeCount=0;
                for(var i=0;i<chain.GetArrayLength();++i)
                {
                    token.ThrowIfCancellationRequested();var text=chain[i].GetString();Require(NativeApfsSnapshotReader.IsU64(text!,false));var xid=ulong.Parse(text!,CultureInfo.InvariantCulture);
                    Require(xid>previousXid);previousXid=xid;var cp=checkpoints[i];Object(cp,"checkpointXid metadataRanges payloadRanges");Require(Number(cp,"checkpointXid",false)==xid);
                    ulong total=0;
                    foreach(var kind in new[]{"metadataRanges","payloadRanges"})
                    {
                        var ranges=cp.GetProperty(kind);Require(ranges.ValueKind==JsonValueKind.Array&&ranges.GetArrayLength()<=1000000&&(kind!="metadataRanges"||ranges.GetArrayLength()>0));
                        rangeCount+=ranges.GetArrayLength();Require(rangeCount<=1000000);ulong end=0;var first=true;
                        foreach(var range in ranges.EnumerateArray())
                        {
                            token.ThrowIfCancellationRequested();Object(range,"physicalBlock blockCount");var start=Number(range,"physicalBlock");var count=Number(range,"blockCount",false);
                            Require(Address(start,count)&&start<=ulong.MaxValue-count&&(first||start>end)&&count<=capacity-total);end=start+count;first=false;total+=count;
                        }
                    }
                }
                Require(chain[0].GetString()==request.FromXid&&chain[chain.GetArrayLength()-1].GetString()==q.CheckpointXid);
                ulong comparisons=0;
                foreach(var a in checkpoints.EnumerateArray())foreach(var b in checkpoints.EnumerateArray())
                {
                    token.ThrowIfCancellationRequested();Require(++comparisons<=1000000);
                    var metadata=a.GetProperty("metadataRanges");var payload=b.GetProperty("payloadRanges");var m=0;var p=0;
                    while(m<metadata.GetArrayLength()&&p<payload.GetArrayLength())
                    {
                        token.ThrowIfCancellationRequested();Require(++comparisons<=1000000);
                        var ms=Number(metadata[m],"physicalBlock");var me=ms+Number(metadata[m],"blockCount",false);
                        var ps=Number(payload[p],"physicalBlock");var pe=ps+Number(payload[p],"blockCount",false);
                        if(me<=ps)++m;else if(pe<=ms)++p;else Require(false);
                    }
                }
            }
            return new(exitCode,(ApfsVerificationOutcome)outcome,root.Clone());
        }
        catch(Exception ex)when(ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or ArgumentException)
        {throw new InvalidDataException("Native observer returned invalid or mismatched retained profile output.",ex);}
    }
}
