using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class CurrentProfileVerificationTests
{
    private const string MainId="windows-file:1:2:131072:3", TierId="windows-file:1:4:32768:3";
    private static ApfsCurrentProfileVerificationRequest Request(bool fusion) => new(
        fusion?"fusion-clean-cache":"encrypted-onekey-generation-zero",@"D:\profile\main.apfs","apfs-container:"+new string('a',32),
        new string('b',32),"101","7",fusion?"8192":"20480","131072",fusion?@"D:\profile\tier.apfs":null,
        fusion?"4096":null,fusion?"32768":null,fusion?new string('c',32):null,fusion?"linux-apfs-last-byte-low-bit":null);
    private static JsonObject Report(bool fusion=true)
    {
        var req=Request(fusion);
        var scope=JsonSerializer.SerializeToNode(new {
            containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",
            storeOffsetBytes=fusion?"8192":"0",storeSizeBytes="131072",maxReads="65536",maxReadBytes="268435456",maxRecords="1000000",maxRecordBytes="268435456",
            requireWholeVolume=false,requirePayloadContentHashes=false,observePayloadContent=false,accountRetainedOwnership=false,retainedFromXid=(string?)null
        })!.AsObject();
        var selected=scope.DeepClone().AsObject();
        foreach(var key in scope.Select(p=>p.Key).ToArray())if(key is not("containerUuid" or "volumeUuid" or "volumeOid" or "checkpointXid" or "storeOffsetBytes" or "storeSizeBytes"))selected.Remove(key);
        selected["checkpointPhysicalBlock"]="1";selected["volumeSuperblockPhysicalBlock"]="2";selected["volumeSuperblockXid"]="7";selected["rootOid"]="1001";selected["rootPhysicalBlock"]="3";
        var identity=fusion?MainId+":fusion:"+req.FusionUuid+":"+TierId:MainId+":scope:20480:131072";
        var stores=new JsonArray(JsonSerializer.SerializeToNode(new {role=fusion?"main":"container",id=fusion?MainId:identity,label=req.Image,offsetBytes=fusion?"8192":"0",sizeBytes="131072"}));
        if(fusion)stores.Add(JsonSerializer.SerializeToNode(new {role="tier2",id=TierId,label=req.Tier2Image,offsetBytes="4096",sizeBytes="32768"}));
        var coverage=new JsonArray();
        foreach(var id in new[]{1,2,3,5,6,7,8,9,11,13,17}.Concat(fusion?new[]{16,18}:new[]{15}))
            coverage.Add(JsonSerializer.SerializeToNode(new {check=id,implemented=id!=13,required=id!=13,state=id==13?5:2,scopeDetail="Canonical current proof; history outside scope"}));
        return new JsonObject {
            ["format"]="apfs-access-current-profile-verification",["version"]=1,["readOnly"]=true,["profile"]=req.Profile,
            ["source"]=new JsonObject{["identity"]=identity,["coordinateSystem"]=fusion?"member-image-relative":"container-relative",["stores"]=stores},
            ["requestedScope"]=scope,["selected"]=selected,["outcome"]=1,["outcomeName"]="Complete",["wholeVolumeVerified"]=false,["retainedOwnershipComplete"]=false,["payloadContentHashesVerified"]=false,
            ["sourceReads"]="2",["sourceReadBytes"]="8192",["counts"]=JsonSerializer.SerializeToNode(new {allocationUnitBytes=4096,volumeCount=fusion?"2":"1",filesystemRecords="10",physicalExtentRecords="2",metadataDependencyBlocks="6",metadataCountScope=fusion?"current-object-tree-union":"current-metadata-dependency-and-guard-union"}),
            ["snapshotAllocationChargeBytes"]=null,["applePurgeableBytes"]=null,["reclaimableBytes"]=null,["findings"]=new JsonArray(),["coverage"]=coverage
        };
    }
    private static ApfsCurrentProfileVerificationResult Parse(JsonObject r,bool fusion=true,int exit=0,CancellationToken token=default)
        => NativeApfsImageVerifier.ParseCurrentProfile(r.ToJsonString(),exit,Request(fusion),MainId,fusion?TierId:null,token);

    [Fact]
    public void BothProfilesBindTheirDistinctCoordinatesAndPolicyUnknowns()
    {
        foreach(var fusion in new[]{false,true})
        {
            var result=Parse(Report(fusion),fusion);Assert.Equal(ApfsVerificationOutcome.Complete,result.Outcome);
            Assert.Equal(fusion?"8192":"0",result.Report.GetProperty("requestedScope").GetProperty("storeOffsetBytes").GetString());
            Assert.Equal(JsonValueKind.Null,result.Report.GetProperty("applePurgeableBytes").ValueKind);
            Assert.Contains(result.Report.GetProperty("coverage").EnumerateArray(),r=>r.GetProperty("check").GetInt32()==11&&r.GetProperty("required").GetBoolean()&&r.GetProperty("state").GetInt32()==2);
        }
    }
    [Fact]
    public void ContradictoryBindingsCoverageAndCapacityAreRejected()
    {
        Action<JsonObject>[] faults=[
            r=>r["version"]=2,r=>r["format"]="apfs-access-verification",r=>r["wholeVolumeVerified"]=true,
            r=>r["retainedOwnershipComplete"]=true,r=>r["source"]!["identity"]="foreign",r=>r["source"]!["coordinateSystem"]="container-relative",
            r=>r["source"]!["stores"]![1]!["id"]=MainId,r=>r["source"]!["stores"]![1]!["offsetBytes"]="0",
            r=>r["requestedScope"]!["checkpointXid"]="6",r=>r["requestedScope"]!["maxReads"]="65537",
            r=>r["selected"]!["rootPhysicalBlock"]="100",r=>r["selected"]=null,r=>r["counts"]!["metadataDependencyBlocks"]="40",
            r=>r["counts"]!["allocationUnitBytes"]=2048,r=>r["counts"]!["metadataCountScope"]="logical-charge",
            r=>r["coverage"]!.AsArray().RemoveAt(8),r=>r["coverage"]![8]!["required"]=false,
            r=>r["coverage"]![8]!["implemented"]=false,r=>r["coverage"]![8]!["state"]=4,
            r=>r["coverage"]!.AsArray().Add(r["coverage"]![0]!.DeepClone()),r=>r["applePurgeableBytes"]="0",
            r=>r["reclaimableBytes"]="4096",r=>r["snapshotAllocationChargeBytes"]="4096",r=>r["extraAuthority"]=true
        ];
        foreach(var fault in faults){var value=Report();fault(value);Assert.Throws<InvalidDataException>(()=>Parse(value));}
    }
    [Fact]
    public void TypedRefusalAndIncompleteNeverHaveCompleteCounts()
    {
        foreach(var refused in new[]{false,true})
        {
            var r=Report();r["outcome"]=refused?3:2;r["outcomeName"]=refused?"Refused":"Incomplete";r["counts"]=null;r["selected"]=null;
            r["coverage"]![0]!["state"]=refused?4:3;
            r["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new {code=refused?8:6,severity=refused?2:3,check=1,volumeOid="101",objectId=(string?)null,physicalBlock=(string?)null,checkpointXid="7",failedSourceOffsetBytes=(string?)null,detail="typed current failure"}));
            var result=Parse(r,exit:refused?4:3);Assert.Equal(JsonValueKind.Null,result.Report.GetProperty("counts").ValueKind);
            r["counts"]=Report()["counts"]!.DeepClone();Assert.Throws<InvalidDataException>(()=>Parse(r,exit:refused?4:3));
        }
    }
    [Fact]
    public void DuplicatePropertiesAndCancellationAreRejected()
    {
        var text=Report().ToJsonString().Replace("\"version\":1","\"version\":1,\"version\":1",StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(()=>NativeApfsImageVerifier.ParseCurrentProfile(text,0,Request(true),MainId,TierId));
        using var stopped=new CancellationTokenSource();stopped.Cancel();Assert.Throws<OperationCanceledException>(()=>Parse(Report(),token:stopped.Token));
    }
}
