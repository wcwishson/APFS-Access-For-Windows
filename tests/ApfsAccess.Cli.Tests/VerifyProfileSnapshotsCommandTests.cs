using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class VerifyProfileSnapshotsCommandTests : IDisposable
{
    private readonly string folder=Path.Combine(Path.GetTempPath(),"visible-cli-"+Guid.NewGuid().ToString("N"));
    public VerifyProfileSnapshotsCommandTests(){Directory.CreateDirectory(folder);foreach(var name in new[]{"main","tier"})File.WriteAllBytes(Path.Combine(folder,name),new byte[32768]);}
    public void Dispose()=>Directory.Delete(folder,true);
    private string[] Args=>["--verification-profile","fusion-clean-cache","--image",Path.Combine(folder,"main"),"--container-id","apfs-container:"+new string('a',32),
        "--volume-uuid",new string('b',32),"--volume-oid","101","--checkpoint-xid","7","--store-offset-bytes","0","--store-size-bytes","32768",
        "--tier2-image",Path.Combine(folder,"tier"),"--tier2-offset-bytes","0","--tier2-size-bytes","32768","--fusion-uuid",new string('c',32),"--fusion-role-convention","linux-apfs-last-byte-low-bit"];
    private static (int Exit,JsonElement Json) Run(string[] args,Func<ApfsVisibleSnapshotProfileRequest,SupervisedCredential?,CancellationToken,ApfsVisibleSnapshotProfileResult> action)
    {
        var old=Console.Out;using var output=new StringWriter();Console.SetOut(output);
        try{var code=VerifyProfileSnapshotsCommand.Run(args,action);using var json=JsonDocument.Parse(output.ToString());return(code,json.RootElement.Clone());}
        finally{Console.SetOut(old);}
    }
    [Fact] public void NewRouteSeparatesOptionalParentAndPreservesLegacyCurrentDefault()
    {
        foreach(var from in new[]{false,true}){
            var result=Run(from?[..Args,"--retained-from-xid","5"]:Args,(q,c,t)=>{
                Assert.Equal(from?"5":null,q.FromXid);Assert.Null(q.Endpoint.RetainedFromXid);Assert.Null(c);
                return new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(new{outcome=1}));});
            Assert.Equal(0,result.Exit);Assert.Equal("verify-profile-snapshots",result.Json.GetProperty("command").GetString());
        }
        Assert.Null(VerifyProfileCommand.Parse(Args).RetainedFromXid);
        foreach(var bad in new[]{"0","05","7","8"})Assert.Throws<ArgumentException>(()=>VerifyProfileSnapshotsCommand.Parse([..Args,"--retained-from-xid",bad]));
        Assert.Throws<ArgumentException>(()=>VerifyProfileSnapshotsCommand.Parse([..Args,"--password","secret"]));
    }
    [Fact] public void TerminalMismatchCancellationAndRefusedScopeRemainTyped()
    {
        var result=Run(Args,(_,_,_)=>new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(new{outcome=3})));
        Assert.Equal(5,result.Exit);Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
        result=Run(Args,(_,_,_)=>throw new OperationCanceledException());Assert.Equal(12,result.Exit);Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
        result=Run([..Args,"--require-whole-volume"],(q,_,_)=>{Assert.True(q.Endpoint.RequireWholeVolume);return new(4,ApfsVerificationOutcome.Refused,JsonSerializer.SerializeToElement(new{outcome=3}));});
        Assert.Equal(4,result.Exit);Assert.False(result.Json.GetProperty("success").GetBoolean());
    }
}
