using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class VerifyProfileCommandTests : IDisposable
{
    private readonly string root=Path.Combine(Path.GetTempPath(),"profile-cli-"+Guid.NewGuid().ToString("N"));
    private string Image=>Path.Combine(root,"main.apfs");
    private string Tier=>Path.Combine(root,"tier.apfs");
    private string[] Args=>["--verification-profile","fusion-clean-cache","--image",Image,"--container-id","apfs-container:"+new string('a',32),
        "--volume-uuid",new string('b',32),"--volume-oid","101","--checkpoint-xid","7","--store-offset-bytes","0","--store-size-bytes","32768",
        "--tier2-image",Tier,"--tier2-offset-bytes","0","--tier2-size-bytes","32768","--fusion-uuid",new string('c',32),"--fusion-role-convention","linux-apfs-last-byte-low-bit"];
    public VerifyProfileCommandTests(){Directory.CreateDirectory(root);File.WriteAllBytes(Image,new byte[32768]);File.WriteAllBytes(Tier,new byte[32768]);}
    public void Dispose()=>Directory.Delete(root,true);
    private static (int Exit,JsonElement Json) Run(string[] args,Func<ApfsCurrentProfileVerificationRequest,SupervisedCredential?,CancellationToken,ApfsCurrentProfileVerificationResult> action)
    {
        var old=Console.Out;using var output=new StringWriter();Console.SetOut(output);
        try{var code=VerifyProfileCommand.Run(args,action);using var json=JsonDocument.Parse(output.ToString());return(code,json.RootElement.Clone());}
        finally{Console.SetOut(old);}
    }
    [Fact]
    public void ExactCurrentProfileIsDispatchedWithoutCredentialForFusion()
    {
        var called=false;var result=Run(Args,(r,c,t)=>{called=true;Assert.Null(c);Assert.Equal("fusion-clean-cache",r.Profile);Assert.Equal(Tier,r.Tier2Image);
            return new(0,ApfsVerificationOutcome.Complete,JsonDocument.Parse("{\"outcome\":1}").RootElement.Clone());});
        Assert.True(called);Assert.Equal(0,result.Exit);Assert.True(result.Json.GetProperty("success").GetBoolean());
    }
    [Fact]
    public void InvalidOrSecretArgumentsNeverDispatch()
    {
        foreach(var extra in new[]{new[]{"--password","secret"},new[]{"--credential-stdin"},new[]{"--image",Image},new[]{"--device","x"},new[]{"--json","--json"}})
        {
            var called=false;var result=Run([..Args,..extra],(_,_,_)=>{called=true;throw new InvalidOperationException();});
            Assert.False(called);Assert.Equal(2,result.Exit);Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
        }
    }
    [Fact]
    public void ProtocolFailureAndCancellationClearAssignedResult()
    {
        var result=Run(Args,(_,_,_)=>new(0,ApfsVerificationOutcome.Complete,JsonDocument.Parse("{\"outcome\":3}").RootElement.Clone()));
        Assert.Equal(5,result.Exit);Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
        result=Run(Args,(_,_,_)=>throw new OperationCanceledException());Assert.Equal(12,result.Exit);Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
    }
    [Fact]
    public void BroaderRequestStaysExplicitAndRefused()
    {
        var result=Run([..Args,"--account-retained-ownership"],(r,_,_)=>{Assert.True(r.AccountRetainedOwnership);
            return new(4,ApfsVerificationOutcome.Refused,JsonDocument.Parse("{\"outcome\":3}").RootElement.Clone());});
        Assert.Equal(4,result.Exit);Assert.False(result.Json.GetProperty("success").GetBoolean());
    }
    private static (int Exit,JsonElement Json) RunHistory(string[] args,
        Func<ApfsRetainedProfileVerificationRequest,SupervisedCredential?,CancellationToken,ApfsRetainedProfileVerificationResult> action)
    {
        var old=Console.Out;using var output=new StringWriter();Console.SetOut(output);
        try{var code=VerifyProfileHistoryCommand.Run(args,action);using var json=JsonDocument.Parse(output.ToString());return(code,json.RootElement.Clone());}
        finally{Console.SetOut(old);}
    }
    [Fact] public void RetainedCommandBindsExplicitFromSeparatelyAndPreservesCurrentCommand()
    {
        var calls=0;var result=RunHistory([..Args,"--retained-from-xid","5"],(q,c,t)=>{
            ++calls;Assert.Equal("5",q.FromXid);Assert.Null(q.Endpoint.RetainedFromXid);Assert.Null(c);Assert.Equal(Tier,q.Endpoint.Tier2Image);
            return new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(new{outcome=1}));});
        Assert.Equal(1,calls);Assert.Equal(0,result.Exit);Assert.Equal("verify-profile-history",result.Json.GetProperty("command").GetString());
        Assert.Equal(2,result.Json.GetProperty("schemaVersion").GetInt32());Assert.Null(VerifyProfileCommand.Parse(Args).RetainedFromXid);
        foreach(var extra in new[]{Array.Empty<string>(),new[]{"--retained-from-xid","0"},new[]{"--retained-from-xid","7"},new[]{"--retained-from-xid","05"},
            new[]{"--retained-from-xid","5","--retained-from-xid","5"},new[]{"--retained-from-xid","5","--password","secret"}}){
            result=RunHistory([..Args,..extra],(_,_,_)=>{++calls;throw new InvalidOperationException();});Assert.Equal(2,result.Exit);Assert.Equal(1,calls);}
    }
    [Fact] public void RetainedProtocolFailureAndCancellationClearResult()
    {
        var args=Args.Concat(new[]{"--retained-from-xid","5"}).ToArray();
        var result=RunHistory(args,(_,_,_)=>new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(new{outcome=3})));
        Assert.Equal(5,result.Exit);Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
        result=RunHistory(args,(_,_,_)=>throw new OperationCanceledException());Assert.Equal(12,result.Exit);
        Assert.Equal(JsonValueKind.Null,result.Json.GetProperty("verification").ValueKind);
        result=RunHistory([..args,"--account-retained-ownership"],(q,_,_)=>{Assert.True(q.Endpoint.AccountRetainedOwnership);
            return new(4,ApfsVerificationOutcome.Refused,JsonSerializer.SerializeToElement(new{outcome=3}));});Assert.Equal(4,result.Exit);
    }
}
