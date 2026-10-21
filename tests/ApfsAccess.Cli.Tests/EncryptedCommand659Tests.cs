using ApfsAccess.Cli;
namespace ApfsAccess.Cli.Tests;
public sealed class EncryptedCommand659Tests
{
    [Theory] [InlineData("--password")] [InlineData("--password=value")] [InlineData("--credential-file")]
    public void PasswordAndFileCredentialsAreNeverAccepted(string option)
    {var error=Assert.Throws<ArgumentException>(()=>EncryptedImageCommand.Parse(["unlock",option,"sensitive-test-value"]));Assert.DoesNotContain("sensitive-test-value",error.Message);}
    [Theory] [InlineData("--device-id")] [InlineData("--volume-id")] [InlineData("--credential-stdin")]
    public void DuplicateSelectionOrCredentialSourceRefuses(string duplicate)
    {
        var args=new List<string>{"unlock","--device-id",@"D:\a.apfs","--volume-id","apfs-vol:id:1","--credential-stdin",duplicate};
        if(duplicate!="--credential-stdin")args.Add("other");Assert.Throws<ArgumentException>(()=>EncryptedImageCommand.Parse(args.ToArray()));
    }
    [Fact] public void StdinUnlockAndLockUsePublicControlCommandNames()
    {
        Assert.True(EncryptedImageCommand.Parse(["unlock","--device-id",@"D:\a.apfs","--volume-id","id","--credential-stdin"]).CredentialStdin);
        Assert.Equal("lock",EncryptedImageCommand.Parse(["lock","--device-id",@"D:\a.apfs","--volume-id","id"]).Command);
        Assert.Throws<ArgumentException>(()=>EncryptedImageCommand.Parse(["unlock","--device-id",@"D:\a.apfs","--volume-id","id"]));
    }
    [Theory] [InlineData("unlock")] [InlineData("lock")] [InlineData("register-image")]
    public void PublicQueryRecognizesCanonicalEncryptedTerminalProof(string command)
    {
        var p=new ApfsAccess.Core.EncryptedImageProfile(@"D:\test-image.apfs","windows-file:1:2:4096:4:scope:0:4096",0,4096,
            "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",12,8,1,8,2,8,
            "33333333-3333-3333-3333-333333333333","includes-header");
        var now=DateTime.UtcNow;var request=new ApfsAccess.Ipc.ControlOperationRequestPayload(Guid.NewGuid().ToString("D"),command,ApfsAccess.Ipc.SelectedControlTarget.ForImage(p),ExpiresAtUtc:now.AddSeconds(30));
        var result=new ApfsAccess.Ipc.OperationResultPayload(request.OperationId,command,request.Target,ApfsAccess.Ipc.ApfsOperationFingerprint.Compute(request),
            "succeeded","ok",true,now,now,now,FinalStatus:command=="unlock"?"unlocked-read-only":"locked",
            EffectiveMode:command=="unlock"?"read-only":null,MountProof:command=="unlock"?"present":command=="lock"?"absent":null,
            OwnershipProof:command=="lock"?"proven":null,DurabilityProof:command=="lock"?"proven":null,ExpiresAtUtc:request.ExpiresAtUtc,
            EncryptionState:command=="unlock"?ApfsAccess.Core.EncryptedVolumeState.Unlocked:ApfsAccess.Core.EncryptedVolumeState.Locked);
        var validate=typeof(Program).GetMethod("HasVerifiedTerminalSuccess",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        Assert.True((bool)validate.Invoke(null,[result])!);
        Assert.False((bool)validate.Invoke(null,[result with { EncryptionState=null }])!);
    }
    [Fact] public async Task ActualProgramDispatcherRejectsPasswordBeforeConnectingOrLaunching()
    {Assert.Equal(2,await Program.RunForTestAsync(["unlock","--password","invalid-test-argument"]));}
    private static async Task<(int Exit,System.Text.Json.JsonElement Json)> RunEnvelopeAsync(string[] args)
    {
        var previous=Console.Out;using var output=new StringWriter();
        try{Console.SetOut(output);var exit=await EncryptedImageCommand.RunAsync(args);return (exit,System.Text.Json.JsonDocument.Parse(output.ToString()).RootElement.Clone());}
        finally{Console.SetOut(previous);}
    }
    [Fact] public async Task ArgumentErrorEmitsSchema2EnvelopeWithoutSecrets()
    {
        var (exit,json)=await RunEnvelopeAsync(["unlock","--device-id",@"D:\a.apfs"]);
        Assert.Equal(2,exit);
        Assert.Equal(2,json.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("unlock",json.GetProperty("command").GetString());
        Assert.True(Guid.TryParseExact(json.GetProperty("operationId").GetString(),"D",out _));
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal(2,json.GetProperty("exitCode").GetInt32());
        Assert.DoesNotContain(@"D:\a.apfs",json.GetProperty("message").GetString());
    }
    [Fact] public async Task ArgumentErrorEchoesSuppliedCanonicalOperationId()
    {
        const string supplied="01234567-89ab-cdef-0123-456789abcdef";
        var (exit,json)=await RunEnvelopeAsync(["lock","--device-id",@"D:\a.apfs","--operation-id",supplied]);
        Assert.Equal(2,exit);
        Assert.Equal(supplied,json.GetProperty("operationId").GetString());
    }
}
