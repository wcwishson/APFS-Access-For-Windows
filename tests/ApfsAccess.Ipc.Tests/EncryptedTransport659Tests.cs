using System.Security;
using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using ApfsAccess.Cli;
using ApfsAccess.Core;
namespace ApfsAccess.Ipc.Tests;
public sealed class EncryptedTransport659Tests
{
    private static SupervisedCredential Credential() {using var s=new SecureString();s.AppendChar('x');return SupervisedCredential.FromSecureString(s);}
    private static long StartTime => Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks;
    private static nint Memory(SupervisedCredential c)=>(nint)typeof(SupervisedCredential).GetField("memory",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(c)!;
    [Theory] [InlineData(false)] [InlineData(true)]
    public void SecurePromptConversionPreservesExactUtf8AtByteBoundary(bool multibyte)
    {
        using var secret = new SecureString();
        for (var i = 0; i < (multibyte ? 341 : 1024); ++i) secret.AppendChar(multibyte ? '\u4e2d' : 'x');
        using var value = SupervisedCredential.FromSecureString(secret);
        var pointer = Memory(value);
        Assert.Equal(0x31435041, Marshal.ReadInt32(pointer));
        var length = multibyte ? 1023 : 1024;
        Assert.Equal(length, Marshal.ReadInt32(pointer, 4));
        for (var i = 0; i < length; ++i)
            Assert.Equal(multibyte ? (byte)(i % 3 == 0 ? 0xe4 : i % 3 == 1 ? 0xb8 : 0xad) : (byte)'x', Marshal.ReadByte(pointer, 8 + i));
        value.Dispose();
        Assert.Equal(0, Memory(value));
    }
    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void SecurePromptConversionRefusesInvalidUtf8AndByteBoundsWithoutInputInError(int kind)
    {
        using var secret=new SecureString();
        if(kind==0) secret.AppendChar('\0');
        if(kind==1) secret.AppendChar('\ud800');
        if(kind==2) for(var i=0;i<342;i++) secret.AppendChar('\u4e2d');
        var error=Assert.Throws<IOException>(()=>SupervisedCredential.FromSecureString(secret));
        Assert.Equal("Credential transport refused: InvalidFrame",error.Message);
    }
    [Fact] public async Task OneShotPipeRoundTripZerosBothOwnedCopies()
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(4)); var id=Guid.NewGuid().ToString("D");
        var receiver=EncryptedCredentialTransport.ReceiveCoreAsync(id,Environment.ProcessId,StartTime,timeout.Token,_=>{});
        using var sent=Credential(); await EncryptedCredentialTransport.SendCoreAsync(id,sent,timeout.Token,_=>{});
        using var received=await receiver; Assert.Equal(0,Memory(sent)); Assert.NotEqual(0,Memory(received));
        Assert.Equal((byte)'x',Marshal.ReadByte(Memory(received),8)); received.Dispose();Assert.Equal(0,Memory(received));
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task WrongProcessOrCreationTimeCannotReceiveCredential(bool wrongPid)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));var id=Guid.NewGuid().ToString("D");
        var receive=EncryptedCredentialTransport.ReceiveCoreAsync(id,wrongPid?Environment.ProcessId+1:Environment.ProcessId,wrongPid?StartTime:StartTime+1,timeout.Token,_=>{});
        using var secret=Credential(); var send=EncryptedCredentialTransport.SendCoreAsync(id,secret,timeout.Token,_=>{});
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async()=>await receive);
        await Assert.ThrowsAnyAsync<Exception>(async()=>await send);Assert.Equal(0,Memory(secret));
    }
    [Fact] public async Task AuthenticationFailureNeverWritesSecret()
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));var id=Guid.NewGuid().ToString("D");
        await using var server=new NamedPipeServerStream(EncryptedCredentialTransport.PipeName(id),PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
        var connection=server.WaitForConnectionAsync(timeout.Token); using var secret=Credential();
        var send=EncryptedCredentialTransport.SendCoreAsync(id,secret,timeout.Token,_=>throw new UnauthorizedAccessException());await connection;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async()=>await send); Assert.Equal(0,Memory(secret));
        var bytes=new byte[1];Assert.Equal(0,await server.ReadAsync(bytes,timeout.Token));
    }
    [Theory] [InlineData(0)] [InlineData(1025)] [InlineData(-1)]
    public async Task OversizedOrEmptyFrameRefusesWithoutPayloadAllocation(int length)
    {
        var bytes=new byte[8];BitConverter.GetBytes(0x31435041).CopyTo(bytes,0);BitConverter.GetBytes(length).CopyTo(bytes,4);
        using var stream=new MemoryStream(bytes);await Assert.ThrowsAsync<IOException>(async()=>await SupervisedCredential.ReceiveAsync(stream,default));
    }
    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)]
    public async Task TruncatedNulAndTrailingBytesRefuse(int kind)
    {
        byte[] bytes=kind switch {0=>[65,80,67,49,2,0,0,0,120],1=>[65,80,67,49,1,0,0,0,0],_=>[65,80,67,49,1,0,0,0,120,121]};
        using var stream=new MemoryStream(bytes); await Assert.ThrowsAnyAsync<IOException>(async()=>await SupervisedCredential.ReceiveAsync(stream,default));
    }
    [Fact] public async Task CancellationClosesPendingPipeAndAllowsFreshOperation()
    {
        using var timeout=new CancellationTokenSource();var id=Guid.NewGuid().ToString("D");
        var receive=EncryptedCredentialTransport.ReceiveCoreAsync(id,Environment.ProcessId,StartTime,timeout.Token,_=>{});
        timeout.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await receive);
        await using var replacement=new NamedPipeServerStream(EncryptedCredentialTransport.PipeName(id),PipeDirection.InOut,1);
    }
    [Theory] [InlineData("unlock")] [InlineData("lock")] [InlineData("register-image")]
    public void UnknownPasswordJsonFieldRejectedWithoutReflectionIntoDiagnostics(string command)
    {
        var id=Guid.NewGuid().ToString("D");var envelope=PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,new ControlOperationRequestPayload(id,command,new("D:\\a","D:\\a|v"),ExpiresAtUtc:DateTime.UtcNow.AddSeconds(30)),id,2);
        var marker=Guid.NewGuid().ToString("N");envelope.Payload!["password"]=marker;
        var validation=PipeMessageCodec.Validate(envelope);Assert.False(validation.IsValid);Assert.DoesNotContain(marker,validation.Diagnostic??"");
    }
}
