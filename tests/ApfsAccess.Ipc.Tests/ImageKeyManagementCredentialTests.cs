using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using ApfsAccess.Cli;

namespace ApfsAccess.Ipc.Tests;

public sealed class ImageKeyManagementCredentialTests
{
    private static SupervisedCredential Credential(char marker)
    {
        using var text = new SecureString(); text.AppendChar(marker);
        return SupervisedCredential.FromSecureString(text);
    }
    private static long StartTime => Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks;
    private static nint Memory(SupervisedCredential value) => (nint)typeof(SupervisedCredential)
        .GetField("memory", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(value)!;
    private static SupervisedCredential[] Owners(SupervisedCredentialSet value) => (SupervisedCredential[])typeof(SupervisedCredentialSet)
        .GetField("values", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(value)!;

    [Fact]
    public async Task TwoOrderedFramesRemainLockedAndAllOwnersAreWiped()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var id = Guid.NewGuid().ToString("D");
        var receive = ImageKeyManagementCredentialTransport.ReceiveCoreAsync(id, Environment.ProcessId, StartTime, 2, timeout.Token, _ => { });
        using var old = Credential('a'); using var replacement = Credential('b');
        using var sent = SupervisedCredentialSet.Own(old, replacement);
        await ImageKeyManagementCredentialTransport.SendCoreAsync(id, sent, timeout.Token, _ => { });
        using var received = await receive;
        Assert.Equal(0, sent.Count); Assert.Equal(0, Memory(old)); Assert.Equal(0, Memory(replacement));
        var owners = Owners(received);
        Assert.Equal(2, received.Count);
        Assert.All(owners, value => Assert.NotEqual(0, Memory(value)));
        Assert.Equal((byte)'a', Marshal.ReadByte(Memory(owners[0]), 8));
        Assert.Equal((byte)'b', Marshal.ReadByte(Memory(owners[1]), 8));
        received.Dispose(); Assert.All(owners, value => Assert.Equal(0, Memory(value)));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 1)]
    public async Task WrongExactCountRefusesAndWipesSender(int sentCount, int expectedCount)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var id = Guid.NewGuid().ToString("D");
        var receive = ImageKeyManagementCredentialTransport.ReceiveCoreAsync(id, Environment.ProcessId, StartTime, expectedCount, timeout.Token, _ => { });
        using var first = Credential('a'); using var second = sentCount == 2 ? Credential('b') : null;
        using var sent = SupervisedCredentialSet.Own(first, second);
        var sending = ImageKeyManagementCredentialTransport.SendCoreAsync(id, sent, timeout.Token, _ => { });
        await Assert.ThrowsAnyAsync<IOException>(async () => await receive);
        try { await sending; } catch (IOException) { }
        Assert.Equal(0, Memory(first));
        if (second is not null) Assert.Equal(0, Memory(second));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExactClientProcessAndCreationTimeRemainRequired(bool wrongPid)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var id = Guid.NewGuid().ToString("D");
        var receive = ImageKeyManagementCredentialTransport.ReceiveCoreAsync(id, wrongPid ? Environment.ProcessId + 1 : Environment.ProcessId,
            wrongPid ? StartTime : StartTime + 1, 2, timeout.Token, _ => { });
        using var first = Credential('a'); using var second = Credential('b');
        using var sent = SupervisedCredentialSet.Own(first, second);
        var sending = ImageKeyManagementCredentialTransport.SendCoreAsync(id, sent, timeout.Token, _ => { });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await receive);
        await Assert.ThrowsAnyAsync<Exception>(async () => await sending);
        Assert.Equal(0, Memory(first)); Assert.Equal(0, Memory(second));
    }

    [Fact]
    public async Task FailedServerAuthenticationTransmitsNoFrame()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var id = Guid.NewGuid().ToString("D");
        await using var server = new NamedPipeServerStream(ImageKeyManagementCredentialTransport.PipeName(id), PipeDirection.InOut,
            1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var connected = server.WaitForConnectionAsync(timeout.Token);
        using var first = Credential('a'); using var second = Credential('b');
        using var sent = SupervisedCredentialSet.Own(first, second);
        var sending = ImageKeyManagementCredentialTransport.SendCoreAsync(id, sent, timeout.Token, _ => throw new UnauthorizedAccessException());
        await connected; await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await sending);
        Assert.Equal(0, Memory(first)); Assert.Equal(0, Memory(second));
        Assert.Equal(0, await server.ReadAsync(new byte[1], timeout.Token));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task InvalidCountCannotReadTheInput(int count)
    {
        using var input = new MemoryStream();
        await Assert.ThrowsAsync<IOException>(async () => await SupervisedCredentialSet.ReceiveAsync(input, count, default));
        Assert.Equal(0, input.Position);
    }

    [Fact]
    public async Task CancellationReleasesTheExactOperationPipe()
    {
        using var cancel = new CancellationTokenSource(); var id = Guid.NewGuid().ToString("D");
        var receive = ImageKeyManagementCredentialTransport.ReceiveCoreAsync(id, Environment.ProcessId, StartTime, 2, cancel.Token, _ => { });
        cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await receive);
        await using var replacement = new NamedPipeServerStream(ImageKeyManagementCredentialTransport.PipeName(id), PipeDirection.InOut, 1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task MalformedSecondFrameCannotReturnTheFirstCredential(int kind)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var name = "ApfsAccess.KeyManagement.FrameTest." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.Out, PipeOptions.Asynchronous);
        var connecting = server.WaitForConnectionAsync(timeout.Token); await client.ConnectAsync(timeout.Token); await connecting;
        var receiving = SupervisedCredentialSet.ReceiveAsync(server, 2, timeout.Token);
        using var first = Credential('a'); await first.SendAsync(client, timeout.Token);
        var header = new byte[8]; BitConverter.GetBytes(0x31435041).CopyTo(header, 0);
        BitConverter.GetBytes(kind == 0 ? 0 : kind == 1 ? 1025 : 1).CopyTo(header, 4);
        await client.WriteAsync(header, timeout.Token);
        if (kind == 2) await client.WriteAsync(new byte[] { 0 }, timeout.Token);
        await client.DisposeAsync();
        await Assert.ThrowsAnyAsync<IOException>(async () => await receiving);
        Assert.Equal(0, Memory(first));
    }

    [Theory]
    [InlineData(2, 2, 0)]
    [InlineData(1, 2, 5)]
    [InlineData(2, 1, 5)]
    public async Task ChildStandardInputUsesTheExactFramedNativeReceiver(int sentCount, int expectedCount, int expectedExit)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var receiver = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "ApfsAccess.Credential.TestChild.exe");
        Assert.True(File.Exists(receiver), "Build the normal SDK credential test child.");
        var start = new ProcessStartInfo(receiver) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("--frame-child");
        start.ArgumentList.Add(expectedCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var child = Process.Start(start)!;
        using var first = Credential('a'); using var second = sentCount == 2 ? Credential('b') : null;
        using var sent = SupervisedCredentialSet.Own(first, second);
        try
        {
            await sent.SendAsync(child.StandardInput.BaseStream, timeout.Token); child.StandardInput.Close();
            await child.WaitForExitAsync(timeout.Token);
            Assert.Equal(expectedExit, child.ExitCode);
            Assert.Equal(string.Empty, await child.StandardOutput.ReadToEndAsync(timeout.Token));
            Assert.Equal(string.Empty, await child.StandardError.ReadToEndAsync(timeout.Token));
            Assert.Equal(0, Memory(first)); if (second is not null) Assert.Equal(0, Memory(second));
        }
        finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(); } }
    }
}
