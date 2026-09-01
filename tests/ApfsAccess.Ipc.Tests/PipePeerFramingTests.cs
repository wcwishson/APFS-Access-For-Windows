using System.Text;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class PipePeerFramingTests
{
    private const int MaximumFrameBytes = 1024 * 1024;

    [Fact]
    public async Task ReadMessageAsync_ReturnsNullOnlyForCleanEndOfStream()
    {
        await using var stream = new MemoryStream();
        await using var peer = new PipePeer(stream);

        var message = await peer.ReadMessageAsync(CancellationToken.None);

        Assert.Null(message);
    }

    [Fact]
    public async Task ReadMessageAsync_RejectsMalformedJsonInsteadOfReportingDisconnect()
    {
        await using var stream = Frame("{not-json}");
        await using var peer = new PipePeer(stream);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => peer.ReadMessageAsync(CancellationToken.None));

        Assert.Contains("malformed", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadMessageAsync_RejectsFrameAboveBound()
    {
        await using var stream = Frame(new string('x', MaximumFrameBytes + 1));
        await using var peer = new PipePeer(stream);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => peer.ReadMessageAsync(CancellationToken.None));

        Assert.Contains("maximum", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SendAsync_RejectsFrameAboveBoundBeforeWriting()
    {
        await using var stream = new MemoryStream();
        await using var peer = new PipePeer(stream);
        var message = PipeMessageCodec.Create(
            ApfsMessageTypes.Ping,
            new { Data = new string('x', MaximumFrameBytes) },
            requestId: "oversized-send");

        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => peer.SendAsync(message, CancellationToken.None));

        Assert.Contains("maximum", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, stream.Length);
    }

    [Fact]
    public async Task DisposeAsync_ConcurrentAndRepeatedCallersShareOneCleanup()
    {
        var stream = new BlockingDisposeStream();
        var peer = new PipePeer(stream);

        var first = peer.DisposeAsync().AsTask();
        await stream.DisposeStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var concurrent = Enumerable.Range(0, 8)
            .Select(_ => peer.DisposeAsync().AsTask())
            .ToArray();
        stream.ReleaseDispose.TrySetResult();

        await Task.WhenAll(concurrent.Prepend(first)).WaitAsync(TimeSpan.FromSeconds(2));
        await peer.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(1, stream.DisposeAsyncCalls);
    }

    private static MemoryStream Frame(string value)
        => new(Encoding.UTF8.GetBytes(value + "\n"), writable: true);

    private sealed class BlockingDisposeStream : MemoryStream
    {
        public TaskCompletionSource DisposeStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDispose { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int DisposeAsyncCalls;

        public override async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref DisposeAsyncCalls);
            DisposeStarted.TrySetResult();
            await ReleaseDispose.Task.ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }
}
