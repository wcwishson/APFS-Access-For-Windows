using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class SnapshotBrowseLifetimeTests
{
    [Theory]
    [InlineData("")]
    [InlineData("close")]
    [InlineData("close\n")]
    [InlineData("close\r\n")]
    [InlineData("close\r")]
    public async Task CommandOrParentPipeClosureReleasesTheSession(string text)
        => await SnapshotBrowseCommand.WaitForCloseInputAsync(new StringReader(text), CancellationToken.None);

    [Theory]
    [InlineData("c")]
    [InlineData("clos")]
    [InlineData("CLOSE\n")]
    [InlineData("close-more\n")]
    [InlineData("close\rX")]
    [InlineData("\n")]
    [InlineData("quit\n")]
    public async Task MalformedControlCannotMasqueradeAsARequestedClose(string text)
        => await Assert.ThrowsAsync<ArgumentException>(() =>
            SnapshotBrowseCommand.WaitForCloseInputAsync(new StringReader(text), CancellationToken.None));

    [Fact]
    public async Task UnboundedInputIsRejectedAfterASmallFixedPrefix()
    {
        using var input = new RepeatingReader();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            SnapshotBrowseCommand.WaitForCloseInputAsync(input, CancellationToken.None));
        Assert.Equal(6, input.Reads);
    }

    [Fact]
    public async Task CancelledOwnerDoesNotReadMoreInput()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        using var input = new RepeatingReader();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            SnapshotBrowseCommand.WaitForCloseInputAsync(input, cancelled.Token));
        Assert.Equal(0, input.Reads);
    }

    private sealed class RepeatingReader : TextReader
    {
        public int Reads { get; private set; }
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            buffer.Span[0] = Reads < 5 ? "close"[Reads] : 'x';
            ++Reads;
            return ValueTask.FromResult(1);
        }
    }
}
