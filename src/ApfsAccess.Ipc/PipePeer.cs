using System.IO.Pipes;
using System.Text;

namespace ApfsAccess.Ipc;

public sealed class PipePeer : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public PipePeer(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        _writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true)
        {
            AutoFlush = true,
            NewLine = "\n",
        };
    }

    public async Task SendAsync(PipeEnvelope message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        var line = PipeMessageCodec.Serialize(message);
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<PipeEnvelope?> ReadMessageAsync(CancellationToken cancellationToken)
    {
        string? line;
        try
        {
            line = await _reader.ReadLineAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }

        if (line is null)
        {
            return null;
        }

        return PipeMessageCodec.TryDeserialize(line, out var envelope) ? envelope : null;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            _writer.Dispose();
        }
        catch (ObjectDisposedException)
        {
            // The peer may have already closed the pipe; disposal should stay idempotent.
        }
        catch (IOException)
        {
            // Treat disconnects during cleanup as normal pipe shutdown.
        }

        _reader.Dispose();
        _writeLock.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}
