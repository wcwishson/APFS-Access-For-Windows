using System.IO.Pipes;
using System.Text;

namespace ApfsAccess.Ipc;

public sealed class PipePeer : IAsyncDisposable
{
    public const int MaximumFrameBytes = 1024 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private readonly Stream _stream;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly object _disposeSync = new();
    private readonly byte[] _readBuffer = new byte[4096];
    private Task? _disposeTask;
    private int _readOffset;
    private int _readCount;

    public PipePeer(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
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
        if (StrictUtf8.GetByteCount(line) > MaximumFrameBytes)
        {
            throw new InvalidDataException(
                $"The pipe frame exceeds the {MaximumFrameBytes}-byte maximum.");
        }

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
        using var frame = new MemoryStream(capacity: 4096);
        while (true)
        {
            if (_readOffset < _readCount)
            {
                var newlineIndex = Array.IndexOf(
                    _readBuffer,
                    (byte)'\n',
                    _readOffset,
                    _readCount - _readOffset);
                var segmentEnd = newlineIndex >= 0 ? newlineIndex : _readCount;
                var segmentLength = segmentEnd - _readOffset;
                if (frame.Length + segmentLength > MaximumFrameBytes)
                {
                    throw new InvalidDataException(
                        $"The pipe frame exceeds the {MaximumFrameBytes}-byte maximum.");
                }

                frame.Write(_readBuffer, _readOffset, segmentLength);
                _readOffset = newlineIndex >= 0 ? newlineIndex + 1 : segmentEnd;
                if (newlineIndex >= 0)
                {
                    return ParseFrame(frame);
                }
            }

            _readCount = await _stream
                .ReadAsync(_readBuffer.AsMemory(), cancellationToken)
                .ConfigureAwait(false);
            _readOffset = 0;
            if (_readCount == 0)
            {
                return frame.Length == 0 ? null : ParseFrame(frame);
            }
        }
    }

    private static PipeEnvelope ParseFrame(MemoryStream frame)
    {
        var length = checked((int)frame.Length);
        var buffer = frame.GetBuffer();
        if (length > 0 && buffer[length - 1] == (byte)'\r')
        {
            length--;
        }

        string line;
        try
        {
            line = StrictUtf8.GetString(buffer, 0, length);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("The pipe frame contains invalid UTF-8.", exception);
        }

        if (!PipeMessageCodec.TryDeserializeSyntaxOnly(line, out var envelope) || envelope is null)
        {
            throw new InvalidDataException("The pipe frame contains malformed JSON.");
        }

        return envelope;
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeSync)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    public Task DisposeAsync(TimeSpan timeout)
    {
        if (timeout < TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        // Keep one underlying cleanup task; only this wait is bounded.
        return DisposeAsync().AsTask().WaitAsync(timeout);
    }

    private async Task DisposeCoreAsync()
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

        try
        {
            _writeLock.Dispose();
        }
        catch (ObjectDisposedException)
        {
        }

        try
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (IOException)
        {
            // Treat disconnects during cleanup as normal pipe shutdown.
        }
    }
}
