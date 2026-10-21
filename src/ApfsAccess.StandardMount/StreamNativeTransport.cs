namespace ApfsAccess.StandardMount;

public sealed record StandardNativeOwnerExit(bool ProcessExited, bool JobEmpty, bool NamespaceAbsent, int? ExitCode);
public delegate ValueTask<StandardNativeOwnerExit> StandardNativeOwnerTerminalObserver(CancellationToken cancellationToken);

// The launch factory retains the exact process/job and supplies their observer.
// Stream EOF, Stop receipts and disposal never prove process or namespace absence.
public sealed class StreamNativeTransport : IStandardNativeTransport
{
    private readonly Stream toOwner, fromOwner;
    private readonly StandardNativeOwnerTerminalObserver observeOwner;
    private readonly SemaphoreSlim io = new(1, 1), retirement = new(1, 1);
    private ulong transmitted;
    private int closing, failed;
    private bool stopAttempted, inputClosed;
    private StandardNativeStopReceipt? stop;
    private StandardNativeRetirement? terminal;
    public StandardNativeBinding Binding { get; }

    private StreamNativeTransport(Stream toOwner, Stream fromOwner, StandardNativeBinding binding, StandardNativeOwnerTerminalObserver observer)
    { this.toOwner = toOwner; this.fromOwner = fromOwner; Binding = binding; observeOwner = observer; }

    // The caller still owns launch cleanup if Hello admission throws. Stream
    // ownership transfers only after this method returns the admitted transport.
    public static async ValueTask<StreamNativeTransport> ConnectAsync(Stream toOwner, Stream fromOwner,
        string expectedSourceIdentity, string expectedVolumeIdentity, ulong expectedCheckpointXid,
        StandardNativeOwnerTerminalObserver observer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(toOwner); ArgumentNullException.ThrowIfNull(fromOwner); ArgumentNullException.ThrowIfNull(observer);
        if (!toOwner.CanWrite || !fromOwner.CanRead || ReferenceEquals(toOwner, fromOwner)) throw new ArgumentException("Distinct owned byte streams are required.");
        var frame = await StandardWireCodec.ReadFrameAsync(fromOwner, cancellationToken).ConfigureAwait(false);
        var binding = StandardWireCodec.DecodeHello(frame, expectedSourceIdentity, expectedVolumeIdentity, expectedCheckpointXid);
        return new(toOwner, fromOwner, binding, observer);
    }
    public async ValueTask<StandardNativeReply> InvokeAsync(StandardNativeCall call, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref closing) != 0) throw new IOException("Native owner is retiring.");
        await io.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref closing) != 0 || Volatile.Read(ref failed) != 0) throw new IOException("Native transport is unavailable.");
            if (transmitted == ulong.MaxValue || call.RequestId != transmitted + 1) throw new InvalidDataException("Native request sequence is not contiguous.");
            var encoded = StandardWireCodec.EncodeRequest(call, Binding.OwnerEpoch);
            try
            {
                await toOwner.WriteAsync(encoded, cancellationToken).ConfigureAwait(false);
                await toOwner.FlushAsync(cancellationToken).ConfigureAwait(false);
                transmitted = call.RequestId;
                var frame = await StandardWireCodec.ReadFrameAsync(fromOwner, cancellationToken).ConfigureAwait(false);
                return StandardWireCodec.DecodeReply(frame, call, Binding.OwnerEpoch);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            { Interlocked.Exchange(ref failed, 1); throw; }
        }
        finally { io.Release(); }
    }
    public async ValueTask<StandardNativeRetirement> RetireAsync(CancellationToken cancellationToken)
    {
        Interlocked.Exchange(ref closing, 1);
        await retirement.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (terminal is { OriginalOwnerAbsent: true, NamespaceAbsent: true }) return terminal;
            await io.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (!stopAttempted && Volatile.Read(ref failed) == 0 && transmitted != ulong.MaxValue)
                {
                    stopAttempted = true;
                    try
                    {
                        var next = transmitted + 1;
                        await toOwner.WriteAsync(StandardWireCodec.EncodeStop(next, Binding.OwnerEpoch), cancellationToken).ConfigureAwait(false);
                        await toOwner.FlushAsync(cancellationToken).ConfigureAwait(false);
                        transmitted = next;
                        var frame = await StandardWireCodec.ReadFrameAsync(fromOwner, cancellationToken).ConfigureAwait(false);
                        stop = StandardWireCodec.DecodeStop(frame, next, Binding.OwnerEpoch);
                    }
                    catch (Exception e) when (e is not OutOfMemoryException)
                    { Interlocked.Exchange(ref failed, 1); }
                }
                if (!inputClosed)
                {
                    try { await toOwner.DisposeAsync().ConfigureAwait(false); inputClosed = true; }
                    catch (IOException) { Interlocked.Exchange(ref failed, 1); }
                }
            }
            finally { io.Release(); }
            var observed = await observeOwner(cancellationToken).ConfigureAwait(false);
            var absent = observed.ProcessExited && observed.JobEmpty;
            var clean = Volatile.Read(ref failed) == 0 && stop is { Clean: true, Status: 0 } &&
                stop.Accepted == stop.Durable && stop.Durable == stop.Cleaned && absent && observed.NamespaceAbsent && observed.ExitCode == 0;
            terminal = new(absent, observed.NamespaceAbsent, clean, stop?.Accepted ?? 0, stop?.Durable ?? 0,
                stop?.Cleaned ?? 0, clean ? 0u : stop is { Status: not 0 } ? stop.Status : 0xC0000185u);
            return terminal;
        }
        finally { retirement.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var result = await RetireAsync(timeout.Token).ConfigureAwait(false);
        if (!result.OriginalOwnerAbsent || !result.NamespaceAbsent) throw new IOException("Native launch ownership remains reserved.");
        await fromOwner.DisposeAsync().ConfigureAwait(false);
    }
}
