using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

// Owns an ordered credential exchange. The array contains owners, never bytes.
public sealed class SupervisedCredentialSet : IDisposable
{
    private readonly SupervisedCredential[] values;
    private bool disposed;

    internal SupervisedCredentialSet(SupervisedCredential[] values) => this.values = values;
    public int Count => disposed ? 0 : values.Length;
    internal IReadOnlyList<SupervisedCredential> Values => !disposed ? values : throw new ObjectDisposedException(nameof(SupervisedCredentialSet));
    public SafeFileHandle? Reader => !disposed ? values[0].Reader : null;

    public static SupervisedCredentialSet Own(SupervisedCredential first, SupervisedCredential? second = null)
    {
        ArgumentNullException.ThrowIfNull(first);
        if (ReferenceEquals(first, second)) throw new ArgumentException("Distinct credential owners are required.");
        return new(second is null ? [first] : [first, second]);
    }

    public static SupervisedCredentialSet Receive(nint input, int expectedCount, CancellationToken cancellation,
        Action checkOwner, int timeoutMs = 5000) => SupervisedCredential.ReceiveFrames(input, expectedCount, cancellation, checkOwner, timeoutMs);

    public static Task<SupervisedCredentialSet> ReceiveAsync(Stream input, int expectedCount, CancellationToken token)
        => SupervisedCredential.ReceiveFramesAsync(input, expectedCount, token);

    public void CreateChildPipe() => Values[0].CreateChildPipe();
    public void ReleaseLocalReader() { if (!disposed) values[0].ReleaseLocalReader(); }

    public void Send(CancellationToken cancellation, Action checkOwnerAndChild)
    {
        try { SupervisedCredential.SendFrames(Values, cancellation, checkOwnerAndChild); }
        finally { Dispose(); }
    }

    public async Task SendAsync(Stream output, CancellationToken token)
    {
        try { await SupervisedCredential.SendFramesAsync(Values, output, token).ConfigureAwait(false); }
        finally { Dispose(); }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var value in values) value.Dispose();
    }
}
