using ApfsAccess.Core;

namespace ApfsAccess.Tray;

// The operation outlives its view. Detachment only cancels and blocks UI work;
// the backend keeps accepted publication/recovery ownership until retirement.
internal sealed class ImageKeyManagementDialogLifetime
{
    private readonly object sync = new();
    private readonly CancellationTokenSource cancellation = new();
    private bool detached;
    private Task<ImageKeyManagementReceipt>? running;
    internal ImageKeyManagementReceipt? Receipt { get; private set; }
    internal bool CanUpdateView { get { lock (sync) return !detached; } }
    internal Task<ImageKeyManagementReceipt>? Running { get { lock (sync) return running; } }

    internal Task<ImageKeyManagementReceipt> Start(Func<CancellationToken, Task<ImageKeyManagementReceipt>> operation)
    {
        lock (sync)
        {
            if (detached || running is not null) throw new InvalidOperationException("The image operation view is no longer available.");
            running = CompleteAsync(operation);
            _ = running.ContinueWith(task => { _ = task.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return running;
        }
    }

    private async Task<ImageKeyManagementReceipt> CompleteAsync(Func<CancellationToken, Task<ImageKeyManagementReceipt>> operation)
    {
        try
        {
            var receipt = await operation(cancellation.Token).ConfigureAwait(false);
            lock (sync) Receipt = receipt;
            return receipt;
        }
        finally { cancellation.Dispose(); }
    }

    internal bool UpdateView(Action update)
    {
        lock (sync) { if (detached) return false; update(); return true; }
    }

    internal void Cancel()
    {
        try { cancellation.Cancel(); }
        catch (ObjectDisposedException) { }
        catch (AggregateException) { /* The observed operation still owns its completion and recovery proof. */ }
    }

    internal void Detach()
    {
        bool unused;
        lock (sync) { detached = true; unused = running is null; }
        Cancel();
        if (unused) cancellation.Dispose();
    }
}
