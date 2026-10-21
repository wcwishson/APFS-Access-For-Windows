namespace ApfsAccess.Tray;

// Detaching the view does not detach its accepted operation or fault observer.
internal sealed class DialogPendingOperation
{
    private readonly object gate = new();
    private bool detached;
    internal Task? Pending { get; private set; }
    internal bool ViewAttached { get { lock (gate) return !detached; } }

    internal void Observe(Task pending)
    {
        lock (gate) Pending = pending;
        _ = pending.ContinueWith(task => { _ = task.Exception; }, CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    internal void UpdateView(Action update)
    {
        lock (gate) { if (!detached) update(); }
    }

    internal void Detach(Action cancel)
    {
        lock (gate) detached = true;
        try { cancel(); }
        catch (ObjectDisposedException) { }
        catch (AggregateException) { /* The pending operation still owns retirement. */ }
    }
}
