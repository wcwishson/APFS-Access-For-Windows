using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class VolumeSnapshotDialogLifetimeTests
{
    [Fact]
    public void DisposedSpaceViewKeepsPendingWaiterAndPublishesNoCancelledAmounts() => OnSta(() =>
    {
        var pending = new TaskCompletionSource<SnapshotSpaceExit>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken accepted = default;
        var client = new SnapshotSpaceClient((_, token) => { accepted = token; return pending.Task; });
        var workflow = Workflow(_ => throw new Exception("Space observation cannot dispatch service work."));
        using var form = new VolumeSnapshotDialog(workflow, _ => throw new Exception("No snapshot was opened."), spaceClient: client);
        var changes = Watch(form);
        var run = Invoke(form, "ReadSpaceAsync");
        try
        {
            Assert.True(accepted.CanBeCanceled);
            Assert.False(run.IsCompleted);
            form.Dispose();
            var afterDispose = changes();
            Assert.True(accepted.IsCancellationRequested);
            Assert.False(run.IsCompleted);
            Assert.False(Pending(form).IsCompleted);
            // Cancellation requests retirement; the accepted dependency still decides when it has ended.
            pending.SetResult(new(0, "deliberately invalid late output"));
            run.GetAwaiter().GetResult();
            Assert.True(Pending(form).IsCompleted);
            Assert.Null(workflow.SpaceSummary);
            Assert.Equal(afterDispose, changes());
        }
        finally { pending.TrySetCanceled(); }
    });

    [Fact]
    public void DisposedServiceViewRetainsAcceptedWaitAndObservesLateFailure() => OnSta(() =>
    {
        var pending = new TaskCompletionSource<OperationResultPayload>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var workflow = Workflow(_ => { calls++; return pending.Task; });
        using var form = new VolumeSnapshotDialog(workflow, _ => throw new Exception("No snapshot was opened."));
        var changes = Watch(form);
        var run = Invoke(form, "RunAsync", ApfsControlCommands.SnapshotList, null, null);
        try
        {
            Assert.Equal(1, calls);
            form.Dispose();
            var afterDispose = changes();
            Assert.False(run.IsCompleted);
            Assert.False(Pending(form).IsCompleted);
            pending.SetException(new IOException("accepted service waiter failed after view disposal"));
            run.GetAwaiter().GetResult();
            Assert.True(Pending(form).IsFaulted);
            Assert.Null(workflow.Inventory);
            Assert.Equal(afterDispose, changes());
        }
        finally { pending.TrySetCanceled(); }
    });

    private static VolumeSnapshotWorkflow Workflow(Func<ControlOperationRequestPayload, Task<OperationResultPayload>> send)
    {
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [WindowsSurfaceFixture.Inventory(2097152)] };
        var row = TopologyDashboard.Project(status).Single(n => n.Row is not null).Row!;
        return new(row, () => status, send);
    }

    private static Task Invoke(VolumeSnapshotDialog form, string name, params object?[] args) =>
        (Task)typeof(VolumeSnapshotDialog).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(form, args)!;

    private static Task Pending(VolumeSnapshotDialog form) =>
        ((DialogPendingOperation)typeof(VolumeSnapshotDialog).GetField("_lifetime", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(form)!).Pending!;

    private static Func<int> Watch(Form form)
    {
        var changes = 0;
        void Track(Control control)
        {
            control.TextChanged += (_, _) => Interlocked.Increment(ref changes);
            control.EnabledChanged += (_, _) => Interlocked.Increment(ref changes);
            if (control is DataGridView grid) grid.DataSourceChanged += (_, _) => Interlocked.Increment(ref changes);
            foreach (Control child in control.Controls) Track(child);
        }
        Track(form);
        form.Shown += (_, _) => throw new Exception("The lifetime probe must remain headless.");
        form.Activated += (_, _) => throw new Exception("The lifetime probe must not activate a window.");
        return () => Volatile.Read(ref changes);
    }

    private static void OnSta(Action probe)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var autoInstall = WindowsFormsSynchronizationContext.AutoInstall;
            try
            {
                // The probe has no UI message loop. Only detached continuations may run on its worker pool.
                WindowsFormsSynchronizationContext.AutoInstall = false;
                SynchronizationContext.SetSynchronizationContext(null);
                probe();
            }
            catch (Exception error) { failure = error; }
            finally { WindowsFormsSynchronizationContext.AutoInstall = autoInstall; }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The accepted operation must finish after its waiter is released.");
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
