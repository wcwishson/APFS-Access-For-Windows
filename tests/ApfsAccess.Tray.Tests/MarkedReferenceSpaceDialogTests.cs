using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Backend.Native;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class MarkedReferenceSpaceDialogTests
{
    [Fact]
    public void DisposedMarkedViewRetainsAcceptedWaitAndNoLatePublication() => OnSta(() =>
    {
        var scope = MarkedReferenceSpaceWorkflowTests.TemporaryScope();
        var status = MarkedReferenceSpaceWorkflowTests.StatusFor(scope);
        var workflow = MarkedReferenceSpaceWorkflowTests.Workflow(scope, () => status);
        var pending = new TaskCompletionSource<ApfsMarkedReferenceSpaceResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken accepted = default;
        var client = new MarkedReferenceSpaceClient(true, (_, token) => { accepted = token; return pending.Task; });
        using var form = new VolumeSnapshotDialog(workflow, _ => throw new Exception("No browse action."), markedSpaceClient: client);
        var detail = Field<TextBox>(form, "_markedSpaceDetails"); var changes = 0;
        detail.TextChanged += (_, _) => changes++;
        var run = Invoke(form); form.Dispose(); var after = changes;
        Assert.True(accepted.IsCancellationRequested); Assert.False(run.IsCompleted);
        pending.SetResult(MarkedReferenceSpaceWorkflowTests.Unknown()); run.GetAwaiter().GetResult();
        Assert.Equal(after, changes); Assert.Null(workflow.MarkedSpaceSummary);
    });

    internal static Task Invoke(VolumeSnapshotDialog form) => (Task)typeof(VolumeSnapshotDialog)
        .GetMethod("ReadMarkedSpaceAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(form, [])!;

    internal static T Field<T>(VolumeSnapshotDialog form, string name) => (T)typeof(VolumeSnapshotDialog)
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(form)!;

    internal static void OnSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() => {
            var auto = WindowsFormsSynchronizationContext.AutoInstall;
            try { WindowsFormsSynchronizationContext.AutoInstall = false; SynchronizationContext.SetSynchronizationContext(null); action(); }
            catch (Exception error) { failure = error; }
            finally { WindowsFormsSynchronizationContext.AutoInstall = auto; }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)));
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
