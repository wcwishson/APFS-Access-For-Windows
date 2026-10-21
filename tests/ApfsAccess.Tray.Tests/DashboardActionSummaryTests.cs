using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

// Never shown; callbacks and continuations run only on the test's STA thread.
public sealed class DashboardActionSummaryTests
{
    private const string Working = "Opening drive...";

    [Fact]
    public void CompletedOpenRestoresSummaryDespiteRepeatedCachedStatus() => Sta(context =>
    {
        var opened = new List<string?>();
        using var form = NewForm(path => { opened.Add(path); return Task.CompletedTask; });
        var status = Mounted();
        SelectVolume(form, status);
        var summary = Summary(form);
        var expected = summary.Text;
        var open = OpenButton(form);
        typeof(Button).GetMethod("OnClick", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(open, [EventArgs.Empty]);

        Assert.Equal(["R:\\"], opened);
        Assert.Equal(expected, summary.Text);
        form.ApplyStatus(status with { TimestampUtc = status.TimestampUtc.AddSeconds(1) });
        Assert.Equal(expected, summary.Text);
        Assert.True(open.Enabled);
        Assert.False(form.Visible);
    });

    [Fact]
    public void PendingActionKeepsWorkingStateUntilItsContinuationCompletes() => Sta(context =>
    {
        using var form = NewForm();
        var status = Mounted();
        SelectVolume(form, status);
        var expected = Summary(form).Text;
        var pending = new TaskCompletionSource();
        var operation = Run(form, () => pending.Task);
        try
        {
            Assert.False(operation.IsCompleted);
            Assert.Equal(Working, Summary(form).Text);
            Assert.False(OpenButton(form).Enabled);
            AssertWorkingIndicator(form, true);
            form.ApplyStatus(status with { TimestampUtc = status.TimestampUtc.AddSeconds(1) });
            context.Drain();
            Assert.False(operation.IsCompleted);
            Assert.Equal(Working, Summary(form).Text);
            Assert.False(OpenButton(form).Enabled);
        }
        finally
        {
            pending.TrySetResult();
            context.Finish(operation);
        }
        Assert.Equal(expected, Summary(form).Text);
        Assert.True(OpenButton(form).Enabled);
        AssertWorkingIndicator(form, false);
        Assert.False(form.Visible);
    });

    [Theory]
    [InlineData("Drive opened successfully.", false)]
    [InlineData("Unable to open drive: access denied.", false)]
    [InlineData("Drive opened successfully.", true)]
    [InlineData("Unable to open drive: access denied.", true)]
    public void ActionSuppliedResultSurvivesCompletionAndCachedRefresh(string message, bool deferred) => Sta(context =>
    {
        using var form = NewForm();
        var status = Mounted();
        SelectVolume(form, status);
        var pending = new TaskCompletionSource();
        var operation = Run(form, async () =>
        {
            if (deferred) await pending.Task;
            form.SetFooter(message);
        });
        pending.SetResult();
        context.Finish(operation);

        Assert.Equal(message, Summary(form).Text);
        form.ApplyStatus(status with { TimestampUtc = status.TimestampUtc.AddSeconds(1) });
        Assert.Equal(message, Summary(form).Text);
        Assert.True(OpenButton(form).Enabled);
        AssertWorkingIndicator(form, false);
        Assert.False(form.Visible);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompletionUsesLatestRealSummary(bool footerStillWorking) => Sta(context =>
    {
        using var form = NewForm();
        SelectVolume(form, Mounted());
        var oldSummary = Summary(form).Text;
        var pending = new TaskCompletionSource();
        var operation = Run(form, () => pending.Task);
        try
        {
            form.ApplyStatus(Mounted() with { State = RuntimeState.Error, LastError = "The drive needs attention." });
            var latest = Summary(form).Text;
            Assert.NotEqual(oldSummary, latest);
            if (footerStillWorking) form.SetFooter(Working);
            pending.SetResult();
            context.Finish(operation);
            Assert.Equal(latest, Summary(form).Text);
            Assert.True(OpenButton(form).Enabled);
            Assert.False(form.Visible);
        }
        finally
        {
            pending.TrySetResult();
            context.Finish(operation);
        }
    });

    [Theory]
    [InlineData(false, "Open failed: access denied.")]
    [InlineData(true, "Opening drive...")]
    public void FailureRetainsErrorEvenWhenItEqualsWorkingMessage(bool deferred, string error) => Sta(context =>
    {
        using var form = NewForm();
        var status = Mounted();
        SelectVolume(form, status);
        var healthy = Summary(form).Text;
        var pending = new TaskCompletionSource();
        using var dialogs = new RejectThreadDialogs();
        var operation = Run(form, () => deferred ? pending.Task : throw new InvalidOperationException(error));
        if (deferred)
        {
            Assert.False(operation.IsCompleted);
            Assert.False(OpenButton(form).Enabled);
            pending.SetException(new InvalidOperationException(error));
        }
        context.Finish(operation);

        Assert.Equal(1, dialogs.Rejected);
        Assert.Equal(error, Summary(form).Text);
        Assert.NotEqual(healthy, Summary(form).Text);
        form.ApplyStatus(status with { TimestampUtc = status.TimestampUtc.AddSeconds(1) });
        Assert.Equal(error, Summary(form).Text);
        Assert.True(OpenButton(form).Enabled);
        AssertWorkingIndicator(form, false);
        Assert.False(form.Visible);
    });

    private static DashboardForm NewForm(Func<string?, Task>? open = null) =>
        new(open ?? (_ => Task.CompletedTask), _ => Task.CompletedTask, _ => Task.CompletedTask);

    private static StatusChangedPayload Mounted() => new(RuntimeState.MountedRw, ["R:\\"], null,
        new DateTime(2026, 10, 19, 0, 0, 0, DateTimeKind.Utc), [], true, [],
        MountedVolumes: [new("summary-test|volume", "R:\\", "Volume", "summary-test", "Disk", MountAccessMode.ReadWrite)]);

    private static void SelectVolume(DashboardForm form, StatusChangedPayload status)
    {
        form.ApplyStatus(status);
        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        tree.SelectedNode = tree.Nodes.Cast<TreeNode>().SelectMany(n => n.Nodes.Cast<TreeNode>())
            .Single(n => n.Tag is TopologyDashboardNode { Row: not null });
        Assert.Equal(DriveDashboardPresenter.BuildSummary(status), Summary(form).Text);
        Assert.True(OpenButton(form).Enabled);
    }

    private static Label Summary(DashboardForm form) => (Label)typeof(DashboardForm)
        .GetField("_summaryLabel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

    private static Button OpenButton(DashboardForm form) => Controls(form).OfType<Button>().Single(b => b.Text == "Open");

    private static Task Run(DashboardForm form, Func<Task> action) => (Task)typeof(DashboardForm)
        .GetMethod("RunActionAsync", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, [Working, action])!;

    private static void AssertWorkingIndicator(DashboardForm form, bool active)
    {
        var progress = Controls(form).OfType<ProgressBar>().Single();
        // Visible includes the hidden parent's state; GetState tests the local flag.
        var localVisible = (bool)typeof(Control).GetMethod("GetState", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(progress, [2])!;
        Assert.Equal(active, localVisible);
        Assert.Equal(active ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks, progress.Style);
    }

    private static IEnumerable<Control> Controls(Control root)
    {
        foreach (Control child in root.Controls)
        {
            yield return child;
            foreach (var descendant in Controls(child)) yield return descendant;
        }
    }

    private static void Sta(Action<HeadlessContext> body)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var auto = WindowsFormsSynchronizationContext.AutoInstall;
            var previous = SynchronizationContext.Current;
            try
            {
                WindowsFormsSynchronizationContext.AutoInstall = false;
                var context = new HeadlessContext();
                SynchronizationContext.SetSynchronizationContext(context);
                body(context);
            }
            catch (Exception ex) { failure = ex; }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(previous);
                WindowsFormsSynchronizationContext.AutoInstall = auto;
            }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Hidden-form operation did not finish.");
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private sealed class HeadlessContext : SynchronizationContext
    {
        private readonly ConcurrentQueue<(SendOrPostCallback Callback, object? State)> queue = new();
        public override void Post(SendOrPostCallback callback, object? state) => queue.Enqueue((callback, state));
        internal void Drain() { while (queue.TryDequeue(out var item)) item.Callback(item.State); }
        internal void Finish(Task operation)
        {
            var deadline = Environment.TickCount64 + 5000;
            while (!operation.IsCompleted && Environment.TickCount64 < deadline)
            {
                Drain();
                Thread.Sleep(1);
            }
            Assert.True(operation.IsCompleted, "Action continuation was not completed on its STA thread.");
            operation.GetAwaiter().GetResult();
        }
    }

    // A thread-local CBT hook vetoes only dialog creation in this test thread.
    // No window is displayed, no input is sent and no other process is touched.
    private sealed class RejectThreadDialogs : IDisposable
    {
        private readonly Hook callback;
        private readonly nint handle;
        internal int Rejected { get; private set; }
        internal RejectThreadDialogs()
        {
            callback = OnHook;
            handle = SetWindowsHookExW(5, callback, 0, GetCurrentThreadId());
            Assert.NotEqual(nint.Zero, handle);
        }
        private nint OnHook(int code, nint window, nint data)
        {
            if (code == 3)
            {
                var name = new StringBuilder(32);
                GetClassNameW(window, name, name.Capacity);
                if (name.ToString() == "#32770") { Rejected++; return 1; }
            }
            return CallNextHookEx(handle, code, window, data);
        }
        public void Dispose()
        {
            var removed = UnhookWindowsHookEx(handle);
            GC.KeepAlive(callback);
            Assert.True(removed);
        }
        private delegate nint Hook(int code, nint window, nint data);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern nint SetWindowsHookExW(int id, Hook callback, nint module, uint thread);
        [DllImport("user32.dll")]
        private static extern nint CallNextHookEx(nint hook, int code, nint window, nint data);
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(nint hook);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassNameW(nint window, StringBuilder name, int length);
        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();
    }
}
