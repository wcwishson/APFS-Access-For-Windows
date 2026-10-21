using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Tray;

internal static class ImageKeyManagementDialogLifetimeProbe
{
    private static void Require(bool value) { if (!value) throw new InvalidOperationException("DialogLifetimeProofFailed"); }
    private static async Task<int> Main(string[] args)
    {
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
        var receipt = JsonSerializer.Deserialize<ImageKeyManagementReceipt>(File.ReadAllText(args.Single()), json)!;
        Require(receipt.Proves(new(receipt.OperationId, receipt.Action, receipt.Before)));
        var accepted = new TaskCompletionSource<ImageKeyManagementReceipt>(TaskCreationOptions.RunContinuationsAsynchronously);
        var lifetime = new ImageKeyManagementDialogLifetime(); CancellationToken operationToken = default;
        var running = lifetime.Start(token => { operationToken = token; return accepted.Task; });
        lifetime.Detach(); lifetime.Detach();
        Require(operationToken.IsCancellationRequested && !running.IsCompleted && ReferenceEquals(lifetime.Running, running));
        Require(!lifetime.UpdateView(() => throw new ObjectDisposedException("View")));
        accepted.SetResult(receipt);
        Require(ReferenceEquals(await running, receipt) && ReferenceEquals(lifetime.Receipt, receipt));
        Require(!lifetime.UpdateView(() => throw new ObjectDisposedException("View")));
        lifetime.Detach();

        var failed = new ImageKeyManagementDialogLifetime();
        var failure = new TaskCompletionSource<ImageKeyManagementReceipt>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pendingFailure = failed.Start(_ => failure.Task); failed.Detach(); failure.SetException(new IOException("RetainedRecoveryRequired"));
        try { await pendingFailure; throw new InvalidOperationException(); } catch (IOException) { }
        Require(failed.Running!.IsFaulted && !failed.UpdateView(() => throw new ObjectDisposedException("View")));

        var refreshing = new ImageKeyManagementDialogLifetime();
        var refresh = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var refreshEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var updates = 0;
        async Task FinishView()
        {
            try
            {
                await refreshing.Start(_ => Task.FromResult(receipt));
                if (!refreshing.CanUpdateView) return;
                refreshEntered.SetResult(); await refresh.Task;
                refreshing.UpdateView(() => updates++);
            }
            finally { refreshing.UpdateView(() => updates++); }
        }
        var viewTask = FinishView(); await refreshEntered.Task; refreshing.Detach(); refresh.SetResult(); await viewTask;
        Require(updates == 0 && ReferenceEquals(refreshing.Receipt, receipt));

        var unused = new ImageKeyManagementDialogLifetime(); unused.Detach();
        try { unused.Start(_ => Task.FromResult(receipt)); throw new IOException(); } catch (InvalidOperationException) { }
        Require(unused.Running is null && !unused.CanUpdateView);
        Console.WriteLine("HEADLESS_DIALOG_ACCEPTED_DISPOSE_REFRESH_FAILURE_PASS"); return 0;
    }
}
