namespace ApfsAccess.Service.Tests;

public sealed class TrayQuitNotificationContractTests
{
    [Fact]
    public void ServiceStopping_IsExplicitAndSuppressesOnlyTheWatchdogPath()
    {
        var source = File.ReadAllText(FindRepositoryFile("src", "ApfsAccess.Tray", "TrayApplicationContext.cs"));

        Assert.Contains("ApfsMessageTypes.ServiceStopping", source);
        Assert.Contains("HandleServiceStopping();", source);
        Assert.Contains("Interlocked.Exchange(ref _exitRequested, 1)", source);
        Assert.Contains("Volatile.Read(ref _exitRequested)", source);

        var stoppingIndex = source.IndexOf("if (message.Type == ApfsMessageTypes.ServiceStopping", StringComparison.Ordinal);
        var handlerIndex = source.IndexOf("private void HandleServiceStopping()", StringComparison.Ordinal);
        var nextMessageBranchIndex = source.IndexOf(
            "if (message.Type == ApfsMessageTypes.StatusChanged",
            stoppingIndex,
            StringComparison.Ordinal);
        var stoppingBranch = source[stoppingIndex..nextMessageBranchIndex];
        Assert.True(stoppingIndex >= 0);
        Assert.True(handlerIndex > stoppingIndex);
        Assert.DoesNotContain("TryStartServiceProcessIfMissing();", stoppingBranch);

        var listenerStart = source.IndexOf("private async Task RunStatusListenerAsync", StringComparison.Ordinal);
        var listenerEnd = source.IndexOf("private void TryStartServiceProcessIfMissing()", listenerStart, StringComparison.Ordinal);
        var listenerSource = source[listenerStart..listenerEnd];
        var eofIndex = listenerSource.IndexOf("if (message is null)", StringComparison.Ordinal);
        var eofWatchdogIndex = listenerSource.IndexOf("TryStartServiceProcessIfMissing();", StringComparison.Ordinal);
        Assert.True(eofIndex >= 0);
        Assert.True(eofWatchdogIndex >= 0, "Unexpected pipe closure must retain watchdog recovery.");
        Assert.Contains("break;", listenerSource[eofIndex..]);
    }

    [Fact]
    public void ServiceQuitOrdering_PreservesAcceptedAckThenNotificationThenStop()
    {
        var source = File.ReadAllText(FindRepositoryFile("src", "ApfsAccess.Service", "TrayPipeHostService.cs"));

        var quitIndex = source.IndexOf("case ApfsMessageTypes.QuitRequested:", StringComparison.Ordinal);
        var ackIndex = source.IndexOf("TrySendAckBestEffortAsync(", quitIndex, StringComparison.Ordinal);
        var stoppingIndex = source.IndexOf("await BroadcastServiceStoppingAsync(", ackIndex, StringComparison.Ordinal);
        var stopIndex = source.IndexOf("_applicationLifetime.StopApplication();", stoppingIndex, StringComparison.Ordinal);

        Assert.True(quitIndex >= 0);
        Assert.True(ackIndex > quitIndex);
        Assert.True(stoppingIndex > ackIndex);
        Assert.True(stopIndex > stoppingIndex);
        Assert.Contains("Shutdown requested.", source);
    }

    [Fact]
    public void ServiceQuitOrdering_PersistsMarkerBeforeAckThenNotificationThenStop()
    {
        var source = File.ReadAllText(FindRepositoryFile("src", "ApfsAccess.Service", "TrayPipeHostService.cs"));
        var executorSource = File.ReadAllText(FindRepositoryFile(
            "src",
            "ApfsAccess.Service",
            "AgentControlCommandExecutor.cs"));

        var quitIndex = source.IndexOf("case ApfsMessageTypes.QuitRequested:", StringComparison.Ordinal);
        var executeIndex = source.IndexOf("var result = await ExecuteLegacyMutationAsync(", quitIndex, StringComparison.Ordinal);
        var ackIndex = source.IndexOf("TrySendAckBestEffortAsync(", quitIndex, StringComparison.Ordinal);
        var stoppingIndex = source.IndexOf("await BroadcastServiceStoppingAsync(", ackIndex, StringComparison.Ordinal);
        var stopIndex = source.IndexOf("_applicationLifetime.StopApplication();", stoppingIndex, StringComparison.Ordinal);
        var executorQuitIndex = executorSource.IndexOf("private async Task<OperationResultPayload> ExecuteQuitAsync(", StringComparison.Ordinal);
        var markerIndex = executorSource.IndexOf("_quitMarkerWriter(", executorQuitIndex, StringComparison.Ordinal);
        var shutdownIndex = executorSource.IndexOf("PrepareForShutdownAsync(", markerIndex, StringComparison.Ordinal);

        Assert.True(quitIndex >= 0);
        Assert.True(executeIndex > quitIndex);
        Assert.True(ackIndex > executeIndex, "Durable quit execution must complete before the ACK is sent.");
        Assert.True(stoppingIndex > ackIndex);
        Assert.True(stopIndex > stoppingIndex);
        Assert.True(executorQuitIndex >= 0);
        Assert.True(markerIndex > executorQuitIndex);
        Assert.True(shutdownIndex > markerIndex, "The quit marker must be durable before mount shutdown begins.");
        Assert.Contains("Shutdown requested.", source);
    }

    [Fact]
    public void TrayWatchdog_ConsultsDurableQuitMarkerBeforeRestartingTheService()
    {
        var source = File.ReadAllText(FindRepositoryFile("src", "ApfsAccess.Tray", "TrayApplicationContext.cs"));

        var methodStart = source.IndexOf("private void TryStartServiceProcessIfMissing()", StringComparison.Ordinal);
        Assert.True(methodStart >= 0);
        var methodEnd = source.IndexOf(
            "private static IEnumerable<string> GetServiceExeCandidates()",
            methodStart,
            StringComparison.Ordinal);
        Assert.True(methodEnd > methodStart);
        var methodSource = source[methodStart..methodEnd];

        var markerGuardIndex = methodSource.IndexOf("HandleIntentionalQuitMarker();", StringComparison.Ordinal);
        var exitGuardIndex = methodSource.IndexOf("Volatile.Read(ref _exitRequested) != 0", StringComparison.Ordinal);
        var processStartIndex = methodSource.IndexOf("Process.Start(new ProcessStartInfo", StringComparison.Ordinal);

        Assert.True(markerGuardIndex >= 0, "Watchdog must consult the durable quit marker before deciding to restart.");
        Assert.True(processStartIndex > markerGuardIndex, "A fresh quit marker must suppress service restart.");

        var afterMarkerGuardIndex = methodSource.IndexOf("HandleIntentionalQuitMarker();", markerGuardIndex + 1, StringComparison.Ordinal);
        Assert.True(
            exitGuardIndex >= 0 && exitGuardIndex < processStartIndex,
            "Watchdog must re-check the exit flag after consulting the marker.");
        Assert.True(
            afterMarkerGuardIndex < 0 || afterMarkerGuardIndex > processStartIndex,
            "Marker consultation must precede the service start.");

        var helperStart = source.IndexOf("private void HandleIntentionalQuitMarker()", StringComparison.Ordinal);
        Assert.True(helperStart >= 0);
        var helperEnd = source.IndexOf("private void ExitTrayForShutdown()", helperStart, StringComparison.Ordinal);
        Assert.True(helperEnd > helperStart);
        var helperSource = source[helperStart..helperEnd];
        Assert.Contains("QuitRequestMarker.TryReadMarkerTimestampUtc", helperSource);
        Assert.Contains("QuitRequestMarker.ShouldHonorMarker", helperSource);
        Assert.Contains("QuitRequestMarker.ClearMarker", helperSource);
        Assert.Contains("ExitTrayForShutdown();", helperSource);
    }

    [Fact]
    public void TrayStartup_ConsultsDurableQuitMarkerBeforeFirstServiceStart()
    {
        var source = File.ReadAllText(FindRepositoryFile("src", "ApfsAccess.Tray", "TrayApplicationContext.cs"));

        var ctorCallIndex = source.IndexOf("HandleIntentionalQuitMarker();", StringComparison.Ordinal);
        Assert.True(ctorCallIndex >= 0);

        var ctorStart = source.IndexOf("public TrayApplicationContext()", StringComparison.Ordinal);
        var ctorEnd = source.IndexOf("private void OnNotifyIconMouseClick", ctorStart, StringComparison.Ordinal);
        Assert.True(ctorStart >= 0);
        Assert.True(ctorEnd > ctorStart);
        var ctorSource = source[ctorStart..ctorEnd];
        Assert.Contains("TryStartServiceProcessIfMissing();", ctorSource);
        Assert.True(
            ctorSource.IndexOf("HandleIntentionalQuitMarker();", StringComparison.Ordinal) <
            ctorSource.IndexOf("TryStartServiceProcessIfMissing();", StringComparison.Ordinal),
            "The tray must honor an in-flight intentional quit before starting the service.");
    }

    private static string FindRepositoryFile(params string[] segments)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine([current.FullName, ..segments]);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate repository file.");
    }
}
