namespace ApfsAccess.Tray.Tests;

public sealed class TrayQuitTransportTests
{
    [Fact]
    public void QuitRequest_UsesSharedStatusChannelAndShutdownTimeout()
    {
        var source = ReadTrayApplicationContextSource();
        var method = SliceMethod(
            source,
            "private async Task<bool> TrySendQuitAsync(",
            "private async Task<bool> TryPrimeStatusFromServiceAsync(");

        Assert.Contains("TrySendRequestAsync(", method);
        Assert.Contains("UpdateShutdownTimeout", method);
        Assert.DoesNotContain("NamedPipeMessageClient", method);
    }

    [Fact]
    public void ServiceStopping_ExitsTrayWhileQuitRequestIsPending()
    {
        var source = ReadTrayApplicationContextSource();
        var method = SliceMethod(
            source,
            "private void HandleServiceStopping()",
            "private void HandleIntentionalQuitMarker()");

        Assert.Contains("Interlocked.Exchange(ref _exitRequested, 1);", method);
        Assert.DoesNotContain("if (Interlocked.Exchange(ref _exitRequested, 1) != 0)", method);
        Assert.Contains("ExitTrayForShutdown();", method);
    }

    private static string ReadTrayApplicationContextSource()
        => File.ReadAllText(FindRepositoryFile(
            "src",
            "ApfsAccess.Tray",
            "TrayApplicationContext.cs"));

    private static string SliceMethod(string source, string startToken, string endToken)
    {
        var start = source.IndexOf(startToken, StringComparison.Ordinal);
        var end = source.IndexOf(endToken, start, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Missing method start token: {startToken}");
        Assert.True(end > start, $"Missing method end token: {endToken}");
        return source[start..end];
    }

    private static string FindRepositoryFile(params string[] segments)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine([current.FullName, .. segments]);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate repository file.");
    }
}
