using System.Text;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ContainerControlChannelTests
{
    [Fact]
    public async Task SendAsync_AcceptsOnlyMatchingResponse_AndCleansEndpoints()
    {
        using var temp = DTempDirectory.Create("container-control-success");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var token = new string('a', 64);
        var responder = RespondAsync(requestPath, "ok", "Detached");

        var result = await ContainerControlChannel.SendAsync(
            requestPath,
            token,
            ContainerControlAction.Detach,
            101,
            TimeSpan.FromSeconds(3),
            CancellationToken.None);
        await responder;

        Assert.True(result.Success, result.Code);
        Assert.Equal("Detached", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_RejectsMismatchedRequestId_AndCleansEndpoints()
    {
        using var temp = DTempDirectory.Create("container-control-correlation");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var token = new string('b', 64);
        var responder = RespondAsync(
            requestPath,
            "ok",
            "Detached",
            requestIdOverride: Guid.NewGuid().ToString("N"));

        var result = await ContainerControlChannel.SendAsync(
            requestPath,
            token,
            ContainerControlAction.Detach,
            102,
            TimeSpan.FromSeconds(3),
            CancellationToken.None);
        await responder;

        Assert.False(result.Success);
        Assert.Equal("ControlResponseInvalid", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_TimesOutAndRemovesPublishedRequest()
    {
        using var temp = DTempDirectory.Create("container-control-timeout");
        var requestPath = Path.Combine(temp.Path, "request.control");

        var result = await ContainerControlChannel.SendAsync(
            requestPath,
            new string('c', 64),
            ContainerControlAction.Attach,
            103,
            TimeSpan.FromMilliseconds(100),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("ControlResponseTimeout", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_CancelAfterPublication_ReturnsAmbiguousFailureAndCleansEndpoints()
    {
        using var temp = DTempDirectory.Create("container-control-cancel-published");
        var requestPath = Path.Combine(temp.Path, "request.control");
        using var cancellation = new CancellationTokenSource();
        var cancelAfterPublish = CancelAfterPublicationAsync(requestPath, cancellation);

        var result = await ContainerControlChannel.SendAsync(
            requestPath,
            new string('e', 64),
            ContainerControlAction.Attach,
            105,
            TimeSpan.FromSeconds(3),
            cancellation.Token);
        await cancelAfterPublish;

        Assert.False(result.Success);
        Assert.Equal("ControlCanceledAfterPublish", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_RefusesReparsePointParent()
    {
        using var temp = DTempDirectory.Create("container-control-reparse");
        var target = Path.Combine(temp.Path, "target");
        var link = Path.Combine(temp.Path, "link");
        Directory.CreateDirectory(target);
        Directory.CreateSymbolicLink(link, target);
        var requestPath = Path.Combine(link, "request.control");

        await Assert.ThrowsAsync<IOException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('d', 64),
                ContainerControlAction.Detach,
                104,
                TimeSpan.FromSeconds(1),
                CancellationToken.None));

        Assert.False(File.Exists(Path.Combine(target, "request.control")));
    }

    private static async Task RespondAsync(
        string requestPath,
        string outcome,
        string code,
        string? requestIdOverride = null)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!File.Exists(requestPath))
        {
            await Task.Delay(10, timeout.Token);
        }

        var fields = await File.ReadAllLinesAsync(
            requestPath,
            Encoding.ASCII,
            timeout.Token);
        Assert.Equal("APFS-CONTROL/1", fields[0]);
        Assert.Equal(5, fields.Length);
        var responsePath = requestPath + ".response";
        var response = string.Join('\n',
            "APFS-CONTROL/1",
            requestIdOverride ?? fields[1],
            outcome,
            code) + "\n";
        var temporaryResponsePath = responsePath + ".tmp-" + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(
            temporaryResponsePath,
            response,
            Encoding.ASCII,
            timeout.Token);
        File.Move(temporaryResponsePath, responsePath, overwrite: false);
    }

    private static Task CancelAfterPublicationAsync(
        string requestPath,
        CancellationTokenSource cancellation)
        => Task.Factory.StartNew(
            () =>
            {
                var deadline = DateTime.UtcNow.AddSeconds(3);
                while (!File.Exists(requestPath) && DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(1);
                }
                Assert.True(File.Exists(requestPath), "Control request was not published before the deadline.");
                cancellation.Cancel();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

    private static void AssertNoEndpoints(string requestPath)
    {
        Assert.False(File.Exists(requestPath));
        Assert.False(File.Exists(requestPath + ".response"));
        var directory = Path.GetDirectoryName(requestPath)!;
        var prefix = Path.GetFileName(requestPath) + ".tmp-";
        Assert.Empty(Directory.EnumerateFiles(
            directory,
            prefix + "*",
            SearchOption.TopDirectoryOnly));
    }
}
