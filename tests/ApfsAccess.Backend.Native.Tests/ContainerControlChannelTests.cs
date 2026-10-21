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
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            token,
            ContainerControlAction.Detach,
            101,
            TimeSpan.FromSeconds(3),
            CancellationToken.None);
        var responder = RespondAsync(requestPath, send, "ok", "Detached");
        var result = await send;
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
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            token,
            ContainerControlAction.Detach,
            102,
            TimeSpan.FromSeconds(3),
            CancellationToken.None);
        var responder = RespondAsync(
            requestPath,
            send,
            "ok",
            "Detached",
            requestIdOverride: Guid.NewGuid().ToString("N"));
        var result = await send;
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
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            new string('e', 64),
            ContainerControlAction.Attach,
            105,
            TimeSpan.FromSeconds(3),
            cancellation.Token);
        var cancelAfterPublish = CancelAfterPublicationAsync(requestPath, cancellation, send);
        var result = await send;
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

    [Fact]
    public async Task SendAsync_SnapshotCreate_PublishesExactEnvelope()
    {
        using var temp = DTempDirectory.Create("container-control-snapcreate");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var token = new string('a', 64);
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            token,
            ContainerControlAction.SnapshotCreate,
            101,
            TimeSpan.FromSeconds(3),
            CancellationToken.None,
            ["backup"]);
        var responder = RespondAsync(requestPath, send, "ok", "SnapshotCreated", expectedLines: 6);
        var result = await send;
        await responder;

        Assert.True(result.Success, result.Code);
        Assert.Equal("SnapshotCreated", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_SnapshotCreate_TransmitsNameAsUtf8Bytes()
    {
        using var temp = DTempDirectory.Create("container-control-snaputf8");
        var requestPath = Path.Combine(temp.Path, "request.control");
        const string name = "备份-2026";
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            new string('b', 64),
            ContainerControlAction.SnapshotCreate,
            101,
            TimeSpan.FromSeconds(3),
            CancellationToken.None,
            [name]);
        var responder = RespondRawAsync(requestPath, send, "ok", "SnapshotCreated", raw =>
        {
            var text = Encoding.UTF8.GetString(raw);
            Assert.EndsWith("snapshot-create\n101\n" + name + "\n", text, StringComparison.Ordinal);
            Assert.True(raw.Length <= 512, $"envelope is {raw.Length} bytes");
        });
        var result = await send;
        await responder;

        Assert.True(result.Success, result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_RetriesLockedResponseWithinExistingTimeout()
    {
        using var temp = DTempDirectory.Create("container-control-response-locked");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var send = ContainerControlChannel.SendAsync(
            requestPath, new string('a', 64), ContainerControlAction.Attach,
            101, TimeSpan.FromSeconds(3), CancellationToken.None);
        await WaitForRequestAsync(requestPath, send);
        using var readTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var request = Encoding.UTF8.GetString(await ReadPublishedRequestAsync(requestPath, readTimeout.Token));
        var requestId = request.Split('\n')[1];
        var responsePath = requestPath + ".response";
        var temporaryResponsePath = responsePath + ".tmp-held";
        await File.WriteAllTextAsync(temporaryResponsePath,
            $"APFS-CONTROL/1\n{requestId}\nok\nAttached\n", Encoding.ASCII);

        using (var held = new FileStream(temporaryResponsePath, FileMode.Open, FileAccess.Read, FileShare.Delete))
        {
            File.Move(temporaryResponsePath, responsePath, overwrite: false);
            var sharing = Assert.Throws<IOException>(() => File.ReadAllLines(responsePath, Encoding.ASCII));
            Assert.Equal(32, sharing.HResult & 0xffff);
            await Task.Delay(150);
            Assert.False(send.IsCompleted);
        }

        var result = await send;
        Assert.True(result.Success, result.Code);
        Assert.Equal("Attached", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_NonSharingResponseErrorStillPropagates()
    {
        using var temp = DTempDirectory.Create("container-control-response-reparse");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var send = ContainerControlChannel.SendAsync(
            requestPath, new string('b', 64), ContainerControlAction.Attach,
            101, TimeSpan.FromSeconds(3), CancellationToken.None);
        await WaitForRequestAsync(requestPath, send);
        var target = Path.Combine(temp.Path, "response-target");
        await File.WriteAllTextAsync(target, "APFS-CONTROL/1\n", Encoding.ASCII);
        File.CreateSymbolicLink(requestPath + ".response", target);

        var error = await Assert.ThrowsAsync<IOException>(() => send);
        Assert.Contains("unsafe", error.Message, StringComparison.OrdinalIgnoreCase);
        AssertNoEndpoints(requestPath);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public async Task SendAsync_SnapshotDelete_PublishesNineIdentityLines()
    {
        using var temp = DTempDirectory.Create("container-control-snapdelete");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var identity = new[] { "21", "victim", "249", "17", "230", "8293", "8", "250", "20" };
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            new string('c', 64),
            ContainerControlAction.SnapshotDelete,
            101,
            TimeSpan.FromSeconds(3),
            CancellationToken.None,
            identity);
        var responder = RespondAsync(requestPath, send, "ok", "SnapshotDeleted", expectedLines: 14, extraLines: identity);
        var result = await send;
        await responder;

        Assert.True(result.Success, result.Code);
        Assert.Equal("SnapshotDeleted", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Fact]
    public async Task SendAsync_SnapshotRecover_PublishesBareEnvelope()
    {
        using var temp = DTempDirectory.Create("container-control-snaprecover");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var send = ContainerControlChannel.SendAsync(
            requestPath,
            new string('d', 64),
            ContainerControlAction.SnapshotRecover,
            101,
            TimeSpan.FromSeconds(3),
            CancellationToken.None);
        var responder = RespondAsync(requestPath, send, "ok", "SnapshotRecovered", expectedLines: 5);
        var result = await send;
        await responder;

        Assert.True(result.Success, result.Code);
        Assert.Equal("SnapshotRecovered", result.Code);
        AssertNoEndpoints(requestPath);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a\nb")]
    [InlineData("a\rb")]
    public async Task SendAsync_SnapshotCreate_RefusesInvalidNames(string name)
    {
        using var temp = DTempDirectory.Create("container-control-snapname-refused");
        var requestPath = Path.Combine(temp.Path, "request.control");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('e', 64),
                ContainerControlAction.SnapshotCreate,
                101,
                TimeSpan.FromSeconds(1),
                CancellationToken.None,
                [name]));

        Assert.False(File.Exists(requestPath));
    }

    [Fact]
    public async Task SendAsync_SnapshotCreate_RefusesOverlongName()
    {
        using var temp = DTempDirectory.Create("container-control-snapname-long");
        var requestPath = Path.Combine(temp.Path, "request.control");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('f', 64),
                ContainerControlAction.SnapshotCreate,
                101,
                TimeSpan.FromSeconds(1),
                CancellationToken.None,
                [new string('y', 256)]));

        Assert.False(File.Exists(requestPath));
    }

    [Theory]
    [InlineData("01")]
    [InlineData("0")]
    [InlineData("21x")]
    [InlineData("")]
    [InlineData("18446744073709551616")]
    public async Task SendAsync_SnapshotDelete_RefusesNoncanonicalNumbers(string xid)
    {
        using var temp = DTempDirectory.Create("container-control-snapnum-refused");
        var requestPath = Path.Combine(temp.Path, "request.control");
        var identity = new[] { xid, "victim", "249", "17", "230", "8293", "8", "250", "20" };

        await Assert.ThrowsAsync<ArgumentException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('a', 64),
                ContainerControlAction.SnapshotDelete,
                101,
                TimeSpan.FromSeconds(1),
                CancellationToken.None,
                identity));

        Assert.False(File.Exists(requestPath));
    }

    [Fact]
    public async Task SendAsync_SnapshotDelete_RefusesWrongIdentityLength()
    {
        using var temp = DTempDirectory.Create("container-control-snaplen-refused");
        var requestPath = Path.Combine(temp.Path, "request.control");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('b', 64),
                ContainerControlAction.SnapshotDelete,
                101,
                TimeSpan.FromSeconds(1),
                CancellationToken.None,
                ["21", "victim"]));

        Assert.False(File.Exists(requestPath));
    }

    [Fact]
    public async Task SendAsync_SnapshotRecover_RefusesTrailingLines()
    {
        using var temp = DTempDirectory.Create("container-control-snaptrail-refused");
        var requestPath = Path.Combine(temp.Path, "request.control");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('c', 64),
                ContainerControlAction.SnapshotRecover,
                101,
                TimeSpan.FromSeconds(1),
                CancellationToken.None,
                ["extra"]));

        Assert.False(File.Exists(requestPath));
    }

    [Fact]
    public async Task SendAsync_Attach_RefusesExtraLines()
    {
        using var temp = DTempDirectory.Create("container-control-attachtrail-refused");
        var requestPath = Path.Combine(temp.Path, "request.control");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            ContainerControlChannel.SendAsync(
                requestPath,
                new string('d', 64),
                ContainerControlAction.Attach,
                101,
                TimeSpan.FromSeconds(1),
                CancellationToken.None,
                ["trailing"]));

        Assert.False(File.Exists(requestPath));
    }

    private static async Task RespondAsync(
        string requestPath,
        Task<ContainerControlResult> send,
        string outcome,
        string code,
        string? requestIdOverride = null,
        int expectedLines = 5,
        string[]? extraLines = null)
    {
        await WaitForRequestAsync(requestPath, send);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));

        var fields = await File.ReadAllLinesAsync(
            requestPath,
            Encoding.UTF8,
            timeout.Token);
        Assert.Equal("APFS-CONTROL/1", fields[0]);
        Assert.Equal(expectedLines, fields.Length);
        Assert.Equal(32, fields[1].Length);
        Assert.Equal(64, fields[2].Length);
        if (extraLines is not null)
        {
            Assert.Equal(extraLines, fields[5..]);
        }
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

    private static async Task RespondRawAsync(
        string requestPath,
        Task<ContainerControlResult> send,
        string outcome,
        string code,
        Action<byte[]> inspect)
    {
        await WaitForRequestAsync(requestPath, send);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));

        var raw = await ReadPublishedRequestAsync(requestPath, timeout.Token);
        inspect(raw);
        var fields = Encoding.UTF8.GetString(raw).Split('\n');
        var responsePath = requestPath + ".response";
        var response = string.Join('\n',
            "APFS-CONTROL/1",
            fields[1],
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
        CancellationTokenSource cancellation,
        Task<ContainerControlResult> send)
        => Task.Factory.StartNew(
            () =>
            {
                while (!File.Exists(requestPath) && !send.IsCompleted)
                {
                    Thread.Sleep(1);
                }
                Assert.True(File.Exists(requestPath), "Control request completed before publication was observed.");
                cancellation.Cancel();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

    private static async Task WaitForRequestAsync(string requestPath, Task<ContainerControlResult> send)
    {
        while (!File.Exists(requestPath) && !send.IsCompleted)
        {
            await Task.Delay(10);
        }
        Assert.True(File.Exists(requestPath), "Control send completed before publication was observed.");
    }

    private static async Task<byte[]> ReadPublishedRequestAsync(string requestPath, CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await File.ReadAllBytesAsync(requestPath, cancellationToken);
            }
            catch (IOException ex) when ((ex.HResult & 0xffff) == 32 && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(10, cancellationToken);
            }
        }
    }

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
