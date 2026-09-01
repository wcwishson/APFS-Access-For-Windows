using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class GitHubReleaseUpdateClientTests
{
    private const string LatestReleaseEndpoint =
        "https://api.github.com/repos/wcwishson/APFS-Access-For-Windows/releases/latest";
    private const string ReleasePage =
        "https://github.com/wcwishson/APFS-Access-For-Windows/releases/tag/v1.0.6";
    private const string DownloadUrl =
        "https://github.com/wcwishson/APFS-Access-For-Windows/releases/download/v1.0.6/APFS.Access.exe";

    [Fact]
    public void ProductionConstructor_OwnsHandlerWithAutomaticRedirectsDisabled()
    {
        using var client = new GitHubReleaseUpdateClient();

        Assert.False(client.ProductionHandler.AllowAutoRedirect);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReturnsReadyForStableReleaseAndStagesVerifiedAsset()
    {
        using var workspace = new TestWorkspace();
        var launcherBytes = Encoding.UTF8.GetBytes("current launcher");
        var updateBytes = Encoding.UTF8.GetBytes("updated launcher");
        var digest = $"SHA256:{Convert.ToHexString(SHA256.HashData(updateBytes)).ToLowerInvariant()}";
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes, digest: digest)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", launcherBytes);

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        Assert.Equal(AppUpdateDecision.Ready, result.Decision);
        Assert.NotNull(result.Release);
        Assert.Equal(new Version(1, 0, 6), result.Release.Version);
        Assert.Equal("v1.0.6", result.Release.Tag);
        Assert.Equal(new Uri(ReleasePage), result.Release.ReleasePage);
        Assert.Equal(new Uri(DownloadUrl), result.Release.DownloadUrl);
        Assert.Equal(updateBytes.LongLength, result.Release.Size);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(updateBytes)), result.Release.Sha256);
        Assert.NotNull(result.Download);
        Assert.Equal(launcherPath, result.Download.LauncherPath);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(launcherBytes)),
            result.Download.CurrentSha256);
        Assert.Equal(updateBytes, await File.ReadAllBytesAsync(result.Download.ReadyPath));
        Assert.Equal(1, handler.DownloadRequests);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task CheckAndDownloadAsync_RejectsDraftAndPrerelease(bool draft, bool prerelease)
    {
        using var workspace = new TestWorkspace();
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, Encoding.UTF8.GetBytes("ignored")), draft, prerelease),
            Encoding.UTF8.GetBytes("ignored"));
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Theory]
    [InlineData("1.0.6")]
    [InlineData("v1.0")]
    [InlineData("v1.0.6.0")]
    [InlineData("v01.0.6")]
    [InlineData("v1.0.6-beta")]
    public async Task CheckAndDownloadAsync_RejectsMalformedOrNonVTag(string tag)
    {
        using var workspace = new TestWorkspace();
        var handler = new FakeReleaseHandler(
            BuildReleaseJson(tag, Asset(DownloadUrl, Encoding.UTF8.GetBytes("ignored"))),
            Encoding.UTF8.GetBytes("ignored"));
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_TreatsLowerReleaseAsUpToDate()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("older launcher");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.4", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        Assert.Equal(AppUpdateDecision.UpToDate, result.Decision);
        Assert.Null(result.Download);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_RejectsMissingMatchingAsset()
    {
        using var workspace = new TestWorkspace();
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset("https://github.com/wcwishson/APFS-Access-For-Windows/download/other.exe", Encoding.UTF8.GetBytes("other"), "other.exe")),
            Encoding.UTF8.GetBytes("ignored"));
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_RejectsDuplicateMatchingAssets()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var asset = Asset(DownloadUrl, updateBytes);
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", asset, assets: new[] { asset, asset }),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("sha256:")]
    [InlineData("sha256:xyz")]
    [InlineData("md5:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public async Task CheckAndDownloadAsync_RejectsMissingOrMalformedDigest(string? digest)
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var asset = digest is null
            ? new AssetDescriptor("APFS.Access.exe", DownloadUrl, updateBytes.LongLength, null)
            : Asset(DownloadUrl, updateBytes, digest: digest);
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", asset),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Theory]
    [InlineData("http://github.com/wcwishson/APFS-Access-For-Windows/releases/tag/v1.0.6", DownloadUrl)]
    [InlineData(ReleasePage, "http://github.com/wcwishson/APFS-Access-For-Windows/releases/download/v1.0.6/APFS.Access.exe")]
    public async Task CheckAndDownloadAsync_RejectsNonHttpsReleaseUrls(string releasePage, string downloadUrl)
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson(
                "v1.0.6",
                Asset(downloadUrl, updateBytes),
                releasePage: releasePage),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_RejectsRedirectOutsideHttps()
    {
        using var workspace = new TestWorkspace();
        var handler = new RedirectingHandler();
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal([new Uri(LatestReleaseEndpoint)], handler.RequestedUris);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReturnsUpToDateForSameVersionAndDigest()
    {
        using var workspace = new TestWorkspace();
        var launcherBytes = Encoding.UTF8.GetBytes("current");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.5", Asset(DownloadUrl, launcherBytes)),
            launcherBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", launcherBytes);

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        Assert.Equal(AppUpdateDecision.UpToDate, result.Decision);
        Assert.NotNull(result.Release);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(launcherBytes)), result.Release.Sha256);
        Assert.Null(result.Download);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReturnsReadyForSameVersionAndDifferentDigest()
    {
        using var workspace = new TestWorkspace();
        var launcherBytes = Encoding.UTF8.GetBytes("current");
        var updateBytes = Encoding.UTF8.GetBytes("revised current version");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.5", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", launcherBytes);

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        Assert.Equal(AppUpdateDecision.Ready, result.Decision);
        Assert.NotNull(result.Download);
        Assert.Equal(1, handler.DownloadRequests);
        Assert.Equal(updateBytes, await File.ReadAllBytesAsync(result.Download.ReadyPath));
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReturnsReadyForFourPartSameVersionAndDifferentDigest()
    {
        using var workspace = new TestWorkspace();
        var launcherBytes = Encoding.UTF8.GetBytes("current");
        var updateBytes = Encoding.UTF8.GetBytes("revised current version");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.5", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", launcherBytes);

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5, 0));

        Assert.Equal(AppUpdateDecision.Ready, result.Decision);
        Assert.NotNull(result.Download);
        Assert.Equal(1, handler.DownloadRequests);
        Assert.Equal(updateBytes, await File.ReadAllBytesAsync(result.Download.ReadyPath));
    }

    [Fact]
    public async Task CheckAndDownloadAsync_DoesNotDowngradeNewerBuildRevision()
    {
        using var workspace = new TestWorkspace();
        var launcherBytes = Encoding.UTF8.GetBytes("newer local build");
        var updateBytes = Encoding.UTF8.GetBytes("older published build");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.5", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", launcherBytes);

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5, 1));

        Assert.Equal(AppUpdateDecision.UpToDate, result.Decision);
        Assert.Null(result.Download);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_RejectsOversizedReleaseResponse()
    {
        using var workspace = new TestWorkspace();
        var handler = new FakeReleaseHandler(new string('x', checked((int)GitHubReleaseUpdateClient.MaximumReleaseResponseBytes + 1)), []);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReportsBoundedStreamingProgress()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Enumerable.Range(0, 100_003).Select(index => (byte)(index % 251)).ToArray();
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));
        var progress = new RecordingProgress();

        var result = await CheckAsync(
            handler,
            launcherPath,
            new Version(1, 0, 5),
            progress: progress);

        Assert.Equal(AppUpdateDecision.Ready, result.Decision);
        Assert.NotEmpty(progress.Values);
        Assert.Equal(0, progress.Values[0].BytesReceived);
        Assert.Equal(updateBytes.LongLength, progress.Values[^1].BytesReceived);
        Assert.All(progress.Values, value =>
        {
            Assert.InRange(value.Percentage, 0, 100);
            Assert.InRange(value.BytesReceived, 0, updateBytes.LongLength);
        });
    }

    [Fact]
    public async Task CheckAndDownloadAsync_RejectsAssetOverConfiguredMaximum()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("too large");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(
            handler,
            launcherPath,
            new Version(1, 0, 5),
            maximumDownloadBytes: updateBytes.Length - 1);

        AssertFailed(result);
        Assert.Equal(0, handler.DownloadRequests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_RejectsContentLengthDisagreement()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes,
            declaredLength: updateBytes.Length - 1);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        AssertNoIncompleteStagingFiles(workspace.Root);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_CleansUpWhenStreamOverflowsDeclaredSize()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var asset = new AssetDescriptor(
            "APFS.Access.exe",
            DownloadUrl,
            updateBytes.LongLength - 1,
            $"sha256:{Convert.ToHexString(SHA256.HashData(updateBytes))}");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", asset),
            updateBytes,
            suppressContentLength: true);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        AssertNoIncompleteStagingFiles(workspace.Root);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_CleansUpWhenDownloadedDigestDoesNotMatch()
    {
        using var workspace = new TestWorkspace();
        var expectedBytes = Encoding.UTF8.GetBytes("right!");
        var actualBytes = Encoding.UTF8.GetBytes("wrong!");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, expectedBytes)),
            actualBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        AssertNoIncompleteStagingFiles(workspace.Root);
        Assert.DoesNotContain(
            Directory.EnumerateFiles(workspace.Root),
            path => path.EndsWith(".update.ready", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReportsWhenIncompleteStagingFileCannotBeDeleted()
    {
        using var workspace = new TestWorkspace();
        var expectedBytes = Encoding.UTF8.GetBytes("right!");
        var actualBytes = Encoding.UTF8.GetBytes("wrong!");
        var handler = new ReadOnlyStagingHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, expectedBytes)),
            actualBytes,
            workspace.Root);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        try
        {
            var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

            AssertFailed(result);
            Assert.Contains("could not be removed", result.Error, StringComparison.OrdinalIgnoreCase);
            Assert.Single(Directory.GetFiles(workspace.Root, ".APFS.Access.exe.update.*.download"));
        }
        finally
        {
            foreach (var path in Directory.GetFiles(workspace.Root, ".APFS.Access.exe.update.*.download"))
            {
                File.SetAttributes(path, FileAttributes.Normal);
            }
        }
    }

    [Fact]
    public async Task CheckAndDownloadAsync_CleansUpWhenDownloadedStreamIsIncomplete()
    {
        using var workspace = new TestWorkspace();
        var expectedBytes = Encoding.UTF8.GetBytes("expected asset");
        var actualBytes = Encoding.UTF8.GetBytes("short");
        var handler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, expectedBytes)),
            actualBytes,
            suppressContentLength: true);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(handler, launcherPath, new Version(1, 0, 5));

        AssertFailed(result);
        AssertNoIncompleteStagingFiles(workspace.Root);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReturnsFailureAndCleansUpWhenCanceledDuringDownload()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var handler = new BlockingDownloadHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes.Length);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

        var result = await CheckAsync(
            handler,
            launcherPath,
            new Version(1, 0, 5),
            cancellationToken: cancellation.Token);

        AssertFailed(result);
        AssertNoIncompleteStagingFiles(workspace.Root);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReturnsFailureWhenReleaseRequestTimesOut()
    {
        using var workspace = new TestWorkspace();
        var handler = new TimeoutReleaseHandler();
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));

        var result = await CheckAsync(
            handler,
            launcherPath,
            new Version(1, 0, 5),
            timeout: TimeSpan.FromMilliseconds(100));

        AssertFailed(result);
        Assert.Equal(1, handler.Requests);
    }

    [Fact]
    public async Task CheckAndDownloadAsync_ReusesVerifiedReadyFileWithoutRedownloading()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));
        var firstHandler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes);

        var firstResult = await CheckAsync(firstHandler, launcherPath, new Version(1, 0, 5));
        Assert.Equal(AppUpdateDecision.Ready, firstResult.Decision);
        Assert.NotNull(firstResult.Download);

        var secondHandler = new FakeReleaseHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var secondResult = await CheckAsync(secondHandler, launcherPath, new Version(1, 0, 5));

        Assert.Equal(AppUpdateDecision.Ready, secondResult.Decision);
        Assert.Equal(firstResult.Download.ReadyPath, secondResult.Download!.ReadyPath);
        Assert.Equal(0, secondHandler.DownloadRequests);
        Assert.Equal(updateBytes, await File.ReadAllBytesAsync(secondResult.Download.ReadyPath));
    }

    [Fact]
    public async Task CheckAndDownloadAsync_UsesUniqueSameDirectoryStagingFilesForConcurrentDownloads()
    {
        using var workspace = new TestWorkspace();
        var updateBytes = Encoding.UTF8.GetBytes("updated");
        var handler = new GateDownloadHandler(
            BuildReleaseJson("v1.0.6", Asset(DownloadUrl, updateBytes)),
            updateBytes);
        var launcherPath = workspace.CreateFile("APFS.Access.exe", Encoding.UTF8.GetBytes("current"));
        using var cancellation = new CancellationTokenSource();

        var first = CheckAsync(handler, launcherPath, new Version(1, 0, 5), cancellationToken: cancellation.Token);
        var second = CheckAsync(handler, launcherPath, new Version(1, 0, 5), cancellationToken: cancellation.Token);

        await handler.BothDownloadsStarted.WaitAsync(TimeSpan.FromSeconds(5));
        var stagingFiles = Directory.GetFiles(workspace.Root, ".APFS.Access.exe.update.*.download");
        Assert.Equal(2, stagingFiles.Length);
        Assert.All(stagingFiles, path => Assert.Equal(workspace.Root, Path.GetDirectoryName(path)));

        cancellation.Cancel();
        var results = await Task.WhenAll(first, second);
        Assert.All(results, AssertFailed);
        AssertNoIncompleteStagingFiles(workspace.Root);
    }

    private static async Task<AppUpdateCheckResult> CheckAsync(
        HttpMessageHandler handler,
        string launcherPath,
        Version currentVersion,
        IProgress<AppUpdateProgress>? progress = null,
        CancellationToken cancellationToken = default,
        long maximumDownloadBytes = GitHubReleaseUpdateClient.MaximumDownloadBytes,
        TimeSpan? timeout = null)
    {
        using var client = new GitHubReleaseUpdateClient(
            handler,
            maximumDownloadBytes,
            timeout);
        return await client.CheckAndDownloadAsync(
            launcherPath,
            currentVersion,
            progress,
            cancellationToken);
    }

    private static void AssertNoIncompleteStagingFiles(string root)
        => Assert.Empty(Directory.GetFiles(root, ".APFS.Access.exe.update.*.download"));

    private static HttpResponseMessage Response(HttpStatusCode statusCode, HttpContent content)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = content,
        };
        response.Content.Headers.ContentType ??= new MediaTypeHeaderValue("application/octet-stream");
        return response;
    }

    private static void AssertFailed(AppUpdateCheckResult result)
    {
        Assert.Equal(AppUpdateDecision.Failed, result.Decision);
        Assert.Null(result.Download);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }

    private static string BuildReleaseJson(
        string tag,
        AssetDescriptor? primaryAsset,
        bool draft = false,
        bool prerelease = false,
        string releasePage = ReleasePage,
        IEnumerable<AssetDescriptor>? assets = null)
    {
        var releaseAssets = assets?.ToArray() ?? (primaryAsset is null ? Array.Empty<AssetDescriptor>() : new[] { primaryAsset });
        return JsonSerializer.Serialize(new
        {
            tag_name = tag,
            draft,
            prerelease,
            html_url = releasePage,
            assets = releaseAssets.Select(asset => new
            {
                name = asset.Name,
                browser_download_url = asset.DownloadUrl,
                size = asset.Size,
                digest = asset.Digest,
            }),
        });
    }

    private static AssetDescriptor Asset(
        string downloadUrl,
        byte[] content,
        string name = "APFS.Access.exe",
        string? digest = null)
        => new(
            name,
            downloadUrl,
            content.LongLength,
            digest ?? $"sha256:{Convert.ToHexString(SHA256.HashData(content))}");

    private sealed record AssetDescriptor(string Name, string DownloadUrl, long Size, string? Digest);

    private sealed class FakeReleaseHandler(
        string releaseJson,
        byte[] downloadBytes,
        long? declaredLength = null,
        bool suppressContentLength = false) : HttpMessageHandler
    {
        public int DownloadRequests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.NotNull(request.RequestUri);
            Assert.Equal("APFSAccessPortable/1.0", request.Headers.UserAgent.ToString());

            if (request.RequestUri!.AbsoluteUri == LatestReleaseEndpoint)
            {
                return Task.FromResult(Response(HttpStatusCode.OK, new StringContent(
                    releaseJson,
                    Encoding.UTF8,
                    "application/json")));
            }

            DownloadRequests++;
            var content = new ByteArrayContent(downloadBytes);
            if (suppressContentLength)
            {
                content.Headers.ContentLength = null;
            }
            else if (declaredLength.HasValue)
            {
                content.Headers.ContentLength = declaredLength.Value;
            }

            return Task.FromResult(Response(HttpStatusCode.OK, content));
        }

    }

    private sealed class RecordingProgress : IProgress<AppUpdateProgress>
    {
        public List<AppUpdateProgress> Values { get; } = [];

        public void Report(AppUpdateProgress value)
            => Values.Add(value);
    }

    private sealed class TimeoutReleaseHandler : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("The timeout test should not return a response.");
        }
    }

    private sealed class RedirectingHandler : HttpMessageHandler
    {
        public List<Uri> RequestedUris { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestedUris.Add(request.RequestUri!);
            var response = new HttpResponseMessage(HttpStatusCode.Redirect)
            {
                RequestMessage = request,
            };
            response.Headers.Location = new Uri(
                "http://github.com/wcwishson/APFS-Access-For-Windows/releases/latest");
            return Task.FromResult(response);
        }
    }

    private sealed class ReadOnlyStagingHandler(
        string releaseJson,
        byte[] downloadBytes,
        string stagingDirectory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsoluteUri == LatestReleaseEndpoint)
            {
                return Task.FromResult(Response(HttpStatusCode.OK, new StringContent(
                    releaseJson,
                    Encoding.UTF8,
                    "application/json")));
            }

            var content = new StreamContent(new ReadOnlyStagingStream(stagingDirectory, downloadBytes));
            content.Headers.ContentLength = downloadBytes.LongLength;
            return Task.FromResult(Response(HttpStatusCode.OK, content));
        }

        private sealed class ReadOnlyStagingStream(string stagingDirectory, byte[] bytes) : MemoryStream(bytes)
        {
            private bool _markedReadOnly;

            public override ValueTask<int> ReadAsync(
                Memory<byte> buffer,
                CancellationToken cancellationToken = default)
            {
                MarkStagingFileReadOnly();
                return base.ReadAsync(buffer, cancellationToken);
            }

            public override Task<int> ReadAsync(
                byte[] buffer,
                int offset,
                int count,
                CancellationToken cancellationToken)
            {
                MarkStagingFileReadOnly();
                return base.ReadAsync(buffer, offset, count, cancellationToken);
            }

            private void MarkStagingFileReadOnly()
            {
                if (_markedReadOnly)
                {
                    return;
                }

                var stagingPath = Assert.Single(Directory.GetFiles(
                    stagingDirectory,
                    ".APFS.Access.exe.update.*.download"));
                File.SetAttributes(stagingPath, File.GetAttributes(stagingPath) | FileAttributes.ReadOnly);
                _markedReadOnly = true;
            }
        }
    }

    private sealed class BlockingDownloadHandler(string releaseJson, int contentLength) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsoluteUri == LatestReleaseEndpoint)
            {
                return Task.FromResult(Response(HttpStatusCode.OK, new StringContent(
                    releaseJson,
                    Encoding.UTF8,
                    "application/json")));
            }

            var content = new StreamContent(new BlockingReadStream());
            content.Headers.ContentLength = contentLength;
            return Task.FromResult(Response(HttpStatusCode.OK, content));
        }
    }

    private sealed class GateDownloadHandler(string releaseJson, byte[] downloadBytes) : HttpMessageHandler
    {
        private readonly TaskCompletionSource _bothDownloadsStarted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _startedReaders;

        public Task BothDownloadsStarted => _bothDownloadsStarted.Task;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsoluteUri == LatestReleaseEndpoint)
            {
                return Task.FromResult(Response(HttpStatusCode.OK, new StringContent(
                    releaseJson,
                    Encoding.UTF8,
                    "application/json")));
            }

            var content = new StreamContent(new GatedReadStream(this, downloadBytes));
            content.Headers.ContentLength = null;
            return Task.FromResult(Response(HttpStatusCode.OK, content));
        }

        private async Task WaitForBothReadersAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _startedReaders) == 2)
            {
                _bothDownloadsStarted.TrySetResult();
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        private sealed class GatedReadStream(GateDownloadHandler owner, byte[] bytes) : Stream
        {
            private bool _sent;

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => bytes.Length;
            public override long Position { get; set; }

            public override void Flush()
            {
            }

            public override async ValueTask<int> ReadAsync(
                Memory<byte> buffer,
                CancellationToken cancellationToken = default)
            {
                if (_sent)
                {
                    return 0;
                }

                await owner.WaitForBothReadersAsync(cancellationToken);
                bytes.AsSpan().CopyTo(buffer.Span);
                _sent = true;
                return bytes.Length;
            }

            public override int Read(byte[] buffer, int offset, int count)
                => throw new NotSupportedException();

            public override Task<int> ReadAsync(
                byte[] buffer,
                int offset,
                int count,
                CancellationToken cancellationToken)
                => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

            public override long Seek(long offset, SeekOrigin origin)
                => throw new NotSupportedException();

            public override void SetLength(long value)
                => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
                => throw new NotSupportedException();
        }
    }

    private sealed class BlockingReadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 0;
        public override long Position { get; set; }

        public override void Flush()
        {
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }

    private sealed class TestWorkspace : IDisposable
    {
        public TestWorkspace()
        {
            Root = Path.Combine(
                @"D:\ApfsAccessScratch\TestRuns\ApfsAccess.Tray.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public string CreateFile(string fileName, byte[] content)
        {
            var path = Path.Combine(Root, fileName);
            File.WriteAllBytes(path, content);
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
