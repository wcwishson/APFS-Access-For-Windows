using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace ApfsAccess.Tray;

public sealed class GitHubReleaseUpdateClient : IAppUpdateClient, IDisposable
{
    public const string LatestReleaseEndpoint =
        "https://api.github.com/repos/wcwishson/APFS-Access-For-Windows/releases/latest";
    public const string ExpectedAssetName = "APFS.Access.exe";
    public const string ProductUserAgent = "APFSAccessPortable/1.0";
    public const long MaximumDownloadBytes = 512L * 1024L * 1024L;
    public const long MaximumReleaseResponseBytes = 1L * 1024L * 1024L;

    private const int MaximumRedirects = 5;
    private const int BufferSize = 64 * 1024;

    private readonly HttpClient _httpClient;
    private readonly long _maximumDownloadBytes;
    private readonly HttpClientHandler? _productionHandler;

    public GitHubReleaseUpdateClient()
        : this(CreateProductionTransport(), MaximumDownloadBytes)
    {
    }

    internal GitHubReleaseUpdateClient(
        HttpMessageHandler handler,
        long maximumDownloadBytes = MaximumDownloadBytes,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ValidateMaximumDownloadBytes(maximumDownloadBytes);

        _httpClient = new HttpClient(handler, disposeHandler: false);
        if (timeout.HasValue)
        {
            _httpClient.Timeout = timeout.Value;
        }

        _maximumDownloadBytes = maximumDownloadBytes;
    }

    private GitHubReleaseUpdateClient(
        ProductionTransport transport,
        long maximumDownloadBytes)
    {
        ValidateMaximumDownloadBytes(maximumDownloadBytes);

        _productionHandler = transport.Handler;
        _httpClient = transport.Client;
        _maximumDownloadBytes = maximumDownloadBytes;
    }

    internal HttpClientHandler ProductionHandler
        => _productionHandler ?? throw new InvalidOperationException(
            "The injected test transport does not have a production handler.");

    public void Dispose()
        => _httpClient.Dispose();

    private static ProductionTransport CreateProductionTransport()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
        };

        return new ProductionTransport(
            handler,
            new HttpClient(handler, disposeHandler: true));
    }

    private static void ValidateMaximumDownloadBytes(long maximumDownloadBytes)
    {
        if (maximumDownloadBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDownloadBytes));
        }
    }

    public async Task<AppUpdateCheckResult> CheckAndDownloadAsync(
        string launcherPath,
        Version currentVersion,
        IProgress<AppUpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (!TryResolveLauncherPath(launcherPath, out var fullLauncherPath))
        {
            return Failure("The current launcher could not be identified.");
        }

        if (currentVersion is null)
        {
            return Failure("The current application version is invalid.");
        }

        try
        {
            var currentSha256 = await ComputeSha256Async(fullLauncherPath, cancellationToken).ConfigureAwait(false);

            using var releaseResponse = await SendGetAsync(
                new Uri(LatestReleaseEndpoint, UriKind.Absolute),
                cancellationToken).ConfigureAwait(false);
            if (!releaseResponse.IsSuccessStatusCode)
            {
                return Failure("The latest release could not be retrieved.");
            }

            using var releaseDocument = await ReadBoundedJsonAsync(
                releaseResponse.Content,
                cancellationToken).ConfigureAwait(false);
            string? releaseError = null;
            AppUpdateRelease? release = null;
            var releaseIsValid = releaseDocument is not null && TryParseRelease(
                releaseDocument.RootElement,
                _maximumDownloadBytes,
                out release,
                out releaseError);
            if (!releaseIsValid)
            {
                return Failure(releaseError ?? "The latest release metadata is invalid.");
            }

            var comparison = CompareSemanticVersion(release!.Version, currentVersion);
            if (comparison < 0 || (comparison == 0 &&
                                   string.Equals(currentSha256, release.Sha256, StringComparison.OrdinalIgnoreCase)))
            {
                return new AppUpdateCheckResult(
                    AppUpdateDecision.UpToDate,
                    release,
                    Error: null);
            }

            var readyPath = GetReadyPath(fullLauncherPath);
            if (await IsVerifiedReadyFileAsync(
                    readyPath,
                    release,
                    cancellationToken).ConfigureAwait(false))
            {
                return new AppUpdateCheckResult(
                    AppUpdateDecision.Ready,
                    release,
                    new AppUpdateDownload(release, readyPath, fullLauncherPath, currentSha256));
            }

            return await DownloadAndStageAsync(
                release,
                fullLauncherPath,
                currentSha256,
                readyPath,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        catch (IncompleteStagingCleanupException)
        {
            return Failure(
                "The incomplete update file could not be removed. Close any program using it and retry.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Failure("The update check was canceled.");
        }
        catch (TaskCanceledException)
        {
            return Failure("The update request timed out.");
        }
        catch (HttpRequestException)
        {
            return Failure("The update request failed.");
        }
        catch (JsonException)
        {
            return Failure("The update metadata is invalid.");
        }
        catch (IOException)
        {
            return Failure("The update files could not be read or written.");
        }
        catch (UnauthorizedAccessException)
        {
            return Failure("The update files could not be accessed.");
        }
        catch (Exception)
        {
            return Failure("The update could not be completed.");
        }
    }

    private async Task<AppUpdateCheckResult> DownloadAndStageAsync(
        AppUpdateRelease release,
        string launcherPath,
        string currentSha256,
        string readyPath,
        IProgress<AppUpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(launcherPath);
        var fileName = Path.GetFileName(launcherPath);
        if (string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(fileName))
        {
            return Failure("The launcher directory could not be identified.");
        }

        var stagingPath = Path.Combine(
            directory,
            $".{fileName}.update.{Guid.NewGuid():N}.download");

        try
        {
            using var response = await SendGetAsync(release.DownloadUrl, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return Failure("The update asset could not be retrieved.");
            }

            var declaredLength = response.Content.Headers.ContentLength;
            if (declaredLength.HasValue && declaredLength.Value != release.Size)
            {
                return Failure("The downloaded asset size does not match its release metadata.");
            }

            if (declaredLength.HasValue && declaredLength.Value > _maximumDownloadBytes)
            {
                return Failure("The downloaded asset is too large.");
            }

            await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
            await using (var destination = new FileStream(
                stagingPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var buffer = new byte[BufferSize];
                long received = 0;
                progress?.Report(new AppUpdateProgress(0, release.Size));

                int read;
                while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
                {
                    received += read;
                    if (received > release.Size || received > _maximumDownloadBytes)
                    {
                        return Failure("The downloaded asset is too large.");
                    }

                    hash.AppendData(buffer, 0, read);
                    await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    progress?.Report(new AppUpdateProgress(received, release.Size));
                }

                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
                destination.Flush(flushToDisk: true);

                if (received != release.Size)
                {
                    return Failure("The downloaded asset is incomplete.");
                }

                var actualSha256 = Convert.ToHexString(hash.GetHashAndReset());
                if (!string.Equals(actualSha256, release.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return Failure("The downloaded asset failed verification.");
                }
            }

            File.Move(stagingPath, readyPath);
            stagingPath = string.Empty;

            return new AppUpdateCheckResult(
                AppUpdateDecision.Ready,
                release,
                new AppUpdateDownload(release, readyPath, launcherPath, currentSha256));
        }
        finally
        {
            if (!string.IsNullOrEmpty(stagingPath))
            {
                DeleteIncompleteFile(stagingPath);
            }
        }
    }

    private async Task<bool> IsVerifiedReadyFileAsync(
        string readyPath,
        AppUpdateRelease release,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(readyPath))
        {
            return false;
        }

        if (new FileInfo(readyPath).Length != release.Size)
        {
            File.Delete(readyPath);
            return false;
        }

        var readySha256 = await ComputeSha256Async(readyPath, cancellationToken).ConfigureAwait(false);
        if (string.Equals(readySha256, release.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        File.Delete(readyPath);
        return false;
    }

    private async Task<HttpResponseMessage> SendGetAsync(Uri uri, CancellationToken cancellationToken)
    {
        var currentUri = uri;
        for (var redirectCount = 0; ; redirectCount++)
        {
            if (!IsHttps(currentUri))
            {
                throw new InvalidDataException("Only HTTPS update URLs are accepted.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            request.Headers.UserAgent.ParseAdd(ProductUserAgent);
            var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            if (!IsRedirect(response.StatusCode))
            {
                if (response.RequestMessage?.RequestUri is Uri finalUri && !IsHttps(finalUri))
                {
                    response.Dispose();
                    throw new InvalidDataException("Only HTTPS update redirects are accepted.");
                }

                return response;
            }

            var location = response.Headers.Location;
            response.Dispose();
            if (location is null || redirectCount >= MaximumRedirects)
            {
                throw new InvalidDataException("The update redirect chain is invalid.");
            }

            var redirectUri = new Uri(currentUri, location);
            if (!IsHttps(redirectUri))
            {
                throw new InvalidDataException("Only HTTPS update redirects are accepted.");
            }

            currentUri = redirectUri;
        }
    }

    private static async Task<JsonDocument?> ReadBoundedJsonAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumReleaseResponseBytes)
        {
            return null;
        }

        await using var source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[BufferSize];
        long total = 0;

        int read;
        while ((read = await source.ReadAsync(chunk.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > MaximumReleaseResponseBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return JsonDocument.Parse(buffer.ToArray());
    }

    private static bool TryParseRelease(
        JsonElement root,
        long maximumDownloadBytes,
        out AppUpdateRelease release,
        out string? error)
    {
        release = null!;
        error = null;

        if (root.ValueKind != JsonValueKind.Object ||
            !TryGetBoolean(root, "draft", out var draft) ||
            !TryGetBoolean(root, "prerelease", out var prerelease))
        {
            error = "The latest release metadata is incomplete.";
            return false;
        }

        if (draft || prerelease)
        {
            error = "Draft and prerelease releases are not eligible.";
            return false;
        }

        if (!TryGetString(root, "tag_name", out var tag) || !TryParseVersionTag(tag, out var version))
        {
            error = "The latest release tag is invalid.";
            return false;
        }

        if (!TryGetHttpsUri(root, "html_url", out var releasePage))
        {
            error = "The release page URL is invalid.";
            return false;
        }

        if (!root.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
        {
            error = "The release assets are invalid.";
            return false;
        }

        var matchingAssets = new List<JsonElement>();
        foreach (var asset in assets.EnumerateArray())
        {
            if (asset.ValueKind != JsonValueKind.Object || !TryGetString(asset, "name", out var name))
            {
                error = "The release assets are invalid.";
                return false;
            }

            if (string.Equals(name, ExpectedAssetName, StringComparison.Ordinal))
            {
                matchingAssets.Add(asset);
            }
        }

        if (matchingAssets.Count != 1)
        {
            error = "The release must contain exactly one portable asset.";
            return false;
        }

        var matchingAsset = matchingAssets[0];
        if (!TryGetHttpsUri(matchingAsset, "browser_download_url", out var downloadUrl) ||
            !TryGetInt64(matchingAsset, "size", out var size) ||
            size <= 0 ||
            size > maximumDownloadBytes ||
            !TryGetString(matchingAsset, "digest", out var digest) ||
            !TryNormalizeSha256(digest, out var sha256))
        {
            error = "The portable asset metadata is invalid.";
            return false;
        }

        release = new AppUpdateRelease(version, tag, releasePage, downloadUrl, size, sha256);
        return true;
    }

    private static bool TryParseVersionTag(string tag, out Version version)
    {
        version = null!;
        if (string.IsNullOrEmpty(tag) || tag[0] != 'v')
        {
            return false;
        }

        var components = tag[1..].Split('.', StringSplitOptions.None);
        if (components.Length != 3)
        {
            return false;
        }

        var numbers = new int[3];
        for (var index = 0; index < components.Length; index++)
        {
            var component = components[index];
            if (component.Length == 0 ||
                (component.Length > 1 && component[0] == '0') ||
                !int.TryParse(component, NumberStyles.None, CultureInfo.InvariantCulture, out numbers[index]))
            {
                return false;
            }
        }

        version = new Version(numbers[0], numbers[1], numbers[2]);
        return true;
    }

    private static int CompareSemanticVersion(Version left, Version right)
    {
        var comparison = left.Major.CompareTo(right.Major);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = left.Minor.CompareTo(right.Minor);
        if (comparison != 0)
        {
            return comparison;
        }

        var leftPatch = Math.Max(left.Build, 0);
        var rightPatch = Math.Max(right.Build, 0);
        comparison = leftPatch.CompareTo(rightPatch);
        if (comparison != 0)
        {
            return comparison;
        }

        var leftRevision = Math.Max(left.Revision, 0);
        var rightRevision = Math.Max(right.Revision, 0);
        return leftRevision.CompareTo(rightRevision);
    }

    private static bool TryNormalizeSha256(string value, out string sha256)
    {
        sha256 = string.Empty;
        const string prefix = "sha256:";
        if (value.Length != prefix.Length + 64 ||
            !value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var hex = value[prefix.Length..];
        foreach (var character in hex)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        sha256 = hex.ToUpperInvariant();
        return true;
    }

    private static bool TryGetString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var candidate = property.GetString();
        if (string.IsNullOrEmpty(candidate))
        {
            return false;
        }

        value = candidate;
        return true;
    }

    private static bool TryGetBoolean(JsonElement element, string propertyName, out bool value)
    {
        value = false;
        if (!element.TryGetProperty(propertyName, out var property) ||
            (property.ValueKind != JsonValueKind.True && property.ValueKind != JsonValueKind.False))
        {
            return false;
        }

        value = property.GetBoolean();
        return true;
    }

    private static bool TryGetInt64(JsonElement element, string propertyName, out long value)
    {
        value = 0;
        return element.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.Number &&
               property.TryGetInt64(out value);
    }

    private static bool TryGetHttpsUri(JsonElement element, string propertyName, out Uri uri)
    {
        uri = null!;
        if (!TryGetString(element, propertyName, out var value) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var candidate) ||
            !IsHttps(candidate))
        {
            return false;
        }

        uri = candidate;
        return true;
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferSize];

        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static bool TryResolveLauncherPath(string launcherPath, out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(launcherPath) || !Path.IsPathFullyQualified(launcherPath))
        {
            return false;
        }

        try
        {
            fullPath = Path.GetFullPath(launcherPath);
            return File.Exists(fullPath) && !string.IsNullOrWhiteSpace(Path.GetFileName(fullPath));
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static string GetReadyPath(string launcherPath)
    {
        var directory = Path.GetDirectoryName(launcherPath)!;
        var fileName = Path.GetFileName(launcherPath);
        return Path.Combine(directory, $".{fileName}.update.ready");
    }

    private static bool IsHttps(Uri uri)
        => uri.IsAbsoluteUri && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static bool IsRedirect(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.Moved or
            HttpStatusCode.Found or
            HttpStatusCode.SeeOther or
            HttpStatusCode.TemporaryRedirect or
            HttpStatusCode.PermanentRedirect;

    private static AppUpdateCheckResult Failure(string message)
        => new(AppUpdateDecision.Failed, Error: message);

    private static void DeleteIncompleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new IncompleteStagingCleanupException(ex);
        }
    }

    private sealed class IncompleteStagingCleanupException(Exception innerException)
        : Exception("The incomplete staging file could not be deleted.", innerException);

    private sealed record ProductionTransport(HttpClientHandler Handler, HttpClient Client);
}
