namespace ApfsAccess.Tray;

public enum AppUpdateDecision
{
    UpToDate,
    Ready,
    Failed,
}

public sealed record AppUpdateRelease(
    Version Version,
    string Tag,
    Uri ReleasePage,
    Uri DownloadUrl,
    long Size,
    string Sha256);

public sealed record AppUpdateDownload(
    AppUpdateRelease Release,
    string ReadyPath,
    string LauncherPath,
    string CurrentSha256);

public sealed record AppUpdateProgress(long BytesReceived, long TotalBytes)
{
    public int Percentage
    {
        get
        {
            if (TotalBytes <= 0)
            {
                return BytesReceived <= 0 ? 0 : 100;
            }

            var percentage = (decimal)BytesReceived * 100m / TotalBytes;
            return (int)Math.Clamp(percentage, 0m, 100m);
        }
    }
}

public sealed record AppUpdateCheckResult(
    AppUpdateDecision Decision,
    AppUpdateRelease? Release = null,
    AppUpdateDownload? Download = null,
    string? Error = null);

public interface IAppUpdateClient
{
    Task<AppUpdateCheckResult> CheckAndDownloadAsync(
        string launcherPath,
        Version currentVersion,
        IProgress<AppUpdateProgress>? progress,
        CancellationToken cancellationToken);
}
