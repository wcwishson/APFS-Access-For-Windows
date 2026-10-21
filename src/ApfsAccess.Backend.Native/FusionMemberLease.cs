namespace ApfsAccess.Backend.Native;

// Atomic two-file lifecycle boundary for one Fusion member pair. Opens both
// members with read access and deny-write sharing in one operation: either
// both handles are held or neither is (failure opening the second releases
// the first). While held, overlapping writers fail at the OS with an
// IOException; readers may still share. Length + last-write time captured at
// acquire feed VerifyUnchanged, an advisory stale tripwire only: content
// identity, tier roles, and generations stay authoritative to the native bind
// (exact file identity re-verified at open). Dispose is idempotent and
// releases both handles; after disposal both files reopen exclusively,
// proving no leaked handle. This lease never interprets APFS bytes.
public sealed class FusionMemberLease : IDisposable
{
    private FileStream? _primary;
    private FileStream? _secondary;
    private bool _disposed;

    public string PrimaryPath { get; }

    public string SecondaryPath { get; }

    public long PrimaryLengthBytes { get; }

    public long SecondaryLengthBytes { get; }

    public DateTime PrimaryLastWriteTimeUtc { get; }

    public DateTime SecondaryLastWriteTimeUtc { get; }

    private FusionMemberLease(
        string primaryPath, string secondaryPath,
        FileStream primary, FileStream secondary)
    {
        PrimaryPath = primaryPath;
        SecondaryPath = secondaryPath;
        _primary = primary;
        _secondary = secondary;
        PrimaryLengthBytes = primary.Length;
        SecondaryLengthBytes = secondary.Length;
        PrimaryLastWriteTimeUtc = File.GetLastWriteTimeUtc(primaryPath);
        SecondaryLastWriteTimeUtc = File.GetLastWriteTimeUtc(secondaryPath);
    }

    public static bool TryAcquire(
        string primaryPath, string secondaryPath,
        out FusionMemberLease? lease, out string error)
    {
        lease = null;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(primaryPath) || string.IsNullOrWhiteSpace(secondaryPath))
        {
            error = "Fusion lease requires two member paths.";
            return false;
        }

        if (string.Equals(primaryPath, secondaryPath, StringComparison.OrdinalIgnoreCase))
        {
            error = "Fusion lease requires two distinct member paths.";
            return false;
        }

        FileStream? primary = null;
        FileStream? secondary = null;
        try
        {
            primary = new FileStream(
                primaryPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                secondary = new FileStream(
                    secondaryPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException or DirectoryNotFoundException)
            {
                error = $"Fusion lease failed on secondary member '{secondaryPath}': {ex.Message}";
                return false;
            }

            lease = new FusionMemberLease(primaryPath, secondaryPath, primary, secondary);
            primary = null;
            secondary = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException or DirectoryNotFoundException or ArgumentException)
        {
            error = $"Fusion lease failed on member '{primaryPath}': {ex.Message}";
            return false;
        }
        finally
        {
            // Atomicity: a half-open pair never escapes. Whichever handle did
            // not transfer to the lease is released here.
            primary?.Dispose();
            secondary?.Dispose();
        }
    }

    // Advisory stale tripwire: true when both files still match acquire-time
    // length and last-write time. Any I/O failure also reports changed (never
    // healthy on unreadable members).
    public bool VerifyUnchanged(out string error)
    {
        error = string.Empty;
        if (_disposed || _primary is null || _secondary is null)
        {
            error = "Fusion lease is released.";
            return false;
        }

        try
        {
            var primaryInfo = new FileInfo(PrimaryPath);
            var secondaryInfo = new FileInfo(SecondaryPath);
            if (!primaryInfo.Exists || !secondaryInfo.Exists ||
                primaryInfo.Length != PrimaryLengthBytes ||
                secondaryInfo.Length != SecondaryLengthBytes ||
                primaryInfo.LastWriteTimeUtc != PrimaryLastWriteTimeUtc ||
                secondaryInfo.LastWriteTimeUtc != SecondaryLastWriteTimeUtc)
            {
                error = "Fusion member files changed since lease acquisition.";
                return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = $"Fusion lease verification failed: {ex.Message}";
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _primary?.Dispose();
        _secondary?.Dispose();
        _primary = null;
        _secondary = null;
    }
}
