using System.Text;

namespace ApfsAccess.Backend.Native;

internal sealed class HostLifetimeSentinel : IDisposable
{
    private FileStream? _lease;

    private HostLifetimeSentinel(string filePath, FileStream lease)
    {
        FilePath = filePath;
        _lease = lease;
    }

    public string FilePath { get; }

    public static HostLifetimeSentinel Create(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);

        var lease = new FileStream(
            filePath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 4096,
            FileOptions.DeleteOnClose);
        try
        {
            lease.Write("alive"u8);
            lease.Flush();
            return new HostLifetimeSentinel(filePath, lease);
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _lease, null)?.Dispose();
    }
}

internal sealed class HostStartupGate : IDisposable
{
    private static readonly Encoding Utf8WithoutBom = new UTF8Encoding(false);
    private readonly object _sync = new();
    private bool _authorized;
    private bool _disposed;

    private HostStartupGate(string filePath, string authorizationToken)
    {
        FilePath = filePath;
        AuthorizationToken = authorizationToken;
    }

    public string FilePath { get; }

    public string AuthorizationToken { get; }

    public static HostStartupGate Create(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, $"startup_{Guid.NewGuid():N}.gate");
        var token = Guid.NewGuid().ToString("N");
        File.WriteAllText(path, "pending", Utf8WithoutBom);
        return new HostStartupGate(path, token);
    }

    public void Authorize()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_authorized)
            {
                return;
            }

            File.WriteAllText(FilePath, AuthorizationToken, Utf8WithoutBom);
            _authorized = true;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            if (_authorized)
            {
                return;
            }

            try
            {
                File.Delete(FilePath);
            }
            catch
            {
                // The child remains fail-closed on a pending or unreadable gate.
            }
        }
    }
}
