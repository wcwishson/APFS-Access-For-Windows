using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace ApfsAccess.Backend.Native;

internal enum ContainerControlAction
{
    Attach,
    Detach,
}

internal sealed record ContainerControlResult(bool Success, string Code);

internal static class ContainerControlChannel
{
    private const string Protocol = "APFS-CONTROL/1";

    public static string CreateToken()
        => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    public static async Task<ContainerControlResult> SendAsync(
        string requestPath,
        string token,
        ContainerControlAction action,
        ulong volumeObjectId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        if (!IsLowerHex(token, 64) || volumeObjectId == 0 || timeout <= TimeSpan.Zero)
        {
            throw new ArgumentException("Container control endpoint arguments are invalid.");
        }

        var fullRequestPath = Path.GetFullPath(requestPath);
        var responsePath = fullRequestPath + ".response";
        EnsureSafeEndpoint(fullRequestPath, requireLeaf: false);
        EnsureSafeEndpoint(responsePath, requireLeaf: false);
        if (File.Exists(fullRequestPath) || File.Exists(responsePath))
        {
            return new ContainerControlResult(false, "ControlEndpointBusy");
        }

        var requestId = Guid.NewGuid().ToString("N");
        var actionName = action == ContainerControlAction.Attach ? "attach" : "detach";
        var contents = string.Join('\n',
            Protocol,
            requestId,
            token,
            actionName,
            volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture)) + "\n";
        var temporaryPath = fullRequestPath + ".tmp-" + Guid.NewGuid().ToString("N");
        var published = false;
        try
        {
            await using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                var bytes = Encoding.ASCII.GetBytes(contents);
                await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, fullRequestPath, overwrite: false);
            published = true;

            var startedAt = Stopwatch.GetTimestamp();
            while (Stopwatch.GetElapsedTime(startedAt) < timeout)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (File.Exists(responsePath))
                {
                    return ReadResponse(responsePath, requestId);
                }
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
            return new ContainerControlResult(false, "ControlResponseTimeout");
        }
        catch (OperationCanceledException) when (published)
        {
            // The owner may already have consumed the request. Return an
            // ambiguous failure so the caller contains the shared owner.
            return new ContainerControlResult(false, "ControlCanceledAfterPublish");
        }
        finally
        {
            DeleteEndpointBestEffort(temporaryPath);
            DeleteEndpointBestEffort(fullRequestPath);
            DeleteEndpointBestEffort(responsePath);
        }
    }

    public static void CleanupEndpoint(string? requestPath)
    {
        if (string.IsNullOrWhiteSpace(requestPath))
        {
            return;
        }
        DeleteEndpointBestEffort(requestPath);
        DeleteEndpointBestEffort(requestPath + ".response");
        var directory = Path.GetDirectoryName(requestPath);
        var prefix = Path.GetFileName(requestPath) + ".tmp-";
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return;
        }
        try
        {
            foreach (var path in Directory.EnumerateFiles(directory, prefix + "*", SearchOption.TopDirectoryOnly))
            {
                DeleteEndpointBestEffort(path);
            }
        }
        catch
        {
        }
    }

    private static ContainerControlResult ReadResponse(string responsePath, string requestId)
    {
        EnsureSafeEndpoint(responsePath, requireLeaf: true);
        var info = new FileInfo(responsePath);
        if (info.Length is <= 0 or > 512)
        {
            return new ContainerControlResult(false, "ControlResponseInvalid");
        }
        var fields = File.ReadAllLines(responsePath, Encoding.ASCII)
            .Select(static value => value.TrimEnd('\r'))
            .ToArray();
        if (fields.Length != 4 || fields[0] != Protocol || fields[1] != requestId ||
            (fields[2] != "ok" && fields[2] != "error") || !IsCode(fields[3]))
        {
            return new ContainerControlResult(false, "ControlResponseInvalid");
        }
        return new ContainerControlResult(fields[2] == "ok", fields[3]);
    }

    private static void EnsureSafeEndpoint(string path, bool requireLeaf)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath);
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(root) || string.IsNullOrWhiteSpace(directory))
        {
            throw new IOException("Container control endpoint must be absolute.");
        }
        for (var current = new DirectoryInfo(directory); current is not null; current = current.Parent)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Container control endpoint cannot traverse a reparse point.");
            }
            if (string.Equals(current.FullName, root, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
        }
        try
        {
            var attributes = File.GetAttributes(fullPath);
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            {
                throw new IOException("Container control endpoint leaf is unsafe.");
            }
        }
        catch (FileNotFoundException) when (!requireLeaf)
        {
        }
    }

    private static bool IsLowerHex(string value, int length)
        => value.Length == length && value.All(static ch =>
            ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCode(string value)
        => value.Length is > 0 and <= 64 && value.All(static ch =>
            ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');

    private static void DeleteEndpointBestEffort(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
        }
    }
}
