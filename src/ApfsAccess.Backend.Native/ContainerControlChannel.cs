using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

internal enum ContainerControlAction
{
    Attach,
    Activate,
    Detach,
    SnapshotCreate,
    SnapshotDelete,
    SnapshotRecover,
    SnapshotList,
    VolumeVerify,
    VolumeVerifyMetadata,
}

internal sealed record ContainerControlResult(bool Success, string Code, LiveSnapshotInventory? Inventory = null,
    LiveVolumeVerificationReport? VerificationReport = null);

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
        CancellationToken cancellationToken,
        IReadOnlyList<string>? extraLines = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        if (!IsLowerHex(token, 64) || volumeObjectId == 0 || timeout <= TimeSpan.Zero)
        {
            throw new ArgumentException("Container control endpoint arguments are invalid.");
        }

        var actionName = action switch
        {
            ContainerControlAction.Attach => "attach",
            ContainerControlAction.Activate => "activate",
            ContainerControlAction.Detach => "detach",
            ContainerControlAction.SnapshotCreate => "snapshot-create",
            ContainerControlAction.SnapshotDelete => "snapshot-delete",
            ContainerControlAction.SnapshotRecover => "snapshot-recover",
            ContainerControlAction.SnapshotList => "snapshot-list",
            ContainerControlAction.VolumeVerify => "volume-verify",
            ContainerControlAction.VolumeVerifyMetadata => "volume-verify-metadata",
            _ => throw new ArgumentException("Container control action is not supported."),
        };
        var extras = ValidateSnapshotExtras(action, extraLines);

        var fullRequestPath = Path.GetFullPath(requestPath);
        var responsePath = fullRequestPath + ".response";
        EnsureSafeEndpoint(fullRequestPath, requireLeaf: false);
        EnsureSafeEndpoint(responsePath, requireLeaf: false);
        if (File.Exists(fullRequestPath) || File.Exists(responsePath))
        {
            return new ContainerControlResult(false, "ControlEndpointBusy");
        }

        var requestId = Guid.NewGuid().ToString("N");
        var lines = new List<string>(capacity: 5 + extras.Count)
        {
            Protocol,
            requestId,
            token,
            actionName,
            volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };
        lines.AddRange(extras);
        var bytes = Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n");
        if (bytes.Length is <= 0 or > 512)
        {
            throw new ArgumentException("Container control request exceeds the 512-byte envelope.");
        }
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
                    try
                    {
                        return ReadResponse(responsePath, requestId, action, volumeObjectId);
                    }
                    catch (IOException ex) when ((ex.HResult & 0xffff) == 32)
                    {
                        // A transient sharing lock can outlive atomic response publication.
                    }
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

    // Mirrors the native envelope parser: attach/detach carry no extra lines,
    // snapshot-create carries exactly the name, snapshot-delete carries the
    // nine-field exact identity (xid, name, apsb, omap, omap-tree, root oid,
    // root block, extentref, source xid), and snapshot-recover carries none.
    // Physical inventory List carries the retained six-field source scope;
    // image List remains bare. The retained backend chooses the source profile.
    private static IReadOnlyList<string> ValidateSnapshotExtras(
        ContainerControlAction action, IReadOnlyList<string>? extraLines)
    {
        if (action == ContainerControlAction.Activate)
        {
            if (extraLines is not { Count: 2 } || extraLines[0].Length != 3 ||
                extraLines[0][0] is < 'A' or > 'Z' || extraLines[0][1] != ':' || extraLines[0][2] != '\\' ||
                extraLines[1] is not ("W" or "R"))
                throw new ArgumentException("Activation requires a current drive root and access mode.");
            return extraLines;
        }
        if (action is ContainerControlAction.VolumeVerify or ContainerControlAction.VolumeVerifyMetadata ||
            action == ContainerControlAction.SnapshotList && extraLines is { Count: > 0 })
        {
            if (extraLines is not { Count: 6 } || !IsLowerHex(extraLines[0], 32) || extraLines[0].All(c => c == '0') ||
                !IsLowerHex(extraLines[1], 32) || extraLines[1].All(c => c == '0') ||
                !IsCanonicalNonzeroDecimal(extraLines[2]) || !IsCanonicalNonzeroDecimal(extraLines[4]) ||
                !(extraLines[3] == "0" || IsCanonicalNonzeroDecimal(extraLines[3])) ||
                extraLines[5].Length is < 1 or > 192 || extraLines[5].Any(c => c is < '!' or > '~'))
                throw new ArgumentException("Retained inspection requires the exact held-source scope.");
            if (ulong.Parse(extraLines[4], System.Globalization.CultureInfo.InvariantCulture) >
                ulong.MaxValue - ulong.Parse(extraLines[3], System.Globalization.CultureInfo.InvariantCulture))
                throw new ArgumentException("Retained inspection window overflows.");
            return extraLines;
        }
        if (action is ContainerControlAction.Attach or ContainerControlAction.Detach)
        {
            if (extraLines is { Count: > 0 })
            {
                throw new ArgumentException("Container control action carries no extra lines.");
            }
            return Array.Empty<string>();
        }
        if (action is ContainerControlAction.SnapshotRecover or ContainerControlAction.SnapshotList)
        {
            if (extraLines is { Count: > 0 })
            {
                throw new ArgumentException("Snapshot recover/list carries no extra lines.");
            }
            return Array.Empty<string>();
        }
        if (action == ContainerControlAction.SnapshotCreate)
        {
            if (extraLines is not { Count: 1 } || !IsSnapshotName(extraLines[0]))
            {
                throw new ArgumentException("Snapshot create requires exactly one valid name line.");
            }
            return extraLines;
        }
        if (extraLines is not { Count: 9 } || !IsSnapshotName(extraLines[1]))
        {
            throw new ArgumentException("Snapshot delete requires the nine-line exact identity.");
        }
        foreach (var index in new[] { 0, 2, 3, 4, 5, 6, 7, 8 })
        {
            if (!IsCanonicalNonzeroDecimal(extraLines[index]))
            {
                throw new ArgumentException("Snapshot delete identity numbers must be canonical nonzero decimals.");
            }
        }
        return extraLines;
    }

    private static bool IsSnapshotName(string value)
        => value.Length is > 0 and <= 255 &&
            value.All(static ch => ch != '\0' && ch != '\r' && ch != '\n');

    private static bool IsCanonicalNonzeroDecimal(string value)
        => value.Length > 0 &&
            ulong.TryParse(value, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
            parsed != 0 &&
            parsed.ToString(System.Globalization.CultureInfo.InvariantCulture) == value;

    private static ContainerControlResult ReadResponse(string responsePath, string requestId,
        ContainerControlAction action, ulong volumeObjectId)
    {
        EnsureSafeEndpoint(responsePath, requireLeaf: true);
        using var stream = new FileStream(responsePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var maximum = action is ContainerControlAction.VolumeVerify or ContainerControlAction.VolumeVerifyMetadata ? LiveVolumeVerificationReport.MaximumResponseBytes :
            action == ContainerControlAction.SnapshotList ? LiveSnapshotInventory.MaximumResponseBytes : 512;
        if (stream.Length <= 0 || stream.Length > maximum)
        {
            return new ContainerControlResult(false, "ControlResponseInvalid");
        }
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
        string[] fields;
        try
        {
            var text = reader.ReadToEnd();
            if (text.EndsWith('\n')) text = text[..^1];
            fields = text.Split('\n').Select(static value => value.TrimEnd('\r')).ToArray();
        }
        catch (DecoderFallbackException) { return new(false, "ControlResponseInvalid"); }
        if (fields.Length is not (4 or 6) || fields[0] != Protocol || fields[1] != requestId ||
            (fields[2] != "ok" && fields[2] != "error") || !IsCode(fields[3]))
        {
            return new ContainerControlResult(false, "ControlResponseInvalid");
        }
        if (fields.Length == 4)
            return action is ContainerControlAction.SnapshotList or ContainerControlAction.VolumeVerify or ContainerControlAction.VolumeVerifyMetadata && fields[2] == "ok"
                ? new(false, "ControlResponseInvalid") : new(fields[2] == "ok", fields[3]);
        if (action is ContainerControlAction.VolumeVerify or ContainerControlAction.VolumeVerifyMetadata)
        {
            if (fields[2] != "ok" || fields[3] != "VolumeVerificationReport" || fields[4] != "volume-verification-json/1")
                return new(false, "ControlResponseInvalid");
            try
            {
                using var document = JsonDocument.Parse(fields[5]);
                var report = LiveVolumeVerificationReport.Parse(document.RootElement);
                return report.Scope.VolumeOid == volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    ? new(true, fields[3], VerificationReport: report) : new(false, "ControlResponseInvalid");
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            { return new(false, "ControlResponseInvalid"); }
        }
        if (action != ContainerControlAction.SnapshotList || fields[2] != "ok" || fields[3] != "SnapshotInventory" ||
            fields[4] != "snapshot-inventory-json/1") return new(false, "ControlResponseInvalid");
        try
        {
            using var document = JsonDocument.Parse(fields[5]);
            var inventory = LiveSnapshotInventory.Parse(document.RootElement);
            if (inventory.VolumeOid != volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture))
                return new(false, "ControlResponseInvalid");
            return new(true, fields[3], inventory);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        { return new(false, "ControlResponseInvalid"); }
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
