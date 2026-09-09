using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

/// <summary>Reads validated snapshot inventory from a packaged, read-only native observer.</summary>
public sealed class NativeApfsSnapshotReader
{
    private readonly IObserverRunner runner;
    private readonly string? observerPath;

    public NativeApfsSnapshotReader() : this(new ProcessObserverRunner(), ResolvePackagedObserver()) { }

    internal NativeApfsSnapshotReader(IObserverRunner runner, string? observerPath)
    {
        this.runner = runner;
        this.observerPath = observerPath;
    }

    private static string? ResolvePackagedObserver()
        => new[] { Path.Combine(AppContext.BaseDirectory, NativeApfsObserver.ObserverExeName),
            Path.Combine(AppContext.BaseDirectory, "native", NativeApfsObserver.ObserverExeName) }
            .FirstOrDefault(path => File.Exists(path) && NativeApfsObserver.IsPackagedObserverPath(path));

    public static void ValidateRequest(string image, string containerId, string volumeOid)
    {
        if (!ApfsTopology.TryParseContainerId(containerId, out var hex) ||
            containerId != ApfsTopology.BuildContainerId(hex) || hex.All(c => c == '0') ||
            !IsU64(volumeOid, false))
            throw new ArgumentException("An exact canonical apfs-container:lowercase32hex and nonzero decimal volume OID are required.");
        ValidateLocalFile(image);
    }

    private static void ValidateLocalFile(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Length < 4 || !char.IsAsciiLetter(path[0]) ||
            path[1] != ':' || path[2] is not ('\\' or '/') || path[2..].Contains(':') ||
            path.Contains('\0') || !Path.IsPathFullyQualified(path) ||
            path[3..].Split(['\\', '/']).Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new ArgumentException("Use an absolute regular local image path without device, UNC, ADS, or alias syntax.");
        if (!File.Exists(path) || (File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0)
            throw new ArgumentException("The image must be an existing regular local file.");
        for (var dir = new FileInfo(path).Directory; dir is not null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new ArgumentException("Reparse paths are not supported for snapshot inventory.");
        if (new DriveInfo(Path.GetPathRoot(path)!).DriveType == DriveType.Network)
            throw new ArgumentException("Network images are not supported.");
        _ = new UTF8Encoding(false, true).GetBytes(path);
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        ValidateIdentity(handle, path);
    }

    private static void ValidateIdentity(SafeFileHandle handle, string path)
    {
        var resolved = new StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, resolved, (uint)resolved.Capacity, 0);
        if (length == 0 || length >= resolved.Capacity)
            throw new IOException("Cannot establish the image's local file identity.");
        if (!string.Equals(resolved.ToString(), @"\\?\" + Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Use the resolved local file path, without short-name or reparse aliases.");
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);

    public JsonElement Read(string image, string containerId, string volumeOid, CancellationToken cancellationToken = default)
    {
        ValidateRequest(image, containerId, volumeOid);
        if (observerPath is null) throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        ValidateLocalFile(observerPath);
        // Keep a read-only sharing lease throughout hashing and native observation.
        using var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
        ValidateIdentity(source.SafeFileHandle, image);
        cancellationToken.ThrowIfCancellationRequested();
        var hash = Convert.ToHexStringLower(SHA256.HashDataAsync(source, cancellationToken).GetAwaiter().GetResult());
        var result = runner.Run(observerPath, ["--image", image, "--mode", "snapshots",
            "--container-uuid", containerId[15..], "--volume-oid", volumeOid], cancellationToken);
        if (result.ExitCode != 0)
            throw new InvalidDataException($"Native snapshot inventory refused (exit {result.ExitCode}): {result.StandardError}");
        var inventory = ParseInventory(result.StandardOutput, image, containerId, volumeOid, source.Length, hash);
        // FileShare.Read excludes writers and replacement until this lease closes;
        // ParseInventory also requires the native full-source hash to agree.
        cancellationToken.ThrowIfCancellationRequested();
        return inventory;
    }

    internal static bool IsU64(string? text, bool zero = true)
        => text is { Length: > 0 } && (text.Length == 1 || text[0] != '0') &&
            text.All(char.IsAsciiDigit) && ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && (zero || value != 0);

    internal static JsonElement ParseInventory(string json, string image, string containerId, string oid, long size, string hash)
    {
        try
        {
            // Also protect injected runners: JsonDocument's string overload can
            // otherwise replace an unpaired UTF-16 surrogate while encoding it.
            _ = new UTF8Encoding(false, true).GetByteCount(json);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            CheckObject(root, "format version readOnly source containerUuid volumeUuid volumeId volumeOid checkpointXid storeOffsetBytes storeSizeBytes snapshots");
            Require(Text(root, "format") == "apfs-access-snapshot-inventory" && root.GetProperty("version").GetInt32() == 1 && root.GetProperty("readOnly").ValueKind == JsonValueKind.True);
            Require(Text(root, "containerUuid") == containerId[15..] && Text(root, "volumeOid") == oid &&
                Text(root, "volumeId") == $"apfs-vol:{containerId[15..]}:{oid}");
            Hex(Text(root, "containerUuid")); Hex(Text(root, "volumeUuid"));
            Number(root, "volumeOid", false); Number(root, "checkpointXid", false);
            var offset = Number(root, "storeOffsetBytes"); var storeSize = Number(root, "storeSizeBytes", false);
            Require(offset <= (ulong)size && storeSize <= (ulong)size - offset);
            var source = root.GetProperty("source");
            CheckObject(source, "kind path sizeBytes hashScope sha256");
            Require(Text(source, "kind") == "image" && Text(source, "hashScope") == "full" &&
                string.Equals(Path.GetFullPath(Text(source, "path")), Path.GetFullPath(image), StringComparison.OrdinalIgnoreCase) &&
                source.GetProperty("sizeBytes").GetInt64() == size && Text(source, "sha256") == hash);
            var snapshots = root.GetProperty("snapshots"); Require(snapshots.ValueKind == JsonValueKind.Array);
            var xids = new HashSet<string>(StringComparer.Ordinal);
            var names = new HashSet<string>(StringComparer.Ordinal);
            var uuids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var snapshot in snapshots.EnumerateArray())
            {
                CheckObject(snapshot, "xid name uuid createTimeNs superblockPhysicalBlock omapPhysicalBlock omapTreePhysicalBlock rootOid rootPhysicalBlock extentrefPhysicalBlock", "uuid");
                Number(snapshot, "xid", false);
                Require(xids.Add(Text(snapshot, "xid")) && names.Add(Text(snapshot, "name")) && Text(snapshot, "name").Length > 0 && !Text(snapshot, "name").Contains('\0'));
                Number(snapshot, "createTimeNs");
                foreach (var key in new[] { "superblockPhysicalBlock", "omapPhysicalBlock", "omapTreePhysicalBlock", "rootOid", "rootPhysicalBlock", "extentrefPhysicalBlock" }) Number(snapshot, key, false);
                if (snapshot.TryGetProperty("uuid", out var uuid) && uuid.ValueKind != JsonValueKind.Null)
                { var value = uuid.GetString()!; Hex(value); Require(uuids.Add(value)); }
            }
            return root.Clone();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or KeyNotFoundException)
        { throw new InvalidDataException("Native observer returned invalid or mismatched snapshot inventory.", ex); }
    }

    private static string Text(JsonElement element, string key)
    {
        var text = element.GetProperty(key).GetString() ?? throw new InvalidDataException("Null inventory string.");
        // Literal U+FFFD is valid. Malformed wire UTF-8 is rejected by the runner.
        _ = new UTF8Encoding(false, true).GetBytes(text);
        return text;
    }
    private static ulong Number(JsonElement element, string key, bool zero = true)
    { var text = Text(element, key); Require(IsU64(text, zero)); return ulong.Parse(text, CultureInfo.InvariantCulture); }
    private static void Hex(string value)
        => Require(value.Length == 32 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') && value.Any(c => c != '0'));
    private static void Require(bool condition)
    { if (!condition) throw new InvalidDataException("Native observer returned invalid or mismatched snapshot inventory."); }
    private static void CheckObject(JsonElement element, string fields, string? optional = null)
    {
        Require(element.ValueKind == JsonValueKind.Object);
        var expected = fields.Split(' ').ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject()) Require(expected.Contains(property.Name) && seen.Add(property.Name));
        Require(expected.All(key => key == optional || seen.Contains(key)));
    }
}
