using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Security;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Core;

/// <summary>Preferences keyed only by APFS volume UUIDs from an authoritative catalog snapshot.</summary>
public sealed class VolumeDriveLetterAssignments
{
    private readonly string _path;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> SettingsGates = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _settingsGate;
    private Dictionary<Guid, char>? _committedState;
    private readonly object _catalogLock = new();
    private Dictionary<string, Guid> _catalog = new(StringComparer.Ordinal);
    private bool _requireVolumeUuid;

    public VolumeDriveLetterAssignments(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _settingsGate = SettingsGates.GetOrAdd(_path, _ => new SemaphoreSlim(1, 1));
    }

    /// <summary>Replace the complete discovery snapshot; ambiguous IDs and UUIDs are ineligible.</summary>
    public void UpdateCatalog(IEnumerable<ApfsVolumeRecord> volumes)
    {
        ArgumentNullException.ThrowIfNull(volumes);
        ReplaceCatalog(volumes.Select(v => (Id: (string?)v.Id, Uuid: (string?)v.Uuid)).ToArray(), requireVolumeUuid: false);
    }

    /// <summary>Replace all runtime associations, including clearing disconnected volumes.</summary>
    public void UpdateDiscovery(IEnumerable<VolumeInfo> volumes)
    {
        ArgumentNullException.ThrowIfNull(volumes);
        ReplaceCatalog(volumes.Select(v => (Id: v.CatalogVolumeId, Uuid: v.CatalogVolumeUuid)).ToArray(),
            requireVolumeUuid: true);
    }

    private void ReplaceCatalog((string? Id, string? Uuid)[] records, bool requireVolumeUuid)
    {
        var duplicateIds = records.GroupBy(v => v.Id).Where(g => g.Count() != 1)
            .Select(g => g.Key).ToHashSet(StringComparer.Ordinal);
        var uuids = records.Select(v => TryUuid(v.Uuid, out var uuid) ? uuid : Guid.Empty).ToArray();
        var duplicateUuids = uuids.GroupBy(uuid => uuid).Where(g => g.Count() != 1)
            .Select(g => g.Key).ToHashSet();
        var catalog = new Dictionary<string, Guid>(StringComparer.Ordinal);
        for (var i = 0; i < records.Length; i++)
        {
            var record = records[i];
            if (uuids[i] != Guid.Empty && !duplicateUuids.Contains(uuids[i]) &&
                record.Id is not null && !duplicateIds.Contains(record.Id) &&
                ApfsTopology.TryParseVolumeId(record.Id, out _, out var objectId) && objectId != 0)
            {
                catalog.Add(record.Id, uuids[i]);
            }
        }

        lock (_catalogLock)
        {
            _catalog = catalog;
            _requireVolumeUuid = requireVolumeUuid;
        }
    }

    public bool TryResolveUuid(VolumeInfo volume, out Guid uuid)
    {
        lock (_catalogLock)
        {
            uuid = Guid.Empty;
            return volume.CatalogVolumeId is not null && _catalog.TryGetValue(volume.CatalogVolumeId, out uuid) &&
                (!_requireVolumeUuid || (TryUuid(volume.CatalogVolumeUuid, out var actual) && actual == uuid));
        }
    }

    public bool TryGetPreference(Guid uuid, out char? letter, CancellationToken cancellationToken = default)
    {
        char? value = null;
        var success = WithState(state => { if (state.TryGetValue(uuid, out var saved)) value = saved; return false; }, cancellationToken);
        letter = value;
        return success;
    }

    internal char Select(VolumeInfo volume, char[] pool, IReadOnlySet<char> occupied, char fallback)
    {
        return TryResolveUuid(volume, out var uuid) ? Select(uuid, pool, occupied, fallback, CancellationToken.None) : fallback;
    }

    internal char Select(Guid uuid, char[] pool, IReadOnlySet<char> occupied, char fallback, CancellationToken cancellationToken)
    {
        var selected = fallback;
        WithState(state =>
        {
            if (state.TryGetValue(uuid, out var preferred))
            {
                if (pool.Contains(preferred) && !occupied.Contains(preferred)) selected = preferred;
                return false; // A temporary collision or pool change never replaces the preference.
            }

            state.Add(uuid, fallback);
            return true;
        }, cancellationToken);
        return selected;
    }

    // Publication under the mount lock may only inspect the last completed read/commit.
    internal bool TryGetCachedPreference(Guid uuid, out char? letter)
    {
        var state = Volatile.Read(ref _committedState);
        letter = state is not null && state.TryGetValue(uuid, out var saved) ? saved : null;
        return state is not null;
    }

    /// <summary>Persist an explicit user choice for an actual APFS volume UUID.</summary>
    public bool SetPreference(Guid volumeUuid, char letter)
        => SetPreference(volumeUuid, letter, CancellationToken.None);

    public bool SetPreference(Guid volumeUuid, char letter, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        letter = char.ToUpperInvariant(letter);
        if (volumeUuid == Guid.Empty || letter is < 'A' or > 'Z') return false;
        return WithState(state => { state[volumeUuid] = letter; return true; }, cancellationToken);
    }

    private bool WithState(Func<Dictionary<Guid, char>, bool> update, CancellationToken cancellationToken = default)
    {
        // Coordinate our own readers/writers before attempting the exclusive filesystem
        // lease. External/stale leases still fail conservatively. Callers doing I/O must
        // wait here outside the worker's global mount-operation lock.
        _settingsGate.Wait(cancellationToken);
        try
        {
            var success = WithLeasedState(update, cancellationToken);
            if (!success) Volatile.Write(ref _committedState, null);
            return success;
        }
        finally { _settingsGate.Release(); }
    }

    private bool WithLeasedState(Func<Dictionary<Guid, char>, bool> update, CancellationToken cancellationToken)
    {
        // Do not create directories through a potentially redirected path. The service owns
        // creation of its durable runtime directory. Pin every ancestor against rename on Windows.
        var directories = new List<SafeFileHandle>();
        string? temporary = null;
        try
        {
            if (!OperatingSystem.IsWindows()) return false;
            var directory = Path.GetDirectoryName(_path)!;
            var ancestors = new Stack<string>();
            for (var current = new DirectoryInfo(directory); current is not null; current = current.Parent)
                ancestors.Push(current.FullName);
            foreach (var ancestor in ancestors)
            {
                cancellationToken.ThrowIfCancellationRequested();
                directories.Add(OpenChecked(ancestor, directory: true));
            }

            // Exclusive creation avoids opening a redirected lock file. A stale lock disables
            // persistence conservatively; no stale snapshot is ever written by another instance.
            using var lease = new FileStream(_path + ".lock", FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 1, FileOptions.DeleteOnClose);
            var state = new Dictionary<Guid, char>();
            try
            {
                using var handle = OpenChecked(_path, directory: false);
                using var stream = new FileStream(handle, FileAccess.Read);
                if (stream.Length > 1024 * 1024) return false;
                using var json = JsonDocument.Parse(stream);
                if (json.RootElement.ValueKind != JsonValueKind.Object) return false;
                foreach (var entry in json.RootElement.EnumerateObject())
                {
                    if (!TryUuid(entry.Name, out var uuid) || entry.Value.ValueKind != JsonValueKind.String)
                        return false;
                    var value = entry.Value.GetString();
                    if (value is null || value.Length != 1) return false;
                    var letter = char.ToUpperInvariant(value[0]);
                    if (letter is < 'A' or > 'Z' || !state.TryAdd(uuid, letter)) return false;
                }
            }
            catch (FileNotFoundException) { }

            cancellationToken.ThrowIfCancellationRequested();
            if (!update(state))
            {
                Volatile.Write(ref _committedState, new Dictionary<Guid, char>(state));
                return true;
            }
            temporary = Path.Combine(directory, $".drive-letters-{Guid.NewGuid():N}.tmp");
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, state.ToDictionary(p => p.Key.ToString("D"), p => p.Value.ToString()));
                stream.Flush(flushToDisk: true);
            }

            // Rename replaces the directory entry, never writes through a destination symlink
            // or hard link. Pinned ancestors keep both names inside the checked directory.
            // Last cancellable point. Once rename starts, return its result even if
            // the token expires: cancellation is not a rollback of an atomic commit.
            // Windows synchronous open/flush/rename cannot be bounded by this token;
            // the service awaits this operation outside its global mount lock.
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporary, _path, overwrite: true);
            temporary = null;
            Volatile.Write(ref _committedState, new Dictionary<Guid, char>(state));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or JsonException)
        {
            Volatile.Write(ref _committedState, null);
            return false;
        }
        finally
        {
            if (temporary is not null)
            {
                try { File.Delete(temporary); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            foreach (var handle in directories) handle.Dispose();
        }
    }

    private static bool TryUuid(string? text, out Guid uuid)
    {
        uuid = Guid.Empty;
        return (Guid.TryParseExact(text, "D", out uuid) || Guid.TryParseExact(text, "N", out uuid)) && uuid != Guid.Empty;
    }

    private static SafeFileHandle OpenChecked(string path, bool directory)
    {
        var handle = CreateFileW(path, directory ? 0u : 0x80000000u, directory ? 3u : 1u, IntPtr.Zero, 3,
            0x00200000u | (directory ? 0x02000000u : 0), IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error == 2) throw new FileNotFoundException();
            throw new IOException($"Cannot open preference path (Windows error {error}).");
        }

        if (!GetFileInformationByHandleEx(handle, 0, out var info, (uint)Marshal.SizeOf<FileBasicInfo>()) ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            ((info.Attributes & FileAttributes.Directory) != 0) != directory)
        {
            handle.Dispose();
            throw new IOException("Preference path is not an ordinary file or directory.");
        }

        return handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
        public FileAttributes Attributes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass,
        out FileBasicInfo information, uint size);
}
