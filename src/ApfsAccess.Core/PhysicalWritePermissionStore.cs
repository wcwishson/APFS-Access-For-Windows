using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Core;

internal sealed class PhysicalWritePermissionStore
{
    private const int MaximumBytes = 256 * 1024;
    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _path;
    private readonly object _gate;

    internal PhysicalWritePermissionStore(string path)
    {
        _path = Path.GetFullPath(path);
        _gate = Gates.GetOrAdd(_path, _ => new());
    }

    internal bool Contains(PermissionIdentity identity, Guid? pendingId)
    {
        try { return WithState(rows => (false, rows.Any(r => r.Identity == identity && (r.PendingId is null || r.PendingId == pendingId))), default); }
        catch (Exception ex) when (IsStoreError(ex)) { return false; }
    }

    internal Guid? Begin(PermissionIdentity identity, CancellationToken token)
        => WithState(rows =>
        {
            if (rows.Any(r => r.Identity == identity && r.PendingId is null)) return (false, (Guid?)null);
            rows.RemoveAll(r => r.Identity == identity && r.PendingId is not null);
            if (rows.Count >= 128) throw new IOException("PhysicalWritePermissionStoreFull");
            var pending = Guid.NewGuid();
            rows.Add(new(identity, pending));
            return (true, (Guid?)pending);
        }, token);

    internal void Confirm(PermissionIdentity identity, Guid? pendingId, CancellationToken token)
        => WithState(rows =>
        {
            var index = rows.FindIndex(r => r.Identity == identity && r.PendingId == pendingId);
            if (index < 0) throw new IOException("PhysicalWritePermissionPendingRecordChanged");
            if (pendingId is null) return (false, true);
            rows[index] = new(identity, null);
            return (true, true);
        }, token);

    private T WithState<T>(Func<List<Entry>, (bool Write, T Result)> action, CancellationToken token)
    {
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows()) throw new IOException("PhysicalWritePermissionStoreRequiresWindows");
            var pinned = new List<SafeFileHandle>();
            string? temporary = null;
            try
            {
                var directory = Path.GetDirectoryName(_path)!;
                var ancestors = new Stack<string>();
                for (var current = new DirectoryInfo(directory); current is not null; current = current.Parent)
                    ancestors.Push(current.FullName);
                foreach (var ancestor in ancestors)
                {
                    token.ThrowIfCancellationRequested();
                    pinned.Add(VolumeDriveLetterAssignments.OpenChecked(ancestor, directory: true));
                }
                using var lease = new FileStream(_path + ".lock", FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
                var rows = new List<Entry>();
                try
                {
                    using var handle = VolumeDriveLetterAssignments.OpenChecked(_path, directory: false);
                    using var stream = new FileStream(handle, FileAccess.Read);
                    if (stream.Length > MaximumBytes) throw new IOException("PhysicalWritePermissionStoreTooLarge");
                    var envelope = JsonSerializer.Deserialize<Envelope>(stream, Json);
                    if (envelope is not { Version: 1, Protected: { Length: > 0 } }) throw new JsonException("Invalid permission envelope.");
                    var bytes = Protect(Convert.FromBase64String(envelope.Protected), unprotect: true);
                    if (bytes.Length > MaximumBytes) throw new JsonException("Permission payload too large.");
                    rows = JsonSerializer.Deserialize<List<Entry>>(bytes, Json) ?? throw new JsonException("Missing permission payload.");
                    if (rows.Count > 128 || rows.Any(r => r.Identity is null || !r.Identity.IsValid ||
                        r.PendingId == Guid.Empty) || rows.Select(r => r.Identity).Distinct().Count() != rows.Count)
                        throw new JsonException("Invalid or duplicate permission identity.");
                }
                catch (FileNotFoundException) { }
                token.ThrowIfCancellationRequested();
                var result = action(rows);
                if (!result.Write) return result.Result;
                var output = JsonSerializer.SerializeToUtf8Bytes(new Envelope(1,
                    Convert.ToBase64String(Protect(JsonSerializer.SerializeToUtf8Bytes(rows), unprotect: false))));
                if (output.Length > MaximumBytes) throw new IOException("PhysicalWritePermissionStoreTooLarge");
                temporary = Path.Combine(directory, $".physical-write-permissions-{Guid.NewGuid():N}.tmp");
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(output);
                    stream.Flush(flushToDisk: true);
                }
                token.ThrowIfCancellationRequested();
                File.Move(temporary, _path, overwrite: true);
                temporary = null;
                return result.Result;
            }
            finally
            {
                if (temporary is not null)
                    try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                foreach (var handle in pinned) handle.Dispose();
            }
        }
    }

    internal static bool IsStoreError(Exception ex)
        => ex is IOException or UnauthorizedAccessException or SecurityException or JsonException or CryptographicException or FormatException;

    private static byte[] Protect(byte[] bytes, bool unprotect)
    {
        var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        var input = new DataBlob { Size = bytes.Length, Data = pin.AddrOfPinnedObject() };
        var output = new DataBlob();
        try
        {
            var ok = unprotect
                ? CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptProtectData(ref input, "APFS Access selected physical-volume permission v1", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new CryptographicException(Marshal.GetLastWin32Error());
            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero) LocalFree(output.Data);
            pin.Free();
        }
    }

    private sealed record Envelope(int Version, string Protected);
    private sealed record Entry(PermissionIdentity Identity, Guid? PendingId);
    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
