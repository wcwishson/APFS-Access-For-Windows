using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Service;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record VolumeManagementIntent(ControlOperationRequestPayload Original,
    VolumeTopologyRequest NativeRequest, string State, VolumeTopologyResult? Result = null, string? ConfirmationToken = null)
{
    public bool Pending => State is "preparing" or "prepared" or "applying" or "recovery-required";
}

public sealed class VolumeManagementIntentStore : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _root;
    private readonly SafeFileHandle _lease;
    public VolumeManagementIntentStore(string root)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        if (!Directory.Exists(root)) throw new IOException("ManagementJournalRoot must already exist.");
        _root = root;
        _lease = CreateFile(root, 0x80, 3, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (_lease.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public IReadOnlyList<VolumeManagementIntent> ReadAll()
    {
        if (Directory.EnumerateFiles(_root, "managed-volume-*.tmp").Any())
            throw new InvalidDataException("Incomplete managed volume intent is preserved.");
        var files = Directory.EnumerateFiles(_root, "managed-volume-*.json").Take(1025).ToArray();
        if (files.Length > 1024) throw new InvalidDataException("Managed volume intent inventory limit exceeded.");
        var records = files.Select(Read).ToArray();
        if (records.Where(r => r.Pending).GroupBy(r => r.NativeRequest.Image, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            throw new InvalidDataException("Conflicting pending volume intents.");
        return records;
    }
    public void Save(VolumeManagementIntent intent)
    {
        Validate(intent);
        var path = FilePath(intent.Original.OperationId);
        if (File.Exists(path))
        {
            var old = Read(path);
            if (JsonSerializer.Serialize(old.NativeRequest, Json) != JsonSerializer.Serialize(intent.NativeRequest, Json) ||
                ApfsOperationFingerprint.Compute(old.Original) != ApfsOperationFingerprint.Compute(intent.Original))
                throw new InvalidDataException("Original volume intent cannot be replaced.");
            if (!old.Pending && (intent.State != old.State || JsonSerializer.Serialize(intent.Result, Json) != JsonSerializer.Serialize(old.Result, Json)))
                throw new InvalidDataException("Terminal volume intent cannot be reopened.");
            if (old.ConfirmationToken is not null && intent.ConfirmationToken != old.ConfirmationToken)
                throw new InvalidDataException("Original native token cannot be replaced.");
        }
        var payload = JsonSerializer.Serialize(intent, Json);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new Frame(1, Hash(payload), payload), Json);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { output.Write(bytes); output.Flush(true); }
        if (!MoveFileEx(temp, path, 9)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes)) throw new IOException("Managed intent durable readback failed.");
        _ = Read(path);
    }
    private VolumeManagementIntent Read(string path)
    {
        NativeApfsVolumeManagement.ValidateIntentFile(path);
        if (new FileInfo(path).Length > 512 * 1024) throw new InvalidDataException("Volume intent exceeds its size limit.");
        var frame = JsonSerializer.Deserialize<Frame>(File.ReadAllBytes(path), Json) ?? throw new InvalidDataException("Missing volume intent.");
        if (frame.Schema != 1 || frame.Digest != Hash(frame.Payload)) throw new InvalidDataException("Corrupt volume intent is preserved.");
        var record = JsonSerializer.Deserialize<VolumeManagementIntent>(frame.Payload, Json) ?? throw new InvalidDataException("Missing original request.");
        Validate(record);
        if (!string.Equals(path, FilePath(record.Original.OperationId), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Volume intent filename binding changed.");
        return record;
    }
    private void Validate(VolumeManagementIntent r)
    {
        if (r.NativeRequest is null || r.Original is null) throw new InvalidDataException("Missing original volume intent identity.");
        NativeApfsVolumeManagement.ValidateRequest(r.NativeRequest);
        if (!string.Equals(r.NativeRequest.JournalRoot, _root, StringComparison.OrdinalIgnoreCase) ||
            !VolumeManagementParameters.Valid(r.Original.Command, r.Original.VolumeManagement) ||
            !VolumeManagementParameters.IsPlan(r.Original.Command) ||
            r.Original.VolumeManagement!.Kind != r.NativeRequest.Operation || r.Original.Target is null ||
            !string.Equals(r.Original.Target.DeviceId, r.NativeRequest.Image, StringComparison.OrdinalIgnoreCase) ||
            !TopologyAdmission.SameUuid(r.Original.Target.ContainerUuid, r.NativeRequest.ContainerUuid) ||
            r.State is not ("preparing" or "prepared" or "applying" or "recovery-required" or "committed" or "cancelled" or "refused"))
            throw new InvalidDataException("Invalid original volume management binding.");
        if (r.State is "prepared" or "applying" && r.ConfirmationToken is not { Length: 64 })
            throw new InvalidDataException("Prepared intent has no saved native token.");
        _ = ApfsOperationFingerprint.Compute(r.Original);
        _ = FilePath(r.Original.OperationId);
    }
    private string FilePath(string id) => Guid.TryParseExact(id, "D", out var guid) && guid.ToString("D") == id
        ? Path.Combine(_root, "managed-volume-" + id + ".json") : throw new InvalidDataException("Invalid intent ID.");
    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));
    public void Dispose() => _lease.Dispose();
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record Frame(int Schema, string Digest, string Payload);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool MoveFileEx(string source, string destination, uint flags);
}
