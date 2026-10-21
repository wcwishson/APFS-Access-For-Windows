using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal static class XattrCommand
{
    internal const string Prefix = ":APFS.Xattr.";
    internal const string ProtocolStream = ":APFS.XattrProtocol:$DATA";
    private const string Suffix = ":$DATA";
    private const int MaxWriteBytes = 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly UnicodeEncoding Utf16 = new(false, false, true);
    internal sealed record AttributeInfo(string Name, long Bytes);

    internal static string StreamName(string name)
    {
        var bytes = Utf8.GetBytes(name);
        if (bytes.Length is 0 or > 821 || name.Contains('\0'))
            throw new ArgumentException("The attribute name must contain 1 to 821 UTF-8 bytes and no NUL.");
        return Prefix + Convert.ToHexString(bytes) + Suffix;
    }

    internal static string? AttributeName(string stream)
    {
        if (!stream.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) return null;
        if (!stream.EndsWith(Suffix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The APFS attribute stream has an invalid type.");
        var encoded = stream[Prefix.Length..^Suffix.Length];
        try
        {
            var name = Utf8.GetString(Convert.FromHexString(encoded));
            _ = StreamName(name);
            return name;
        }
        catch (ArgumentException e) { throw new InvalidDataException("Invalid APFS attribute stream name.", e); }
        catch (FormatException e) { throw new InvalidDataException("Invalid APFS attribute stream name.", e); }
    }

    internal static IReadOnlyList<AttributeInfo> ParseStreamInformation(ReadOnlySpan<byte> buffer)
    {
        var result = new List<AttributeInfo>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        var offset = 0;
        for (;;)
        {
            if (buffer.Length - offset < 24) throw new InvalidDataException("Truncated stream information.");
            var entry = buffer[offset..];
            var next = BinaryPrimitives.ReadUInt32LittleEndian(entry);
            var nameBytes = BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
            var size = BinaryPrimitives.ReadInt64LittleEndian(entry[8..]);
            if ((nameBytes & 1) != 0 || nameBytes > entry.Length - 24 || size < 0)
                throw new InvalidDataException("Invalid stream information bounds.");
            var stream = Utf16.GetString(entry.Slice(24, checked((int)nameBytes)));
            if (AttributeName(stream) is { } name)
            {
                if (!names.Add(name)) throw new InvalidDataException("Duplicate APFS attribute stream.");
                result.Add(new(name, size));
            }
            if (next == 0) break;
            if ((next & 7) != 0 || next < 24 + nameBytes || next > entry.Length - 24)
                throw new InvalidDataException("Invalid stream information link.");
            offset += checked((int)next);
        }
        return result.OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
    }

    internal static int Run(string[] args)
    {
        var action = args.FirstOrDefault() ?? "help";
        var operationId = Guid.NewGuid().ToString("N");
        try
        {
            if (action is "help" or "--help")
            {
                Print(new { success = true, command = "xattr", operationId, exitCode = 0,
                    usage = new[] { "xattr list --path PATH", "xattr read --path PATH --name NAME --output FILE",
                        "xattr write --path PATH --name NAME --input FILE", "xattr remove --path PATH --name NAME" },
                    maxWriteBytes = MaxWriteBytes });
                return 0;
            }
            if (action is not ("list" or "read" or "write" or "remove"))
                throw new ArgumentException("Unknown xattr action. Use xattr help.");
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 1; i < args.Length; i++)
            {
                if (args[i] == "--json") continue;
                if (args[i] is not ("--path" or "--name" or "--input" or "--output") ||
                    i + 1 == args.Length || !options.TryAdd(args[i], args[++i]))
                    throw new ArgumentException("Unknown, duplicate, or incomplete xattr option.");
            }
            string Required(string key) => options.TryGetValue(key, out var value) && value.Length != 0
                ? value : throw new ArgumentException($"Missing {key}.");
            var path = ValidateFilePath(Required("--path"));
            var name = action == "list" ? null : Required("--name");
            var allowed = action switch
            {
                "list" => new[] { "--path" },
                "read" => new[] { "--path", "--name", "--output" },
                "write" => new[] { "--path", "--name", "--input" },
                _ => new[] { "--path", "--name" },
            };
            if (options.Keys.Any(k => !allowed.Contains(k)))
                throw new ArgumentException("An option is not applicable to this xattr action.");
            var transfer = action is "read" or "write"
                ? ValidateFilePath(Required(action == "read" ? "--output" : "--input")) : null;
            byte[]? payload = null;
            if (action == "write")
            {
                using var input = new FileStream(transfer!, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (input.Length > MaxWriteBytes) throw new ArgumentException("Attribute writes currently support at most 1 MiB.");
                payload = new byte[checked((int)input.Length)];
                input.ReadExactly(payload);
                if (input.ReadByte() != -1) throw new IOException("Input changed while reading.");
            }
            using var owner = OpenApfsOwner(path, out var streamOwnerPath);
            var stream = name is null ? null : streamOwnerPath + StreamName(name);
            long? bytes = null;
            IReadOnlyList<AttributeInfo>? attributes = null;
            switch (action)
            {
                case "list": attributes = Enumerate(owner.SafeFileHandle); break;
                case "read":
                    bytes = Export(stream!, transfer!);
                    break;
                case "write":
                    using (var output = new FileStream(stream!, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                    {
                        output.Write(payload!);
                        output.SetLength(payload!.Length);
                        output.Flush(true);
                        output.Position = 0;
                        var readback = new byte[payload.Length];
                        output.ReadExactly(readback);
                        if (!readback.AsSpan().SequenceEqual(payload) || output.ReadByte() != -1)
                            throw new IOException("The attribute readback did not match the input.");
                        bytes = payload.Length;
                    }
                    break;
                case "remove":
                    if (!DeleteFileW(stream!)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    // Provider stream cleanup owns durable removal; verify fresh namespace visibility.
                    using (var query = CreateFileW(stream!, 0x80, 3, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero))
                    {
                        if (!query.IsInvalid) throw new IOException("The attribute remains visible after removal.");
                        var error = Marshal.GetLastWin32Error();
                        if (error is not (2 or 3)) throw new Win32Exception(error);
                    }
                    break;
            }
            Print(new { success = true, command = "xattr", action, operationId, exitCode = 0, path, name, bytes, attributes });
            return 0;
        }
        catch (Exception e) when (e is ArgumentException or IOException or InvalidDataException or Win32Exception or UnauthorizedAccessException or NotSupportedException)
        {
            var code = e is ArgumentException ? 2 : 5;
            Print(new { success = false, command = "xattr", action, operationId, exitCode = code,
                errorCode = code == 2 ? "InvalidArguments" : "OperationFailed", error = e.Message });
            return code;
        }
    }

    internal static string ValidateFilePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.Contains('\0'))
            throw new ArgumentException("Use a fully qualified file path without a device prefix or stream suffix.");
        var fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith(@"\\.\", StringComparison.Ordinal) || fullPath.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            fullPath.AsSpan(Math.Min(fullPath.Length, 2)).Contains(':'))
            throw new ArgumentException("Use a fully qualified file path without a device prefix or stream suffix.");
        return fullPath;
    }

    private static FileStream OpenApfsOwner(string path, out string streamOwnerPath)
    {
        // A live data-read stream open participates in base-file delete sharing.
        // Metadata-only opens would allow the pathname to be replaced during the operation.
        var owner = OpenProtocol(path, out streamOwnerPath);
        try
        {
            var name = new StringBuilder(64);
            if (!GetVolumeInformationByHandleW(owner.SafeFileHandle, IntPtr.Zero, 0, out _, out _, out _, name, (uint)name.Capacity))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!string.Equals(name.ToString(), "APFS", StringComparison.Ordinal))
                throw new NotSupportedException("The path must belong to a mounted APFS volume.");
            ReadProviderProtocol(owner);
            return owner;
        }
        catch { owner.Dispose(); throw; }
    }

    private static long Export(string stream, string destination)
    {
        if (File.Exists(destination)) throw new IOException("The output file already exists.");
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var created = false;
        try
        {
            long length;
            using (var input = new FileStream(stream, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                input.CopyTo(output, 64 * 1024);
                output.Flush(true);
                length = output.Length;
            }
            File.Move(temporary, destination, overwrite: false);
            created = false;
            return length;
        }
        finally { if (created) File.Delete(temporary); }
    }

    internal static void VerifyProviderProtocol(string path)
    {
        using var protocol = OpenProtocol(path, out _);
        ReadProviderProtocol(protocol);
    }

    private static FileStream OpenProtocol(string path, out string streamOwnerPath)
    {
        streamOwnerPath = path;
        try
        {
            return new FileStream(path + ProtocolStream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }
        catch (FileNotFoundException e)
        {
            // A directory mount's root streams use the explicit dot component.
            // Retain the successful protocol handle while accessing that spelling.
            if (Directory.Exists(path))
            {
                streamOwnerPath = path.TrimEnd('\\', '/') + @"\.";
                try
                {
                    return new FileStream(streamOwnerPath + ProtocolStream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                }
                catch (FileNotFoundException) { }
                catch (IOException fallback) when ((fallback.HResult & 0xffff) == 123) { }
            }
            throw new NotSupportedException("The path must belong to a mounted APFS volume providing durable attributes. Remount with the updated app.", e);
        }
    }

    private static void ReadProviderProtocol(Stream protocol)
    {
        ReadOnlySpan<byte> expected = "APFS-XATTR/1\n"u8;
        Span<byte> bytes = stackalloc byte[expected.Length];
        protocol.ReadExactly(bytes);
        if (!bytes.SequenceEqual(expected) || protocol.ReadByte() != -1)
            throw new InvalidDataException("The mounted provider has an incompatible attribute protocol.");
    }

    private static IReadOnlyList<AttributeInfo> Enumerate(SafeFileHandle owner)
    {
        for (var size = 64 * 1024; size <= 16 * 1024 * 1024; size *= 2)
        {
            var buffer = new byte[size];
            if (GetFileInformationByHandleEx(owner, 7, buffer, (uint)buffer.Length))
                return ParseStreamInformation(buffer);
            var error = Marshal.GetLastWin32Error();
            if (error == 38) return [];
            if (error is not (122 or 234)) throw new Win32Exception(error);
        }
        throw new IOException("The attribute listing exceeds the bounded enumeration buffer.");
    }

    private static void Print(object value) => Console.WriteLine(JsonSerializer.Serialize(value,
        new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr volume, uint volumeSize,
        out uint serial, out uint maxComponentLength, out uint flags, StringBuilder filesystem, uint filesystemSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass,
        [Out] byte[] information, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteFileW(string name);
}
