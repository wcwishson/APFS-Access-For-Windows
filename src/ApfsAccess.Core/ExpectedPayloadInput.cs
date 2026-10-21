using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Core;

/// <summary>A bounded snapshot of a caller-owned, held input stream. Does not authenticate its origin.</summary>
public sealed class ExpectedPayloadInput
{
    private readonly Stream stream;
    private readonly byte[] bytes;
    private readonly int maximumBytes;
    public string Sha256 { get; }
    public int ByteCount => bytes.Length;

    private ExpectedPayloadInput(Stream stream, byte[] bytes, int maximumBytes)
    {
        this.stream = stream; this.bytes = bytes; this.maximumBytes = maximumBytes;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    public static ExpectedPayloadInput Read(Stream stream, int maximumBytes, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (maximumBytes is < 1 or > 64 * 1024 * 1024 || !stream.CanRead || !stream.CanSeek)
            throw new ArgumentException("A readable, seekable held input and a bounded byte limit are required.");
        if (stream.Length > maximumBytes) throw new InvalidDataException("Payload comparison input exceeds its byte limit.");
        stream.Position = 0;
        using var buffer = new MemoryStream();
        var chunk = new byte[16384];
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var read = stream.Read(chunk, 0, Math.Min(chunk.Length, maximumBytes - (int)buffer.Length + 1));
            if (read == 0) break;
            if (buffer.Length + read > maximumBytes) throw new InvalidDataException("Payload comparison input exceeds its byte limit.");
            buffer.Write(chunk, 0, read);
        }
        var input = new ExpectedPayloadInput(stream, buffer.ToArray(), maximumBytes);
        input.EnsureUnchanged(token);
        return input;
    }

    public JsonDocument ParseDocument()
    {
        try
        {
            _ = new UTF8Encoding(false, true).GetCharCount(bytes);
            return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        }
        catch (Exception ex) when (ex is JsonException or DecoderFallbackException)
        { throw new InvalidDataException("Payload comparison input must be bounded strict UTF-8 JSON.", ex); }
    }

    public void EnsureUnchanged(CancellationToken token = default)
    {
        stream.Position = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var chunk = new byte[16384]; var total = 0;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var read = stream.Read(chunk, 0, Math.Min(chunk.Length, maximumBytes - total + 1));
            if (read == 0) break;
            total += read;
            if (total > maximumBytes) throw new InvalidDataException("Payload comparison input changed or exceeded its byte limit.");
            hash.AppendData(chunk, 0, read);
        }
        if (total != bytes.Length || Convert.ToHexStringLower(hash.GetHashAndReset()) != Sha256)
            throw new InvalidDataException("Payload comparison input changed while held.");
    }

    public static FileStream OpenFile(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) ||
            path.Length < 3 || path[1] != ':' || path[2] != '\\' || path[2..].Contains(':') ||
            path.Split('\\', '/').Skip(1).Any(p => p is "." or ".." || p.EndsWith('.') || p.EndsWith(' ') ||
                IsDeviceName(p)))
            throw new ArgumentException("Payload comparison inputs must be absolute regular local file paths.");
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new ArgumentException("Payload comparison inputs must be regular files.");
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 16384, FileOptions.SequentialScan);
    }

    private static bool IsDeviceName(string part)
    {
        var name = part.Split('.')[0].ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" ||
            name.Length == 4 && name[3] is >= '1' and <= '9' && name[..3] is "COM" or "LPT";
    }
}
