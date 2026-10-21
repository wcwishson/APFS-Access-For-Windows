using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static class EncryptedImageRegistration
{
    public static EncryptedImageProfile ReadProfile(Stream source)
    {
        // Read one extra byte so both seekable and nonseekable inputs obey the CLI bound.
        var bytes = new byte[8193];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = source.Read(bytes, count, bytes.Length - count);
            if (read == 0) break;
            count += read;
        }
        if (count is < 2 or > 8192) throw new InvalidDataException("Image selector file exceeds bounds.");
        try
        {
            using var doc = JsonDocument.Parse(bytes.AsMemory(0, count));
            var fields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                doc.RootElement.EnumerateObject().Any(p => !fields.Add(p.Name)))
                throw new InvalidDataException("Duplicate or invalid image selector fields.");
            var profile = doc.RootElement.Deserialize<EncryptedImageProfile>(new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (profile is null || !profile.IsValid()) throw new InvalidDataException("Invalid image selectors.");
            return profile;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or NotSupportedException)
        { throw new InvalidDataException("Invalid image selectors. Choose a public image selector profile.", ex); }
    }

    public static async Task<OperationResultPayload?> RunAsync(EncryptedImageProfile profile,
        Func<string, bool> confirm, Func<ControlOperationRequestPayload, Task<OperationResultPayload>> send)
    {
        if (!profile.IsValid()) throw new InvalidDataException("Invalid image selectors.");
        if (!confirm($"Image: {profile.ImagePath}\r\nContainer: {profile.ContainerUuid}\r\nVolume: {profile.VolumeUuid}\r\n" +
            $"Object: {profile.VolumeObjectId}\r\nCheckpoint: {profile.CheckpointXid}\r\n\r\nRegister this encrypted image?")) return null;
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.RegisterImage,
            SelectedControlTarget.ForImage(profile), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(80));
        var result = await send(request).ConfigureAwait(true);
        ControlOperationReply.RequireSuccess(request, result);
        return result;
    }
}
