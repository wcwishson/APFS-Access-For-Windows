using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

internal static class ImageKeyManagementSelection
{
    internal static ImageKeyManagementEndpoint Read(Stream source)
    {
        var bytes = new byte[8193];
        var count = 0;
        while (count < bytes.Length)
        {
            var got = source.Read(bytes, count, bytes.Length - count);
            if (got == 0) break;
            count += got;
        }
        if (count is < 2 or > 8192) throw new InvalidDataException("Image selectors exceed bounds.");
        try
        {
            using var document = JsonDocument.Parse(bytes.AsMemory(0, count));
            static bool Unique(JsonElement element) => element.ValueKind == JsonValueKind.Object ?
                element.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == element.EnumerateObject().Count() &&
                    element.EnumerateObject().All(p => Unique(p.Value)) : element.ValueKind != JsonValueKind.Array || element.EnumerateArray().All(Unique);
            if (!Unique(document.RootElement)) throw new JsonException();
            var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
            { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, Converters = { new JsonStringEnumConverter() } };
            var endpoint = document.RootElement.TryGetProperty("mode", out _) ?
                document.RootElement.Deserialize<ImageKeyManagementEndpoint>(options) :
                ImageKeyManagementEndpoint.FromWritableProfile(document.RootElement.Deserialize<EncryptedImageProfile>(options) ?? throw new JsonException());
            return endpoint is not null && endpoint.IsValid() ? endpoint : throw new JsonException();
        }
        catch (Exception error) when (error is JsonException or ArgumentException or NotSupportedException)
        { throw new InvalidDataException("Select the public endpoint or writable profile for this image."); }
    }
}
