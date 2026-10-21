using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static class FusionImageRegistration
{
    public static FusionImageProfile ReadProfile(Stream source)
    {
        var bytes = new byte[65537]; var count = 0;
        while (count < bytes.Length) { var n = source.Read(bytes, count, bytes.Length - count); if (n == 0) break; count += n; }
        if (count is < 2 or > 65536) throw new InvalidDataException("Fusion selector file exceeds bounds.");
        using var document = JsonDocument.Parse(bytes.AsMemory(0, count));
        static void Unique(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject()) { if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate Fusion selector."); Unique(property.Value); }
            }
            else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
        }
        Unique(document.RootElement);
        var profile = document.RootElement.Deserialize<FusionImageProfile>(new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        if (profile is null || !profile.IsValid()) throw new InvalidDataException("Select a complete Fusion image pair with exact volume and store windows.");
        return profile;
    }

    public static ControlOperationRequestPayload CreateRequest(FusionImageProfile profile)
    {
        if (!profile.IsValid()) throw new InvalidDataException("Invalid Fusion image selectors.");
        return new(Guid.NewGuid().ToString("D"), ApfsControlCommands.RegisterFusion, SelectedControlTarget.ForFusion(profile),
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(90));
    }
}
