using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ApfsAccess.Core;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FusionImageMemberProfile(string Path, string Role, string StoreId,
    ulong StoreOffset, ulong StoreSize, string? Identity = null);

// Public selectors and captured file identities. Native parsing remains the
// authority for the member roles, allocation and writable volume profile.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FusionImageProfile(string ContainerUuid, string FusionUuid, string VolumeUuid,
    ulong VolumeOid, ulong CheckpointXid, FusionImageMemberProfile[] Members)
{
    public bool IsValid()
    {
        static bool Uuid(string? s) => s is { Length: 32 } && s.Any(c => c != '0') &&
            s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
        if (!Uuid(ContainerUuid) || !Uuid(FusionUuid) || !Uuid(VolumeUuid) || VolumeOid == 0 || CheckpointXid == 0 ||
            Members is not { Length: 2 }) return false;
        foreach (var m in Members)
        {
            if (m is null || m.Path is not { Length: > 3 and < 4096 } || !char.IsAsciiLetter(m.Path[0]) ||
                m.Path[1] != ':' || m.Path[2] != '\\' || m.Path[2..].Contains(':') || m.Path.Any(char.IsControl) ||
                m.Role is not ("main" or "tier2") || m.StoreId is not { Length: > 0 and <= 256 } ||
                m.StoreId.Any(c => c is < ' ' or > '~') || m.StoreSize == 0 || m.StoreOffset % 4096 != 0 || m.StoreSize % 4096 != 0 ||
                m.StoreOffset > long.MaxValue || m.StoreSize > (ulong)long.MaxValue - m.StoreOffset ||
                m.Identity is { } identity && (identity.Length is < 1 or > 256 || identity.Any(c => c is < ' ' or > '~'))) return false;
            try { if (System.IO.Path.GetFullPath(m.Path) != m.Path) return false; } catch (Exception e) when (e is ArgumentException or NotSupportedException) { return false; }
        }
        return Members[0].Role != Members[1].Role && Members[0].StoreId != Members[1].StoreId &&
            !string.Equals(Members[0].Path, Members[1].Path, StringComparison.OrdinalIgnoreCase);
    }
    [JsonIgnore] public string VolumeId => ApfsTopology.BuildVolumeId(ContainerUuid, VolumeOid);
    [JsonIgnore] public string DeviceId => Members[0].Path;
    [JsonIgnore] public string Contract => "selected-v1:" + Convert.ToHexStringLower(SHA256.HashData(
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this, ContractOptions))));
    public FusionImageProfile Snapshot() => this with { Members = [.. Members] };
    private static readonly JsonSerializerOptions ContractOptions = new() { IgnoreReadOnlyProperties = true };
}

public interface IFusionImageBackend
{
    Task RegisterFusionImageAsync(FusionImageProfile profile, CancellationToken token);
    Task<MountResult> MountFusionImageAsync(FusionImageProfile profile, CancellationToken token);
}
