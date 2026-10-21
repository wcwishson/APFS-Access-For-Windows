using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace ApfsAccess.Core;

public enum EncryptedVolumeState { Locked, Unlocking, Unlocked, Locking, Failed }

// Public selectors only. Read-only registration holds a read lease;
// native admission remains the authority for the encrypted format and key profile.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EncryptedImageProfile(string ImagePath, string SourceId, ulong StoreOffset, ulong StoreSize,
    string ContainerUuid, string VolumeUuid, ulong VolumeObjectId, ulong CheckpointXid,
    ulong ContainerBagOid, ulong ContainerBagXid, ulong VolumeBagOid, ulong VolumeBagXid,
    string UserUuid, string BagLength)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Writable { get; init; }
    [JsonIgnore] public MountAccessMode AccessMode => Writable ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;

    public bool IsValid() => ImagePath is { Length: > 3 and < 1024 } && char.IsAsciiLetter(ImagePath[0]) &&
        ImagePath[1] == ':' && ImagePath[2] is '\\' or '/' && !ImagePath[2..].Contains(':') &&
        !ImagePath.Any(char.IsControl) && Path.GetFullPath(ImagePath) == ImagePath &&
        SourceId is { Length: > 0 and < 256 } && SourceId.All(c => c is >= ' ' and <= '~') &&
        SourceId.StartsWith(Writable ? "image-writer-v1:" : "windows-file:",StringComparison.Ordinal) &&
        SourceId.EndsWith(Writable ? $":{StoreOffset}:{StoreSize}" : $":scope:{StoreOffset}:{StoreSize}",StringComparison.Ordinal) &&
        Uuid(ContainerUuid) && Uuid(VolumeUuid) && Uuid(UserUuid) && VolumeObjectId > 0 &&
        StoreSize > 0 && StoreOffset <= long.MaxValue && StoreSize <= (ulong)long.MaxValue-StoreOffset &&
        // Physical keybag header object IDs may be zero; they are not volume selectors.
        CheckpointXid > 0 && ContainerBagXid > 0 && VolumeBagXid > 0 &&
        BagLength is "includes-header" or "entries-only";
    private static bool Uuid(string s) => Guid.TryParseExact(s,"D",out var id) && id != Guid.Empty && id.ToString("D") == s;
    [JsonIgnore] public string VolumeId => ApfsTopology.BuildVolumeId(Guid.Parse(ContainerUuid).ToString("N"), VolumeObjectId);
    [JsonIgnore] public string Contract => "selected-v1:"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this, ContractOptions)))).ToLowerInvariant();
    private static readonly JsonSerializerOptions ContractOptions = new() { IgnoreReadOnlyProperties = true };
    public IReadOnlyList<string> HostArguments() => [
        "--encrypted-image", "--encrypted-source-id", SourceId,
        "--container-id", Guid.Parse(ContainerUuid).ToString("N"), "--volume-oid", VolumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--encrypted-store-size", StoreSize.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--encrypted-volume-uuid", Guid.Parse(VolumeUuid).ToString("N"), "--encrypted-user-uuid", Guid.Parse(UserUuid).ToString("N"),
        "--encrypted-checkpoint-xid", CheckpointXid.ToString(),
        "--encrypted-container-bag-oid", ContainerBagOid.ToString(), "--encrypted-container-bag-xid", ContainerBagXid.ToString(),
        "--encrypted-volume-bag-oid", VolumeBagOid.ToString(), "--encrypted-volume-bag-xid", VolumeBagXid.ToString(),
        "--encrypted-bag-length", BagLength];
}

public interface IEncryptedImageBackend
{
    Task RegisterEncryptedImageAsync(EncryptedImageProfile profile, CancellationToken token);
    Task<MountResult> UnlockEncryptedImageAsync(MountRequest request, EncryptedImageProfile profile,
        ApfsAccess.Cli.SupervisedCredential credential, CancellationToken token);
    void SetEncryptionState(string volumeId, EncryptedVolumeState state);
}

public enum EncryptedImageLockObservation { Unproven, AlreadyLocked }

// A point-in-time observation of an earlier owned clean retirement, not a new commit receipt.
public interface IEncryptedImageLockObserver
{
    Task<EncryptedImageLockObservation> ObserveLockedImageAsync(EncryptedImageProfile profile, CancellationToken token);
}
