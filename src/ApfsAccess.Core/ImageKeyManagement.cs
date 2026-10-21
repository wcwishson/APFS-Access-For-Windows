using System.Text.Json.Serialization;

namespace ApfsAccess.Core;

public enum ImageKeyManagementAction { ChangePassword, RotateVolumeKey, Encrypt, Decrypt, Observe }
public enum ImageEncryptionMode { Plain, SoftwareOneKeyGenerationZero }

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageSoftwareKeybagSelection(ulong ContainerBagOid, ulong ContainerBagXid,
    ulong VolumeBagOid, ulong VolumeBagXid, string UserUuid, string BagLength)
{
    public bool IsValid(ulong checkpoint) => ContainerBagXid > 0 && ContainerBagXid <= checkpoint &&
        VolumeBagXid > 0 && VolumeBagXid <= checkpoint && Guid.TryParseExact(UserUuid, "D", out var id) &&
        id != Guid.Empty && id.ToString("D") == UserUuid && BagLength is "includes-header" or "entries-only";
}

// Public expectations only. Native admission must independently observe the
// exact held image and clean protected journals before using a credential.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageKeyManagementEndpoint(string ImagePath, string SourceId,
    ulong StoreOffset, ulong StoreSize, string ContainerUuid, string VolumeUuid,
    ulong VolumeObjectId, ulong CheckpointXid, ImageEncryptionMode Mode,
    ImageSoftwareKeybagSelection? Keybag = null)
{
    public bool IsValid()
    {
        if (ImagePath is not { Length: > 3 and < 1024 } || !char.IsAsciiLetter(ImagePath[0]) ||
            ImagePath[1] != ':' || ImagePath[2] != '\\' || ImagePath[2..].Contains(':') ||
            ImagePath.Any(char.IsControl) || SourceId is not { Length: > 0 and < 256 } ||
            !SourceId.All(c => c is >= ' ' and <= '~') ||
            !SourceId.StartsWith("image-writer-v1:", StringComparison.Ordinal) ||
            !SourceId.EndsWith(FormattableString.Invariant($":{StoreOffset}:{StoreSize}"), StringComparison.Ordinal) ||
            !Uuid(ContainerUuid) || !Uuid(VolumeUuid) || VolumeObjectId == 0 || CheckpointXid == 0 ||
            StoreSize == 0 || StoreOffset > long.MaxValue || StoreSize > (ulong)long.MaxValue - StoreOffset ||
            !Enum.IsDefined(Mode) || (Mode == ImageEncryptionMode.Plain ? Keybag is not null :
                Keybag is null || !Keybag.IsValid(CheckpointXid))) return false;
        try { return Path.GetFullPath(ImagePath) == ImagePath; }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    internal bool SameImage(ImageKeyManagementEndpoint other) =>
        ImagePath == other.ImagePath && SourceId == other.SourceId && StoreOffset == other.StoreOffset &&
        StoreSize == other.StoreSize && ContainerUuid == other.ContainerUuid && VolumeUuid == other.VolumeUuid &&
        VolumeObjectId == other.VolumeObjectId;

    public EncryptedImageProfile ToWritableEncryptedProfile()
    {
        if (!IsValid() || Mode != ImageEncryptionMode.SoftwareOneKeyGenerationZero || Keybag is null)
            throw new InvalidOperationException("A freshly observed encrypted endpoint is required.");
        return new(ImagePath, SourceId, StoreOffset, StoreSize, ContainerUuid, VolumeUuid,
            VolumeObjectId, CheckpointXid, Keybag.ContainerBagOid, Keybag.ContainerBagXid,
            Keybag.VolumeBagOid, Keybag.VolumeBagXid, Keybag.UserUuid, Keybag.BagLength) { Writable = true };
    }

    public static ImageKeyManagementEndpoint FromWritableProfile(EncryptedImageProfile profile)
    {
        if (!profile.Writable || !profile.IsValid()) throw new ArgumentException("A writable image profile is required.");
        var endpoint = new ImageKeyManagementEndpoint(profile.ImagePath, profile.SourceId, profile.StoreOffset, profile.StoreSize,
            profile.ContainerUuid, profile.VolumeUuid, profile.VolumeObjectId, profile.CheckpointXid,
            ImageEncryptionMode.SoftwareOneKeyGenerationZero, new(profile.ContainerBagOid, profile.ContainerBagXid,
                profile.VolumeBagOid, profile.VolumeBagXid, profile.UserUuid, profile.BagLength));
        return endpoint.IsValid() ? endpoint : throw new ArgumentException("The image profile is outside the supported key-management bounds.");
    }

    private static bool Uuid(string value) => Guid.TryParseExact(value, "D", out var id) &&
        id != Guid.Empty && id.ToString("D") == value;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageKeyManagementRequest(string OperationId, ImageKeyManagementAction Action,
    ImageKeyManagementEndpoint Expected)
{
    [JsonIgnore] public int CredentialCount => Action == ImageKeyManagementAction.Observe ? 0 :
        Action is ImageKeyManagementAction.ChangePassword or ImageKeyManagementAction.RotateVolumeKey ? 2 : 1;
    [JsonIgnore] public ImageEncryptionMode ResultMode => Action == ImageKeyManagementAction.Observe ? Expected.Mode :
        Action == ImageKeyManagementAction.Decrypt ? ImageEncryptionMode.Plain : ImageEncryptionMode.SoftwareOneKeyGenerationZero;

    public bool IsValid() => Guid.TryParseExact(OperationId, "D", out var id) && id != Guid.Empty &&
        id.ToString("D") == OperationId && Enum.IsDefined(Action) && Expected is not null && Expected.IsValid() &&
        (Action == ImageKeyManagementAction.Observe ||
         Expected.Mode == (Action == ImageKeyManagementAction.Encrypt ? ImageEncryptionMode.Plain :
            ImageEncryptionMode.SoftwareOneKeyGenerationZero));
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ImageKeyManagementReceipt(string OperationId, ImageKeyManagementAction Action,
    ImageKeyManagementEndpoint Before, ImageKeyManagementEndpoint After,
    ulong AcceptedSequence, ulong DurableSequence, ulong CleanedSequence,
    bool KeyRevoked, bool OwnerClosed)
{
    public bool Proves(ImageKeyManagementRequest request) => request.IsValid() &&
        OperationId == request.OperationId && Action == request.Action && Before == request.Expected &&
        After is not null && After.IsValid() && Before.SameImage(After) &&
        (request.Action == ImageKeyManagementAction.Observe ? After.CheckpointXid >= Before.CheckpointXid :
            After.CheckpointXid > Before.CheckpointXid && After.Mode == request.ResultMode && AcceptedSequence > 0) &&
        AcceptedSequence == DurableSequence && DurableSequence == CleanedSequence &&
        KeyRevoked && OwnerClosed;
}

public interface IImageKeyManagementBackend
{
    Task<ImageKeyManagementReceipt> ManageImageKeysAsync(ImageKeyManagementRequest request,
        ApfsAccess.Cli.SupervisedCredentialSet credentials, CancellationToken cancellation);
}

public interface IImageKeyManagementObserver
{
    Task<ImageKeyManagementReceipt> ObserveImageKeysAsync(ImageKeyManagementRequest request,
        CancellationToken cancellation);
}
