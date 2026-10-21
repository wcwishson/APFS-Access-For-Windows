using System.Globalization;
using System.Text.Json.Serialization;

namespace ApfsAccess.Core;

public enum VolumeTopologyMode { Prepare, Apply, Cancel, Recover }

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record VolumeTopologyWal(string Oid, string VolumeUuid, string Path);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record VolumeTopologyObservation(string Image, string OffsetBytes, string StoreSizeBytes,
    string SourceIdentity, string ContainerUuid, string CheckpointXid, string BlockBytes, string NextOid,
    string SpoolRoot, IReadOnlyList<VolumeTopologyWal> Volumes,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PhysicalBindingHex = null);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record VolumeTopologyRequest(string Operation, string Image, string JournalRoot,
    string OffsetBytes, string ContainerUuid, string VolumeUuid, string VolumeOid, string PreXid,
    string SourceIdentity, string SpoolRoot, IReadOnlyList<VolumeTopologyWal> SiblingWals,
    string? Name = null, string? QuotaBlocks = null, string? ReserveBlocks = null, bool? CaseSensitive = null,
    VolumeImageOptions? ImageOptions = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PhysicalBindingHex = null);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record VolumeImageOptions(string ExpectedBytes, string TargetBytes, string? NewContainerUuid = null,
    string? NewVolumeUuid = null, string? NewVolumeWal = null);

public sealed record VolumeTopologyResult(string Outcome, string Error, string SourceIdentity,
    string Journal, string PreXid, string PostXid, string BlockBytes, string ConfirmationToken,
    long ExpiresUnixSeconds, System.Text.Json.JsonElement Report)
{
    public bool Committed => Outcome == "committed";
}

public interface IVolumeTopologyBackend
{
    Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, CancellationToken token);
    Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, string operation, CancellationToken token)
        => ObserveVolumeTopologyAsync(scope, inventory, token);
    Task<VolumeTopologyResult> RunVolumeTopologyAsync(VolumeTopologyRequest request,
        VolumeTopologyMode mode, string? confirmation, CancellationToken token);
}

public static class VolumeTopologyProfile
{
    public const ulong MaximumImageBytes = 256UL * 1024 * 1024;
    public const ulong MaximumStreamedImageBytes = 1UL << 40;
    public static bool Number(string? text, bool zero = true) =>
        ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) &&
        (zero || value != 0) && value.ToString(CultureInfo.InvariantCulture) == text;
    public static bool Uuid(string? text) => text is { Length: 32 } &&
        text.All(char.IsAsciiHexDigitLower) && text.Any(c => c != '0');
    public static bool LocalPath(string? path) => path is not null && VerifyScopeDerivation.IsLocalImagePath(path);
    public static bool IsBounded(VerifyScope scope) => Number(scope.StoreSizeBytes, false) &&
        ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture) <= MaximumImageBytes;
    public static bool IsStreamedImage(VerifyScope scope, string operation) =>
        operation is "format" or "erase" or "grow" or "shrink" && LocalPath(scope.ImagePath) && scope.StoreOffsetBytes == "0" &&
        Number(scope.StoreSizeBytes, false) && ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture) is >= 1048576 and <= MaximumStreamedImageBytes &&
        ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture) % 4096 == 0;
    public static bool IsPhysicalFormat(VerifyScope scope, string operation) => operation is "format" or "erase" && IsPhysicalShape(scope);
    public static bool IsPhysicalResize(VerifyScope scope,string operation) => operation is "grow" or "shrink" && IsPhysicalShape(scope);
    public static bool IsPhysicalTopology(VerifyScope scope, string operation) => operation is "create" or "delete" &&
        IsPhysicalShape(scope) && IsBounded(scope);
    public static bool IsPhysicalManagement(VerifyScope scope,string operation) =>
        IsPhysicalFormat(scope,operation) || IsPhysicalResize(scope,operation) || IsPhysicalTopology(scope,operation);
    private static bool IsPhysicalShape(VerifyScope scope) =>
        VolumePhysicalBinding.IsDevicePath(scope.ImagePath) && Number(scope.StoreOffsetBytes) && Number(scope.StoreSizeBytes, false) &&
        ulong.Parse(scope.StoreOffsetBytes, CultureInfo.InvariantCulture) % 4096 == 0 &&
        ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture) is >= 1048576 and <= MaximumStreamedImageBytes &&
        ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture) % 4096 == 0 &&
        ulong.Parse(scope.StoreOffsetBytes, CultureInfo.InvariantCulture) <= long.MaxValue - ulong.Parse(scope.StoreSizeBytes, CultureInfo.InvariantCulture);
    public static VerifyScopeVerdict DeriveManagementScope(DeviceInventory inventory, VolumeInfo row, string operation)
        => operation is "format" or "erase" or "grow" or "shrink" or "create" or "delete" && VolumePhysicalBinding.IsDevicePath(row.DeviceId)
            ? VerifyScopeDerivation.TryDerivePhysicalManagement(inventory, row) : VerifyScopeDerivation.TryDerive(inventory, row);
    public static string Blocks(string bytes, string blockBytes)
    {
        if (!Number(bytes) || !Number(blockBytes, false)) throw new ArgumentException("Canonical byte limits and block size are required.");
        var amount = ulong.Parse(bytes, CultureInfo.InvariantCulture);
        var block = ulong.Parse(blockBytes, CultureInfo.InvariantCulture);
        return (amount / block + (amount % block == 0 ? 0UL : 1UL)).ToString(CultureInfo.InvariantCulture);
    }
}
