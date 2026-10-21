namespace ApfsAccess.Core;

// Task 11 Step 3: management keeper contract. A keeper executes one
// planned topology mutation through a native image tool after the service
// has verified the plan, confirmed freshness, and consumed the single-use
// token. All identity fields are canonical strings (lowercase hex UUIDs,
// decimal uint64), matching the pipe and tool contracts. The native tool
// re-proves every identity claim from image bytes; a mismatched file,
// twin image at an older generation, or unexpected bytes fail closed.
public sealed record ManagementKeeperRenameRequest(
    string ImagePath,
    string ContainerUuid,
    string VolumeUuid,
    string VolumeObjectId,
    string PreimageXid,
    string NewLabel,
    string JournalRoot);

public static class ManagementKeeperCodes
{
    public const string Committed = "Committed";
    public const string Refused = "Refused";
    public const string StalePreimage = "StalePreimage";
    public const string KeeperUnavailable = "KeeperUnavailable";
    public const string InvalidRequest = "InvalidRequest";
    public const string Unproven = "Unproven";
}

public sealed record ManagementKeeperRenameResult(
    bool Committed,
    ulong CommittedXid,
    string Code,
    string? Detail);

public sealed record ManagementKeeperQuotaRequest(
    string ImagePath,
    string ContainerUuid,
    string VolumeUuid,
    string VolumeObjectId,
    string PreimageXid,
    string QuotaBytes,
    string ReserveBytes,
    IReadOnlyList<string> SiblingObjectIds,
    string JournalRoot);

public sealed record ManagementKeeperQuotaResult(
    bool Committed,
    ulong CommittedXid,
    string Code,
    string? Detail);

public interface IManagementRenameKeeper
{
    // Renames one volume in an offline image through the exact plan-bound
    // identity. The backend scopes its journal to the image path, recovers
    // one accepted-but-unrecovered operation at most, and verifies the
    // tool's claims (exit code, exact stdout binding, stable file
    // identity) before reporting Committed.
    Task<ManagementKeeperRenameResult> RenameVolumeAsync(
        ManagementKeeperRenameRequest request,
        CancellationToken cancellationToken);
}

public interface IManagementQuotaKeeper
{
    // Sets quota/reserve maximums on one volume in an offline image. The
    // backend observes the container block size with a read-only dry-run,
    // converts the requested byte limits to whole blocks (rounding up;
    // zero clears), re-runs the dry-run to bind a native confirm token,
    // and commits only against that token. SiblingObjectIds must list
    // every other volume object ID in the container so the tool receives
    // its required complete per-volume WAL census; the native side
    // re-verifies completeness from bytes.
    Task<ManagementKeeperQuotaResult> SetQuotaReserveAsync(
        ManagementKeeperQuotaRequest request,
        CancellationToken cancellationToken);
}
