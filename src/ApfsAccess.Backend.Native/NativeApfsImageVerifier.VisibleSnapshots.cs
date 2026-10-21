using System.Globalization;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Backend.Native;

public sealed record ApfsVisibleSnapshotProfileRequest(ApfsCurrentProfileVerificationRequest Endpoint, string? FromXid = null);
public sealed record ApfsVisibleSnapshotProfileResult(int NativeExitCode, ApfsVerificationOutcome Outcome, JsonElement Report);

public sealed partial class NativeApfsImageVerifier
{
    public static void ValidateVisibleSnapshotProfileRequest(ApfsVisibleSnapshotProfileRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateCurrentProfileRequest(request.Endpoint);
        if (request.Endpoint.RetainedFromXid is not null || request.FromXid is not null &&
            (!NativeApfsSnapshotReader.IsU64(request.FromXid, false) || ulong.Parse(request.FromXid, CultureInfo.InvariantCulture) >=
                ulong.Parse(request.Endpoint.CheckpointXid, CultureInfo.InvariantCulture)))
            throw new ArgumentException("Select an optional earlier explicit parent XID for visible snapshot verification.");
    }

    public ApfsVisibleSnapshotProfileResult VerifyVisibleSnapshotProfile(ApfsVisibleSnapshotProfileRequest request,
        SupervisedCredential? credential = null, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested(); ValidateVisibleSnapshotProfileRequest(request);
        var q = request.Endpoint;
        if (q.Fusion == (credential is not null)) throw new ArgumentException("Only encrypted verification requires a supervised credential pipe.");
        if (observerPath is null) throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath);
        using var held = new CurrentProfileSources(q);
        var args = new List<string> { "--mode", "verify-profile-snapshots", "--verification-profile", q.Profile,
            q.Fusion ? "--store-a" : "--image", q.Image, "--expected-main-identity", held.MainId,
            "--container-uuid", q.ContainerId[15..], "--volume-uuid", q.VolumeUuid, "--volume-oid", q.VolumeOid,
            "--checkpoint-xid", q.CheckpointXid, "--store-offset-bytes", q.StoreOffsetBytes, "--store-size-bytes", q.StoreSizeBytes };
        if (q.Fusion) args.AddRange(["--store-b", q.Tier2Image!, "--expected-tier2-identity", held.TierId!,
            "--tier2-offset-bytes", q.Tier2OffsetBytes!, "--tier2-size-bytes", q.Tier2SizeBytes!,
            "--fusion-uuid", q.FusionUuid!, "--fusion-role-convention", q.FusionRoleConvention!]);
        else args.Add("--credential-stdin");
        if (request.FromXid is not null) args.AddRange(["--retained-from-xid", request.FromXid]);
        if (q.RequireWholeVolume) args.Add("--require-whole-volume");
        if (q.RequirePayloadContentHashes) args.Add("--require-payload-content-hashes");
        if (q.AccountRetainedOwnership) args.Add("--account-retained-ownership");
        var wire = credential is null ? runner.Run(observerPath, args, token) : runner.RunWithCredential(observerPath, args, credential, token);
        token.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3 or 4)) throw new NativeVerificationExitException(wire.ExitCode, wire.StandardError);
        var result = ValidateVisibleSnapshotProfileReport(wire.StandardOutput, wire.ExitCode, request, held.MainId, held.TierId, token);
        held.RequireUnchanged(); token.ThrowIfCancellationRequested(); return result;
    }

    public static ApfsVisibleSnapshotProfileResult ValidateVisibleSnapshotProfileReport(string json, int exitCode,
        ApfsVisibleSnapshotProfileRequest request, string mainId, string? tierId, CancellationToken token = default)
    {
        try
        {
            token.ThrowIfCancellationRequested(); ValidateVisibleSnapshotProfileRequest(request); var q = request.Endpoint;
            Require(new UTF8Encoding(false, true).GetByteCount(json) <= MaxReportBytes &&
                (q.ExpectedMainIdentity is null || q.ExpectedMainIdentity == mainId) &&
                (q.ExpectedTier2Identity is null || q.ExpectedTier2Identity == tierId) && (!q.Fusion || tierId is not null && tierId != mainId));
            using var document = JsonDocument.Parse(json); var root = document.RootElement;
            Object(root, "format version readOnly profile source requestedScope fromXid selected outcome outcomeName wholeVolumeVerified retainedOwnershipComplete payloadContentHashesVerified visibleSnapshotNamespacesVerified sourceReads sourceReadBytes graph attribution counterMeaning independentSnapshotChargeVerified snapshotAllocationChargeBytes applePurgeableBytes reclaimableBytes findings coverage");
            Require(Text(root, "format") == "apfs-access-visible-snapshot-profile-verification" && root.GetProperty("version").GetInt32() == 1 &&
                Bool(root, "readOnly") && Text(root, "profile") == q.Profile && !Bool(root, "wholeVolumeVerified") &&
                !Bool(root, "retainedOwnershipComplete") && !Bool(root, "payloadContentHashesVerified") && !Bool(root, "independentSnapshotChargeVerified") &&
                Text(root, "counterMeaning") == "parsed-apfs-fs-alloc-count-at-descriptor-xid");
            Require(request.FromXid is null ? root.GetProperty("fromXid").ValueKind == JsonValueKind.Null : Text(root, "fromXid") == request.FromXid);
            foreach (var field in new[] { "snapshotAllocationChargeBytes", "applePurgeableBytes", "reclaimableBytes" }) Require(root.GetProperty(field).ValueKind == JsonValueKind.Null);
            var outcome = EnumNumber(root, "outcome", 3); var complete = outcome == 1;
            Require(exitCode == (complete ? 0 : outcome == 2 ? 3 : 4) && Text(root, "outcomeName") == ((ApfsVerificationOutcome)outcome).ToString());
            var source = root.GetProperty("source"); Object(source, "identity coordinateSystem stores");
            var identity = q.Fusion ? mainId + ":fusion:" + q.FusionUuid + ":" + tierId : mainId + ":scope:" + q.StoreOffsetBytes + ":" + q.StoreSizeBytes;
            Require(Text(source, "identity") == identity && Text(source, "coordinateSystem") == (q.Fusion ? "member-image-relative" : "container-relative"));
            var stores = source.GetProperty("stores"); Require(stores.ValueKind == JsonValueKind.Array && stores.GetArrayLength() == (q.Fusion ? 2 : 1));
            var sizes = new ulong[stores.GetArrayLength()]; var offsets = new ulong[sizes.Length];
            for (var i = 0; i < sizes.Length; ++i)
            {
                var store = stores[i]; Object(store, "role id label offsetBytes sizeBytes");
                Require(Text(store, "role") == (q.Fusion ? (i == 0 ? "main" : "tier2") : "container") &&
                    Text(store, "id") == (q.Fusion ? (i == 0 ? mainId : tierId) : identity) && Text(store, "label") == (i == 0 ? q.Image : q.Tier2Image) &&
                    Text(store, "offsetBytes") == (i == 0 ? q.WireScope.StoreOffsetBytes : q.Tier2OffsetBytes) && Text(store, "sizeBytes") == (i == 0 ? q.StoreSizeBytes : q.Tier2SizeBytes));
                sizes[i] = Number(store, "sizeBytes", false); offsets[i] = Number(store, "offsetBytes");
                Require(offsets[i] <= ulong.MaxValue - sizes[i] && offsets[i] % 4096 == 0 && sizes[i] % 4096 == 0);
            }
            var scope = root.GetProperty("requestedScope");
            Object(scope, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes maxReads maxReadBytes maxRecords maxRecordBytes requireWholeVolume requirePayloadContentHashes observePayloadContent accountRetainedOwnership retainedFromXid");
            Exact(scope, q.WireScope);
            Require(Number(scope, "maxReads") == 65536 && Number(scope, "maxReadBytes") == 268435456 && Number(scope, "maxRecords") == 1000000 &&
                Number(scope, "maxRecordBytes") == 268435456 && Bool(scope, "requireWholeVolume") == q.RequireWholeVolume &&
                Bool(scope, "requirePayloadContentHashes") == q.RequirePayloadContentHashes && Bool(scope, "accountRetainedOwnership") == q.AccountRetainedOwnership &&
                !Bool(scope, "observePayloadContent") && scope.GetProperty("retainedFromXid").ValueKind == JsonValueKind.Null &&
                Number(root, "sourceReads") <= 65536 && Number(root, "sourceReadBytes") <= 268435456);
            var findings = root.GetProperty("findings"); Require(findings.ValueKind == JsonValueKind.Array && findings.GetArrayLength() <= 1000000 && complete == (findings.GetArrayLength() == 0));
            foreach (var finding in findings.EnumerateArray())
            {
                token.ThrowIfCancellationRequested(); Object(finding, "code severity check volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
                EnumNumber(finding, "code", 27); Require(EnumNumber(finding, "check", 22) == 20 && EnumNumber(finding, "severity", 3) == (outcome == 3 ? 2 : 3));
                foreach (var field in new[] { "volumeOid", "objectId", "physicalBlock", "checkpointXid", "failedSourceOffsetBytes" })
                    if (finding.GetProperty(field).ValueKind != JsonValueKind.Null) Number(finding, field);
                ProfileText(finding, "detail");
            }
            var coverage = root.GetProperty("coverage"); Require(coverage.ValueKind == JsonValueKind.Array && coverage.GetArrayLength() == 1);
            var covered = coverage[0]; Object(covered, "check implemented required state scopeDetail");
            Require(EnumNumber(covered, "check", 22) == 20 && Bool(covered, "implemented") && Bool(covered, "required") && EnumNumber(covered, "state", 5) == (complete ? 2 : outcome == 3 ? 4 : 3));
            ProfileText(covered, "scopeDetail");
            if (!complete)
                Require(root.GetProperty("selected").ValueKind == JsonValueKind.Null && root.GetProperty("graph").ValueKind == JsonValueKind.Null &&
                    root.GetProperty("attribution").ValueKind == JsonValueKind.Null && root.GetProperty("visibleSnapshotNamespacesVerified").ValueKind == JsonValueKind.Null);
            else
            {
                Require(!q.RequireWholeVolume && !q.RequirePayloadContentHashes && !q.AccountRetainedOwnership && Bool(root, "visibleSnapshotNamespacesVerified") &&
                    Number(root, "sourceReads", false) > 0 && Number(root, "sourceReadBytes", false) > 0);
                ValidateVisibleSnapshotSets(root, request, sizes, offsets, token);
            }
            return new(exitCode, (ApfsVerificationOutcome)outcome, root.Clone());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or ArgumentException)
        { throw new InvalidDataException("Native observer returned invalid or mismatched visible snapshot profile output.", ex); }
    }
}
