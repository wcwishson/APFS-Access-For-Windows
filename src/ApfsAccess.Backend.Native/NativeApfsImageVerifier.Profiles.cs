using System.Globalization;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Backend.Native;

public sealed record ApfsCurrentProfileVerificationRequest(string Profile, string Image, string ContainerId,
    string VolumeUuid, string VolumeOid, string CheckpointXid, string StoreOffsetBytes, string StoreSizeBytes,
    string? Tier2Image = null, string? Tier2OffsetBytes = null, string? Tier2SizeBytes = null,
    string? FusionUuid = null, string? FusionRoleConvention = null, bool RequireWholeVolume = false,
    bool RequirePayloadContentHashes = false, bool AccountRetainedOwnership = false, string? RetainedFromXid = null)
{
    public string? ExpectedMainIdentity { get; init; }
    public string? ExpectedTier2Identity { get; init; }
    internal bool Fusion => Profile == "fusion-clean-cache";
    internal ApfsImageVerificationRequest ImageScope => new(Image, ContainerId, VolumeUuid, VolumeOid, CheckpointXid,
        StoreOffsetBytes, StoreSizeBytes, RequireWholeVolume, RequirePayloadContentHashes, RetainedFromXid, AccountRetainedOwnership);
    internal ApfsImageVerificationRequest WireScope => ImageScope with { StoreOffsetBytes = Fusion ? StoreOffsetBytes : "0" };
}

public sealed record ApfsCurrentProfileVerificationResult(int NativeExitCode, ApfsVerificationOutcome Outcome, JsonElement Report);

public sealed partial class NativeApfsImageVerifier
{
    public bool CurrentProfileObserverAvailable => observerPath is not null && File.Exists(observerPath);

    public static ApfsCurrentProfileVerificationRequest CaptureCurrentProfileBindings(ApfsCurrentProfileVerificationRequest request)
    {
        using var held = new CurrentProfileSources(request);
        return request with { ExpectedMainIdentity = held.MainId, ExpectedTier2Identity = held.TierId };
    }

    public static IDisposable HoldCurrentProfileSources(ApfsCurrentProfileVerificationRequest request)
        => new CurrentProfileSources(request);

    public static ApfsCurrentProfileVerificationResult ValidateCurrentProfileReport(string json, int exitCode,
        ApfsCurrentProfileVerificationRequest request, string mainId, string? tierId, CancellationToken token = default)
        => ParseCurrentProfile(json,exitCode,request,mainId,tierId,token);

    private sealed class CurrentProfileSources : IDisposable
    {
        private readonly ApfsCurrentProfileVerificationRequest request;
        private Microsoft.Win32.SafeHandles.SafeFileHandle? main, tier;
        internal string MainId { get; private set; } = "";
        internal string? TierId { get; private set; }
        internal CurrentProfileSources(ApfsCurrentProfileVerificationRequest value)
        {
            request=value; ValidateCurrentProfileRequest(value);
            try
            {
                main=File.OpenHandle(value.Image,FileMode.Open,FileAccess.Read,FileShare.Read);
                NativeApfsSnapshotReader.ValidateIdentity(main,value.Image); MainId=ReadIdentity(main);
                if(value.Fusion)
                {
                    tier=File.OpenHandle(value.Tier2Image!,FileMode.Open,FileAccess.Read,FileShare.Read);
                    NativeApfsSnapshotReader.ValidateIdentity(tier,value.Tier2Image!); TierId=ReadIdentity(tier); Require(TierId!=MainId);
                }
                Require((value.ExpectedMainIdentity is null || value.ExpectedMainIdentity==MainId) &&
                    (value.ExpectedTier2Identity is null || value.ExpectedTier2Identity==TierId));
            }
            catch { Dispose(); throw; }
        }
        internal void RequireUnchanged()
        {
            NativeApfsSnapshotReader.ValidateIdentity(main!,request.Image); Require(ReadIdentity(main!)==MainId);
            if(tier is not null) { NativeApfsSnapshotReader.ValidateIdentity(tier,request.Tier2Image!);Require(ReadIdentity(tier)==TierId); }
        }
        public void Dispose(){tier?.Dispose();main?.Dispose();tier=null;main=null;}
    }

    public static void ValidateCurrentProfileRequest(ApfsCurrentProfileVerificationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Profile is not ("fusion-clean-cache" or "encrypted-onekey-generation-zero"))
            throw new ArgumentException("Select an explicit supported current verification profile.");
        ValidateRequest(request.ImageScope);
        if (request.Fusion)
        {
            if (request.Tier2Image is null || request.Tier2OffsetBytes is null || request.Tier2SizeBytes is null ||
                !IsHex(request.FusionUuid) || request.FusionRoleConvention != "linux-apfs-last-byte-low-bit")
                throw new ArgumentException("Fusion requires both exact member windows, Fusion UUID and explicit linux-apfs-last-byte-low-bit convention.");
            ValidateRequest(request.ImageScope with { Image = request.Tier2Image, StoreOffsetBytes = request.Tier2OffsetBytes, StoreSizeBytes = request.Tier2SizeBytes });
            if (string.Equals(request.Image, request.Tier2Image, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Fusion members must be distinct files.");
        }
        else if (request.Tier2Image is not null || request.Tier2OffsetBytes is not null || request.Tier2SizeBytes is not null ||
            request.FusionUuid is not null || request.FusionRoleConvention is not null || request.ExpectedTier2Identity is not null)
            throw new ArgumentException("Encrypted current verification accepts one exact image window.");
    }

    public ApfsCurrentProfileVerificationResult VerifyCurrentProfile(ApfsCurrentProfileVerificationRequest request,
        SupervisedCredential? credential = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested(); ValidateCurrentProfileRequest(request);
        if (request.Fusion == (credential is not null)) throw new ArgumentException("Only encrypted verification requires a supervised credential pipe.");
        if (observerPath is null) throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath);
        using var held = new CurrentProfileSources(request);
        var mainId=held.MainId;var tierId=held.TierId;
        var args = new List<string> { "--mode", "verify-profile", "--verification-profile", request.Profile,
            request.Fusion ? "--store-a" : "--image", request.Image, "--expected-main-identity", mainId,
            "--container-uuid", request.ContainerId[15..], "--volume-uuid", request.VolumeUuid, "--volume-oid", request.VolumeOid,
            "--checkpoint-xid", request.CheckpointXid, "--store-offset-bytes", request.StoreOffsetBytes, "--store-size-bytes", request.StoreSizeBytes };
        if (request.Fusion) args.AddRange(["--store-b", request.Tier2Image!, "--expected-tier2-identity", tierId!,
            "--tier2-offset-bytes", request.Tier2OffsetBytes!, "--tier2-size-bytes", request.Tier2SizeBytes!,
            "--fusion-uuid", request.FusionUuid!, "--fusion-role-convention", request.FusionRoleConvention!]);
        else args.Add("--credential-stdin");
        if (request.RequireWholeVolume) args.Add("--require-whole-volume");
        if (request.RequirePayloadContentHashes) args.Add("--require-payload-content-hashes");
        if (request.AccountRetainedOwnership) args.Add("--account-retained-ownership");
        if (request.RetainedFromXid is not null) args.AddRange(["--retained-from-xid", request.RetainedFromXid]);
        var wire = credential is null ? runner.Run(observerPath, args, cancellationToken) : runner.RunWithCredential(observerPath, args, credential, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3 or 4)) throw new NativeVerificationExitException(wire.ExitCode, wire.StandardError);
        var result = ParseCurrentProfile(wire.StandardOutput, wire.ExitCode, request, mainId, tierId, cancellationToken);
        held.RequireUnchanged();
        cancellationToken.ThrowIfCancellationRequested(); return result;
    }

    internal static ApfsCurrentProfileVerificationResult ParseCurrentProfile(string json, int exitCode,
        ApfsCurrentProfileVerificationRequest request, string mainId, string? tierId, CancellationToken token = default)
    {
        try
        {
            token.ThrowIfCancellationRequested(); Require(new UTF8Encoding(false, true).GetByteCount(json) <= MaxReportBytes &&
                request.Profile is "fusion-clean-cache" or "encrypted-onekey-generation-zero" &&
                (request.ExpectedMainIdentity is null || request.ExpectedMainIdentity==mainId) &&
                (request.ExpectedTier2Identity is null || request.ExpectedTier2Identity==tierId) &&
                (!request.Fusion || tierId is not null && tierId != mainId));
            using var document = JsonDocument.Parse(json); var root = document.RootElement;
            Object(root, "format version readOnly profile source requestedScope selected outcome outcomeName wholeVolumeVerified retainedOwnershipComplete payloadContentHashesVerified sourceReads sourceReadBytes counts snapshotAllocationChargeBytes applePurgeableBytes reclaimableBytes findings coverage");
            Require(Text(root, "format") == "apfs-access-current-profile-verification" && root.GetProperty("version").GetInt32() == 1 &&
                Bool(root, "readOnly") && Text(root, "profile") == request.Profile &&
                !Bool(root, "wholeVolumeVerified") && !Bool(root, "retainedOwnershipComplete") && !Bool(root, "payloadContentHashesVerified"));
            foreach (var key in new[] { "snapshotAllocationChargeBytes", "applePurgeableBytes", "reclaimableBytes" }) Require(root.GetProperty(key).ValueKind == JsonValueKind.Null);
            var outcome = EnumNumber(root, "outcome", 3); Require(exitCode == (outcome == 1 ? 0 : outcome == 2 ? 3 : 4) &&
                Text(root, "outcomeName") == ((ApfsVerificationOutcome)outcome).ToString());
            var source = root.GetProperty("source"); Object(source, "identity coordinateSystem stores");
            var identity = request.Fusion ? mainId + ":fusion:" + request.FusionUuid + ":" + tierId : mainId + ":scope:" + request.StoreOffsetBytes + ":" + request.StoreSizeBytes;
            Require(Text(source, "identity") == identity && Text(source, "coordinateSystem") == (request.Fusion ? "member-image-relative" : "container-relative"));
            var stores = source.GetProperty("stores"); Require(stores.ValueKind == JsonValueKind.Array && stores.GetArrayLength() == (request.Fusion ? 2 : 1));
            for (var i = 0; i < stores.GetArrayLength(); ++i)
            {
                var s = stores[i]; Object(s, "role id label offsetBytes sizeBytes");
                Require(Text(s, "role") == (request.Fusion ? (i == 0 ? "main" : "tier2") : "container") &&
                    Text(s, "id") == (request.Fusion ? (i == 0 ? mainId : tierId) : identity) &&
                    Text(s, "label") == (i == 0 ? request.Image : request.Tier2Image) &&
                    Text(s, "offsetBytes") == (i == 0 ? request.WireScope.StoreOffsetBytes : request.Tier2OffsetBytes) &&
                    Text(s, "sizeBytes") == (i == 0 ? request.StoreSizeBytes : request.Tier2SizeBytes));
                Require(Number(s, "sizeBytes", false) > 0); Number(s, "offsetBytes");
            }
            var scope = root.GetProperty("requestedScope");
            Object(scope, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes maxReads maxReadBytes maxRecords maxRecordBytes requireWholeVolume requirePayloadContentHashes observePayloadContent accountRetainedOwnership retainedFromXid");
            Exact(scope, request.WireScope);
            Require(Number(scope, "maxReads") == 65536 && Number(scope, "maxReadBytes") == 268435456 && Number(scope, "maxRecords") == 1000000 && Number(scope, "maxRecordBytes") == 268435456 &&
                Bool(scope, "requireWholeVolume") == request.RequireWholeVolume && Bool(scope, "requirePayloadContentHashes") == request.RequirePayloadContentHashes &&
                !Bool(scope, "observePayloadContent") && Bool(scope, "accountRetainedOwnership") == request.AccountRetainedOwnership &&
                (request.RetainedFromXid is null ? scope.GetProperty("retainedFromXid").ValueKind == JsonValueKind.Null : Text(scope, "retainedFromXid") == request.RetainedFromXid));
            Require(Number(root, "sourceReads") <= 65536 && Number(root, "sourceReadBytes") <= 268435456);
            var selected = root.GetProperty("selected");
            if (selected.ValueKind != JsonValueKind.Null)
            {
                Object(selected, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock"); Exact(selected, request.WireScope);
                Require(Number(selected, "volumeSuperblockXid", false) <= Number(scope, "checkpointXid", false));
                foreach (var field in new[] { "checkpointPhysicalBlock", "volumeSuperblockPhysicalBlock", "rootOid", "rootPhysicalBlock" }) Number(selected, field, false);
            }
            var expectedChecks = new HashSet<int> {1,2,3,5,6,7,8,9,11,13,17};
            expectedChecks.UnionWith(request.Fusion ? new[] {16,18} : new[] {15});
            var coverage = root.GetProperty("coverage"); Require(coverage.ValueKind == JsonValueKind.Array && coverage.GetArrayLength() == expectedChecks.Count);
            var states = new Dictionary<int,int>();
            foreach (var row in coverage.EnumerateArray())
            {
                token.ThrowIfCancellationRequested(); Object(row, "check implemented required state scopeDetail");
                var id = EnumNumber(row, "check", 22); var state = EnumNumber(row, "state", 5);
                Require(expectedChecks.Remove(id) && states.TryAdd(id,state)); ProfileText(row, "scopeDetail");
                Require(id == 13 ? (!Bool(row,"implemented") && !Bool(row,"required") && state == 5) :
                    (Bool(row,"implemented") && Bool(row,"required") && state != 5 && (outcome != 1 || state == 2)));
            }
            Require(expectedChecks.Count == 0);
            var findings = root.GetProperty("findings"); Require(findings.ValueKind == JsonValueKind.Array && findings.GetArrayLength() <= 1000000 && (findings.GetArrayLength() == 0) == (outcome == 1));
            var affected = new HashSet<int>();
            foreach (var f in findings.EnumerateArray())
            {
                token.ThrowIfCancellationRequested(); Object(f,"code severity check volumeOid objectId physicalBlock checkpointXid failedSourceOffsetBytes detail");
                EnumNumber(f,"code",27); var check = EnumNumber(f,"check",22);
                Require(states.TryGetValue(check,out var state) && state == (outcome == 3 ? 4 : 3) && EnumNumber(f,"severity",3) == (outcome == 3 ? 2 : 3)); affected.Add(check);
                foreach (var key in new[] {"volumeOid","objectId","physicalBlock","checkpointXid","failedSourceOffsetBytes"})
                    if (f.GetProperty(key).ValueKind != JsonValueKind.Null) Number(f,key);
                ProfileText(f,"detail");
            }
            foreach (var state in states) if (state.Value is 3 or 4) Require(affected.Contains(state.Key));
            var counts = root.GetProperty("counts");
            if (outcome != 1) Require(counts.ValueKind == JsonValueKind.Null);
            else
            {
                Require(selected.ValueKind == JsonValueKind.Object && !request.RequireWholeVolume && !request.RequirePayloadContentHashes && !request.AccountRetainedOwnership && request.RetainedFromXid is null);
                Object(counts,"allocationUnitBytes volumeCount filesystemRecords physicalExtentRecords metadataDependencyBlocks metadataCountScope");
                var bs = counts.GetProperty("allocationUnitBytes").GetUInt32(); Require(bs is >= 4096 and <= 65536 && (bs & (bs-1)) == 0);
                ulong capacity = 0;
                foreach (var s in stores.EnumerateArray()) { Require(Number(s,"offsetBytes") % bs == 0 && Number(s,"sizeBytes") % bs == 0); capacity = checked(capacity + Number(s,"sizeBytes") / bs); }
                var metadata = Number(counts,"metadataDependencyBlocks",false); var extents = Number(counts,"physicalExtentRecords");
                Require(metadata <= capacity && extents <= capacity-metadata && metadata <= 1000000 && extents <= 1000000 && Number(counts,"filesystemRecords",false) <= 1000000 && Number(counts,"volumeCount",false) <= 1000000 &&
                    (request.Fusion || Number(counts,"volumeCount") == 1) && Number(root,"sourceReads",false) > 0 && Number(root,"sourceReadBytes",false) > 0 &&
                    Text(counts,"metadataCountScope") == (request.Fusion ? "current-object-tree-union" : "current-metadata-dependency-and-guard-union"));
                bool Address(ulong block) => block < Number(stores[0],"sizeBytes") / bs || request.Fusion && block >= 0x4000000000000000UL / bs && block - 0x4000000000000000UL / bs < Number(stores[1],"sizeBytes") / bs;
                Require(Address(Number(selected,"checkpointPhysicalBlock",false)) && Address(Number(selected,"volumeSuperblockPhysicalBlock",false)) && Address(Number(selected,"rootPhysicalBlock",false)) &&
                    (!request.Fusion || Number(selected,"checkpointPhysicalBlock") < Number(stores[0],"sizeBytes") / bs));
            }
            return new(exitCode,(ApfsVerificationOutcome)outcome,root.Clone());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or KeyNotFoundException)
        { throw new InvalidDataException("Native current-profile report is invalid or mismatched.",ex); }
    }
    private static void ProfileText(JsonElement value, string key)
    { var text=Text(value,key); Require(text.Length > 0 && !text.Contains('\0') && Encoding.UTF8.GetByteCount(text) <= 65535); }
}
