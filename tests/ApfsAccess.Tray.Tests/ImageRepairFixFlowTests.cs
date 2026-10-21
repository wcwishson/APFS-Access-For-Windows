using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;
using System.Text.Json;

namespace ApfsAccess.Tray.Tests;

public sealed class ImageRepairFixFlowTests
{
    private readonly DateTime now = DateTime.UtcNow;
    private const string Image = @"D:\ApfsAccessScratch\Tests\repair-flow.apfsimg";
    private static readonly string Container = new('1', 32);
    private static readonly string Volume = new('2', 32);

    // Captured from a successful authenticated ordinary-image snapshot gate.
    private static (ControlOperationRequestPayload Request, OperationResultPayload Result) ActualSnapshotReceipt()
    {
        const string requestJson = """
            {
              "operationId": "7b1798e6-d0de-44c5-bc17-7a9fefa9c741",
              "command": "snapshot-list",
              "target": {
                "deviceId": "D:\\ApfsAccessScratch\\WindowsClosure\\used-rename-u05-20261017\\actual-20261017-234925-107\\image.apfs",
                "volumeId": "apfs-vol:88c088bb461c4cf18b0223e8c230f343:1024",
                "recoveryIdentity": "apfs-recovery-v1-0Kzx-d5_gaSScdG2BFgG0HIxKmFCp3vKeuBHa6DAmuI",
                "volumeUuid": "98c088bb461c4cf18b0223e8c230f344",
                "containerUuid": "88c088bb461c4cf18b0223e8c230f343",
                "volumeObjectId": 1024,
                "observationContract": "selected-v1:82983a7999de57cf1be9dee7a18ef47f767696263af34c39503637f3758481e4",
                "registeredImage": null,
                "registeredFusion": null
              },
              "requestedMode": null,
              "expiresAtUtc": "2026-10-17T16:58:48.3555501Z"
            }
            """;
        const string resultJson = """
            {
              "operationId": "7b1798e6-d0de-44c5-bc17-7a9fefa9c741",
              "command": "snapshot-list",
              "target": {
                "deviceId": "d:\\apfsaccessscratch\\windowsclosure\\used-rename-u05-20261017\\actual-20261017-234925-107\\image.apfs",
                "volumeId": "apfs-vol:88c088bb461c4cf18b0223e8c230f343:1024",
                "recoveryIdentity": "apfs-recovery-v1-0Kzx-d5_gaSScdG2BFgG0HIxKmFCp3vKeuBHa6DAmuI",
                "volumeUuid": "98c088bb461c4cf18b0223e8c230f344",
                "containerUuid": "88c088bb461c4cf18b0223e8c230f343",
                "volumeObjectId": 1024,
                "observationContract": "selected-v1:82983a7999de57cf1be9dee7a18ef47f767696263af34c39503637f3758481e4",
                "registeredImage": null,
                "registeredFusion": null
              },
              "fingerprint": "sha256:d922db1502fb5fc2affe0dcfd5f2384ded631ebe42a8074cefd7ac7b6a99377c",
              "state": "succeeded",
              "code": "ok",
              "success": true,
              "requestedAtUtc": "2026-10-17T16:57:28.6533707Z",
              "startedAtUtc": "2026-10-17T16:57:28.8239026Z",
              "completedAtUtc": "2026-10-17T16:57:30.1866764Z",
              "finalStatus": "snapshot-inventory",
              "evidencePath": "D:\\ApfsAccessScratch\\WindowsClosure\\used-rename-u05-20261017\\snapshot-actual-20261018-005720-872\\runtime\\agent-operations\\7b1798e6-d0de-44c5-bc17-7a9fefa9c741.json",
              "requestedMode": null,
              "effectiveMode": null,
              "recoveryState": null,
              "recoveryActive": false,
              "dirtyTransactionCount": 0,
              "pendingDurability": false,
              "mountProof": "absent",
              "ownershipProof": "proven",
              "durabilityProof": "not-applicable",
              "diagnostic": "Read-only snapshot inventory from the exact offline image.",
              "quitMarkerWritten": false,
              "expiresAtUtc": "2026-10-17T16:58:48.3555501Z",
              "encryptionState": null,
              "snapshotInventory": {
                "format": "apfs-access-snapshot-inventory",
                "version": 1,
                "readOnly": true,
                "source": {
                  "kind": "image",
                  "path": "D:\\ApfsAccessScratch\\WindowsClosure\\used-rename-u05-20261017\\actual-20261017-234925-107\\image.apfs",
                  "sizeBytes": 4194304,
                  "hashScope": "full",
                  "sha256": "cdc5b0383bf77fb2b20e4a115db3b058ab9edbd0b569708068b79c439efe4b3e"
                },
                "containerUuid": "88c088bb461c4cf18b0223e8c230f343",
                "volumeUuid": "98c088bb461c4cf18b0223e8c230f344",
                "volumeId": "apfs-vol:88c088bb461c4cf18b0223e8c230f343:1024",
                "volumeOid": "1024",
                "checkpointXid": "31",
                "storeOffsetBytes": "0",
                "storeSizeBytes": "4194304",
                "snapshots": [
                  {
                    "xid": "30",
                    "name": "U05-retained-1024",
                    "uuid": null,
                    "createTimeNs": "1792253778440265800",
                    "superblockPhysicalBlock": "12",
                    "omapPhysicalBlock": "21",
                    "omapTreePhysicalBlock": "20",
                    "rootOid": "1024",
                    "rootPhysicalBlock": "19",
                    "extentrefPhysicalBlock": "35"
                  }
                ]
              }
            }
            """;
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        return (JsonSerializer.Deserialize<ControlOperationRequestPayload>(requestJson, options)!,
            JsonSerializer.Deserialize<OperationResultPayload>(resultJson, options)!);
    }

    [Fact]
    public void ActualSuccessfulServiceReceiptAcceptsCanonicalWindowsDeviceSpelling()
    {
        var (request, result) = ActualSnapshotReceipt();
        Assert.NotEqual(request.Target!.DeviceId, result.Target!.DeviceId);
        Assert.Equal(request.Target.DeviceId.ToLowerInvariant(), result.Target.DeviceId);
        ControlOperationReply.RequireSuccess(request, result);
    }

    [Theory]
    [InlineData("device")]
    [InlineData("operation")]
    [InlineData("volume")]
    [InlineData("recovery")]
    [InlineData("volume-uuid")]
    [InlineData("container")]
    [InlineData("scope")]
    [InlineData("ownership")]
    public void ActualReceiptCannotHideOtherIdentityOrProofChanges(string fault)
    {
        var (request, result) = ActualSnapshotReceipt();
        result = fault switch
        {
            "device" => result with { Target = result.Target! with { DeviceId = @"D:\ApfsAccessScratch\other.apfs" } },
            "operation" => result with { OperationId = Guid.NewGuid().ToString("D") },
            "volume" => result with { Target = result.Target! with { VolumeId = result.Target.VolumeId.ToUpperInvariant() } },
            "recovery" => result with { Target = result.Target! with { RecoveryIdentity = result.Target.RecoveryIdentity!.ToLowerInvariant() } },
            "volume-uuid" => result with { Target = result.Target! with { VolumeUuid = result.Target.VolumeUuid!.ToUpperInvariant() } },
            "container" => result with { Target = result.Target! with { ContainerUuid = result.Target.ContainerUuid!.ToUpperInvariant() } },
            "scope" => result with { Target = result.Target! with { ObservationContract = result.Target.ObservationContract!.ToUpperInvariant() } },
            _ => result with { OwnershipProof = "invented-proof" },
        };
        Assert.Throws<IOException>(() => ControlOperationReply.RequireSuccess(request, result));
    }

    [Fact]
    public void OpaqueDeviceIdentityDoesNotBecomeCaseInsensitive()
    {
        var (request, result) = ActualSnapshotReceipt();
        request = request with { Target = request.Target! with { DeviceId = "opaque:Device" } };
        result = result with { Target = request.Target with { DeviceId = "opaque:device" }, Fingerprint = ApfsOperationFingerprint.Compute(request) };
        Assert.Throws<IOException>(() => ControlOperationReply.RequireSuccess(request, result));
    }

    private (ControlOperationRequestPayload Request, OperationResultPayload Result) FusionRoundTripReceipt()
    {
        var profile = new FusionImageProfile(new('a', 32), new('b', 32), new('c', 32), 101, 7,
            [new(@"D:\ApfsAccessScratch\main.apfs", "main", "main-store", 0, 131072, "main-identity"),
             new(@"D:\ApfsAccessScratch\tier.apfs", "tier2", "tier-store", 0, 32768, "tier-identity")]);
        Assert.True(profile.IsValid());
        var request = FusionImageRegistration.CreateRequest(profile);
        var result = new OperationResultPayload(request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request), ApfsOperationStates.Succeeded,
            ApfsOperationCodes.OperationSucceeded, true, now, now, now,
            FinalStatus: "registered", MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc);
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, options);
        var copy = JsonSerializer.Deserialize<OperationResultPayload>(bytes, options)!;
        Assert.Equal(bytes, JsonSerializer.SerializeToUtf8Bytes(copy, options));
        Assert.NotSame(request.Target!.RegisteredFusion!.Members, copy.Target!.RegisteredFusion!.Members);
        Assert.NotEqual(request.Target, copy.Target);
        return (request, copy);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FusionRegistrationWireRoundTripAcceptsOrderedMemberValues(bool lowercaseDevice)
    {
        var (request, result) = FusionRoundTripReceipt();
        if (lowercaseDevice) result = result with { Target = result.Target! with { DeviceId = result.Target.DeviceId.ToLowerInvariant() } };
        ControlOperationReply.RequireSuccess(request, result);
    }

    [Theory]
    [InlineData("path")]
    [InlineData("role")]
    [InlineData("store")]
    [InlineData("offset")]
    [InlineData("size")]
    [InlineData("identity")]
    [InlineData("reordered")]
    [InlineData("missing")]
    [InlineData("profile-missing")]
    [InlineData("container")]
    [InlineData("fusion")]
    [InlineData("volume")]
    [InlineData("oid")]
    [InlineData("xid")]
    public void FusionWireRoundTripCannotChangeMemberOrProfileAuthority(string fault)
    {
        var (request, result) = FusionRoundTripReceipt();
        var profile = result.Target!.RegisteredFusion!;
        var member = profile.Members[0];
        var changed = fault switch
        {
            "path" => profile with { Members = [member with { Path = member.Path.ToLowerInvariant() }, profile.Members[1]] },
            "role" => profile with { Members = [member with { Role = "tier2" }, profile.Members[1]] },
            "store" => profile with { Members = [member with { StoreId = "other" }, profile.Members[1]] },
            "offset" => profile with { Members = [member with { StoreOffset = 4096 }, profile.Members[1]] },
            "size" => profile with { Members = [member with { StoreSize = 65536 }, profile.Members[1]] },
            "identity" => profile with { Members = [member with { Identity = "other" }, profile.Members[1]] },
            "reordered" => profile with { Members = [profile.Members[1], member] },
            "missing" => profile with { Members = [member] },
            "profile-missing" => null,
            "container" => profile with { ContainerUuid = new('d', 32) },
            "fusion" => profile with { FusionUuid = new('d', 32) },
            "volume" => profile with { VolumeUuid = new('d', 32) },
            "oid" => profile with { VolumeOid = 102 },
            _ => profile with { CheckpointXid = 8 },
        };
        result = result with { Target = result.Target with { RegisteredFusion = changed } };
        Assert.Throws<IOException>(() => ControlOperationReply.RequireSuccess(request, result));
    }

    [Fact]
    public async Task RepairOfferAndFinalReceiptAcceptOnlyWindowsDeviceCaseChange()
    {
        var request = Request();
        var offer = Offer();
        var calls = 0;
        var result = await ImageRepairFixFlow.ExecuteAsync(request, sent =>
        {
            var reply = ++calls == 1 ? Offered(sent, offer) : Healthy(sent, offer);
            return Task.FromResult(reply with { Target = reply.Target! with { DeviceId = reply.Target.DeviceId.ToLowerInvariant() } });
        }, _ => Task.FromResult(true), () => now);
        Assert.Equal(2, calls);
        Assert.True(result!.Success);
        Assert.True(result.ImageRepairReceipt!.NativePostVerifyComplete);
    }

    [Theory]
    [InlineData("device")]
    [InlineData("operation")]
    [InlineData("volume")]
    public async Task NormalizedRepairReplyCannotChangeOtherAuthority(string fault)
    {
        var request = Request();
        var reply = Healthy(request) with { Target = request.Target! with { DeviceId = request.Target.DeviceId.ToLowerInvariant() } };
        reply = fault switch
        {
            "device" => reply with { Target = reply.Target! with { DeviceId = @"D:\ApfsAccessScratch\other.apfs" } },
            "operation" => reply with { OperationId = Guid.NewGuid().ToString("D") },
            _ => reply with { Target = reply.Target! with { VolumeId = reply.Target.VolumeId + "-other" } },
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() => ImageRepairFixFlow.ExecuteAsync(request,
            _ => Task.FromResult(reply), _ => throw new InvalidOperationException("No prompt permitted"), () => now));
    }

    private ControlOperationRequestPayload Request() => new(Guid.NewGuid().ToString("D"), ApfsControlCommands.Fix,
        new(Image, "apfs-vol:" + Container + ":101", "recovery-fixture", Volume, Container, 101,
            "selected-v1:" + new string('e', 64)), ExpiresAtUtc: now.AddMinutes(1));

    private ImageRepairOffer Offer() => new(new string('d', 64), now.AddMinutes(3),
        new(Image, "apfs-container:" + Container, Volume, "101", "7", "0", "16777216"),
        "recovery-fixture", "selected-v1:" + new string('e', 64), new string('c', 64), "0",
        "windows-image-v1:" + new string('a', 48) + "00000000000000000000000001000000:100", new string('b', 64));

    private OperationResultPayload Offered(ControlOperationRequestPayload request, ImageRepairOffer? offer = null)
        => new(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Failed, ApfsOperationCodes.BlockedRecovery, false, now, now, now,
            FinalStatus: "repair-confirmation-required", MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "proven", ExpiresAtUtc: request.ExpiresAtUtc, ImageRepairOffer: offer ?? Offer());

    private OperationResultPayload Healthy(ControlOperationRequestPayload request, ImageRepairOffer? binding = null)
        => new(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, now, now, now,
            FinalStatus: "healthy-rw", EffectiveMode: ApfsControlModes.ReadWrite, RecoveryState: "inactive",
            MountProof: "present", OwnershipProof: "not-applicable", DurabilityProof: "not-applicable",
            ExpiresAtUtc: request.ExpiresAtUtc, ApprovedImageRepairPlanId: request.ApprovedImageRepairPlanId,
            ImageRepairReceipt: binding is null ? null : new(binding.PlanId, "repaired", binding,
                @"D:\ApfsAccessScratch\Tests\lineage\original.rct2", @"D:\ApfsAccessScratch\Tests\lineage\evidence",
                "RepairedAndVerified", 0, NativePostVerifyComplete: true));

    [Fact]
    public async Task HealthyFixDoesNotPromptOrSendAnotherOperation()
    {
        var request = Request();
        var healthy = Healthy(request);
        var calls = 0;
        var result = await ImageRepairFixFlow.ExecuteAsync(request, _ => { ++calls; return Task.FromResult(healthy); },
            _ => throw new InvalidOperationException("Healthy Fix must not prompt."), () => now);
        Assert.Same(healthy, result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task DecliningDoesNotDispatchApproval()
    {
        var request = Request();
        var calls = 0;
        var prompts = 0;
        var result = await ImageRepairFixFlow.ExecuteAsync(request,
            value => { ++calls; Assert.Null(value.ApprovedImageRepairPlanId); return Task.FromResult(Offered(request)); },
            _ => { ++prompts; return Task.FromResult(false); }, () => now);
        Assert.Null(result);
        Assert.Equal(1, calls);
        Assert.Equal(1, prompts);
    }

    [Fact]
    public async Task PreviouslyAcceptedRecoveryDoesNotPromptForFreshApproval()
    {
        var request = Request();
        var binding = Offer() with { ExpiresAtUtc = now.AddMinutes(-1) };
        var recovered = Healthy(request, binding);
        recovered = recovered with
        {
            ImageRepairReceipt = recovered.ImageRepairReceipt! with
            { OriginalAcceptedOperationId = Guid.NewGuid().ToString("D"), Replayed = true },
        };
        var calls = 0;
        var result = await ImageRepairFixFlow.ExecuteAsync(request,
            sent => { calls++; Assert.Null(sent.ApprovedImageRepairPlanId); return Task.FromResult(recovered); },
            _ => throw new InvalidOperationException("Accepted recovery must not ask for a new repair approval."), () => now);
        Assert.Same(recovered, result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ConfirmationIssuesOneFreshCorrelatedApproval()
    {
        var request = Request();
        var offer = Offer();
        var sent = new List<ControlOperationRequestPayload>();
        var result = await ImageRepairFixFlow.ExecuteAsync(request, value =>
        {
            sent.Add(value);
            return Task.FromResult(sent.Count == 1 ? Offered(request, offer) : Healthy(value, offer));
        }, shown => { Assert.Same(offer, shown); return Task.FromResult(true); }, () => now);
        Assert.Equal(2, sent.Count);
        Assert.Equal(request.Target, sent[1].Target);
        Assert.NotEqual(request.OperationId, sent[1].OperationId);
        Assert.Equal(offer.PlanId, sent[1].ApprovedImageRepairPlanId);
        Assert.Equal(now.AddMinutes(2), sent[1].ExpiresAtUtc);
        Assert.True(sent[1].ExpiresAtUtc <= offer.ExpiresAtUtc);
        Assert.True(result!.Success);
        Assert.Equal(offer, result.ImageRepairReceipt!.Binding);
    }

    [Theory]
    [InlineData("image")]
    [InlineData("volume")]
    [InlineData("recovery")]
    [InlineData("observation")]
    [InlineData("oid")]
    [InlineData("expired")]
    public async Task InvalidOfferDoesNotPromptOrApprove(string mutation)
    {
        var request = Request();
        var offer = Offer();
        offer = mutation switch
        {
            "image" => offer with { Scope = offer.Scope with { ImagePath = @"D:\ApfsAccessScratch\Tests\other.apfsimg" } },
            "volume" => offer with { Scope = offer.Scope with { VolumeUuid = new string('3', 32) } },
            "recovery" => offer with { RecoveryIdentity = "other-recovery" },
            "observation" => offer with { ObservationContract = "selected-v1:" + new string('a', 64) },
            "oid" => offer with { Scope = offer.Scope with { VolumeObjectId = "102" } },
            _ => offer with { ExpiresAtUtc = now.AddTicks(-1) },
        };
        var calls = 0;
        var prompts = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ImageRepairFixFlow.ExecuteAsync(request,
            _ => { ++calls; return Task.FromResult(Offered(request, offer)); },
            _ => { ++prompts; return Task.FromResult(true); }, () => now));
        Assert.Equal(1, calls);
        Assert.Equal(0, prompts);
    }

    [Fact]
    public async Task ExpiryWhileConfirmingPreventsApply()
    {
        var request = Request();
        var offer = Offer();
        var current = now;
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ImageRepairFixFlow.ExecuteAsync(request,
            _ => { ++calls; return Task.FromResult(Offered(request, offer)); },
            _ => { current = offer.ExpiresAtUtc; return Task.FromResult(true); }, () => current));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CancelledPromptCannotApply()
    {
        var request = Request();
        var calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ImageRepairFixFlow.ExecuteAsync(request,
            _ => { ++calls; return Task.FromResult(Offered(request)); },
            _ => Task.FromCanceled<bool>(new CancellationToken(true)), () => now));
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("echo")]
    [InlineData("binding")]
    [InlineData("receipt")]
    [InlineData("post-verify")]
    [InlineData("mount")]
    public async Task MissingFinalRepairOrMountProofCannotBecomeSuccess(string mutation)
    {
        var request = Request();
        var offer = Offer();
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ImageRepairFixFlow.ExecuteAsync(request, value =>
        {
            if (++calls == 1) return Task.FromResult(Offered(request, offer));
            var terminal = Healthy(value, offer);
            terminal = mutation switch
            {
                "echo" => terminal with { ApprovedImageRepairPlanId = null },
                "binding" => terminal with { ImageRepairReceipt = terminal.ImageRepairReceipt! with
                    { Binding = offer with { SourceSha256 = new string('f', 64) } } },
                "receipt" => terminal with { ImageRepairReceipt = null },
                "post-verify" => terminal with { ImageRepairReceipt = terminal.ImageRepairReceipt! with { NativePostVerifyComplete = false } },
                _ => terminal with { Success = false, FinalStatus = "verification-not-complete" },
            };
            return Task.FromResult(terminal);
        }, _ => Task.FromResult(true), () => now));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task ForgedOfferFingerprintCannotPrompt()
    {
        var request = Request();
        var calls = 0;
        var prompts = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => ImageRepairFixFlow.ExecuteAsync(request,
            _ => { ++calls; return Task.FromResult(Offered(request) with { Fingerprint = "sha256:" + new string('f', 64) }); },
            _ => { ++prompts; return Task.FromResult(true); }, () => now));
        Assert.Equal(1, calls);
        Assert.Equal(0, prompts);
    }
}
