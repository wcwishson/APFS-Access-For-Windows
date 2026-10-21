using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    private static readonly long LiveFixOwnerCreationTime = new DateTime(2026, 10, 15, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

    [Theory]
    [InlineData("healthy", 2, 0, 0)]
    [InlineData("remount", 2, 1, 1)]
    [InlineData("bootstrap", 1, 1, 0)]
    public async Task LiveFixVerifiesExactPhysicalOwnerBeforeAndAfterAdmittedMount(
        string initial, int verifies, int mounts, int unmounts)
    {
        using var route = await OpenLiveFixAsync(initial);
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("healthy-rw", result.FinalStatus);
        Assert.Equal("not-applicable", result.OwnershipProof);
        Assert.Equal(verifies, route.Backend.Calls.Count);
        Assert.Equal(verifies, route.Backend.MetadataCalls);
        Assert.Equal(0, route.Backend.FullCalls);
        Assert.Equal(mounts, route.Inner.MountCalls);
        Assert.Equal(unmounts, route.Inner.UnmountCalls);
        Assert.Equal(route.Backend.FinalOwner.VolumeVerificationScope, route.Backend.Calls[^1]);
        Assert.True(route.InitialOwner.HostProcessCreationTimeFileTimeUtc > 0);
        Assert.True(route.Backend.FinalOwner.HostProcessCreationTimeFileTimeUtc > 0);
        if (initial == "remount")
        {
            Assert.NotEqual(route.Backend.Calls[0], route.Backend.Calls[1]);
            Assert.NotEqual(route.InitialOwner.HostProcessCreationTimeFileTimeUtc, route.Backend.FinalOwner.HostProcessCreationTimeFileTimeUtc);
        }
        Assert.Null(result.VolumeVerificationReport);
        var report = LiveVolumeVerificationReport.Parse(route.Backend.Reports[^1].Json);
        Assert.True(report.Complete);
        Assert.False(report.Json.GetProperty("wholeVolumeVerified").GetBoolean());
        Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
        Assert.Contains("Covered metadata only", result.Diagnostic);
        Assert.Contains("verify-after:complete findings=0", result.Diagnostic);
        Assert.Equal(0, route.Backend.OfflineCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("healthy", 2)]
    [InlineData("remount", 2)]
    [InlineData("bootstrap", 1)]
    public async Task LiveFixMetadataDoesNotObservePopulatedVolumePayloadOrHitFullReportBound(string initial, int verifies)
    {
        using var route = await OpenLiveFixAsync(initial);
        // Models R07's populated-volume refusal without allocating or reading its two 256 MiB files.
        route.Backend.FullVerify = (_, _) => Task.FromResult(new LiveVolumeVerificationResult(false, "VolumeVerificationReportBound"));
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("healthy-rw", result.FinalStatus);
        Assert.Equal(verifies, route.Backend.MetadataCalls);
        Assert.Equal(0, route.Backend.FullCalls);
        Assert.All(route.Backend.Reports, report =>
        {
            Assert.True(report.Complete);
            Assert.Equal(20, report.Json.GetProperty("coverage").GetArrayLength());
            Assert.Null(report.PayloadInventory);
            Assert.False(report.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
            Assert.Equal("65536", report.Json.GetProperty("limits").GetProperty("maxReads").GetString());
        });
        Assert.Contains("Covered metadata only", result.Diagnostic);
        Assert.Equal(0, route.Backend.OfflineCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LiveFixLeavesOrdinaryVolumeVerifyOnFullRouteIncludingPayloadBoundRefusal(bool bounded)
    {
        using var route = await OpenLiveFixAsync("healthy");
        route.Backend.FullVerify = (scope, _) => Task.FromResult(bounded
            ? new LiveVolumeVerificationResult(false, "VolumeVerificationReportBound") : LiveFixReport(scope));
        var result = await route.ExecuteVolumeVerifyAsync();
        Assert.Equal(!bounded, result.Success);
        Assert.Equal(1, route.Backend.FullCalls);
        Assert.Equal(0, route.Backend.MetadataCalls);
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Equal(0, route.Inner.UnmountCalls);
        if (bounded) Assert.Contains("VolumeVerificationReportBound", result.Diagnostic);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LiveFixMetadataInterfaceDefaultPreservesLegacyVerifierChecks(bool refusal)
    {
        var scope = LiveVerificationFixture.Scope();
        var result = refusal ? new LiveVolumeVerificationResult(false, "LegacyVerifierRefused") : LiveFixReport(scope);
        var legacy = new LiveFixLegacyVerifier(result);
        using var cancellation = new CancellationTokenSource();
        ILiveVolumeVerificationBackend backend = legacy;
        Assert.Same(result, await backend.VerifyLiveVolumeMetadataAsync(scope, cancellation.Token));
        Assert.Equal(scope, legacy.Scope); Assert.Equal(cancellation.Token, legacy.Token); Assert.Equal(1, legacy.Calls);
    }

    [Theory]
    [InlineData("findings", 1)] [InlineData("findings", 2)]
    [InlineData("incomplete", 1)] [InlineData("incomplete", 2)]
    [InlineData("refused", 1)] [InlineData("refused", 2)]
    [InlineData("error", 1)] [InlineData("error", 2)]
    [InlineData("response-scope", 1)] [InlineData("response-scope", 2)]
    [InlineData("owner-pid", 1)] [InlineData("owner-pid", 2)]
    [InlineData("owner-identity", 1)] [InlineData("owner-identity", 2)]
    [InlineData("owner-scope", 1)] [InlineData("owner-scope", 2)]
    [InlineData("absent", 1)] [InlineData("absent", 2)]
    [InlineData("probe-failure", 1)] [InlineData("probe-failure", 2)]
    [InlineData("inventory-identity", 1)] [InlineData("inventory-identity", 2)]
    [InlineData("cancel", 1)] [InlineData("cancel", 2)]
    public async Task LiveFixNeverReportsHealthyWhenVerificationOrOwnerProofFails(string failure, int phase)
    {
        using var route = await OpenLiveFixAsync("remount");
        using var cancellation = new CancellationTokenSource();
        route.Backend.Verify = (call, scope, token) =>
        {
            if (call != phase) return Task.FromResult(LiveFixReport(scope));
            var owner = call == 1 ? route.InitialOwner : route.Backend.FinalOwner;
            switch (failure)
            {
                case "findings": return Task.FromResult(LiveFixReport(scope, "findings"));
                case "incomplete": return Task.FromResult(LiveFixReport(scope, "incomplete"));
                case "refused": return Task.FromResult(LiveFixReport(scope, "refused"));
                case "error": throw new IOException("LiveFixInjectedReadFailure");
                case "response-scope": return Task.FromResult(LiveFixReport(scope with { StoreOffsetBytes = "12288" }));
                case "owner-pid": route.Inner.SetMounted(owner with { HostProcessId = owner.HostProcessId + 1 }); break;
                case "owner-identity": route.Inner.SetMounted(owner with { RecoveryIdentity = "replacement" }); break;
                case "owner-scope": route.Inner.SetMounted(owner with { VolumeVerificationScope = scope with { SourceIdentity = "raw:replacement" } }); break;
                case "absent": route.Backend.HideOwners = true; break;
                case "probe-failure": route.Backend.FailProbes = true; break;
                case "inventory-identity": route.Inner.CurrentRecoveryIdentity = "replacement"; break;
                case "cancel": cancellation.Cancel(); token.ThrowIfCancellationRequested(); break;
            }
            return Task.FromResult(LiveFixReport(scope));
        };
        var result = await route.ExecuteAsync(cancellation.Token);
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.NotEqual("proven", result.OwnershipProof);
        Assert.Equal(phase, route.Backend.Calls.Count);
        Assert.Equal(phase - 1, route.Inner.MountCalls);
        Assert.Equal(phase - 1, route.Inner.UnmountCalls);
        if (failure == "cancel")
        {
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        }
        Assert.Equal(0, route.Backend.OfflineCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("duplicate")] [InlineData("foreign-owner")] [InlineData("scope-kind")]
    [InlineData("scope-volume")] [InlineData("scope-container")] [InlineData("scope-oid")]
    [InlineData("no-pid")] [InlineData("no-identity")]
    [InlineData("no-creation")] [InlineData("negative-creation")]
    public async Task LiveFixRejectsUnprovenInitialOwnerBeforeMutation(string failure)
    {
        using var route = await OpenLiveFixAsync("remount");
        var owner = route.InitialOwner;
        route.Inner.SetMounted(failure switch
        {
            "foreign-owner" => owner with { RecoveryIdentity = "replacement" },
            "scope-kind" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { SourceKind = "retained-image" } },
            "scope-volume" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { VolumeUuid = new string('f', 32) } },
            "scope-container" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { ContainerUuid = new string('f', 32) } },
            "scope-oid" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { VolumeOid = "102" } },
            "no-pid" => owner with { HostProcessId = 0 },
            "no-identity" => owner with { RecoveryIdentity = null },
            // Missing owner metadata uses the model's default zero creation time.
            "no-creation" => owner with { HostProcessCreationTimeFileTimeUtc = default },
            "negative-creation" => owner with { HostProcessCreationTimeFileTimeUtc = -1 },
            _ => owner,
        });
        if (failure == "duplicate") route.Inner.SetMounted(owner with { MountPoint = "F:\\" });
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Empty(route.Backend.Calls);
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Equal(0, route.Inner.UnmountCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task LiveFixMissingRecoveryCapabilityRequiresVerifiedFinalOwner(bool recovered)
    {
        using var route = await OpenLiveFixAsync("remount");
        route.Inner.SetMounted(route.InitialOwner with { VolumeVerificationSupported = false, VolumeVerificationScope = null });
        if (!recovered) route.Backend.FinalOwner = route.Backend.FinalOwner with
            { VolumeVerificationSupported = false, VolumeVerificationScope = null };
        var result = await route.ExecuteAsync();
        Assert.Equal(recovered, result.Success);
        Assert.Equal(recovered ? 1 : 0, route.Backend.Calls.Count);
        Assert.Equal(1, route.Inner.MountCalls);
        Assert.Contains("verify-first:unavailable", result.Diagnostic);
        if (!recovered)
        {
            Assert.NotEqual("healthy-rw", result.FinalStatus);
            Assert.Contains("VolumeVerificationOwnerRefused", result.Diagnostic);
        }
        AssertWireResult(result);
    }

    [Fact]
    public async Task LiveFixAdmittedMountFailureCannotBeRescuedByHealthyObservation()
    {
        using var route = await OpenLiveFixAsync("bootstrap");
        route.Backend.FailMountReceipt = true;
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Null(result.VolumeVerificationReport);
        Assert.Empty(route.Backend.Calls);
        AssertWireResult(result);
    }

    [Fact]
    public async Task LiveFixLegacyWithoutVerificationCapabilityRemainsExplicitlyUnverified()
    {
        using var route = await OpenLiveFixAsync("healthy");
        route.Target = new ApfsControlTarget(InventoryPhysicalSource, route.Target.VolumeId);
        route.Inner.SetMounted(route.InitialOwner with { VolumeVerificationSupported = false,
            VolumeVerificationScope = null, RuntimeWatermarksKnown = null, HostProcessId = 0,
            HostProcessCreationTimeFileTimeUtc = default });
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.Contains("legacy", result.Diagnostic);
        Assert.Contains("unverified", result.Diagnostic);
        Assert.Null(result.VolumeVerificationReport);
        Assert.NotEqual("proven", result.OwnershipProof);
        Assert.Empty(route.Backend.Calls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("pid")] [InlineData("scope")] [InlineData("capability")]
    [InlineData("disappeared")] [InlineData("probe")] [InlineData("inventory")]
    [InlineData("creation")] [InlineData("zero-creation")]
    public async Task LiveFixFinalRecheckRevokesCompletedVerification(string change)
    {
        using var route = await OpenLiveFixAsync("healthy");
        route.Backend.AfterVerifyProbe = count =>
        {
            // The helper's target and owner check uses reads 1 and 2. Final
            // target resolution and its independent owner probe use 3 and 4.
            if (count != (change == "inventory" ? 2 : 4)) return;
            var owner = route.Backend.FinalOwner;
            switch (change)
            {
                case "pid": route.Inner.SetMounted(owner with { HostProcessId = owner.HostProcessId + 1 }); break;
                case "creation": route.Inner.SetMounted(owner with
                    { HostProcessCreationTimeFileTimeUtc = owner.HostProcessCreationTimeFileTimeUtc + TimeSpan.FromMinutes(2).Ticks }); break;
                case "zero-creation": route.Inner.SetMounted(owner with { HostProcessCreationTimeFileTimeUtc = 0 }); break;
                case "scope": route.Inner.SetMounted(owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { CheckpointXid = "92" } }); break;
                case "capability": route.Inner.SetMounted(owner with { VolumeVerificationSupported = false }); break;
                case "disappeared": route.Backend.HideOwners = true; break;
                case "probe": route.Backend.FailProbes = true; break;
                case "inventory": route.Inner.CurrentRecoveryIdentity = "replacement"; break;
            }
        };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Equal(2, route.Backend.Calls.Count);
        Assert.All(route.Backend.Reports, report => Assert.True(report.Complete));
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Equal(0, route.Inner.UnmountCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task LiveFixOlderCallerBindsFinalInventoryToVerifiedOwner(bool replaceInventory)
    {
        using var route = await OpenLiveFixAsync("healthy");
        route.Target = new ApfsControlTarget(InventoryPhysicalSource, route.Target.VolumeId);
        route.Backend.AfterVerifyProbe = count =>
        {
            if (replaceInventory && count == 2) route.Inner.CurrentRecoveryIdentity = "replacement";
        };
        var result = await route.ExecuteAsync();
        Assert.Equal(!replaceInventory, result.Success);
        Assert.Equal(2, route.Backend.Calls.Count);
        Assert.All(route.Backend.Reports, report => Assert.True(report.Complete));
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Equal(0, route.Inner.UnmountCalls);
        Assert.Null(result.VolumeVerificationReport);
        if (replaceInventory)
        {
            Assert.NotEqual("healthy-rw", result.FinalStatus);
            Assert.Contains("LiveFixVerificationNotProven", result.Diagnostic);
        }
        else
        {
            Assert.Contains("Covered metadata only", result.Diagnostic);
            Assert.DoesNotContain("legacy owner", result.Diagnostic);
        }
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("healthy", 1)] [InlineData("healthy", 2)]
    [InlineData("remount", 1)] [InlineData("remount", 2)]
    [InlineData("bootstrap", 1)]
    public async Task LiveFixRejectsSamePidDifferentCreationDuringVerification(string initial, int phase)
    {
        using var route = await OpenLiveFixAsync(initial);
        route.Backend.Verify = (call, scope, _) =>
        {
            if (call == phase)
            {
                var owner = initial == "bootstrap" || call == 2 ? route.Backend.FinalOwner : route.InitialOwner;
                route.Inner.SetMounted(owner with
                    { HostProcessCreationTimeFileTimeUtc = owner.HostProcessCreationTimeFileTimeUtc + TimeSpan.FromMinutes(2).Ticks });
            }
            return Task.FromResult(LiveFixReport(scope));
        };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Equal(phase, route.Backend.Calls.Count);
        Assert.All(route.Backend.Reports, report => Assert.True(report.Complete));
        Assert.Equal(initial == "bootstrap" || initial == "remount" && phase == 2 ? 1 : 0, route.Inner.MountCalls);
        Assert.Equal(initial == "remount" && phase == 2 ? 1 : 0, route.Inner.UnmountCalls);
        Assert.Equal(0, route.Backend.OfflineCalls);
        AssertWireResult(result);
    }

    [Fact]
    public async Task LiveFixHealthySamePidReplacementCannotInheritFirstVerificationOrRemount()
    {
        using var route = await OpenLiveFixAsync("healthy");
        route.Backend.AfterFirstVerifyInventory = count =>
        {
            // Inventory 1 belongs to the verifier's recheck; inventory 2 starts
            // the existing mount admission after verify-first has completed.
            if (count == 2) route.Inner.SetMounted(route.InitialOwner with
                { HostProcessCreationTimeFileTimeUtc = route.InitialOwner.HostProcessCreationTimeFileTimeUtc + TimeSpan.FromMinutes(2).Ticks });
        };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Contains("LiveFixOwnerChangedWithoutRemount", result.Diagnostic);
        Assert.Single(route.Backend.Calls);
        Assert.True(Assert.Single(route.Backend.Reports).Complete);
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Equal(0, route.Inner.UnmountCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("remount", 0L)] [InlineData("bootstrap", 0L)]
    [InlineData("remount", -1L)] [InlineData("bootstrap", -1L)]
    public async Task LiveFixRequiresPositiveCreationTimeOnNewAdmittedOwner(string initial, long creationTime)
    {
        using var route = await OpenLiveFixAsync(initial);
        route.Backend.FinalOwner = route.Backend.FinalOwner with { HostProcessCreationTimeFileTimeUtc = creationTime };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Contains("VolumeVerificationOwnerRefused", result.Diagnostic);
        Assert.Equal(initial == "remount" ? 1 : 0, route.Backend.Calls.Count);
        Assert.Equal(1, route.Inner.MountCalls);
        Assert.Equal(initial == "remount" ? 1 : 0, route.Inner.UnmountCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("remount")] [InlineData("bootstrap")]
    public async Task LiveFixAdmittedReplacementMayReusePidWithItsOwnPositiveCreationTime(string initial)
    {
        using var route = await OpenLiveFixAsync(initial);
        route.Backend.FinalOwner = route.Backend.FinalOwner with { HostProcessId = route.InitialOwner.HostProcessId };
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.True(route.Backend.FinalOwner.HostProcessCreationTimeFileTimeUtc > 0);
        Assert.NotEqual(route.InitialOwner.HostProcessCreationTimeFileTimeUtc, route.Backend.FinalOwner.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(initial == "remount" ? 2 : 1, route.Backend.Calls.Count);
        Assert.Equal(route.Backend.FinalOwner.VolumeVerificationScope, route.Backend.Calls[^1]);
        Assert.Equal(1, route.Inner.MountCalls);
        Assert.Equal(initial == "remount" ? 1 : 0, route.Inner.UnmountCalls);
        AssertWireResult(result);
    }

    private static LiveVolumeVerificationResult LiveFixReport(LiveVolumeVerificationScope scope, string outcome = "complete")
    {
        // Reuse the validated wire fixture to test routing and proof binding, not APFS metadata correctness.
        var json = LiveVerificationFixture.Report(scope, outcome != "complete");
        if (outcome is "incomplete" or "refused")
        {
            var finding = json["findings"]![0]!;
            finding["code"] = outcome == "refused" ? 8 : 3;
            finding["severity"] = outcome == "refused" ? 2 : 3;
            finding["detail"] = outcome == "refused" ? "unsupported metadata" : "read budget exhausted";
            json["coverage"]![4]!["state"] = outcome == "refused" ? 4 : 1;
            if (outcome == "refused") { json["outcome"] = 3; json["outcomeName"] = "Refused"; }
            json["repair"]!["planId"] = LiveVerificationFixture.PlanId(json);
        }
        return new(true, "VolumeVerificationReport", LiveVolumeVerificationReport.Parse(LiveVerificationFixture.Element(json)));
    }

    private static async Task<LiveFixRoute> OpenLiveFixAsync(string initial)
    {
        var inner = PhysicalInventoryBackend();
        var backend = new LiveFixBackend(inner);
        var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend, new FixedMountPolicy(),
            new RuntimeStatusPublisher(), new FixedOptionsMonitor(new ServiceHostOptions
            {
                AutoMountEnabled = true, NativeAutoRemountOnReconnect = false, EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled", WriteBackendMode = "Native", ReadWriteMode = "RwWithRoFallback",
                NativeWritePromotionPolicy = "PilotHardware", NativeWriteAllowRawPhysicalDevices = true,
                NativeWriteHardwarePilotDeviceAllowList = [InventoryPhysicalSource],
            }));
        var device = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == InventoryPhysicalSource);
        var volume = device.Volumes[0];
        var owner = PhysicalInventoryMount(volume, PhysicalInventoryScope(volume)) with { HostProcessId = 4321,
            HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime,
            MountReady = true, RuntimeWatermarksKnown = true, WalAcceptedSequence = 2,
            WalApfsDurableSequence = 2, WalCleanupSequence = 2 };
        backend.FinalOwner = initial == "healthy" ? owner : owner with { HostProcessId = 5432,
            HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime + TimeSpan.FromMinutes(1).Ticks,
            VolumeVerificationScope = owner.VolumeVerificationScope! with { SourceIdentity = "raw:new-admitted-owner", CheckpointXid = "92" } };
        if (initial == "remount") owner = owner with { AccessMode = MountAccessMode.ReadOnly, RecoveryActive = true,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback };
        if (initial != "bootstrap") inner.SetMounted(owner);
        return new(inner, backend, worker, SelectedControlTarget.Create(device, volume), owner);
    }

    private sealed class LiveFixRoute(ScenarioBackend inner, LiveFixBackend backend, ApfsMountWorker worker,
        ApfsControlTarget target, MountedVolumeState owner) : IDisposable
    {
        public ScenarioBackend Inner => inner;
        public LiveFixBackend Backend => backend;
        public ApfsControlTarget Target { get; set; } = target;
        public MountedVolumeState InitialOwner => owner;
        public Task<OperationResultPayload> ExecuteAsync(CancellationToken token = default)
            => CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix, Target), token);
        public Task<OperationResultPayload> ExecuteVolumeVerifyAsync(CancellationToken token = default)
            => CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.VolumeVerify, Target), token);
        public void Dispose() => worker.Dispose();
    }

    private sealed class LiveFixBackend(ScenarioBackend inner) : IApfsBackend, ILiveVolumeVerificationBackend, IVerifyBackend
    {
        public MountedVolumeState FinalOwner { get; set; } = null!;
        public bool HideOwners { get; set; }
        public bool FailProbes { get; set; }
        public bool FailMountReceipt { get; set; }
        public int OfflineCalls { get; private set; }
        public int MetadataCalls { get; private set; }
        public int FullCalls { get; private set; }
        public Func<LiveVolumeVerificationScope, CancellationToken, Task<LiveVolumeVerificationResult>>? FullVerify { get; set; }
        public List<LiveVolumeVerificationScope> Calls { get; } = [];
        public List<LiveVolumeVerificationReport> Reports { get; } = [];
        public Action<int>? AfterVerifyProbe { get; set; }
        private int _afterVerifyProbes;
        public Action<int>? AfterFirstVerifyInventory { get; set; }
        private int _afterFirstVerifyInventories;
        public Func<int, LiveVolumeVerificationScope, CancellationToken, Task<LiveVolumeVerificationResult>>? Verify { get; set; }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => inner.ProbeDevicesAsync(token);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => inner.ProbeVolumesAsync(device, token);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            if (Calls.Count == 1) AfterFirstVerifyInventory?.Invoke(++_afterFirstVerifyInventories);
            return inner.ProbeInventoryAsync(authoritative, token);
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            if (Calls.Count == 2) AfterVerifyProbe?.Invoke(++_afterVerifyProbes);
            return FailProbes ? throw new IOException("LiveFixInjectedProbeFailure") : HideOwners
                ? Task.FromResult<IReadOnlyList<MountedVolumeState>>([]) : inner.GetMountStateAsync(token);
        }
        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            var result = await inner.MountAsync(request, token);
            inner.SetMounted(FinalOwner with { MountPoint = result.MountPoint! });
            if (FailMountReceipt) throw new IOException("LiveFixInjectedMountFailure");
            return result;
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) => inner.UnmountAsync(point, token);
        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
            => VerifyCoreAsync(scope, token, metadataOnly: false);
        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeMetadataAsync(LiveVolumeVerificationScope scope, CancellationToken token)
            => VerifyCoreAsync(scope, token, metadataOnly: true);
        private async Task<LiveVolumeVerificationResult> VerifyCoreAsync(LiveVolumeVerificationScope scope, CancellationToken token, bool metadataOnly)
        {
            if (metadataOnly) MetadataCalls++; else FullCalls++;
            Calls.Add(scope);
            var result = await ((!metadataOnly ? FullVerify?.Invoke(scope, token) : null) ??
                Verify?.Invoke(Calls.Count, scope, token) ?? Task.FromResult(LiveFixReport(scope)));
            if (result.Report is { } report) Reports.Add(report);
            return result;
        }
        public Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken token)
        {
            OfflineCalls++;
            throw new InvalidOperationException("Physical Fix cannot run offline verification.");
        }
    }

    private sealed class LiveFixLegacyVerifier(LiveVolumeVerificationResult result) : ILiveVolumeVerificationBackend
    {
        public int Calls;
        public LiveVolumeVerificationScope? Scope;
        public CancellationToken Token;
        public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        { Calls++; Scope = scope; Token = token; return Task.FromResult(result); }
    }
}
