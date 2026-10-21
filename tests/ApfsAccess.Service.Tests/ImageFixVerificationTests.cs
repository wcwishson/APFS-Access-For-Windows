using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    private const string ImageFixDevice = @"D:\image-fix-service-fixture.apfs";
    private const string ImageFixVolume = ImageFixDevice + "|Main";

    [Theory]
    [InlineData("healthy", false)] [InlineData("healthy", true)]
    [InlineData("readonly", false)] [InlineData("bootstrap", false)]
    public async Task ImageFixRemountsThenVerifiesFreshExactOwner(string initial, bool olderCaller)
    {
        using var route = await OpenImageFixAsync(initial, olderCaller);
        var result = await route.ExecuteAsync();
        Assert.True(result.Success, result.Diagnostic);
        Assert.Equal("healthy-rw", result.FinalStatus);
        Assert.Equal(1, route.Inner.MountCalls);
        Assert.Equal(initial == "bootstrap" ? 0 : 1, route.Inner.UnmountCalls);
        var offline = Assert.Single(route.Backend.OfflineCalls);
        Assert.Equal(initial == "bootstrap" ? "90" : "91", offline.CheckpointXid);
        Assert.Equal(ImageFixDevice, offline.ImagePath);
        var live = Assert.Single(route.Backend.LiveCalls);
        Assert.Equal(route.Backend.FinalOwner.VolumeVerificationScope, live);
        Assert.Equal("92", live.CheckpointXid);
        Assert.NotEqual(route.InitialOwner.HostProcessCreationTimeFileTimeUtc,
            route.Backend.FinalOwner.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(initial == "bootstrap" ? new[] { "offline", "mount", "live" } :
            new[] { "unmount", "offline", "mount", "live" }, route.Backend.Events);
        Assert.Contains("verify-after:complete findings=0", result.Diagnostic);
        Assert.Contains("Covered metadata only", result.Diagnostic);
        Assert.Null(result.VolumeVerificationReport);
        Assert.Equal("not-applicable", result.OwnershipProof);
        AssertWireResult(result);
    }

    [Fact]
    public async Task ImageFixHealthyMountWithoutPostVerificationCannotSucceed()
    {
        using var route = await OpenImageFixAsync();
        route.Backend.FinalOwner = route.Backend.FinalOwner with
            { VolumeVerificationSupported = false, VolumeVerificationScope = null };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Single(route.Backend.OfflineCalls);
        Assert.Empty(route.Backend.LiveCalls);
        Assert.Equal(1, route.Inner.MountCalls);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("incomplete")] [InlineData("refused")] [InlineData("error")]
    [InlineData("report-kind")] [InlineData("report-volume")] [InlineData("report-xid")]
    [InlineData("pid")] [InlineData("pid-reuse")] [InlineData("identity")]
    [InlineData("owner-scope")] [InlineData("cancel")] [InlineData("absent")]
    [InlineData("probe-failure")] [InlineData("inventory-identity")] [InlineData("watermarks")]
    public async Task ImageFixPostVerificationFailureCannotBeRescuedByMountHealth(string failure)
    {
        using var route = await OpenImageFixAsync();
        using var cancellation = new CancellationTokenSource();
        route.Backend.Verify = (scope, token) =>
        {
            var owner = route.Backend.FinalOwner;
            switch (failure)
            {
                case "incomplete": return Task.FromResult(LiveFixReport(scope, "incomplete"));
                case "refused": return Task.FromResult(LiveFixReport(scope, "refused"));
                case "error": throw new IOException("ImageFixInjectedVerificationFailure");
                case "report-kind": return Task.FromResult(LiveFixReport(scope with { SourceKind = "retained-admitted-raw" }));
                case "report-volume": return Task.FromResult(LiveFixReport(scope with { VolumeUuid = new string('f', 32) }));
                case "report-xid": return Task.FromResult(LiveFixReport(scope with { CheckpointXid = "93" }));
                case "pid": route.Inner.SetMounted(owner with { HostProcessId = owner.HostProcessId + 1 }); break;
                case "pid-reuse": route.Inner.SetMounted(owner with
                    { HostProcessCreationTimeFileTimeUtc = owner.HostProcessCreationTimeFileTimeUtc + 1 }); break;
                case "identity": route.Inner.SetMounted(owner with { RecoveryIdentity = "replacement" }); break;
                case "owner-scope": route.Inner.SetMounted(owner with
                    { VolumeVerificationScope = scope with { SourceIdentity = "image:replacement" } }); break;
                case "cancel": cancellation.Cancel(); token.ThrowIfCancellationRequested(); break;
                case "absent": route.Backend.HideOwners = true; break;
                case "probe-failure": route.Backend.FailProbes = true; break;
                case "inventory-identity": route.Inner.CurrentRecoveryIdentity = "replacement"; break;
                case "watermarks": route.Inner.SetMounted(owner with
                    { WalAcceptedSequence = 3, WalApfsDurableSequence = 3, WalCleanupSequence = 3 }); break;
            }
            return Task.FromResult(LiveFixReport(scope));
        };
        var result = await route.ExecuteAsync(cancellation.Token);
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Single(route.Backend.LiveCalls);
        Assert.Equal(1, route.Inner.MountCalls);
        if (failure == "cancel")
        {
            Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
            Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        }
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("kind")] [InlineData("volume")] [InlineData("container")]
    [InlineData("oid")] [InlineData("xid")] [InlineData("offset")] [InlineData("size")]
    [InlineData("no-pid")] [InlineData("no-creation")] [InlineData("no-identity")]
    [InlineData("no-watermarks")] [InlineData("pending")] [InlineData("duplicate")]
    [InlineData("sibling-owner")]
    public async Task ImageFixRejectsInvalidFreshOwnerProof(string failure)
    {
        using var route = await OpenImageFixAsync();
        var owner = route.Backend.FinalOwner;
        var scope = owner.VolumeVerificationScope!;
        route.Backend.FinalOwner = failure switch
        {
            "kind" => owner with { VolumeVerificationScope = scope with { SourceKind = "retained-admitted-raw" } },
            "volume" => owner with { VolumeVerificationScope = scope with { VolumeUuid = new string('f', 32) } },
            "container" => owner with { VolumeVerificationScope = scope with { ContainerUuid = new string('f', 32) } },
            "oid" => owner with { VolumeVerificationScope = scope with { VolumeOid = "102" } },
            "xid" => owner with { VolumeVerificationScope = scope with { CheckpointXid = "91" } },
            "offset" => owner with { VolumeVerificationScope = scope with { StoreOffsetBytes = "4096" } },
            "size" => owner with { VolumeVerificationScope = scope with { StoreSizeBytes = "99999995904" } },
            "no-pid" => owner with { HostProcessId = 0 },
            "no-creation" => owner with { HostProcessCreationTimeFileTimeUtc = 0 },
            "no-identity" => owner with { RecoveryIdentity = null },
            "no-watermarks" => owner with { RuntimeWatermarksKnown = null },
            "pending" => owner with { WalCleanupSequence = 1 },
            _ => owner,
        };
        route.Backend.DuplicateAfterMount = failure == "duplicate";
        route.Backend.SiblingAfterMount = failure == "sibling-owner";
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("identity", false)] [InlineData("identity", true)]
    [InlineData("cohort", false)] [InlineData("cohort", true)]
    [InlineData("xid", false)] [InlineData("scope", false)]
    [InlineData("pid-reuse", false)] [InlineData("watermarks", false)]
    [InlineData("cancel", false)] [InlineData("sibling-owner", false)]
    public async Task ImageFixFinalReconciliationRevokesCompletedReport(string change, bool olderCaller)
    {
        using var route = await OpenImageFixAsync(olderCaller: olderCaller);
        using var cancellation = new CancellationTokenSource();
        route.Backend.AfterLiveInventory = count =>
        {
            // The first inventory belongs to the verifier's recheck. Its
            // successor is the terminal inventory, after a complete report.
            if (count != 2) return;
            var owner = route.Backend.FinalOwner;
            switch (change)
            {
                case "identity": route.Inner.CurrentRecoveryIdentity = "replacement"; break;
                case "cohort": route.Backend.DropSibling = true; break;
                case "xid": route.Inner.ImageTopologyXid = "93"; break;
                case "scope": route.Inner.SetMounted(owner with { VolumeVerificationScope =
                    owner.VolumeVerificationScope! with { SourceIdentity = "image:replacement" } }); break;
                case "pid-reuse": route.Inner.SetMounted(owner with
                    { HostProcessCreationTimeFileTimeUtc = owner.HostProcessCreationTimeFileTimeUtc + 1 }); break;
                case "watermarks": route.Inner.SetMounted(owner with
                    { WalAcceptedSequence = 3, WalApfsDurableSequence = 3, WalCleanupSequence = 3 }); break;
                case "cancel": cancellation.Cancel(); break;
                case "sibling-owner": route.Inner.SetMounted(owner with { MountPoint = "F:\\",
                    VolumeId = ImageFixDevice + "|Archive", CatalogVolumeObjectId = 102 }); break;
            }
        };
        var result = await route.ExecuteAsync(cancellation.Token);
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.True(Assert.Single(route.Backend.Reports).Complete);
        if (change == "cancel") Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("identity")] [InlineData("cohort")]
    public async Task ImageFixOlderCallerCannotChangeSelectionAcrossOfflineDrain(string change)
    {
        using var route = await OpenImageFixAsync(olderCaller: true);
        route.Backend.AfterOffline = () =>
        {
            if (change == "identity") route.Inner.CurrentRecoveryIdentity = "replacement";
            else route.Backend.DropSibling = true;
        };
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Empty(route.Backend.LiveCalls);
        AssertWireResult(result);
    }

    [Fact]
    public async Task ImageFixOfflineFindingsKeepSeparateRepairGuidanceAndDoNotRemount()
    {
        using var route = await OpenImageFixAsync();
        route.Backend.OfflineResult = new(true, "Incomplete", 3, 1, null);
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.Equal(0, route.Inner.MountCalls);
        Assert.Empty(route.Backend.LiveCalls);
        Assert.Contains("verify:findings:1", result.Diagnostic);
        Assert.Contains("APFSAccess.Cli.exe verify --help", result.Diagnostic);
        Assert.Contains("separate repair command", result.Diagnostic);
        AssertWireResult(result);
    }

    [Theory]
    [InlineData("offline")] [InlineData("mount")]
    public async Task ImageFixCancellationDuringTransitionReturnsCancelledTerminalResult(string phase)
    {
        using var route = await OpenImageFixAsync();
        using var cancellation = new CancellationTokenSource();
        if (phase == "offline") route.Backend.AfterOffline = cancellation.Cancel;
        else route.Backend.AfterMount = cancellation.Cancel;
        var result = await route.ExecuteAsync(cancellation.Token);
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Equal(ApfsOperationStates.Cancelled, result.State);
        Assert.Equal(ApfsOperationCodes.OperationCancelled, result.Code);
        Assert.Empty(route.Backend.LiveCalls);
        AssertWireResult(result);
    }

    [Fact]
    public async Task ImageFixFailedMountReceiptCannotBeRescuedByHealthyOwner()
    {
        using var route = await OpenImageFixAsync();
        route.Backend.FailMountReceipt = true;
        var result = await route.ExecuteAsync();
        Assert.False(result.Success);
        Assert.NotEqual("healthy-rw", result.FinalStatus);
        Assert.Empty(route.Backend.LiveCalls);
        AssertWireResult(result);
    }

    private static MountedVolumeState ImageFixProofOwner(VolumeInfo volume, string xid)
        => HealthyMount() with
        {
            DeviceId = volume.DeviceId, VolumeId = volume.VolumeId, RecoveryIdentity = volume.RecoveryIdentity,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeObjectId = volume.CatalogVolumeObjectId, CatalogVolumeId = volume.CatalogVolumeId,
            HostProcessId = 6202, HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime + TimeSpan.FromMinutes(1).Ticks,
            MountReady = true, RuntimeWatermarksKnown = true, WalAcceptedSequence = 2,
            WalApfsDurableSequence = 2, WalCleanupSequence = 2, SnapshotRecoverySupported = false,
            VolumeVerificationSupported = true, VolumeVerificationScope = new("image:fresh-fixture-owner", "retained-image",
                volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!,
                volume.CatalogVolumeObjectId!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), xid, "0", "100000000000"),
        };

    private static async Task<ImageFixRoute> OpenImageFixAsync(string initial = "healthy", bool olderCaller = false)
    {
        var inner = new ScenarioBackend { ImageDeviceId = ImageFixDevice,
            ImageVolumeId = ImageFixVolume, ImageTopologyXid = "90" };
        var backend = new ImageFixBackend(inner);
        var journalRoot = Directory.CreateDirectory(Path.Combine(
            Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!, "image-fix-" + Guid.NewGuid().ToString("N"))).FullName;
        var worker = CreateWorker(backend, journalRoot, autoRemount: false);
        var inventory = (await worker.GetInventoryAsync(default)).Single(d => d.Device.DeviceId == ImageFixDevice);
        var volume = inventory.Volumes.Single();
        var owner = HealthyMount() with { DeviceId = ImageFixDevice, VolumeId = ImageFixVolume,
            CatalogContainerUuid = volume.CatalogContainerUuid, CatalogVolumeUuid = volume.CatalogVolumeUuid,
            CatalogVolumeObjectId = volume.CatalogVolumeObjectId, CatalogVolumeId = volume.CatalogVolumeId,
            HostProcessId = 6201, HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime,
            MountReady = true, RuntimeWatermarksKnown = true, WalAcceptedSequence = 2,
            WalApfsDurableSequence = 2, WalCleanupSequence = 2, SnapshotRecoverySupported = false,
            VolumeVerificationSupported = true, VolumeVerificationScope = new("image:initial-owner", "retained-image",
                volume.CatalogContainerUuid!, volume.CatalogVolumeUuid!, "101", "90", "0", "100000000000") };
        backend.FinalOwner = owner with { HostProcessId = 6202,
            HostProcessCreationTimeFileTimeUtc = LiveFixOwnerCreationTime + TimeSpan.FromMinutes(1).Ticks,
            VolumeVerificationScope = owner.VolumeVerificationScope! with { SourceIdentity = "image:fresh-owner", CheckpointXid = "92" } };
        if (initial == "readonly") owner = owner with { AccessMode = MountAccessMode.ReadOnly,
            RecoveryActive = true, NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback };
        if (initial != "bootstrap") inner.SetMounted(owner);
        return new(inner, backend, worker, olderCaller ? new(ImageFixDevice, ImageFixVolume) :
            SelectedControlTarget.Create(inventory, volume), owner);
    }

    private sealed class ImageFixRoute(ScenarioBackend inner, ImageFixBackend backend, ApfsMountWorker worker,
        ApfsControlTarget target, MountedVolumeState initialOwner) : IDisposable
    {
        public ScenarioBackend Inner => inner;
        public ImageFixBackend Backend => backend;
        public MountedVolumeState InitialOwner => initialOwner;
        public Task<OperationResultPayload> ExecuteAsync(CancellationToken token = default)
            => CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix, target), token);
        public void Dispose() => worker.Dispose();
    }

    // Scripted service boundary only. No native tools, processes or image files are opened.
    private sealed class ImageFixBackend(ScenarioBackend inner, IVerifyBackend? offlineVerifier = null,
        bool advanceCheckpoints = true) : IApfsBackend, IVerifyBackend, ILiveVolumeVerificationBackend
    {
        public MountedVolumeState FinalOwner { get; set; } = null!;
        public bool HideOwners { get; set; }
        public bool FailProbes { get; set; }
        public bool DropSibling { get; set; }
        public bool DuplicateAfterMount { get; set; }
        public bool SiblingAfterMount { get; set; }
        public bool FailMountReceipt { get; set; }
        public ImageVerifyResult OfflineResult { get; set; } = new(true, "Complete", 0, 0, null);
        public List<VerifyScope> OfflineCalls { get; } = [];
        public List<LiveVolumeVerificationScope> LiveCalls { get; } = [];
        public List<LiveVolumeVerificationReport> Reports { get; } = [];
        public List<string> Events { get; } = [];
        public Action? AfterOffline { get; set; }
        public Action? AfterMount { get; set; }
        public Action<int>? AfterLiveInventory { get; set; }
        private int _afterLiveInventories;
        public Func<LiveVolumeVerificationScope, CancellationToken, Task<LiveVolumeVerificationResult>>? Verify { get; set; }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => inner.ProbeDevicesAsync(token);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => inner.ProbeVolumesAsync(device, token);
        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            if (LiveCalls.Count != 0) AfterLiveInventory?.Invoke(++_afterLiveInventories);
            var devices = await inner.ProbeInventoryAsync(authoritative, token);
            if (!DropSibling) return devices;
            return devices.Select(d => d.Device.DeviceId != ImageFixDevice ? d : d with { Topology = d.Topology! with
            {
                Snapshot = d.Topology.Snapshot with
                {
                    Containers = d.Topology.Snapshot.Containers.Select(c => c with
                        { VolumeIds = c.VolumeIds.Where(id => !id.EndsWith(":102", StringComparison.Ordinal)).ToArray() }).ToArray(),
                    Volumes = d.Topology.Snapshot.Volumes.Where(v => v.ObjectId != "102").ToArray(),
                },
            } }).ToArray();
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
            => FailProbes ? throw new IOException("ImageFixInjectedProbeFailure") : HideOwners
                ? Task.FromResult<IReadOnlyList<MountedVolumeState>>([]) : inner.GetMountStateAsync(token);
        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            Events.Add("mount");
            var result = await inner.MountAsync(request, token);
            if (advanceCheckpoints) inner.ImageTopologyXid = "92";
            FinalOwner = FinalOwner with { MountPoint = result.MountPoint! };
            inner.SetMounted(FinalOwner);
            if (DuplicateAfterMount) inner.SetMounted(FinalOwner with { MountPoint = "F:\\" });
            if (SiblingAfterMount) inner.SetMounted(FinalOwner with { MountPoint = "F:\\",
                VolumeId = ImageFixDevice + "|Archive", CatalogVolumeObjectId = 102 });
            AfterMount?.Invoke();
            if (FailMountReceipt) throw new IOException("ImageFixInjectedMountReceiptFailure");
            return result;
        }
        public async Task<UnmountResult> UnmountAsync(string point, CancellationToken token)
        {
            Events.Add("unmount");
            var result = await inner.UnmountAsync(point, token);
            if (advanceCheckpoints) inner.ImageTopologyXid = "91";
            return result;
        }
        public async Task<ImageVerifyResult> VerifyImageAsync(VerifyScope scope, CancellationToken token)
        {
            Assert.Empty(await inner.GetMountStateAsync(token));
            Events.Add("offline");
            OfflineCalls.Add(scope);
            AfterOffline?.Invoke();
            return offlineVerifier is null ? OfflineResult : await offlineVerifier.VerifyImageAsync(scope, token);
        }
        public async Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        {
            Events.Add("live");
            LiveCalls.Add(scope);
            var result = await (Verify?.Invoke(scope, token) ?? Task.FromResult(LiveFixReport(scope)));
            if (result.Report is { } report) Reports.Add(report);
            return result;
        }
    }
}
