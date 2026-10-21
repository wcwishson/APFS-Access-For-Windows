using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class DriveLetterLeaseOverlapTests : IDisposable
{
    private const BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Instance;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "letter-lease-" + Guid.NewGuid().ToString("N"));
    private static readonly Guid A = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid B = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");
    private static readonly VolumeInfo Volume = new("volume", "device", "Name", false,
        CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 201), CatalogVolumeUuid: A.ToString("N"));
    public DriveLetterLeaseOverlapTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);
    private VolumeDriveLetterAssignments Store() => new(Path.Combine(_root, "letters.json"));
    private static Task Cycle(ApfsMountWorker worker) => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", Private)!.Invoke(worker, [CancellationToken.None])!;
    private static ApfsMountWorker Worker(Backend backend, IMountPolicy policy, RuntimeStatusPublisher publisher)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, policy, publisher, new Options());
    private static DriveLetterPreferenceRequestPayload Request => new(Volume.DeviceId, Volume.VolumeId, A.ToString("D"), "T");

    // The callback runs inside production WithState, after the real .lock lease and
    // checked JSON read. No mock serializes or replaces the storage operation.
    private sealed class ReadLease : IAsyncDisposable
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _read;
        public ReadLease(VolumeDriveLetterAssignments store)
        {
            _read = Task.Run(() =>
            {
                Func<Dictionary<Guid, char>, bool> read = state =>
                {
                    Assert.Equal('T', state[A]);
                    Entered.SetResult();
                    if (!_release.Task.Wait(TimeSpan.FromSeconds(15))) throw new TimeoutException("Lease test was not released.");
                    return false;
                };
                Assert.Equal(true, typeof(VolumeDriveLetterAssignments).GetMethod("WithState", Private)!.Invoke(store, [read, CancellationToken.None]));
            });
        }
        public async ValueTask DisposeAsync() { _release.TrySetResult(); await _read; }
    }

    [Theory]
    [InlineData("cycle")]
    [InlineData("refresh")]
    [InlineData("exact")]
    [InlineData("batch")]
    public async Task ActualReadLeaseCannotDiscardAvailableSavedT(string caller)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var backend = new Backend { Batch = caller == "batch" };
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(backend, new FirstFreeMountPolicy(["R", "T", "S"], store), publisher);
        var lease = new ReadLease(store);
        Task operation = Task.CompletedTask;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Throws<IOException>(() => new FileStream(Path.Combine(_root, "letters.json.lock"), FileMode.CreateNew).Dispose());
            operation = caller switch
            {
                "refresh" => worker.RefreshAsync(false, CancellationToken.None),
                "exact" => worker.EnsureMountedExactAsync(Volume.DeviceId, Volume.VolumeId, null, CancellationToken.None),
                _ => Cycle(worker)
            };
            // Reach a real queued settings operation, not merely an unscheduled task.
            await WaitForSettingsWaiter(store);
            var mountGate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", Private)!.GetValue(worker)!;
            Assert.True(await mountGate.WaitAsync(TimeSpan.FromSeconds(2)));
            mountGate.Release();
            Assert.Empty(backend.Requests);
        }
        finally { await lease.DisposeAsync(); await operation.WaitAsync(TimeSpan.FromSeconds(5)); }
        Assert.Equal('T', Assert.Single(backend.Requests, r => r.VolumeId == Volume.VolumeId).DriveLetter);
        Assert.Equal(caller == "batch" ? 2 : 1, backend.Requests.Count);
        Assert.Equal("T", publisher.Latest.MountedVolumes!.Single(m => m.VolumeId == Volume.VolumeId).DriveLetterPreference!.PreferredLetter);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentInventoryAndExplicitSaveWaitForRealReadLease(bool separateStore)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        using var worker = Worker(new(), new FirstFreeMountPolicy(["R", "T"], store), new());
        var lease = new ReadLease(separateStore ? Store() : store);
        Task<IReadOnlyList<DeviceInventory>>? inventory = null;
        Task<AckPayload>? save = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            inventory = worker.GetInventoryAsync(CancellationToken.None);
            save = worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None);
            await WaitForSettingsWaiter(store);
            Assert.False(inventory.IsCompleted);
            Assert.False(save.IsCompleted);
            Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
        }
        finally { await lease.DisposeAsync(); }
        Assert.True((await save!.WaitAsync(TimeSpan.FromSeconds(5))).Success);
        Assert.Equal("T", Assert.Single(Assert.Single(await inventory!).Volumes).DriveLetterPreference!.PreferredLetter);
    }

    [Fact]
    public async Task CancellationWhileWaitingForRealReadLeaseDoesNotCommit()
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        using var worker = Worker(new(), new FirstFreeMountPolicy(["R", "T"], store), new());
        await using var lease = new ReadLease(store);
        await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        using var cancel = new CancellationTokenSource();
        var save = worker.SetDriveLetterPreferenceAsync(Request with { Letter = "R" }, cancel.Token);
        await WaitForSettingsWaiter(store);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => save.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
    }

    [Theory]
    [InlineData("eject")]
    [InlineData("replacement")]
    public async Task SelectionRevalidatesAfterWaitingForActualLease(string competing)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var backend = new Backend();
        using var worker = Worker(backend, new FirstFreeMountPolicy(["R", "T"], store), new());
        var lease = new ReadLease(store);
        Task cycle = Task.CompletedTask;
        Task? inventory = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            cycle = Cycle(worker);
            await WaitForSettingsWaiter(store);
            if (competing == "eject")
                Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
            else
            {
                backend.Volumes = [Volume with { CatalogVolumeUuid = B.ToString("D") }];
                inventory = worker.GetInventoryAsync(CancellationToken.None);
                Assert.Equal(2, backend.Observations);
            }
        }
        finally { await lease.DisposeAsync(); await cycle.WaitAsync(TimeSpan.FromSeconds(5)); if (inventory is not null) await inventory; }
        Assert.Empty(backend.Requests);
        Assert.True(store.TryGetPreference(A, out var saved));
        Assert.Equal('T', saved);
        Assert.True(store.TryGetPreference(B, out var replacement));
        Assert.Null(replacement);
    }

    private static async Task WaitForSettingsWaiter(VolumeDriveLetterAssignments store)
    {
        // Monitor.Wait inside SemaphoreSlim.Wait increments this field while the
        // real synchronous store caller waits. Inspect only test-owned objects.
        var gate = (SemaphoreSlim)typeof(VolumeDriveLetterAssignments).GetField("_settingsGate", Private)!.GetValue(store)!;
        var count = typeof(SemaphoreSlim).GetField("m_waitCount", Private)!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while ((int)count.GetValue(gate)! == 0) await Task.Delay(5, timeout.Token);
    }

    [Theory]
    [InlineData("inventory", true)]
    [InlineData("idle-cycle", true)]
    [InlineData("empty-journal", true)]
    [InlineData("reconcile", false)]
    [InlineData("corrupt-intent", false)]
    [InlineData("incomplete-intent", false)]
    [InlineData("unsafe-journal", false)]
    [InlineData("missing-journal", false)]
    [InlineData("inventory-owner", false)]
    [InlineData("inventory-same-owner", true)]
    [InlineData("inventory-replaced-owner", false)]
    [InlineData("peer-replacement", false)]
    [InlineData("replacement-aba", false)]
    [InlineData("duplicate", false)]
    [InlineData("empty", false)]
    [InlineData("topology", false)]
    [InlineData("capability", false)]
    [InlineData("write-admission", false)]
    [InlineData("eject", false)]
    [InlineData("shutdown", false)]
    [InlineData("backend-owner", false)]
    public async Task ContainerPreparationRetainsEquivalentEvidenceAcrossRealStorageWait(string observation, bool allowed)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        Assert.True(store.SetPreference(B, 'S'));
        var lettersBefore = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        var hex = new string('a', 32);
        var original = new[] {
            Volume with { VolumeName = "Alpha", CatalogContainerUuid = hex, CatalogVolumeObjectId = 201,
                CatalogDecision = ApfsCapabilityDecision.Writable, CatalogReasons = [], CatalogAutoMountAllowed = true,
                RecoveryIdentity = "original-alpha" },
            Volume with { VolumeId = "sibling", VolumeName = "Beta", CatalogVolumeId = ApfsTopology.BuildVolumeId(hex, 202),
                CatalogContainerUuid = hex, CatalogVolumeUuid = B.ToString("N"), CatalogVolumeObjectId = 202,
                CatalogDecision = ApfsCapabilityDecision.Writable, CatalogReasons = [], CatalogAutoMountAllowed = true,
                RecoveryIdentity = "original-beta" }
        };
        var backend = new Backend { Volumes = original, WithTopology = true };
        if (observation is "inventory-same-owner" or "inventory-replaced-owner") backend.SetUnrelatedOwner(5678);
        var publisher = new RuntimeStatusPublisher();
        var options = new Options();
        options.CurrentValue.AutoMountEnabled = false;
        var journal = Path.Combine(_root, "journal");
        if (observation is "empty-journal" or "reconcile" or "corrupt-intent" or "incomplete-intent" or "unsafe-journal" or "missing-journal")
        {
            Directory.CreateDirectory(journal);
            options.CurrentValue.ManagementJournalRoot = journal;
        }
        if (observation == "write-admission")
        {
            options.CurrentValue.EnableNativeWrite = true;
            options.CurrentValue.WriteRolloutChannel = "Pilot";
        }
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            new FirstFreeMountPolicy(["R", "T", "S"], store), publisher, options);
        var lease = new ReadLease(store);
        Task<(bool Success, string Message)> mount = Task.FromResult((false, "not started"));
        var observations = new List<Task>();
        VolumeManagementIntent? recoveryIntent = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            mount = worker.MountContainerAsync("device", hex, original, MountAccessMode.ReadOnly, CancellationToken.None);
            await WaitForSettingsWaiter(store);
            var generation = publisher.Latest.InventoryGeneration;
            var operation = (long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)!;
            var command = (long)typeof(ApfsMountWorker).GetField("_mountCommandGeneration", Private)!.GetValue(worker)!;
            Assert.Empty(backend.Requests); // Storage preparation precedes the first backend batch.
            var gate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", Private)!.GetValue(worker)!;
            Assert.True(await gate.WaitAsync(TimeSpan.FromSeconds(2)));
            gate.Release(); // The real settings wait releases the mount lock.
            switch (observation)
            {
                case "inventory":
                    observations.Add(worker.GetInventoryAsync(CancellationToken.None));
                    break;
                case "idle-cycle":
                    await Cycle(worker).WaitAsync(TimeSpan.FromSeconds(3));
                    break;
                case "empty-journal":
                    Assert.Empty(Directory.EnumerateFileSystemEntries(journal));
                    await Cycle(worker).WaitAsync(TimeSpan.FromSeconds(3));
                    Assert.Empty(backend.Reconciliations);
                    Assert.Equal(operation, (long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)!);
                    break;
                case "reconcile":
                    recoveryIntent = PendingIntent(journal);
                    using (var intents = new VolumeManagementIntentStore(journal)) intents.Save(recoveryIntent);
                    await Cycle(worker).WaitAsync(TimeSpan.FromSeconds(3));
                    var recovery = Assert.Single(backend.Reconciliations);
                    Assert.Equal(VolumeTopologyMode.Recover, recovery.Mode);
                    Assert.Null(recovery.Confirmation);
                    Assert.Equal(System.Text.Json.JsonSerializer.Serialize(recoveryIntent.NativeRequest),
                        System.Text.Json.JsonSerializer.Serialize(recovery.Request));
                    using (var intents = new VolumeManagementIntentStore(journal))
                        Assert.Equal("cancelled", Assert.Single(intents.ReadAll()).State);
                    Assert.True((long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)! > operation);
                    break;
                case "corrupt-intent":
                case "incomplete-intent":
                case "unsafe-journal":
                case "missing-journal":
                    var evidence = Path.Combine(journal, observation switch {
                        "corrupt-intent" => "managed-volume-" + Guid.NewGuid().ToString("D") + ".json",
                        "incomplete-intent" => "managed-volume-pending.tmp",
                        _ => "unproved.vmt1"
                    });
                    if (observation == "missing-journal") Directory.Delete(journal);
                    else File.WriteAllText(evidence, "unproved evidence");
                    var blockedCycle = Cycle(worker).WaitAsync(TimeSpan.FromSeconds(3));
                    if (observation == "corrupt-intent")
                        await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => blockedCycle);
                    else if (observation == "incomplete-intent")
                        await Assert.ThrowsAsync<InvalidDataException>(() => blockedCycle);
                    else await blockedCycle;
                    Assert.True((long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)! > operation);
                    Assert.Empty(backend.Reconciliations);
                    if (observation != "missing-journal") Assert.Equal("unproved evidence", File.ReadAllText(evidence));
                    break;
                case "inventory-owner":
                case "inventory-same-owner":
                case "inventory-replaced-owner":
                    if (observation == "inventory-owner") backend.AddOriginalOwner(original[0]);
                    else backend.SetUnrelatedOwner(observation == "inventory-replaced-owner" ? 5679 : 5678, dirty: 1);
                    var mountReads = backend.MountReads;
                    observations.Add(worker.GetInventoryAsync(CancellationToken.None));
                    Assert.True(backend.MountReads > mountReads);
                    Assert.Equal(operation, (long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)!);
                    break;
                case "backend-owner":
                    backend.AddOriginalOwner(original[0]);
                    await Cycle(worker).WaitAsync(TimeSpan.FromSeconds(3));
                    Assert.True((long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)! > operation);
                    break;
                case "eject":
                    Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).Success);
                    break;
                case "shutdown":
                    Assert.True((await worker.PrepareForShutdownAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).CleanupCompleted);
                    break;
                default:
                    backend.Volumes = observation switch {
                        "empty" => [], "duplicate" => [original[0], original[0]],
                        "topology" => original,
                        "capability" => [original[0], original[1] with { SupportsExplorerMount = false }],
                        "write-admission" => [original[0], original[1] with { NativeWriteAdmissionBlockReason = "new-source-refusal" }],
                        _ => [original[0], original[1] with { CatalogVolumeUuid = Guid.Parse("99999999-8888-7777-6666-555555555555").ToString("N") }]
                    };
                    if (observation == "topology") backend.StoreOffset = 4096;
                    observations.Add(worker.GetInventoryAsync(CancellationToken.None));
                    if (observation == "replacement-aba")
                    {
                        backend.Volumes = original;
                        observations.Add(worker.GetInventoryAsync(CancellationToken.None));
                    }
                    break;
            }
            if (observation is not ("eject" or "shutdown"))
            {
                Assert.True(publisher.Latest.InventoryGeneration > generation);
                Assert.Equal(command, (long)typeof(ApfsMountWorker).GetField("_mountCommandGeneration", Private)!.GetValue(worker)!);
            }
            if (observation == "inventory")
                Assert.Equal(operation, (long)typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!.GetValue(worker)!);
            Assert.Empty(backend.Requests);
            Assert.Equal(0, backend.BatchCalls);
        }
        finally
        {
            await lease.DisposeAsync();
            await mount.WaitAsync(TimeSpan.FromSeconds(5));
            await Task.WhenAll(observations).WaitAsync(TimeSpan.FromSeconds(5));
        }
        var result = await mount;
        Assert.Equal(allowed, result.Success);
        if (allowed)
        {
            Assert.Equal(2, backend.Requests.Count);
            Assert.Equal('T', backend.Requests.Single(r => r.VolumeId == original[0].VolumeId).DriveLetter);
            Assert.Equal('S', backend.Requests.Single(r => r.VolumeId == original[1].VolumeId).DriveLetter);
            Assert.Equal(1, backend.BatchCalls);
        }
        else
        {
            Assert.Contains("superseded", result.Message);
            Assert.Empty(backend.Requests);
            Assert.Equal(0, backend.BatchCalls);
        }
        Assert.Equal(lettersBefore, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        if (observation is "backend-owner" or "inventory-owner")
        {
            var owner = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
            Assert.Equal(1234, owner.HostProcessId);
            Assert.Equal(5678, owner.HostProcessCreationTimeFileTimeUtc);
            Assert.Equal("T:\\", owner.MountPoint);
            Assert.Equal(original[0].CatalogVolumeUuid, owner.CatalogVolumeUuid);
            Assert.Equal(original[0].RecoveryIdentity, owner.RecoveryIdentity);
            Assert.Equal(0, backend.Unmounts);
        }
        if (observation is "inventory-same-owner" or "inventory-replaced-owner")
        {
            var owner = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None), m => m.VolumeId == "unrelated");
            Assert.Equal(4321, owner.HostProcessId);
            Assert.Equal(observation == "inventory-replaced-owner" ? 5679 : 5678, owner.HostProcessCreationTimeFileTimeUtc);
            Assert.Equal(1, owner.DirtyTransactionCount);
            Assert.Equal(0, backend.Unmounts);
        }
    }

    private static VolumeInfo TopologyVolume => Volume with
    {
        VolumeName = "Alpha", CatalogContainerUuid = new string('a', 32), CatalogVolumeObjectId = 201,
        CatalogDecision = ApfsCapabilityDecision.Writable, CatalogReasons = [], CatalogAutoMountAllowed = true,
        RecoveryIdentity = "original-alpha", SupportsNativeWrite = true
    };

    private static long Generation(ApfsMountWorker worker, string field)
        => (long)typeof(ApfsMountWorker).GetField(field, Private)!.GetValue(worker)!;

    private static async Task AssertMountGateAvailable(ApfsMountWorker worker)
    {
        var gate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", Private)!.GetValue(worker)!;
        Assert.True(await gate.WaitAsync(TimeSpan.FromSeconds(2)));
        gate.Release();
    }

    private static Task<IReadOnlyList<DeviceInventory>> ObserveEquivalentInventory(
        ApfsMountWorker worker, Backend backend, RuntimeStatusPublisher publisher)
    {
        var admitted = publisher.Latest.InventoryGeneration;
        var selection = Generation(worker, "_selectionEvidenceGeneration");
        var operation = Generation(worker, "_mountOperationGeneration");
        var command = Generation(worker, "_mountCommandGeneration");
        var reads = backend.MountReads;
        var inventory = worker.GetInventoryAsync(CancellationToken.None);
        Assert.True(backend.MountReads > reads);
        Assert.True(publisher.Latest.InventoryGeneration > admitted);
        Assert.Equal(selection, Generation(worker, "_selectionEvidenceGeneration"));
        Assert.Equal(operation, Generation(worker, "_mountOperationGeneration"));
        Assert.Equal(command, Generation(worker, "_mountCommandGeneration"));
        Assert.NotNull(Assert.Single(publisher.Latest.ConnectedInventory!).Topology);
        return inventory;
    }

    [Theory]
    [InlineData("refresh", false)]
    [InlineData("refresh", true)]
    [InlineData("exact", false)]
    [InlineData("exact", true)]
    [InlineData("selected", false)]
    [InlineData("selected", true)]
    public async Task UpgradeInventoryOwnerRevalidatedAcrossRealStorageWait(string caller, bool sameOwner)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        var volume = TopologyVolume;
        var backend = new Backend { Volumes = [volume], WithTopology = true };
        backend.AddOriginalOwner(volume);
        var original = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        var publisher = new RuntimeStatusPublisher();
        var options = new Options();
        options.CurrentValue.EnableNativeWrite = true;
        options.CurrentValue.WriteRolloutChannel = "Enabled";
        Assert.True(WriteGatePolicy.EvaluateForVolume(options.CurrentValue, volume).AllowWrite);
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            new FirstFreeMountPolicy(["R", "T"], store), publisher, options);
        var target = caller == "selected" ? SelectedControlTarget.Create(
            Assert.Single(await backend.ProbeInventoryAsync(true, CancellationToken.None)), volume) : null;
        var lease = new ReadLease(store);
        Task<(bool Success, string Message)> operation = Task.FromResult((false, "not started"));
        Task<IReadOnlyList<DeviceInventory>>? inventory = null;
        var observed = original with
        {
            HostProcessCreationTimeFileTimeUtc = sameOwner ? 5678 : 5679,
            DirtyTransactionCount = 1, WalAcceptedSequence = 42, NativeWriteDiagnostics = []
        };
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            operation = caller == "refresh" ? worker.RefreshAsync(true, CancellationToken.None)
                : worker.EnsureMountedExactAsync(volume.DeviceId, volume.VolumeId, MountAccessMode.ReadWrite,
                    CancellationToken.None, selectedTarget: target);
            await WaitForSettingsWaiter(store);
            await AssertMountGateAvailable(worker);
            Assert.Empty(backend.Requests);
            Assert.Equal(0, backend.Unmounts);
            backend.ReplaceOwner(observed);
            inventory = ObserveEquivalentInventory(worker, backend, publisher);
            Assert.False(operation.IsCompleted);
            Assert.Equal(observed, Assert.Single(await backend.GetMountStateAsync(CancellationToken.None)));
        }
        finally
        {
            await lease.DisposeAsync();
            await operation.WaitAsync(TimeSpan.FromSeconds(5));
            if (inventory is not null) await inventory.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Assert.True((await operation).Success);
        if (sameOwner)
        {
            var request = Assert.Single(backend.Requests);
            Assert.Equal('T', request.DriveLetter);
            Assert.Equal(MountAccessMode.ReadWrite, request.AccessMode);
            Assert.Equal(1, backend.Unmounts);
            Assert.Equal(MountAccessMode.ReadWrite, Assert.Single(await backend.GetMountStateAsync(CancellationToken.None)).AccessMode);
        }
        else
        {
            Assert.Empty(backend.Requests);
            Assert.Equal(0, backend.Unmounts);
            Assert.Equal(observed, Assert.Single(await backend.GetMountStateAsync(CancellationToken.None)));
        }
        Assert.Equal(0, backend.BatchCalls);
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        await AssertMountGateAvailable(worker);
    }

    [Theory]
    [InlineData("container", "inventory-owner", false)]
    [InlineData("exact", "inventory-owner", false)]
    [InlineData("container", "inventory-replaced-owner", false)]
    [InlineData("exact", "inventory-replaced-owner", false)]
    [InlineData("container", "inventory-same-owner", true)]
    [InlineData("exact", "inventory-same-owner", true)]
    [InlineData("selected", "inventory-owner", false)]
    [InlineData("selected", "inventory-replaced-owner", false)]
    [InlineData("selected", "inventory-same-owner", true)]
    [InlineData("container", "cancel", false)]
    [InlineData("container", "eject", false)]
    [InlineData("container", "shutdown", false)]
    [InlineData("container", "selection", false)]
    public async Task SingleMountOwnerRevalidatedAcrossRealStorageWait(string caller, string observation, bool allowed)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        var volume = TopologyVolume;
        var backend = new Backend { Volumes = [volume], WithTopology = true };
        if (observation is "inventory-same-owner" or "inventory-replaced-owner") backend.SetUnrelatedOwner(5678);
        var publisher = new RuntimeStatusPublisher();
        var options = new Options();
        options.CurrentValue.AutoMountEnabled = false;
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            new FirstFreeMountPolicy(["R", "T"], store), publisher, options);
        var target = caller == "selected" ? SelectedControlTarget.Create(
            Assert.Single(await backend.ProbeInventoryAsync(true, CancellationToken.None)), volume) : null;
        var lease = new ReadLease(store);
        using var cancel = new CancellationTokenSource();
        Task<(bool Success, string Message)> operation = Task.FromResult((false, "not started"));
        Task<IReadOnlyList<DeviceInventory>>? inventory = null;
        MountedVolumeState? observed = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            operation = caller == "container"
                ? worker.MountContainerAsync(volume.DeviceId, volume.CatalogContainerUuid!, [volume], MountAccessMode.ReadOnly, cancel.Token)
                : worker.EnsureMountedExactAsync(volume.DeviceId, volume.VolumeId, MountAccessMode.ReadOnly,
                    cancel.Token, selectedTarget: target);
            await WaitForSettingsWaiter(store);
            await AssertMountGateAvailable(worker);
            Assert.Empty(backend.Requests);
            switch (observation)
            {
                case "cancel": cancel.Cancel(); break;
                case "eject": Assert.True((await worker.EjectAllAsync(CancellationToken.None)).Success); break;
                case "shutdown": Assert.True((await worker.PrepareForShutdownAsync(CancellationToken.None)).CleanupCompleted); break;
                case "selection":
                    backend.Volumes = [volume with { RecoveryIdentity = "replacement-selection" }];
                    inventory = worker.GetInventoryAsync(CancellationToken.None);
                    break;
                default:
                    if (observation == "inventory-owner") backend.AddOriginalOwner(volume);
                    else backend.SetUnrelatedOwner(observation == "inventory-replaced-owner" ? 5679 : 5678, dirty: 1);
                    observed = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
                    inventory = ObserveEquivalentInventory(worker, backend, publisher);
                    Assert.False(operation.IsCompleted);
                    break;
            }
        }
        finally
        {
            await lease.DisposeAsync();
            if (observation == "cancel")
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
            else await operation.WaitAsync(TimeSpan.FromSeconds(5));
            if (inventory is not null) await inventory.WaitAsync(TimeSpan.FromSeconds(5));
        }
        if (allowed)
        {
            Assert.True((await operation).Success);
            var request = Assert.Single(backend.Requests);
            Assert.Equal(volume.VolumeId, request.VolumeId);
            Assert.Equal('T', request.DriveLetter);
        }
        else
        {
            if (observation != "cancel")
            {
                Assert.False((await operation).Success);
                Assert.Contains("superseded", (await operation).Message);
            }
            Assert.Empty(backend.Requests);
        }
        if (observed is not null)
            Assert.Equal(observed, Assert.Single(await backend.GetMountStateAsync(CancellationToken.None), m => m.VolumeId == observed.VolumeId));
        Assert.Equal(0, backend.BatchCalls);
        Assert.Equal(0, backend.Unmounts);
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        await AssertMountGateAvailable(worker);
    }

    [Theory]
    [InlineData("AA", "AB", false)]
    [InlineData("AB", "AA", false)]
    [InlineData("AA", "AA", false)]
    [InlineData("AB", "AB", true)]
    [InlineData("AB", "BA", true)]
    [InlineData("AB", "telemetry", true)]
    public async Task PreparedOwnersRequireBijectionAcrossRealStorageWait(string preparedShape, string currentShape, bool allowed)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        var volume = TopologyVolume;
        var ownerA = new MountedVolumeState("owner-a", "U:\\", MountAccessMode.ReadOnly,
            DeviceId: "other-device", HostProcessId: 1234, HostProcessCreationTimeFileTimeUtc: 5678);
        var ownerB = ownerA with { VolumeId = "owner-b", MountPoint = "V:\\", HostProcessId = 2345 };
        MountedVolumeState[] Owners(string shape) => shape switch
        {
            "AA" => [ownerA, ownerA], "AB" => [ownerA, ownerB], "BA" => [ownerB, ownerA],
            _ => [ownerA with { DirtyTransactionCount = 1 }, ownerB with { WalAcceptedSequence = 42 }]
        };
        var backend = new Backend { Volumes = [volume], WithTopology = true };
        backend.SetOwners(Owners(preparedShape));
        var publisher = new RuntimeStatusPublisher();
        var options = new Options();
        options.CurrentValue.AutoMountEnabled = false;
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            new FirstFreeMountPolicy(["R", "T"], store), publisher, options);
        var lease = new ReadLease(store);
        Task<(bool Success, string Message)> operation = Task.FromResult((false, "not started"));
        Task<IReadOnlyList<DeviceInventory>>? inventory = null;
        var current = Owners(currentShape);
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            operation = worker.MountContainerAsync(volume.DeviceId, volume.CatalogContainerUuid!, [volume],
                MountAccessMode.ReadOnly, CancellationToken.None);
            await WaitForSettingsWaiter(store);
            await AssertMountGateAvailable(worker);
            Assert.Empty(backend.Requests);
            backend.SetOwners(current);
            inventory = ObserveEquivalentInventory(worker, backend, publisher);
            Assert.False(operation.IsCompleted);
        }
        finally
        {
            await lease.DisposeAsync();
            await operation.WaitAsync(TimeSpan.FromSeconds(5));
            if (inventory is not null) await inventory.WaitAsync(TimeSpan.FromSeconds(5));
        }
        if (allowed)
        {
            Assert.True((await operation).Success);
            Assert.Equal('T', Assert.Single(backend.Requests).DriveLetter);
        }
        else
        {
            Assert.Empty(backend.Requests);
            Assert.False((await operation).Success);
            Assert.Contains("superseded", (await operation).Message);
        }
        Assert.Equal(current, (await backend.GetMountStateAsync(CancellationToken.None)).Where(m => m.VolumeId != volume.VolumeId));
        Assert.Equal(0, backend.Unmounts);
        Assert.Equal(0, backend.BatchCalls);
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        await AssertMountGateAvailable(worker);
    }

    [Theory]
    [InlineData("container", "inventory-owner", false)]
    [InlineData("selected", "inventory-owner", false)]
    [InlineData("container", "inventory-replaced-owner", false)]
    [InlineData("selected", "inventory-replaced-owner", false)]
    [InlineData("container", "leaked-owner", false)]
    [InlineData("selected", "leaked-owner", false)]
    [InlineData("upgrade", "leaked-owner", false)]
    [InlineData("container", "unchanged", true)]
    [InlineData("selected", "unchanged", true)]
    [InlineData("upgrade", "unchanged", true)]
    [InlineData("container", "inventory-same-owner", true)]
    [InlineData("selected", "inventory-same-owner", true)]
    public async Task FailedPrimaryRevalidatesOwnersBeforeFallback(string caller, string observation, bool allowed)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        var volume = TopologyVolume;
        var pause = new FailedPrimaryPause();
        var backend = new Backend { Volumes = [volume], WithTopology = true, PrimaryPause = pause };
        if (observation is "unchanged" or "inventory-same-owner" or "inventory-replaced-owner") backend.SetUnrelatedOwner(5678);
        if (caller == "upgrade") backend.AddOriginalOwner(volume);
        var publisher = new RuntimeStatusPublisher();
        var options = new Options();
        options.CurrentValue.AutoMountEnabled = caller == "upgrade";
        options.CurrentValue.EnableNativeWrite = true;
        options.CurrentValue.WriteRolloutChannel = "Enabled";
        options.CurrentValue.ReadWriteMode = "RwWithRoFallback";
        Assert.True(WriteGatePolicy.EvaluateForVolume(options.CurrentValue, volume).AllowWrite);
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            new FirstFreeMountPolicy(["R", "T"], store), publisher, options);
        var target = caller == "selected" ? SelectedControlTarget.Create(
            Assert.Single(await backend.ProbeInventoryAsync(true, CancellationToken.None)), volume) : null;
        var operation = caller switch
        {
            "container" => worker.MountContainerAsync(volume.DeviceId, volume.CatalogContainerUuid!, [volume],
                MountAccessMode.ReadWrite, CancellationToken.None),
            "upgrade" => worker.RefreshAsync(true, CancellationToken.None),
            _ => worker.EnsureMountedExactAsync(volume.DeviceId, volume.VolumeId, MountAccessMode.ReadWrite,
                CancellationToken.None, selectedTarget: target)
        };
        MountedVolumeState[] observed = [];
        try
        {
            await Task.WhenAny(pause.Entered.Task, operation).WaitAsync(TimeSpan.FromSeconds(3));
            if (!pause.Entered.Task.IsCompleted) Assert.Fail($"Primary mount was never entered: {(await operation).Message}");
            Assert.False(operation.IsCompleted);
            var primary = Assert.Single(backend.Requests);
            Assert.Equal(MountAccessMode.ReadWrite, primary.AccessMode);
            Assert.Equal('T', primary.DriveLetter);
            Assert.Equal(caller == "upgrade" ? 1 : 0, backend.Unmounts);
            if (observation is "inventory-owner" or "leaked-owner") backend.AddOriginalOwner(volume);
            else if (observation is "inventory-replaced-owner" or "inventory-same-owner")
                backend.SetUnrelatedOwner(observation == "inventory-replaced-owner" ? 5679 : 5678, dirty: 1);
            if (observation.StartsWith("inventory", StringComparison.Ordinal))
                await ObserveEquivalentInventory(worker, backend, publisher).WaitAsync(TimeSpan.FromSeconds(3));
            observed = (await backend.GetMountStateAsync(CancellationToken.None)).ToArray();
            Assert.Single(backend.Requests); // The primary is still awaited; no RO request can precede its failure.
        }
        finally
        {
            pause.Resume.TrySetResult();
            await operation.WaitAsync(TimeSpan.FromSeconds(5));
        }
        if (allowed)
        {
            Assert.True((await operation).Success);
            Assert.Equal(new[] { MountAccessMode.ReadWrite, MountAccessMode.ReadOnly }, backend.Requests.Select(r => r.AccessMode));
            Assert.All(backend.Requests, r => Assert.Equal('T', r.DriveLetter));
            Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(await backend.GetMountStateAsync(CancellationToken.None),
                m => m.VolumeId == volume.VolumeId).AccessMode);
            Assert.All(observed, owner => Assert.Contains(owner, backend.Mounts));
        }
        else
        {
            Assert.Single(backend.Requests);
            Assert.False((await operation).Success);
            Assert.Contains("superseded", (await operation).Message);
            Assert.Equal(observed, await backend.GetMountStateAsync(CancellationToken.None));
        }
        Assert.Equal(caller == "upgrade" ? 1 : 0, backend.Unmounts);
        Assert.Equal(0, backend.BatchCalls);
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        await AssertMountGateAvailable(worker);
    }

    private sealed class FailedPrimaryPause
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Resume { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    [Theory]
    [InlineData(true, "native-vmt1", false)]
    [InlineData(true, "native-vif1", false)]
    [InlineData(false, "native-vmt1", true)]
    [InlineData(false, "native-vif1", true)]
    [InlineData(true, "pending", true)]
    [InlineData(false, "pending", true)]
    [InlineData(true, "corrupt", true)]
    [InlineData(false, "corrupt", true)]
    [InlineData(true, "incomplete", true)]
    [InlineData(false, "incomplete", true)]
    [InlineData(true, "missing", true)]
    [InlineData(false, "missing", true)]
    public async Task ReconciliationDelegatesOnlyOpaqueNativeEvidenceAndPreservesManagedInvalidation(
        bool native, string evidence, bool invalidates)
    {
        var journal = Path.Combine(_root, "native-journal");
        Directory.CreateDirectory(journal);
        var options = new Options();
        options.CurrentValue.ManagementJournalRoot = journal;
        using var nativeBackend = native ? new ApfsAccess.Backend.Native.NativeApfsBackend(new ServiceHostOptions {
            BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false, ManagementJournalRoot = journal,
            NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            NativeWriteEvidenceStorePath = Path.Combine(_root, "evidence.json") }) : null;
        IApfsBackend backend = nativeBackend is null ? new Backend() : nativeBackend;
        using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
            new FirstFreeMountPolicy(["R", "T"], Store()), new RuntimeStatusPublisher(), options);
        string? retained = null;
        if (evidence == "pending")
        {
            var token = new string('a', 64);
            using var report = System.Text.Json.JsonDocument.Parse("{}");
            var intent = PendingIntent(journal) with { State = "prepared", ConfirmationToken = token,
                Result = new("prepared", "", new string('c', 80), "journal", "21", "22", "4096", token,
                    DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(), report.RootElement.Clone()) };
            using (var intents = new VolumeManagementIntentStore(journal)) intents.Save(intent);
            // A fresh live plan is not recovered here, but its presence must
            // invalidate an outstanding selection and keep mutation blocked.
            typeof(ApfsMountWorker).GetMethod("RememberVolumePlan", Private)!.Invoke(worker, [token]);
            retained = Directory.GetFiles(journal, "managed-volume-*.json").Single();
        }
        else if (evidence == "missing") Directory.Delete(journal);
        else
        {
            retained = Path.Combine(journal, evidence switch {
                "native-vmt1" => new string('a', 64) + ".vmt1",
                "native-vif1" => new string('a', 64) + ".vif1",
                "corrupt" => "managed-volume-" + Guid.NewGuid().ToString("D") + ".json",
                _ => "managed-volume-pending.tmp"
            });
            File.WriteAllText(retained, "opaque retained evidence");
        }
        var before = retained is null ? null : File.ReadAllBytes(retained);
        var generation = typeof(ApfsMountWorker).GetField("_mountOperationGeneration", Private)!;
        var original = (long)generation.GetValue(worker)!;
        for (var attempt = 1; attempt <= 2; ++attempt)
        {
            await ((Task)typeof(ApfsMountWorker).GetMethod("ReconcileVolumeIntentsAsync", Private)!
                .Invoke(worker, [CancellationToken.None])!).WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(original + (invalidates ? attempt : 0), (long)generation.GetValue(worker)!);
            var inspect = typeof(ApfsMountWorker).GetMethod("TryInspectManagementRoot", Private)!;
            if (evidence == "corrupt")
                Assert.IsAssignableFrom<System.Text.Json.JsonException>(Assert.Throws<TargetInvocationException>(() => inspect.Invoke(worker, null)).InnerException);
            else if (evidence == "incomplete")
                Assert.IsType<InvalidDataException>(Assert.Throws<TargetInvocationException>(() => inspect.Invoke(worker, null)).InnerException);
            else Assert.Equal(!invalidates, (bool)inspect.Invoke(worker, null)!);
            Assert.Equal(invalidates, (bool)typeof(ApfsMountWorker).GetMethod("VolumeIntentBlocks", Private)!
                .Invoke(worker, [Path.Combine(journal, "recovery.apfs")])!);
            if (retained is not null) Assert.Equal(before, File.ReadAllBytes(retained));
        }
    }

    private static VolumeManagementIntent PendingIntent(string journal)
    {
        var image = Path.Combine(journal, "recovery.apfs");
        var container = new string('b', 32);
        var uuid = B.ToString("N");
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeDeletePlan,
            new(image, "recovery", ContainerUuid: container), ExpiresAtUtc: DateTime.UtcNow.AddMinutes(1),
            VolumeManagement: new("delete"));
        return new(request, new("delete", image, journal, "0", container, uuid, "202", "21", new string('c', 80),
            journal, [new("202", uuid, Path.Combine(journal, "202.wal"))]), "preparing");
    }

    [Fact]
    public async Task PreferenceSubscriberCanReenterInventoryAndSaveOutsideWorkerLocks()
    {
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(new(), new FirstFreeMountPolicy(["R", "T"], Store()), publisher);
        await Cycle(worker);
        var invoked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        publisher.StatusChanged += payload =>
        {
            if (payload.MountedVolumes?.SingleOrDefault()?.DriveLetterPreference?.PreferredLetter != "T") return;
            try
            {
                Task.Run(async () =>
                {
                    _ = publisher.Latest;
                    await worker.GetInventoryAsync(CancellationToken.None);
                    Assert.True((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None)).Success);
                }).WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
                invoked.TrySetResult();
            }
            catch (Exception ex) { invoked.TrySetException(ex); }
        };
        Assert.True((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None)).Success);
        await invoked.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task AtomicReplacementRejectsActualCompetingEjectAndPreservesItsWholePayload()
    {
        var backend = new Backend();
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(backend, new FirstFreeMountPolicy(["R", "T"], Store()), publisher);
        await Cycle(worker);
        var expected = publisher.Latest;
        Assert.Single(expected.MountedVolumes!);
        var attempted = expected with { MountedVolumes = expected.MountedVolumes!.Select(m => m with
            { DriveLetterPreference = new(A.ToString("D"), "T", "R", "next-mount", "Saved", "RT", true) }).ToArray() };
        var checkedStatus = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var replace = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var publication = Task.Run(async () =>
        {
            Assert.Same(expected, publisher.Latest); // The old caller-side check passed.
            checkedStatus.SetResult();
            await replace.Task;
            Assert.False(publisher.TryPublish(expected, attempted, out var notify));
            Assert.Null(notify);
        });
        try
        {
            await checkedStatus.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.True((await worker.EjectAllAsync(CancellationToken.None)).Success);
            Assert.Equal(1, backend.Unmounts);
            var ejected = publisher.Latest;
            Assert.Empty(ejected.MountedVolumes!);
            Assert.Empty(ejected.MountPoints);
            Assert.NotEmpty(ejected.Warnings);
            replace.SetResult();
            await publication.WaitAsync(TimeSpan.FromSeconds(3));
            // Reference identity proves every non-preference field (health, warnings,
            // durability, timestamp, mounts and errors) is still the eject payload.
            Assert.Same(ejected, publisher.Latest);
        }
        finally { replace.TrySetResult(); await publication; }
    }

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = true, EnableNativeWrite = false };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class Backend : IApfsBackend, IContainerMountBackend, IVolumeTopologyBackend
    {
        public bool Batch;
        public bool WithTopology;
        public int BatchCalls;
        public int MountReads;
        public List<(VolumeTopologyRequest Request, VolumeTopologyMode Mode, string? Confirmation)> Reconciliations { get; } = [];
        public long StoreOffset;
        public VolumeInfo[] Volumes = [Volume];
        public List<MountRequest> Requests { get; } = [];
        private readonly List<MountedVolumeState> _mounts = [];
        public int Observations;
        public int Unmounts;
        public FailedPrimaryPause? PrimaryPause;
        public IReadOnlyList<MountedVolumeState> Mounts => _mounts;
        private VolumeInfo[] InventoryVolumes => Batch ? new[] { Volume, Volume with { VolumeId = "sibling",
            CatalogVolumeId = ApfsTopology.BuildVolumeId(new string('a', 32), 202), CatalogVolumeUuid = B.ToString("N") } } : Volumes;
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            Observations++;
            var volumes = InventoryVolumes;
            ApfsDiscoveryTopology? topology = null;
            if (WithTopology)
            {
                var hex = new string('a', 32); var cid = ApfsTopology.BuildContainerId(hex);
                var disk = "apfs-disk:test"; var store = "apfs-store:test";
                var graph = new ApfsTopologySnapshot([new(disk, "device", null, 134217728)], [],
                    [new(store, hex, "", cid, StoreOffset, 134217728 - StoreOffset, DiskId: disk)],
                    [new(cid, hex, 4096, [store], volumes.Select(v => v.CatalogVolumeId!).ToArray(), false, "21", [], [], [])],
                    volumes.Select(v => new ApfsVolumeRecord(v.CatalogVolumeId!, v.CatalogVolumeUuid!, v.CatalogVolumeObjectId!.Value.ToString(),
                        cid, v.VolumeName, true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "21")).ToArray(), []);
                topology = new(Observations, "device", [disk], graph);
            }
            return Task.FromResult<IReadOnlyList<DeviceInventory>>([new(new("device", "Disk", true), volumes, topology)]);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            MountReads++;
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.ToArray());
        }
        public Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, CancellationToken token)
            => throw new IOException("No offline image observation in this fixture.");
        public Task<VolumeTopologyResult> RunVolumeTopologyAsync(VolumeTopologyRequest request, VolumeTopologyMode mode, string? confirmation, CancellationToken token)
        {
            Reconciliations.Add((request, mode, confirmation));
            return Task.FromResult(new VolumeTopologyResult("cancelled", "", request.SourceIdentity, Path.Combine(request.JournalRoot, "test.vmt1"),
                request.PreXid, "0", "4096", "", 0, System.Text.Json.JsonSerializer.SerializeToElement(new { outcome = "cancelled" })));
        }
        public async Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            Requests.Add(request);
            if (request.AccessMode == MountAccessMode.ReadWrite && PrimaryPause is { } pause)
            {
                pause.Entered.TrySetResult();
                await pause.Resume.Task.WaitAsync(token);
                return new MountResult(false, null, "Paused primary RW refusal.", MountAccessMode.ReadOnly);
            }
            var volume = Assert.Single(InventoryVolumes, v => v.VolumeId == request.VolumeId);
            _mounts.Add(new(request.VolumeId, $"{request.DriveLetter}:\\", request.AccessMode, volume.VolumeName, volume.DeviceId, "Disk",
                RecoveryIdentity: volume.RecoveryIdentity, CatalogVolumeId: volume.CatalogVolumeId,
                CatalogContainerUuid: volume.CatalogContainerUuid, CatalogVolumeObjectId: volume.CatalogVolumeObjectId,
                CatalogVolumeUuid: volume.CatalogVolumeUuid));
            return new MountResult(true, $"{request.DriveLetter}:\\", null, request.AccessMode);
        }
        public async Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken token)
        {
            BatchCalls++;
            var results = new List<MountResult>();
            foreach (var request in requests) results.Add(await MountAsync(request, token));
            return results;
        }
        public void AddOriginalOwner(VolumeInfo volume) => _mounts.Add(new(volume.VolumeId, "T:\\", MountAccessMode.ReadOnly,
            DeviceId: "device", RecoveryIdentity: volume.RecoveryIdentity, CatalogVolumeId: volume.CatalogVolumeId,
            CatalogVolumeUuid: volume.CatalogVolumeUuid, CatalogContainerUuid: volume.CatalogContainerUuid,
            CatalogVolumeObjectId: volume.CatalogVolumeObjectId, HostProcessId: 1234, HostProcessCreationTimeFileTimeUtc: 5678));
        public void SetOwners(params MountedVolumeState[] owners)
        {
            _mounts.Clear();
            _mounts.AddRange(owners);
        }
        public void ReplaceOwner(MountedVolumeState owner)
        {
            _mounts.RemoveAll(m => m.VolumeId == owner.VolumeId);
            _mounts.Add(owner);
        }
        public void SetUnrelatedOwner(long creationTime, int dirty = 0)
        {
            _mounts.RemoveAll(m => m.VolumeId == "unrelated");
            _mounts.Add(new("unrelated", "U:\\", MountAccessMode.ReadOnly, DeviceId: "other-device",
                HostProcessId: 4321, HostProcessCreationTimeFileTimeUtc: creationTime, DirtyTransactionCount: dirty));
        }
        public Task<UnmountResult> UnmountAsync(string path, CancellationToken token)
        {
            Unmounts++;
            _mounts.RemoveAll(m => m.MountPoint == path);
            return Task.FromResult(new UnmountResult(true, path, null, true, true, true));
        }
    }
}
