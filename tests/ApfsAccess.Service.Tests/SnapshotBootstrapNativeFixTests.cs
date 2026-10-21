using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [BootstrapNativeTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FixRetainedSnapshotUsesGenuineNativeOwnerAuthenticatedRecoveryAndLiveVerification(bool deleting)
    {
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_BOOTSTRAP_ARTIFACT_ROOT")!, Guid.NewGuid().ToString("N")[..8]);
        Assert.StartsWith("D:", root, StringComparison.OrdinalIgnoreCase);
        Directory.CreateDirectory(root);
        var handshake = Path.Combine(root, "handshake.json");
        using var process = new Process { StartInfo = new(Environment.GetEnvironmentVariable("APFSACCESS_BOOTSTRAP_NATIVE")!) {
            WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true } };
        process.StartInfo.ArgumentList.Add(deleting ? "--serve-bootstrap" : "--serve-bootstrap-create"); process.StartInfo.ArgumentList.Add(handshake);
        Assert.True(process.Start());
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        string? stop = null;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            while (!File.Exists(handshake) && !process.HasExited) await Task.Delay(20, deadline.Token);
            Assert.False(process.HasExited, "Native owner exited before readiness.");
            using var ready = JsonDocument.Parse(await File.ReadAllTextAsync(handshake, deadline.Token));
            var data = ready.RootElement;
            Assert.True(data.GetProperty("headless").GetBoolean());
            stop = data.GetProperty("stopFile").GetString()!;
            var statusPath = data.GetProperty("statusFile").GetString()!;
            var source = data.GetProperty("source").GetString()!;
            Assert.Equal(".bin", Path.GetExtension(source));
            var control = data.GetProperty("controlFile").GetString()!;
            var disabled = await ReadNativeStatusAsync(statusPath, deadline.Token);
            await File.WriteAllTextAsync(Path.Combine(root, "disabled-native-status.json"), disabled, deadline.Token);
            var status = ContainerStatusReader.Parse(disabled);
            var selected = status.Volumes.Single(v => v.ObjectId == 101);
            Assert.False(selected.Writable); Assert.True(selected.RecoveryActive); Assert.True(selected.SnapshotRecoverySupported);
            using var original = JsonDocument.Parse(disabled);
            Assert.Equal(process.Id, original.RootElement.GetProperty("ownerPid").GetInt32());
            Assert.Equal(process.StartTime.ToUniversalTime().ToFileTimeUtc(), original.RootElement.GetProperty("ownerStartFileTimeUtc").GetInt64());
            var fixture = new SnapshotRecoveryFixture(disabled, source, data.GetProperty("volumeUuid").GetString()!, data.GetProperty("storeSizeBytes").GetInt64());
            using var route = new GenuineSnapshotFixRoute(process, status, source, statusPath, control,
                fixture.Inventory(status.ContainerUuid, 101, selected.RecoveryIdentity!));
            using var worker = CreateWorker(route, autoMountEnabled: false, autoRemount: false);
            await worker.RefreshAsync(false, deadline.Token);
            var inventory = Assert.Single(await worker.GetInventoryAsync(deadline.Token));
            var admittedOwner = Assert.Single(await route.GetMountStateAsync(deadline.Token));
            Assert.Equal(status.OwnerStartFileTimeUtc, admittedOwner.HostProcessCreationTimeFileTimeUtc);
            Assert.True(admittedOwner.HostProcessCreationTimeFileTimeUtc > 0);
            var result = await CreateExecutor(worker).ExecuteAsync(CreateRequest(ApfsControlCommands.Fix,
                SelectedControlTarget.Create(inventory, inventory.Volumes[0])), deadline.Token);
            await File.WriteAllTextAsync(Path.Combine(root, "fix-result.json"), JsonSerializer.Serialize(result), deadline.Token);
            Assert.True(result.Success, result.Diagnostic); AssertWireResult(result);
            Assert.Equal("healthy-rw", result.FinalStatus); Assert.Equal("not-applicable", result.OwnershipProof); Assert.Equal("not-applicable", result.DurabilityProof);
            Assert.Equal(1, route.RecoverCalls); Assert.Equal(1, route.VerifyCalls); Assert.Equal(0, route.MountCalls); Assert.Equal(0, route.UnmountCalls);
            Assert.NotNull(route.FirstPostRecovery);
            Assert.Equal(NativeWriteReadiness.CommitReady, route.FirstPostRecovery!.NativeWriteReadiness);
            Assert.True(SnapshotFixHealthyForTest(route.FirstPostRecovery));
            Assert.True(route.FirstPostRecovery.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite);
            await File.WriteAllTextAsync(Path.Combine(root, "first-service-post-recovery-probe.json"), JsonSerializer.Serialize(route.FirstPostRecovery), deadline.Token);
            Assert.NotNull(route.Verification);
            await File.WriteAllTextAsync(Path.Combine(root, "actual-live-verification.json"), route.Verification!.Json.GetRawText(), deadline.Token);
            Assert.Equal("Complete", route.Verification.Outcome);
            Assert.Equal(0, route.Verification.Json.GetProperty("findings").GetArrayLength());
            Assert.False(route.Verification.Json.GetProperty("wholeVolumeVerified").GetBoolean());
            Assert.False(route.Verification.Json.GetProperty("payloadContentHashesVerified").GetBoolean());
            Assert.DoesNotContain("Generic verification remains Refused", result.Diagnostic);
            var final = Assert.Single(await route.GetMountStateAsync(deadline.Token));
            Assert.Equal(process.Id, final.HostProcessId); Assert.Equal(selected.RecoveryIdentity, final.RecoveryIdentity);
            Assert.Equal(admittedOwner.HostProcessCreationTimeFileTimeUtc, final.HostProcessCreationTimeFileTimeUtc);
            Assert.True(SnapshotFixHealthyForTest(final));
            await File.WriteAllTextAsync(Path.Combine(root, "recovered-native-status.json"), await ReadNativeStatusAsync(statusPath, deadline.Token), deadline.Token);
            await File.WriteAllTextAsync(stop, "stop", deadline.Token);
            await process.WaitForExitAsync(deadline.Token); Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            if (stop is not null && !process.HasExited) await File.WriteAllTextAsync(stop, "stop");
            if (!process.HasExited) await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(190));
            await File.WriteAllTextAsync(Path.Combine(root, "native-stdout.log"), await stdout);
            await File.WriteAllTextAsync(Path.Combine(root, "native-stderr.log"), await stderr);
        }
    }

    [BootstrapNativeTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task NativeInactiveMemberStatusParsesAndPreservesHealthySibling(bool detached)
    {
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFSACCESS_BOOTSTRAP_ARTIFACT_ROOT")!, Guid.NewGuid().ToString("N")[..8]);
        Assert.StartsWith("D:", root, StringComparison.OrdinalIgnoreCase);
        Directory.CreateDirectory(root);
        var output = Path.Combine(root, "inactive-status.json");
        using var process = new Process { StartInfo = new(Environment.GetEnvironmentVariable("APFSACCESS_BOOTSTRAP_NATIVE")!) {
            WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true } };
        process.StartInfo.ArgumentList.Add(detached ? "--emit-detached-status" : "--emit-unready-status");
        process.StartInfo.ArgumentList.Add(output);
        Assert.True(process.Start());
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(90));
        await File.WriteAllTextAsync(Path.Combine(root, "native-stdout.log"), await stdout);
        await File.WriteAllTextAsync(Path.Combine(root, "native-stderr.log"), await stderr);
        Assert.Equal(0, process.ExitCode);
        var before = ContainerStatusReader.Parse(await File.ReadAllTextAsync(output + ".before.json"));
        var after = ContainerStatusReader.Parse(await File.ReadAllTextAsync(output));
        Assert.True(before.IsKnown);
        Assert.True(after.IsKnown);
        Assert.Equal(2, after.Volumes.Count);
        var originalAlpha = Assert.Single(before.Volumes, v => v.ObjectId == 101);
        Assert.True(originalAlpha.SnapshotInventorySupported);
        Assert.True(originalAlpha.SnapshotMutationSupported);
        var alpha = Assert.Single(after.Volumes, v => v.ObjectId == 101);
        Assert.Equal(!detached, alpha.Mounted);
        Assert.False(alpha.Ready);
        Assert.False(alpha.Writable);
        Assert.False(alpha.SnapshotInventorySupported);
        Assert.False(alpha.SnapshotMutationSupported);
        Assert.False(alpha.SnapshotRecoverySupported);
        var originalBeta = Assert.Single(before.Volumes, v => v.ObjectId == 102);
        var beta = Assert.Single(after.Volumes, v => v.ObjectId == 102);
        Assert.True(beta.Mounted);
        Assert.True(beta.Ready);
        Assert.True(beta.Writable);
        Assert.Equal(originalBeta.SnapshotInventorySupported, beta.SnapshotInventorySupported);
        Assert.Equal(originalBeta.SnapshotMutationSupported, beta.SnapshotMutationSupported);
        Assert.Equal(originalBeta.SnapshotRecoverySupported, beta.SnapshotRecoverySupported);
        Assert.Equal(originalBeta.RecoveryIdentity, beta.RecoveryIdentity);
        Assert.Equal(originalBeta.Drain, beta.Drain);
        Assert.Equal(before.OwnerPid, after.OwnerPid);
        Assert.Equal(before.OwnerStartFileTimeUtc, after.OwnerStartFileTimeUtc);
        Assert.Equal(before.CheckpointXid, after.CheckpointXid);
    }

    private static async Task<string> ReadNativeStatusAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(token);
    }

    private static bool SnapshotFixHealthyForTest(MountedVolumeState mount)
        => mount.MountReady && mount.AccessMode == MountAccessMode.ReadWrite && !mount.RecoveryActive &&
            mount.WalAcceptedSequence == mount.WalApfsDurableSequence && mount.WalAcceptedSequence == mount.WalCleanupSequence &&
            mount.RuntimeWatermarksKnown == true && !mount.RuntimeMutationPending && mount.VolumeVerificationSupported;

    // Only routing registration and captured inventory are seeded. PID/start,
    // status, original WAL ownership, recovery and verification come from the
    // separate native witness through the production authenticated file channel.
    private sealed class GenuineSnapshotFixRoute : IApfsBackend, ISnapshotControlBackend, ILiveVolumeVerificationBackend, IDisposable
    {
        private readonly NativeApfsBackend _backend;
        private readonly DeviceInventory _inventory;
        private readonly IDictionary _groups, _mounts;
        private readonly Process _backendProcess;
        public int RecoverCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public int MountCalls { get; private set; }
        public int UnmountCalls { get; private set; }
        public LiveVolumeVerificationReport? Verification { get; private set; }
        public MountedVolumeState? FirstPostRecovery { get; private set; }
        private bool _recoveryReturned;

        public GenuineSnapshotFixRoute(Process process, ContainerMountStatus status, string source, string statusPath, string control, DeviceInventory inventory)
        {
            _inventory = inventory;
            _backendProcess = Process.GetProcessById(process.Id);
            Assert.Equal(process.StartTime.ToUniversalTime(), _backendProcess.StartTime.ToUniversalTime());
            _backend = new(new ServiceHostOptions { EnableImageSnapshots = true, WriteBackendMode = "Native", NativeAutoRemountOnReconnect = false });
            const BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
            var hostType = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            var owner = hostType.GetConstructors(flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [_backendProcess, null, null, "", "", statusPath, MountAccessMode.ReadWrite, "Native"]);
            hostType.GetProperty("ContainerControlFilePath")!.SetValue(owner, control);
            hostType.GetProperty("ContainerControlToken")!.SetValue(owner, new string('b', 64));
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var group = groupType.GetConstructors(flags).Single().Invoke([status.ContainerUuid, source, 0UL, "", owner, true]);
            var child = status.Volumes.Single(v => v.ObjectId == 101);
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            var member = memberType.GetConstructors(flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [child.CanonicalId, "R:\\", 101UL, true, child.RecoveryIdentity, true, true, DateTime.UtcNow]);
            ((IDictionary)groupType.GetProperty("Members")!.GetValue(group)!)["R:\\"] = member;
            _groups = (IDictionary)typeof(NativeApfsBackend).GetField("_containerGroups", flags)!.GetValue(_backend)!;
            _groups[status.ContainerUuid] = group;
            _mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", flags)!.GetValue(_backend)!;
            var volume = inventory.Volumes[0];
            _mounts["R:\\"] = new MountedVolumeState(child.CanonicalId, "R:\\", MountAccessMode.ReadOnly,
                DeviceId: source, RecoveryIdentity: child.RecoveryIdentity, CatalogContainerUuid: status.ContainerUuid,
                CatalogVolumeObjectId: 101, CatalogVolumeUuid: volume.CatalogVolumeUuid, CatalogVolumeId: volume.CatalogVolumeId);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInfo>>([_inventory.Device]);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => Task.FromResult(_inventory.Volumes);
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token) => Task.FromResult<IReadOnlyList<DeviceInventory>>([_inventory]);
        public async Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            var rows = await _backend.GetMountStateAsync(token);
            if (_recoveryReturned && FirstPostRecovery is null) FirstPostRecovery = Assert.Single(rows);
            return rows;
        }
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) { MountCalls++; throw new InvalidOperationException("Retained Fix must not mount."); }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) { UnmountCalls++; throw new InvalidOperationException("Retained Fix must not unmount."); }
        public async Task<SnapshotControlResult> SendSnapshotControlAsync(string container, ulong oid, SnapshotControlAction action, IReadOnlyList<string>? extras, CancellationToken token)
        {
            Assert.Equal(SnapshotControlAction.Recover, action); RecoverCalls++;
            var result = await _backend.SendSnapshotControlAsync(container, oid, action, extras, token);
            _recoveryReturned = result.Success && result.Code == "SnapshotRecovered";
            return result;
        }
        public async Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        { VerifyCalls++; var result = await _backend.VerifyLiveVolumeAsync(scope, token); Verification = result.Report; return result; }
        public void Dispose() { _groups.Clear(); _mounts.Clear(); _backend.Dispose(); _backendProcess.Dispose(); }
    }
}

internal sealed class BootstrapNativeTheoryAttribute : TheoryAttribute
{
    public BootstrapNativeTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_BOOTSTRAP_NATIVE") is null ||
            Environment.GetEnvironmentVariable("APFSACCESS_BOOTSTRAP_ARTIFACT_ROOT") is null)
            Skip = "The exclusive native runtime window and frozen private native witness are required.";
    }
}
