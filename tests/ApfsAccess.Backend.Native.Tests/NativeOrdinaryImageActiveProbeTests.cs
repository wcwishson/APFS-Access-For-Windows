using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ObserverPathEnv")]
public sealed class NativeOrdinaryImageActiveProbeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProductionProbeRetainsBothSiblingsUnderAnExclusiveWriter(bool authoritative)
    {
        using var scope = await Scenario.Create();
        scope.AttachOwner();
        var frame = File.ReadAllBytes(scope.FramePath);
        using var writer = new FileStream(scope.Image, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.ThrowsAny<IOException>(() => File.OpenRead(scope.Image));
        writer.Position = writer.Length - 1;
        writer.WriteByte(1);
        writer.Flush(true);

        var inventory = Assert.Single(await scope.Backend.ProbeInventoryAsync(authoritative, default));
        Assert.Equal(scope.Before.Volumes.Select(v => v.VolumeId), inventory.Volumes.Select(v => v.VolumeId));
        Assert.Equal(2, inventory.Volumes.Count);
        Assert.Equal(2, (await scope.Backend.ProbeVolumesAsync(scope.Image, default)).Count);
        Assert.Equal(1, scope.Runner.Calls);
        Assert.Equal(frame, File.ReadAllBytes(scope.FramePath));
        Assert.Empty(Directory.GetFiles(scope.Spool, "*", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData("spool")]
    [InlineData("recovery")]
    [InlineData("journal")]
    [InlineData("source-config")]
    [InlineData("destination-config")]
    [InlineData("registration-removed")]
    [InlineData("frame-corrupt")]
    [InlineData("frame-valid-drift")]
    [InlineData("unknown-handle")]
    [InlineData("exited-handle")]
    [InlineData("foreign-process-identity")]
    [InlineData("missing-launch")]
    [InlineData("missing-inventory")]
    [InlineData("poisoned-owner")]
    [InlineData("source-size-drift")]
    public async Task ActiveProbeRefusesChangedOrUnprovedAuthority(string drift)
    {
        using var scope = await Scenario.Create();
        scope.AttachOwner();
        using var writer = new FileStream(scope.Image, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var frame = File.ReadAllBytes(scope.FramePath);
        switch (drift)
        {
            case "spool": Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", scope.OtherRoot); break;
            case "recovery": Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", scope.OtherRoot); break;
            case "journal": scope.Options.ManagementJournalRoot = scope.OtherRoot; break;
            case "source-config": scope.Options.OrdinaryManagementImages = [new(scope.OtherSource, scope.Image)]; break;
            case "destination-config": scope.Options.OrdinaryManagementImages = [new(scope.Source, scope.OtherSource)]; break;
            case "registration-removed": scope.Options.OrdinaryManagementImages = []; break;
            case "frame-corrupt": File.WriteAllText(scope.FramePath, "{}"); break;
            case "frame-valid-drift":
                var outer = JsonNode.Parse(frame)!.AsObject();
                var payload = JsonNode.Parse(outer["payload"]!.GetValue<string>())!.AsObject();
                payload["launchBindings"]!.AsArray().Clear();
                var changed = payload.ToJsonString();
                outer["payload"] = changed;
                outer["digest"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(changed)));
                File.WriteAllText(scope.FramePath, outer.ToJsonString());
                break;
            case "unknown-handle": scope.Hooks.ProbeExactProcessHandleExit = _ => null; break;
            case "exited-handle": scope.Hooks.ProbeExactProcessHandleExit = _ => true; break;
            case "foreign-process-identity": scope.Hooks.ProbeProcessCreationTime = _ => 1; break;
            case "missing-launch": Set(scope.Owner!, "OrdinaryImageLaunch", null); break;
            case "missing-inventory": Set(scope.Owner!, "OrdinaryImageDiscovery", null); break;
            case "poisoned-owner": scope.Group!.GetType().GetMethod("Poison")!.Invoke(scope.Group, ["test-contained-owner"]); break;
            case "source-size-drift": writer.SetLength(writer.Length + 4096); writer.Flush(true); break;
        }
        await Assert.ThrowsAnyAsync<IOException>(() => scope.Backend.ProbeInventoryAsync(true, default));
        Assert.Equal(1, scope.Runner.Calls);
        if (drift is not ("frame-corrupt" or "frame-valid-drift")) Assert.Equal(frame, File.ReadAllBytes(scope.FramePath));
    }

    [Fact]
    public async Task AForeignExclusiveWriterCannotReuseFreshProvenanceByFilename()
    {
        using var scope = await Scenario.Create();
        using var writer = new FileStream(scope.Image, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        await Assert.ThrowsAnyAsync<IOException>(() => scope.Backend.ProbeInventoryAsync(false, default));
        Assert.Equal(1, scope.Runner.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AReplacedSourceCannotReuseLiveOrReleasedOwnerAuthority(bool delete)
    {
        using var scope = await Scenario.Create();
        scope.AttachOwner();
        using (var writer = new FileStream(scope.Image, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            Assert.ThrowsAny<IOException>(() => File.Move(scope.Image, scope.Image + ".old"));
        if (delete) File.Delete(scope.Image);
        else File.Move(scope.Image, scope.Image + ".old");
        File.Copy(scope.Source, scope.Image);
        await Assert.ThrowsAnyAsync<IOException>(() => scope.Backend.ProbeInventoryAsync(false, default));
        scope.DetachOwner();
        scope.Launch!.Dispose();
        await Assert.ThrowsAnyAsync<IOException>(() => scope.Backend.ProbeInventoryAsync(false, default));
        Assert.Equal(1, scope.Runner.Calls);
    }

    [Fact]
    public async Task ReadOnlyOwnerCanReuseRegistrationWithoutManufacturingWritableLaunchHistory()
    {
        using var scope = await Scenario.Create();
        scope.AttachOwner(readOnly: true);
        using var reader = new FileStream(scope.Image, FileMode.Open, FileAccess.Read, FileShare.None);
        Assert.Equal(2, Assert.Single(await scope.Backend.ProbeInventoryAsync(true, default)).Volumes.Count);
        Assert.Empty(scope.Launch!.Record.LaunchBindings);
        Assert.Equal(1, scope.Runner.Calls);
    }

    [Fact]
    public async Task HostResourceCleanupReleasesIdentityAndCannotLeaveReusableAuthority()
    {
        using var scope = await Scenario.Create();
        scope.AttachOwner(dedicated: true);
        var frame = File.ReadAllBytes(scope.FramePath);
        scope.Backend.Dispose();
        var terminal = scope.Owner!.GetType().GetProperty("CompletedStopResult")!.GetValue(scope.Owner);
        Assert.NotNull(terminal);
        Assert.True((bool)terminal!.GetType().GetProperty("OwnershipReleased")!.GetValue(terminal)!);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => scope.Backend.ProbeInventoryAsync(false, default));
        Assert.Equal(frame, File.ReadAllBytes(scope.FramePath));
        File.Move(scope.Image, scope.Image + ".closed");
    }

    private static void Set(object instance, string name, object? value) => instance.GetType().GetProperty(name)!.SetValue(instance, value);
    private static IDictionary Field(object instance, string name) => (IDictionary)instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(instance)!;

    private sealed class Scenario : IDisposable
    {
        private readonly DTempDirectory _temp = DTempDirectory.Create("ordinary-active-probe");
        private readonly string? _oldSpool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT");
        private readonly string? _oldRecovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");
        private Process? _process;
        private Process? _dedicatedObserver;
        internal string Image = null!, Source = null!, Spool = null!, Recovery = null!, Root = null!, OtherRoot = null!, OtherSource = null!;
        internal NativeApfsBackend Backend = null!;
        internal ServiceHostOptions Options = null!;
        internal DeviceInventory Before = null!;
        internal HostProcessLifecycleTestHooks Hooks = new();
        internal CountingRunner Runner = null!;
        internal NativeOrdinaryImageOwnership.RetainedLaunch? Launch;
        internal object? Owner, Group;
        internal string FramePath => Directory.GetFiles(Root, "ordinary-image-*.json").Single();

        internal static async Task<Scenario> Create()
        {
            var scope = new Scenario();
            try
            {
                scope.Source = Path.Combine(scope._temp.Path, "source.apfs.img");
                scope.Image = Path.Combine(scope._temp.Path, "owned.apfs.img");
                scope.Root = Path.Combine(scope._temp.Path, "journals");
                scope.Spool = Path.Combine(scope._temp.Path, "spool");
                scope.Recovery = Path.Combine(scope._temp.Path, "recovery");
                scope.OtherRoot = Path.Combine(scope._temp.Path, "other-root");
                scope.OtherSource = Path.Combine(scope._temp.Path, "other.apfs.img");
                foreach (var root in new[] { scope.Root, scope.Spool, scope.Recovery, scope.OtherRoot }) Directory.CreateDirectory(root);
                SyntheticApfsTestImage.Create(scope.Source, sizeMiB: 8);
                File.Copy(scope.Source, scope.OtherSource);
                Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", scope.Spool);
                Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", scope.Recovery);
                var json = JsonNode.Parse(ObserverEvidenceJson.BuildSingleContainer(new string('a', 32),
                    [new("Data", 201), new("Backup", 202)], devicePath: scope.Image))!;
                var rows = json["topology"]!["volumes"]!.AsArray();
                rows[0]!["uuid"] = new string('b', 32); rows[1]!["uuid"] = new string('c', 32);
                scope.Runner = new(json.ToJsonString());
                var observer = Path.Combine(scope._temp.Path, "ApfsObserver.exe");
                File.WriteAllBytes(observer, [0x4d, 0x5a]);
                scope.Options = new() { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false,
                    ManagementJournalRoot = scope.Root, OrdinaryManagementImages = [new(scope.Source, scope.Image)],
                    NativeWriteEvidenceStorePath = Path.Combine(scope._temp.Path, "evidence.json") };
                scope.Backend = new(scope.Options, scope.Hooks, scope.Runner, observer);
                scope.Before = Assert.Single(await scope.Backend.ProbeInventoryAsync(false, default));
                Assert.Equal(2, scope.Before.Volumes.Count);
                return scope;
            }
            catch { scope.Dispose(); throw; }
        }

        internal void AttachOwner(bool readOnly = false, bool dedicated = false)
        {
            var start = new ProcessStartInfo("no-process-started.exe");
            start.Environment["APFSACCESS_SPOOL_ROOT"] = Spool; start.Environment["APFSACCESS_RECOVERY_ROOT"] = Recovery;
            var record = readOnly ? NativeOrdinaryImageOwnership.Read(Root, Image, "0") :
                NativeOrdinaryImageOwnership.CaptureLaunch(start, Root, Image, "0", Before.Volumes);
            Launch = new(record, "0");
            var lifetime = dedicated ? Path.Combine(_temp.Path, "owner.alive") : string.Empty;
            var status = dedicated ? Path.Combine(_temp.Path, "owner.status.json") : string.Empty;
            if (dedicated)
            {
                var executable = Environment.GetEnvironmentVariable("APFSACCESS_GUARDIAN_TEST_CHILD");
                Assert.True(File.Exists(executable), "The pinned managed guardian helper is required.");
                File.WriteAllText(lifetime, "alive");
                var child = new ProcessStartInfo(executable!) { UseShellExecute = false, CreateNoWindow = true };
                child.ArgumentList.Add("--ready"); child.ArgumentList.Add(Path.Combine(_temp.Path, "owner.ready"));
                child.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetime;
                _process = Process.Start(child)!;
                _dedicatedObserver = Process.GetProcessById(_process.Id);
                Assert.True(SpinWait.SpinUntil(() => File.Exists(Path.Combine(_temp.Path, "owner.ready")), TimeSpan.FromSeconds(5)));
            }
            else
            {
                _process = Process.GetCurrentProcess();
                Hooks.ProbeExactProcessHandleExit = _ => false;
                Hooks.ProbeProcessCreationTime = _ => _process.StartTime.ToFileTimeUtc();
            }
            var type = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            Owner = Activator.CreateInstance(type, BindingFlags.Instance | BindingFlags.NonPublic, null,
                [_process, lifetime, status, readOnly ? MountAccessMode.ReadOnly : MountAccessMode.ReadWrite, "Native"], null)!;
            if (dedicated) HostTerminalFixture.BindOrdinary(Owner, _process, status);
            Set(Owner, "OrdinaryImageLaunch", Launch);
            var cached = Field(Backend, "_deviceDiscoveryCache")[Image]!;
            Set(Owner, "OrdinaryImageDiscovery", cached.GetType().GetProperty("Device")!.GetValue(cached));
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            Group = Activator.CreateInstance(groupType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null,
                [new string('a', 32), Image, 0UL, string.Empty, Owner, !readOnly], null)!;
            var members = (IDictionary)groupType.GetProperty("Members")!.GetValue(Group)!;
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            foreach (var volume in Before.Volumes)
            {
                var mount = Path.Combine(_temp.Path, "unused-mount-" + volume.CatalogVolumeObjectId);
                members[mount] = Activator.CreateInstance(memberType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, null,
                    [volume.VolumeId, mount, volume.CatalogVolumeObjectId!.Value, !readOnly, volume.RecoveryIdentity!, true, true, DateTime.UtcNow], null)!;
            }
            Field(Backend, "_containerGroups")[new string('a', 32)] = Group;
        }

        internal void DetachOwner() => Field(Backend, "_containerGroups").Clear();

        public void Dispose()
        {
            if (Backend is not null) { DetachOwner(); Backend.Dispose(); }
            if (_dedicatedObserver is not null)
            {
                try
                {
                    if (!_dedicatedObserver.HasExited)
                    {
                        _dedicatedObserver.Kill(entireProcessTree: true);
                        Assert.True(_dedicatedObserver.WaitForExit(5_000));
                    }
                }
                finally { _dedicatedObserver.Dispose(); }
            }
            Launch?.Dispose();
            _process?.Dispose();
            Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT", _oldSpool);
            Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT", _oldRecovery);
            _temp.Dispose();
        }
    }

    private sealed class CountingRunner(string json) : IObserverRunner
    {
        internal int Calls;
        public ObserverRunResult Run(string executable, IReadOnlyList<string> arguments) => Run(executable, arguments, default);
        public ObserverRunResult Run(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        { Calls++; return new(0, json, string.Empty); }
    }
}
