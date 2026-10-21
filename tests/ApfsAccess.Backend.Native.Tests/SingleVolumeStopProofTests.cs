using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class ContainerSessionRoutingTests
{
    [Theory]
    [InlineData(2, "eject", "none")]
    [InlineData(3, "eject", "none")]
    [InlineData(2, "quit", "none")]
    [InlineData(3, "quit", "none")]
    [InlineData(2, "eject-beta", "none")]
    [InlineData(2, "eject", "query-unknown")]
    [InlineData(2, "eject", "late-peer-unknown")]
    [InlineData(2, "eject", "wrong-birth")]
    [InlineData(2, "eject", "missing-terminal")]
    [InlineData(2, "eject", "recovery-debt")]
    public async Task CensusStop_RealManifestRetainsOnlyNamespacesAndPreservesProofGuards(int count, string action, string failure)
    {
        using var temp = DTempDirectory.Create("census-stop-proof");
        var launched = new List<string[]>();
        var visibility = new ConcurrentDictionary<string, bool>();
        var queryNames = new ConcurrentBag<string>();
        Process? child = null;
        Task gracefulExit = Task.CompletedTask;
        string[]? arguments = null;
        var uncertain = false;
        var correctedTerminal = false;
        void WriteTerminal()
        {
            if (failure == "missing-terminal" && !correctedTerminal) return;
            File.WriteAllText(ArgumentValue(arguments!, "--status-file"), JsonSerializer.Serialize(new
            {
                containerUuid = ContainerHexA, ownerPid = child!.Id,
                ownerStartFileTimeUtc = child.StartTime.ToUniversalTime().ToFileTimeUtc() +
                    (failure == "wrong-birth" && !correctedTerminal ? 1 : 0),
                leaseHeld = failure == "recovery-debt" && !correctedTerminal, checkpointXid = 7ul,
                recoveryRequired = failure == "recovery-debt" && !correctedTerminal,
                recoveryVolumeObjectId = (ulong?)null,
                recoveryReason = failure == "recovery-debt" && !correctedTerminal ? "UnresolvedPeerDebt" : string.Empty,
                volumes = Array.Empty<object>(),
            }));
        }
        var rows = Enumerable.Range(0, count).Select(i => new ObserverEvidenceJson.VolumeJson("Data" + i, (ulong)(101 + i))).ToArray();
        var evidence = JsonNode.Parse(ObserverEvidenceJson.BuildSingleContainer(ContainerHexA, rows,
            devicePath: Path.Combine(temp.Path, "fixture.apfs.img")))!;
        for (var i = 0; i < count; i++)
            evidence["topology"]!["volumes"]![i]!["uuid"] = (101 + i).ToString("x32");
        var backend = await CreateProbedBackendAsync(temp, evidence.ToJsonString(), launched, visibility, hooks =>
            {
                hooks.IsMountVisible = null;
                hooks.QueryDosDevice = (name, _) =>
                {
                    queryNames.Add(name);
                    var unknownPoint = failure == "late-peer-unknown" ? "T:" : "R:";
                    return uncertain && name == unknownPoint ? (0u, 5) :
                        visibility.GetValueOrDefault(name + "\\") ? (1u, 0) : (0u, 2);
                };
                hooks.StartProcess = start =>
                {
                    arguments = start.ArgumentList.ToArray();
                    launched.Add(arguments);
                    child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
                    {
                        ArgumentList = { "/d", "/c", "set /p census_stop=&exit /b 0" },
                        UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                        RedirectStandardOutput = true, RedirectStandardError = true,
                    })!;
                    lock (_sync) _children.Add(child);
                    gracefulExit = Task.Run(async () =>
                    {
                        var lifetime = ArgumentValue(arguments, "--lifetime-file");
                        var deadline = DateTime.UtcNow.AddSeconds(20);
                        while (File.Exists(lifetime) && DateTime.UtcNow < deadline) await Task.Delay(10);
                        Assert.False(File.Exists(lifetime), "The owner received no graceful lifetime stop.");
                        visibility["R:\\"] = false;
                        visibility["T:\\"] = false;
                        WriteTerminal();
                        await child.StandardInput.WriteLineAsync("done");
                        await child.StandardInput.FlushAsync();
                        await child.WaitForExitAsync();
                        Assert.Equal(0, child.ExitCode);
                    });
                    return child;
                };
            }, configureOptions: options =>
            {
                EnableCensusWrite(options);
                options.ManagementJournalRoot = Path.Combine(temp.Path, "management");
                Directory.CreateDirectory(options.ManagementJournalRoot);
            });
        CensusOptions(backend);
        AdmitFixtureCatalog(backend);
        var selectBeta = action == "eject-beta";
        var planned = BuildPlanned(backend, selectBeta ? ["S", "R"] : count == 2 ? ["R", "S"] : ["R", "S", "T"], MountAccessMode.ReadWrite);
        backend.StartContainerGroupOwner(new(ContainerHexA, [planned[selectBeta ? 1 : 0]]));
        var group = GetContainerGroup(backend, ContainerHexA);
        var owner = group.GetType().GetProperty("Owner")!.GetValue(group)!;
        var originalPoints = (IReadOnlyList<string>)owner.GetType().GetProperty("OriginalMountPoints")!.GetValue(owner)!;
        using (var manifest = JsonDocument.Parse(File.ReadAllText(GetContainerManifestPath(backend, ContainerHexA))))
        {
            Assert.Equal(2, manifest.RootElement.GetProperty("version").GetInt32());
            Assert.Equal(count, manifest.RootElement.GetProperty("volumes").GetArrayLength());
            Assert.Equal(count - 1, manifest.RootElement.GetProperty("volumes").EnumerateArray().Count(v => !v.GetProperty("initiallyActive").GetBoolean()));
            if (selectBeta)
                Assert.Equal(102ul, manifest.RootElement.GetProperty("volumes").EnumerateArray().Single(v => v.GetProperty("initiallyActive").GetBoolean()).GetProperty("objectId").GetUInt64());
        }
        visibility["R:\\"] = true;
        PublishContainerStatus(arguments!, child!.Id, visibility, status =>
        {
            foreach (var row in status["volumes"]!.AsArray())
                row!["writable"] = row["mounted"]!.GetValue<bool>();
        });
        var mounted = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadWrite, mounted.AccessMode);
        Assert.Equal("R:\\", mounted.MountPoint);
        if (failure == "late-peer-unknown")
        {
            // The activation path records its current namespace in Members, not in the launch manifest.
            typeof(NativeApfsBackend).GetMethod("RegisterContainerMember_NoLock", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(backend, [group, planned[1].Volume, "T:\\", planned[1].VolumeObjectId!.Value,
                    MountAccessMode.ReadOnly, planned[1].RecoveryIdentity!, false]);
            var members = (IDictionary)group.GetType().GetProperty("Members")!.GetValue(group)!;
            var later = members["T:\\"]!;
            later.GetType().GetProperty("Attached")!.SetValue(later, false);
        }
        uncertain = failure is "query-unknown" or "late-peer-unknown";
        try
        {
            if (action == "quit")
            {
                using var worker = new ApfsMountWorker(NullLogger<ApfsMountWorker>.Instance, backend,
                    new FirstFreeMountPolicy(["R"]), new RuntimeStatusPublisher(),
                    new CensusStopOptions(new ServiceHostOptions { NativeHostStopTimeoutSeconds = 2 }));
                var result = await worker.PrepareForShutdownAsync(CancellationToken.None);
                await gracefulExit.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.True(result.CleanupCompleted, result.Diagnostic);
                Assert.True(result.HostOwnershipReleased, result.Diagnostic);
                Assert.True(result.PendingDurabilityCleared, result.Diagnostic);
                Assert.Empty(result.RemainingMounts);
            }
            else
            {
                var result = await backend.UnmountAsync("R:\\", CancellationToken.None);
                await gracefulExit.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.False(result.ContainerMemberDetached);
                if (failure != "none")
                {
                    Assert.False(result.Success);
                    Assert.False(result.PendingDurabilityCleared);
                    Assert.False(result.HostOwnershipReleased);
                    Assert.Equal(1, GetContainerGroupCount(backend));
                    uncertain = false; correctedTerminal = true; WriteTerminal();
                    result = await backend.UnmountAsync("R:\\", CancellationToken.None);
                }
                Assert.True(result.Success, result.Error);
                Assert.True(result.MountRemoved);
                Assert.True(result.HostOwnershipReleased);
                Assert.True(result.PendingDurabilityCleared);
            }
            Assert.Equal(["R:\\"], originalPoints);
            Assert.Equal(0, GetContainerGroupCount(backend));
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
            Assert.All(queryNames, name => Assert.Contains(name, new[] { "R:", "T:" }));
            if (failure == "late-peer-unknown") Assert.Contains("T:", queryNames);
        }
        finally
        {
            uncertain = false; correctedTerminal = true;
            if (File.Exists(ArgumentValue(arguments!, "--lifetime-file"))) File.Delete(ArgumentValue(arguments!, "--lifetime-file"));
            await gracefulExit.WaitAsync(TimeSpan.FromSeconds(5));
            if (GetContainerGroupCount(backend) > 0) WriteTerminal();
            // Keep a RED assertion from retaining the test's own OS handles.
            owner.GetType().GetProperty("OriginalMountPoints")!.SetValue(owner, new[] { "R:\\" });
            backend.Dispose();
        }
    }

    private sealed class CensusStopOptions(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;
        public ServiceHostOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
}
