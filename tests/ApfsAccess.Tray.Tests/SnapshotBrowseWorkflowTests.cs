using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class SnapshotBrowseWorkflowTests
{
    private const string Session = @"D:\FictionalSnapshotSessions\session-one";
    private const string Destination = @"D:\FictionalSnapshotCopies\new-copy";
    private const string OperationId = "11111111-2222-3333-4444-555555555555";

    private static JsonElement Inventory()
    {
        var r = JsonNode.Parse(WindowsSurfaceFixture.SnapshotInventory().GetRawText())!;
        r["source"] = new JsonObject { ["kind"] = "image", ["path"] = WindowsSurfaceFixture.Image,
            ["sizeBytes"] = 100000, ["hashScope"] = "full", ["sha256"] = new string('c', 64) };
        r["storeOffsetBytes"] = "0"; r["storeSizeBytes"] = "100000";
        return JsonSerializer.SerializeToElement(r);
    }

    private static DriveDashboardRow Row(StatusChangedPayload status) =>
        Assert.Single(TopologyDashboard.Project(status), n => n.Row is not null).Row!;

    private static VolumeSnapshotWorkflow Workflow(Func<StatusChangedPayload> status,
        Func<ControlOperationRequestPayload, Task<OperationResultPayload>>? send = null) => new(Row(status()), status, send ?? (r =>
            Task.FromResult(new OperationResultPayload(r.OperationId, r.Command, r.Target, ApfsOperationFingerprint.Compute(r),
                ApfsOperationStates.Succeeded, "ok", true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
                FinalStatus: "snapshot-inventory", MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "not-applicable",
                ExpiresAtUtc: r.ExpiresAtUtc, SnapshotInventory: Inventory()))));

    private static async Task<(VolumeSnapshotWorkflow Workflow, SnapshotBrowseRequest Request)> Prepared()
    {
        var status = WindowsSurfaceFixture.Status(); var workflow = Workflow(() => status);
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        return (workflow, workflow.PrepareBrowse(Assert.Single(workflow.Inventory!.Entries), null, Session));
    }

    // Public CLI ready.json and final JSON shape, with deterministic fictional identities.
    private static JsonObject Selection(SnapshotBrowseRequest r) => new()
    {
        ["image"] = r.Scope.ImagePath, ["sourceSizeBytes"] = r.SourceSizeBytes, ["sourceSha256"] = r.SourceSha256,
        ["containerUuid"] = WindowsSurfaceFixture.Hex, ["volumeUuid"] = WindowsSurfaceFixture.VolumeHex,
        ["volumeOid"] = "101", ["checkpointXid"] = "90", ["storeOffsetBytes"] = "0", ["storeSizeBytes"] = "100000",
        ["snapshotXid"] = "21", ["name"] = "backup", ["snapshot"] = JsonNode.Parse(r.Snapshot.NativeIdentity!.Value.GetRawText())
    };

    private static JsonObject Ready(SnapshotBrowseRequest r) => new()
    {
        ["operationId"] = OperationId, ["mountPoint"] = Path.Combine(Session, "mount"), ["selection"] = Selection(r),
        ["immutableSnapshot"] = true, ["mountedReadinessProven"] = true, ["copyOut"] = r.CopyOut
    };

    private static SnapshotBrowseExit Terminal(SnapshotBrowseRequest r, Action<JsonObject>? change = null, int exit = 0)
    {
        var node = new JsonObject { ["schemaVersion"] = 2, ["command"] = "snapshots-browse", ["operationId"] = OperationId,
            ["success"] = exit == 0, ["exitCode"] = exit, ["code"] = exit == 0 ? "ok" : "Timeout",
            ["error"] = exit == 0 ? null : "Cancelled copy; destination may be partial.", ["sessionDirectory"] = Session,
            ["mountPoint"] = Path.Combine(Session, "mount"), ["selection"] = Selection(r), ["mountedReadinessProven"] = true,
            ["teardownProven"] = true, ["supervisorEvidence"] = Path.Combine(Session, "supervisor.json"),
            ["copyOut"] = r.CopyOut is null ? null : new JsonObject { ["files"] = 3, ["directories"] = 2, ["bytes"] = 8192 } };
        change?.Invoke(node); return new(exit, node.ToJsonString(), "");
    }

    private sealed class Process : ISnapshotBrowseProcess
    {
        internal readonly TaskCompletionSource<SnapshotBrowseExit> Terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal SnapshotBrowseExit? ExitOnClose;
        internal int Closes;
        internal bool Disposed;
        public Task<SnapshotBrowseExit> Completion => Terminal.Task;
        public Task CloseAsync() { Closes++; if (ExitOnClose is not null) Terminal.TrySetResult(ExitOnClose); return Task.CompletedTask; }
        public void Dispose() => Disposed = true;
    }

    [Fact]
    public async Task OfflineImageSelectedFromFreshInventoryBuildsExactPublicArguments()
    {
        var (workflow, r) = await Prepared(); Assert.True(workflow.CanBrowse(r.Snapshot));
        var start = SnapshotBrowseProcess.StartInfo(r with { CopyOut = Destination }, @"D:\FictionalPackage\ApfsAccess.Cli.exe");
        Assert.False(start.UseShellExecute); Assert.True(start.CreateNoWindow);
        Assert.True(start.RedirectStandardInput && start.RedirectStandardOutput && start.RedirectStandardError);
        Assert.Equal(new[] { "snapshots", "browse", "--image", WindowsSurfaceFixture.Image, "--container-id", "apfs-container:" + WindowsSurfaceFixture.Hex,
            "--volume-oid", "101", "--snapshot-xid", "21", "--session-dir", Session, "--close-on-stdin", "--json", "--copy-out", Destination }, start.ArgumentList);
    }

    [Theory]
    [InlineData("not-selected")] [InlineData("cloned-entry")] [InlineData("refreshed-entry")] [InlineData("invalidated")]
    public async Task OldOrUnselectedEntriesCannotLaunch(string kind)
    {
        var (workflow, r) = await Prepared(); var entry = r.Snapshot;
        if (kind == "refreshed-entry") await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        if (kind == "invalidated") workflow.Invalidate();
        Assert.False(workflow.CanBrowse(kind == "not-selected" ? null : kind == "cloned-entry" ? entry with { } : entry));
        if (kind == "not-selected")
        { Assert.Throws<InvalidOperationException>(() => workflow.PrepareBrowse(null, null, Session)); return; }
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(kind == "cloned-entry" ? entry with { } : entry,
            null, new(_ => { calls++; throw new Exception(); }), _ => { }, default, Session));
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("hash")] [InlineData("window")] [InlineData("kind")] [InlineData("hash-scope")] [InlineData("checkpoint")]
    public async Task IncompleteOrContradictoryImageInventoryCannotLaunch(string field)
    {
        var status = WindowsSurfaceFixture.Status(); var node = JsonNode.Parse(Inventory().GetRawText())!;
        switch (field)
        {
            case "hash": node["source"]!["sha256"] = "unknown"; break;
            case "window": node["storeSizeBytes"] = "99999"; break;
            case "kind": node["source"]!["kind"] = "physical"; break;
            case "hash-scope": node["source"]!["hashScope"] = "window"; break;
            default: node["checkpointXid"] = "89"; break;
        }
        var workflow = Workflow(() => status, r => Task.FromResult(new OperationResultPayload(r.OperationId, r.Command, r.Target,
            ApfsOperationFingerprint.Compute(r), ApfsOperationStates.Succeeded, "ok", true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
            FinalStatus: "snapshot-inventory", MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "not-applicable",
            ExpiresAtUtc: r.ExpiresAtUtc, SnapshotInventory: JsonSerializer.SerializeToElement(node))));
        await workflow.RunAsync(ApfsControlCommands.SnapshotList);
        Assert.False(workflow.CanBrowse(Assert.Single(workflow.Inventory!.Entries)));
    }

    [Theory]
    [InlineData("image")] [InlineData("source-hash")] [InlineData("size")] [InlineData("volume")]
    [InlineData("window")] [InlineData("checkpoint")] [InlineData("root")] [InlineData("name")]
    [InlineData("mount")] [InlineData("mutable")] [InlineData("not-ready")] [InlineData("destination")]
    public async Task ForgedReadyEvidenceClosesWithoutOpeningExplorer(string change)
    {
        var (_, r) = await Prepared(); var node = Ready(r);
        switch (change)
        {
            case "image": node["selection"]!["image"] = @"D:\other.apfs"; break;
            case "source-hash": node["selection"]!["sourceSha256"] = new string('d', 64); break;
            case "size": node["selection"]!["sourceSizeBytes"] = 99999; break;
            case "volume": node["selection"]!["volumeUuid"] = new string('d', 32); break;
            case "window": node["selection"]!["storeOffsetBytes"] = "4096"; break;
            case "checkpoint": node["selection"]!["checkpointXid"] = "91"; break;
            case "root": node["selection"]!["snapshot"]!["rootPhysicalBlock"] = "9"; break;
            case "name": node["selection"]!["name"] = "other"; break;
            case "mount": node["mountPoint"] = @"D:\other-mount"; break;
            case "mutable": node["immutableSnapshot"] = false; break;
            case "not-ready": node["mountedReadinessProven"] = false; break;
            default: node["copyOut"] = Destination; break;
        }
        var process = new Process { ExitOnClose = Terminal(r) }; var opened = 0;
        var client = new SnapshotBrowseClient(_ => process, _ => JsonSerializer.SerializeToElement(node));
        await Assert.ThrowsAsync<InvalidDataException>(() => client.RunAsync(r, _ => opened++, () => { }, default));
        Assert.Equal(0, opened); Assert.Equal(1, process.Closes); Assert.True(process.Disposed);
    }

    [Theory]
    [InlineData("teardown")] [InlineData("selection")] [InlineData("operation")] [InlineData("session")]
    [InlineData("evidence")] [InlineData("copy-count")] [InlineData("exit")]
    public async Task TerminalProofMustMatchSelectionAndOperation(string change)
    {
        var (_, original) = await Prepared(); var r = original with { CopyOut = Destination };
        var terminal = Terminal(r, node =>
        {
            switch (change)
            {
                case "teardown": node["teardownProven"] = false; break;
                case "selection": node["selection"]!["snapshotXid"] = "22"; break;
                case "operation": node["operationId"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"; break;
                case "session": node["sessionDirectory"] = @"D:\other"; break;
                case "evidence": node["supervisorEvidence"] = @"D:\other.json"; break;
                case "copy-count": node["copyOut"]!["bytes"] = -1; break;
                default: node["exitCode"] = 5; break;
            }
        });
        Assert.Throws<IOException>(() => SnapshotBrowseProtocol.Terminal(terminal, r, OperationId));
    }

    [Fact]
    public async Task BrowseOpensOnlyExactReadyPathAndWaitsForConfirmedClose()
    {
        var (_, r) = await Prepared(); using var cancel = new CancellationTokenSource(); var process = new Process();
        var opened = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var run = new SnapshotBrowseClient(_ => process, _ => JsonSerializer.SerializeToElement(Ready(r))).RunAsync(r,
            p => opened.SetResult(p), () => { }, cancel.Token);
        Assert.Equal(Path.Combine(Session, "mount"), await opened.Task.WaitAsync(TimeSpan.FromSeconds(3)));
        cancel.Cancel(); await Task.Delay(180);
        Assert.Equal(1, process.Closes); Assert.False(run.IsCompleted); Assert.False(process.Disposed);
        process.Terminal.SetResult(Terminal(r));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.True(process.Disposed);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task StartupCancellationAndTimeoutRequestCloseBeforeDisposal(bool timeout)
    {
        var (_, r) = await Prepared(); using var cancel = new CancellationTokenSource();
        var process = new Process { ExitOnClose = Terminal(r) };
        var client = new SnapshotBrowseClient(_ => process, _ => null, timeout ? TimeSpan.Zero : TimeSpan.FromSeconds(10));
        var run = client.RunAsync(r, _ => throw new Exception("No readiness"), () => { }, cancel.Token);
        if (!timeout) cancel.Cancel();
        if (timeout) await Assert.ThrowsAsync<TimeoutException>(() => run);
        else await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(1, process.Closes); Assert.True(process.Disposed);
    }

    [Theory]
    [InlineData("checkpoint")] [InlineData("recovery")] [InlineData("disconnected")] [InlineData("mounted")]
    public async Task ServiceSelectionDriftDuringReadinessClosesWithoutOpening(string change)
    {
        var status = WindowsSurfaceFixture.Status(); var workflow = Workflow(() => status);
        await workflow.RunAsync(ApfsControlCommands.SnapshotList); var entry = Assert.Single(workflow.Inventory!.Entries);
        var r = workflow.PrepareBrowse(entry, null, Session); var process = new Process { ExitOnClose = Terminal(r) }; var opened = 0;
        var client = new SnapshotBrowseClient(_ => process, _ =>
        {
            var d = status.ConnectedInventory![0];
            status = change switch
            {
                "checkpoint" => status with { ConnectedInventory = [d with { Topology = d.Topology! with { Snapshot = d.Topology.Snapshot with {
                    Containers = [d.Topology.Snapshot.Containers[0] with { CheckpointXid = "91" }] } } }] },
                "recovery" => status with { ConnectedInventory = [d with { Volumes = [d.Volumes[0] with { RecoveryIdentity = "changed" }] }] },
                "mounted" => WindowsSurfaceFixture.Status(true),
                _ => status with { ConnectedInventory = [], MountedVolumes = [] }
            };
            return JsonSerializer.SerializeToElement(Ready(r));
        });
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(entry, null, client, _ => opened++, default, Session));
        Assert.Equal(0, opened); Assert.Equal(1, process.Closes); Assert.Null(workflow.Inventory);
    }

    [Fact]
    public async Task CopyOutSuccessUsesTerminalCountsWithoutOpeningExplorer()
    {
        var (_, original) = await Prepared(); var r = original with { CopyOut = Destination }; var process = new Process();
        var client = new SnapshotBrowseClient(_ => process, _ =>
        { process.Terminal.TrySetResult(Terminal(r)); return JsonSerializer.SerializeToElement(Ready(r)); });
        var result = await client.RunAsync(r, _ => throw new Exception("Copy must not open Explorer"), () => { }, default);
        Assert.Equal(new SnapshotBrowseResult(Destination, 3, 2, 8192), result); Assert.True(process.Disposed);
    }

    [Fact]
    public async Task CancelledCopyKeepsPartialDestinationAndDoesNotClaimSuccess()
    {
        var (_, original) = await Prepared(); var r = original with { CopyOut = Destination };
        using var cancel = new CancellationTokenSource(); var process = new Process { ExitOnClose = Terminal(r, exit: 4) };
        var client = new SnapshotBrowseClient(_ => process, _ => { cancel.Cancel(); return JsonSerializer.SerializeToElement(Ready(r)); });
        var error = await Assert.ThrowsAsync<IOException>(() => client.RunAsync(r, _ => { }, () => { }, cancel.Token));
        Assert.Contains("partial", error.Message); Assert.Equal(1, process.Closes); Assert.True(process.Disposed);
    }

    [Fact]
    public async Task ActiveBrowsePreventsCompetingServiceDispatch()
    {
        var (workflow, r) = await Prepared(); var process = new Process(); using var stop = new CancellationTokenSource();
        var client = new SnapshotBrowseClient(_ => process, _ => null);
        var run = workflow.BrowseAsync(r.Snapshot, null, client, _ => { }, stop.Token, Session);
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.RunAsync(ApfsControlCommands.SnapshotList));
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(r.Snapshot, null, client, _ => { }, default, Session));
        stop.Cancel(); process.Terminal.SetResult(Terminal(r));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Theory]
    [InlineData("physical")] [InlineData("mounted")] [InlineData("encrypted")] [InlineData("offset")]
    public async Task UnsupportedSourcesCannotReachTheCli(string kind)
    {
        var (_, original) = await Prepared(); var status = WindowsSurfaceFixture.Status(kind == "mounted");
        var device = status.ConnectedInventory![0];
        if (kind == "physical")
        {
            var json = JsonSerializer.Serialize(status).Replace(JsonSerializer.Serialize(WindowsSurfaceFixture.Image),
                JsonSerializer.Serialize(@"\\.\PhysicalDrive9"), StringComparison.Ordinal);
            status = JsonSerializer.Deserialize<StatusChangedPayload>(json)!;
        }
        if (kind == "encrypted") status = status with { ConnectedInventory = [device with {
            Volumes = [device.Volumes[0] with { IsEncrypted = true }] }] };
        if (kind == "offset") status = status with { ConnectedInventory = [device with { Topology = device.Topology! with {
            Snapshot = device.Topology.Snapshot with { Stores = [device.Topology.Snapshot.Stores[0] with { OffsetBytes = 4096 }] } } }] };
        var workflow = Workflow(() => status); var calls = 0;
        Assert.False(workflow.CanBrowse(original.Snapshot));
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(original.Snapshot, null,
            new(_ => { calls++; throw new Exception(); }), _ => { }, default, Session));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task FailedServiceRefreshRevokesBrowseSelection()
    {
        var status = WindowsSurfaceFixture.Status(); var fail = false;
        var workflow = Workflow(() => fail ? throw new IOException("Service disconnected") : status);
        await workflow.RunAsync(ApfsControlCommands.SnapshotList); var entry = Assert.Single(workflow.Inventory!.Entries);
        fail = true;
        Assert.False(workflow.CanBrowse(entry)); Assert.Null(workflow.Inventory);
        var calls = 0;
        await Assert.ThrowsAsync<IOException>(() => workflow.BrowseAsync(entry, null,
            new(_ => { calls++; throw new Exception(); }), _ => { }, default, Session));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task DuplicateReadyPropertiesAndMissingTerminalCannotEstablishAuthority()
    {
        var (_, r) = await Prepared();
        using var duplicate = JsonDocument.Parse(Ready(r).ToJsonString().Insert(1, "\"immutableSnapshot\":false,"));
        Assert.Throws<InvalidDataException>(() => SnapshotBrowseProtocol.Ready(duplicate.RootElement, r));
        Assert.Throws<IOException>(() => SnapshotBrowseProtocol.Terminal(new(0, "{", ""), r, OperationId));
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive0")] [InlineData(@"\\server\share\folder")]
    [InlineData(@"D:\copy:stream")] [InlineData(@"D:\copy\..\folder")]
    [InlineData(Session)] [InlineData(Session + @"\child")]
    public async Task InvalidCopyDestinationsNeverLaunch(string destination)
    {
        var (workflow, r) = await Prepared(); var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(r.Snapshot, destination,
            new(_ => { calls++; throw new Exception(); }), _ => { }, default, Session));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task DriftAfterReadinessClosesTheAlreadyOpenSession()
    {
        var status = WindowsSurfaceFixture.Status(); var workflow = Workflow(() => status);
        await workflow.RunAsync(ApfsControlCommands.SnapshotList); var entry = Assert.Single(workflow.Inventory!.Entries);
        var r = workflow.PrepareBrowse(entry, null, Session); var process = new Process { ExitOnClose = Terminal(r) }; var opened = 0;
        var client = new SnapshotBrowseClient(_ => process, _ => JsonSerializer.SerializeToElement(Ready(r)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(entry, null, client, _ =>
        { opened++; status = status with { ConnectedInventory = [], MountedVolumes = [] }; }, default, Session));
        Assert.Equal(1, opened); Assert.Equal(1, process.Closes); Assert.True(process.Disposed); Assert.Null(workflow.Inventory);
    }

    [Fact]
    public async Task CancelledCopyWithoutTeardownProofReportsUnconfirmedClosure()
    {
        var (_, original) = await Prepared(); var r = original with { CopyOut = Destination }; using var stop = new CancellationTokenSource();
        var process = new Process { ExitOnClose = Terminal(r, n => n["teardownProven"] = false, exit: 4) };
        var client = new SnapshotBrowseClient(_ => process, _ => { stop.Cancel(); return JsonSerializer.SerializeToElement(Ready(r)); });
        var error = await Assert.ThrowsAsync<IOException>(() => client.RunAsync(r, _ => { }, () => { }, stop.Token));
        Assert.Contains("not confirmed", error.Message); Assert.Contains(Session, error.Message);
    }

    [Fact]
    public async Task ExistingSessionDirectoryCannotReuseReadinessOrStartAProcess()
    {
        var (_, r) = await Prepared();
        Assert.Throws<InvalidOperationException>(() => SnapshotBrowseProcess.Start(r with { SessionDirectory = Path.GetTempPath() }));
    }

    [Fact]
    public async Task CatalogCapabilityDowngradeClosesActiveBrowse()
    {
        var status = WindowsSurfaceFixture.Status(); var workflow = Workflow(() => status);
        await workflow.RunAsync(ApfsControlCommands.SnapshotList); var entry = Assert.Single(workflow.Inventory!.Entries);
        var r = workflow.PrepareBrowse(entry, null, Session); var process = new Process { ExitOnClose = Terminal(r) };
        var client = new SnapshotBrowseClient(_ => process, _ => JsonSerializer.SerializeToElement(Ready(r)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => workflow.BrowseAsync(entry, null, client, _ =>
        {
            var device = status.ConnectedInventory![0];
            status = status with { ConnectedInventory = [device with { Volumes = [device.Volumes[0] with {
                CatalogDecision = ApfsCapabilityDecision.Readable, CatalogReasons = ["special-role:system"], CatalogAutoMountAllowed = false }] }] };
        }, default, Session));
        Assert.Equal(1, process.Closes); Assert.True(process.Disposed); Assert.Null(workflow.Inventory);
    }
}
