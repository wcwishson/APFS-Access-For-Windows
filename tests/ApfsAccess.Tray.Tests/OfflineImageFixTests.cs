using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class OfflineImageFixTests
{
    internal static StatusChangedPayload Status(bool mounted = false)
    {
        var status = ContainerVerificationFixture.Status(live: mounted);
        return status with { MountedVolumes = status.MountedVolumes!.Select(m => m with {
            AccessMode = MountAccessMode.ReadOnly, State = RuntimeState.MountedRo, WriteEnabled = false,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback, HostProcessId = 800,
            HostProcessCreationTimeFileTimeUtc = 134048736000000000 }).ToArray() };
    }

    internal static OperationResultPayload Healthy(ControlOperationRequestPayload request) => new(
        request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request),
        ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
        FinalStatus: "healthy-rw", RequestedMode: request.RequestedMode, ExpiresAtUtc: request.ExpiresAtUtc,
        EffectiveMode: ApfsControlModes.ReadWrite, RecoveryState: "inactive", MountProof: "present",
        OwnershipProof: "not-applicable", DurabilityProof: "not-applicable");

    internal static StatusChangedPayload AfterFirst(StatusChangedPayload status)
    {
        var original = ContainerVerificationFixture.Status();
        var first = original.MountedVolumes![0] with { HostProcessId = 900, HostProcessCreationTimeFileTimeUtc = 134048736000000100,
            VolumeVerificationScope = original.MountedVolumes[0].VolumeVerificationScope! with { CheckpointXid = "91" } };
        var device = status.ConnectedInventory![0];
        return status with { MountedVolumes = [first], TimestampUtc = status.TimestampUtc.AddSeconds(1),
            ConnectedInventory = [device with { Topology = device.Topology! with { Snapshot = device.Topology.Snapshot with {
                Containers = device.Topology.Snapshot.Containers.Select(c => c with { CheckpointXid = "91" }).ToArray(),
                Volumes = device.Topology.Snapshot.Volumes.Select(v => v with { SuperblockXid = "91" }).ToArray() } } }] };
    }

    internal static StatusChangedPayload AfterAll(StatusChangedPayload status) => status with {
        MountedVolumes = ContainerVerificationFixture.Status().MountedVolumes!.Select(m => m with {
            HostProcessId = 900, HostProcessCreationTimeFileTimeUtc = 134048736000000100,
            VolumeVerificationScope = m.VolumeVerificationScope! with { CheckpointXid = "91" } }).ToArray(),
        TimestampUtc = status.TimestampUtc.AddSeconds(1) };

    [Fact]
    public void OfflineFixRed_PresenterExposesExplicitFixWithoutLosingMount()
    {
        var status = Status(); var row = ContainerVerificationFixture.Rows(status)[0];
        var mount = DriveDashboardPresenter.CreateSelectedRequest(status, row, ApfsControlCommands.Mount);
        Assert.Equal(ApfsControlCommands.Mount, mount.Command);
        var fix = DriveDashboardPresenter.CreateSelectedRequest(status, row, ApfsControlCommands.Fix);
        Assert.Equal(ApfsControlCommands.Fix, fix.Command); Assert.Null(fix.RequestedMode);
        Assert.Equal(SelectedControlTarget.Create(status.ConnectedInventory![0], status.ConnectedInventory[0].Volumes[0]), fix.Target);
    }

    [Fact]
    public async Task OfflineFixRed_ContainerReResolvesSiblingAfterAcknowledgedCohortTransition()
    {
        var status = Status(mounted: true);
        var flow = ContainerFixFlow.Capture(status, ContainerVerificationFixture.Rows(status));
        var sent = new List<ControlOperationRequestPayload>();
        var report = await flow.RunAsync(() => status, request => {
            sent.Add(request);
            status = sent.Count == 1 ? AfterFirst(status) : AfterAll(status);
            var reply = Healthy(request);
            var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, reply, reply.OperationId, PipeSchemaVersions.Schema2));
            Assert.True(validation.IsValid, validation.Diagnostic);
            return Task.FromResult(reply);
        }, _ => throw new Exception("A healthy Fix must not ask for approval."));
        Assert.True(report.Success, report.Summary + " " + string.Join("; ", report.Members.Select(m => m.Diagnostic)));
        Assert.Equal(2, sent.Count); Assert.NotEqual(sent[0].Target!.VolumeId, sent[1].Target!.VolumeId);
    }

    [Fact]
    public void OfflineFixRed_HiddenFormHasSeparateMountAndFixDispatch() => Sta(() => {
        var status = Status(); var selected = ContainerVerificationFixture.Rows(status)[0];
        var mounted = new List<string>(); var fixedVolumes = new List<string>();
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask,
            _ => throw new Exception("Offline Fix must use the exact selected target."),
            mountVolumeAsync: row => { mounted.Add(row.VolumeId); return Task.CompletedTask; },
            fixVolumeAsync: row => { fixedVolumes.Add(row.VolumeId); return Task.CompletedTask; });
        form.ApplyStatus(status);
        var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
        tree.SelectedNode = Nodes(tree.Nodes).Single(n => (n.Tag as TopologyDashboardNode)?.Row?.VolumeId == selected.VolumeId);
        var buttons = Controls(form).OfType<Button>().ToArray();
        var fix = Assert.Single(buttons, b => b.Text == "Fix" && b.Enabled);
        var mount = Assert.Single(buttons, b => b.Text == "Mount" && b.Enabled);
        Click(fix); Click(mount);
        Assert.Equal([selected.VolumeId], fixedVolumes); Assert.Equal([selected.VolumeId], mounted); Assert.False(form.Visible);
        typeof(DashboardForm).GetMethod("PopulateContextMenu", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(form, null);
        var menu = tree.ContextMenuStrip!;
        var fixItem = Assert.Single(menu.Items.OfType<ToolStripMenuItem>(), i => i.Text == "Fix " + selected.VolumeName);
        var mountItem = Assert.Single(menu.Items.OfType<ToolStripMenuItem>(), i => i.Text == "Mount " + selected.VolumeName);
        Assert.True(fixItem.Enabled); Assert.True(mountItem.Enabled);
        fixItem.PerformClick(); mountItem.PerformClick();
        Assert.Equal(2, fixedVolumes.Count); Assert.Equal(2, mounted.Count);
        form.SetActionsEnabled(false); Click(fix); Click(mount);
        Assert.Equal(2, fixedVolumes.Count); Assert.Equal(2, mounted.Count);
    });

    [Fact]
    public void OfflinePhysicalMountAndProtectedImageChoicesRemainBounded()
    {
        var physical = ContainerVerificationFixture.Status(live: false, raw: true);
        foreach (var row in ContainerVerificationFixture.Rows(physical))
        {
            Assert.False(DriveDashboardPresenter.CanFixVolume(row));
            Assert.Equal(ApfsControlCommands.Mount, DriveDashboardPresenter.CreateMountRequest(physical, row).Command);
            Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSelectedRequest(physical,row,ApfsControlCommands.Fix));
        }
        var status = Status(); var ordinary = ContainerVerificationFixture.Rows(status)[0];
        Assert.False(DriveDashboardPresenter.CanFixVolume(ordinary with { SnapshotScope = null }));
        Assert.False(DriveDashboardPresenter.CanFixVolume(ordinary with { CanFix = false }));
        Assert.False(DriveDashboardPresenter.CanFixVolume(ordinary with { SnapshotScope = ordinary.SnapshotScope! with { ImagePath = @"D:\replacement.apfs" } }));
        var d = status.ConnectedInventory![0];
        var encrypted = status with { ConnectedInventory = [d with { Volumes = d.Volumes.Select(v => v with { IsEncrypted = true }).ToArray() }] };
        Assert.All(ContainerVerificationFixture.Rows(encrypted), r => Assert.False(DriveDashboardPresenter.CanFixVolume(r)));
    }

    [Fact]
    public void TrayFixAndMountMenusUseExplicitFreshSelectedTargets() => Sta(() => {
        var status = Status();
        var fixRows = TrayApplicationContext.SelectedActionRows(status,ApfsControlCommands.Fix);
        Assert.Equal(2,fixRows.Length);
        Assert.Equal(2,TrayApplicationContext.SelectedActionRows(status,ApfsControlCommands.Mount).Length);
        Assert.Empty(TrayApplicationContext.SelectedActionRows(ContainerVerificationFixture.Status(live:false,raw:true),ApfsControlCommands.Fix));
        var sent = new List<ControlOperationRequestPayload>();
        using var item = TrayApplicationContext.CreateSelectedActionItem(fixRows[0],ApfsControlCommands.Fix,
            (row,command) => { sent.Add(DriveDashboardPresenter.CreateSelectedRequest(status,row,command)); return Task.CompletedTask; },
            ex => throw new Xunit.Sdk.XunitException(ex.Message));
        item.PerformClick();
        var request = Assert.Single(sent); Assert.Equal(ApfsControlCommands.Fix,request.Command);
        Assert.Equal(SelectedControlTarget.Create(status.ConnectedInventory![0],status.ConnectedInventory[0].Volumes[0]),request.Target);
    });

    [Fact]
    public void OfflineContainerFormDispatchUsesAllCurrentMemberRows() => Sta(() => {
        var status = Status(); var captured = new List<IReadOnlyList<DriveDashboardRow>>();
        using var form = new DashboardForm(_ => Task.CompletedTask,_ => Task.CompletedTask,_ => Task.CompletedTask,
            fixContainerAsync: rows => { captured.Add(rows); return Task.CompletedTask; });
        form.ApplyStatus(status);
        var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
        tree.SelectedNode = Nodes(tree.Nodes).Single(n => n.Tag is TopologyDashboardNode node && node.Text.StartsWith("APFS container",StringComparison.Ordinal));
        var fix = Assert.Single(Controls(form).OfType<Button>(), b => b.Text == "Fix container");
        Assert.True(fix.Enabled); Click(fix);
        Assert.Equal(ContainerVerificationFixture.Rows(status).Select(r=>r.CatalogVolumeId),Assert.Single(captured).Select(r=>r.CatalogVolumeId));
        Assert.False(form.Visible);
    });

    internal static IEnumerable<Control> Controls(Control root) { foreach (Control child in root.Controls) { yield return child; foreach (var c in Controls(child)) yield return c; } }
    internal static IEnumerable<TreeNode> Nodes(TreeNodeCollection nodes) { foreach (TreeNode node in nodes) { yield return node; foreach (var child in Nodes(node.Nodes)) yield return child; } }
    internal static void Click(Button button) => typeof(Button).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(button, [EventArgs.Empty]);
    internal static void Sta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception ex) { error = ex; } });
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Hidden form test must finish without dialogs.");
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
    }
}
