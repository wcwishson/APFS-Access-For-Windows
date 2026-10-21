using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

// No Show(), desktop focus, dialogs or real transport callbacks.
public sealed class DashboardFormTests
{
    [Fact]
    public void NotifyIconLeftClick_ShowsDashboard()
    {
        // Exercise the actual event-handler branch without constructing a tray icon
        // or displaying a form. Left click invokes ShowDashboard exactly once.
        var shown = 0;
        TrayApplicationContext.HandleNotifyIconClick(MouseButtons.Left, () => shown++);
        Assert.Equal(1, shown);
        TrayApplicationContext.HandleNotifyIconClick(MouseButtons.Right, () => shown++);
        TrayApplicationContext.HandleNotifyIconClick(MouseButtons.Middle, () => shown++);
        Assert.Equal(1, shown);
    }

    [Fact]
    public void PreferencesAndUpdaterRetainTheirCallbacks() => Sta(() =>
    {
        var startup = new List<bool>();
        var minimized = new List<bool>();
        var updates = 0;
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            new(true, true), v => { startup.Add(v); return Task.CompletedTask; },
            v => { minimized.Add(v); return Task.CompletedTask; }, () => { updates++; return Task.CompletedTask; });
        var boxes = Controls(form).OfType<CheckBox>().ToArray();
        Assert.Equal(2, boxes.Length);
        Assert.All(boxes, b => { Assert.True(b.Checked); Assert.True(b.AutoSize); });
        boxes.Single(b => b.Text == "Start the program with Windows").Checked = false;
        boxes.Single(b => b.Text == "Start minimized").Checked = false;
        Click(Controls(form).OfType<Button>().Single(b => b.Text == "Check for updates"));
        Assert.Equal([false], startup);
        Assert.Equal([false], minimized);
        Assert.Equal(1, updates);
        Assert.False(form.Visible);
    });

    [Fact]
    public void CloseToTrayCancelsUserCloseUntilApplicationExit() => Sta(() =>
    {
        using var form = NewForm();
        var method = typeof(DashboardForm).GetMethod("OnFormClosing", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var close = new FormClosingEventArgs(CloseReason.UserClosing, false);
        method.Invoke(form, [close]);
        Assert.True(close.Cancel);
        form.AllowCloseForApplicationExit();
        close = new(CloseReason.UserClosing, false);
        method.Invoke(form, [close]);
        Assert.False(close.Cancel);
        Assert.False(form.Visible);
    });

    [Fact]
    public void EjectAndFixUseSelectedVolumeAndBusyStateSurvivesRefresh() => Sta(() =>
    {
        string? ejected = null, fixedId = null;
        using var form = new DashboardForm(_ => Task.CompletedTask,
            id => { ejected = id; return Task.CompletedTask; }, id => { fixedId = id; return Task.CompletedTask; });
        var status = Mounted();
        SelectVolume(form, status);
        var eject = Controls(form).OfType<Button>().Single(b => b.Text == "Eject");
        var fix = Controls(form).OfType<Button>().Single(b => b.Text == "Fix");
        Assert.True(eject.Enabled);
        Assert.True(fix.Enabled);
        form.SetActionsEnabled(false);
        form.ApplyStatus(status with { TimestampUtc = DateTime.UtcNow.AddSeconds(1) });
        Assert.Same(eject, Controls(form).OfType<Button>().Single(b => b.Text == "Eject"));
        Assert.False(eject.Enabled);
        Assert.False(fix.Enabled);
        form.SetActionsEnabled(true);
        Click(eject);
        Click(fix);
        Assert.Equal("device|volume", ejected);
        Assert.Equal("device|volume", fixedId);
    });

    [Fact]
    public void HealthyReadWriteDisablesFixAndUpdatesSelectedPaneInPlace() => Sta(() =>
    {
        using var form = NewForm();
        var status = Mounted();
        SelectVolume(form, status);
        var fix = Controls(form).OfType<Button>().Single(b => b.Text == "Fix");
        var tree = Controls(form).OfType<TreeView>().Single();
        var selected = tree.SelectedNode;
        form.ApplyStatus(status with { State = RuntimeState.MountedRw, WriteEnabled = true,
            MountedVolumes = [status.MountedVolumes![0] with { AccessMode = MountAccessMode.ReadWrite }] });
        Assert.Same(fix, Controls(form).OfType<Button>().Single(b => b.Text == "Fix"));
        Assert.False(fix.Enabled);
        Assert.Same(selected, tree.SelectedNode);
    });

    [Theory]
    [InlineData(460)]
    [InlineData(1100)]
    public void LongTextWrapsWithinScrollablePane(int width) => Sta(() =>
    {
        using var form = NewForm();
        form.Size = new Size(width, 900);
        var status = Mounted();
        status = status with { MountedVolumes = [status.MountedVolumes![0] with {
            VolumeName = string.Join(" ", Enumerable.Repeat("Long volume name", 40)) }] };
        SelectVolume(form, status);
        form.PerformLayout();
        var row = Controls(form).OfType<Panel>().Single(p => p.BorderStyle == BorderStyle.FixedSingle);
        row.PerformLayout();
        Assert.True(row.Height > 100);
        Assert.All(Controls(row).OfType<Label>(), l => Assert.True(l.MaximumSize.Width > 0));
        Assert.True(row.Width <= row.Parent!.ClientSize.Width);
        Assert.All(Controls(row).OfType<Button>(), b => Assert.True(b.AutoSize));
        Assert.False(form.Visible);
    });

    [Fact]
    public void ContainerMountButton_InvokesDelegateWithResolvedContainer() => Sta(() =>
    {
        var mounted = new List<(string DeviceId, string ContainerUuid)>();
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            mountContainerAsync: (d, c) => { mounted.Add((d, c)); return Task.CompletedTask; },
            unmountContainerAsync: (d, c) => Task.CompletedTask);
        form.ApplyStatus(ContainerInventory());
        SelectDeviceNode(form);
        var mount = Controls(form).OfType<Button>().Single(b => b.Text == "Mount container");
        // NOTE: Visible is hierarchy-dependent and always false on a never-shown
        // headless form; Enabled carries the availability contract instead.
        Assert.True(mount.Enabled);
        Assert.All(Controls(form).OfType<Button>().Where(b => b.Text == "Unmount container"),
            b => Assert.False(b.Enabled));
        Click(mount);
        var single = Assert.Single(mounted);
        Assert.Equal(@"\\.\PhysicalDrive2", single.DeviceId);
        Assert.Equal(new string('a', 32), single.ContainerUuid);
    });

    [Fact]
    public void ContainerUnmountButton_InvokesDelegateForMountedContainer() => Sta(() =>
    {
        var unmounted = new List<(string DeviceId, string ContainerUuid)>();
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            mountContainerAsync: (d, c) => Task.CompletedTask,
            unmountContainerAsync: (d, c) => { unmounted.Add((d, c)); return Task.CompletedTask; });
        form.ApplyStatus(ContainerMounted());
        SelectDeviceNode(form);
        var unmount = Controls(form).OfType<Button>().Single(b => b.Text == "Unmount container");
        Assert.True(unmount.Enabled);
        Click(unmount);
        var single = Assert.Single(unmounted);
        Assert.Equal(@"\\.\PhysicalDrive2", single.DeviceId);
        Assert.Equal(new string('a', 32), single.ContainerUuid);
    });

    [Fact]
    public void UnavailableContainerActionsRenderDisabledWithRefusalReason() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            mountContainerAsync: (d, c) => Task.CompletedTask,
            unmountContainerAsync: (d, c) => Task.CompletedTask);
        form.ApplyStatus(ContainerMounted());
        SelectDeviceNode(form);
        var verify = Controls(form).OfType<Button>().Single(b => b.Text == "Verify volumes");
        var manage = Controls(form).OfType<Button>().Single(b => b.Text == "Manage offline volume");
        Assert.False(verify.Enabled);
        Assert.False(manage.Enabled);
        Assert.False(ContainerVolumeVerification.TryCapture(ContainerMounted(),
            DriveDashboardPresenter.BuildRows(ContainerMounted()), out _, out _));
        Assert.Contains("offline", manage.AccessibleDescription, StringComparison.OrdinalIgnoreCase);
    });

    [Fact]
    public void VerifyVolumesButtonDelegatesExactBatchAndHonorsBusyState() => Sta(() =>
    {
        var status = ContainerVerificationFixture.Status();
        var sent = new List<ControlOperationRequestPayload>();
        var callbacks = 0;
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            verifyContainerAsync: async batch =>
            {
                callbacks++;
                var report = await batch.RunAsync(() => status, request =>
                {
                    sent.Add(request);
                    return Task.FromResult(ContainerVerificationFixture.Result(request));
                });
                Assert.True(report.Success);
            });
        form.ApplyStatus(status);
        SelectVerificationContainer(form);
        var verify = Controls(form).OfType<Button>().Single(b => b.Text == "Verify volumes");
        Assert.True(verify.Enabled);
        Assert.False(Controls(form).OfType<Button>().Single(b => b.Text == "Manage offline volume").Enabled);
        form.SetActionsEnabled(false);
        Assert.False(verify.Enabled);
        Click(verify);
        Assert.Equal(0, callbacks);
        form.SetActionsEnabled(true);
        Click(verify);
        Assert.Equal(1, callbacks);
        Assert.Equal(ContainerVerificationFixture.Rows(status).Select(r => r.VolumeId), sent.Select(r => r.Target!.VolumeId));
        Assert.All(sent, r => Assert.Equal(ApfsControlCommands.VolumeVerify, r.Command));
        typeof(DashboardForm).GetMethod("PopulateContextMenu", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);
        var menu = Controls(form).OfType<TreeView>().Single().ContextMenuStrip!;
        var verifyItem = menu.Items.OfType<ToolStripMenuItem>().Single(i => i.Text == "Verify volumes");
        Assert.True(verifyItem.Enabled);
        verifyItem.PerformClick();
        Assert.Equal(2, callbacks);
        Assert.Equal(4, sent.Count);
        Assert.False(form.Visible);
    });

    [Fact]
    public void VerifyVolumesButtonDisablesAfterMemberCapabilityChanges() => Sta(() =>
    {
        var status = ContainerVerificationFixture.Status();
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            verifyContainerAsync: _ => throw new Xunit.Sdk.XunitException("Must not delegate"));
        form.ApplyStatus(status);
        SelectVerificationContainer(form);
        var verify = Controls(form).OfType<Button>().Single(b => b.Text == "Verify volumes");
        Assert.True(verify.Enabled);
        form.ApplyStatus(ContainerVerificationFixture.OwnerChange(status, 1, m => m with { VolumeVerificationSupported = false }));
        Assert.False(verify.Enabled);
        Click(verify);
        Assert.False(Controls(form).OfType<Button>().Single(b => b.Text == "Manage offline volume").Enabled);
    });

    private static void SelectVerificationContainer(DashboardForm form)
    {
        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        var container = TopologyTreeRefreshTestNodes(tree.Nodes).Single(n =>
            n.Tag is TopologyDashboardNode node && node.Text.StartsWith("APFS container", StringComparison.Ordinal));
        tree.SelectedNode = container;
    }

    private static IEnumerable<TreeNode> TopologyTreeRefreshTestNodes(TreeNodeCollection nodes)
    {
        foreach (TreeNode node in nodes)
        {
            yield return node;
            foreach (var child in TopologyTreeRefreshTestNodes(node.Nodes)) yield return child;
        }
    }

    [Fact]
    public void IsDisplayEqual_IgnoresTimestampButNotContent()
    {
        var a = new StatusChangedPayload(ApfsAccess.Core.RuntimeState.MountedRw, ["E:\\"], null,
            new DateTime(2026, 9, 23, 1, 0, 0, DateTimeKind.Utc), [], true, []);
        var b = a with { TimestampUtc = new DateTime(2026, 9, 23, 1, 0, 2, DateTimeKind.Utc) };
        Assert.True(DashboardForm.IsDisplayEqual(a, b));
        Assert.True(DashboardForm.IsDisplayEqual(a, a));
        Assert.False(DashboardForm.IsDisplayEqual(a, b with { WriteEnabled = false }));
        Assert.False(DashboardForm.IsDisplayEqual(a, b with { MountPoints = ["F:\\"] }));
    }

    [Fact]
    public void DeviceEjectButton_InvokesDelegateWithDeviceId() => Sta(() =>
    {
        var ejected = new List<string>();
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            ejectDeviceAsync: d => { ejected.Add(d); return Task.CompletedTask; });
        form.ApplyStatus(ContainerMounted());
        SelectDeviceNode(form);
        var eject = Controls(form).OfType<Button>().Single(b => b.Text == "Eject device");
        Assert.True(eject.Enabled);
        Click(eject);
        Assert.Equal(@"\\.\PhysicalDrive2", Assert.Single(ejected));
    });

    [Fact]
    public void DeviceEjectButton_AbsentWithoutDelegate() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        form.ApplyStatus(ContainerMounted());
        SelectDeviceNode(form);
        Assert.DoesNotContain(Controls(form).OfType<Button>(), b => b.Text == "Eject device");
    });

    [Fact]
    public void FixContainerButton_InvokesDelegateWithMemberRows() => Sta(() =>
    {
        var fixedContainers = new List<IReadOnlyList<DriveDashboardRow>>();
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            fixContainerAsync: rows => { fixedContainers.Add(rows); return Task.CompletedTask; });
        form.ApplyStatus(OfflineImageFixTests.Status(mounted: true));
        SelectVerificationContainer(form);
        var fix = Controls(form).OfType<Button>().Single(b => b.Text == "Fix container");
        Assert.True(fix.Enabled);
        Click(fix);
        var rows = Assert.Single(fixedContainers);
        Assert.Equal(2, rows.Count);
    });

    private static void SelectDeviceNode(DashboardForm form)
    {
        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        tree.SelectedNode = tree.Nodes.Cast<TreeNode>()
            .First(n => n.Tag is TopologyDashboardNode { Row: null } &&
                n.Nodes.Cast<TreeNode>().Any(c => (c.Tag as TopologyDashboardNode)?.Row is not null));
    }

    private static StatusChangedPayload ContainerInventory() => new(RuntimeState.Idle, [], null,
        DateTime.UtcNow, [], false, [], ConnectedInventory:
        [
            new DeviceInventory(new DeviceInfo(@"\\.\PhysicalDrive2", "APFS USB Device", true),
            [
                ContainerInventoryVolume(@"\\.\PhysicalDrive2|Main", "Main", 101),
                ContainerInventoryVolume(@"\\.\PhysicalDrive2|Backup", "Backup", 102),
            ]),
        ]);

    private static VolumeInfo ContainerInventoryVolume(string volumeId, string name, ulong objectId)
        => new(
            VolumeId: volumeId,
            DeviceId: @"\\.\PhysicalDrive2",
            VolumeName: name,
            SupportsReadWrite: true,
            RecoveryIdentity: "apfs-recovery-v1|main",
            CatalogVolumeId: volumeId,
            CatalogContainerUuid: new string('a', 32),
            CatalogVolumeObjectId: objectId,
            CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [],
            CatalogAutoMountAllowed: true,
            CatalogVolumeUuid: new string('b', 32));

    private static StatusChangedPayload ContainerMounted()
    {
        var mounted = new[]
        {
            new MountedVolumeDisplay(
                VolumeId: @"\\.\PhysicalDrive2|Main",
                MountPoint: "E:\\",
                VolumeName: "Main",
                DeviceId: @"\\.\PhysicalDrive2",
                DeviceDisplayName: "APFS USB Device",
                AccessMode: MountAccessMode.ReadWrite,
                RecoveryIdentity: "apfs-recovery-v1|main",
                CatalogVolumeId: @"\\.\PhysicalDrive2|Main",
                CatalogContainerUuid: new string('a', 32),
                CatalogVolumeObjectId: 101,
                CatalogVolumeUuid: new string('b', 32)),
            new MountedVolumeDisplay(
                VolumeId: @"\\.\PhysicalDrive2|Backup",
                MountPoint: "F:\\",
                VolumeName: "Backup",
                DeviceId: @"\\.\PhysicalDrive2",
                DeviceDisplayName: "APFS USB Device",
                AccessMode: MountAccessMode.ReadWrite,
                RecoveryIdentity: "apfs-recovery-v1|main",
                CatalogVolumeId: @"\\.\PhysicalDrive2|Backup",
                CatalogContainerUuid: new string('a', 32),
                CatalogVolumeObjectId: 102,
                CatalogVolumeUuid: new string('b', 32)),
        };
        return new StatusChangedPayload(RuntimeState.MountedRw, ["E:\\", "F:\\"], null,
            DateTime.UtcNow, [], true, [], MountedVolumes: mounted, ConnectedInventory:
            [
                new DeviceInventory(new DeviceInfo(@"\\.\PhysicalDrive2", "APFS USB Device", true),
                    mounted.Select(static m => ContainerInventoryVolume(m.VolumeId, m.VolumeName,
                        m.CatalogVolumeObjectId ?? 101)).ToArray()),
            ]);
    }

    private static StatusChangedPayload ContainerNeedsFix()
    {
        var mounted = new[]
        {
            new MountedVolumeDisplay(
                VolumeId: @"\\.\PhysicalDrive2|Main",
                MountPoint: "E:\\",
                VolumeName: "Main",
                DeviceId: @"\\.\PhysicalDrive2",
                DeviceDisplayName: "APFS USB Device",
                AccessMode: MountAccessMode.ReadOnly,
                RecoveryIdentity: "apfs-recovery-v1|main",
                CatalogVolumeId: @"\\.\PhysicalDrive2|Main",
                CatalogContainerUuid: new string('a', 32),
                CatalogVolumeObjectId: 101,
                CatalogVolumeUuid: new string('b', 32),
                CatalogDecision: ApfsCapabilityDecision.Writable,
                CatalogReasons: [],
                CatalogAutoMountAllowed: true),
            new MountedVolumeDisplay(
                VolumeId: @"\\.\PhysicalDrive2|Backup",
                MountPoint: "F:\\",
                VolumeName: "Backup",
                DeviceId: @"\\.\PhysicalDrive2",
                DeviceDisplayName: "APFS USB Device",
                AccessMode: MountAccessMode.ReadOnly,
                RecoveryIdentity: "apfs-recovery-v1|main",
                CatalogVolumeId: @"\\.\PhysicalDrive2|Backup",
                CatalogContainerUuid: new string('a', 32),
                CatalogVolumeObjectId: 102,
                CatalogVolumeUuid: new string('b', 32),
                CatalogDecision: ApfsCapabilityDecision.Writable,
                CatalogReasons: [],
                CatalogAutoMountAllowed: true),
        };
        return new StatusChangedPayload(RuntimeState.MountedRo, ["E:\\", "F:\\"], null,
            DateTime.UtcNow, [], false, [], MountedVolumes: mounted, ConnectedInventory:
            [
                new DeviceInventory(new DeviceInfo(@"\\.\PhysicalDrive2", "APFS USB Device", true),
                    mounted.Select(static m => ContainerInventoryVolume(m.VolumeId, m.VolumeName,
                        m.CatalogVolumeObjectId ?? 101)).ToArray()),
            ]);
    }

    [Fact]
    public void RescanRunsCallbackWithoutDeviceEjectAlias() => Sta(() =>
    {
        var scans = 0;
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            rescanAsync: () => { scans++; return Task.CompletedTask; });
        form.ApplyStatus(Mounted());
        var scan = Controls(form).OfType<Button>().Single(b => b.Text == "Rescan devices");
        form.SetActionsEnabled(false);
        Assert.False(scan.Enabled);
        form.SetActionsEnabled(true);
        Click(scan);
        Assert.Equal(1, scans);
        Assert.DoesNotContain(Controls(form).OfType<Button>(), b => b.Text == "Eject device");
    });

    [Fact]
    public void MemberHealthButton_VisibleOnPartitionOrStoreAndUpdatesDetails() => Sta(() =>
    {
        using var form = NewForm();
        var (status, topology) = PartitionAndStoreTopology();
        form.ApplyTopologyStatus(status, topology);
        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        var partNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .Single(n => n.Tag is TopologyDashboardNode tn && tn.Id.StartsWith("apfs-part:", StringComparison.Ordinal));
        tree.SelectedNode = partNode;
        var memberHealth = Controls(form).OfType<Button>().Single(b => b.Text == "Member health");
        var isLocallyVisible = (bool)typeof(Control).GetMethod("GetState", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(memberHealth, [2])!;
        Assert.True(isLocallyVisible);
        Assert.True(memberHealth.Enabled);
        Click(memberHealth);
        var details = Controls(form).OfType<Label>().Single(l => l.AccessibleName == "Selected node details");
        Assert.Contains("Health: Healthy and attached", details.Text);
    });

    [Fact]
    public void UnavailableVolumeActionsRenderDisabledWithRefusalReason() => Sta(() =>
    {
        using var form = NewForm();
        var status = Mounted();
        SelectVolume(form, status);
        var snapshots = Controls(form).OfType<Button>().Single(b => b.Text == "Volume snapshots");
        var manage = Controls(form).OfType<Button>().Single(b => b.Text == "Manage volume");
        Assert.False(snapshots.Enabled);
        Assert.False(manage.Enabled);
        Assert.Contains("SnapshotRuntimeOwnerNotReady", snapshots.AccessibleDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("offline", manage.AccessibleDescription, StringComparison.OrdinalIgnoreCase);
    });

    [Fact]
    public void RescanButton_TextReflectsDeviceSelection() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            rescanAsync: () => Task.CompletedTask,
            ejectDeviceAsync: _ => Task.CompletedTask);
        form.ApplyStatus(ContainerMounted());
        var rescan = Controls(form).OfType<Button>().Single(b => b.Text.StartsWith("Rescan", StringComparison.Ordinal));

        SelectDeviceNode(form);
        Assert.Equal("Rescan device", rescan.Text);

        var tree = Controls(form).OfType<TreeView>().Single();
        var volNode = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes).First(n => (n.Tag as TopologyDashboardNode)?.Row is not null);
        tree.SelectedNode = volNode;
        Assert.Equal("Rescan devices", rescan.Text);
    });

    private static (StatusChangedPayload Status, ApfsTopologySnapshot Topology) PartitionAndStoreTopology()
    {
        var container = ApfsTopology.BuildContainerId(new string('a', 32));
        var part = ApfsTopology.BuildPartitionId(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var store = ApfsTopology.BuildStoreId(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var volume = ApfsTopology.BuildVolumeId(new string('a', 32), 10);
        var status = new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, []);
        var topology = new ApfsTopologySnapshot(
            [new("apfs-disk:d1", "device1", null, 10000)],
            [new(part, "p1", "apfs-disk:d1", 1, 0, 5000, "apfs", "APFS")],
            [new(store, "s1", part, container, 0, 5000)],
            [new(container, "container-uuid", 4096, [store], [volume], false, "1", [], [], [])],
            [new(volume, "uuid-10", "10", container, "Data", true, ["data"], 0, null, "sensitive", "none", false, [], [], [], "1", "1")],
            []);
        return (status, topology);
    }

    private static IEnumerable<TreeNode> EnumerateTreeNodes(TreeNode root)
    {
        yield return root;
        foreach (TreeNode child in root.Nodes)
        {
            foreach (var descendant in EnumerateTreeNodes(child))
                yield return descendant;
        }
    }

    private static DashboardForm NewForm() => new(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
    [Fact]
    public void ImageResizeFormatButtonsAndDialogsCarryActualSelectionsWithoutShowingForm() => Sta(() =>
    {
        DriveDashboardRow? resized = null, formatted = null;
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            resizeImageAsync: row => { resized = row; return Task.CompletedTask; }, formatImageAsync: row => { formatted = row; return Task.CompletedTask; });
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [WindowsSurfaceFixture.Inventory(2097152)],
            ImageResizeFormatEnabled = true, VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
        form.ApplyStatus(status); var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
        tree.SelectedNode = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes).Single(n => n.Tag is TopologyDashboardNode { Row: not null });
        var resize = Controls(form).OfType<Button>().Single(b => b.Text == "Resize image container");
        var format = Controls(form).OfType<Button>().Single(b => b.Text == "Format image container");
        Assert.True(resize.Enabled); Assert.True(format.Enabled); Click(resize); Click(format);
        Assert.Equal(resized, formatted); Assert.Equal(WindowsSurfaceFixture.Image, resized!.DeviceId);
        using var resizeDialog = new VolumeImageDialog(resized, false);
        Controls(resizeDialog).OfType<NumericUpDown>().Single().Value = 3145728;
        Click(Controls(resizeDialog).OfType<Button>().Single(b => b.Name == "ReviewPlan"));
        Assert.Equal(DialogResult.OK, resizeDialog.DialogResult); Assert.Equal("3145728", resizeDialog.Parameters.TargetBytes);
        using var formatDialog = new VolumeImageDialog(formatted!, true);
        Controls(formatDialog).OfType<TextBox>().Single(b => b.Name == "VolumeName").Text = "Fresh data";
        Controls(formatDialog).OfType<RadioButton>().Single(b => b.Text == "Erase free space").Checked = true;
        Click(Controls(formatDialog).OfType<Button>().Single(b => b.Name == "ReviewPlan"));
        Assert.Equal(DialogResult.OK, formatDialog.DialogResult); Assert.Equal("erase", formatDialog.Parameters.Kind);
        form.ApplyStatus(status with { ImageResizeFormatEnabled = false });
        Assert.False(resize.Enabled); Assert.False(format.Enabled); Assert.False(form.Visible);
    });
    [Fact]
    public void BoundedImageManagementAndSnapshotButtonsDispatchActualSelectedCallbacks() => Sta(() =>
    {
        string? renamed = null, deleted = null, snapshots = null, created = null, verified = null;
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
            manageVolumeAsync: row => { renamed = row.VolumeId; return Task.CompletedTask; },
            snapshotsVolumeAsync: row => { snapshots = row.VolumeId; return Task.CompletedTask; },
            verifyVolumeAsync: row => { verified = row.VolumeId; return Task.CompletedTask; },
            createVolumeAsync: (image, container) => { created = image + ":" + container; return Task.CompletedTask; },
            deleteVolumeAsync: row => { deleted = row.VolumeId; return Task.CompletedTask; });
        var offline = WindowsSurfaceFixture.Status() with { VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
        form.ApplyStatus(offline);
        var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
        var nodes = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes).ToArray();
        tree.SelectedNode = nodes.Single(n => n.Tag is TopologyDashboardNode { Row: not null });
        Click(Controls(form).OfType<Button>().Single(b => b.Text == "Manage volume"));
        Click(Controls(form).OfType<Button>().Single(b => b.Text == "Delete image volume"));
        Assert.Equal(WindowsSurfaceFixture.Inventory().Volumes[0].VolumeId, renamed); Assert.Equal(renamed, deleted);
        tree.SelectedNode = nodes.Single(n => n.Tag is TopologyDashboardNode node && node.Text.StartsWith("APFS container", StringComparison.Ordinal));
        var create = Controls(form).OfType<Button>().Single(b => b.Text == "Create image volume");
        Assert.True(create.Enabled); Click(create);
        Assert.Equal(WindowsSurfaceFixture.Image + ":" + WindowsSurfaceFixture.Hex, created);
        form.ApplyStatus(WindowsSurfaceFixture.Status(true));
        nodes = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes).ToArray();
        tree.SelectedNode = nodes.Single(n => n.Tag is TopologyDashboardNode { Row: not null });
        var button = Controls(form).OfType<Button>().Single(b => b.Text == "Volume snapshots");
        Assert.True(button.Enabled); Click(button);
        Assert.Equal(renamed, snapshots);
        var mounted = WindowsSurfaceFixture.Status(true);
        form.ApplyStatus(mounted with { MountedVolumes = [mounted.MountedVolumes![0] with {
            VolumeVerificationSupported = true, VolumeVerificationScope = new("image:held-test", "retained-image",
                WindowsSurfaceFixture.Hex, WindowsSurfaceFixture.VolumeHex, "101", "90", "0", "100000") }] });
        tree.SelectedNode = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes)
            .Single(n => n.Tag is TopologyDashboardNode { Row: not null });
        var verify = Controls(form).OfType<Button>().Single(b => b.Text == "Verify volume");
        Assert.True(verify.Enabled); Click(verify); Assert.Equal(renamed, verified); Assert.False(form.Visible);
    });
    private static StatusChangedPayload Mounted() => new(RuntimeState.MountedRo, ["R:\\"], null,
        DateTime.UtcNow, [], false, [], MountedVolumes: [new("device|volume", "R:\\", "Volume", "device", "Disk", MountAccessMode.ReadOnly)]);
    private static void SelectVolume(DashboardForm form, StatusChangedPayload status)
    {
        form.ApplyStatus(status);
        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        tree.SelectedNode = tree.Nodes.Cast<TreeNode>().SelectMany(n => n.Nodes.Cast<TreeNode>())
            .Single(n => n.Tag is TopologyDashboardNode { Row: not null });
    }
    private static void Click(Button button) => typeof(Button).GetMethod("OnClick", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(button, [EventArgs.Empty]);
    private static IEnumerable<Control> Controls(Control root)
    {
        foreach (Control c in root.Controls) { yield return c; foreach (var child in Controls(c)) yield return child; }
    }
    private static void Sta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception e) { error = e; } });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)));
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
    }
}
