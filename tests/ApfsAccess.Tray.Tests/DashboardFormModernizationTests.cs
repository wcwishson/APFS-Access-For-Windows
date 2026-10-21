using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;
using Xunit;

namespace ApfsAccess.Tray.Tests;

public sealed class DashboardFormModernizationTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [Theory]
    [InlineData(1900, 1000)]
    [InlineData(1100, 700)]
    public void DashboardForm_ScaledRoundTripKeepsContentInsideViewport(int finalWidth, int finalHeight) => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        _ = form.Handle;
        form.ApplyStatus(ContainerMounted());
        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        tree.SelectedNode = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes)
            .First(n => n.Tag is TopologyDashboardNode { Row: not null });
        var root = form.Controls.OfType<TableLayoutPanel>().Single();
        var topology = (TableLayoutPanel)tree.Parent!;
        var content = Controls(form).OfType<SplitContainer>().Single();
        Assert.Same(root, topology.Parent);
        var samples = new List<(string Stage, Rectangle Viewport, Rectangle Bounds)>();

        void LayoutAt(string stage, Size size)
        {
            form.ClientSize = size;
            // Run the real nested layout engines, including preferred-size caches.
            // Control.Scale exercises scaling without synthesizing OS DPI messages.
            for (var pass = 0; pass < 3; pass++) LayoutDescendants(form);
            Assert.Equal(size, form.ClientSize);
            Assert.Equal(form.ClientRectangle, root.Bounds);
            Assert.True(topology.Width > 0 && content.Width > 0);
            foreach (Control child in root.Controls)
            {
                var viewport = Rectangle.FromLTRB(root.Padding.Left, root.Padding.Top,
                    root.ClientSize.Width - root.Padding.Right, root.ClientSize.Height - root.Padding.Bottom);
                samples.Add(($"{stage}: root child {child.GetType().Name}", viewport, child.Bounds));
            }
            foreach (var child in new Control[] { tree, content })
                samples.Add(($"{stage}: {child.GetType().Name}", child.Parent!.ClientRectangle, child.Bounds));
            output.WriteLine($"{stage}: root={root.ClientSize}, topology={topology.Bounds}, " +
                $"columnWidths={string.Join(',', root.GetColumnWidths())}, content={content.Bounds}");
            Assert.False(form.Visible);
        }

        LayoutAt("initial 1x", new Size(1900, 1000));
        form.Scale(new SizeF(2F, 2F));
        LayoutAt("scaled 2x wide", new Size(3814, 2000));
        form.Scale(new SizeF(.5F, .5F));
        LayoutAt("scaled back to 1x", new Size(1900, 1000));
        form.Scale(new SizeF(2F, 2F));
        LayoutAt("return to 2x wide", new Size(3814, 2000));
        form.Scale(new SizeF(.5F, .5F));
        LayoutAt("final 1x viewport", new Size(finalWidth, finalHeight));

        // Check actual geometry after the whole sequence so a failure reports both
        // slight padding overflow and retained child widths after a large shrink.
        Assert.All(samples, sample => Assert.True(sample.Viewport.Contains(sample.Bounds),
            $"{sample.Stage}: child {sample.Bounds} exceeds viewport {sample.Viewport}."));
    });

    private static void LayoutDescendants(Control parent)
    {
        parent.PerformLayout();
        foreach (Control child in parent.Controls) LayoutDescendants(child);
    }

    [Fact]
    public void ApfsStorageBarControl_SetStorage_UpdatesPropertiesAndPaintsCleanly()
    {
        using var control = new ApfsStorageBarControl();
        Assert.Equal(0, control.TotalBytes);
        Assert.Equal(0, control.FreeBytes);
        Assert.Empty(control.Segments);

        var segments = new[]
        {
            new ApfsStorageBarControl.Segment("Alpha", 10_000_000_000L, Color.SkyBlue),
            new ApfsStorageBarControl.Segment("Beta", 20_000_000_000L, Color.Purple)
        };

        control.SetStorage(100_000_000_000L, 70_000_000_000L, segments, "Test APFS Container");
        Assert.Equal(100_000_000_000L, control.TotalBytes);
        Assert.Equal(70_000_000_000L, control.FreeBytes);
        Assert.Equal(2, control.Segments.Count);
        Assert.Equal("Test APFS Container", control.Title);

        // Verify paint rendering does not throw
        control.Size = new Size(500, 70);
        using var bmp = new Bitmap(500, 70);
        control.DrawToBitmap(bmp, new Rectangle(0, 0, 500, 70));
    }

    [Fact]
    public void DashboardForm_ContainsModernControls() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        var controls = Controls(form).ToList();

        // 1. Storage Bar
        var storageBars = controls.OfType<ApfsStorageBarControl>().ToList();
        Assert.Single(storageBars);

        // 2. Activity Bar (ProgressBar)
        var progressBars = controls.OfType<ProgressBar>().ToList();
        Assert.Single(progressBars);
        var activityBar = progressBars[0];
        Assert.False(activityBar.Visible);

        // Verify SetActionsEnabled toggles the activity bar
        form.SetActionsEnabled(false);
        var isLocallyVisible = (bool)typeof(Control).GetMethod("GetState", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(activityBar, [2])!;
        Assert.True(isLocallyVisible);
        Assert.Equal(ProgressBarStyle.Marquee, activityBar.Style);
        Assert.True(activityBar.MarqueeAnimationSpeed > 0);

        form.SetActionsEnabled(true);
        isLocallyVisible = (bool)typeof(Control).GetMethod("GetState", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(activityBar, [2])!;
        Assert.False(isLocallyVisible);
        Assert.Equal(ProgressBarStyle.Blocks, activityBar.Style);
        Assert.Equal(0, activityBar.MarqueeAnimationSpeed);

        // 3. Quick Copy Buttons in Inspector
        var copyDetails = controls.OfType<Button>().Single(b => b.Text == "Copy info");
        var copyJson = controls.OfType<Button>().Single(b => b.Text == "Copy JSON");
        Assert.NotNull(copyDetails);
        Assert.NotNull(copyJson);

        // Verify clicking copy buttons does not throw
        Click(copyDetails);
        Click(copyJson);
    });

    [Fact]
    public void DashboardForm_ContextMenu_PopulatesForNodes() => Sta(() =>
    {
        using var form = new DashboardForm(
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            mountContainerAsync: (d, c) => Task.CompletedTask,
            unmountContainerAsync: (d, c) => Task.CompletedTask,
            ejectDeviceAsync: d => Task.CompletedTask,
            fixContainerAsync: _ => Task.CompletedTask);

        var tree = Controls(form).OfType<TreeView>().Single();
        Assert.NotNull(tree.ContextMenuStrip);

        var status = ContainerMounted();
        form.ApplyStatus(status);

        // Select volume node
        _ = tree.Handle;
        var volNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .First(n => (n.Tag as TopologyDashboardNode)?.Row is not null);
        tree.SelectedNode = volNode;

        // Populate context menu
        var method = typeof(DashboardForm).GetMethod("PopulateContextMenu", BindingFlags.NonPublic | BindingFlags.Instance)!;
        method.Invoke(form, null);

        var menu = tree.ContextMenuStrip;
        Assert.NotNull(menu);
        Assert.NotEmpty(menu.Items);
        var menuTexts = menu.Items.OfType<ToolStripMenuItem>().Select(i => i.Text ?? string.Empty).ToList();
        Assert.Contains(menuTexts, t => t.StartsWith("Open ", StringComparison.Ordinal));
        Assert.Contains(menuTexts, t => t.StartsWith("Eject ", StringComparison.Ordinal));
        Assert.Contains(menuTexts, t => t.Contains("Volume UUID", StringComparison.Ordinal));
    });

    [Fact]
    public void DashboardForm_MemberPanel_AdjustsHeightDynamicallyWithoutClipping() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        _ = form.Handle;
        form.ApplyStatus(ContainerMounted());

        var tree = Controls(form).OfType<TreeView>().Single();
        _ = tree.Handle;
        var volNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .First(n => (n.Tag as TopologyDashboardNode)?.Row is not null);
        tree.SelectedNode = volNode;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        var detailsTopPanel = (Panel)typeof(DashboardForm).GetField("_detailsTopPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var memberPanel = (FlowLayoutPanel)typeof(DashboardForm).GetField("_memberPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var storageBar = (ApfsStorageBarControl)typeof(DashboardForm).GetField("_storageBar", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        Assert.NotNull(detailsTopPanel);
        Assert.NotNull(memberPanel);
        Assert.NotNull(storageBar);

        form.PerformLayout();
        var pref = memberPanel.GetPreferredSize(new Size(Math.Max(100, memberPanel.ClientSize.Width), 0));
        var expectedFlowHeight = Math.Max(28, pref.Height);
        Assert.True(detailsTopPanel.Height >= expectedFlowHeight);
        Assert.True(detailsTopPanel.Height > 0);
    });

    [Fact]
    public void DashboardForm_ContentSplit_AdjustsDistanceToFitPartitionCardWithoutScrollbar() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        form.ClientSize = new Size(800, 600);
        form.PerformLayout();
        form.ApplyStatus(ContainerMounted());

        var tree = (TreeView)typeof(DashboardForm).GetField("_topologyTree", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var volumeNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .FirstOrDefault(n => n.Tag is TopologyDashboardNode tdn && tdn.Row is not null);
        Assert.NotNull(volumeNode);

        tree.SelectedNode = volumeNode;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        var contentSplit = (SplitContainer)typeof(DashboardForm).GetField("_contentSplit", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var rowsPanel = (FlowLayoutPanel)typeof(DashboardForm).GetField("_rowsPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        Assert.False(contentSplit.Panel1Collapsed);
        Assert.Single(rowsPanel.Controls);
        var card = rowsPanel.Controls[0];
        Assert.True(card.Height > 0);
        Assert.True(contentSplit.SplitterDistance >= card.Height + card.Margin.Vertical);
        Assert.False(rowsPanel.VerticalScroll.Visible);
    });

    [Fact]
    public void DashboardForm_ContainerNode_HasNoRedundantDetailsButton() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        form.ClientSize = new Size(800, 600);
        form.ApplyStatus(ContainerMounted());

        var tree = (TreeView)typeof(DashboardForm).GetField("_topologyTree", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var memberPanel = (FlowLayoutPanel)typeof(DashboardForm).GetField("_memberPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var nodeDetails = (Label)typeof(DashboardForm).GetField("_nodeDetails", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        // Verify there is no button with text "Topology details" in memberPanel
        var buttons = memberPanel.Controls.OfType<Button>().ToList();
        Assert.DoesNotContain(buttons, b => b.Text == "Topology details");

        // Select container node
        var containerNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .FirstOrDefault(n => n.Tag is TopologyDashboardNode tdn && tdn.Id.StartsWith("apfs-container:", StringComparison.Ordinal));
        if (containerNode is not null)
        {
            tree.SelectedNode = containerNode;
            typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

            // Verify container details are displayed in inspector label
            Assert.Contains("apfs-container:", nodeDetails.Text, StringComparison.OrdinalIgnoreCase);
        }
    });

    [Fact]
    public void DashboardForm_MemberHealthButton_TogglesDetailsAndHealth() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        form.ClientSize = new Size(800, 600);
        form.ApplyStatus(ContainerMounted());

        var tree = (TreeView)typeof(DashboardForm).GetField("_topologyTree", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var memberHealthBtn = (Button)typeof(DashboardForm).GetField("_memberHealthButton", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var nodeDetails = (Label)typeof(DashboardForm).GetField("_nodeDetails", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        var partNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .FirstOrDefault(n => n.Tag is TopologyDashboardNode tdn && tdn.Id.StartsWith("apfs-part:", StringComparison.Ordinal));
        if (partNode is not null)
        {
            tree.SelectedNode = partNode;
            typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

            Assert.Equal("Member health", memberHealthBtn.Text);
            var originalDetails = nodeDetails.Text;

            // Click health button -> toggles to health and button becomes "Node details"
            Click(memberHealthBtn);
            Assert.Equal("Node details", memberHealthBtn.Text);
            Assert.NotEqual(originalDetails, nodeDetails.Text);

            // Click health button again -> toggles back to node details and button becomes "Member health"
            Click(memberHealthBtn);
            Assert.Equal("Member health", memberHealthBtn.Text);
            Assert.Equal(originalDetails, nodeDetails.Text);
        }
    });

    [Fact]
    public void DashboardForm_VolumeCard_HasNoRedundantDetailsButton() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        form.ClientSize = new Size(800, 600);
        form.ApplyStatus(ContainerMounted());

        var tree = (TreeView)typeof(DashboardForm).GetField("_topologyTree", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var rowsPanel = (FlowLayoutPanel)typeof(DashboardForm).GetField("_rowsPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        var volNode = tree.Nodes.Cast<TreeNode>()
            .SelectMany(EnumerateTreeNodes)
            .FirstOrDefault(n => (n.Tag as TopologyDashboardNode)?.Row is not null);
        Assert.NotNull(volNode);

        tree.SelectedNode = volNode;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        Assert.Single(rowsPanel.Controls);
        var card = rowsPanel.Controls[0];
        var buttons = Controls(card).OfType<Button>().Select(b => b.Text).ToList();

        // Verify "Details" is NOT present on the volume card
        Assert.DoesNotContain("Details", buttons);
        Assert.Contains("Open", buttons);
        Assert.Contains("Eject", buttons);
        Assert.Contains(buttons, b => b.StartsWith("Drive letter", StringComparison.Ordinal));
    });

    [Fact]
    public void DashboardForm_GetOccupiedDriveLetters_ExcludesSystemDrivesAndKeepsCurrentMount()
    {
        var mockDrives = new[] { @"C:\", @"D:\", @"E:\" };

        // Test with volume mounted on E:
        var rowMountedE = new DriveDashboardRow(
            VolumeId: "vol1",
            DeviceName: "Disk 2",
            VolumeName: "Alpha",
            MountPoint: "E:",
            MountPath: @"E:\",
            State: DriveDashboardState.HealthyReadWrite,
            Palette: DashboardPalette.Green,
            StateText: "Mounted",
            Summary: "Normal",
            CanOpen: true,
            CanEject: true,
            CanFix: false,
            Details: [],
            FixGuidance: []);

        var occupiedE = DashboardForm.GetOccupiedDriveLetters(rowMountedE, () => mockDrives);
        Assert.Contains('C', occupiedE);
        Assert.Contains('D', occupiedE);
        Assert.DoesNotContain('E', occupiedE);

        // Filter candidate letters
        const string candidates = "DEFGHIJKLMNOPQRSTUVWXYZ";
        var availableForE = candidates.Where(c => !occupiedE.Contains(c)).ToList();
        Assert.DoesNotContain('D', availableForE);
        Assert.Contains('E', availableForE);
        Assert.Contains('F', availableForE);

        // Test with unmounted volume (MountPoint is empty)
        var rowUnmounted = rowMountedE with { MountPoint = string.Empty, MountPath = string.Empty };
        var occupiedUnmounted = DashboardForm.GetOccupiedDriveLetters(rowUnmounted, () => mockDrives);
        Assert.Contains('C', occupiedUnmounted);
        Assert.Contains('D', occupiedUnmounted);
        Assert.Contains('E', occupiedUnmounted);

        var availableForUnmounted = candidates.Where(c => !occupiedUnmounted.Contains(c)).ToList();
        Assert.DoesNotContain('C', availableForUnmounted);
        Assert.DoesNotContain('D', availableForUnmounted);
        Assert.DoesNotContain('E', availableForUnmounted);
        Assert.Contains('F', availableForUnmounted);
    }

    [Fact]
    public void DashboardForm_SelectingDifferentTreeNodesUpdatesStorageBarContext() => Sta(() =>
    {
        using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
        form.ClientSize = new Size(900, 700);

        var diskId = "apfs-disk:PhysicalDrive2";
        var part1Id = "apfs-part:part1";
        var part2Id = "apfs-part:part2";
        var storeId = "apfs-store:store1";
        var containerId = "apfs-container:cont1";
        var vol1Id = "apfs-vol:cont1:101";
        var vol2Id = "apfs-vol:cont1:102";

        var sharedSpace = new ApfsSharedSpaceProjection(
            ContainerId: containerId,
            CheckpointXid: 50,
            AllocationUnitBytes: 4096,
            Total: new ApfsSpaceAmount(25000, 102400000), // 100 MB
            Free: new ApfsSpaceAmount(15000, 61440000),
            Used: new ApfsSpaceAmount(10000, 40960000),
            Volumes: [
                new ApfsVolumeSpaceProjection(vol1Id, 101, new ApfsSpaceAmount(6000, 24576000), null, null, new ApfsSpaceAmount(0, 0), new ApfsSpaceAmount(15000, 61440000), null, null),
                new ApfsVolumeSpaceProjection(vol2Id, 102, new ApfsSpaceAmount(4000, 16384000), null, null, new ApfsSpaceAmount(0, 0), new ApfsSpaceAmount(15000, 61440000), null, null)
            ]);

        var topology = new ApfsTopologySnapshot(
            Disks: [new(diskId, @"\\.\PhysicalDrive2", "uuid-disk", 100_000_000_000L)],
            Partitions: [
                new(part1Id, "uuid-p1", diskId, 1, 20480, 200_000_000L, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "efi"),
                new(part2Id, "uuid-p2", diskId, 2, 200020480, 99_800_000_000L, "7c3457ef-0000-11aa-aa11-00306543ecac", "apfs")
            ],
            Stores: [new(storeId, "uuid-store", part2Id, containerId, 200020480, 99_800_000_000L)],
            Containers: [new(containerId, "uuid-cont", 4096, [storeId], [vol1Id, vol2Id], false, "50", [], [], [], SharedSpace: sharedSpace)],
            Volumes: [
                new(vol1Id, "uuid-v1", "101", containerId, "Alpha", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "10", "50"),
                new(vol2Id, "uuid-v2", "102", containerId, "Beta", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "11", "50")
            ],
            Groups: []);

        var status = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["E:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: [],
            WriteEnabled: true,
            CompatibilityWarnings: [],
            MountedVolumes: [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Alpha",
                    MountPoint: "E:\\",
                    VolumeName: "Alpha",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS Disk",
                    AccessMode: MountAccessMode.ReadWrite,
                    CatalogVolumeId: vol1Id)
            ]);

        form.ApplyTopologyStatus(status, topology);

        var tree = (TreeView)typeof(DashboardForm).GetField("_topologyTree", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var storageBar = (ApfsStorageBarControl)typeof(DashboardForm).GetField("_storageBar", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var allNodes = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes).ToList();

        bool IsActive() => (bool)typeof(DashboardForm).GetField("_storageBarActive", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        // 1. Select Disk Node
        var diskNode = allNodes.Single(n => n.Name == diskId);
        tree.SelectedNode = diskNode;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);
        Assert.True(IsActive());
        Assert.Contains("Disk", storageBar.Title);
        Assert.Contains("Physical Layout", storageBar.Title);
        Assert.Equal(2, storageBar.Segments.Count);

        // 2. Select Container Node
        var contNode = allNodes.Single(n => n.Name == containerId);
        tree.SelectedNode = contNode;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);
        Assert.True(IsActive());
        Assert.Contains("Container Storage Pool", storageBar.Title);
        Assert.Equal(2, storageBar.Segments.Count);

        // 3. Select Volume Alpha Node
        var vol1Node = allNodes.Single(n => n.Name == vol1Id);
        tree.SelectedNode = vol1Node;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);
        Assert.True(IsActive());
        Assert.Contains("Volume \"Alpha\"", storageBar.Title);
        Assert.Contains("Alpha (Selected)", storageBar.Segments[0].Name);

        var detailsTopPanel = (Panel)typeof(DashboardForm).GetField("_detailsTopPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var memberPanel = (FlowLayoutPanel)typeof(DashboardForm).GetField("_memberPanel", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;
        var contentSplit = (SplitContainer)typeof(DashboardForm).GetField("_contentSplit", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(form)!;

        // 1. Select Store (Row is null)
        var storeNode = allNodes.Single(n => n.Name == storeId);
        tree.SelectedNode = storeNode;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        // 2. Select Volume Alpha (Row is not null)
        tree.SelectedNode = vol1Node;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        // 3. Select Container (Row is null)
        var contNode2 = allNodes.Single(n => n.Name == containerId);
        tree.SelectedNode = contNode2;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        // 4. Select Volume Alpha back (Row is not null)
        tree.SelectedNode = vol1Node;
        typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);

        bool IsLocallyVisible(Control c) => (bool)typeof(Control).GetMethod("GetState", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(c, [2])!;
        var visibleButtons = memberPanel.Controls.Cast<Control>().Where(IsLocallyVisible).ToList();
        Assert.NotEmpty(visibleButtons);
        Assert.True(memberPanel.Height >= 28, $"memberPanel.Height was {memberPanel.Height}");
        Assert.True(detailsTopPanel.Height >= storageBar.Height + memberPanel.Height, $"detailsTopPanel.Height was {detailsTopPanel.Height}, expected at least {storageBar.Height + memberPanel.Height}");
        foreach (var btn in visibleButtons)
        {
            Assert.True(btn.Width > 0 && btn.Height > 0, $"Button '{btn.Text}' had zero bounds: {btn.Bounds}");
        }

        // 4. Verify User-adjusted content split distance is preserved on ResizeRows
        typeof(DashboardForm).GetField("_userAdjustedContentSplit", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(form, true);
        contentSplit.SplitterDistance = 180;
        typeof(DashboardForm).GetMethod("ResizeRows", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);
        Assert.Equal(180, contentSplit.SplitterDistance);
    });

    private static StatusChangedPayload ContainerMounted()
    {
        var mounted = new[]
        {
            new MountedVolumeDisplay(
                VolumeId: @"\\.\PhysicalDrive2|Alpha",
                MountPoint: "E:\\",
                VolumeName: "Alpha",
                DeviceId: @"\\.\PhysicalDrive2",
                DeviceDisplayName: "APFS USB Device",
                AccessMode: MountAccessMode.ReadWrite,
                RecoveryIdentity: "apfs-recovery-v1|alpha",
                CatalogVolumeId: @"\\.\PhysicalDrive2|Alpha",
                CatalogContainerUuid: new string('a', 32),
                CatalogVolumeObjectId: 101,
                CatalogVolumeUuid: new string('b', 32)),
        };
        return new StatusChangedPayload(RuntimeState.MountedRw, ["E:\\"], null,
            DateTime.UtcNow, [], true, [], MountedVolumes: mounted, ConnectedInventory:
            [
                new DeviceInventory(new DeviceInfo(@"\\.\PhysicalDrive2", "APFS USB Device", true),
                [
                    new VolumeInfo(
                        VolumeId: @"\\.\PhysicalDrive2|Alpha",
                        DeviceId: @"\\.\PhysicalDrive2",
                        VolumeName: "Alpha",
                        SupportsReadWrite: true,
                        RecoveryIdentity: "apfs-recovery-v1|alpha",
                        CatalogVolumeId: @"\\.\PhysicalDrive2|Alpha",
                        CatalogContainerUuid: new string('a', 32),
                        CatalogVolumeObjectId: 101,
                        CatalogDecision: ApfsCapabilityDecision.Writable,
                        CatalogReasons: [],
                        CatalogAutoMountAllowed: true,
                        CatalogVolumeUuid: new string('b', 32))
                ]),
            ]);
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

    private static IEnumerable<Control> Controls(Control root)
    {
        foreach (Control c in root.Controls)
        {
            yield return c;
            foreach (var child in Controls(c))
                yield return child;
        }
    }

    private static void Click(Button button) => typeof(Button).GetMethod("OnClick", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(button, [EventArgs.Empty]);

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
