using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class TopologyDashboardTests
{
    private static StatusChangedPayload Status => new(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, []);
    private static ApfsTopologySnapshot Topology(bool multi = false)
    {
        var container = ApfsTopology.BuildContainerId(new string('a', 32));
        var part = ApfsTopology.BuildPartitionId(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var store = ApfsTopology.BuildStoreId(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var part2 = ApfsTopology.BuildPartitionId(Guid.Parse("22222222-2222-2222-2222-222222222222"));
        var store2 = ApfsTopology.BuildStoreId(Guid.Parse("22222222-2222-2222-2222-222222222222"));
        ApfsVolumeRecord Volume(ulong oid, string role) => new(ApfsTopology.BuildVolumeId(new string('a', 32), oid),
            $"uuid-{oid}", oid.ToString(), container, "Same name", true, [role], 0, null, "sensitive", "none", false, [], [], [], "1", "1");
        return new([new("apfs-disk:d1", "device1", null, 10000), new("apfs-disk:d2", "device2", null, 10000)],
            [new(part, "p1", "apfs-disk:d1", 1, 0, 5000, "apfs", "APFS"), new(part2, "p2", "apfs-disk:d2", 1, 0, 5000, "apfs", "APFS")],
            multi ? [new(store, "s1", part, container, 0, 5000), new(store2, "s2", part2, container, 0, 5000)] : [new(store, "s1", part, container, 0, 5000)],
            [new(container, "container-uuid", 4096, multi ? [store, store2] : [store], Enumerable.Range(10, 5).Select(i => ApfsTopology.BuildVolumeId(new string('a', 32), (ulong)i)).ToArray(), multi, "1", [], [], [])],
            [Volume(10, "data"), Volume(11, "system"), Volume(12, "preboot"), Volume(13, "recovery"), Volume(14, "vm")], []);
    }

    [Fact]
    public void HierarchyUsesExplicitEdgesAndKeepsSameNamesAndSpecialVolumes()
    {
        var t = Topology();
        var nodes = TopologyDashboard.Project(Status, t);
        Assert.Equal(t.Stores[0].Id, nodes.Single(n => n.Id == t.Containers[0].Id).ParentId);
        Assert.Equal(t.Partitions[0].Id, nodes.Single(n => n.Id == t.Stores[0].Id).ParentId);
        foreach (var v in t.Volumes)
        {
            var n = nodes.Single(n => n.Id == v.Id);
            Assert.Equal(v.ContainerId, n.ParentId);
            Assert.DoesNotContain(v.Uuid, n.Text);
            Assert.Contains(v.Uuid, n.Details);
            Assert.Null(n.Row);
            Assert.Equal(DashboardPalette.Gray, n.Palette);
        }
    }

    [Fact]
    public void MultiStoreHasOneCanonicalContainerAndReferencesFromBothDisks()
    {
        var t = Topology(true);
        var nodes = TopologyDashboard.Project(Status, t);
        var canonical = Assert.Single(nodes, n => n.Id == t.Containers[0].Id);
        Assert.Null(canonical.ParentId);
        var references = nodes.Where(n => n.ReferenceId == canonical.Id).ToArray();
        Assert.Equal(2, references.Length);
        Assert.Equal(t.Stores.Select(s => s.Id).Order(), references.Select(n => n.ParentId).Order());
        Assert.All(references, n => Assert.Equal(canonical.Palette, n.Palette));
        Assert.Equal(5, nodes.Count(n => n.ParentId == canonical.Id));
    }

    [Fact]
    public void MissingMemberIsRedAndRawStoreOwnershipIsNotGuessed()
    {
        var t = Topology(true);
        t = t with { Stores = [t.Stores[0] with { PartitionId = "" }] };
        var nodes = TopologyDashboard.Project(Status, t);
        Assert.Equal(DashboardPalette.Red, nodes.Single(n => n.Id == t.Containers[0].Id).Palette);
        Assert.Null(nodes.Single(n => n.Id == t.Stores[0].Id).ParentId);
    }

    [Theory]
    [InlineData(DashboardPalette.Red, DashboardPalette.Orange, DashboardPalette.Red)]
    [InlineData(DashboardPalette.Orange, DashboardPalette.Yellow, DashboardPalette.Orange)]
    [InlineData(DashboardPalette.Yellow, DashboardPalette.Blue, DashboardPalette.Yellow)]
    [InlineData(DashboardPalette.Green, DashboardPalette.Gray, DashboardPalette.Yellow)]
    [InlineData(DashboardPalette.Blue, DashboardPalette.Blue, DashboardPalette.Blue)]
    [InlineData(DashboardPalette.Green, DashboardPalette.Green, DashboardPalette.Green)]
    public void HealthOrderAndMixedTruth(DashboardPalette a, DashboardPalette b, DashboardPalette expected)
        => Assert.Equal(expected, TopologyDashboard.Aggregate([(a, true), (b, true)]));

    [Fact]
    public void UnknownEligibilityNeverPromisesHealthyData()
    {
        Assert.Equal(DashboardPalette.Gray, TopologyDashboard.Aggregate([(DashboardPalette.Green, false)]));
        Assert.Contains(TopologyDashboard.Project(Status), n => n.Details == TopologyDashboard.Unavailable);
    }

    [Fact]
    public void CatalogIdentityJoinsExactVolumeAndMixedParentDoesNotOverwriteChildren()
    {
        var t = Topology();
        var status = Status with { MountedVolumes = [
            new("device1|one", "R:\\", "Same name", "device1", "Disk", MountAccessMode.ReadWrite,
                CatalogVolumeId: t.Volumes[0].Id),
            new("device1|two", "S:\\", "Same name", "device1", "Disk", MountAccessMode.ReadOnly,
                CatalogVolumeId: t.Volumes[1].Id)] };
        var rows = DriveDashboardPresenter.BuildRows(status);
        var nodes = TopologyDashboard.Project(status, t);
        Assert.Equal("device1|one", nodes.Single(n => n.Id == t.Volumes[0].Id).Row!.VolumeId);
        Assert.Equal("device1|two", nodes.Single(n => n.Id == t.Volumes[1].Id).Row!.VolumeId);
        Assert.Equal(rows.Single(r => r.VolumeId == "device1|one").Palette, nodes.Single(n => n.Id == t.Volumes[0].Id).Palette);
        Assert.Equal(DashboardPalette.Yellow, nodes.Single(n => n.Id == t.Containers[0].Id).Palette);
        var noExactMatch = status with { MountedVolumes = [status.MountedVolumes![0] with { CatalogVolumeId = "stale-id" }] };
        Assert.Null(TopologyDashboard.Project(noExactMatch, t).Single(n => n.Id == t.Volumes[0].Id).Row);
    }

    [Fact]
    public void SelectedVolumeOpenUsesCurrentCallbackAfterRefreshWithoutShowingWindow()
        => Sta(() =>
        {
            string? opened = null;
            using var form = new DashboardForm(path => { opened = path; return Task.CompletedTask; },
                _ => Task.CompletedTask, _ => Task.CompletedTask);
            var t = Topology();
            var status = Status with { MountedVolumes = [new("device1|one", "R:\\", "Same name", "device1", "Disk",
                MountAccessMode.ReadOnly, CatalogVolumeId: t.Volumes[0].Id)] };
            form.ApplyTopologyStatus(status, t);
            var tree = Descendants(form).OfType<TreeView>().Single();
            _ = tree.Handle;
            tree.SelectedNode = tree.Nodes.Find(t.Volumes[0].Id, true).Single();
            var button = Descendants(form).OfType<Button>().Single(b => b.Text == "Open");
            form.ApplyTopologyStatus(status with { MountedVolumes = [status.MountedVolumes![0] with { MountPoint = "S:\\" }] }, t);
            Assert.Same(button, Descendants(form).OfType<Button>().Single(b => b.Text == "Open"));
            Assert.True(button.Enabled);
            typeof(Button).GetMethod("OnClick", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                .Invoke(button, [EventArgs.Empty]);
            Assert.Equal("S:\\", opened);
            Assert.False(form.Visible);
        });

    [Fact]
    public void IncrementalRefreshRetainsNodeSelectionExpansionAndTopDuringReorderAndDeletion()
        => Sta(() =>
        {
            using var tree = new TreeView();
            tree.CreateControl();
            var models = TopologyDashboard.Project(Status, Topology());
            TopologyTreeRefresh.Apply(tree, models);
            var parent = tree.Nodes[0];
            parent.Expand();
            var selected = parent.Nodes[0];
            tree.SelectedNode = selected;
            var top = tree.TopNode;
            TopologyTreeRefresh.Apply(tree, models.Reverse().Select(n => n with { Text = n.Text + " changed" }).ToArray());
            Assert.Same(parent, tree.Nodes[0]);
            Assert.Same(selected, tree.SelectedNode);
            Assert.True(parent.IsExpanded);
            Assert.Same(top, tree.TopNode);
            TopologyTreeRefresh.Apply(tree, models.Where(n => n.Id != "apfs-disk:d2").ToArray());
            Assert.Empty(tree.Nodes.Find("apfs-disk:d2", true));
            Assert.Same(selected, tree.SelectedNode);
        });

    [Theory]
    [InlineData(460)]
    [InlineData(1100)]
    [InlineData(2000)]
    public void OffscreenLayoutStacksAndKeepsDetailsWithinClient(int width)
        => Sta(() =>
        {
            using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
            form.Size = new Size(width, 800);
            form.ApplyTopologyStatus(Status, Topology(true));
            form.PerformLayout();
            var tree = Descendants(form).OfType<TreeView>().Single();
            var layout = (TableLayoutPanel)tree.Parent!;
            layout.PerformLayout();
            var details = layout.Controls.Cast<Control>().Single(c => c != tree);
            Assert.False(form.Visible);
            Assert.True(tree.Width > 0);
            Assert.True(details.Width > 0);
            Assert.True(details.Right <= layout.ClientSize.Width);
            Assert.Equal(width < 900 ? 1 : 0, layout.GetRow(details));
            Assert.Equal("APFS topology", tree.AccessibleName);
            Assert.False(tree.HideSelection);
        });

    [Fact]
    public void ContainerAndVolumeNodesDisplayFormattedSizesWhenAvailable()
    {
        var t = Topology();
        var sharedSpace = new ApfsSharedSpaceProjection(
            ContainerId: t.Containers[0].Id,
            CheckpointXid: 100,
            AllocationUnitBytes: 4096,
            Total: new ApfsSpaceAmount(100000, 409600000),
            Free: new ApfsSpaceAmount(80000, 327680000),
            Used: new ApfsSpaceAmount(20000, 81920000),
            Volumes: [
                new ApfsVolumeSpaceProjection(
                    VolumeId: t.Volumes[0].Id,
                    ObjectId: 10,
                    Allocated: new ApfsSpaceAmount(5000, 20480000),
                    Reserve: null,
                    Quota: null,
                    SiblingReserveRemaining: new ApfsSpaceAmount(0, 0),
                    Available: new ApfsSpaceAmount(80000, 327680000),
                    Snapshot: null,
                    Purgeable: null)
            ]);

        var updatedContainers = new[] { t.Containers[0] with { SharedSpace = sharedSpace } };
        var updatedTopology = t with { Containers = updatedContainers };

        var nodes = TopologyDashboard.Project(Status, updatedTopology);
        var containerNode = nodes.Single(n => n.Id == t.Containers[0].Id);
        var volumeNode = nodes.Single(n => n.Id == t.Volumes[0].Id);

        Assert.Contains(DriveDashboardPresenter.FormatSpaceBytes(409600000), containerNode.Text);
        Assert.Contains(DriveDashboardPresenter.FormatSpaceBytes(20480000), volumeNode.Text);
    }

    private static IEnumerable<Control> Descendants(Control root)
    {
        foreach (Control c in root.Controls) { yield return c; foreach (var child in Descendants(c)) yield return child; }
    }
    private static void Sta(Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception e) { error = e; } });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "Offscreen layout timed out.");
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
    }
}
