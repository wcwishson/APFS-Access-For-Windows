using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public sealed record TopologyDashboardNode(string Id, string? ParentId, string Text,
    string Details, DashboardPalette Palette = DashboardPalette.Gray,
    DriveDashboardRow? Row = null, string? ReferenceId = null, bool EligibleData = false,
    IReadOnlyList<string>? MemberIds = null);

public static class TopologyDashboard
{
    public const string Unavailable = "Details unavailable";

    public static DashboardPalette Aggregate(IEnumerable<(DashboardPalette Palette, bool Eligible)> children)
    {
        var items = children.ToArray();
        foreach (var severity in new[] { DashboardPalette.Red, DashboardPalette.Orange, DashboardPalette.Yellow })
            if (items.Any(x => x.Palette == severity)) return severity;
        if (items.Select(x => x.Palette).Distinct().Count() > 1) return DashboardPalette.Yellow;
        if (items.Any(x => x.Palette == DashboardPalette.Blue)) return DashboardPalette.Blue;
        return items.Any(x => x.Eligible) && items.Where(x => x.Eligible).All(x => x.Palette == DashboardPalette.Green)
            ? DashboardPalette.Green : DashboardPalette.Gray;
    }

    public static IReadOnlyList<TopologyDashboardNode> Project(StatusChangedPayload status, ApfsTopologySnapshot? topology = null)
    {
        if (!TopologyStatusProjection.IsBounded(status)) return [new("invalid-status", null, "Details unavailable", Unavailable, DashboardPalette.Red)];
        if (topology is null && (status.InventoryGeneration is not null || status.ConnectedInventory?.Any(d => d.Topology is not null) == true))
            return TopologyStatusProjection.Project(status);
        var graph = TopologyGraphIndex.Create(topology);
        if (topology is not null && graph is null)
            return [new("invalid-topology", null, "Details unavailable", Unavailable, DashboardPalette.Red)];
        var rows = DriveDashboardPresenter.BuildRows(status).Where(r => r.VolumeId.Length > 0).ToArray();
        if (graph is not null)
        {
            var volumeIds = topology!.Volumes.Select(v => v.Id).ToHashSet(StringComparer.Ordinal);
            rows = rows.Select(r => !graph.Complete || r.CatalogVolumeId is null || !volumeIds.Contains(r.CatalogVolumeId)
                ? TopologyStatusProjection.DisableActions(r) : r).ToArray();
        }
        var rowsByCatalog = rows.Where(r => r.CatalogVolumeId is not null)
            .ToLookup(r => r.CatalogVolumeId!, StringComparer.Ordinal);
        var nodes = new List<TopologyDashboardNode>();
        var mapped = new HashSet<string>(StringComparer.Ordinal);
        if (topology is not null)
        {
            foreach (var d in topology.Disks)
                nodes.Add(new(d.Id, null, $"Disk · {d.DeviceIdentifier} · {DriveDashboardPresenter.FormatByteSize(d.SizeBytes)}", $"{d.Id}\nUUID: {d.Uuid}\nDevice: {d.DeviceIdentifier}\nCapacity: {DriveDashboardPresenter.FormatByteSize(d.SizeBytes)}"));
            foreach (var p in topology.Partitions)
                nodes.Add(new(p.Id, p.DiskId, $"GPT partition {p.Index} · {DriveDashboardPresenter.FormatByteSize(p.SizeBytes)}", $"{p.Id}\nUUID: {p.Uuid}\nCapacity: {DriveDashboardPresenter.FormatByteSize(p.SizeBytes)}\nType: {p.TypeGuid}\nUsage: {p.Usage}\nStart: {DriveDashboardPresenter.FormatByteSize(p.StartByte)}"));
            foreach (var s in topology.Stores)
                nodes.Add(new(s.Id, string.IsNullOrEmpty(s.PartitionId) ? s.DiskId : s.PartitionId,
                    $"Store · {DriveDashboardPresenter.FormatByteSize(s.SizeBytes)}", $"{s.Id}\nCapacity: {DriveDashboardPresenter.FormatByteSize(s.SizeBytes)}\nBlock size: {(s.BlockSizeBytes is {} blockSize ? DriveDashboardPresenter.FormatByteSize(blockSize) : "unknown")}\nPartition: {s.PartitionId}\nContainer: {s.ContainerId}\nOffset: {DriveDashboardPresenter.FormatByteSize(s.OffsetBytes)}\n" +
                    (string.IsNullOrEmpty(s.PartitionId) ? s.DiskId is null ? "Parent: unknown" : "Disk: " + s.DiskId : "")));
            foreach (var c in topology.Containers)
            {
                var members = c.StoreIds.Distinct(StringComparer.Ordinal).ToArray();
                var missing = members.Any(id => !graph!.Stores.TryGetValue(id, out var member) || member.ContainerId != c.Id);
                var containerCapacity = c.SharedSpace is { } sharedSpace && sharedSpace.Total.Bytes > 0
                    ? sharedSpace.Total.Bytes
                    : (ulong)c.StoreIds.Select(id => graph?.Stores.TryGetValue(id, out var s) == true ? s.SizeBytes : 0L).Sum();
                var containerSizeText = containerCapacity > 0 ? $" · {DriveDashboardPresenter.FormatSpaceBytes(containerCapacity)}" : "";
                var containerHeader = (c.Fusion ? "Shared APFS container · Fusion" : "APFS container") + containerSizeText;
                nodes.Add(new(c.Id, members.Length == 1 && !missing ? members[0] : null,
                    containerHeader,
                    $"{c.Id}\nUUID: {c.Uuid}\nMembers:\n{string.Join("\n", members)}\nCheckpoint: {c.CheckpointXid}\n" +
                    (c.SharedSpace is {} space ? $"Shared total: {DriveDashboardPresenter.FormatSpaceBytes(space.Total.Bytes)}; free: {DriveDashboardPresenter.FormatSpaceBytes(space.Free.Bytes)}\n" : "Shared space: unknown\n") +
                    (missing ? "Missing member" : ""), missing ? DashboardPalette.Red : DashboardPalette.Gray, MemberIds: members));
                if (members.Length > 1)
                    foreach (var id in members.Where(id => graph!.Stores.ContainsKey(id)))
                        nodes.Add(new("reference:" + id + ":" + c.Id, id, "Go to shared APFS container",
                            "Member reference to " + c.Id, ReferenceId: c.Id));
            }
            foreach (var g in topology.Groups)
                nodes.Add(new(g.Id, g.ContainerId, "Volume group · " + g.VolumeIds.Count + " volumes",
                    $"{g.Id}\nUUID: {g.Uuid}\nAssociation: {g.AssociationStatus}", MemberIds: g.VolumeIds));
            foreach (var v in topology.Volumes)
            {
                var matches = rowsByCatalog[v.Id].ToArray();
                var row = matches.Length == 1 ? matches[0] : null;
                if (row is not null && v.Locked) row = row with { CanFix = false, CanInspectReadOnly = false, CanMountBackupReadWrite = false };
                if (row is not null) mapped.Add(DriveDashboardPresenter.RowIdentity(row));
                var eligible = v.Roles.Count > 0 && v.Roles.All(r => r.Equals("data", StringComparison.Ordinal));
                var palette = row?.Palette ?? (v.Locked ? DashboardPalette.Yellow : DashboardPalette.Gray);

                var parentContainer = topology.Containers.FirstOrDefault(ct => ct.Id == v.ContainerId);
                var volSpace = parentContainer?.SharedSpace?.Volumes.FirstOrDefault(sp =>
                    string.Equals(sp.VolumeId, v.Id, StringComparison.Ordinal) ||
                    sp.ObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture) == v.ObjectId);
                var volSizeBytes = volSpace?.Allocated.Bytes;
                var sizeText = volSizeBytes.HasValue ? DriveDashboardPresenter.FormatSpaceBytes(volSizeBytes.Value) : null;

                var parts = new List<string> { v.Name };
                if (v.Roles.Count > 0) parts.Add(string.Join(", ", v.Roles));
                if (sizeText is not null) parts.Add(sizeText);
                if (!string.IsNullOrWhiteSpace(row?.MountPoint)) parts.Add(row.MountPoint);
                parts.Add(row?.StateText ?? (v.Locked ? "Locked" : "Not mounted"));
                var volHeader = string.Join(" · ", parts);

                nodes.Add(new(v.Id, v.GroupId ?? v.ContainerId, volHeader,
                    $"{v.Id}\nUUID: {v.Uuid}\nObject: {v.ObjectId}\nRoles: {string.Join(", ", v.Roles)}\nGroup: {v.GroupId}\nCase: {v.CaseMode}\nEncryption: {v.EncryptionMode}; locked: {v.Locked}\nUnsupported features: {string.Join(", ", v.IncompatibleFeatureBits.Concat(v.UnknownFeatureBits))}\n" +
                    string.Join("\n", row?.Details ?? []), palette, row, EligibleData: eligible && row?.IsMounted == true));
            }
        }
        else nodes.Add(new("topology-unavailable", null, "Details unavailable", Unavailable));

        foreach (var group in rows.Where(r => !mapped.Contains(DriveDashboardPresenter.RowIdentity(r))).GroupBy(r => r.DeviceId, StringComparer.Ordinal))
        {
            var key = "inventory-device:" + group.Key;
            nodes.Add(new(key, null, group.First().DeviceName, $"Device: {group.Key}\n{Unavailable}"));
            foreach (var r in group)
            {
                var parent=key;
                if(r.RegisteredImage is {} p)
                {
                    var store="registered-store:"+p.Contract; var container="registered-container:"+p.Contract;
                    nodes.Add(new(store,key,$"Image member · {DriveDashboardPresenter.FormatSpaceBytes(p.StoreSize)}",$"Source: {p.SourceId}\nOffset: {p.StoreOffset}\nSize: {DriveDashboardPresenter.FormatSpaceBytes(p.StoreSize)}"));
                    var regContainerHeader = p.StoreSize > 0 ? $"APFS container · {DriveDashboardPresenter.FormatSpaceBytes(p.StoreSize)}" : "APFS container";
                    nodes.Add(new(container,store,regContainerHeader,$"UUID: {p.ContainerUuid}\nCheckpoint: {p.CheckpointXid}"));
                    parent=container;
                }
                nodes.Add(new("inventory-volume:" + DriveDashboardPresenter.RowIdentity(r), parent,
                    $"{r.VolumeName} · {r.MountPoint} · {r.StateText}",
                    string.Join("\n", r.Details), r.StateText == "Locked" ? DashboardPalette.Yellow : r.Palette, r));
            }
        }
        // The validated, typed graph has at most five parent levels. Index once;
        // references share the canonical summary without cloning volume instances.
        var byId = nodes.ToDictionary(n => n.Id, StringComparer.Ordinal);
        for (var i = 0; i < nodes.Count; i++)
            if (nodes[i].ParentId is {} parent && !byId.ContainsKey(parent))
                nodes[i] = nodes[i] with { ParentId = null, Details = nodes[i].Details + "\nParent: unknown" };
        var children = nodes.Where(n => n.ParentId is not null).ToLookup(n => n.ParentId!, StringComparer.Ordinal);
        var summaries = new Dictionary<string, (DashboardPalette Palette, bool Eligible)>(StringComparer.Ordinal);
        (DashboardPalette Palette, bool Eligible) Summarize(TopologyDashboardNode node)
        {
            if (summaries.TryGetValue(node.Id, out var cached)) return cached;
            var result = (node.Palette, node.EligibleData);
            if (node.ReferenceId is {} target) result = Summarize(byId[target]);
            else
            {
                var values = children[node.Id].Select(Summarize).ToArray();
                if (values.Length > 0)
                    result = (node.Palette == DashboardPalette.Red ? DashboardPalette.Red : Aggregate(values), values.Any(v => v.Eligible));
            }
            summaries[node.Id] = result;
            return result;
        }
        return nodes.Select(n => n with { Palette = Summarize(n).Palette,
            Text = n.Text + (children.Contains(n.Id) ? $" · {children[n.Id].Count()} items" : "") }).ToArray();
    }
}

internal static class TopologyTreeRefresh
{
    private static string StateLabel(DashboardPalette palette) => palette switch
    {
        DashboardPalette.Red => "Problem", DashboardPalette.Orange => "Attention",
        DashboardPalette.Yellow => "Limited", DashboardPalette.Blue => "Working",
        DashboardPalette.Green => "Ready", _ => "Inactive"
    };

    internal static void Apply(TreeView tree, IReadOnlyList<TopologyDashboardNode> models)
    {
        var selected = tree.SelectedNode;
        var top = tree.IsHandleCreated ? tree.TopNode : null;
        var existing = new Dictionary<string, TreeNode>(StringComparer.Ordinal);
        void Collect(TreeNodeCollection nodes) { foreach (TreeNode n in nodes) { existing[n.Name] = n; Collect(n.Nodes); } }
        Collect(tree.Nodes);
        var desired = models.ToDictionary(n => n.Id, StringComparer.Ordinal);
        tree.BeginUpdate();
        try
        {
            foreach (var model in models)
                if (!existing.ContainsKey(model.Id)) existing[model.Id] = new TreeNode { Name = model.Id };
            foreach (var model in models)
            {
                var node = existing[model.Id];
                node.Tag = model;
                var text = $"{StateLabel(model.Palette)}: {model.Text}";
                if (node.Text != text) node.Text = text;
                var isDark = tree.BackColor.GetBrightness() < 0.5f;
                node.ForeColor = GetNodeColor(model.Palette, isDark);
                node.ToolTipText = string.Empty;
                var parent = model.ParentId is {} id && existing.TryGetValue(id, out var p) ? p : null;
                var collection = parent?.Nodes ?? tree.Nodes;
                if (node.TreeView != tree || node.Parent != parent) { node.Remove(); collection.Add(node); }
            }
            foreach (var pair in existing.Where(p => !desired.ContainsKey(p.Key))) pair.Value.Remove();
            if (selected?.TreeView == tree) tree.SelectedNode = selected;
            else if (tree.SelectedNode is null && tree.Nodes.Count > 0) tree.SelectedNode = tree.Nodes[0];
            if (top?.TreeView == tree && tree.IsHandleCreated) tree.TopNode = top;
        }
        finally { tree.EndUpdate(); }
    }

    internal static Color GetNodeColor(DashboardPalette palette, bool isDark)
    {
        if (SystemInformation.HighContrast) return SystemColors.WindowText;
        return isDark switch
        {
            true => palette switch
            {
                DashboardPalette.Red => Color.FromArgb(248, 113, 113),
                DashboardPalette.Orange => Color.FromArgb(251, 146, 60),
                DashboardPalette.Yellow => Color.FromArgb(250, 204, 21),
                DashboardPalette.Blue => Color.FromArgb(96, 165, 250),
                DashboardPalette.Green => Color.FromArgb(74, 222, 128),
                _ => Color.FromArgb(226, 232, 240)
            },
            false => palette switch
            {
                DashboardPalette.Red => Color.Firebrick,
                DashboardPalette.Orange => Color.SaddleBrown,
                DashboardPalette.Yellow => Color.DarkGoldenrod,
                DashboardPalette.Blue => Color.RoyalBlue,
                DashboardPalette.Green => Color.DarkGreen,
                _ => SystemColors.WindowText
            }
        };
    }

    internal static void ReapplyColors(TreeView tree)
    {
        var isDark = tree.BackColor.GetBrightness() < 0.5f;
        void Update(TreeNodeCollection nodes)
        {
            foreach (TreeNode node in nodes)
            {
                if (node.Tag is TopologyDashboardNode model)
                {
                    node.ForeColor = GetNodeColor(model.Palette, isDark);
                }
                Update(node.Nodes);
            }
        }
        tree.BeginUpdate();
        try { Update(tree.Nodes); }
        finally { tree.EndUpdate(); }
    }
}
