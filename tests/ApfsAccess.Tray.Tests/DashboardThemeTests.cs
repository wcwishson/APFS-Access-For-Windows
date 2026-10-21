using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class DashboardThemeTests
{
    private static void Sta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) throw failure;
    }

    [Fact]
    public void DashboardTheme_Presets_HaveExpectedProperties()
    {
        var light = DashboardTheme.Light;
        var dark = DashboardTheme.Dark;

        Assert.False(light.IsDark);
        Assert.True(dark.IsDark);

        Assert.NotEqual(light.WindowBackground, dark.WindowBackground);
        Assert.NotEqual(light.CardBackground, dark.CardBackground);
        Assert.NotEqual(light.TextPrimary, dark.TextPrimary);
        Assert.NotEqual(light.ButtonBackground, dark.ButtonBackground);
        Assert.NotEqual(light.TreeViewBackground, dark.TreeViewBackground);
    }

    [Fact]
    public void DashboardTheme_Resolve_ReturnsMatchingTheme()
    {
        var light = DashboardTheme.Resolve(AppThemeMode.Light);
        Assert.False(light.IsDark);
        Assert.Equal(DashboardTheme.Light.WindowBackground, light.WindowBackground);

        var dark = DashboardTheme.Resolve(AppThemeMode.Dark);
        Assert.True(dark.IsDark);
        Assert.Equal(DashboardTheme.Dark.WindowBackground, dark.WindowBackground);

        var system = DashboardTheme.Resolve(AppThemeMode.System);
        Assert.NotNull(system);
    }

    [Fact]
    public void StartupSettingsManager_PersistsAndLoads_ThemeMode()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"tray-theme-test-{Guid.NewGuid():N}.json");
        try
        {
            var manager = new StartupSettingsManager(
                new MemoryStartupRegistry(),
                tempFile,
                () => @"D:\Apps\APFS Access.exe");

            var initial = manager.Load();
            Assert.Equal(AppThemeMode.System, initial.ThemeMode);

            manager.SetThemeMode(AppThemeMode.Dark);
            var updated = manager.Load();
            Assert.Equal(AppThemeMode.Dark, updated.ThemeMode);

            manager.SetThemeMode(AppThemeMode.Light);
            var lightUpdated = manager.Load();
            Assert.Equal(AppThemeMode.Light, lightUpdated.ThemeMode);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public void DashboardForm_InitializesWithTheme_AndCanSwitchDynamically() => Sta(() =>
    {
        var modes = new List<AppThemeMode>();
        using var form = new DashboardForm(
            openAsync: _ => Task.CompletedTask,
            ejectAsync: _ => Task.CompletedTask,
            fixAsync: _ => Task.CompletedTask,
            startupPreferences: new StartupPreferences(StartWithWindows: false, StartMinimized: false, ThemeMode: AppThemeMode.Light),
            setThemeModeAsync: mode => { modes.Add(mode); return Task.CompletedTask; });

        Assert.Equal(AppThemeMode.Light, form.ThemeMode);
        Assert.False(form.CurrentTheme.IsDark);
        Assert.Equal(DashboardTheme.Light.WindowBackground, form.BackColor);

        // Switch to Dark Mode dynamically
        form.ApplyTheme(AppThemeMode.Dark);
        Assert.Equal(AppThemeMode.Dark, form.ThemeMode);
        Assert.True(form.CurrentTheme.IsDark);
        Assert.Equal(DashboardTheme.Dark.WindowBackground, form.BackColor);

        // Switch back to Light Mode dynamically
        form.ApplyTheme(AppThemeMode.Light);
        Assert.Equal(AppThemeMode.Light, form.ThemeMode);
        Assert.False(form.CurrentTheme.IsDark);
        Assert.Equal(DashboardTheme.Light.WindowBackground, form.BackColor);
    });

    [Fact]
    public void DashboardForm_ThemeComboBox_ChangesThemeMode() => Sta(() =>
    {
        var modes = new List<AppThemeMode>();
        using var form = new DashboardForm(
            openAsync: _ => Task.CompletedTask,
            ejectAsync: _ => Task.CompletedTask,
            fixAsync: _ => Task.CompletedTask,
            startupPreferences: new StartupPreferences(StartWithWindows: false, StartMinimized: false, ThemeMode: AppThemeMode.Light),
            setThemeModeAsync: mode => { modes.Add(mode); return Task.CompletedTask; });

        var themeCombo = typeof(DashboardForm)
            .GetField("_themeComboBox", BindingFlags.NonPublic | BindingFlags.Instance)?
            .GetValue(form) as ComboBox;

        Assert.NotNull(themeCombo);
        Assert.Equal(1, themeCombo.SelectedIndex); // Light

        themeCombo.SelectedIndex = 2; // Dark
        Assert.Equal(AppThemeMode.Dark, form.ThemeMode);
        Assert.True(form.CurrentTheme.IsDark);
    });

    [Fact]
    public void StorageBarControl_SupportsDarkModeFlag() => Sta(() =>
    {
        using var bar = new ApfsStorageBarControl
        {
            IsDarkMode = false,
        };
        Assert.False(bar.IsDarkMode);

        bar.IsDarkMode = true;
        Assert.True(bar.IsDarkMode);
    });

    [Fact]
    public void TopologyTreeRefresh_ReapplyColors_WorksWithoutError() => Sta(() =>
    {
        using var tree = new TreeView
        {
            BackColor = Color.White
        };
        tree.Nodes.Add("node1", "Ready: Volume 1");
        tree.Nodes[0].Tag = new TopologyDashboardNode("v1", null, "Volume 1", "Details", DashboardPalette.Green);

        // Reapply with light background
        TopologyTreeRefresh.ReapplyColors(tree);
        Assert.Equal(Color.DarkGreen, tree.Nodes[0].ForeColor);

        // Reapply with dark background
        tree.BackColor = Color.FromArgb(24, 25, 28);
        TopologyTreeRefresh.ReapplyColors(tree);
        Assert.Equal(Color.FromArgb(74, 222, 128), tree.Nodes[0].ForeColor);
    });

    [Fact]
    public void DashboardForm_TopologyTree_DisablesHoverToolTips() => Sta(() =>
    {
        using var form = new DashboardForm(
            openAsync: _ => Task.CompletedTask,
            ejectAsync: _ => Task.CompletedTask,
            fixAsync: _ => Task.CompletedTask);

        var tree = typeof(DashboardForm)
            .GetField("_topologyTree", BindingFlags.NonPublic | BindingFlags.Instance)?
            .GetValue(form) as TreeView;

        Assert.NotNull(tree);
        Assert.False(tree.ShowNodeToolTips);
    });

    [Fact]
    public void TopologyTreeRefresh_DoesNotSetNodeToolTips() => Sta(() =>
    {
        using var tree = new TreeView();
        var nodes = new[]
        {
            new TopologyDashboardNode("v1", null, "Volume 1", "Long redundant diagnostics details", DashboardPalette.Green)
        };
        TopologyTreeRefresh.Apply(tree, nodes);
        Assert.Single(tree.Nodes);
        Assert.True(string.IsNullOrEmpty(tree.Nodes[0].ToolTipText));
    });

    [Fact]
    public void DashboardForm_DarkTheme_ButtonsAndCheckBoxesHaveLegibleText() => Sta(() =>
    {
        using var form = new DashboardForm(
            openAsync: _ => Task.CompletedTask,
            ejectAsync: _ => Task.CompletedTask,
            fixAsync: _ => Task.CompletedTask,
            startupPreferences: new StartupPreferences(StartWithWindows: false, StartMinimized: false, ThemeMode: AppThemeMode.Dark));

        Assert.True(DashboardTheme.Dark.ButtonDisabledText.GetBrightness() > 0.5f);
        Assert.True(DashboardTheme.Dark.ButtonText.GetBrightness() > 0.8f);

        var buttons = Controls(form).OfType<Button>().ToList();
        Assert.NotEmpty(buttons);
        foreach (var btn in buttons)
        {
            Assert.True(btn.ForeColor.GetBrightness() > 0.45f,
                $"Button '{btn.Text}' ForeColor brightness {btn.ForeColor.GetBrightness()} is too dark: {btn.ForeColor}");
        }

        var checkBoxes = Controls(form).OfType<CheckBox>().ToList();
        Assert.NotEmpty(checkBoxes);
        foreach (var cb in checkBoxes)
        {
            Assert.True(cb.ForeColor.GetBrightness() > 0.7f,
                $"CheckBox '{cb.Text}' ForeColor is too dark: {cb.ForeColor}");
        }

        var artifactDir = Environment.GetEnvironmentVariable("APFSACCESS_GUI_CAPTURE_DIR");
        if (!string.IsNullOrWhiteSpace(artifactDir) && Directory.Exists(artifactDir))
        {
            _ = form.Handle;
            form.Size = new Size(1140, 740);
            form.Show();
            Application.DoEvents();

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
            var status = new StatusChangedPayload(RuntimeState.MountedRw, ["E:\\"], null,
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

            form.ApplyStatus(status);
            Application.DoEvents();

            var tree = Controls(form).OfType<TreeView>().Single();
            var volNode = tree.Nodes.Cast<TreeNode>().SelectMany(EnumerateTreeNodes).FirstOrDefault(n => (n.Tag as TopologyDashboardNode)?.Row is not null);
            if (volNode != null)
            {
                tree.SelectedNode = volNode;
                typeof(DashboardForm).GetMethod("ShowSelectedNode", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(form, null);
                Application.DoEvents();
            }

            using var bmp = new Bitmap(1140, 740);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(form.BackColor);
            }
            RenderControlTree(form, bmp, Point.Empty);
            bmp.Save(Path.Combine(artifactDir, "dashboard_dark_screenshot.png"), System.Drawing.Imaging.ImageFormat.Png);
            bmp.Save(Path.Combine(artifactDir, "dashboard_screenshot.png"), System.Drawing.Imaging.ImageFormat.Png);
            bmp.Save(Path.Combine(artifactDir, "dashboard_volume_screenshot.png"), System.Drawing.Imaging.ImageFormat.Png);

            // Also crop the middle-right action buttons
            var buttonsPanel = Controls(form).OfType<FlowLayoutPanel>().FirstOrDefault(p => p.Controls.OfType<Button>().Count() > 2);
            if (buttonsPanel != null)
            {
                using var btnBmp = new Bitmap(buttonsPanel.Width, buttonsPanel.Height);
                buttonsPanel.DrawToBitmap(btnBmp, new Rectangle(0, 0, buttonsPanel.Width, buttonsPanel.Height));
                btnBmp.Save(Path.Combine(artifactDir, "action_buttons_crop.png"), System.Drawing.Imaging.ImageFormat.Png);
                btnBmp.Save(Path.Combine(artifactDir, "exact_buttons.png"), System.Drawing.Imaging.ImageFormat.Png);
            }

            var disabledToolbar = Controls(form).OfType<FlowLayoutPanel>().FirstOrDefault(p => p.Controls.OfType<Button>().Any(b => b.Text == "Verify container"));
            if (disabledToolbar != null)
            {
                using var tbBmp = new Bitmap(disabledToolbar.Width, disabledToolbar.Height);
                disabledToolbar.DrawToBitmap(tbBmp, new Rectangle(0, 0, disabledToolbar.Width, disabledToolbar.Height));
                tbBmp.Save(Path.Combine(artifactDir, "buttons_crop.png"), System.Drawing.Imaging.ImageFormat.Png);
                tbBmp.Save(Path.Combine(artifactDir, "disabled_button_test.png"), System.Drawing.Imaging.ImageFormat.Png);
                tbBmp.Save(Path.Combine(artifactDir, "toolbar_crop.png"), System.Drawing.Imaging.ImageFormat.Png);
            }
        }
    });

    private static IEnumerable<TreeNode> EnumerateTreeNodes(TreeNode root)
    {
        yield return root;
        foreach (TreeNode child in root.Nodes)
        {
            foreach (var descendant in EnumerateTreeNodes(child))
                yield return descendant;
        }
    }

    private static void RenderControlTree(Control parent, Bitmap target, Point offset)
    {
        for (int i = parent.Controls.Count - 1; i >= 0; i--)
        {
            var child = parent.Controls[i];
            if (!child.Visible || child.Width <= 0 || child.Height <= 0) continue;
            var pt = new Point(offset.X + child.Left, offset.Y + child.Top);
            using var cbmp = new Bitmap(child.Width, child.Height);
            child.DrawToBitmap(cbmp, new Rectangle(0, 0, child.Width, child.Height));
            using (var g = Graphics.FromImage(target))
            {
                g.DrawImage(cbmp, pt);
            }
            RenderControlTree(child, target, pt);
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

    private sealed class MemoryStartupRegistry : IStartupRegistry
    {
        public string? Value { get; set; }
        public string? GetCurrentUserRunValue(string name) => Value;
        public void SetCurrentUserRunValue(string name, string value) => Value = value;
        public void DeleteCurrentUserRunValue(string name) => Value = null;
    }
}
