using System.Reflection;
using System.Runtime.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class DashboardFormTests
{
    [Fact]
    public void Constructor_DoesNotCrashWhenInitialSizeTriggersResize()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);
                Assert.False(form.IsDisposed);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void ApplyStatus_RendersReadableActionButtonsForMountedVolume()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);

                form.ApplyStatus(NewMountedReadWritePayload());

                var buttons = EnumerateControls(form).OfType<Button>().ToArray();

                foreach (var text in new[] { "Open", "Eject", "Fix", "Details" })
                {
                    var button = Assert.Single(buttons, candidate => candidate.Text == text);
                    Assert.True(button.AutoSize, $"{text} button should size from its content.");
                    Assert.Equal(AutoSizeMode.GrowAndShrink, button.AutoSizeMode);
                    Assert.True(button.Width >= button.GetPreferredSize(Size.Empty).Width, $"{text} button width was {button.Width}.");
                    Assert.True(button.Height >= button.GetPreferredSize(Size.Empty).Height, $"{text} button height was {button.Height}.");
                }
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void ApplyStatus_ExpandsMountedRowsForLongText()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);

                form.Show();
                form.Width = form.MinimumSize.Width;
                form.ApplyStatus(NewLongMountedPayload());
                form.PerformLayout();
                Application.DoEvents();

                var row = Assert.Single(
                    EnumerateControls(form).OfType<Panel>(),
                    static panel => panel.BorderStyle == BorderStyle.FixedSingle);
                var labels = EnumerateControls(row).OfType<Label>().ToArray();
                var requiredTextHeight = labels.Sum(label =>
                    TextRenderer.MeasureText(
                        label.Text,
                        label.Font,
                        new Size(label.MaximumSize.Width, int.MaxValue),
                        TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl).Height);

                Assert.True(row.Height >= requiredTextHeight, $"Long-text row height was {row.Height}; required text height was {requiredTextHeight}.");
                Assert.DoesNotContain(labels, static label => label.AutoEllipsis);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void ApplyStatus_KeepsRowTextAndButtonsInsideRowBounds()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);

                form.Show();
                form.ApplyStatus(NewMountedReadWritePayload());
                form.PerformLayout();
                Application.DoEvents();

                var row = Assert.Single(
                    EnumerateControls(form).OfType<Panel>(),
                    static panel => panel.BorderStyle == BorderStyle.FixedSingle);
                var rowBounds = row.RectangleToScreen(row.ClientRectangle);
                var controls = EnumerateControls(row)
                    .Where(static control => control is Label or Button)
                    .ToArray();

                Assert.NotEmpty(controls);
                foreach (var control in controls)
                {
                    Assert.False(control.Bounds.IsEmpty, $"{control.Text} has empty bounds.");
                    var bounds = control.RectangleToScreen(control.ClientRectangle);
                    Assert.True(rowBounds.Contains(bounds), $"{control.Text} bounds {bounds} should fit inside row {rowBounds}.");
                }
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void ApplyStatus_DoesNotRebuildRowsWhenDashboardStateIsUnchanged()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);
                var payload = NewMountedReadWritePayload();

                form.ApplyStatus(payload);
                var firstRow = Assert.Single(
                    EnumerateControls(form).OfType<Panel>(),
                    static panel => panel.BorderStyle == BorderStyle.FixedSingle);

                form.ApplyStatus(payload);
                var secondRow = Assert.Single(
                    EnumerateControls(form).OfType<Panel>(),
                    static panel => panel.BorderStyle == BorderStyle.FixedSingle);

                Assert.Same(firstRow, secondRow);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void ApplyStatus_DoesNotRebuildReadOnlyRowsWhenHiddenDetailsChange()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);

                form.ApplyStatus(NewMountedReadOnlyPayload(lastCommitXid: 10316));
                var firstRow = Assert.Single(
                    EnumerateControls(form).OfType<Panel>(),
                    static panel => panel.BorderStyle == BorderStyle.FixedSingle);

                form.ApplyStatus(NewMountedReadOnlyPayload(lastCommitXid: 10317));
                var secondRow = Assert.Single(
                    EnumerateControls(form).OfType<Panel>(),
                    static panel => panel.BorderStyle == BorderStyle.FixedSingle);

                Assert.Same(firstRow, secondRow);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void EjectAndFixButtonsInvokeCallbacksWithVolumeId()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                var ejectedVolumes = new List<string?>();
                var fixedVolumes = new List<string?>();
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    volumeId =>
                    {
                        ejectedVolumes.Add(volumeId);
                        return Task.CompletedTask;
                    },
                    volumeId =>
                    {
                        fixedVolumes.Add(volumeId);
                        return Task.CompletedTask;
                    });

                form.Show();
                form.ApplyStatus(NewMountedReadOnlyPayload());
                form.PerformLayout();
                Application.DoEvents();

                var buttons = EnumerateControls(form).OfType<Button>().ToArray();
                Assert.Single(buttons, static button => button.Text == "Eject").PerformClick();
                Assert.Single(buttons, static button => button.Text == "Fix").PerformClick();
                Application.DoEvents();

                Assert.Equal([@"\\.\PhysicalDrive2|Main"], ejectedVolumes);
                Assert.Equal([@"\\.\PhysicalDrive2|Main"], fixedVolumes);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void HealthyReadWriteStatusDisablesFixButton()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);

                form.ApplyStatus(NewMountedReadWritePayload());

                var fix = Assert.Single(
                    EnumerateControls(form).OfType<Button>(),
                    static button => button.Text == "Fix");
                Assert.False(fix.Enabled);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void Constructor_DoesNotShowCloseToTrayReminder()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            try
            {
                using var form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);

                var labels = EnumerateControls(form).OfType<Label>().ToArray();

                Assert.DoesNotContain(labels, static label =>
                    label.Visible &&
                    label.Text.Contains("Close this window", StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception ex)
            {
                exception = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    [Fact]
    public void NotifyIconLeftClick_ShowsDashboard()
    {
        Exception? exception = null;
        var thread = new Thread(() =>
        {
            DashboardForm? form = null;
            try
            {
                form = new DashboardForm(
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask,
                    _ => Task.CompletedTask);
#pragma warning disable SYSLIB0050
                var context = (TrayApplicationContext)FormatterServices.GetUninitializedObject(typeof(TrayApplicationContext));
#pragma warning restore SYSLIB0050
                var dashboardField = typeof(TrayApplicationContext).GetField(
                    "_dashboard",
                    BindingFlags.Instance | BindingFlags.NonPublic);
                Assert.NotNull(dashboardField);
                dashboardField!.SetValue(context, form);

                var clickMethod = typeof(TrayApplicationContext).GetMethod(
                    "OnNotifyIconMouseClick",
                    BindingFlags.Instance | BindingFlags.NonPublic);
                Assert.NotNull(clickMethod);

                clickMethod!.Invoke(context, [null, new MouseEventArgs(MouseButtons.Left, 1, 0, 0, 0)]);

                Assert.True(form.Visible);
            }
            catch (TargetInvocationException ex)
            {
                exception = ex.InnerException ?? ex;
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            finally
            {
                if (form is not null)
                {
                    form.AllowCloseForApplicationExit();
                    form.Close();
                    form.Dispose();
                }
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(exception);
    }

    private static StatusChangedPayload NewMountedReadWritePayload()
        => new(
            State: RuntimeState.MountedRw,
            MountPoints: ["E:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteEngineState: NativeWriteEngineState.HardwareValidated,
            NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            RecoveryActive: false,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

    private static StatusChangedPayload NewMountedReadOnlyPayload(ulong lastCommitXid = 10316)
        => NewMountedReadWritePayload() with
        {
            State = RuntimeState.MountedRo,
            WriteEnabled = false,
            MountedVolumes =
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
            LastCommitXid = lastCommitXid,
        };

    private static StatusChangedPayload NewLongMountedPayload()
    {
        var longSuffix = string.Join(
            " ",
            Enumerable.Repeat("Wrapping verification text", 12));

        return NewMountedReadWritePayload() with
        {
            MountedVolumes =
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: $"Main APFS Data Partition {longSuffix}",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: $"Samsung Flash Drive FIT USB Device {longSuffix}",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            MountPoints = ["E:\\"],
        };
    }

    private static IEnumerable<Control> EnumerateControls(Control root)
    {
        foreach (Control control in root.Controls)
        {
            yield return control;

            foreach (var child in EnumerateControls(control))
            {
                yield return child;
            }
        }
    }
}
