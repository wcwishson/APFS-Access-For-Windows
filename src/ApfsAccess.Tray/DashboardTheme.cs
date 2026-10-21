using System.ComponentModel;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ApfsAccess.Tray;

public enum AppThemeMode
{
    System = 0,
    Light = 1,
    Dark = 2,
}

public sealed class DashboardTheme
{
    public bool IsDark { get; init; }
    public Color WindowBackground { get; init; }
    public Color SurfaceBackground { get; init; }
    public Color CardBackground { get; init; }
    public Color CardBorder { get; init; }
    public Color TextPrimary { get; init; }
    public Color TextSecondary { get; init; }
    public Color TextMuted { get; init; }
    public Color SplitterColor { get; init; }
    public Color ButtonBackground { get; init; }
    public Color ButtonBorder { get; init; }
    public Color ButtonHover { get; init; }
    public Color ButtonPressed { get; init; }
    public Color ButtonText { get; init; }
    public Color ButtonDisabledBackground { get; init; }
    public Color ButtonDisabledBorder { get; init; }
    public Color ButtonDisabledText { get; init; }
    public Color DetailsBackground { get; init; }
    public Color DetailsText { get; init; }
    public Color TreeViewBackground { get; init; }
    public Color TreeViewText { get; init; }
    public Color TreeViewLineColor { get; init; }
    public Color DropdownBackground { get; init; }
    public Color DropdownText { get; init; }
    public Color DropdownBorder { get; init; }
    public Color CheckBoxText { get; init; }
    public Color StorageTrackBackground { get; init; }
    public Color StorageBorder { get; init; }

    public static readonly DashboardTheme Light = new()
    {
        IsDark = false,
        WindowBackground = Color.FromArgb(248, 250, 252),      // Slate 50
        SurfaceBackground = Color.FromArgb(248, 250, 252),
        CardBackground = Color.White,
        CardBorder = Color.FromArgb(226, 232, 240),            // Slate 200
        TextPrimary = Color.FromArgb(15, 23, 42),              // Slate 900
        TextSecondary = Color.FromArgb(55, 65, 81),            // Gray 700
        TextMuted = Color.FromArgb(100, 116, 139),             // Slate 500
        SplitterColor = Color.FromArgb(226, 232, 240),
        ButtonBackground = Color.FromArgb(241, 245, 249),
        ButtonBorder = Color.FromArgb(203, 213, 225),
        ButtonHover = Color.FromArgb(226, 232, 240),
        ButtonPressed = Color.FromArgb(203, 213, 225),
        ButtonText = Color.FromArgb(15, 23, 42),
        ButtonDisabledBackground = Color.FromArgb(241, 245, 249),
        ButtonDisabledBorder = Color.FromArgb(226, 232, 240),
        ButtonDisabledText = Color.FromArgb(148, 163, 184),
        DetailsBackground = Color.White,
        DetailsText = Color.FromArgb(30, 41, 59),
        TreeViewBackground = Color.White,
        TreeViewText = Color.FromArgb(15, 23, 42),
        TreeViewLineColor = Color.FromArgb(203, 213, 225),
        DropdownBackground = Color.White,
        DropdownText = Color.FromArgb(15, 23, 42),
        DropdownBorder = Color.FromArgb(203, 213, 225),
        CheckBoxText = Color.FromArgb(15, 23, 42),
        StorageTrackBackground = Color.FromArgb(226, 232, 240),
        StorageBorder = Color.FromArgb(203, 213, 225),
    };

    public static readonly DashboardTheme Dark = new()
    {
        IsDark = true,
        WindowBackground = Color.FromArgb(24, 25, 28),         // Modern deep neutral dark
        SurfaceBackground = Color.FromArgb(24, 25, 28),
        CardBackground = Color.FromArgb(32, 34, 38),           // Elevated dark card
        CardBorder = Color.FromArgb(50, 53, 60),               // Subtle card border
        TextPrimary = Color.FromArgb(243, 244, 246),           // Gray 100
        TextSecondary = Color.FromArgb(180, 186, 196),         // Light slate
        TextMuted = Color.FromArgb(140, 147, 160),             // Muted slate
        SplitterColor = Color.FromArgb(45, 48, 55),
        ButtonBackground = Color.FromArgb(42, 45, 52),         // Button dark surface
        ButtonBorder = Color.FromArgb(64, 68, 78),             // Button border
        ButtonHover = Color.FromArgb(55, 59, 68),              // Button hover
        ButtonPressed = Color.FromArgb(68, 73, 84),            // Button pressed
        ButtonText = Color.FromArgb(240, 242, 245),
        ButtonDisabledBackground = Color.FromArgb(34, 36, 42),
        ButtonDisabledBorder = Color.FromArgb(50, 54, 62),
        ButtonDisabledText = Color.FromArgb(152, 158, 170),
        DetailsBackground = Color.FromArgb(18, 19, 22),        // Dark code inspector background
        DetailsText = Color.FromArgb(226, 232, 240),
        TreeViewBackground = Color.FromArgb(28, 30, 34),       // Tree panel background
        TreeViewText = Color.FromArgb(235, 238, 242),
        TreeViewLineColor = Color.FromArgb(65, 70, 80),
        DropdownBackground = Color.FromArgb(38, 41, 47),
        DropdownText = Color.FromArgb(240, 242, 245),
        DropdownBorder = Color.FromArgb(64, 68, 78),
        CheckBoxText = Color.FromArgb(226, 232, 240),
        StorageTrackBackground = Color.FromArgb(45, 48, 56),
        StorageBorder = Color.FromArgb(65, 70, 80),
    };

    public static bool IsSystemDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int val)
            {
                return val == 0;
            }
        }
        catch
        {
        }
        return false;
    }

    public static DashboardTheme Resolve(AppThemeMode mode)
        => mode switch
        {
            AppThemeMode.Dark => Dark,
            AppThemeMode.Light => Light,
            _ => IsSystemDark() ? Dark : Light,
        };

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    [DllImport("uxtheme.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string? pszSubIdList);

    public static void ApplyImmersiveDarkMode(IntPtr hWnd, bool isDark)
    {
        if (hWnd == IntPtr.Zero) return;
        try
        {
            int val = isDark ? 1 : 0;
            if (DwmSetWindowAttribute(hWnd, 20, ref val, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(hWnd, 19, ref val, sizeof(int));
            }
        }
        catch
        {
        }
    }

    public static void ApplyWindowTheme(IntPtr hWnd, bool isDark)
    {
        if (hWnd == IntPtr.Zero) return;
        try
        {
            SetWindowTheme(hWnd, isDark ? "DarkMode_Explorer" : "Explorer", null);
        }
        catch
        {
        }
    }
}

internal sealed class DarkToolStripColorTable : ProfessionalColorTable
{
    public override Color ToolStripDropDownBackground => Color.FromArgb(32, 34, 38);
    public override Color MenuBorder => Color.FromArgb(60, 64, 72);
    public override Color MenuItemBorder => Color.FromArgb(60, 64, 72);
    public override Color MenuItemSelected => Color.FromArgb(52, 56, 64);
    public override Color MenuItemSelectedGradientBegin => Color.FromArgb(52, 56, 64);
    public override Color MenuItemSelectedGradientEnd => Color.FromArgb(52, 56, 64);
    public override Color MenuItemPressedGradientBegin => Color.FromArgb(42, 45, 52);
    public override Color MenuItemPressedGradientEnd => Color.FromArgb(42, 45, 52);
    public override Color ImageMarginGradientBegin => Color.FromArgb(32, 34, 38);
    public override Color ImageMarginGradientMiddle => Color.FromArgb(32, 34, 38);
    public override Color ImageMarginGradientEnd => Color.FromArgb(32, 34, 38);
    public override Color CheckBackground => Color.FromArgb(52, 56, 64);
    public override Color CheckSelectedBackground => Color.FromArgb(64, 68, 78);
    public override Color CheckPressedBackground => Color.FromArgb(42, 45, 52);
    public override Color SeparatorDark => Color.FromArgb(60, 64, 72);
    public override Color SeparatorLight => Color.FromArgb(42, 45, 52);
}

internal sealed class DarkToolStripRenderer : ToolStripProfessionalRenderer
{
    public DarkToolStripRenderer() : base(new DarkToolStripColorTable())
    {
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        if (e.Item is not null)
        {
            e.TextColor = e.Item.Enabled ? Color.FromArgb(240, 242, 245) : Color.FromArgb(120, 125, 135);
        }
        base.OnRenderItemText(e);
    }

    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
    {
        if (e.Item is not null)
        {
            e.ArrowColor = e.Item.Enabled ? Color.FromArgb(240, 242, 245) : Color.FromArgb(120, 125, 135);
        }
        base.OnRenderArrow(e);
    }
}
