namespace ApfsAccess.Tray;

using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

public static class Program
{
    [STAThread]
    private static void Main()
    {
        if (ShouldRelaunchElevated())
        {
            RelaunchElevated();
            return;
        }

        ApplicationConfiguration.Initialize();
        using var context = new TrayApplicationContext();
        Application.Run(context);
    }

    private static bool ShouldRelaunchElevated()
    {
        if (string.Equals(
                Environment.GetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED"),
                "1",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return !principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void RelaunchElevated()
    {
        var selfPath = Environment.ProcessPath ?? Application.ExecutablePath;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = selfPath,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = true,
                Verb = "runas",
            });
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            MessageBox.Show(
                "Administrator permission is required so APFS Access can read APFS USB drives and mount them in This PC.",
                "APFS Access",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
    }
}
