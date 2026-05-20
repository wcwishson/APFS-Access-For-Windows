using ApfsAccess.Tray;
using System.Reflection;

namespace ApfsAccess.Tray.Tests;

public sealed class TrayProgramElevationTests
{
    [Fact]
    public void Program_HasAllowUnelevatedEscapeHatchForDiagnostics()
    {
        var method = typeof(Program).GetMethod("ShouldRelaunchElevated", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var previous = Environment.GetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED");
        try
        {
            Environment.SetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED", "1");
            var result = method!.Invoke(null, null);

            Assert.False(Assert.IsType<bool>(result));
        }
        finally
        {
            Environment.SetEnvironmentVariable("APFSACCESS_ALLOW_UNELEVATED", previous);
        }
    }
}
