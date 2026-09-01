using System.Reflection;

namespace ApfsAccess.Tray.Tests;

public sealed class BootstrapPayloadSelectionTests : IDisposable
{
    private const string UseAdjacentClickRunVariable = "APFSACCESS_USE_ADJACENT_CLICK_RUN";
    private readonly string? _originalValue = Environment.GetEnvironmentVariable(UseAdjacentClickRunVariable);

    [Fact]
    public void ShouldUseAdjacentClickRunDirectory_DefaultsToEmbeddedPayload()
    {
        Environment.SetEnvironmentVariable(UseAdjacentClickRunVariable, null);

        var useAdjacent = InvokeShouldUseAdjacentClickRunDirectory();

        Assert.False(useAdjacent);
    }

    [Fact]
    public void ShouldUseAdjacentClickRunDirectory_AllowsExplicitDeveloperOverride()
    {
        Environment.SetEnvironmentVariable(UseAdjacentClickRunVariable, "1");

        var useAdjacent = InvokeShouldUseAdjacentClickRunDirectory();

        Assert.True(useAdjacent);
    }

    [Fact]
    public void WinFspInstallerArguments_DisableRestartManagerAndSuppressImmediateRestart()
    {
        var arguments = InvokeBuildWinFspInstallerArguments(@"D:\scratch\winfsp.msi");

        Assert.Contains("MSIRESTARTMANAGERCONTROL=Disable", arguments, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("REBOOT=ReallySuppress", arguments, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/norestart", arguments, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1641, true)]
    [InlineData(3010, true)]
    [InlineData(1603, false)]
    public void SuccessfulWinFspInstall_AlwaysRequiresRestart(int exitCode, bool expected)
    {
        Assert.Equal(expected, InvokeWinFspInstallRequiresRestart(exitCode));
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(UseAdjacentClickRunVariable, _originalValue);
    }

    private static bool InvokeShouldUseAdjacentClickRunDirectory()
    {
        var assemblyPath = Path.Combine(AppContext.BaseDirectory, "APFS Access.dll");
        var assembly = Assembly.LoadFrom(assemblyPath);
        var programType = assembly.GetType("ApfsAccess.Bootstrap.Program");
        Assert.NotNull(programType);

        var method = programType!.GetMethod(
            "ShouldUseAdjacentClickRunDirectory",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, []);
        return Assert.IsType<bool>(result);
    }

    private static string InvokeBuildWinFspInstallerArguments(string msiPath)
    {
        var method = LoadBootstrapProgramType().GetMethod(
            "BuildWinFspInstallerArguments",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [msiPath]);
        return Assert.IsType<string>(result);
    }

    private static bool InvokeWinFspInstallRequiresRestart(int exitCode)
    {
        var method = LoadBootstrapProgramType().GetMethod(
            "WinFspInstallRequiresRestart",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [exitCode]);
        return Assert.IsType<bool>(result);
    }

    private static Type LoadBootstrapProgramType()
    {
        var assemblyPath = Path.Combine(AppContext.BaseDirectory, "APFS Access.dll");
        var assembly = Assembly.LoadFrom(assemblyPath);
        var programType = assembly.GetType("ApfsAccess.Bootstrap.Program");
        Assert.NotNull(programType);
        return programType!;
    }
}
