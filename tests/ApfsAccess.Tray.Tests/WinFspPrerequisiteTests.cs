using System.Reflection;

namespace ApfsAccess.Tray.Tests;

public sealed class WinFspPrerequisiteTests
{
    [Theory]
    [InlineData(2, 1, 25156, false)]
    [InlineData(2, 2, 26214, false)]
    [InlineData(2, 2, 26215, true)]
    [InlineData(3, 0, 0, true)]
    public void IsSupportedWinFspVersion_EnforcesTeardownFixFloor(
        int major,
        int minor,
        int build,
        bool expected)
    {
        var programType = LoadBootstrapProgramType();
        var method = programType.GetMethod(
            "IsSupportedWinFspVersion",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var actual = method!.Invoke(null, [major, minor, build]);

        Assert.Equal(expected, Assert.IsType<bool>(actual));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1641, true)]
    [InlineData(3010, true)]
    public void IsRestartRequiredInstallerExitCode_DistinguishesInstalledFromActiveRuntime(
        int exitCode,
        bool expected)
    {
        var programType = LoadBootstrapProgramType();
        var method = programType.GetMethod(
            "IsRestartRequiredInstallerExitCode",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var actual = method!.Invoke(null, [exitCode]);

        Assert.Equal(expected, Assert.IsType<bool>(actual));
    }

    [Theory]
    [InlineData(2, 2, 26215, 0, 2, 2, 26215, 0, true)]
    [InlineData(2, 2, 26215, 0, 2, 2, 26216, 0, false)]
    [InlineData(2, 2, 26215, 0, 2, 2, 26215, 1, false)]
    [InlineData(2, 1, 25156, 0, 2, 1, 25156, 0, false)]
    public void IsMatchingSupportedWinFspFileVersions_RequiresExactSafePair(
        int dllMajor,
        int dllMinor,
        int dllBuild,
        int dllRevision,
        int driverMajor,
        int driverMinor,
        int driverBuild,
        int driverRevision,
        bool expected)
    {
        var programType = LoadBootstrapProgramType();
        var method = programType.GetMethod(
            "IsMatchingSupportedWinFspFileVersions",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var actual = method!.Invoke(
            null,
            [
                dllMajor,
                dllMinor,
                dllBuild,
                dllRevision,
                driverMajor,
                driverMinor,
                driverBuild,
                driverRevision,
            ]);

        Assert.Equal(expected, Assert.IsType<bool>(actual));
    }

    [Theory]
    [InlineData(-60, -60, false)]
    [InlineData(0, -60, true)]
    [InlineData(-60, 1, true)]
    public void RequiresRestartForWinFspRuntimeFileTimes_RejectsSameBootReplacement(
        int dllCreationOffsetSeconds,
        int driverCreationOffsetSeconds,
        bool expected)
    {
        var programType = LoadBootstrapProgramType();
        var method = programType.GetMethod(
            "RequiresRestartForWinFspRuntimeFileTimes",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var bootUtc = new DateTime(2026, 8, 26, 8, 0, 0, DateTimeKind.Utc);
        var actual = method!.Invoke(
            null,
            [
                bootUtc.AddSeconds(dllCreationOffsetSeconds),
                bootUtc.AddSeconds(driverCreationOffsetSeconds),
                bootUtc,
            ]);

        Assert.Equal(expected, Assert.IsType<bool>(actual));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1641, true)]
    [InlineData(3010, true)]
    public void RecordInstallerExitCode_LatchesRestartRequirement(int exitCode, bool expected)
    {
        var programType = LoadBootstrapProgramType();
        var restartRequired = programType.GetField(
            "_restartRequired",
            BindingFlags.NonPublic | BindingFlags.Static);
        var method = programType.GetMethod(
            "RecordInstallerExitCode",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(restartRequired);
        Assert.NotNull(method);

        try
        {
            restartRequired!.SetValue(null, false);
            var accepted = method!.Invoke(null, [exitCode]);

            Assert.Equal(exitCode is 0 or 1641 or 3010, Assert.IsType<bool>(accepted));
            Assert.Equal(expected, Assert.IsType<bool>(restartRequired.GetValue(null)));
        }
        finally
        {
            restartRequired!.SetValue(null, false);
        }
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
