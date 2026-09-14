using System.Diagnostics;
using System.Text.Json;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

// Task 5 generic CLI surface: these tests invoke the real built CLI
// executable (not helper functions) over mount-free paths only — version,
// xattr help/validation, and the management refusal surface. Anything
// requiring a WinFsp mount or the service pipe stays out; those need
// elevated/media gates and are covered by helper-level tests instead.
public sealed class RealCliContractTests
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);

    private sealed class RealCliFactAttribute : FactAttribute
    {
        public RealCliFactAttribute()
        {
            if (!File.Exists(CliExePath()))
                Skip = "Real CLI executable not found next to ApfsAccess.Cli.dll; build ApfsAccess.Cli first.";
        }
    }

    private sealed class RealCliTheoryAttribute : TheoryAttribute
    {
        public RealCliTheoryAttribute()
        {
            if (!File.Exists(CliExePath()))
                Skip = "Real CLI executable not found next to ApfsAccess.Cli.dll; build ApfsAccess.Cli first.";
        }
    }

    private static string CliExePath()
    {
        var dll = typeof(XattrCommand).Assembly.Location;
        return Path.ChangeExtension(dll, ".exe");
    }

    private static (int ExitCode, JsonElement Json, string Stderr) Run(params string[] args)
    {
        var exe = CliExePath();
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        var stdout = new System.Text.StringBuilder();
        var stderr = new System.Text.StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };
        Assert.True(process.Start(), "Real CLI process starts.");
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        if (!process.WaitForExit(CommandTimeout))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            Assert.Fail($"Real CLI timed out after {CommandTimeout.TotalSeconds:n0}s: {exe} {string.Join(' ', args)}.");
        }

        process.WaitForExit();
        using var document = JsonDocument.Parse(stdout.ToString());
        return (process.ExitCode, document.RootElement.Clone(), stderr.ToString());
    }

    [RealCliFact]
    public void RealCli_Version_ReportsContract()
    {
        var (exit, json, _) = Run("version");
        Assert.Equal(0, exit);
        Assert.True(json.GetProperty("success").GetBoolean());
        Assert.Equal("version", json.GetProperty("command").GetString());
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("version").GetString()));
        Assert.Contains("xattr", json.GetProperty("commands").EnumerateArray().Select(e => e.GetString()));
    }

    [RealCliFact]
    public void RealCli_XattrHelp_ListsFourVerbsAndBound()
    {
        var (exit, json, _) = Run("xattr", "help");
        Assert.Equal(0, exit);
        Assert.True(json.GetProperty("success").GetBoolean());
        var usage = json.GetProperty("usage").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Contains("xattr list --path PATH", usage);
        Assert.Contains("xattr read --path PATH --name NAME --output FILE", usage);
        Assert.Contains("xattr write --path PATH --name NAME --input FILE", usage);
        Assert.Contains("xattr remove --path PATH --name NAME", usage);
        Assert.Equal(1048576, json.GetProperty("maxWriteBytes").GetInt32());
    }

    [RealCliTheory]
    [InlineData("bogus")]
    [InlineData("--help-me")]
    public void RealCli_XattrUnknownAction_RefusesWithUsageError(string action)
    {
        var (exit, json, _) = Run("xattr", action);
        Assert.Equal(2, exit);
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal("xattr", json.GetProperty("command").GetString());
        Assert.Equal(action, json.GetProperty("action").GetString());
        Assert.Equal(2, json.GetProperty("exitCode").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("error").GetString()));
    }

    [RealCliFact]
    public void RealCli_XattrWriteMissingOptions_RefusesBeforeTouchingDisk()
    {
        var (exit, json, _) = Run("xattr", "write", "--path", @"D:\definitely-not-here\owner.txt");
        Assert.Equal(2, exit);
        Assert.False(json.GetProperty("success").GetBoolean());
        Assert.Equal("InvalidArguments", json.GetProperty("errorCode").GetString());
    }

    [RealCliTheory]
    [InlineData("volume")]
    [InlineData("format")]
    [InlineData("manage")]
    public void RealCli_ManagementVerbs_RefusedUnknown(string command)
    {
        var (exit, _, _) = Run(command);
        Assert.Equal(2, exit);
    }
}

