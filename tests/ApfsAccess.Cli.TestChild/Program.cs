using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli.TestChild;

internal static class Program
{
    private const int StandardOutputHandle = -11;
    private const int MaximumSleepMilliseconds = 5_000;

    public static int Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("The standard-handle probe requires Windows.");
            }

            if (args is ["--probe", ..])
            {
                return RunProbe(args);
            }

            var options = ParseArguments(args);
            var process = Process.GetCurrentProcess();
            var imagePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                throw new InvalidOperationException("The child image path was unavailable.");
            }

            var handle = GetStdHandle(StandardOutputHandle);
            var evidence = new StandardHandleEvidence(
                SchemaVersion: 1,
                ProcessId: process.Id,
                ProcessStartTimeUtcTicks: process.StartTime.ToUniversalTime().Ticks,
                ImagePath: Path.GetFullPath(imagePath),
                StandardOutputHandleValue: handle.ToInt64(),
                StandardOutputFileType: GetFileType(handle));

            WriteEvidenceAtomically(options.ResultPath, evidence);
            if (options.SleepMilliseconds > 0)
            {
                Thread.Sleep(options.SleepMilliseconds);
            }

            return 0;
        }
        catch
        {
            return 2;
        }
    }

    private static ChildOptions ParseArguments(string[] args)
    {
        if (args.Length != 4 ||
            !string.Equals(args[0], "--result-path", StringComparison.Ordinal) ||
            !string.Equals(args[2], "--sleep-ms", StringComparison.Ordinal))
        {
            throw new ArgumentException("Expected --result-path <path> --sleep-ms <milliseconds>.");
        }

        if (string.IsNullOrWhiteSpace(args[1]))
        {
            throw new ArgumentException("The result path is required.");
        }

        var resultPath = Path.GetFullPath(args[1]);
        if (
            !int.TryParse(args[3], out var sleepMilliseconds) ||
            sleepMilliseconds < 0 ||
            sleepMilliseconds > MaximumSleepMilliseconds)
        {
            throw new ArgumentException("The child arguments are invalid.");
        }

        return new ChildOptions(resultPath, sleepMilliseconds);
    }

    private static int RunProbe(string[] args)
    {
        switch (args)
        {
            case ["--probe", "ready-exit", "--result-path", var readyPath, "--release-path", var readyRelease,
                "--exit-code", var readyExit]:
                if (!int.TryParse(readyExit, out var code) || code is not (0 or 73))
                    throw new ArgumentException("Invalid supervisor test exit.");
                WriteEvidenceAtomically(readyPath, new { mountReady = true, hostPid = Environment.ProcessId });
                var readyDeadline = Stopwatch.StartNew();
                while (!File.Exists(readyRelease))
                {
                    if (readyDeadline.Elapsed >= TimeSpan.FromSeconds(15)) return 2;
                    Thread.Sleep(25);
                }
                return code;
            case ["--probe", "environment", "--result-path", var environmentPath]:
                var values = new Dictionary<string, string?>();
                foreach (var name in new[]
                {
                    "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE",
                    "DOTNET_ROOT_X64", "DOTNET_ROOT(x86)", "DOTNET_ROLL_FORWARD",
                    "CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER_PATH", "COR_ENABLE_PROFILING",
                    "COR_PROFILER", "COMPlus_ReadyToRunExcludeList", "APFSACCESS_TEST_STARTUP_HOOK_MARKER",
                    "APFSACCESS_TRACE_MOVES", "PACKAGED_SERVICE_BENIGN", "PATH", "PATHEXT", "COMSPEC",
                })
                {
                    values.Add(name, Environment.GetEnvironmentVariable(name));
                }
                WriteEvidenceAtomically(environmentPath, values);
                return 0;
            case ["--probe", "handle", "--result-path", var handlePath,
                "--handle", var value, "--expected-path", var expectedPath]:
                var handle = new nint(long.Parse(value, System.Globalization.CultureInfo.InvariantCulture));
                var path = new StringBuilder(32768);
                var length = GetFinalPathNameByHandle(handle, path, path.Capacity, 0);
                if (length >= path.Capacity) throw new IOException("Observed handle path exceeded its bound.");
                var observedPath = length == 0 ? string.Empty : path.ToString();
                if (observedPath.StartsWith(@"\\?\", StringComparison.Ordinal)) observedPath = observedPath[4..];
                WriteEvidenceAtomically(handlePath, new
                {
                    inheritedSentinel = string.Equals(observedPath, expectedPath, StringComparison.OrdinalIgnoreCase),
                    observedPath,
                });
                return 0;
            case ["--probe", "grandchild", "--result-path", var grandchildPath, "--release-path", var releasePath]:
                return RunGrandchildProbe(grandchildPath, releasePath);
            case ["--probe", "wait", "--result-path", var inheritedPath,
                "--handle", var inheritedHandle, "--expected-path", var inheritedExpectedPath]:
                var inherited = new nint(long.Parse(inheritedHandle, System.Globalization.CultureInfo.InvariantCulture));
                var inheritedName = new StringBuilder(32768);
                var inheritedLength = GetFinalPathNameByHandle(inherited, inheritedName, inheritedName.Capacity, 0);
                if (inheritedLength == 0 || inheritedLength >= inheritedName.Capacity ||
                    !string.Equals(inheritedName.ToString(), @"\\?\" + inheritedExpectedPath, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The native inheritance positive control failed.");
                WriteEvidenceAtomically(inheritedPath, new { inheritedSentinel = true });
                Thread.Sleep(30_000);
                return 0;
            case ["--probe", "service", "--result-path", var servicePath, "--accepted-path", var acceptedPath]:
                using (var process = Process.GetCurrentProcess())
                    WriteEvidenceAtomically(servicePath, new
                    {
                        processId = process.Id,
                        startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks,
                        imagePath = Environment.ProcessPath,
                    });
                var acceptedDeadline = Stopwatch.StartNew();
                while (!File.Exists(acceptedPath))
                {
                    if (acceptedDeadline.Elapsed >= TimeSpan.FromSeconds(5)) return 0;
                    Thread.Sleep(25);
                }
                Thread.Sleep(30_000);
                return 0;
            default:
                throw new ArgumentException("Invalid bounded launcher probe arguments.");
        }
    }

    private static int RunGrandchildProbe(string resultPath, string releasePath)
    {
        var executable = Environment.ProcessPath ?? throw new IOException("Missing child image path.");
        var sentinelPath = resultPath + ".sentinel";
        using var sentinel = File.OpenHandle(sentinelPath, FileMode.CreateNew, FileAccess.ReadWrite,
            FileShare.ReadWrite | FileShare.Delete);
        if (!SetHandleInformation(sentinel, 1, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var inheritedPath = resultPath + ".inherited";
        var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
        var command = new StringBuilder($"\"{executable}\" --probe wait --result-path \"{inheritedPath}\" " +
            $"--handle {sentinel.DangerousGetHandle().ToInt64()} --expected-path \"{sentinelPath}\"");
        if (!CreateProcess(executable, command, 0, 0, true, 0x08000000, 0,
                Path.GetDirectoryName(executable)!, ref startup, out var information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            using var grandchild = Process.GetProcessById(information.ProcessId);
            var inheritedDeadline = Stopwatch.StartNew();
            while (!File.Exists(inheritedPath))
            {
                if (grandchild.HasExited || inheritedDeadline.Elapsed >= TimeSpan.FromSeconds(5))
                    throw new IOException("The inheriting grandchild did not become ready.");
                Thread.Sleep(25);
            }
            using var inheritedEvidence = JsonDocument.Parse(File.ReadAllText(inheritedPath));
            if (!inheritedEvidence.RootElement.GetProperty("inheritedSentinel").GetBoolean())
                throw new IOException("The inherited handle was unusable.");
            WriteEvidenceAtomically(resultPath, new
            {
                processId = grandchild.Id,
                startTimeUtcTicks = grandchild.StartTime.ToUniversalTime().Ticks,
                imagePath = grandchild.MainModule!.FileName,
                inheritedSentinel = true,
            });
            var deadline = Stopwatch.StartNew();
            while (!File.Exists(releasePath))
            {
                if (deadline.Elapsed >= TimeSpan.FromSeconds(30)) return 3;
                Thread.Sleep(25);
            }
            return 0;
        }
        finally
        {
            CloseHandle(information.Thread);
            CloseHandle(information.Process);
        }
    }

    private static void WriteEvidenceAtomically<T>(string resultPath, T evidence)
    {
        var directory = Path.GetDirectoryName(resultPath)
            ?? throw new ArgumentException("The result path has no parent directory.", nameof(resultPath));
        Directory.CreateDirectory(directory);

        var temporaryPath = resultPath + ".tmp." + Environment.ProcessId.ToString("D", System.Globalization.CultureInfo.InvariantCulture);
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.Read,
                       bufferSize: 4 * 1024,
                       options: FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, evidence);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, resultPath);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
            catch
            {
                // The parent test treats an undeleted test directory as a failure.
            }
        }
    }

    private static uint GetFileType(nint handle)
        => GetFileTypeNative(handle);

    [DllImport("kernel32.dll", EntryPoint = "GetStdHandle", SetLastError = true)]
    private static extern nint GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", EntryPoint = "GetFileType", SetLastError = true)]
    private static extern uint GetFileTypeNative(nint handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(nint handle, StringBuilder path, int length, uint flags);

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string applicationName, StringBuilder commandLine,
        nint processAttributes, nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags, nint environment, string currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        internal int Size;
        internal nint Reserved, Desktop, Title;
        internal int X, Y, Width, Height, XCharacters, YCharacters, FillAttribute, Flags;
        internal short ShowWindow, ReservedBytes;
        internal nint ReservedPointer, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal nint Process, Thread;
        internal int ProcessId, ThreadId;
    }

    private sealed record ChildOptions(string ResultPath, int SleepMilliseconds);

    private sealed record StandardHandleEvidence(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("processId")] int ProcessId,
        [property: JsonPropertyName("processStartTimeUtcTicks")] long ProcessStartTimeUtcTicks,
        [property: JsonPropertyName("imagePath")] string ImagePath,
        [property: JsonPropertyName("standardOutputHandleValue")] long StandardOutputHandleValue,
        [property: JsonPropertyName("standardOutputFileType")] uint StandardOutputFileType);
}
