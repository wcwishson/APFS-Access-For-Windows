using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

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

    private static void WriteEvidenceAtomically(string resultPath, StandardHandleEvidence evidence)
    {
        var directory = Path.GetDirectoryName(resultPath)
            ?? throw new ArgumentException("The result path has no parent directory.", nameof(resultPath));
        Directory.CreateDirectory(directory);

        var temporaryPath = resultPath + ".tmp." + evidence.ProcessId.ToString("D", System.Globalization.CultureInfo.InvariantCulture);
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

    private sealed record ChildOptions(string ResultPath, int SleepMilliseconds);

    private sealed record StandardHandleEvidence(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("processId")] int ProcessId,
        [property: JsonPropertyName("processStartTimeUtcTicks")] long ProcessStartTimeUtcTicks,
        [property: JsonPropertyName("imagePath")] string ImagePath,
        [property: JsonPropertyName("standardOutputHandleValue")] long StandardOutputHandleValue,
        [property: JsonPropertyName("standardOutputFileType")] uint StandardOutputFileType);
}
