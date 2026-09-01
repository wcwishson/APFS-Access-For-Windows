using System.Globalization;

namespace ApfsAccess.Core;

public static class QuitRequestMarker
{
    private const string MarkerFileName = "quit-requested";

    public static string ResolveMarkerPath()
    {
        var runtimeRoot = Environment.GetEnvironmentVariable("APFSACCESS_RUNTIME_ROOT");
        var baseRoot = !string.IsNullOrWhiteSpace(runtimeRoot)
            ? runtimeRoot
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ApfsAccess");
        return Path.Combine(baseRoot, "temp", "ApfsAccess", MarkerFileName);
    }

    public static bool WriteMarker(DateTime timestampUtc, string? markerPath = null)
    {
        try
        {
            var path = markerPath ?? ResolveMarkerPath();
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = $"{path}.{Guid.NewGuid():N}.tmp";
            File.WriteAllText(tempPath, timestampUtc.ToString("O", CultureInfo.InvariantCulture));
            File.Move(tempPath, path, overwrite: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static DateTime? TryReadMarkerTimestampUtc(string? markerPath = null)
    {
        try
        {
            var path = markerPath ?? ResolveMarkerPath();
            if (!File.Exists(path))
            {
                return null;
            }

            var content = File.ReadAllText(path).Trim();
            if (string.IsNullOrWhiteSpace(content))
            {
                return null;
            }

            return DateTime.TryParse(
                content,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed)
                ? parsed
                : null;
        }
        catch
        {
            return null;
        }
    }

    public static void ClearMarker(string? markerPath = null)
    {
        try
        {
            var path = markerPath ?? ResolveMarkerPath();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    public static bool ShouldHonorMarker(DateTime markerTimestampUtc, DateTime sessionStartedUtc)
        => markerTimestampUtc >= sessionStartedUtc;
}