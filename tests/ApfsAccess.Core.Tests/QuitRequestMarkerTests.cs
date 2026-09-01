using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class QuitRequestMarkerTests
{
    [Fact]
    public void ShouldHonorMarker_ReturnsTrueOnlyForMarkersFromCurrentOrLaterSession()
    {
        var sessionStartedUtc = new DateTime(2026, 8, 13, 5, 0, 0, DateTimeKind.Utc);

        Assert.True(QuitRequestMarker.ShouldHonorMarker(
            sessionStartedUtc,
            sessionStartedUtc));
        Assert.True(QuitRequestMarker.ShouldHonorMarker(
            sessionStartedUtc.AddSeconds(90),
            sessionStartedUtc));
        Assert.False(QuitRequestMarker.ShouldHonorMarker(
            sessionStartedUtc.AddSeconds(-1),
            sessionStartedUtc));
        Assert.False(QuitRequestMarker.ShouldHonorMarker(
            DateTime.MinValue,
            sessionStartedUtc));
    }

    [Fact]
    public void WriteReadClear_RoundTripsTimestampAtExplicitPath()
    {
        var markerPath = BuildMarkerPath();

        try
        {
            var written = new DateTime(2026, 8, 13, 5, 1, 17, DateTimeKind.Utc);
            Assert.True(QuitRequestMarker.WriteMarker(written, markerPath));
            Assert.Equal(written, QuitRequestMarker.TryReadMarkerTimestampUtc(markerPath));

            QuitRequestMarker.ClearMarker(markerPath);
            Assert.Null(QuitRequestMarker.TryReadMarkerTimestampUtc(markerPath));
        }
        finally
        {
            QuitRequestMarker.ClearMarker(markerPath);
        }
    }

    [Fact]
    public void TryReadMarkerTimestampUtc_ReturnsNullForAbsentOrMalformedMarker()
    {
        var markerPath = BuildMarkerPath();

        try
        {
            Assert.Null(QuitRequestMarker.TryReadMarkerTimestampUtc(markerPath));

            Directory.CreateDirectory(Path.GetDirectoryName(markerPath)!);
            File.WriteAllText(markerPath, "not-a-timestamp");
            Assert.Null(QuitRequestMarker.TryReadMarkerTimestampUtc(markerPath));

            File.WriteAllText(markerPath, string.Empty);
            Assert.Null(QuitRequestMarker.TryReadMarkerTimestampUtc(markerPath));
        }
        finally
        {
            QuitRequestMarker.ClearMarker(markerPath);
        }
    }

    [Fact]
    public void WriteMarker_OverwritesExistingMarkerAtomically()
    {
        var markerPath = BuildMarkerPath();

        try
        {
            var first = new DateTime(2026, 8, 13, 5, 0, 0, DateTimeKind.Utc);
            var second = new DateTime(2026, 8, 13, 5, 1, 0, DateTimeKind.Utc);

            Assert.True(QuitRequestMarker.WriteMarker(first, markerPath));
            Assert.True(QuitRequestMarker.WriteMarker(second, markerPath));

            Assert.Equal(second, QuitRequestMarker.TryReadMarkerTimestampUtc(markerPath));
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(markerPath)!, "*.tmp"));
        }
        finally
        {
            QuitRequestMarker.ClearMarker(markerPath);
        }
    }

    private static string BuildMarkerPath()
        => Path.Combine(
            Path.GetTempPath(),
            "apfsaccess-quit-marker-tests",
            Guid.NewGuid().ToString("N"),
            "temp",
            "ApfsAccess",
            "quit-requested");
}