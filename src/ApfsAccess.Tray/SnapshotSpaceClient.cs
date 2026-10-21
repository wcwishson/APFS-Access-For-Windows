using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

public sealed record SnapshotSpaceRow(string Name, string Xid, ulong MetadataBytes, ulong PayloadBytes,
    ulong SharedWithLiveBytes, ulong PotentialReclaimUpperBoundBytes);

public sealed record SnapshotSpaceSummary(bool Complete, string Summary, IReadOnlyList<SnapshotSpaceRow> Snapshots)
{
    public string Details => Summary + (Snapshots.Count == 0 ? "" : "\r\n\r\n" + string.Join("\r\n", Snapshots.Select(s =>
        $"{s.Name} (XID {s.Xid}): metadata {s.MetadataBytes:N0} bytes; data {s.PayloadBytes:N0} bytes; " +
        $"data shared with current files {s.SharedWithLiveBytes:N0} bytes; potential reclaim upper bound {s.PotentialReclaimUpperBoundBytes:N0} bytes.")));
}

internal sealed record SnapshotSpaceExit(int ExitCode, string StandardOutput);

public sealed class SnapshotSpaceClient
{
    private const int MaxOutputCharacters = 64 * 1024 * 1024;
    private readonly Func<VerifyScope, CancellationToken, Task<SnapshotSpaceExit>> _run;
    public SnapshotSpaceClient() : this(RunProcessAsync) { }
    internal SnapshotSpaceClient(Func<VerifyScope, CancellationToken, Task<SnapshotSpaceExit>> run) => _run = run;

    public async Task<SnapshotSpaceSummary> RunAsync(VerifyScope scope, Action requireCurrent, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(requireCurrent);
        token.ThrowIfCancellationRequested();
        requireCurrent();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var exit = await _run(scope, deadline.Token).ConfigureAwait(true);
        deadline.Token.ThrowIfCancellationRequested();
        var result = Parse(exit, scope);
        requireCurrent();
        token.ThrowIfCancellationRequested();
        return result;
    }

    internal static ProcessStartInfo StartInfo(VerifyScope scope, string executable)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false, true), StandardErrorEncoding = new UTF8Encoding(false, true) };
        foreach (var arg in new[] { "snapshots", "space", "--image", scope.ImagePath, "--container-id", scope.ContainerId,
            "--volume-uuid", scope.VolumeUuid, "--volume-oid", scope.VolumeObjectId, "--checkpoint-xid", scope.CheckpointXid,
            "--store-offset-bytes", scope.StoreOffsetBytes, "--store-size-bytes", scope.StoreSizeBytes, "--json" })
            start.ArgumentList.Add(arg);
        return start;
    }

    private static async Task<SnapshotSpaceExit> RunProcessAsync(VerifyScope scope, CancellationToken token)
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "ApfsAccess.Cli.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("The packaged snapshot CLI is unavailable.", executable);
        using var process = Process.Start(StartInfo(scope, executable)) ?? throw new IOException("Cannot start snapshot space observation.");
        void Stop()
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        using var cancel = token.Register(Stop);
        async Task<string> ReadAsync(StreamReader reader)
        {
            var text = new StringBuilder(); var buffer = new char[4096];
            while (true)
            {
                var count = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                if (count == 0) return text.ToString();
                if (count > MaxOutputCharacters - text.Length)
                { Stop(); throw new InvalidDataException("Snapshot space output exceeds its size bound."); }
                text.Append(buffer, 0, count);
            }
        }
        var stdout = ReadAsync(process.StandardOutput); var stderr = ReadAsync(process.StandardError);
        try
        {
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(token)).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return new(process.ExitCode, await stdout.ConfigureAwait(false));
        }
        finally
        {
            Stop();
            if (!process.HasExited)
                // Cancellation detaches the view, not the owned child handle.
                // Keep awaiting retirement instead of turning a wait timeout
                // into an apparent closed observation.
                await process.WaitForExitAsync().ConfigureAwait(false);
        }
    }

    internal static SnapshotSpaceSummary Parse(SnapshotSpaceExit exit, VerifyScope scope)
    {
        try
        {
            Require(exit.StandardOutput.Length <= MaxOutputCharacters);
            using var document = JsonDocument.Parse(exit.StandardOutput);
            var root = document.RootElement; Unique(root);
            Require(root.GetProperty("schemaVersion").GetInt32() == 2 && Text(root, "command") == "snapshots-space" &&
                Guid.TryParseExact(Text(root, "operationId"), "D", out _) && root.GetProperty("exitCode").GetInt32() == exit.ExitCode);
            if (exit.ExitCode is not (0 or 3) || root.GetProperty("observation").ValueKind != JsonValueKind.Object)
                throw new InvalidDataException(root.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String
                    ? e.GetString() : "Snapshot space observation failed.");
            var report = root.GetProperty("observation");
            var complete = report.GetProperty("complete").GetBoolean();
            Require(report.GetProperty("version").GetInt32() == 1 && report.GetProperty("readOnly").GetBoolean() &&
                Text(report, "format") == "apfs-access-snapshot-space-attribution" &&
                root.GetProperty("success").GetBoolean() == complete && exit.ExitCode == (complete ? 0 : 3) &&
                root.GetProperty("nativeExitCode").GetInt32() == exit.ExitCode &&
                Text(root, "code") == (complete ? "SnapshotSpaceAttributed" : "SnapshotSpaceUnknown") &&
                root.GetProperty("error").ValueKind == JsonValueKind.Null && root.GetProperty("usage").ValueKind == JsonValueKind.Null &&
                Text(report.GetProperty("source"), "path") == scope.ImagePath &&
                Text(report.GetProperty("source"), "identity").StartsWith("windows-file:", StringComparison.Ordinal));
            var actual = report.GetProperty("scope");
            Require(scope.ContainerId.StartsWith("apfs-container:", StringComparison.Ordinal) &&
                Text(actual, "containerUuid") == scope.ContainerId[15..] && Text(actual, "volumeUuid") == scope.VolumeUuid &&
                Text(actual, "volumeOid") == scope.VolumeObjectId && Text(actual, "checkpointXid") == scope.CheckpointXid &&
                Text(actual, "storeOffsetBytes") == scope.StoreOffsetBytes && Text(actual, "storeSizeBytes") == scope.StoreSizeBytes);
            if (!complete)
            {
                Require(report.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal)
                    .SetEquals(["format", "version", "readOnly", "complete", "source", "scope", "reason"]));
                var reason = Text(report, "reason"); Require(reason.Length is > 0 and <= 65535 && !reason.Contains('\0'));
                return new(false, "Snapshot space is unknown for this image. " + reason, []);
            }
            var unit = report.GetProperty("allocationUnitBytes").GetUInt32();
            var size = Number(actual, "storeSizeBytes");
            Require(unit is >= 4096 and <= 65536 && (unit & (unit - 1)) == 0 && size > 0 && size % unit == 0);
            var metadata = Amount(report.GetProperty("referencedMetadata"), size, unit);
            var payload = Amount(report.GetProperty("referencedPayload"), size, unit);
            var catalog = Amount(report.GetProperty("catalogMetadata"), size, unit);
            Require(catalog > 0 && metadata <= catalog && payload <= size - catalog);
            var rows = report.GetProperty("snapshots"); Require(rows.ValueKind == JsonValueKind.Array && rows.GetArrayLength() <= 4096);
            var output = new List<SnapshotSpaceRow>(); var names = new HashSet<string>(StringComparer.Ordinal); ulong prior = 0;
            foreach (var row in rows.EnumerateArray())
            {
                var xid = Number(row, "snapshotXid"); var name = Text(row, "name");
                Require(xid > prior && xid <= Number(actual, "checkpointXid") && name.Length is > 0 and <= 65535 &&
                    !name.Contains('\0') && names.Add(name) && row.GetProperty("applePurgeable").ValueKind == JsonValueKind.Null &&
                    row.GetProperty("reclaimable").ValueKind == JsonValueKind.Null && Amount(row.GetProperty("purgeableMarkedPayload"), size, unit) == 0);
                prior = xid;
                var m = Amount(row.GetProperty("metadata").GetProperty("referenced"), size, unit);
                var p = Amount(row.GetProperty("payload").GetProperty("referenced"), size, unit);
                var shared = Amount(row.GetProperty("payload").GetProperty("sharedWithLive"), size, unit);
                var bound = Amount(row.GetProperty("payload").GetProperty("potentialReclaimUpperBound"), size, unit);
                Require(m > 0 && m <= metadata && p <= payload && shared <= p && bound <= p - shared);
                output.Add(new(name, xid.ToString(CultureInfo.InvariantCulture), m, p, shared, bound));
            }
            Require(output.Count > 0 || metadata == 0 && payload == 0);
            return new(true, $"Snapshot references: metadata {metadata:N0} bytes; file data {payload:N0} bytes. " +
                "Shared blocks are counted once in these totals. Apple purgeability and exact deletion savings are unknown.", output.AsReadOnly());
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        { throw new InvalidDataException("Snapshot space output does not match the selected volume.", ex); }
    }

    private static ulong Amount(JsonElement value, ulong capacity, uint unit)
    {
        var bytes = Number(value, "bytes"); Require(bytes <= capacity && checked(Number(value, "blocks") * unit) == bytes); return bytes;
    }
    private static ulong Number(JsonElement value, string key)
    {
        var text = Text(value, key);
        Require(ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number) &&
            text == number.ToString(CultureInfo.InvariantCulture)); return number;
    }
    private static string Text(JsonElement value, string key) => value.GetProperty(key).GetString() ?? throw new InvalidDataException("Missing snapshot field.");
    private static void Require(bool value) { if (!value) throw new InvalidDataException("Invalid snapshot space output."); }
    private static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in value.EnumerateObject()) { Require(names.Add(p.Name)); Unique(p.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
    }
}
