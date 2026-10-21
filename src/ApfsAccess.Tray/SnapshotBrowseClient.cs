using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Tray;

internal sealed record SnapshotBrowseRequest(VerifyScope Scope, SnapshotInventoryEntry Snapshot,
    long SourceSizeBytes, string SourceSha256, string SessionDirectory, string? CopyOut);
internal sealed record SnapshotBrowseExit(int ExitCode, string StandardOutput, string StandardError);
internal sealed record SnapshotBrowseResult(string? CopyDestination, int Files, int Directories, long Bytes);

internal interface ISnapshotBrowseProcess : IDisposable
{
    Task<SnapshotBrowseExit> Completion { get; }
    Task CloseAsync();
}

internal sealed class SnapshotBrowseClient
{
    private readonly Func<SnapshotBrowseRequest, ISnapshotBrowseProcess> _start;
    private readonly Func<string, JsonElement?> _read;
    private readonly TimeSpan _startupTimeout;

    internal SnapshotBrowseClient(Func<SnapshotBrowseRequest, ISnapshotBrowseProcess>? start = null,
        Func<string, JsonElement?>? read = null, TimeSpan? startupTimeout = null)
    {
        _start = start ?? SnapshotBrowseProcess.Start;
        _read = read ?? ReadReady;
        _startupTimeout = startupTimeout ?? TimeSpan.FromSeconds(45);
    }

    internal async Task<SnapshotBrowseResult> RunAsync(SnapshotBrowseRequest request, Action<string> ready,
        Action requireCurrent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        requireCurrent();
        using var process = _start(request);
        var started = Stopwatch.StartNew();
        var readySeen = false;
        string? operationId = null;
        Exception? failure = null;
        try
        {
            while (!process.Completion.IsCompleted)
            {
                cancellationToken.ThrowIfCancellationRequested();
                requireCurrent();
                if (!readySeen)
                {
                    if (_read(Path.Combine(request.SessionDirectory, "ready.json")) is { } state)
                    {
                        operationId = SnapshotBrowseProtocol.Ready(state, request);
                        requireCurrent();
                        readySeen = true;
                        if (request.CopyOut is null) ready(Path.Combine(request.SessionDirectory, "mount"));
                    }
                    else if (started.Elapsed >= _startupTimeout)
                        throw new TimeoutException("The selected snapshot did not become ready. Closing the snapshot session.");
                }
                await Task.WhenAny(process.Completion, Task.Delay(100)).ConfigureAwait(true);
            }
        }
        catch (Exception ex) { failure = ex; }
        if (failure is null && cancellationToken.IsCancellationRequested)
            failure = new OperationCanceledException(cancellationToken);

        // Always request graceful close, including stale selection and readiness failures.
        // Keep the owner alive until the terminal result proves host and mount teardown.
        Exception? closeFailure = null;
        try { await process.CloseAsync().ConfigureAwait(true); }
        catch (Exception ex) { closeFailure = ex; }
        SnapshotBrowseExit terminal;
        try { terminal = await process.Completion.ConfigureAwait(true); }
        catch (Exception ex) { throw new IOException($"Snapshot closure is not confirmed. Evidence: {request.SessionDirectory}", ex); }
        var result = SnapshotBrowseProtocol.Terminal(terminal, request, operationId);
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        if (closeFailure is not null && terminal.ExitCode != 0)
            throw new IOException($"Snapshot close failed. Evidence: {request.SessionDirectory}", closeFailure);
        requireCurrent();
        return result;
    }

    private static JsonElement? ReadReady(string path)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length > 1024 * 1024) throw new InvalidDataException("Snapshot readiness exceeds its size bound.");
            using var json = JsonDocument.Parse(file);
            return json.RootElement.Clone();
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (JsonException) { return null; }
    }
}

internal static class SnapshotBrowseProtocol
{
    internal static string Ready(JsonElement root, SnapshotBrowseRequest request)
    {
        try
        {
            Unique(root);
            Require(root.GetProperty("immutableSnapshot").ValueKind == JsonValueKind.True &&
                root.GetProperty("mountedReadinessProven").ValueKind == JsonValueKind.True);
            Require(SamePath(Text(root, "mountPoint"), Path.Combine(request.SessionDirectory, "mount")));
            Require(OptionalText(root, "copyOut") == request.CopyOut);
            Selection(root.GetProperty("selection"), request);
            var id = Text(root, "operationId"); Require(Guid.TryParseExact(id, "D", out _)); return id;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        { throw new InvalidDataException("Snapshot readiness does not match the selected image snapshot.", ex); }
    }

    internal static SnapshotBrowseResult Terminal(SnapshotBrowseExit exit, SnapshotBrowseRequest request, string? operationId)
    {
        try
        {
            using var document = JsonDocument.Parse(exit.StandardOutput);
            var root = document.RootElement; Unique(root);
            Require(root.GetProperty("schemaVersion").GetInt32() == 2 && Text(root, "command") == "snapshots-browse");
            var id = Text(root, "operationId"); Require(Guid.TryParseExact(id, "D", out _) && (operationId is null || id == operationId));
            Require(SamePath(Text(root, "sessionDirectory"), request.SessionDirectory) &&
                SamePath(Text(root, "supervisorEvidence"), Path.Combine(request.SessionDirectory, "supervisor.json")));
            Require(root.GetProperty("teardownProven").ValueKind == JsonValueKind.True);
            Require(root.GetProperty("exitCode").GetInt32() == exit.ExitCode);
            // Early CLI refusals have no selection. They cannot establish successful work.
            if (root.GetProperty("selection").ValueKind != JsonValueKind.Null) Selection(root.GetProperty("selection"), request);
            if (exit.ExitCode != 0 || root.GetProperty("success").ValueKind != JsonValueKind.True)
                throw new IOException($"Snapshot operation failed; copy destination may be partial. Evidence: {request.SessionDirectory}. " +
                    (OptionalText(root, "error") ?? Text(root, "code")));
            Require(Text(root, "code") == ApfsAccess.Ipc.ApfsOperationCodes.OperationSucceeded && root.GetProperty("mountedReadinessProven").ValueKind == JsonValueKind.True);
            Selection(root.GetProperty("selection"), request);
            Require(SamePath(Text(root, "mountPoint"), Path.Combine(request.SessionDirectory, "mount")));
            var copy = root.GetProperty("copyOut");
            if (request.CopyOut is null) { Require(copy.ValueKind == JsonValueKind.Null); return new(null, 0, 0, 0); }
            Require(copy.ValueKind == JsonValueKind.Object);
            var files = copy.GetProperty("files").GetInt32(); var directories = copy.GetProperty("directories").GetInt32();
            var bytes = copy.GetProperty("bytes").GetInt64(); Require(files >= 0 && directories >= 1 && bytes >= 0);
            return new(request.CopyOut, files, directories, bytes);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or InvalidDataException)
        { throw new IOException($"Snapshot closure or result identity is not confirmed. Evidence: {request.SessionDirectory}", ex); }
    }

    private static void Selection(JsonElement selection, SnapshotBrowseRequest request)
    {
        Unique(selection);
        var s = request.Scope;
        Require(SamePath(Text(selection, "image"), s.ImagePath) && selection.GetProperty("sourceSizeBytes").GetInt64() == request.SourceSizeBytes &&
            Text(selection, "sourceSha256") == request.SourceSha256 && Text(selection, "containerUuid") == s.ContainerId[15..] &&
            Text(selection, "volumeUuid") == s.VolumeUuid && Text(selection, "volumeOid") == s.VolumeObjectId &&
            Text(selection, "checkpointXid") == s.CheckpointXid && Text(selection, "storeOffsetBytes") == s.StoreOffsetBytes &&
            Text(selection, "storeSizeBytes") == s.StoreSizeBytes && Text(selection, "snapshotXid") == request.Snapshot.Xid &&
            Text(selection, "name") == request.Snapshot.Name && request.Snapshot.NativeIdentity is { });
        Require(JsonNode.DeepEquals(JsonNode.Parse(selection.GetProperty("snapshot").GetRawText()),
            JsonNode.Parse(request.Snapshot.NativeIdentity!.Value.GetRawText())));
    }

    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in element.EnumerateObject()) { Require(names.Add(p.Name)); Unique(p.Value); }
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) Unique(item);
    }
    private static string Text(JsonElement root, string name) => root.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing snapshot evidence.");
    private static string? OptionalText(JsonElement root, string name) => root.GetProperty(name).ValueKind == JsonValueKind.Null ? null : Text(root, name);
    private static bool SamePath(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static void Require(bool condition) { if (!condition) throw new InvalidDataException("Snapshot evidence does not match the selected identity."); }
}

internal sealed class SnapshotBrowseProcess : ISnapshotBrowseProcess
{
    private readonly Process _process;
    private readonly object _closeGate = new();
    private Task? _close;
    public Task<SnapshotBrowseExit> Completion { get; }

    private SnapshotBrowseProcess(Process process)
    { _process = process; Completion = CompleteAsync(); }

    internal static ProcessStartInfo StartInfo(SnapshotBrowseRequest request, string executable)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false, true), StandardOutputEncoding = new UTF8Encoding(false, true),
            StandardErrorEncoding = new UTF8Encoding(false, true) };
        foreach (var arg in new[] { "snapshots", "browse", "--image", request.Scope.ImagePath, "--container-id", request.Scope.ContainerId,
            "--volume-oid", request.Scope.VolumeObjectId, "--snapshot-xid", request.Snapshot.Xid,
            "--session-dir", request.SessionDirectory, "--close-on-stdin", "--json" }) start.ArgumentList.Add(arg);
        if (request.CopyOut is not null) { start.ArgumentList.Add("--copy-out"); start.ArgumentList.Add(request.CopyOut); }
        return start;
    }

    internal static ISnapshotBrowseProcess Start(SnapshotBrowseRequest request)
    {
        if (Directory.Exists(request.SessionDirectory) || File.Exists(request.SessionDirectory))
            throw new InvalidOperationException("A snapshot session needs a new private directory; old readiness cannot be reused.");
        var executable = Path.Combine(AppContext.BaseDirectory, "ApfsAccess.Cli.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("The packaged snapshot CLI is unavailable.", executable);
        return Start(StartInfo(request, executable));
    }

    internal static ISnapshotBrowseProcess Start(ProcessStartInfo start)
        => new SnapshotBrowseProcess(Process.Start(start) ?? throw new IOException("Cannot start the packaged browse CLI."));

    public Task CloseAsync() { lock (_closeGate) return _close ??= CloseCoreAsync(); }
    private async Task CloseCoreAsync()
    {
        try { await _process.StandardInput.WriteAsync("close\n").ConfigureAwait(false); await _process.StandardInput.FlushAsync().ConfigureAwait(false); }
        catch (IOException) { }
        finally { _process.StandardInput.Close(); }
    }

    private async Task<SnapshotBrowseExit> CompleteAsync()
    {
        var stdout = ReadBoundedAsync(_process.StandardOutput); var stderr = ReadBoundedAsync(_process.StandardError);
        await _process.WaitForExitAsync().ConfigureAwait(false);
        return new(_process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    private async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        var text = new StringBuilder(); var buffer = new char[4096]; var overflow = false;
        int count;
        while ((count = await reader.ReadAsync(buffer).ConfigureAwait(false)) != 0)
        {
            if (text.Length + count <= 2 * 1024 * 1024 && !overflow) text.Append(buffer, 0, count);
            else { overflow = true; await CloseAsync().ConfigureAwait(false); }
        }
        if (overflow) throw new InvalidDataException("Snapshot CLI output exceeded its size bound.");
        return text.ToString();
    }

    public void Dispose() => _process.Dispose();
}
