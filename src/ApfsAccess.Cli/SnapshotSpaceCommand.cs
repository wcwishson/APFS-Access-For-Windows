using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class SnapshotSpaceCommand
{
    internal const string Usage = "snapshots space --image ABSOLUTE_FILE --container-id APFS_CONTAINER_ID --volume-uuid HEX32 " +
        "--volume-oid OID --checkpoint-xid XID --store-offset-bytes OFFSET --store-size-bytes SIZE [--json]";

    internal static ApfsSnapshotAttributionRequest Parse(string[] args)
    {
        if (args.Length == 0 || args[0] != "space") throw new ArgumentException(Usage);
        var flags = new HashSet<string>(["--image", "--container-id", "--volume-uuid", "--volume-oid",
            "--checkpoint-xid", "--store-offset-bytes", "--store-size-bytes"], StringComparer.Ordinal);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var json = false;
        for (var index = 1; index < args.Length; ++index)
        {
            var flag = args[index];
            if (flag == "--json" && !json) { json = true; continue; }
            if (!flags.Contains(flag) || ++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal) ||
                !values.TryAdd(flag, args[index])) throw new ArgumentException(Usage);
        }
        if (values.Count != flags.Count) throw new ArgumentException(Usage);
        var result = new ApfsSnapshotAttributionRequest(values["--image"], values["--container-id"], values["--volume-uuid"],
            values["--volume-oid"], values["--checkpoint-xid"], values["--store-offset-bytes"], values["--store-size-bytes"]);
        NativeApfsImageVerifier.ValidateSnapshotAttributionRequest(result);
        return result;
    }

    internal static int Run(string[] args, Func<ApfsSnapshotAttributionRequest, CancellationToken, ApfsSnapshotAttributionResult>? read = null,
        CancellationToken cancellationToken = default)
    {
        var help = args is ["space", "--help"] or ["space", "help"];
        var exit = 0;
        var code = "SnapshotSpaceAttributed";
        string? error = null;
        int? nativeExit = null;
        JsonElement? observation = null;
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stopping.Cancel(); };
        Console.CancelKeyPress += handler;
        try
        {
            if (!help)
            {
                var request = Parse(args);
                stopping.Token.ThrowIfCancellationRequested();
                var result = read is null ? new NativeApfsImageVerifier().ObserveSnapshotAttribution(request, stopping.Token)
                    : read(request, stopping.Token);
                stopping.Token.ThrowIfCancellationRequested();
                if (result.NativeExitCode != (result.Complete ? 0 : 3) || result.Report.ValueKind != JsonValueKind.Object ||
                    result.Report.GetProperty("complete").GetBoolean() != result.Complete)
                    throw new InvalidDataException("Snapshot accounting returned an inconsistent terminal result.");
                observation = result.Report;
                nativeExit = result.NativeExitCode;
                if (!result.Complete) { exit = 3; code = "SnapshotSpaceUnknown"; }
            }
            else code = ApfsOperationCodes.OperationSucceeded;
        }
        catch (ArgumentException ex) { exit = 2; code = ApfsOperationCodes.InvalidArguments; error = ex.Message; }
        catch (NativeVerificationExitException ex) { exit = 5; code = "NativeSnapshotSpaceFailed"; nativeExit = ex.NativeExitCode; error = ex.Message; }
        catch (Exception ex) when (ex is FileNotFoundException or Win32Exception)
        { exit = 3; code = ApfsOperationCodes.ServiceUnavailable; error = ex.Message; }
        catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
        { exit = 4; code = ApfsOperationCodes.Timeout; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = "InvalidSnapshotSpaceOutput"; error = ex.Message; }
        finally { Console.CancelKeyPress -= handler; }
        if (exit is not (0 or 3) || error is not null) observation = null;
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = "snapshots-space", operationId = Guid.NewGuid().ToString("D"),
            success = exit == 0, exitCode = exit, nativeExitCode = nativeExit, code, errorCode = exit == 0 ? null : code,
            error, observation, usage = help ? Usage : null,
            description = help ? "Read snapshot metadata and file-data footprints. Shared blocks are counted once. Potential reclaim is only an upper bound; Apple purgeability and exact deletion savings remain unknown." : null
        }, new JsonSerializerOptions { WriteIndented = true }));
        return exit;
    }
}
