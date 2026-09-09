using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class SnapshotCommand
{
    internal const string Usage = "snapshots list --image ABSOLUTE_FILE --container-id APFS_CONTAINER_ID --volume-oid OID [--json]";

    internal static int Run(string[] args, Func<string, string, string, JsonElement>? read = null, CancellationToken cancellationToken = default)
    {
        var exit = 0;
        var code = ApfsOperationCodes.OperationSucceeded;
        string? error = null;
        JsonElement? inventory = null;
        var help = args is ["help"] or ["--help"] or ["list", "--help"];
        try
        {
            if (!help)
            {
                if (args.Length == 0 || args[0] != "list") throw new ArgumentException(Usage);
                var values = new Dictionary<string, string>(StringComparer.Ordinal);
                var json = false;
                for (var i = 1; i < args.Length; i++)
                {
                    var flag = args[i];
                    if (flag == "--json" && !json) { json = true; continue; }
                    if (flag is not ("--image" or "--container-id" or "--volume-oid") || ++i >= args.Length ||
                        args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(flag, args[i]))
                        throw new ArgumentException(Usage);
                }
                if (values.Count != 3) throw new ArgumentException(Usage);
                var image = values["--image"]; var container = values["--container-id"]; var oid = values["--volume-oid"];
                NativeApfsSnapshotReader.ValidateRequest(image, container, oid);
                cancellationToken.ThrowIfCancellationRequested();
                if (read is null)
                {
                    using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
                    Console.CancelKeyPress += handler;
                    try { inventory = new NativeApfsSnapshotReader().Read(image, container, oid, cancellation.Token); }
                    finally { Console.CancelKeyPress -= handler; }
                }
                else inventory = read(image, container, oid);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        catch (ArgumentException ex) { exit = 2; code = ApfsOperationCodes.InvalidArguments; error = ex.Message; }
        catch (FileNotFoundException ex) { exit = 3; code = ApfsOperationCodes.ServiceUnavailable; error = ex.Message; }
        catch (Win32Exception ex) { exit = 3; code = ApfsOperationCodes.ServiceUnavailable; error = ex.Message; }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        { exit = 4; code = ApfsOperationCodes.Timeout; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = ApfsOperationCodes.OperationFailed; error = ex.Message; }
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = "snapshots", operationId = Guid.NewGuid().ToString("D"),
            success = exit == 0, exitCode = exit, code, resultCode = code, errorCode = exit == 0 ? null : code,
            message = error, error, inventory, usage = help ? Usage : null,
            description = help ? "Read-only snapshot inventory for a regular local image. Use the canonical apfs-container:lowercase32hex identity and a nonzero decimal volume OID." : null
        }, new JsonSerializerOptions { WriteIndented = true }));
        return exit;
    }
}
