using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class VerifyCommand
{
    internal const string Usage = "verify --image ABSOLUTE_FILE --container-id apfs-container:hex32 --volume-uuid hex32 --volume-oid OID --checkpoint-xid XID --store-offset-bytes N --store-size-bytes N [--require-whole-volume] [--require-payload-content-hashes] [--json]";
    internal const string Description = "Read-only regular local image verification. Complete verifies only the covered current metadata subset; inspect every coverage entry and finding. Whole-volume and payload-content-hash verification are unavailable in v1. UUIDs must be nonzero lowercase hex32; IDs and byte ranges must be canonical decimal uint64 strings. Exact scope is required; no volume or checkpoint is selected implicitly. JSON is the default output. Exits: 0 subset complete, 3 incomplete, 4 refused, 2 invalid arguments, 5 observer/protocol failure, 6 timeout, 12 cancelled.";

    internal static int Run(string[] args, Func<ApfsImageVerificationRequest, CancellationToken, ApfsImageVerificationResult>? verify = null,
        CancellationToken cancellationToken = default)
    {
        var exit = 0; var code = "VerificationHelp"; string? error = null;
        int? nativeExit = null; ApfsImageVerificationResult? result = null;
        var help = args is ["help"] or ["--help"];
        try
        {
            if (!help)
            {
                var request = ParseArguments(args);
                NativeApfsImageVerifier.ValidateRequest(request);
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
                Console.CancelKeyPress += handler;
                try
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    result = (verify ?? new NativeApfsImageVerifier().Verify)(request, cancellation.Token);
                    cancellation.Token.ThrowIfCancellationRequested();
                }
                finally { Console.CancelKeyPress -= handler; }
                exit = result.NativeExitCode; nativeExit = exit;
                code = result.Outcome switch { ApfsVerificationOutcome.Complete => "CurrentMetadataSubsetVerified",
                    ApfsVerificationOutcome.Incomplete => "VerificationIncomplete", _ => "VerificationRefused" };
            }
        }
        catch (ArgumentException ex) { exit = 2; code = "InvalidArguments"; error = ex.Message; }
        catch (NativeVerificationExitException ex) { exit = 5; code = "NativeVerificationFailed"; nativeExit = ex.NativeExitCode; error = ex.Message; }
        catch (FileNotFoundException ex) { exit = 5; code = "ObserverUnavailable"; error = ex.Message; }
        catch (Win32Exception ex) { exit = 5; code = "ObserverLaunchFailed"; error = ex.Message; }
        catch (TimeoutException ex) { exit = 6; code = "VerificationTimeout"; error = ex.Message; }
        catch (OperationCanceledException ex) { exit = 12; code = "VerificationCancelled"; error = ex.Message; }
        catch (InvalidDataException ex) { exit = 5; code = "InvalidVerificationOutput"; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = "VerificationFailed"; error = ex.Message; }
        // A transport/protocol failure never publishes a previously assigned result.
        if (error is not null) result = null;
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = "verify", operationId = Guid.NewGuid().ToString("D"),
            success = exit == 0, exitCode = exit, nativeExitCode = nativeExit, code, resultCode = code,
            errorCode = exit == 0 ? null : code, message = error ?? (help ? Description :
                result?.Outcome == ApfsVerificationOutcome.Complete ? "The covered current metadata subset passed verification." : "See verification findings and coverage."),
            error, verification = result?.Report, usage = help ? Usage : null, description = help ? Description : null
        }, new JsonSerializerOptions { WriteIndented = true }));
        return exit;
    }

    internal static ApfsImageVerificationRequest ParseArguments(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var switches = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var flag = args[i];
            if (flag is "--json" or "--require-whole-volume" or "--require-payload-content-hashes")
            { if (!switches.Add(flag)) throw new ArgumentException(Usage); continue; }
            if (flag is not ("--image" or "--container-id" or "--volume-uuid" or "--volume-oid" or "--checkpoint-xid" or "--store-offset-bytes" or "--store-size-bytes") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(flag, args[i]))
                throw new ArgumentException(Usage);
        }
        if (values.Count != 7) throw new ArgumentException(Usage);
        return new(values["--image"], values["--container-id"], values["--volume-uuid"], values["--volume-oid"],
            values["--checkpoint-xid"], values["--store-offset-bytes"], values["--store-size-bytes"],
            switches.Contains("--require-whole-volume"), switches.Contains("--require-payload-content-hashes"));
    }
}
