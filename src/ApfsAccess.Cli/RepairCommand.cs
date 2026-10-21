using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class RepairCommand
{
    internal const string Usage = "repair --image ABSOLUTE_FILE --container-id apfs-container:hex32 --volume-uuid hex32 --volume-oid OID --checkpoint-xid XID --store-offset-bytes N --store-size-bytes N --journal ABSOLUTE_FILE --evidence-dir ABSOLUTE_DIR [--expected-count N --confirm] [--approval-mode exact-source-v1 [--approved-source-identity ID --approved-source-sha256 HEX64]]";
    internal const string Description = "Bounded offline RCT2 (APSB regular-file count) repair. Without --confirm, prepares and displays a new plan without mutation (exit 3 when a finding exists, 0 when healthy). Passing the original journal of an accepted interrupted repair resumes that approved work and may write without a new confirmation. With --confirm plus the exact displayed --expected-count, applies once and post-verifies (exit 0). For source-bound approval, prepare with --approval-mode exact-source-v1, then keep that mode and supply the displayed --approved-source-identity and --approved-source-sha256 with the count and --confirm. The native tool requires the same image identity and complete image bytes at apply; changed content requires a fresh plan. The native process generates and consumes its own one-use confirmation token internally; the CLI carries only intent. Refusals (exit 4) leave image bytes unchanged: snapshot-bearing, concurrent owner, foreign journal, wrong selectors, Fusion/encrypted/whole-volume shapes. Exits: 0 repaired/healthy and verified, 3 needs confirmation, 4 refused, 2 invalid arguments, 5 tool/transport failure, 6 timeout, 12 cancelled.";

    internal static int Run(string[] args, Func<ApfsVolumeRepairRequest, CancellationToken, ApfsVolumeRepairResult>? repair = null,
        CancellationToken cancellationToken = default)
    {
        var exit = 0; var code = "RepairHelp"; string? error = null;
        int? nativeExit = null; ApfsVolumeRepairResult? result = null;
        var help = args is ["help"] or ["--help"];
        try
        {
            if (!help)
            {
                var request = ParseArguments(args);
                NativeApfsVolumeRepair.ValidateRequest(request);
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
                Console.CancelKeyPress += handler;
                try
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    result = (repair ?? new NativeApfsVolumeRepair().Repair)(request, cancellation.Token);
                    cancellation.Token.ThrowIfCancellationRequested();
                }
                finally { Console.CancelKeyPress -= handler; }
                exit = result.NativeExitCode; nativeExit = exit;
                code = result.Outcome switch
                {
                    ApfsRepairOutcome.RepairedAndVerified => "RepairedAndVerified",
                    ApfsRepairOutcome.HealthyNoFinding => "RepairHealthyNoFinding",
                    ApfsRepairOutcome.NeedsConfirmation => "RepairNeedsConfirmation",
                    _ => "RepairRefused",
                };
            }
        }
        catch (ArgumentException ex) { exit = 2; code = "InvalidArguments"; error = ex.Message; }
        catch (NativeRepairExitException ex) { exit = 5; code = "NativeRepairFailed"; nativeExit = ex.NativeExitCode; error = ex.Message; }
        catch (FileNotFoundException ex) { exit = 5; code = "RepairToolUnavailable"; error = ex.Message; }
        catch (Win32Exception ex) { exit = 5; code = "RepairToolLaunchFailed"; error = ex.Message; }
        catch (TimeoutException ex) { exit = 6; code = "RepairTimeout"; error = ex.Message; }
        catch (OperationCanceledException ex) { exit = 12; code = "RepairCancelled"; error = ex.Message; }
        catch (InvalidDataException ex) { exit = 5; code = "InvalidRepairOutput"; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = "RepairFailed"; error = ex.Message; }
        // A transport/protocol failure never publishes a previously assigned result.
        if (error is not null) result = null;
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = "repair", operationId = Guid.NewGuid().ToString("D"),
            success = exit == 0, exitCode = exit, nativeExitCode = nativeExit, code, resultCode = code,
            errorCode = exit == 0 ? null : code, message = error ?? (help ? Description :
                result?.Outcome == ApfsRepairOutcome.RepairedAndVerified ? "The count was repaired and post-verified." :
                result?.Outcome == ApfsRepairOutcome.HealthyNoFinding ? "No repair finding; the image is unchanged." :
                result?.Outcome == ApfsRepairOutcome.NeedsConfirmation ? ConfirmationMessage(result) :
                "See the repair report; refused operations leave image bytes unchanged."),
            error, repair = result?.Report, usage = help ? Usage : null, description = help ? Description : null
        }, new JsonSerializerOptions { WriteIndented = true }));
        return exit;
    }

    private static string ConfirmationMessage(ApfsVolumeRepairResult result)
        => result.Report.TryGetProperty("version", out var version) && version.ValueKind == JsonValueKind.Number &&
            version.TryGetInt32(out var value) && value == 2
            ? "A source-bound repair plan is prepared; retain --approval-mode exact-source-v1 and supply the displayed --approved-source-identity, --approved-source-sha256 and --expected-count plus --confirm to apply."
            : "A repair plan is prepared; rerun with the exact --expected-count plus --confirm to apply.";

    internal static ApfsVolumeRepairRequest ParseArguments(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var switches = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var flag = args[i];
            if (flag is "--confirm")
            { if (!switches.Add(flag)) throw new ArgumentException(Usage); continue; }
            if (flag is not ("--image" or "--container-id" or "--volume-uuid" or "--volume-oid" or "--checkpoint-xid" or
                    "--store-offset-bytes" or "--store-size-bytes" or "--journal" or "--evidence-dir" or "--expected-count" or
                    "--approval-mode" or "--approved-source-identity" or "--approved-source-sha256") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(flag, args[i]))
                throw new ArgumentException(Usage);
        }
        foreach (var required in (string[])[ "--image", "--container-id", "--volume-uuid", "--volume-oid", "--checkpoint-xid",
            "--store-offset-bytes", "--store-size-bytes", "--journal", "--evidence-dir" ])
            if (!values.ContainsKey(required)) throw new ArgumentException(Usage);
        var confirm = switches.Contains("--confirm");
        values.TryGetValue("--expected-count", out var expected);
        values.TryGetValue("--approval-mode", out var approvalMode);
        values.TryGetValue("--approved-source-identity", out var approvedIdentity);
        values.TryGetValue("--approved-source-sha256", out var approvedDigest);
        if (values.ContainsKey("--approval-mode") && approvalMode != NativeApfsVolumeRepair.ExactSourceApprovalMode ||
            values.ContainsKey("--approved-source-identity") && string.IsNullOrEmpty(approvedIdentity) ||
            values.ContainsKey("--approved-source-sha256") && string.IsNullOrEmpty(approvedDigest))
            throw new ArgumentException(Usage);
        return new(values["--image"], values["--container-id"], values["--volume-uuid"], values["--volume-oid"],
            values["--checkpoint-xid"], values["--store-offset-bytes"], values["--store-size-bytes"],
            values["--journal"], values["--evidence-dir"], expected ?? string.Empty, confirm)
        {
            ApprovalMode = approvalMode ?? string.Empty,
            ApprovedSourceIdentity = approvedIdentity ?? string.Empty,
            ApprovedSourceSha256 = approvedDigest ?? string.Empty,
        };
    }
}
