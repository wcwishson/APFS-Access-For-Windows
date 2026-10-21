using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class VerifyCommand
{
    internal const string Usage = "verify --image ABSOLUTE_FILE --container-id apfs-container:hex32 --volume-uuid hex32 --volume-oid OID --checkpoint-xid XID --store-offset-bytes N --store-size-bytes N [--retained-from-xid START_XID] [--account-retained-ownership] [--require-whole-volume] [--require-payload-content-hashes] [--expected-manifest ABSOLUTE_FILE] [--json]; or verify --verification-report ABSOLUTE_FILE --expected-manifest ABSOLUTE_FILE [--json]";
    internal const string Description = "Read-only regular local image verification. Complete verifies the requested covered scope; inspect every coverage entry and finding. Version 2 includes allocationCensus on subset completion: current metadata/payload block counts and unattributed main/internal ranges. Residual allocation is unattributed, never reclaimable. The default check does not cover retained allocation ownership; use --account-retained-ownership for that supported scope. Whole-volume and payload-content-hash certification remain unavailable. UUIDs must be nonzero lowercase hex32; IDs, counts and byte ranges are canonical decimal uint64 strings. Census physical blocks are relative to the selected container; use its reported blockSizeBytes. Exact scope is required; no volume or checkpoint is selected implicitly. JSON is the default output; version 1 reports remain supported without a census. Exits: 0 requested scope complete, 3 incomplete, 4 refused, 2 invalid arguments, 5 observer/protocol failure, 6 timeout, 12 cancelled.";

    internal static int Run(string[] args, Func<ApfsImageVerificationRequest, CancellationToken, ApfsImageVerificationResult>? verify = null,
        CancellationToken cancellationToken = default)
    {
        var exit = 0; var code = "VerificationHelp"; string? error = null;
        int? nativeExit = null; ApfsImageVerificationResult? result = null;
        JsonElement? offlineReport = null; ExpectedPayloadComparison? comparison = null;
        string? reportSha256 = null;
        var comparisonRequested = args.Contains("--expected-manifest", StringComparer.Ordinal);
        var help = args is ["help"] or ["--help"];
        try
        {
            if (!help)
            {
                var options = ParseOptions(args);
                if (options.Request is not null) NativeApfsImageVerifier.ValidateRequest(options.Request);
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
                Console.CancelKeyPress += handler;
                try
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    using var manifestFile = options.Manifest is null ? null : ExpectedPayloadInput.OpenFile(options.Manifest);
                    var manifestInput = manifestFile is null ? null : ExpectedPayloadInput.Read(manifestFile,
                        ExpectedPayloadManifest.MaximumManifestBytes, cancellation.Token);
                    var manifest = manifestInput is null ? null : ExpectedPayloadManifest.Parse(manifestInput);
                    if (options.Report is not null)
                    {
                        using var reportFile = ExpectedPayloadInput.OpenFile(options.Report);
                        var input = ExpectedPayloadInput.Read(reportFile, LiveVolumeVerificationReport.MaximumResponseBytes, cancellation.Token);
                        using var document = input.ParseDocument();
                        var report = LiveVolumeVerificationReport.Parse(document.RootElement);
                        comparison = manifest!.Compare(report);
                        input.EnsureUnchanged(cancellation.Token);
                        reportSha256 = input.Sha256;
                        offlineReport = report.Json;
                        exit = report.Complete ? 0 : report.Outcome == "Refused" ? 4 : 3;
                    }
                    else
                    {
                        result = (verify ?? new NativeApfsImageVerifier().Verify)(options.Request!, cancellation.Token);
                        exit = result.NativeExitCode; nativeExit = exit;
                        if (manifest is not null)
                        {
                            var source = result.Report.GetProperty("source");
                            var scope = result.Report.GetProperty("requestedScope");
                            comparison = manifest.Compare(new ExpectedPayloadScope(source.GetProperty("identity").GetString()!,
                                source.GetProperty("kind").GetString()!, scope.GetProperty("containerUuid").GetString()!,
                                scope.GetProperty("volumeUuid").GetString()!, scope.GetProperty("volumeOid").GetString()!,
                                scope.GetProperty("checkpointXid").GetString()!, scope.GetProperty("storeOffsetBytes").GetString()!,
                                scope.GetProperty("storeSizeBytes").GetString()!), result.PayloadInventory);
                        }
                    }
                    manifestInput?.EnsureUnchanged(cancellation.Token);
                    cancellation.Token.ThrowIfCancellationRequested();
                    code = exit == 0 ? (options.Request?.AccountRetainedOwnership == true ? "RetainedAllocationOwnershipVerified" :
                        options.Request?.RetainedFromXid is not null ? "RequestedProtectedHistoryAndCurrentMetadataVerified" :
                        "CurrentMetadataSubsetVerified") : exit == 3 ? "VerificationIncomplete" : "VerificationRefused";
                    if (options.Report is not null && exit == 0) code = "MatchingProvidedManifest";
                    if (comparison is not null && !comparison.MatchingProvidedManifest)
                    {
                        exit = exit == 4 || comparison.Outcome == "Refused" ? 4 : 3;
                        code = "ExpectedPayloadComparison" + comparison.Outcome;
                    }
                }
                finally { Console.CancelKeyPress -= handler; }
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
        if (error is not null) { result = null; offlineReport = null; comparison = null; reportSha256 = null; }
        var payload = JsonSerializer.SerializeToNode(new {
            schemaVersion = PipeSchemaVersions.Schema2, command = "verify", operationId = Guid.NewGuid().ToString("D"),
            success = exit == 0, exitCode = exit, nativeExitCode = nativeExit, code, resultCode = code,
            errorCode = exit == 0 ? null : code, message = error ?? (help ? Description + HistoryDescription + AccountingDescription + ComparisonDescription :
                comparison is not null ? "See the separate caller-provided expectation comparison and native coverage." :
                code == "RequestedProtectedHistoryAndCurrentMetadataVerified" ? "Only the requested protected checkpoint chain and covered current metadata passed verification." :
                code == "RetainedAllocationOwnershipVerified" ? "Allocated blocks are accounted for across the retained checkpoints. This does not certify file contents or reclaimable space." :
                result?.Outcome == ApfsVerificationOutcome.Complete ? "The covered current metadata subset passed verification." : "See verification findings and coverage."),
            error, verification = result?.Report ?? offlineReport, usage = help ? Usage : null,
            description = help ? Description + HistoryDescription + AccountingDescription + ComparisonDescription : null
        })!.AsObject();
        if (comparisonRequested)
            payload["expectedPayloadComparison"] = JsonSerializer.SerializeToNode(comparison,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        if (reportSha256 is not null)
            payload["verificationReportInput"] = JsonSerializer.SerializeToNode(new {
                sha256 = reportSha256, source = "caller-supplied-report-file", liveSourceRechecked = false,
                trust = "report origin and authenticity not authenticated"
            });
        Console.WriteLine(payload.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        return exit;
    }

    internal static ApfsImageVerificationRequest ParseArguments(string[] args)
        => ParseOptions(args).Request ?? throw new ArgumentException(Usage);

    private const string HistoryDescription = " Optional --retained-from-xid START_XID verifies only the requested protected checkpoint chain through the selected current checkpoint, plus covered current metadata. START_XID must be canonical, nonzero and less than --checkpoint-xid. The protected-history v1 report has requestedHistory and no repair authority. This option cannot be combined with --require-whole-volume, --require-payload-content-hashes, --expected-manifest or --verification-report. Full historical reachability, complete allocation accounting and payload hashes remain unproven.";

    private const string AccountingDescription = " Optional --account-retained-ownership checks allocated blocks against all retained checkpoint owners and reports orphan allocations in a version 4 report. It requires a supported unencrypted single-store image. Snapshot totals and purgeable bytes remain unknown. This option cannot be combined with --retained-from-xid or --verification-report.";

    private const string ComparisonDescription = " Optional --expected-manifest compares the complete current payload inventory against caller-supplied SHA256 expectations, without authenticating their origin or independence. MatchingProvidedManifest requires every exact identity, size and hash and complete inventory coverage. Native verified flags remain false. --verification-report reads a raw apfs-access-live-volume-verification JSON report offline, with no observer or source access. Manifest format apfs-access-expected-payload-manifest v1 requires expectedSource, algorithm SHA256, coverage complete-current-payload-inventory, scope (sourceIdentity, sourceKind, containerUuid, volumeUuid, volumeOid, checkpointXid, storeOffsetBytes, storeSizeBytes), and entries (kind, inodeOid, streamOid, nameUtf8, logicalSizeBytes, expectedSha256). File names are null; xattr names retain exact UTF-8 identity. Unknown/duplicate fields are rejected. Limits: 1 MiB per input, 1024 entries, 4096 UTF-8 bytes per name, 256 MiB logical payload. Comparison mismatch/incomplete exits 3; scope refusal exits 4; invalid input exits 5. Offline reports are supplied evidence, not a live source recheck.";

    private sealed record Options(ApfsImageVerificationRequest? Request, string? Manifest, string? Report);
    private static Options ParseOptions(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var switches = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var flag = args[i];
            if (flag is "--json" or "--require-whole-volume" or "--require-payload-content-hashes" or "--account-retained-ownership")
            { if (!switches.Add(flag)) throw new ArgumentException(Usage); continue; }
            if (flag is not ("--image" or "--container-id" or "--volume-uuid" or "--volume-oid" or "--checkpoint-xid" or "--store-offset-bytes" or "--store-size-bytes" or "--expected-manifest" or "--verification-report" or "--retained-from-xid") ||
                ++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal) || !values.TryAdd(flag, args[i]))
                throw new ArgumentException(Usage);
        }
        values.Remove("--expected-manifest", out var manifest);
        values.Remove("--verification-report", out var report);
        values.Remove("--retained-from-xid", out var retainedFromXid);
        if (retainedFromXid is not null && (manifest is not null || report is not null ||
            switches.Contains("--require-whole-volume") || switches.Contains("--require-payload-content-hashes") ||
            switches.Contains("--account-retained-ownership")))
            throw new ArgumentException(Usage);
        if (report is not null)
        {
            if (manifest is null || values.Count != 0 || switches.Any(s => s != "--json")) throw new ArgumentException(Usage);
            return new(null, manifest, report);
        }
        if (values.Count != 7) throw new ArgumentException(Usage);
        return new(new(values["--image"], values["--container-id"], values["--volume-uuid"], values["--volume-oid"],
            values["--checkpoint-xid"], values["--store-offset-bytes"], values["--store-size-bytes"],
            switches.Contains("--require-whole-volume"), switches.Contains("--require-payload-content-hashes"), retainedFromXid,
            switches.Contains("--account-retained-ownership")), manifest, null);
    }
}
