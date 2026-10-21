using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli;

internal static class VerifyProfileSnapshotsCommand
{
    internal static string Usage => VerifyProfileCommand.Usage.Replace("verify-profile ", "verify-profile-snapshots ", StringComparison.Ordinal);
    internal static ApfsVisibleSnapshotProfileRequest Parse(string[] args)
    {
        var endpoint = VerifyProfileCommand.Parse(args, true);
        var request = new ApfsVisibleSnapshotProfileRequest(endpoint with { RetainedFromXid = null }, endpoint.RetainedFromXid);
        NativeApfsImageVerifier.ValidateVisibleSnapshotProfileRequest(request); return request;
    }
    internal static int Run(string[] args,
        Func<ApfsVisibleSnapshotProfileRequest, SupervisedCredential?, CancellationToken, ApfsVisibleSnapshotProfileResult>? verify = null,
        Func<CancellationToken, SupervisedCredential>? receive = null, CancellationToken token = default)
    {
        var help = args is ["--help"] or ["help"]; var exit = 0; var code = "VisibleSnapshotProfileHelp"; string? error = null; int? nativeExit = null;
        ApfsVisibleSnapshotProfileResult? result = null;
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token);
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stopping.Cancel(); }; Console.CancelKeyPress += handler;
        try
        {
            if (!help)
            {
                var request = Parse(args); stopping.Token.ThrowIfCancellationRequested();
                using var credential = request.Endpoint.Profile == "fusion-clean-cache" ? null :
                    receive is null ? SupervisedCredential.Receive(SupervisedCredential.TakeStandardInput(), stopping.Token, () => { }) : receive(stopping.Token);
                result = verify is null ? new NativeApfsImageVerifier().VerifyVisibleSnapshotProfile(request, credential, stopping.Token) : verify(request, credential, stopping.Token);
                stopping.Token.ThrowIfCancellationRequested(); exit = result.NativeExitCode; nativeExit = exit;
                if (exit != (result.Outcome == ApfsVerificationOutcome.Complete ? 0 : result.Outcome == ApfsVerificationOutcome.Incomplete ? 3 : 4) ||
                    result.Report.ValueKind != JsonValueKind.Object || result.Report.GetProperty("outcome").GetInt32() != (int)result.Outcome)
                    throw new InvalidDataException("Inconsistent visible snapshot profile terminal result.");
                code = exit == 0 ? "VisibleSnapshotProfileVerified" : exit == 3 ? "VisibleSnapshotProfileIncomplete" : "VisibleSnapshotProfileRefused";
            }
        }
        catch (ArgumentException ex) { exit = 2; code = "InvalidArguments"; error = ex.Message; }
        catch (NativeVerificationExitException ex) { exit = 5; code = "NativeVisibleSnapshotProfileFailed"; nativeExit = ex.NativeExitCode; error = ex.Message; }
        catch (Exception ex) when (ex is FileNotFoundException or Win32Exception) { exit = 5; code = "ObserverUnavailable"; error = ex.Message; }
        catch (TimeoutException ex) { exit = 6; code = "VisibleSnapshotProfileTimeout"; error = ex.Message; }
        catch (OperationCanceledException ex) { exit = 12; code = "VisibleSnapshotProfileCancelled"; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = "VisibleSnapshotProfileProtocolFailed"; error = ex.Message; }
        finally { Console.CancelKeyPress -= handler; }
        if (error is not null) result = null;
        Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 2, command = "verify-profile-snapshots", success = exit == 0, exitCode = exit,
            nativeExitCode = nativeExit, code, error, verification = result?.Report, usage = help ? Usage : null,
            description = help ? "Verify canonical visible snapshot and parent graphs, optionally through an explicit retained chain. Physical sharing and potential release upper bounds are separate from unknown Apple charges and purgeability. No exhaustive hidden-owner/orphan or content-hash proof. Encrypted credentials use APC1 stdin only." : null },
            new JsonSerializerOptions { WriteIndented = true }));
        return exit;
    }
}
