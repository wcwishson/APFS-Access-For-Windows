using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli;

internal static class MarkedReferenceSpaceCommand
{
    internal static string Usage => SnapshotSpaceCommand.Usage.Replace("snapshots space ", "marked-reference-space ", StringComparison.Ordinal);
    internal static int Run(string[] args,
        Func<ApfsSnapshotAttributionRequest, CancellationToken, ApfsMarkedReferenceSpaceResult>? observe = null,
        CancellationToken token = default)
    {
        var help = args is ["help"] or ["--help"]; var exit = 0; var code = "MarkedReferenceSpaceObserved";
        string? error = null; int? nativeExit = null; JsonElement? report = null;
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(token);
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stopping.Cancel(); }; Console.CancelKeyPress += handler;
        try
        {
            if (!help)
            {
                var request = SnapshotSpaceCommand.Parse(["space", .. args]); stopping.Token.ThrowIfCancellationRequested();
                var result = observe is null ? new NativeApfsImageVerifier().ObserveMarkedReferenceSpace(request, stopping.Token) : observe(request, stopping.Token);
                stopping.Token.ThrowIfCancellationRequested(); nativeExit = result.NativeExitCode;
                if (result.NativeExitCode != (result.Complete ? 0 : 3) || result.Report.ValueKind != JsonValueKind.Object ||
                    result.Report.GetProperty("complete").GetBoolean() != result.Complete) throw new InvalidDataException("Inconsistent marked-reference result.");
                report = result.Report; if (!result.Complete) { exit = 3; code = "MarkedReferenceSpaceUnknown"; }
            }
        }
        catch (ArgumentException ex) { exit = 2; code = "InvalidArguments"; error = ex.Message; }
        catch (NativeVerificationExitException ex) { exit = 5; code = "NativeMarkedReferenceFailed"; nativeExit = ex.NativeExitCode; error = ex.Message; }
        catch (Exception ex) when (ex is FileNotFoundException or Win32Exception) { exit = 5; code = "ObserverUnavailable"; error = ex.Message; }
        catch (TimeoutException ex) { exit = 6; code = "MarkedReferenceTimeout"; error = ex.Message; }
        catch (OperationCanceledException ex) { exit = 12; code = "MarkedReferenceCancelled"; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = "InvalidMarkedReferenceOutput"; error = ex.Message; }
        finally { Console.CancelKeyPress -= handler; }
        if (error is not null) report = null;
        Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 2, command = "marked-reference-space", success = exit == 0,
            exitCode = exit, nativeExitCode = nativeExit, code, error, observation = report, usage = help ? Usage : null,
            description = help ? "Read literal IS_PURGEABLE file and external-attribute physical sets with directory7 and allocation checks. WANT-only is separate. Apple snapshot charges, OS purgeability and exact release permissions remain unknown." : null },
            new JsonSerializerOptions { WriteIndented = true })); return exit;
    }
}
