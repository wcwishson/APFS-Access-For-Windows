using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli;

internal static class MarkedOwnerSpaceCommand
{
    internal static ApfsMarkedOwnerSpaceRequest Parse(string[] args)
    {
        var ordinary = new List<string>(); string? from = null;
        for (var i = 0; i < args.Length; ++i)
        {
            if (args[i] != "--retained-from-xid") { ordinary.Add(args[i]); continue; }
            if (from is not null || ++i == args.Length) throw new ArgumentException("Provide one earlier retained checkpoint XID.");
            from = args[i];
        }
        var request = new ApfsMarkedOwnerSpaceRequest(SnapshotSpaceCommand.Parse(["space", .. ordinary]), from);
        NativeApfsImageVerifier.ValidateMarkedOwnerSpaceRequest(request); return request;
    }
    internal static int Run(string[] args, Func<ApfsMarkedOwnerSpaceRequest, CancellationToken, ApfsMarkedOwnerSpaceResult>? observe = null,
        CancellationToken token = default)
    {
        var help = args is ["help"] or ["--help"]; var exit = 0; var code = "MarkedOwnerSpaceAttributed";
        string? error = null; int? native = null; JsonElement? report = null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stop.Cancel(); }; Console.CancelKeyPress += handler;
        try {
            if (!help) {
                var request = Parse(args); stop.Token.ThrowIfCancellationRequested();
                var result = observe is null ? new NativeApfsImageVerifier().ObserveMarkedOwnerSpace(request, stop.Token) : observe(request, stop.Token);
                stop.Token.ThrowIfCancellationRequested();
                if (result.NativeExitCode != (result.Complete ? 0 : 3) || result.Report.GetProperty("complete").GetBoolean() != result.Complete)
                    throw new InvalidDataException("Inconsistent marked-owner terminal result.");
                native = result.NativeExitCode; report = result.Report;
                if (!result.Complete) { exit = 3; code = "MarkedOwnerSpaceUnknown"; }
            }
        }
        catch (ArgumentException ex) { exit = 2; code = "InvalidArguments"; error = ex.Message; }
        catch (NativeVerificationExitException ex) { exit = 5; native = ex.NativeExitCode; code = "NativeMarkedOwnerFailed"; error = ex.Message; }
        catch (Exception ex) when (ex is FileNotFoundException or Win32Exception) { exit = 5; code = "ObserverUnavailable"; error = ex.Message; }
        catch (TimeoutException ex) { exit = 6; code = "MarkedOwnerTimeout"; error = ex.Message; }
        catch (OperationCanceledException ex) { exit = 12; code = "MarkedOwnerCancelled"; error = ex.Message; }
        catch (Exception ex) { exit = 5; code = "InvalidMarkedOwnerOutput"; error = ex.Message; }
        finally { Console.CancelKeyPress -= handler; }
        if (error is not null) report = null;
        Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 2, command = "marked-owner-space", success = exit == 0,
            exitCode = exit, nativeExitCode = native, code, error, observation = report,
            usage = help ? SnapshotSpaceCommand.Usage.Replace("snapshots space", "marked-owner-space") + " [--retained-from-xid XID]" : null },
            new JsonSerializerOptions { WriteIndented = true })); return exit;
    }
}
