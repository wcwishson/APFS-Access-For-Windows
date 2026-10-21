using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli;

internal static class VerifyProfileCommand
{
    internal const string Usage = "verify-profile --verification-profile fusion-clean-cache|encrypted-onekey-generation-zero --image ABSOLUTE_FILE --container-id apfs-container:hex32 --volume-uuid hex32 --volume-oid OID --checkpoint-xid XID --store-offset-bytes N --store-size-bytes N [--tier2-image ABSOLUTE_FILE --tier2-offset-bytes N --tier2-size-bytes N --fusion-uuid hex32 --fusion-role-convention linux-apfs-last-byte-low-bit | --credential-stdin] [--require-whole-volume] [--require-payload-content-hashes] [--account-retained-ownership] [--retained-from-xid XID] [--json]";
    internal static ApfsCurrentProfileVerificationRequest Parse(string[] args)=>Parse(args,false);
    internal static ApfsCurrentProfileVerificationRequest Parse(string[] args,bool retainedProfileHistory)
    {
        var values = new Dictionary<string,string>(StringComparer.Ordinal);
        var switches = new HashSet<string>(StringComparer.Ordinal);
        var required = new[] {"--verification-profile","--image","--container-id","--volume-uuid","--volume-oid","--checkpoint-xid","--store-offset-bytes","--store-size-bytes"};
        var flags = new HashSet<string>(required,StringComparer.Ordinal);
        flags.UnionWith(["--tier2-image","--tier2-offset-bytes","--tier2-size-bytes","--fusion-uuid","--fusion-role-convention","--retained-from-xid"]);
        for (var i=0;i<args.Length;++i)
        {
            var flag=args[i];
            if (flag is "--json" or "--credential-stdin" or "--require-whole-volume" or "--require-payload-content-hashes" or "--account-retained-ownership")
            { if (!switches.Add(flag)) throw new ArgumentException(Usage); continue; }
            if (!flags.Contains(flag) || ++i>=args.Length || args[i].StartsWith("--",StringComparison.Ordinal) || !values.TryAdd(flag,args[i])) throw new ArgumentException(Usage);
        }
        if (required.Any(key=>!values.ContainsKey(key))) throw new ArgumentException(Usage);
        var request = new ApfsCurrentProfileVerificationRequest(values["--verification-profile"],values["--image"],values["--container-id"],values["--volume-uuid"],
            values["--volume-oid"],values["--checkpoint-xid"],values["--store-offset-bytes"],values["--store-size-bytes"],
            values.GetValueOrDefault("--tier2-image"),values.GetValueOrDefault("--tier2-offset-bytes"),values.GetValueOrDefault("--tier2-size-bytes"),
            values.GetValueOrDefault("--fusion-uuid"),values.GetValueOrDefault("--fusion-role-convention"),switches.Contains("--require-whole-volume"),
            switches.Contains("--require-payload-content-hashes"),switches.Contains("--account-retained-ownership"),values.GetValueOrDefault("--retained-from-xid"));
        if ((request.Profile == "fusion-clean-cache") == switches.Contains("--credential-stdin")) throw new ArgumentException(Usage);
        NativeApfsImageVerifier.ValidateCurrentProfileRequest(retainedProfileHistory?request with{RetainedFromXid=null}:request); return request;
    }

    internal static int Run(string[] args,
        Func<ApfsCurrentProfileVerificationRequest,SupervisedCredential?,CancellationToken,ApfsCurrentProfileVerificationResult>? verify = null,
        Func<CancellationToken,SupervisedCredential>? receive = null, CancellationToken cancellationToken = default)
    {
        var help=args is ["--help"] or ["help"]; var exit=0; var code="CurrentProfileHelp"; string? error=null; int? nativeExit=null;
        ApfsCurrentProfileVerificationResult? result=null;
        using var stopping=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ConsoleCancelEventHandler handler=(_,e)=>{e.Cancel=true;stopping.Cancel();}; Console.CancelKeyPress+=handler;
        try
        {
            if (!help)
            {
                var request=Parse(args); stopping.Token.ThrowIfCancellationRequested();
                using var credential=request.Profile == "fusion-clean-cache" ? null : (receive is null ? SupervisedCredential.Receive(SupervisedCredential.TakeStandardInput(),stopping.Token,()=>{}) : receive(stopping.Token));
                result=verify is null ? new NativeApfsImageVerifier().VerifyCurrentProfile(request,credential,stopping.Token) : verify(request,credential,stopping.Token);
                stopping.Token.ThrowIfCancellationRequested();
                exit=result.NativeExitCode; nativeExit=exit;
                if (exit != (result.Outcome==ApfsVerificationOutcome.Complete ? 0 : result.Outcome==ApfsVerificationOutcome.Incomplete ? 3 : 4) ||
                    result.Report.ValueKind!=JsonValueKind.Object || result.Report.GetProperty("outcome").GetInt32()!=(int)result.Outcome)
                    throw new InvalidDataException("Inconsistent current profile terminal result.");
                code=exit==0 ? "CoveredCurrentProfileVerified" : exit==3 ? "CurrentProfileIncomplete" : "CurrentProfileRefused";
            }
        }
        catch (ArgumentException ex) {exit=2;code="InvalidArguments";error=ex.Message;}
        catch (NativeVerificationExitException ex) {exit=5;code="NativeCurrentProfileFailed";nativeExit=ex.NativeExitCode;error=ex.Message;}
        catch (Exception ex) when (ex is FileNotFoundException or Win32Exception) {exit=5;code="ObserverUnavailable";error=ex.Message;}
        catch (TimeoutException ex) {exit=6;code="CurrentProfileTimeout";error=ex.Message;}
        catch (OperationCanceledException ex) {exit=12;code="CurrentProfileCancelled";error=ex.Message;}
        catch (Exception ex) {exit=5;code="CurrentProfileProtocolFailed";error=ex.Message;}
        finally {Console.CancelKeyPress-=handler;}
        if (error is not null) result=null;
        Console.WriteLine(JsonSerializer.Serialize(new {
            schemaVersion=2,command="verify-profile",success=exit==0,exitCode=exit,nativeExitCode=nativeExit,code,error,
            verification=result?.Report,usage=help?Usage:null,
            description=help?"Verify the exact supported current Fusion or encrypted graph. Inspect every coverage row. Retained history, orphan completeness, expected content hashes and Apple policy charges are outside this profile. Passwords use an APC1 stdin pipe only.":null
        },new JsonSerializerOptions{WriteIndented=true}));
        return exit;
    }
}
