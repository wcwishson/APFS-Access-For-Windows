using System.ComponentModel;
using System.Text.Json;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Cli;

internal static class VerifyProfileHistoryCommand
{
    internal static string Usage=>VerifyProfileCommand.Usage.Replace("verify-profile ","verify-profile-history ",StringComparison.Ordinal)+
        " (requires --retained-from-xid; explicit finite chain only)";
    internal static ApfsRetainedProfileVerificationRequest Parse(string[] args)
    {
        var endpoint=VerifyProfileCommand.Parse(args,true);
        var from=endpoint.RetainedFromXid??throw new ArgumentException(Usage);
        var request=new ApfsRetainedProfileVerificationRequest(endpoint with {RetainedFromXid=null},from);
        NativeApfsImageVerifier.ValidateRetainedProfileRequest(request);return request;
    }
    internal static int Run(string[] args,
        Func<ApfsRetainedProfileVerificationRequest,SupervisedCredential?,CancellationToken,ApfsRetainedProfileVerificationResult>? verify=null,
        Func<CancellationToken,SupervisedCredential>? receive=null,CancellationToken token=default)
    {
        var help=args is ["--help"] or ["help"];var exit=0;var code="RetainedProfileHelp";string? error=null;int? nativeExit=null;
        ApfsRetainedProfileVerificationResult? result=null;
        using var stopping=CancellationTokenSource.CreateLinkedTokenSource(token);
        ConsoleCancelEventHandler handler=(_,e)=>{e.Cancel=true;stopping.Cancel();};Console.CancelKeyPress+=handler;
        try
        {
            if(!help)
            {
                var request=Parse(args);stopping.Token.ThrowIfCancellationRequested();
                using var credential=request.Endpoint.Profile=="fusion-clean-cache"?null:
                    receive is null?SupervisedCredential.Receive(SupervisedCredential.TakeStandardInput(),stopping.Token,()=>{}):receive(stopping.Token);
                result=verify is null?new NativeApfsImageVerifier().VerifyRetainedProfile(request,credential,stopping.Token):verify(request,credential,stopping.Token);
                stopping.Token.ThrowIfCancellationRequested();exit=result.NativeExitCode;nativeExit=exit;
                if(exit!=(result.Outcome==ApfsVerificationOutcome.Complete?0:result.Outcome==ApfsVerificationOutcome.Incomplete?3:4)||
                    result.Report.ValueKind!=JsonValueKind.Object||result.Report.GetProperty("outcome").GetInt32()!=(int)result.Outcome)
                    throw new InvalidDataException("Inconsistent retained profile terminal result.");
                code=exit==0?"RequestedRetainedProfileVerified":exit==3?"RetainedProfileIncomplete":"RetainedProfileRefused";
            }
        }
        catch(ArgumentException ex){exit=2;code="InvalidArguments";error=ex.Message;}
        catch(NativeVerificationExitException ex){exit=5;code="NativeRetainedProfileFailed";nativeExit=ex.NativeExitCode;error=ex.Message;}
        catch(Exception ex)when(ex is FileNotFoundException or Win32Exception){exit=5;code="ObserverUnavailable";error=ex.Message;}
        catch(TimeoutException ex){exit=6;code="RetainedProfileTimeout";error=ex.Message;}
        catch(OperationCanceledException ex){exit=12;code="RetainedProfileCancelled";error=ex.Message;}
        catch(Exception ex){exit=5;code="RetainedProfileProtocolFailed";error=ex.Message;}
        finally{Console.CancelKeyPress-=handler;}
        if(error is not null)result=null;
        Console.WriteLine(JsonSerializer.Serialize(new{schemaVersion=2,command="verify-profile-history",success=exit==0,exitCode=exit,
            nativeExitCode=nativeExit,code,error,verification=result?.Report,usage=help?Usage:null,
            description=help?"Verify an explicit checkpoint chain with canonical namespace and physical protection continuity. Inspect coverage and snapshotOwnerScope. No whole-volume, hidden-owner/orphan census or Apple policy charges are supplied. Passwords use APC1 stdin only.":null},new JsonSerializerOptions{WriteIndented=true}));
        return exit;
    }
}
