using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
namespace ApfsAccess.Cli;

internal sealed record EncryptedCommandOptions(string Command,string? ProfilePath,string? Device,string? Volume,bool CredentialStdin,string OperationId,Guid? PrivateInstanceId = null);
internal static class EncryptedImageCommand
{
    internal static EncryptedCommandOptions Parse(string[] args)
    {
        if(args.Length==0 || args[0] is not ("register-image" or "unlock" or "lock")) throw new ArgumentException("Unknown encrypted image command.");
        var values=new Dictionary<string,string>(StringComparer.Ordinal); var stdin=false;
        for(var i=1;i<args.Length;i++)
        {
            if(args[i]=="--credential-stdin") { if(stdin) throw new ArgumentException("Duplicate credential input."); stdin=true; continue; }
            if(args[i] is not ("--profile" or "--device-id" or "--volume-id" or "--operation-id" or "--private-instance") || i+1==args.Length || !values.TryAdd(args[i],args[++i]))
                throw new ArgumentException("Invalid or duplicate encrypted image option. Password arguments are forbidden.");
        }
        var operationId=values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
        if(!Guid.TryParseExact(operationId,"D",out var parsedId) || parsedId.ToString("D")!=operationId) throw new ArgumentException("Invalid operation identity.");
        values.Remove("--operation-id");
        Guid? instance=null;
        if(values.Remove("--private-instance",out var instanceText))
        {
            if(!Guid.TryParseExact(instanceText,"D",out var id) || id==Guid.Empty || id.ToString("D")!=instanceText)
                throw new ArgumentException("Use a canonical nonempty private service instance identity.");
            instance=id;
        }
        if(args[0]=="register-image" ? values.Count!=1 || !values.ContainsKey("--profile") || stdin :
            values.Count!=2 || !values.ContainsKey("--device-id") || !values.ContainsKey("--volume-id") || stdin!=(args[0]=="unlock"))
            throw new ArgumentException("Use register-image --profile <selectors.json>, unlock --device-id <image> --volume-id <id> --credential-stdin, or lock --device-id <image> --volume-id <id>.");
        return new(args[0],values.GetValueOrDefault("--profile"),values.GetValueOrDefault("--device-id"),values.GetValueOrDefault("--volume-id"),stdin,operationId,instance);
    }
    internal static EncryptedImageProfile ReadProfile(string path)
    {
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length is < 2 or > 8192) throw new ArgumentException("Image selector file exceeds bounds.");
        using var doc=JsonDocument.Parse(file); var fields=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if(doc.RootElement.ValueKind!=JsonValueKind.Object || doc.RootElement.EnumerateObject().Any(p=>!fields.Add(p.Name)))
            throw new ArgumentException("Duplicate or invalid image selector fields.");
        var profile=doc.RootElement.Deserialize<EncryptedImageProfile>(new JsonSerializerOptions { PropertyNameCaseInsensitive=true });
        if(profile is null || !profile.IsValid()) throw new ArgumentException("Invalid image selectors.");
        return profile;
    }
    internal static string CommandName(string[] args) =>
        args.Length > 0 && args[0] is "register-image" or "unlock" or "lock" ? args[0] : "encrypted-image";
    internal static string? TryExtractCanonicalOperationId(string[] args)
    {
        for (var i = 0; i + 1 < args.Length; i++)
        {
            if (!string.Equals(args[i], "--operation-id", StringComparison.Ordinal)) continue;
            var candidate = args[i + 1];
            if (Guid.TryParseExact(candidate, "D", out var parsed) && parsed.ToString("D") == candidate)
                return candidate;
            return null;
        }
        return null;
    }
    internal static async Task<int> RunAsync(string[] args,
        Func<string, int, CancellationToken, Task<AgentControlClient>>? clientConnect = null,
        string? pipeOverride = null)
    {
        string? operationId=null;
        try
        {
            var options=Parse(args); operationId=options.OperationId;
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(90));
            using var credential=options.CredentialStdin
                ? SupervisedCredential.Receive(SupervisedCredential.TakeStandardInput(),deadline.Token,()=>{}) : null;
            var pipe=pipeOverride ?? (options.PrivateInstanceId is {} instance ? FusionControlEndpoint.ForPrivateInstance(instance) : ApfsPipeConstants.PipeName);
            clientConnect ??= AgentControlClient.ConnectAsync;
            await using var client=await clientConnect(pipe,2000,deadline.Token).ConfigureAwait(false);
            ApfsControlTarget target;
            if(options.ProfilePath is {} path) target=SelectedControlTarget.ForImage(ReadProfile(path));
            else
            {
                await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.InventoryRequested,new { },"encrypted-inventory"),deadline.Token).ConfigureAwait(false);
                InventoryPayload? inventory=null;
                while(inventory is null)
                {
                    var response=await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                    if(response.Type==ApfsMessageTypes.Inventory) PipeMessageCodec.TryGetPayload(response,out inventory);
                }
                var matches=inventory.Devices.SelectMany(d=>d.Volumes.Select(v=>(d,v))).Where(x=>
                    string.Equals(x.v.DeviceId,options.Device,StringComparison.OrdinalIgnoreCase) && x.v.VolumeId==options.Volume && x.v.RegisteredImage is not null).ToArray();
                if(matches.Length!=1) throw new ArgumentException("Select one registered encrypted image volume.");
                target=SelectedControlTarget.Create(matches[0].d,matches[0].v);
                if(!SelectedControlTarget.Matches(inventory.Devices,target)) throw new ArgumentException("Ambiguous image identity.");
            }
            var request=new ControlOperationRequestPayload(options.OperationId,options.Command,target,ExpiresAtUtc:DateTime.UtcNow.AddSeconds(80));
            var envelope=PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,request,request.OperationId,PipeSchemaVersions.Schema2);
            if(!PipeMessageCodec.Validate(envelope).IsValid) throw new ArgumentException("Invalid encrypted operation.");
            await client.SendAsync(envelope,deadline.Token).ConfigureAwait(false);
            using var sending=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var send=credential is null ? Task.CompletedTask : EncryptedCredentialTransport.SendAsync(request.OperationId,credential,sending.Token);
            try
            {
            while(true)
            {
                var response=await client.ReadMessageAsync(deadline.Token).ConfigureAwait(false) ?? throw new IOException();
                if(response.Type!=ApfsMessageTypes.OperationResult || response.RequestId!=request.OperationId) continue;
                if(!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response,out var result) ||
                    result is null || result.Fingerprint!=ApfsOperationFingerprint.Compute(request)) throw new IOException();
                if(result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
                {
                    await Task.Delay(200,deadline.Token).ConfigureAwait(false);
                    await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery,new OperationResultQueryPayload(request.OperationId),request.OperationId,2),deadline.Token).ConfigureAwait(false);
                    continue;
                }
                Console.WriteLine(JsonSerializer.Serialize(result,new JsonSerializerOptions { PropertyNamingPolicy=JsonNamingPolicy.CamelCase, Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()} }));
                return result.Success?0:5;
            }
            }
            finally { sending.Cancel(); try { await send.ConfigureAwait(false); } catch { /* Terminal result or the generic transport failure owns reporting. */ } }
        }
        catch(ArgumentException ex) {
            Console.WriteLine(JsonSerializer.Serialize(new {
                schemaVersion = PipeSchemaVersions.Schema2, command = CommandName(args),
                operationId = operationId ?? TryExtractCanonicalOperationId(args) ?? Guid.NewGuid().ToString("D"),
                success = false, exitCode = 2, code = ApfsOperationCodes.InvalidArguments,
                resultCode = ApfsOperationCodes.InvalidArguments, errorCode = ApfsOperationCodes.InvalidArguments,
                message = ex.Message, error = ex.Message
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 2;
        }
        catch { Console.Error.WriteLine(JsonSerializer.Serialize(new { operationId, success=false, message="Encrypted image operation interrupted. Use query --operation-id to inspect the owned operation before retrying." })); return 5; }
    }
}
