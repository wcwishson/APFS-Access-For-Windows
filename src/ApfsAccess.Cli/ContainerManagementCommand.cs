using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Cli;

internal static class ContainerManagementCommand
{
    internal const string Usage="container-manage plan|apply --device-id ID --container-id UUID --volume-id ID --operation rename-volume|set-quota-reserve [existing management plan/apply options] [--private-instance UUID]";

    internal static (string[] LeafArguments,string ContainerUuid,Guid? PrivateInstance) Translate(string[] args)
    {
        if(args.Length<2||args[0]!="container-manage"||args[1] is not ("plan" or "apply"))throw new ArgumentException(Usage);
        var leaf=new List<string>{args[1]=="plan"?"management-plan":"management-apply"};string? container=null;Guid? instance=null;
        for(var i=2;i<args.Length;++i)
        {
            var flag=args[i];
            if(flag=="--dry-run"){leaf.Add(flag);continue;}
            if(++i>=args.Length)throw new ArgumentException(Usage);
            var value=args[i];
            if(flag=="--container-id")
            {
                if(container is not null)throw new ArgumentException(Usage);container=value;
            }
            else if(flag=="--private-instance")
            {
                if(instance is not null||!Guid.TryParseExact(value,"D",out var id)||id==Guid.Empty||id.ToString("D")!=value)
                    throw new ArgumentException("Select a canonical private service instance. "+Usage);
                instance=id;
            }
            else {leaf.Add(flag);leaf.Add(value);}
        }
        if(!Guid.TryParse(container,out var uuid)||uuid==Guid.Empty)throw new ArgumentException("Select an exact container UUID. "+Usage);
        _=ManagementCommand.Parse(leaf.ToArray());return (leaf.ToArray(),uuid.ToString("N"),instance);
    }

    internal static async Task<int> RunAsync(string[] args,Func<string[],string,Task<int>>? run=null,
        CancellationToken token=default,DateTimeOffset? operationDeadlineUtc=null)
    {
        try
        {
            var selected=Translate(args);
            return run is null?await ManagementCommand.RunAsync(selected.LeafArguments,selected.ContainerUuid,token,operationDeadlineUtc,selected.PrivateInstance).ConfigureAwait(false):
                await run(selected.LeafArguments,selected.ContainerUuid).ConfigureAwait(false);
        }
        catch(ArgumentException ex)
        {
            Console.WriteLine(JsonSerializer.Serialize(new{schemaVersion=2,command="container-manage",success=false,exitCode=2,
                operationId=ManagementCommand.TryExtractCanonicalOperationId(args)??Guid.NewGuid().ToString("D"),code="invalid-arguments",error=ex.Message,usage=Usage}));
            return 2;
        }
    }
}
