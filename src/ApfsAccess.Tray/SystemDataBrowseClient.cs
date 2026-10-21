using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Tray;

internal sealed record SystemDataBrowseRequest(SystemDataBrowseSelection Selection,string SessionDirectory,string? CopyOut);
internal sealed record SystemDataBrowseResult(string Evidence,string? Destination,int Files,int Directories,long Bytes);
internal sealed class SystemDataBrowseCancelledException(string evidence,Exception cause,CancellationToken token)
    : OperationCanceledException("Cancelled; native teardown confirmed. Evidence: "+evidence,cause,token) { }
internal sealed class SystemDataBrowseException(string message,bool teardownConfirmed,Exception? cause=null)
    : IOException(message,cause)
{ internal bool TeardownConfirmed {get;}=teardownConfirmed; }

internal sealed class SystemDataBrowseClient
{
    private readonly Func<SystemDataBrowseRequest,ISnapshotBrowseProcess> start;
    private readonly Func<string,JsonElement?> read;
    private readonly TimeSpan startup;
    internal bool Available {get;}
    internal SystemDataBrowseClient(Func<SystemDataBrowseRequest,ISnapshotBrowseProcess>? launch=null,
        Func<string,JsonElement?>? readReady=null,TimeSpan? startupTimeout=null)
    { start=launch??Start;read=readReady??ReadReady;startup=startupTimeout??TimeSpan.FromSeconds(45);
        Available=launch is not null||File.Exists(Path.Combine(AppContext.BaseDirectory,"ApfsAccess.Cli.exe")); }

    internal async Task<SystemDataBrowseResult> RunAsync(SystemDataBrowseRequest request,Action<string> ready,
        Action requireCurrent,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();requireCurrent();ValidatePaths(request);
        if(!Available)throw new FileNotFoundException("The packaged System/Data CLI is unavailable.");
        using var held=await SystemDataBrowseWorkflow.HoldAsync(request.Selection,token).ConfigureAwait(true);
        token.ThrowIfCancellationRequested();requireCurrent();
        using var process=start(request);var elapsed=Stopwatch.StartNew();string? operation=null;Exception? failure=null;
        try
        {
            while(!process.Completion.IsCompleted)
            {
                token.ThrowIfCancellationRequested();requireCurrent();held.RequireSource();
                if(operation is null)
                {
                    if(read(Path.Combine(request.SessionDirectory,"ready.json")) is { } state)
                    {
                        operation=SystemDataBrowseProtocol.Ready(state,request);requireCurrent();held.RequireSource();
                        if(request.CopyOut is null)ready(Path.Combine(request.SessionDirectory,"mount"));
                    }
                    else if(elapsed.Elapsed>startup)throw new TimeoutException("The selected System/Data pair did not become ready.");
                }
                await Task.WhenAny(process.Completion,Task.Delay(100)).ConfigureAwait(true);
            }
        }
        catch(Exception ex){failure=ex;}
        if(failure is null && token.IsCancellationRequested)failure=new OperationCanceledException(token);
        try{await process.CloseAsync().ConfigureAwait(true);}catch(Exception ex){failure??=ex;}
        SnapshotBrowseExit terminal;
        try{terminal=await process.Completion.ConfigureAwait(true);}
        catch(Exception ex){throw new SystemDataBrowseException("System/Data closure is unconfirmed. Evidence: "+request.SessionDirectory,false,ex);}
        var result=SystemDataBrowseProtocol.Terminal(terminal,request,operation,failure is not null);
        if(failure is OperationCanceledException)throw new SystemDataBrowseCancelledException(request.SessionDirectory,failure,token);
        if(failure is not null)throw new SystemDataBrowseException(failure.Message+" Native teardown confirmed. Evidence: "+request.SessionDirectory,true,failure);
        requireCurrent();held.RequireSource();token.ThrowIfCancellationRequested();return result;
    }

    internal static void ValidatePaths(SystemDataBrowseRequest request)
    {
        SystemDataBrowseWorkflow.Validate(request.Selection);
        var session=NativeSnapshotBrowseLaunch.ValidateLocalPath(request.SessionDirectory);
        static bool Inside(string a,string b)=>a.Equals(b,StringComparison.OrdinalIgnoreCase)||a.StartsWith(b.TrimEnd('\\','/')+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
        if(File.Exists(session)||Directory.Exists(session)||Inside(request.Selection.Image,session))throw new ArgumentException("Use a new private session outside the source image.");
        if(request.CopyOut is { } copy)
        {
            NativeSnapshotBrowseLaunch.ValidateLocalPath(copy);
            if(File.Exists(copy)||Directory.Exists(copy)||Inside(copy,session)||Inside(session,copy)||Inside(request.Selection.Image,copy))
                throw new ArgumentException("Copy to a new directory outside the source and session.");
        }
    }

    internal static ProcessStartInfo StartInfo(SystemDataBrowseRequest request,string executable)
    {
        var s=request.Selection;
        var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,
            RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false,true),
            StandardOutputEncoding=new UTF8Encoding(false,true),StandardErrorEncoding=new UTF8Encoding(false,true)};
        foreach(var arg in new[]{"system-data","browse","--image",s.Image,"--container-id","apfs-container:"+s.ContainerUuid,
            "--group-uuid",s.GroupUuid,"--system-oid",s.SystemOid,"--data-oid",s.DataOid,"--checkpoint-xid",s.CheckpointXid,
            "--session-dir",request.SessionDirectory,"--close-on-stdin","--json"})info.ArgumentList.Add(arg);
        if(request.CopyOut is { } copy){info.ArgumentList.Add("--copy-out");info.ArgumentList.Add(copy);}return info;
    }

    private static ISnapshotBrowseProcess Start(SystemDataBrowseRequest request)
        =>SnapshotBrowseProcess.Start(StartInfo(request,Path.Combine(AppContext.BaseDirectory,"ApfsAccess.Cli.exe")));

    private static JsonElement? ReadReady(string path)
    {
        try{using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
            if(file.Length>65536)throw new InvalidDataException("System/Data readiness exceeds 64 KiB.");
            using var document=JsonDocument.Parse(file);return document.RootElement.Clone();}
        catch(FileNotFoundException){return null;}catch(DirectoryNotFoundException){return null;}catch(JsonException){return null;}
    }
}

internal static class SystemDataBrowseProtocol
{
    private static readonly JsonSerializerOptions Options=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    private static void Require(bool value){if(!value)throw new InvalidDataException("System/Data evidence differs from the selected source, pair or owner.");}
    private static string Text(JsonElement root,string field)=>root.GetProperty(field).GetString()??throw new InvalidDataException("Missing System/Data evidence.");
    private static bool PathEquals(string a,string b)=>string.Equals(a,b,StringComparison.OrdinalIgnoreCase);
    private static void Unique(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);
            foreach(var p in value.EnumerateObject()){Require(names.Add(p.Name));Unique(p.Value);}}
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Unique(item);
    }
    private static void Selection(JsonElement value,SystemDataBrowseSelection expected)
        =>Require(JsonNode.DeepEquals(JsonNode.Parse(value.GetRawText()),JsonSerializer.SerializeToNode(expected,Options)));
    private static void Capability(JsonElement root)
        =>Require(JsonNode.DeepEquals(JsonNode.Parse(root.GetProperty("capability").GetRawText()),JsonSerializer.SerializeToNode(NativeSystemDataBrowseLaunch.Capability,Options)));
    internal static string Ready(JsonElement value,SystemDataBrowseRequest request)
    {
        Unique(value);Capability(value);Selection(value.GetProperty("selection"),request.Selection);
        Require(value.GetProperty("imageDerivedAdmission").ValueKind==JsonValueKind.True&&
            PathEquals(Text(value,"mountPoint"),Path.Combine(request.SessionDirectory,"mount")));
        var id=Text(value,"operationId");Require(Guid.TryParseExact(id,"D",out _));return id;
    }
    internal static SystemDataBrowseResult Terminal(SnapshotBrowseExit exit,SystemDataBrowseRequest request,string? operation,bool interrupted)
    {
        try
        {
            using var doc=JsonDocument.Parse(exit.StandardOutput);var root=doc.RootElement;Unique(root);Capability(root);
            Require(root.GetProperty("schemaVersion").GetInt32()==2&&Text(root,"command")=="system-data-browse"&&
                root.GetProperty("exitCode").GetInt32()==exit.ExitCode);
            var id=Text(root,"operationId");Require(Guid.TryParseExact(id,"D",out _)&&(operation is null||operation==id));
            Require(PathEquals(Text(root,"sessionDirectory"),request.SessionDirectory)&&
                PathEquals(Text(root,"supervisorEvidence"),Path.Combine(request.SessionDirectory,"supervisor.json"))&&
                root.GetProperty("teardownProven").ValueKind==JsonValueKind.True);
            if(root.GetProperty("selection").ValueKind!=JsonValueKind.Null)Selection(root.GetProperty("selection"),request.Selection);
            if(interrupted)return new(request.SessionDirectory,null,0,0,0);
            if(exit.ExitCode!=0||root.GetProperty("success").ValueKind!=JsonValueKind.True)
                throw new SystemDataBrowseException("System/Data was refused or failed; native teardown confirmed. Copy may be partial. Evidence: "+request.SessionDirectory+". "+Text(root,"error"),true);
            Require(root.GetProperty("nativeAdmissionProven").ValueKind==JsonValueKind.True&&
                PathEquals(Text(root,"mountPoint"),Path.Combine(request.SessionDirectory,"mount")));
            Selection(root.GetProperty("selection"),request.Selection);
            var copy=root.GetProperty("copyOut");
            if(request.CopyOut is null){Require(copy.ValueKind==JsonValueKind.Null);return new(request.SessionDirectory,null,0,0,0);}
            var files=copy.GetProperty("files").GetInt32();var directories=copy.GetProperty("directories").GetInt32();var bytes=copy.GetProperty("bytes").GetInt64();
            Require(files>=0&&directories>=1&&bytes>=0);return new(request.SessionDirectory,request.CopyOut,files,directories,bytes);
        }
        catch(Exception ex)when(ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or InvalidDataException)
        {throw new SystemDataBrowseException("System/Data closure or result identity is unconfirmed. Evidence: "+request.SessionDirectory,false,ex);}
    }
}
