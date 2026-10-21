using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Cli.Tests;

public sealed class MarkedOwnerSpaceCommandTests : IDisposable
{
    private readonly string image=Path.Combine(Path.GetTempPath(),"marked-owner-cli-"+Guid.NewGuid().ToString("N"));
    public MarkedOwnerSpaceCommandTests(){File.WriteAllBytes(image,new byte[32768]);}
    public void Dispose()=>File.Delete(image);
    private string[] Args=>["--image",image,"--container-id","apfs-container:"+new string('a',32),"--volume-uuid",new string('b',32),
        "--volume-oid","101","--checkpoint-xid","20","--store-offset-bytes","0","--store-size-bytes","32768"];
    [Fact] public void ExplicitParentIsBoundAndInvalidSelectorsNeverLaunch()
    {
        Assert.Equal("18",MarkedOwnerSpaceCommand.Parse([..Args,"--retained-from-xid","18"]).FromXid);
        foreach(var flags in new[]{new[]{"--retained-from-xid","20"},["--retained-from-xid","018"],
            ["--retained-from-xid","18","--retained-from-xid","19"],["--require-whole-volume"],["--credential-stdin"]})
            Assert.Throws<ArgumentException>(()=>MarkedOwnerSpaceCommand.Parse([..Args,..flags]));
    }
    [Fact] public void CancelledAndContradictoryTerminalResponsesPublishNoObservation()
    {
        var saved=Console.Out;using var text=new StringWriter();Console.SetOut(text);
        try {
            Assert.Equal(12,MarkedOwnerSpaceCommand.Run(Args,(_,_)=>throw new OperationCanceledException()));
            using(var doc=JsonDocument.Parse(text.ToString()))Assert.Equal(JsonValueKind.Null,doc.RootElement.GetProperty("observation").ValueKind);
            text.GetStringBuilder().Clear();
            Assert.Equal(5,MarkedOwnerSpaceCommand.Run(Args,(_,_)=>new(0,false,JsonSerializer.SerializeToElement(new{complete=false}))));
            using var failure=JsonDocument.Parse(text.ToString());Assert.Equal(JsonValueKind.Null,failure.RootElement.GetProperty("observation").ValueKind);
        }finally{Console.SetOut(saved);}
    }
}
