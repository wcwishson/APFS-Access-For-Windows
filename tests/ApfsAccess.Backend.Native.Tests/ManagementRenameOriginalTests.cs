using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ManagementRenameOriginalTests
{
    private sealed class Fixture : IDisposable
    {
        internal readonly DTempDirectory Temp=DTempDirectory.Create("rename-original");
        internal readonly string Image,Tool,Root,Identity;
        internal readonly ManagementKeeperRenameRequest Request;
        internal readonly (ulong Oid,string Path)[] Wals;
        internal Fixture()
        {
            Root=Path.Combine(Temp.Path,"journals");Directory.CreateDirectory(Root);
            Image=Path.Combine(Temp.Path,"image.apfs");File.WriteAllBytes(Image,new byte[1048576]);
            Tool=Path.Combine(Temp.Path,"VolumeRenameImage.exe");File.WriteAllBytes(Tool,[0x4d,0x5a]);
            Wals=[(101,Path.Combine(Temp.Path,"original-101.wal")),(102,Path.Combine(Temp.Path,"original-102.wal"))];
            foreach(var wal in Wals)File.WriteAllText(wal.Path,"Retained original, never substituted.");
            Identity=NativeApfsVolumeManagement.SourceIdentity(Image,"0");
            Request=new(Image,new string('a',32),new string('b',32),"101","90","Repeated exact label",Root);
        }
        internal string Plan(bool recover=false)=>JsonSerializer.Serialize(new{schema=1,mode="rename-original",recover,oid=101,xid=90,
            sourceIdentity=Identity,labelSha256=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Request.NewLabel))),confirm=new string('c',64)});
        internal string Durable(ulong xid=91,ulong accepted=20,ulong durable=20,ulong clean=20)=>
            JsonSerializer.Serialize(new{durable=true,checkpointXid=xid,acceptedSequence=accepted,apfsDurableSequence=durable,cleanupSequence=clean});
        public void Dispose()=>Temp.Dispose();
    }
    private sealed class Runner(Func<int,IReadOnlyList<string>,ObserverRunResult> execute):IObserverRunner
    {
        internal readonly List<IReadOnlyList<string>> Calls=[];
        public ObserverRunResult Run(string path,IReadOnlyList<string> args)
        {Calls.Add(args.ToArray());return execute(Calls.Count,args);}
    }

    [Fact] public void ExistingOriginalsAreExplicitlyBoundAndNoFreshJournalIsInvented()
    {
        using var f=new Fixture();var before=f.Wals.Select(w=>File.ReadAllBytes(w.Path)).ToArray();
        var runner=new Runner((call,args)=>new(0,call==1?f.Plan():f.Plan()+"\n"+f.Durable(),""));
        var result=new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default);
        Assert.True(result.Committed);Assert.Equal(91UL,result.CommittedXid);Assert.Equal(2,runner.Calls.Count);
        Assert.Empty(Directory.EnumerateFileSystemEntries(f.Root));
        foreach(var args in runner.Calls)
        {
            Assert.Equal("--original",args[0]);Assert.Contains(f.Identity,args);
            Assert.Contains("101="+f.Wals[0].Path,args);Assert.Contains("102="+f.Wals[1].Path,args);
            Assert.DoesNotContain(NativeApfsVolumeRename.JournalDirFor(f.Root,f.Image),args);
        }
        Assert.Contains("--dry-run",runner.Calls[0]);Assert.Contains("--commit",runner.Calls[1]);
        Assert.Contains(new string('c',64),runner.Calls[1]);
        for(var i=0;i<f.Wals.Length;++i)Assert.Equal(before[i],File.ReadAllBytes(f.Wals[i].Path));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void AcceptedRecoveryRequiresReplanningAndDoesNotApplyAnotherRename(bool cleanupOnly)
    {
        using var f=new Fixture();
        var runner=new Runner((call,args)=>call==1?new(1,"","REFUSED VolumeRenameOriginalRecoveryRequired"):
            new(0,call==2?f.Plan(true):f.Plan(true)+"\n"+f.Durable(cleanupOnly?90UL:91UL),""));
        var result=new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default);
        Assert.False(result.Committed);Assert.Equal(ManagementKeeperCodes.StalePreimage,result.Code);Assert.Equal(3,runner.Calls.Count);
        Assert.DoesNotContain("--recover",runner.Calls[0]);Assert.Contains("--recover",runner.Calls[1]);Assert.Contains("--recover",runner.Calls[2]);
    }

    [Theory]
    [InlineData("preview-write")] [InlineData("source-binding")] [InlineData("label-binding")] [InlineData("duplicate-field")]
    public void InvalidOrMutatingPreviewCannotReachCommit(string fault)
    {
        using var f=new Fixture();
        var runner=new Runner((call,args)=>{
            var plan=f.Plan();
            if(fault=="preview-write"){using var file=new FileStream(f.Image,FileMode.Open,FileAccess.Write,FileShare.None);file.Position=4096;file.WriteByte(1);}
            if(fault=="source-binding")plan=plan.Replace(f.Identity,new string('f',80),StringComparison.Ordinal);
            if(fault=="label-binding")plan=plan.Replace("labelSha256\":\"","labelSha256\":\"0",StringComparison.Ordinal);
            if(fault=="duplicate-field")plan=plan.Replace("\"schema\":1","\"schema\":1,\"schema\":1",StringComparison.Ordinal);
            return new(0,plan,"");
        });
        Assert.Throws<InvalidDataException>(()=>new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default));
        Assert.Single(runner.Calls);
    }

    [Theory]
    [InlineData("echo")] [InlineData("durability")] [InlineData("no-advance")] [InlineData("recovery-backwards")]
    public void CommitMustEchoTheExactPreviewAndActualCompleteBoundary(string fault)
    {
        using var f=new Fixture();var recover=fault=="recovery-backwards";
        var runner=new Runner((call,args)=>{
            if(recover&&call==1)return new(1,"","REFUSED VolumeRenameOriginalRecoveryRequired");
            if(call==(recover?2:1))return new(0,f.Plan(recover),"");
            var plan=f.Plan(recover);
            if(fault=="echo")plan=plan.Replace(new string('c',64),new string('d',64),StringComparison.Ordinal);
            var final=fault=="durability"?f.Durable(durable:19):f.Durable(fault=="no-advance"?90UL:recover?89UL:91UL);
            return new(0,plan+"\n"+final,"");
        });
        var result=new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default);
        Assert.False(result.Committed);Assert.Equal(ManagementKeeperCodes.Unproven,result.Code);
        Assert.Equal(recover?3:2,runner.Calls.Count);
    }

    [Fact] public void CommitFailureCannotClaimOrdinaryRefusal()
    {
        using var f=new Fixture();
        var runner=new Runner((call,args)=>call==1?new(0,f.Plan(),""):
            new(1,"","VolumeMetadataInjectedBeforeDurable"));
        var result=new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default);
        Assert.False(result.Committed);Assert.Equal(ManagementKeeperCodes.Unproven,result.Code);
        Assert.Equal(2,runner.Calls.Count);Assert.Contains("--commit",runner.Calls[1]);
    }

    [Fact] public void PreviewRefusalStillProvesNoCommitWasDispatched()
    {
        using var f=new Fixture();
        var runner=new Runner((call,args)=>new(1,"","Private pre-acceptance refusal"));
        var result=new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default);
        Assert.Equal(ManagementKeeperCodes.Refused,result.Code);Assert.Single(runner.Calls);
        Assert.DoesNotContain("--commit",runner.Calls[0]);
    }

    [Theory]
    [InlineData("timeout")] [InlineData("cancelled")] [InlineData("io")]
    public void MissingPostDispatchTerminalEvidenceRequiresOriginalRecovery(string fault)
    {
        using var f=new Fixture();
        var runner=new Runner((call,args)=>call==1?new(0,f.Plan(),""):throw (fault switch {
            "timeout" => new TimeoutException("Owned tool exit confirmed after deadline"),
            "cancelled" => new OperationCanceledException("Owned tool exit confirmed after cancellation"),
            _ => new IOException("No terminal bytes"),
        }));
        var result=new NativeApfsVolumeRename(runner,f.Tool,f.Root).RenameWithOriginalWals(f.Request,f.Wals,f.Identity,default);
        Assert.False(result.Committed);Assert.Equal(ManagementKeeperCodes.Unproven,result.Code);
        Assert.Equal(2,runner.Calls.Count);Assert.Contains("--commit",runner.Calls[1]);
    }

    [Fact] public void WrongDuplicateOrCancelledAuthorityRefusesBeforeContact()
    {
        using var f=new Fixture();var runner=new Runner((call,args)=>throw new InvalidOperationException("No native contact permitted"));
        var keeper=new NativeApfsVolumeRename(runner,f.Tool,f.Root);
        Assert.Throws<InvalidDataException>(()=>keeper.RenameWithOriginalWals(f.Request,f.Wals,new string('0',80),default));
        Assert.Throws<InvalidDataException>(()=>keeper.RenameWithOriginalWals(f.Request,[f.Wals[0],f.Wals[0]],f.Identity,default));
        Assert.Throws<InvalidDataException>(()=>keeper.RenameWithOriginalWals(f.Request,[f.Wals[1]],f.Identity,default));
        using var stop=new CancellationTokenSource();stop.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(()=>keeper.RenameWithOriginalWals(f.Request,f.Wals,f.Identity,stop.Token));
        Assert.Empty(runner.Calls);
    }
}
