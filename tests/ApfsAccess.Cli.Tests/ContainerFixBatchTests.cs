using System.Text.Json;
using System.Text;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ContainerFixBatchTests
{
    private static ContainerControlOptions Options(bool dryRun=false) => CliContainerVerificationFixture.Options(dryRun) with {Action="container-fix"};
    private static StatusChangedPayload Status(bool mounted=false, bool raw=false, int count=2)
    {
        var s=CliContainerVerificationFixture.Status(count:count,live:mounted,raw:raw);var d=s.ConnectedInventory![0];
        return s with {ConnectedInventory=[d with {Volumes=d.Volumes.Select(v=>v with {VolumeId=v.CatalogVolumeId!}).ToArray()}],
            MountedVolumes=s.MountedVolumes!.Select(m=>m with {VolumeId=m.CatalogVolumeId!,AccessMode=MountAccessMode.ReadOnly,
                State=RuntimeState.MountedRo,WriteEnabled=false,NativeWriteSafetyState=NativeWriteSafetyState.ReadOnlyFallback,
                HostProcessId=800,HostProcessCreationTimeFileTimeUtc=134048736000000000}).ToArray()};
    }
    private static StatusChangedPayload AfterFirst(StatusChangedPayload s)
    {
        var d=s.ConnectedInventory![0];
        return s with {MountedVolumes=[HealthyOwners()[0]],ConnectedInventory=[d with {Topology=d.Topology! with {Snapshot=d.Topology.Snapshot with {
            Containers=d.Topology.Snapshot.Containers.Select(c=>c with {CheckpointXid="91"}).ToArray(),
            Volumes=d.Topology.Snapshot.Volumes.Select(v=>v with {SuperblockXid="91"}).ToArray()}}}]};
    }
    private static MountedVolumeDisplay[] HealthyOwners() => CliContainerVerificationFixture.Status().MountedVolumes!.Select(m=>m with {
        VolumeId=m.CatalogVolumeId!,HostProcessId=900,HostProcessCreationTimeFileTimeUtc=134048736000000100,
        VolumeVerificationScope=m.VolumeVerificationScope! with {CheckpointXid="91"}}).ToArray();
    private static OperationResultPayload Healthy(ControlOperationRequestPayload r) => new(r.OperationId,r.Command,r.Target,ApfsOperationFingerprint.Compute(r),
        ApfsOperationStates.Succeeded,ApfsOperationCodes.OperationSucceeded,true,DateTime.UtcNow,DateTime.UtcNow,DateTime.UtcNow,
        FinalStatus:"healthy-rw",RequestedMode:r.RequestedMode,ExpiresAtUtc:r.ExpiresAtUtc,EffectiveMode:ApfsControlModes.ReadWrite,
        RecoveryState:"inactive",MountProof:"present",OwnershipProof:"not-applicable",DurabilityProof:"not-applicable");
    private static OperationResultPayload Offered(StatusChangedPayload s,ControlOperationRequestPayload r)
    {
        var d=s.ConnectedInventory![0];var v=d.Volumes.Single(v=>v.VolumeId==r.Target!.VolumeId);
        var offer=new ImageRepairOffer(new string('d',64),DateTime.UtcNow.AddMinutes(3),VerifyScopeDerivation.TryDerive(d,v).Scope!,
            r.Target!.RecoveryIdentity!,r.Target.ObservationContract!,new string('c',64),"0",
            "windows-image-v1:"+new string('a',48)+"00000000000000000000000000200000:100",new string('b',64));
        return new(r.OperationId,r.Command,r.Target,ApfsOperationFingerprint.Compute(r),ApfsOperationStates.Failed,ApfsOperationCodes.BlockedRecovery,
            false,DateTime.UtcNow,DateTime.UtcNow,DateTime.UtcNow,FinalStatus:"repair-confirmation-required",MountProof:"absent",OwnershipProof:"proven",
            DurabilityProof:"proven",ExpiresAtUtc:r.ExpiresAtUtc,ImageRepairOffer:offer);
    }
    [Fact]
    public void MissingContainerFixRed_ParsesExplicitDryRunWithoutApproval()
    {
        var options = ContainerCommand.Parse(["container-fix", "--device-id", CliContainerVerificationFixture.Image,
            "--container-id", CliContainerVerificationFixture.Hex, "--dry-run", "--no-start-service"]);
        Assert.Equal("container-fix", options.Action);
        Assert.True(options.DryRun);
        Assert.Null(options.RequestedMode);
    }

    [Fact]
    public async Task MissingContainerFixRed_DryRunInspectsMembersWithoutDispatch()
    {
        var client = new FakeContainerVerificationClient(CliContainerVerificationFixture.Status(live: false));
        var old = Console.Out; using var output = new StringWriter(); Console.SetOut(output);
        int exit;
        try { exit = await ContainerCommand.RunAsync(["container-fix", "--device-id", CliContainerVerificationFixture.Image,
            "--container-id", CliContainerVerificationFixture.Hex, "--dry-run"], client); }
        finally { Console.SetOut(old); }
        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal("container-fix", json.RootElement.GetProperty("command").GetString());
        Assert.False(json.RootElement.GetProperty("operationIssued").GetBoolean());
        Assert.Equal(2, json.RootElement.GetProperty("volumes").GetArrayLength());
        Assert.Empty(client.Requests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OrdinaryImageBatchRefreshesCohortAndCurrentCheckpointBeforeNextFix(bool normalizedWireTarget)
    {
        var client=new FakeContainerVerificationClient(Status(mounted:true));
        client.Send=(r,_)=>{
            client.Status=client.Requests.Count==1?AfterFirst(client.Status):client.Status with {MountedVolumes=HealthyOwners()};
            var result=Healthy(r);
            if(normalizedWireTarget) result=result with {Target=r.Target! with {
                DeviceId=r.Target.DeviceId.ToLowerInvariant(),VolumeId=r.Target.VolumeId.ToLowerInvariant(),
                ContainerUuid=r.Target.ContainerUuid?.ToLowerInvariant()}};
            return Task.FromResult(result);
        };
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.True(report.Success,report.Diagnostic+string.Join(";",report.Volumes.Select(v=>v.Diagnostic)));
        Assert.Equal(["Completed","Completed"],report.Volumes.Select(v=>v.State));Assert.Equal(2,client.Requests.Count);
        Assert.Equal(2,client.Requests.Select(r=>r.OperationId).Distinct().Count());
        Assert.DoesNotContain(Options().OperationId,client.Requests.Select(r=>r.OperationId));
        Assert.All(client.Requests,r=>{Assert.Equal(ApfsControlCommands.Fix,r.Command);Assert.Null(r.ApprovedImageRepairPlanId);Assert.Null(r.RequestedMode);
            Assert.True(SelectedControlTarget.Matches(client.Status.ConnectedInventory!,r.Target!));});
    }

    [Fact]
    public async Task RestoredGreenPeerIsNoFixNeededWithoutIndependentVerificationClaim()
    {
        var client=new FakeContainerVerificationClient(Status(mounted:true));
        client.Send=(r,_)=>{client.Status=AfterFirst(client.Status) with {MountedVolumes=HealthyOwners()};return Task.FromResult(Healthy(r));};
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.True(report.Success);Assert.Single(client.Requests);Assert.Equal(["Completed","NoFixNeeded"],report.Volumes.Select(v=>v.State));
        Assert.Contains("independent verification were not run",report.Volumes[1].Diagnostic);Assert.Null(report.Volumes[1].OperationId);
    }

    [Theory]
    [InlineData("pid")] [InlineData("source")] [InlineData("uuid")] [InlineData("added")]
    public async Task OriginalSourceOwnerUuidAndMembershipAreRecheckedBeforeSecondDispatch(string change)
    {
        var client=new FakeContainerVerificationClient(Status(mounted:true));
        client.Send=(r,_)=>{client.Status=AfterFirst(client.Status);return Task.FromResult(Healthy(r));};
        client.ReadStatus=count=>count==4?CliContainerVerificationFixture.Change(client.Status,change,change=="uuid"?1:0):client.Status;
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.False(report.Success);Assert.Single(client.Requests);Assert.Equal(["Completed","NotAttempted"],report.Volumes.Select(v=>v.State));
    }

    [Fact]
    public async Task RepairOfferIsReturnedAndStopsBatchWithoutAutomaticApproval()
    {
        var client=new FakeContainerVerificationClient(Status());client.Send=(r,_)=>Task.FromResult(Offered(client.Status,r));
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.False(report.Success);Assert.Equal(5,report.ExitCode);Assert.Single(client.Requests);
        Assert.Equal(["RequiresApproval","NotAttempted"],report.Volumes.Select(v=>v.State));
        Assert.NotNull(report.Volumes[0].Result!.ImageRepairOffer);Assert.Null(report.Volumes[1].OperationId);
        Assert.All(client.Requests,r=>Assert.Null(r.ApprovedImageRepairPlanId));
        var old=Console.Out;using var output=new StringWriter();try{Console.SetOut(output);ContainerFixBatch.Emit(report);}finally{Console.SetOut(old);}
        using var json=JsonDocument.Parse(output.ToString());var root=json.RootElement;
        Assert.Equal(1,root.GetProperty("attempted").GetInt32());Assert.Equal(1,root.GetProperty("requiresApproval").GetInt32());
        Assert.Equal(0,root.GetProperty("completed").GetInt32());Assert.False(root.GetProperty("atomicContainerRepair").GetBoolean());
        Assert.Equal(new string('d',64),root.GetProperty("volumes")[0].GetProperty("result").GetProperty("imageRepairOffer").GetProperty("planId").GetString());
    }

    [Fact]
    public async Task PhysicalCohortReplacementKeepsAcknowledgedChildAndRequiresRefreshForRest()
    {
        var client=new FakeContainerVerificationClient(Status(mounted:true,raw:true));
        client.Send=(r,_)=>{var healthy=CliContainerVerificationFixture.Status(raw:true);client.Status=healthy with {MountedVolumes=healthy.MountedVolumes!.Select(m=>m with {
            VolumeId=m.CatalogVolumeId!,HostProcessId=900,HostProcessCreationTimeFileTimeUtc=134048736000000100}).ToArray(),
            ConnectedInventory=[healthy.ConnectedInventory![0] with {Volumes=healthy.ConnectedInventory[0].Volumes.Select(v=>v with {VolumeId=v.CatalogVolumeId!}).ToArray()}]};
            return Task.FromResult(Healthy(r));};
        var report=await ContainerFixBatch.RunAsync(Options() with {DeviceId=client.Status.ConnectedInventory![0].Device.DeviceId},client);
        Assert.False(report.Success);Assert.Single(client.Requests);Assert.Equal(["Completed","NotAttempted"],report.Volumes.Select(v=>v.State));
        Assert.Contains("physical owner cohort changed",report.Diagnostic);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PhysicalReplacementOnLastOrSoleChildRetainsBatchStop(bool sole)
    {
        var count = sole ? 1 : 2;
        var status = Status(mounted: true, raw: true, count: count);
        status = status with { MountedVolumes = status.MountedVolumes!.Select((m, i) => i < count - 1 ? m with {
            AccessMode = MountAccessMode.ReadWrite, State = RuntimeState.MountedRw, WriteEnabled = true,
            NativeWriteSafetyState = NativeWriteSafetyState.StableReadWrite } : m).ToArray() };
        var client = new FakeContainerVerificationClient(status);
        client.Send = (request, _) => {
            client.Status = client.Status with { MountedVolumes = client.Status.MountedVolumes!.Select(m => m with {
                AccessMode = MountAccessMode.ReadWrite, State = RuntimeState.MountedRw, WriteEnabled = true,
                NativeWriteSafetyState = NativeWriteSafetyState.StableReadWrite, HostProcessId = 900,
                HostProcessCreationTimeFileTimeUtc = 134048736000000100 }).ToArray() };
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options() with { DeviceId = status.ConnectedInventory![0].Device.DeviceId }, client);
        var child = Assert.Single(client.Requests);
        Assert.Equal(status.ConnectedInventory![0].Volumes[^1].VolumeId, child.Target!.VolumeId);
        Assert.Null(child.ApprovedImageRepairPlanId);
        Assert.Equal(sole ? ["Completed"] : new[] { "NoFixNeeded", "Completed" }, report.Volumes.Select(v => v.State));
        Assert.True(report.Volumes[^1].Result!.Success);
        Assert.DoesNotContain(report.Volumes, v => v.State is "Failed" or "NotAttempted");
        Assert.Contains("physical owner cohort changed", report.Diagnostic);
        Assert.False(report.Success);
        Assert.Equal(5, report.ExitCode);
        Assert.Equal("container-fix-incomplete", report.Code);
        var old = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); Assert.Equal(5, ContainerFixBatch.Emit(report)); }
        finally { Console.SetOut(old); }
        using var json = JsonDocument.Parse(output.ToString());
        var root = json.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal(1, root.GetProperty("attempted").GetInt32());
        Assert.Equal(1, root.GetProperty("completed").GetInt32());
        Assert.Equal(0, root.GetProperty("failed").GetInt32());
        Assert.Equal(0, root.GetProperty("notAttempted").GetInt32());
        Assert.Contains("physical owner cohort changed", root.GetProperty("diagnostic").GetString());
    }

    [Theory]
    [InlineData("missing", false, false)]
    [InlineData("replaced", false, false)]
    [InlineData("missing", true, false)]
    [InlineData("replaced", true, false)]
    [InlineData("missing", false, true)]
    [InlineData("replaced", false, true)]
    [InlineData("missing", true, true)]
    [InlineData("replaced", true, true)]
    [InlineData("unhealthy", false, false)]
    [InlineData("unhealthy", true, false)]
    [InlineData("unhealthy", false, true)]
    [InlineData("unhealthy", true, true)]
    [InlineData("cohort-replaced", false, false)]
    [InlineData("cohort-replaced", true, false)]
    [InlineData("cohort-replaced", false, true)]
    [InlineData("cohort-replaced", true, true)]
    public async Task AcknowledgedEarlierMemberMissingOrReplacedVetoesAggregate(string change, bool earlierWasStatusOnly, bool afterLastObservation)
    {
        var status = earlierWasStatusOnly ? AfterFirst(Status()) : Status();
        var original = status.ConnectedInventory![0].Volumes;
        var client = new FakeContainerVerificationClient(status);
        var lastSucceeded = false; var deferred = false;
        StatusChangedPayload ChangeEarlier(StatusChangedPayload s) => s with { MountedVolumes = change == "cohort-replaced"
            ? s.MountedVolumes!.Select(m => m with { HostProcessId = 950, HostProcessCreationTimeFileTimeUtc = 134048736000000200 }).ToArray()
            : change == "missing"
            ? s.MountedVolumes!.Where(m => m.VolumeId != original[0].VolumeId).ToArray()
            : s.MountedVolumes!.Select(m => m.VolumeId != original[0].VolumeId ? m : change == "replaced"
                ? m with { HostProcessId = 777 } : m with { WriteEnabled = false }).ToArray() };
        client.ReadStatus = _ => {
            var snapshot = client.Status;
            if (lastSucceeded && afterLastObservation && !deferred)
            { deferred = true; client.Status = ChangeEarlier(client.Status); }
            return snapshot;
        };
        client.Send = (request, _) => {
            if (request.Target!.VolumeId == original[0].VolumeId) client.Status = AfterFirst(client.Status);
            else
            {
                lastSucceeded = true;
                client.Status = client.Status with { MountedVolumes = HealthyOwners() };
                if (!afterLastObservation) client.Status = ChangeEarlier(client.Status);
            }
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client);
        Assert.True(lastSucceeded);
        Assert.True(TopologyAdmission.Validate(client.Status.ConnectedInventory![0]));
        if (change == "missing") Assert.DoesNotContain(client.Status.MountedVolumes!, m => m.VolumeId == original[0].VolumeId);
        else if (change is "replaced" or "cohort-replaced") Assert.Equal(change == "replaced" ? 777 : 950,
            client.Status.MountedVolumes!.Single(m => m.VolumeId == original[0].VolumeId).HostProcessId);
        else Assert.False(client.Status.MountedVolumes!.Single(m => m.VolumeId == original[0].VolumeId).WriteEnabled);
        Assert.Equal(earlierWasStatusOnly ? 1 : 2, client.Requests.Count);
        Assert.All(client.Requests, r => Assert.Null(r.ApprovedImageRepairPlanId));
        Assert.Equal(new[] { earlierWasStatusOnly ? "NoFixNeeded" : "Completed", "Completed" }, report.Volumes.Select(v => v.State));
        Assert.True(report.Volumes[^1].Result!.Success);
        Assert.False(report.Success);
        Assert.Equal(5, report.ExitCode);
        Assert.Contains("cohort", report.Diagnostic, StringComparison.OrdinalIgnoreCase);
        var old = Console.Out; using var output = new StringWriter();
        try { Console.SetOut(output); Assert.Equal(5, ContainerFixBatch.Emit(report)); }
        finally { Console.SetOut(old); }
        using var json = JsonDocument.Parse(output.ToString());
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(earlierWasStatusOnly ? 1 : 2, json.RootElement.GetProperty("completed").GetInt32());
        Assert.Equal(0, json.RootElement.GetProperty("failed").GetInt32());
        Assert.Equal(0, json.RootElement.GetProperty("notAttempted").GetInt32());
    }

    [Theory]
    [InlineData("source")] [InlineData("uuid")] [InlineData("recovery")] [InlineData("added")]
    [InlineData("pid")] [InlineData("creation")] [InlineData("mount")] [InlineData("window")]
    [InlineData("checkpoint")] [InlineData("duplicate-owner")] [InlineData("no-inventory")]
    public async Task FinalCohortObservationRechecksBindingAfterLastChild(string change)
    {
        var client = new FakeContainerVerificationClient(Status()); var finalReads = 0; var deferred = false;
        client.ReadStatus = _ => {
            var snapshot = client.Status;
            if (client.Requests.Count == 2)
            {
                ++finalReads;
                if (!deferred)
                {
                    deferred = true;
                    client.Status = change == "checkpoint" ? client.Status with {
                        MountedVolumes = client.Status.MountedVolumes!.Select((m, i) => i == 0 ? m with {
                            VolumeVerificationScope = m.VolumeVerificationScope! with { CheckpointXid = "92" } } : m).ToArray()
                    } : CliContainerVerificationFixture.Change(client.Status, change, 0);
                }
            }
            return snapshot;
        };
        client.Send = (request, _) => {
            client.Status = client.Requests.Count == 1 ? AfterFirst(client.Status) : client.Status with { MountedVolumes = HealthyOwners() };
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client);
        Assert.Equal(2, client.Requests.Count);
        Assert.All(report.Volumes, v => { Assert.Equal("Completed", v.State); Assert.True(v.Result!.Success); });
        Assert.False(report.Success); Assert.Equal(5, report.ExitCode);
        Assert.Equal(2, finalReads);
        Assert.Contains("Final original cohort", report.Diagnostic);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task CancellationAtFinalObservationRetainsAcknowledgedHistory(bool lastStatusOnly)
    {
        var client = new FakeContainerVerificationClient(Status());
        using var cts = new CancellationTokenSource();
        client.ReadStatus = count => { if (count == (lastStatusOnly ? 5 : 6)) cts.Cancel(); return client.Status; };
        client.Send = (request, _) => {
            client.Status = client.Requests.Count == 1 ? AfterFirst(client.Status) : client.Status with { MountedVolumes = HealthyOwners() };
            if (lastStatusOnly) client.Status = client.Status with { MountedVolumes = HealthyOwners() };
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client, cts.Token);
        Assert.Equal(lastStatusOnly ? 1 : 2, client.Requests.Count);
        Assert.Equal(new[] { "Completed", lastStatusOnly ? "NoFixNeeded" : "Completed" }, report.Volumes.Select(v => v.State));
        Assert.False(report.Success); Assert.Equal(4, report.ExitCode);
        Assert.True(cts.IsCancellationRequested); Assert.Empty(client.Cancellations);
        Assert.Contains("cancel", report.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FinalObservationFailureRetainsAcknowledgedChildren()
    {
        var client = new FakeContainerVerificationClient(Status());
        client.ReadStatus = count => count == 6 ? throw new IOException("Final status unavailable.") : client.Status;
        client.Send = (request, _) => {
            client.Status = client.Requests.Count == 1 ? AfterFirst(client.Status) : client.Status with { MountedVolumes = HealthyOwners() };
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client);
        Assert.Equal(2, client.Requests.Count);
        Assert.All(report.Volumes, v => { Assert.Equal("Completed", v.State); Assert.True(v.Result!.Success); });
        Assert.False(report.Success); Assert.Equal(5, report.ExitCode);
        Assert.Contains("Final status unavailable", report.Diagnostic);
    }

    [Theory]
    [InlineData("identity")] [InlineData("scope")] [InlineData("source")] [InlineData("duplicate")]
    public async Task AcknowledgedLastChildWithInvalidPeerEvidenceKeepsHistory(string change)
    {
        var client = new FakeContainerVerificationClient(Status());
        client.Send = (request, _) => {
            client.Status = AfterFirst(client.Status);
            if (client.Requests.Count == 2)
            {
                var healthy = HealthyOwners();
                healthy[0] = change switch {
                    "identity" => healthy[0] with { RecoveryIdentity = "replacement" },
                    "scope" => healthy[0] with { VolumeVerificationScope = null },
                    "source" => healthy[0] with { VolumeVerificationScope = healthy[0].VolumeVerificationScope! with { SourceIdentity = "replacement" } },
                    _ => healthy[0]
                };
                client.Status = client.Status with { MountedVolumes = change == "duplicate" ? [..healthy, healthy[0]] : healthy };
            }
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client);
        Assert.Equal(2, client.Requests.Count);
        Assert.All(report.Volumes, v => { Assert.Equal("Completed", v.State); Assert.True(v.Result!.Success); });
        Assert.False(report.Success); Assert.Equal(5, report.ExitCode);
        Assert.Equal("container-fix-incomplete", report.Code);
        Assert.Contains("cohort", report.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task FinalCohortAfterOnlyStatusMembersVetoesChangeOrCancellation(bool cancel)
    {
        var client = new FakeContainerVerificationClient(AfterFirst(Status()) with { MountedVolumes = HealthyOwners() });
        using var cts = new CancellationTokenSource();
        client.ReadStatus = count => {
            if (count == 4)
            {
                if (cancel) cts.Cancel();
                else client.Status = client.Status with { MountedVolumes = client.Status.MountedVolumes!.Skip(1).ToArray() };
            }
            return client.Status;
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client, cts.Token);
        Assert.All(report.Volumes, v => { Assert.Equal("NoFixNeeded", v.State); Assert.Null(v.Result); Assert.Null(v.OperationId); });
        Assert.Empty(client.Requests); Assert.Empty(client.Cancellations); Assert.False(report.OperationIssued);
        Assert.False(report.Success); Assert.Equal(cancel ? 4 : 5, report.ExitCode);
        Assert.Contains(cancel ? "cancel" : "cohort", report.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IntermediateAbsentEarlierImageMemberCanBeRestoredByLastFix()
    {
        var client = new FakeContainerVerificationClient(Status(count: 3));
        var healthy = CliContainerVerificationFixture.Status(count: 3).MountedVolumes!.Select(m => m with {
            VolumeId = m.CatalogVolumeId!, HostProcessId = 900, HostProcessCreationTimeFileTimeUtc = 134048736000000100,
            VolumeVerificationScope = m.VolumeVerificationScope! with { CheckpointXid = "91" } }).ToArray();
        var sawAbsentEarlier = false;
        client.ReadStatus = _ => {
            if (client.Requests.Count == 2) sawAbsentEarlier = client.Status.MountedVolumes!.All(m => m.VolumeId != healthy[0].VolumeId);
            return client.Status;
        };
        client.Send = (request, _) => {
            client.Status = AfterFirst(client.Status) with { MountedVolumes = client.Requests.Count == 3 ? healthy : [healthy[client.Requests.Count - 1]] };
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options(), client);
        Assert.True(sawAbsentEarlier); Assert.Equal(3, client.Requests.Count);
        Assert.Equal(healthy.Select(m => m.VolumeId), client.Requests.Select(r => r.Target!.VolumeId));
        Assert.All(client.Requests, r => Assert.Null(r.ApprovedImageRepairPlanId));
        Assert.True(report.Success, report.Diagnostic);
        Assert.All(report.Volumes, v => Assert.Equal("Completed", v.State));
    }

    [Fact]
    public async Task PhysicalRetainedOwnerCanCompleteSoleChild()
    {
        var client = new FakeContainerVerificationClient(Status(mounted: true, raw: true, count: 1));
        client.Send = (request, _) => {
            client.Status = client.Status with { MountedVolumes = client.Status.MountedVolumes!.Select(m => m with {
                AccessMode = MountAccessMode.ReadWrite, State = RuntimeState.MountedRw, WriteEnabled = true,
                NativeWriteSafetyState = NativeWriteSafetyState.StableReadWrite }).ToArray() };
            return Task.FromResult(Healthy(request));
        };
        var report = await ContainerFixBatch.RunAsync(Options() with { DeviceId = client.Status.ConnectedInventory![0].Device.DeviceId }, client);
        Assert.Single(client.Requests); Assert.True(report.Success, report.Diagnostic);
        Assert.Equal("Completed", Assert.Single(report.Volumes).State);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task DryRunOnlyInspectsInitialCohort(bool healthy)
    {
        var status = healthy ? AfterFirst(Status()) with { MountedVolumes = HealthyOwners() } : Status();
        var client = new FakeContainerVerificationClient(status);
        client.ReadStatus = count => count == 1 ? client.Status : throw new Exception("Dry run must only inspect its captured status.");
        var report = await ContainerFixBatch.RunAsync(Options(dryRun: true), client);
        Assert.True(report.Success); Assert.Equal("inspection-complete", report.Code); Assert.True(report.DryRun);
        Assert.Equal(1, client.StatusReads); Assert.False(report.OperationIssued);
        Assert.Empty(client.Requests); Assert.Empty(client.Cancellations);
        Assert.All(report.Volumes, v => { Assert.Equal("NotAttempted", v.State); Assert.Null(v.Result); Assert.Null(v.OperationId); });
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task FailedOrMismatchedChildStopsWithoutTryingPeers(bool mismatch)
    {
        var client=new FakeContainerVerificationClient(Status());client.Send=(r,_)=>Task.FromResult(mismatch?
            Healthy(r) with {Fingerprint=new string('f',64)}:Healthy(r) with {Success=false,State=ApfsOperationStates.Failed,Code=ApfsOperationCodes.OperationFailed});
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.False(report.Success);Assert.Single(client.Requests);Assert.Equal(["Failed","NotAttempted"],report.Volumes.Select(v=>v.State));
    }

    [Fact]
    public async Task CancellationOfIssuedChildOnlyRequestsItsCancellationAndLeavesPeersUnattempted()
    {
        var client=new FakeContainerVerificationClient(Status());client.Send=(_,_)=>Task.FromCanceled<OperationResultPayload>(new CancellationToken(true));
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.Equal(4,report.ExitCode);Assert.False(report.Success);Assert.Single(client.Requests);Assert.Equal(client.Requests[0].OperationId,Assert.Single(client.Cancellations));
        Assert.Equal(["Failed","NotAttempted"],report.Volumes.Select(v=>v.State));
    }

    [Fact]
    public async Task MissingContainerRefusesAndAllHealthyMembersAreOnlyStatusNoOps()
    {
        var client=new FakeContainerVerificationClient(Status());
        Assert.False((await ContainerFixBatch.RunAsync(Options() with {ContainerId=new string('f',32)},client)).Success);Assert.Empty(client.Requests);
        client.Status=AfterFirst(client.Status) with {MountedVolumes=HealthyOwners()};
        var report=await ContainerFixBatch.RunAsync(Options(),client);
        Assert.True(report.Success);Assert.Empty(client.Requests);Assert.All(report.Volumes,v=>{Assert.Equal("NoFixNeeded",v.State);Assert.Null(v.OperationId);});
    }

    [Theory]
    [InlineData("--approve-image-repair","abcd")] [InlineData("--mode","read-write")] [InlineData("--force","yes")]
    public void ContainerFixRejectsApprovalAndUnrelatedModeFlags(string option,string value)
        =>Assert.Throws<ArgumentException>(()=>ContainerCommand.Parse(["container-fix","--device-id",CliContainerVerificationFixture.Image,
            "--container-id",CliContainerVerificationFixture.Hex,option,value]));

    [Fact]
    public async Task PublicDispatchHelpAndCapabilitiesAdvertiseExistingFixBatchScope()
    {
        var old=Console.Out;using var output=new StringWriter();
        try {Console.SetOut(output);Assert.Equal(2,await Program.RunForTestAsync(["container-fix","--device-id",CliContainerVerificationFixture.Image]));}
        finally{Console.SetOut(old);}
        using(var json=JsonDocument.Parse(output.ToString()))Assert.Equal("container-fix",json.RootElement.GetProperty("command").GetString());
        foreach(var command in new[]{"help","capabilities"})
        {
            output.GetStringBuilder().Clear();try{Console.SetOut(output);Assert.Equal(0,await Program.RunForTestAsync([command]));}finally{Console.SetOut(old);}
            using var json=JsonDocument.Parse(output.ToString());
            Assert.Contains("container-fix",json.RootElement.GetProperty("commands").EnumerateArray().Select(x=>x.GetString()));
            Assert.Contains("per-volume approval",json.RootElement.GetProperty("containerFixAvailability").GetString());
        }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ExistingPipeTransportReadsFixTerminalAndRejectsWrongCorrelatedEvidence(bool mismatch)
    {
        var status=Status();var target=ContainerFixProof.CaptureForContainer(status,CliContainerVerificationFixture.Image,CliContainerVerificationFixture.Hex).Targets[0];
        var request=new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"),ApfsControlCommands.Fix,target,ExpiresAtUtc:DateTime.UtcNow.AddSeconds(80));
        var result=Healthy(request);if(mismatch)result=result with {Target=target with {RecoveryIdentity="replacement"}};
        var stream=new ScriptedVerificationStream([PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,status),
            PipeMessageCodec.Create(ApfsMessageTypes.OperationResult,result,request.OperationId,2)]);
        await using var client=new PipeContainerVerificationClient(_=>Task.FromResult(new PipePeer(stream)));
        _=await client.ReadFreshStatusAsync(CancellationToken.None);
        if(mismatch)
        {
            var error=await Assert.ThrowsAsync<IOException>(()=>client.VerifyAsync(request,CancellationToken.None));
            Assert.Equal("Malformed verification result; the child outcome is unconfirmed.",error.Message);
        }
        else {var terminal=await client.VerifyAsync(request,CancellationToken.None);ContainerFixProof.ValidateReply(request,terminal);Assert.True(terminal.Success);}
        var line=Assert.Single(Encoding.UTF8.GetString(stream.Output.ToArray()).Split('\n',StringSplitOptions.RemoveEmptyEntries));
        Assert.True(PipeMessageCodec.TryDeserialize(line,out var envelope));Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(envelope!,out var sent));
        Assert.Equal(ApfsControlCommands.Fix,sent!.Command);Assert.Equal(request.OperationId,sent.OperationId);Assert.Null(sent.ApprovedImageRepairPlanId);
    }
}
