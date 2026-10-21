using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class ContainerFixFlowTests
{
    private static DriveDashboardRow[] Rows(StatusChangedPayload s) => ContainerVerificationFixture.Rows(s);
    private static OperationResultPayload Offered(StatusChangedPayload status, ControlOperationRequestPayload request)
    {
        var volume = status.ConnectedInventory![0].Volumes.Single(v => v.VolumeId == request.Target!.VolumeId);
        var scope = VerifyScopeDerivation.TryDerive(status.ConnectedInventory[0],volume).Scope!;
        var offer = new ImageRepairOffer(new string('d',64),DateTime.UtcNow.AddMinutes(3),scope,
            request.Target!.RecoveryIdentity!,request.Target.ObservationContract!,new string('c',64),"0",
            "windows-image-v1:"+new string('a',48)+"00000000000000000000000000200000:100",new string('b',64));
        return new(request.OperationId,request.Command,request.Target,ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Failed,ApfsOperationCodes.BlockedRecovery,false,DateTime.UtcNow,DateTime.UtcNow,DateTime.UtcNow,
            FinalStatus:"repair-confirmation-required",MountProof:"absent",OwnershipProof:"proven",DurabilityProof:"proven",
            ExpiresAtUtc:request.ExpiresAtUtc,ImageRepairOffer:offer);
    }
    private static StatusChangedPayload Replace(StatusChangedPayload s, string kind)
    {
        var d = s.ConnectedInventory![0]; var t = d.Topology!.Snapshot;
        return kind switch
        {
            "source" => s with { ConnectedInventory = [d with { Topology = d.Topology with { Snapshot = t with {
                Disks = t.Disks.Select(x => x with { DeviceIdentifier = @"D:\replacement.apfs" }).ToArray() } } }] },
            "uuid" => s with { ConnectedInventory = [d with { Volumes = d.Volumes.Select((v,i) => i == 1 ? v with { CatalogVolumeUuid = new string('f',32) } : v).ToArray(),
                Topology = d.Topology with { Snapshot = t with { Volumes = t.Volumes.Select((v,i) => i == 1 ? v with { Uuid = new string('f',32) } : v).ToArray() } } }] },
            "recovery" => s with { ConnectedInventory = [d with { Volumes = d.Volumes.Select((v,i) => i == 1 ? v with { RecoveryIdentity = "replacement" } : v).ToArray() }] },
            "membership" => ContainerVerificationFixture.Status(count: 3),
            "owner" => s with { MountedVolumes = s.MountedVolumes!.Select((m,i) => i == 0 ? m with { HostProcessId = 9999 } : m).ToArray() },
            "retained-source" => s with { MountedVolumes = s.MountedVolumes!.Select(m => m with {
                VolumeVerificationScope = m.VolumeVerificationScope! with { SourceIdentity = "replaced-source" } }).ToArray() },
            "capability" => s with { ConnectedInventory = [d with { Volumes = d.Volumes.Select((v,i) => i == 1 ? v with { IsEncrypted = true } : v).ToArray() }] },
            "disconnected" => s with { ConnectedInventory = [d with { Device = d.Device with { IsConnected = false } }] },
            _ => throw new ArgumentException(kind)
        };
    }

    [Theory]
    [InlineData("source")] [InlineData("uuid")] [InlineData("recovery")] [InlineData("membership")]
    [InlineData("owner")] [InlineData("capability")] [InlineData("disconnected")]
    public async Task ReplacementBeforeDispatchNeverSends(string kind)
    {
        var status = OfflineImageFixTests.Status(mounted: true);
        var flow = ContainerFixFlow.Capture(status, Rows(status)); status = Replace(status, kind);
        var sent = 0;
        var report = await flow.RunAsync(() => status, request => { ++sent; return Task.FromResult(OfflineImageFixTests.Healthy(request)); },
            _ => throw new Exception("No approval expected."));
        Assert.False(report.Success); Assert.Equal(0, sent);
        Assert.Contains(report.Members, m => m.State == ContainerFixState.Failed);
        Assert.Equal(ContainerFixState.NotAttempted, report.Members[1].State);
    }

    [Theory]
    [InlineData("source")] [InlineData("uuid")] [InlineData("recovery")] [InlineData("membership")]
    [InlineData("owner")] [InlineData("retained-source")]
    public async Task RechecksCompletedAndUntouchedMembersBeforeEveryDispatch(string kind)
    {
        var status = OfflineImageFixTests.Status(mounted: true);
        var flow = ContainerFixFlow.Capture(status, Rows(status)); var reads = 0; var sent = 0;
        var report = await flow.RunAsync(() => { if (++reads == 3) status = Replace(status, kind); return status; }, request => {
            ++sent; status = OfflineImageFixTests.AfterFirst(status); return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."));
        Assert.Equal(1, sent); Assert.False(report.Success);
        Assert.Equal(ContainerFixState.Completed, report.Members[0].State);
        Assert.Equal(ContainerFixState.Failed, report.Members[1].State);
    }

    [Fact]
    public async Task GreenPeerIsStatusOnlyAndReceivesNoFixOrVerification()
    {
        var status = OfflineImageFixTests.Status(mounted: true);
        var flow = ContainerFixFlow.Capture(status, Rows(status)); var sent = new List<string>();
        var report = await flow.RunAsync(() => status, request => {
            sent.Add(request.Command); status = OfflineImageFixTests.AfterAll(OfflineImageFixTests.AfterFirst(status));
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."));
        Assert.True(report.Success, report.Summary); Assert.Equal([ApfsControlCommands.Fix], sent);
        Assert.Equal(ContainerFixState.Completed, report.Members[0].State);
        Assert.Equal(ContainerFixState.NoFixNeeded, report.Members[1].State);
        Assert.Contains("status only, not verified", report.Summary);
    }

    [Fact]
    public async Task DeclinedRepairStopsBatchWithoutApprovingOrClaimingRepair()
    {
        var status = OfflineImageFixTests.Status(); var flow = ContainerFixFlow.Capture(status, Rows(status));
        var sent = new List<ControlOperationRequestPayload>(); var prompts = 0;
        var report = await flow.RunAsync(() => status, request => {
            sent.Add(request); var scope = VerifyScopeDerivation.TryDerive(status.ConnectedInventory![0], status.ConnectedInventory[0].Volumes[0]).Scope!;
            var offer = new ImageRepairOffer(new string('d',64), DateTime.UtcNow.AddMinutes(3), scope,
                request.Target!.RecoveryIdentity!, request.Target.ObservationContract!, new string('c',64), "0",
                "windows-image-v1:" + new string('a',48) + "00000000000000000000000000200000:100", new string('b',64));
            return Task.FromResult(new OperationResultPayload(request.OperationId, request.Command, request.Target,
                ApfsOperationFingerprint.Compute(request), ApfsOperationStates.Failed, ApfsOperationCodes.BlockedRecovery, false,
                DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, FinalStatus: "repair-confirmation-required", MountProof: "absent",
                OwnershipProof: "proven", DurabilityProof: "proven", ExpiresAtUtc: request.ExpiresAtUtc, ImageRepairOffer: offer));
        }, _ => { ++prompts; return Task.FromResult(false); });
        Assert.False(report.Success); Assert.Single(sent); Assert.Equal(1,prompts);
        Assert.All(sent,r => Assert.Null(r.ApprovedImageRepairPlanId));
        Assert.Equal(ContainerFixState.Declined, report.Members[0].State);
        Assert.Equal(ContainerFixState.NotAttempted, report.Members[1].State);
        Assert.DoesNotContain(report.Members, m => m.State == ContainerFixState.Completed);
    }

    [Theory]
    [InlineData("membership")] [InlineData("recovery")] [InlineData("owner")] [InlineData("cancel")]
    public async Task ApprovalRechecksOriginalMembersAndCancellationBeforeApply(string change)
    {
        var status=OfflineImageFixTests.Status(mounted:true);var flow=ContainerFixFlow.Capture(status,Rows(status));var sent=0;var prompts=0;
        using var cts=new CancellationTokenSource();
        var report=await flow.RunAsync(()=>status,request=>{++sent;return Task.FromResult(Offered(status,request));},_=>{
            ++prompts;
            if(change=="cancel")cts.Cancel();else status=Replace(status,change);
            return Task.FromResult(true);
        },cts.Token);
        Assert.Equal(1,prompts);Assert.Equal(1,sent);Assert.False(report.Success);
        Assert.Equal(ContainerFixState.Failed,report.Members[0].State);Assert.Equal(ContainerFixState.NotAttempted,report.Members[1].State);
    }

    [Fact]
    public async Task ExplicitConfirmationCanDrainOldCohortThenCompleteWithoutApprovingPeer()
    {
        var status=OfflineImageFixTests.Status(mounted:true);var flow=ContainerFixFlow.Capture(status,Rows(status));
        var sent=new List<ControlOperationRequestPayload>();ImageRepairOffer? binding=null;var prompts=0;
        var report=await flow.RunAsync(()=>status,request=>{
            sent.Add(request);
            if(request.ApprovedImageRepairPlanId is null){var offered=Offered(status,request);binding=offered.ImageRepairOffer;return Task.FromResult(offered);}
            status=OfflineImageFixTests.AfterAll(OfflineImageFixTests.AfterFirst(status));
            return Task.FromResult(OfflineImageFixTests.Healthy(request) with {
                ApprovedImageRepairPlanId=request.ApprovedImageRepairPlanId,
                ImageRepairReceipt=new(binding!.PlanId,"repaired",binding,@"D:\ApfsAccessScratch\test-original.rct2",@"D:\ApfsAccessScratch\test-evidence",
                    "RepairedAndVerified",0,NativePostVerifyComplete:true)});
        },_=>{++prompts;status=status with {MountedVolumes=[]};return Task.FromResult(true);});
        Assert.True(report.Success,report.Summary);Assert.Equal(1,prompts);Assert.Equal(2,sent.Count);
        Assert.Null(sent[0].ApprovedImageRepairPlanId);Assert.Equal(binding!.PlanId,sent[1].ApprovedImageRepairPlanId);
        Assert.Equal(ContainerFixState.Completed,report.Members[0].State);Assert.Equal(ContainerFixState.NoFixNeeded,report.Members[1].State);
    }

    [Fact]
    public async Task PhysicalRoFixMayReplaceCohortButRemainingMembersRequireRefresh()
    {
        var status=ContainerVerificationFixture.Status(raw:true);
        status=status with {MountedVolumes=status.MountedVolumes!.Select(m=>m with {AccessMode=MountAccessMode.ReadOnly,
            State=RuntimeState.MountedRo,WriteEnabled=false,NativeWriteSafetyState=NativeWriteSafetyState.ReadOnlyFallback}).ToArray()};
        var flow=ContainerFixFlow.Capture(status,Rows(status));var sent=0;
        var report=await flow.RunAsync(()=>status,request=>{
            ++sent;status=ContainerVerificationFixture.Status(raw:true) with {MountedVolumes=ContainerVerificationFixture.Status(raw:true).MountedVolumes!.Select(m=>m with {
                HostProcessId=900,HostProcessCreationTimeFileTimeUtc=134048736000000100}).ToArray()};
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        },_=>throw new Exception("No image approval on physical Fix."));
        Assert.Equal(1,sent);Assert.False(report.Success);
        Assert.Equal(ContainerFixState.Completed,report.Members[0].State);Assert.Equal(ContainerFixState.NotAttempted,report.Members[1].State);
        Assert.Contains("physical owner cohort changed",report.Summary);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PhysicalReplacementOnLastOrSoleChildRetainsBatchStop(bool sole)
    {
        var count = sole ? 1 : 2;
        var status = ContainerVerificationFixture.Status(count: count, raw: true);
        status = status with { MountedVolumes = status.MountedVolumes!.Select((m, i) => i == count - 1 ? m with {
            AccessMode = MountAccessMode.ReadOnly, State = RuntimeState.MountedRo, WriteEnabled = false,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback } : m).ToArray() };
        var originalRows = Rows(status);
        var flow = ContainerFixFlow.Capture(status, originalRows);
        var sent = new List<ControlOperationRequestPayload>();
        var report = await flow.RunAsync(() => status, request => {
            sent.Add(request);
            status = status with { MountedVolumes = status.MountedVolumes!.Select(m => m with {
                AccessMode = MountAccessMode.ReadWrite, State = RuntimeState.MountedRw, WriteEnabled = true,
                NativeWriteSafetyState = NativeWriteSafetyState.StableReadWrite, HostProcessId = 900,
                HostProcessCreationTimeFileTimeUtc = 134048736000000100 }).ToArray() };
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("Physical Fix cannot request image repair approval."));
        var child = Assert.Single(sent);
        Assert.Equal(originalRows[^1].VolumeId, child.Target!.VolumeId);
        Assert.Null(child.ApprovedImageRepairPlanId);
        Assert.Equal(sole ? [ContainerFixState.Completed] : new[] { ContainerFixState.NoFixNeeded, ContainerFixState.Completed },
            report.Members.Select(m => m.State));
        Assert.DoesNotContain(report.Members, m => m.State is ContainerFixState.Failed or ContainerFixState.NotAttempted);
        Assert.False(report.Success);
        Assert.Contains("physical owner cohort changed", report.Summary);
        Assert.Contains("Refresh", report.Summary);
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
        var status = earlierWasStatusOnly ? OfflineImageFixTests.AfterFirst(OfflineImageFixTests.Status()) : OfflineImageFixTests.Status();
        var original = Rows(status);
        var flow = ContainerFixFlow.Capture(status, original);
        var sent = new List<ControlOperationRequestPayload>();
        var lastSucceeded = false; var deferred = false;
        StatusChangedPayload ChangeEarlier(StatusChangedPayload s) => s with { MountedVolumes = change == "cohort-replaced"
            ? s.MountedVolumes!.Select(m => m with { HostProcessId = 950, HostProcessCreationTimeFileTimeUtc = 134048736000000200 }).ToArray()
            : change == "missing"
            ? s.MountedVolumes!.Where(m => m.VolumeId != original[0].VolumeId).ToArray()
            : s.MountedVolumes!.Select(m => m.VolumeId != original[0].VolumeId ? m : change == "replaced"
                ? m with { HostProcessId = 777 } : m with { WriteEnabled = false }).ToArray() };
        var report = await flow.RunAsync(() => {
            var snapshot = status;
            if (lastSucceeded && afterLastObservation && !deferred)
            { deferred = true; status = ChangeEarlier(status); }
            return snapshot;
        }, request => {
            sent.Add(request);
            if (request.Target!.VolumeId == original[0].VolumeId) status = OfflineImageFixTests.AfterFirst(status);
            else
            {
                lastSucceeded = true;
                status = OfflineImageFixTests.AfterAll(status);
                if (!afterLastObservation) status = ChangeEarlier(status);
            }
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval is required for these acknowledged successes."));
        Assert.True(lastSucceeded);
        Assert.True(TopologyAdmission.Validate(status.ConnectedInventory![0]));
        if (change == "missing") Assert.DoesNotContain(status.MountedVolumes!, m => m.VolumeId == original[0].VolumeId);
        else if (change is "replaced" or "cohort-replaced") Assert.Equal(change == "replaced" ? 777 : 950,
            status.MountedVolumes!.Single(m => m.VolumeId == original[0].VolumeId).HostProcessId);
        else Assert.False(status.MountedVolumes!.Single(m => m.VolumeId == original[0].VolumeId).WriteEnabled);
        Assert.Equal(earlierWasStatusOnly ? 1 : 2, sent.Count);
        Assert.All(sent, r => Assert.Null(r.ApprovedImageRepairPlanId));
        Assert.Equal(new[] { earlierWasStatusOnly ? ContainerFixState.NoFixNeeded : ContainerFixState.Completed, ContainerFixState.Completed },
            report.Members.Select(m => m.State));
        Assert.False(report.Success);
        Assert.NotNull(report.StopReason);
        Assert.Contains("cohort", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("source")] [InlineData("uuid")] [InlineData("recovery")] [InlineData("membership")]
    [InlineData("owner")] [InlineData("retained-source")] [InlineData("capability")] [InlineData("disconnected")]
    public async Task FinalCohortObservationRechecksBindingAfterLastChild(string change)
    {
        var status = OfflineImageFixTests.Status();
        var flow = ContainerFixFlow.Capture(status, Rows(status));
        var sent = 0; var finalReads = 0; var deferred = false;
        var report = await flow.RunAsync(() => {
            var snapshot = status;
            if (sent == 2)
            {
                ++finalReads;
                if (!deferred) { deferred = true; status = Replace(status, change); }
            }
            return snapshot;
        }, request => {
            status = ++sent == 1 ? OfflineImageFixTests.AfterFirst(status) : OfflineImageFixTests.AfterAll(status);
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."));
        Assert.Equal(2, sent);
        Assert.All(report.Members, m => Assert.Equal(ContainerFixState.Completed, m.State));
        Assert.False(report.Success);
        Assert.Equal(2, finalReads);
        Assert.Contains("Final original cohort", report.StopReason);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task CancellationAtFinalObservationRetainsAcknowledgedHistory(bool lastStatusOnly)
    {
        var status = OfflineImageFixTests.Status();
        var flow = ContainerFixFlow.Capture(status, Rows(status));
        using var cts = new CancellationTokenSource();
        var reads = 0; var sent = 0;
        var report = await flow.RunAsync(() => {
            if (++reads == (lastStatusOnly ? 4 : 5)) cts.Cancel();
            return status;
        }, request => {
            ++sent;
            status = sent == 1 ? OfflineImageFixTests.AfterFirst(status) : OfflineImageFixTests.AfterAll(status);
            if (lastStatusOnly) status = OfflineImageFixTests.AfterAll(status);
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."), cts.Token);
        Assert.Equal(lastStatusOnly ? 1 : 2, sent);
        Assert.Equal(new[] { ContainerFixState.Completed, lastStatusOnly ? ContainerFixState.NoFixNeeded : ContainerFixState.Completed },
            report.Members.Select(m => m.State));
        Assert.False(report.Success);
        Assert.True(cts.IsCancellationRequested);
        Assert.Contains("cancel", report.StopReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CancellationOnLastStatusOnlyObservationVetoesSuccess()
    {
        var status = OfflineImageFixTests.Status(); var flow = ContainerFixFlow.Capture(status, Rows(status));
        using var cts = new CancellationTokenSource(); var reads = 0; var sent = 0;
        var report = await flow.RunAsync(() => { if (++reads == 3) cts.Cancel(); return status; }, request => {
            ++sent; status = OfflineImageFixTests.AfterAll(OfflineImageFixTests.AfterFirst(status));
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."), cts.Token);
        Assert.True(cts.IsCancellationRequested); Assert.Equal(1, sent);
        Assert.Equal(new[] { ContainerFixState.Completed, ContainerFixState.NoFixNeeded }, report.Members.Select(m => m.State));
        Assert.False(report.Success);
        Assert.Contains("cancel", report.StopReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FinalObservationFailureRetainsAcknowledgedChildren()
    {
        var status = OfflineImageFixTests.Status(); var flow = ContainerFixFlow.Capture(status, Rows(status));
        var reads = 0; var sent = 0;
        var report = await flow.RunAsync(() => ++reads == 5 ? throw new IOException("Final status unavailable.") : status, request => {
            status = ++sent == 1 ? OfflineImageFixTests.AfterFirst(status) : OfflineImageFixTests.AfterAll(status);
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."));
        Assert.Equal(2, sent); Assert.All(report.Members, m => Assert.Equal(ContainerFixState.Completed, m.State));
        Assert.False(report.Success);
        Assert.Contains("Final status unavailable", report.StopReason);
    }

    [Theory]
    [InlineData("identity")] [InlineData("scope")] [InlineData("source")] [InlineData("duplicate")]
    public async Task AcknowledgedLastChildWithInvalidPeerEvidenceKeepsHistory(string change)
    {
        var status = OfflineImageFixTests.Status(); var flow = ContainerFixFlow.Capture(status, Rows(status)); var sent = 0;
        var report = await flow.RunAsync(() => status, request => {
            status = OfflineImageFixTests.AfterFirst(status);
            if (++sent == 2)
            {
                var healthy = OfflineImageFixTests.AfterAll(status).MountedVolumes!.ToArray();
                healthy[0] = change switch {
                    "identity" => healthy[0] with { RecoveryIdentity = "replacement" },
                    "scope" => healthy[0] with { VolumeVerificationScope = null },
                    "source" => healthy[0] with { VolumeVerificationScope = healthy[0].VolumeVerificationScope! with { SourceIdentity = "replacement" } },
                    _ => healthy[0]
                };
                status = status with { MountedVolumes = change == "duplicate" ? [..healthy, healthy[0]] : healthy };
            }
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."));
        Assert.Equal(2, sent); Assert.All(report.Members, m => Assert.Equal(ContainerFixState.Completed, m.State));
        Assert.False(report.Success);
        Assert.Contains("cohort", report.StopReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IntermediateAbsentEarlierImageMemberCanBeRestoredByLastFix()
    {
        var status = ContainerVerificationFixture.Status(count: 3, live: false);
        var healthy = ContainerVerificationFixture.Status(count: 3).MountedVolumes!.Select(m => m with {
            HostProcessId = 900, HostProcessCreationTimeFileTimeUtc = 134048736000000100,
            VolumeVerificationScope = m.VolumeVerificationScope! with { CheckpointXid = "91" } }).ToArray();
        var flow = ContainerFixFlow.Capture(status, Rows(status)); var sent = new List<ControlOperationRequestPayload>();
        var sawAbsentEarlier = false;
        var report = await flow.RunAsync(() => {
            if (sent.Count == 2) sawAbsentEarlier = status.MountedVolumes!.All(m => m.VolumeId != healthy[0].VolumeId);
            return status;
        }, request => {
            sent.Add(request);
            status = OfflineImageFixTests.AfterFirst(status) with { MountedVolumes = sent.Count == 3 ? healthy : [healthy[sent.Count - 1]] };
            return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("No approval expected."));
        Assert.True(sawAbsentEarlier); Assert.Equal(3, sent.Count);
        Assert.Equal(healthy.Select(m => m.VolumeId), sent.Select(r => r.Target!.VolumeId));
        Assert.All(sent, r => Assert.Null(r.ApprovedImageRepairPlanId));
        Assert.True(report.Success, report.Summary);
        Assert.All(report.Members, m => Assert.Equal(ContainerFixState.Completed, m.State));
    }

    [Fact]
    public async Task PhysicalRetainedOwnerCanCompleteSoleChild()
    {
        var status = ContainerVerificationFixture.Status(count: 1, raw: true);
        var healthy = status;
        status = status with { MountedVolumes = status.MountedVolumes!.Select(m => m with {
            AccessMode = MountAccessMode.ReadOnly, State = RuntimeState.MountedRo, WriteEnabled = false }).ToArray() };
        var flow = ContainerFixFlow.Capture(status, Rows(status)); var sent = 0;
        var report = await flow.RunAsync(() => status, request => {
            ++sent; status = healthy; return Task.FromResult(OfflineImageFixTests.Healthy(request));
        }, _ => throw new Exception("Physical Fix cannot request image approval."));
        Assert.Equal(1, sent); Assert.True(report.Success, report.Summary);
        Assert.Equal(ContainerFixState.Completed, Assert.Single(report.Members).State);
    }

    [Fact]
    public async Task CancellationBeforeDispatchStopsEveryMember()
    {
        var status = OfflineImageFixTests.Status(); var flow = ContainerFixFlow.Capture(status, Rows(status));
        using var cts = new CancellationTokenSource(); cts.Cancel();
        var report = await flow.RunAsync(() => status, _ => throw new Exception("No dispatch after cancellation."),
            _ => throw new Exception("No approval after cancellation."), cts.Token);
        Assert.False(report.Success); Assert.All(report.Members,m => Assert.Equal(ContainerFixState.NotAttempted,m.State));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task UnconfirmedFailureOrMismatchedReplyStopsRemainingPeers(bool mismatch)
    {
        var status = OfflineImageFixTests.Status(mounted:true); var flow = ContainerFixFlow.Capture(status,Rows(status)); var sent=0;
        var report = await flow.RunAsync(() => status,request => {
            ++sent;
            return Task.FromResult(mismatch ? OfflineImageFixTests.Healthy(request) with { Fingerprint = new string('f',64) } :
                OfflineImageFixTests.Healthy(request) with { Success=false, State=ApfsOperationStates.Failed, Code=ApfsOperationCodes.BlockedRecovery });
        },_ => throw new Exception("No approval expected."));
        Assert.False(report.Success);Assert.Equal(1,sent);Assert.Equal(ContainerFixState.Failed,report.Members[0].State);
        Assert.Equal(ContainerFixState.NotAttempted,report.Members[1].State);
    }

    [Fact]
    public void EmptyEligibleSetAndIncompleteSelectionsRefuse()
    {
        var status=OfflineImageFixTests.Status(); var rows=Rows(status);
        Assert.Throws<InvalidOperationException>(()=>ContainerFixFlow.Capture(status,[]));
        Assert.Throws<InvalidOperationException>(()=>ContainerFixFlow.Capture(status,[rows[0]]));
        Assert.Throws<InvalidOperationException>(()=>ContainerFixFlow.Capture(status,[rows[0],rows[0]]));
        var healthy=ContainerVerificationFixture.Status();
        Assert.Throws<InvalidOperationException>(()=>ContainerFixFlow.Capture(healthy,Rows(healthy)));
    }
}
