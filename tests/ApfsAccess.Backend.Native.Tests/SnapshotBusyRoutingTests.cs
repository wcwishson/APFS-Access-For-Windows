using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class SnapshotBusyRoutingTests
{
    private const string CapturedHash = "77F7661E46A17CDBE73D74A3D874D9AC18C33CCEFEE29DBA932283AEF48A53AF";
    private static readonly string[] DeleteIdentity = ["21", "backup", "249", "17", "230", "8293", "8", "250", "7"];

    [SnapshotBusyStatusFact]
    public void CapturedCleanWatermarksDoNotInferCapabilitiesAndRetainExplicitBusyReason()
    {
        var status = ContainerStatusReader.Parse(Captured().ToJsonString());
        Assert.Equal(2, status.Volumes.Count);
        Assert.False(status.RecoveryRequired);
        foreach (var volume in status.Volumes)
        {
            Assert.Equal("SnapshotControlBusy", volume.SnapshotControlRefusal);
            Assert.False(volume.SnapshotInventorySupported);
            Assert.False(volume.SnapshotMutationSupported);
            Assert.NotNull(volume.Drain);
            Assert.Equal(volume.Drain.Accepted, volume.Drain.Durable);
            Assert.Equal(volume.Drain.Durable, volume.Drain.Cleanup);
            Assert.Equal(0, volume.Drain.DirtyTransactions);
        }
    }

    [SnapshotBusyStatusTheory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("42")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("oversized")]
    [InlineData("inventory-contradiction")]
    [InlineData("mutation-contradiction")]
    public void OptionalReasonRejectsMalformedTypesBoundsAndContradictoryBusyClaims(string failure)
    {
        var raw = Captured(); var row = Child(raw);
        if (failure == "oversized") row["snapshotControlRefusal"] = new string('x', 257);
        else if (failure == "inventory-contradiction") row["snapshotInventorySupported"] = true;
        else if (failure == "mutation-contradiction") row["snapshotMutationSupported"] = true;
        else row["snapshotControlRefusal"] = JsonNode.Parse(failure);
        Assert.Throws<ContainerManifestException>(() => ContainerStatusReader.Parse(raw.ToJsonString()));
        using var route = new RetainedRoute(raw);
        var status = ContainerStatusReader.TryRead(route.StatusPath, route.Container);
        Assert.False(status.IsKnown);
        Assert.Equal(ContainerStatusUnknownReasons.SchemaViolation, status.UnknownReason);
    }

    [SnapshotBusyStatusFact]
    public void OptionalReasonSupportsLegacyAbsenceEmptyAndBoundedOtherDiagnostics()
    {
        var raw = Captured(); var row = Child(raw);
        row.AsObject().Remove("snapshotControlRefusal");
        Assert.Equal("", ContainerStatusReader.Parse(raw.ToJsonString()).Volumes.Single(v => v.ObjectId == 201).SnapshotControlRefusal);
        row["snapshotControlRefusal"] = "";
        Assert.Equal("", ContainerStatusReader.Parse(raw.ToJsonString()).Volumes.Single(v => v.ObjectId == 201).SnapshotControlRefusal);
        row["snapshotControlRefusal"] = new string('x', 256);
        Assert.Equal(256, ContainerStatusReader.Parse(raw.ToJsonString()).Volumes.Single(v => v.ObjectId == 201).SnapshotControlRefusal.Length);
    }

    [SnapshotBusyStatusTheory]
    [InlineData(SnapshotControlAction.List)]
    [InlineData(SnapshotControlAction.Create)]
    [InlineData(SnapshotControlAction.Delete)]
    public async Task ExplicitBusyWaitsForFreshEligibleStatusBeforeAuthenticatedDispatch(SnapshotControlAction action)
    {
        using var route = new RetainedRoute(Captured());
        var pending = route.Send(action);
        await Task.Delay(250);
        Assert.False(pending.IsCompleted, "An explicit busy status must wait for the next native status tick.");
        Assert.False(File.Exists(route.ControlPath));
        Assert.Equal(0, route.Gate.CurrentCount);
        route.Publish(Eligible(Captured()));
        var lines = await route.Request(pending);
        AssertEnvelope(route, action, lines);
        await route.Reply(lines, action);
        var result = await pending;
        Assert.True(result.Success, result.Code);
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusTheory]
    [InlineData(SnapshotControlAction.List, null)]
    [InlineData(SnapshotControlAction.Create, null)]
    [InlineData(SnapshotControlAction.Delete, null)]
    [InlineData(SnapshotControlAction.Delete, "SnapshotRuntimeDeleteStaleIdentity")]
    public async Task NativePreacceptanceBusyUsesFreshNonceAndRereadsStatusWithoutChangingRequest(SnapshotControlAction action, string? terminalCode)
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        var extras = Extras(action);
        var original = extras?.ToArray();
        var pending = route.Send(action, extras);
        var first = await route.Request(pending);
        AssertEnvelope(route, action, first);
        route.Publish(Captured());
        await route.Reply(first, action, "SnapshotControlBusy");
        if (extras is { Length: > 0 }) extras[0] = "999";
        await Task.Delay(250);
        Assert.False(pending.IsCompleted);
        Assert.False(File.Exists(route.ControlPath), "A cached capability must not authorize another dispatch while current status is busy.");
        route.Publish(Eligible(Captured()));
        var second = await route.Request(pending, first[1]);
        AssertEnvelope(route, action, second);
        Assert.NotEqual(first[1], second[1]);
        Assert.Equal(first[2], second[2]);
        Assert.Equal(original ?? [], second.Skip(5));
        await route.Reply(second, action, terminalCode);
        var result = await pending;
        Assert.Equal(terminalCode is null, result.Success);
        if (terminalCode is not null) Assert.Equal(terminalCode, result.Code);
        await Task.Delay(150);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusTheory]
    [InlineData("SnapshotStaleIdentity")]
    [InlineData("SnapshotRuntimeDeleteStaleIdentity")]
    [InlineData("SnapshotApplyFailed")]
    [InlineData("SnapshotAcceptedRecoveryRequired")]
    [InlineData("ControlCanceledAfterPublish")]
    [InlineData("ControlResponseInvalid")]
    [InlineData("ControlResponseTimeout")]
    [InlineData("ControlEndpointBusy")]
    [InlineData("SnapshotControlPeersInvalid")]
    [InlineData("SnapshotRuntimeOwnerNotReady")]
    [InlineData("SnapshotControlBusy ")]
    [InlineData("snapshotcontrolbusy")]
    public async Task OtherNativeOrAmbiguousFailuresNeverRetryOrChangeDeleteIdentity(string code)
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        var pending = route.Send(SnapshotControlAction.Delete);
        var lines = await route.Request(pending);
        AssertEnvelope(route, SnapshotControlAction.Delete, lines);
        await route.Reply(lines, SnapshotControlAction.Delete, code);
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(result.Success);
        Assert.Equal(code == "SnapshotControlBusy " ? "ControlResponseInvalid" : code, result.Code);
        await Task.Delay(150);
        Assert.False(File.Exists(route.ControlPath));
        Assert.False(File.Exists(route.ControlPath + ".response"));
    }

    [SnapshotBusyStatusFact]
    public async Task UnauthenticatedBusyResponseIsAmbiguousAndNeverRetried()
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        var pending = route.Send(SnapshotControlAction.Delete);
        var lines = await route.Request(pending);
        AssertEnvelope(route, SnapshotControlAction.Delete, lines);
        await route.Reply(lines, SnapshotControlAction.Delete, "SnapshotControlBusy", new string('f', 32));
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("ControlResponseInvalid", result.Code);
        await Task.Delay(150);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusTheory]
    [InlineData("dirty")]
    [InlineData("peer-debt")]
    [InlineData("profile")]
    [InlineData("owner")]
    [InlineData("status-member")]
    [InlineData("refusal")]
    [InlineData("stale")]
    public async Task NativeBusyRetryRevalidatesFullStatusEvenWhenCapabilitiesAreTrue(string failure)
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        var pending = route.Send(SnapshotControlAction.List);
        var lines = await route.Request(pending);
        var raw = Eligible(Captured());
        switch (failure)
        {
            case "dirty": Child(raw)["dirtyTransactionCount"] = 1; break;
            case "peer-debt": Child(raw, 202)["walAcceptedSequence"] = 28; break;
            case "profile": route.Options.NativeWriteRequireCanonicalCommit = false; break;
            case "status-member": Child(raw)["recoveryIdentity"] = "wrong"; break;
            case "refusal": Child(raw)["snapshotControlRefusal"] = "SnapshotCleanPeerJournalRequired"; break;
        }
        route.Publish(raw, ownerStartDelta: failure == "owner" ? 1 : 0);
        if (failure == "stale") File.SetLastWriteTimeUtc(route.StatusPath, DateTime.UtcNow.AddMinutes(-2));
        await route.Reply(lines, SnapshotControlAction.List, "SnapshotControlBusy");
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("SnapshotRuntimeOwnerNotReady", result.Code);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusFact]
    public async Task PermanentExplicitBusyIsBoundedWithoutPublishingAnyChannelRequest()
    {
        using var route = new RetainedRoute(Captured());
        var watch = Stopwatch.StartNew();
        var result = await route.Send(SnapshotControlAction.List).WaitAsync(TimeSpan.FromSeconds(8));
        RecordTiming("permanent-status-busy", watch.Elapsed, 0, result.Code);
        Assert.False(result.Success); Assert.Equal("SnapshotControlBusy", result.Code);
        Assert.InRange(watch.Elapsed.TotalSeconds, 4.8, 6.5);
        Assert.False(File.Exists(route.ControlPath));
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusFact]
    public async Task StatusAndNativeResponseBusyShareOneWallBudget()
    {
        using var route = new RetainedRoute(Captured());
        var watch = Stopwatch.StartNew();
        var pending = route.Send(SnapshotControlAction.Delete);
        await Task.Delay(3000);
        Assert.False(pending.IsCompleted); Assert.False(File.Exists(route.ControlPath));
        route.Publish(Eligible(Captured()));
        string? nonce = null;
        var attempts = 0;
        // Finish both acknowledged exchanges before waiting out the remaining
        // budget in a known-busy status; an unanswered dispatch is a different case.
        while (attempts < 2)
        {
            var lines = await route.Request(pending, nonce);
            AssertEnvelope(route, SnapshotControlAction.Delete, lines);
            nonce = lines[1]; ++attempts;
            if (attempts == 2) route.Publish(Captured());
            await route.Reply(lines, SnapshotControlAction.Delete, "SnapshotControlBusy");
        }
        Assert.Null(await route.RequestOrCompletion(pending, nonce));
        var result = await pending;
        RecordTiming("shared-status-channel-busy", watch.Elapsed, attempts, result.Code);
        Assert.False(result.Success); Assert.Equal("SnapshotControlBusy", result.Code);
        Assert.Equal(2, attempts);
        Assert.InRange(watch.Elapsed.TotalSeconds, 4.8, 6.5);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusFact]
    public async Task BusyWaitDoesNotConsumePublishedResponseBudget()
    {
        using var route = new RetainedRoute(Captured());
        var watch = Stopwatch.StartNew();
        var pending = route.Send(SnapshotControlAction.Delete);
        await Task.Delay(3500);
        route.Publish(Eligible(Captured()));
        var lines = await route.Request(pending);
        AssertEnvelope(route, SnapshotControlAction.Delete, lines);
        var dispatched = Stopwatch.StartNew();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(3));
        RecordTiming("busy-then-response-timeout", watch.Elapsed, 1, result.Code);
        Assert.False(result.Success);
        Assert.Equal("ControlResponseTimeout", result.Code);
        Assert.InRange(dispatched.Elapsed.TotalSeconds, 1.9, 3);
        Assert.False(File.Exists(route.ControlPath));
        Assert.False(File.Exists(route.ControlPath + ".response"));
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusTheory]
    [InlineData(SnapshotControlAction.Create)]
    [InlineData(SnapshotControlAction.Delete)]
    [InlineData(SnapshotControlAction.List)]
    public async Task PublishedRequestCanCompleteAfterFiveSecondsWithinOwnerResponseBudget(SnapshotControlAction action)
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        route.Options.NativeHostStopTimeoutSeconds = 8;
        var watch = Stopwatch.StartNew();
        var pending = route.Send(action);
        var lines = await route.Request(pending);
        AssertEnvelope(route, action, lines);
        await Task.Delay(5600);
        Assert.False(pending.IsCompleted, "The preacceptance busy deadline must not cancel an already published request.");
        Assert.Equal(lines, await File.ReadAllLinesAsync(route.ControlPath));
        Assert.Equal(0, route.Gate.CurrentCount);
        await route.Reply(lines, action);
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(2));
        RecordTiming("delayed-success-" + action, watch.Elapsed, 1, result.Code, 8);
        Assert.True(result.Success, result.Code);
        Assert.Equal(1, route.Gate.CurrentCount);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusFact]
    public async Task LateAuthenticatedPreacceptanceBusyCannotRestartExpiredBusyWindow()
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        route.Options.NativeHostStopTimeoutSeconds = 8;
        var pending = route.Send(SnapshotControlAction.Delete);
        var lines = await route.Request(pending);
        await Task.Delay(5600);
        Assert.False(pending.IsCompleted);
        await route.Reply(lines, SnapshotControlAction.Delete, "SnapshotControlBusy");
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("SnapshotControlBusy", result.Code);
        Assert.False(File.Exists(route.ControlPath));
        Assert.False(File.Exists(route.ControlPath + ".response"));
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusFact]
    public async Task ResponseTimeoutNeverRetriesAndLateCompletionIsNotConsumedAsANewRequest()
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        var pending = route.Send(SnapshotControlAction.Delete);
        var lines = await route.Request(pending);
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.False(result.Success); Assert.Equal("ControlResponseTimeout", result.Code);
        Assert.False(File.Exists(route.ControlPath));
        await route.Reply(lines, SnapshotControlAction.Delete);
        var next = await route.Send(SnapshotControlAction.Delete).WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(next.Success); Assert.Equal("ControlEndpointBusy", next.Code);
        Assert.False(File.Exists(route.ControlPath));
        Assert.True(File.Exists(route.ControlPath + ".response"));
        Assert.Equal("ControlResponseTimeout", (await pending).Code);
    }

    [SnapshotBusyStatusFact]
    public async Task CancellationAfterFiveSecondsStillReportsPublishedAmbiguityWithoutRetry()
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        route.Options.NativeHostStopTimeoutSeconds = 8;
        using var cancellation = new CancellationTokenSource();
        var pending = route.Send(SnapshotControlAction.Delete, cancellation: cancellation.Token);
        var lines = await route.Request(pending);
        await Task.Delay(5600);
        Assert.False(pending.IsCompleted);
        cancellation.Cancel();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("ControlCanceledAfterPublish", result.Code);
        await route.Reply(lines, SnapshotControlAction.Delete);
        await Task.Delay(150);
        Assert.False(File.Exists(route.ControlPath));
        Assert.True(File.Exists(route.ControlPath + ".response"));
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusFact]
    public async Task BusyStatusWaitIsCancellableAndReleasesGateWithoutDispatch()
    {
        using var route = new RetainedRoute(Captured());
        using var cancellation = new CancellationTokenSource();
        var pending = route.Send(SnapshotControlAction.Create, cancellation: cancellation.Token);
        await Task.Delay(150);
        Assert.False(pending.IsCompleted);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        Assert.False(File.Exists(route.ControlPath));
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusFact]
    public async Task CancellationAfterPublishReturnsAmbiguousFailureWithoutRetry()
    {
        using var route = new RetainedRoute(Eligible(Captured()));
        using var cancellation = new CancellationTokenSource();
        var pending = route.Send(SnapshotControlAction.Create, cancellation: cancellation.Token);
        await route.Request(pending);
        cancellation.Cancel();
        var result = await pending;
        Assert.False(result.Success); Assert.Equal("ControlCanceledAfterPublish", result.Code);
        await Task.Delay(150);
        Assert.False(File.Exists(route.ControlPath));
        Assert.Equal(1, route.Gate.CurrentCount);
    }

    [SnapshotBusyStatusTheory]
    [InlineData("legacy")]
    [InlineData("empty")]
    [InlineData("generic")]
    [InlineData("other-refusal")]
    [InlineData("case")]
    [InlineData("whitespace")]
    [InlineData("dirty")]
    [InlineData("deferred")]
    [InlineData("recovery")]
    [InlineData("degraded")]
    [InlineData("stale")]
    [InlineData("malformed")]
    [InlineData("profile")]
    public async Task UnsupportedUnknownDirtyAndLegacyStatusRefuseImmediately(string failure)
    {
        var raw = Captured(); var row = Child(raw);
        switch (failure)
        {
            case "legacy": row.AsObject().Remove("snapshotControlRefusal"); break;
            case "empty": row["snapshotControlRefusal"] = ""; break;
            case "generic": row["snapshotControlRefusal"] = "OwnerNotReady"; break;
            case "other-refusal": row["snapshotControlRefusal"] = "SnapshotCleanPeerJournalRequired"; break;
            case "case": row["snapshotControlRefusal"] = "snapshotcontrolbusy"; break;
            case "whitespace": row["snapshotControlRefusal"] = "SnapshotControlBusy "; break;
            case "dirty": row["walAcceptedSequence"] = 45; row["dirtyTransactionCount"] = 1; break;
            case "deferred": row["deferredCommitRequested"] = true; break;
            case "recovery": raw["recoveryRequired"] = true; raw["recoveryVolumeObjectId"] = 201;
                raw["recoveryReason"] = "OwnerLatched"; row["writable"] = false; Child(raw, 202)["writable"] = false; break;
            case "degraded": row["writeDegraded"] = true; row["writable"] = false; break;
            case "malformed": row["snapshotControlRefusal"] = 42; break;
        }
        using var route = new RetainedRoute(raw);
        if (failure == "stale") File.SetLastWriteTimeUtc(route.StatusPath, DateTime.UtcNow.AddMinutes(-2));
        if (failure == "profile") route.Options.NativeWriteRequireCanonicalCommit = false;
        var pending = route.Send(SnapshotControlAction.List);
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("SnapshotRuntimeOwnerNotReady", result.Code);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusTheory]
    [InlineData("owner-start")]
    [InlineData("owner-pid")]
    [InlineData("lease")]
    [InlineData("status-member")]
    [InlineData("group-owner")]
    [InlineData("retained-member")]
    [InlineData("malformed-reason")]
    [InlineData("changed-refusal")]
    public async Task RetryRefusesChangedOwnerLeaseMemberOrReasonBeforeDispatch(string failure)
    {
        using var route = new RetainedRoute(Captured());
        var pending = route.Send(SnapshotControlAction.Delete);
        await Task.Delay(150);
        Assert.False(pending.IsCompleted);
        var raw = Eligible(Captured());
        switch (failure)
        {
            case "owner-start": route.Publish(raw, ownerStartDelta: 1); break;
            case "owner-pid": route.Publish(raw, ownerPid: 0); break;
            case "lease": raw["leaseHeld"] = false; Child(raw)["snapshotInventorySupported"] = false;
                Child(raw)["snapshotMutationSupported"] = false; route.Publish(raw); break;
            case "status-member": Child(raw)["recoveryIdentity"] = "wrong"; route.Publish(raw); break;
            case "group-owner": route.ReplaceGroup(); route.Publish(raw); break;
            case "retained-member": route.ReplaceMember(); route.Publish(raw); break;
            case "malformed-reason": Child(raw)["snapshotControlRefusal"] = null; route.Publish(raw); break;
            default: Child(raw)["snapshotInventorySupported"] = false; Child(raw)["snapshotMutationSupported"] = false;
                Child(raw)["snapshotControlRefusal"] = "SnapshotCleanPeerJournalRequired"; route.Publish(raw); break;
        }
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("SnapshotRuntimeOwnerNotReady", result.Code);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotBusyStatusFact]
    public async Task RecoveryDoesNotWaitForBusyOrRetryItsNativeResponse()
    {
        var raw = Captured(); Child(raw)["snapshotRecoverySupported"] = true;
        using var route = new RetainedRoute(raw);
        var pending = route.Send(SnapshotControlAction.Recover);
        var lines = await route.Request(pending);
        AssertEnvelope(route, SnapshotControlAction.Recover, lines);
        await route.Reply(lines, SnapshotControlAction.Recover, "SnapshotControlBusy");
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(result.Success); Assert.Equal("SnapshotControlBusy", result.Code);
        Assert.False(File.Exists(route.ControlPath));
    }

    private static JsonObject Captured()
    {
        var bytes = File.ReadAllBytes(Environment.GetEnvironmentVariable("APFSACCESS_SNAPSHOT_BUSY_STATUS")!);
        Assert.Equal(CapturedHash, Convert.ToHexString(SHA256.HashData(bytes)));
        return JsonNode.Parse(bytes)!.AsObject();
    }

    private static void RecordTiming(string name, TimeSpan elapsed, int attempts, string code, int responseBudgetSeconds = 2)
    {
        var root = Environment.GetEnvironmentVariable("APFSACCESS_TEST_ROOT")!;
        File.WriteAllText(Path.Combine(root, name + ".json"), JsonSerializer.Serialize(new
        {
            elapsedSeconds = elapsed.TotalSeconds, dispatchAttempts = attempts, terminalCode = code,
            configuredBusyRetryBudgetSeconds = 5, configuredResponseBudgetSeconds = responseBudgetSeconds,
            pollingDelayMilliseconds = 100
        }));
    }

    private static JsonNode Child(JsonNode raw, ulong oid = 201)
        => raw["volumes"]!.AsArray().Single(v => v!["objectId"]!.GetValue<ulong>() == oid)!;

    private static JsonObject Eligible(JsonObject raw)
    {
        var row = Child(raw);
        row["snapshotControlRefusal"] = "";
        row["snapshotInventorySupported"] = true;
        row["snapshotMutationSupported"] = true;
        return raw;
    }

    private static string[]? Extras(SnapshotControlAction action) => action switch
    {
        SnapshotControlAction.Create => ["busy-test"],
        SnapshotControlAction.Delete => DeleteIdentity.ToArray(),
        _ => null
    };

    private static void AssertEnvelope(RetainedRoute route, SnapshotControlAction action, string[] lines)
    {
        Assert.Equal("APFS-CONTROL/1", lines[0]); Assert.Equal(route.Token, lines[2]); Assert.Equal("201", lines[4]);
        Assert.Equal(action switch { SnapshotControlAction.List => "snapshot-list", SnapshotControlAction.Create => "snapshot-create",
            SnapshotControlAction.Delete => "snapshot-delete", _ => "snapshot-recover" }, lines[3]);
        Assert.Equal(Extras(action) ?? [], lines.Skip(5));
    }

    // Replay the captured native document with only test owner/endpoint routing; no host, mount or native lease is launched.
    private sealed class RetainedRoute : IDisposable
    {
        private const BindingFlags Flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        private readonly DTempDirectory _temp = DTempDirectory.Create("snapshot-busy-route");
        private readonly Process _process = Process.GetCurrentProcess();
        private readonly IDictionary _groups;
        private readonly object _owner;
        private object _group;
        private readonly string _recovery;
        public NativeApfsBackend Backend { get; }
        public ServiceHostOptions Options { get; } = new() { EnableImageSnapshots = true, WriteBackendMode = "Native", NativeHostStopTimeoutSeconds = 2 };
        public string StatusPath { get; }
        public string ControlPath { get; }
        public string Container { get; }
        public string Token { get; } = new('b', 64);
        public SemaphoreSlim Gate => (SemaphoreSlim)typeof(NativeApfsBackend).GetField("_gate", Flags)!.GetValue(Backend)!;

        public RetainedRoute(JsonObject raw)
        {
            Container = raw["containerUuid"]!.GetValue<string>();
            _recovery = Child(raw)["recoveryIdentity"]!.GetValue<string>();
            StatusPath = Path.Combine(_temp.Path, "status.json");
            ControlPath = Path.Combine(_temp.Path, "control");
            Publish(raw);
            Backend = new(Options);
            var type = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            _owner = type.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [_process, null, null, "", "", StatusPath, MountAccessMode.ReadWrite, "Native"]);
            type.GetProperty("ContainerControlFilePath")!.SetValue(_owner, ControlPath);
            type.GetProperty("ContainerControlToken")!.SetValue(_owner, Token);
            _group = NewGroup();
            _groups = (IDictionary)typeof(NativeApfsBackend).GetField("_containerGroups", Flags)!.GetValue(Backend)!;
            _groups[Container] = _group;
        }

        private object NewGroup()
        {
            var type = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var group = type.GetConstructors(Flags).Single().Invoke([Container, Path.Combine(_temp.Path, "ordinary.apfs.img"), 0UL, "", _owner, true]);
            ((IDictionary)type.GetProperty("Members")!.GetValue(group)!)["R:\\"] = NewMember(_recovery);
            return group;
        }

        private object NewMember(string recovery)
            => typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!
                .GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                    [$"apfs-vol:{Container}:201", "R:\\", 201UL, true, recovery, true, true, DateTime.UtcNow]);

        public void ReplaceGroup() { _group = NewGroup(); _groups[Container] = _group; }
        public void ReplaceMember() => ((IDictionary)_group.GetType().GetProperty("Members")!.GetValue(_group)!)["R:\\"] = NewMember("changed");

        public void Publish(JsonObject raw, long ownerStartDelta = 0, int? ownerPid = null)
        {
            raw["ownerPid"] = ownerPid ?? _process.Id;
            raw["ownerStartFileTimeUtc"] = _process.StartTime.ToUniversalTime().ToFileTimeUtc() + ownerStartDelta;
            var temporary = StatusPath + ".tmp";
            File.WriteAllText(temporary, raw.ToJsonString()); File.Move(temporary, StatusPath, true);
        }

        public Task<SnapshotControlResult> Send(SnapshotControlAction action, string[]? extras = null, CancellationToken cancellation = default)
            => Backend.SendSnapshotControlAsync(Container, 201, action, extras ?? Extras(action), cancellation);

        public async Task<string[]> Request(Task<SnapshotControlResult> pending, string? previousNonce = null)
            => await RequestOrCompletion(pending, previousNonce) ?? throw new Xunit.Sdk.XunitException("No authenticated request was dispatched: " + (await pending).Code);

        public async Task<string[]?> RequestOrCompletion(Task<SnapshotControlResult> pending, string? previousNonce = null)
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            while (!pending.IsCompleted)
            {
                try
                {
                    if (File.Exists(ControlPath))
                    {
                        var lines = await File.ReadAllLinesAsync(ControlPath, limit.Token);
                        if (lines.Length >= 5 && lines[1] != previousNonce) return lines;
                    }
                }
                catch (IOException) { }
                await Task.Delay(5, limit.Token);
            }
            return null;
        }

        public async Task Reply(string[] lines, SnapshotControlAction action, string? error = null, string? nonce = null)
        {
            var response = $"APFS-CONTROL/1\n{nonce ?? lines[1]}\n";
            if (error is not null) response += $"error\n{error}\n";
            else if (action == SnapshotControlAction.List)
            {
                var inventory = new LiveSnapshotInventory(Container, new string('a', 32), "201", "23", "0", "4194304", []);
                response += $"ok\nSnapshotInventory\nsnapshot-inventory-json/1\n{inventory.ToJson().GetRawText()}\n";
            }
            else response += "ok\nSnapshotCompleted\n";
            File.Delete(ControlPath);
            await File.WriteAllTextAsync(ControlPath + ".tmp", response);
            File.Move(ControlPath + ".tmp", ControlPath + ".response");
        }

        public void Dispose()
        {
            _groups.Clear(); Backend.Dispose(); _process.Dispose(); _temp.Dispose();
        }
    }
}

internal sealed class SnapshotBusyStatusFactAttribute : FactAttribute
{
    public SnapshotBusyStatusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_SNAPSHOT_BUSY_STATUS") is null)
            Skip = "Requires the pinned actual 184502 native SnapshotControlBusy status capture; no native launch.";
    }
}

internal sealed class SnapshotBusyStatusTheoryAttribute : TheoryAttribute
{
    public SnapshotBusyStatusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_SNAPSHOT_BUSY_STATUS") is null)
            Skip = "Requires the pinned actual 184502 native SnapshotControlBusy status capture; no native launch.";
    }
}
