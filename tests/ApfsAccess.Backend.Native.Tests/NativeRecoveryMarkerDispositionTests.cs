using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeRecoveryMarkerDispositionTests
{
    [Theory]
    [InlineData("__._PhysicalDrive2_Main_Native.state", "48810")]
    [InlineData("__._PhysicalDrive0_Other-label_Native.state", "1")]
    [InlineData("__._PhysicalDrive99_Another label_Native.state", "18446744073709551615")]
    [InlineData("__._physicaldrive2_Main_native.STATE", "48810")]
    [InlineData("__._PHYSICALDRIVE0_Data_NaTiVe.StAtE", "1")]
    public void LegacyTerminalIsOnlyAnUnboundFencedNativeKeeperCandidate(string name, string xid)
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "9"); fixture.AddMarker("202", "9");
        var legacy = Path.Combine(fixture.Recovery, name); File.WriteAllText(legacy, "dirty=0\nlastCommitXid=" + xid + "\n");
        var before = fixture.Evidence(); var identity = NativeApfsVolumeRename.StableFileId(legacy); var written = File.GetLastWriteTimeUtc(legacy);
        using (NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals))
        {
            Assert.Throws<IOException>(() => new FileStream(legacy, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Delete(legacy));
            Assert.Throws<IOException>(() => File.Move(legacy, legacy + ".moved"));
        }
        Assert.Equal(before, fixture.Evidence()); Assert.Equal(identity, NativeApfsVolumeRename.StableFileId(legacy));
        Assert.Equal(written, File.GetLastWriteTimeUtc(legacy));
        using var released = new FileStream(legacy, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void NativeHandoffKeepsLegacyFenceAndExactRootsAndPropagatesNativeClosureRefusal(bool imageKeeper)
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "15817"); fixture.AddMarker("202", "15803");
        var legacy = Path.Combine(fixture.Recovery, "__._PhysicalDrive2_Main_Native.state");
        File.WriteAllText(legacy, "dirty=0\nlastCommitXid=48810\n");
        var request = fixture.Request with { PreXid = "15817" };
        if (imageKeeper) request = request with { Operation = "format", Name = "Fresh", CaseSensitive = false,
            ImageOptions = new("2097152", "2097152", new string('d', 32), new string('e', 32),
                NativeApfsVolumeImageManagement.DestinationWal(fixture.Spool, new string('d', 32))) };
        var tool = Path.Combine(fixture.Temp.Path, "keeper-test.exe"); File.WriteAllBytes(tool, [1]);
        var before = fixture.Evidence(); var called = false;
        var runner = new LegacyHandoffRunner(args =>
        {
            called = true;
            string Value(string key) => args[args.ToList().IndexOf(key) + 1];
            Assert.Equal(request.Image, Value("--image")); Assert.Equal(request.JournalRoot, Value("--journal-directory"));
            Assert.Equal(request.SpoolRoot, Value("--history-spool-root")); Assert.Equal(fixture.Recovery, Value("--history-recovery-root"));
            Assert.Equal(request.ContainerUuid, Value("--container")); Assert.Equal("15817", Value("--xid"));
            Assert.Throws<IOException>(() => new FileStream(legacy, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Delete(legacy));
        });
        using (NativeRecoveryStorage.AcquireForNativeKeeper(request, fixture.Recovery, fixture.Journals))
        {
            var error = Assert.Throws<IOException>(() => {
                if (imageKeeper) new NativeApfsVolumeImageManagement(runner, tool, fixture.Journals, fixture.Spool)
                    .Execute(request, VolumeTopologyMode.Prepare, null, default, fixture.Recovery);
                else new NativeApfsVolumeManagement(runner, tool, fixture.Journals, fixture.Spool)
                    .Execute(request, VolumeTopologyMode.Prepare, null, default, fixture.Recovery);
            });
            Assert.Equal("NativeClosureStillUnproved", error.Message);
        }
        Assert.True(called); Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void GenericCensusDispositionAndQuotaKeepLegacyRefusal()
    {
        using var fixture = new Fixture(); var legacy = Path.Combine(fixture.Recovery, "__._PhysicalDrive2_Main_Native.state");
        File.WriteAllText(legacy, "dirty=0\nlastCommitXid=48810\n"); var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.RequireDisposition(fixture.Spool, fixture.Recovery, fixture.Census));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.RequireDisposition(fixture.Request, fixture.Recovery));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(fixture.Scope, fixture.Inventory,
            fixture.Census.Select(w => (w.VolumeUuid, w.Oid)).ToArray(), fixture.Spool, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
        fixture.AddMarker("201", "9"); fixture.AddMarker("202", "9"); before = fixture.Evidence();
        var bindings = NativeOrdinaryImageOwnership.Read(fixture.Journals, fixture.Image, "0").LaunchBindings;
        var quota = Assert.Throws<IOException>(() => NativeApfsBackend.AcquireManagementQuotaDisposition(
            fixture.Request with { Operation = "quota" }, bindings, fixture.Recovery, fixture.Journals));
        Assert.Contains("__._PhysicalDrive2_Main", quota.Message); Assert.Equal(before, fixture.Evidence());
    }

    [Theory]
    [InlineData("quota")] [InlineData("rename")]
    public void OtherMutationFamiliesCannotOptIntoNativeKeeperDeferral(string operation)
    {
        using var fixture = new Fixture();
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(
            fixture.Request with { Operation = operation }, fixture.Recovery, fixture.Journals));
        Assert.Contains("HeldNativeKeeperRequired", error.Message);
    }

    [Theory]
    [InlineData("dirty=1\nlastCommitXid=48810\n")]
    [InlineData("dirty=false\nlastCommitXid=48810\n")]
    [InlineData("dirty=0\nlastCommitXid=\n")]
    [InlineData("dirty=0\nlastCommitXid=0\n")]
    [InlineData("dirty=0\nlastCommitXid=048810\n")]
    [InlineData("dirty=0\nlastCommitXid=-1\n")]
    [InlineData("dirty=0\nlastCommitXid=+1\n")]
    [InlineData("dirty=0\nlastCommitXid=18446744073709551616\n")]
    [InlineData("dirty=0\nlastCommitXid=184467440737095516150\n")]
    [InlineData("dirty=0\nlastCommitXid=48810")]
    [InlineData("dirty=0\r\nlastCommitXid=48810\r\n")]
    [InlineData("\uFEFFdirty=0\nlastCommitXid=48810\n")]
    [InlineData("lastCommitXid=48810\ndirty=0\n")]
    [InlineData("dirty=0\nlastCommitXid=48810\ndirty=1\n")]
    [InlineData("dirty=0\nlastCommitXid=48810\nother=0\n")]
    public void DirtyOrMalformedLegacyCandidatesRefuseWithoutChangingEvidence(string text)
    {
        using var fixture = new Fixture(); var legacy = Path.Combine(fixture.Recovery, "__._PhysicalDrive2_Main_Native.state");
        File.WriteAllBytes(legacy, Encoding.UTF8.GetBytes(text)); var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
        using var released = new FileStream(legacy, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    [Theory]
    [InlineData("foreign_Native.state")] [InlineData("__._PhysicalDrive02_Main_Native.state")]
    [InlineData("__._PhysicalDrive_Main_Native.state")] [InlineData("__._PhysicalDrive123456789_Main_Native.state")]
    [InlineData("__._PhysicalDrive2__Native.state")] [InlineData("__._PhysicalDrive2_ _Native.state")]
    [InlineData("__._PhysicalDrive2_Main_Overlay.state")] [InlineData("__._PhysicalDrive2_Main_Native.state.tmp")]
    [InlineData("apfs_recovery_v1_unknown_Native.state")]
    public void UnknownCanonicalLookingAndMalformedLegacyNamesRemainRefused(string name)
    {
        using var fixture = new Fixture(); File.WriteAllText(Path.Combine(fixture.Recovery, name), "dirty=0\nlastCommitXid=48810\n");
        var before = fixture.Evidence();
        if (name.StartsWith("apfs_recovery_v1_", StringComparison.Ordinal))
            Assert.Throws<InvalidDataException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
        else Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void LegacyCandidateHardlinkAndActiveWriterRefuseAndPreserveOriginal()
    {
        using var fixture = new Fixture(); var legacy = Path.Combine(fixture.Recovery, "__._PhysicalDrive2_Main_Native.state");
        File.WriteAllText(legacy, "dirty=0\nlastCommitXid=48810\n"); var before = fixture.Evidence();
        using (var writer = new FileStream(legacy, FileMode.Open, FileAccess.Write, FileShare.Read))
            Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
        var alias = Path.Combine(fixture.Temp.Path, "legacy-alias"); Assert.True(CreateHardLink(alias, legacy, IntPtr.Zero)); before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void LegacyCandidateCannotMaskSelectedDirtyMarkerOrSpoolResidue(bool spoolResidue)
    {
        using var fixture = new Fixture();
        File.WriteAllText(Path.Combine(fixture.Recovery, "__._PhysicalDrive2_Main_Native.state"), "dirty=0\nlastCommitXid=48810\n");
        if (spoolResidue) File.WriteAllText(fixture.Census[0].Path + ".compact.pending", "unproved selected residue");
        else File.WriteAllText(fixture.AddMarker("201", "9"), "dirty=1\nlastCommitXid=9\n");
        var before = fixture.Evidence();
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Contains(spoolResidue ? "HistoricalOrSpoolDebtUnproved" : "RecoveryMarkerDirtyOrInvalid", error.Message);
        Assert.Equal(before, fixture.Evidence());
    }

    private sealed class LegacyHandoffRunner(Action<IReadOnlyList<string>> inspect) : IObserverRunner
    {
        public ObserverRunResult Run(string path, IReadOnlyList<string> args)
        { inspect(args); throw new IOException("NativeClosureStillUnproved"); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void GenuineForeignCurrentDirectoryAndDirtyMarkerCoexistWithoutOpeningActivePayload(bool physicalWitness)
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "8");
        var foreign = fixture.AddNamespace(new string('d', 32), 101, physicalWitness);
        var payload = Path.Combine(Path.GetDirectoryName(foreign.Wal)!, "payload-spool.bin");
        File.WriteAllText(payload, "foreign active payload is not selected cleanup authority");
        var before = fixture.Evidence();
        using (var activePayload = new FileStream(payload, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        using (var activeMarker = new FileStream(foreign.Marker, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        using (NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals))
        {
            Assert.Throws<IOException>(() => new FileStream(foreign.Witness, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Delete(foreign.Witness));
        }
        Assert.Equal(before, fixture.Evidence());
        using var released = new FileStream(foreign.Witness, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    [Theory]
    [InlineData("missing")] [InlineData("temporary-only")] [InlineData("truncated")] [InlineData("oversize")]
    [InlineData("mode")] [InlineData("mode0-guid")] [InlineData("mode1-zero-guid")] [InlineData("version")]
    [InlineData("zero-container")] [InlineData("zero-oid")] [InlineData("guid-order")] [InlineData("hash-mismatch")]
    public void ForeignDescriptorMalformedOrMismatchedEvidenceIsPreserved(string mutation)
    {
        using var fixture = new Fixture(); var foreign = fixture.AddNamespace(new string('d', 32), 101, true);
        var bytes = File.ReadAllBytes(foreign.Witness);
        switch (mutation)
        {
            case "missing": File.Delete(foreign.Witness); break;
            case "temporary-only": File.Move(foreign.Witness, foreign.Witness + ".tmp-retained"); break;
            case "truncated": File.WriteAllBytes(foreign.Witness, bytes[..41]); break;
            case "oversize": File.WriteAllBytes(foreign.Witness, [.. bytes, 0]); break;
            default:
                switch (mutation)
                {
                    case "mode": bytes[0] = 2; break;
                    case "mode0-guid": bytes[0] = 0; break;
                    case "mode1-zero-guid": bytes.AsSpan(1, 16).Clear(); break;
                    case "version": bytes[33] = 2; break;
                    case "zero-container": bytes.AsSpan(17, 16).Clear(); break;
                    case "zero-oid": bytes.AsSpan(34, 8).Clear(); break;
                    case "guid-order": Array.Reverse(bytes, 1, 4); Array.Reverse(bytes, 5, 2); Array.Reverse(bytes, 7, 2); break;
                    case "hash-mismatch": bytes[17] ^= 1; break;
                }
                File.WriteAllBytes(foreign.Witness, bytes); break;
        }
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void SameContainerUnknownOidAndPhysicalAliasOfImageRemainRefused(bool physicalWitness)
    {
        using var fixture = new Fixture(); fixture.AddNamespace(fixture.Request.ContainerUuid, 999, physicalWitness);
        var before = fixture.Evidence();
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Contains("NamespaceScopeAmbiguous", error.Message); Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void KnownRetiredDifferentContainerCannotBeHiddenByItsValidForeignDescriptor()
    {
        using var fixture = new Fixture();
        var retired = fixture.AddNamespace(new string('d', 32), 301, false);
        var start = new ProcessStartInfo("no-process-launched.exe"); start.Environment["APFSACCESS_SPOOL_ROOT"] = fixture.Spool;
        start.Environment["APFSACCESS_RECOVERY_ROOT"] = fixture.Recovery;
        var row = fixture.Inventory.Volumes[0] with { CatalogContainerUuid = new string('d', 32), CatalogVolumeObjectId = 301,
            CatalogVolumeUuid = new string('e', 32), RecoveryIdentity = retired.Identity };
        NativeOrdinaryImageOwnership.CaptureLaunch(start, fixture.Journals, fixture.Image, "0", [row]);
        var before = fixture.Evidence();
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Contains("HistoricalOrSpoolDebtUnproved", error.Message); Assert.Equal(before, fixture.Evidence());
        var history = fixture.Census.Select(w => new NativeRecoveryStorage.HistoryMember(fixture.Request.ContainerUuid, w, "9"))
            .Append(new(new string('d', 32), new("301", new string('e', 32), retired.Wal), "8")).ToArray();
        error = Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(fixture.Scope, fixture.Inventory,
            fixture.Census.Select(w => (w.VolumeUuid, w.Oid)).ToArray(), fixture.Spool, fixture.Recovery, fixture.Journals, () => history));
        Assert.Contains("RecoveryMarkerDirtyOrInvalid", error.Message); Assert.Equal(before, fixture.Evidence());
    }

    [Theory]
    [InlineData("payload-spool.bin")] [InlineData("payload-spool.idx")]
    public void SelectedPayloadNeedsHeldSingleLinkEmptyFileAndNonemptyEvidenceRefuses(string name)
    {
        using var fixture = new Fixture(); var payload = Path.Combine(Path.GetDirectoryName(fixture.Census[0].Path)!, name);
        File.WriteAllBytes(payload, []);
        using (NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals))
        {
            Assert.Throws<IOException>(() => new FileStream(payload, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Delete(payload));
        }
        var alias = Path.Combine(fixture.Temp.Path, "empty-payload-alias"); Assert.True(CreateHardLink(alias, payload, IntPtr.Zero));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        File.Delete(alias);
        File.WriteAllText(payload, "pending, unindexed, or protected payload cannot be accepted by name");
        var before = fixture.Evidence();
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Contains("SelectedPayloadDispositionUnproved", error.Message); Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void SelectedDirtyMarkerIsCheckedBeforeAnyForeignDescriptor()
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "8");
        var foreign = fixture.AddNamespace(new string('d', 32), 101, false); File.WriteAllBytes(foreign.Witness, []);
        fixture.AddMarker("201", "9"); File.WriteAllText(fixture.Markers["201"], "dirty=1\nlastCommitXid=9\n");
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Contains("RecoveryMarkerDirtyOrInvalid", error.Message);
    }

    [Fact]
    public void ForeignDescriptorHardlinkAliasRefusesAndOriginalBytesRemain()
    {
        using var fixture = new Fixture(); var foreign = fixture.AddNamespace(new string('d', 32), 101, false);
        var alias = Path.Combine(fixture.Temp.Path, "witness-alias"); Assert.True(CreateHardLink(alias, foreign.Witness, IntPtr.Zero));
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void OriginalCleanNativeMarkersJoinObservedCensusWithoutChangingEvidence()
    {
        using var fixture = new Fixture();
        var first = fixture.AddMarker("201", "8"); var second = fixture.AddMarker("202", "9");
        var before = fixture.Evidence();
        var result = NativeRecoveryStorage.BindCensus(fixture.Scope, fixture.Inventory,
            fixture.Census.Select(w => (w.VolumeUuid, w.Oid)).ToArray(), fixture.Spool, fixture.Recovery, fixture.Journals);
        Assert.Equal(fixture.Census, result);
        using (NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals))
        { Assert.True(File.Exists(first)); Assert.True(File.Exists(second)); }
        Assert.Equal(before, fixture.Evidence());
        // Census/path authority alone does not dispose original host recovery evidence.
        Assert.Throws<IOException>(() => NativeRecoveryStorage.RequireDisposition(fixture.Request, fixture.Recovery));
    }

    [Theory]
    [InlineData("dirty=1\nlastCommitXid=9\n")]
    [InlineData("dirty=false\nlastCommitXid=9\n")]
    [InlineData("dirty=0\nlastCommitXid=\n")]
    [InlineData("dirty=0\nlastCommitXid=0\n")]
    [InlineData("dirty=0\nlastCommitXid=09\n")]
    [InlineData("dirty=0\nlastCommitXid=10\n")]
    [InlineData("dirty=0\nlastCommitXid=9")]
    [InlineData("dirty=0\nlastCommitXid=9\nextra=0\n")]
    [InlineData("dirty=0\nlastCommitXid=9\ndirty=0\n")]
    [InlineData("dirty=0\nlastCommitXid=18446744073709551616\n")]
    [InlineData("dirty=0\nlastCommitXid=-1\n")]
    [InlineData("dirty=0\r\nlastCommitXid=9\r\n")]
    [InlineData("\uFEFFdirty=0\nlastCommitXid=9\n")]
    public void DirtyMalformedTruncatedOrAheadMarkersRefuseAndRemainUnchanged(string bytes)
    {
        using var fixture = new Fixture();
        var marker = fixture.AddMarker("201", "8");
        File.WriteAllBytes(marker, Encoding.UTF8.GetBytes(bytes));
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
        // A failing scan releases every previously acquired read fence.
        using var reopen = new FileStream(marker, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    [Fact]
    public void ForeignBackendUnknownDirectoryAndCompactionDebtRemainRefused()
    {
        using var fixture = new Fixture();
        fixture.AddMarker("201", "8");
        var foreign = Path.Combine(fixture.Recovery, "foreign_Native.state");
        File.WriteAllText(foreign, "dirty=0\nlastCommitXid=9\n");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.True(File.Exists(foreign)); File.Delete(foreign);
        var backend = Path.Combine(fixture.Recovery, Path.GetFileName(fixture.Markers["201"]).Replace("_Native.state", "_Overlay.state"));
        File.WriteAllText(backend, "dirty=0\nlastCommitXid=9\n");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        File.Delete(backend);
        var directory = Path.Combine(fixture.Recovery, Path.GetFileName(fixture.Markers["202"])); Directory.CreateDirectory(directory);
        Assert.Throws<ArgumentException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Directory.Delete(directory);
        var debt = fixture.Census[0].Path + ".compact.pending"; File.WriteAllText(debt, "unproved native compaction debt");
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void MissingOriginalOwnershipMissingSiblingAndRootDriftCannotAdmitCleanMarkers()
    {
        using var fixture = new Fixture();
        fixture.AddMarker("201", "8"); var before = fixture.Evidence();
        var drift = Path.Combine(fixture.Temp.Path, "other-recovery"); Directory.CreateDirectory(drift);
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, drift, fixture.Journals));
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request with { JournalRoot = drift }, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
        var wal = fixture.Census[1].Path; File.Move(wal, wal + ".original");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        File.Move(wal + ".original", wal);
        var frame = Assert.Single(Directory.GetFiles(fixture.Journals, "ordinary-image-*.json")); File.Move(frame, frame + ".original");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        File.Move(frame + ".original", frame); Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void CleanMarkerHandlesStayFencedUntilNativeKeeperReturns()
    {
        using var fixture = new Fixture(); var marker = fixture.AddMarker("201", "8");
        var before = fixture.Evidence();
        using (NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals))
        {
            Assert.Throws<IOException>(() => new FileStream(marker, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Delete(marker));
        }
        using (var writable = new FileStream(marker, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void NativeObservationConsumerUsesOriginalLaunchMarkerBindings()
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "8"); fixture.AddMarker("202", "9");
        var tool = Path.Combine(fixture.Temp.Path, "observer-test.exe"); File.WriteAllBytes(tool, [1]);
        var keeper = new NativeApfsVolumeManagement(new ObservationRunner(fixture.Observation()), tool, fixture.Journals, fixture.Spool);
        Assert.Equal(fixture.Census, keeper.Observe(fixture.Scope, fixture.Inventory, fixture.Recovery, default).Volumes);
    }

    [Theory]
    [InlineData("checkpointXid", "10")]
    [InlineData("containerUuid", "dddddddddddddddddddddddddddddddd")]
    [InlineData("sourceIdentity", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void NativeScopeMustMatchBeforeCleanMarkerDisposition(string field, string value)
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "8");
        var tool = Path.Combine(fixture.Temp.Path, "observer-test.exe"); File.WriteAllBytes(tool, [1]);
        var document = JsonNode.Parse(fixture.Observation())!; document[field] = value;
        var before = fixture.Evidence();
        var keeper = new NativeApfsVolumeManagement(new ObservationRunner(document.ToJsonString()), tool, fixture.Journals, fixture.Spool);
        Assert.Throws<InvalidDataException>(() => keeper.Observe(fixture.Scope, fixture.Inventory, fixture.Recovery, default));
        Assert.Equal(before, fixture.Evidence());
    }

    [Fact]
    public void CanonicalMarkerHardlinkAliasIsRefusedAndPreserved()
    {
        using var fixture = new Fixture(); var marker = fixture.AddMarker("201", "8");
        var alias = Path.Combine(fixture.Temp.Path, "marker-alias.state");
        Assert.True(CreateHardLink(alias, marker, IntPtr.Zero));
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        Assert.Equal(before, fixture.Evidence());
    }

    private sealed class ObservationRunner(string document) : IObserverRunner
    {
        public ObserverRunResult Run(string path, IReadOnlyList<string> args)
        { Assert.Contains("observe", args); return new(0, document, ""); }
    }

    [Fact]
    public void NativeKeeperPreflightDefersOnlyCheckpointBoundAndKeepsCanonicalFence()
    {
        using var fixture = new Fixture(); var marker = fixture.AddMarker("201", "11");
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireDisposition(fixture.Request, fixture.Recovery, fixture.Journals));
        using (NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals))
            Assert.Throws<IOException>(() => new FileStream(marker, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
        Assert.Equal(before, fixture.Evidence());
        File.WriteAllText(marker, "dirty=0\nlastCommitXid=011\n");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.AcquireForNativeKeeper(fixture.Request, fixture.Recovery, fixture.Journals));
    }

    [Fact]
    public void HistoryObservationRequiresOriginalLaunchIdentityAndRetiredMarkerBound()
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "8"); fixture.AddMarker("202", "9");
        var topology = fixture.Inventory.Topology!;
        var row = fixture.Inventory.Volumes[1];
        var inventory = fixture.Inventory with { Volumes = [row], Topology = topology with { Snapshot = topology.Snapshot with {
            Volumes = [topology.Snapshot.Volumes[1]],
            Containers = [topology.Snapshot.Containers[0] with { VolumeIds = [row.VolumeId] }] } } };
        var scope = VerifyScopeDerivation.TryDerive(inventory, row).Scope!;
        var history = fixture.Census.Select(w => new NativeRecoveryStorage.HistoryMember(fixture.Request.ContainerUuid, w, w.Oid == "201" ? "8" : "9")).ToArray();
        var nativeVolumes = new[] { (row.CatalogVolumeUuid!, "202") };
        var before = fixture.Evidence();
        Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(scope, inventory, nativeVolumes, fixture.Spool, fixture.Recovery, fixture.Journals));
        var result = NativeRecoveryStorage.BindCensus(scope, inventory, nativeVolumes, fixture.Spool, fixture.Recovery, fixture.Journals, () => history);
        Assert.Equal([fixture.Census[1]], result); Assert.Equal(before, fixture.Evidence());
        var forged = history.ToArray(); forged[0] = forged[0] with { Wal = forged[0].Wal with { VolumeUuid = new string('d', 32) } };
        Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(scope, inventory, nativeVolumes, fixture.Spool, fixture.Recovery, fixture.Journals, () => forged));
        fixture.AddMarker("201", "9");
        Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(scope, inventory, nativeVolumes, fixture.Spool, fixture.Recovery, fixture.Journals, () => history));
    }

    [Fact]
    public void MissingNativeHistoryProofRemainsRefusalAndIsNeverBootstrapped()
    {
        using var fixture = new Fixture(); fixture.AddMarker("201", "8");
        var unknown = Path.Combine(fixture.Spool, "unproved-original"); Directory.CreateDirectory(unknown);
        File.WriteAllText(Path.Combine(unknown, "write-ahead.wal"), "opaque unproved WAL");
        var before = fixture.Evidence(); var called = false;
        var error = Assert.Throws<IOException>(() => NativeRecoveryStorage.BindCensus(fixture.Scope, fixture.Inventory,
            fixture.Census.Select(w => (w.VolumeUuid, w.Oid)).ToArray(), fixture.Spool, fixture.Recovery, fixture.Journals,
            () => { called = true; throw new IOException("KeeperHistoryEvidenceMissingOrBusy"); }));
        Assert.True(called); Assert.Contains("KeeperHistoryEvidenceMissingOrBusy", error.Message); Assert.Equal(before, fixture.Evidence());
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);

    private sealed class Fixture : IDisposable
    {
        internal readonly DTempDirectory Temp = DTempDirectory.Create("clean-native-marker");
        internal readonly string Journals, Spool, Recovery, Image;
        internal readonly DeviceInventory Inventory;
        internal readonly VerifyScope Scope;
        internal readonly IReadOnlyList<VolumeTopologyWal> Census;
        internal readonly VolumeTopologyRequest Request;
        internal readonly Dictionary<string, string> Markers = [];
        internal Fixture()
        {
            Journals = Path.Combine(Temp.Path, "journals"); Spool = Path.Combine(Temp.Path, "spool"); Recovery = Path.Combine(Temp.Path, "recovery");
            Directory.CreateDirectory(Journals); Directory.CreateDirectory(Spool); Directory.CreateDirectory(Recovery);
            var source = Path.Combine(Temp.Path, "source.apfs"); Image = Path.Combine(Temp.Path, "fresh.apfs");
            File.WriteAllBytes(source, new byte[2097152]);
            NativeOrdinaryImageOwnership.RegisterFreshCopy(new(source, Image), Journals, Spool, Recovery);
            var inventory = NativeRecoveryStorageTests.Inventory(Image);
            var cid = inventory.Volumes[0].CatalogContainerUuid!;
            var rows = new[] { (Oid: 201UL, Uuid: new string('b', 32)), (Oid: 202UL, Uuid: new string('c', 32)) }.Select(v =>
            {
                var vid = ApfsTopology.BuildVolumeId(cid, v.Oid);
                return inventory.Volumes[0] with { VolumeId = vid, CatalogVolumeId = vid, CatalogVolumeObjectId = v.Oid,
                    CatalogVolumeUuid = v.Uuid, RecoveryIdentity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, cid, v.Oid, true) };
            }).ToArray();
            var topology = inventory.Topology!.Snapshot;
            var catalog = topology.Volumes[0];
            var volumes = rows.Select(row => catalog with { Id = row.CatalogVolumeId!, Uuid = row.CatalogVolumeUuid!,
                ObjectId = row.CatalogVolumeObjectId!.Value.ToString(), SuperblockXid = "9" }).ToArray();
            Inventory = inventory with { Volumes = rows, Topology = inventory.Topology with { Snapshot = topology with {
                Containers = [topology.Containers[0] with { VolumeIds = rows.Select(row => row.VolumeId).ToArray(), CheckpointXid = "9" }], Volumes = volumes } } };
            Scope = VerifyScopeDerivation.TryDerive(Inventory, rows[0]).Scope!;
            var launch = new ProcessStartInfo("no-process-launched.exe"); launch.Environment["APFSACCESS_SPOOL_ROOT"] = Spool; launch.Environment["APFSACCESS_RECOVERY_ROOT"] = Recovery;
            NativeOrdinaryImageOwnership.CaptureLaunch(launch, Journals, Image, "0", rows);
            Census = rows.Select(row => new VolumeTopologyWal(row.CatalogVolumeObjectId!.Value.ToString(), row.CatalogVolumeUuid!,
                NativeRecoveryStorage.CanonicalWal(Spool, row.RecoveryIdentity!))).ToArray();
            foreach (var wal in Census)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(wal.Path)!); File.WriteAllBytes(wal.Path, []);
                var identity = rows.Single(row => row.CatalogVolumeObjectId!.Value.ToString() == wal.Oid).RecoveryIdentity!;
                Markers.Add(wal.Oid, NativeRecoveryStorage.CanonicalNativeMarker(Recovery, identity));
            }
            Request = new("delete", Image, Journals, "0", cid, rows[0].CatalogVolumeUuid!, "201", "9",
                NativeApfsVolumeManagement.SourceIdentity(Image, "0"), Spool, Census);
        }
        internal string AddMarker(string oid, string xid) { var path = Markers[oid]; File.WriteAllText(path, "dirty=0\nlastCommitXid=" + xid + "\n"); return path; }
        internal (string Identity, string Wal, string Marker, string Witness) AddNamespace(string container, ulong oid, bool physical)
        {
            Guid? partition = physical ? Guid.Parse("ad5417e5-775b-4ea1-bc68-2c794301dc6d") : null;
            var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partition, container, oid, !physical)!;
            NativeRecoveryStorage.EnsureNamespaceWitness(Journals, partition is { } p ? ApfsTopology.BuildPartitionId(p) : null, container, oid, identity, !physical);
            var wal = NativeRecoveryStorage.CanonicalWal(Spool, identity); Directory.CreateDirectory(Path.GetDirectoryName(wal)!);
            File.WriteAllText(wal, "active foreign pending WAL");
            var marker = NativeRecoveryStorage.CanonicalNativeMarker(Recovery, identity); File.WriteAllText(marker, "dirty=1\nlastCommitXid=500\n");
            return (identity, wal, marker, NativeRecoveryStorage.NamespaceWitnessPath(Journals, identity));
        }
        internal string Observation() => JsonSerializer.Serialize(new { schemaVersion = 1, operation = "volume-management-observe", readOnly = true,
            image = Image, offsetBytes = "0", storeSizeBytes = "2097152", sourceIdentity = Request.SourceIdentity,
            containerUuid = Request.ContainerUuid, checkpointXid = "9", blockBytes = "4096", nextOid = "1024",
            volumes = Census.Select(w => new { volumeUuid = w.VolumeUuid, oid = w.Oid }) });
        internal string[] Evidence() => Directory.GetFiles(Temp.Path, "*", SearchOption.AllDirectories).Order(StringComparer.OrdinalIgnoreCase)
            .Select(path => path + ":" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)))).ToArray();
        public void Dispose() => Temp.Dispose();
    }
}
