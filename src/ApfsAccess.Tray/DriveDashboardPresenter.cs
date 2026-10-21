using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static partial class DriveDashboardPresenter
{
    private static readonly System.Text.Json.JsonSerializerOptions ScopeWireOptions = new()
    {
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
    };

    public static IReadOnlyList<DriveDashboardRow> BuildRows(StatusChangedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var rows = (payload.MountedVolumes ?? [])
            .Where(v => !string.IsNullOrWhiteSpace(v.VolumeId) && !string.IsNullOrWhiteSpace(v.MountPoint))
            .Select(v => BuildRow(payload, v)).ToList();
        var inventory = (payload.ConnectedInventory ?? []).Where(d => d.Device.IsConnected)
            .SelectMany(d => d.Volumes.Select(v => (Device: d.Device, Volume: v))).ToArray();
        foreach (var item in inventory)
        {
            var v = item.Volume;
            if (rows.Any(r => SameIdentity(r, v))) continue;
            var unique = inventory.Count(i => SameTarget(i.Volume, v)) == 1 &&
                string.Equals(item.Device.DeviceId, v.DeviceId, StringComparison.OrdinalIgnoreCase);
            rows.Add(BuildConnectedRow(payload, item.Device, v, unique));
        }
        // A duplicate routing identity is never actionable, even when catalog IDs differ.
        rows = rows.GroupBy(RowIdentity).Select(g => g.OrderByDescending(r => r.State).First()).Select(r =>
            inventory.Count(i => string.Equals(i.Volume.DeviceId, r.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(i.Volume.VolumeId, r.VolumeId, StringComparison.OrdinalIgnoreCase)) > 1
                ? r with { CanFix = false, CanInspectReadOnly = false, CanMountBackupReadWrite = false, CanEject = false,
                    Summary = "Ambiguous volume identity. Refresh after resolving duplicate identities." } : r).ToList();
        if (rows.Count == 0)
        {
            var idleState = ClassifyIdle(payload);
            return
            [
                new DriveDashboardRow(
                    VolumeId: string.Empty,
                    DeviceName: BuildIdleTitle(payload),
                    VolumeName: string.Empty,
                    MountPoint: string.Empty,
                    MountPath: string.Empty,
                    State: idleState,
                    Palette: ToPalette(idleState),
                    StateText: BuildIdleStateText(payload, idleState),
                    Summary: BuildIdleSummary(payload),
                    CanOpen: false,
                    CanEject: false,
                    CanFix: payload.ConnectedInventory is null && idleState is (DriveDashboardState.Attention or DriveDashboardState.Problem),
                    Details: BuildIdleDetails(payload),
                    FixGuidance: BuildFixGuidance(idleState, payload), IsMounted: false)
            ];
        }

        rows = rows.Select(r => {
            var candidates = inventory.Where(i => i.Volume.RegisteredImage is not null &&
                (SameIdentity(r, i.Volume) || i.Volume.RegisteredImage.Writable &&
                    string.Equals(r.DeviceId, i.Volume.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.VolumeId, i.Volume.VolumeId, StringComparison.OrdinalIgnoreCase))).ToArray();
            if (candidates.Length != 1) return r;
            var v=candidates[0].Volume; var state=v.EncryptionState ?? EncryptedVolumeState.Locked;
            var writable=v.RegisteredImage?.Writable==true;
            if (writable && state == EncryptedVolumeState.Unlocked)
                return EncryptedWriterRow(payload, r, v);
            var text=state switch { EncryptedVolumeState.Unlocked => writable ? "Unlocked · Read/write" : "Unlocked · Read-only", EncryptedVolumeState.Unlocking => "Unlocking…",
                EncryptedVolumeState.Locking => "Locking…", EncryptedVolumeState.Failed => "Unlock or lock failed", _ => "Locked" };
            return r with { RegisteredImage=v.RegisteredImage, EncryptionState=state, CanFix=false, CanInspectReadOnly=false,
                State=writable && state==EncryptedVolumeState.Failed ? DriveDashboardState.Problem : r.State,
                CanOpen=!(writable && state==EncryptedVolumeState.Failed) && r.CanOpen,
                CanUnlock=!r.IsMounted && state is EncryptedVolumeState.Locked or EncryptedVolumeState.Failed,
                CanLock=r.IsMounted && state is EncryptedVolumeState.Unlocked or EncryptedVolumeState.Failed,
                Palette=state is EncryptedVolumeState.Unlocking or EncryptedVolumeState.Locking ? DashboardPalette.Blue :
                    writable && state==EncryptedVolumeState.Failed ? DashboardPalette.Red : DashboardPalette.Yellow,
                StateText=text, Summary=r.IsMounted && state==EncryptedVolumeState.Unlocked
                    ? writable ? "Read/write access. Changes are written to this image." : "Read-only access. You can open and copy files."
                    : text };
        }).ToList();
        rows = rows.Select(r =>
        {
            var devices = (payload.ConnectedInventory ?? []).Where(d => d.Device.DeviceId == r.DeviceId).ToArray();
            if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0])) return r;
            var matches = devices[0].Volumes.Where(v => SameIdentity(r, v)).ToArray();
            if (matches.Length != 1 || matches[0].RegisteredImage is not null || matches[0].IsEncrypted) return r;
            var scoped = VerifyScopeDerivation.TryDerive(devices[0], matches[0]);
            var owners = (payload.MountedVolumes ?? []).Where(m =>
                TopologyStatusProjection.Matches(m, matches[0], requireUuid: true)).ToArray();
            var ownerProven = owners.Length == 1 && owners[0] is { HasRuntimeStatus: true, MountReady: true, HostProcessId: > 0 };
            var snapshotProfile = scoped.Ok && scoped.Scope?.StoreOffsetBytes == "0" && CatalogMountPolicy.AllowsOrdinaryMount(matches[0]);
            var rawScope = ownerProven && r.IsMounted && r.State == DriveDashboardState.HealthyReadWrite &&
                payload.InventoryGeneration is > 0 &&
                inventory.Count(i => string.Equals(i.Volume.VolumeId, r.VolumeId, StringComparison.OrdinalIgnoreCase)) == 1 &&
                (payload.MountedVolumes ?? []).Count(m => string.Equals(m.DeviceId, r.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(m.VolumeId, r.VolumeId, StringComparison.OrdinalIgnoreCase)) == 1
                ? MatchRawSnapshotScope(devices[0], matches[0], owners[0]) : null;
            var canList = ownerProven && (snapshotProfile || rawScope is not null) && owners[0].SnapshotInventorySupported;
            var canMutate = canList && owners[0].SnapshotMutationSupported;
            var canVerifyLive = owners.Length == 1 && owners[0] is { HasRuntimeStatus: true, HostProcessId: > 0,
                VolumeVerificationSupported: true, VolumeVerificationScope: {} liveScope } &&
                TopologyAdmission.SameUuid(liveScope.ContainerUuid, matches[0].CatalogContainerUuid) &&
                TopologyAdmission.SameUuid(liveScope.VolumeUuid, matches[0].CatalogVolumeUuid) &&
                liveScope.VolumeOid == matches[0].CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture) &&
                CatalogMountPolicy.AllowsOrdinaryMount(matches[0]);
            var quiesced = !rows.Any(other => other.IsMounted &&
                (string.Equals(other.DeviceId, r.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                    TopologyAdmission.SameUuid(other.CatalogContainerUuid, r.CatalogContainerUuid)));
            var offline = scoped.Ok && quiesced;
            var managementScope = VolumeTopologyProfile.DeriveManagementScope(devices[0], matches[0], "format").Scope;
            return r with { CanVerifyOffline = offline, CanVerifyLive = canVerifyLive, CanListSnapshots = canList, SnapshotScope = scoped.Scope ?? rawScope,
                CanMutateSnapshots = canMutate && r.IsMounted && r.State == DriveDashboardState.HealthyReadWrite,
                CanRecoverSnapshots = ownerProven && snapshotProfile && owners[0].SnapshotRecoverySupported && r.IsMounted,
                CatalogSpace = matches[0].CatalogSpace,
                CanManageOffline = offline && payload.ManagementJournalRootInspected && CatalogMountPolicy.AllowsOrdinaryMount(matches[0]),
                ManagementScope = managementScope,
                CanResizeFormatImage = quiesced && payload.ImageManagementMutationsEnabled && payload.ImageResizeFormatEnabled && payload.ManagementJournalRootInspected &&
                    CatalogMountPolicy.AllowsOrdinaryMount(matches[0]) && managementScope is { } imageScope &&
                    (VolumeTopologyProfile.IsStreamedImage(imageScope, "format") || VolumeTopologyProfile.IsStreamedImage(imageScope, "erase") ||
                        VolumeTopologyProfile.IsStreamedImage(imageScope, "grow") || VolumeTopologyProfile.IsStreamedImage(imageScope, "shrink") ||
                        VolumeTopologyProfile.IsPhysicalFormat(imageScope, "format")) &&
                    payload.VolumeManagementReadyImages?.Contains(r.DeviceId!, StringComparer.OrdinalIgnoreCase) == true,
                CanManageTopologyImage = quiesced && payload.ImageManagementMutationsEnabled && CatalogMountPolicy.AllowsOrdinaryMount(matches[0]) && managementScope is { } topologyScope &&
                    payload.ManagementJournalRootInspected && (VolumeTopologyProfile.LocalPath(topologyScope.ImagePath) && VolumeTopologyProfile.IsBounded(topologyScope) ||
                        VolumeTopologyProfile.IsPhysicalTopology(topologyScope, "create")) &&
                    payload.VolumeManagementReadyImages?.Contains(r.DeviceId!, StringComparer.OrdinalIgnoreCase) == true };
        }).ToList();
        rows = FusionDashboardRows.Apply(rows, payload);
        return rows.OrderByDescending(r => r.IsMounted).ThenBy(RowIdentity, StringComparer.Ordinal).ToArray();
    }

    public static string RowIdentity(DriveDashboardRow row) => string.IsNullOrWhiteSpace(row.VolumeId) ? "idle" :
        System.Text.Json.JsonSerializer.Serialize(new object?[] { row.DeviceId?.ToUpperInvariant(), row.VolumeId.ToUpperInvariant(),
            row.CatalogContainerUuid?.ToUpperInvariant(), row.CatalogVolumeId?.ToUpperInvariant(), row.CatalogVolumeObjectId,
            row.CatalogVolumeUuid?.ToUpperInvariant() });

    private static VerifyScope? MatchRawSnapshotScope(DeviceInventory device, VolumeInfo volume, MountedVolumeDisplay owner)
    {
        var path = volume.DeviceId;
        var prefix = path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ? @"\\.\PhysicalDrive" : @"\\?\PhysicalDrive";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || path.Length == prefix.Length ||
            !path[prefix.Length..].All(char.IsAsciiDigit) || device.Topology is null ||
            !CatalogMountPolicy.AllowsOrdinaryMount(volume) ||
            !TopologyGraphIndex.Text(volume.RecoveryIdentity) || owner.HostProcessCreationTimeFileTimeUtc <= 0 ||
            !owner.VolumeVerificationSupported || owner.VolumeVerificationScope is not { SourceKind: "retained-admitted-raw" } scope ||
            owner.AccessMode != MountAccessMode.ReadWrite || !owner.WriteEnabled || owner.RecoveryActive ||
            owner.NativeWriteReadiness is NativeWriteReadiness.Degraded or NativeWriteReadiness.RecoveryMode ||
            !string.IsNullOrEmpty(owner.RecoveryReason) || !string.Equals(owner.WriteBackend, "Native", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            _ = DateTime.FromFileTimeUtc(owner.HostProcessCreationTimeFileTimeUtc);
            _ = LiveVolumeVerificationScope.Parse(System.Text.Json.JsonSerializer.SerializeToElement(scope, ScopeWireOptions));
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidDataException or System.Text.Json.JsonException) { return null; }
        var topology = device.Topology.Snapshot;
        var catalog = topology.Volumes.SingleOrDefault(v => v.Id == volume.CatalogVolumeId);
        var container = catalog is null ? null : topology.Containers.SingleOrDefault(c => c.Id == catalog.ContainerId);
        if (container is null || container.Fusion || container.StoreIds.Count != 1 ||
            !TopologyAdmission.SameUuid(scope.ContainerUuid, volume.CatalogContainerUuid) ||
            !TopologyAdmission.SameUuid(scope.VolumeUuid, volume.CatalogVolumeUuid) ||
            scope.VolumeOid != volume.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture)) return null;
        var store = topology.Stores.SingleOrDefault(s => s.Id == container.StoreIds[0] && s.ContainerId == container.Id);
        if (store is null || store.OffsetBytes < 0 || store.SizeBytes <= 0 ||
            !TopologyAdmission.SameUuid(store.Uuid, scope.ContainerUuid) ||
            scope.StoreOffsetBytes != store.OffsetBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)) return null;
        // Catalog size is the GPT range. Only the native-authorized held NX window is actionable.
        var blockSize = store.BlockSizeBytes ?? container.BlockSizeBytes;
        var scopeSize = ulong.Parse(scope.StoreSizeBytes, System.Globalization.CultureInfo.InvariantCulture);
        var scopeOffset = ulong.Parse(scope.StoreOffsetBytes, System.Globalization.CultureInfo.InvariantCulture);
        if (blockSize <= 0 || blockSize != container.BlockSizeBytes || scopeSize == 0 ||
            scopeSize % (ulong)blockSize != 0 || scopeSize > (ulong)store.SizeBytes ||
            scopeOffset > ulong.MaxValue - scopeSize) return null;
        if (store.TotalBlocks is { } blocks && (blocks == 0 || blocks > ulong.MaxValue / (ulong)blockSize ||
            scopeSize != blocks * (ulong)blockSize)) return null;
        return new(volume.DeviceId, container.Id, scope.VolumeUuid, scope.VolumeOid, scope.CheckpointXid,
            scope.StoreOffsetBytes, scope.StoreSizeBytes);
    }

    private static bool SameTarget(VolumeInfo a, VolumeInfo b) =>
        string.Equals(a.DeviceId, b.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.VolumeId, b.VolumeId, StringComparison.OrdinalIgnoreCase);

    private static bool SameIdentity(DriveDashboardRow r, VolumeInfo v) =>
        string.Equals(r.DeviceId, v.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(r.VolumeId, v.VolumeId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(r.CatalogContainerUuid, v.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(r.CatalogVolumeId, v.CatalogVolumeId, StringComparison.OrdinalIgnoreCase) &&
        r.CatalogVolumeObjectId == v.CatalogVolumeObjectId &&
        string.Equals(r.CatalogVolumeUuid, v.CatalogVolumeUuid, StringComparison.OrdinalIgnoreCase);

    private static DriveDashboardRow BuildConnectedRow(StatusChangedPayload payload, DeviceInfo device, VolumeInfo v, bool unique)
    {
        var ordinary = CatalogMountPolicy.AllowsMount(v, false);
        var observedDevices = (payload.ConnectedInventory ?? []).Where(d => d.Device.DeviceId == v.DeviceId).ToArray();
        var backup = v.SupportsNativeWrite && BackupImageMountPolicy.HasCandidate(v) && observedDevices.Length == 1 &&
            observedDevices[0].Topology is { } topology && TopologyAdmission.Validate(observedDevices[0]) &&
            BackupImageMountPolicy.Observe(v, topology) == v.BackupImageWrite;
        var inspect = !ordinary && CatalogMountPolicy.AllowsReadOnlyInspection(v);
        var reason = v.IsEncrypted || v.CatalogDecision == ApfsCapabilityDecision.Locked ? "Locked."
            : !v.SupportsExplorerMount ? "Explorer mounting is unsupported for this volume."
            : backup ? v.BackupImageWrite?.PartitionUuid is null
                ? "Backup image. Native write admission required."
                : "Backup volume. Held source and recovery admission required."
            : ordinary ? "Not mounted."
            : inspect ? "Read-only."
            : "Unavailable.";
        if (!unique) reason = "Unavailable.";
        var display = new MountedVolumeDisplay(v.VolumeId, "", v.VolumeName, v.DeviceId, device.DisplayName,
            MountAccessMode.ReadOnly, CatalogVolumeId: v.CatalogVolumeId, CatalogContainerUuid: v.CatalogContainerUuid,
            CatalogVolumeObjectId: v.CatalogVolumeObjectId, CatalogSpace: v.CatalogSpace);
        var details = BuildDetails(payload with { State = RuntimeState.Idle }, display, DriveDashboardState.Idle)
            .Where(line => line.StartsWith("Device:") || line.StartsWith("Volume:") || line.StartsWith("Catalog ") ||
                line.Contains("space", StringComparison.OrdinalIgnoreCase) || line.StartsWith("Shared container") ||
                line.StartsWith("Volume ") || line.StartsWith("Reserved for") || line.StartsWith("Purgeable"))
            .Concat(new[] { $"Device identity: {v.DeviceId}", $"Routing identity: {v.VolumeId}",
                $"Catalog decision: {v.CatalogDecision?.ToString() ?? "Legacy / unspecified"}",
                $"Catalog reasons: {string.Join(", ", v.CatalogReasons ?? [])}", reason,
                // Aggregate diagnostics do not identify which catalog volume failed.
                $"Service state: {payload.State}",
                $"Service last error: {FirstNonBlank(payload.LastError, "none")}",
                $"Service warnings: {FormatWarnings(payload)}",
                $"Service diagnostics: {(payload.NativeWriteDiagnostics is { Count: > 0 } diagnostics
                    ? string.Join(" | ", diagnostics.Select(static diagnostic => $"{diagnostic.Code}: {diagnostic.Message}"))
                    : "none")}" })
            .Concat(v.CatalogReasons?.Contains("special-role:backup") == true
                ? new[] { $"Write availability: {v.WriteBlockReason ?? (backup ? "Native admission required" : "Read-only")}" }
                : []).ToArray();
        return new(v.VolumeId, device.DisplayName, v.VolumeName, "", "", DriveDashboardState.Idle, DashboardPalette.Gray,
            v.IsEncrypted || v.CatalogDecision == ApfsCapabilityDecision.Locked ? "Locked" : ordinary || inspect ? "Not mounted" : "Unavailable",
            reason, false, false, unique && ordinary, details, [reason], v.CatalogVolumeId, v.CatalogContainerUuid,
            v.CatalogVolumeObjectId, v.DeviceId, IsMounted: false, CanInspectReadOnly: unique && inspect,
            RecoveryIdentity: v.RecoveryIdentity, CatalogVolumeUuid: v.CatalogVolumeUuid,
            CanMountBackupReadWrite: unique && backup);
    }

    public static ControlOperationRequestPayload CreateMountRequest(StatusChangedPayload current, DriveDashboardRow selected)
        => CreateSelectedRequest(current, selected, ApfsControlCommands.Mount);

    public static bool CanFixVolume(DriveDashboardRow row) => row.CanFix && (row.IsMounted ||
        row.RegisteredImage is null && row.SnapshotScope is { } scope && VolumeTopologyProfile.LocalPath(row.DeviceId) &&
        string.Equals(scope.ImagePath, row.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        TopologyAdmission.SameUuid(scope.VolumeUuid, row.CatalogVolumeUuid) &&
        ApfsTopology.MatchesContainerUuid(scope.ContainerId, row.CatalogContainerUuid) &&
        scope.VolumeObjectId == row.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture));

    public static ControlOperationRequestPayload CreateSelectedRequest(StatusChangedPayload current, DriveDashboardRow selected, string command)
    {
        var candidates = TopologyDashboard.Project(current).Where(n => n.Row is not null).Select(n => n.Row!);
        var matches = candidates.Where(r => RowIdentity(r) == RowIdentity(selected)).ToArray();
        if (matches.Length != 1 || matches[0].RecoveryIdentity != selected.RecoveryIdentity ||
            matches[0].IsMounted != selected.IsMounted || matches[0].CanInspectReadOnly != selected.CanInspectReadOnly ||
            matches[0].CanMountBackupReadWrite != selected.CanMountBackupReadWrite)
            throw new InvalidOperationException("Volume identity or capability changed. Refresh before acting.");
        var row = matches[0];
        if (!(command switch {
            ApfsControlCommands.Unlock => row.CanUnlock,
            ApfsControlCommands.Lock => row.CanLock,
            ApfsControlCommands.Mount => row.CanMount,
            ApfsControlCommands.Fix => CanFixVolume(row) && row.CanFix == selected.CanFix &&
                (row.IsMounted || row.SnapshotScope == selected.SnapshotScope),
            ApfsControlCommands.VolumeVerify => row.CanVerifyOffline || row.CanVerifyLive,
            ApfsControlCommands.SnapshotList => row.CanVerifyOffline,
            ApfsControlCommands.Eject => row.IsMounted && row.CanEject,
            _ => false })) throw new InvalidOperationException("Selected action is unavailable.");
        var devices = (current.ConnectedInventory ?? []).Where(d => d.Device.DeviceId == row.DeviceId).ToArray();
        ApfsControlTarget target;
        if (devices.Length == 1 && (devices[0].Topology is not null || row.RegisteredImage is not null || row.RegisteredFusion is not null))
        {
            var volume = devices[0].Volumes.Single(v => v.VolumeId == row.VolumeId);
            target = SelectedControlTarget.Create(devices[0], volume);
        }
        else if (current.InventoryGeneration is null && current.ConnectedInventory?.Any(d => d.Topology is not null) != true)
            target = new(row.DeviceId!, row.VolumeId, row.RecoveryIdentity); // Explicit older status contract only.
        else throw new InvalidOperationException("Current selected topology evidence is unavailable.");
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), command, target,
            command != ApfsControlCommands.Mount ? null : row.CanMountBackupReadWrite ? ApfsControlModes.ReadWrite :
                row.CanInspectReadOnly ? ApfsControlModes.ReadOnly : ApfsControlModes.ReadWrite,
            DateTime.UtcNow.AddSeconds(90));
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        if (!validation.IsValid) throw new InvalidOperationException(validation.Diagnostic ?? "Invalid volume identity.");
        return request;
    }

    public static ControlOperationRequestPayload CreateSnapshotRequest(StatusChangedPayload current,
        DriveDashboardRow selected, string command, string? name = null, IReadOnlyList<string>? identity = null)
    {
        var row = TopologyDashboard.Project(current).Where(n => n.Row is not null).Select(n => n.Row!)
            .SingleOrDefault(r => RowIdentity(r) == RowIdentity(selected) && r.RecoveryIdentity == selected.RecoveryIdentity)
            ?? throw new InvalidOperationException("Snapshot volume identity changed. Refresh before acting.");
        if (row.IsMounted != selected.IsMounted || !(command switch
            {
                ApfsControlCommands.SnapshotCreate or ApfsControlCommands.SnapshotDelete => row.CanMutateSnapshots,
                ApfsControlCommands.SnapshotRecover => row.CanRecoverSnapshots,
                ApfsControlCommands.SnapshotList => row.CanVerifyOffline || row.CanListSnapshots,
                _ => false
            })) throw new InvalidOperationException("Selected snapshot action is unavailable.");
        if (row.SnapshotRuntimeAuthority is not null || selected.SnapshotRuntimeAuthority is not null)
        {
            if (row.SnapshotRuntimeAuthority != selected.SnapshotRuntimeAuthority || row.SnapshotScope != selected.SnapshotScope ||
                row.CanListSnapshots != selected.CanListSnapshots || row.CanMutateSnapshots != selected.CanMutateSnapshots)
                throw new InvalidOperationException("Snapshot runtime owner, source scope or capability changed. Refresh before acting.");
        }
        var device = (current.ConnectedInventory ?? []).Single(d => d.Device.DeviceId == row.DeviceId);
        var volume = device.Volumes.Single(v => v.VolumeId == row.VolumeId);
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), command,
            SelectedControlTarget.Create(device, volume), ExpiresAtUtc: DateTime.UtcNow.AddSeconds(90),
            SnapshotName: name, SnapshotIdentity: identity?.ToArray());
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        if (!validation.IsValid) throw new InvalidOperationException(validation.Diagnostic ?? "Invalid snapshot parameters.");
        return request;
    }

    // Task 12 management parity: presenter-side request builders for the
    // service verify-plan-confirm-apply path (mirrors the CLI
    // management-plan/management-apply contract). Identity validation matches
    // CreateSelectedRequest; the row must additionally be container-identified
    // (mirrors service TryManagementIdentity). The service remains the planner
    // authority (checkpoint/quiesce/keeper semantics); refusal surfaces live
    // through the owned operation result.
    public static ControlOperationRequestPayload CreateManagementPlanRequest(
        StatusChangedPayload current, DriveDashboardRow selected, string operation)
        => CreateManagementRequest(current, selected, ApfsControlCommands.ManagementPlan,
            operation, null, null, null, null, null);

    public static ControlOperationRequestPayload CreateManagementApplyRequest(
        StatusChangedPayload current, DriveDashboardRow selected, string operation, string token,
        string? name = null, string? quotaBytes = null, string? reserveBytes = null, string? imagePath = null)
        => CreateManagementRequest(current, selected, ApfsControlCommands.ManagementApply,
            operation, token, name, quotaBytes, reserveBytes, imagePath);

    private static ControlOperationRequestPayload CreateManagementRequest(
        StatusChangedPayload current, DriveDashboardRow selected, string command, string operation,
        string? token, string? name, string? quotaBytes, string? reserveBytes, string? imagePath)
    {
        if (operation is not (ApfsManagementOperations.RenameVolume or ApfsManagementOperations.SetQuotaReserve))
            throw new InvalidOperationException("Management operation must be rename-volume or set-quota-reserve.");
        var candidates = TopologyDashboard.Project(current).Where(n => n.Row is not null).Select(n => n.Row!);
        var matches = candidates.Where(r => RowIdentity(r) == RowIdentity(selected)).ToArray();
        if (matches.Length != 1 || matches[0].RecoveryIdentity != selected.RecoveryIdentity ||
            matches[0].IsMounted != selected.IsMounted || matches[0].CanInspectReadOnly != selected.CanInspectReadOnly)
            throw new InvalidOperationException("Volume identity or capability changed. Refresh before acting.");
        var row = matches[0];
        if (!row.CanManageOffline)
            throw new InvalidOperationException("Management requires an eligible offline image with every sibling unmounted.");
        if (string.IsNullOrWhiteSpace(row.CatalogContainerUuid))
            throw new InvalidOperationException("Selected volume is not container-identified.");
        var isRename = string.Equals(operation, ApfsManagementOperations.RenameVolume, StringComparison.Ordinal);
        if (command == ApfsControlCommands.ManagementApply)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(imagePath))
                throw new InvalidOperationException("Management apply requires a confirmation token and an image path.");
            if (!string.Equals(imagePath, row.DeviceId, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Management must use the selected image source.");
            if (isRename)
            {
                if (string.IsNullOrWhiteSpace(name) ||
                    quotaBytes is not null || reserveBytes is not null)
                    throw new InvalidOperationException("Management rename apply requires name with no quota values.");
            }
            else if (name is not null ||
                string.IsNullOrWhiteSpace(quotaBytes) || string.IsNullOrWhiteSpace(reserveBytes))
            {
                throw new InvalidOperationException("Management quota apply requires quota and reserve values with no name.");
            }
        }
        else if (token is not null || name is not null || quotaBytes is not null || reserveBytes is not null || imagePath is not null)
        {
            throw new InvalidOperationException("Management plan takes only device, volume, and operation.");
        }
        var devices = (current.ConnectedInventory ?? []).Where(d => d.Device.DeviceId == row.DeviceId).ToArray();
        ApfsControlTarget target;
        if (devices.Length == 1 && (devices[0].Topology is not null || row.RegisteredImage is not null))
        {
            var volume = devices[0].Volumes.Single(v => v.VolumeId == row.VolumeId);
            target = SelectedControlTarget.Create(devices[0], volume);
        }
        else if (current.InventoryGeneration is null && current.ConnectedInventory?.Any(d => d.Topology is not null) != true)
            target = new(row.DeviceId!, row.VolumeId, row.RecoveryIdentity); // Explicit older status contract only.
        else throw new InvalidOperationException("Current selected topology evidence is unavailable.");
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), command, target,
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(90),
            ManagementOperation: operation,
            ManagementToken: token,
            ManagementName: name,
            ManagementQuotaBytes: quotaBytes,
            ManagementReserveBytes: reserveBytes,
            ManagementImagePath: imagePath);
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        if (!validation.IsValid) throw new InvalidOperationException(validation.Diagnostic ?? "Invalid volume identity.");
        return request;
    }

    public static DriveLetterPreferenceRequestPayload CreatePreferenceRequest(StatusChangedPayload current, DriveDashboardRow selected, string letter)
    {
        var rows = TopologyDashboard.Project(current).Where(n => n.Row is not null).Select(n => n.Row!)
            .Where(r => RowIdentity(r) == RowIdentity(selected) && r.RecoveryIdentity == selected.RecoveryIdentity).ToArray();
        if (rows.Length != 1 || rows[0].DriveLetterPreference is not { CanEdit: true, VolumeUuid: not null } preference ||
            !TopologyAdmission.SameUuid(preference.VolumeUuid, selected.DriveLetterPreference?.VolumeUuid))
            throw new InvalidOperationException("Selected preference identity changed. Refresh before saving.");
        var row = rows[0];
        var d = (current.ConnectedInventory ?? []).Single(d => d.Device.DeviceId == row.DeviceId);
        var v = d.Volumes.Single(v => v.VolumeId == row.VolumeId);
        var target = d.Topology is null ? null : SelectedControlTarget.Create(d, v);
        return new(row.DeviceId!, row.VolumeId, preference.VolumeUuid, letter, target);
    }

    public static DriveDashboardRow ProjectObservedMount(MountedVolumeState mount)
    {
        var status = new StatusChangedPayload(mount.AccessMode == MountAccessMode.ReadWrite ? RuntimeState.MountedRw : RuntimeState.MountedRo,
            [mount.MountPoint], null, DateTime.UtcNow, [], mount.AccessMode == MountAccessMode.ReadWrite, [],
            MountedVolumes: MountedStatusProjection.FromMounts([mount]));
        return BuildRows(status).Single();
    }

    // Task 12 Step 3 container actions (mount eligible / unmount all). Rows
    // come from the selected tree node's descendant volume rows, so this
    // works for every projection path (typed topology, inventory fallback,
    // registered images) without node-id parsing. The service re-resolves
    // membership authoritatively; the checks here only gate the buttons and
    // fail closed on stale selection.
    public static bool TryResolveContainerTarget(
        IReadOnlyList<DriveDashboardRow> rows,
        out string deviceId,
        out string containerUuid)
    {
        deviceId = string.Empty;
        containerUuid = string.Empty;
        if (rows.Count == 0)
        {
            return false;
        }

        var devices = rows
            .Select(static r => r.DeviceId)
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var containers = rows
            .Select(static r => r.CatalogContainerUuid)
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (devices.Length != 1 || containers.Length != 1 ||
            rows.Any(static r => string.IsNullOrWhiteSpace(r.DeviceId) ||
                string.IsNullOrWhiteSpace(r.CatalogContainerUuid) ||
                string.IsNullOrWhiteSpace(r.VolumeId)))
        {
            return false;
        }

        deviceId = devices[0]!;
        containerUuid = containers[0]!;
        return true;
    }

    public static bool ContainerMountAvailable(IReadOnlyList<DriveDashboardRow> rows)
        => rows.Any(static r => r.CanMount);

    public static bool ContainerUnmountAvailable(IReadOnlyList<DriveDashboardRow> rows)
        => rows.Any(static r => r.IsMounted && r.CanEject);

    public static bool ContainerFixAvailable(IReadOnlyList<DriveDashboardRow> rows)
        => rows.Any(CanFixVolume);

    // Preliminary row eligibility only. ContainerVolumeVerification also binds
    // the complete current topology and retained owners before any dispatch.
    public static bool ContainerVerifyAvailable(IReadOnlyList<DriveDashboardRow> rows)
        => TryResolveContainerTarget(rows, out _, out _) &&
            rows.Select(RowIdentity).Distinct(StringComparer.Ordinal).Count() == rows.Count &&
            rows.Select(r => r.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() == rows.Count &&
            rows.All(r => r.CatalogVolumeObjectId is > 0 &&
                TopologyAdmission.SameUuid(r.CatalogVolumeUuid, r.CatalogVolumeUuid) &&
                (r.IsMounted ? r.CanVerifyLive : r.CanVerifyOffline));

    public static bool ContainerManageAvailable(IReadOnlyList<DriveDashboardRow> rows)
        => TryResolveContainerTarget(rows,out _,out _) && rows.Count>0 &&
            rows.Select(RowIdentity).Distinct(StringComparer.Ordinal).Count()==rows.Count &&
            rows.Select(r=>r.VolumeId).Distinct(StringComparer.Ordinal).Count()==rows.Count &&
            rows.All(r=>!r.IsMounted) && rows.Any(r=>r.CanManageOffline);

    public static string ContainerUnavailableActionReason(string action) =>
        action == "container-manage"
            ? "Select an admitted offline container member for a service-backed management plan. An unbound atomic container change is unavailable."
            : "Verify volumes requires every current container member to have an exact eligible per-volume verification target. Refresh before retrying.";

    public static string VolumeUnavailableActionReason(string action) =>
        action == "snapshots"
            ? "SnapshotRuntimeOwnerNotReady: Snapshot changes require explicit native runtime enrollment; image inventory requires every source volume unmounted."
            : "Volume rename and quota/reserve require an eligible offline image and an explicitly configured management journal root.";

    public static string FormatMemberHealth(TopologyDashboardNode node)
    {
        var isStore = node.Id.StartsWith("apfs-store:", StringComparison.Ordinal) ||
                      node.Id.StartsWith("registered-store:", StringComparison.Ordinal);
        var isPartition = node.Id.StartsWith("apfs-part:", StringComparison.Ordinal);
        var missing = node.Details.Contains("Missing member", StringComparison.OrdinalIgnoreCase);
        var kind = isStore ? "APFS Physical Store" : isPartition ? "GPT Partition" : "Member";
        var status = missing ? "Degraded (member missing or unassigned)" : "Healthy and attached";

        return $"{kind} Health: {status}\nIdentity: {node.Id}\n{node.Details}";
    }

    // Task 12 Step 3 physical-disk action (eject device): drains every
    // container/volume on one physical device. Rows only need a shared
    // device; containers may differ (the service fans out per container).
    public static bool TryResolveDeviceTarget(
        IReadOnlyList<DriveDashboardRow> rows,
        out string deviceId)
    {
        deviceId = string.Empty;
        if (rows.Count == 0)
        {
            return false;
        }

        var devices = rows
            .Select(static r => r.DeviceId)
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (devices.Length != 1 ||
            rows.Any(static r => string.IsNullOrWhiteSpace(r.DeviceId) ||
                string.IsNullOrWhiteSpace(r.VolumeId)))
        {
            return false;
        }

        deviceId = devices[0]!;
        return true;
    }

    public static bool DeviceEjectAvailable(IReadOnlyList<DriveDashboardRow> rows)
        => rows.Any(static r => r.IsMounted);

    public static ControlOperationRequestPayload CreateDeviceRequest(
        StatusChangedPayload current,
        IReadOnlyList<DriveDashboardRow> rows)
    {
        if (!TryResolveDeviceTarget(rows, out var deviceId))
        {
            throw new InvalidOperationException("Selected volumes do not share exactly one device. Refresh before acting.");
        }

        var devices = (current.ConnectedInventory ?? [])
            .Where(d => string.Equals(d.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (devices.Length != 1 || !devices[0].Device.IsConnected)
        {
            throw new InvalidOperationException("Selected device is unavailable. Refresh before acting.");
        }

        // Freshness: every selected row must still exist.
        var wanted = rows.Select(RowIdentity).ToHashSet(StringComparer.Ordinal);
        var fresh = BuildRows(current).Where(r => wanted.Contains(RowIdentity(r))).ToArray();
        if (fresh.Length != rows.Count)
        {
            throw new InvalidOperationException("Volume identity or capability changed. Refresh before acting.");
        }

        if (!DeviceEjectAvailable(fresh))
        {
            throw new InvalidOperationException("Selected action is unavailable.");
        }

        var target = new ApfsControlTarget(deviceId, string.Empty);
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"),
            ApfsControlCommands.DeviceEject, target, ExpiresAtUtc: DateTime.UtcNow.AddSeconds(170));
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        if (!validation.IsValid) throw new InvalidOperationException(validation.Diagnostic ?? "Invalid device identity.");
        return request;
    }

    public static ControlOperationRequestPayload CreateContainerRequest(
        StatusChangedPayload current,
        IReadOnlyList<DriveDashboardRow> rows,
        string command)
    {
        if (command is not (ApfsControlCommands.ContainerMount or ApfsControlCommands.ContainerUnmount))
        {
            throw new InvalidOperationException("Unknown container action.");
        }

        if (!TryResolveContainerTarget(rows, out var deviceId, out var containerUuid))
        {
            throw new InvalidOperationException("Selected volumes do not form exactly one container. Refresh before acting.");
        }

        // Freshness: every selected row must still exist with identical
        // identity and capability flags, mirroring CreateSelectedRequest.
        var wanted = rows.Select(RowIdentity).ToHashSet(StringComparer.Ordinal);
        var fresh = BuildRows(current).Where(r => wanted.Contains(RowIdentity(r))).ToArray();
        if (fresh.Length != rows.Count)
        {
            throw new InvalidOperationException("Volume identity or capability changed. Refresh before acting.");
        }

        foreach (var row in rows)
        {
            var live = fresh.Single(r => RowIdentity(r) == RowIdentity(row));
            if (live.RecoveryIdentity != row.RecoveryIdentity || live.IsMounted != row.IsMounted ||
                live.CanFix != row.CanFix || live.CanInspectReadOnly != row.CanInspectReadOnly ||
                live.CanMountBackupReadWrite != row.CanMountBackupReadWrite ||
                live.CanEject != row.CanEject)
            {
                throw new InvalidOperationException("Volume identity or capability changed. Refresh before acting.");
            }
        }

        // Membership against live inventory: every selected row must belong
        // to the resolved container right now.
        var devices = (current.ConnectedInventory ?? [])
            .Where(d => string.Equals(d.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (devices.Length != 1)
        {
            throw new InvalidOperationException("Selected device is unavailable. Refresh before acting.");
        }

        foreach (var row in rows)
        {
            var member = devices[0].Volumes.Where(v =>
                string.Equals(v.DeviceId, row.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(v.VolumeId, row.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                ApfsTopology.MatchesContainerUuid(containerUuid, v.CatalogContainerUuid)).ToArray();
            if (member.Length != 1)
            {
                throw new InvalidOperationException("Selected container membership changed. Refresh before acting.");
            }
        }

        var available = command == ApfsControlCommands.ContainerMount
            ? ContainerMountAvailable(fresh)
            : ContainerUnmountAvailable(fresh);
        if (!available)
        {
            throw new InvalidOperationException("Selected action is unavailable.");
        }

        var mode = command != ApfsControlCommands.ContainerMount
            ? null
            : fresh.Any(static r => r.CanFix || r.CanMountBackupReadWrite) ? ApfsControlModes.ReadWrite : ApfsControlModes.ReadOnly;
        var target = new ApfsControlTarget(deviceId, string.Empty, null, null, containerUuid.Trim().ToLowerInvariant());
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), command, target,
            mode, DateTime.UtcNow.AddSeconds(90));
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        if (!validation.IsValid) throw new InvalidOperationException(validation.Diagnostic ?? "Invalid container identity.");
        return request;
    }

    public static string BuildSummary(StatusChangedPayload payload)
    {
        var rows = BuildRows(payload);
        var mountedRows = (payload.MountedVolumes ?? [])
            .Where(v => !string.IsNullOrWhiteSpace(v.VolumeId) && !string.IsNullOrWhiteSpace(v.MountPoint))
            .Select(v => BuildRow(payload, v)).ToArray();
        if (mountedRows.Length == 0)
        {
            return payload.ConnectedInventory is not null ? "No APFS drives mounted." : rows[0].Summary;
        }

        var countText = mountedRows.Length == 1 ? "1 APFS drive mounted" : $"{mountedRows.Length} APFS drives mounted";
        var worst = mountedRows.Select(static row => row.State).Max();
        return worst switch
        {
            DriveDashboardState.HealthyReadWrite => $"{countText}. Full read/write access is available.",
            DriveDashboardState.FinishingWrites => $"{countText}. Finishing recent writes.",
            DriveDashboardState.ReadOnly => $"{countText}. Attention may be needed.",
            DriveDashboardState.Attention => $"{countText}. Attention may be needed.",
            DriveDashboardState.Problem => $"{countText}. A problem needs attention.",
            _ => $"{countText}.",
        };
    }

    public static string NormalizeDriveLabel(string? mountPoint)
    {
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            return string.Empty;
        }

        var trimmed = mountPoint.Trim();
        if ((trimmed.Length == 2 || trimmed.Length == 3 && trimmed[2] is '\\' or '/') &&
            char.IsAsciiLetter(trimmed[0]) && trimmed[1] == ':')
        {
            return $"{char.ToUpperInvariant(trimmed[0])}:";
        }

        return trimmed.TrimEnd('\\');
    }

    private static DriveDashboardRow BuildRow(StatusChangedPayload payload, MountedVolumeDisplay volume)
    {
        payload = StatusForVolume(payload, volume);
        var state = Classify(payload, volume);
        var palette = ToPalette(state);
        var mountPoint = NormalizeDriveLabel(volume.MountPoint);
        var details = BuildDetails(payload, volume, state);
        var ordinaryMount = CatalogMountPolicy.AllowsOrdinaryMount(
            volume.CatalogDecision, volume.CatalogReasons, volume.CatalogAutoMountAllowed);
        return new DriveDashboardRow(
            VolumeId: volume.VolumeId,
            DeviceName: FirstNonBlank(volume.DeviceDisplayName, volume.DeviceId, "APFS drive"),
            VolumeName: FirstNonBlank(volume.VolumeName, "APFS volume"),
            MountPoint: mountPoint,
            MountPath: NormalizeMountPath(volume.MountPoint),
            State: state,
            Palette: palette,
            StateText: ToStateText(state),
            Summary: (ordinaryMount ? BuildRowSummary(payload, volume, state)
                : "Catalog policy blocks writes and automatic mounting for this volume.") +
                (volume.DriveLetterPreference is { } preference ? " " + preference.Text + "." : string.Empty),
            CanOpen: !string.IsNullOrWhiteSpace(mountPoint),
            CanEject: !string.IsNullOrWhiteSpace(volume.VolumeId) || !string.IsNullOrWhiteSpace(mountPoint),
            CanFix: ordinaryMount && state is (DriveDashboardState.ReadOnly or DriveDashboardState.Attention or DriveDashboardState.Problem),
            Details: details,
            FixGuidance: ordinaryMount ? AppendRepairPointer(BuildFixGuidance(state, payload), IsRegisteredImageVolume(payload, volume))
                : ["Catalog policy prevents writable repair for this volume. Read-only inspection does not enable writes."],
            CatalogVolumeId: volume.CatalogVolumeId,
            CatalogContainerUuid: volume.CatalogContainerUuid,
            CatalogVolumeObjectId: volume.CatalogVolumeObjectId,
            DeviceId: volume.DeviceId,
            DriveLetterPreference: volume.DriveLetterPreference,
            RecoveryIdentity: volume.RecoveryIdentity, CatalogVolumeUuid: volume.CatalogVolumeUuid,
            SnapshotRuntimeAuthority: volume.VolumeVerificationScope is { SourceKind: "retained-admitted-raw" } scope
                ? new(volume.HostProcessId, volume.HostProcessCreationTimeFileTimeUtc, scope) : null);
    }

    private static StatusChangedPayload StatusForVolume(StatusChangedPayload aggregate, MountedVolumeDisplay volume)
    {
        // Older senders omit this marker and only supply aggregate health.
        if (!volume.HasRuntimeStatus) return aggregate;
        return aggregate with
        {
            State = volume.State,
            LastError = null,
            // Aggregate warnings may describe failed attempts on other volumes.
            Warnings = Array.Empty<string>(),
            CompatibilityWarnings = Array.Empty<string>(),
            WriteEnabled = volume.WriteEnabled,
            WriteBackend = volume.WriteBackend,
            CommitModel = volume.CommitModel,
            NativeWriteReadiness = volume.NativeWriteReadiness,
            NativeWriteEngineState = volume.NativeWriteEngineState,
            NativeWriteValidationState = volume.NativeWriteValidationState,
            NativeWriteSafetyState = volume.NativeWriteSafetyState,
            NativeWriteValidationEvidence = volume.NativeWriteValidationEvidence,
            NativeWriteDiagnostics = volume.NativeWriteDiagnostics,
            RecoveryActive = volume.RecoveryActive,
            RecoveryReason = volume.RecoveryReason,
            LastRecoveryAction = volume.LastRecoveryAction,
            LastCommitXid = volume.LastCommitXid,
            WriteIncompatibilities = volume.WriteIncompatibilities,
            WriteUnsupportedFeatures = volume.WriteUnsupportedFeatures,
            DirtyTransactionCount = volume.DirtyTransactionCount,
            ShutdownDrainActive = volume.ShutdownDrainActive,
            InFlightMutationCallbacks = volume.InFlightMutationCallbacks,
        };
    }

    private static DriveDashboardState Classify(StatusChangedPayload payload, MountedVolumeDisplay volume)
    {
        if (payload.State == RuntimeState.Error)
        {
            return DriveDashboardState.Problem;
        }

        if (volume.HasRuntimeStatus)
        {
            if (volume.RecoveryActive || volume.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked)
                return DriveDashboardState.Problem;
            if (volume.PendingDurability || volume.WalAcceptedSequence > volume.WalApfsDurableSequence ||
                volume.DirtyTransactionCount > 0 || volume.ShutdownDrainActive || volume.InFlightMutationCallbacks > 0)
                return DriveDashboardState.FinishingWrites;
            if (volume.AccessMode != MountAccessMode.ReadWrite || !volume.WriteEnabled ||
                volume.NativeWriteSafetyState == NativeWriteSafetyState.ReadOnlyFallback)
                return DriveDashboardState.ReadOnly;
            if (volume.State != RuntimeState.MountedRw || !volume.MountReady)
                return DriveDashboardState.Attention;
            return DriveDashboardState.HealthyReadWrite;
        }

        if (volume.AccessMode == MountAccessMode.ReadWrite &&
            payload.State == RuntimeState.MountedRw)
        {
            if (payload.DirtyTransactionCount > 0 ||
                payload.ShutdownDrainActive)
            {
                return DriveDashboardState.FinishingWrites;
            }

            return DriveDashboardState.HealthyReadWrite;
        }

        if (payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked ||
            payload.RecoveryActive)
        {
            return DriveDashboardState.Problem;
        }

        if (payload.DirtyTransactionCount > 0 ||
            payload.ShutdownDrainActive)
        {
            return DriveDashboardState.FinishingWrites;
        }

        if (volume.AccessMode == MountAccessMode.ReadOnly ||
            payload.State == RuntimeState.MountedRo)
        {
            return DriveDashboardState.ReadOnly;
        }

        if (!payload.WriteEnabled ||
            payload.NativeWriteSafetyState == NativeWriteSafetyState.ReadOnlyFallback)
        {
            return DriveDashboardState.ReadOnly;
        }

        if (HasWarnings(payload))
        {
            return DriveDashboardState.Attention;
        }

        return DriveDashboardState.Idle;
    }

    private static DriveDashboardState ClassifyIdle(StatusChangedPayload payload)
    {
        if (payload.State == RuntimeState.Error ||
            payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked ||
            payload.RecoveryActive)
        {
            return DriveDashboardState.Problem;
        }

        if (payload.State is RuntimeState.Starting or RuntimeState.Stopping ||
            payload.DirtyTransactionCount > 0 ||
            payload.ShutdownDrainActive ||
            HasWarnings(payload))
        {
            return DriveDashboardState.Attention;
        }

        return DriveDashboardState.Idle;
    }

    private static DashboardPalette ToPalette(DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.HealthyReadWrite => DashboardPalette.Green,
            DriveDashboardState.FinishingWrites => DashboardPalette.Blue,
            DriveDashboardState.ReadOnly => DashboardPalette.Yellow,
            DriveDashboardState.Attention => DashboardPalette.Orange,
            DriveDashboardState.Problem => DashboardPalette.Red,
            _ => DashboardPalette.Gray,
        };

    private static string ToStateText(DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.HealthyReadWrite => "Healthy read/write",
            DriveDashboardState.FinishingWrites => "Finishing writes",
            DriveDashboardState.ReadOnly => "Read-only",
            DriveDashboardState.Attention => "Needs attention",
            DriveDashboardState.Problem => "Problem",
            _ => "Idle",
        };

    private static string BuildRowSummary(StatusChangedPayload payload, MountedVolumeDisplay volume, DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.HealthyReadWrite => "Full read/write access is available.",
            DriveDashboardState.FinishingWrites => volume.HasRuntimeStatus &&
                (volume.PendingDurability || volume.WalAcceptedSequence > volume.WalApfsDurableSequence)
                    ? "Recent writes are still settling. Wait a moment before unplugging."
                    : BuildAttentionSummary(payload),
            DriveDashboardState.ReadOnly => "The drive is mounted for reading, but writes are not currently available.",
            DriveDashboardState.Attention => BuildAttentionSummary(payload),
            DriveDashboardState.Problem => BuildProblemSummary(payload),
            _ => string.IsNullOrWhiteSpace(volume.MountPoint) ? "The APFS volume is not mounted." : "Waiting for status.",
        };

    private static string BuildAttentionSummary(StatusChangedPayload payload)
    {
        if (payload.DirtyTransactionCount > 0)
        {
            return "Recent writes are still settling. Wait a moment before unplugging.";
        }

        if (payload.ShutdownDrainActive)
        {
            return "APFS Access is finishing pending work before shutdown or eject.";
        }

        if (payload.InFlightMutationCallbacks > 0)
        {
            return "A file operation is still in progress.";
        }

        return "There are warnings for this drive. Check details or try Fix.";
    }

    private static string BuildProblemSummary(StatusChangedPayload payload)
    {
        if (!string.IsNullOrWhiteSpace(payload.RecoveryReason))
        {
            return $"Writes are blocked by recovery state: {payload.RecoveryReason}.";
        }

        if (!string.IsNullOrWhiteSpace(payload.LastError))
        {
            return payload.LastError;
        }

        return "APFS Access detected a problem that needs attention.";
    }

    private static IReadOnlyList<string> BuildDetails(
        StatusChangedPayload payload,
        MountedVolumeDisplay volume,
        DriveDashboardState state)
    {
        var warnings = payload.Warnings
            .Concat(payload.CompatibilityWarnings)
            .Where(static warning => !string.IsNullOrWhiteSpace(warning))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var diagnostics = payload.NativeWriteDiagnostics ?? Array.Empty<NativeWriteDiagnostic>();
        var details = new List<string>
        {
            $"Device: {FirstNonBlank(volume.DeviceDisplayName, volume.DeviceId, "APFS drive")}",
            $"Volume: {FirstNonBlank(volume.VolumeName, "APFS volume")}",
            $"Drive: {FirstNonBlank(NormalizeDriveLabel(volume.MountPoint), "not mounted")}",
            $"State: {ToStateText(state)}",
            $"Backend: {payload.WriteBackend}",
            $"Commit model: {payload.CommitModel}",
            $"Readiness: {payload.NativeWriteReadiness}",
            $"Safety: {payload.NativeWriteSafetyState}",
            $"Validation: {payload.NativeWriteValidationState}",
            $"Recovery: {(payload.RecoveryActive ? "active" : "inactive")}",
            $"Recovery reason: {FirstNonBlank(payload.RecoveryReason, "none")}",
            $"Dirty transactions: {payload.DirtyTransactionCount}",
            $"Active file operations: {payload.InFlightMutationCallbacks}",
            $"Last commit: {(payload.LastCommitXid.HasValue ? payload.LastCommitXid.Value.ToString() : "none")}",
            $"Warnings: {(warnings.Length == 0 ? "none" : string.Join(" | ", warnings))}",
            $"Diagnostics: {(diagnostics.Count == 0 ? "none" : string.Join(" | ", diagnostics.Select(static x => $"{x.Code}: {x.Message}")))}",
            $"Catalog volume: {FirstNonBlank(volume.CatalogVolumeId, "none")}",
            $"Catalog container: {FirstNonBlank(volume.CatalogContainerUuid, "none")}",
            $"Catalog OID: {(volume.CatalogVolumeObjectId.HasValue ? volume.CatalogVolumeObjectId.Value.ToString() : "none")}",
        };

        if (volume.CatalogSpace is { } space &&
            space.Volume.VolumeId == volume.CatalogVolumeId &&
            space.Volume.ObjectId == volume.CatalogVolumeObjectId &&
            space.ContainerId == "apfs-container:" + volume.CatalogContainerUuid)
        {
            details.Add($"Space at last scan (checkpoint {space.CheckpointXid}):");
            details.Add($"Shared container capacity: {FormatSpaceBytes(space.ContainerTotal.Bytes)}");
            details.Add($"Shared container free: {FormatSpaceBytes(space.ContainerFree.Bytes)}");
            details.Add($"Volume allocated: {FormatSpaceBytes(space.Volume.Allocated.Bytes)}");
            details.Add($"Volume available at scan: {FormatSpaceBytes(space.Volume.Available.Bytes)}");
            details.Add($"Volume quota: {(space.Volume.Quota is { } quota ? FormatSpaceBytes(quota.Bytes) : "No limit")}");
            details.Add($"Volume reservation: {(space.Volume.Reserve is { } reserve ? FormatSpaceBytes(reserve.Bytes) : "None")}");
            details.Add($"Reserved for other volumes: {FormatSpaceBytes(space.Volume.SiblingReserveRemaining.Bytes)}");
            details.Add($"Snapshot space: {(space.Volume.Snapshot is { } snapshot ? FormatSpaceBytes(snapshot.Bytes) : "Unknown")}");
            details.Add($"Purgeable space: {(space.Volume.Purgeable is { } purgeable ? FormatSpaceBytes(purgeable.Bytes) : "Unknown")}");
        }
        return details;
    }

    internal static string FormatSpaceBytes(ulong bytes)
    {
        const double unit = 1024.0;
        var culture = System.Globalization.CultureInfo.CurrentCulture;
        if (bytes >= 1024UL * 1024 * 1024)
            return (bytes / (unit * unit * unit)).ToString("N2", culture) + " GB";
        if (bytes >= 1024UL * 1024)
            return (bytes / (unit * unit)).ToString("N2", culture) + " MB";
        if (bytes >= 1024UL)
            return (bytes / unit).ToString("N2", culture) + " KB";
        return bytes.ToString("N0", culture) + " bytes";
    }

    internal static string FormatByteSize(long bytes)
        => FormatSpaceBytes(bytes < 0 ? 0UL : (ulong)bytes);

    private static IReadOnlyList<string> BuildIdleDetails(StatusChangedPayload payload)
    {
        return
        [
            $"State: {payload.State}",
            $"Last error: {FirstNonBlank(payload.LastError, "none")}",
            $"Warnings: {FormatWarnings(payload)}",
        ];
    }

    private static IReadOnlyList<string> BuildFixGuidance(DriveDashboardState state, StatusChangedPayload payload)
    {
        if (state is DriveDashboardState.HealthyReadWrite or DriveDashboardState.FinishingWrites or DriveDashboardState.Idle)
        {
            return Array.Empty<string>();
        }

        var guidance = new List<string>
        {
            "APFS Access will first refresh the drive and try to remount it safely.",
            "If it stays degraded, close Explorer windows and any files open from this drive.",
            "If it still does not recover, use Eject, unplug the drive, wait a few seconds, and plug it back in.",
            "If recovery remains blocked, copy important files off before doing more writes.",
        };

        if (!string.IsNullOrWhiteSpace(payload.RecoveryReason))
        {
            guidance.Insert(0, $"Current recovery reason: {payload.RecoveryReason}");
        }

        return guidance;
    }

    // Repair pointer for registered image files only: physical devices cannot
    // use the offline image repair tool, and healthy states carry no guidance
    // at all, so the pointer appears exactly on non-healthy image rows.
    private static IReadOnlyList<string> AppendRepairPointer(
        IReadOnlyList<string> guidance, bool isRegisteredImage)
    {
        if (!isRegisteredImage || guidance.Count == 0)
        {
            return guidance;
        }

        return
        [
            ..guidance,
            "Registered image file: diagnose read-only first with APFSAccess.Cli.exe verify --help; " +
            "bounded offline count repair, if eligible, is a separate repair command that refuses anything outside its contract.",
        ];
    }

    private static bool IsRegisteredImageVolume(StatusChangedPayload payload, MountedVolumeDisplay volume)
        => (payload.ConnectedInventory ?? []).SelectMany(static device => device.Volumes).Any(candidate =>
            candidate.RegisteredImage is not null &&
            string.Equals(candidate.DeviceId, volume.DeviceId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(candidate.VolumeId, volume.VolumeId, StringComparison.OrdinalIgnoreCase));

    private static string BuildIdleTitle(StatusChangedPayload payload)
        => payload.State switch
        {
            RuntimeState.Starting => "APFS Access is starting",
            RuntimeState.Stopping => "APFS Access is stopping",
            RuntimeState.Error => "APFS Access needs attention",
            _ => "No APFS drives mounted",
        };

    private static string BuildIdleStateText(StatusChangedPayload payload, DriveDashboardState state)
    {
        if (state != DriveDashboardState.Idle)
        {
            return ToStateText(state);
        }

        return payload.State switch
        {
            RuntimeState.Starting => "Starting",
            RuntimeState.Stopping => "Stopping",
            _ => "Idle",
        };
    }

    private static string BuildIdleSummary(StatusChangedPayload payload)
    {
        if (HasSafelyEjectedWarning(payload))
        {
            return "The drive was safely ejected. Use Fix to remount it, or unplug and reinsert it.";
        }

        return payload.State switch
        {
            RuntimeState.Starting => "Waiting for the APFS Access service.",
            RuntimeState.Stopping => "APFS Access is shutting down.",
            RuntimeState.Error => FirstNonBlank(payload.LastError, "The service reported an error."),
            _ => "Plug in an APFS drive or refresh after reconnecting one.",
        };
    }

    private static bool HasWarnings(StatusChangedPayload payload)
        => payload.Warnings.Any(static warning => !string.IsNullOrWhiteSpace(warning)) ||
           payload.CompatibilityWarnings.Any(static warning => !string.IsNullOrWhiteSpace(warning)) ||
           payload.NativeWriteDiagnostics is { Count: > 0 };

    private static bool HasSafelyEjectedWarning(StatusChangedPayload payload)
        => payload.Warnings
            .Concat(payload.CompatibilityWarnings)
            .Any(static warning => warning.Contains("safely ejected", StringComparison.OrdinalIgnoreCase));

    private static string FormatWarnings(StatusChangedPayload payload)
    {
        var warnings = payload.Warnings
            .Concat(payload.CompatibilityWarnings)
            .Where(static warning => !string.IsNullOrWhiteSpace(warning))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return warnings.Length == 0 ? "none" : string.Join(" | ", warnings);
    }

    private static string NormalizeMountPath(string? mountPoint)
    {
        var label = NormalizeDriveLabel(mountPoint);
        if (string.IsNullOrWhiteSpace(label))
        {
            return string.Empty;
        }

        return label.EndsWith(':') ? $"{label}\\" : label;
    }

    private static string FirstNonBlank(params string?[] candidates)
        => candidates.FirstOrDefault(static candidate => !string.IsNullOrWhiteSpace(candidate))?.Trim() ?? string.Empty;
}
