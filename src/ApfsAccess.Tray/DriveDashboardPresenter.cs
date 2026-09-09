using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static class DriveDashboardPresenter
{
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
                ? r with { CanFix = false, CanInspectReadOnly = false, CanEject = false,
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

        return rows.OrderByDescending(r => r.IsMounted).ThenBy(RowIdentity, StringComparer.Ordinal).ToArray();
    }

    public static string RowIdentity(DriveDashboardRow row) => string.IsNullOrWhiteSpace(row.VolumeId) ? "idle" :
        System.Text.Json.JsonSerializer.Serialize(new object?[] { row.DeviceId?.ToUpperInvariant(), row.VolumeId.ToUpperInvariant(),
            row.CatalogContainerUuid?.ToUpperInvariant(), row.CatalogVolumeId?.ToUpperInvariant(), row.CatalogVolumeObjectId });

    private static bool SameTarget(VolumeInfo a, VolumeInfo b) =>
        string.Equals(a.DeviceId, b.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.VolumeId, b.VolumeId, StringComparison.OrdinalIgnoreCase);

    private static bool SameIdentity(DriveDashboardRow r, VolumeInfo v) =>
        string.Equals(r.DeviceId, v.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(r.VolumeId, v.VolumeId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(r.CatalogContainerUuid, v.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(r.CatalogVolumeId, v.CatalogVolumeId, StringComparison.OrdinalIgnoreCase) &&
        r.CatalogVolumeObjectId == v.CatalogVolumeObjectId;

    private static DriveDashboardRow BuildConnectedRow(StatusChangedPayload payload, DeviceInfo device, VolumeInfo v, bool unique)
    {
        var ordinary = CatalogMountPolicy.AllowsMount(v, false);
        var inspect = !ordinary && CatalogMountPolicy.AllowsReadOnlyInspection(v);
        var reason = v.IsEncrypted || v.CatalogDecision == ApfsCapabilityDecision.Locked ? "Locked; unlock support is required before mounting."
            : !v.SupportsExplorerMount ? "Explorer mounting is unsupported for this volume."
            : ordinary ? "Not mounted. Mount this volume using the current service policy."
            : inspect ? "Not mounted by default. Read-only inspection is available; writes remain blocked."
            : "Mounting is unavailable: the catalog does not prove this volume readable.";
        if (!unique) reason = "Ambiguous or inconsistent device/volume identity. Mounting is unavailable.";
        var display = new MountedVolumeDisplay(v.VolumeId, "", v.VolumeName, v.DeviceId, device.DisplayName,
            MountAccessMode.ReadOnly, CatalogVolumeId: v.CatalogVolumeId, CatalogContainerUuid: v.CatalogContainerUuid,
            CatalogVolumeObjectId: v.CatalogVolumeObjectId, CatalogSpace: v.CatalogSpace);
        var details = BuildDetails(payload with { State = RuntimeState.Idle }, display, DriveDashboardState.Idle)
            .Where(line => line.StartsWith("Device:") || line.StartsWith("Volume:") || line.StartsWith("Catalog ") ||
                line.Contains("space", StringComparison.OrdinalIgnoreCase) || line.StartsWith("Shared container") ||
                line.StartsWith("Volume ") || line.StartsWith("Reserved for") || line.StartsWith("Purgeable"))
            .Concat(new[] { $"Device identity: {v.DeviceId}", $"Routing identity: {v.VolumeId}",
                $"Catalog decision: {v.CatalogDecision?.ToString() ?? "Legacy / unspecified"}",
                $"Catalog reasons: {string.Join(", ", v.CatalogReasons ?? [])}", reason }).ToArray();
        return new(v.VolumeId, device.DisplayName, v.VolumeName, "", "", DriveDashboardState.Idle, DashboardPalette.Gray,
            v.IsEncrypted || v.CatalogDecision == ApfsCapabilityDecision.Locked ? "Locked" : ordinary || inspect ? "Not mounted" : "Unavailable",
            reason, false, false, unique && ordinary, details, [reason], v.CatalogVolumeId, v.CatalogContainerUuid,
            v.CatalogVolumeObjectId, v.DeviceId, IsMounted: false, CanInspectReadOnly: unique && inspect, RecoveryIdentity: v.RecoveryIdentity);
    }

    public static ControlOperationRequestPayload CreateMountRequest(StatusChangedPayload current, DriveDashboardRow selected)
    {
        var matches = BuildRows(current).Where(r => RowIdentity(r) == RowIdentity(selected)).ToArray();
        if (matches.Length != 1 || matches[0].IsMounted ||
            !(matches[0].CanFix || matches[0].CanInspectReadOnly) ||
            matches[0].CanInspectReadOnly != selected.CanInspectReadOnly || matches[0].CanFix != selected.CanFix ||
            matches[0].RecoveryIdentity != selected.RecoveryIdentity)
            throw new InvalidOperationException("Volume identity or capability changed. Refresh before mounting.");
        var row = matches[0];
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.Mount,
            new ApfsControlTarget(row.DeviceId!, row.VolumeId, row.RecoveryIdentity),
            row.CanInspectReadOnly ? ApfsControlModes.ReadOnly : ApfsControlModes.ReadWrite, DateTime.UtcNow.AddSeconds(90));
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        if (!validation.IsValid) throw new InvalidOperationException(validation.Diagnostic ?? "Invalid volume identity.");
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
            FixGuidance: ordinaryMount ? BuildFixGuidance(state, payload)
                : ["Catalog policy prevents writable repair for this volume. Read-only inspection does not enable writes."],
            CatalogVolumeId: volume.CatalogVolumeId,
            CatalogContainerUuid: volume.CatalogContainerUuid,
            CatalogVolumeObjectId: volume.CatalogVolumeObjectId,
            DeviceId: volume.DeviceId,
            DriveLetterPreference: volume.DriveLetterPreference);
    }

    private static StatusChangedPayload StatusForVolume(StatusChangedPayload aggregate, MountedVolumeDisplay volume)
    {
        // Older senders omit this marker and only supply aggregate health.
        if (!volume.HasRuntimeStatus) return aggregate;
        return aggregate with
        {
            State = volume.State,
            LastError = null,
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

    private static string FormatSpaceBytes(ulong bytes)
        => bytes.ToString("N0", System.Globalization.CultureInfo.CurrentCulture) + " bytes";

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
