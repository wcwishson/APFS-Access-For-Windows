using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static class DriveDashboardPresenter
{
    public static IReadOnlyList<DriveDashboardRow> BuildRows(StatusChangedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.MountedVolumes is not { Count: > 0 })
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
                    CanFix: idleState is DriveDashboardState.Attention or DriveDashboardState.Problem,
                    Details: BuildIdleDetails(payload),
                    FixGuidance: BuildFixGuidance(idleState, payload))
            ];
        }

        return payload.MountedVolumes
            .Where(static volume => !string.IsNullOrWhiteSpace(volume.VolumeId))
            .OrderBy(static volume => NormalizeDriveLabel(volume.MountPoint), StringComparer.OrdinalIgnoreCase)
            .Select(volume => BuildRow(payload, volume))
            .ToArray();
    }

    public static string BuildSummary(StatusChangedPayload payload)
    {
        var rows = BuildRows(payload);
        var mountedRows = rows.Where(static row => row.State != DriveDashboardState.Idle).ToArray();
        if (mountedRows.Length == 0)
        {
            return rows[0].Summary;
        }

        var countText = mountedRows.Length == 1 ? "1 APFS drive mounted" : $"{mountedRows.Length} APFS drives mounted";
        var worst = mountedRows.Select(static row => row.State).Max();
        return worst switch
        {
            DriveDashboardState.HealthyReadWrite => $"{countText}. All listed drives are healthy.",
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
        if (trimmed.Length >= 2 && trimmed[1] == ':')
        {
            return $"{char.ToUpperInvariant(trimmed[0])}:";
        }

        return trimmed.TrimEnd('\\');
    }

    private static DriveDashboardRow BuildRow(StatusChangedPayload payload, MountedVolumeDisplay volume)
    {
        var state = Classify(payload, volume);
        var palette = ToPalette(state);
        var mountPoint = NormalizeDriveLabel(volume.MountPoint);
        var details = BuildDetails(payload, volume, state);
        return new DriveDashboardRow(
            VolumeId: volume.VolumeId,
            DeviceName: FirstNonBlank(volume.DeviceDisplayName, volume.DeviceId, "APFS drive"),
            VolumeName: FirstNonBlank(volume.VolumeName, "APFS volume"),
            MountPoint: mountPoint,
            MountPath: NormalizeMountPath(volume.MountPoint),
            State: state,
            Palette: palette,
            StateText: ToStateText(state),
            Summary: BuildRowSummary(payload, volume, state),
            CanOpen: !string.IsNullOrWhiteSpace(mountPoint),
            CanEject: !string.IsNullOrWhiteSpace(volume.VolumeId) || !string.IsNullOrWhiteSpace(mountPoint),
            CanFix: state is DriveDashboardState.ReadOnly or DriveDashboardState.Attention or DriveDashboardState.Problem,
            Details: details,
            FixGuidance: BuildFixGuidance(state, payload));
    }

    private static DriveDashboardState Classify(StatusChangedPayload payload, MountedVolumeDisplay volume)
    {
        if (payload.State == RuntimeState.Error ||
            payload.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked ||
            payload.RecoveryActive)
        {
            return DriveDashboardState.Problem;
        }

        if (payload.DirtyTransactionCount > 0 ||
            payload.ShutdownDrainActive ||
            payload.InFlightMutationCallbacks > 0 ||
            HasWarnings(payload))
        {
            return DriveDashboardState.Attention;
        }

        if (volume.AccessMode == MountAccessMode.ReadOnly ||
            payload.State == RuntimeState.MountedRo ||
            !payload.WriteEnabled ||
            payload.NativeWriteSafetyState == NativeWriteSafetyState.ReadOnlyFallback)
        {
            return DriveDashboardState.ReadOnly;
        }

        if (volume.AccessMode == MountAccessMode.ReadWrite &&
            payload.State == RuntimeState.MountedRw &&
            payload.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite)
        {
            return DriveDashboardState.HealthyReadWrite;
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
            payload.InFlightMutationCallbacks > 0 ||
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
            DriveDashboardState.ReadOnly => DashboardPalette.Yellow,
            DriveDashboardState.Attention => DashboardPalette.Orange,
            DriveDashboardState.Problem => DashboardPalette.Red,
            _ => DashboardPalette.Gray,
        };

    private static string ToStateText(DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.HealthyReadWrite => "Healthy read/write",
            DriveDashboardState.ReadOnly => "Read-only",
            DriveDashboardState.Attention => "Needs attention",
            DriveDashboardState.Problem => "Problem",
            _ => "Idle",
        };

    private static string BuildRowSummary(StatusChangedPayload payload, MountedVolumeDisplay volume, DriveDashboardState state)
        => state switch
        {
            DriveDashboardState.HealthyReadWrite => "Full read/write access is available.",
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
            $"Last commit: {(payload.LastCommitXid.HasValue ? payload.LastCommitXid.Value.ToString() : "none")}",
            $"Warnings: {(warnings.Length == 0 ? "none" : string.Join(" | ", warnings))}",
            $"Diagnostics: {(diagnostics.Count == 0 ? "none" : string.Join(" | ", diagnostics.Select(static x => $"{x.Code}: {x.Message}")))}",
        };

        return details;
    }

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
        if (state == DriveDashboardState.HealthyReadWrite || state == DriveDashboardState.Idle)
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
