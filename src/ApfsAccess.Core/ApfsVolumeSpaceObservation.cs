namespace ApfsAccess.Core;

// One catalog scan, retained with its checkpoint identity. Runtime availability
// is reported by FsHost; this observation must never authorize allocation.
public sealed record ApfsVolumeSpaceObservation(
    string ContainerId,
    ulong CheckpointXid,
    ApfsSpaceAmount ContainerTotal,
    ApfsSpaceAmount ContainerFree,
    ApfsVolumeSpaceProjection Volume);
