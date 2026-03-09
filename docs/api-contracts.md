# API Contracts

## Core interfaces

### `IApfsBackend`

- `ProbeDevicesAsync(CancellationToken)`
- `ProbeVolumesAsync(string deviceId, CancellationToken)`
- `MountAsync(MountRequest, CancellationToken)`
- `UnmountAsync(string mountPoint, CancellationToken)`
- `GetMountStateAsync(CancellationToken)`

### `IMountPolicy`

- `SelectDriveLetter(VolumeInfo, IReadOnlySet<char>)`
- `ShouldAutoMount(VolumeInfo)`

## Core models

### `VolumeInfo`

- `VolumeId`
- `DeviceId`
- `VolumeName`
- `SupportsReadWrite`
- `IsEncrypted`
- `SupportsExplorerMount`
- `NativeVolumePath`
- `SupportsNativeWrite`
- `WriteBlockReason`
- `WriteIncompatibilities`
- `WriteUnsupportedFeatures`
- `NativeWriteReadiness` (`Unavailable|BootstrapReady|MutationReady|CommitReady|RecoveryMode|Degraded`)

### `MountResult`

- `Success`
- `MountPoint`
- `Error`
- `EffectiveAccessMode`
- `DiagnosticCode`
- `IsReadOnly`
- `WriteEnabled`
- `SafetyGateState`
- `WriteBackend` (`Disabled|Overlay|Native`)
- `CommitModel` (`ScaffoldCheckpoint|CanonicalApfsCheckpoint`)
- `NativeWriteReadiness`
- `NativeWriteEngineState` (`Scaffold|Transactional|HardwareValidated|Stable`)
- `NativeWriteValidationState` (`Scaffold|CanonicalImageValidated|HardwarePilotValidated|CrossOsValidated|Stable`)
- `NativeWriteSafetyState` (`ReadOnlyFallback|PilotReadWrite|StableReadWrite|RecoveryBlocked`)
- `WriteIncompatibilities`
- `WriteUnsupportedFeatures`
- `LastRecoveryAction`
- `DirtyTransactionCount`
- `ShutdownDrainActive`
- `InFlightMutationCallbacks`
- `NativeWriteValidationEvidence`
- `NativeWriteDiagnostics[]`

### `NativeWriteDiagnostic`

- `Code`
- `Message`
- `IsFailClosed`
- `Scope`
- `RecoveryReason`
- `RecoveryAction`
- `ValidationState`
- `RequiredValidationState`
- `ValidationEvidence`
- `CommitStage`
- `ReplayStage`
- `CommitBlobMagic`
- `CanonicalPathActive`
- `DeviceProfileId`
- `ValidationScenario`
- `EvidenceSnapshotId`

### `MountedVolumeState`

- `VolumeId`
- `MountPoint`
- `AccessMode`
- `WriteBackend` (`Disabled|Overlay|Native`)
- `CommitModel` (`ScaffoldCheckpoint|CanonicalApfsCheckpoint`)
- `NativeWriteReadiness`
- `NativeWriteEngineState` (`Scaffold|Transactional|HardwareValidated|Stable`)
- `NativeWriteValidationState` (`Scaffold|CanonicalImageValidated|HardwarePilotValidated|CrossOsValidated|Stable`)
- `RecoveryActive`
- `RecoveryReason`
- `LastCommitXid`
- `NativeWriteSafetyState`
- `WriteIncompatibilities`
- `WriteUnsupportedFeatures`
- `LastRecoveryAction`
- `DirtyTransactionCount`
- `ShutdownDrainActive`
- `InFlightMutationCallbacks`
- `NativeWriteValidationEvidence`
- `NativeWriteDiagnostics[]`

### `ServiceHostOptions` additions

- `NativeFsHostPath`
- `WinFspMode`
- `MountLetterPool`
- `EnableNativeWrite`
- `WriteRolloutChannel`
- `WriteSafetyLevel`
- `WriteBackendMode`
- `AllowWriteOnUnsupportedFeatures`
- `WriteCommitTimeoutSeconds`
- `NativeWriteStrictMode`
- `NativeWriteMaxDirtyTransactions`
- `NativeWriteRecoveryPolicy` (`FailClosed` default)
- `NativeWriteAllowRawPhysicalDevices` (default `false`)
- `NativeWritePilotVolumeAllowList` (default empty)
- `NativeWriteIntegrityCheckOnMount` (default `true`)
- `NativeWriteCrashReplayMode` (`FailClosed|ReplayIfSafe`)
- `NativeWritePromotionPolicy` (`ScaffoldOnly|PilotHardware|Stable`)
- `NativeWriteRequireCanonicalCommit` (default `true`)
- `NativeWriteAllowLegacyScaffoldForFixtures` (default `true`)
- `NativeWriteDisallowScaffoldCommitOnNonFixture` / `NativeWriteRejectScaffoldReplayBlobOnNonFixture` / `NativeWriteRequireCanonicalReplayCandidateOnNonFixture`:
  effective behavior is fail-closed strict for non-fixture media; configurable relaxations are fixture-only.
- `NativeWriteHardwarePilotDeviceAllowList` (default empty)
- `NativeWriteCrossOsValidationRequired` (default `true`)
- `NativeWriteCrashFaultMatrixRequired` (default `true`)
- `NativeWriteRequireMacOsValidationForStable` (default `true`)
- `NativeWriteMinCrashFaultPasses` (default `1`)
- `NativeWriteMinCrashStageMatrixPasses` (default `1`)
- `NativeWriteMinHardwarePilotPasses` (default `3`)
- `NativeWriteMinHotUnplugPasses` (default `1`)
- `NativeWriteMinMacOsValidationPasses` (default `2`)
- `NativeWriteMinMacOsConsistencyPasses` (default `2`)
- `NativeWriteMinPowerLossReplayPasses` (default `1`)
- `NativeWriteStableRequiresPowerLossPass` (default `true`)
- `NativeWriteEvidenceSeedCrashFaultPasses` (default `0`)
- `NativeWriteEvidenceSeedCrashStageMatrixPasses` (default `0`)
- `NativeWriteEvidenceSeedHardwarePilotPasses` (default `0`)
- `NativeWriteEvidenceSeedHotUnplugPasses` (default `0`)
- `NativeWriteEvidenceSeedMacOsValidationPasses` (default `0`)
- `NativeWriteEvidenceSeedMacOsConsistencyPasses` (default `0`)
- `NativeWriteEvidenceSeedPowerLossReplayPasses` (default `0`)
- `NativeWriteEvidenceSeedPowerLossPassVerified` (default `false`)
- `NativeWriteEvidenceSeedLastValidatedUtc` (default `null`)
- `NativeWriteEvidenceSeedLastValidationProfileId` (default `null`)
- `NativeWriteEvidenceStorePath` (default `%ProgramData%\\ApfsAccess\\write-evidence.json`)
- Raw physical-device counter promotion above `CanonicalImageValidated` requires explicit validation-evidence signal payloads (or persisted evidence store records); runtime validation-state alone does not advance pilot/stable counters.
- Runtime validation-evidence payloads are profile-bound: mismatched `lastValidationProfileId` payloads are ignored for promotion/evidence accrual.
- In the current repo state, raw physical-device native write remains pilot-only; promotion to `PilotHardware` / `Stable` depends on external evidence imported into `NativeWriteEvidenceStorePath` and checked with `scripts/evaluate_write_promotion.ps1`.
- `SkipEncryptedVolumes`
- `NativeAutoRemountOnReconnect`
- `NativeHostStartupTimeoutSeconds`
- `NativeHostStopTimeoutSeconds`

## IPC envelope

```json
{
  "type": "StatusChanged|QuitRequested|Ack|Ping|Pong",
  "requestId": "optional-string",
  "payload": {}
}
```

## `StatusChangedPayload`

```json
{
  "state": "Starting|Idle|MountedRw|MountedRo|Error|Stopping",
  "mountPoints": ["X:\\"],
  "lastError": null,
  "timestampUtc": "2026-02-10T09:00:00Z",
  "warnings": ["Encrypted volume skipped: ..."],
  "writeEnabled": false,
  "compatibilityWarnings": ["Write blocked for 'Main' (gate=VolumeCapability): ..."],
  "writeBackend": "Disabled|Overlay|Native",
  "commitModel": "ScaffoldCheckpoint|CanonicalApfsCheckpoint",
  "nativeWriteReadiness": "Unavailable|BootstrapReady|MutationReady|CommitReady|RecoveryMode|Degraded",
  "nativeWriteEngineState": "Scaffold|Transactional|HardwareValidated|Stable",
  "nativeWriteValidationState": "Scaffold|CanonicalImageValidated|HardwarePilotValidated|CrossOsValidated|Stable",
  "recoveryActive": false,
  "recoveryReason": null,
  "lastCommitXid": 0,
  "nativeWriteSafetyState": "ReadOnlyFallback|PilotReadWrite|StableReadWrite|RecoveryBlocked",
  "writeIncompatibilities": [],
  "writeUnsupportedFeatures": [],
  "lastRecoveryAction": null,
  "dirtyTransactionCount": 0,
  "shutdownDrainActive": false,
  "inFlightMutationCallbacks": 0,
  "nativeWriteValidationEvidence": {
    "crashFaultPasses": 0,
    "crashStageMatrixPasses": 0,
    "hardwarePilotPasses": 0,
    "hotUnplugPasses": 0,
    "macOsValidationPasses": 0,
    "macOsConsistencyPasses": 0,
    "powerLossReplayPasses": 0,
    "powerLossPassVerified": false,
    "lastValidatedUtc": null,
    "lastValidationProfileId": null
  },
  "nativeWriteDiagnostics": [
    {
      "code": "NativeWriteValidationCrashFaultEvidenceInsufficient",
      "message": "native write crash-fault evidence does not meet the configured promotion threshold",
      "isFailClosed": true,
      "scope": "Runtime:ValidationGate",
      "recoveryReason": "ValidationCrashFaultEvidenceInsufficient",
      "recoveryAction": "DowngradedAfterValidationCrashFaultGate",
      "validationState": "CanonicalImageValidated",
      "requiredValidationState": "HardwarePilotValidated",
      "validationScenario": "CrashFault",
      "evidenceSnapshotId": "snapshot-20260224-010203",
      "validationEvidence": {
        "crashFaultPasses": 1,
        "crashStageMatrixPasses": 0,
        "hardwarePilotPasses": 0,
        "hotUnplugPasses": 0,
        "macOsValidationPasses": 0,
        "macOsConsistencyPasses": 0,
        "powerLossReplayPasses": 0,
        "powerLossPassVerified": false,
        "lastValidatedUtc": "2026-02-24T00:00:00Z",
        "lastValidationProfileId": "raw::physicaldrive3::main"
      }
    }
  ]
}
```
