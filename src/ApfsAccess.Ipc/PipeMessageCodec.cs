using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

public static partial class PipeMessageCodec
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };

    public static PipeEnvelope Create<TPayload>(
        string type,
        TPayload payload,
        string? requestId = null,
        int schemaVersion = PipeSchemaVersions.Schema1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(type);

        JsonObject? node = null;
        if (payload is not null)
        {
            node = JsonSerializer.SerializeToNode(payload, SerializerOptions) as JsonObject;
        }

        return new PipeEnvelope(type, requestId, node, schemaVersion);
    }

    public static string Serialize(PipeEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return JsonSerializer.Serialize(envelope, SerializerOptions);
    }

    private static void RejectDuplicateJsonFields(string json)
    {
        using var document = JsonDocument.Parse(json);
        void Visit(JsonElement node)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in node.EnumerateObject())
                {
                    if (!names.Add(property.Name)) throw new JsonException("Duplicate message identity or evidence field.");
                    Visit(property.Value);
                }
            }
            else if (node.ValueKind == JsonValueKind.Array) foreach (var item in node.EnumerateArray()) Visit(item);
        }
        Visit(document.RootElement);
    }

    public static bool TryDeserializeSyntaxOnly(string json, out PipeEnvelope? envelope)
    {
        envelope = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            RejectDuplicateJsonFields(json);
            var parsed = JsonSerializer.Deserialize<PipeEnvelope>(json, SerializerOptions);
            if (parsed is null || string.IsNullOrWhiteSpace(parsed.Type))
            {
                return false;
            }

            envelope = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    public static bool TryDeserialize(string json, out PipeEnvelope? envelope)
        => TryDeserialize(json, out envelope, out _, out _);

    public static bool TryDeserialize(
        string json,
        out PipeEnvelope? envelope,
        out string code,
        out string? diagnostic)
    {
        envelope = null;
        code = ApfsOperationCodes.MalformedMessage;
        diagnostic = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            diagnostic = "The JSON message is blank.";
            return false;
        }

        try
        {
            RejectDuplicateJsonFields(json);
            var parsed = JsonSerializer.Deserialize<PipeEnvelope>(json, SerializerOptions);
            if (parsed is null || string.IsNullOrWhiteSpace(parsed.Type))
            {
                diagnostic = "The JSON message must contain a nonblank type.";
                return false;
            }

            var validation = Validate(parsed);
            code = validation.Code;
            diagnostic = validation.Diagnostic;
            if (!validation.IsValid)
            {
                return false;
            }

            envelope = parsed;
            return true;
        }
        catch (JsonException)
        {
            diagnostic = "The JSON message is malformed.";
            return false;
        }
        catch (NotSupportedException)
        {
            diagnostic = "The JSON message uses an unsupported shape.";
            return false;
        }
    }

    public static PipeMessageValidationResult Validate(PipeEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        if (string.IsNullOrWhiteSpace(envelope.Type))
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "The message type is blank.");
        }

        if (envelope.SchemaVersion is not PipeSchemaVersions.Schema1 and not PipeSchemaVersions.Schema2)
        {
            return Invalid(
                ApfsOperationCodes.UnsupportedSchema,
                $"Schema version '{envelope.SchemaVersion}' is not supported.");
        }

        if (envelope.Type == ApfsMessageTypes.StatusChanged)
        {
            var authorityValidation = ValidateRuntimeOwnerIncarnation(envelope);
            if (!authorityValidation.IsValid) return authorityValidation;
        }

        if (envelope.SchemaVersion == PipeSchemaVersions.Schema1)
        {
            return Valid();
        }

        if (!IsSchema2Type(envelope.Type))
        {
            return Invalid(
                ApfsOperationCodes.UnsupportedMessageType,
                $"Schema 2 does not define message type '{envelope.Type}'.");
        }

        if (IsLegacyMessageType(envelope.Type))
        {
            return Valid();
        }

        return envelope.Type switch
        {
            ApfsMessageTypes.ControlOperationRequest => ValidateControlOperationRequest(envelope),
            ApfsMessageTypes.OperationResultQuery => ValidateOperationIdRequest(envelope, "result query"),
            ApfsMessageTypes.CancellationRequest => ValidateOperationIdRequest(envelope, "cancellation request"),
            ApfsMessageTypes.OperationResult => ValidateOperationResult(envelope),
            _ => Valid(),
        };
    }

    private static PipeMessageValidationResult ValidateRuntimeOwnerIncarnation(PipeEnvelope envelope)
    {
        if (envelope.Payload is not {} payload ||
            !TryGetProperty(payload, "mountedVolumes", out var mounts) || mounts is not JsonArray volumes) return Valid();
        foreach (var node in volumes)
        {
            if (node is not JsonObject volume ||
                !TryGetProperty(volume, "hostProcessCreationTimeFileTimeUtc", out var creation)) continue;
            try
            {
                if (creation is null) throw new InvalidOperationException();
                var value = creation.GetValue<long>();
                if (value == 0) continue; // Legacy or unknown incarnation never enables raw actions.
                if (value < 0 || !TryGetProperty(volume, "hostProcessId", out var pid) || pid?.GetValue<int>() is not > 0)
                    throw new InvalidOperationException();
                _ = DateTime.FromFileTimeUtc(value);
            }
            catch (Exception ex) when (ex is InvalidOperationException or FormatException or OverflowException or ArgumentOutOfRangeException)
            {
                return Invalid(ApfsOperationCodes.MalformedMessage, "Mounted runtime owner incarnation is invalid.");
            }
        }
        return Valid();
    }

    public static bool TryValidate(
        PipeEnvelope envelope,
        out string code,
        out string? diagnostic)
    {
        var validation = Validate(envelope);
        code = validation.Code;
        diagnostic = validation.Diagnostic;
        return validation.IsValid;
    }

    public static bool TryGetPayload<TPayload>(PipeEnvelope envelope, out TPayload? payload)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        payload = default;
        if (!Validate(envelope).IsValid)
        {
            return false;
        }

        if (envelope.Payload is null)
        {
            return false;
        }

        try
        {
            payload = envelope.Payload.Deserialize<TPayload>(SerializerOptions);
            return payload is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static PipeMessageValidationResult ValidateControlOperationRequest(PipeEnvelope envelope)
    {
        if (!TryGetPayloadObject(envelope, out var payload))
        {
            return Invalid(
                ApfsOperationCodes.InvalidArguments,
                "Control operation request payload must be a JSON object.");
        }

        if (!TryGetString(payload, "operationId", out var operationId))
        {
            return Invalid(
                ApfsOperationCodes.InvalidOperationId,
                "Control operation request operationId is missing.");
        }

        var identityValidation = ValidateOperationIdentity(envelope, operationId, "control operation request");
        if (!identityValidation.IsValid)
        {
            return identityValidation;
        }

        if (payload.Any(p => !new[] { "operationId", "command", "target", "requestedMode", "expiresAtUtc", "snapshotName", "snapshotIdentity", "managementOperation", "managementToken", "managementName", "managementQuotaBytes", "managementReserveBytes", "managementImagePath", "volumeManagement", "approvedImageRepairPlanId", "keyManagement" }.Contains(p.Key, StringComparer.OrdinalIgnoreCase)))
            return Invalid(ApfsOperationCodes.InvalidArguments,"Unknown control request field.");

        if (!TryGetString(payload, "command", out var command) ||
            !IsCanonicalCommand(command))
        {
            return Invalid(
                ApfsOperationCodes.UnknownCommand,
                "Control operation request command is missing, unknown, or not canonical.");
        }

        var hasTarget = TryGetProperty(payload, "target", out var targetNode);
        var keyManagementValidation = ValidateKeyManagementRequest(command!, operationId!, payload);
        if (!keyManagementValidation.IsValid) return keyManagementValidation;
        VolumeManagementParameters? topology;
        try { topology = payload["volumeManagement"]?.Deserialize<VolumeManagementParameters>(SerializerOptions); }
        catch (JsonException) { return Invalid(ApfsOperationCodes.InvalidArguments, "Invalid volume management parameters."); }
        if (!VolumeManagementParameters.Valid(command!, topology))
            return Invalid(ApfsOperationCodes.InvalidArguments, "Invalid volume management parameters.");
        var targetValidation = ValidateCommandTarget(command!, targetNode, hasTarget, topology);
        if (!targetValidation.IsValid)
        {
            return targetValidation;
        }

        if (!TryGetOptionalString(payload, "requestedMode", out var requestedMode))
        {
            return Invalid(
                ApfsOperationCodes.InvalidArguments,
                "Control operation request requestedMode must be null or a string.");
        }

        var modeValidation = ValidateRequestedMode(command!, requestedMode);
        if (!modeValidation.IsValid)
        {
            return modeValidation;
        }

        if (!TryGetOptionalString(payload, "approvedImageRepairPlanId", out var repairId) ||
            repairId is not null && (command != ApfsControlCommands.Fix || !ImageRepairPersistence.Hex(repairId) ||
                requestedMode == ApfsControlModes.ReadOnly || targetNode is not JsonObject repairTarget ||
                !TryGetString(repairTarget, "deviceId", out var image) || !ImageRepairPersistence.LocalPath(image)))
            return Invalid(ApfsOperationCodes.InvalidArguments, "Only ordinary image Fix accepts an exact opaque repair plan ID.");

        if (!TryGetString(payload, "expiresAtUtc", out var expiresAtUtc) ||
            !DateTimeOffset.TryParse(
                expiresAtUtc,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var parsedExpiry) ||
            parsedExpiry.Offset != TimeSpan.Zero)
        {
            return Invalid(
                ApfsOperationCodes.InvalidArguments,
                "Control operation request expiresAtUtc is required and must be an absolute UTC timestamp.");
        }

        var snapshotValidation = ValidateSnapshotParameters(command!, payload);
        if (!snapshotValidation.IsValid)
        {
            return snapshotValidation;
        }

        return ValidateManagementParameters(command!, payload);
    }

    private static PipeMessageValidationResult ValidateSnapshotParameters(string command, JsonObject payload)
    {
        var isCreate = command == ApfsControlCommands.SnapshotCreate;
        var isDelete = command == ApfsControlCommands.SnapshotDelete;
        var isRecover = command == ApfsControlCommands.SnapshotRecover;
        if (!TryGetOptionalString(payload, "snapshotName", out var snapshotName))
        {
            return Invalid(
                ApfsOperationCodes.InvalidArguments,
                "Control operation request snapshotName must be null or a string.");
        }

        var hasIdentity = TryGetProperty(payload, "snapshotIdentity", out var identityNode) && identityNode is not null;
        if (isCreate)
        {
            if (!IsSnapshotName(snapshotName) || hasIdentity)
            {
                return Invalid(
                    ApfsOperationCodes.InvalidArguments,
                    "Snapshot create requires exactly one valid name and no identity.");
            }

            return Valid();
        }

        if (isDelete)
        {
            if (snapshotName is not null || !IsSnapshotIdentity(identityNode))
            {
                return Invalid(
                    ApfsOperationCodes.InvalidArguments,
                    "Snapshot delete requires the nine-line exact identity and no separate name.");
            }

            return Valid();
        }

        if (isRecover)
        {
            return snapshotName is null && !hasIdentity
                ? Valid()
                : Invalid(
                    ApfsOperationCodes.InvalidArguments,
                    "Snapshot recover carries no snapshot parameters.");
        }

        return snapshotName is null && !hasIdentity
            ? Valid()
            : Invalid(
                ApfsOperationCodes.InvalidArguments,
                $"The {command} command must not include snapshot parameters.");
    }

    private static bool IsSnapshotName(string? value)
        => value is not null && value.Length is > 0 and <= 255 &&
            value.All(static ch => ch != '\0' && ch != '\r' && ch != '\n');

    // Management parameters ride the envelope as plain strings. The codec
    // enforces presence/shape per command; membership and canonical values
    // belong to service admission and the executor, mirroring snapshots.
    private static PipeMessageValidationResult ValidateManagementParameters(string command, JsonObject payload)
    {
        var isPlan = command == ApfsControlCommands.ManagementPlan;
        var isApply = command == ApfsControlCommands.ManagementApply;
        if (!TryGetOptionalString(payload, "managementOperation", out var operation) ||
            !TryGetOptionalString(payload, "managementToken", out var token) ||
            !TryGetOptionalString(payload, "managementName", out _) ||
            !TryGetOptionalString(payload, "managementQuotaBytes", out _) ||
            !TryGetOptionalString(payload, "managementReserveBytes", out _) ||
            !TryGetOptionalString(payload, "managementImagePath", out var imagePath))
        {
            return Invalid(
                ApfsOperationCodes.InvalidArguments,
                "Control operation request management parameters must be null or strings.");
        }

        if (isPlan)
        {
            return !string.IsNullOrWhiteSpace(operation) && token is null &&
                !HasManagementValue(payload, "managementName") &&
                !HasManagementValue(payload, "managementQuotaBytes") &&
                !HasManagementValue(payload, "managementReserveBytes") &&
                !HasManagementValue(payload, "managementImagePath")
                ? Valid()
                : Invalid(
                    ApfsOperationCodes.InvalidArguments,
                    "Management plan requires exactly one operation and no token, path, or mutation values.");
        }

        if (isApply)
        {
            return !string.IsNullOrWhiteSpace(operation) && !string.IsNullOrWhiteSpace(token) &&
                !string.IsNullOrWhiteSpace(imagePath)
                ? Valid()
                : Invalid(
                    ApfsOperationCodes.InvalidArguments,
                    "Management apply requires an operation, a confirmation token, and an image path.");
        }

        return operation is null && token is null &&
            !HasManagementValue(payload, "managementName") &&
            !HasManagementValue(payload, "managementQuotaBytes") &&
            !HasManagementValue(payload, "managementReserveBytes") &&
            !HasManagementValue(payload, "managementImagePath")
            ? Valid()
            : Invalid(
                ApfsOperationCodes.InvalidArguments,
                $"The {command} command must not include management parameters.");
    }

    private static bool HasManagementValue(JsonObject payload, string name)
        => TryGetProperty(payload, name, out var node) && node is not null;

    private static bool IsSnapshotIdentity(JsonNode? node)
    {
        if (node is not System.Text.Json.Nodes.JsonArray identity || identity.Count != 9)
        {
            return false;
        }

        var fields = new string?[9];
        for (var index = 0; index < 9; index++)
        {
            try
            {
                fields[index] = identity[index]?.GetValue<string>();
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        if (!IsSnapshotName(fields[1]))
        {
            return false;
        }

        foreach (var index in new[] { 0, 2, 3, 4, 5, 6, 7, 8 })
        {
            if (!IsCanonicalNonzeroDecimal(fields[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsCanonicalNonzeroDecimal(string? value)
        => value is not null &&
            ulong.TryParse(value, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
            parsed != 0 &&
            parsed.ToString(System.Globalization.CultureInfo.InvariantCulture) == value;

    private static PipeMessageValidationResult ValidateOperationIdRequest(
        PipeEnvelope envelope,
        string requestKind)
    {
        if (!TryGetPayloadObject(envelope, out var payload) ||
            !TryGetString(payload, "operationId", out var operationId))
        {
            return Invalid(
                ApfsOperationCodes.InvalidOperationId,
                $"Schema 2 {requestKind} operationId is missing.");
        }

        return ValidateOperationIdentity(envelope, operationId, requestKind);
    }

    private static PipeMessageValidationResult ValidateOperationResult(PipeEnvelope envelope)
    {
        if (!TryGetPayloadObject(envelope, out var payload))
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result payload must be a JSON object.");
        }

        OperationResultPayload? result;
        try
        {
            result = payload.Deserialize<OperationResultPayload>(SerializerOptions);
        }
        catch (JsonException)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result payload has invalid field types.");
        }
        catch (NotSupportedException)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result payload uses an unsupported shape.");
        }

        if (result is null)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result payload is empty.");
        }

        var identityValidation = ValidateOperationIdentity(envelope, result.OperationId, "operation result");
        if (!identityValidation.IsValid)
        {
            return identityValidation;
        }

        var isPreAdmissionFailure = result.State == ApfsOperationStates.Failed &&
                                    IsPreAdmissionFailureCode(result.Code);
        var isContextlessResult = string.Equals(
            result.Command,
            ApfsControlCommands.Unknown,
            StringComparison.Ordinal);
        if (!IsCanonicalCommand(result.Command) && !isContextlessResult)
        {
            return Invalid(ApfsOperationCodes.UnknownCommand, "Operation result command is unknown or not canonical.");
        }

        if (isContextlessResult)
        {
            if (result.Success || result.Target is not null || result.RequestedMode is not null)
            {
                return Invalid(
                    ApfsOperationCodes.MalformedMessage,
                    "Contextless operation results must be unsuccessful and must not include a target or requestedMode.");
            }
        }
        else if (!isPreAdmissionFailure)
        {
            var hasTarget = TryGetProperty(payload, "target", out var targetNode);
            if (!VolumeManagementParameters.Valid(result.Command, result.VolumeManagement))
                return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid volume management request echoes.");
            var targetValidation = ValidateCommandTarget(result.Command, targetNode, hasTarget, result.VolumeManagement);
            if (!targetValidation.IsValid)
            {
                return targetValidation;
            }

            var requestedModeValidation = ValidateRequestedMode(result.Command, result.RequestedMode);
            if (!requestedModeValidation.IsValid)
            {
                return requestedModeValidation;
            }
        }

        if (result.EffectiveMode is not null && !IsCanonicalMode(result.EffectiveMode))
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result effectiveMode is unknown or not canonical.");
        }

        if (result.DirtyTransactionCount < 0)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result dirtyTransactionCount cannot be negative.");
        }

        if (!IsCanonicalState(result.State) || !IsKnownCode(result.Code))
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result state or code is unknown or not canonical.");
        }

        if (result.RequestedAtUtc == default)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result requestedAtUtc is required.");
        }

        if (!result.ExpiresAtUtc.HasValue)
        {
            if (!isContextlessResult)
            {
                return Invalid(
                    ApfsOperationCodes.MalformedMessage,
                    "Contextual operation result expiresAtUtc is required.");
            }
        }
        else if (result.ExpiresAtUtc.Value.Kind != DateTimeKind.Utc)
        {
            return Invalid(
                ApfsOperationCodes.MalformedMessage,
                "Operation result expiresAtUtc must be an absolute UTC timestamp.");
        }

        var fingerprintValidation = ValidateOperationFingerprint(
            result,
            isContextlessResult,
            isPreAdmissionFailure);
        if (!fingerprintValidation.IsValid)
        {
            return fingerprintValidation;
        }

        if (result.StartedAtUtc.HasValue && result.StartedAtUtc.Value < result.RequestedAtUtc)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result startedAtUtc precedes requestedAtUtc.");
        }

        if (result.CompletedAtUtc.HasValue && result.CompletedAtUtc.Value < result.RequestedAtUtc)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result completedAtUtc precedes requestedAtUtc.");
        }

        if (result.StartedAtUtc.HasValue &&
            result.CompletedAtUtc.HasValue &&
            result.CompletedAtUtc.Value < result.StartedAtUtc.Value)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Operation result completedAtUtc precedes startedAtUtc.");
        }

        if (result.VolumeVerificationReport is not null)
        {
            if (result.State is not (ApfsOperationStates.Succeeded or ApfsOperationStates.Failed))
                return Invalid(ApfsOperationCodes.MalformedMessage, "A pending operation cannot carry verification proof.");
            var verification = ValidateVerificationProof(result);
            if (!verification.IsValid) return verification;
        }
        var imageRepair = ValidateImageRepairProof(result, payload);
        if (!imageRepair.IsValid) return imageRepair;
        var keyManagement = ValidateKeyManagementResult(result);
        if (!keyManagement.IsValid) return keyManagement;
        return result.State switch
        {
            ApfsOperationStates.Accepted => ValidateAcceptedResult(result),
            ApfsOperationStates.InProgress => ValidateInProgressResult(result),
            ApfsOperationStates.Succeeded => ValidateSucceededResult(result),
            ApfsOperationStates.Failed => ValidateFailedResult(result),
            ApfsOperationStates.Cancelled => ValidateCancelledResult(result),
            _ => Invalid(ApfsOperationCodes.MalformedMessage, "Operation result state is unknown."),
        };
    }

    private static PipeMessageValidationResult ValidateImageRepairProof(OperationResultPayload result, JsonObject payload)
    {
        if (result.ApprovedImageRepairPlanId is not null && (result.Command != ApfsControlCommands.Fix ||
            !ImageRepairPersistence.Hex(result.ApprovedImageRepairPlanId)))
            return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid image repair approval echo.");
        if (result.ImageRepairOffer is null && result.ImageRepairReceipt is null)
            return result.ApprovedImageRepairPlanId is not null && result.Success
                ? Invalid(ApfsOperationCodes.MalformedMessage, "Approved image repair success requires its original native receipt.") : Valid();
        if (result.Command != ApfsControlCommands.Fix || result.Target is null ||
            result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
            return Invalid(ApfsOperationCodes.MalformedMessage, "Repair proof belongs only to terminal ordinary image Fix.");
        static bool ScopeClosed(JsonNode? offer) => offer is JsonObject obj && obj["scope"] is JsonObject scope &&
            scope.Count == 7 && scope.All(p => new[] { "imagePath", "containerId", "volumeUuid", "volumeObjectId", "checkpointXid", "storeOffsetBytes", "storeSizeBytes" }.Contains(p.Key, StringComparer.Ordinal));
        var offer = result.ImageRepairOffer;
        if (offer is not null && (!ImageRepairPersistence.ValidOffer(offer) || !ScopeClosed(payload["imageRepairOffer"]) ||
            result.Success || result.State != ApfsOperationStates.Failed || result.ApprovedImageRepairPlanId is not null || result.ImageRepairReceipt is not null ||
            result.FinalStatus != "repair-confirmation-required" || result.Code != ApfsOperationCodes.BlockedRecovery ||
            offer.ExpiresAtUtc <= result.RequestedAtUtc || offer.ExpiresAtUtc > result.RequestedAtUtc.AddMinutes(5)))
            return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid image repair offer.");
        var receipt = result.ImageRepairReceipt;
        if (receipt is not null && (!ImageRepairPersistence.ValidReceipt(receipt) ||
            !ScopeClosed(payload["imageRepairReceipt"]?["binding"]) ||
            receipt.PlanId != result.ApprovedImageRepairPlanId && !(result.ApprovedImageRepairPlanId is null &&
                receipt.OriginalAcceptedOperationId is not null && receipt.State is "recovery-required" or "repaired" or "refused") ||
            receipt.State is "applying" or "recovery-required" && !result.PendingDurability ||
            result.Success && (receipt.State != "repaired" || !receipt.NativePostVerifyComplete)))
            return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid image repair receipt or terminal claim.");
        var binding = offer ?? receipt!.Binding;
        var target = result.Target;
        if (!string.Equals(target.DeviceId, binding.Scope.ImagePath, StringComparison.OrdinalIgnoreCase) ||
            target.VolumeId != ImageRepairPersistence.VolumeId(binding.Scope) ||
            target.VolumeUuid is not null && !TopologyAdmission.SameUuid(target.VolumeUuid, binding.Scope.VolumeUuid) ||
            target.ContainerUuid is not null && !TopologyAdmission.SameUuid(target.ContainerUuid, binding.Scope.ContainerId[15..]) ||
            target.VolumeObjectId is not null && target.VolumeObjectId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) != binding.Scope.VolumeObjectId ||
            target.RecoveryIdentity is not null && target.RecoveryIdentity != binding.RecoveryIdentity ||
            target.ObservationContract is not null && target.ObservationContract != binding.ObservationContract)
            return Invalid(ApfsOperationCodes.MalformedMessage, "Repair proof differs from the selected request target.");
        return Valid();
    }

    private static PipeMessageValidationResult ValidateAcceptedResult(OperationResultPayload result)
        => result.Code != ApfsOperationCodes.OperationInProgress ||
           result.Success ||
           result.StartedAtUtc is not null ||
           result.CompletedAtUtc is not null ||
           !HasConservativePendingProof(result)
            ? Invalid(ApfsOperationCodes.MalformedMessage, "Accepted operation result fields are inconsistent.")
            : Valid();

    private static PipeMessageValidationResult ValidateInProgressResult(OperationResultPayload result)
        => result.Code != ApfsOperationCodes.OperationInProgress ||
           result.Success ||
           result.StartedAtUtc is null ||
           result.CompletedAtUtc is not null ||
           !HasConservativePendingProof(result)
            ? Invalid(ApfsOperationCodes.MalformedMessage, "In-progress operation result fields are inconsistent.")
            : Valid();

    private static PipeMessageValidationResult ValidateSucceededResult(OperationResultPayload result)
    {
        if (!result.Success || result.StartedAtUtc is null || result.CompletedAtUtc is null)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Succeeded operation result flags or timestamps are inconsistent.");
        }

        if (result.Code == ApfsOperationCodes.AlreadyAchieved)
        {
            if (result.Command == ApfsControlCommands.Lock)
                return result.Target?.RegisteredImage is { Writable: true } image && image.IsValid() &&
                       result.FinalStatus == "already-locked" && result.EncryptionState == EncryptedVolumeState.Locked &&
                       result.MountProof == "absent" && result.OwnershipProof == "proven" &&
                       result.DurabilityProof == "not-applicable" && !result.PendingDurability && !result.RecoveryActive &&
                       result.RequestedMode is null && result.EffectiveMode is null
                    ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage, "Already-locked image result lacks exact retirement observation.");
            // Container unmount mirrors per-volume eject: nothing mounted is a
            // stable success, with absence proven and ownership/durability
            // honestly not-proven (nothing was released by this operation).
            // Device eject shares the same already-achieved shape.
            return (result.Command == ApfsControlCommands.Eject &&
                   result.FinalStatus == "absent" ||
                   result.Command == ApfsControlCommands.ContainerUnmount &&
                   result.FinalStatus == "container-unmounted" ||
                   result.Command == ApfsControlCommands.DeviceEject &&
                   result.FinalStatus == "device-ejected") &&
                   result.MountProof == "absent" &&
                   result.OwnershipProof == "not-proven" &&
                   result.DurabilityProof == "not-proven" &&
                   !result.PendingDurability
                ? Valid()
                : Invalid(ApfsOperationCodes.MalformedMessage, "Already-achieved eject result lacks consistent absence proof.");
        }

        if (result.Code != ApfsOperationCodes.OperationSucceeded)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Succeeded operation result uses a non-success code.");
        }

        return ValidateCommandSuccessProof(result);
    }

    private static PipeMessageValidationResult ValidateFailedResult(OperationResultPayload result)
    {
        if (result.Success ||
            result.StartedAtUtc is null ||
            result.CompletedAtUtc is null ||
            !IsFailureCode(result.Code))
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Failed operation result fields are inconsistent.");
        }

        return result.Code == ApfsOperationCodes.Timeout && !HasConservativePendingProof(result)
            ? Invalid(ApfsOperationCodes.MalformedMessage, "Timeout operation result lacks conservative pending proof.")
            : Valid();
    }

    private static PipeMessageValidationResult ValidateCancelledResult(OperationResultPayload result)
        => result.Success ||
           result.StartedAtUtc is null ||
           result.CompletedAtUtc is null ||
           result.Code != ApfsOperationCodes.OperationCancelled
            ? Invalid(ApfsOperationCodes.MalformedMessage, "Cancelled operation result fields are inconsistent.")
            : Valid();

    private static PipeMessageValidationResult ValidateOperationFingerprint(
        OperationResultPayload result,
        bool isContextlessResult,
        bool isPreAdmissionFailure)
    {
        if (isContextlessResult)
        {
            return result.Fingerprint is null
                ? Valid()
                : Invalid(
                    ApfsOperationCodes.MalformedMessage,
                    "Contextless operation results must not include a fingerprint.");
        }

        if (isPreAdmissionFailure && result.Fingerprint is null)
        {
            return Valid();
        }

        if (string.IsNullOrWhiteSpace(result.Fingerprint) || !result.ExpiresAtUtc.HasValue)
        {
            return Invalid(
                ApfsOperationCodes.MalformedMessage,
                "Contextual operation result fingerprint is required.");
        }

        string expected;
        try
        {
            // Results echo the operation, plan token, and mutation values
            // (mirroring the snapshot name/identity echo); ComputeForResult
            // reproduces the request fingerprint from those echoes.
            expected = ApfsOperationFingerprint.ComputeForResult(result);
        }
        catch (ArgumentException exception)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, exception.Message);
        }

        return string.Equals(result.Fingerprint, expected, StringComparison.Ordinal)
            ? Valid()
            : Invalid(
                ApfsOperationCodes.MalformedMessage,
                "Operation result fingerprint does not match its command, target, requestedMode, and expiry.");
    }

    private static bool HasConservativePendingProof(OperationResultPayload result)
        => result.PendingDurability &&
           string.Equals(result.FinalStatus, "not-proven", StringComparison.Ordinal) &&
           string.Equals(result.MountProof, "not-proven", StringComparison.Ordinal) &&
           string.Equals(result.OwnershipProof, "not-proven", StringComparison.Ordinal) &&
           string.Equals(result.DurabilityProof, "not-proven", StringComparison.Ordinal);

    private static PipeMessageValidationResult ValidateCommandSuccessProof(OperationResultPayload result)
    {
        if (string.IsNullOrWhiteSpace(result.FinalStatus) || result.PendingDurability)
        {
            return Invalid(ApfsOperationCodes.MalformedMessage, "Successful operation result lacks final status or durability clearance.");
        }

        return result.Command switch
        {
            ApfsControlCommands.ImageKeyManagement => ValidateKeyManagementSuccess(result),
            ApfsControlCommands.RegisterFusion => result.FinalStatus == "registered" && result.Target?.RegisteredFusion is {} fusion && fusion.IsValid()
                ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage, "Invalid Fusion registration result."),
            ApfsControlCommands.RegisterImage => result.FinalStatus == "locked" && result.EncryptionState == EncryptedVolumeState.Locked
                ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage,"Invalid registered image result."),
            ApfsControlCommands.Unlock => result.Target?.RegisteredImage is {} image && image.IsValid() &&
                result.FinalStatus == (image.Writable ? "unlocked-read-write" : "unlocked-read-only") &&
                result.EncryptionState == EncryptedVolumeState.Unlocked &&
                result.EffectiveMode == (image.Writable ? ApfsControlModes.ReadWrite : ApfsControlModes.ReadOnly) && result.MountProof == "present"
                ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage,"Unlock lacks the exact selected access-mode mount proof."),
            ApfsControlCommands.Lock => result.FinalStatus == "locked" && result.EncryptionState == EncryptedVolumeState.Locked &&
                result.MountProof == "absent" && result.OwnershipProof == "proven" && result.DurabilityProof == "proven"
                ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage,"Lock lacks original host and mount absence proof."),
            ApfsControlCommands.Mount =>
                result.RequestedMode == result.EffectiveMode &&
                result.MountProof == "present" &&
                result.OwnershipProof == "not-applicable" &&
                result.DurabilityProof == "not-applicable"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful mount result lacks matching mode or mount proof."),
            ApfsControlCommands.Fix =>
                result.EffectiveMode == ApfsControlModes.ReadWrite &&
                result.FinalStatus == "healthy-rw" &&
                !result.RecoveryActive &&
                result.DirtyTransactionCount == 0 &&
                result.MountProof == "present" &&
                result.OwnershipProof == "not-applicable" &&
                result.DurabilityProof == "not-applicable"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful fix result lacks healthy read-write proof."),
            ApfsControlCommands.Eject =>
                result.FinalStatus == "absent" &&
                result.MountProof == "absent" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful eject result lacks absence, ownership, or durability proof."),
            ApfsControlCommands.Quit =>
                result.FinalStatus == "shutdown-complete" &&
                result.MountProof == "no-mounts" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven" &&
                result.QuitMarkerWritten &&
                !result.RecoveryActive &&
                result.DirtyTransactionCount == 0
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful quit result lacks shutdown, ownership, durability, or marker proof."),
            ApfsControlCommands.SnapshotCreate =>
                result.FinalStatus == "snapshot-created" &&
                result.MountProof == "present" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "not-applicable"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful snapshot-create result lacks creation, mount, or ownership proof."),
            ApfsControlCommands.SnapshotDelete =>
                result.FinalStatus == "snapshot-deleted" &&
                result.MountProof == "present" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "not-applicable"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful snapshot-delete result lacks deletion, mount, or ownership proof."),
            ApfsControlCommands.SnapshotRecover =>
                (result.FinalStatus == "snapshot-recovered" || result.FinalStatus == "snapshot-recover-noop") &&
                result.MountProof == "present" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "not-applicable"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful snapshot-recover result lacks recovery, mount, or ownership proof."),
            ApfsControlCommands.SnapshotList =>
                ValidateSnapshotInventorySuccess(result),
            ApfsControlCommands.VolumeCreatePlan or ApfsControlCommands.VolumeDeletePlan or ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan =>
                ValidateVolumeManagementSuccess(result, "prepared", "volume-management-prepared", "not-applicable"),
            ApfsControlCommands.VolumeManagementApply =>
                ValidateVolumeManagementSuccess(result, "committed", "volume-management-committed", "proven"),
            ApfsControlCommands.VolumeManagementCancel =>
                ValidateVolumeManagementSuccess(result, "cancelled", "volume-management-cancelled", "not-applicable"),
            ApfsControlCommands.VolumeManagementRecover =>
                result.VolumeManagementReport is { ValueKind: JsonValueKind.Object } nativeReport &&
                    nativeReport.TryGetProperty("outcome", out var nativeOutcome) && nativeOutcome.ValueKind == JsonValueKind.String && nativeOutcome.GetString() == "committed"
                    ? ValidateVolumeManagementSuccess(result, "committed", "volume-management-committed", "proven")
                    : ValidateVolumeManagementSuccess(result, "cancelled", "volume-management-cancelled", "not-applicable"),
            ApfsControlCommands.VolumeVerify =>
                result.FinalStatus == "verified-covered-scope" && result.MountProof is "absent" or "present" &&
                result.OwnershipProof == "proven" && result.DurabilityProof == "not-applicable"
                    ? ValidateVerificationProof(result) : Invalid(ApfsOperationCodes.MalformedMessage, "Verification lacks covered-scope or ownership proof."),
            // A dry-run plan binds identity and generation without mounting
            // or mutating: the target must be provably absent, the identity
            // proven from the live row, and the issued plan echoes present.
            ApfsControlCommands.ManagementPlan =>
                result.FinalStatus == "management-plan-issued" &&
                result.MountProof == "absent" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "not-applicable" &&
                !string.IsNullOrWhiteSpace(result.ManagementOperation) &&
                !string.IsNullOrWhiteSpace(result.ManagementPlanId) &&
                !string.IsNullOrWhiteSpace(result.ManagementToken) &&
                IsCanonicalNonzeroDecimal(result.ManagementObservedXid)
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful management-plan result lacks issuance, quiesce, identity, or plan echoes."),
            // A committed apply proves the keeper executed exactly once: the
            // target stayed absent, the identity stayed proven, the journal
            // reached a durable commit, and every request echo round-trips
            // (the observed generation is the post-commit checkpoint, which
            // must advance past the plan generation).
            ApfsControlCommands.ManagementApply =>
                result.FinalStatus == "management-applied" &&
                result.MountProof == "absent" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven" &&
                !string.IsNullOrWhiteSpace(result.ManagementOperation) &&
                !string.IsNullOrWhiteSpace(result.ManagementToken) &&
                !string.IsNullOrWhiteSpace(result.ManagementImagePath) &&
                IsCanonicalNonzeroDecimal(result.ManagementObservedXid)
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful management-apply result lacks commit, quiesce, identity, or apply echoes."),
            // Container-wide results aggregate per-volume terminal evidence in
            // the diagnostic (`vol:<volumeId>=mounted|absent|skipped|failed`
            // tokens); the scalar proofs below describe the container as a
            // whole and are only valid when every attempted member is proven.
            ApfsControlCommands.ContainerMount =>
                result.FinalStatus == "container-mounted" &&
                result.RequestedMode == result.EffectiveMode &&
                result.MountProof == "present" &&
                result.OwnershipProof == "not-applicable" &&
                result.DurabilityProof == "not-applicable"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful container-mount result lacks uniform mode or all-members-present proof."),
            ApfsControlCommands.ContainerUnmount =>
                result.FinalStatus == "container-unmounted" &&
                result.MountProof == "absent" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful container-unmount result lacks absence, ownership, or durability proof."),
            ApfsControlCommands.DeviceEject =>
                result.FinalStatus == "device-ejected" &&
                result.MountProof == "absent" &&
                result.OwnershipProof == "proven" &&
                result.DurabilityProof == "proven"
                    ? Valid()
                    : Invalid(ApfsOperationCodes.MalformedMessage, "Successful device-eject result lacks absence, ownership, or durability proof."),
            _ => Invalid(ApfsOperationCodes.UnknownCommand, "Operation result command is unknown."),
        };
    }

    private static bool IsPreAdmissionFailureCode(string code)
        => code is ApfsOperationCodes.InvalidArguments
            or ApfsOperationCodes.MalformedMessage
            or ApfsOperationCodes.UnsupportedSchema
            or ApfsOperationCodes.UnsupportedMessageType
            or ApfsOperationCodes.InvalidOperationId
            or ApfsOperationCodes.UnknownCommand
            or ApfsOperationCodes.AmbiguousTarget;

    private static PipeMessageValidationResult ValidateOperationIdentity(
        PipeEnvelope envelope,
        string? operationId,
        string messageKind)
    {
        if (string.IsNullOrWhiteSpace(envelope.RequestId))
        {
            return Invalid(
                ApfsOperationCodes.InvalidArguments,
                $"Schema 2 {messageKind} requestId is missing.");
        }

        if (!IsCanonicalOperationId(operationId) || !IsCanonicalOperationId(envelope.RequestId))
        {
            return Invalid(
                ApfsOperationCodes.InvalidOperationId,
                $"Schema 2 {messageKind} operationId and requestId must be lowercase canonical GUIDs in D format.");
        }

        return string.Equals(envelope.RequestId, operationId, StringComparison.Ordinal)
            ? Valid()
            : Invalid(
                ApfsOperationCodes.InvalidOperationId,
                $"Schema 2 {messageKind} requestId must equal payload operationId.");
    }

    private static PipeMessageValidationResult ValidateCommandTarget(
        string command,
        JsonNode? targetNode,
        bool hasTarget,
        VolumeManagementParameters? topology = null)
    {
        if (command == ApfsControlCommands.ImageKeyManagement)
            return targetNode is null ? Valid() : Invalid(ApfsOperationCodes.InvalidArguments, "Key management uses its exact typed image endpoint.");
        if (command == ApfsControlCommands.Quit)
        {
            return hasTarget && targetNode is not null
                ? Invalid(ApfsOperationCodes.InvalidArguments, "The quit command must not include a target.")
                : Valid();
        }

        if (command is ApfsControlCommands.ContainerMount or ApfsControlCommands.ContainerUnmount ||
            VolumeManagementParameters.IsCommand(command) && topology?.Kind == "create")
        {
            return ValidateContainerTarget(targetNode, hasTarget);
        }

        if (command == ApfsControlCommands.DeviceEject)
        {
            return ValidateDeviceTarget(targetNode, hasTarget);
        }

        return ValidateTarget(targetNode, hasTarget);
    }

    private static PipeMessageValidationResult ValidateVerificationProof(OperationResultPayload result)
    {
        if (result.MountProof == "absent" && result.VolumeVerificationReport is null) return Valid();
        if (result.MountProof != "present" || result.VolumeVerificationReport is not {} json ||
            result.Command != ApfsControlCommands.VolumeVerify || result.Target is not {} target ||
            result.PendingDurability || result.OwnershipProof != "proven" || result.DurabilityProof != "not-applicable")
            return Invalid(ApfsOperationCodes.MalformedMessage, "Live verification lacks the retained-source report.");
        try
        {
            var report = LiveVolumeVerificationReport.Parse(json);
            return result.Success == report.Complete && TopologyAdmission.SameUuid(report.Scope.ContainerUuid, target.ContainerUuid) &&
                TopologyAdmission.SameUuid(report.Scope.VolumeUuid, target.VolumeUuid) &&
                report.Scope.VolumeOid == target.VolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture)
                ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage, "Live verification verdict or identity conflicts with its report.");
        }
        catch (InvalidDataException) { return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid live verification report."); }
    }

    private static PipeMessageValidationResult ValidateSnapshotInventorySuccess(OperationResultPayload result)
    {
        if (result.FinalStatus != "snapshot-inventory" || result.OwnershipProof != "proven" ||
            result.DurabilityProof != "not-applicable" || result.SnapshotInventory is not { ValueKind: JsonValueKind.Object } inventory)
            return Invalid(ApfsOperationCodes.MalformedMessage, "Snapshot inventory lacks ownership or inventory evidence.");
        if (result.MountProof == "absent")
            return inventory.TryGetProperty("format", out var format) && format.ValueKind == JsonValueKind.String &&
                format.GetString() == "apfs-access-snapshot-inventory" ? Valid() :
                Invalid(ApfsOperationCodes.MalformedMessage, "Offline inventory has the wrong format.");
        try
        {
            var live = ApfsAccess.Core.LiveSnapshotInventory.Parse(inventory);
            return result.MountProof == "present" && result.Target is {} target &&
                ApfsAccess.Core.TopologyAdmission.SameUuid(live.ContainerUuid, target.ContainerUuid) &&
                ApfsAccess.Core.TopologyAdmission.SameUuid(live.VolumeUuid, target.VolumeUuid) &&
                live.VolumeOid == target.VolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture)
                ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage, "Live inventory has a different target scope.");
        }
        catch (InvalidDataException)
        { return Invalid(ApfsOperationCodes.MalformedMessage, "Live inventory is malformed."); }
    }

    private static PipeMessageValidationResult ValidateVolumeManagementSuccess(OperationResultPayload r,
        string outcome, string status, string durability)
    {
        if (r.FinalStatus != status || r.MountProof != "absent" || r.OwnershipProof != "proven" ||
            r.DurabilityProof != durability || r.VolumeManagementReport is not { ValueKind: JsonValueKind.Object } report)
            return Invalid(ApfsOperationCodes.MalformedMessage, "Volume management lacks native terminal proof.");
        try
        {
            var imageKind = r.VolumeManagement is {} options && VolumeManagementParameters.IsImageKind(options.Kind);
            if (report.GetProperty("schemaVersion").GetInt32() != 1 || report.GetProperty("operation").GetString() != (imageKind ? r.VolumeManagement!.Kind : "volume-" + r.VolumeManagement?.Kind) ||
                report.GetProperty("outcome").GetString() != outcome || report.GetProperty("sourceIdentity").GetString() is not { Length: 80 } identity || !identity.All(char.IsAsciiHexDigitLower) ||
                !VolumeTopologyProfile.Uuid(report.GetProperty("containerUuid").GetString()) ||
                !TopologyAdmission.SameUuid(report.GetProperty("containerUuid").GetString(), r.Target?.ContainerUuid) ||
                !VolumeTopologyProfile.Uuid(report.GetProperty("volumeUuid").GetString()) ||
                !IsCanonicalNonzeroDecimal(report.GetProperty("volumeOid").GetString()) ||
                !(outcome == "cancelled" ? VolumeTopologyProfile.Number(report.GetProperty("preXid").GetString()) : IsCanonicalNonzeroDecimal(report.GetProperty("preXid").GetString())))
                return Invalid(ApfsOperationCodes.MalformedMessage, "Volume management native evidence is incomplete.");
            if ((r.VolumeManagement?.Kind == "delete" || imageKind) && (!TopologyAdmission.SameUuid(report.GetProperty("volumeUuid").GetString(), r.Target?.VolumeUuid) ||
                report.GetProperty("volumeOid").GetString() != r.Target?.VolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture)))
                return Invalid(ApfsOperationCodes.MalformedMessage, "Volume deletion native evidence targets another volume.");
            if (imageKind && (!IsCanonicalNonzeroDecimal(report.GetProperty("expectedBytes").GetString()) ||
                !IsCanonicalNonzeroDecimal(report.GetProperty("targetBytes").GetString()) ||
                (r.VolumeManagement!.Kind is "grow" or "shrink" && report.GetProperty("targetBytes").GetString() != r.VolumeManagement.TargetBytes) ||
                (r.VolumeManagement.Kind is "format" or "erase" &&
                 (!VolumeTopologyProfile.Uuid(report.GetProperty("newContainerUuid").GetString()) ||
                  !VolumeTopologyProfile.Uuid(report.GetProperty("newVolumeUuid").GetString()) || report.GetProperty("newVolumeOid").GetString() != "1024"))))
                return Invalid(ApfsOperationCodes.MalformedMessage, "Image management capacity or destination proof is missing.");
            if (outcome == "committed" && (!IsCanonicalNonzeroDecimal(report.GetProperty("postXid").GetString()) ||
                ulong.Parse(report.GetProperty("postXid").GetString()!) <= ulong.Parse(report.GetProperty("preXid").GetString()!)))
                return Invalid(ApfsOperationCodes.MalformedMessage, "Volume management commit did not advance the checkpoint.");
            if (outcome == "prepared" && report.GetProperty("confirmationToken").GetString() is not { Length: 64 })
                return Invalid(ApfsOperationCodes.MalformedMessage, "Volume management plan has no native token.");
            return Valid();
        }
        catch (Exception e) when (e is InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid native volume management evidence."); }
    }

    private static PipeMessageValidationResult ValidateRequestedMode(string command, string? requestedMode)
    {
        if (command is ApfsControlCommands.Mount or ApfsControlCommands.ContainerMount)
        {
            return IsCanonicalMode(requestedMode)
                ? Valid()
                : Invalid(ApfsOperationCodes.InvalidArguments, "Mount requires requestedMode read-only or read-write.");
        }

        return requestedMode is null
            ? Valid()
            : Invalid(ApfsOperationCodes.InvalidArguments, $"The {command} command must not include requestedMode.");
    }

    private static PipeMessageValidationResult ValidateTarget(JsonNode? targetNode, bool hasTarget)
    {
        if (!hasTarget || targetNode is not JsonObject target)
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Mount, fix, and eject require an exact deviceId and volumeId target.");
        }

        if (target.Select(p => p.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != target.Count)
            return Invalid(ApfsOperationCodes.AmbiguousTarget, "Duplicate target identity fields are ambiguous.");
        foreach (var property in target)
        {
            if (!IsTargetProperty(property.Key))
            {
                return Invalid(
                    ApfsOperationCodes.AmbiguousTarget,
                    $"Target property '{property.Key}' is not part of the stable target identity.");
            }
        }

        if (!TryGetString(target, "deviceId", out var deviceId) ||
            string.IsNullOrWhiteSpace(deviceId) ||
            !TryGetString(target, "volumeId", out var volumeId) ||
            string.IsNullOrWhiteSpace(volumeId))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Target must contain nonblank deviceId and volumeId values.");
        }

        var canonicalVolumeId = ApfsTopology.TryParseVolumeId(volumeId, out _, out _);
        var separatorIndex = volumeId.IndexOf('|');
        var legacyVolumeIdMatchesDevice = separatorIndex > 0 &&
            separatorIndex < volumeId.Length - 1 &&
            string.Equals(volumeId[..separatorIndex], deviceId, StringComparison.OrdinalIgnoreCase);
        if (!canonicalVolumeId && !legacyVolumeIdMatchesDevice)
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Target volumeId must be a canonical APFS volume ID or begin with the exact deviceId followed by '|'.");
        }

        if (TryGetProperty(target, "recoveryIdentity", out var recoveryIdentityNode) &&
            recoveryIdentityNode is not null &&
            (!TryGetString(target, "recoveryIdentity", out var recoveryIdentity) ||
             string.IsNullOrWhiteSpace(recoveryIdentity)))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Target recoveryIdentity must be null or a nonblank string.");
        }

        try
        {
            var typed = target.Deserialize<ApfsControlTarget>(new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (typed is null || !SelectedControlTarget.IsWellFormed(typed))
                return Invalid(ApfsOperationCodes.AmbiguousTarget, "Selected identity requires UUID, container, object, recovery and observation contract together.");
        }
        catch (JsonException) { return Invalid(ApfsOperationCodes.AmbiguousTarget, "Malformed selected identity."); }
        return Valid();
    }

    // Container-wide commands address a whole APFS container, never one
    // volume: deviceId plus containerUuid are required, and a volumeId is
    // refused so a container request can never be mistaken for (or routed
    // as) a single-volume request. Membership is resolved against live
    // inventory downstream; the envelope only enforces shape here.
    private static PipeMessageValidationResult ValidateContainerTarget(JsonNode? targetNode, bool hasTarget)
    {
        if (!hasTarget || targetNode is not JsonObject target)
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Container mount and unmount require an exact deviceId and containerUuid target.");
        }

        if (target.Select(p => p.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != target.Count)
            return Invalid(ApfsOperationCodes.AmbiguousTarget, "Duplicate target identity fields are ambiguous.");
        foreach (var property in target)
        {
            if (!IsTargetProperty(property.Key))
            {
                return Invalid(
                    ApfsOperationCodes.AmbiguousTarget,
                    $"Target property '{property.Key}' is not part of the stable target identity.");
            }
        }

        if (!TryGetString(target, "deviceId", out var deviceId) ||
            string.IsNullOrWhiteSpace(deviceId) ||
            !TryGetString(target, "containerUuid", out var containerUuid) ||
            string.IsNullOrWhiteSpace(containerUuid))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Container target must contain nonblank deviceId and containerUuid values.");
        }

        if (TryGetString(target, "volumeId", out var volumeId) && !string.IsNullOrWhiteSpace(volumeId))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Container target must not contain a volumeId; address one volume with mount/unmount/eject instead.");
        }

        return Valid();
    }

    // Device-wide eject addresses a whole physical device: deviceId only, no
    // container or volume identity. Membership (every container on the
    // device) is resolved against live inventory downstream.
    private static PipeMessageValidationResult ValidateDeviceTarget(JsonNode? targetNode, bool hasTarget)
    {
        if (!hasTarget || targetNode is not JsonObject target)
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Device eject requires an exact deviceId target.");
        }

        if (target.Select(p => p.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != target.Count)
            return Invalid(ApfsOperationCodes.AmbiguousTarget, "Duplicate target identity fields are ambiguous.");
        foreach (var property in target)
        {
            if (!IsTargetProperty(property.Key))
            {
                return Invalid(
                    ApfsOperationCodes.AmbiguousTarget,
                    $"Target property '{property.Key}' is not part of the stable target identity.");
            }
        }

        if (!TryGetString(target, "deviceId", out var deviceId) ||
            string.IsNullOrWhiteSpace(deviceId))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Device target must contain a nonblank deviceId value.");
        }

        if ((TryGetString(target, "volumeId", out var volumeId) && !string.IsNullOrWhiteSpace(volumeId)) ||
            (TryGetString(target, "containerUuid", out var containerUuid) && !string.IsNullOrWhiteSpace(containerUuid)))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Device target must not contain a volumeId or containerUuid; address narrower scopes with their own commands.");
        }

        return Valid();
    }

    private static bool TryGetPayloadObject(PipeEnvelope envelope, out JsonObject payload)
    {
        payload = null!;
        if (envelope.Payload is null)
        {
            return false;
        }

        payload = envelope.Payload;
        return true;
    }

    private static bool TryGetString(JsonObject json, string propertyName, out string? value)
    {
        value = null;
        if (!TryGetProperty(json, propertyName, out var node) || node is null)
        {
            return false;
        }

        try
        {
            value = node.GetValue<string>();
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryGetOptionalString(JsonObject json, string propertyName, out string? value)
    {
        value = null;
        if (!TryGetProperty(json, propertyName, out var node) || node is null)
        {
            return true;
        }

        try
        {
            value = node.GetValue<string>();
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryGetProperty(JsonObject json, string propertyName, out JsonNode? value)
    {
        foreach (var property in json)
        {
            if (string.Equals(property.Key, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = null;
        return false;
    }

    private static bool IsCanonicalOperationId(string? operationId)
        => operationId is not null &&
           Guid.TryParseExact(operationId, "D", out var parsed) &&
           string.Equals(operationId, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool IsCanonicalCommand(string? command)
        => command is ApfsControlCommands.ImageKeyManagement or ApfsControlCommands.RegisterFusion or ApfsControlCommands.RegisterImage or ApfsControlCommands.Unlock or ApfsControlCommands.Lock or ApfsControlCommands.Mount or
            ApfsControlCommands.ContainerMount or
            ApfsControlCommands.ContainerUnmount or
            ApfsControlCommands.DeviceEject or
            ApfsControlCommands.Fix or
            ApfsControlCommands.Eject or
            ApfsControlCommands.Quit or
            ApfsControlCommands.SnapshotCreate or
            ApfsControlCommands.SnapshotDelete or
            ApfsControlCommands.SnapshotRecover or
            ApfsControlCommands.SnapshotList or
            ApfsControlCommands.VolumeCreatePlan or ApfsControlCommands.VolumeDeletePlan or ApfsControlCommands.VolumeResizePlan or ApfsControlCommands.VolumeFormatPlan or
            ApfsControlCommands.VolumeManagementApply or ApfsControlCommands.VolumeManagementCancel or ApfsControlCommands.VolumeManagementRecover or
            ApfsControlCommands.ManagementPlan or
            ApfsControlCommands.ManagementApply or ApfsControlCommands.VolumeVerify;

    private static bool IsCanonicalMode(string? mode)
        => mode is ApfsControlModes.ReadOnly or ApfsControlModes.ReadWrite;

    private static bool IsCanonicalState(string? state)
        => state is ApfsOperationStates.Accepted or
            ApfsOperationStates.InProgress or
            ApfsOperationStates.Succeeded or
            ApfsOperationStates.Failed or
            ApfsOperationStates.Cancelled;

    private static bool IsKnownCode(string? code)
        => code is ApfsOperationCodes.OperationSucceeded or
            ApfsOperationCodes.AlreadyAchieved or
            ApfsOperationCodes.InvalidArguments or
            ApfsOperationCodes.MissingVolume or
            ApfsOperationCodes.Timeout or
            ApfsOperationCodes.BlockedRecovery or
            ApfsOperationCodes.UnsafeOwnership or
            ApfsOperationCodes.OperationFailed or
            ApfsOperationCodes.MalformedMessage or
            ApfsOperationCodes.UnsupportedSchema or
            ApfsOperationCodes.UnsupportedMessageType or
            ApfsOperationCodes.InvalidOperationId or
            ApfsOperationCodes.UnknownCommand or
            ApfsOperationCodes.AmbiguousTarget or
            ApfsOperationCodes.ElevationFailed or
            ApfsOperationCodes.OperationConflict or
            ApfsOperationCodes.OperationInProgress or
            ApfsOperationCodes.OperationCancelled or
            ApfsOperationCodes.NotCancellable or
            ApfsOperationCodes.ServiceUnavailable;

    private static bool IsFailureCode(string? code)
        => IsKnownCode(code) &&
           code is not ApfsOperationCodes.OperationSucceeded and
           not ApfsOperationCodes.AlreadyAchieved and
           not ApfsOperationCodes.OperationInProgress and
           not ApfsOperationCodes.OperationCancelled;

    private static bool IsTargetProperty(string propertyName)
        => string.Equals(propertyName, "deviceId", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(propertyName, "volumeId", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(propertyName, "recoveryIdentity", StringComparison.OrdinalIgnoreCase) ||
             new[] { "volumeUuid", "containerUuid", "volumeObjectId", "observationContract", "registeredImage", "registeredFusion" }.Contains(propertyName, StringComparer.OrdinalIgnoreCase);

    private static bool IsSchema2Type(string type)
        => IsLegacyMessageType(type) ||
           string.Equals(type, ApfsMessageTypes.ControlOperationRequest, StringComparison.Ordinal) ||
           string.Equals(type, ApfsMessageTypes.OperationResultQuery, StringComparison.Ordinal) ||
           string.Equals(type, ApfsMessageTypes.CancellationRequest, StringComparison.Ordinal) ||
           string.Equals(type, ApfsMessageTypes.OperationResult, StringComparison.Ordinal);

    private static bool IsLegacyMessageType(string type)
        => type is ApfsMessageTypes.StatusChanged or
            ApfsMessageTypes.QuitRequested or
            ApfsMessageTypes.ServiceStopping or
            ApfsMessageTypes.EjectRequested or
            ApfsMessageTypes.RefreshRequested or
            ApfsMessageTypes.DriveLetterPreferenceRequested or
            ApfsMessageTypes.InventoryRequested or
            ApfsMessageTypes.MountRequested or
            ApfsMessageTypes.FixRequested or
            ApfsMessageTypes.Inventory or
            ApfsMessageTypes.Ack or
            ApfsMessageTypes.Ping or
            ApfsMessageTypes.Pong;

    private static PipeMessageValidationResult Valid()
        => new(true, ApfsOperationCodes.OperationSucceeded, null);

    private static PipeMessageValidationResult Invalid(string code, string diagnostic)
        => new(false, code, diagnostic);
}
