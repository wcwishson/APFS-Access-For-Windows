using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Ipc;

public static class PipeMessageCodec
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

    public static bool TryDeserializeSyntaxOnly(string json, out PipeEnvelope? envelope)
    {
        envelope = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
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

        if (!TryGetString(payload, "command", out var command) ||
            !IsCanonicalCommand(command))
        {
            return Invalid(
                ApfsOperationCodes.UnknownCommand,
                "Control operation request command is missing, unknown, or not canonical.");
        }

        var hasTarget = TryGetProperty(payload, "target", out var targetNode);
        var targetValidation = ValidateCommandTarget(command!, targetNode, hasTarget);
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

        return Valid();
    }

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
            var targetValidation = ValidateCommandTarget(result.Command, targetNode, hasTarget);
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
            return result.Command == ApfsControlCommands.Eject &&
                   result.FinalStatus == "absent" &&
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
            expected = ApfsOperationFingerprint.Compute(
                result.Command,
                result.Target,
                result.RequestedMode,
                result.ExpiresAtUtc.Value);
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
        bool hasTarget)
    {
        if (command == ApfsControlCommands.Quit)
        {
            return hasTarget && targetNode is not null
                ? Invalid(ApfsOperationCodes.InvalidArguments, "The quit command must not include a target.")
                : Valid();
        }

        return ValidateTarget(targetNode, hasTarget);
    }

    private static PipeMessageValidationResult ValidateRequestedMode(string command, string? requestedMode)
    {
        if (command == ApfsControlCommands.Mount)
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

        var separatorIndex = volumeId.IndexOf('|');
        if (separatorIndex < 1 ||
            separatorIndex == volumeId.Length - 1 ||
            !string.Equals(volumeId[..separatorIndex], deviceId, StringComparison.OrdinalIgnoreCase))
        {
            return Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Target volumeId must begin with the exact deviceId followed by '|'.");
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
        => command is ApfsControlCommands.Mount or
            ApfsControlCommands.Fix or
            ApfsControlCommands.Eject or
            ApfsControlCommands.Quit;

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
           string.Equals(propertyName, "recoveryIdentity", StringComparison.OrdinalIgnoreCase);

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
