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

    public static PipeEnvelope Create<TPayload>(string type, TPayload payload, string? requestId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(type);

        JsonObject? node = null;
        if (payload is not null)
        {
            node = JsonSerializer.SerializeToNode(payload, SerializerOptions) as JsonObject;
        }

        return new PipeEnvelope(type, requestId, node);
    }

    public static string Serialize(PipeEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return JsonSerializer.Serialize(envelope, SerializerOptions);
    }

    public static bool TryDeserialize(string json, out PipeEnvelope? envelope)
    {
        envelope = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            envelope = JsonSerializer.Deserialize<PipeEnvelope>(json, SerializerOptions);
            return envelope is not null && !string.IsNullOrWhiteSpace(envelope.Type);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static bool TryGetPayload<TPayload>(PipeEnvelope envelope, out TPayload? payload)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        payload = default;
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
}
