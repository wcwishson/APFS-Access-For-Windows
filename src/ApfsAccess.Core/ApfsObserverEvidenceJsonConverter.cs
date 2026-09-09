using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace ApfsAccess.Core;

// The envelope determines omission, including when there are no volumes or
// containers. A private derived wire record reuses all inherited properties;
// System.Text.Json does not inherit a base type's converter attribute.
public sealed class ApfsObserverEvidenceJsonConverter : JsonConverter<ApfsObserverEvidence>
{
    private sealed record WireEvidence : ApfsObserverEvidence
    {
        public WireEvidence() : base(null!, 0, null!, null!, null!, null!, false, null!, null!) { }
        public WireEvidence(ApfsObserverEvidence value) : base(value) { }
    }

    public override ApfsObserverEvidence? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => JsonSerializer.Deserialize<WireEvidence>(ref reader, options)?.CopyEvidenceRecord();

    public override void Write(Utf8JsonWriter writer, ApfsObserverEvidence value, JsonSerializerOptions options)
    {
        var extended = value.TopologyMetadataVersion.HasValue;
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info =>
        {
            foreach (var property in info.Properties)
            {
                var extension = info.Type == typeof(WireEvidence) && property.Name == "topologyMetadataVersion" ||
                    info.Type == typeof(ApfsContainerRecord) && property.Name == "sharedSpace" ||
                    info.Type == typeof(ApfsVolumeRecord) && property.Name is
                        "roleName" or "groupUuid" or "groupMetadataValid" or "groupAssociationStatus" ||
                    info.Type == typeof(ApfsGroupRecord) && property.Name is
                        "containerId" or "associationStatus" or "systemVolumeId" or "dataVolumeId";
                if (extension) property.ShouldSerialize = (_, _) => extended;
            }
        });
        var wireOptions = new JsonSerializerOptions(options)
        {
            TypeInfoResolver = resolver,
            // Required nulls and known zeros are part of the evidence contract.
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        };
        JsonSerializer.Serialize(writer, new WireEvidence(value), wireOptions);
    }
}
