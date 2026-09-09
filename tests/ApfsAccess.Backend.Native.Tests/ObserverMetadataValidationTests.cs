using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ObserverMetadataValidationTests
{
    internal const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    internal const string Group = "dddddddddddddddddddddddddddddddd";

    internal static JsonObject Payload(bool pair = false)
    {
        var root = JsonNode.Parse(ObserverEvidenceJson.BuildSingleContainer(Container,
            pair ? [new("System", 101, Role: 1, Roles: ["system"]), new("Data", 102, Role: 64)]
                 : [new("Data", 101, Role: 0)]))!.AsObject();
        root["topologyMetadataVersion"] = 1;
        var topology = root["topology"]!;
        topology["containers"]![0]!["sharedSpace"] = null;
        var volumes = topology["volumes"]!.AsArray();
        for (var i = 0; i < volumes.Count; i++)
        {
            var v = volumes[i]!;
            v["uuid"] = new string((char)('b' + i), 32);
            v["roleName"] = pair ? (i == 0 ? "system" : "data") : "none";
            v["groupUuid"] = pair ? Group : null;
            v["groupMetadataValid"] = true;
            v["groupAssociationStatus"] = pair ? "valid-system-data" : "none";
            if (pair)
            {
                v["groupId"] = "apfs-group:" + Group;
                v["compatibleFeatureBits"] = new JsonArray("0x10");
            }
        }
        if (pair) topology["groups"]!.AsArray().Add(new JsonObject
        {
            ["id"] = "apfs-group:" + Group, ["uuid"] = Group,
            ["containerId"] = "apfs-container:" + Container,
            ["volumeIds"] = new JsonArray($"apfs-vol:{Container}:101", $"apfs-vol:{Container}:102"),
            ["associationStatus"] = "valid-system-data",
            ["systemVolumeId"] = $"apfs-vol:{Container}:101", ["dataVolumeId"] = $"apfs-vol:{Container}:102",
        });
        return root;
    }

    [Fact]
    public void CompleteExtensionAccepted() => Parse(Payload(true));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ZeroRoleMustBeExplicitlyPresent(bool extended)
    {
        var root = Payload();
        if (!extended) StripExtension(root);
        Assert.Equal(0, Parse(root).Topology.Volumes[0].RoleRaw);
        root["topology"]!["volumes"]![0]!.AsObject().Remove("roleRaw");
        Assert.Contains("missing required roleRaw", Assert.Throws<InvalidOperationException>(() => Parse(root)).Message);
    }

    [Theory]
    [InlineData(false, "pair")][InlineData(true, "pair")]
    [InlineData(false, "singleton")][InlineData(true, "singleton")]
    [InlineData(false, "zero-volumes")][InlineData(true, "zero-volumes")]
    [InlineData(false, "zero-containers")][InlineData(true, "zero-containers")]
    public void EvidenceRoundTripPreservesVersionedOmission(bool extended, string shape)
    {
        var root = Payload(shape == "pair");
        var t = root["topology"]!;
        if (shape is "zero-volumes" or "zero-containers")
        {
            t["volumes"] = new JsonArray();
            t["containers"]![0]!["volumeIds"] = new JsonArray();
        }
        if (shape == "zero-containers")
        {
            t["containers"] = new JsonArray();
            t["stores"] = new JsonArray();
        }
        foreach (var store in t["stores"]!.AsArray())
        {
            store!.AsObject().Remove("blockSizeBytes");
            store.AsObject().Remove("totalBlocks");
        }
        if (!extended) StripExtension(root);
        var serialized = RoundTrip(root, empty: shape is "zero-volumes" or "zero-containers");
        Assert.Equal(extended, serialized.ContainsKey("topologyMetadataVersion"));
        foreach (var store in serialized["topology"]!["stores"]!.AsArray())
        {
            Assert.False(store!.AsObject().ContainsKey("blockSizeBytes"));
            Assert.False(store.AsObject().ContainsKey("totalBlocks"));
        }
        foreach (var c in serialized["topology"]!["containers"]!.AsArray())
        {
            Assert.Equal(extended, c!.AsObject().ContainsKey("sharedSpace"));
            Assert.Null(c["sharedSpace"]);
        }
        foreach (var v in serialized["topology"]!["volumes"]!.AsArray())
            foreach (var field in new[] { "roleName", "groupUuid", "groupMetadataValid", "groupAssociationStatus" })
                Assert.Equal(extended, v!.AsObject().ContainsKey(field));
        foreach (var g in serialized["topology"]!["groups"]!.AsArray())
            foreach (var field in new[] { "containerId", "associationStatus", "systemVolumeId", "dataVolumeId" })
                Assert.Equal(extended, g!.AsObject().ContainsKey(field));
    }

    [Fact]
    public void RoundTripPreservesRequiredNullsAndExactZeros()
    {
        var root = ObserverSharedSpaceValidationTests.Payload();
        var space = root["topology"]!["containers"]![0]!["sharedSpace"]!;
        space["free"] = new JsonObject { ["blocks"] = "0", ["bytes"] = "0" };
        space["used"] = space["total"]!.DeepClone();
        foreach (var v in space["volumes"]!.AsArray())
        {
            foreach (var field in new[] { "allocated", "siblingReserveRemaining", "available" })
                v![field] = new JsonObject { ["blocks"] = "0", ["bytes"] = "0" };
            v!["reserve"] = null; v["quota"] = null;
        }
        var round = RoundTrip(root)["topology"]!["containers"]![0]!["sharedSpace"]!;
        foreach (var v in round["volumes"]!.AsArray())
        {
            foreach (var field in new[] { "reserve", "quota", "snapshot", "purgeable" })
            {
                Assert.True(v!.AsObject().ContainsKey(field)); Assert.Null(v[field]);
            }
            foreach (var field in new[] { "allocated", "siblingReserveRemaining", "available" })
            {
                Assert.Equal("0", v![field]!["blocks"]!.GetValue<string>());
                Assert.Equal("0", v[field]!["bytes"]!.GetValue<string>());
            }
        }
    }

    [Theory]
    [InlineData(false, "blockSizeBytes")][InlineData(true, "blockSizeBytes")]
    [InlineData(false, "totalBlocks")][InlineData(true, "totalBlocks")]
    public void OptionalGeometryFieldsAreIndependentlyOmitted(bool extended, string absent)
    {
        var root = Payload();
        var store = root["topology"]!["stores"]![0]!.AsObject();
        store["blockSizeBytes"] = 4096; store["totalBlocks"] = 2048;
        store.Remove(absent);
        if (!extended) StripExtension(root);
        var round = RoundTrip(root)["topology"]!["stores"]![0]!.AsObject();
        Assert.False(round.ContainsKey(absent));
        var present = absent == "totalBlocks" ? "blockSizeBytes" : "totalBlocks";
        Assert.True(JsonNode.DeepEquals(store[present], round[present]));
        store[absent] = null;
        Assert.Throws<InvalidOperationException>(() => Parse(root));
    }

    private static JsonObject RoundTrip(JsonObject root, bool empty = false)
    {
        void ValidateBoundary(string text)
        {
            if (empty)
            {
                ObserverTopologyMetadataValidation.ValidateShape(text);
                Assert.Contains("empty topology", Assert.Throws<InvalidOperationException>(
                    () => NativeApfsObserver.ParseAndValidateEvidence(text)).Message);
            }
            else NativeApfsObserver.ParseAndValidateEvidence(text);
        }
        ValidateBoundary(root.ToJsonString());
        var evidence = ApfsTopology.ParseEvidence(root.ToJsonString());
        // Exercise the plain default call and the local indented/camel-case pattern.
        var json = JsonSerializer.Serialize(evidence);
        foreach (var options in new[] { new JsonSerializerOptions(), new JsonSerializerOptions
            { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase } })
        {
            var serialized = JsonSerializer.Serialize(evidence, options);
            var direct = JsonSerializer.Deserialize<ApfsObserverEvidence>(serialized, options);
            Assert.IsType<ApfsObserverEvidence>(direct);
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(json), JsonNode.Parse(JsonSerializer.Serialize(direct, options))));
            ValidateBoundary(serialized);
        }
        ValidateBoundary(json);
        return JsonNode.Parse(json)!.AsObject();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SameGroupUuidInTwoContainersIsQualifiedAndAccepted(bool legacy)
    {
        var root = Payload(true);
        var other = JsonNode.Parse(Payload(true).ToJsonString().Replace(Container, new string('e', 32)))!;
        foreach (var collection in new[] { "containers", "stores", "volumes", "groups" })
            foreach (var node in other["topology"]![collection]!.AsArray())
                root["topology"]![collection]!.AsArray().Add(node!.DeepClone());
        if (legacy) StripExtension(root);
        var parsed = Parse(root);
        Assert.Equal(2, parsed.Topology.Groups.Count);
        Assert.Equal(parsed.Topology.Groups[0].Id, parsed.Topology.Groups[1].Id);
        if (legacy) Assert.All(parsed.Topology.Groups, g => { Assert.Null(g.DataVolumeId); Assert.Null(g.ContainerId); });
        else Assert.NotEqual(parsed.Topology.Groups[0].DataVolumeId, parsed.Topology.Groups[1].DataVolumeId);
    }

    [Theory]
    [InlineData("incomplete")]
    [InlineData("ambiguous")]
    [InlineData("malformed")]
    public void UnresolvedGroupsRemainVisibleWithoutTargets(string status)
    {
        var root = Payload(true); var t = root["topology"]!;
        var g = t["groups"]![0]!;
        if (status == "incomplete")
        {
            t["volumes"]!.AsArray().RemoveAt(1); t["containers"]![0]!["volumeIds"]!.AsArray().RemoveAt(1);
            t["groups"] = new JsonArray(); t["volumes"]![0]!["groupId"] = null;
        }
        else
        {
            g["associationStatus"] = status; g["systemVolumeId"] = null; g["dataVolumeId"] = null;
            if (status == "ambiguous")
            {
                t["volumes"]![1]!["roleName"] = "system"; t["volumes"]![1]!["roleRaw"] = 1;
                t["volumes"]![1]!["roles"] = new JsonArray("system");
            }
            else
            {
                t["volumes"]![0]!["compatibleFeatureBits"] = new JsonArray();
                t["volumes"]![0]!["groupMetadataValid"] = false;
            }
        }
        foreach (var v in t["volumes"]!.AsArray()) v!["groupAssociationStatus"] = status;
        var parsed = Parse(root);
        Assert.All(parsed.Topology.Volumes, v => Assert.Equal(status, v.GroupAssociationStatus));
        Assert.All(parsed.Topology.Groups, group => { Assert.Null(group.SystemVolumeId); Assert.Null(group.DataVolumeId); });
        var serialized = RoundTrip(root);
        foreach (var group in serialized["topology"]!["groups"]!.AsArray())
            foreach (var field in new[] { "systemVolumeId", "dataVolumeId" })
            {
                Assert.True(group!.AsObject().ContainsKey(field)); Assert.Null(group[field]);
            }
    }

    [Theory]
    [InlineData(0, "none", "data")]
    [InlineData(192, "update", "update")]
    [InlineData(384, "backup", "backup")]
    [InlineData(65, "unknown", "unknown")]
    [InlineData(65535, "unknown", "unknown")]
    public void ExactNativeRolesRemainLossless(int raw, string name, string category)
    {
        var root = Payload(); var v = root["topology"]!["volumes"]![0]!;
        v["roleRaw"] = raw; v["roleName"] = name; v["roles"] = new JsonArray(category);
        var parsed = Parse(root).Topology.Volumes[0];
        Assert.Equal(raw, parsed.RoleRaw); Assert.Equal(name, parsed.RoleName);
    }

    [Theory]
    [InlineData("cross-container")][InlineData("nonreciprocal")][InlineData("wrong-group-uuid")]
    [InlineData("extra-assignment")][InlineData("duplicate-uuid")][InlineData("zero-uuid")]
    [InlineData("unknown-known-role")][InlineData("too-large-role")]
    public void FalseGroupAndRoleClaimsRejected(string mutation)
    {
        var root = Payload(true); var t = root["topology"]!; var v = t["volumes"]![0]!;
        switch (mutation)
        {
            case "cross-container": t["groups"]![0]!["volumeIds"]![1] = $"apfs-vol:{new string('e',32)}:102"; break;
            case "nonreciprocal": v["groupId"] = null; break;
            case "wrong-group-uuid": v["groupUuid"] = new string('e',32); break;
            case "extra-assignment":
                var group = t["groups"]![0]!.DeepClone(); group["id"] = "apfs-group:" + new string('e',32); group["uuid"] = new string('e',32);
                t["groups"]!.AsArray().Add(group); break;
            case "duplicate-uuid": v["uuid"] = t["volumes"]![1]!["uuid"]!.DeepClone(); break;
            case "zero-uuid": v["uuid"] = new string('0',32); break;
            case "unknown-known-role": v["roleName"] = "unknown"; v["roles"] = new JsonArray("unknown"); break;
            case "too-large-role": v["roleRaw"] = 65536; break;
        }
        Assert.Throws<InvalidOperationException>(() => Parse(root));
    }

    [Fact]
    public void DuplicateJsonClaimsAreRejected()
    {
        var json = Payload().ToJsonString().Replace("\"roleName\":\"none\"", "\"roleName\":\"system\",\"roleName\":\"none\"");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void LegacyEmptyGroupIdRemainsAbsentButExtensionRequiresNull()
    {
        var root = Payload(); root["topology"]!["volumes"]![0]!["groupId"] = "";
        Assert.Throws<InvalidOperationException>(() => Parse(root));
        StripExtension(root);
        var parsed = Parse(root);
        Assert.Null(parsed.Topology.Volumes[0].GroupAssociationStatus);
        Assert.Empty(parsed.Topology.Groups);
    }

    private static void StripExtension(JsonObject root)
    {
        root.Remove("topologyMetadataVersion");
        foreach (var c in root["topology"]!["containers"]!.AsArray()) c!.AsObject().Remove("sharedSpace");
        foreach (var v in root["topology"]!["volumes"]!.AsArray())
            foreach (var field in new[] { "roleName", "groupUuid", "groupMetadataValid", "groupAssociationStatus" }) v!.AsObject().Remove(field);
        foreach (var g in root["topology"]!["groups"]!.AsArray())
            foreach (var field in new[] { "containerId", "associationStatus", "systemVolumeId", "dataVolumeId" }) g!.AsObject().Remove(field);
    }

    [Theory]
    [InlineData("missing-version")]
    [InlineData("null-version")]
    [InlineData("future-version")]
    [InlineData("missing-role")]
    [InlineData("null-role")]
    [InlineData("wrong-role")]
    [InlineData("missing-space")]
    [InlineData("empty-space")]
    [InlineData("false-status")]
    [InlineData("false-validity")]
    [InlineData("wrong-container")]
    [InlineData("swapped-targets")]
    [InlineData("missing-target")]
    [InlineData("missing-group")]
    [InlineData("duplicate-group")]
    [InlineData("future-checkpoint")]
    [InlineData("wrong-store-uuid")]
    public void ContradictoryOrPartialExtensionRejected(string mutation)
    {
        var root = Payload(true);
        var t = root["topology"]!;
        var v = t["volumes"]![0]!.AsObject();
        var g = t["groups"]![0]!.AsObject();
        switch (mutation)
        {
            case "missing-version": root.Remove("topologyMetadataVersion"); break;
            case "null-version": root["topologyMetadataVersion"] = null; break;
            case "future-version": root["topologyMetadataVersion"] = 2; break;
            case "missing-role": v.Remove("roleName"); break;
            case "null-role": v["roleName"] = null; break;
            case "wrong-role": v["roleName"] = "data"; break;
            case "missing-space": t["containers"]![0]!.AsObject().Remove("sharedSpace"); break;
            case "empty-space": t["containers"]![0]!["sharedSpace"] = new JsonObject(); break;
            case "false-status": v["groupAssociationStatus"] = "none"; break;
            case "false-validity": v["groupMetadataValid"] = false; break;
            case "wrong-container": g["containerId"] = "apfs-container:" + new string('f', 32); break;
            case "swapped-targets": g["dataVolumeId"] = g["systemVolumeId"]!.DeepClone(); break;
            case "missing-target": g.Remove("systemVolumeId"); break;
            case "missing-group": t["groups"] = new JsonArray(); break;
            case "duplicate-group": t["groups"]!.AsArray().Add(g.DeepClone()); break;
            case "future-checkpoint": v["superblockXid"] = "8"; break;
            case "wrong-store-uuid": t["stores"]![0]!["uuid"] = new string('f', 32); break;
        }
        Assert.Throws<InvalidOperationException>(() => Parse(root));
    }

    internal static ApfsAccess.Core.ApfsObserverEvidence Parse(JsonObject root)
        => NativeApfsObserver.ParseAndValidateEvidence(root.ToJsonString());
}
