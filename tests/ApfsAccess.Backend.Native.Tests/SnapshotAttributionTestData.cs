using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

internal static class SnapshotAttributionTestData
{
    internal const string Identity = "windows-file:1:2:2097152:3";

    // Native-derived snapshot fixture result. Source labels are fictional;
    // geometry, ownership and amounts are the independent canonical fixture's.
    internal static JsonObject Read(string image) => JsonNode.Parse("""
    {
      "format":"apfs-access-snapshot-space-attribution","version":1,"readOnly":true,"complete":true,
      "source":{"path":"fixture.apfs","identity":"windows-file:1:2:2097152:3"},
      "scope":{"containerUuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","volumeUuid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "volumeOid":"101","checkpointXid":"22","storeOffsetBytes":"0","storeSizeBytes":"2097152"},
      "allocationUnitBytes":4096,"retainedCheckpointXids":["20","21","22"],
      "referencedMetadata":{"blocks":"5","bytes":"20480"},
      "referencedPayload":{"blocks":"1","bytes":"4096"},
      "catalogMetadata":{"blocks":"14","bytes":"57344"},
      "snapshots":[{"snapshotXid":"21","name":"retained",
        "metadata":{
          "referenced":{"blocks":"5","bytes":"20480"},"sharedWithLive":{"blocks":"0","bytes":"0"},
          "absentFromLive":{"blocks":"5","bytes":"20480"},"sharedWithOtherSnapshots":{"blocks":"0","bytes":"0"},
          "uniqueInVisibleInventory":{"blocks":"5","bytes":"20480"},"retainedOrPeerProtected":{"blocks":"5","bytes":"20480"},
          "potentialReclaimUpperBound":{"blocks":"0","bytes":"0"}},
        "payload":{
          "referenced":{"blocks":"1","bytes":"4096"},"sharedWithLive":{"blocks":"0","bytes":"0"},
          "absentFromLive":{"blocks":"1","bytes":"4096"},"sharedWithOtherSnapshots":{"blocks":"0","bytes":"0"},
          "uniqueInVisibleInventory":{"blocks":"1","bytes":"4096"},"retainedOrPeerProtected":{"blocks":"1","bytes":"4096"},
          "potentialReclaimUpperBound":{"blocks":"0","bytes":"0"}},
        "purgeableMarkedPayload":{"blocks":"0","bytes":"0"},"applePurgeable":null,"reclaimable":null}]
    }
    """)!.AsObject().WithPath(image);

    private static JsonObject WithPath(this JsonObject value, string image)
    { value["source"]!["path"] = image; return value; }

    internal static JsonObject Unknown(string image) => new()
    {
        ["format"] = "apfs-access-snapshot-space-attribution", ["version"] = 1,
        ["readOnly"] = true, ["complete"] = false,
        ["source"] = new JsonObject { ["path"] = image, ["identity"] = Identity },
        ["scope"] = Read(image)["scope"]!.DeepClone(), ["reason"] = "SnapshotAttributionVerificationIncomplete:AllocatedOrphan"
    };

    internal static ApfsSnapshotAttributionRequest Request(string image)
        => new(image, "apfs-container:" + new string('a', 32), new string('b', 32), "101", "22", "0", "2097152");
}
