using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

// Sanitized native-derived fixtures. Only source path/identity and its first plan field differ.
internal static class RetainedOwnershipNativeReports
{
    internal static JsonObject Read(string name = "ordinary")
    {
        using var stream = typeof(RetainedOwnershipNativeReports).Assembly.GetManifestResourceStream(
            "RetainedOwnershipNativeReports." + name + ".json") ?? throw new InvalidDataException("Missing native report fixture.");
        return JsonNode.Parse(stream)!.AsObject();
    }

    internal static ApfsImageVerificationRequest Request(string name = "ordinary") => new(
        Read(name)["source"]!["path"]!.GetValue<string>(), "apfs-container:" + new string('a', 32),
        name == "wrong-volume" ? new string('c', 32) : new string('b', 32), "101", name == "snapshot" ? "22" : "31",
        "0", "2097152", AccountRetainedOwnership: name != "ordinary-default");

    internal static string Identity(string name = "ordinary") => Read(name)["source"]!["identity"]!.GetValue<string>();

    internal static void MoveSource(JsonObject report, string path, string identity)
    {
        var old = report["source"]!["identity"]!.GetValue<string>();
        var plan = report["repair"]!["planId"]!.GetValue<string>();
        var prefix = report["version"]!.GetValue<int>() == 4 ? "apfs-verifier-refusal-ownership-v1|" : "apfs-verifier-refusal-v2|";
        static string Field(string value) => Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture) + ":" + value;
        if (!plan.StartsWith(prefix + Field(old), StringComparison.Ordinal)) throw new InvalidDataException("Native fixture binding drift.");
        // Replace only the first length-prefixed identity; retain every other native binding byte.
        report["repair"]!["planId"] = prefix + Field(identity) + plan[(prefix.Length + Field(old).Length)..];
        report["source"]!["path"] = path;
        report["source"]!["identity"] = identity;
    }
}
