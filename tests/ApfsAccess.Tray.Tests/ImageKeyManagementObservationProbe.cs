using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc.Tests;
using ApfsAccess.Tray;

internal static class ImageKeyManagementObservationProbe
{
    private static async Task<int> Main(string[] args)
    {
        var contracts = new ImageKeyManagementObservationTests();
        contracts.PristineCleanObservationNeedsNoAcceptedMutation();
        contracts.KeylessAcceptedRecoveryMayAdvanceModeButCannotSubstituteImageOrRollback();
        contracts.PersistedObservationCannotMasqueradeAsAConfirmedMutation();
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
        var receipt = JsonSerializer.Deserialize<ImageKeyManagementReceipt>(File.ReadAllText(args.Single()), options)!;
        void Require(bool value) { if (!value) throw new IOException("ImageSelectorProofFailed"); }
        ImageKeyManagementEndpoint Read(string text) { using var input = new MemoryStream(Encoding.UTF8.GetBytes(text)); return ImageKeyManagementSelection.Read(input); }
        Require(Read(JsonSerializer.Serialize(receipt.Before, options)) == receipt.Before);
        Require(Read(JsonSerializer.Serialize(receipt.Before.ToWritableEncryptedProfile(), options)) == receipt.Before);
        var duplicate = JsonSerializer.Serialize(receipt.Before, options).Replace("\"containerBagOid\":", "\"ContainerBagOid\":0,\"containerBagOid\":", StringComparison.Ordinal);
        try { Read(duplicate); throw new IOException("NestedDuplicateAdmitted"); } catch (InvalidDataException) { }
        try { Read(new string('x', 8193)); throw new IOException("OversizeSelectorsAdmitted"); } catch (InvalidDataException) { }
        try { Read(JsonSerializer.Serialize(receipt.Before.ToWritableEncryptedProfile() with { Writable = false }, options));
            throw new IOException("ReadOnlyIdentityAdmitted"); } catch (InvalidDataException) { }
        var lifetime = (Task<int>)typeof(ImageKeyManagementDialogLifetimeProbe).GetMethod("Main", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [args])!;
        Require(await lifetime == 0);
        Console.WriteLine("KEY_OBSERVATION_IDENTITY_MODE_CLEAN_PREFIX_SELECTOR_LIFETIME_PASS"); return 0;
    }
}
