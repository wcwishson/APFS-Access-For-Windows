using System.Text.Json;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class DriveLetterCommand
{
    internal const string Usage = "drive-letter --device-id <exact-id> --volume-id <exact-id> --volume-uuid <actual-uuid> --letter <A-Z> [--human]";

    internal static async Task<int> RunAsync(string[] args,
        Func<DriveLetterPreferenceRequestPayload, Task<AckPayload>>? send = null)
    {
        var human = args.Contains("--human", StringComparer.Ordinal);
        if (args is ["--help"] or ["help"])
        {
            Console.WriteLine(Usage + "\nUse list to find the actual volume UUID and allowed letters. Saves for the next clean mount; the service must be running.");
            return 0;
        }
        AckPayload result;
        var exit = 1;
        try
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i] == "--human") continue;
                var key = args[i];
                if (key is not ("--device-id" or "--volume-id" or "--volume-uuid" or "--letter") ||
                    ++i >= args.Length || string.IsNullOrWhiteSpace(args[i]) || !values.TryAdd(key, args[i]))
                    throw new ArgumentException(Usage);
            }
            if (values.Count != 4 ||
                !(Guid.TryParseExact(values["--volume-uuid"], "D", out var uuid) || Guid.TryParseExact(values["--volume-uuid"], "N", out uuid)) || uuid == Guid.Empty ||
                values["--letter"] is not { Length: 1 } letter || char.ToUpperInvariant(letter[0]) is < 'A' or > 'Z')
                throw new ArgumentException(Usage);
            result = await (send ?? SendAsync)(new(values["--device-id"], values["--volume-id"], uuid.ToString("D"), letter.ToUpperInvariant())).ConfigureAwait(false);
            exit = result.Success ? 0 : result.Code == ApfsOperationCodes.InvalidArguments ? 2 : 1;
        }
        catch (ArgumentException ex) { result = new(false, ex.Message, ApfsOperationCodes.InvalidArguments); exit = 2; }
        catch (OperationCanceledException) { result = new(false, "Preference request timed out; refresh before retrying.", ApfsOperationCodes.Timeout); exit = 3; }
        catch (Exception ex) { result = new(false, ex.Message, ApfsOperationCodes.ServiceUnavailable); }
        Console.WriteLine(human ? result.Message : JsonSerializer.Serialize(new {
            schemaVersion = 2, command = "drive-letter", operationId = Guid.NewGuid().ToString("D"),
            success = result.Success, code = result.Code, message = result.Message,
            exitCode = exit, appliesOn = "next-clean-mount"
        }));
        return exit;
    }

    private static async Task<AckPayload> SendAsync(DriveLetterPreferenceRequestPayload request)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using var peer = await NamedPipeMessageClient.ConnectAsync(ApfsPipeConstants.PipeName, 3000, deadline.Token).ConfigureAwait(false);
        var id = Guid.NewGuid().ToString("D");
        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.DriveLetterPreferenceRequested, request, id), deadline.Token).ConfigureAwait(false);
        while (await peer.ReadMessageAsync(deadline.Token).ConfigureAwait(false) is { } message)
        {
            if (message.RequestId != id || message.Type != ApfsMessageTypes.Ack) continue;
            if (!PipeMessageCodec.TryGetPayload<AckPayload>(message, out var ack) || ack is null)
                throw new InvalidDataException("Malformed preference response.");
            return ack;
        }
        throw new IOException("The service disconnected before acknowledging the preference.");
    }
}
