using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal static class ImageKeyManagementCommand
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, Converters = { new JsonStringEnumConverter() } };

    internal static async Task<int> RunAsync(string[] args)
    {
        string? operationId = null;
        var stage = "arguments";
        try
        {
            if (args.Length == 0) throw new ArgumentException();
            var action = args[0] switch
            {
                "change-password" => ImageKeyManagementAction.ChangePassword,
                "rotate" => ImageKeyManagementAction.RotateVolumeKey,
                "encrypt" => ImageKeyManagementAction.Encrypt,
                "decrypt" => ImageKeyManagementAction.Decrypt,
                "observe" => ImageKeyManagementAction.Observe,
                _ => throw new ArgumentException()
            };
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            var stdin = false;
            for (var i = 1; i < args.Length; ++i)
            {
                if (args[i] == "--credential-stdin") { if (stdin) throw new ArgumentException(); stdin = true; continue; }
                if (args[i] is not ("--endpoint" or "--operation-id" or "--private-instance") || i + 1 == args.Length ||
                    !values.TryAdd(args[i], args[++i])) throw new ArgumentException();
            }
            if (stdin == (action == ImageKeyManagementAction.Observe) || !values.TryGetValue("--endpoint", out var path))
                throw new ArgumentException();
            operationId = values.GetValueOrDefault("--operation-id") ?? Guid.NewGuid().ToString("D");
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length is < 2 or > 8192) throw new ArgumentException();
            using var document = JsonDocument.Parse(file);
            static bool Unique(JsonElement element) => element.ValueKind == JsonValueKind.Object ?
                element.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == element.EnumerateObject().Count() &&
                    element.EnumerateObject().All(p => Unique(p.Value)) : element.ValueKind != JsonValueKind.Array || element.EnumerateArray().All(Unique);
            if (!Unique(document.RootElement)) throw new ArgumentException();
            var endpoint = document.RootElement.Deserialize<ImageKeyManagementEndpoint>(Json) ?? throw new ArgumentException();
            var request = new ImageKeyManagementRequest(operationId, action, endpoint);
            if (!request.IsValid()) throw new ArgumentException();
            string? pipe = null;
            if (values.TryGetValue("--private-instance", out var text))
            {
                if (!Guid.TryParseExact(text, "D", out var instance) || instance == Guid.Empty || instance.ToString("D") != text) throw new ArgumentException();
                pipe = FusionControlEndpoint.ForPrivateInstance(instance);
            }
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; deadline.Cancel(); };
            Console.CancelKeyPress += cancel;
            try
            {
                stage = "credential-input";
                if (action == ImageKeyManagementAction.Observe)
                {
                    stage = "service-exchange";
                    var observed = await ImageKeyManagementControlClient.ObserveOperationAsync(request, deadline.Token, pipe).ConfigureAwait(false);
                    Console.WriteLine(JsonSerializer.Serialize(observed, Json)); return observed.Success ? 0 : 5;
                }
                using var credentials = SupervisedCredentialSet.Receive(SupervisedCredential.TakeStandardInput(), request.CredentialCount, deadline.Token, () => { });
                stage = "service-exchange";
                var result = await ImageKeyManagementControlClient.ManageAsync(request, credentials, deadline.Token, pipe).ConfigureAwait(false);
                Console.WriteLine(JsonSerializer.Serialize(result, Json)); return result.Success ? 0 : 5;
            }
            finally { Console.CancelKeyPress -= cancel; }
        }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("Use image-keys <change-password|rotate|encrypt|decrypt> --endpoint <endpoint.json> --credential-stdin [--operation-id <id>].");
            Console.Error.WriteLine("Use image-keys observe --endpoint <endpoint.json> [--operation-id <id>] to refresh without a credential.");
            return 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { operationId, success = false,
                stage, errorType = error.GetType().Name, protocolCode = error.Data["KeyManagementProtocolCode"] as string,
                message = "Key management interrupted. Query this operation and refresh the image before retrying." }, Json));
            return 5;
        }
    }
}
