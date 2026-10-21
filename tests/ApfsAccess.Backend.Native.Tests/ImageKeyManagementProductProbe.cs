using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

internal static class ImageKeyManagementProductProbe
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() }
    };
    internal static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 1 && args[0] == "--allocation")
            {
                ulong bytes = 0; var count = 0;
                foreach (var root in args[1..]) foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    var low = GetCompressedFileSizeW(path, out var high);
                    if (low == uint.MaxValue && Marshal.GetLastWin32Error() != 0) throw new IOException();
                    bytes += ((ulong)high << 32) | low; ++count;
                }
                Console.WriteLine(JsonSerializer.Serialize(new { allocatedDataBytes = bytes, files = count })); return 0;
            }
            if (args.Length != 5) return 2;
            using var input = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read);
            var request = JsonSerializer.Deserialize<ImageKeyManagementRequest>(input, Json) ?? throw new IOException();
            if (!request.IsValid()) return 2;
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            using var credentials = SupervisedCredentialSet.Receive(SupervisedCredential.TakeStandardInput(), request.CredentialCount,
                cancellation.Token, () => { });
            var backend = new NativeImageKeyManagementBackend(args[1], args[2], args[3]);
            var receipt = await backend.ManageImageKeysAsync(request, credentials, cancellation.Token).ConfigureAwait(false);
            if (!receipt.Proves(request)) throw new IOException();
            using (var output = new FileStream(args[4], FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            { JsonSerializer.Serialize(output, receipt, Json); output.Flush(flushToDisk: true); }
            Console.WriteLine("PRODUCT_TYPED_BACKEND_CLEAN_CLOSE_PASS"); return 0;
        }
        catch (Exception error)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { refused = true, error = error.GetType().Name, nativeExitCode = error.Data["NativeExitCode"] })); return 1;
        }
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetCompressedFileSizeW(string path, out uint high);
}
