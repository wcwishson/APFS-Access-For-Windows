using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

public sealed partial class SupervisedCredential
{
    private static void RequireFrameCount(int count)
    {
        if (count is not (1 or 2)) throw Failure("InvalidFrameCount");
    }

    private static int FrameLength(SupervisedCredential value)
    {
        var size = Marshal.ReadInt32(value.memory, 4);
        if (Marshal.ReadInt32(value.memory) != 0x31435041 || size is < 1 or > 1024) throw Failure("InvalidFrame");
        return size + 8;
    }

    private static void ValidateFrame(SupervisedCredential value, int size)
    {
        for (var i = 8; i < size; ++i)
            if (Marshal.ReadByte(value.memory, i) == 0) throw Failure("InvalidFrame");
        value.length = size;
    }

    internal static async Task<SupervisedCredentialSet> ReceiveFramesAsync(Stream input, int expectedCount, CancellationToken token)
    {
        RequireFrameCount(expectedCount);
        var values = new SupervisedCredential[expectedCount];
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            for (var i = 0; i < values.Length; ++i)
            {
                var value = values[i] = Allocate();
                using var bytes = new BorrowedMemory(value.memory, Capacity);
                await input.ReadExactlyAsync(bytes.Memory[..8], deadline.Token).ConfigureAwait(false);
                var size = FrameLength(value);
                await input.ReadExactlyAsync(bytes.Memory.Slice(8, size - 8), deadline.Token).ConfigureAwait(false);
                ValidateFrame(value, size);
                if (i == values.Length - 1 && await input.ReadAsync(bytes.Memory.Slice(size, 1), deadline.Token).ConfigureAwait(false) != 0)
                    throw Failure("InvalidFrameCount");
            }
            return new(values);
        }
        catch
        {
            foreach (var value in values) value?.Dispose();
            throw;
        }
    }

    internal static SupervisedCredentialSet ReceiveFrames(nint input, int expectedCount, CancellationToken cancellation,
        Action checkOwner, int timeoutMs)
    {
        RequireFrameCount(expectedCount);
        if (timeoutMs is < 1 or > 60000) throw Failure("InvalidDeadline");
        var values = new SupervisedCredential[expectedCount];
        try
        {
            using var ownedInput = new SafeFileHandle(input, true);
            if (GetFileType(input) != 3 || !GetNamedPipeInfo(input, out var flags, 0, 0, 0) || (flags & 4) != 0)
                throw Failure("PipeRequired");
            if (!SetHandleInformation(input, 1, 0)) throw Failure("InputHandle");
            var watch = Stopwatch.StartNew();
            var index = 0; var received = 0; var expected = 8; var header = false; var complete = false;
            values[0] = Allocate();
            while (true)
            {
                cancellation.ThrowIfCancellationRequested(); checkOwner();
                if (watch.ElapsedMilliseconds >= timeoutMs) throw Failure("Timeout");
                if (!PeekNamedPipe(input, 0, 0, 0, out var available, 0))
                {
                    if (Marshal.GetLastWin32Error() != 109) throw Failure("ReadFailure");
                    if (!complete) throw Failure("TruncatedFrame");
                    return new(values);
                }
                if (available == 0) { Thread.Sleep(5); continue; }
                var value = values[index];
                var count = complete ? 1u : Math.Min(available, checked((uint)(expected - received)));
                if (!ReadFile(input, value.memory + received, count, out var got, 0) || got == 0) throw Failure("TruncatedFrame");
                if (complete) throw Failure("InvalidFrameCount");
                received += checked((int)got);
                if (!header && received == 8) { expected = FrameLength(value); header = true; }
                else if (header && received == expected)
                {
                    ValidateFrame(value, expected);
                    if (index == values.Length - 1) complete = true;
                    else
                    {
                        values[++index] = Allocate(); received = 0; expected = 8; header = false;
                    }
                }
            }
        }
        catch
        {
            foreach (var value in values) value?.Dispose();
            throw;
        }
    }

    private static void RequireLiveFrames(IReadOnlyList<SupervisedCredential> values)
    {
        RequireFrameCount(values.Count);
        if (values.Count == 2 && ReferenceEquals(values[0], values[1])) throw Failure("InvalidFrameOwners");
        foreach (var value in values)
            if (value is null || value.memory == 0 || value.length <= 8 || FrameLength(value) != value.length) throw Failure("Expired");
    }

    internal static async Task SendFramesAsync(IReadOnlyList<SupervisedCredential> values, Stream output, CancellationToken token)
    {
        RequireLiveFrames(values);
        foreach (var value in values)
        {
            token.ThrowIfCancellationRequested();
            using var bytes = new BorrowedMemory(value.memory, value.length);
            await output.WriteAsync(bytes.Memory, token).ConfigureAwait(false);
        }
        await output.FlushAsync(token).ConfigureAwait(false);
    }

    internal static void SendFrames(IReadOnlyList<SupervisedCredential> values, CancellationToken cancellation, Action checkOwnerAndChild)
    {
        RequireLiveFrames(values);
        var writer = values[0].writer;
        if (writer is null) throw Failure("PipeRequired");
        var watch = Stopwatch.StartNew();
        foreach (var value in values)
        {
            cancellation.ThrowIfCancellationRequested(); checkOwnerAndChild();
            // Both maximum frames fit in the existing empty 4096-byte pipe.
            if (!WriteFile(writer, value.memory, (uint)value.length, out var written, 0) || written != value.length)
                throw Failure("WriteFailure");
            if (watch.ElapsedMilliseconds >= 1000) throw Failure("WriteDeadline");
        }
        cancellation.ThrowIfCancellationRequested(); checkOwnerAndChild();
    }
}
