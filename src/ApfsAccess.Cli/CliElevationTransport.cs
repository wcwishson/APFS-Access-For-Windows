using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal sealed record CliElevationWireMessage(
    int SchemaVersion,
    string Type,
    string Token,
    CliElevationProcessIdentity? Process = null,
    CliElevationPackageIdentity? Package = null,
    CliElevationResultEnvelope? Result = null,
    bool Authorized = false,
    DateTimeOffset? OperationDeadlineUtc = null);

internal interface ICliElevationServerChannel : IAsyncDisposable
{
    int? PeerProcessId { get; }
    Task WaitForExactPeerAsync(int expectedProcessId, TimeSpan timeout);
    Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout);
    Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout);
}

internal interface ICliElevationClientChannel : IAsyncDisposable
{
    int? PeerProcessId { get; }
    Task ConnectToExactServerAsync(int expectedProcessId, TimeSpan timeout);
    Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout);
    Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout);
}

internal interface ICliElevationJob : IDisposable
{
    string Name { get; }
    void AssignCurrentProcess();
    bool ContainsOnlyProcess(int processId);
    Task<bool> TerminateAndProveEmptyAsync(TimeSpan timeout);
}

internal static class CliElevationTransport
{
    internal const int WireSchemaVersion = 2;
    internal const string HelloMessage = "hello";
    internal const string AuthorizationMessage = "authorize";
    internal const string ResultMessage = "result";

    internal static ICliElevationServerChannel CreateServer(string pipeName)
        => new WindowsPipeServerChannel(pipeName);

    internal static ICliElevationClientChannel CreateClient(string pipeName)
        => new WindowsPipeClientChannel(pipeName);

    internal static ICliElevationJob CreateJob(string jobName)
        => WindowsElevationJob.Create(jobName);

    internal static ICliElevationJob OpenJob(string jobName)
        => WindowsElevationJob.Open(jobName);

    private sealed class WindowsPipeServerChannel : ICliElevationServerChannel
    {
        private readonly NamedPipeServerStream _stream;

        internal WindowsPipeServerChannel(string pipeName)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("CLI elevation transport requires Windows named pipes.");
            }

            _stream = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: 16 * 1024,
                outBufferSize: 16 * 1024);
        }

        public int? PeerProcessId { get; private set; }

        public async Task WaitForExactPeerAsync(int expectedProcessId, TimeSpan timeout)
        {
            using var cts = CreateTimeout(timeout);
            while (true)
            {
                await _stream.WaitForConnectionAsync(cts.Token).ConfigureAwait(false);
                if (!NativeMethods.GetNamedPipeClientProcessId(_stream.SafePipeHandle, out var processId))
                {
                    var error = Marshal.GetLastWin32Error();
                    _stream.Disconnect();
                    throw new Win32Exception(error, "Could not observe the elevation pipe client process.");
                }

                if (processId == (uint)expectedProcessId)
                {
                    PeerProcessId = expectedProcessId;
                    return;
                }

                _stream.Disconnect();
            }
        }

        public Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout)
            => PipeFraming.ReadAsync(_stream, timeout);

        public Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout)
            => PipeFraming.WriteAsync(_stream, message, timeout);

        public ValueTask DisposeAsync() => _stream.DisposeAsync();
    }

    private sealed class WindowsPipeClientChannel : ICliElevationClientChannel
    {
        private readonly NamedPipeClientStream _stream;

        internal WindowsPipeClientChannel(string pipeName)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("CLI elevation transport requires Windows named pipes.");
            }

            _stream = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification);
        }

        public int? PeerProcessId { get; private set; }

        public async Task ConnectToExactServerAsync(int expectedProcessId, TimeSpan timeout)
        {
            using var cts = CreateTimeout(timeout);
            await _stream.ConnectAsync(cts.Token).ConfigureAwait(false);
            if (!NativeMethods.GetNamedPipeServerProcessId(_stream.SafePipeHandle, out var processId))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not observe the elevation pipe server process.");
            }

            if (processId != (uint)expectedProcessId)
            {
                throw new CliElevationValidationException("The elevation authorization channel belongs to the wrong parent process.");
            }

            PeerProcessId = expectedProcessId;
        }

        public Task<CliElevationWireMessage> ReadAsync(TimeSpan timeout)
            => PipeFraming.ReadAsync(_stream, timeout);

        public Task WriteAsync(CliElevationWireMessage message, TimeSpan timeout)
            => PipeFraming.WriteAsync(_stream, message, timeout);

        public ValueTask DisposeAsync() => _stream.DisposeAsync();
    }

    private static CancellationTokenSource CreateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
        {
            throw new TimeoutException("The elevation IPC deadline has expired.");
        }

        return new CancellationTokenSource(timeout);
    }

    private static class PipeFraming
    {
        private const int MaximumMessageBytes = 32 * 1024 * 1024;

        internal static async Task<CliElevationWireMessage> ReadAsync(PipeStream stream, TimeSpan timeout)
        {
            using var cts = CreateTimeout(timeout);
            var lengthBytes = new byte[sizeof(int)];
            await ReadExactlyAsync(stream, lengthBytes, cts.Token).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length <= 0 || length > MaximumMessageBytes)
            {
                throw new CliElevationValidationException("The elevation IPC message length is invalid.");
            }

            var payload = new byte[length];
            await ReadExactlyAsync(stream, payload, cts.Token).ConfigureAwait(false);
            try
            {
                return JsonSerializer.Deserialize<CliElevationWireMessage>(payload, CliElevation.SerializerOptions)
                    ?? throw new CliElevationValidationException("The elevation IPC message is empty.");
            }
            catch (CliElevationValidationException)
            {
                throw;
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
                throw new CliElevationValidationException($"The elevation IPC message is malformed: {ex.Message}");
            }
        }

        internal static async Task WriteAsync(
            PipeStream stream,
            CliElevationWireMessage message,
            TimeSpan timeout)
        {
            var payload = JsonSerializer.SerializeToUtf8Bytes(message, CliElevation.SerializerOptions);
            if (payload.Length > MaximumMessageBytes)
            {
                throw new CliElevationValidationException("The elevation IPC message exceeds the bounded size.");
            }

            using var cts = CreateTimeout(timeout);
            var lengthBytes = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, payload.Length);
            await stream.WriteAsync(lengthBytes, cts.Token).ConfigureAwait(false);
            await stream.WriteAsync(payload, cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);
        }

        private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("The elevation IPC peer disconnected before completing a message.");
                }

                offset += read;
            }
        }
    }

    private sealed class WindowsElevationJob : ICliElevationJob
    {
        private const int ErrorAlreadyExists = 183;
        private const uint JobObjectAssignProcess = 0x0001;
        private const int JobObjectBasicProcessIdList = 3;
        private const int JobObjectExtendedLimitInformationClass = 9;
        private const uint JobObjectLimitBreakawayOk = 0x00000800;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private readonly SafeFileHandle _handle;

        private WindowsElevationJob(string name, SafeFileHandle handle)
        {
            Name = name;
            _handle = handle;
        }

        public string Name { get; }

        internal static WindowsElevationJob Create(string name)
        {
            var handle = NativeMethods.CreateJobObject(IntPtr.Zero, name);
            var createError = Marshal.GetLastWin32Error();
            if (handle.IsInvalid)
            {
                throw new Win32Exception(createError, "Could not create the elevation job object.");
            }

            if (createError == ErrorAlreadyExists)
            {
                handle.Dispose();
                throw new CliElevationValidationException("The token-specific elevation job already exists.");
            }

            var limits = new NativeMethods.JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation
                {
                    LimitFlags = JobObjectLimitKillOnJobClose | JobObjectLimitBreakawayOk,
                },
            };
            if (!NativeMethods.SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformationClass,
                    ref limits,
                    (uint)Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>()))
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not make the elevation job fail closed on owner exit.");
            }

            return new WindowsElevationJob(name, handle);
        }

        internal static WindowsElevationJob Open(string name)
        {
            var handle = NativeMethods.OpenJobObject(
                JobObjectAssignProcess,
                inheritHandle: false,
                name);
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open the elevation job object.");
            }

            return new WindowsElevationJob(name, handle);
        }

        public void AssignCurrentProcess()
        {
            using var process = System.Diagnostics.Process.GetCurrentProcess();
            if (!NativeMethods.AssignProcessToJobObject(_handle, process.Handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not bind the elevated child to its ownership job.");
            }
        }

        public bool ContainsOnlyProcess(int processId)
        {
            var processes = QueryProcessIds();
            return processes is not null && processes.Count == 1 && processes[0] == (nuint)processId;
        }

        public async Task<bool> TerminateAndProveEmptyAsync(TimeSpan timeout)
        {
            try
            {
                if (!NativeMethods.TerminateJobObject(_handle, 4))
                {
                    return false;
                }

                var deadline = Stopwatch.GetTimestamp() + Math.Max(
                    1,
                    checked((long)Math.Ceiling(timeout.TotalSeconds * Stopwatch.Frequency)));
                while (Stopwatch.GetTimestamp() < deadline)
                {
                    var processes = QueryProcessIds();
                    if (processes is { Count: 0 })
                    {
                        return true;
                    }

                    await Task.Delay(25).ConfigureAwait(false);
                }

                return QueryProcessIds() is { Count: 0 };
            }
            catch
            {
                return false;
            }
        }

        public void Dispose() => _handle.Dispose();

        private IReadOnlyList<nuint>? QueryProcessIds()
        {
            var capacity = 16 + (IntPtr.Size * 16);
            while (capacity <= 1024 * 1024)
            {
                var buffer = Marshal.AllocHGlobal(capacity);
                try
                {
                    if (NativeMethods.QueryInformationJobObject(
                            _handle,
                            JobObjectBasicProcessIdList,
                            buffer,
                            (uint)capacity,
                            out _))
                    {
                        var count = Marshal.ReadInt32(buffer, sizeof(uint));
                        if (count < 0 || 8L + ((long)count * IntPtr.Size) > capacity)
                        {
                            return null;
                        }

                        var result = new nuint[count];
                        for (var index = 0; index < count; index++)
                        {
                            result[index] = IntPtr.Size == sizeof(long)
                                ? (nuint)Marshal.ReadInt64(buffer, 8 + (index * IntPtr.Size))
                                : (nuint)Marshal.ReadInt32(buffer, 8 + (index * IntPtr.Size));
                        }

                        return result;
                    }

                    if (Marshal.GetLastWin32Error() != 234)
                    {
                        return null;
                    }

                    capacity *= 2;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return null;
        }
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectBasicLimitInformation
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IoCounters
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectExtendedLimitInformation
        {
            internal JobObjectBasicLimitInformation BasicLimitInformation;
            internal IoCounters IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateJobObject(IntPtr jobAttributes, string? name);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle OpenJobObject(uint desiredAccess, bool inheritHandle, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeFileHandle job,
            int informationClass,
            ref JobObjectExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryInformationJobObject(
            SafeFileHandle job,
            int informationClass,
            IntPtr information,
            uint informationLength,
            out uint returnLength);
    }
}
