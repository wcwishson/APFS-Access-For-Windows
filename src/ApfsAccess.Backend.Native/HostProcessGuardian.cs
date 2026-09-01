using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

// The service owns one guardian for every FsHost. Closing the job handle is an
// OS-level fallback that terminates the child if the service itself exits while
// the host is stuck in WinFsp teardown.
internal sealed class HostProcessGuardian : IDisposable
{
    private const uint JobObjectBasicAccountingInformationClass = 1;
    private const uint JobObjectExtendedLimitInformation = 9;
    private const uint KillOnJobClose = 0x2000;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint WaitObject = 0;
    private const uint StartupFailureExitCode = 0xE1;
    private static readonly TimeSpan StartupCleanupTimeout = TimeSpan.FromSeconds(5);
    private SafeKernelHandle? _job;
    private SafeProcessHandle? _processHandle;
    private SafeThreadHandle? _suspendedThread;
    private readonly uint _processId;
    private readonly long _creationTimeFileTimeUtc;

    private HostProcessGuardian(
        SafeKernelHandle job,
        SafeProcessHandle? processHandle = null,
        SafeThreadHandle? suspendedThread = null,
        uint processId = 0,
        long creationTimeFileTimeUtc = 0)
    {
        _job = job;
        _processHandle = processHandle;
        _suspendedThread = suspendedThread;
        _processId = processId;
        _creationTimeFileTimeUtc = creationTimeFileTimeUtc;
    }

    internal uint ProcessId => _processId;

    internal long CreationTimeFileTimeUtc => _creationTimeFileTimeUtc;

    internal bool TryGetActiveProcessCount(out uint activeProcesses)
    {
        activeProcesses = 0;
        var job = Volatile.Read(ref _job);
        if (job is null || job.IsInvalid || job.IsClosed)
        {
            return false;
        }

        var accounting = default(JobObjectBasicAccountingInformationStruct);
        if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformationClass,
                ref accounting,
                (uint)Marshal.SizeOf<JobObjectBasicAccountingInformationStruct>(),
                out _))
        {
            return false;
        }

        activeProcesses = accounting.ActiveProcesses;
        return true;
    }

    internal sealed class LaunchResult
    {
        public LaunchResult(Process process, HostProcessGuardian? guardian)
        {
            Process = process;
            Guardian = guardian;
        }

        public Process Process { get; }

        public HostProcessGuardian? Guardian { get; }
    }

    public static LaunchResult Start(ProcessStartInfo startInfo, HostStartupGate startupGate)
        => StartCore(startInfo, startupGate, processCreated: null);

    internal static LaunchResult Start(
        ProcessStartInfo startInfo,
        HostStartupGate startupGate,
        Action<uint>? processCreated)
        => StartCore(startInfo, startupGate, processCreated);

    private static LaunchResult StartCore(
        ProcessStartInfo startInfo,
        HostStartupGate startupGate,
        Action<uint>? processCreated)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        ArgumentNullException.ThrowIfNull(startupGate);

        if (!OperatingSystem.IsWindows())
        {
            var process = Process.Start(startInfo);
            if (process is null)
            {
                throw new InvalidOperationException("Unable to start native mount host process.");
            }

            try
            {
                startupGate.Authorize();
                return new LaunchResult(process, guardian: null);
            }
            catch
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }

                    process.WaitForExit((int)StartupCleanupTimeout.TotalMilliseconds);
                }
                finally
                {
                    process.Dispose();
                }

                throw;
            }
        }

        using var suspended = SuspendedProcess.Create(startInfo);
        Process? processObject = null;
        HostProcessGuardian? guardian = null;
        try
        {
            processCreated?.Invoke(suspended.ProcessId);

            // The process is still suspended here, so resolving the public
            // Process wrapper by PID cannot race with PID reuse or child code.
            processObject = Process.GetProcessById(checked((int)suspended.ProcessId));
            guardian = Create(suspended, startupGate);
            guardian.ResumeSuspendedProcess();
            return new LaunchResult(processObject, guardian);
        }
        catch (Exception error)
        {
            Exception? cleanupError = null;
            try
            {
                if (guardian is not null)
                {
                    guardian.AbortStartup();
                }
                else
                {
                    suspended.AbortStartup();
                }
            }
            catch (Exception cleanup)
            {
                cleanupError = cleanup;
            }
            finally
            {
                processObject?.Dispose();
            }

            if (cleanupError is not null)
            {
                throw new AggregateException(
                    "Native mount host startup failed and exact process cleanup could not be proven.",
                    error,
                    cleanupError);
            }

            throw;
        }
    }

    public static HostProcessGuardian Create(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);

        SafeKernelHandle? job = null;
        try
        {
            job = CreateConfiguredJob();
            // Use the handle returned for this exact Process.Start instance.
            // Reopening by PID would allow PID reuse between launch and job
            // assignment to target an unrelated process.
            if (!AssignProcessToJobObject(job, process.SafeHandle))
            {
                throw LastWin32Error("AssignProcessToJobObject");
            }

            var guardian = new HostProcessGuardian(job);
            job = null;
            return guardian;
        }
        catch
        {
            try
            {
                TryTerminateAndProveExit(job, process.SafeHandle);
            }
            finally
            {
                job?.Dispose();
            }

            throw;
        }
    }

    public static HostProcessGuardian Create(Process process, HostStartupGate startupGate)
    {
        ArgumentNullException.ThrowIfNull(startupGate);
        var guardian = Create(process);
        try
        {
            startupGate.Authorize();
            return guardian;
        }
        catch
        {
            guardian.AbortStartup();
            throw;
        }
    }

    private static HostProcessGuardian Create(
        SuspendedProcess suspended,
        HostStartupGate startupGate)
    {
        SafeKernelHandle? job = null;
        HostProcessGuardian? guardian = null;
        try
        {
            job = CreateConfiguredJob();
            if (!AssignProcessToJobObject(job, suspended.ProcessHandle))
            {
                throw LastWin32Error("AssignProcessToJobObject");
            }

            if (!TryGetProcessCreationTime(
                    suspended.ProcessHandle,
                    out var creationTimeFileTimeUtc))
            {
                throw LastWin32Error("GetProcessTimes");
            }

            guardian = new HostProcessGuardian(
                job,
                suspended.DetachProcessHandle(),
                suspended.DetachThreadHandle(),
                suspended.ProcessId,
                creationTimeFileTimeUtc);
            job = null;

            // Authorization is still part of the suspended transaction. The
            // host cannot observe or consume this gate until ResumeThread.
            startupGate.Authorize();
            return guardian;
        }
        catch
        {
            if (guardian is not null)
            {
                guardian.AbortStartup();
            }
            else
            {
                try
                {
                    TryTerminateAndProveExit(job, suspended.ProcessHandle);
                }
                finally
                {
                    job?.Dispose();
                }
            }

            throw;
        }
    }

    private static SafeKernelHandle CreateConfiguredJob()
    {
        var jobHandle = CreateJobObjectW(nint.Zero, null);
        if (jobHandle == nint.Zero)
        {
            throw LastWin32Error("CreateJobObjectW");
        }

        var job = new SafeKernelHandle(jobHandle);
        try
        {
            var limits = new JobObjectExtendedLimitInformationStruct
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    LimitFlags = KillOnJobClose,
                },
            };

            if (!SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    ref limits,
                    (uint)Marshal.SizeOf<JobObjectExtendedLimitInformationStruct>()))
            {
                throw LastWin32Error("SetInformationJobObject");
            }

            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    private void ResumeSuspendedProcess()
    {
        var thread = _suspendedThread;
        if (thread is null || thread.IsInvalid || thread.IsClosed)
        {
            throw new InvalidOperationException("The guarded host process has no suspended primary thread.");
        }

        if (ResumeThread(thread) == uint.MaxValue)
        {
            throw LastWin32Error("ResumeThread");
        }

        Interlocked.Exchange(ref _suspendedThread, null)?.Dispose();
    }

    private void AbortStartup()
    {
        var job = Volatile.Read(ref _job);
        var process = Volatile.Read(ref _processHandle);
        if (job is not null && !job.IsInvalid && !job.IsClosed)
        {
            TerminateJobObject(job, StartupFailureExitCode);
        }

        if (process is not null && !process.IsInvalid && !process.IsClosed)
        {
            TerminateProcess(process, StartupFailureExitCode);
        }

        var processExited = process is null || WaitForSingleObject(
            process,
            (uint)StartupCleanupTimeout.TotalMilliseconds) == WaitObject;
        var jobEmpty = job is null || WaitForJobEmpty(job, StartupCleanupTimeout);

        Interlocked.Exchange(ref _suspendedThread, null)?.Dispose();
        Interlocked.Exchange(ref _job, null)?.Dispose();
        Interlocked.Exchange(ref _processHandle, null)?.Dispose();

        if (!processExited || !jobEmpty)
        {
            throw new InvalidOperationException(
                "Native mount host startup cleanup could not prove the exact process and job were empty.");
        }
    }

    private static void TryTerminateAndProveExit(
        SafeKernelHandle? job,
        SafeProcessHandle process)
    {
        if (job is not null && !job.IsInvalid && !job.IsClosed)
        {
            TerminateJobObject(job, StartupFailureExitCode);
        }

        TerminateProcess(process, StartupFailureExitCode);
        var processExited = WaitForSingleObject(
            process,
            (uint)StartupCleanupTimeout.TotalMilliseconds) == WaitObject;
        var jobEmpty = job is null || WaitForJobEmpty(job, StartupCleanupTimeout);
        if (!processExited || !jobEmpty)
        {
            throw new InvalidOperationException(
                "Native mount host startup cleanup could not prove the exact process and job were empty.");
        }
    }

    private static bool WaitForJobEmpty(SafeKernelHandle job, TimeSpan timeout)
    {
        var started = Stopwatch.StartNew();
        while (true)
        {
            var accounting = default(JobObjectBasicAccountingInformationStruct);
            if (!QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformationClass,
                    ref accounting,
                    (uint)Marshal.SizeOf<JobObjectBasicAccountingInformationStruct>(),
                    out _))
            {
                return false;
            }

            if (accounting.ActiveProcesses == 0)
            {
                return true;
            }

            if (started.Elapsed >= timeout)
            {
                return false;
            }

            Thread.Sleep(10);
        }
    }

    public bool TryTerminate(uint exitCode)
    {
        var job = Volatile.Read(ref _job);
        if (job is not null && !job.IsInvalid && !job.IsClosed)
        {
            try
            {
                return TerminateJobObject(job, exitCode);
            }
            catch
            {
                return false;
            }
        }

        var process = Volatile.Read(ref _processHandle);
        if (process is null || process.IsInvalid || process.IsClosed)
        {
            return false;
        }

        try
        {
            return TerminateProcess(process, exitCode);
        }
        catch
        {
            return false;
        }
    }

    public bool WaitForEmpty(TimeSpan timeout)
    {
        if (timeout < TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var job = Volatile.Read(ref _job);
        if (job is null || job.IsInvalid || job.IsClosed)
        {
            return false;
        }

        var stopwatch = Stopwatch.StartNew();
        var observedEmpty = false;
        while (true)
        {
            try
            {
                var accounting = default(JobObjectBasicAccountingInformationStruct);
                if (!QueryInformationJobObject(
                        job,
                        JobObjectBasicAccountingInformationClass,
                        ref accounting,
                        (uint)Marshal.SizeOf<JobObjectBasicAccountingInformationStruct>(),
                        out _))
                {
                    return false;
                }

                if (accounting.ActiveProcesses == 0)
                {
                    if (observedEmpty)
                    {
                        return true;
                    }

                    observedEmpty = true;
                }
                else
                {
                    observedEmpty = false;
                }
            }
            catch (ObjectDisposedException)
            {
                return false;
            }

            if (timeout != Timeout.InfiniteTimeSpan && stopwatch.Elapsed >= timeout)
            {
                return false;
            }

            Thread.Sleep(10);
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _job, null)?.Dispose();
        Interlocked.Exchange(ref _suspendedThread, null)?.Dispose();
        Interlocked.Exchange(ref _processHandle, null)?.Dispose();
    }

    private static Win32Exception LastWin32Error(string operation)
    {
        var error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"{operation} failed with Win32 error {error}.");
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint CreateJobObjectW(nint jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeKernelHandle job,
        uint informationClass,
        ref JobObjectExtendedLimitInformationStruct limits,
        uint limitsLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(
        SafeKernelHandle job,
        SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeKernelHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle process,
        out FileTime creationTime,
        out FileTime exitTime,
        out FileTime kernelTime,
        out FileTime userTime);

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string? applicationName,
        StringBuilder commandLine,
        nint processAttributes,
        nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        nint environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeKernelHandle job,
        uint informationClass,
        ref JobObjectBasicAccountingInformationStruct accounting,
        uint accountingLength,
        out uint returnLength);

    private sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeKernelHandle()
            : base(ownsHandle: true)
        {
        }

        public SafeKernelHandle(nint handle)
            : base(ownsHandle: true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(nint handle);
    }

    private sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeThreadHandle(nint handle)
            : base(ownsHandle: true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(nint handle);
    }

    private sealed class SuspendedProcess : IDisposable
    {
        private SafeProcessHandle? _processHandle;
        private SafeThreadHandle? _threadHandle;

        private SuspendedProcess(
            SafeProcessHandle processHandle,
            SafeThreadHandle threadHandle,
            uint processId)
        {
            _processHandle = processHandle;
            _threadHandle = threadHandle;
            ProcessId = processId;
        }

        public uint ProcessId { get; }

        public SafeProcessHandle ProcessHandle
            => _processHandle ?? throw new ObjectDisposedException(nameof(SuspendedProcess));

        public static SuspendedProcess Create(ProcessStartInfo startInfo)
        {
            if (startInfo.UseShellExecute)
            {
                throw new InvalidOperationException(
                    "Suspended native host startup requires UseShellExecute=false.");
            }

            if (startInfo.RedirectStandardInput ||
                startInfo.RedirectStandardOutput ||
                startInfo.RedirectStandardError)
            {
                throw new InvalidOperationException(
                    "Suspended native host startup does not support redirected standard streams.");
            }

            var commandLine = BuildCommandLine(startInfo);
            var environmentBlock = BuildEnvironmentBlock(startInfo.Environment);
            var environmentPointer = Marshal.StringToHGlobalUni(environmentBlock);
            try
            {
                var startupInfo = new StartupInfo
                {
                    Size = Marshal.SizeOf<StartupInfo>(),
                };
                var creationFlags = CreateSuspended | CreateUnicodeEnvironment;
                if (startInfo.CreateNoWindow)
                {
                    creationFlags |= CreateNoWindow;
                }

                if (!CreateProcessW(
                        startInfo.FileName,
                        commandLine,
                        nint.Zero,
                        nint.Zero,
                        inheritHandles: false,
                        creationFlags,
                        environmentPointer,
                        string.IsNullOrWhiteSpace(startInfo.WorkingDirectory)
                            ? null
                            : startInfo.WorkingDirectory,
                        ref startupInfo,
                        out var processInformation))
                {
                    throw LastWin32Error("CreateProcessW");
                }

                if (processInformation.ProcessHandle == nint.Zero ||
                    processInformation.ThreadHandle == nint.Zero)
                {
                    if (processInformation.ProcessHandle != nint.Zero)
                    {
                        CloseHandle(processInformation.ProcessHandle);
                    }

                    if (processInformation.ThreadHandle != nint.Zero)
                    {
                        CloseHandle(processInformation.ThreadHandle);
                    }

                    throw new InvalidOperationException(
                        "CreateProcessW returned incomplete process handles.");
                }

                return new SuspendedProcess(
                    new SafeProcessHandle(processInformation.ProcessHandle, ownsHandle: true),
                    new SafeThreadHandle(processInformation.ThreadHandle),
                    processInformation.ProcessId);
            }
            finally
            {
                Marshal.FreeHGlobal(environmentPointer);
            }
        }

        public SafeProcessHandle DetachProcessHandle()
            => Interlocked.Exchange(ref _processHandle, null)
               ?? throw new ObjectDisposedException(nameof(SuspendedProcess));

        public SafeThreadHandle DetachThreadHandle()
            => Interlocked.Exchange(ref _threadHandle, null)
               ?? throw new ObjectDisposedException(nameof(SuspendedProcess));

        public void AbortStartup()
        {
            var process = _processHandle;
            if (process is null)
            {
                return;
            }

            TerminateProcess(process, StartupFailureExitCode);
            var processExited = WaitForSingleObject(
                process,
                (uint)StartupCleanupTimeout.TotalMilliseconds) == WaitObject;
            Dispose();
            if (!processExited)
            {
                throw new InvalidOperationException(
                    "Native mount host startup cleanup could not prove the exact process exited.");
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _threadHandle, null)?.Dispose();
            Interlocked.Exchange(ref _processHandle, null)?.Dispose();
        }

        private static StringBuilder BuildCommandLine(ProcessStartInfo startInfo)
        {
            var arguments = startInfo.ArgumentList.Count > 0
                ? string.Join(" ", startInfo.ArgumentList.Select(QuoteArgument))
                : startInfo.Arguments;
            var commandLine = QuoteArgument(startInfo.FileName);
            if (!string.IsNullOrEmpty(arguments))
            {
                commandLine += " " + arguments;
            }

            return new StringBuilder(commandLine, commandLine.Length + 1);
        }

        private static string BuildEnvironmentBlock(
            System.Collections.Generic.IDictionary<string, string?> environment)
        {
            var entries = environment
                .Where(static pair => pair.Key.IndexOf('\0') < 0 &&
                                      pair.Value is not null &&
                                      pair.Value.IndexOf('\0') < 0)
                .Select(static pair => $"{pair.Key}={pair.Value ?? string.Empty}")
                .OrderBy(static entry => entry, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return string.Join('\0', entries) + "\0\0";
        }

        private static string QuoteArgument(string argument)
        {
            if (argument.Length == 0)
            {
                return "\"\"";
            }

            var needsQuotes = argument.Any(static character =>
                char.IsWhiteSpace(character) || character == '\"');
            if (!needsQuotes)
            {
                return argument;
            }

            var builder = new StringBuilder(argument.Length + 2);
            builder.Append('\"');
            var backslashes = 0;
            foreach (var character in argument)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (character == '\"')
                {
                    builder.Append('\\', backslashes * 2 + 1);
                    builder.Append('\"');
                    backslashes = 0;
                    continue;
                }

                builder.Append('\\', backslashes);
                builder.Append(character);
                backslashes = 0;
            }

            builder.Append('\\', backslashes * 2);
            builder.Append('\"');
            return builder.ToString();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2;
        public nint Reserved2Pointer;
        public nint StandardInput;
        public nint StandardOutput;
        public nint StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint ProcessHandle;
        public nint ThreadHandle;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    private static bool TryGetProcessCreationTime(
        SafeProcessHandle process,
        out long creationTimeFileTimeUtc)
    {
        creationTimeFileTimeUtc = 0;
        if (!GetProcessTimes(
                process,
                out var creationTime,
                out _,
                out _,
                out _))
        {
            return false;
        }

        creationTimeFileTimeUtc = ((long)creationTime.HighDateTime << 32) |
                                   creationTime.LowDateTime;
        return true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformationStruct
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicAccountingInformationStruct
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
}

internal sealed class HostProcessLifecycleTestHooks
{
    public Func<ProcessStartInfo, Process?>? StartProcess { get; set; }

    public Func<Process, HostStartupGate, HostProcessGuardian>? CreateGuardian { get; set; }

    public Func<Process, TimeSpan, bool>? WaitForExit { get; set; }

    public Func<Process, bool>? KillProcess { get; set; }

    public Func<int, bool?>? ProbeSystemProcessPresence { get; set; }

    public Func<int, bool?>? ProbeFallbackSystemProcessPresence { get; set; }

    public Func<Process, bool?>? ProbeExactProcessHandleExit { get; set; }

    public Func<int, long?>? ProbeProcessCreationTime { get; set; }

    public Action<Process>? BeforeObserverProof { get; set; }

    public Action<string>? OnLifecycleDiagnostic { get; set; }
}
