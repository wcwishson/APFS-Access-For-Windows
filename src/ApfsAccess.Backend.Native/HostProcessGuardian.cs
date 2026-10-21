using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

// The service owns one guardian for every FsHost. Closing the job handle is an
// OS-level fallback that terminates the child if the service itself exits while
// the host is stuck in WinFsp teardown.
internal sealed partial class HostProcessGuardian : IDisposable
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
    private long _creationTimeFileTimeUtc;
    private readonly object _ownershipSync = new();
    private readonly HostGuardianCleanupTestHooks? _cleanupHooks = CleanupTestHooks.Value;
    private readonly TaskCompletionSource _ownershipReleased = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool _disposeRequested;
    private bool _keeperRunning;
    private uint _terminationExitCode = StartupFailureExitCode;
    internal static readonly AsyncLocal<HostGuardianCleanupTestHooks?> CleanupTestHooks = new();

    private HostProcessGuardian(
        SafeKernelHandle? job,
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

    internal Task OwnershipReleased => _ownershipReleased.Task;

    internal bool TryGetActiveProcessCount(out uint activeProcesses)
    {
        lock (_ownershipSync)
        {
            return TryReadActiveProcessCount(out activeProcesses);
        }
    }

    private bool TryReadActiveProcessCount(out uint activeProcesses)
    {
        activeProcesses = 0;
        var job = _job;
        if (job is null || job.IsInvalid || job.IsClosed) return false;
        if (_cleanupHooks?.ActiveProcessCount is { } query)
        {
            var count = query(job);
            activeProcesses = count.GetValueOrDefault();
            return count.HasValue;
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
        public LaunchResult(Process process, HostProcessGuardian? guardian, HostStartupStderr? startupStderr = null)
        {
            Process = process;
            Guardian = guardian;
            StartupStderr = startupStderr;
        }

        public Process Process { get; }

        public HostProcessGuardian? Guardian { get; }

        public HostStartupStderr? StartupStderr { get; }
    }

    internal static LaunchResult StartWithCredential(ProcessStartInfo startInfo, HostStartupGate startupGate, SafeFileHandle? input)
        => StartCore(startInfo, startupGate, null, input);

    internal static LaunchResult StartWithStreams(ProcessStartInfo startInfo, HostStartupGate startupGate,
        SafeHandle input, SafeHandle output)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (input.IsInvalid || input.IsClosed || output.IsInvalid || output.IsClosed)
            throw new ArgumentException("Open native byte-pipe endpoints are required.");
        if (GetNativeStreamFileType(input) != 3 || GetNativeStreamFileType(output) != 3)
            throw new ArgumentException("Native standard transport requires byte pipes.");
        return StartCore(startInfo, startupGate, null, input, output);
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
        Action<uint>? processCreated, SafeHandle? credentialInput = null, SafeHandle? standardOutput = null)
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

        using var suspended = SuspendedProcess.Create(startInfo, credentialInput, standardOutput);
        Process? processObject = null;
        HostProcessGuardian? guardian = null;
        try
        {
            processCreated?.Invoke(suspended.ProcessId);

            // The process is still suspended here, so resolving the public
            // Process wrapper by PID cannot race with PID reuse or child code.
            processObject = Process.GetProcessById(checked((int)suspended.ProcessId));
            // Retain the wrapper handle before an immediately exiting child runs.
            _ = processObject.SafeHandle;
            guardian = Create(suspended, startupGate);
            guardian.ResumeSuspendedProcess();
            return new LaunchResult(processObject, guardian, suspended.DetachStartupStderr());
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

        if (!DuplicateHandle(-1, process.SafeHandle, -1, out var originalHandle, 0, false, 2))
        {
            throw LastWin32Error("DuplicateHandle(original process)");
        }
        var guardian = new HostProcessGuardian(null, originalHandle, processId: GetProcessId(originalHandle));
        try
        {
            if (guardian.ProcessId == 0 ||
                !TryGetProcessCreationTime(originalHandle, out guardian._creationTimeFileTimeUtc))
            {
                throw LastWin32Error("Capture original process identity");
            }
            guardian._job = CreateConfiguredJob();
            // Use the handle returned for this exact Process.Start instance.
            // Reopening by PID would allow PID reuse between launch and job
            // assignment to target an unrelated process.
            if (!AssignProcessToJobObject(guardian._job, originalHandle))
            {
                throw LastWin32Error("AssignProcessToJobObject");
            }

            return guardian;
        }
        catch (Exception error)
        {
            guardian.AbortFailedStartup(error);
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
        catch (Exception error)
        {
            guardian.AbortFailedStartup(error);
            throw;
        }
    }

    private static HostProcessGuardian Create(
        SuspendedProcess suspended,
        HostStartupGate startupGate)
    {
        var guardian = new HostProcessGuardian(
            null,
            suspended.DetachProcessHandle(),
            suspended.DetachThreadHandle(),
            suspended.ProcessId);
        try
        {
            if (!TryGetProcessCreationTime(
                    guardian._processHandle!,
                    out guardian._creationTimeFileTimeUtc))
            {
                throw LastWin32Error("GetProcessTimes");
            }

            guardian._job = CreateConfiguredJob();
            if (!AssignProcessToJobObject(guardian._job, guardian._processHandle!))
            {
                throw LastWin32Error("AssignProcessToJobObject");
            }

            // Authorization is still part of the suspended transaction. The
            // host cannot observe or consume this gate until ResumeThread.
            startupGate.Authorize();
            return guardian;
        }
        catch (Exception error)
        {
            guardian.AbortFailedStartup(error);
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

    private void AbortFailedStartup(Exception error)
    {
        try
        {
            AbortStartup();
        }
        catch (Exception cleanup)
        {
            throw new AggregateException(
                "Native mount host startup failed and exact process cleanup could not be proven.", error, cleanup);
        }
    }

    private void AbortStartup()
    {
        var proven = false;
        try
        {
            TryTerminate(StartupFailureExitCode);
            var started = Stopwatch.StartNew();
            do
            {
                lock (_ownershipSync)
                {
                    proven = TryProveOwnershipReleased();
                }
                if (proven) break;
                Thread.Sleep(10);
            }
            while (started.Elapsed < (_cleanupHooks?.StartupCleanupTimeout ?? StartupCleanupTimeout));
        }
        finally
        {
            Dispose();
        }
        if (!proven)
        {
            throw new InvalidOperationException(
                "Native mount host startup cleanup could not prove the exact process and job were empty.");
        }
    }

    private int? _observedExitCode;

    internal bool TryObserveProcessExit(out int? exitCode)
    {
        lock (_ownershipSync)
        {
            exitCode = _observedExitCode;
            if (_ownershipReleased.Task.IsCompleted) return true;
            try
            {
                var process = _processHandle;
                if (process is null || process.IsClosed || process.IsInvalid || _processId == 0 ||
                    !(_cleanupHooks?.OriginalHandleSignaled?.Invoke(process) ?? WaitForSingleObject(process, 0) == WaitObject))
                    return false;
                if (GetExitCodeProcess(process, out var nativeCode))
                    exitCode = _observedExitCode = unchecked((int)nativeCode);
                var absent = _cleanupHooks?.OriginalIdentityAbsent is { } probe
                    ? probe(_processId, _creationTimeFileTimeUtc)
                    : TryObserveOriginalPidAbsence(_processId);
                if (absent == true) return true;
                if (absent != false || _creationTimeFileTimeUtc <= 0) return false;
                var currentCreation = _cleanupHooks?.CurrentProcessCreationTime is { } currentProbe
                    ? currentProbe(_processId)
                    : ObserveCurrentProcessCreationTime(_processId);
                return currentCreation > 0 && currentCreation != _creationTimeFileTimeUtc;
            }
            catch { return false; }
        }
    }

    internal bool IsSettled
    {
        get { lock (_ownershipSync) return _ownershipReleased.Task.IsCompleted || TryProveOwnershipReleased(); }
    }

    private static long? ObserveCurrentProcessCreationTime(uint processId)
    {
        // Query-only observation of a reused row. Enforcement never uses this handle.
        using var current = OpenProcess(0x1000, false, processId);
        return !current.IsInvalid && TryGetProcessCreationTime(current, out var creation) ? creation : null;
    }

    public bool TryTerminate(uint exitCode)
    {
        lock (_ownershipSync)
        {
            _terminationExitCode = exitCode;
            var terminated = TryTerminateOnce(exitCode);
            if (!_ownershipReleased.Task.IsCompleted && !TryProveOwnershipReleased()) StartKeeper();
            return terminated;
        }
    }

    private bool TryTerminateOnce(uint exitCode)
    {
        var terminated = false;
        try
        {
            if (_job is { IsInvalid: false, IsClosed: false } job)
                terminated = _cleanupHooks?.TerminateJob?.Invoke(job, exitCode) ?? TerminateJobObject(job, exitCode);
        }
        catch { }
        try
        {
            if (_processHandle is { IsInvalid: false, IsClosed: false } process)
                terminated |= _cleanupHooks?.TerminateProcess?.Invoke(process, exitCode) ?? TerminateProcess(process, exitCode);
        }
        catch { }
        return terminated;
    }

    public bool WaitForEmpty(TimeSpan timeout)
    {
        if (timeout < TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var stopwatch = Stopwatch.StartNew();
        var observedEmpty = false;
        while (true)
        {
            lock (_ownershipSync)
            {
                if (_job is null || _job.IsClosed || _job.IsInvalid) return false;
                if (TryProveOwnershipReleased())
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
            if (timeout != Timeout.InfiniteTimeSpan && stopwatch.Elapsed >= timeout)
            {
                return false;
            }

            Thread.Sleep(10);
        }
    }

    public void Dispose()
    {
        lock (_ownershipSync)
        {
            if (_disposeRequested) return;
            _disposeRequested = true;
            if (TryProveOwnershipReleased())
            {
                ReleaseProvenOwnership();
                return;
            }
            TryTerminateOnce(_terminationExitCode);
            if (TryProveOwnershipReleased())
            {
                ReleaseProvenOwnership();
                return;
            }
            StartKeeper();
        }
    }

    private void StartKeeper()
    {
        if (_keeperRunning) return;
        _keeperRunning = true;
        // Keep the service process and the original handles alive while
        // enforcement is unresolved. Only original handles can terminate; PID
        // row queries above are observation-only. There is no lease process.
        try
        {
            new Thread(KeepOwnershipUntilProven)
            {
                IsBackground = false,
                Name = "APFS host ownership keeper",
            }.Start();
        }
        catch
        {
            // If a thread cannot be created, this owner must keep enforcing.
            KeepOwnershipUntilProven();
        }
    }

    private void KeepOwnershipUntilProven()
    {
        while (true)
        {
            lock (_ownershipSync)
            {
                if (_ownershipReleased.Task.IsCompleted)
                {
                    _keeperRunning = false;
                    return;
                }
                TryTerminateOnce(_terminationExitCode);
                if (TryProveOwnershipReleased())
                {
                    _keeperRunning = false;
                    if (_disposeRequested) ReleaseProvenOwnership();
                    return;
                }
            }
            Thread.Sleep(100);
        }
    }

    private bool TryProveOwnershipReleased()
    {
        try
        {
            if (!TryObserveProcessExit(out _)) return false;
            return _job is null || (TryReadActiveProcessCount(out var count) && count == 0);
        }
        catch
        {
            return false;
        }
    }

    private void ReleaseProvenOwnership()
    {
        Interlocked.Exchange(ref _job, null)?.Dispose();
        Interlocked.Exchange(ref _suspendedThread, null)?.Dispose();
        Interlocked.Exchange(ref _processHandle, null)?.Dispose();
        _ownershipReleased.TrySetResult();
    }

    private static bool? TryObserveOriginalPidAbsence(uint processId)
    {
        // PID absence is a conservative identity proof. Enumeration never
        // opens a process handle, including when a PID row remains visible.
        for (var capacity = 1024; capacity <= 1_048_576; capacity *= 2)
        {
            var ids = new uint[capacity];
            var bytes = checked((uint)(ids.Length * sizeof(uint)));
            if (!EnumProcesses(ids, bytes, out var needed)) return null;
            if (needed >= bytes) continue;
            if (needed % sizeof(uint) != 0) return null;
            return !ids.AsSpan(0, checked((int)(needed / sizeof(uint)))).Contains(processId);
        }
        return null;
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
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(nint sourceProcess, SafeProcessHandle source, nint targetProcess,
        out SafeProcessHandle target, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumProcesses([Out] uint[] processIds, uint bytes, out uint needed);

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
        private HostStartupStderr? _startupStderr;

        private SuspendedProcess(
            SafeProcessHandle processHandle,
            SafeThreadHandle threadHandle,
            uint processId,
            HostStartupStderr? startupStderr)
        {
            _processHandle = processHandle;
            _threadHandle = threadHandle;
            ProcessId = processId;
            _startupStderr = startupStderr;
        }

        public uint ProcessId { get; }

        public SafeProcessHandle ProcessHandle
            => _processHandle ?? throw new ObjectDisposedException(nameof(SuspendedProcess));

        public HostStartupStderr? DetachStartupStderr()
            => Interlocked.Exchange(ref _startupStderr, null);

        public static SuspendedProcess Create(ProcessStartInfo startInfo, SafeHandle? credentialInput = null,
            SafeHandle? standardOutput = null)
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
            AnonymousPipeServerStream? stderrPipe = null;
            try
            {
                if (credentialInput is null || standardOutput is not null)
                {
                    stderrPipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
                }
                var creationFlags = CreateSuspended | CreateUnicodeEnvironment;
                if (startInfo.CreateNoWindow)
                {
                    creationFlags |= CreateNoWindow;
                }

                ProcessInformation processInformation;
                var created = CreateRestrictedProcess(
                    startInfo, commandLine, environmentPointer, creationFlags,
                    credentialInput, stderrPipe?.ClientSafePipeHandle, out processInformation, standardOutput);
                if (!created)
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

                var suspended = new SuspendedProcess(
                    new SafeProcessHandle(processInformation.ProcessHandle, ownsHandle: true),
                    new SafeThreadHandle(processInformation.ThreadHandle),
                    processInformation.ProcessId,
                    startupStderr: null);
                try
                {
                    stderrPipe?.DisposeLocalCopyOfClientHandle();
                    suspended._startupStderr = stderrPipe is null ? null : HostStartupStderr.Start(stderrPipe);
                    return suspended;
                }
                catch
                {
                    suspended.AbortStartup();
                    throw;
                }
            }
            catch
            {
                stderrPipe?.Dispose();
                throw;
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

            var guardian = new HostProcessGuardian(null, DetachProcessHandle(), DetachThreadHandle(), ProcessId);
            TryGetProcessCreationTime(process, out guardian._creationTimeFileTimeUtc);
            guardian.AbortStartup();
        }

        public void Dispose()
        {
            try
            {
                AbortStartup();
            }
            finally
            {
                Interlocked.Exchange(ref _startupStderr, null)?.Dispose();
            }
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

internal sealed class HostGuardianCleanupTestHooks
{
    public Func<SafeHandle, uint, bool>? TerminateJob { get; init; }
    public Func<SafeProcessHandle, uint, bool>? TerminateProcess { get; init; }
    public Func<SafeProcessHandle, bool>? OriginalHandleSignaled { get; init; }
    public Func<uint, long, bool?>? OriginalIdentityAbsent { get; init; }
    public Func<uint, long?>? CurrentProcessCreationTime { get; init; }
    public Func<SafeHandle, uint?>? ActiveProcessCount { get; init; }
    public TimeSpan? StartupCleanupTimeout { get; init; }
}

internal sealed class HostProcessLifecycleTestHooks
{
    public Func<string, ServiceHostOptions, string?>? SourceAdmission { get; set; }

    public Func<ProcessStartInfo, Process?>? StartProcess { get; set; }

    public Func<Process, HostStartupGate, HostProcessGuardian>? CreateGuardian { get; set; }

    public Func<Process, TimeSpan, bool>? WaitForExit { get; set; }

    public Func<Process, CancellationToken, Task>? WaitForExitAsync { get; set; }

    public Func<Process, bool>? KillProcess { get; set; }

    public Func<int, bool?>? ProbeSystemProcessPresence { get; set; }

    public Func<int, bool?>? ProbeFallbackSystemProcessPresence { get; set; }

    public Func<Process, bool?>? ProbeExactProcessHandleExit { get; set; }

    public Func<int, long?>? ProbeProcessCreationTime { get; set; }

    public Action<Process>? BeforeObserverProof { get; set; }

    public Action<string>? OnLifecycleDiagnostic { get; set; }

    public Func<string, bool>? IsMountVisible { get; set; }

    public Func<string, int, (uint Length, int Error)>? QueryDosDevice { get; set; }

    public Func<string, (uint Attributes, int Error)>? QueryMountAttributes { get; set; }
}

internal sealed class HostStartupStderr : IDisposable
{
    private const int MaxTailCharacters = 8192;
    private readonly Stream _stream;
    private readonly StringBuilder _tail = new();
    private readonly object _sync = new();
    private readonly Task _drain;

    private HostStartupStderr(Stream stream)
    {
        _stream = stream;
        _drain = DrainAsync();
    }

    public static HostStartupStderr Start(Stream stream) => new(stream);

    public async Task<string?> GetLastLineAsync()
    {
        await Task.WhenAny(_drain, Task.Delay(250)).ConfigureAwait(false);
        lock (_sync)
        {
            var lines = _tail.ToString().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            return lines.LastOrDefault(static line => !string.IsNullOrWhiteSpace(line))?.Trim();
        }
    }

    private async Task DrainAsync()
    {
        try
        {
            using var reader = new StreamReader(_stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
                bufferSize: 1024, leaveOpen: true);
            var buffer = new char[1024];
            int read;
            while ((read = await reader.ReadAsync(buffer).ConfigureAwait(false)) > 0)
            {
                lock (_sync)
                {
                    _tail.Append(buffer, 0, read);
                    if (_tail.Length > MaxTailCharacters)
                    {
                        _tail.Remove(0, _tail.Length - MaxTailCharacters);
                    }
                }
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    public void Dispose() => _stream.Dispose();
}
