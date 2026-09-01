using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

internal sealed record PackagedServiceStartedProcess(
    int ProcessId,
    long StartTimeUtcTicks,
    string ImagePath,
    PackagedServicePackageIdentity Package);

internal sealed class PackagedServiceStartup : IDisposable
{
    private readonly object _sync = new();
    private SafeFileHandle? _process;
    private SafeFileHandle? _job;
    private bool _transferred;

    internal PackagedServiceStartup(
        PackagedServiceStartedProcess started,
        SafeFileHandle process,
        SafeFileHandle job)
    {
        Started = started;
        _process = process;
        _job = job;
    }

    internal PackagedServiceStartedProcess Started { get; }

    internal void TransferOwnership()
    {
        lock (_sync)
        {
            if (_transferred)
            {
                return;
            }

            var process = _process
                ?? throw new ObjectDisposedException(nameof(PackagedServiceStartup));
            var job = _job
                ?? throw new ObjectDisposedException(nameof(PackagedServiceStartup));
            PackagedServiceLauncher.TransferStartupOwnership(Started, process, job);
            _transferred = true;
            ReleaseHandles();
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_process is null && _job is null)
            {
                return;
            }

            try
            {
                if (!_transferred)
                {
                    PackagedServiceLauncher.TerminateStartupAndProveEmpty(
                        _process
                            ?? throw new CliElevationUnsafeOwnershipException(
                                "The provisional packaged service process handle is missing."),
                        _job
                            ?? throw new CliElevationUnsafeOwnershipException(
                                "The provisional packaged service job handle is missing."));
                }
            }
            finally
            {
                ReleaseHandles();
            }
        }
    }

    private void ReleaseHandles()
    {
        _process?.Dispose();
        _process = null;
        _job?.Dispose();
        _job = null;
    }
}

internal static class PackagedServiceLauncher
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint CreateBreakawayFromJob = 0x01000000;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint WaitObject0 = 0x00000000;
    private const int JobObjectBasicProcessIdList = 3;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint DuplicateSameAccess = 0x00000002;
    private const int ErrorInsufficientBuffer = 122;
    private static readonly IntPtr ProcThreadAttributeHandleList = new(0x00020002);
    private static readonly HashSet<string> AllowedApplicationEnvironmentVariables = new(
        new[]
        {
            "APFSACCESS_PORTABLE_ROOT",
            "APFSACCESS_RUNTIME_ROOT",
            "APFSACCESS_SPOOL_ROOT",
            "APFSACCESS_TRACE_MOVES",
            "APFSACCESS_PERF_COUNTERS",
            "APFSACCESS_TRACE_COMMITS",
            "APFSACCESS_TRACE_READS",
            "APFSACCESS_DEFER_CLOSE_COMMITS",
            "APFSACCESS_DISABLE_CONTENT_WRITEBACK",
            "APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE",
            "APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE",
            "APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE",
            "APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK",
            "APFSACCESS_DISABLE_NAMESPACE_WRITEBACK",
            "APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
            "APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
            "APFSACCESS_CHECKPOINT_DELTA_SHADOW",
            "APFSACCESS_STRICT_COMMIT_VERIFY",
            "APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE",
            "APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE",
            "APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX",
            "APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE",
            "APFSACCESS_DISABLE_INDEX_DELTA",
        },
        StringComparer.OrdinalIgnoreCase);

    internal static int Start(ProcessStartInfo startInfo)
        => StartVerified(startInfo).ProcessId;

    internal static PackagedServiceStartedProcess StartVerified(ProcessStartInfo startInfo)
    {
        using var startup = StartOwned(startInfo);
        startup.TransferOwnership();
        return startup.Started;
    }

    internal static PackagedServiceStartup StartOwned(ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Packaged APFS service startup requires Windows.");
        }

        if (startInfo.UseShellExecute)
        {
            throw new ArgumentException("Packaged service startup cannot use shell execution.", nameof(startInfo));
        }

        PackagedServicePackageLease? packageLease = PackagedServicePackageLease.Acquire(startInfo.FileName);
        var applicationPath = packageLease.Identity.AppHost.CanonicalPath;
        var workingDirectory = string.IsNullOrWhiteSpace(startInfo.WorkingDirectory)
            ? Path.GetDirectoryName(applicationPath) ?? AppContext.BaseDirectory
            : Path.GetFullPath(startInfo.WorkingDirectory);
        var packageDirectory = Path.GetDirectoryName(applicationPath)
            ?? throw new CliElevationValidationException("The packaged service directory is unavailable.");
        if (!string.Equals(workingDirectory, packageDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new CliElevationValidationException("Packaged service startup requires its canonical package directory.");
        }

        var commandLine = new StringBuilder(BuildCommandLine(startInfo, applicationPath));

        using var standardInput = OpenNullHandle(GenericRead);
        using var standardOutput = OpenNullHandle(GenericWrite);
        using var standardError = OpenNullHandle(GenericWrite);

        var handles = new[]
        {
            standardInput.DangerousGetHandle(),
            standardOutput.DangerousGetHandle(),
            standardError.DangerousGetHandle(),
        };
        var startupInfo = new StartupInfoEx
        {
            StartupInfo = new StartupInfo
            {
                Size = Marshal.SizeOf<StartupInfoEx>(),
                Flags = StartfUseStdHandles,
                StandardInput = handles[0],
                StandardOutput = handles[1],
                StandardError = handles[2],
            },
        };

        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        var attributeListInitialized = false;
        var processInformation = default(ProcessInformation);
        var processCreated = false;
        var processResumed = false;
        SafeFileHandle? startupJob = null;

        try
        {
            nuint attributeListSize = 0;
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeListSize);
            var sizeError = Marshal.GetLastWin32Error();
            if (attributeListSize == 0 || sizeError != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(sizeError, "Could not size the packaged-service handle list.");
            }

            attributeList = Marshal.AllocHGlobal(checked((nint)attributeListSize));
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not initialize the packaged-service handle list.");
            }

            attributeListInitialized = true;
            handleList = Marshal.AllocHGlobal(checked(handles.Length * IntPtr.Size));
            for (var index = 0; index < handles.Length; index++)
            {
                Marshal.WriteIntPtr(handleList, index * IntPtr.Size, handles[index]);
            }

            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    handleList,
                    checked((nuint)(handles.Length * IntPtr.Size)),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not restrict packaged-service handle inheritance.");
            }

            startupInfo.AttributeList = attributeList;
            environmentBlock = BuildEnvironmentBlock(startInfo.Environment, packageDirectory);
            startupJob = CreateStartupJob();
            if (!CreateProcessW(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CreateNoWindow |
                    CreateSuspended |
                    CreateUnicodeEnvironment |
                    ExtendedStartupInfoPresent |
                    CreateBreakawayFromJob,
                    environmentBlock,
                    workingDirectory,
                    ref startupInfo,
                    out processInformation))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not start packaged service '{applicationPath}'.");
            }

            processCreated = true;
            if (!AssignProcessToJobObject(startupJob, processInformation.Process))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not bind the provisional packaged service to its startup job.");
            }

            var started = CaptureAndValidateStartedProcess(processInformation, packageLease.Identity);
            packageLease.Revalidate();
            DuplicatePackageLeaseHandles(packageLease.LeaseHandles, processInformation.Process);
            packageLease.Dispose();
            packageLease = null;
            if (ResumeThread(processInformation.Thread) == uint.MaxValue)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not resume packaged service '{applicationPath}'.");
            }

            processResumed = true;
            var ownedProcess = new SafeFileHandle(processInformation.Process, ownsHandle: true);
            processInformation.Process = IntPtr.Zero;
            var ownedJob = startupJob;
            startupJob = null;
            return new PackagedServiceStartup(started, ownedProcess, ownedJob);
        }
        catch (Exception ex)
        {
            if (processCreated && !processResumed)
            {
                try
                {
                    TerminateSuspendedProcessAndProveExit(processInformation.Process);
                }
                catch (Exception cleanupException)
                {
                    throw new CliElevationUnsafeOwnershipException(
                        "The rejected packaged service process could not be proven absent.",
                        new AggregateException(ex, cleanupException));
                }
            }

            throw;
        }
        finally
        {
            packageLease?.Dispose();
            startupJob?.Dispose();
            if (processInformation.Thread != IntPtr.Zero)
            {
                _ = CloseHandle(processInformation.Thread);
            }

            if (processInformation.Process != IntPtr.Zero)
            {
                _ = CloseHandle(processInformation.Process);
            }

            if (environmentBlock != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(environmentBlock);
            }

            if (attributeListInitialized)
            {
                DeleteProcThreadAttributeList(attributeList);
            }

            if (handleList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handleList);
            }

            if (attributeList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attributeList);
            }
        }
    }

    private static SafeFileHandle CreateStartupJob()
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            job.Dispose();
            throw new Win32Exception(error, "Could not create the provisional packaged-service job.");
        }

        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose,
            },
        };
        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                ref limits,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            var error = Marshal.GetLastWin32Error();
            job.Dispose();
            throw new Win32Exception(error, "Could not make the packaged-service startup job fail closed.");
        }

        return job;
    }

    internal static void TransferStartupOwnership(
        PackagedServiceStartedProcess started,
        SafeFileHandle process,
        SafeFileHandle job)
    {
        ValidateStartedProcessHandle(started, process);
        if (WaitForSingleObject(process.DangerousGetHandle(), 0) == WaitObject0)
        {
            throw new CliElevationUnsafeOwnershipException(
                "The packaged service exited before startup ownership could be transferred.");
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                job.DangerousGetHandle(),
                process.DangerousGetHandle(),
                out _,
                0,
                false,
                DuplicateSameAccess))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not transfer the packaged-service lifecycle job to the ready service.");
        }
    }

    internal static void TerminateStartupAndProveEmpty(
        SafeFileHandle process,
        SafeFileHandle job)
    {
        if (!TerminateJobObject(job, 4) &&
            WaitForSingleObject(process.DangerousGetHandle(), 0) != WaitObject0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not terminate the provisional packaged-service startup job.");
        }

        var deadline = Stopwatch.GetTimestamp() + (5 * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (WaitForSingleObject(process.DangerousGetHandle(), 0) == WaitObject0 &&
                QueryActiveJobProcessCount(job) == 0)
            {
                return;
            }

            Thread.Sleep(25);
        }

        throw new CliElevationUnsafeOwnershipException(
            "The provisional packaged-service startup job did not become empty within five seconds.");
    }

    private static int QueryActiveJobProcessCount(SafeFileHandle job)
    {
        var buffer = Marshal.AllocHGlobal(4096);
        try
        {
            if (!QueryInformationJobObject(
                    job,
                    JobObjectBasicProcessIdList,
                    buffer,
                    4096,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not query the provisional packaged-service startup job.");
            }

            return Marshal.ReadInt32(buffer, sizeof(uint));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ValidateStartedProcessHandle(
        PackagedServiceStartedProcess started,
        SafeFileHandle process)
    {
        var handle = process.DangerousGetHandle();
        var processId = GetProcessId(handle);
        if (processId != (uint)started.ProcessId ||
            !string.Equals(QueryProcessImagePath(handle), started.ImagePath, StringComparison.OrdinalIgnoreCase) ||
            !GetProcessTimes(handle, out var creationTime, out _, out _, out _))
        {
            throw new CliElevationUnsafeOwnershipException(
                "The packaged-service startup identity changed before ownership transfer.");
        }

        var startFileTime = ((long)creationTime.dwHighDateTime << 32) | (uint)creationTime.dwLowDateTime;
        if (DateTime.FromFileTimeUtc(startFileTime).Ticks != started.StartTimeUtcTicks)
        {
            throw new CliElevationUnsafeOwnershipException(
                "The packaged-service startup time changed before ownership transfer.");
        }
    }

    private static void DuplicatePackageLeaseHandles(
        IEnumerable<SafeFileHandle> leaseHandles,
        IntPtr targetProcess)
    {
        var currentProcess = GetCurrentProcess();
        foreach (var leaseHandle in leaseHandles)
        {
            if (!DuplicateHandle(
                    currentProcess,
                    leaseHandle.DangerousGetHandle(),
                    targetProcess,
                    out _,
                    0,
                    false,
                    DuplicateSameAccess))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not duplicate a verified package lease into the suspended service.");
            }
        }
    }

    private static PackagedServiceStartedProcess CaptureAndValidateStartedProcess(
        ProcessInformation processInformation,
        PackagedServicePackageIdentity package)
    {
        var observedProcessId = GetProcessId(processInformation.Process);
        if (observedProcessId == 0 || observedProcessId != processInformation.ProcessId)
        {
            throw new CliElevationValidationException("The packaged service process ID could not be verified.");
        }

        var imagePath = QueryProcessImagePath(processInformation.Process);
        if (!string.Equals(imagePath, package.AppHost.CanonicalPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new CliElevationValidationException("The packaged service started from the wrong apphost path.");
        }

        if (!GetProcessTimes(
                processInformation.Process,
                out var creationTime,
                out _,
                out _,
                out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not capture the packaged service start identity.");
        }

        var startFileTime = ((long)creationTime.dwHighDateTime << 32) | (uint)creationTime.dwLowDateTime;
        var startTimeUtcTicks = DateTime.FromFileTimeUtc(startFileTime).Ticks;
        if (startTimeUtcTicks <= 0)
        {
            throw new CliElevationValidationException("The packaged service start identity is invalid.");
        }

        return new PackagedServiceStartedProcess(
            checked((int)observedProcessId),
            startTimeUtcTicks,
            imagePath,
            package);
    }

    private static string QueryProcessImagePath(IntPtr process)
    {
        var capacity = 512;
        while (capacity <= 32_768)
        {
            var builder = new StringBuilder(capacity);
            var size = builder.Capacity;
            if (QueryFullProcessImageName(process, 0, builder, ref size))
            {
                return Path.GetFullPath(builder.ToString());
            }

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(error, "Could not query the packaged service process image path.");
            }

            capacity *= 2;
        }

        throw new CliElevationValidationException("The packaged service process image path is too long.");
    }

    private static void TerminateSuspendedProcessAndProveExit(IntPtr process)
    {
        if (!TerminateProcess(process, 4) && WaitForSingleObject(process, 0) != WaitObject0)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not terminate the rejected packaged service process.");
        }

        var waitResult = WaitForSingleObject(process, 5_000);
        if (waitResult != WaitObject0)
        {
            throw new CliElevationUnsafeOwnershipException(
                "The rejected packaged service process did not reach verified termination.");
        }
    }

    private static SafeFileHandle OpenNullHandle(uint access)
    {
        var securityAttributes = new SecurityAttributes
        {
            Size = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true,
        };
        var handle = CreateFileW(
            "NUL",
            access,
            FileShareRead | FileShareWrite,
            ref securityAttributes,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Could not open an isolated standard-stream handle.");
        }

        return handle;
    }

    private static IntPtr BuildEnvironmentBlock(
        IDictionary<string, string?> environment,
        string packageDirectory)
    {
        var windowsDirectory = GetTrustedWindowsDirectory();
        var systemDirectory = Path.Combine(windowsDirectory, "System32");
        var trusted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windowsDirectory,
            ["WINDIR"] = windowsDirectory,
            ["SystemDrive"] = Path.GetPathRoot(windowsDirectory) ?? "C:\\",
            ["COMSPEC"] = Path.Combine(systemDirectory, "cmd.exe"),
            ["PATH"] = string.Join(';', packageDirectory, systemDirectory, windowsDirectory),
            ["PATHEXT"] = ".COM;.EXE;.BAT;.CMD",
        };

        foreach (var entry in environment)
        {
            if (entry.Value is not null && AllowedApplicationEnvironmentVariables.Contains(entry.Key))
            {
                trusted[entry.Key] = entry.Value;
            }
        }

        var builder = new StringBuilder();
        foreach (var entry in trusted.OrderBy(static item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (entry.Key.Length == 0 ||
                entry.Key.Contains('=', StringComparison.Ordinal) ||
                entry.Key.Contains('\0', StringComparison.Ordinal) ||
                entry.Value.Contains('\0', StringComparison.Ordinal))
            {
                throw new ArgumentException("The packaged-service environment contains an invalid entry.", nameof(environment));
            }

            builder.Append(entry.Key)
                .Append('=')
                .Append(entry.Value)
                .Append('\0');
        }

        builder.Append('\0');
        return Marshal.StringToHGlobalUni(builder.ToString());
    }

    private static string GetTrustedWindowsDirectory()
    {
        var builder = new StringBuilder(260);
        var length = GetWindowsDirectoryW(builder, builder.Capacity);
        if (length == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve the Windows directory.");
        }

        if (length >= builder.Capacity)
        {
            builder = new StringBuilder(checked((int)length + 1));
            length = GetWindowsDirectoryW(builder, builder.Capacity);
            if (length == 0 || length >= builder.Capacity)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve the Windows directory.");
            }
        }

        return Path.GetFullPath(builder.ToString());
    }

    private static string BuildCommandLine(ProcessStartInfo startInfo, string applicationPath)
    {
        var builder = new StringBuilder();
        AppendArgument(builder, applicationPath);

        if (startInfo.ArgumentList.Count > 0)
        {
            if (!string.IsNullOrEmpty(startInfo.Arguments))
            {
                throw new ArgumentException(
                    "Arguments and ArgumentList cannot both be populated.",
                    nameof(startInfo));
            }

            foreach (var argument in startInfo.ArgumentList)
            {
                AppendArgument(builder, argument);
            }
        }
        else if (!string.IsNullOrEmpty(startInfo.Arguments))
        {
            builder.Append(' ').Append(startInfo.Arguments);
        }

        return builder.ToString();
    }

    private static void AppendArgument(StringBuilder builder, string argument)
    {
        if (builder.Length > 0)
        {
            builder.Append(' ');
        }

        if (argument.Length > 0 && !argument.Any(static character => char.IsWhiteSpace(character) || character == '"'))
        {
            builder.Append(argument);
            return;
        }

        builder.Append('"');
        var backslashCount = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashCount++;
                continue;
            }

            if (character == '"')
            {
                builder.Append('\\', checked(backslashCount * 2 + 1));
                builder.Append('"');
                backslashCount = 0;
                continue;
            }

            builder.Append('\\', backslashCount);
            builder.Append(character);
            backslashCount = 0;
        }

        builder.Append('\\', checked(backslashCount * 2));
        builder.Append('"');
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Size;
        public IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Size;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public uint Flags;
        public short ShowWindow;
        public short ReservedSize;
        public IntPtr ReservedPointer;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref nuint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        nuint size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess,
        IntPtr sourceHandle,
        IntPtr targetProcess,
        out IntPtr targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        int flags,
        StringBuilder executableName,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        IntPtr process,
        out System.Runtime.InteropServices.ComTypes.FILETIME creationTime,
        out System.Runtime.InteropServices.ComTypes.FILETIME exitTime,
        out System.Runtime.InteropServices.ComTypes.FILETIME kernelTime,
        out System.Runtime.InteropServices.ComTypes.FILETIME userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetWindowsDirectoryW(StringBuilder buffer, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
