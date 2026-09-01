using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Ipc;

internal sealed record PipeEndpointProcessIdentity(
    int ProcessId,
    string UserSid,
    int SessionId,
    int IntegrityRid,
    string ImagePath);

internal static class PipeIntegrityLevels
{
    internal const int Low = 0x1000;
    internal const int Medium = 0x2000;
    internal const int High = 0x3000;
}

internal static class NamedPipeEndpointAuthenticationPolicy
{
    private const string ServiceExecutableName = "ApfsAccess.Service.exe";
    private const string TrayExecutableName = "ApfsAccess.Tray.exe";
    private const string CliExecutableName = "ApfsAccess.Cli.exe";

    internal static void ValidateClientForService(
        PipeEndpointProcessIdentity service,
        PipeEndpointProcessIdentity client)
    {
        ValidateCommon(service, client);
        ValidateImageName(service.ImagePath, ServiceExecutableName, "service");
        ValidateMinimumIntegrity(service, PipeIntegrityLevels.High, "service");
        ValidateMinimumIntegrity(client, PipeIntegrityLevels.Medium, "control client");

        var allowedPaths = BuildAllowedClientPaths(service.ImagePath);
        ValidateAllowedPath(client.ImagePath, allowedPaths, "control client");
    }

    internal static void ValidateServiceForClient(
        PipeEndpointProcessIdentity client,
        PipeEndpointProcessIdentity service)
    {
        ValidateCommon(client, service);
        ValidateImageName(client.ImagePath, [TrayExecutableName, CliExecutableName], "control client");
        ValidateMinimumIntegrity(client, PipeIntegrityLevels.Medium, "control client");
        ValidateMinimumIntegrity(service, PipeIntegrityLevels.High, "service");

        var allowedPaths = BuildAllowedServicePaths(client.ImagePath);
        ValidateAllowedPath(service.ImagePath, allowedPaths, "service");
    }

    private static void ValidateCommon(
        PipeEndpointProcessIdentity local,
        PipeEndpointProcessIdentity peer)
    {
        // The deployed service is an elevated process owned by the same user
        // in the same interactive session as Tray/CLI. A future LocalSystem
        // session-0 service needs an explicit user/session binding contract;
        // silently relaxing these checks would reintroduce cross-user control.
        if (local.ProcessId <= 0 || peer.ProcessId <= 0 || local.ProcessId == peer.ProcessId)
        {
            throw Rejected("The pipe endpoint process identity is invalid.");
        }

        if (string.IsNullOrWhiteSpace(local.UserSid) ||
            !string.Equals(local.UserSid, peer.UserSid, StringComparison.OrdinalIgnoreCase))
        {
            throw Rejected("The pipe endpoint belongs to a different Windows user.");
        }

        if (local.SessionId < 0 || local.SessionId != peer.SessionId)
        {
            throw Rejected("The pipe endpoint belongs to a different Windows session.");
        }
    }

    private static void ValidateMinimumIntegrity(
        PipeEndpointProcessIdentity identity,
        int minimumIntegrityRid,
        string endpointName)
    {
        if (identity.IntegrityRid < minimumIntegrityRid)
        {
            throw Rejected($"The {endpointName} has insufficient Windows integrity.");
        }
    }

    private static void ValidateImageName(string imagePath, string expectedName, string endpointName)
        => ValidateImageName(imagePath, [expectedName], endpointName);

    private static void ValidateImageName(
        string imagePath,
        IReadOnlyCollection<string> expectedNames,
        string endpointName)
    {
        var actualName = Path.GetFileName(NormalizePath(imagePath));
        if (!expectedNames.Contains(actualName, StringComparer.OrdinalIgnoreCase))
        {
            throw Rejected($"The {endpointName} executable identity is not allowed.");
        }
    }

    private static void ValidateAllowedPath(
        string imagePath,
        IReadOnlyCollection<string> allowedPaths,
        string endpointName)
    {
        var normalized = NormalizePath(imagePath);
        if (!allowedPaths.Contains(normalized, StringComparer.OrdinalIgnoreCase))
        {
            throw Rejected($"The {endpointName} executable path is not part of this package.");
        }
    }

    private static IReadOnlyCollection<string> BuildAllowedClientPaths(string serviceImagePath)
    {
        var servicePath = NormalizePath(serviceImagePath);
        var serviceDirectory = Path.GetDirectoryName(servicePath)
            ?? throw Rejected("The service executable path has no package directory.");
        var packageDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            serviceDirectory,
        };

        if (string.Equals(
                Path.GetFileName(serviceDirectory),
                "service",
                StringComparison.OrdinalIgnoreCase))
        {
            var parent = Directory.GetParent(serviceDirectory)?.FullName;
            if (!string.IsNullOrWhiteSpace(parent))
            {
                var packageRoot = NormalizePath(parent);
                packageDirectories.Add(packageRoot);
                packageDirectories.Add(NormalizePath(Path.Combine(packageRoot, "tray")));
                packageDirectories.Add(NormalizePath(Path.Combine(packageRoot, "cli")));
            }
        }

        return packageDirectories
            .SelectMany(directory => new[]
            {
                NormalizePath(Path.Combine(directory, TrayExecutableName)),
                NormalizePath(Path.Combine(directory, CliExecutableName)),
            })
            .ToArray();
    }

    private static IReadOnlyCollection<string> BuildAllowedServicePaths(string clientImagePath)
    {
        var clientPath = NormalizePath(clientImagePath);
        var packageDirectory = Path.GetDirectoryName(clientPath)
            ?? throw Rejected("The control client executable path has no package directory.");
        var allowedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            NormalizePath(Path.Combine(packageDirectory, ServiceExecutableName)),
            NormalizePath(Path.Combine(packageDirectory, "service", ServiceExecutableName)),
        };

        var clientDirectoryName = Path.GetFileName(packageDirectory);
        if (string.Equals(clientDirectoryName, "tray", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(clientDirectoryName, "cli", StringComparison.OrdinalIgnoreCase))
        {
            var packageRoot = Directory.GetParent(packageDirectory)?.FullName;
            if (!string.IsNullOrWhiteSpace(packageRoot))
            {
                allowedPaths.Add(NormalizePath(Path.Combine(
                    packageRoot,
                    "service",
                    ServiceExecutableName)));
            }
        }

        return allowedPaths;
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw Rejected("The pipe endpoint executable path is missing.");
        }

        var normalized = Path.GetFullPath(path);
        if (normalized.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + normalized[8..];
        }

        return normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
            ? normalized[4..]
            : normalized;
    }

    private static UnauthorizedAccessException Rejected(string message)
        => new($"APFS Access pipe authentication failed. {message}");
}

internal static class NamedPipeEndpointAuthentication
{
    internal static bool IsRequired(string pipeName)
        => string.Equals(pipeName, ApfsPipeConstants.PipeName, StringComparison.OrdinalIgnoreCase);

    [SupportedOSPlatform("windows")]
    internal static void AuthenticateClient(NamedPipeServerStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        Authenticate(
            WindowsPipeEndpointIdentitySource.Instance.GetClientProcessId,
            stream,
            NamedPipeEndpointAuthenticationPolicy.ValidateClientForService,
            "control client");
    }

    [SupportedOSPlatform("windows")]
    internal static void AuthenticateServer(NamedPipeClientStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        Authenticate(
            WindowsPipeEndpointIdentitySource.Instance.GetServerProcessId,
            stream,
            NamedPipeEndpointAuthenticationPolicy.ValidateServiceForClient,
            "service");
    }

    [SupportedOSPlatform("windows")]
    private static void Authenticate<TStream>(
        Func<TStream, int> observePeerProcessId,
        TStream stream,
        Action<PipeEndpointProcessIdentity, PipeEndpointProcessIdentity> validate,
        string endpointName)
    {
        try
        {
            var firstProcessId = observePeerProcessId(stream);
            var source = WindowsPipeEndpointIdentitySource.Instance;
            var local = source.GetCurrentProcessIdentity();
            var peer = source.GetProcessIdentity(firstProcessId);
            var secondProcessId = observePeerProcessId(stream);
            if (firstProcessId != secondProcessId || peer.ProcessId != firstProcessId)
            {
                throw new UnauthorizedAccessException(
                    $"APFS Access pipe authentication failed. The {endpointName} process identity changed during authentication.");
            }

            validate(local, peer);
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception exception) when (exception is Win32Exception
            or ArgumentException
            or IOException
            or InvalidOperationException
            or NotSupportedException
            or SecurityException)
        {
            throw new UnauthorizedAccessException(
                $"APFS Access pipe authentication failed. The {endpointName} Windows identity could not be verified.",
                exception);
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsPipeEndpointIdentitySource
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int ErrorInsufficientBuffer = 122;

    internal static WindowsPipeEndpointIdentitySource Instance { get; } = new();

    private WindowsPipeEndpointIdentitySource()
    {
    }

    internal int GetClientProcessId(NamedPipeServerStream stream)
    {
        if (!NativeMethods.GetNamedPipeClientProcessId(stream.SafePipeHandle, out var processId))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not observe the named-pipe client process.");
        }

        return CheckedProcessId(processId);
    }

    internal int GetServerProcessId(NamedPipeClientStream stream)
    {
        if (!NativeMethods.GetNamedPipeServerProcessId(stream.SafePipeHandle, out var processId))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not observe the named-pipe server process.");
        }

        return CheckedProcessId(processId);
    }

    internal PipeEndpointProcessIdentity GetCurrentProcessIdentity()
        => GetProcessIdentity(Environment.ProcessId);

    internal PipeEndpointProcessIdentity GetProcessIdentity(int processId)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }

        using var process = NativeMethods.OpenProcess(
            ProcessQueryLimitedInformation,
            inheritHandle: false,
            (uint)processId);
        if (process.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not open pipe endpoint process {processId}.");
        }

        var imagePath = QueryProcessImagePath(process, processId);
        if (!NativeMethods.OpenProcessToken(process, TokenQuery, out var token))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not open pipe endpoint process token {processId}.");
        }

        using (token)
        {
            return new PipeEndpointProcessIdentity(
                processId,
                QueryUserSid(token),
                QuerySessionId(token),
                QueryIntegrityRid(token),
                imagePath);
        }
    }

    private static int CheckedProcessId(uint processId)
    {
        if (processId == 0 || processId > int.MaxValue)
        {
            throw new UnauthorizedAccessException(
                "APFS Access pipe authentication failed. The endpoint process identifier is invalid.");
        }

        return (int)processId;
    }

    private static string QueryProcessImagePath(SafeProcessHandle process, int processId)
    {
        var capacity = 1024;
        while (capacity <= 32_768)
        {
            var builder = new StringBuilder(capacity);
            var length = (uint)builder.Capacity;
            if (NativeMethods.QueryFullProcessImageName(process, 0, builder, ref length))
            {
                return Path.GetFullPath(builder.ToString());
            }

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(
                    error,
                    $"Could not query pipe endpoint process image {processId}.");
            }

            capacity *= 2;
        }

        throw new InvalidOperationException("The pipe endpoint process image path is too long.");
    }

    private static string QueryUserSid(SafeAccessTokenHandle token)
    {
        using var information = QueryTokenInformation(token, TokenInformationClass.TokenUser);
        var sid = Marshal.ReadIntPtr(information.DangerousGetHandle());
        if (sid == IntPtr.Zero)
        {
            throw new InvalidOperationException("The pipe endpoint token has no user SID.");
        }

        return new SecurityIdentifier(sid).Value;
    }

    private static int QuerySessionId(SafeAccessTokenHandle token)
    {
        using var information = QueryTokenInformation(token, TokenInformationClass.TokenSessionId);
        return Marshal.ReadInt32(information.DangerousGetHandle());
    }

    private static int QueryIntegrityRid(SafeAccessTokenHandle token)
    {
        using var information = QueryTokenInformation(token, TokenInformationClass.TokenIntegrityLevel);
        var sid = Marshal.ReadIntPtr(information.DangerousGetHandle());
        if (sid == IntPtr.Zero)
        {
            throw new InvalidOperationException("The pipe endpoint token has no integrity SID.");
        }

        var subAuthorityCountPointer = NativeMethods.GetSidSubAuthorityCount(sid);
        if (subAuthorityCountPointer == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not read the pipe endpoint integrity SID.");
        }

        var subAuthorityCount = Marshal.ReadByte(subAuthorityCountPointer);
        if (subAuthorityCount == 0)
        {
            throw new InvalidOperationException("The pipe endpoint integrity SID is invalid.");
        }

        var ridPointer = NativeMethods.GetSidSubAuthority(sid, (uint)(subAuthorityCount - 1));
        if (ridPointer == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not read the pipe endpoint integrity level.");
        }

        return Marshal.ReadInt32(ridPointer);
    }

    private static SafeHGlobalHandle QueryTokenInformation(
        SafeAccessTokenHandle token,
        TokenInformationClass informationClass)
    {
        _ = NativeMethods.GetTokenInformation(
            token,
            informationClass,
            IntPtr.Zero,
            0,
            out var requiredLength);
        var error = Marshal.GetLastWin32Error();
        if (requiredLength <= 0 || error != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(error, "Could not size pipe endpoint token information.");
        }

        var buffer = new SafeHGlobalHandle(requiredLength);
        if (!NativeMethods.GetTokenInformation(
                token,
                informationClass,
                buffer.DangerousGetHandle(),
                requiredLength,
                out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not query pipe endpoint token information.");
        }

        return buffer;
    }

    private enum TokenInformationClass
    {
        TokenUser = 1,
        TokenSessionId = 12,
        TokenIntegrityLevel = 25,
    }

    private sealed class SafeHGlobalHandle : SafeHandle
    {
        internal SafeHGlobalHandle(int byteCount)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            SetHandle(Marshal.AllocHGlobal(byteCount));
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeClientProcessId(
            SafePipeHandle pipe,
            out uint clientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeServerProcessId(
            SafePipeHandle pipe,
            out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint processId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(
            SafeProcessHandle process,
            uint desiredAccess,
            out SafeAccessTokenHandle token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetTokenInformation(
            SafeAccessTokenHandle token,
            TokenInformationClass informationClass,
            IntPtr information,
            int informationLength,
            out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            uint flags,
            StringBuilder executableName,
            ref uint size);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);
    }
}
