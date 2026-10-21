using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace ApfsAccess.Backend.Native;
internal sealed partial class HostProcessGuardian
{
    private static bool CreateRestrictedProcess(ProcessStartInfo start, StringBuilder command, nint environment,
        uint flags, SafeHandle? input, SafeHandle? stderr, out ProcessInformation process, SafeHandle? output = null)
    {
        nuint size=0; InitializeProcThreadAttributeList(0,1,0,ref size);
        if(size==0) throw LastWin32Error("Credential handle list");
        SafeHandle?[] endpoints = [input, output, stderr];
        var count = endpoints.Count(handle => handle is not null);
        if (count == 0) throw new ArgumentException("A native stream endpoint is required.");
        nint list = 0, handles = 0;
        var initialized=false;
        var retained = new SafeHandle?[count];
        var retainedCount = 0;
        try
        {
            list=Marshal.AllocHGlobal(checked((nint)size));
            handles=Marshal.AllocHGlobal(nint.Size * count);
            if(!InitializeProcThreadAttributeList(list,1,0,ref size)) throw LastWin32Error("Credential handle list");
            initialized=true;
            var index = 0;
            foreach (var handle in endpoints)
            {
                if (handle is null) continue;
                var added = false;
                handle.DangerousAddRef(ref added);
                if (added) retained[retainedCount++] = handle;
                Marshal.WriteIntPtr(handles, nint.Size * index++, handle.DangerousGetHandle());
            }
            if(!UpdateProcThreadAttribute(list,0,0x20002,handles,(nuint)(nint.Size * count),0,0)) throw LastWin32Error("Credential handle list");
            var info=new StartupInfoEx { Info=new StartupInfo { Size=Marshal.SizeOf<StartupInfoEx>(), Flags=0x100,
                StandardInput=input?.DangerousGetHandle() ?? -1, StandardOutput=output?.DangerousGetHandle() ?? -1,
                StandardError=stderr?.DangerousGetHandle() ?? -1 }, Attributes=list };
            return CreateCredentialProcessW(start.FileName,command,0,0,true,flags|0x80000,environment,start.WorkingDirectory,ref info,out process);
        }
        finally
        {
            if(initialized) DeleteProcThreadAttributeList(list);
            Marshal.FreeHGlobal(handles); Marshal.FreeHGlobal(list);
            for (var index = retainedCount - 1; index >= 0; --index) retained[index]!.DangerousRelease();
            GC.KeepAlive(input); GC.KeepAlive(output); GC.KeepAlive(stderr);
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Info; public nint Attributes; }
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool InitializeProcThreadAttributeList(nint list,int count,uint flags,ref nuint size);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool UpdateProcThreadAttribute(nint list,uint flags,nuint attribute,nint value,nuint size,nint old,nint returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(nint list);
    [DllImport("kernel32.dll", EntryPoint="GetFileType", SetLastError=true)]
    private static extern uint GetNativeStreamFileType(SafeHandle handle);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",SetLastError=true,CharSet=CharSet.Unicode)]
    private static extern bool CreateCredentialProcessW(string application,StringBuilder command,nint processAttributes,nint threadAttributes,
        bool inherit,uint flags,nint environment,string? directory,ref StartupInfoEx startup,out ProcessInformation process);
}
