#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winioctl.h>

namespace {
// Ordinary files have no CHECK_VERIFY2 ioctl. The loopback target supplies only
// that storage response after checking the real file handle. All reads, writes,
// geometry queries, descriptor qualification and flushes use production code.
BOOL WINAPI RawRuntimeDeviceIoControl(HANDLE handle,DWORD code,LPVOID input,DWORD input_bytes,
    LPVOID output,DWORD output_bytes,LPDWORD returned,LPOVERLAPPED overlapped)
{
    if(code==IOCTL_STORAGE_CHECK_VERIFY2){
        FILE_STANDARD_INFO info{};
        if(GetFileType(handle)==FILE_TYPE_DISK&&
            GetFileInformationByHandleEx(handle,FileStandardInfo,&info,sizeof(info))&&
            !info.Directory&&!info.DeletePending&&info.EndOfFile.QuadPart>0){if(returned)*returned=0;return TRUE;}
        SetLastError(ERROR_INVALID_HANDLE);return FALSE;
    }
    return DeviceIoControl(handle,code,input,input_bytes,output,output_bytes,returned,overlapped);
}
}

// Compiled only into RawSnapshotRuntimeTests instead of the archive's device
// object. Shipping BlockDevice has no admission or storage-query override.
#define DeviceIoControl RawRuntimeDeviceIoControl
#include "../src/BlockDevice.cpp"
#undef DeviceIoControl
