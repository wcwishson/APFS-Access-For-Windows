#pragma once
#include <Windows.h>
// Only the test's separate BlockDevice object is compiled with this header.
BOOL WINAPI NativeSparseMeasuredReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
BOOL WINAPI NativeSparseMeasuredWriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
#define ReadFile NativeSparseMeasuredReadFile
#define WriteFile NativeSparseMeasuredWriteFile
