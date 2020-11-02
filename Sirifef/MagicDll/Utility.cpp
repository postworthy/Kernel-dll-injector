#include "pch.h"
#include "Utility.h"

String Utility::GetProcessName(DWORD pid) {

    HANDLE Handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (Handle)
    {
        TCHAR Buffer[MAX_PATH];
        if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
            return Buffer;
        else
            return String();
        CloseHandle(Handle);
    }
}