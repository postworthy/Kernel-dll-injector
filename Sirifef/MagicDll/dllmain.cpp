// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Log.h"
#include "Utility.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    auto pid = GetCurrentProcessId();
    auto path = String(L"c:\\out" + std::to_wstring(pid) + L".txt");
    auto log = new Log(&path);
    auto utility = new Utility();
    auto procName = utility->GetProcessName(pid);
    String msg;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        msg = L"Attached to " + procName + L"\n";
        log->Write(&msg);
        break;
    case DLL_PROCESS_DETACH:
        msg = L"Detatched from " + procName + L"\n";
        log->Write(&msg);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

