#include <Windows.h>
#include <fstream>
#include <string>

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lParam)
{
	std::ofstream myfile;
	auto pid = GetCurrentProcessId();

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:		
		myfile.open("c:\\out" + std::to_string(pid) + ".txt", std::ios_base::app);
		myfile << "Attached to " << pid << "\n";
		myfile.close();
		break;
	case DLL_PROCESS_DETACH:
		myfile.open("c:\\out" + std::to_string(pid) + ".txt", std::ios_base::app);
		myfile << "Detatched from " << pid << "\n";
		myfile.close();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	default:
		break;
	}

	return TRUE;
}