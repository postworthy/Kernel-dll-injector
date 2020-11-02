#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#include "Sf.h"

GET_ADDRESS Hash = { 0 };

static HANDLE handle = NULL;

static size_t StrLen(PCSTR str)
{
	size_t len = 0;
	while (*str++)
	{
		++len;
	}
	return len;
}

static int StrCmp(PCSTR a, PCSTR b, size_t len)
{
	char result = 0;
	for (; len != 0; ++a, ++b, --len)
	{
		char c = *b;
		result = *a - c;
		if (result || c == 0)
			break;
	}
	if (result < 0)
		return -1;
	else if (result > 0)
		return 1;
	else
		return result;
}

ULONG Log(PSTR buffer)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	NTSTATUS ntstatus;
	IO_STATUS_BLOCK    ioStatusBlock;

	if (handle == NULL) {
		UNICODE_STRING     uniName;
		OBJECT_ATTRIBUTES  objAttr;

		RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\mylog.txt");
		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);


		ntstatus = ZwCreateFile(&handle,
			FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE,
			&objAttr, &ioStatusBlock, NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0);
	}
	else ntstatus = STATUS_SUCCESS;

	if (NT_SUCCESS(ntstatus)) {
		ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
			buffer, strlen(buffer), NULL, NULL);
	}

	return 0;
}

PVOID GetProcedureAddress(PVOID ModuleBase, PCSTR ProcName, ULONG Data)
{
	Log("GetProcedureAddress\r\n");
	size_t nameSize = StrLen(ProcName) + 1;
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ImageNtHeaders = ((PIMAGE_NT_HEADERS)(RtlOffsetToPointer(ModuleBase, ImageDosHeader->e_lfanew)));
		if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			if (ImageNtHeaders->OptionalHeader.DataDirectory[Data].VirtualAddress && Data < ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
				PIMAGE_EXPORT_DIRECTORY ImageExport = (((PIMAGE_EXPORT_DIRECTORY)(PUCHAR)RtlOffsetToPointer(ModuleBase, ImageNtHeaders->OptionalHeader.DataDirectory[Data].VirtualAddress)));
				if (ImageExport)
				{
					PULONG AddressOfNames = ((PULONG)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfNames));
					for (ULONG n = 0; n < ImageExport->NumberOfNames; ++n)
					{
						LPSTR Func = ((LPSTR)RtlOffsetToPointer(ModuleBase, AddressOfNames[n]));
						if (StrCmp(ProcName, Func, nameSize) == 0)
						{
							Log("FOUND: ");
							Log(ProcName);
							Log("\r\n");
							PULONG AddressOfFunctions = ((PULONG)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfFunctions));
							PUSHORT AddressOfOrdinals = ((PUSHORT)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfNameOrdinals));
							return ((PVOID)RtlOffsetToPointer(ModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));
						}
					}
				}
			}
		}
	}
	return NULL;
}

PVOID ResolveDynamicImport(PVOID ModuleBase, PCSTR ProcName)
{
	return GetProcedureAddress(ModuleBase, ProcName, 0);
}

VOID NTAPI APCKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SysArg1, PVOID* SysArg2, PVOID* Context)
{
	ExFreePool(Apc);
	return;
}

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS Peprocess, PETHREAD Pethread, BOOLEAN Alert)
{
	Log("DllInject\r\n");
	HANDLE hProcess;
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID cidprocess = { 0 };
	CHAR DllFormatPath[] = "C:\\MyDLL.dll";
	ULONG Size = strlen(DllFormatPath) + 1;
	PVOID pvMemory = NULL;

	cidprocess.UniqueProcess = ProcessId;
	cidprocess.UniqueThread = 0;
	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cidprocess)))
	{
		auto result = ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (NT_SUCCESS(result))
		{
			KAPC_STATE KasState;
			PKAPC Apc;

			KeStackAttachProcess(Peprocess, &KasState);
			strcpy(pvMemory, DllFormatPath);
			KeUnstackDetachProcess(&KasState);
			Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (Apc)
			{
				KeInitializeApc(Apc, Pethread, 0, (PKKERNEL_ROUTINE)APCKernelRoutine, 0, (PKNORMAL_ROUTINE)Hash.pvLoadLibraryExA, UserMode, pvMemory);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
			else
				Log("ExAllocatePool Failed!");
		}
		else
		{
			auto str[100];
			sprintf(str, "ZwAllocateVirtualMemory Failed [%d]", result);
			Log(str);
			Log("\r\n");
		}
		ZwClose(hProcess);
	}
	else
		Log("Failed to Open Process!");

	return STATUS_NO_MEMORY;
}

VOID SirifefWorkerRoutine(PVOID Context)
{
	auto result = DllInject(((PSIRIFEF_INJECTION_DATA)Context)->ProcessId, ((PSIRIFEF_INJECTION_DATA)Context)->Process, ((PSIRIFEF_INJECTION_DATA)Context)->Ethread, FALSE);
	KeSetEvent(&((PSIRIFEF_INJECTION_DATA)Context)->Event, (KPRIORITY)0, FALSE);

	if (NT_SUCCESS(result))
		Log("Successful Injection!");

	return;
}

VOID NTAPI APCInjectorRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SystemArgument1, PVOID* SystemArgument2, PVOID* Context)
{
	SIRIFEF_INJECTION_DATA Sf;

	RtlSecureZeroMemory(&Sf, sizeof(SIRIFEF_INJECTION_DATA));
	ExFreePool(Apc);
	Sf.Ethread = KeGetCurrentThread();
	Sf.Process = IoGetCurrentProcess();
	Sf.ProcessId = PsGetCurrentProcessId();
	KeInitializeEvent(&Sf.Event, NotificationEvent, FALSE);
	ExInitializeWorkItem(&Sf.WorkItem, (PWORKER_THREAD_ROUTINE)SirifefWorkerRoutine, &Sf);
	ExQueueWorkItem(&Sf.WorkItem, DelayedWorkQueue);
	KeWaitForSingleObject(&Sf.Event, Executive, KernelMode, TRUE, 0);
	return;

}

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING ImageName, IN HANDLE ProcessId, IN PIMAGE_INFO pImageInfo)
{
	if (ImageName != NULL)
	{
		ANSI_STRING ansiStr;
		RtlInitAnsiString(&ansiStr, NULL);
		if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiStr, ImageName, TRUE)))
		{
			Log("Image Name ");
			Log(ansiStr.Buffer);
			Log("\r\n");
		}

		WCHAR kernel32Mask[] = L"*\\KERNEL32.DLL";
		UNICODE_STRING kernel32us;

		RtlInitUnicodeString(&kernel32us, kernel32Mask);
		if (FsRtlIsNameInExpression(&kernel32us, ImageName, TRUE, NULL))
		{
			PKAPC Apc;

			if (Hash.Kernel32dll == 0)
			{
				Hash.Kernel32dll = (PVOID)pImageInfo->ImageBase;
				Hash.pvLoadLibraryExA = (fnLoadLibraryExA)ResolveDynamicImport(Hash.Kernel32dll, "LoadLibraryExA");
			}

			Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (Apc)
			{
				KeInitializeApc(Apc, KeGetCurrentThread(), 0, (PKKERNEL_ROUTINE)APCInjectorRoutine, 0, 0, KernelMode, 0);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
			}
		}
	}

	return;
}


VOID Unload(IN PDRIVER_OBJECT pDriverobject)
{
	Log("Unload\r\n");
	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	if (handle != NULL)
		ZwClose(handle);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverobject, IN PUNICODE_STRING pRegister)
{
	Log("DriverEntry\r\n");
	NTSTATUS st;

	PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);

	pDriverobject->DriverUnload = (PDRIVER_UNLOAD)Unload;

	return STATUS_SUCCESS;
}