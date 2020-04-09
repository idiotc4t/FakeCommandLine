#include <stdio.h>
#include <Windows.h>
#include <winternl.h>


typedef DWORD(*pNtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main()
//at-infosec ssh username:nihao password:buuhao user pass admin uname pword
{
	HANDLE hProcess =0;
	ULONG lenght = 0;
	HANDLE hModule;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	pNtQueryInformationProcess NtQueryInformationProcess;
	wchar_t CommandLine[] = L"C:\\Windows\\system32\\notepad.exe";
	wchar_t CurrentDirectory[] = L"C:\\Windows\\system32\\";

	hModule =  GetModuleHandleA("Ntdll.dll");
	hProcess = GetCurrentProcess();
	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);

	//WriteProcessMemory(hProcess, ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Length, &CommandLine, sizeof(CommandLine), NULL);
	//WriteProcessMemory(hProcess, ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Length, &CurrentDirectory, sizeof(CurrentDirectory), NULL);
	ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Length = sizeof(CommandLine);
	ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Length = sizeof(CurrentDirectory);
	ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Buffer = &CommandLine;
	ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = &CurrentDirectory;

	getchar();
	return 0;
}