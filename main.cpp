#include <Windows.h>
#include <tlhelp32.h>
#include <iostream> 
#include <string.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
struct pidList {
	int pid;
	int parentPID; 
	pidList(int _pid = -1, int _parentPID = -1) {
		pid = _pid, parentPID = _parentPID;
	}
};
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL
);
pidList findPID_and_parentPID(char *processName) {
	pidList ans;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		goto meow;
	}
	PROCESSENTRY32 pe;
	ZeroMemory(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &pe)) {
		do {
			if (strcmp(processName, pe.szExeFile) == 0) {
				ans.pid = pe.th32ProcessID; 
				ans.parentPID = pe.th32ParentProcessID;
				goto meow;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
meow:
	if (hSnapshot) {
		CloseHandle(hSnapshot);
	}
	return ans;
}
WORD getMachineNtQuery(int pid) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	WORD machineType = 0;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	HMODULE hNtdll = NULL;
	DWORD offset = 0;
	BYTE* baseAddr = NULL;
	pNtQueryInformationProcess myNtQueryInformationProcess;
	if (hProcess == INVALID_HANDLE_VALUE) {
		goto getMachineNtQuery_meow;
	}
	hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		goto getMachineNtQuery_meow;
	}
	myNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	myNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof pbi, NULL);
	peb = pbi.PebBaseAddress;
	if (ReadProcessMemory(hProcess, (LPVOID)((BYTE*)peb + 0x10), (LPVOID)(&baseAddr), 8, NULL)) {
		//printf("baseAddr: 0x%llx\n", baseAddr);
		if (ReadProcessMemory(hProcess, (LPVOID)(baseAddr + 0x3c), (LPVOID)&offset, 4, NULL)) {
			//printf("offset: 0x%x\n", offset);
			if (ReadProcessMemory(hProcess, (LPVOID)(baseAddr + offset + 4), (LPVOID)&machineType, 2, NULL)) {
				//printf("Machine type: 0x%x\n", machineType);
				goto getMachineNtQuery_meow;
			}
		}
	}
getMachineNtQuery_meow:
	if (hProcess) {
		CloseHandle(hProcess);
	}
	return machineType;
}
WORD getMachine_Module(int pid) {
	WORD machineType = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	MODULEENTRY32 me;
	DWORD offset = NULL;
	if (hSnapshot == NULL) {
		goto getMachine_Modulemeow;
	}
	if (hProcess == NULL) {
		goto getMachine_Modulemeow;
	}
	ZeroMemory(&me, sizeof MODULEENTRY32);
	me.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &me)) {
		BYTE* baseAddr = me.modBaseAddr;
		//printf("base addr: 0x%llx\n", baseAddr + 0x3c);
		if (ReadProcessMemory(hProcess, (LPVOID)(baseAddr + 0x3c), (LPVOID)&offset, 4, NULL)) {
			//printf("offset: 0x%x\n", offset);
			if (ReadProcessMemory(hProcess, (LPVOID)(baseAddr + offset + 4), (LPVOID)&machineType, 2, NULL)) {
				//printf("Machine type: 0x%x\n", machineType);
				goto getMachine_Modulemeow;
			}
		}
	}

getMachine_Modulemeow:
	if (hSnapshot) {
		CloseHandle(hSnapshot);
	}
	if (hProcess) {
		CloseHandle(hProcess);
	}
	return machineType;
}
WORD getMachine_EnumProcessModules(int pid) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	WORD machineType = 0;
	HMODULE listModule[1024];
	DWORD lpcbNeeded;
	HMODULE procModule = NULL;
	DWORD offset = NULL;
	if (hProcess == INVALID_HANDLE_VALUE) {
		goto getMachineModule_meow;
	}
	if (EnumProcessModulesEx(hProcess, listModule, sizeof listModule, &lpcbNeeded, LIST_MODULES_ALL)) {
		procModule = listModule[0];
	}
	else {
		goto getMachineModule_meow;
	}
	if (ReadProcessMemory(hProcess, (LPVOID)((BYTE*)procModule + 0x3c), (LPVOID)&offset, 4, NULL)) {
		if (ReadProcessMemory(hProcess, (LPVOID)((BYTE*)procModule + offset + 4), (LPVOID)&machineType, 2, NULL)) {
			goto getMachineModule_meow;
		}
	}
	else {
		printf("error: %d\n", GetLastError());
	}
getMachineModule_meow:
	if (hProcess) {
		CloseHandle(hProcess);
	}
	return machineType;
}
char *findProgramPath(int pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 meowDule;
	char* buffer = NULL;
	ZeroMemory(&meowDule, sizeof(MODULEENTRY32));
	meowDule.dwSize = sizeof(MODULEENTRY32);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		goto programPathMeow;
	}
	if (Module32First(hSnapshot, &meowDule)) {
		buffer = (char*)malloc(strlen(meowDule.szExePath) + 1);
		if (buffer == NULL) {
			goto programPathMeow;
		}
		memset(buffer, 0, strlen(meowDule.szExePath));
		memcpy(buffer, meowDule.szExePath, strlen(meowDule.szExePath));
		buffer[strlen(meowDule.szExePath)] = '\x00';
	}
programPathMeow:
	if (hSnapshot) {
		CloseHandle(hSnapshot);
	}
	return buffer;
}
wchar_t* findCommandLine(int pid, WORD machineType) {
	if (machineType == 0) {
		return NULL;
	}
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	PROCESS_BASIC_INFORMATION pbi;
	wchar_t* buffer = NULL;
	void* procParam;
	UNICODE_STRING myString;	
	PPEB peb;
	pNtQueryInformationProcess myNtQueryInformationProcess;
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll == NULL) {
		goto findCommandLine_meow;
	}
	myNtQueryInformationProcess = (pNtQueryInformationProcess)(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (myNtQueryInformationProcess == NULL) {
		goto findCommandLine_meow;
	}
	myNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof pbi, NULL);
	peb = pbi.PebBaseAddress;
	//printf("peb: 0x%llx\n", peb);
	if (machineType == 0x8664 || machineType == 0x14c) {
		//printf("read from: 0x%llx\n", (BYTE*)peb + 0x20);
		if (ReadProcessMemory(hProcess, (LPVOID)((BYTE*)peb + 0x20), (LPVOID)&procParam, 8, NULL)) {
			//printf("procParam: 0x%llx\n", procParam);
			ReadProcessMemory(hProcess, (LPVOID)((BYTE*)procParam + 0x70), (LPVOID)&myString.Length, 2, NULL);
			ReadProcessMemory(hProcess, (LPVOID)((BYTE*)procParam + 0x70 + 2), (LPVOID)&myString.MaximumLength, 2, NULL);
			ReadProcessMemory(hProcess, (LPVOID)((BYTE*)procParam + 0x70 + 8), (LPVOID)&myString.Buffer, 8, NULL);
			//printf("Length: %x\n", myString.Length);
			//printf("Maximum Length: %x\n", myString.MaximumLength);
			//printf("Buffer: 0x%llx\n", myString.Buffer);
			buffer = (wchar_t*)malloc(2 * myString.Length);
			if (buffer == NULL) {
				goto findCommandLine_meow;
			}
			ReadProcessMemory(hProcess, (LPVOID)(myString.Buffer), (LPVOID)buffer, myString.Length * 2, NULL);
		}
	}
findCommandLine_meow:
	if (hProcess) {
		CloseHandle(hProcess);
	}
	return buffer;
}
void threadIdAndState(int pid) {
	NTSTATUS status;
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	pNtQuerySystemInformation myNtQuerySystemInformation;
	PSYSTEM_PROCESS_INFORMATION spi;
	ULONG returnLength;
	void* buffer = NULL;
	if (ntdll == NULL) {
		goto threadIdAndState_end;
	}
	myNtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (myNtQuerySystemInformation == NULL) {
		goto threadIdAndState_end;
	}
	status = myNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnLength);
	buffer = malloc(returnLength);
	if (buffer == NULL) {
		goto threadIdAndState_end;
	}
	spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
	status = myNtQuerySystemInformation(SystemProcessInformation, spi, returnLength, NULL);
	if (!NT_SUCCESS(status)) {
		goto threadIdAndState_end;
	}
	printf("Thread list: \n");
	while (spi->NextEntryOffset) {
		if ((int)spi->UniqueProcessId == pid) {
			for (int i = 0; i < spi->NumberOfThreads; i++) {
				PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)((BYTE*)spi + sizeof(SYSTEM_PROCESS_INFORMATION) + i * sizeof(SYSTEM_THREAD_INFORMATION));
				printf("- Thread number %u: ThreadID = %u, ThreadState = %s\n", i, sti->ClientId.UniqueThread, ((sti->ThreadState == 5 && sti->WaitReason == 5) ? "SUSPENDED" : "RUNNING"));
			}
		}
		spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
	}
threadIdAndState_end:
	if (buffer) {
		free(buffer);
	}
	return;
}
void enumerateDll(int pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 me;
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		goto enumerateDll_end;
	}
	ZeroMemory(&me, sizeof MODULEENTRY32);
	me.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &me)) {
		printf("Dll list:\n");
		while (Module32Next(hSnapshot, &me)) {
			printf("- %s ", me.szModule);
			printf("0x%llx\n", me.modBaseAddr);
		} 
	}
enumerateDll_end:
	if (hSnapshot) {
		CloseHandle(hSnapshot);
	}
}
void getImports(char* fileName) {
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	void* fileData = NULL;
	DWORD bytesRead = NULL;
	PIMAGE_NT_HEADERS imh = NULL;
	DWORD importDirectoryRVA = NULL;
	DWORD sectionOffset = NULL;
	DWORD rawAddress = NULL;
	DWORD virtualAddress = NULL;
	DWORD importDirectoryRaw = NULL;
	DWORD originalFirstThunk = NULL;
	DWORD firstThunk = NULL;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	PIMAGE_THUNK_DATA importNameTable = NULL;
	file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		goto getImports_end;
	}
	fileSize = GetFileSize(file, NULL);
	fileData = malloc(fileSize);
	if (fileData == NULL) {
		goto getImports_end;
	}
	ReadFile(file, (LPVOID)fileData, fileSize, &bytesRead, NULL);
	if (bytesRead != fileSize) {
		goto getImports_end;
	}
	imh = (PIMAGE_NT_HEADERS)((BYTE*)fileData + *(DWORD*)((BYTE*)fileData + 0x3c));
	importDirectoryRVA = imh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	sectionOffset = 4 + sizeof(IMAGE_FILE_HEADER) + imh->FileHeader.SizeOfOptionalHeader;
	for (int i = 0; i < imh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER currentSection = (PIMAGE_SECTION_HEADER)((BYTE*)imh + sectionOffset);
		if (currentSection->VirtualAddress <= importDirectoryRVA && importDirectoryRVA < currentSection->VirtualAddress + currentSection->Misc.VirtualSize) {
			rawAddress = currentSection->PointerToRawData;
			virtualAddress = currentSection->VirtualAddress;
		}
		sectionOffset += sizeof(IMAGE_SECTION_HEADER);
	}
	importDirectoryRaw = importDirectoryRVA - virtualAddress + rawAddress;
	printf("importDirectoryRVA: 0x%llx, importDirectoryRaw: 0x%llx\n", importDirectoryRVA, importDirectoryRaw);
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileData + importDirectoryRaw);
	printf("importDescriptor: 0x%llx\n", importDescriptor);
	printf("Import information:\n");
	for (; importDescriptor->Name; importDescriptor++) {
		printf("- %s:\n", ((BYTE*)fileData + importDescriptor->Name - virtualAddress + rawAddress));
		importNameTable = (PIMAGE_THUNK_DATA)((BYTE*)fileData + importDescriptor->OriginalFirstThunk - virtualAddress + rawAddress);
		for (; importNameTable->u1.AddressOfData; importNameTable++) {
			if (IMAGE_SNAP_BY_ORDINAL64(importNameTable->u1.Ordinal)) {
				printf("\tOrdinal: 0x%x\n", (WORD)importNameTable->u1.Ordinal);
			}
			else {
				printf("\tFunction: %s\n", ((BYTE*)fileData + importNameTable->u1.AddressOfData - virtualAddress + rawAddress + 2));
			}
		}
	}
getImports_end:
	if (fileData) {
		free(fileData);
	}
	return;
}
void getImports32(char* fileName) {
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	void* fileData = NULL;
	DWORD bytesRead = NULL;
	PIMAGE_NT_HEADERS32 imh = NULL;
	DWORD importDirectoryRVA = NULL;
	DWORD sectionOffset = NULL;
	DWORD rawAddress = NULL;
	DWORD virtualAddress = NULL;
	DWORD importDirectoryRaw = NULL;
	DWORD originalFirstThunk = NULL;
	DWORD firstThunk = NULL;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	PIMAGE_THUNK_DATA32 importNameTable = NULL;
	file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		goto getImports32_end;
	}
	fileSize = GetFileSize(file, NULL);
	fileData = malloc(fileSize);
	if (fileData == NULL) {
		goto getImports32_end;
	}
	ReadFile(file, (LPVOID)fileData, fileSize, &bytesRead, NULL);
	if (bytesRead != fileSize) {
		goto getImports32_end;
	}
	imh = (PIMAGE_NT_HEADERS32)((BYTE*)fileData + *(DWORD*)((BYTE*)fileData + 0x3c));
	importDirectoryRVA = imh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	sectionOffset = 4 + sizeof(IMAGE_FILE_HEADER) + imh->FileHeader.SizeOfOptionalHeader;
	for (int i = 0; i < imh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER currentSection = (PIMAGE_SECTION_HEADER)((BYTE*)imh + sectionOffset);
		if (currentSection->VirtualAddress <= importDirectoryRVA && importDirectoryRVA < currentSection->VirtualAddress + currentSection->Misc.VirtualSize) {
			rawAddress = currentSection->PointerToRawData;
			virtualAddress = currentSection->VirtualAddress;
		}
		sectionOffset += sizeof(IMAGE_SECTION_HEADER);
	}
	importDirectoryRaw = importDirectoryRVA - virtualAddress + rawAddress;
	printf("importDirectoryRVA: 0x%x, importDirectoryRaw: 0x%x\n", importDirectoryRVA, importDirectoryRaw);
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileData + importDirectoryRaw);
	printf("importDescriptor: 0x%x\n", importDescriptor);
	printf("Import information:\n");
	for (; importDescriptor->Name; importDescriptor++) {
		printf("- %s:\n", ((BYTE*)fileData + importDescriptor->Name - virtualAddress + rawAddress));
		importNameTable = (PIMAGE_THUNK_DATA32)((BYTE*)fileData + importDescriptor->OriginalFirstThunk - virtualAddress + rawAddress);
		for (; importNameTable->u1.AddressOfData; importNameTable++) {
			if (IMAGE_SNAP_BY_ORDINAL32(importNameTable->u1.Ordinal)) {
				printf("\tOrdinal: 0x%x\n", (WORD)importNameTable->u1.Ordinal);
			}
			else {
				printf("\tFunction: %s\n", ((BYTE*)fileData + importNameTable->u1.AddressOfData - virtualAddress + rawAddress + 2));
			}
		}
	}
getImports32_end:
	if (fileData) {
		free(fileData);
	}
	return;
}
int main(int argc, char *argv[], char *envp[])
{
	if (argc == 1) {
		printf("Using: %s targetProcessName", argv[0]);
		return -1;
	}
	//printf("Process name: %s\n", argv[1]);
	pidList pid = findPID_and_parentPID(argv[1]);
		
	if (pid.pid == -1 && pid.parentPID == -1) {
		printf("Couldnt find your process...");
		return -2;
	}

	printf("PID: %d\n", pid.pid);
	printf("Parent PID: %d\n", pid.parentPID);
	WORD machineType = getMachine_EnumProcessModules(pid.pid);
	if (machineType != 0) {
		printf("Machine Type: %s\n", (machineType == 0x8664 ? "x64" : (machineType == 0x14c ? "x86" : "invalid machine type")));
	}
	char* fullProgramPath = findProgramPath(pid.pid);
	if (fullProgramPath) {
		printf("Program full path: %s\n", fullProgramPath);
	}
	wchar_t* commandLine = findCommandLine(pid.pid, machineType);
	//printf("where?: 0x%llx\n", commandLine);
	if (commandLine) {
		printf("Program command line: %ws\n", commandLine);
	}
	if (pid.pid) {
		threadIdAndState(pid.pid);
		enumerateDll(pid.pid);
	}
	if (machineType && fullProgramPath) {
		if (machineType == 0x8664) getImports(fullProgramPath);
		else if (machineType == 0x14c) getImports32(fullProgramPath);
	}
	return 0;
}
