#include <windows.h>

/////////////////////
//  CALLBACK ARGS  //
/////////////////////

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNoHookedSyscallAddr;       // pointer to Syscall inst - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9;
    SIZE_T zeroBits;
    ULONG allocationType;                // MEM_RESERVE | MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, * PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    UINT_PTR pNoHookedSyscallAddr;
    HANDLE hProcess;
    PVOID address;
    PVOID buffer;
    ULONG numberOfBytesToWrite;
    PULONG numberOfBytesWritten;
} NTWRITEVIRTUALMEMORY_ARGS, * PNTWRITEVIRTUALMEMORY_ARGS;

typedef struct _NTCREATETHREADEX_ARGS {
    UINT_PTR pNoHookedSyscallAddr;
    PHANDLE threadHandle;        // Pointer to a variable that receives a handle to the new thread
    ACCESS_MASK desiredAccess;   // Desired access to the thread
    PVOID objectAttributes;      // Pointer to an OBJECT_ATTRIBUTES structure that specifies the object's attributes
    HANDLE processHandle;        // Handle to the process in which the thread is to be created
    PVOID lpStartAddress;        // Pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread
    PVOID lpParameter;           // Pointer to a variable to be passed to the thread
    ULONG flags;                 // Flags that control the creation of the thread
    SIZE_T stackZeroBits;        // A pointer to a variable that specifies the number of high-order address bits that must be zero in the stack pointer
    SIZE_T sizeOfStackCommit;    // The size of the stack that must be committed at thread creation
    SIZE_T sizeOfStackReserve;   // The size of the stack that must be reserved at thread creation
    PVOID lpBytesBuffer;          // Pointer to a variable that receives any output data from the system
} NTCREATETHREADEX_ARGS, * PNTCREATETHREADEX_ARGS;

//////////////////////////
//  ASSEMBLY FUNCTIONS  //
//////////////////////////

extern "C" void NtAllocateVirtualMemory_Callback(
    HANDLE processHandle,
    PVOID address,
    SIZE_T zeroBits,
    PSIZE_T size,
    ULONG allocationType,
    ULONG permissions,
    UINT_PTR pNoHookedSyscallAddr
);

extern "C" void NtWriteVirtualMemory_Callback(
    HANDLE hProcess,
    PVOID address,
    PVOID buffer,
    ULONG numberOfBytesToWrite,
    PULONG numberOfBytesWritten,
    UINT_PTR pNoHookedSyscallAddr
);

extern "C" void NtCreateThreadEx_Callback(
    PHANDLE threadHandle,
    ACCESS_MASK desiredAccess,
    PVOID objectAttributes,
    HANDLE processHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG flags,
    SIZE_T stackZeroBits,
    SIZE_T sizeOfStackCommit,
    SIZE_T sizeOfStackReserve,
    PVOID lpBytesBuffer,
    UINT_PTR pNoHookedSyscallAddr
);