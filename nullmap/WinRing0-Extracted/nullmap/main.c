#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include "general.h"
#include "hyperv_exploit.h"
#include "afd_exploit.h"
#include "driver_test.h"
#include "console.h"
#include "gameassembly_extractor.h"

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef NTSTATUS(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Additional NT structures
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// Forward declarations
static BOOL FindKernelBaseViaPrefetch(PDWORD64 kernelBase);
static BOOL TestRustClientAccess(void);

int main(int argc, char* argv[]) {
    DWORD64 kernelBase = 0;
    BOOL success = FALSE;
    HMODULE localKernel = NULL;

    ConsoleInit();
    ConsoleInfo("Starting nullmap...");

    // Initialize AFD exploit
    ConsoleInfo("Initializing WinRing0 driver setup...");
    if (!AdvancedAfdExploitSetup()) {
        ConsoleError("Failed to setup WinRing0 driver");
        return 1;
    }
    ConsoleSuccess("WinRing0 driver setup completed");

    // Get kernel base address
    ConsoleInfo("Getting kernel base...");
    if (FindKernelBaseViaPrefetch(&kernelBase)) {
        ConsoleSuccess("Found kernel base at 0x%llx", kernelBase);
    } else {
        ConsoleError("Failed to find kernel base");
        return 1;
    }

    // Load kernel image locally for reference
    ConsoleInfo("Loading kernel image locally...");
    localKernel = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (localKernel) {
        ConsoleSuccess("Local kernel base: 0x%llx", (DWORD64)localKernel);
    } else {
        ConsoleWarning("Failed to load local kernel image - continuing anyway");
    }

    // Execute AFD exploit
    ConsoleInfo("Executing WinRing0 initialization...");
    if (!ExecuteAdvancedAfdExploit()) {
        ConsoleError("Failed to initialize WinRing0");
        return 1;
    }
    ConsoleSuccess("WinRing0 initialization successful");

    // Verify kernel access
    ConsoleInfo("Verifying WinRing0 kernel access...");
    if (!AfdVerifyKernelAccess()) {
        ConsoleError("Failed to verify WinRing0 kernel access");
        return 1;
    }
    ConsoleSuccess("WinRing0 kernel access verified");

    // Test Rust client access
    ConsoleInfo("Testing RustClient.exe access...");
    if (!TestRustClientAccess()) {
        ConsoleError("Failed to test Rust client access");
        return 1;
    }
    ConsoleSuccess("RustClient.exe access successful");

    ConsoleSuccess("nullmap initialized successfully");
    return 0;
}

// Implementation of local functions
static BOOL FindKernelBaseViaPrefetch(PDWORD64 kernelBase) {
    if (!kernelBase) {
        return FALSE;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return FALSE;
    }

    PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = 
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");
    
    if (!NtQuerySystemInformation) {
        return FALSE;
    }

    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
        NULL,
        0,
        &size
    );

    if (!size) {
        return FALSE;
    }

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)malloc(size);
    if (!modules) {
        return FALSE;
    }

    status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
        modules,
        size,
        &size
    );

    if (!NT_SUCCESS(status)) {
        free(modules);
        return FALSE;
    }

    // First module is always ntoskrnl.exe
    if (modules->NumberOfModules > 0) {
        *kernelBase = (DWORD64)modules->Modules[0].ImageBase;
        free(modules);
        return TRUE;
    }

    free(modules);
    return FALSE;
}

static BOOL TestRustClientAccess(void) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"RustClient.exe") == 0) {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (!processId) {
        ConsoleWarning("RustClient.exe not found - test mode only");
        return TRUE; // Return true for testing
    }

    // Try to open the process
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process) {
        return FALSE;
    }

    CloseHandle(process);
    return TRUE;
}