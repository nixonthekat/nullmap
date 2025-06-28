#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "general.h"
#include "driver_test.h"
#include "hyperv_exploit.h"

BOOL FindGameProcess(const char* processName, GAME_CONTEXT* context) {
    // Convert process name to wide string
    WCHAR wProcessName[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, processName, -1, wProcessName, MAX_PATH) == 0) {
        ConsoleError("Failed to convert process name: %d", GetLastError());
        return FALSE;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        ConsoleError("Failed to create process snapshot: %d", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    BOOL found = FALSE;

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, wProcessName) == 0) {
                context->processId = processEntry.th32ProcessID;
                found = TRUE;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);

    if (!found) {
        ConsoleError("Process %s not found", processName);
        return FALSE;
    }

    // Try to open the process with required access
    context->processHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        context->processId
    );

    if (!context->processHandle) {
        ConsoleError("Failed to open process handle: %d", GetLastError());
        return FALSE;
    }

    ConsoleSuccess("Found %s - PID: %d", processName, context->processId);
    ConsoleSuccess("Successfully opened %s process handle", processName);
    return TRUE;
}

BOOL FindGameAssemblyKernel(GAME_CONTEXT* context) {
    ConsoleInfo("Attempting kernel-level GameAssembly.dll detection...");

    BYTE buffer[MAX_SAFE_READ_SIZE];
    
    // Read process CR3 using Hyper-V exploit
    ConsoleInfo("Reading process structures...");
    
    // Read process DirectoryTableBase (CR3)
    if (!HyperVExploitRead((ULONG64)context->processHandle + 0x28, buffer, sizeof(DWORD64))) {
        ConsoleWarning("Failed to read process CR3 - trying alternative method");
        return FALSE;
    }
    
    DWORD64 processCr3 = *(DWORD64*)buffer;
    ConsoleInfo("Process CR3: 0x%016llX", processCr3);

    // Read PEB address safely
    if (!HyperVExploitRead((ULONG64)context->processHandle + 0x3F8, buffer, sizeof(DWORD64))) {
        ConsoleWarning("Failed to read PEB address - trying alternative method");
        return FALSE;
    }
    
    DWORD64 pebAddress = *(DWORD64*)buffer;
    if (!pebAddress) {
        ConsoleWarning("Invalid PEB address");
        return FALSE;
    }
    
    ConsoleInfo("PEB Address: 0x%016llX", pebAddress);

    // Read Ldr from PEB safely
    if (!HyperVExploitRead(pebAddress + 0x18, buffer, sizeof(DWORD64))) {
        ConsoleWarning("Failed to read PEB.Ldr");
        return FALSE;
    }
    
    DWORD64 ldrAddress = *(DWORD64*)buffer;
    if (!ldrAddress) {
        ConsoleWarning("Invalid LDR address");
        return FALSE;
    }

    // Read first module link
    if (!HyperVExploitRead(ldrAddress + 0x10, buffer, sizeof(DWORD64))) {
        ConsoleWarning("Failed to read module list");
        return FALSE;
    }
    
    DWORD64 firstLink = *(DWORD64*)buffer;
    if (!firstLink) {
        ConsoleWarning("Invalid module list");
        return FALSE;
    }
    
    DWORD64 currentLink = firstLink;
    WCHAR moduleName[256];
    UNICODE_STRING moduleNameUs;
    int moduleCount = 0;
    const int MAX_MODULES = 1000; // Safety limit
    
    ConsoleInfo("Scanning loaded modules...");
    
    do {
        if (moduleCount++ > MAX_MODULES) {
            ConsoleWarning("Module limit exceeded - possible circular list");
            return FALSE;
        }

        // Read module entry carefully
        if (!HyperVExploitRead(currentLink + 0x60, buffer, sizeof(UNICODE_STRING))) {
            ConsoleWarning("Failed to read module name structure at 0x%016llX", currentLink);
            break;
        }
        
        moduleNameUs = *(UNICODE_STRING*)buffer;

        if (moduleNameUs.Length > 0 && moduleNameUs.Length < 512 && moduleNameUs.Buffer) {
            // Read module name
            if (!HyperVExploitRead((ULONG64)moduleNameUs.Buffer, buffer, moduleNameUs.Length)) {
                ConsoleWarning("Failed to read module name buffer");
                break;
            }
            
            // Copy and null terminate
            memcpy(moduleName, buffer, moduleNameUs.Length);
            moduleName[moduleNameUs.Length/2] = L'\0';
            
            // Check for our target
            if (wcsstr(moduleName, L"GameAssembly.dll") != NULL) {
                ConsoleInfo("Found GameAssembly.dll entry, reading details...");
                
                // Read base address
                if (!HyperVExploitRead(currentLink + 0x30, buffer, sizeof(DWORD64))) {
                    ConsoleWarning("Failed to read module base address");
                    break;
                }
                
                context->gameAssemblyBase = *(DWORD64*)buffer;
                ConsoleSuccess("Found GameAssembly.dll at 0x%016llX", context->gameAssemblyBase);
                
                // Read image size
                if (!HyperVExploitRead(currentLink + 0x40, buffer, sizeof(DWORD64))) {
                    ConsoleWarning("Failed to read module size");
                    // Continue anyway since we have the base address
                }
                
                context->gameAssemblySize = *(DWORD64*)buffer;
                context->gameAssemblyFound = TRUE;
                return TRUE;
            }
        }

        // Move to next entry safely
        if (!HyperVExploitRead(currentLink, buffer, sizeof(DWORD64))) {
            ConsoleWarning("Failed to read next module link");
            break;
        }
        
        currentLink = *(DWORD64*)buffer;

    } while (currentLink && currentLink != firstLink);

    ConsoleInfo("Finished scanning modules - GameAssembly.dll not found");
    return FALSE;
}

BOOL SetupProcessHollow(GAME_CONTEXT* context) {
    ConsoleInfo("Setting up process hollowing...");

    // Create suspended SteelSeries.gg process
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;
    WCHAR cmdLine[] = L"C:\\Program Files\\SteelSeries\\GG\\SteelSeries GG.exe";
    
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        ConsoleError("Failed to create hollow process: %d", GetLastError());
        return FALSE;
    }

    context->hollowedHandle = pi.hProcess;
    context->isHollowed = TRUE;

    ConsoleSuccess("Created hollow process: %d", pi.dwProcessId);
    return TRUE;
}

BOOL BypassEacProtection(GAME_CONTEXT* context) {
    ConsoleInfo("Initiating EAC protection bypass...");

    // First try kernel-level detection
    if (!FindGameAssemblyKernel(context)) {
        ConsoleWarning("Kernel-level detection failed, trying process hollowing...");
        
        // Set up process hollowing as fallback
        if (!SetupProcessHollow(context)) {
            return FALSE;
        }
        
        // Try memory scanning in hollowed process context
        ConsoleInfo("Attempting memory scan through hollowed process...");
        
        // Common Unity base addresses to scan
        DWORD64 addresses[] = {
            0x00007FF700000000, 0x00007FF710000000, 0x00007FF720000000,
            0x00007FF730000000, 0x00007FF740000000, 0x00007FF750000000,
            0x00007FF760000000, 0x00007FF770000000, 0x00007FF780000000
        };
        
        for (int i = 0; i < sizeof(addresses)/sizeof(addresses[0]); i++) {
            BYTE buffer[2048];
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(context->hollowedHandle, (LPVOID)addresses[i], 
                buffer, sizeof(buffer), &bytesRead)) {
                
                if (bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A) {
                    ConsoleInfo("Found potential PE header at: 0x%p", (void*)addresses[i]);
                    
                    // Verify Unity signatures
                    for (SIZE_T j = 0; j < bytesRead - 12; j++) {
                        if (memcmp(&buffer[j], "Unity", 5) == 0 || 
                            memcmp(&buffer[j], "GameAssembly", 12) == 0 ||
                            memcmp(&buffer[j], "il2cpp", 6) == 0) {
                            
                            context->gameAssemblyBase = addresses[i];
                            context->gameAssemblyFound = TRUE;
                            ConsoleSuccess("Located GameAssembly.dll via hollowed process");
                            return TRUE;
                        }
                    }
                }
            }
        }
    }

    return context->gameAssemblyFound;
}

BOOL FindGameAssembly(GAME_CONTEXT* context) {
    // First try normal module enumeration
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, context->processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        ConsoleWarning("Failed to create module snapshot: %d", GetLastError());
        ConsoleInfo("Attempting enhanced GameAssembly detection...");
        return BypassEacProtection(context);
    }

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);
    
    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            if (_wcsicmp(moduleEntry.szModule, L"GameAssembly.dll") == 0) {
                context->gameAssemblyBase = (DWORD64)moduleEntry.modBaseAddr;
                context->gameAssemblyFound = TRUE;
                CloseHandle(snapshot);
                return TRUE;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }
    
    CloseHandle(snapshot);
    
    // If normal enumeration fails, try our bypass methods
    return BypassEacProtection(context);
}

void ShowTestMenu(void) {
    ConsoleInfo("=== Driver Test Menu ===");
    ConsoleInfo("1. Find Game Process");
    ConsoleInfo("2. Test Memory Operations");
    ConsoleInfo("3. Exit");
}

BOOL HandleTestMode(void) {
    ConsoleInfo("Entering test mode...");
    
    GAME_CONTEXT context = { 0 };
    
    // Try to find Rust process
    if (FindGameProcess(RUST_PROCESS_NAME, &context)) {
        ConsoleSuccess("Successfully found and opened game process");
        
        // Try kernel-level detection
        if (FindGameAssemblyKernel(&context)) {
            ConsoleSuccess("Kernel-level GameAssembly detection successful");
        } else {
            ConsoleWarning("Kernel-level detection failed, trying usermode");
        }
    } else {
        ConsoleWarning("Game process not found, continuing with other tests");
    }
    
    ShowTestMenu();
    return TRUE;
} 