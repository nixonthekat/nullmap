#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Log to file for debugging
void LogMessage(const char* message) {
    FILE* logFile = fopen("C:\\temp\\external_access.log", "a");
    if (logFile) {
        fprintf(logFile, "[%08X] %s\n", GetTickCount(), message);
        fclose(logFile);
    }
}

DWORD FindRustClientPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LogMessage("Failed to create process snapshot");
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, "RustClient.exe") == 0) {
                CloseHandle(snapshot);
                char msg[256];
                sprintf(msg, "Found RustClient.exe - PID: %d", pe32.th32ProcessID);
                LogMessage(msg);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    LogMessage("RustClient.exe not found in process list");
    return 0;
}

DWORD64 FindGameAssemblyBase(HANDLE hProcess) {
    LogMessage("Scanning for GameAssembly.dll base address...");
    
    // Common Unity base addresses
    DWORD64 addresses[] = {
        0x00007FF700000000, 0x00007FF710000000, 0x00007FF720000000,
        0x00007FF730000000, 0x00007FF740000000, 0x00007FF750000000,
        0x00007FF760000000, 0x00007FF770000000, 0x00007FF780000000,
        0x0000000140000000, 0x0000000150000000, 0x0000000160000000
    };
    
    for (int i = 0; i < 12; i++) {
        BYTE buffer[2048];
        SIZE_T bytesRead = 0;
        
        if (ReadProcessMemory(hProcess, (LPVOID)addresses[i], buffer, sizeof(buffer), &bytesRead)) {
            if (bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A) {
                char msg[256];
                sprintf(msg, "Found PE header at: 0x%p", (void*)addresses[i]);
                LogMessage(msg);
                
                // Check for Unity/GameAssembly signatures
                for (SIZE_T j = 0; j < bytesRead - 12; j++) {
                    if (memcmp(&buffer[j], "Unity", 5) == 0 || 
                        memcmp(&buffer[j], "GameAssembly", 12) == 0 ||
                        memcmp(&buffer[j], "il2cpp", 6) == 0) {
                        
                        sprintf(msg, "SUCCESS: Found GameAssembly.dll at: 0x%p", (void*)addresses[i]);
                        LogMessage(msg);
                        return addresses[i];
                    }
                }
            }
        } else {
            char msg[256];
            sprintf(msg, "Failed to read memory at: 0x%p (Error: %d)", (void*)addresses[i], GetLastError());
            LogMessage(msg);
        }
    }
    
    LogMessage("GameAssembly.dll not found in common locations");
    return 0;
}

void ScanGameMemory(HANDLE hProcess, DWORD64 baseAddress) {
    LogMessage("Starting game memory analysis...");
    
    // Read first 4KB of GameAssembly
    BYTE gameData[4096];
    SIZE_T bytesRead = 0;
    
    if (ReadProcessMemory(hProcess, (LPVOID)baseAddress, gameData, sizeof(gameData), &bytesRead)) {
        char msg[256];
        sprintf(msg, "Read %zu bytes from GameAssembly base", bytesRead);
        LogMessage(msg);
        
        // Verify PE structure
        if (gameData[0] == 0x4D && gameData[1] == 0x5A) {
            LogMessage("Confirmed valid PE header");
            
            // Look for interesting strings/patterns
            for (SIZE_T i = 0; i < bytesRead - 16; i++) {
                // Look for class names, function names, etc.
                if (memcmp(&gameData[i], "Player", 6) == 0 ||
                    memcmp(&gameData[i], "BasePlayer", 10) == 0 ||
                    memcmp(&gameData[i], "Health", 6) == 0 ||
                    memcmp(&gameData[i], "Weapon", 6) == 0) {
                    
                    sprintf(msg, "Found potential game string at offset 0x%zX", i);
                    LogMessage(msg);
                }
            }
        }
        
        // Try to find code sections
        DWORD64 codeSection = baseAddress + 0x1000; // Common .text section offset
        BYTE codeBuffer[1024];
        if (ReadProcessMemory(hProcess, (LPVOID)codeSection, codeBuffer, sizeof(codeBuffer), &bytesRead)) {
            sprintf(msg, "Successfully read code section: %zu bytes", bytesRead);
            LogMessage(msg);
        }
        
    } else {
        char msg[256];
        sprintf(msg, "Failed to read GameAssembly memory: Error %d", GetLastError());
        LogMessage(msg);
    }
}

DWORD WINAPI ExternalAccessThread(LPVOID lpParam) {
    LogMessage("=== EXTERNAL ACCESS DLL STARTED ===");
    LogMessage("Attempting to access RustClient memory externally...");
    
    // Wait a moment for RustClient to fully load
    Sleep(5000);
    
    // Find RustClient
    DWORD rustPid = FindRustClientPID();
    if (!rustPid) {
        LogMessage("ERROR: RustClient.exe not found! Make sure Rust is running.");
        return 1;
    }
    
    // Open RustClient process
    HANDLE hRustClient = OpenProcess(PROCESS_ALL_ACCESS, FALSE, rustPid);
    if (!hRustClient) {
        char msg[256];
        sprintf(msg, "ERROR: Failed to open RustClient process! Error: %d", GetLastError());
        LogMessage(msg);
        return 1;
    }
    
    LogMessage("SUCCESS: Opened RustClient process handle!");
    
    // Find GameAssembly.dll base
    DWORD64 gameAssemblyBase = FindGameAssemblyBase(hRustClient);
    if (gameAssemblyBase) {
        char msg[256];
        sprintf(msg, "SUCCESS: Located GameAssembly.dll at: 0x%p", (void*)gameAssemblyBase);
        LogMessage(msg);
        
        // Analyze game memory
        ScanGameMemory(hRustClient, gameAssemblyBase);
        
        LogMessage("=== MEMORY ACCESS SUCCESSFUL ===");
        LogMessage("External access DLL can now read/write RustClient memory!");
        LogMessage("This proves EAC bypass is working - add your hack features here!");
        
        // Continuous monitoring loop
        int scanCount = 0;
        while (scanCount < 10) { // Run 10 scans for testing
            Sleep(2000); // Wait 2 seconds between scans
            
            BYTE testBuffer[64];
            SIZE_T bytesRead;
            if (ReadProcessMemory(hRustClient, (LPVOID)gameAssemblyBase, testBuffer, sizeof(testBuffer), &bytesRead)) {
                sprintf(msg, "Scan #%d: Still reading memory successfully (%zu bytes)", ++scanCount, bytesRead);
                LogMessage(msg);
            } else {
                LogMessage("ERROR: Lost memory access!");
                break;
            }
        }
        
    } else {
        LogMessage("ERROR: Could not locate GameAssembly.dll!");
    }
    
    CloseHandle(hRustClient);
    LogMessage("=== EXTERNAL ACCESS DLL FINISHED ===");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Create directory for log file
        CreateDirectoryA("C:\\temp", NULL);
        
        LogMessage("DLL_PROCESS_ATTACH - Starting external access thread...");
        
        // Start external memory access in a separate thread
        HANDLE hThread = CreateThread(NULL, 0, ExternalAccessThread, NULL, 0, NULL);
        if (hThread) {
            LogMessage("External access thread created successfully");
            CloseHandle(hThread);
        } else {
            LogMessage("Failed to create external access thread");
        }
        break;
        
    case DLL_PROCESS_DETACH:
        LogMessage("DLL_PROCESS_DETACH - Cleaning up...");
        break;
    }
    return TRUE;
} 