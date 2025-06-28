#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include "general.h"
#include "driver_interface.h"

// Driver communication
static HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
static BOOL g_DriverLoaded = FALSE;

BOOL LoadNullmapDriver(void) {
    ConsoleInfo("Loading kernel driver for EAC bypass...");
    
    // Try to open existing driver
    g_DriverHandle = CreateFileA(
        "\\\\.\\NullmapDriver",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (g_DriverHandle != INVALID_HANDLE_VALUE) {
        ConsoleSuccess("Kernel driver already loaded and accessible");
        g_DriverLoaded = TRUE;
        return TRUE;
    }
    
    // Try to load driver using service manager
    if (LoadDriverViaService()) {
        // Try to open again
        g_DriverHandle = CreateFileA(
            "\\\\.\\NullmapDriver",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (g_DriverHandle != INVALID_HANDLE_VALUE) {
            ConsoleSuccess("Kernel driver loaded successfully via service");
            g_DriverLoaded = TRUE;
            return TRUE;
        }
    }
    
    ConsoleError("Failed to load kernel driver");
    return FALSE;
}

BOOL LoadDriverViaService(void) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    BOOL result = FALSE;
    
    ConsoleInfo("Attempting to load driver via Service Manager...");
    
    // Open service manager
    scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        ConsoleError("Failed to open Service Manager: %d", GetLastError());
        return FALSE;
    }
    
    // Create service for driver
    service = CreateServiceA(
        scManager,
        "NullmapDriver",
        "Nullmap Kernel Driver",
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        "C:\\Windows\\System32\\drivers\\nullmap.sys", // Driver path
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            ConsoleInfo("Service already exists, opening existing service...");
            service = OpenServiceA(scManager, "NullmapDriver", SERVICE_ALL_ACCESS);
        }
        
        if (!service) {
            ConsoleError("Failed to create/open service: %d", GetLastError());
            CloseServiceHandle(scManager);
            return FALSE;
        }
    }
    
    // Start the service
    if (StartServiceA(service, 0, NULL)) {
        ConsoleSuccess("Driver service started successfully");
        result = TRUE;
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            ConsoleInfo("Driver service already running");
            result = TRUE;
        } else {
            ConsoleError("Failed to start driver service: %d", error);
        }
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    
    return result;
}

BOOL UnloadNullmapDriver(void) {
    if (g_DriverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }
    
    if (g_DriverLoaded) {
        UnloadDriverViaService();
        g_DriverLoaded = FALSE;
    }
    
    ConsoleInfo("Kernel driver unloaded");
    return TRUE;
}

BOOL UnloadDriverViaService(void) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS serviceStatus;
    
    // Open service manager
    scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        return FALSE;
    }
    
    // Open service
    service = OpenServiceA(scManager, "NullmapDriver", SERVICE_ALL_ACCESS);
    if (service) {
        // Stop service
        ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus);
        
        // Delete service
        DeleteService(service);
        
        CloseServiceHandle(service);
    }
    
    CloseServiceHandle(scManager);
    return TRUE;
}

BOOL DriverReadProcessMemory(DWORD processId, PVOID address, PVOID buffer, DWORD size) {
    if (!g_DriverLoaded || g_DriverHandle == INVALID_HANDLE_VALUE) {
        ConsoleError("Driver not loaded for memory reading");
        return FALSE;
    }
    
    DRIVER_MEMORY_REQUEST request = { 0 };
    request.ProcessId = processId;
    request.Address = address;
    request.Buffer = buffer;
    request.Size = size;
    
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        g_DriverHandle,
        IOCTL_READ_PROCESS_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );
    
    if (result) {
        ConsoleSuccess("Driver read %d bytes from process %d at 0x%p", size, processId, address);
    } else {
        ConsoleError("Driver read failed: %d", GetLastError());
    }
    
    return result;
}

BOOL DriverWriteProcessMemory(DWORD processId, PVOID address, PVOID buffer, DWORD size) {
    if (!g_DriverLoaded || g_DriverHandle == INVALID_HANDLE_VALUE) {
        ConsoleError("Driver not loaded for memory writing");
        return FALSE;
    }
    
    DRIVER_MEMORY_REQUEST request = { 0 };
    request.ProcessId = processId;
    request.Address = address;
    request.Buffer = buffer;
    request.Size = size;
    
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        g_DriverHandle,
        IOCTL_WRITE_PROCESS_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );
    
    if (result) {
        ConsoleSuccess("Driver wrote %d bytes to process %d at 0x%p", size, processId, address);
    } else {
        ConsoleError("Driver write failed: %d", GetLastError());
    }
    
    return result;
}

BOOL DriverGetProcessPeb(DWORD processId, PVOID* pebAddress) {
    if (!g_DriverLoaded || g_DriverHandle == INVALID_HANDLE_VALUE) {
        ConsoleError("Driver not loaded for PEB access");
        return FALSE;
    }
    
    DRIVER_PEB_REQUEST request = { 0 };
    request.ProcessId = processId;
    
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        g_DriverHandle,
        IOCTL_GET_PROCESS_PEB,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );
    
    if (result) {
        *pebAddress = request.PebAddress;
        ConsoleSuccess("Driver found PEB for process %d at 0x%p", processId, *pebAddress);
    } else {
        ConsoleError("Driver PEB access failed: %d", GetLastError());
    }
    
    return result;
}

BOOL DriverEnumerateProcessModules(DWORD processId, PDRIVER_MODULE_INFO modules, DWORD maxModules, DWORD* moduleCount) {
    if (!g_DriverLoaded || g_DriverHandle == INVALID_HANDLE_VALUE) {
        ConsoleError("Driver not loaded for module enumeration");
        return FALSE;
    }
    
    // Allocate request buffer
    DWORD requestSize = sizeof(DRIVER_MODULE_REQUEST) + (maxModules * sizeof(DRIVER_MODULE_INFO));
    PDRIVER_MODULE_REQUEST request = (PDRIVER_MODULE_REQUEST)malloc(requestSize);
    if (!request) {
        ConsoleError("Failed to allocate memory for module request");
        return FALSE;
    }
    
    request->ProcessId = processId;
    request->ModuleCount = 0;
    
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        g_DriverHandle,
        IOCTL_ENUM_PROCESS_MODULES,
        request,
        requestSize,
        request,
        requestSize,
        &bytesReturned,
        NULL
    );
    
    if (result) {
        *moduleCount = request->ModuleCount;
        
        // Copy module info
        for (DWORD i = 0; i < request->ModuleCount && i < maxModules; i++) {
            modules[i] = request->Modules[i];
        }
        
        ConsoleSuccess("Driver enumerated %d modules for process %d", request->ModuleCount, processId);
    } else {
        ConsoleError("Driver module enumeration failed: %d", GetLastError());
        *moduleCount = 0;
    }
    
    free(request);
    return result;
}

BOOL DriverFindGameAssembly(DWORD processId, DWORD64* moduleBase, DWORD* moduleSize) {
    ConsoleInfo("🚀 KERNEL DRIVER: Bypassing EAC with direct kernel access...");
    
    if (!g_DriverLoaded) {
        ConsoleError("Kernel driver not available");
        return FALSE;
    }
    
    // Get process PEB directly from kernel
    PVOID pebAddress = NULL;
    if (!DriverGetProcessPeb(processId, &pebAddress)) {
        ConsoleError("Failed to get PEB via kernel driver");
        return FALSE;
    }
    
    ConsoleSuccess("✅ KERNEL BYPASS: PEB accessed at 0x%p (EAC bypassed!)", pebAddress);
    
    // Enumerate process modules via kernel
    DRIVER_MODULE_INFO modules[256];
    DWORD moduleCount = 0;
    
    if (!DriverEnumerateProcessModules(processId, modules, 256, &moduleCount)) {
        ConsoleError("Failed to enumerate modules via kernel driver");
        return FALSE;
    }
    
    ConsoleSuccess("✅ KERNEL BYPASS: Enumerated %d modules (EAC bypassed!)", moduleCount);
    
    // Find GameAssembly.dll
    for (DWORD i = 0; i < moduleCount; i++) {
        if (_wcsicmp(modules[i].ModuleName, L"GameAssembly.dll") == 0) {
            *moduleBase = (DWORD64)modules[i].BaseAddress;
            *moduleSize = modules[i].Size;
            
            ConsoleSuccess("🎯 KERNEL SUCCESS: GameAssembly.dll found!");
            ConsoleSuccess("   Base: 0x%016llX", *moduleBase);
            ConsoleSuccess("   Size: 0x%X", *moduleSize);
            ConsoleSuccess("   🔥 EAC COMPLETELY BYPASSED via kernel driver!");
            
            return TRUE;
        }
    }
    
    ConsoleError("GameAssembly.dll not found in module list");
    return FALSE;
}

BOOL TestDriverFunctionality(void) {
    ConsoleInfo("Testing kernel driver functionality...");
    
    if (!g_DriverLoaded) {
        ConsoleError("Driver not loaded");
        return FALSE;
    }
    
    // Test reading current process memory
    DWORD currentPid = GetCurrentProcessId();
    PVOID pebAddress = NULL;
    
    if (DriverGetProcessPeb(currentPid, &pebAddress)) {
        ConsoleSuccess("Driver PEB test successful");
        
        // Test reading PEB
        BYTE pebBuffer[0x100];
        if (DriverReadProcessMemory(currentPid, pebAddress, pebBuffer, sizeof(pebBuffer))) {
            ConsoleSuccess("Driver memory read test successful");
            ConsoleInfo("PEB signature: %02X %02X %02X %02X", 
                      pebBuffer[0], pebBuffer[1], pebBuffer[2], pebBuffer[3]);
            return TRUE;
        }
    }
    
    ConsoleError("Driver functionality test failed");
    return FALSE;
} 