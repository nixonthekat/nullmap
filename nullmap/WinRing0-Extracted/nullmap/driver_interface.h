#ifndef DRIVER_INTERFACE_H
#define DRIVER_INTERFACE_H

#include <Windows.h>

// IOCTL codes for driver communication
#define IOCTL_READ_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_PEB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_PROCESS_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Request structures for driver communication
typedef struct _DRIVER_MEMORY_REQUEST {
    ULONG ProcessId;
    PVOID Address;
    PVOID Buffer;
    ULONG Size;
} DRIVER_MEMORY_REQUEST, *PDRIVER_MEMORY_REQUEST;

typedef struct _DRIVER_PEB_REQUEST {
    ULONG ProcessId;
    PVOID PebAddress;
} DRIVER_PEB_REQUEST, *PDRIVER_PEB_REQUEST;

typedef struct _DRIVER_MODULE_INFO {
    PVOID BaseAddress;
    ULONG Size;
    WCHAR ModuleName[256];
} DRIVER_MODULE_INFO, *PDRIVER_MODULE_INFO;

typedef struct _DRIVER_MODULE_REQUEST {
    ULONG ProcessId;
    ULONG ModuleCount;
    DRIVER_MODULE_INFO Modules[1];
} DRIVER_MODULE_REQUEST, *PDRIVER_MODULE_REQUEST;

// Driver interface functions
BOOL LoadNullmapDriver(void);
BOOL LoadDriverViaService(void);
BOOL UnloadNullmapDriver(void);
BOOL UnloadDriverViaService(void);

// Driver communication functions
BOOL DriverReadProcessMemory(DWORD processId, PVOID address, PVOID buffer, DWORD size);
BOOL DriverWriteProcessMemory(DWORD processId, PVOID address, PVOID buffer, DWORD size);
BOOL DriverGetProcessPeb(DWORD processId, PVOID* pebAddress);
BOOL DriverEnumerateProcessModules(DWORD processId, PDRIVER_MODULE_INFO modules, DWORD maxModules, DWORD* moduleCount);

// High-level functions
BOOL DriverFindGameAssembly(DWORD processId, DWORD64* moduleBase, DWORD* moduleSize);
BOOL TestDriverFunctionality(void);

#endif // DRIVER_INTERFACE_H 