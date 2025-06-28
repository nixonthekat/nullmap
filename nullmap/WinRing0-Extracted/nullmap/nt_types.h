#ifndef _NT_TYPES_H_
#define _NT_TYPES_H_

#include <Windows.h>
#include <winternl.h>

// Constants
#define MAX_SAFE_READ_SIZE 0x100000
#define RUST_PROCESS_NAME "RustClient.exe"

// NT Status codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_SUPPORTED           ((NTSTATUS)0xC00000BBL)
#define STATUS_INSUFFICIENT_RESOURCES  ((NTSTATUS)0xC000009AL)
#define STATUS_INVALID_PARAMETER_1     ((NTSTATUS)0xC00000EFL)
#define STATUS_NOT_FOUND              ((NTSTATUS)0xC0000225L)
#define STATUS_INFO_LENGTH_MISMATCH   ((NTSTATUS)0xC0000004L)

// Memory types
#define NonPagedPool 0
#define OBJ_CASE_INSENSITIVE 0x00000040L

// Forward declarations
typedef struct _DRIVER_OBJECT DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef enum _POOL_TYPE {
    NonPagedPool_t,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE;

// Additional System Information Class values not in winternl.h
#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif
#ifndef SystemHandleInformation  
#define SystemHandleInformation 16
#endif

// System Module Entry
typedef struct _SYSTEM_MODULE {
    PVOID  Reserved1;
    PVOID  Reserved2;
    PVOID  Base;
    ULONG  Size;
    ULONG  Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT PathLength;
    CHAR   ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

// System Module Information
typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ulModuleCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Function Types
typedef PVOID (NTAPI *ExAllocatePool_t)(POOL_TYPE PoolType, SIZE_T NumberOfBytes);
typedef NTSTATUS (NTAPI *PDRIVER_INITIALIZE)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

// Console Colors
typedef enum _CONSOLE_COLOR {
    White = 7,
    DarkWhite = 8,
    Red = 12,
    Green = 10,
    Yellow = 14,
    Purple = 13,
    Cyan = 11
} CONSOLE_COLOR;

// NT Function Declarations
NTSYSAPI NTSTATUS NTAPI NtCreateSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING LinkTarget
);

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(
    OUT PHANDLE IoCompletionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG Count OPTIONAL
);

NTSYSAPI NTSTATUS NTAPI NtSetIoCompletion(
    IN HANDLE IoCompletionHandle,
    IN PVOID KeyContext,
    IN PVOID ApcContext OPTIONAL,
    IN NTSTATUS IoStatus,
    IN ULONG_PTR IoStatusInformation
);

// Define NT_SUCCESS macro if not defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#endif // _NT_TYPES_H_ 