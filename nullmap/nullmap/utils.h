#ifndef _UTILS_H_
#define _UTILS_H_

#include <Windows.h>
#include "nt_types.h"

// Use SYSTEM_INFORMATION_CLASS from winternl.h instead of redefining
// Just define the constants we need
#define SystemModuleInformation 11
#define SystemHandleInformation 16

typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define RELATIVE_ADDRESS(address, size) ((VOID *)((UINT8 *)(address) + *(INT32 *)((UINT8 *)(address) + ((size) - (INT32)sizeof(INT32))) + (size)))
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

// Function declarations
PVOID UtilsReadFile(const char* path, SIZE_T* fileSize);
PIMAGE_NT_HEADERS64 UtilsGetImageHeaders(PVOID imageStart, SIZE_T maximumSize);
char* UtilsCompare(const char* haystack, const char* needle);
PVOID UtilsGetModuleBase(const char* moduleName);
DWORD64 UtilsFindPattern(void* baseAddress, DWORD64 size, const char* pattern);
DWORD64 UtilsFindPatternImage(void* base, const char* pattern);
BOOL UtilsGetObjectPointer(ULONG processId, HANDLE targetHandle, PULONG64 objectPointer);

#endif // _UTILS_H_
