#include <Windows.h>
#include <stdio.h>
#include "winring0.h"
#include "console.h"

// Global state
static HANDLE g_hDriver = INVALID_HANDLE_VALUE;
static BOOL g_bInitialized = FALSE;
static BOOL g_bKernelAccess = FALSE;

// Memory access structures
#pragma pack(push, 1)
typedef struct _MEMORY_REQUEST {
    DWORD64 Address;
    DWORD Size;
    BYTE Data[1];
} MEMORY_REQUEST, *PMEMORY_REQUEST;
#pragma pack(pop)

BOOL InitializeWinRing0Driver(void) {
    if (g_bInitialized) {
        return TRUE;
    }

    // Try to open existing driver
    g_hDriver = CreateFileA("\\\\.\\WinRing0_1_2_0",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_hDriver == INVALID_HANDLE_VALUE) {
        ConsoleError("Failed to open WinRing0 driver");
        return FALSE;
    }

    g_bInitialized = TRUE;
    return TRUE;
}

BOOL TestWinRing0Capabilities(void) {
    if (!g_bInitialized || g_hDriver == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Test physical memory read
    BYTE testBuffer[8] = {0};
    if (!ReadPhysicalMemory(0x1000, testBuffer, sizeof(testBuffer))) {
        ConsoleWarning("Physical memory read test failed");
        return FALSE;
    }

    // Test IOCTL functionality
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(g_hDriver,
        IOCTL_READ_MEMORY,
        NULL,
        0,
        testBuffer,
        sizeof(testBuffer),
        &bytesReturned,
        NULL)) {
        ConsoleWarning("IOCTL test failed");
        return FALSE;
    }

    return TRUE;
}

BOOL EstablishWinRing0KernelAccess(void) {
    if (!g_bInitialized || g_hDriver == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Test kernel access by reading a known physical address
    BYTE testBuffer[8] = {0};
    if (!ReadPhysicalMemory(0x1000, testBuffer, sizeof(testBuffer))) {
        return FALSE;
    }

    g_bKernelAccess = TRUE;
    return TRUE;
}

BOOL ReadPhysicalMemory(DWORD64 physicalAddress, PVOID buffer, SIZE_T size) {
    if (!g_bInitialized || g_hDriver == INVALID_HANDLE_VALUE || !buffer || !size) {
        return FALSE;
    }

    // Allocate request buffer
    SIZE_T requestSize = sizeof(MEMORY_REQUEST) + size - 1;
    PMEMORY_REQUEST request = (PMEMORY_REQUEST)malloc(requestSize);
    if (!request) {
        return FALSE;
    }

    // Setup request
    request->Address = physicalAddress;
    request->Size = (DWORD)size;

    // Send IOCTL
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(g_hDriver,
        IOCTL_READ_MEMORY,
        request,
        (DWORD)requestSize,
        request,
        (DWORD)requestSize,
        &bytesReturned,
        NULL);

    if (success) {
        memcpy(buffer, request->Data, size);
    }

    free(request);
    return success;
}

BOOL WritePhysicalMemory(DWORD64 physicalAddress, PVOID buffer, SIZE_T size) {
    if (!g_bInitialized || g_hDriver == INVALID_HANDLE_VALUE || !buffer || !size) {
        return FALSE;
    }

    // Allocate request buffer
    SIZE_T requestSize = sizeof(MEMORY_REQUEST) + size - 1;
    PMEMORY_REQUEST request = (PMEMORY_REQUEST)malloc(requestSize);
    if (!request) {
        return FALSE;
    }

    // Setup request
    request->Address = physicalAddress;
    request->Size = (DWORD)size;
    memcpy(request->Data, buffer, size);

    // Send IOCTL
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(g_hDriver,
        IOCTL_WRITE_MEMORY,
        request,
        (DWORD)requestSize,
        NULL,
        0,
        &bytesReturned,
        NULL);

    free(request);
    return success;
} 