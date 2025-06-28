#ifndef _NT_IORING_H
#define _NT_IORING_H

#include <ntdef.h>
#include <windef.h>

#if defined(__cplusplus)
extern "C" {
#endif

//
// IoRing Version Information
//
typedef ULONG IORING_VERSION, *PIORING_VERSION;
#define IORING_VERSION_INVALID  ((IORING_VERSION)0)
#define IORING_VERSION_1       ((IORING_VERSION)1)
#define IORING_VERSION_2       ((IORING_VERSION)2)
#define IORING_VERSION_CURRENT IORING_VERSION_2

//
// IoRing Handle
//
typedef PVOID HIORING, *PHIORING;

//
// IoRing Buffer Entry
//
typedef struct _IORING_BUFFER_INFO {
    PVOID    Address;
    SIZE_T   Length;
} IORING_BUFFER_INFO, *PIORING_BUFFER_INFO;

//
// IoRing Object
//
typedef struct _IORING_OBJECT {
    USHORT Type;
    USHORT Size;
    PVOID Unknown1[2];
    PVOID Section;
    PVOID Unknown2[8];
    ULONG RegBuffersCount;
    PVOID RegBuffers;
} IORING_OBJECT, *PIORING_OBJECT;

//
// IoRing Create Flags
//
typedef ULONG IORING_CREATE_FLAGS;
#define IORING_CREATE_REQUIRED_NONE    0x00000000
#define IORING_CREATE_ADVISORY_NONE    0x00000000

//
// IoRing Function Declarations
//
NTSTATUS
NTAPI
NtCreateIoRing(
    _Out_ PHIORING IoRing,
    _In_ IORING_VERSION Version,
    _In_ IORING_CREATE_FLAGS Flags,
    _In_ ULONG SubmissionQueueSize,
    _In_ ULONG CompletionQueueSize
);

NTSTATUS
NTAPI
NtSubmitIoRing(
    _In_ HIORING IoRing,
    _In_ ULONG SubmitFlags,
    _In_ ULONG WaitFlags,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSTATUS
NTAPI
NtCloseIoRing(
    _In_ HIORING IoRing
);

#if defined(__cplusplus)
}
#endif

#endif // _NT_IORING_H 