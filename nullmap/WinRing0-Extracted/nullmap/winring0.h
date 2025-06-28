#ifndef _WINRING0_H_
#define _WINRING0_H_

#include <Windows.h>

// WinRing0 driver interface
BOOL InitializeWinRing0Driver(void);
BOOL TestWinRing0Capabilities(void);
BOOL EstablishWinRing0KernelAccess(void);
BOOL ReadPhysicalMemory(DWORD64 physicalAddress, PVOID buffer, SIZE_T size);
BOOL WritePhysicalMemory(DWORD64 physicalAddress, PVOID buffer, SIZE_T size);

// WinRing0 IOCTL codes
#define IOCTL_READ_MEMORY      0x9C402000
#define IOCTL_WRITE_MEMORY     0x9C402004
#define IOCTL_READ_MSR         0x9C402008
#define IOCTL_WRITE_MSR        0x9C40200C

#endif // _WINRING0_H_ 