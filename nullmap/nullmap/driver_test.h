#ifndef _DRIVER_TEST_H_
#define _DRIVER_TEST_H_

#include <Windows.h>
#include "nt_types.h"

// Game context structure
typedef struct _GAME_CONTEXT {
    DWORD processId;
    HANDLE processHandle;
    BOOL gameAssemblyFound;
    DWORD64 gameAssemblyBase;
    DWORD64 unityPlayerBase;
    SIZE_T gameAssemblySize;
    BOOL isHollowed;
    HANDLE hollowedHandle;
} GAME_CONTEXT;

// Function declarations
BOOL FindGameProcess(const char* processName, GAME_CONTEXT* context);
BOOL FindGameAssembly(GAME_CONTEXT* context);
BOOL FindGameAssemblyKernel(GAME_CONTEXT* context);
BOOL SetupProcessHollow(GAME_CONTEXT* context);
BOOL BypassEacProtection(GAME_CONTEXT* context);
void ShowTestMenu(void);
BOOL HandleTestMode(void);

#endif // _DRIVER_TEST_H_ 