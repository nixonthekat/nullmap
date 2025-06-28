#ifndef _GENERAL_H_
#define _GENERAL_H_

#include <stdio.h>
#include <Windows.h>
#include "nt_types.h"
#include "console.h"

// Console output functions
void ConsoleInfo(const char* format, ...);
void ConsoleSuccess(const char* format, ...);
void ConsoleError(const char* format, ...);
void ConsoleWarning(const char* format, ...);

#endif // _GENERAL_H_