#ifndef _CONSOLE_H_
#define _CONSOLE_H_

#include "nt_types.h"

// Console initialization
void ConsoleInit(void);

// Console output functions
void ConsoleSetColor(CONSOLE_COLOR color);
void ConsoleResetColor(void);
void ConsoleInfo(const char* format, ...);
void ConsoleSuccess(const char* format, ...);
void ConsoleError(const char* format, ...);
void ConsoleWarning(const char* format, ...);
void ConsoleDebug(const char* format, ...);
void ConsoleStatus(const char* format, ...);
void ConsoleTitle(const char* name);

#endif // _CONSOLE_H_