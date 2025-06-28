#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "console.h"

// ASCII frames for the animation
static const char* nixware_frames[] = {
	// Frame 1
	"\n"
	"  +---------------+\n"
	"  | N I X W A R E |\n"
	"  +---------------+\n",

	// Frame 2 (with glow effect)
	"\n"
	"  \033[1;36m+---------------+\n"
	"  | N I X W A R E |\n"
	"  +---------------+\033[0m\n",

	// Frame 3 (with different glow effect)
	"\n"
	"  \033[1;35m+---------------+\n"
	"  | N I X W A R E |\n"
	"  +---------------+\033[0m\n"
};

static void ConsoleAnimateNixware(void) {
	// Enable ANSI escape sequences
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode = 0;
	GetConsoleMode(hConsole, &mode);
	SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

	// Play animation
	for (int i = 0; i < 6; i++) {
		// Clear previous frame (move cursor up 4 lines if not first frame)
		if (i > 0) {
			printf("\033[4A");  // Move cursor up 4 lines
		}
		
		// Display current frame
		printf("%s", nixware_frames[i % 3]);
		
		// Add small delay
		Sleep(150);
	}

	// Final newline
	printf("\n");
}

static void ConsoleBase(CONSOLE_COLOR color, const char* prefix, const char* format, va_list args) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, (WORD)color);
	printf("[%s] ", prefix);
	vprintf(format, args);
	printf("\n");
	SetConsoleTextAttribute(hConsole, (WORD)White);
}

void ConsoleInit(void) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) {
		return;
	}

	// Enable ANSI escape sequences
	DWORD mode = 0;
	if (GetConsoleMode(hConsole, &mode)) {
		SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}

	// Set initial color
	SetConsoleTextAttribute(hConsole, (WORD)White);

	// Print initial banner
	ConsoleTitle("nullmap");
	printf("build on %s\n\n", __DATE__);

	// Display animated nixware logo
	ConsoleAnimateNixware();
}

void ConsoleInfo(const char* format, ...) {
	va_list args;
	va_start(args, format);
	ConsoleBase(DarkWhite, "*", format, args);
	va_end(args);
}

void ConsoleDebug(const char* format, ...) {
	va_list args;
	va_start(args, format);
	ConsoleBase(Cyan, "DEBUG", format, args);
	va_end(args);
}

void ConsoleWarning(const char* format, ...) {
	va_list args;
	va_start(args, format);
	ConsoleBase(Yellow, "!", format, args);
	va_end(args);
}

void ConsoleError(const char* format, ...) {
	va_list args;
	va_start(args, format);
	ConsoleBase(Red, "ERROR", format, args);
	va_end(args);
}

void ConsoleSuccess(const char* format, ...) {
	va_list args;
	va_start(args, format);
	ConsoleBase(Green, "+", format, args);
	va_end(args);
}

void ConsoleStatus(const char* format, ...) {
	va_list args;
	va_start(args, format);
	ConsoleBase(Purple, "STATUS", format, args);
	va_end(args);
}

void ConsoleResetColor(void) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, (WORD)DarkWhite);
}

void ConsoleTitle(const char* name)
{
	const HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	SetConsoleTextAttribute(consoleHandle, Purple);
	printf("%s\n", name);

	SetConsoleTextAttribute(consoleHandle, DarkWhite);
	printf("build on %s\n\n", __DATE__);
}