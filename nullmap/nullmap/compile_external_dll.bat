@echo off
echo Compiling external access DLL...

cl.exe /LD /MD external_access_dll.c /Fe:external_access.dll ^
    /link kernel32.lib advapi32.lib user32.lib

if %errorlevel% equ 0 (
    echo Success! external_access.dll created
    dir external_access.dll
) else (
    echo Compilation failed!
)

pause 