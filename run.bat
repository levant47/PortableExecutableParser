@echo off
cl /Zi /nologo /Gy /I .. /Zl /Os /GS- main.cpp ^
    /link /SUBSYSTEM:console /NODEFAULTLIB /ENTRY:main kernel32.lib user32.lib dnsapi.lib ^
    || exit /b
main
