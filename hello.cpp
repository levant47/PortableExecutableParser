#include <windows.h>

int main()
{
    char message[] = "Hello, world!\n";
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), message, sizeof(message) - 1, nullptr, nullptr);
    return 0;
}
