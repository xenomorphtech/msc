/* Windows-side input for repeatable Wine gameplay checks. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HWND game;
static BOOL CALLBACK find_game(HWND window, LPARAM ignored) {
    char title[128];
    (void)ignored;
    GetWindowTextA(window, title, sizeof(title));
    if (strcmp(title, "MapleStory") == 0 && IsWindowVisible(window)) {
        game = window; return FALSE;
    }
    return TRUE;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned key = (unsigned)strtoul(argv[1], NULL, 0);
    unsigned duration = (unsigned)strtoul(argv[2], NULL, 0);
    if (key > 255 || duration > 10000) return 3;
    EnumWindows(find_game, 0);
    if (!game) return 4;
    SetForegroundWindow(game);
    SetFocus(game);
    Sleep(150);
    INPUT input = {0};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = 0;
    input.ki.wScan = (WORD)MapVirtualKeyA(key, MAPVK_VK_TO_VSC);
    input.ki.dwFlags = KEYEVENTF_SCANCODE;
    if (key >= VK_LEFT && key <= VK_DOWN) input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    if (SendInput(1, &input, sizeof(input)) != 1) return 5;
    Sleep(duration);
    printf("key=%u async=%x foreground=%p target=%p\n", key,
           (unsigned)(unsigned short)GetAsyncKeyState((int)key), (void *)GetForegroundWindow(), (void *)game);
    input.ki.dwFlags |= KEYEVENTF_KEYUP;
    if (SendInput(1, &input, sizeof(input)) != 1) return 6;
    return 0;
}
