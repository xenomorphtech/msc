/* Incremental runtime adapter. The recovered function bodies are generated
 * verbatim into the translation unit that includes this file. */
#ifdef _WIN32
#include <windows.h>
static HANDLE cw_log = INVALID_HANDLE_VALUE;
static SRWLOCK cw_log_lock = SRWLOCK_INIT;
static volatile LONG64 cw_counts[5];

static void cw_record(const char *event, int index, LONG64 count) {
    char line[256];
    DWORD written;
    int length = snprintf(line, sizeof(line),
        "{\"event\":\"%s\",\"pid\":%lu,\"function\":%d,\"calls\":%lld,\"tick\":%llu}\n",
        event, (unsigned long)GetCurrentProcessId(), index, (long long)count,
        (unsigned long long)GetTickCount64());
    AcquireSRWLockExclusive(&cw_log_lock);
    if (cw_log != INVALID_HANDLE_VALUE)
        WriteFile(cw_log, line, (DWORD)length, &written, NULL);
    ReleaseSRWLockExclusive(&cw_log_lock);
}

static void cw_called(int index) {
    LONG64 count = InterlockedIncrement64(&cw_counts[index]);
    if ((count & (count - 1)) == 0) cw_record("returned", index, count);
}

static void cw_init(void) { FUN_140cc12a0(); cw_called(0); }
static void cw_expand(undefined4 *key, undefined4 *context) {
    if (DAT_143b53c50 == 0) cw_init();
    FUN_140cc1970(key, context);
    cw_called(1);
}
static void cw_block(longlong context, uint *block) {
    FUN_140cc1af0(context, block); cw_called(2);
}
static uint cw_shuffle(longlong bytes, int length, uint *state) {
    uint result = FUN_140cc3f30(bytes, length, state);
    cw_called(3); return result;
}
static void cw_additive(ulonglong out, ulonglong in, uint length, char *iv, int enabled) {
    FUN_1407475e0(out, in, length, iv, enabled); cw_called(4);
}

__declspec(dllexport) void cw_rebuilt_probe(void) {}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        cw_image = (unsigned char *)GetModuleHandleA(NULL);
        DisableThreadLibraryCalls(module);
        DWORD length = GetModuleFileNameA(NULL, path, sizeof(path));
        if (!length || length >= sizeof(path) - 48) return FALSE;
        char *slash = strrchr(path, '\\');
        if (!slash) return FALSE;
        snprintf(slash + 1, sizeof(path) - (size_t)(slash + 1 - path),
                 "cw-rebuilt-%lu.jsonl", (unsigned long)GetCurrentProcessId());
        cw_log = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (cw_log == INVALID_HANDLE_VALUE) return FALSE;
        /* Verify every preimage before changing any entry point. The launcher
         * separately pins the complete executable and DLL hashes. */
        for (int i = 0; i < 5; i++) {
            if (memcmp(cw_image + cw_patch_rvas[i], cw_patch_bytes[i], 32)) {
                cw_record("preimage_mismatch", i, 0); return FALSE;
            }
        }
        void *targets[] = {(void *)cw_init, (void *)cw_expand, (void *)cw_block,
                            (void *)cw_shuffle, (void *)cw_additive};
        for (int i = 0; i < 5; i++) {
            unsigned char jump[14] = {0xff, 0x25, 0, 0, 0, 0};
            DWORD previous, ignored;
            memcpy(jump + 6, &targets[i], 8);
            void *entry = cw_image + cw_patch_rvas[i];
            if (!VirtualProtect(entry, sizeof(jump), PAGE_EXECUTE_READWRITE, &previous)) {
                cw_record("protect_failed", i, 0); return FALSE;
            }
            memcpy(entry, jump, sizeof(jump));
            FlushInstructionCache(GetCurrentProcess(), entry, sizeof(jump));
            VirtualProtect(entry, sizeof(jump), previous, &ignored);
            cw_record("installed", i, 0);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        for (int i = 0; i < 5; i++) cw_record("total", i, cw_counts[i]);
        if (cw_log != INVALID_HANDLE_VALUE) CloseHandle(cw_log);
    }
    return TRUE;
}
#endif
