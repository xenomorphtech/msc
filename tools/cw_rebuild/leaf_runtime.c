/* Incremental replacement adapter for verified integer leaf functions. */
#if defined(_WIN32) && defined(CW_LEAF_DLL)
#include <windows.h>
static HANDLE cw_leaf_log = INVALID_HANDLE_VALUE;
static SRWLOCK cw_leaf_lock = SRWLOCK_INIT;
static volatile LONG64 cw_leaf_counts[CW_LEAF_COUNT];

static void cw_leaf_record(const char *event, unsigned index, LONG64 count) {
    char line[240];
    DWORD written;
    int length = snprintf(line, sizeof(line),
        "{\"event\":\"%s\",\"pid\":%lu,\"function\":%u,\"calls\":%lld}\n",
        event, (unsigned long)GetCurrentProcessId(), index, (long long)count);
    AcquireSRWLockExclusive(&cw_leaf_lock);
    if (cw_leaf_log != INVALID_HANDLE_VALUE)
        WriteFile(cw_leaf_log, line, (DWORD)length, &written, NULL);
    ReleaseSRWLockExclusive(&cw_leaf_lock);
}

static void cw_leaf_called(unsigned index) {
    LONG64 count = InterlockedIncrement64(&cw_leaf_counts[index]);
    if ((count & (count - 1)) == 0) cw_leaf_record("returned", index, count);
}

/* CW_WRAPPERS */

__declspec(dllexport) void cw_leaf_probe(void) {}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        DWORD length = GetModuleFileNameA(NULL, path, sizeof(path));
        if (!length || length >= sizeof(path) - 48) return FALSE;
        char *slash = strrchr(path, '\\');
        if (!slash) return FALSE;
        /* The oracle loads the DLL into its test executable too. Only install
         * replacements when the host is the pinned game client. */
        if (_stricmp(slash + 1, "MapleStory.exe") != 0) return TRUE;
        DisableThreadLibraryCalls(module);
        snprintf(slash + 1, sizeof(path) - (size_t)(slash + 1 - path),
                 "cw-leaf-%lu.jsonl", (unsigned long)GetCurrentProcessId());
        cw_leaf_log = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (cw_leaf_log == INVALID_HANDLE_VALUE) return FALSE;
        unsigned char *image = (unsigned char *)GetModuleHandleA(NULL);
        for (unsigned i = 0; i < CW_LEAF_COUNT; i++) {
            if (memcmp(image + cw_leaf_rvas[i], cw_leaf_preimages[i], 32)) {
                cw_leaf_record("preimage_mismatch", i, 0); return FALSE;
            }
        }
        for (unsigned i = 0; i < CW_LEAF_COUNT; i++) {
            unsigned char jump[14] = {0xff, 0x25, 0, 0, 0, 0};
            DWORD previous, ignored;
            memcpy(jump + 6, &cw_leaf_targets[i], 8);
            void *entry = image + cw_leaf_rvas[i];
            if (!VirtualProtect(entry, sizeof(jump), PAGE_EXECUTE_READWRITE, &previous)) {
                cw_leaf_record("protect_failed", i, 0); return FALSE;
            }
            memcpy(entry, jump, sizeof(jump));
            FlushInstructionCache(GetCurrentProcess(), entry, sizeof(jump));
            VirtualProtect(entry, sizeof(jump), previous, &ignored);
            cw_leaf_record("installed", i, 0);
        }
    } else if (reason == DLL_PROCESS_DETACH && cw_leaf_log != INVALID_HANDLE_VALUE) {
        for (unsigned i = 0; i < CW_LEAF_COUNT; i++) cw_leaf_record("total", i, cw_leaf_counts[i]);
        CloseHandle(cw_leaf_log);
    }
    return TRUE;
}
#endif
