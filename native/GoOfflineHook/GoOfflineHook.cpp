// GoOfflineHook.dll — makes network calls fail in the host process so it behaves
// as if the adapter is unplugged. Loaded by GoOffline.exe via remote LoadLibrary.
//
// Two layers, both installed on load (and after each LoadLibrary):
//
//   1. IAT hook. For every loaded module we walk its import descriptors and swap
//      the stored function pointer for a stub. Cheap, surgical, catches imports
//      resolved at load time.
//
//   2. Inline hook. At the first instruction of each real target function in
//      ws2_32/wininet/winhttp we write a short absolute jump to our stub. Catches
//      callers that resolve the function dynamically via GetProcAddress and cache
//      the pointer — the IAT entry is irrelevant to them.
//
//   Because our stubs always return an error (never resume the real function),
//   we don't need a trampoline. The thread-suspend dance is the standard safe
//   patch pattern: pause other threads, patch, resume.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <winhttp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

// --- Replacement stubs -------------------------------------------------------
// Each one mirrors the real function's signature and returns an "offline" error.

static int WINAPI Hook_connect(SOCKET, const struct sockaddr*, int) {
    WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR;
}
static int WINAPI Hook_WSAConnect(SOCKET, const struct sockaddr*, int,
                                  LPWSABUF, LPWSABUF, LPQOS, LPQOS) {
    WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR;
}
static int WINAPI Hook_getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*) {
    WSASetLastError(WSAHOST_NOT_FOUND); return WSAHOST_NOT_FOUND;
}
static int WINAPI Hook_GetAddrInfoW(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*) {
    WSASetLastError(WSAHOST_NOT_FOUND); return WSAHOST_NOT_FOUND;
}
static struct hostent* WINAPI Hook_gethostbyname(const char*) {
    WSASetLastError(WSAHOST_NOT_FOUND); return nullptr;
}
static int WINAPI Hook_WSAStartup(WORD, LPWSADATA data) {
    if (data) memset(data, 0, sizeof(*data));
    return WSASYSNOTREADY;
}
static HINTERNET WINAPI Hook_InternetOpenA(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) {
    SetLastError(ERROR_INTERNET_DISCONNECTED); return nullptr;
}
static HINTERNET WINAPI Hook_InternetOpenW(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) {
    SetLastError(ERROR_INTERNET_DISCONNECTED); return nullptr;
}
static HINTERNET WINAPI Hook_InternetConnectA(HINTERNET, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) {
    SetLastError(ERROR_INTERNET_DISCONNECTED); return nullptr;
}
static HINTERNET WINAPI Hook_InternetConnectW(HINTERNET, LPCWSTR, WORD, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR) {
    SetLastError(ERROR_INTERNET_DISCONNECTED); return nullptr;
}
static HINTERNET WINAPI Hook_WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) {
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT); return nullptr;
}
static HINTERNET WINAPI Hook_WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) {
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT); return nullptr;
}

// Forward-decl so the LoadLibrary hooks can call the installer.
static void PatchAllModules();

typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef HMODULE (WINAPI *LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
static LoadLibraryA_t   Real_LoadLibraryA   = LoadLibraryA;
static LoadLibraryW_t   Real_LoadLibraryW   = LoadLibraryW;
static LoadLibraryExA_t Real_LoadLibraryExA = LoadLibraryExA;
static LoadLibraryExW_t Real_LoadLibraryExW = LoadLibraryExW;

// Forward decl for the inline installer, so these can call it after a new DLL loads.
static void InstallInlineHooks();

static void AfterLoad() { PatchAllModules(); InstallInlineHooks(); }

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR n)                       { HMODULE h = Real_LoadLibraryA(n);       if (h) AfterLoad(); return h; }
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR n)                      { HMODULE h = Real_LoadLibraryW(n);       if (h) AfterLoad(); return h; }
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD g)  { HMODULE h = Real_LoadLibraryExA(n,f,g); if (h) AfterLoad(); return h; }
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD g) { HMODULE h = Real_LoadLibraryExW(n,f,g); if (h) AfterLoad(); return h; }

// --- IAT patch table ---------------------------------------------------------
struct HookEntry {
    const char* dllName;   // which import module (case-insensitive match on filename)
    const char* funcName;  // which exported name
    void*       replacement;
};

static const HookEntry kHooks[] = {
    { "ws2_32.dll",  "connect",         (void*)Hook_connect },
    { "ws2_32.dll",  "WSAConnect",      (void*)Hook_WSAConnect },
    { "ws2_32.dll",  "getaddrinfo",     (void*)Hook_getaddrinfo },
    { "ws2_32.dll",  "GetAddrInfoW",    (void*)Hook_GetAddrInfoW },
    { "ws2_32.dll",  "gethostbyname",   (void*)Hook_gethostbyname },
    { "ws2_32.dll",  "WSAStartup",      (void*)Hook_WSAStartup },
    { "wininet.dll", "InternetOpenA",   (void*)Hook_InternetOpenA },
    { "wininet.dll", "InternetOpenW",   (void*)Hook_InternetOpenW },
    { "wininet.dll", "InternetConnectA",(void*)Hook_InternetConnectA },
    { "wininet.dll", "InternetConnectW",(void*)Hook_InternetConnectW },
    { "winhttp.dll", "WinHttpOpen",     (void*)Hook_WinHttpOpen },
    { "winhttp.dll", "WinHttpConnect",  (void*)Hook_WinHttpConnect },
    { "kernel32.dll","LoadLibraryA",    (void*)Hook_LoadLibraryA },
    { "kernel32.dll","LoadLibraryW",    (void*)Hook_LoadLibraryW },
    { "kernel32.dll","LoadLibraryExA",  (void*)Hook_LoadLibraryExA },
    { "kernel32.dll","LoadLibraryExW",  (void*)Hook_LoadLibraryExW },
};

static bool EqualIgnoreCase(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return false;
        ++a; ++b;
    }
    return *a == *b;
}

static void PatchModule(HMODULE mod) {
    if (!mod) return;
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return;

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* dllName = (const char*)(base + imp->Name);
        // Skip our own patch target entries we don't care about.
        bool anyMatch = false;
        for (auto& h : kHooks) if (EqualIgnoreCase(dllName, h.dllName)) { anyMatch = true; break; }
        if (!anyMatch) continue;

        IMAGE_THUNK_DATA* nameThunk = (IMAGE_THUNK_DATA*)(base +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        IMAGE_THUNK_DATA* addrThunk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);

        for (; nameThunk->u1.AddressOfData; ++nameThunk, ++addrThunk) {
            if (nameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue; // skip by-ordinal
            IMAGE_IMPORT_BY_NAME* byName = (IMAGE_IMPORT_BY_NAME*)(base + nameThunk->u1.AddressOfData);
            for (auto& h : kHooks) {
                if (!EqualIgnoreCase(dllName, h.dllName)) continue;
                if (strcmp((const char*)byName->Name, h.funcName) != 0) continue;

                DWORD old;
                if (VirtualProtect(&addrThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                    addrThunk->u1.Function = (ULONG_PTR)h.replacement;
                    VirtualProtect(&addrThunk->u1.Function, sizeof(void*), old, &old);
                }
                break;
            }
        }
    }
}

static void PatchAllModules() {
    HANDLE proc = GetCurrentProcess();
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) PatchModule(mods[i]);
}

// --- Inline (prologue) hooks -------------------------------------------------
//
// For each real target function we overwrite the first PATCH_LEN bytes with an
// absolute jump to our stub. On x64 that's:
//     48 B8 <8 byte addr>   ; mov rax, imm64
//     FF E0                 ; jmp rax
// On x86:
//     B8 <4 byte addr>      ; mov eax, imm32
//     FF E0                 ; jmp eax
// Our stubs never return to the real function, so no trampoline is needed.

#ifdef _WIN64
static constexpr size_t PATCH_LEN = 12;
#else
static constexpr size_t PATCH_LEN = 7;
#endif

struct InlineTarget {
    const char* dllName;
    const char* funcName;
    void*       hook;
    bool        installed;
    BYTE        original[PATCH_LEN];
    void*       target;
};

static InlineTarget kInline[] = {
    { "ws2_32.dll",  "connect",         (void*)Hook_connect },
    { "ws2_32.dll",  "WSAConnect",      (void*)Hook_WSAConnect },
    { "ws2_32.dll",  "getaddrinfo",     (void*)Hook_getaddrinfo },
    { "ws2_32.dll",  "GetAddrInfoW",    (void*)Hook_GetAddrInfoW },
    { "ws2_32.dll",  "gethostbyname",   (void*)Hook_gethostbyname },
    { "wininet.dll", "InternetConnectA",(void*)Hook_InternetConnectA },
    { "wininet.dll", "InternetConnectW",(void*)Hook_InternetConnectW },
    { "winhttp.dll", "WinHttpConnect",  (void*)Hook_WinHttpConnect },
};

static void WriteJump(BYTE* at, void* dest) {
#ifdef _WIN64
    at[0] = 0x48; at[1] = 0xB8;              // mov rax, imm64
    *(void**)(at + 2) = dest;                // 8 bytes
    at[10] = 0xFF; at[11] = 0xE0;            // jmp rax
#else
    at[0] = 0xB8;                            // mov eax, imm32
    *(void**)(at + 1) = dest;                // 4 bytes
    at[5] = 0xFF; at[6] = 0xE0;              // jmp eax
#endif
}

// Pause every other thread in this process while patching. If a thread were running
// inside the bytes we're about to overwrite, resuming after would crash it.
static DWORD SuspendOtherThreads(HANDLE* handles, DWORD maxH) {
    DWORD count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{ sizeof(te) };
    DWORD pid = GetCurrentProcessId(), self = GetCurrentThreadId();
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!h) continue;
        if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
        if (count < maxH) handles[count++] = h; else CloseHandle(h);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return count;
}

static void ResumeAndClose(HANDLE* handles, DWORD count) {
    for (DWORD i = 0; i < count; ++i) { ResumeThread(handles[i]); CloseHandle(handles[i]); }
}

static void InstallInlineHooks() {
    HANDLE suspended[2048];
    DWORD  suspCount = SuspendOtherThreads(suspended, 2048);

    for (auto& t : kInline) {
        if (t.installed) continue;
        HMODULE mod = GetModuleHandleA(t.dllName);
        if (!mod) continue; // DLL not loaded yet — try again after next LoadLibrary
        void* fn = (void*)GetProcAddress(mod, t.funcName);
        if (!fn) continue;

        // Skip if the first byte already looks like our jump prologue.
        BYTE* bytes = (BYTE*)fn;
#ifdef _WIN64
        if (bytes[0] == 0x48 && bytes[1] == 0xB8) { t.installed = true; continue; }
#else
        if (bytes[0] == 0xB8 && bytes[5] == 0xFF && bytes[6] == 0xE0) { t.installed = true; continue; }
#endif
        DWORD old;
        if (!VirtualProtect(fn, PATCH_LEN, PAGE_EXECUTE_READWRITE, &old)) continue;
        memcpy(t.original, fn, PATCH_LEN);
        WriteJump(bytes, t.hook);
        VirtualProtect(fn, PATCH_LEN, old, &old);
        FlushInstructionCache(GetCurrentProcess(), fn, PATCH_LEN);
        t.target = fn;
        t.installed = true;
    }

    ResumeAndClose(suspended, suspCount);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        PatchAllModules();      // IAT pass
        InstallInlineHooks();   // inline pass
    }
    return TRUE;
}
