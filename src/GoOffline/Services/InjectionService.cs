using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace GoOffline.Services;

/// <summary>
/// Why Hard mode fails on a given PID. The caller uses this to show a specific message:
/// Sandbox and Protected are permanent; everything else is worth retrying.
/// </summary>
public enum InjectResult
{
    Ok,
    AlreadyHooked,
    Sandbox,       // UWP / AppContainer — CreateRemoteThread refused by design.
    Protected,     // Game anti-cheat / antivirus / DRM — OpenProcess denied by the kernel.
    Transient,     // Something else (process exiting, momentary access denial). Retry.
    HookDllMissing,
}

public static class InjectionService
{
    private const int ProcessCreateThread      = 0x0002;
    private const int ProcessQueryInformation  = 0x0400;
    private const int ProcessVmOperation       = 0x0008;
    private const int ProcessVmWrite           = 0x0020;
    private const int ProcessVmRead            = 0x0010;
    private const int AllAccess = ProcessCreateThread | ProcessQueryInformation |
                                  ProcessVmOperation | ProcessVmWrite | ProcessVmRead;

    private const uint MemCommit = 0x1000, MemReserve = 0x2000, MemRelease = 0x8000;
    private const uint PageReadWrite = 0x04;
    private const int ErrorAccessDenied = 5;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(IntPtr p, IntPtr addr, uint size, uint type);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr p, IntPtr addr, byte[] buf, uint size, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr p, IntPtr attrs, uint stack,
        IntPtr start, IntPtr param, uint flags, IntPtr tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandleW(string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr mod, string proc);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr p, out bool wow64);

    // --- Process classification --------------------------------------------------

    // IsProtectedProcess info via NtQueryInformationProcess(ProcessProtectionInformation=61).
    [StructLayout(LayoutKind.Sequential)]
    private struct PsProtection { public byte Level; }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr h, int infoClass, ref PsProtection buf, int len, out int ret);

    // GetTokenInformation(TokenIsAppContainer=29).
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tok, int cls, out int buf, int len, out int ret);
    private const uint TokenQuery = 0x8;
    private const int TokenIsAppContainer = 29;

    public static bool IsAppContainer(int pid)
    {
        var h = OpenProcess(ProcessQueryInformation, false, pid);
        if (h == IntPtr.Zero) return false;
        try
        {
            if (!OpenProcessToken(h, TokenQuery, out var tok)) return false;
            try { return GetTokenInformation(tok, TokenIsAppContainer, out int ac, 4, out _) && ac != 0; }
            finally { CloseHandle(tok); }
        }
        finally { CloseHandle(h); }
    }

    public static bool IsProtected(int pid)
    {
        var h = OpenProcess(ProcessQueryInformation, false, pid);
        if (h == IntPtr.Zero) return false;
        try
        {
            var p = new PsProtection();
            return NtQueryInformationProcess(h, 61, ref p, 1, out _) == 0 && p.Level != 0;
        }
        finally { CloseHandle(h); }
    }

    public static string? HookDllPathFor(int pid)
    {
        bool target32 = IsProcess32Bit(pid);
        string baseDir = Path.Combine(AppContext.BaseDirectory, "native");
        string name = target32 ? "GoOfflineHook32.dll" : "GoOfflineHook64.dll";
        string path = Path.Combine(baseDir, name);
        return File.Exists(path) ? path : null;
    }

    private static bool IsProcess32Bit(int pid)
    {
        if (!Environment.Is64BitOperatingSystem) return true;
        IntPtr h = OpenProcess(ProcessQueryInformation, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return IsWow64Process(h, out bool wow) && wow; }
        finally { CloseHandle(h); }
    }

    // --- Injection ---------------------------------------------------------------

    /// <summary>Inject the hook DLL into one PID. Never throws; returns a reason the caller can act on.</summary>
    public static InjectResult Inject(int pid)
    {
        if (IsAppContainer(pid)) return InjectResult.Sandbox;
        if (IsProtected(pid))    return InjectResult.Protected;

        var dll = HookDllPathFor(pid);
        if (dll == null) return InjectResult.HookDllMissing;

        IntPtr proc = OpenProcess(AllAccess, false, pid);
        if (proc == IntPtr.Zero)
            return Marshal.GetLastWin32Error() == ErrorAccessDenied ? InjectResult.Protected : InjectResult.Transient;

        IntPtr remote = IntPtr.Zero;
        try
        {
            byte[] bytes = Encoding.Unicode.GetBytes(dll + "\0");
            remote = VirtualAllocEx(proc, IntPtr.Zero, (uint)bytes.Length,
                                    MemCommit | MemReserve, PageReadWrite);
            if (remote == IntPtr.Zero) return InjectResult.Transient;

            if (!WriteProcessMemory(proc, remote, bytes, (uint)bytes.Length, out _))
                return InjectResult.Transient;

            IntPtr k32 = GetModuleHandleW("kernel32.dll");
            IntPtr loadLib = GetProcAddress(k32, "LoadLibraryW");
            if (loadLib == IntPtr.Zero) return InjectResult.Transient;

            IntPtr thread = CreateRemoteThread(proc, IntPtr.Zero, 0, loadLib, remote, 0, IntPtr.Zero);
            if (thread == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == ErrorAccessDenied ? InjectResult.Protected : InjectResult.Transient;

            WaitForSingleObject(thread, 10000);
            CloseHandle(thread);
            return InjectResult.Ok;
        }
        finally
        {
            if (remote != IntPtr.Zero) VirtualFreeEx(proc, remote, 0, MemRelease);
            CloseHandle(proc);
        }
    }

    public record struct InjectSummary(int Ok, int Sandbox, int Protected_, int Transient, int Missing)
    {
        public int Total => Ok + Sandbox + Protected_ + Transient + Missing;
        public bool AnyPermanent => Sandbox > 0 || Protected_ > 0;
        public string? Blurb =>
            Total == 0            ? null :
            Sandbox   > 0         ? "runs in a sandbox (UWP/Store) — Hard mode can't attach, firewall still blocks it" :
            Protected_ > 0        ? "process is protected (anti-cheat/antivirus) — Hard mode can't attach, firewall still blocks it" :
            Missing > 0           ? "hook DLL missing — rebuild native/GoOfflineHook" :
            Ok > 0 && Transient == 0 ? $"hooked {Ok} process(es)" :
            Ok > 0                ? $"hooked {Ok}/{Total}, retrying rest" :
            "nothing to hook";
    }

    /// <summary>Inject into every running instance of exePath. Caller renders Blurb() in the UI.</summary>
    public static InjectSummary InjectAll(string exePath)
    {
        var pids = ProcessService.Snapshot()
            .Where(kv => kv.Value.Equals(exePath, StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key).ToList();

        var s = new InjectSummary();
        foreach (var pid in pids)
        {
            switch (Inject(pid))
            {
                case InjectResult.Ok:
                case InjectResult.AlreadyHooked: s.Ok++; break;
                case InjectResult.Sandbox:       s.Sandbox++; break;
                case InjectResult.Protected:     s.Protected_++; break;
                case InjectResult.HookDllMissing: s.Missing++; break;
                default:                         s.Transient++; break;
            }
        }
        return s;
    }
}
