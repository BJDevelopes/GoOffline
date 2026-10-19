using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace GoOffline.Services;

/// <summary>Finds running processes by exe path and resets their open TCP connections.</summary>
public static class ProcessService
{
    private const int ProcessQueryLimitedInformation = 0x1000;
    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const uint MibTcpStateDeleteTcb = 12;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetTcpEntry(ref MibTcpRow row);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
    }

    public static string? GetImagePath(int pid)
    {
        IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    /// <summary>pid -> exe path for every process we can inspect.</summary>
    /// <summary>pid -> parent pid for every process we can see (via Toolhelp snapshot).</summary>
    public static Dictionary<int, int> ParentMap()
    {
        var map = new Dictionary<int, int>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == InvalidHandle) return map;
        try
        {
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref pe))
                do { map[(int)pe.th32ProcessID] = (int)pe.th32ParentProcessID; }
                while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
        return map;
    }

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr InvalidHandle = new(-1);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W pe);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W pe);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    public static Dictionary<int, string> Snapshot()
    {
        var map = new Dictionary<int, string>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                var path = GetImagePath(p.Id);
                if (path != null) map[p.Id] = path;
            }
        }
        return map;
    }

    /// <summary>
    /// Resets every established IPv4 TCP connection owned by the given PIDs.
    /// (Windows only exposes this for IPv4; the firewall rule covers the rest.)
    /// </summary>
    public static int ResetConnections(ICollection<int> pids)
    {
        if (pids.Count == 0) return 0;

        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        IntPtr buf = Marshal.AllocHGlobal(size);
        int killed = 0;
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0) return 0;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            for (int i = 0; i < count; i++)
            {
                var r = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buf + 4 + i * rowSize);
                if (!pids.Contains((int)r.OwningPid)) continue;
                if ((r.RemoteAddr & 0xFF) == 127) continue; // leave loopback alone
                var row = new MibTcpRow
                {
                    State = MibTcpStateDeleteTcb,
                    LocalAddr = r.LocalAddr, LocalPort = r.LocalPort,
                    RemoteAddr = r.RemoteAddr, RemotePort = r.RemotePort,
                };
                if (SetTcpEntry(ref row) == 0) killed++;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return killed;
    }
}
