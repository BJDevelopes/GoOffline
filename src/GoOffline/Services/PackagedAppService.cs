using System.Runtime.InteropServices;

namespace GoOffline.Services;

/// <summary>
/// Helpers for Microsoft Store / UWP packaged apps. Their firewall traffic is only
/// filtered when a rule targets the package's AppContainer SID — a path-based rule
/// does nothing. Everything here is about going from an .exe inside WindowsApps
/// back to that SID.
/// </summary>
public static class PackagedAppService
{
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr h);

    private const string Marker = @"\WindowsApps\";

    public static bool IsPackaged(string exePath) =>
        exePath.IndexOf(Marker, StringComparison.OrdinalIgnoreCase) >= 0;

    /// <summary>e.g. "SpotifyAB.SpotifyMusic_zpdnekdrzrea0" — Name + "_" + PublisherHash.</summary>
    public static string? GetPackageFamilyName(string exePath)
    {
        int i = exePath.IndexOf(Marker, StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        var rest = exePath[(i + Marker.Length)..];
        int sep = rest.IndexOf('\\');
        if (sep < 0) return null;

        // Folder: "<Name>_<Version>_<Arch>__<PublisherHash>"
        var folder = rest[..sep];
        var parts = folder.Split('_');
        if (parts.Length < 4) return null;
        return parts[0] + "_" + parts[^1];
    }

    /// <summary>SID string ("S-1-15-2-...") the firewall can filter by. Null on failure.</summary>
    public static string? GetPackageSid(string familyName)
    {
        if (DeriveAppContainerSidFromAppContainerName(familyName, out var sid) != 0 || sid == IntPtr.Zero)
            return null;
        try
        {
            if (!ConvertSidToStringSid(sid, out var str)) return null;
            try { return Marshal.PtrToStringUni(str); }
            finally { LocalFree(str); }
        }
        finally { LocalFree(sid); }
    }
}
