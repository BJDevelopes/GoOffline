using System.IO;

namespace GoOffline.Services;

/// <summary>
/// Builds a block list that goes beyond "just this exe": the whole install folder
/// (every .exe under it) plus any running descendants (child processes, grandchildren, …).
///
/// Why: programs that phone home — licensing checks, auto-updaters, telemetry daemons,
/// Electron helpers — often spawn a sibling .exe that holds the actual socket. A rule
/// against the main exe doesn't catch them. Folder enumeration catches the predictable
/// case (helpers next to the main binary); descendant discovery catches the odd one
/// (child spawned into %Temp% or AppData at runtime).
/// </summary>
public static class UniversalBlockService
{
    private static readonly string[] SkipNames =
    {
        "uninstall.exe", "uninst.exe", "unins000.exe", "unins001.exe",
        "setup.exe", "installer.exe", "update.exe", "updater.exe",
        "crashreport.exe", "crash_handler.exe", "crashpad_handler.exe",
    };

    /// <summary>Every .exe under exePath's folder that we should block together with it.</summary>
    public static List<string> SiblingExes(string exePath)
    {
        var dir = Path.GetDirectoryName(exePath);
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return new();

        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories); }
        catch { return new(); }

        var result = new List<string>();
        foreach (var f in files)
        {
            var name = Path.GetFileName(f);
            if (SkipNames.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            result.Add(Path.GetFullPath(f));
        }
        return result;
    }

    /// <summary>Running processes whose ancestor chain includes any of the given PIDs.</summary>
    public static Dictionary<int, string> DescendantsOf(IEnumerable<int> rootPids)
    {
        var roots = new HashSet<int>(rootPids);
        if (roots.Count == 0) return new();

        var parents = ProcessService.ParentMap();           // pid -> parentPid
        var paths   = ProcessService.Snapshot();            // pid -> exe path
        var result  = new Dictionary<int, string>();

        foreach (var kv in paths)
        {
            if (roots.Contains(kv.Key)) continue;
            int walker = kv.Key, hops = 0;
            while (parents.TryGetValue(walker, out var parent) && hops++ < 16)
            {
                if (roots.Contains(parent)) { result[kv.Key] = kv.Value; break; }
                walker = parent;
            }
        }
        return result;
    }

    /// <summary>
    /// Block an app's whole install folder plus any live descendants of its running processes.
    /// Returns every path a GoOffline rule was created for (including the main one),
    /// so the caller can remember them for later unblocking.
    /// </summary>
    public static List<string> BlockAll(string mainExe)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { mainExe };
        foreach (var sibling in SiblingExes(mainExe)) paths.Add(sibling);

        var rootPids = ProcessService.Snapshot()
            .Where(kv => kv.Value.Equals(mainExe, StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key).ToList();
        foreach (var child in DescendantsOf(rootPids).Values) paths.Add(child);

        foreach (var p in paths)
        {
            try { FirewallService.Block(p); } catch { /* best effort — report at caller */ }
        }
        return paths.ToList();
    }

    public static void UnblockAll(IEnumerable<string> paths)
    {
        foreach (var p in paths)
            try { FirewallService.Unblock(p); } catch { }
    }
}
