using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace GoOffline.Services;

public record InstalledApp(string Name, string ExePath, string? Publisher);

/// <summary>
/// Lists the programs a user actually launches, using the same source as the Start menu's
/// "All apps" (shell:AppsFolder). Frameworks, runtimes, SDKs and drivers never appear there,
/// so no keyword filtering is needed. Each entry is resolved to a real .exe:
///   - known-folder paths  ({GUID}\Vendor\App.exe)
///   - absolute paths      (D:\Adobe\...\Illustrator.exe)
///   - Store/UWP IDs       (Family!App) via the package's AppxManifest.xml
///   - everything else     via the Start Menu shortcut with the same name
/// Entries that don't resolve to an .exe (help files, URLs, .msc consoles) are dropped.
/// </summary>
public static class InstalledAppsService
{
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid id, uint flags, IntPtr token, out IntPtr path);

    [DllImport("ole32.dll")]
    private static extern void CoTaskMemFree(IntPtr p);

    private static readonly Regex JunkName = new(
        @"\b(uninstall|readme|read me|release notes|change ?log|license|documentation|manual|help)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<InstalledApp> Discover()
    {
        var items = EnumerateAppsFolder();
        var shortcuts = BuildShortcutIndex();
        var packages = new Lazy<List<Package>>(LoadPackages);

        var byPath = new Dictionary<string, InstalledApp>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, appId) in items)
        {
            if (JunkName.IsMatch(name)) continue;

            string? exe = null;
            try { exe = ResolveAppId(appId, packages) ?? (shortcuts.TryGetValue(name, out var s) ? s : null); }
            catch { }
            if (exe == null || IsWindowsComponent(exe)) continue;

            byPath.TryAdd(exe, new InstalledApp(name, exe, null));
        }

        return byPath.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---- shell:AppsFolder -----------------------------------------------------

    private static List<(string Name, string AppId)> EnumerateAppsFolder()
    {
        var result = new List<(string, string)>();
        var t = new Thread(() =>
        {
            try
            {
                dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application")!)!;
                dynamic folder = shell.NameSpace("shell:AppsFolder");
                dynamic items = folder.Items();
                int count = items.Count;
                for (int i = 0; i < count; i++)
                {
                    dynamic it = items.Item(i);
                    string name = it.Name;
                    string path = it.Path;
                    if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(path))
                        result.Add((name.Trim(), path.Trim()));
                }
            }
            catch { }
        });
        t.SetApartmentState(ApartmentState.STA); // Shell COM objects want an STA
        t.Start();
        t.Join();
        return result;
    }

    // ---- AppID -> exe ---------------------------------------------------------

    private static string? ResolveAppId(string appId, Lazy<List<Package>> packages)
    {
        // Store/UWP: "PackageFamilyName!AppId" (no path separators)
        int bang = appId.IndexOf('!');
        if (bang > 0 && !appId.Contains('\\') && !appId.Contains('/'))
            return ResolveUwp(appId[..bang], appId[(bang + 1)..], packages.Value);

        // Known-folder prefix: "{GUID}\rest\of\path.exe"
        var m = Regex.Match(appId, @"^\{([0-9A-Fa-f\-]{36})\}\\(.+)$");
        if (m.Success)
        {
            var folder = KnownFolder(Guid.Parse(m.Groups[1].Value));
            return folder == null ? null : ExistingExe(Path.Combine(folder, m.Groups[2].Value));
        }

        return ExistingExe(appId);
    }

    private static string? ExistingExe(string path)
    {
        path = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        try { return File.Exists(path) ? Path.GetFullPath(path) : null; }
        catch { return null; }
    }

    private static string? KnownFolder(Guid id)
    {
        if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out var p) != 0) return null;
        try { return Marshal.PtrToStringUni(p); }
        finally { CoTaskMemFree(p); }
    }

    private static bool IsWindowsComponent(string exe)
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return exe.StartsWith(win + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Store / UWP packages -------------------------------------------------

    private record Package(string FolderName, string Dir, Dictionary<string, string> AppExes);

    private static List<Package> LoadPackages()
    {
        var list = new List<Package>();
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
        IEnumerable<string> dirs;
        try { dirs = Directory.EnumerateDirectories(root).ToList(); }
        catch { return list; } // needs admin; GoOffline always runs elevated

        foreach (var dir in dirs)
        {
            try
            {
                var manifest = Path.Combine(dir, "AppxManifest.xml");
                if (!File.Exists(manifest)) continue;
                var xml = XDocument.Load(manifest);
                var apps = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var a in xml.Descendants().Where(e => e.Name.LocalName == "Application"))
                {
                    var id = a.Attribute("Id")?.Value;
                    var exe = a.Attribute("Executable")?.Value;
                    if (id != null && !string.IsNullOrEmpty(exe)) apps[id] = exe;
                }
                if (apps.Count > 0) list.Add(new Package(Path.GetFileName(dir), dir, apps));
            }
            catch { }
        }
        return list;
    }

    private static string? ResolveUwp(string familyName, string appId, List<Package> packages)
    {
        // Family name = "<Name>_<publisherHash>"; install folder = "<Name>_<ver>_<arch>__<publisherHash>".
        int us = familyName.LastIndexOf('_');
        if (us <= 0) return null;
        var name = familyName[..us];
        var hash = familyName[(us + 1)..];

        foreach (var p in packages
                     .Where(p => p.FolderName.StartsWith(name + "_", StringComparison.OrdinalIgnoreCase)
                              && p.FolderName.EndsWith("__" + hash, StringComparison.OrdinalIgnoreCase))
                     .OrderByDescending(p => p.FolderName))
        {
            if (p.AppExes.TryGetValue(appId, out var rel))
            {
                var exe = Path.Combine(p.Dir, rel);
                if (File.Exists(exe)) return exe;
            }
        }
        return null;
    }

    // ---- Start Menu shortcuts (fallback for IDs we can't resolve directly) ----

    private static Dictionary<string, string> BuildShortcutIndex()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var t = new Thread(() =>
        {
            dynamic? shell;
            try { shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!); }
            catch { return; }

            foreach (var dir in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                         Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                     })
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                IEnumerable<string> lnks;
                try { lnks = Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories).ToList(); }
                catch { continue; }

                foreach (var lnk in lnks)
                {
                    try
                    {
                        dynamic sc = shell!.CreateShortcut(lnk);
                        string target = sc.TargetPath ?? "";
                        string args = sc.Arguments ?? "";
                        var exe = ResolveShortcutTarget(target, args);
                        if (exe != null) map.TryAdd(Path.GetFileNameWithoutExtension(lnk), exe);
                    }
                    catch { }
                }
            }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        return map;
    }

    private static string? ResolveShortcutTarget(string target, string args)
    {
        var exe = ExistingExe(target);
        if (exe == null) return null;

        // Squirrel apps (Discord, Slack, ...) point at Update.exe --processStart <App>.exe;
        // the real program lives in the newest sibling app-<version> folder.
        if (Path.GetFileName(exe).Equals("Update.exe", StringComparison.OrdinalIgnoreCase))
        {
            var m = Regex.Match(args, @"--processStart(?:AndWait)?\s+""?([^"" ]+\.exe)", RegexOptions.IgnoreCase);
            if (!m.Success) return null;
            var dir = Path.GetDirectoryName(exe)!;
            var appDir = Directory.EnumerateDirectories(dir, "app-*")
                .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
            return appDir == null ? null : ExistingExe(Path.Combine(appDir, m.Groups[1].Value));
        }
        return exe;
    }
}
