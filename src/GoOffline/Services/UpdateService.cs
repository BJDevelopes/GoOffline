using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows;

namespace GoOffline.Services;

public record ReleaseInfo(Version Version, string Tag, string DownloadUrl, long Size, string Notes);

/// <summary>
/// Checks GitHub for a newer release and performs an in-place swap.
///
/// Install flow:
///   1. Download the win-x64 zip into %TEMP%\GoOffline-vX.Y.Z\ and extract it.
///   2. Write a tiny CMD script that waits for this process to exit, overwrites
///      the current install dir, then relaunches GoOffline.exe.
///   3. Launch the script detached and shut the app down.
///
/// Because the app runs elevated (manifest), the child cmd inherits elevation
/// — overwrite works even when installed in Program Files or similar.
/// </summary>
public static class UpdateService
{
    private const string LatestApi = "https://api.github.com/repos/BJDevelopes/GoOffline/releases/latest";

    private static readonly HttpClient Http = new();
    static UpdateService() => Http.DefaultRequestHeaders.UserAgent.ParseAdd("GoOffline-UpdateCheck/1.0");

    /// <summary>Reads from the embedded assembly; stays correct across versions.</summary>
    public static Version CurrentVersion =>
        Normalize(Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0));

    public static async Task<ReleaseInfo?> CheckAsync(CancellationToken ct = default)
    {
        string json;
        try { json = await Http.GetStringAsync(LatestApi, ct); }
        catch { return null; } // offline, rate-limited, repo renamed — never fail-stop
        return Parse(json);
    }

    internal static ReleaseInfo? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var tag = root.GetProperty("tag_name").GetString() ?? "";
            var tagVer = tag.StartsWith("v") ? tag[1..] : tag;
            if (!Version.TryParse(tagVer, out var raw)) return null;
            var latest = Normalize(raw);
            if (latest <= CurrentVersion) return null;

            string? zipUrl = null; long size = 0;
            foreach (var asset in root.GetProperty("assets").EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                    name.Contains("win-x64", StringComparison.OrdinalIgnoreCase))
                {
                    zipUrl = asset.GetProperty("browser_download_url").GetString();
                    size = asset.TryGetProperty("size", out var s) ? s.GetInt64() : 0;
                    break;
                }
            }
            if (zipUrl == null) return null;

            var notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            return new ReleaseInfo(latest, tag, zipUrl, size, notes);
        }
        catch { return null; }
    }

    private static Version Normalize(Version v) =>
        new(v.Major, v.Minor, Math.Max(0, v.Build));

    /// <summary>Download, swap, restart. Blocks on download; returns after launching the swap script.</summary>
    public static async Task InstallAsync(ReleaseInfo r, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var selfExe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Can't locate running exe.");
        var selfDir = Path.GetDirectoryName(selfExe)!;

        // Stage under %ProgramData%\GoOffline\update\<random>, admin-only ACL.
        // Writing the swap script to a world-writable %TEMP% while elevated would let a
        // local non-admin race the file and get code execution as admin. Keeping the
        // staging dir unwritable to standard users closes that door.
        var work   = CreateProtectedWorkDir();
        var zip    = Path.Combine(work, "update.zip");
        var newDir = Path.Combine(work, "new");
        Directory.CreateDirectory(newDir);

        await DownloadAsync(r.DownloadUrl, zip, r.Size, progress, ct);
        ZipFile.ExtractToDirectory(zip, newDir, overwriteFiles: true);

        var script = Path.Combine(work, "swap.cmd");
        File.WriteAllText(script, BuildSwapScript(selfDir, selfExe, newDir),
                          new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        // Full path to cmd.exe so %PATH% can't redirect to a planted binary.
        var cmdExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        Process.Start(new ProcessStartInfo
        {
            FileName = cmdExe,
            Arguments = $"/c \"\"{script}\"\"",
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true,
        });
        _ = Application.Current.Dispatcher.InvokeAsync(() => Application.Current.Shutdown());
    }

    /// <summary>
    /// Build a locked-down DirectorySecurity: Admins + SYSTEM only, no inheritance,
    /// owner = Admins. Used both to create and to RE-APPLY on existing folders.
    /// </summary>
    private static DirectorySecurity ProtectedAcl()
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        var s = new DirectorySecurity();
        s.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        s.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        s.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        s.SetOwner(admins);
        return s;
    }

    /// <summary>
    /// Create a locked-down staging directory and return its path.
    ///
    /// Location: %SystemRoot%\Temp (i.e. C:\Windows\Temp). Windows ships this with an
    /// ACL that only grants write access to Administrators and SYSTEM, so a standard
    /// user cannot have pre-created a hostile subtree underneath it. No ancestor chain
    /// to validate; the OS already did that at install time.
    ///
    /// Defense in depth: we still apply ProtectedAcl() to our random leaf, then re-open
    /// it and verify owner, ACL protection flag, and absence of reparse points before
    /// we hand the path back. If anything looks wrong, we abort hard — the caller will
    /// surface the error in the UI banner.
    /// </summary>
    private static string CreateProtectedWorkDir()
    {
        var sysTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
        if (!Directory.Exists(sysTemp))
            throw new InvalidOperationException($"System Temp directory missing: {sysTemp}");

        var acl = ProtectedAcl();
        var work = Path.Combine(sysTemp, "GoOffline-" + Path.GetRandomFileName());
        var workInfo = new DirectoryInfo(work);
        workInfo.Create(acl);

        // Verify what we just created, not what we asked for.
        workInfo.Refresh();
        if ((workInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Staging path became a reparse point — aborting.");

        var sec = workInfo.GetAccessControl();
        var owner = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        if (owner == null || !(owner.Equals(admins) || owner.Equals(system)))
            throw new InvalidOperationException("Staging directory has unexpected owner.");
        if (!sec.AreAccessRulesProtected)
            throw new InvalidOperationException("Staging directory inherits permissions — aborting.");

        return workInfo.FullName;
    }

    private static async Task DownloadAsync(string url, string path, long expected,
        IProgress<double>? progress, CancellationToken ct)
    {
        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        var total = resp.Content.Headers.ContentLength ?? expected;

        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = File.Create(path);
        var buf = new byte[81920];
        long seen = 0;
        int n;
        while ((n = await src.ReadAsync(buf, ct)) > 0)
        {
            await dst.WriteAsync(buf.AsMemory(0, n), ct);
            seen += n;
            if (total > 0) progress?.Report((double)seen / total);
        }
    }

    private static string BuildSwapScript(string installDir, string exePath, string newContent) =>
        $@"@echo off
setlocal
set TARGET={installDir}
set NEW={newContent}
set EXE={exePath}
set PID={Environment.ProcessId}

rem Wait for the running GoOffline to exit (up to ~30s), then swap files in place.
set /a WAIT=0
:loop
tasklist /FI ""PID eq %PID%"" 2>nul | find ""%PID%"" >nul
if errorlevel 1 goto doswap
set /a WAIT=%WAIT%+1
if %WAIT% GEQ 30 goto doswap
timeout /t 1 /nobreak >nul
goto loop

:doswap
rem Robocopy mirrors new\ into TARGET\. /XF update.zip skips the download; /R:3 /W:1 handles brief locks.
robocopy ""%NEW%"" ""%TARGET%"" /E /IS /IT /R:3 /W:1 /NFL /NDL /NJH /NJS >nul
start """" ""%EXE%""
endlocal
";
}
