using System.Collections;
using System.Diagnostics;
using System.Text;

namespace GoOffline.Services;

/// <summary>
/// Blocks / unblocks a program via Windows Firewall (inbound + outbound, all profiles).
/// Rules are named "GoOffline - &lt;dir&gt; - &lt;path&gt;" and grouped under "GoOffline" so a
/// user can also spot and remove them from wf.msc.
///
/// Two kinds of rule:
///   - Classic desktop app: path-based rule via the FwPolicy2 COM API.
///   - Store / UWP app (anything under C:\Program Files\WindowsApps): package SID rule
///     via PowerShell's New-NetFirewallRule, because a path-based rule is NOT enforced
///     for packaged apps — Windows filters UWP traffic by AppContainer SID.
/// </summary>
public static class FirewallService
{
    private const string Group = "GoOffline";
    private const string Prefix = "GoOffline - ";
    private const int DirIn = 1, DirOut = 2;
    private const int ActionBlock = 0;
    private const int AllProfiles = 0x7FFFFFFF;

    private static dynamic NewPolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;

    // Note: '|' is reserved in the firewall rule store and makes the Name setter throw E_INVALIDARG.
    private static string RuleName(string dir, string path) => $"{Prefix}{dir} - {path}";

    public static void Block(string exePath)
    {
        Unblock(exePath); // never stack duplicates

        if (PackagedAppService.IsPackaged(exePath))
        {
            BlockPackaged(exePath);
            return;
        }

        dynamic policy = NewPolicy();
        foreach (var (dir, code) in new[] { ("out", DirOut), ("in", DirIn) })
        {
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
            rule.Name = RuleName(dir, exePath);
            rule.Description = "Created by GoOffline. Removing the program from GoOffline deletes this rule.";
            rule.ApplicationName = exePath;
            rule.Direction = code;
            rule.Action = ActionBlock;
            rule.Profiles = AllProfiles;
            rule.Grouping = Group;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
    }

    public static void Unblock(string exePath)
    {
        dynamic policy = NewPolicy();
        foreach (var dir in new[] { "out", "in" })
        {
            string name = RuleName(dir, exePath);
            // Remove() deletes one rule per call; loop in case something duplicated it.
            for (int i = 0; i < 10 && Exists(policy, name); i++)
                policy.Rules.Remove(name);
        }
    }

    /// <summary>Paths of every program currently blocked by a GoOffline rule.</summary>
    public static HashSet<string> GetBlockedPaths()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        dynamic policy = NewPolicy();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
        {
            string name = rule.Name;
            if (!name.StartsWith(Prefix, StringComparison.Ordinal)) continue;
            if (!(bool)rule.Enabled) continue;

            // Classic rules carry the exe in ApplicationName.
            string? app = rule.ApplicationName;
            if (!string.IsNullOrEmpty(app)) { result.Add(app); continue; }

            // Packaged rules (SID-based) have no ApplicationName; recover the path from the name.
            //   "GoOffline - out - C:\path\to.exe"
            int dash = name.IndexOf(" - ", Prefix.Length, StringComparison.Ordinal);
            if (dash > 0) result.Add(name[(dash + 3)..]);
        }
        return result;
    }

    public static void UnblockAll()
    {
        dynamic policy = NewPolicy();
        var names = new List<string>();
        foreach (dynamic rule in (IEnumerable)policy.Rules)
        {
            string name = rule.Name;
            if (name.StartsWith(Prefix, StringComparison.Ordinal)) names.Add(name);
        }
        foreach (var n in names) policy.Rules.Remove(n);
    }

    // ---- UWP / packaged apps --------------------------------------------------

    private static void BlockPackaged(string exePath)
    {
        var family = PackagedAppService.GetPackageFamilyName(exePath)
            ?? throw new InvalidOperationException($"Can't read the package family name from {exePath}.");
        var sid = PackagedAppService.GetPackageSid(family)
            ?? throw new InvalidOperationException($"Can't derive the package SID for {family}.");

        // One PowerShell session, two rules. New-NetFirewallRule writes directly to the store.
        var script = new StringBuilder();
        foreach (var dir in new[] { "Outbound", "Inbound" })
        {
            var name = RuleName(dir == "Outbound" ? "out" : "in", exePath);
            script.Append($@"
New-NetFirewallRule -DisplayName '{Escape(name)}' -Group '{Group}' `
    -Direction {dir} -Action Block -Enabled True -Profile Any `
    -Package '{sid}' `
    -Description 'Created by GoOffline. Removing the program from GoOffline deletes this rule.' `
    | Out-Null
");
        }
        RunPwsh(script.ToString());
    }

    private static void RunPwsh(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -Command -")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        p.StandardInput.WriteLine(script);
        p.StandardInput.Close();
        string err = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException(
                "PowerShell failed to add the firewall rule: " +
                (string.IsNullOrWhiteSpace(err) ? "exit " + p.ExitCode : err.Trim()));
    }

    private static string Escape(string s) => s.Replace("'", "''");

    private static bool Exists(dynamic policy, string name)
    {
        try { return policy.Rules.Item(name) != null; }
        catch { return false; }
    }
}
