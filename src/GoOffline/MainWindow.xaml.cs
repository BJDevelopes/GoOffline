using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Threading;
using GoOffline.Models;
using GoOffline.Services;
using Microsoft.Win32;

namespace GoOffline;

public partial class MainWindow : Window
{
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private readonly ObservableCollection<AppEntry> _apps = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private bool _refreshing;

    public MainWindow()
    {
        InitializeComponent();
        AppList.ItemsSource = _apps;
        _apps.CollectionChanged += (_, _) => EmptyHint.Visibility = _apps.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        HashSet<string> blocked;
        try { blocked = FirewallService.GetBlockedPaths(); }
        catch (Exception ex) { blocked = new(); SetStatus("Couldn't read firewall: " + ex.Message); }

        // Saved list + anything already blocked by a GoOffline rule (e.g. list file was deleted).
        var stored = AppStore.Load();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in stored)
        {
            if (seen.Add(s.Path))
            {
                var entry = new AppEntry(s.Path) { IsOffline = blocked.Contains(s.Path), HardMode = s.HardMode };
                if (s.ExtraBlocked != null) entry.ExtraBlocked = new List<string>(s.ExtraBlocked);
                _apps.Add(entry);
            }
        }
        foreach (var p in blocked)
            if (seen.Add(p)) _apps.Add(new AppEntry(p) { IsOffline = true });
        EmptyHint.Visibility = _apps.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        _timer.Tick += async (_, _) => await RefreshRunningAsync();
        _timer.Start();
        _ = RefreshRunningAsync();
        _ = CheckForUpdateAsync();
    }

    // ---- auto-update -----------------------------------------------------------

    private ReleaseInfo? _pendingUpdate;

    private async Task CheckForUpdateAsync()
    {
        var r = await UpdateService.CheckAsync();
        if (r == null) return;
        _pendingUpdate = r;
        UpdateTitle.Text = $"GoOffline {r.Tag} is available";
        UpdateSubtitle.Text = r.Size > 0
            ? $"You're on v{UpdateService.CurrentVersion}. Update is {r.Size / (1024.0 * 1024.0):0.0} MB."
            : $"You're on v{UpdateService.CurrentVersion}.";
        UpdateBanner.Visibility = Visibility.Visible;
    }

    private void UpdateDismiss_Click(object sender, RoutedEventArgs e)
    {
        UpdateBanner.Visibility = Visibility.Collapsed;
        _pendingUpdate = null;
    }

    private async void UpdateInstall_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate == null) return;
        var r = _pendingUpdate;
        UpdateTitle.Text = $"Downloading GoOffline {r.Tag}…";
        UpdateSubtitle.Text = "0%";
        var progress = new Progress<double>(p =>
            UpdateSubtitle.Text = $"{p * 100:0}% — GoOffline will restart when done.");
        try
        {
            await UpdateService.InstallAsync(r, progress);
            // InstallAsync shuts the app down after launching the swap script.
        }
        catch (Exception ex)
        {
            UpdateTitle.Text = "Update failed";
            UpdateSubtitle.Text = ex.Message;
        }
    }

    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        int on = 1; // dark title bar
        DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20, ref on, sizeof(int));
    }

    private void SetStatus(string text) => StatusText.Text = text;

    private void Save() => AppStore.Save(_apps.Select(a =>
        new StoredApp(a.Path, a.HardMode, a.ExtraBlocked.Count == 0 ? null : new List<string>(a.ExtraBlocked))));

    // ---- adding ----------------------------------------------------------------

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        var picker = new PickerWindow { Owner = this };
        if (picker.ShowDialog() == true && !string.IsNullOrEmpty(picker.SelectedPath))
            AddPath(picker.SelectedPath);
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
            foreach (var f in files) AddPath(f);
    }

    private void AddPath(string path)
    {
        if (path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            SetStatus("Shortcuts aren't supported — pick the program's .exe itself.");
            return;
        }
        if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
        {
            SetStatus("Only .exe files can be added.");
            return;
        }
        path = Path.GetFullPath(path);
        if (_apps.Any(a => a.Path.Equals(path, StringComparison.OrdinalIgnoreCase))) return;
        _apps.Add(new AppEntry(path));
        Save();
        SetStatus($"Added {Path.GetFileName(path)}");
    }

    // ---- toggling --------------------------------------------------------------

    private void Toggle_Click(object sender, RoutedEventArgs e)
    {
        var btn = (ToggleButton)sender;
        var app = (AppEntry)btn.DataContext;
        bool goOffline = btn.IsChecked == true;
        try
        {
            if (goOffline)
            {
                // Universal: block the whole install folder + any running descendants,
                // not just the main exe. Catches helper .exes, auto-updaters, licensing
                // daemons, and child processes that keep the socket on their own.
                var blocked = UniversalBlockService.BlockAll(app.Path);
                app.ExtraBlocked = blocked;
                app.IsOffline = true;
                int cut = 0;
                foreach (var p in blocked) cut += CutConnections(p);
                var extra = app.HardMode ? ApplyHardMode(app) : "";
                int helpers = blocked.Count - 1;
                string helperBlurb = helpers > 0 ? $", {helpers} helper .exe(s)" : "";
                SetStatus($"{app.Name} is offline" + helperBlurb +
                    (cut > 0 ? $" — dropped {cut} connection(s)" : "") + extra + ".");

                var stray = FindStrayCopies(app.Path);
                if (stray.Count > 0)
                    SetStatus($"Heads up: another copy of {app.Name} is running from {stray[0]} " +
                              "— add that .exe too (Add program → Browse) to block it.");
                Save();
            }
            else
            {
                var toClear = app.ExtraBlocked.Count > 0 ? app.ExtraBlocked : new List<string> { app.Path };
                UniversalBlockService.UnblockAll(toClear);
                app.ExtraBlocked = new();
                app.IsOffline = false;
                SetStatus($"{app.Name} is back online.");
                Save();
            }
        }
        catch (Exception ex)
        {
            btn.IsChecked = app.IsOffline; // snap back to reality
            SetStatus("Failed: " + ex.Message);
        }
    }

    private void HardMode_Click(object sender, RoutedEventArgs e)
    {
        var cb = (CheckBox)sender;
        var app = (AppEntry)cb.DataContext;
        app.HardMode = cb.IsChecked == true;
        Save();
        if (app.IsOffline && app.HardMode)
            SetStatus(ApplyHardMode(app).TrimStart(' ', ',', '—'));
    }

    private static string ApplyHardMode(AppEntry app)
    {
        var s = InjectionService.InjectAll(app.Path);
        var blurb = s.Blurb;
        return string.IsNullOrEmpty(blurb) ? "" : ", " + blurb;
    }

    private static int CutConnections(string exePath)
    {
        var pids = ProcessService.Snapshot()
            .Where(kv => kv.Value.Equals(exePath, StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key).ToList();
        return ProcessService.ResetConnections(pids);
    }

    /// <summary>Descendants of each offline app's live processes whose paths aren't blocked yet.</summary>
    private List<(AppEntry app, string path)> DiscoverNewChildren()
    {
        var results = new List<(AppEntry, string)>();
        var snapshot = ProcessService.Snapshot();
        foreach (var app in _apps.Where(a => a.IsOffline))
        {
            var rootPids = snapshot
                .Where(kv => kv.Value.Equals(app.Path, StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Key).ToList();
            if (rootPids.Count == 0) continue;
            foreach (var path in UniversalBlockService.DescendantsOf(rootPids).Values.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (app.ExtraBlocked.Contains(path, StringComparer.OrdinalIgnoreCase)) continue;
                results.Add((app, path));
            }
        }
        return results;
    }

    /// <summary>Paths of running processes with the same exe name but a different location.</summary>
    private static List<string> FindStrayCopies(string exePath)
    {
        var name = System.IO.Path.GetFileName(exePath);
        return ProcessService.Snapshot().Values
            .Where(p => System.IO.Path.GetFileName(p).Equals(name, StringComparison.OrdinalIgnoreCase)
                     && !p.Equals(exePath, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var app = (AppEntry)((Button)sender).DataContext;
        try { FirewallService.Unblock(app.Path); } catch (Exception ex) { SetStatus("Failed: " + ex.Message); return; }
        _apps.Remove(app);
        Save();
    }

    private void RestoreAll_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            FirewallService.UnblockAll();
            foreach (var a in _apps) a.IsOffline = false;
            SetStatus("Everything is back online.");
        }
        catch (Exception ex) { SetStatus("Failed: " + ex.Message); }
    }

    // ---- live status -----------------------------------------------------------

    private async Task RefreshRunningAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
        try
        {
            var offline = _apps.Where(a => a.IsOffline).Select(a => a.Path).ToList();
            var running = await Task.Run(() =>
            {
                var set = new HashSet<string>(ProcessService.Snapshot().Values, StringComparer.OrdinalIgnoreCase);
                // Belt and braces: re-cut anything offline that's running (new processes, stubborn sockets).
                foreach (var p in offline.Where(set.Contains)) CutConnections(p);
                return set;
            });
            foreach (var a in _apps) a.IsRunning = running.Contains(a.Path);
            // Re-apply Hard mode to any newly-spawned processes of hard-mode apps.
            foreach (var a in _apps.Where(a => a.IsOffline && a.HardMode && a.IsRunning).ToList())
                _ = Task.Run(() => InjectionService.InjectAll(a.Path));

            // Catch new descendants spawned since the switch was flipped: if the main exe
            // is running and spawned a child whose path we haven't blocked yet, block it now.
            var discovered = await Task.Run(() => DiscoverNewChildren());
            if (discovered.Count > 0)
            {
                foreach (var (app, newPath) in discovered)
                {
                    try
                    {
                        FirewallService.Block(newPath);
                        if (!app.ExtraBlocked.Contains(newPath, StringComparer.OrdinalIgnoreCase))
                            app.ExtraBlocked.Add(newPath);
                    }
                    catch { /* best effort */ }
                }
                Save();
            }

            // Quietly watch for stray copies of blocked apps running from unexpected paths.
            // Only mention them when the status bar is otherwise idle, so we don't nag.
            if (string.IsNullOrEmpty(StatusText.Text) || StatusText.Text.StartsWith("Heads up"))
            {
                var strays = _apps.Where(a => a.IsOffline)
                    .Select(a => (app: a, extras: FindStrayCopies(a.Path)))
                    .Where(x => x.extras.Count > 0)
                    .ToList();
                SetStatus(strays.Count == 0 ? "" :
                    $"Heads up: another copy of {strays[0].app.Name} is running from {strays[0].extras[0]}.");
            }
        }
        catch { /* transient; try again next tick */ }
        finally { _refreshing = false; }
    }
}
