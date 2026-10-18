using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Interop;
using System.Windows.Media.Imaging;

namespace GoOffline.Models;

public class AppEntry : INotifyPropertyChanged
{
    private bool _isOffline;
    private bool _isRunning;
    private bool _hardMode;

    public AppEntry(string path)
    {
        Path = path;
        Name = System.IO.Path.GetFileNameWithoutExtension(path);
        Icon = LoadIcon(path);
    }

    public string Path { get; }
    public string Name { get; }
    public BitmapSource? Icon { get; }
    public bool Exists => File.Exists(Path);

    public bool IsOffline
    {
        get => _isOffline;
        set { if (_isOffline != value) { _isOffline = value; Notify(); Notify(nameof(Status)); } }
    }

    public bool IsRunning
    {
        get => _isRunning;
        set { if (_isRunning != value) { _isRunning = value; Notify(); Notify(nameof(Status)); } }
    }

    /// <summary>Hard mode: also inject the hook DLL to kill network calls from inside the process.</summary>
    public bool HardMode
    {
        get => _hardMode;
        set { if (_hardMode != value) { _hardMode = value; Notify(); } }
    }

    public string Status =>
        (IsOffline, IsRunning) switch
        {
            (true, true) => "Offline · running",
            (true, false) => "Offline · not running",
            (false, true) => "Online · running",
            _ => "Online · not running",
        };

    private static BitmapSource? LoadIcon(string path)
    {
        try
        {
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon == null) return null;
            var src = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, System.Windows.Int32Rect.Empty,
                BitmapSizeOptions.FromEmptyOptions());
            src.Freeze();
            return src;
        }
        catch { return null; }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
