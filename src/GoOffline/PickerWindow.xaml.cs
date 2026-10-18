using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using GoOffline.Services;
using Microsoft.Win32;

namespace GoOffline;

public partial class PickerWindow : Window
{
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private List<Row> _all = new();
    public string? SelectedPath { get; private set; }

    public PickerWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await LoadAsync();
    }

    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        int on = 1;
        DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20, ref on, sizeof(int));
    }

    private async Task LoadAsync()
    {
        var apps = await Task.Run(InstalledAppsService.Discover);
        _all = apps.Select(a => new Row(a)).ToList();
        Loading.Visibility = Visibility.Collapsed;
        Apply(null);
        Search.Focus();
    }

    private void Search_Changed(object sender, TextChangedEventArgs e) => Apply(Search.Text);

    private void Apply(string? query)
    {
        IEnumerable<Row> rows = _all;
        if (!string.IsNullOrWhiteSpace(query))
        {
            var q = query.Trim();
            rows = rows.Where(r => r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                                || r.ExePath.Contains(q, StringComparison.OrdinalIgnoreCase));
        }
        var list = rows.Take(500).ToList();
        List.ItemsSource = list;
        Count.Text = _all.Count == 0 ? "" : $"{list.Count} of {_all.Count}";
    }

    private void Row_Click(object sender, MouseButtonEventArgs e)
    {
        var row = (Row)((System.Windows.Controls.Border)sender).Tag;
        SelectedPath = row.ExePath;
        DialogResult = true;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "Programs (*.exe)|*.exe", Title = "Choose a program" };
        if (dlg.ShowDialog(this) == true)
        {
            SelectedPath = dlg.FileName;
            DialogResult = true;
        }
    }

    public class Row
    {
        public Row(InstalledApp a) { Name = a.Name; ExePath = a.ExePath; Icon = LoadIcon(a.ExePath); }
        public string Name { get; }
        public string ExePath { get; }
        public BitmapSource? Icon { get; }

        private static BitmapSource? LoadIcon(string path)
        {
            try
            {
                using var ic = System.Drawing.Icon.ExtractAssociatedIcon(path);
                if (ic == null) return null;
                var src = Imaging.CreateBitmapSourceFromHIcon(ic.Handle, Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                return src;
            }
            catch { return null; }
        }
    }
}
