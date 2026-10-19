using System.IO;
using System.Text.Json;

namespace GoOffline.Services;

public record StoredApp(string Path, bool HardMode, List<string>? ExtraBlocked = null);

/// <summary>Remembers which programs the user added and their per-app settings.</summary>
public static class AppStore
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GoOffline", "apps.json");

    public static List<StoredApp> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new();
            var text = File.ReadAllText(FilePath);
            // Back-compat: v0.1 stored a flat list of strings.
            if (text.TrimStart().StartsWith("["))
            {
                try
                {
                    var newForm = JsonSerializer.Deserialize<List<StoredApp>>(text);
                    if (newForm != null && newForm.All(x => !string.IsNullOrEmpty(x.Path))) return newForm;
                }
                catch { /* fall through */ }
                var old = JsonSerializer.Deserialize<List<string>>(text);
                if (old != null) return old.Select(p => new StoredApp(p, false)).ToList();
            }
        }
        catch { }
        return new();
    }

    public static void Save(IEnumerable<StoredApp> apps)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(apps.ToList(),
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }
}
