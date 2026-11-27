using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.App.Services;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>
/// Settings: every change is saved straight away (keys and numbers after a short pause, from the
/// page). Only settings v2 acts on are shown; the rest stay untouched in settings.json.
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private bool loading;

    [ObservableProperty] public partial bool VirusTotalEnabled { get; set; }
    [ObservableProperty] public partial bool MetaDefenderEnabled { get; set; }
    [ObservableProperty] public partial bool CymruEnabled { get; set; }
    [ObservableProperty] public partial bool FreeApiLimits { get; set; }
    [ObservableProperty] public partial bool UploadUnknown { get; set; }
    [ObservableProperty] public partial double DelaySeconds { get; set; }
    [ObservableProperty] public partial double TimeoutSeconds { get; set; }
    [ObservableProperty] public partial bool HashCacheEnabled { get; set; }
    [ObservableProperty] public partial bool DeltaScanEnabled { get; set; }
    [ObservableProperty] public partial int ThemeIndex { get; set; }
    [ObservableProperty] public partial string VirusTotalKey { get; set; } = "";
    [ObservableProperty] public partial string MetaDefenderKey { get; set; } = "";
    [ObservableProperty] public partial string SavedText { get; set; } = "";
    [ObservableProperty] public partial string NewPublisher { get; set; } = "";

    public ObservableCollection<string> TrustedPublishers { get; } = [];

    public ObservableCollection<string> IgnoredHashes { get; } = [];

    public ObservableCollection<string> IgnoredPaths { get; } = [];

    public bool HasIgnored => IgnoredHashes.Count + IgnoredPaths.Count > 0;

    public string VirusTotalKeyStatus => KeyStatus(VirusTotalEnabled, VirusTotalKey);

    public string MetaDefenderKeyStatus => KeyStatus(MetaDefenderEnabled, MetaDefenderKey);

    public void Load()
    {
        loading = true;
        try
        {
            var services = AppServices.Instance;
            var s = services.Settings;
            var k = services.Keys;
            VirusTotalEnabled = s.VirusTotalEnabled;
            MetaDefenderEnabled = s.MetaDefenderEnabled;
            CymruEnabled = s.MhrEnabled;
            FreeApiLimits = s.FreeApiLimits;
            UploadUnknown = s.UploadUnknown;
            DelaySeconds = s.DelaySeconds;
            TimeoutSeconds = s.TimeoutSeconds;
            HashCacheEnabled = s.HashCacheEnabled;
            DeltaScanEnabled = s.DeltaScanEnabled;
            ThemeIndex = ThemeIndexOf(s);
            VirusTotalKey = k.VirusTotal;
            MetaDefenderKey = k.MetaDefender;
            Reset(TrustedPublishers, s.TrustedPublishers.OrderBy(p => p, StringComparer.OrdinalIgnoreCase));
            Reset(IgnoredHashes, services.IgnoreList.Hashes.Order(StringComparer.OrdinalIgnoreCase));
            Reset(IgnoredPaths, services.IgnoreList.Paths.Order(StringComparer.OrdinalIgnoreCase));
            OnPropertyChanged(nameof(HasIgnored));
            SavedText = "";
        }
        finally
        {
            loading = false;
        }
    }

    // Toggles save at once.
    partial void OnVirusTotalEnabledChanged(bool value) => SaveAndRefreshKeyStatus();
    partial void OnMetaDefenderEnabledChanged(bool value) => SaveAndRefreshKeyStatus();
    partial void OnCymruEnabledChanged(bool value) => Save();
    partial void OnFreeApiLimitsChanged(bool value) => Save();
    partial void OnUploadUnknownChanged(bool value) => Save();
    partial void OnHashCacheEnabledChanged(bool value) => Save();
    partial void OnDeltaScanEnabledChanged(bool value) => Save();

    partial void OnThemeIndexChanged(int value)
    {
        App.MainWindow?.ApplyTheme(ThemeName(value));
        Save();
    }

    partial void OnVirusTotalKeyChanged(string value) => OnPropertyChanged(nameof(VirusTotalKeyStatus));

    partial void OnMetaDefenderKeyChanged(string value) => OnPropertyChanged(nameof(MetaDefenderKeyStatus));

    /// <summary>Saves everything on the page; the page calls this for keys and numbers after typing pauses.</summary>
    public void Save()
    {
        if (loading)
        {
            return;
        }

        var services = AppServices.Instance;
        var settings = Clone(services.Settings);
        settings.VirusTotalEnabled = VirusTotalEnabled;
        settings.MetaDefenderEnabled = MetaDefenderEnabled;
        settings.MhrEnabled = CymruEnabled;
        settings.FreeApiLimits = FreeApiLimits;
        settings.UploadUnknown = UploadUnknown;
        settings.DelaySeconds = (int)Math.Clamp(double.IsNaN(DelaySeconds) ? 16 : DelaySeconds, 0, 600);
        settings.TimeoutSeconds = (int)Math.Clamp(double.IsNaN(TimeoutSeconds) ? 60 : TimeoutSeconds, 5, 600);
        settings.HashCacheEnabled = HashCacheEnabled;
        settings.DeltaScanEnabled = DeltaScanEnabled;
        settings.UseSystemDefaultColors = ThemeIndex == 0;
        settings.ColorMode = ThemeName(ThemeIndex);
        settings.TrustedPublishers = [.. TrustedPublishers];
        try
        {
            services.Save(settings, new ApiKeys(VirusTotalKey.Trim(), MetaDefenderKey.Trim()));
            services.NotifyFindingsChanged();
            SavedText = $"Saved {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SavedText = $"Couldn't save: {ex.Message}";
        }
    }

    public void AddPublisher()
    {
        var name = HashGuardLogic.NormalizePublisher(NewPublisher);
        if (name.Length == 0 || TrustedPublishers.Any(p => HashGuardLogic.PublisherEquals(p, name)))
        {
            NewPublisher = "";
            return;
        }

        var index = TrustedPublishers.TakeWhile(p => string.Compare(p, name, StringComparison.OrdinalIgnoreCase) < 0).Count();
        TrustedPublishers.Insert(index, name);
        NewPublisher = "";
        Save();
    }

    public void RemovePublisher(string name)
    {
        TrustedPublishers.Remove(name);
        Save();
    }

    public void RemoveIgnoredHash(string hash)
    {
        AppServices.Instance.IgnoreList.RemoveHash(hash);
        IgnoredHashes.Remove(hash);
        OnPropertyChanged(nameof(HasIgnored));
        SavedText = $"Saved {DateTime.Now:HH:mm:ss}";
    }

    public void RemoveIgnoredPath(string path)
    {
        AppServices.Instance.IgnoreList.RemovePath(path);
        IgnoredPaths.Remove(path);
        OnPropertyChanged(nameof(HasIgnored));
        SavedText = $"Saved {DateTime.Now:HH:mm:ss}";
    }

    /// <summary>The theme in settings.json terms: v1's "use system colours" flag, else light or dark.</summary>
    public static string ThemeOf(AppSettings settings) => ThemeName(ThemeIndexOf(settings));

    private static int ThemeIndexOf(AppSettings settings) =>
        settings.UseSystemDefaultColors || settings.ColorMode == AppConstants.ColorModeSystem ? 0
        : settings.ColorMode == AppConstants.ColorModeDark ? 2
        : 1;

    private static string ThemeName(int index) => index switch
    {
        1 => AppConstants.ColorModeLight,
        2 => AppConstants.ColorModeDark,
        _ => AppConstants.ColorModeSystem,
    };

    private void SaveAndRefreshKeyStatus()
    {
        OnPropertyChanged(nameof(VirusTotalKeyStatus));
        OnPropertyChanged(nameof(MetaDefenderKeyStatus));
        Save();
    }

    private static string KeyStatus(bool enabled, string key) =>
        key.Trim().Length > 0 ? "Key saved, encrypted for your Windows account."
        : enabled ? "No key yet: this source is skipped until you add one."
        : "No key.";

    private static AppSettings Clone(AppSettings settings) =>
        JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(settings)) ?? new AppSettings();

    private static void Reset(ObservableCollection<string> target, IEnumerable<string> items)
    {
        target.Clear();
        foreach (var item in items)
        {
            target.Add(item);
        }
    }
}
