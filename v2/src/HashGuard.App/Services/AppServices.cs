using HashGuard.Core;

namespace HashGuard.App.Services;

/// <summary>
/// The engine objects the window shares: settings and keys, ignore list, hash cache and the scan
/// service. Created once at start-up; loading from disk happens off the UI thread.
/// </summary>
public sealed class AppServices
{
    private readonly Lock gate = new();
    private AppSettings settings;
    private ApiKeys keys;

    private AppServices()
    {
        SettingsStore = new SettingsStore();
        settings = SettingsStore.Load();
        keys = SettingsStore.ReadKeys(settings);
        IgnoreList = new IgnoreList();
        IgnoreList.Load();
        HashCache = new HashCache();
        Scans = new ScanService(HashCache, CaptureConfiguration);
        Scans.Completed += outcome =>
        {
            LastOutcome = outcome;
            OutcomeChanged?.Invoke();
        };
    }

    public static AppServices Instance { get; private set; } = null!;

    public SettingsStore SettingsStore { get; }

    public IgnoreList IgnoreList { get; }

    public HashCache HashCache { get; }

    public ScanService Scans { get; }

    /// <summary>The most recent finished scan of any kind, or null before the first one.</summary>
    public ScanOutcome? LastOutcome { get; private set; }

    /// <summary>The last full scan's time from v1's snapshot until this session runs one.</summary>
    public DateTime? LastFullScanLocal { get; private set; }

    /// <summary>Raised (on a worker thread) when a scan finishes or a finding is handled.</summary>
    public event Action? OutcomeChanged;

    public AppSettings Settings
    {
        get
        {
            lock (gate)
            {
                return settings;
            }
        }
    }

    public ApiKeys Keys
    {
        get
        {
            lock (gate)
            {
                return keys;
            }
        }
    }

    /// <summary>
    /// Loads settings, ignore list and the last-scan time (small files, a few milliseconds), then
    /// loads the hash cache in the background so the window isn't held up.
    /// </summary>
    public static void Initialize()
    {
        var services = new AppServices();
        var snapshot = ScanSnapshotStore.Load();
        services.LastFullScanLocal = snapshot is null || snapshot.CapturedAtUtc == default ? null : snapshot.CapturedAtUtc.ToLocalTime().DateTime;
        Instance = services;
        _ = Task.Run(services.HashCache.EnsureLoadedAsync);
    }

    /// <summary>Saves changed settings and keys.</summary>
    public void Save(AppSettings newSettings, ApiKeys newKeys)
    {
        SettingsStore.Save(newSettings, newKeys);
        lock (gate)
        {
            settings = newSettings;
            keys = newKeys;
        }
    }

    /// <summary>Call after the user ignored or quarantined something so counts refresh.</summary>
    public void NotifyFindingsChanged() => OutcomeChanged?.Invoke();

    /// <summary>Records that a full scan just finished.</summary>
    public void MarkFullScan(DateTime finishedLocal) => LastFullScanLocal = finishedLocal;

    /// <summary>The reputation sources switched on (Team Cymru needs no key; the others do).</summary>
    public (int On, int Total) SourcesOnline()
    {
        var s = Settings;
        var k = Keys;
        var on = (s.VirusTotalEnabled && k.VirusTotal.Length > 0 ? 1 : 0)
            + (s.MetaDefenderEnabled && k.MetaDefender.Length > 0 ? 1 : 0)
            + (s.MhrEnabled ? 1 : 0);
        return (on, 3);
    }

    private ScanConfiguration CaptureConfiguration() =>
        new(Settings, Keys, IgnoreList.Hashes, IgnoreList.Paths);
}
