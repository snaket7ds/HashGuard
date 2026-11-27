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
        IsFirstRun = !File.Exists(SettingsStore.Path);
        settings = SettingsStore.Load();
        keys = SettingsStore.ReadKeys(settings);
        IgnoreList = new IgnoreList();
        IgnoreList.Load();
        HashCache = new HashCache();
        Scans = new ScanService(HashCache, CaptureConfiguration);
        Scans.Completed += outcome =>
        {
            if (outcome.Kind is ScanKind.ChangedApps or ScanKind.FileActivity)
            {
                // Background checks add to the list from the last scan instead of replacing it.
                if (outcome.NeedsDecision.Count == 0)
                {
                    return;
                }

                LastOutcome = Merge(LastOutcome, outcome);
                BackgroundFindings?.Invoke(outcome.NeedsDecision);
            }
            else
            {
                LastOutcome = outcome;
            }

            OutcomeChanged?.Invoke();
        };
        Quarantine.Changed += () => OutcomeChanged?.Invoke();
        Network = new NetworkMonitor(
            HashCache,
            () =>
            {
                var s = Settings;
                return new NetworkMonitorSettings(s.NetworkMonitorEnabled, s.NetworkNotifyMode, s.AutoBlockMalicious, s.AutoBlockExceptions, s.TrustedPublishers);
            },
            key => UpdateSettings(s =>
            {
                if (!s.AutoBlockExceptions.Contains(key, StringComparer.Ordinal))
                {
                    s.AutoBlockExceptions.Add(key);
                }
            }),
            prefix => UpdateSettings(s => s.AutoBlockExceptions.RemoveAll(key => key.StartsWith(prefix, StringComparison.Ordinal))));
    }

    /// <summary>Files that a background check (a newly started program, a file you opened) found needing a decision.</summary>
    public event Action<IReadOnlyList<ScanResult>>? BackgroundFindings;

    /// <summary>The earlier results with the background check's results added; a file checked again replaces its old row.</summary>
    private static ScanOutcome Merge(ScanOutcome? earlier, ScanOutcome background)
    {
        if (earlier is null)
        {
            return background;
        }

        var paths = new HashSet<string>(background.Results.Select(r => r.Path), StringComparer.OrdinalIgnoreCase);
        var results = earlier.Results.Where(r => !paths.Contains(r.Path)).Concat(background.Results).ToList();
        return new ScanOutcome(earlier.Kind, results, earlier.NewSinceLastScan, earlier.Skipped);
    }

    /// <summary>Which programs connect where, and HashGuard's firewall blocks.</summary>
    public NetworkMonitor Network { get; }

    /// <summary>True when HashGuard started without a settings file: first-run setup is shown.</summary>
    public bool IsFirstRun { get; private set; }

    /// <summary>Saves the settings for the first time, so setup isn't shown again.</summary>
    public void FinishFirstRun()
    {
        UpdateSettings(s => s.FirstRunSetupShown = true);
        IsFirstRun = false;
    }

    /// <summary>This build's version.</summary>
    public ReleaseVersion Version { get; } = UpdateService.CurrentVersion();

    /// <summary>A newer release found by the last check, or null.</summary>
    public UpdateOffer? AvailableUpdate { get; private set; }

    /// <summary>Raised (on a worker thread) when a check finds a newer release.</summary>
    public event Action<UpdateOffer>? UpdateFound;

    /// <summary>Asks GitHub for a newer release. Throws on network or release problems.</summary>
    public async Task<UpdateOffer?> CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        using var http = UpdateService.CreateClient(Version);
        var offer = await new UpdateService(http, Version).CheckAsync(cancellationToken);
        AvailableUpdate = offer;
        if (offer is not null)
        {
            UpdateFound?.Invoke(offer);
        }

        return offer;
    }

    /// <summary>Downloads and checks the update, then starts the swap; the caller exits HashGuard when this returns true.</summary>
    public async Task<bool> DownloadAndInstallAsync(UpdateOffer offer, IProgress<string>? status = null)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("HashGuard couldn't find its own program file.");
        using var http = UpdateService.CreateClient(Version);
        var download = await new UpdateService(http, Version).DownloadAsync(offer, exe, status);
        return UpdateService.StartInstall(exe, download);
    }

    /// <summary>Start with Windows, the daily scan task and the Explorer menu, for this copy's exe.</summary>
    public WindowsIntegration Integration { get; } = new(Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "HashGuard.exe"), IsRunningElevated());

    /// <summary>
    /// Whether this is an installed copy (under Program Files). Only an installed copy repairs Windows
    /// registrations by itself at start-up; a portable or test copy changes them only when you ask.
    /// </summary>
    public static bool IsInstalledCopy
    {
        get
        {
            var dir = Path.GetFullPath(AppContext.BaseDirectory);
            return new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }
                .Select(Environment.GetFolderPath)
                .Where(path => path.Length > 0)
                .Any(path => dir.StartsWith(Path.GetFullPath(path).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
        }
    }

    private static bool IsRunningElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>Changes settings on a copy and saves it, so readers never see a half-changed object.</summary>
    public void UpdateSettings(Action<AppSettings> change)
    {
        lock (gate)
        {
            var copy = System.Text.Json.JsonSerializer.Deserialize<AppSettings>(System.Text.Json.JsonSerializer.Serialize(settings)) ?? new AppSettings();
            change(copy);
            SettingsStore.Save(copy, keys);
            settings = copy;
        }
    }

    public static AppServices Instance { get; private set; } = null!;

    public QuarantineStore Quarantine { get; } = new();

    public ActivityLogReader ActivityLog { get; } = new();

    public SettingsStore SettingsStore { get; }

    public IgnoreList IgnoreList { get; }

    public HashCache HashCache { get; }

    public ScanService Scans { get; }

    /// <summary>The most recent finished scan of any kind, or null before the first one.</summary>
    public ScanOutcome? LastOutcome { get; private set; }

    /// <summary>The last full scan's time from v1's snapshot until this session runs one.</summary>
    public DateTime? LastFullScanLocal { get; private set; }

    /// <summary>Raised (on any thread) when a scan finishes, a finding is handled or quarantine changes.</summary>
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
