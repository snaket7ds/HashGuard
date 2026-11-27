namespace HashGuard.Core;

/// <summary>Everything a scan reads from the user's setup, captured once when it starts.</summary>
public sealed record ScanConfiguration(AppSettings Settings, ApiKeys Keys, IReadOnlySet<string> IgnoredHashes, IReadOnlySet<string> IgnoredPaths);

public enum ScanKind
{
    /// <summary>Every running app and everything that starts automatically.</summary>
    RunningApps,

    /// <summary>Running apps whose file is new or changed since HashGuard last looked (background monitoring).</summary>
    ChangedApps,

    /// <summary>Files the user picked, opened or sent from Explorer.</summary>
    Files,
}

/// <param name="Done">Files finished so far.</param>
/// <param name="Latest">The file that just finished, or null while collecting files.</param>
public sealed record ScanProgress(ScanKind Kind, int Done, int Total, ScanResult? Latest);

/// <summary>What a finished scan found.</summary>
public sealed class ScanOutcome(ScanKind kind, IReadOnlyList<ScanResult> results, int newSinceLastScan, IReadOnlyList<SkippedProcess> skipped)
{
    public ScanKind Kind { get; } = kind;
    public IReadOnlyList<ScanResult> Results { get; } = results;
    public int NewSinceLastScan { get; } = newSinceLastScan;
    public IReadOnlyList<SkippedProcess> Skipped { get; } = skipped;
    public DateTimeOffset FinishedAt { get; } = DateTimeOffset.Now;
    public IReadOnlyList<ScanResult> NeedsDecision { get; } = results.Where(ScanRules.NeedsAction).ToList();
    public int Threats => NeedsDecision.Count(r => r.IsAlert);
    public int Unknown => Results.Count(r => r.Status is "unknown" or "uploaded");
    public int Errors => NeedsDecision.Count(r => r.Status == "error");
}

public static class ScanRules
{
    /// <summary>True when the user should decide about this file: flagged, failed, high risk or awaiting upload, and not already handled.</summary>
    public static bool NeedsAction(ScanResult result) =>
        !IsHandled(result)
        && HashGuardLogic.NeedsAction(result.Status, $"{result.RiskLevel} {result.RiskScore}", result.Malicious, result.Suspicious, result.NeedsVirusTotalUpload);

    /// <summary>Ignored or quarantined already.</summary>
    public static bool IsHandled(ScanResult result) =>
        string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase)
        || HashGuardLogic.HasIgnoreNote(result.Notes)
        || HashGuardLogic.NoteIndicatesQuarantined(result.Notes);

    /// <summary>True when MetaDefender is switched on without a key: the UI should ask for one before scanning.</summary>
    public static bool MetaDefenderKeyMissing(AppSettings settings, ApiKeys keys) =>
        settings.MetaDefenderEnabled && string.IsNullOrWhiteSpace(keys.MetaDefender);
}

/// <summary>
/// Runs scans. Only one scan runs at a time; a second request while one runs returns null.
/// Files are checked a few at a time and reported in order. Results go to the hash cache and
/// the scan log; full scans also update the "new since last scan" snapshot.
/// </summary>
public sealed class ScanService(HashCache hashCache, Func<ScanConfiguration> configuration)
{
    private readonly ScanGate gate = new();
    private readonly Dictionary<string, ProcessFileState> seenFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock seenGate = new();
    private VirusTotalPacer? pacer;

    /// <summary>Replaceable for tests.</summary>
    public Func<bool, CancellationToken, Task<ProcessCollection>> CollectProcesses { get; init; } = ProcessCollector.CollectAsync;

    /// <summary>Replaceable for tests; defaults to building the enabled providers from settings.</summary>
    public Func<ScanConfiguration, IReadOnlyList<IReputationProvider>>? CreateProviders { get; init; }

    /// <summary>Replaceable for tests; defaults to <see cref="FileAnalyzer"/>.</summary>
    public Func<ScanConfiguration, IReadOnlyList<IReputationProvider>, FileAnalyzer>? CreateAnalyzer { get; init; }

    /// <summary>Where scan rows are written; null skips logging (tests).</summary>
    public Action<IReadOnlyList<ScanResult>>? WriteLog { get; init; } = results => ScanLog.Append(results);

    /// <summary>Saves and compares the last full scan; false skips it (tests).</summary>
    public bool UseSnapshots { get; init; } = true;

    /// <summary>Loads the hash cache before a scan; replaceable for tests.</summary>
    public Func<CancellationToken, Task>? PrepareStorage { get; init; }

    public bool IsBusy => gate.IsBusy;

    /// <summary>True once a full scan finished, so background monitoring knows what "new" means.</summary>
    public bool HasBaseline { get; private set; }

    public event Action<ScanOutcome>? Completed;

    public Task<ScanOutcome?> ScanRunningAppsAsync(IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default) =>
        RunAsync(ScanKind.RunningApps, null, progress, cancellationToken);

    public Task<ScanOutcome?> ScanChangedAppsAsync(IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default) =>
        RunAsync(ScanKind.ChangedApps, null, progress, cancellationToken);

    public Task<ScanOutcome?> ScanFilesAsync(IReadOnlyCollection<string> paths, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default) =>
        RunAsync(ScanKind.Files, paths, progress, cancellationToken);

    private async Task<ScanOutcome?> RunAsync(ScanKind kind, IReadOnlyCollection<string>? filePaths, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        if (!gate.TryEnter())
        {
            return null;
        }

        try
        {
            var config = configuration();
            progress?.Report(new ScanProgress(kind, 0, 0, null));

            IReadOnlyDictionary<string, List<ProcessFile>> targets;
            IReadOnlyList<SkippedProcess> skipped = [];
            if (kind == ScanKind.Files)
            {
                targets = (filePaths ?? [])
                    .Where(p => !string.IsNullOrWhiteSpace(p))
                    .Select(Path.GetFullPath)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(p => p, p => new List<ProcessFile> { new(0, Path.GetFileName(p), p) }, StringComparer.OrdinalIgnoreCase);
            }
            else
            {
                var collection = await CollectProcesses(kind == ScanKind.RunningApps, cancellationToken);
                skipped = collection.Skipped;
                targets = kind == ScanKind.ChangedApps
                    ? collection.Files.Where(pair => IsNewOrChanged(pair.Key)).ToDictionary(StringComparer.OrdinalIgnoreCase)
                    : collection.Files;
                Remember(collection.Files.Keys);
                if (kind == ScanKind.ChangedApps && targets.Count == 0)
                {
                    return new ScanOutcome(kind, [], 0, skipped);
                }
            }

            await (PrepareStorage ?? PrepareStorageAsync)(cancellationToken);
            var providers = (CreateProviders ?? BuildProviders)(config);
            try
            {
                var analyzer = (CreateAnalyzer ?? BuildAnalyzer)(config, providers);
                var paths = targets.Keys.Order(StringComparer.OrdinalIgnoreCase).ToList();
                var results = new List<ScanResult>(paths.Count);
                await OrderedConcurrency.ForEachAsync(
                    paths,
                    AppConstants.MaxConcurrentFileLookups,
                    path => analyzer.AnalyzeAsync(path, targets[path], allowVirusTotalUploads: true, cancellationToken),
                    async (index, result) =>
                    {
                        results.Add(result);
                        progress?.Report(new ScanProgress(kind, index + 1, paths.Count, result));
                        await hashCache.FlushIfDueAsync();
                    },
                    cancellationToken);

                var newSinceLast = 0;
                if (kind == ScanKind.RunningApps && UseSnapshots)
                {
                    ScanSnapshotStore.MarkNewSinceLastScan(results, ScanSnapshotStore.Load());
                    newSinceLast = results.Count(r => r.IsNewSinceLastScan);
                    ScanSnapshotStore.Save(results);
                }

                if (kind == ScanKind.RunningApps)
                {
                    HasBaseline = true;
                }

                TryWriteLog(results);
                var outcome = new ScanOutcome(kind, results, newSinceLast, skipped);
                Completed?.Invoke(outcome);
                return outcome;
            }
            finally
            {
                foreach (var provider in providers.OfType<IDisposable>())
                {
                    provider.Dispose();
                }
            }
        }
        finally
        {
            try
            {
                await hashCache.SaveIfDirtyAsync();
            }
            catch
            {
                // The cache is saved again later; results are already returned.
            }

            gate.Exit();
        }
    }

    private void TryWriteLog(IReadOnlyList<ScanResult> results)
    {
        try
        {
            WriteLog?.Invoke(results);
        }
        catch
        {
            // A full disk or locked log must not lose the scan's results.
        }
    }

    private bool IsNewOrChanged(string path)
    {
        lock (seenGate)
        {
            if (!seenFiles.TryGetValue(path, out var previous))
            {
                return true;
            }

            return TryGetFileState(path, out var current) && current != previous;
        }
    }

    private void Remember(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            if (TryGetFileState(path, out var state))
            {
                lock (seenGate)
                {
                    seenFiles[path] = state;
                }
            }
        }
    }

    private static bool TryGetFileState(string path, out ProcessFileState state)
    {
        state = default;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return false;
            }

            state = new ProcessFileState(info.Length, info.LastWriteTimeUtc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task PrepareStorageAsync(CancellationToken cancellationToken)
    {
        await hashCache.EnsureLoadedAsync();
        cancellationToken.ThrowIfCancellationRequested();
        hashCache.ImportScanLogsIfChanged(AppPaths.GetLogDirectories().ToList());

        // HashGuard trusts its own executable.
        var self = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(self) && !hashCache.IsTrustedCleanPath(self))
        {
            await hashCache.MarkFileCleanAsync(self, "HashGuard executable trusted locally.");
            await hashCache.SaveIfDirtyAsync();
        }
    }

    private IReadOnlyList<IReputationProvider> BuildProviders(ScanConfiguration config)
    {
        var settings = config.Settings;
        var providers = new List<IReputationProvider>();
        if (settings.MetaDefenderEnabled)
        {
            providers.Add(new MetaDefenderProvider(config.Keys.MetaDefender));
        }

        if (settings.VirusTotalEnabled)
        {
            var delay = TimeSpan.FromSeconds(Math.Max(0, settings.DelaySeconds));
            if (pacer is null || pacer.FreeApiLimit != settings.FreeApiLimits || pacer.Delay != delay)
            {
                pacer = new VirusTotalPacer(settings.FreeApiLimits, delay);
            }

            providers.Add(new VirusTotalProvider(config.Keys.VirusTotal, pacer, TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 5, 600))));
        }

        if (settings.MhrEnabled)
        {
            providers.Add(new CymruProvider());
        }

        return providers;
    }

    private FileAnalyzer BuildAnalyzer(ScanConfiguration config, IReadOnlyList<IReputationProvider> providers) =>
        new(hashCache, providers, new AnalyzerSettings
        {
            HashCacheEnabled = config.Settings.HashCacheEnabled,
            DeltaScanEnabled = config.Settings.DeltaScanEnabled,
            UploadUnknown = config.Settings.UploadUnknown,
            TrustedPublishers = config.Settings.TrustedPublishers,
            IgnoredHashes = config.IgnoredHashes,
            IgnoredPaths = config.IgnoredPaths,
        });
}
