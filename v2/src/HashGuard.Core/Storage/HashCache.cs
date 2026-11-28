using System.Diagnostics;
using System.Text.Json;

namespace HashGuard.Core;

public sealed class HashCache
{
    // Concurrent: a scan checks several files at once, and the network monitor reads while scans write.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, CacheEntry> entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, FileStateEntry> fileStates = new(StringComparer.OrdinalIgnoreCase);
    private bool loaded;
    private bool dirty;
    private int unsavedMutations;
    private DateTimeOffset lastSaveUtc = DateTimeOffset.MinValue;
    private string scanLogImportSignature = "";
    // Forget / Clear all must survive restarts, although the cache is re-seeded from the scan logs:
    // log rows checked before these times are not imported again.
    private readonly Dictionary<string, DateTime> forgottenAtUtc = new(StringComparer.OrdinalIgnoreCase);
    private DateTime clearedAtUtc = DateTime.MinValue;

    private sealed class ForgottenFile
    {
        public DateTime ClearedAtUtc { get; set; } = DateTime.MinValue;
        public Dictionary<string, DateTime> Hashes { get; set; } = [];
    }

    private static string GetForgottenPath() => Path.Combine(Path.GetDirectoryName(AppPaths.GetHashCachePath())!, "hash-cache-forgotten.json");
    // Lookups for several files can overlap, so two flushes can be due at once; saves run one at a time.
    private readonly SemaphoreSlim saveGate = new(1, 1);

    public const int FlushEveryMutations = 25;
    public static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(5);

    public int Count => entries.Count;

    /// <summary>A stored hash with the file it was last seen at (empty when unknown), for the Stored hashes list.</summary>
    public readonly record struct StoredHash(string Sha256, CacheEntry Entry, string Path);

    /// <summary>A copy of every stored hash, newest check first. Safe to enumerate while scans continue.</summary>
    public List<StoredHash> Snapshot()
    {
        var pathByHash = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, state) in fileStates.ToList())
        {
            if (!string.IsNullOrEmpty(state.Sha256))
            {
                pathByHash[state.Sha256] = path;
            }
        }

        return entries.ToList()
            .Select(pair => new StoredHash(pair.Key, pair.Value,
                pathByHash.TryGetValue(pair.Key, out var path) ? path : pair.Value.Path ?? ""))
            .OrderByDescending(item => item.Entry.CheckedAtUtc)
            .ToList();
    }

    /// <summary>Forgets one hash (and the file rows that point at it), so the next scan checks that file again.</summary>
    public bool Remove(string sha256)
    {
        forgottenAtUtc[sha256] = DateTime.UtcNow;
        var removed = entries.TryRemove(sha256, out _);
        foreach (var path in fileStates.Where(pair => string.Equals(pair.Value.Sha256, sha256, StringComparison.OrdinalIgnoreCase)).Select(pair => pair.Key).ToList())
        {
            fileStates.TryRemove(path, out _);
            removed = true;
        }

        MarkDirty();
        return removed;
    }

    /// <summary>Forgets every stored hash; every file is checked again on the next scan.</summary>
    public void Clear()
    {
        entries.Clear();
        fileStates.Clear();
        forgottenAtUtc.Clear();
        clearedAtUtc = DateTime.UtcNow;
        MarkDirty();
    }

    private void LoadForgotten()
    {
        forgottenAtUtc.Clear();
        clearedAtUtc = DateTime.MinValue;
        try
        {
            var path = GetForgottenPath();
            if (!File.Exists(path))
            {
                return;
            }

            var stored = JsonSerializer.Deserialize<ForgottenFile>(File.ReadAllText(path));
            if (stored is null)
            {
                return;
            }

            clearedAtUtc = DateTime.SpecifyKind(stored.ClearedAtUtc, DateTimeKind.Utc);
            foreach (var (hash, at) in stored.Hashes)
            {
                forgottenAtUtc[hash] = DateTime.SpecifyKind(at, DateTimeKind.Utc);
            }
        }
        catch
        {
            // A damaged file only means forgotten hashes may be re-learned from old logs.
        }
    }

    /// <summary>True when a log row checked at this time predates a Forget / Clear all for its hash.</summary>
    internal bool IsForgotten(string sha256, DateTime checkedAtUtc) =>
        checkedAtUtc <= clearedAtUtc
        || (forgottenAtUtc.TryGetValue(sha256, out var at) && checkedAtUtc <= at);
    public bool IsLoaded => loaded;
    /// <summary>Load cache from disk once; keep it warm in memory for the process lifetime.</summary>
    public async Task EnsureLoadedAsync()
    {
        if (loaded)
        {
            return;
        }

        await LoadAsync();
    }

    public async Task LoadAsync()
    {
        entries.Clear();
        fileStates.Clear();
        foreach (var cachePath in GetCachePaths().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            await LoadFromPathAsync(cachePath);
        }

        await LoadFileStatesAsync();
        LoadForgotten();
        loaded = true;
        dirty = false;
        unsavedMutations = 0;
        // Force a log re-import after a full reload so disk-backed state is complete.
        scanLogImportSignature = "";
    }

    public static bool IsFlushDue(
        bool isDirty,
        int unsaved,
        DateTimeOffset lastSave,
        DateTimeOffset now,
        int everyMutations = FlushEveryMutations,
        TimeSpan? interval = null)
    {
        if (!isDirty)
        {
            return false;
        }

        var maxAge = interval ?? FlushInterval;
        return unsaved >= everyMutations || now - lastSave >= maxAge;
    }

    public bool TryGet(string sha256, out CacheEntry entry) => entries.TryGetValue(sha256, out entry!);

    public bool TryGetUnchangedFile(string path, out string sha256, out CacheEntry entry)
    {
        sha256 = "";
        entry = null!;

        if (!fileStates.TryGetValue(path, out var fileState) || !entries.TryGetValue(fileState.Sha256, out entry!) || !IsReusableCleanEntry(entry))
        {
            return false;
        }

        try
        {
            var info = new FileInfo(path);
            if (!info.Exists
                || info.Length != fileState.Length
                || info.LastWriteTimeUtc != fileState.LastWriteTimeUtc)
            {
                return false;
            }

            sha256 = fileState.Sha256;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Set(ScanResult result)
    {
        var cacheStatus = string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(result.StatusBeforeIgnore)
                ? result.StatusBeforeIgnore
                : result.Status;
        entries[result.Sha256] = new CacheEntry
        {
            Status = cacheStatus,
            Malicious = result.Malicious,
            Suspicious = result.Suspicious,
            Harmless = result.Harmless,
            Undetected = result.Undetected,
            Link = result.Link,
            Notes = HashGuardLogic.RemoveIgnoreNote(result.Notes),
            CheckedAtUtc = DateTimeOffset.UtcNow,
            VirusTotalDeferred = result.VirusTotalDeferred,
            NeedsVirusTotalUpload = result.NeedsVirusTotalUpload,
            Path = result.Path,
        };
        SetFileState(result);
        MarkDirty();
    }

    public async Task MarkFileCleanAsync(string path, string notes)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var sha256 = await FileHash.Sha256FileAsync(path);
        entries[sha256] = new CacheEntry
        {
            Status = "clean",
            Link = string.Format(AppConstants.VirusTotalGuiReportUrl, sha256),
            Notes = notes,
            CheckedAtUtc = DateTimeOffset.UtcNow,
            Path = path,
        };
        MarkDirty();

        SetFileState(new ScanResult(path, Path.GetFileName(path), Process.GetCurrentProcess().Id.ToString())
        {
            Sha256 = sha256,
            Status = "clean",
            Link = string.Format(AppConstants.VirusTotalGuiReportUrl, sha256),
            Notes = notes,
        });
    }

    /// <summary>
    /// Remembers which hash this file had at this size and time, for every verdict. v1 kept it only
    /// for clean files, so a file flagged malicious could never be looked up by path: the Firewall
    /// page showed it as "Not scanned" and auto-block never fired. Reusing a clean verdict still
    /// requires a clean entry (<see cref="TryGetUnchangedFile"/>).
    /// </summary>
    public void SetFileState(ScanResult result)
    {
        if (string.IsNullOrWhiteSpace(result.Sha256) || !entries.ContainsKey(result.Sha256))
        {
            return;
        }

        try
        {
            var info = new FileInfo(result.Path);
            if (!info.Exists)
            {
                return;
            }

            fileStates[result.Path] = new FileStateEntry
            {
                Sha256 = result.Sha256,
                Length = info.Length,
                LastWriteTimeUtc = info.LastWriteTimeUtc,
            };
            MarkDirty();
        }
        catch
        {
            // File state caching is an optimization; scan results are still valid without it.
        }
    }

    private void MarkDirty()
    {
        dirty = true;
        unsavedMutations++;
    }

    /// <summary>
    /// Import scan CSVs only when log files have changed since the last import.
    /// Caps how many recent files are read so startup/scan prep stays cheap.
    /// </summary>
    public void ImportScanLogsIfChanged(IEnumerable<string> logDirectories)
    {
        var directories = logDirectories.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var signature = BuildScanLogSignature(directories);
        if (string.Equals(scanLogImportSignature, signature, StringComparison.Ordinal))
        {
            return;
        }

        ImportScanLogs(directories);
        scanLogImportSignature = signature;
    }

    public void ImportScanLogs(IEnumerable<string> logDirectories)
    {
        foreach (var logDirectory in logDirectories.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(logDirectory))
            {
                continue;
            }

            // Newest first; only a bounded set is needed to seed the cache.
            foreach (var logPath in Directory.EnumerateFiles(logDirectory, "scan-log-*.csv")
                         .OrderByDescending(File.GetLastWriteTimeUtc)
                         .Take(14))
            {
                ImportScanLog(logPath);
            }
        }
    }

    /// <summary>True when this path is already known clean and unchanged on disk.</summary>
    public bool IsTrustedCleanPath(string path) =>
        !string.IsNullOrWhiteSpace(path) && TryGetUnchangedFile(path, out _, out _);

    /// <summary>
    /// The cached hash when the path is unchanged on disk, even if the clean provider entry
    /// has aged out. A delta scan can reuse this hash to skip re-hashing; the caller re-queries
    /// providers unless the entry is still reusable (see <see cref="IsReusableCleanEntry"/>).
    /// </summary>
    public bool TryGetKnownHash(string path, out string sha256)
    {
        sha256 = "";
        if (string.IsNullOrWhiteSpace(path)
            || !fileStates.TryGetValue(path, out var fileState)
            || string.IsNullOrWhiteSpace(fileState.Sha256))
        {
            return false;
        }

        try
        {
            var info = new FileInfo(path);
            if (!info.Exists
                || info.Length != fileState.Length
                || info.LastWriteTimeUtc != fileState.LastWriteTimeUtc)
            {
                return false;
            }

            sha256 = fileState.Sha256;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildScanLogSignature(IEnumerable<string> logDirectories)
    {
        var parts = new List<string>();
        foreach (var logDirectory in logDirectories)
        {
            if (!Directory.Exists(logDirectory))
            {
                continue;
            }

            foreach (var logPath in Directory.EnumerateFiles(logDirectory, "scan-log-*.csv")
                         .OrderByDescending(File.GetLastWriteTimeUtc)
                         .Take(14))
            {
                try
                {
                    var info = new FileInfo(logPath);
                    parts.Add($"{logPath}|{info.Length}|{info.LastWriteTimeUtc.Ticks}");
                }
                catch
                {
                    parts.Add(logPath);
                }
            }
        }

        return string.Join(";", parts);
    }

    private void ImportScanLog(string logPath)
    {
        try
        {
            var lines = File.ReadLines(logPath).ToList();
            if (lines.Count < 2)
            {
                return;
            }

            var headers = HashGuardLogic.ParseCsvLine(lines[0]);
            var columns = headers
                .Select((name, index) => new { Name = name.Trim(), Index = index })
                .ToDictionary(item => item.Name, item => item.Index, StringComparer.OrdinalIgnoreCase);

            foreach (var line in lines.Skip(1))
            {
                ImportScanLogRow(HashGuardLogic.ParseCsvLine(line), columns, File.GetLastWriteTimeUtc(logPath));
            }
        }
        catch
        {
            // Old or manually edited logs should not block new scans.
        }
    }

    private void ImportScanLogRow(List<string> row, Dictionary<string, int> columns, DateTime checkedAtUtc)
    {
        var sha256 = GetCsvValue(row, columns, "sha256");
        if (sha256.Length != 64)
        {
            return;
        }

        // The row's own time (local "yyyy-MM-dd HH:mm:ss"), else the log file's time.
        if (DateTime.TryParseExact(GetCsvValue(row, columns, "timestamp_computer_time"), "yyyy-MM-dd HH:mm:ss",
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeLocal, out var rowTime))
        {
            checkedAtUtc = rowTime.ToUniversalTime();
        }

        if (IsForgotten(sha256, checkedAtUtc))
        {
            return;
        }

        var status = NormalizeCachedStatus(GetCsvValue(row, columns, "status"));
        if (string.IsNullOrWhiteSpace(status) || string.Equals(status, "error", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var entry = new CacheEntry
        {
            Status = status,
            Malicious = GetCsvInt(row, columns, "malicious"),
            Suspicious = GetCsvInt(row, columns, "suspicious"),
            Harmless = GetCsvInt(row, columns, "harmless"),
            Undetected = GetCsvInt(row, columns, "undetected"),
            Link = GetCsvValue(row, columns, "link"),
            Notes = GetCsvValue(row, columns, "notes"),
            CheckedAtUtc = new DateTimeOffset(DateTime.SpecifyKind(checkedAtUtc, DateTimeKind.Utc)),
            Path = GetCsvValue(row, columns, "path"),
        };

        MergeEntry(sha256, entry, entry.CheckedAtUtc);
        SetFileStateFromLog(GetCsvValue(row, columns, "path"), sha256, entry);
    }

    private static string GetCsvValue(List<string> row, Dictionary<string, int> columns, string columnName) =>
        columns.TryGetValue(columnName, out var index) && index >= 0 && index < row.Count
            ? row[index]
            : "";

    private static int GetCsvInt(List<string> row, Dictionary<string, int> columns, string columnName) =>
        int.TryParse(GetCsvValue(row, columns, columnName), out var value) ? value : 0;

    public static bool IsCleanEntry(CacheEntry entry) =>
        (string.Equals(entry.Status, "clean", StringComparison.OrdinalIgnoreCase)
            || string.Equals(entry.Status, "clean/seen", StringComparison.OrdinalIgnoreCase))
        && entry.Malicious == 0
        && entry.Suspicious == 0;

    public static bool IsReusableCleanEntry(CacheEntry entry) =>
        IsCleanEntry(entry)
        && entry.CheckedAtUtc != default
        && DateTimeOffset.UtcNow - entry.CheckedAtUtc <= AppConstants.CleanCacheMaxAge;

    public static bool IsReusablePendingEntry(CacheEntry entry, bool uploadUnknownEnabled = false) =>
        HashGuardLogic.CanReuseProviderCache(
            entry.Status,
            entry.VirusTotalDeferred,
            entry.CheckedAtUtc,
            DateTimeOffset.UtcNow,
            uploadUnknownEnabled);

    private static string NormalizeCachedStatus(string status) =>
        string.Equals(status, "clean/seen", StringComparison.OrdinalIgnoreCase) ? "clean" : status;

    public async Task SaveAsync()
    {
        await saveGate.WaitAsync();
        try
        {
            // Snapshot first: other lookups keep adding entries while the write awaits.
            var entriesSnapshot = new Dictionary<string, CacheEntry>(entries, StringComparer.OrdinalIgnoreCase);
            var fileStatesSnapshot = new Dictionary<string, FileStateEntry>(fileStates, StringComparer.OrdinalIgnoreCase);
            var mutationsAtSnapshot = unsavedMutations;

            await WriteJsonAtomicAsync(AppPaths.GetHashCachePath(), entriesSnapshot);
            await WriteJsonAtomicAsync(AppPaths.GetFileStateCachePath(), fileStatesSnapshot);
            await WriteJsonAtomicAsync(GetForgottenPath(), new ForgottenFile { ClearedAtUtc = clearedAtUtc, Hashes = new Dictionary<string, DateTime>(forgottenAtUtc) });

            // Changes made during the write are not on disk yet; leave them dirty.
            unsavedMutations = Math.Max(0, unsavedMutations - mutationsAtSnapshot);
            dirty = unsavedMutations > 0;
            lastSaveUtc = DateTimeOffset.UtcNow;
        }
        finally
        {
            saveGate.Release();
        }
    }

    private static async Task WriteJsonAtomicAsync<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tempPath = path + ".tmp";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, value, new JsonSerializerOptions { WriteIndented = true });
        }

        // Replace in one step so a crash or full disk cannot leave a truncated cache that the
        // next launch would parse as empty (silently losing every cached clean result).
        File.Move(tempPath, path, overwrite: true);
    }

    /// <summary>
    /// Drops file-state rows whose file no longer exists (temp files, uninstalled apps) so the
    /// path-keyed cache does not grow without bound across reboots.
    /// </summary>
    private void PruneMissingFileStates()
    {
        if (fileStates.Count == 0)
        {
            return;
        }

        foreach (var path in fileStates.Keys.ToList())
        {
            try
            {
                if (!File.Exists(path))
                {
                    fileStates.TryRemove(path, out _);
                    MarkDirty();
                }
            }
            catch
            {
                // Unreadable paths stay; they can be pruned on a later run.
            }
        }
    }

    public async Task SaveIfDirtyAsync()
    {
        if (!dirty)
        {
            return;
        }

        await SaveAsync();
    }

    public async Task FlushIfDueAsync(bool force = false)
    {
        if (!dirty)
        {
            return;
        }

        if (!force && !IsFlushDue(dirty, unsavedMutations, lastSaveUtc, DateTimeOffset.UtcNow))
        {
            return;
        }

        await SaveAsync();
    }

    private async Task LoadFileStatesAsync()
    {
        var path = AppPaths.GetFileStateCachePath();
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            await using var stream = File.OpenRead(path);
            var loaded = await JsonSerializer.DeserializeAsync<Dictionary<string, FileStateEntry>>(stream);
            if (loaded is null)
            {
                return;
            }

            foreach (var item in loaded)
            {
                if (!string.IsNullOrWhiteSpace(item.Value.Sha256))
                {
                    fileStates[item.Key] = item.Value;
                }
            }

            PruneMissingFileStates();
        }
        catch
        {
            // Ignore stale or malformed file state cache data.
        }
    }

    private static IEnumerable<string> GetCachePaths()
    {
        // Only files HashGuard itself writes are cache candidates. The previous version
        // enumerated every *.json in the config folder, so settings.json, ignored-hashes.json
        // and quarantine-manifest.json were all fed to the cache deserializer; a future file
        // shaped like the cache would silently seed bogus entries.
        yield return AppPaths.GetHashCachePath();
        yield return Path.Combine(AppPaths.GetConfigDirectory(), "cache.json");
        yield return Path.Combine(AppPaths.AppFolder, "hash-cache.json");
    }

    private async Task LoadFromPathAsync(string cachePath)
    {
        if (!File.Exists(cachePath))
        {
            return;
        }

        try
        {
            await using var stream = File.OpenRead(cachePath);
            var loaded = await JsonSerializer.DeserializeAsync<Dictionary<string, CacheEntry>>(stream);
            if (loaded is null)
            {
                return;
            }

            var fileTime = new DateTimeOffset(File.GetLastWriteTimeUtc(cachePath), TimeSpan.Zero);
            foreach (var item in loaded)
            {
                MergeEntry(item.Key, item.Value, fileTime);
            }
        }
        catch
        {
            // Non-cache JSON files may live in config; ignore anything that is not a cache.
        }
    }

    private void MergeEntry(string sha256, CacheEntry entry, DateTimeOffset fallbackCheckedAtUtc)
    {
        entry.Status = NormalizeCachedStatus(entry.Status);
        if (sha256.Length != 64 || string.IsNullOrWhiteSpace(entry.Status))
        {
            return;
        }

        if (entry.CheckedAtUtc == default)
        {
            entry.CheckedAtUtc = fallbackCheckedAtUtc;
        }

        if (!entries.TryGetValue(sha256, out var existing) || entry.CheckedAtUtc > existing.CheckedAtUtc)
        {
            if (string.IsNullOrEmpty(entry.Path) && existing is not null)
            {
                entry.Path = existing.Path;
            }

            entries[sha256] = entry;
        }
        else if (string.IsNullOrEmpty(existing.Path) && !string.IsNullOrEmpty(entry.Path))
        {
            existing.Path = entry.Path;
        }
    }

    private void SetFileStateFromLog(string path, string sha256, CacheEntry entry)
    {
        if (string.IsNullOrWhiteSpace(path) || !IsCleanEntry(entry))
        {
            return;
        }

        try
        {
            var fullPath = Path.GetFullPath(path);
            var info = new FileInfo(fullPath);
            if (!info.Exists)
            {
                return;
            }

            fileStates[fullPath] = new FileStateEntry
            {
                Sha256 = sha256,
                Length = info.Length,
                LastWriteTimeUtc = info.LastWriteTimeUtc,
            };
        }
        catch
        {
            // Log path metadata is best-effort.
        }
    }
}
