using System.Diagnostics;
using System.Text.Json;

namespace HashGuardScanner;

internal sealed class HashCache
{
    private readonly Dictionary<string, CacheEntry> entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FileStateEntry> fileStates = new(StringComparer.OrdinalIgnoreCase);
    private bool loaded;
    private bool dirty;
    private int unsavedMutations;
    private DateTimeOffset lastSaveUtc = DateTimeOffset.MinValue;
    private string scanLogImportSignature = "";

    public const int FlushEveryMutations = 25;
    public static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(5);

    public int Count => entries.Count;
    public bool IsLoaded => loaded;
    public bool IsDirty => dirty;

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

    public void SetFileState(ScanResult result)
    {
        if (string.IsNullOrWhiteSpace(result.Sha256) || !entries.TryGetValue(result.Sha256, out var entry) || !IsReusableCleanEntry(entry))
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
        Directory.CreateDirectory(Path.GetDirectoryName(AppPaths.GetHashCachePath())!);
        await using var stream = File.Create(AppPaths.GetHashCachePath());
        await JsonSerializer.SerializeAsync(stream, entries, new JsonSerializerOptions { WriteIndented = true });

        await using var fileStateStream = File.Create(AppPaths.GetFileStateCachePath());
        await JsonSerializer.SerializeAsync(fileStateStream, fileStates, new JsonSerializerOptions { WriteIndented = true });

        dirty = false;
        unsavedMutations = 0;
        lastSaveUtc = DateTimeOffset.UtcNow;
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
        }
        catch
        {
            // Ignore stale or malformed file state cache data.
        }
    }

    private static IEnumerable<string> GetCachePaths()
    {
        yield return AppPaths.GetHashCachePath();
        yield return Path.Combine(AppPaths.GetConfigDirectory(), "cache.json");
        yield return Path.Combine(AppContext.BaseDirectory, "hash-cache.json");

        if (!Directory.Exists(AppPaths.GetConfigDirectory()))
        {
            yield break;
        }

        foreach (var path in Directory.EnumerateFiles(AppPaths.GetConfigDirectory(), "*.json"))
        {
            yield return path;
        }
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
            entries[sha256] = entry;
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
