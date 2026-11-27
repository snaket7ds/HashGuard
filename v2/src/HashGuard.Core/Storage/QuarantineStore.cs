using System.Globalization;
using System.Text;
using System.Text.Json;

namespace HashGuard.Core;

/// <summary>
/// Files moved out of harm's way. Same layout as v1, so files quarantined by v1 can be restored
/// by v2: the file is moved to <c>config\quarantine\name.yyyyMMddHHmmss.quarantine</c>, listed in
/// <c>config\quarantine-manifest.json</c>, and every action is written to
/// <c>logs\quarantine-log-yyyyMMdd.csv</c>.
/// </summary>
public sealed class QuarantineStore(string? directory = null, string? manifestPath = null, string? logDirectory = null)
{
    private const string LogHeader = "timestamp_computer_time,action,source_path,target_path,details";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly Lock gate = new();
    private List<QuarantineEntry>? entries;

    private string Directory => directory ?? AppPaths.GetQuarantineDirectory();

    private string ManifestPath => manifestPath ?? AppPaths.GetQuarantineManifestPath();

    private string LogDirectory => logDirectory ?? AppPaths.GetLogDirectory();

    /// <summary>The clock, replaceable in tests.</summary>
    internal Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.Now;

    /// <summary>Raised (on the calling thread) after the list changes.</summary>
    public event Action? Changed;

    /// <summary>Everything in the manifest, newest first.</summary>
    public IReadOnlyList<QuarantineEntry> Entries
    {
        get
        {
            lock (gate)
            {
                return [.. Loaded().OrderByDescending(entry => entry.QuarantinedAtUtc)];
            }
        }
    }

    /// <summary>Entries whose quarantined file is still there and can be restored.</summary>
    public int RestorableCount
    {
        get
        {
            lock (gate)
            {
                return HashGuardLogic.CountRestorableQuarantineEntries(Loaded());
            }
        }
    }

    /// <summary>Re-reads the manifest on next use (after another process changed it).</summary>
    public void Reload()
    {
        lock (gate)
        {
            entries = null;
        }
    }

    /// <summary>
    /// Moves <paramref name="path"/> into quarantine. The caller stops a running copy first; a
    /// file that is still running or locked throws and stays where it was.
    /// </summary>
    public QuarantineEntry Quarantine(string path, string sha256, string notes)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("The file is no longer there.", path);
        }

        QuarantineEntry entry;
        lock (gate)
        {
            System.IO.Directory.CreateDirectory(Directory);
            var target = UniqueTarget(Path.GetFileName(path));
            try
            {
                File.Move(path, target);
            }
            catch (Exception ex)
            {
                AppendLog("quarantine-failed", path, "", ex.Message);
                throw;
            }

            entry = new QuarantineEntry
            {
                OriginalPath = path,
                QuarantinePath = target,
                Sha256 = sha256 ?? "",
                Notes = notes ?? "",
                QuarantinedAtUtc = Now().ToUniversalTime(),
            };
            Loaded().Add(entry);
            SaveLocked();
            AppendLog("quarantine", path, target, "moved to quarantine");
        }

        Changed?.Invoke();
        return entry;
    }

    /// <summary>
    /// Moves a quarantined file back to <paramref name="restorePath"/> after checking it is the
    /// same file that went in. An existing file there is replaced only when
    /// <paramref name="replaceExisting"/> is true.
    /// </summary>
    public async Task RestoreAsync(QuarantineEntry entry, string restorePath, bool replaceExisting, CancellationToken cancellationToken = default)
    {
        try
        {
            if (!File.Exists(entry.QuarantinePath))
            {
                throw new FileNotFoundException("The quarantined file is no longer there.", entry.QuarantinePath);
            }

            if (File.Exists(restorePath) && !replaceExisting)
            {
                throw new IOException($"A file already exists at {restorePath}.");
            }

            if (!string.IsNullOrWhiteSpace(entry.Sha256))
            {
                var hash = await FileHash.Sha256FileAsync(entry.QuarantinePath, cancellationToken).ConfigureAwait(false);
                if (!string.Equals(hash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("The quarantined file has changed since it was quarantined, so it was not restored.");
                }
            }

            var folder = Path.GetDirectoryName(restorePath);
            if (!string.IsNullOrWhiteSpace(folder))
            {
                System.IO.Directory.CreateDirectory(folder);
            }

            lock (gate)
            {
                File.Move(entry.QuarantinePath, restorePath, overwrite: replaceExisting);
                Loaded().RemoveAll(item => SameEntry(item, entry));
                SaveLocked();
                AppendLog("restore", entry.QuarantinePath, restorePath, "restored from quarantine");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AppendLog("restore-failed", entry.QuarantinePath, restorePath, ex.Message);
            throw;
        }

        Changed?.Invoke();
    }

    /// <summary>Deletes the quarantined file for good and drops it from the list.</summary>
    public void Delete(QuarantineEntry entry)
    {
        lock (gate)
        {
            try
            {
                if (File.Exists(entry.QuarantinePath))
                {
                    File.Delete(entry.QuarantinePath);
                }
            }
            catch (Exception ex)
            {
                AppendLog("delete-failed", entry.QuarantinePath, entry.OriginalPath, ex.Message);
                throw;
            }

            Loaded().RemoveAll(item => SameEntry(item, entry));
            SaveLocked();
            AppendLog("delete", entry.QuarantinePath, entry.OriginalPath, "deleted from quarantine");
        }

        Changed?.Invoke();
    }

    /// <summary>Drops entries whose quarantined file no longer exists; returns how many.</summary>
    public int RemoveMissing()
    {
        int removed;
        lock (gate)
        {
            var stale = Loaded().Where(entry => !HashGuardLogic.QuarantineEntryIsRestorable(entry)).ToList();
            if (stale.Count == 0)
            {
                return 0;
            }

            Loaded().RemoveAll(entry => stale.Contains(entry));
            SaveLocked();
            foreach (var entry in stale)
            {
                AppendLog("repair-missing", entry.QuarantinePath, entry.OriginalPath, "removed stale manifest entry");
            }

            removed = stale.Count;
        }

        Changed?.Invoke();
        return removed;
    }

    /// <summary>
    /// A free path on the Desktop for restoring <paramref name="entry"/> under its original name:
    /// "name.exe", then "name (1).exe" and so on.
    /// </summary>
    public static string DesktopRestorePath(QuarantineEntry entry, string? desktop = null)
    {
        desktop ??= Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktop))
        {
            desktop = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        var name = Path.GetFileName(entry.OriginalPath);
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(invalid, '_');
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = "HashGuard restored file";
        }

        var stem = Path.GetFileNameWithoutExtension(name);
        var extension = Path.GetExtension(name);
        var candidate = Path.Combine(desktop, name);
        for (var index = 1; File.Exists(candidate); index++)
        {
            candidate = Path.Combine(desktop, $"{stem} ({index}){extension}");
        }

        return candidate;
    }

    private string UniqueTarget(string fileName)
    {
        var stamp = Now().ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        var candidate = Path.Combine(Directory, $"{fileName}.{stamp}.quarantine");
        for (var index = 2; File.Exists(candidate); index++)
        {
            candidate = Path.Combine(Directory, $"{fileName}.{stamp}-{index}.quarantine");
        }

        return candidate;
    }

    private static bool SameEntry(QuarantineEntry a, QuarantineEntry b) =>
        string.Equals(a.QuarantinePath, b.QuarantinePath, StringComparison.OrdinalIgnoreCase);

    private List<QuarantineEntry> Loaded()
    {
        if (entries is not null)
        {
            return entries;
        }

        try
        {
            entries = File.Exists(ManifestPath)
                ? JsonSerializer.Deserialize<List<QuarantineEntry>>(File.ReadAllText(ManifestPath, Encoding.UTF8)) ?? []
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            entries = [];
        }

        return entries;
    }

    private void SaveLocked()
    {
        var folder = Path.GetDirectoryName(ManifestPath);
        if (!string.IsNullOrWhiteSpace(folder))
        {
            System.IO.Directory.CreateDirectory(folder);
        }

        var temp = ManifestPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(Loaded(), JsonOptions), Encoding.UTF8);
        File.Move(temp, ManifestPath, overwrite: true);
    }

    private void AppendLog(string action, string source, string target, string details)
    {
        try
        {
            System.IO.Directory.CreateDirectory(LogDirectory);
            var path = Path.Combine(LogDirectory, $"quarantine-log-{Now():yyyyMMdd}.csv");
            var writeHeader = !File.Exists(path);
            using var writer = new StreamWriter(path, append: true, Encoding.UTF8);
            if (writeHeader)
            {
                writer.WriteLine(LogHeader);
            }

            writer.WriteLine(string.Join(",", new[] { Now().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), action, source, target, details }.Select(Quote)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The log must never block the quarantine action itself.
        }
    }

    private static string Quote(string value) => $"\"{(value ?? "").Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
}
