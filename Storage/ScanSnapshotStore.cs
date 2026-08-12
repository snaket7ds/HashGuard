using System.Text.Json;

namespace HashGuardScanner;

/// <summary>Persists the last full-scan path/hash set for delta comparisons.</summary>
internal static class ScanSnapshotStore
{
    public static ScanSnapshot? Load()
    {
        try
        {
            var path = AppPaths.GetLastScanSnapshotPath();
            if (!File.Exists(path))
            {
                return null;
            }

            return JsonSerializer.Deserialize<ScanSnapshot>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static void Save(IEnumerable<ScanResult> results)
    {
        try
        {
            var snapshot = new ScanSnapshot
            {
                CapturedAtUtc = DateTimeOffset.UtcNow,
                Paths = results
                    .Select(result => result.Path)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                Sha256Hashes = results
                    .Select(result => result.Sha256)
                    .Where(hash => !string.IsNullOrWhiteSpace(hash) && hash.Length == 64)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(hash => hash, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
            };

            Directory.CreateDirectory(AppPaths.GetConfigDirectory());
            File.WriteAllText(
                AppPaths.GetLastScanSnapshotPath(),
                JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // Snapshot is best-effort UX; never block scans.
        }
    }

    public static void MarkNewSinceLastScan(IEnumerable<ScanResult> results, ScanSnapshot? previous)
    {
        if (previous is null)
        {
            foreach (var result in results)
            {
                result.IsNewSinceLastScan = false;
            }

            return;
        }

        var knownPaths = new HashSet<string>(previous.Paths, StringComparer.OrdinalIgnoreCase);
        var knownHashes = new HashSet<string>(previous.Sha256Hashes, StringComparer.OrdinalIgnoreCase);
        foreach (var result in results)
        {
            var pathNew = !string.IsNullOrWhiteSpace(result.Path) && !knownPaths.Contains(result.Path);
            var hashNew = !string.IsNullOrWhiteSpace(result.Sha256)
                && result.Sha256.Length == 64
                && !knownHashes.Contains(result.Sha256);
            result.IsNewSinceLastScan = pathNew || hashNew;
        }
    }
}
