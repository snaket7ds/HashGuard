namespace HashGuardScanner;

/// <summary>
/// Local storage paths. Primary location matches v1.0.50 and earlier:
/// <c>{app folder}/config</c> and <c>{app folder}/logs</c> next to HashGuard.exe.
/// </summary>
internal static class AppPaths
{
    public const string ConfigFolderName = "config";
    public const string AppSettingsFileName = "settings.json";
    public const string IgnoredHashesFileName = "ignored-hashes.json";
    public const string IgnoredPathsFileName = "ignored-paths.json";
    public const string QuarantineFolderName = "quarantine";
    public const string QuarantineManifestFileName = "quarantine-manifest.json";
    public const string LastScanSnapshotFileName = "last-scan-snapshot.json";
    public const string ScanPipeName = "HashGuard.ScanRequest";

    /// <summary>
    /// App-local config directory (same as v1.0.50): next to the executable.
    /// </summary>
    public static string GetConfigDirectory()
    {
        EnsureLegacyLocalAppDataMigration();
        return Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
    }

    public static string GetAppSettingsPath() => Path.Combine(GetConfigDirectory(), AppSettingsFileName);
    public static string GetIgnoredHashesPath() => Path.Combine(GetConfigDirectory(), IgnoredHashesFileName);
    public static string GetIgnoredPathsPath() => Path.Combine(GetConfigDirectory(), IgnoredPathsFileName);
    public static string GetQuarantineDirectory() => Path.Combine(GetConfigDirectory(), QuarantineFolderName);
    public static string GetQuarantineManifestPath() => Path.Combine(GetConfigDirectory(), QuarantineManifestFileName);
    public static string GetLastScanSnapshotPath() => Path.Combine(GetConfigDirectory(), LastScanSnapshotFileName);
    public static string GetHashCachePath() => Path.Combine(GetConfigDirectory(), "hash-cache.json");
    public static string GetFileStateCachePath() => Path.Combine(GetConfigDirectory(), "file-state-cache.json");
    public static string GetQuotaPath() => Path.Combine(GetConfigDirectory(), "free-api-quota.json");

    public static string GetLogDirectory() => Path.Combine(AppContext.BaseDirectory, "logs");

    public static IEnumerable<string> GetLogDirectories()
    {
        yield return GetLogDirectory();
    }

    /// <summary>
    /// v1.0.51 incorrectly stored data under %LocalAppData%\HashGuard\.
    /// Merge any useful files into the app-local config/logs, then delete that
    /// leftover LocalAppData tree so the bug does not leave orphaned files behind.
    /// </summary>
    private static void EnsureLegacyLocalAppDataMigration()
    {
        try
        {
            var legacyRoot = GetLegacyLocalAppDataRoot();
            if (string.IsNullOrWhiteSpace(legacyRoot) || !Directory.Exists(legacyRoot))
            {
                return;
            }

            var primaryConfig = Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
            var primaryLogs = Path.Combine(AppContext.BaseDirectory, "logs");
            var legacyConfig = Path.Combine(legacyRoot, ConfigFolderName);
            var legacyLogs = Path.Combine(legacyRoot, "logs");

            if (Directory.Exists(legacyConfig))
            {
                MergeDirectory(legacyConfig, primaryConfig);
            }

            if (Directory.Exists(legacyLogs))
            {
                MergeDirectory(legacyLogs, primaryLogs);
            }

            // Remove the entire mistaken LocalAppData\HashGuard tree after merge.
            // Retries on later launches if a file was locked the first time.
            TryDeleteDirectory(legacyRoot);
        }
        catch
        {
            // Migration/cleanup is best-effort; never block startup.
        }
    }

    private static string? GetLegacyLocalAppDataRoot()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            return null;
        }

        return Path.Combine(localAppData, "HashGuard");
    }

    private static void MergeDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDir, file);
            var dest = Path.Combine(destDir, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            // Prefer existing app-local files (true pre-1.0.51 data). Only fill gaps from the bug path.
            if (!File.Exists(dest) || new FileInfo(dest).Length == 0)
            {
                File.Copy(file, dest, overwrite: true);
            }
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // Files may be locked; leftover cleanup can retry on next launch.
        }
    }
}
