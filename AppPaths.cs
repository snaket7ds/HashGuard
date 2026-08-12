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

    private static bool migrationAttempted;

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
        // v1.0.51 briefly wrote logs under LocalAppData; keep them discoverable for cache import.
        var legacyLogs = GetLegacyLocalAppDataLogsDirectory();
        if (!string.IsNullOrWhiteSpace(legacyLogs))
        {
            yield return legacyLogs;
        }
    }

    /// <summary>
    /// v1.0.51 incorrectly stored data under %LocalAppData%\HashGuard\config.
    /// If the app-local config is empty/missing but legacy LocalAppData has settings,
    /// copy that data back next to the EXE so keys and preferences return.
    /// </summary>
    private static void EnsureLegacyLocalAppDataMigration()
    {
        if (migrationAttempted)
        {
            return;
        }

        migrationAttempted = true;

        try
        {
            var primaryConfig = Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
            var primarySettings = Path.Combine(primaryConfig, AppSettingsFileName);
            var legacyConfig = GetLegacyLocalAppDataConfigDirectory();
            if (string.IsNullOrWhiteSpace(legacyConfig) || !Directory.Exists(legacyConfig))
            {
                return;
            }

            var legacySettings = Path.Combine(legacyConfig, AppSettingsFileName);
            var primaryMissingOrEmpty = !File.Exists(primarySettings) || new FileInfo(primarySettings).Length == 0;
            var legacyHasSettings = File.Exists(legacySettings) && new FileInfo(legacySettings).Length > 0;

            // Prefer existing next-to-EXE settings (true 1.0.50 data). Only pull from LocalAppData when primary is empty.
            if (!primaryMissingOrEmpty || !legacyHasSettings)
            {
                // If primary is missing but legacy exists, still migrate; handled above.
                // If primary already has settings, leave it alone.
                if (File.Exists(primarySettings) && new FileInfo(primarySettings).Length > 0)
                {
                    return;
                }

                if (!legacyHasSettings)
                {
                    return;
                }
            }

            Directory.CreateDirectory(primaryConfig);
            foreach (var sourcePath in Directory.EnumerateFiles(legacyConfig, "*", SearchOption.TopDirectoryOnly))
            {
                var name = Path.GetFileName(sourcePath);
                var destPath = Path.Combine(primaryConfig, name);
                if (!File.Exists(destPath) || new FileInfo(destPath).Length == 0)
                {
                    File.Copy(sourcePath, destPath, overwrite: true);
                }
            }

            var legacyQuarantine = Path.Combine(legacyConfig, QuarantineFolderName);
            var primaryQuarantine = Path.Combine(primaryConfig, QuarantineFolderName);
            if (Directory.Exists(legacyQuarantine))
            {
                CopyDirectoryIfMissing(legacyQuarantine, primaryQuarantine);
            }
        }
        catch
        {
            // Migration is best-effort; never block startup.
        }
    }

    private static string? GetLegacyLocalAppDataConfigDirectory()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            return null;
        }

        return Path.Combine(localAppData, "HashGuard", ConfigFolderName);
    }

    private static string? GetLegacyLocalAppDataLogsDirectory()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            return null;
        }

        return Path.Combine(localAppData, "HashGuard", "logs");
    }

    private static void CopyDirectoryIfMissing(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDir, file);
            var dest = Path.Combine(destDir, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            if (!File.Exists(dest))
            {
                File.Copy(file, dest, overwrite: false);
            }
        }
    }
}
