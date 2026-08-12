namespace HashGuardScanner;

/// <summary>Local storage paths under the user config directory.</summary>
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

    public static string GetConfigDirectory()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            localAppData = AppContext.BaseDirectory;
        }

        return Path.Combine(localAppData, "HashGuard", ConfigFolderName);
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

    public static string GetLogDirectory()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            localAppData = AppContext.BaseDirectory;
        }

        return Path.Combine(localAppData, "HashGuard", "logs");
    }

    public static IEnumerable<string> GetLogDirectories()
    {
        yield return GetLogDirectory();
        yield return Path.Combine(AppContext.BaseDirectory, "logs");
    }
}
