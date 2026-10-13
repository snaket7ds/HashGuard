namespace HashGuardScanner;

/// <summary>
/// Local storage paths. Primary location matches v1.0.50 and earlier:
/// <c>{app folder}/config</c> and <c>{app folder}/logs</c> next to HashGuard.exe.
/// When the app folder is read-only (for example under Program Files without elevation),
/// config and logs move to <c>%LocalAppData%\HashGuardUserData</c> instead; see
/// <see cref="UsingFallbackStorage"/>.
/// </summary>
internal static class AppPaths
{
    /// <summary>
    /// Not <c>%LocalAppData%\HashGuard</c>: that is the v1.0.51 bug folder, which the legacy
    /// migration below deletes.
    /// </summary>
    public const string FallbackFolderName = "HashGuardUserData";

    private static readonly Lazy<StorageRoot> Root = new(ResolveStorageRoot);

    /// <summary>True when the app folder could not be written and storage moved to LocalAppData.</summary>
    public static bool UsingFallbackStorage => Root.Value.UsingFallback;

    /// <summary>Folder that holds <c>config</c> and <c>logs</c> (the app folder, or the fallback).</summary>
    public static string GetConfigRoot() => Root.Value.Path;

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
        if (UsingFallbackStorage)
        {
            return Path.Combine(GetConfigRoot(), ConfigFolderName);
        }

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

    public static string GetLogDirectory() => Path.Combine(GetConfigRoot(), "logs");

    /// <summary>Log folders to read from. In fallback mode, older logs next to the app are still read.</summary>
    public static IEnumerable<string> GetLogDirectories()
    {
        yield return GetLogDirectory();
        if (UsingFallbackStorage)
        {
            yield return Path.Combine(AppContext.BaseDirectory, "logs");
        }
    }

    private sealed record StorageRoot(string Path, bool UsingFallback);

    private static StorageRoot ResolveStorageRoot()
    {
        var appRoot = AppContext.BaseDirectory;
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var (path, usingFallback) = ChooseStorageRoot(appRoot, localAppData, IsDirectoryWritable);
        if (usingFallback)
        {
            SeedFallbackConfig(Path.Combine(appRoot, ConfigFolderName), Path.Combine(path, ConfigFolderName));
        }

        return new StorageRoot(path, usingFallback);
    }

    /// <summary>
    /// Uses the app folder when its <c>config</c> folder can be written, otherwise the per-user
    /// fallback. With no LocalAppData either, stays on the app folder (saves will report errors).
    /// </summary>
    internal static (string Path, bool UsingFallback) ChooseStorageRoot(
        string appRoot,
        string? localAppData,
        Func<string, bool> isWritable)
    {
        if (isWritable(Path.Combine(appRoot, ConfigFolderName)) || string.IsNullOrWhiteSpace(localAppData))
        {
            return (appRoot, false);
        }

        return (Path.Combine(localAppData, FallbackFolderName), true);
    }

    /// <summary>Creates the folder if needed and writes then deletes a probe file.</summary>
    internal static bool IsDirectoryWritable(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probe = Path.Combine(directory, $".write-test-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// First switch to the fallback: copy the existing settings, ignore lists and caches so the
    /// user keeps them. Files already in the fallback win. The quarantine manifest is not copied,
    /// because the quarantined files it points to stay in the app folder.
    /// </summary>
    internal static void SeedFallbackConfig(string appConfig, string fallbackConfig)
    {
        try
        {
            if (!Directory.Exists(appConfig))
            {
                return;
            }

            Directory.CreateDirectory(fallbackConfig);
            foreach (var file in Directory.EnumerateFiles(appConfig, "*.json"))
            {
                var name = Path.GetFileName(file);
                if (string.Equals(name, QuarantineManifestFileName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var dest = Path.Combine(fallbackConfig, name);
                if (!File.Exists(dest))
                {
                    File.Copy(file, dest);
                }
            }
        }
        catch
        {
            // Seeding is best-effort; the app starts with defaults for anything not copied.
        }
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
