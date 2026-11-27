namespace HashGuard.Core;

/// <summary>
/// Local storage paths. Primary location matches v1.0.50 and earlier:
/// <c>{app folder}/config</c> and <c>{app folder}/logs</c> next to HashGuard.exe.
/// When the app folder is read-only (for example under Program Files without elevation),
/// config and logs move to <c>%LocalAppData%\HashGuardUserData</c> instead; see
/// <see cref="UsingFallbackStorage"/>.
/// </summary>
public static class AppPaths
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
    public static string GetNetworkActionLogPath() => Path.Combine(GetLogDirectory(), "network-actions.log");

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

}
