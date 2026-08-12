namespace HashGuardScanner;

/// <summary>Shared provider URLs, cache ages, and app identity constants.</summary>
internal static class AppConstants
{
    public const string GitHubOwner = "snaket7ds";
    public const string GitHubRepo = "HashGuard";
    public const string TelemetryEndpointUrl = "https://damp-cloud-4908.rod-81a.workers.dev/events";

    public const string VirusTotalFileReportUrl = "https://www.virustotal.com/api/v3/files/{0}";
    public const string VirusTotalFileUploadUrl = "https://www.virustotal.com/api/v3/files";
    public const string VirusTotalLargeFileUploadUrl = "https://www.virustotal.com/api/v3/files/upload_url";
    public const string VirusTotalAnalysisUrl = "https://www.virustotal.com/api/v3/analyses/{0}";
    public const string VirusTotalGuiReportUrl = "https://www.virustotal.com/gui/file/{0}";
    public const string MetaDefenderReportUrl = "https://metadefender.com/results/hash/{0}";
    public const string MetaDefenderHashUrl = "https://api.metadefender.com/v4/hash/{0}";
    public const string CymruDnsQueryUrl = "https://dns.google/resolve?name={0}&type=TXT";

    public const long RegularUploadLimitBytes = 32L * 1024L * 1024L;

    public static readonly TimeSpan CleanCacheMaxAge = TimeSpan.FromDays(7);
    public static readonly TimeSpan UnknownCacheMaxAge = TimeSpan.FromHours(12);
    public static readonly TimeSpan ErrorCacheMaxAge = TimeSpan.FromHours(1);
    public static readonly TimeSpan DeferredCacheMaxAge = TimeSpan.FromMinutes(30);

    public const string ColorModeSystem = "system";
    public const string ColorModeLight = "light";
    public const string ColorModeDark = "dark";

    public static string GetCurrentVersion()
    {
        var version = typeof(AppConstants).Assembly.GetName().Version;
        return version is null ? "1.0.0" : $"{version.Major}.{version.Minor}.{version.Build}";
    }
}
