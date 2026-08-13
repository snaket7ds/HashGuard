using System.Text.Json.Serialization;

namespace HashGuardScanner;

internal sealed record ProcessCollectionResult(Dictionary<string, List<ProcessFile>> Files, List<SkippedProcess> Skipped);
internal sealed record ProcessFile(int Pid, string Name, string Path);
internal sealed record SkippedProcess(int Pid, string Name, string Reason);
internal sealed record PersistenceTarget(string Path, string Source);
internal sealed record SignatureInfo(string Summary, string Publisher);
internal sealed record ProviderResult(string Provider, ProviderState State, string Detail);
internal readonly record struct ProcessFileState(long Length, DateTime LastWriteTimeUtc);
internal readonly record struct QuotaReservation(bool Available, string LimitName);
internal sealed record CymruReputation(DateTimeOffset LastSeenUtc, int DetectionPercent);
internal sealed record IgnoreTarget(string Kind, string Value);

internal enum TrayState
{
    Clean,
    Scanning,
    ActionNeeded,
}

internal sealed class CacheEntry
{
    public string Status { get; set; } = "";
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public string Link { get; set; } = "";
    public string Notes { get; set; } = "";
    public DateTimeOffset CheckedAtUtc { get; set; }
    public bool VirusTotalDeferred { get; set; }
    public bool NeedsVirusTotalUpload { get; set; }
}

internal sealed class FileStateEntry
{
    public string Sha256 { get; set; } = "";
    public long Length { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
}

internal sealed class QuotaState
{
    public string UtcDay { get; set; } = "";
    public int DailyCount { get; set; }
    public List<DateTimeOffset> MinuteRequestsUtc { get; set; } = [];
}

internal sealed class GitHubRelease
{
    [JsonPropertyName("tag_name")]
    public string TagName { get; set; } = "";

    [JsonPropertyName("body")]
    public string Body { get; set; } = "";

    [JsonPropertyName("draft")]
    public bool Draft { get; set; }

    [JsonPropertyName("assets")]
    public List<GitHubAsset> Assets { get; set; } = [];
}

internal sealed class GitHubAsset
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("browser_download_url")]
    public string BrowserDownloadUrl { get; set; } = "";

    [JsonPropertyName("digest")]
    public string Digest { get; set; } = "";
}

internal sealed class QuarantineEntry
{
    public string OriginalPath { get; set; } = "";
    public string QuarantinePath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Notes { get; set; } = "";
    public DateTimeOffset QuarantinedAtUtc { get; set; }
}

internal sealed class ScanResult(string path, string processNames, string pids)
{
    public string Path { get; } = path;
    public string ProcessNames { get; } = processNames;
    public string Pids { get; } = pids;
    public string Sha256 { get; set; } = "";
    public string Status { get; set; } = "";
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public string Link { get; set; } = "";
    public string Notes { get; set; } = "";
    public List<ProviderResult> ProviderResults { get; } = [];
    public string ProviderSummary => ProviderResults.Count == 0
        ? ""
        : string.Join(" | ", ProviderResults.Select(result => $"{result.Provider}: {result.State}{(string.IsNullOrWhiteSpace(result.Detail) ? "" : $" ({result.Detail})")}"));
    public int RiskScore { get; set; }
    public string RiskLevel { get; set; } = "Low";
    public string TrustSummary { get; set; } = "";
    public string SignatureSummary { get; set; } = "";
    public string SignaturePublisher { get; set; } = "";
    public long FileSizeBytes { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
    public double FileAgeDays { get; set; } = -1;
    public List<string> PersistenceSources { get; set; } = [];
    public bool VirusTotalDeferred { get; set; }
    public bool NeedsVirusTotalUpload { get; set; }
    public string StatusBeforeIgnore { get; set; } = "";
    public bool IsNewSinceLastScan { get; set; }
    public bool IsDetection => Malicious > 0 || Suspicious > 0;
    public bool IsAlert => IsDetection && !string.Equals(Status, "ignored", StringComparison.OrdinalIgnoreCase);

    public void ApplyCache(CacheEntry entry, string prefix = "Cached")
    {
        Status = entry.Status;
        Malicious = entry.Malicious;
        Suspicious = entry.Suspicious;
        Harmless = entry.Harmless;
        Undetected = entry.Undetected;
        Link = entry.Link;
        VirusTotalDeferred = entry.VirusTotalDeferred;
        NeedsVirusTotalUpload = entry.NeedsVirusTotalUpload;
        Notes = $"{prefix} {entry.CheckedAtUtc.LocalDateTime:g}";
        if (!string.IsNullOrWhiteSpace(entry.Notes))
        {
            Notes += $"; {entry.Notes}";
        }
    }
}

internal sealed class ScanSnapshot
{
    public DateTimeOffset CapturedAtUtc { get; set; }
    public List<string> Paths { get; set; } = [];
    public List<string> Sha256Hashes { get; set; } = [];
}

internal sealed class AppSettings
{
    public bool FreeApiLimits { get; set; } = true;
    public bool VirusTotalEnabled { get; set; } = true;
    public bool MetaDefenderEnabled { get; set; } = true;
    public bool MhrEnabled { get; set; } = true;
    public bool HashCacheEnabled { get; set; } = true;
    public bool UploadUnknown { get; set; }
    /// <summary>User accepted the VirusTotal full-file upload warning.</summary>
    public bool UploadUnknownAcknowledged { get; set; }
    /// <summary>User accepted the open/selected file scanning warning.</summary>
    public bool ScanAllFilesAcknowledged { get; set; }
    public bool StartMinimized { get; set; }
    public bool AutoProcessScan { get; set; } = true;
    public bool RunElevated { get; set; }
    public bool ScanAllFiles { get; set; }
    public bool AutoUpdateChecks { get; set; }
    public bool TelemetryEnabled { get; set; }
    public string AnonymousInstallId { get; set; } = "";
    public bool AppInstallReported { get; set; }
    public bool UseSystemDefaultColors { get; set; }
    public string ColorMode { get; set; } = AppConstants.ColorModeLight;
    public bool FirstRunSetupShown { get; set; }
    public int DelaySeconds { get; set; } = 16;
    public int TimeoutSeconds { get; set; } = 60;
    public string ApiKeyEncrypted { get; set; } = "";
    public string MetaDefenderApiKeyEncrypted { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string MetaDefenderApiKey { get; set; } = "";
    /// <summary>When true, register a daily scheduled full scan via Task Scheduler.</summary>
    public bool ScheduledDailyScan { get; set; }
    /// <summary>Local hour (0-23) for the daily scheduled scan.</summary>
    public int ScheduledScanHour { get; set; } = 2;
    /// <summary>When true, full scans only re-check files not present in the previous snapshot (still rechecks detections/unknown).</summary>
    public bool PreferDeltaScan { get; set; }
    /// <summary>Suppress repeated tray balloons for the same action-needed hash until the hash set changes.</summary>
    public bool SuppressRepeatTrayAlerts { get; set; } = true;
    public string LastTrayAlertSignature { get; set; } = "";
    public List<string> TrustedPublishers { get; set; } =
    [
        "Microsoft Corporation",
        "Microsoft Windows",
        "NVIDIA Corporation",
        "Advanced Micro Devices",
        "Intel Corporation",
        "Dell Inc.",
        "HP Inc.",
        "Lenovo",
    ];
}
