using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.App.Services;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

public sealed record SourceChip(string Name, bool IsOn)
{
    public string Text => IsOn ? Name : $"{Name} · off";
}

/// <summary>
/// The Scan page: choose what to scan, run it with live progress, and handle the files that need
/// a decision. Lives on the UI thread; the scan itself runs in <see cref="ScanService"/>.
/// </summary>
public sealed partial class ScanViewModel : ObservableObject
{
    private CancellationTokenSource? cancellation;
    private IReadOnlyList<string> chosenFiles = [];

    [ObservableProperty] public partial bool ScanFilesMode { get; set; }
    [ObservableProperty] public partial bool IsScanning { get; set; }
    [ObservableProperty] public partial double ProgressValue { get; set; }
    [ObservableProperty] public partial double ProgressMax { get; set; } = 1;
    [ObservableProperty] public partial bool ProgressIndeterminate { get; set; }
    [ObservableProperty] public partial string ProgressText { get; set; } = "";
    [ObservableProperty] public partial string SummaryText { get; set; } = "";
    [ObservableProperty] public partial string ChosenFilesText { get; set; } = "No files chosen";
    [ObservableProperty] public partial string DecisionCount { get; set; } = "0";
    [ObservableProperty] public partial bool HasFindings { get; set; }
    [ObservableProperty] public partial IReadOnlyList<SourceChip> Sources { get; set; } = [];

    public ObservableCollection<FindingViewModel> Findings { get; } = [];

    public string ScanButtonText => IsScanning ? "Stop" : "Scan";

    public string ScanButtonGlyph => IsScanning ? "" : "";

    public bool CanStart => !ScanFilesMode || chosenFiles.Count > 0;

    /// <summary>Shown when a source is switched on without its key.</summary>
    public string? KeyWarning
    {
        get
        {
            var services = AppServices.Instance;
            if (services is null)
            {
                return null;
            }

            var missing = new List<string>();
            if (services.Settings.VirusTotalEnabled && services.Keys.VirusTotal.Length == 0)
            {
                missing.Add("VirusTotal");
            }

            if (ScanRules.MetaDefenderKeyMissing(services.Settings, services.Keys))
            {
                missing.Add("MetaDefender");
            }

            return missing.Count == 0 ? null : $"{string.Join(" and ", missing)} {(missing.Count == 1 ? "is" : "are")} on but has no API key, so {(missing.Count == 1 ? "it" : "they")} will be skipped. Add keys in Settings → Reputation.";
        }
    }

    public void Load()
    {
        var services = AppServices.Instance;
        var s = services.Settings;
        var k = services.Keys;
        Sources =
        [
            new("VirusTotal", s.VirusTotalEnabled && k.VirusTotal.Length > 0),
            new("MetaDefender", s.MetaDefenderEnabled && k.MetaDefender.Length > 0),
            new("Team Cymru", s.MhrEnabled),
        ];
        OnPropertyChanged(nameof(KeyWarning));
        if (services.LastOutcome is { } last && Findings.Count == 0 && !IsScanning)
        {
            ShowOutcome(last);
        }
    }

    public void SetChosenFiles(IReadOnlyList<string> paths)
    {
        chosenFiles = paths;
        ChosenFilesText = paths.Count switch
        {
            0 => "No files chosen",
            1 => System.IO.Path.GetFileName(paths[0]),
            _ => $"{paths.Count} files chosen",
        };
        ScanFilesMode = true;
        OnPropertyChanged(nameof(CanStart));
    }

    partial void OnScanFilesModeChanged(bool value) => OnPropertyChanged(nameof(CanStart));

    partial void OnIsScanningChanged(bool value)
    {
        OnPropertyChanged(nameof(ScanButtonText));
        OnPropertyChanged(nameof(ScanButtonGlyph));
    }

    /// <summary>Starts a scan, or stops the running one.</summary>
    public async Task ScanOrStopAsync()
    {
        if (IsScanning)
        {
            cancellation?.Cancel();
            ProgressText = "Stopping…";
            return;
        }

        var services = AppServices.Instance;
        using var cts = new CancellationTokenSource();
        cancellation = cts;
        IsScanning = true;
        ProgressIndeterminate = true;
        ProgressValue = 0;
        SummaryText = "";
        ProgressText = ScanFilesMode ? "Starting…" : "Collecting running apps and start-up items…";
        Findings.Clear();
        UpdateCounts();

        var progress = new Progress<ScanProgress>(OnProgress);
        var kind = ScanFilesMode ? ScanKind.Files : ScanKind.RunningApps;
        try
        {
            var outcome = kind == ScanKind.Files
                ? await services.Scans.ScanFilesAsync(chosenFiles, progress, cts.Token)
                : await services.Scans.ScanRunningAppsAsync(progress, cts.Token);
            if (outcome is null)
            {
                ProgressText = "";
                SummaryText = "Another scan is running. Try again when it finishes.";
                return;
            }

            if (kind == ScanKind.RunningApps)
            {
                services.MarkFullScan(DateTime.Now);
            }

            ShowOutcome(outcome);
        }
        catch (OperationCanceledException)
        {
            SummaryText = $"Stopped after {ProgressValue:N0} of {ProgressMax:N0} files.";
        }
        catch (Exception ex)
        {
            SummaryText = $"The scan failed: {ex.Message}";
        }
        finally
        {
            cancellation = null;
            IsScanning = false;
            ProgressIndeterminate = false;
            ProgressText = "";
        }
    }

    public void Ignore(FindingViewModel finding, bool byPath)
    {
        var services = AppServices.Instance;
        if (byPath)
        {
            services.IgnoreList.AddPath(finding.Result.Path);
        }
        else
        {
            services.IgnoreList.AddHash(finding.Result.Sha256);
        }

        FileAnalyzer.ApplyIgnoreRules(finding.Result, services.IgnoreList.Hashes, services.IgnoreList.Paths);
        Findings.Remove(finding);
        UpdateCounts();
        services.NotifyFindingsChanged();
    }

    public async Task SendToVirusTotalAsync(FindingViewModel finding)
    {
        var services = AppServices.Instance;
        var settings = services.Settings;
        finding.IsBusy = true;
        try
        {
            var pacer = new VirusTotalPacer(settings.FreeApiLimits, TimeSpan.FromSeconds(Math.Max(0, settings.DelaySeconds)));
            using var vt = new VirusTotalProvider(services.Keys.VirusTotal, pacer, TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 5, 600)));
            var status = new Progress<string>(text => finding.Pill = text);
            await vt.UploadAndAnalyzeAsync(finding.Result, status, CancellationToken.None);
            RiskScorer.Apply(finding.Result, settings.TrustedPublishers);
            if (settings.HashCacheEnabled)
            {
                services.HashCache.Set(finding.Result);
                await services.HashCache.FlushIfDueAsync();
            }

            ScanLog.Append([finding.Result]);
        }
        finally
        {
            finding.IsBusy = false;
            finding.Refresh();
            if (!ScanRules.NeedsAction(finding.Result))
            {
                Findings.Remove(finding);
            }

            UpdateCounts();
            services.NotifyFindingsChanged();
        }
    }

    private void OnProgress(ScanProgress progress)
    {
        if (!IsScanning)
        {
            return;
        }

        if (progress.Total == 0)
        {
            ProgressIndeterminate = true;
            return;
        }

        ProgressIndeterminate = false;
        ProgressMax = progress.Total;
        ProgressValue = progress.Done;
        var name = progress.Latest is null ? "" : $" · {ActivityText.DisplayName(progress.Latest.ProcessNames, progress.Latest.Path)}";
        ProgressText = $"Checked {progress.Done:N0} of {progress.Total:N0}{name}";
        if (progress.Latest is { } result && ScanRules.NeedsAction(result))
        {
            Findings.Add(new FindingViewModel(result));
            UpdateCounts();
        }
    }

    private void ShowOutcome(ScanOutcome outcome)
    {
        Findings.Clear();
        foreach (var result in outcome.NeedsDecision.Where(ScanRules.NeedsAction)
                     .OrderByDescending(r => r.IsAlert)
                     .ThenByDescending(r => r.RiskScore))
        {
            Findings.Add(new FindingViewModel(result));
        }

        var clean = outcome.Results.Count(r => HashGuardLogic.IsCleanStatus(r.Status));
        var flagged = outcome.Results.Count(r => r.IsAlert);
        var errors = outcome.Results.Count(r => r.Status == "error");
        var checkedText = outcome.Results.Count == 1 ? "1 file checked" : $"{outcome.Results.Count:N0} files checked";
        var newText = outcome.NewSinceLastScan > 0 ? $" · {outcome.NewSinceLastScan} new since last scan" : "";
        SummaryText = $"{checkedText} · {ActivityText.BatchSummary(clean, outcome.Unknown, flagged, errors)}{newText}";
        UpdateCounts();
    }

    private void UpdateCounts()
    {
        DecisionCount = Findings.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);
        HasFindings = Findings.Count > 0;
    }
}
