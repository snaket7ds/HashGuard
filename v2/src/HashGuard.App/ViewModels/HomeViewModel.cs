using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.App.Services;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>
/// Home: one verdict for the PC, from the last scan and the user's settings. The firewall card
/// shows dashes until the network monitor moves to v2.
/// </summary>
public sealed partial class HomeViewModel : ObservableObject
{
    private const string NotYet = "—";

    [ObservableProperty] public partial HomeTone Tone { get; set; }
    [ObservableProperty] public partial string Title { get; set; } = "";
    [ObservableProperty] public partial string Subtitle { get; set; } = "";
    [ObservableProperty] public partial string LastScanChip { get; set; } = "";
    [ObservableProperty] public partial string SourcesChip { get; set; } = "";
    [ObservableProperty] public partial bool SourcesAllOn { get; set; }
    [ObservableProperty] public partial bool IsScanning { get; set; }
    [ObservableProperty] public partial string AvLastScan { get; set; } = "";
    [ObservableProperty] public partial string AvOpenFiles { get; set; } = "";
    [ObservableProperty] public partial string AvSources { get; set; } = "";
    [ObservableProperty] public partial string DecisionCount { get; set; } = "0";
    [ObservableProperty] public partial bool HasDecisions { get; set; }

    [ObservableProperty] public partial string FwOnline { get; set; } = NotYet;
    [ObservableProperty] public partial string FwBlocked { get; set; } = NotYet;
    [ObservableProperty] public partial string FwUntrusted { get; set; } = NotYet;
    [ObservableProperty] public partial string FwChip { get; set; } = "";
    [ObservableProperty] public partial bool FwOn { get; set; }

    /// <summary>The firewall card's numbers, from the network monitor.</summary>
    public async void RefreshFirewall()
    {
        var services = AppServices.Instance;
        FwOn = services.Settings.NetworkMonitorEnabled;
        FwChip = FwOn ? "Monitoring" : "Off";

        // Off the UI thread: the first look at a program checks its signature.
        var (online, blocked, untrusted) = await Task.Run(() =>
        {
            var apps = services.Network.Snapshot();
            return (apps.Count(a => a.Online), apps.Count(a => a.Blocked), apps.Count(a => a.Online && a.Untrusted));
        });
        var culture = System.Globalization.CultureInfo.CurrentCulture;
        FwOnline = online.ToString(culture);
        FwBlocked = blocked.ToString(culture);
        FwUntrusted = untrusted.ToString(culture);
    }
    [ObservableProperty] public partial string QuarantineCount { get; set; } = "0";

    public void Refresh()
    {
        var services = AppServices.Instance;
        var settings = services.Settings;
        var (sourcesOn, sourcesTotal) = services.SourcesOnline();
        var decisions = services.LastOutcome?.NeedsDecision.Where(ScanRules.NeedsAction).ToList() ?? [];
        var threats = decisions.Count(r => r.IsAlert);
        var lastScan = services.LastFullScanLocal;

        IsScanning = services.Scans.IsBusy;
        var status = HomeStatusText.Build(IsScanning, threats, decisions.Count - threats, sourcesOn, sourcesTotal, lastScan, DateTime.Now, firewallOn: settings.NetworkMonitorEnabled);
        Tone = status.Tone;
        Title = status.Title;
        Subtitle = status.Subtitle;
        LastScanChip = status.LastScanChip;
        SourcesChip = status.SourcesChip;
        SourcesAllOn = sourcesOn == sourcesTotal;
        AvLastScan = HomeStatusText.FormatLastScan(lastScan, DateTime.Now).Replace("Last scan ", "", StringComparison.Ordinal);
        AvOpenFiles = settings.ScanAllFiles ? "On (not in v2 yet)" : "Off";
        var names = new List<string>();
        if (settings.VirusTotalEnabled && services.Keys.VirusTotal.Length > 0) names.Add("VirusTotal");
        if (settings.MetaDefenderEnabled && services.Keys.MetaDefender.Length > 0) names.Add("MetaDefender");
        if (settings.MhrEnabled) names.Add("Team Cymru");
        AvSources = names.Count == 0 ? "None" : string.Join(" · ", names);
        DecisionCount = decisions.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);
        HasDecisions = decisions.Count > 0;
        QuarantineCount = services.Quarantine.RestorableCount.ToString(System.Globalization.CultureInfo.CurrentCulture);
        RefreshFirewall();
    }
}
