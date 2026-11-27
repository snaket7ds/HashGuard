using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>
/// Home page state. In the spike the numbers are sample data; phase 1 wires them to HashGuard.Core.
/// </summary>
public sealed partial class HomeViewModel : ObservableObject
{
    private int threats;
    private int needsDecision;
    private DateTime? lastScan = DateTime.Now.AddHours(-2);

    public HomeViewModel()
    {
        Refresh();
    }

    [ObservableProperty] public partial HomeTone Tone { get; set; }
    [ObservableProperty] public partial string Title { get; set; } = "";
    [ObservableProperty] public partial string Subtitle { get; set; } = "";
    [ObservableProperty] public partial string LastScanChip { get; set; } = "";
    [ObservableProperty] public partial string SourcesChip { get; set; } = "";
    [ObservableProperty] public partial bool IsScanning { get; set; }

    [ObservableProperty] public partial string AvLastScan { get; set; } = "";
    public string AvOpenFiles => "On";
    public string AvSources => "VirusTotal · MetaDefender · Team Cymru";

    public string FwOnline => "14 apps";
    public string FwBlocked => "2 apps";
    public string FwAlerts => "Untrusted apps";

    [ObservableProperty] public partial string DecisionCount { get; set; } = "0";
    public string QuarantineCount => "1";

    /// <summary>Spike-only: lets the preview switch between the hero's states.</summary>
    public string[] PreviewStates { get; } = ["Protected", "Needs a decision", "Threat found", "Not scanned yet"];

    public void ApplyPreviewState(int index)
    {
        (threats, needsDecision, lastScan) = index switch
        {
            1 => (0, 3, DateTime.Now.AddHours(-2)),
            2 => (1, 0, DateTime.Now.AddMinutes(-5)),
            3 => (0, 0, (DateTime?)null),
            _ => (0, 0, DateTime.Now.AddHours(-2)),
        };
        Refresh();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ScanAsync()
    {
        IsScanning = true;
        Refresh();
        await Task.Delay(2500); // Sample scan; the real one comes from HashGuard.Core in phase 1.
        lastScan = DateTime.Now;
        IsScanning = false;
        Refresh();
    }

    private void Refresh()
    {
        var status = HomeStatusText.Build(IsScanning, threats, needsDecision, sourcesOn: 3, sourcesTotal: 3, lastScan, DateTime.Now, firewallOn: true);
        Tone = status.Tone;
        Title = status.Title;
        Subtitle = status.Subtitle;
        LastScanChip = status.LastScanChip;
        SourcesChip = status.SourcesChip;
        AvLastScan = HomeStatusText.FormatLastScan(lastScan, DateTime.Now).Replace("Last scan ", "", StringComparison.Ordinal);
        DecisionCount = (threats + needsDecision).ToString(System.Globalization.CultureInfo.CurrentCulture);
    }
}
