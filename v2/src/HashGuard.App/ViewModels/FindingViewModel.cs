using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>One row in "Needs your decision": a file and what HashGuard found.</summary>
public sealed partial class FindingViewModel : ObservableObject
{
    public FindingViewModel(ScanResult result)
    {
        Result = result;
        Refresh();
    }

    public ScanResult Result { get; }

    /// <summary>The row itself, for buttons that need to know which finding they act on.</summary>
    public FindingViewModel Self => this;

    [ObservableProperty] public partial string Title { get; set; } = "";
    [ObservableProperty] public partial string Pill { get; set; } = "";
    [ObservableProperty] public partial ActivityKind Kind { get; set; }
    [ObservableProperty] public partial bool IsExpanded { get; set; }
    [ObservableProperty] public partial bool IsBusy { get; set; }
    [ObservableProperty] public partial bool CanSendToVirusTotal { get; set; }

    public string Name => ActivityText.DisplayName(Result.ProcessNames, Result.Path);

    public string PathText => ActivityText.FriendlyPath(Result.Path);

    /// <summary>Glyph for the tile: error mark for threats, warning for the rest.</summary>
    public string Glyph => Kind switch
    {
        ActivityKind.Threat => "",
        ActivityKind.Suspicious => "",
        ActivityKind.Error => "",
        _ => "",
    };

    /// <summary>Plain-language detail shown under Details: signer, each source's answer, risk notes.</summary>
    public string DetailText
    {
        get
        {
            var lines = new List<string> { ActivityText.FriendlyTrust(Result.TrustSummary) };
            lines.AddRange(Result.ProviderResults.Select(p => string.IsNullOrWhiteSpace(p.Detail) ? $"{p.Provider}: {p.State}" : $"{p.Provider}: {p.Detail}"));
            if (Result.PersistenceSources.Count > 0)
            {
                lines.Add($"Starts automatically: {string.Join("; ", Result.PersistenceSources)}");
            }

            lines.Add($"Risk score {Result.RiskScore} ({Result.RiskLevel})");
            if (!string.IsNullOrWhiteSpace(Result.Sha256))
            {
                lines.Add($"SHA-256 {Result.Sha256}");
            }

            return string.Join(Environment.NewLine, lines.Where(l => !string.IsNullOrWhiteSpace(l)));
        }
    }

    public void Refresh()
    {
        var description = ActivityText.Describe(Result.Status, Result.Malicious, Result.Suspicious, ScanRules.IsHandled(Result), Name);
        Title = description.Title;
        Pill = description.Pill;
        Kind = description.Kind;
        CanSendToVirusTotal = Result.NeedsVirusTotalUpload;
        OnPropertyChanged(nameof(Glyph));
        OnPropertyChanged(nameof(DetailText));
    }
}
