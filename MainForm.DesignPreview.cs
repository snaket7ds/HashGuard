#if DESIGN_PREVIEW
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// Visual check only, never in a release: build with -p:DefineConstants=DESIGN_PREVIEW to fill the
/// review list with a sample "malicious" and "unknown" file and show the new-app alert in the window
/// and then above the tray, so those screens can be compared with the design (e.g. under Wine).
/// </summary>
public sealed partial class MainForm : Form
{
    private async Task RunDesignPreviewAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(20));
        // A scan clears the review list when it starts, so add the samples after the startup scan.
        while (scanCancellation is not null || scanGate.IsBusy)
        {
            await Task.Delay(500);
        }

        await Task.Delay(TimeSpan.FromSeconds(2));
        var folder = Path.Combine(Path.GetTempPath(), "HashGuardPreview");
        Directory.CreateDirectory(folder);
        var malicious = Path.Combine(folder, "invoice_viewer.exe");
        var unknown = Path.Combine(folder, "setup_tool.exe");
        File.WriteAllText(malicious, "design preview sample");
        File.WriteAllText(unknown, "design preview sample 2");

        var threat = new ScanResult(malicious, "invoice_viewer.exe", "")
        {
            Status = "malicious",
            Malicious = 4,
            Sha256 = "9f2c7d0e5b1a44c8e2f9a6d3b7c1e0f4a8d2c6b9e3f7a1d5c9b2e6f0a4d841ab",
            SignatureSummary = "Unsigned or signature unavailable",
            RiskScore = 95,
            RiskLevel = "High",
        };
        threat.ProviderResults.Add(new ProviderResult("VirusTotal", ProviderState.Detected, "4 of 72"));
        var unseen = new ScanResult(unknown, "setup_tool.exe", "4120")
        {
            Status = "unknown",
            Sha256 = "1b7e44f09a2c6d8e3b5f7a1c9d2e4f6a8b0c2d4e6f8a1b3c5d7e9f0a2b4cc093",
            SignatureSummary = "Unsigned or signature unavailable",
            RiskScore = 45,
            RiskLevel = "Medium",
            NeedsVirusTotalUpload = true,
        };
        foreach (var result in new[] { threat, unseen })
        {
            results.Add(result);
            AddResultRow(result);
        }

        UpdateSummary();
        ShowPage(AppPage.Home);

        await Task.Delay(TimeSpan.FromSeconds(25));
        ShowAlert(AlertTone.Warning, "New app went online", "GameUpdater.exe connected to 203.0.113.24:8443 for the first time. Not scanned · Unsigned.",
        [
            new AlertButton("Allow", AlertButtonKind.Normal, card => card.ShowConfirmation("GameUpdater.exe is allowed.", null)),
            new AlertButton("Details", AlertButtonKind.Normal, card => card.Dismiss()),
            new AlertButton("Block", AlertButtonKind.Danger, card => card.ShowConfirmation("GameUpdater.exe is blocked in Windows Firewall.", () => { })),
        ]);

        await Task.Delay(TimeSpan.FromSeconds(25));
        overlayAlert?.Dismiss();
        WindowState = FormWindowState.Minimized;
        MinimizeToTrayIfNeeded();
        await Task.Delay(TimeSpan.FromSeconds(3));
        ShowAlert(AlertTone.Warning, "New app went online", "GameUpdater.exe connected to 203.0.113.24:8443 for the first time. Not scanned · Unsigned.",
        [
            new AlertButton("Allow", AlertButtonKind.Normal, card => card.Dismiss()),
            new AlertButton("Details", AlertButtonKind.Normal, card => card.Dismiss()),
            new AlertButton("Block", AlertButtonKind.Danger, card => card.Dismiss()),
        ]);
    }
}
#endif
