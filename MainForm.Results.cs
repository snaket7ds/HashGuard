using System.Diagnostics;
using System.Drawing;
using System.IO.Pipes;
using System.Net;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using System.Xml.Linq;
using Microsoft.Win32;

namespace HashGuardScanner;

public sealed partial class MainForm : Form
{
    private void AddResultRow(ScanResult result)
    {
        AppendScanLog(result);
        if (!ResultNeedsAction(result))
        {
            if (!batchScanUi)
            {
                UpdateResultsEmptyState();
            }
            return;
        }

        AddReviewQueueRow(result);
    }

    private void AddReviewQueueRow(ScanResult result)
    {
        if (resultsView.Items
            .Cast<ListViewItem>()
            .Any(item => string.Equals(GetSubItemText(item, ColSha256), result.Sha256, StringComparison.OrdinalIgnoreCase)
                && string.Equals(GetSubItemText(item, ColPath), result.Path, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var item = new ListViewItem(result.Status);
        item.SubItems.Add($"{result.RiskLevel} {result.RiskScore}");
        item.SubItems.Add(result.TrustSummary);
        item.SubItems.Add(result.Malicious.ToString());
        item.SubItems.Add(result.Suspicious.ToString());
        item.SubItems.Add(result.ProcessNames);
        item.SubItems.Add(result.Pids);
        item.SubItems.Add(result.Sha256);
        item.SubItems.Add(result.Path);
        var recommendation = resultsView.Name == MainResultsViewName ? BuildReviewRecommendation(result) : result.Notes;
        if (result.IsNewSinceLastScan && appSettings.PreferDeltaScan)
        {
            recommendation = string.IsNullOrWhiteSpace(recommendation)
                ? "New since last scan"
                : $"New since last scan · {recommendation}";
        }

        item.SubItems.Add(recommendation);
        item.Tag = result.Link;

        if (result.IsAlert)
        {
            item.BackColor = Color.FromArgb(253, 232, 232);
        }
        else if (result.IsNewSinceLastScan && appSettings.PreferDeltaScan)
        {
            item.BackColor = Color.FromArgb(232, 245, 233);
        }
        else if (result.Status == "ignored")
        {
            item.BackColor = Color.FromArgb(232, 245, 233);
        }
        else if (result.Status is "unknown" or "uploaded")
        {
            item.BackColor = Color.FromArgb(255, 247, 214);
        }
        else if (result.Status == "limited access")
        {
            item.BackColor = Color.FromArgb(255, 247, 214);
        }
        else if (result.Status == "error")
        {
            item.BackColor = Color.FromArgb(248, 215, 218);
        }

        resultsView.Items.Add(item);
        if (!batchScanUi)
        {
            UpdateResultsEmptyState();
            FitResultColumns(resultsView);
        }
    }

    private void ReconcileReviewQueue(bool updateSummary = true)
    {
        if (reviewQueueBusy)
        {
            return;
        }

        reviewQueueBusy = true;
        try
        {
            if (results.Count == 0)
            {
                resultsView.Items.Clear();
                UpdateResultsEmptyState();
                return;
            }

            resultsView.BeginUpdate();
            try
            {
                foreach (var item in resultsView.Items.Cast<ListViewItem>().ToList())
                {
                    var result = FindResultForReviewQueueRow(item);
                    if (result is null || !ResultNeedsAction(result))
                    {
                        item.Selected = false;
                        item.Focused = false;
                        resultsView.Items.Remove(item);
                        continue;
                    }

                    if (item.SubItems.Count <= ColNotes)
                    {
                        continue;
                    }

                    item.Text = result.Status;
                    item.SubItems[ColRisk].Text = $"{result.RiskLevel} {result.RiskScore}";
                    item.SubItems[ColTrust].Text = result.TrustSummary;
                    item.SubItems[ColMalicious].Text = result.Malicious.ToString();
                    item.SubItems[ColSuspicious].Text = result.Suspicious.ToString();
                    item.SubItems[ColProcess].Text = result.ProcessNames;
                    item.SubItems[ColPids].Text = result.Pids;
                    item.SubItems[ColSha256].Text = result.Sha256;
                    item.SubItems[ColPath].Text = result.Path;
                    item.SubItems[ColNotes].Text = BuildReviewRecommendation(result);
                    ApplyResultRowColor(item);
                }

                foreach (var result in results.Where(ResultNeedsAction))
                {
                    AddReviewQueueRow(result);
                }
            }
            finally
            {
                resultsView.EndUpdate();
            }

            UpdateResultsEmptyState();
            FitResultColumns(resultsView);
            if (updateSummary)
            {
                UpdateSummary();
            }
        }
        finally
        {
            reviewQueueBusy = false;
        }
    }

    private static List<ListViewItem> SafeSelectedItems(ListView view)
    {
        if (view.SelectedIndices.Count == 0)
        {
            return [];
        }

        try
        {
            if (view.SelectedIndices.Cast<int>().Any(index => index < 0))
            {
                return [];
            }

            return [.. view.SelectedItems.Cast<ListViewItem>()];
        }
        catch (ArgumentException)
        {
            return [];
        }
        catch (InvalidOperationException)
        {
            return [];
        }
    }

    private void UpdateReviewQueueActionButtons(
        Button openReport,
        Button openLocation,
        Button ignoreSelected,
        Button ignorePublisher,
        Button quarantineSelected)
    {
        var selected = SafeSelectedItems(resultsView);
        var hasSelection = selected.Count > 0;
        openReport.Enabled = hasSelection;
        openLocation.Enabled = hasSelection;
        ignoreSelected.Enabled = hasSelection;
        ignorePublisher.Enabled = hasSelection;
        quarantineSelected.Enabled = hasSelection;
        if (approveUploadButton is not null)
        {
            approveUploadButton.Enabled = GetVirusTotalUploadTargets(selected).Count > 0;
        }

        if (hasSelection)
        {
            UpdateIgnoreButtonText(resultsView, ignoreSelected);
        }
    }

    private ScanResult? FindResultForReviewQueueRow(ListViewItem item)
    {
        var sha256 = GetSubItemText(item, ColSha256);
        var path = GetSubItemText(item, ColPath);
        return results.FirstOrDefault(result =>
            !string.IsNullOrWhiteSpace(sha256)
                ? string.Equals(result.Sha256, sha256, StringComparison.OrdinalIgnoreCase)
                : string.Equals(result.Path, path, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildReviewRecommendation(ScanResult result)
    {
        if (ResultIsHandled(result))
        {
            return string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase)
                ? "Handled: ignored by user"
                : "Handled: quarantined";
        }

        if (result.IsAlert)
        {
            return $"Review now: {result.Malicious} malicious / {result.Suspicious} suspicious detections";
        }

        if (string.Equals(result.Status, "error", StringComparison.OrdinalIgnoreCase))
        {
            return "Review scan error in Activity Log";
        }

        if (result.RiskScore >= 70)
        {
            return "Review high local risk signals";
        }

        if (result.NeedsVirusTotalUpload)
        {
            return "Approve VirusTotal upload — hash not in VirusTotal";
        }

        if (result.Status is "unknown" or "uploaded" or "limited access")
        {
            return "Monitor: reputation incomplete";
        }

        return "No action needed";
    }

    private void UpdateResultsEmptyState()
    {
        resultsEmptyLabel.Visible = resultsView.Items.Count == 0;
        if (resultsEmptyLabel.Visible)
        {
            resultsEmptyLabel.BringToFront();
        }
    }

    private static void FitResultColumns(ListView view)
    {
        if (view.Columns.Count <= ColNotes)
        {
            return;
        }

        if (view.Name == MainResultsViewName)
        {
            var available = Math.Max(940, view.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 8);
            view.Columns[ColStatus].Width = 112;
            view.Columns[ColRisk].Width = 92;
            view.Columns[ColTrust].Width = Math.Max(190, available * 21 / 100);
            view.Columns[ColMalicious].Width = 0;
            view.Columns[ColSuspicious].Width = 0;
            view.Columns[ColProcess].Width = Math.Max(150, available * 18 / 100);
            view.Columns[ColPids].Width = 0;
            view.Columns[ColSha256].Width = 0;
            view.Columns[ColPath].Width = Math.Max(280, available * 28 / 100);
            view.Columns[ColNotes].Width = Math.Max(240, available - view.Columns[ColStatus].Width - view.Columns[ColRisk].Width - view.Columns[ColTrust].Width - view.Columns[ColProcess].Width - view.Columns[ColPath].Width);
            return;
        }

        view.Columns[ColStatus].Width = 104;
        view.Columns[ColRisk].Width = 96;
        view.Columns[ColMalicious].Width = 52;
        view.Columns[ColSuspicious].Width = 52;
        view.Columns[ColPids].Width = 95;
        view.Columns[ColProcess].Width = Math.Min(220, Math.Max(150, view.Columns[ColProcess].Width));
        view.Columns[ColTrust].Width = Math.Min(320, Math.Max(220, view.Columns[ColTrust].Width));
        view.Columns[ColSha256].Width = Math.Min(360, Math.Max(280, view.Columns[ColSha256].Width));
        view.Columns[ColPath].Width = Math.Min(520, Math.Max(360, view.Columns[ColPath].Width));
        view.Columns[ColNotes].Width = Math.Min(420, Math.Max(300, view.Columns[ColNotes].Width));
    }

    private static void ApplyResultRowColor(ListViewItem item)
    {
        item.BackColor = Color.Empty;
        var status = item.Text;
        var malicious = item.SubItems.Count > ColMalicious && int.TryParse(item.SubItems[ColMalicious].Text, out var mal) ? mal : 0;
        var suspicious = item.SubItems.Count > ColSuspicious && int.TryParse(item.SubItems[ColSuspicious].Text, out var susp) ? susp : 0;
        var riskText = item.SubItems.Count > ColRisk ? item.SubItems[ColRisk].Text : "";

        if (IsHandledActivityItem(item))
        {
            item.BackColor = Color.FromArgb(232, 245, 233);
        }
        else if (malicious > 0 || suspicious > 0)
        {
            item.BackColor = Color.FromArgb(253, 232, 232);
        }
        else if (riskText.StartsWith("Medium", StringComparison.OrdinalIgnoreCase)
            || status is "unknown" or "uploaded" or "limited access")
        {
            item.BackColor = Color.FromArgb(255, 247, 214);
        }
        else if (status == "error")
        {
            item.BackColor = Color.FromArgb(248, 215, 218);
        }
    }

    private void BeginScanUiBatch()
    {
        batchScanUi = true;
        scanUiDirty = 0;
        scanUiLastFlushUtc = DateTime.UtcNow;
    }

    private void PulseScanUi(int completed, int total, string path, string verb = "Scanning")
    {
        statusLabel.Text = $"{verb} {completed} of {total}: {FormatDisplayPath(path)}";
        countLabel.Text = $"{completed} / {total}";
        if (completed >= 0 && completed <= progressBar.Maximum)
        {
            progressBar.Value = completed;
        }

        scanUiDirty++;
        if (scanUiDirty >= ScanUiFlushEvery || DateTime.UtcNow - scanUiLastFlushUtc >= ScanUiFlushInterval)
        {
            FlushScanUi(fitColumns: false);
        }
    }

    private void FlushScanUi(bool fitColumns)
    {
        UpdateSummary();
        if (fitColumns)
        {
            FitResultColumns(resultsView);
            UpdateResultsEmptyState();
        }

        scanUiDirty = 0;
        scanUiLastFlushUtc = DateTime.UtcNow;
    }

    private void EndScanUiBatch()
    {
        if (!batchScanUi)
        {
            return;
        }

        batchScanUi = false;
        FlushScanUi(fitColumns: true);
    }

    private void UpdateSummary()
    {
        var actionsNeeded = results.Count(ResultNeedsAction);
        var alerts = results.Count(result => ResultNeedsAction(result) && result.IsAlert);
        var unknown = results.Count(result => result.Status is "unknown" or "uploaded");
        var errors = results.Count(result => ResultNeedsAction(result) && result.Status == "error");
        var highRisk = results.Count(result => ResultNeedsAction(result) && result.RiskScore >= 70);
        var persistent = results.Count(result => result.PersistenceSources.Count > 0);
        var unsigned = results.Count(result => result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase));
        summaryLabel.Text = $"Items scanned: {results.Count}";
        actionLabel.Text = $"Needs review: {actionsNeeded}";
        toolTip.SetToolTip(summaryLabel, $"{results.Count} scanned | {highRisk} high risk | {persistent} persistent | {unsigned} unsigned | {unknown} unknown");
        toolTip.SetToolTip(actionLabel, $"{actionsNeeded} file(s) need action | {alerts} detections | {highRisk} high risk | {errors} errors");
        if (scanCancellation is not null || scanGate.IsBusy)
        {
            return;
        }

        if (actionsNeeded > 0)
        {
            SetDashboardState("Action needed", $"{actionsNeeded} file(s) still need review. {alerts} detection(s), {highRisk} high risk, {errors} errors.", true);
        }
        else if (results.Count > 0)
        {
            SetDashboardState("Clean", "No action needed.", false);
        }
    }

    private static bool ResultNeedsAction(ScanResult result)
    {
        return !ResultIsHandled(result)
            && HashGuardLogic.NeedsAction(
                result.Status,
                $"{result.RiskLevel} {result.RiskScore}",
                result.Malicious,
                result.Suspicious,
                result.NeedsVirusTotalUpload);
    }

    private static bool ResultIsHandled(ScanResult result)
    {
        return string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase)
            || HashGuardLogic.HasIgnoreNote(result.Notes)
            || result.Notes.Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase);
    }

    private void AppendScanLog(ScanResult result)
    {
        try
        {
            var logDir = AppPaths.GetLogDirectory();
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, $"scan-log-{DateTime.Now:yyyyMMdd}.csv");
            var writeHeader = !File.Exists(logPath);
            using var writer = new StreamWriter(logPath, append: true, Encoding.UTF8);
            if (writeHeader)
            {
                writer.WriteLine("timestamp_computer_time,status,risk_score,risk_level,trust,provider_results,malicious,suspicious,harmless,undetected,process_names,pids,sha256,path,link,notes");
            }

            writer.WriteLine(string.Join(",", new[]
            {
                Csv(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                Csv(result.Status),
                Csv(result.RiskScore.ToString()),
                Csv(result.RiskLevel),
                Csv(result.TrustSummary),
                Csv(result.ProviderSummary),
                Csv(result.Malicious.ToString()),
                Csv(result.Suspicious.ToString()),
                Csv(result.Harmless.ToString()),
                Csv(result.Undetected.ToString()),
                Csv(result.ProcessNames),
                Csv(result.Pids),
                Csv(result.Sha256),
                Csv(result.Path),
                Csv(result.Link),
                Csv(result.Notes),
            }));
            // New scan rows must not be hidden behind a stale Activity Log cache.
            activityLogCache = null;
            activityLogCacheSignature = "";
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Could not write scan log: {ex.Message}";
        }
    }

    private void OpenLogFolder()
    {
        var logDir = AppPaths.GetLogDirectory();
        Directory.CreateDirectory(logDir);
        Process.Start(new ProcessStartInfo(logDir) { UseShellExecute = true });
    }

    private void OpenHashCacheFolder()
    {
        var configDir = AppPaths.GetConfigDirectory();
        Directory.CreateDirectory(configDir);
        Process.Start(new ProcessStartInfo(configDir) { UseShellExecute = true });
    }
}
