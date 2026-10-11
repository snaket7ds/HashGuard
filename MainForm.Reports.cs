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
    private void OpenSelectedReport(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a row with a SHA-256 hash first.", "No report selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var item = sourceView.SelectedItems[0];
        var sha256 = GetSubItemText(item, ColSha256);
        if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
        {
            MessageBox.Show(this, "The selected row has no valid SHA-256 hash.", "No report selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new Form
        {
            Text = "Open Report",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ClientSize = new Size(620, 186),
        };

        var prompt = new Label
        {
            Text = "Choose which report to open for the selected hash:",
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 10),
        };

        var hashLabel = new Label
        {
            Text = sha256,
            AutoEllipsis = true,
            Width = 574,
            Height = 22,
            ForeColor = Color.DimGray,
        };

        var virusTotal = new Button { Text = "VirusTotal", Width = 128, Height = 34 };
        var metaDefender = new Button { Text = "MetaDefender", Width = 150, Height = 34 };
        var mhr = new Button { Text = "Cymru", Width = 108, Height = 34 };
        var cancel = new Button { Text = "Cancel", Width = 92, Height = 34, DialogResult = DialogResult.Cancel };

        virusTotal.Click += (_, _) => OpenReportAndClose(dialog, string.Format(AppConstants.VirusTotalGuiReportUrl, sha256));
        metaDefender.Click += (_, _) => OpenReportAndClose(dialog, string.Format(AppConstants.MetaDefenderReportUrl, sha256));
        mhr.Click += (_, _) => OpenReportAndClose(dialog, string.Format(AppConstants.CymruDnsQueryUrl, Uri.EscapeDataString(ProviderStats.BuildCymruQueryName(sha256))));

        toolTip.SetToolTip(virusTotal, "Open VirusTotal report");
        toolTip.SetToolTip(metaDefender, "Open MetaDefender report");
        toolTip.SetToolTip(mhr, "Open Cymru Malware Hash Registry DNS report");

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0, 14, 0, 0),
        };
        buttons.Controls.Add(virusTotal);
        buttons.Controls.Add(metaDefender);
        buttons.Controls.Add(mhr);
        buttons.Controls.Add(cancel);

        var layout = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(18),
        };
        layout.Controls.Add(prompt);
        layout.Controls.Add(hashLabel);
        layout.Controls.Add(buttons);
        dialog.Controls.Add(layout);
        dialog.CancelButton = cancel;
        dialog.ShowDialog(this);
    }

    private static void OpenReportAndClose(Form dialog, string link)
    {
        Process.Start(new ProcessStartInfo(link) { UseShellExecute = true });
        dialog.DialogResult = DialogResult.OK;
        dialog.Close();
    }

    private void ExportCsv()
    {
        ExportScanReport();
    }

    private void ExportCsv(ListView sourceView)
    {
        // Activity Log still exports the visible rows; main report uses the full in-memory results.
        if (ReferenceEquals(sourceView, resultsView) || results.Count > 0)
        {
            ExportScanReport();
            return;
        }

        MessageBox.Show(this, "There are no rows to export.", "No results", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ExportScanReport()
    {
        if (results.Count == 0)
        {
            MessageBox.Show(this, "Run a scan first, then export the report.", "No results", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = "Export HashGuard scan report",
            Filter = "CSV files (*.csv)|*.csv|HTML report (*.html)|*.html|All files (*.*)|*.*",
            DefaultExt = "csv",
            FileName = $"hashguard-scan-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var extension = Path.GetExtension(dialog.FileName);
        if (string.Equals(extension, ".html", StringComparison.OrdinalIgnoreCase)
            || string.Equals(extension, ".htm", StringComparison.OrdinalIgnoreCase))
        {
            File.WriteAllText(dialog.FileName, ScanReportExport.ToHtml(results, CurrentVersion, DateTimeOffset.Now), Encoding.UTF8);
        }
        else
        {
            File.WriteAllText(dialog.FileName, ScanReportExport.ToCsv(results), Encoding.UTF8);
        }

        MessageBox.Show(this, $"Saved {results.Count} item(s) to:{Environment.NewLine}{dialog.FileName}", "Export complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private List<ScanResult> GetSelectedVirusTotalUploadTargets(ListView sourceView) =>
        GetVirusTotalUploadTargets(SafeSelectedItems(sourceView));

    private List<ScanResult> GetVirusTotalUploadTargets(IEnumerable<ListViewItem> items)
    {
        return items
            .Select(FindResultForReviewQueueRow)
            .Where(result => result is not null && result.NeedsVirusTotalUpload && File.Exists(result.Path))
            .Select(result => result!)
            .GroupBy(result => result.Sha256, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
    }

    private async Task ApproveSelectedVirusTotalUploadsAsync(ListView sourceView)
    {
        var targets = GetSelectedVirusTotalUploadTargets(sourceView);
        if (targets.Count == 0)
        {
            MessageBox.Show(
                this,
                "Select a Review Queue row whose hash is not in VirusTotal. The file must still exist on disk.",
                "No upload pending",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (!virusTotalEnabledBox.Checked)
        {
            MessageBox.Show(this, "Enable VirusTotal in Settings first.", "VirusTotal off", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (!uploadUnknownBox.Checked && !EnableVirusTotalUploadsWithWarning())
        {
            return;
        }

        suppressSettingEvents = true;
        uploadUnknownBox.Checked = true;
        suppressSettingEvents = false;
        SaveCurrentAppSettings();

        var names = string.Join(Environment.NewLine, targets.Take(8).Select(result => Path.GetFileName(result.Path)));
        var extra = targets.Count > 8 ? $"{Environment.NewLine}(+{targets.Count - 8} more)" : "";
        var accepted = MessageBox.Show(
            this,
            $"Upload {targets.Count} file(s) to VirusTotal for analysis?{Environment.NewLine}{Environment.NewLine}{names}{extra}{Environment.NewLine}{Environment.NewLine}The full file is sent to VirusTotal.",
            "Approve VirusTotal upload",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        if (!scanGate.TryEnter())
        {
            MessageBox.Show(this, "A scan is already running. Approve the upload after it finishes.", "Busy", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            using var http = AppHttp.Create((int)timeoutBox.Value);
            var apiKey = apiKeyBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                MessageBox.Show(this, "Add a VirusTotal API key in Settings before uploading.", "API key required", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            var uploaded = 0;
            var failed = 0;
            for (var index = 0; index < targets.Count; index++)
            {
                var result = targets[index];
                statusLabel.Text = $"Uploading {index + 1} of {targets.Count}: {FormatDisplayPath(result.Path)}";
                AppendResultNote(result, "VirusTotal: upload approved from Review Queue.");
                var analysisId = await UploadFileAsync(http, result.Path, result, CancellationToken.None);
                if (string.IsNullOrWhiteSpace(analysisId))
                {
                    failed++;
                    continue;
                }

                result.NeedsVirusTotalUpload = false;
                result.Status = "uploaded";
                AddProviderResult(result, "VirusTotal", ProviderState.Deferred, $"Uploaded for analysis: {analysisId}");
                AppendResultNote(result, $"VirusTotal analysis ID: {analysisId}");
                if (analysisId is "submitted" or "already-exists")
                {
                    await TryApplyExistingVirusTotalReportAsync(http, result, CancellationToken.None);
                }
                else
                {
                    await PollAnalysisAsync(http, analysisId, result, result.Path, CancellationToken.None);
                }

                ApplyRiskAndTrust(result);
                await SaveResultToCacheAsync(result);
                uploaded++;
            }

            statusLabel.Text = failed == 0
                ? $"VirusTotal upload complete. {uploaded} file(s) submitted."
                : $"VirusTotal upload finished. {uploaded} submitted, {failed} failed.";
        }
        catch (Exception ex)
        {
            statusLabel.Text = "VirusTotal upload failed";
            MessageBox.Show(this, FormatScanError(ex), "VirusTotal upload failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            try
            {
                ReconcileReviewQueue();
            }
            catch (ArgumentException)
            {
                // ListView can throw "Value of '-1' is not valid for 'index'" when
                // the uploaded row is removed and selection is cleared.
            }

            if (approveUploadButton is not null)
            {
                approveUploadButton.Enabled = GetSelectedVirusTotalUploadTargets(resultsView).Count > 0;
            }

            scanGate.Exit();
        }
    }
}
