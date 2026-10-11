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
    private void OpenSelectedReport()
    {
        OpenSelectedReport(resultsView);
    }

    private void CopySelectedHash(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a row with a SHA-256 hash first.", "No hash selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var sha256 = GetSubItemText(sourceView.SelectedItems[0], ColSha256);
        if (string.IsNullOrWhiteSpace(sha256))
        {
            MessageBox.Show(this, "The selected row has no SHA-256 hash.", "No hash selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Clipboard.SetText(sha256);
        statusLabel.Text = "SHA-256 copied to clipboard.";
    }

    private void CopySelectedReportSummary(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select one or more rows first.", "No row selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var summaries = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Take(10)
            .Select(BuildReasonSummary);
        Clipboard.SetText(string.Join($"{Environment.NewLine}{Environment.NewLine}", summaries));
        statusLabel.Text = "Selection summary copied to clipboard.";
    }

    private void KillSelectedProcesses(ListView sourceView)
    {
        var selections = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .SelectMany(item => GetSubItemText(item, ColPids)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(pid => new
                {
                    Pid = int.TryParse(pid, out var value) ? value : 0,
                    Path = GetSubItemText(item, ColPath),
                }))
            .Where(selection => selection.Pid > 0 && selection.Pid != Environment.ProcessId)
            .GroupBy(selection => selection.Pid)
            .Select(group => group.First())
            .ToList();

        if (selections.Count == 0)
        {
            MessageBox.Show(this, "Select one or more rows with running process IDs.", "No running process selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Terminate {selections.Count} selected process(es)? HashGuard will only kill a PID if its current executable path still matches the selected row. Unsaved work in those processes may be lost.{Environment.NewLine}{Environment.NewLine}{BuildSelectedActionSummary(sourceView)}",
            "Kill selected processes",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var killed = 0;
        var failures = new List<string>();
        foreach (var selection in selections)
        {
            try
            {
                using var process = Process.GetProcessById(selection.Pid);
                var currentPath = GetProcessPath(process);
                if (string.IsNullOrWhiteSpace(currentPath)
                    || !string.Equals(currentPath, selection.Path, StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add($"{selection.Pid}: current process path no longer matches the selected row.");
                    continue;
                }

                process.Kill(entireProcessTree: true);
                if (process.WaitForExit(5000))
                {
                    killed++;
                }
            }
            catch (Exception ex)
            {
                failures.Add($"{selection.Pid}: {ex.Message}");
            }
        }

        statusLabel.Text = $"Killed {killed} process(es).";
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some processes could not be killed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
