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
    private void OpenSelectedFileLocation(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a row with a file path first.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var path = GetSubItemText(sourceView.SelectedItems[0], ColPath);
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(this, "The selected row has no file path.", "No file path", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
                return;
            }

            var directory = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
            {
                Process.Start(new ProcessStartInfo(directory) { UseShellExecute = true });
                return;
            }

            MessageBox.Show(this, $"File location no longer exists:{Environment.NewLine}{path}", "File location unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not open file location:{Environment.NewLine}{ex.Message}", "Open file location failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ToggleSelectedIgnoreFlag(ListView sourceView)
    {
        var targets = GetSelectedIgnoreTargets(sourceView);
        if (targets.Count > 0 && targets.All(target => IsIgnoredTargetSelected(sourceView, target)))
        {
            ClearSelectedIgnoreFlags(sourceView, targets);
            return;
        }

        IgnoreSelectedDetection(sourceView, targets);
    }

    private void UpdateIgnoreButtonText(ListView sourceView, Button button)
    {
        var targets = GetSelectedIgnoreTargets(sourceView);
        button.Text = targets.Count > 0 && targets.All(target => IsIgnoredTargetSelected(sourceView, target))
            ? "Clear Ignore Flag"
            : "Ignore Selected";
    }

    private static List<IgnoreTarget> GetSelectedIgnoreTargets(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            return [];
        }

        return sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Select(item =>
            {
                var sha256 = GetSubItemText(item, ColSha256);
                return !string.IsNullOrWhiteSpace(sha256)
                    ? new IgnoreTarget("hash", sha256)
                    : new IgnoreTarget("path", GetSubItemText(item, ColPath));
            })
            .Where(target => !string.IsNullOrWhiteSpace(target.Value))
            .GroupBy(target => $"{target.Kind}:{target.Value}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
    }

    private bool IsIgnoredTargetSelected(ListView sourceView, IgnoreTarget target)
    {
        return target.Kind == "hash"
            ? ignoredHashes.Contains(target.Value)
                || sourceView.SelectedItems
                    .Cast<ListViewItem>()
                    .Any(item => string.Equals(GetSubItemText(item, ColSha256), target.Value, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(item.Text, "ignored", StringComparison.OrdinalIgnoreCase))
            : ignoredPaths.Contains(target.Value)
                || sourceView.SelectedItems
                    .Cast<ListViewItem>()
                    .Any(item => string.Equals(GetSubItemText(item, ColPath), target.Value, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(item.Text, "ignored", StringComparison.OrdinalIgnoreCase));
    }

    private void IgnoreSelectedDetection(ListView sourceView, List<IgnoreTarget> targets)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a file row to ignore.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (targets.Count == 0)
        {
            MessageBox.Show(this, "Select one or more file items with a SHA-256 hash or file path.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var hashCount = targets.Count(target => target.Kind == "hash");
        var pathCount = targets.Count - hashCount;
        var accepted = MessageBox.Show(
            this,
            $"Ignore {DescribeIgnoreTargets(hashCount, pathCount)} in future scans?",
            "Ignore files",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        foreach (var target in targets)
        {
            if (target.Kind == "hash")
            {
                ignoredHashes.Add(target.Value);
            }
            else
            {
                ignoredPaths.Add(target.Value);
            }

            MarkIgnoredRows(sourceView, target);
            MarkIgnoredRows(resultsView, target);
            foreach (var result in results.Where(result => TargetMatchesResult(target, result)))
            {
                result.StatusBeforeIgnore = result.Status;
                result.Status = "ignored";
                if (!HashGuardLogic.HasIgnoreNote(result.Notes))
                {
                    var ignoreNote = target.Kind == "hash" ? "File hash ignored by user." : "File path ignored by user.";
                    result.Notes = string.IsNullOrWhiteSpace(result.Notes)
                        ? ignoreNote
                        : $"{result.Notes}; {ignoreNote}";
                }
            }
        }

        SaveIgnoredHashes();
        SaveIgnoredPaths();
        ReconcileReviewQueue(updateSummary: false);
        UpdateSummary();
        statusLabel.Text = $"{DescribeIgnoreTargets(hashCount, pathCount)} ignored. Future scans will mark matching files as ignored.";
    }

    private void ClearSelectedIgnoreFlags(ListView sourceView, List<IgnoreTarget> targets)
    {
        var hashCount = targets.Count(target => target.Kind == "hash");
        var pathCount = targets.Count - hashCount;
        var accepted = MessageBox.Show(
            this,
            $"Clear the ignore flag for {DescribeIgnoreTargets(hashCount, pathCount)}?",
            "Clear ignore flag",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        foreach (var target in targets)
        {
            if (target.Kind == "hash")
            {
                ignoredHashes.Remove(target.Value);
            }
            else
            {
                ignoredPaths.Remove(target.Value);
            }

            MarkUnignoredRows(sourceView, target);
            MarkUnignoredRows(resultsView, target);
            foreach (var result in results.Where(result => TargetMatchesResult(target, result)))
            {
                result.Status = !string.IsNullOrWhiteSpace(result.StatusBeforeIgnore)
                    ? result.StatusBeforeIgnore
                    : result.IsDetection
                        ? "detected"
                        : "unknown";
                result.StatusBeforeIgnore = "";
                result.Notes = HashGuardLogic.RemoveIgnoreNote(result.Notes);
                if (ResultNeedsAction(result))
                {
                    AddReviewQueueRow(result);
                }
            }
        }

        SaveIgnoredHashes();
        SaveIgnoredPaths();
        ReconcileReviewQueue(updateSummary: false);
        UpdateSummary();
        statusLabel.Text = $"{targets.Count} ignore flag(s) cleared.";
    }

    private static void MarkIgnoredRows(ListView view, IgnoreTarget target)
    {
        foreach (var row in view.Items.Cast<ListViewItem>().ToList())
        {
            if (!TargetMatchesRow(target, row))
            {
                continue;
            }

            if (view.Name == MainResultsViewName)
            {
                view.Items.Remove(row);
                continue;
            }

            row.Text = "ignored";
            var notes = GetSubItemText(row, ColNotes);
            var ignoreNote = target.Kind == "hash" ? "File hash ignored by user." : "File path ignored by user.";
            row.SubItems[ColNotes].Text = HashGuardLogic.HasIgnoreNote(notes)
                ? notes
                : string.IsNullOrWhiteSpace(notes)
                    ? ignoreNote
                    : $"{notes}; {ignoreNote}";
            ApplyResultRowColor(row);
        }
    }

    private static void MarkUnignoredRows(ListView view, IgnoreTarget target)
    {
        foreach (ListViewItem row in view.Items)
        {
            if (!TargetMatchesRow(target, row))
            {
                continue;
            }

            var malicious = int.TryParse(GetSubItemText(row, ColMalicious), out var mal) ? mal : 0;
            var suspicious = int.TryParse(GetSubItemText(row, ColSuspicious), out var susp) ? susp : 0;
            row.Text = malicious + suspicious > 0 ? "detected" : "clean";
            row.SubItems[ColNotes].Text = view.Name == MainResultsViewName
                ? malicious + suspicious > 0
                    ? $"Review now: {malicious} malicious / {suspicious} suspicious detections"
                    : "No action needed"
                : HashGuardLogic.RemoveIgnoreNote(GetSubItemText(row, ColNotes));
            ApplyResultRowColor(row);
        }
    }

    private static bool TargetMatchesResult(IgnoreTarget target, ScanResult result)
    {
        return target.Kind == "hash"
            ? string.Equals(result.Sha256, target.Value, StringComparison.OrdinalIgnoreCase)
            : string.Equals(result.Path, target.Value, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TargetMatchesRow(IgnoreTarget target, ListViewItem row)
    {
        return target.Kind == "hash"
            ? string.Equals(GetSubItemText(row, ColSha256), target.Value, StringComparison.OrdinalIgnoreCase)
            : string.Equals(GetSubItemText(row, ColPath), target.Value, StringComparison.OrdinalIgnoreCase);
    }

    private static string DescribeIgnoreTargets(int hashCount, int pathCount)
    {
        return (hashCount, pathCount) switch
        {
            (> 0, > 0) => $"{hashCount} file hash(es) and {pathCount} file path(s)",
            (> 0, _) => $"{hashCount} file hash(es)",
            (_, > 0) => $"{pathCount} file path(s)",
            _ => "0 files",
        };
    }
}
