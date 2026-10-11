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
    private static Button CreateActivityFilterButton(ActivityFilter filter)
    {
        return new Button
        {
            Text = filter switch
            {
                ActivityFilter.ActionNeeded => "Action Needed",
                ActivityFilter.Unknown => "Unknown",
                ActivityFilter.Clean => "Clean",
                ActivityFilter.Errors => "Errors",
                _ => "All",
            },
            Tag = filter,
            AutoSize = true,
            Height = 32,
            Margin = new Padding(0, 0, 8, 0),
            FlatStyle = FlatStyle.Flat,
        };
    }

    private static Button CreateActivityActionButton(string text)
    {
        return new Button
        {
            Text = text,
            Width = Math.Max(96, text.Length * 8 + 24),
            Height = 32,
            Margin = new Padding(0, 0, 8, 6),
            FlatStyle = FlatStyle.Flat,
        };
    }

    private static bool MatchesActivityFilter(ActivityFilter filter, ActivityLogRow row)
    {
        if (filter == ActivityFilter.ActionNeeded && IsHandledActivityRow(row))
        {
            return false;
        }

        return HashGuardLogic.MatchesActivityFilter(filter, row.Status, row.Risk, row.Malicious, row.Suspicious);
    }

    private static bool MatchesActivityFilter(ActivityFilter filter, ListViewItem item)
    {
        if (filter == ActivityFilter.ActionNeeded && IsHandledActivityItem(item))
        {
            return false;
        }

        var malicious = int.TryParse(GetSubItemText(item, ColMalicious), out var mal) ? mal : 0;
        var suspicious = int.TryParse(GetSubItemText(item, ColSuspicious), out var susp) ? susp : 0;
        return HashGuardLogic.MatchesActivityFilter(filter, item.Text, GetSubItemText(item, ColRisk), malicious, suspicious);
    }

    private static bool IsHandledActivityRow(ActivityLogRow row) =>
        string.Equals(row.Status, "ignored", StringComparison.OrdinalIgnoreCase)
        || row.Notes.StartsWith("Handled:", StringComparison.OrdinalIgnoreCase)
        || HashGuardLogic.HasIgnoreNote(row.Notes)
        || row.Notes.Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase);

    private static bool IsHandledActivityItem(ListViewItem item)
    {
        return string.Equals(item.Text, "ignored", StringComparison.OrdinalIgnoreCase)
            || GetSubItemText(item, ColNotes).StartsWith("Handled:", StringComparison.OrdinalIgnoreCase)
            || HashGuardLogic.HasIgnoreNote(GetSubItemText(item, ColNotes))
            || GetSubItemText(item, ColNotes).Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesActivitySearch(ActivityLogRow row, string searchText)
    {
        if (string.IsNullOrWhiteSpace(searchText))
        {
            return true;
        }

        return row.Status.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.Risk.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.Trust.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.ProcessNames.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.Pids.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.Sha256.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.Path.Contains(searchText, StringComparison.OrdinalIgnoreCase)
            || row.Notes.Contains(searchText, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesActivitySearch(ListViewItem item, string searchText)
    {
        if (string.IsNullOrWhiteSpace(searchText))
        {
            return true;
        }

        return item.SubItems
            .Cast<ListViewItem.ListViewSubItem>()
            .Any(subItem => subItem.Text.Contains(searchText, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildActivityLogSummary(
        IReadOnlyCollection<ActivityLogRow> visibleRows,
        IReadOnlyCollection<ActivityLogRow> allRows,
        string searchText)
    {
        var actionNeeded = 0;
        var unknown = 0;
        var errors = 0;
        foreach (var row in allRows)
        {
            if (MatchesActivityFilter(ActivityFilter.ActionNeeded, row))
            {
                actionNeeded++;
            }

            if (MatchesActivityFilter(ActivityFilter.Unknown, row))
            {
                unknown++;
            }

            if (MatchesActivityFilter(ActivityFilter.Errors, row))
            {
                errors++;
            }
        }

        var filtered = visibleRows.Count == allRows.Count && string.IsNullOrWhiteSpace(searchText)
            ? $"{visibleRows.Count} rows"
            : $"{visibleRows.Count} of {allRows.Count} rows";
        var searchSuffix = string.IsNullOrWhiteSpace(searchText) ? "" : $" | Search: {searchText}";
        var capNote = allRows.Count >= ActivityLogMaxRows ? $" | showing latest {ActivityLogMaxRows}" : "";
        return $"{filtered}{capNote} | Action needed: {actionNeeded} | Unknown: {unknown} | Errors: {errors}{searchSuffix}";
    }

    private static ListViewItem CreateActivityListViewItem(ActivityLogRow row)
    {
        var item = new ListViewItem(row.Status);
        item.SubItems.Add(row.Risk);
        item.SubItems.Add(row.Trust);
        item.SubItems.Add(row.Malicious.ToString());
        item.SubItems.Add(row.Suspicious.ToString());
        item.SubItems.Add(row.ProcessNames);
        item.SubItems.Add(row.Pids);
        item.SubItems.Add(row.Sha256);
        item.SubItems.Add(row.Path);
        item.SubItems.Add(row.Notes);
        item.Tag = row.Link;
        ApplyResultRowColor(item);
        return item;
    }

    private static string BuildSelectedReasonSummary(ListView sourceView)
    {
        if (sourceView.SelectedItems.Count == 0)
        {
            return "Select a row to see why HashGuard flagged it and which action is safest.";
        }

        var item = sourceView.SelectedItems[0];
        return BuildReasonSummary(item);
    }

    private static string BuildReasonSummary(ListViewItem item)
    {
        var status = item.Text;
        var risk = GetSubItemText(item, ColRisk);
        var trust = GetSubItemText(item, ColTrust);
        var malicious = GetSubItemText(item, ColMalicious);
        var suspicious = GetSubItemText(item, ColSuspicious);
        var process = GetSubItemText(item, ColProcess);
        var path = GetSubItemText(item, ColPath);
        var notes = GetSubItemText(item, ColNotes);
        var reasons = new List<string>();

        if (int.TryParse(malicious, out var mal) && mal > 0)
        {
            reasons.Add($"{mal} malicious detection(s)");
        }

        if (int.TryParse(suspicious, out var susp) && susp > 0)
        {
            reasons.Add($"{susp} suspicious detection(s)");
        }

        if (risk.StartsWith("High", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("high local risk score");
        }

        if (string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, "limited access", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("cloud reputation is incomplete");
        }

        if (string.Equals(status, "error", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("one or more checks failed");
        }

        foreach (var note in notes.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (note.StartsWith("Risk:", StringComparison.OrdinalIgnoreCase)
                || note.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase)
                || note.Contains("quota", StringComparison.OrdinalIgnoreCase)
                || note.Contains("Quarantined", StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add(note.TrimEnd('.'));
            }
        }

        var reasonText = reasons.Count == 0 ? "No immediate action reason." : string.Join("; ", reasons.Distinct(StringComparer.OrdinalIgnoreCase));
        return $"Status: {status} | Risk: {risk} | Process: {process}{Environment.NewLine}Reason: {reasonText}{Environment.NewLine}Trust: {trust}{Environment.NewLine}Path: {path}";
    }

    private void ShowScanDetailsDialogSafe()
    {
        try
        {
            ShowScanDetailsDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not open Activity Log:{Environment.NewLine}{ex.Message}", "Activity Log", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // Keep Activity Log snappy: only recent files / latest rows, and cache between opens.
    private const int ActivityLogMaxFiles = 14;
    private const int ActivityLogMaxRows = 2500;
    private const long ActivityLogMaxBytesPerFile = 2L * 1024L * 1024L;
    private List<ActivityLogRow>? activityLogCache;
    private string activityLogCacheSignature = "";

    private List<ActivityLogRow> LoadActivityLogRows()
    {
        var signature = BuildActivityLogCacheSignature();
        if (activityLogCache is not null
            && string.Equals(activityLogCacheSignature, signature, StringComparison.Ordinal))
        {
            return activityLogCache;
        }

        var rows = new List<ActivityLogRow>(Math.Min(ActivityLogMaxRows, 512));
        foreach (var logDirectory in GetLogDirectories().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(logDirectory))
            {
                continue;
            }

            foreach (var logPath in Directory.EnumerateFiles(logDirectory, "scan-log-*.csv")
                         .OrderByDescending(File.GetLastWriteTimeUtc)
                         .Take(ActivityLogMaxFiles))
            {
                if (rows.Count >= ActivityLogMaxRows)
                {
                    break;
                }

                rows.AddRange(LoadActivityLogRowsFromFile(logPath, ActivityLogMaxRows - rows.Count));
            }

            if (rows.Count >= ActivityLogMaxRows)
            {
                break;
            }
        }

        activityLogCache = rows;
        activityLogCacheSignature = signature;
        return rows;
    }

    private static string BuildActivityLogCacheSignature()
    {
        var parts = new List<string>();
        foreach (var logDirectory in GetLogDirectories().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(logDirectory))
            {
                continue;
            }

            foreach (var logPath in Directory.EnumerateFiles(logDirectory, "scan-log-*.csv")
                         .OrderByDescending(File.GetLastWriteTimeUtc)
                         .Take(ActivityLogMaxFiles))
            {
                try
                {
                    var info = new FileInfo(logPath);
                    parts.Add($"{logPath}|{info.Length}|{info.LastWriteTimeUtc.Ticks}");
                }
                catch
                {
                    parts.Add(logPath);
                }
            }
        }

        return string.Join(";", parts);
    }

    private static List<ActivityLogRow> LoadActivityLogRowsFromFile(string logPath, int maxRows)
    {
        var results = new List<ActivityLogRow>();
        if (maxRows <= 0)
        {
            return results;
        }

        try
        {
            var lines = ReadActivityLogLines(logPath);
            if (lines.Count < 2)
            {
                return results;
            }

            var headers = ParseCsvLine(lines[0]);
            var columns = headers
                .Select((name, index) => new { Name = name.Trim(), Index = index })
                .ToDictionary(item => item.Name, item => item.Index, StringComparer.OrdinalIgnoreCase);

            // Newest first: walk body lines from the end.
            for (var index = lines.Count - 1; index >= 1 && results.Count < maxRows; index--)
            {
                var line = lines[index];
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var row = ParseCsvLine(line);
                var timestamp = GetCsvValue(row, columns, "timestamp");
                var notes = GetCsvValue(row, columns, "notes");
                if (!string.IsNullOrWhiteSpace(timestamp))
                {
                    notes = string.IsNullOrWhiteSpace(notes) ? timestamp : $"{timestamp}; {notes}";
                }

                var riskLevel = GetCsvValue(row, columns, "risk_level");
                var riskScore = GetCsvValue(row, columns, "risk_score");
                var risk = string.IsNullOrWhiteSpace(riskLevel) && string.IsNullOrWhiteSpace(riskScore)
                    ? ""
                    : $"{riskLevel} {riskScore}".Trim();
                _ = int.TryParse(GetCsvValue(row, columns, "malicious"), out var malicious);
                _ = int.TryParse(GetCsvValue(row, columns, "suspicious"), out var suspicious);

                results.Add(new ActivityLogRow(
                    GetCsvValue(row, columns, "status"),
                    risk,
                    GetCsvValue(row, columns, "trust"),
                    malicious,
                    suspicious,
                    GetCsvValue(row, columns, "process_names"),
                    GetCsvValue(row, columns, "pids"),
                    GetCsvValue(row, columns, "sha256"),
                    GetCsvValue(row, columns, "path"),
                    notes,
                    GetCsvValue(row, columns, "link")));
            }
        }
        catch
        {
            // A corrupt or locked log should not prevent opening the Activity Log.
        }

        return results;
    }

    /// <summary>
    /// Reads CSV lines efficiently. For large logs, only the tail is loaded so open stays fast.
    /// </summary>
    private static List<string> ReadActivityLogLines(string logPath)
    {
        var info = new FileInfo(logPath);
        if (!info.Exists || info.Length == 0)
        {
            return [];
        }

        if (info.Length <= ActivityLogMaxBytesPerFile)
        {
            return File.ReadAllLines(logPath).ToList();
        }

        // Tail-read large files: keep header + trailing chunk.
        using var stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var header = reader.ReadLine() ?? "";
        var start = Math.Max(0, info.Length - ActivityLogMaxBytesPerFile);
        stream.Seek(start, SeekOrigin.Begin);
        // Discard partial first line after seek.
        if (start > 0)
        {
            _ = reader.ReadLine();
        }

        var tail = new List<string> { header };
        while (!reader.EndOfStream)
        {
            var line = reader.ReadLine();
            if (line is not null)
            {
                tail.Add(line);
            }
        }

        return tail;
    }

    private sealed record ActivityLogRow(
        string Status,
        string Risk,
        string Trust,
        int Malicious,
        int Suspicious,
        string ProcessNames,
        string Pids,
        string Sha256,
        string Path,
        string Notes,
        string Link);

    private static string GetCsvValue(List<string> row, Dictionary<string, int> columns, string columnName)
    {
        return columns.TryGetValue(columnName, out var index) && index >= 0 && index < row.Count
            ? row[index]
            : "";
    }

    private static string GetLogDirectory() => AppPaths.GetLogDirectory();


    private static IEnumerable<string> GetLogDirectories()
    {
        yield return AppPaths.GetLogDirectory();
    }

    private static string? ParseStartupScanFile(string[] args)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], "--scan-file", StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }
}
