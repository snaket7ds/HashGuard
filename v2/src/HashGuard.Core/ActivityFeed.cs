using System.Globalization;

namespace HashGuard.Core;

/// <summary>
/// One row on the Activity page. <see cref="Summary"/> rows stand for a batch of checks;
/// <see cref="Folded"/> rows are the clean checks inside a batch, hidden unless it is expanded.
/// </summary>
public sealed record ActivityEntry(
    DateTime? When,
    ActivityKind Kind,
    string Title,
    string Detail,
    string Pill,
    string Path,
    ActivityLogRow? Row = null,
    QuarantineEntry? Quarantine = null,
    bool Summary = false,
    bool Folded = false,
    int BatchId = 0);

/// <summary>The Activity page's filter buttons.</summary>
public enum ActivityShow
{
    All,
    NeedsAction,
    Unknown,
    Actions,
}

/// <summary>
/// Turns the scan history, quarantine list and firewall log into the Activity timeline. Pure, so
/// it is unit-tested.
/// </summary>
public static class ActivityFeed
{
    /// <summary>Checks closer together than this belong to the same batch.</summary>
    public static readonly TimeSpan BatchGap = TimeSpan.FromMinutes(3);

    /// <summary>
    /// The rows to show. With "All" and no search, batches show as their summary and their clean
    /// rows stay folded unless the batch is in <paramref name="expandedBatches"/>. Any other
    /// filter or a search lists matching rows on their own, folded ones included, without summaries.
    /// </summary>
    public static List<ActivityEntry> Visible(IReadOnlyList<ActivityEntry> entries, ActivityShow show, string? search, IReadOnlySet<int> expandedBatches)
    {
        var query = search?.Trim() ?? "";
        if (show == ActivityShow.All && query.Length == 0)
        {
            return [.. entries.Where(entry => !entry.Folded || expandedBatches.Contains(entry.BatchId))];
        }

        return [.. entries.Where(entry => !entry.Summary && Matches(entry, show) && (query.Length == 0 || Contains(entry, query)))];
    }

    /// <summary>A check the user should still look at: flagged, failed or high risk, and not handled.</summary>
    public static bool NeedsAction(ActivityEntry entry) =>
        entry.Row is { } row
        && entry.Kind != ActivityKind.Handled
        && HashGuardLogic.NeedsAction(row.Status, $"{row.RiskLevel} {row.RiskScore}", row.Malicious, row.Suspicious);

    private static bool Matches(ActivityEntry entry, ActivityShow show) => show switch
    {
        ActivityShow.NeedsAction => NeedsAction(entry),
        ActivityShow.Unknown => entry.Kind == ActivityKind.Unknown,
        ActivityShow.Actions => entry.Kind is ActivityKind.Quarantine or ActivityKind.Firewall,
        _ => true,
    };

    private static bool Contains(ActivityEntry entry, string query)
    {
        bool Has(string? value) => value?.Contains(query, StringComparison.OrdinalIgnoreCase) == true;
        return Has(entry.Title) || Has(entry.Detail) || Has(entry.Path) || Has(entry.Pill)
            || (entry.Row is { } row && (Has(row.Sha256) || Has(row.ProcessNames) || Has(row.Notes)))
            || (entry.Quarantine is { } q && Has(q.Sha256));
    }

    /// <summary>
    /// Whether a logged check was dealt with: ignored at the time, or marked handled, or its file
    /// or hash is now on the ignore list, or the file was quarantined.
    /// </summary>
    public static bool IsHandled(
        ActivityLogRow row,
        IReadOnlySet<string> ignoredHashes,
        IReadOnlySet<string> ignoredPaths,
        IReadOnlySet<string> quarantinedPaths) =>
        HashGuardLogic.IsIgnoredStatus(row.Status)
        || row.Notes.StartsWith("Handled:", StringComparison.OrdinalIgnoreCase)
        || HashGuardLogic.HasIgnoreNote(row.Notes)
        || HashGuardLogic.NoteIndicatesQuarantined(row.Notes)
        || (row.Sha256.Length > 0 && ignoredHashes.Contains(row.Sha256))
        || (row.Path.Length > 0 && (ignoredPaths.Contains(row.Path) || quarantinedPaths.Contains(row.Path)));

    public static List<ActivityEntry> Build(
        IEnumerable<ActivityLogRow> rows,
        IEnumerable<QuarantineEntry> quarantine,
        IEnumerable<string> firewallLines,
        Func<ActivityLogRow, bool> isHandled)
    {
        var all = new List<ActivityEntry>();
        var checks = rows.Select(row =>
        {
            var name = ActivityText.DisplayName(row.ProcessNames, row.Path);
            var description = ActivityText.Describe(row.Status, row.Malicious, row.Suspicious, isHandled(row), name);
            var detail = string.Join(" · ", new[] { ActivityText.FriendlyTrust(row.Trust), ActivityText.FriendlyPath(row.Path) }.Where(part => part.Length > 0));
            return new ActivityEntry(row.When, description.Kind, description.Title, detail, description.Pill, row.Path, Row: row);
        }).ToList();

        all.AddRange(checks.Where(entry => entry.When is null));
        AddBatches(all, checks.Where(entry => entry.When is not null).OrderBy(entry => entry.When).ToList());

        foreach (var line in firewallLines)
        {
            if (ParseFirewallLine(line) is { } entry)
            {
                all.Add(entry);
            }
        }

        foreach (var entry in quarantine.Where(entry => entry.QuarantinedAtUtc != default))
        {
            var file = HashGuardLogic.QuarantineDisplayName(entry);
            all.Add(new ActivityEntry(entry.QuarantinedAtUtc.LocalDateTime, ActivityKind.Quarantine, $"Quarantined {file}", $"From {entry.OriginalPath}", "Quarantine", entry.OriginalPath, Quarantine: entry));
        }

        // Newest first; within a batch the summary comes before the checks it stands for.
        return [.. all
            .Select((entry, index) => (entry, index))
            .OrderByDescending(item => item.entry.When ?? DateTime.MinValue)
            .ThenByDescending(item => item.entry.Summary)
            .ThenBy(item => item.index)
            .Select(item => item.entry)];
    }

    /// <summary>
    /// Groups checks into batches (a scan, or files opened in a burst). A batch of two or more
    /// with clean files gets a summary row ("184 files checked · 182 clean · 1 unknown") and its
    /// clean rows are folded into it; anything unknown, flagged or failed keeps its own row.
    /// </summary>
    private static void AddBatches(List<ActivityEntry> all, List<ActivityEntry> timed)
    {
        var batch = new List<ActivityEntry>();
        var batchId = 0;

        void Flush()
        {
            var clean = batch.Count(entry => entry.Kind == ActivityKind.Clean);
            if (batch.Count >= 2 && clean > 0)
            {
                batchId++;
                var flagged = batch.Count(entry => entry.Kind is ActivityKind.Threat or ActivityKind.Suspicious);
                var unknown = batch.Count(entry => entry.Kind == ActivityKind.Unknown);
                var errors = batch.Count(entry => entry.Kind == ActivityKind.Error);
                var started = batch[0].When!.Value;
                var finished = batch[^1].When!.Value;
                var span = finished - started >= TimeSpan.FromMinutes(1) ? $" · {started:HH:mm}–{finished:HH:mm}" : "";
                var title = $"{batch.Count.ToString("N0", CultureInfo.CurrentCulture)} files checked";
                var kind = flagged > 0 ? ActivityKind.Suspicious : unknown + errors > 0 ? ActivityKind.Unknown : ActivityKind.Clean;
                all.Add(new ActivityEntry(finished, kind, title, ActivityText.BatchSummary(clean, unknown, flagged, errors) + span, "Scan", "", Summary: true, BatchId: batchId));
                all.AddRange(batch.Select(entry => entry with { Folded = entry.Kind == ActivityKind.Clean, BatchId = batchId }));
            }
            else
            {
                all.AddRange(batch);
            }

            batch.Clear();
        }

        foreach (var entry in timed)
        {
            if (batch.Count > 0 && entry.When - batch[^1].When > BatchGap)
            {
                Flush();
            }

            batch.Add(entry);
        }

        Flush();
    }

    /// <summary>A line of <c>network-actions.log</c>: "time\taction\tpath".</summary>
    internal static ActivityEntry? ParseFirewallLine(string line)
    {
        var parts = line.Split('\t');
        if (parts.Length < 3)
        {
            return null;
        }

        var file = NetworkActivityTracker.DisplayName(parts[2]);
        var action = parts[1];
        var title = action.StartsWith("Unblocked", StringComparison.OrdinalIgnoreCase) ? $"{file} can connect again"
            : action.StartsWith("Auto-blocked", StringComparison.OrdinalIgnoreCase) ? $"Auto-blocked {file}"
            : action.StartsWith("Blocked", StringComparison.OrdinalIgnoreCase) ? $"Blocked {file} in Windows Firewall"
            : $"{action}: {file}";
        return new ActivityEntry(ActivityText.ParseTimestamp(parts[0]), ActivityKind.Firewall, title, $"{action} · {parts[2]}", "Firewall", parts[2]);
    }

    /// <summary>The newest 1,000 lines of the firewall action log, or none.</summary>
    public static List<string> ReadFirewallLines(string? path = null)
    {
        try
        {
            path ??= AppPaths.GetNetworkActionLogPath();
            return File.Exists(path) ? [.. File.ReadLines(path).Reverse().Take(1000)] : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
