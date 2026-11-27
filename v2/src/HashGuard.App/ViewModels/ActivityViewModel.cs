using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using HashGuard.App.Services;
using HashGuard.Core;

namespace HashGuard.App.ViewModels;

/// <summary>"Today", "Yesterday", … above the rows of that day.</summary>
public sealed record ActivityDayHeader(string Text);

/// <summary>One row on the Activity page.</summary>
public sealed partial class ActivityItemViewModel(ActivityEntry entry, int foldedCount) : ObservableObject
{
    public ActivityEntry Entry { get; } = entry;

    public ActivityItemViewModel Self => this;

    public ActivityKind Kind => Entry.Kind;

    public string Title => Entry.Title;

    public string Detail => Entry.Detail;

    public string Pill => Entry.Pill;

    public string TimeText => Entry.When?.ToString("HH:mm", CultureInfo.CurrentCulture) ?? "";

    public bool IsSummary => Entry.Summary;

    public bool HasDetails => !Entry.Summary;

    /// <summary>For a batch summary: whether its clean rows are shown.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FoldText))]
    public partial bool IsBatchOpen { get; set; }

    [ObservableProperty] public partial bool IsExpanded { get; set; }

    public string FoldText => IsBatchOpen
        ? "Hide clean files"
        : foldedCount == 1 ? "Show 1 clean file" : $"Show {foldedCount.ToString("N0", CultureInfo.CurrentCulture)} clean files";

    public bool CanFold => Entry.Summary && foldedCount > 0;

    public bool CanShowInFolder => !string.IsNullOrWhiteSpace(Entry.Path) && File.Exists(ActivityText.FriendlyPath(Entry.Path));

    public string Glyph => Entry.Summary ? "" : Kind switch
    {
        ActivityKind.Threat => "",
        ActivityKind.Suspicious => "",
        ActivityKind.Unknown => "",
        ActivityKind.Error => "",
        ActivityKind.Firewall => "",
        ActivityKind.Quarantine => "",
        _ => "",
    };

    /// <summary>Everything known about the row, shown under Details.</summary>
    public string DetailText
    {
        get
        {
            var lines = new List<string>();
            if (Entry.When is { } when)
            {
                lines.Add(when.ToString("dddd d MMMM yyyy, HH:mm:ss", CultureInfo.CurrentCulture));
            }

            if (Entry.Row is { } row)
            {
                lines.Add(ActivityText.FriendlyTrust(row.Trust));
                lines.AddRange(row.ProviderResults.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
                if (row.RiskLevel.Length > 0)
                {
                    lines.Add($"Risk score {row.RiskScore} ({row.RiskLevel})");
                }

                if (row.ProcessNames.Length > 0)
                {
                    lines.Add($"Process: {row.ProcessNames}{(row.Pids is "" or "0" ? "" : $" (PID {row.Pids})")}");
                }

                lines.Add(ActivityText.FriendlyPath(row.Path));
                if (row.Sha256.Length > 0)
                {
                    lines.Add($"SHA-256 {row.Sha256}");
                }

                lines.Add(row.Notes);
            }
            else if (Entry.Quarantine is { } q)
            {
                lines.Add($"From {q.OriginalPath}");
                lines.Add($"Stored as {q.QuarantinePath}");
                if (q.Sha256.Length > 0)
                {
                    lines.Add($"SHA-256 {q.Sha256}");
                }
            }
            else
            {
                lines.Add(Entry.Detail);
            }

            return string.Join(Environment.NewLine, lines.Where(line => !string.IsNullOrWhiteSpace(line)));
        }
    }
}

/// <summary>
/// The Activity page: the timeline of checks, quarantine and firewall actions, newest first,
/// grouped by day, with filters and search. Reading happens off the UI thread.
/// </summary>
public sealed partial class ActivityViewModel : ObservableObject
{
    private readonly HashSet<int> openBatches = [];
    private readonly Dictionary<ActivityEntry, ActivityItemViewModel> items = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<string, ActivityDayHeader> headers = [];
    private IReadOnlyList<ActivityEntry> entries = [];
    private int loadVersion;

    /// <summary>Day headers and rows, in order.</summary>
    public ObservableCollection<object> Rows { get; } = [];

    [ObservableProperty] public partial ActivityShow Show { get; set; }
    [ObservableProperty] public partial string Search { get; set; } = "";
    [ObservableProperty] public partial bool IsLoading { get; set; }
    [ObservableProperty] public partial bool IsEmpty { get; set; }
    [ObservableProperty] public partial string EmptyText { get; set; } = "";
    [ObservableProperty] public partial string NeedsActionCount { get; set; } = "";

    partial void OnShowChanged(ActivityShow value) => Rebuild(keepPosition: false);

    partial void OnSearchChanged(string value) => Rebuild(keepPosition: false);

    /// <summary>Reads the history again. Rows keep their place when nothing changed above them.</summary>
    public async Task LoadAsync()
    {
        var version = ++loadVersion;
        IsLoading = entries.Count == 0;
        var services = AppServices.Instance;
        var loaded = await Task.Run(() =>
        {
            var rows = services.ActivityLog.Read();
            var quarantine = services.Quarantine.Entries;
            var quarantined = new HashSet<string>(quarantine.Select(entry => entry.OriginalPath), StringComparer.OrdinalIgnoreCase);
            var hashes = services.IgnoreList.Hashes;
            var paths = services.IgnoreList.Paths;
            return ActivityFeed.Build(rows, quarantine, ActivityFeed.ReadFirewallLines(), row => ActivityFeed.IsHandled(row, hashes, paths, quarantined));
        });

        if (version != loadVersion)
        {
            return; // A newer load started meanwhile.
        }

        entries = loaded;
        items.Clear();
        var needsAction = loaded.Count(ActivityFeed.NeedsAction);
        NeedsActionCount = needsAction == 0 ? "" : needsAction.ToString("N0", CultureInfo.CurrentCulture);
        IsLoading = false;
        Rebuild(keepPosition: false);
    }

    /// <summary>Shows or hides the clean rows of a scan batch.</summary>
    public void ToggleBatch(ActivityItemViewModel summary)
    {
        if (!openBatches.Remove(summary.Entry.BatchId))
        {
            openBatches.Add(summary.Entry.BatchId);
        }

        summary.IsBatchOpen = openBatches.Contains(summary.Entry.BatchId);
        Rebuild(keepPosition: true);
    }

    private void Rebuild(bool keepPosition)
    {
        var visible = ActivityFeed.Visible(entries, Show, Search, openBatches);
        var target = new List<object>(visible.Count + 16);
        var today = DateTime.Today;
        string? lastDay = null;
        foreach (var entry in visible)
        {
            var day = entry.When is { } when ? ActivityText.DayHeader(when.Date, today) : "Earlier";
            if (day != lastDay)
            {
                if (!headers.TryGetValue(day, out var header))
                {
                    header = new ActivityDayHeader(day);
                    headers[day] = header;
                }

                target.Add(header);
                lastDay = day;
            }

            target.Add(ItemFor(entry));
        }

        if (keepPosition)
        {
            Sync(target);
        }
        else
        {
            Rows.Clear();
            foreach (var row in target)
            {
                Rows.Add(row);
            }
        }

        IsEmpty = visible.Count == 0;
        EmptyText = entries.Count == 0
            ? "No activity yet. Scans, quarantined files and firewall actions show up here."
            : "Nothing matches.";
    }

    private ActivityItemViewModel ItemFor(ActivityEntry entry)
    {
        if (!items.TryGetValue(entry, out var item))
        {
            var folded = entry.Summary ? entries.Count(e => e.Folded && e.BatchId == entry.BatchId) : 0;
            item = new ActivityItemViewModel(entry, folded) { IsBatchOpen = entry.Summary && openBatches.Contains(entry.BatchId) };
            items[entry] = item;
        }

        return item;
    }

    /// <summary>Turns <see cref="Rows"/> into <paramref name="target"/> with inserts and removals only, so the list keeps its scroll position.</summary>
    private void Sync(List<object> target)
    {
        var wanted = new HashSet<object>(target, ReferenceEqualityComparer.Instance);
        for (var i = Rows.Count - 1; i >= 0; i--)
        {
            if (!wanted.Contains(Rows[i]))
            {
                Rows.RemoveAt(i);
            }
        }

        for (var i = 0; i < target.Count; i++)
        {
            if (i >= Rows.Count || !ReferenceEquals(Rows[i], target[i]))
            {
                Rows.Insert(i, target[i]);
            }
        }
    }
}
