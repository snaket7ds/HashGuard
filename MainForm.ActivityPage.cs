using System.Drawing;
using System.Globalization;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// The Activity page as designed: filter chips with counts, search, and one history grouped by
/// day that mixes file checks, quarantines and firewall blocks. Double-click or Enter opens the
/// details; right-click (or the menu key) offers the actions the old Activity Log had.
/// </summary>
public sealed partial class MainForm : Form
{
    private sealed record ActivityEntry(DateTime? When, ActivityKind Kind, string Title, string Detail, string Pill, ActivityLogRow? Row, string Path);

    private Control BuildActivityPage()
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };
        var entries = new List<ActivityEntry>();
        var filter = ActivityFilter.All;
        var loadGeneration = 0;

        var chipAll = new ChipButton("All");
        var chipAction = new ChipButton("Action needed");
        var chipUnknown = new ChipButton("Unknown");
        var chipClean = new ChipButton("Clean");
        var chipErrors = new ChipButton("Errors");
        var chips = new[] { (chipAll, ActivityFilter.All), (chipAction, ActivityFilter.ActionNeeded), (chipUnknown, ActivityFilter.Unknown), (chipClean, ActivityFilter.Clean), (chipErrors, ActivityFilter.Errors) };
        var search = new TextBox { Width = 280, PlaceholderText = "Search files, apps or hashes", AccessibleName = "Search activity", Margin = new Padding(0, 6, 10, 0), Font = new Font("Segoe UI", 10, FontStyle.Regular) };
        var export = new Button { Text = "Export report", AutoSize = true, Height = 36, Margin = new Padding(0, 4, 8, 0) };
        var openLogs = new Button { Text = "Open logs", AutoSize = true, Height = 36, Margin = new Padding(0, 4, 0, 0), Tag = "quiet-button" };
        export.Click += (_, _) => ExportScanReport();
        openLogs.Click += (_, _) => OpenLogFolder();

        var bar = new TableLayoutPanel { Dock = DockStyle.Top, Height = 52, ColumnCount = 2, RowCount = 1, Margin = new Padding(0), BackColor = SoftAppBack };
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var chipFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0), BackColor = SoftAppBack };
        foreach (var (chip, _) in chips)
        {
            chip.Margin = new Padding(0, 4, 8, 0);
            chipFlow.Controls.Add(chip);
        }

        var rightFlow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0), BackColor = SoftAppBack };
        rightFlow.Controls.AddRange([search, export, openLogs]);
        bar.Controls.Add(chipFlow, 0, 0);
        bar.Controls.Add(rightFlow, 1, 0);

        var list = new CardList { Dock = DockStyle.Fill, EmptyText = "Loading activity…", AccessibleName = "Activity history" };
        var card = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(1, 1, 1, 4) };
        card.Controls.Add(list);
        var spacer = new Panel { Dock = DockStyle.Top, Height = 12, BackColor = SoftAppBack };
        page.Controls.Add(card);
        page.Controls.Add(spacer);
        page.Controls.Add(bar);

        // The existing row actions read a ListView; one hidden, single-row proxy feeds them.
        var proxy = new ListView { View = View.Details, Size = new Size(1, 1), Location = new Point(-10, -10), TabStop = false };
        ConfigureResultsView(proxy);
        proxy.Dock = DockStyle.None;
        page.Controls.Add(proxy);

        bool WithProxy(ActivityEntry entry)
        {
            if (entry.Row is null)
            {
                return false;
            }

            proxy.Items.Clear();
            var item = CreateActivityListViewItem(entry.Row);
            proxy.Items.Add(item);
            item.Selected = true;
            return true;
        }

        bool Matches(ActivityEntry entry, ActivityFilter which) => which switch
        {
            ActivityFilter.All => true,
            ActivityFilter.ActionNeeded => entry.Kind is ActivityKind.Threat or ActivityKind.Suspicious or ActivityKind.Unknown or ActivityKind.Error,
            ActivityFilter.Unknown => entry.Kind == ActivityKind.Unknown,
            ActivityFilter.Clean => entry.Kind == ActivityKind.Clean,
            ActivityFilter.Errors => entry.Kind == ActivityKind.Error,
            _ => true,
        };

        void Render()
        {
            foreach (var (chip, which) in chips)
            {
                chip.SetState(entries.Count(entry => Matches(entry, which)).ToString("N0", CultureInfo.CurrentCulture), which == filter);
            }

            var query = search.Text.Trim();
            var shown = entries
                .Where(entry => Matches(entry, filter))
                .Where(entry => query.Length == 0
                    || entry.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || entry.Detail.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || entry.Path.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || (entry.Row?.Sha256.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false));
            var items = new List<CardListItem>();
            string? currentDay = null;
            var today = DateTime.Now;
            foreach (var entry in shown)
            {
                var day = entry.When is { } when ? ActivityText.DayHeader(when, today) : "Earlier";
                if (day != currentDay)
                {
                    items.Add(new CardListItem { IsHeader = true, Header = day });
                    currentDay = day;
                }

                var (glyph, tone) = entry.Kind switch
                {
                    ActivityKind.Threat => ("!", CardTone.Bad),
                    ActivityKind.Suspicious => ("!", CardTone.Warn),
                    ActivityKind.Unknown => ("?", CardTone.Warn),
                    ActivityKind.Error => ("×", CardTone.Neutral),
                    ActivityKind.Handled => ("–", CardTone.Neutral),
                    ActivityKind.Firewall => ("", CardTone.Blue),
                    ActivityKind.Quarantine => ("", CardTone.Bad),
                    _ => ("✓", CardTone.Good),
                };
                items.Add(new CardListItem
                {
                    Glyph = glyph,
                    Tone = tone,
                    Title = entry.Title,
                    Detail = entry.Detail,
                    Pill = entry.Pill,
                    Trailing = entry.When is { } at ? at.ToString("HH:mm", CultureInfo.CurrentCulture) : "",
                    Tag = entry,
                });
            }

            list.EmptyText = entries.Count == 0 ? "No activity yet. Scans, blocks and alerts will show up here." : "Nothing here for this filter.";
            list.SetItems(items);
        }

        async Task LoadAsync()
        {
            var generation = ++loadGeneration;
            try
            {
                var rows = await Task.Run(LoadActivityLogRows).ConfigureAwait(true);
                var networkLines = await Task.Run(ReadNetworkActionLines).ConfigureAwait(true);
                var quarantine = LoadQuarantineManifest();
                if (page.IsDisposed || generation != loadGeneration)
                {
                    return;
                }

                entries.Clear();
                entries.AddRange(BuildActivityEntries(rows, networkLines, quarantine));
                Render();
            }
            catch (Exception ex)
            {
                if (!page.IsDisposed)
                {
                    list.EmptyText = $"Could not load activity: {ex.Message}";
                    list.SetItems([]);
                }
            }
        }

        var menu = new ContextMenuStrip();
        var menuDetails = menu.Items.Add("Details…", null, (_, _) => ShowActivityDetails(list.SelectedItem?.Tag as ActivityEntry, WithProxy));
        menu.Items.Add(new ToolStripSeparator());
        var menuReport = menu.Items.Add("Open VirusTotal report", null, (_, _) => { if (list.SelectedItem?.Tag is ActivityEntry e && WithProxy(e)) { OpenSelectedReport(proxy); } });
        var menuLocation = menu.Items.Add("Open file location", null, (_, _) =>
        {
            if (list.SelectedItem?.Tag is ActivityEntry e && File.Exists(e.Path))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"/select,\"{e.Path}\"") { UseShellExecute = true });
            }
        });
        var menuHash = menu.Items.Add("Copy hash", null, (_, _) => { if (list.SelectedItem?.Tag is ActivityEntry e && WithProxy(e)) { CopySelectedHash(proxy); } });
        var menuSummary = menu.Items.Add("Copy summary", null, (_, _) => { if (list.SelectedItem?.Tag is ActivityEntry e && WithProxy(e)) { CopySelectedReportSummary(proxy); } });
        menu.Items.Add(new ToolStripSeparator());
        var menuIgnore = menu.Items.Add("Ignore", null, async (_, _) =>
        {
            if (list.SelectedItem?.Tag is ActivityEntry e && WithProxy(e))
            {
                ToggleSelectedIgnoreFlagWithConfirm(proxy);
                await LoadAsync();
            }
        });
        var menuQuarantine = menu.Items.Add("Quarantine", null, async (_, _) =>
        {
            if (list.SelectedItem?.Tag is ActivityEntry e && WithProxy(e))
            {
                QuarantineSelectedFiles(proxy);
                await LoadAsync();
            }
        });
        var menuKill = menu.Items.Add("Stop the running process", null, (_, _) => { if (list.SelectedItem?.Tag is ActivityEntry e && WithProxy(e)) { KillSelectedProcesses(proxy); } });
        menu.Opening += (_, args) =>
        {
            var entry = list.SelectedItem?.Tag as ActivityEntry;
            var hasRow = entry?.Row is not null;
            var exists = entry is not null && File.Exists(entry.Path);
            if (entry is null)
            {
                args.Cancel = true;
                return;
            }

            menuDetails.Enabled = true;
            menuReport.Enabled = hasRow && !string.IsNullOrWhiteSpace(entry.Row!.Link);
            menuLocation.Enabled = exists;
            menuHash.Enabled = hasRow && !string.IsNullOrWhiteSpace(entry.Row!.Sha256);
            menuSummary.Enabled = hasRow;
            menuIgnore.Enabled = hasRow;
            menuQuarantine.Enabled = hasRow && exists;
            menuKill.Enabled = hasRow && !string.IsNullOrWhiteSpace(entry.Row!.Pids) && entry.Row.Pids != "0";
        };
        list.MenuRequested += point => menu.Show(list, point);
        list.ItemActivated += (_, _) => ShowActivityDetails(list.SelectedItem?.Tag as ActivityEntry, WithProxy);

        foreach (var (chip, which) in chips)
        {
            chip.Click += (_, _) =>
            {
                filter = which;
                Render();
            };
        }

        var debounce = new System.Windows.Forms.Timer { Interval = 200 };
        debounce.Tick += (_, _) =>
        {
            debounce.Stop();
            Render();
        };
        search.TextChanged += (_, _) =>
        {
            debounce.Stop();
            debounce.Start();
        };
        page.HandleCreated += async (_, _) => await LoadAsync();
        page.Disposed += (_, _) =>
        {
            debounce.Dispose();
            menu.Dispose();
        };
        page.ParentChanged += (_, _) => list.ApplyPalette(activePalette);
        list.ApplyPalette(activePalette);
        return page;
    }

    private static List<string> ReadNetworkActionLines()
    {
        try
        {
            var path = GetNetworkActionLogPath();
            return File.Exists(path) ? File.ReadLines(path).Reverse().Take(1000).ToList() : [];
        }
        catch
        {
            return [];
        }
    }

    private static IEnumerable<ActivityEntry> BuildActivityEntries(List<ActivityLogRow> rows, List<string> networkLines, List<QuarantineEntry> quarantine)
    {
        var all = new List<ActivityEntry>();
        foreach (var row in rows)
        {
            var name = ActivityText.DisplayName(row.ProcessNames, row.Path);
            var description = ActivityText.Describe(row.Status, row.Malicious, row.Suspicious, IsHandledActivityRow(row), name);
            var trust = string.IsNullOrWhiteSpace(row.Trust) ? "" : row.Trust + " · ";
            all.Add(new ActivityEntry(ActivityText.ParseTimestamp(row.Timestamp), description.Kind, description.Title, trust + row.Path, description.Pill, row, row.Path));
        }

        foreach (var line in networkLines)
        {
            var parts = line.Split('\t');
            if (parts.Length < 3)
            {
                continue;
            }

            var file = NetworkActivityTracker.DisplayName(parts[2]);
            var action = parts[1];
            var title = action.StartsWith("Unblocked", StringComparison.OrdinalIgnoreCase)
                ? $"{file} can connect again"
                : action.StartsWith("Auto-blocked", StringComparison.OrdinalIgnoreCase)
                    ? $"Auto-blocked {file}"
                    : action.StartsWith("Blocked", StringComparison.OrdinalIgnoreCase)
                        ? $"Blocked {file} in Windows Firewall"
                        : $"{action}: {file}";
            all.Add(new ActivityEntry(ActivityText.ParseTimestamp(parts[0]), ActivityKind.Firewall, title, $"{action} · {parts[2]}", "Firewall", null, parts[2]));
        }

        foreach (var entry in quarantine.Where(entry => entry.QuarantinedAtUtc != default))
        {
            var file = System.IO.Path.GetFileName(entry.OriginalPath);
            all.Add(new ActivityEntry(entry.QuarantinedAtUtc.LocalDateTime, ActivityKind.Quarantine, $"Quarantined {file}", $"From {entry.OriginalPath}", "Quarantine", null, entry.OriginalPath));
        }

        return all.OrderByDescending(entry => entry.When ?? DateTime.MinValue);
    }

    private void ShowActivityDetails(ActivityEntry? entry, Func<ActivityEntry, bool> selectInProxy)
    {
        if (entry is null)
        {
            return;
        }

        var lines = new List<string> { entry.Title, entry.Pill, "" };
        if (entry.Row is { } row)
        {
            lines.AddRange(new[]
            {
                $"Status: {row.Status} · risk {row.Risk}",
                $"Detections: {row.Malicious} malicious, {row.Suspicious} suspicious",
                $"Trust: {(string.IsNullOrWhiteSpace(row.Trust) ? "—" : row.Trust)}",
                $"Process: {(string.IsNullOrWhiteSpace(row.ProcessNames) ? "—" : row.ProcessNames)}{(string.IsNullOrWhiteSpace(row.Pids) || row.Pids == "0" ? "" : $" (PID {row.Pids})")}",
                $"Location: {row.Path}",
                $"SHA-256: {row.Sha256}",
                $"When: {(entry.When is { } when ? when.ToString("f", CultureInfo.CurrentCulture) : "unknown")}",
                "",
                "Notes",
                string.IsNullOrWhiteSpace(row.Notes) ? "—" : row.Notes,
            });
        }
        else
        {
            lines.Add(entry.Detail);
            lines.Add($"When: {(entry.When is { } when ? when.ToString("f", CultureInfo.CurrentCulture) : "unknown")}");
        }

        using var dialog = new Form
        {
            Text = "Activity details",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(640, 520),
            MinimumSize = new Size(480, 360),
            ShowInTaskbar = false,
            MinimizeBox = false,
        };
        var text = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 10, FontStyle.Regular), Text = string.Join(Environment.NewLine, lines) };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 52, Padding = new Padding(12, 10, 12, 8), WrapContents = false };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.OK };
        buttons.Controls.Add(close);
        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18, 16, 18, 8) };
        body.Controls.Add(text);
        dialog.Controls.Add(body);
        dialog.Controls.Add(buttons);
        dialog.AcceptButton = close;
        ApplyAppTheme(dialog);
        text.BackColor = activePalette.Surface;
        text.ForeColor = activePalette.Text;
        dialog.ShowDialog(this);
    }
}
