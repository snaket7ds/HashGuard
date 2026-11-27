using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// The Firewall page as designed: three stat cards and the mode switch, then the app list (letter
/// avatar, publisher and host, verdict label, an on/off switch that allows or blocks the app) and a
/// detail card for the selected app. Block/Unblock, scanning and the data are the v1.0.74 code.
/// </summary>
public sealed partial class MainForm : Form
{
    private enum FirewallFilter
    {
        All,
        Online,
        Blocked,
        NeedsLook,
    }

    private Control BuildFirewallPage()
    {
        EnsureNetworkTracker();
        ReloadNetworkBlockedPaths();
        var elevated = IsRunningElevated();
        var filter = FirewallFilter.All;
        var page = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };

        // Stat cards + mode switch.
        var statOnline = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 38, Font = new Font("Segoe UI Semibold", 18, FontStyle.Regular), UseMnemonic = false };
        var statBlocked = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 38, Font = new Font("Segoe UI Semibold", 18, FontStyle.Regular), UseMnemonic = false };
        var statLook = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 38, Font = new Font("Segoe UI Semibold", 18, FontStyle.Regular), UseMnemonic = false };
        CardPanel StatCard(string caption, Label value)
        {
            var card = new CardPanel { Dock = DockStyle.Fill, Radius = 16, Padding = new Padding(20, 12, 20, 10) };
            card.Controls.Add(value);
            card.Controls.Add(new Label { Text = caption, AutoSize = false, Dock = DockStyle.Top, Height = 20, Tag = "muted", UseMnemonic = false });
            return card;
        }

        var stats = new TableLayoutPanel { Dock = DockStyle.Top, Height = 86, ColumnCount = 4, RowCount = 1, Margin = new Padding(0), BackColor = SoftAppBack };
        for (var column = 0; column < 3; column++)
        {
            stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 3));
        }

        stats.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var onlineCard = StatCard("Online now", statOnline);
        var blockedCard = StatCard("Blocked", statBlocked);
        var lookCard = StatCard("Needs a look", statLook);
        onlineCard.Margin = new Padding(0, 0, 8, 0);
        blockedCard.Margin = new Padding(4, 0, 4, 0);
        lookCard.Margin = new Padding(8, 0, 16, 0);
        stats.Controls.Add(onlineCard, 0, 0);
        stats.Controls.Add(blockedCard, 1, 0);
        stats.Controls.Add(lookCard, 2, 0);
        var mode = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Anchor = AnchorStyles.Top | AnchorStyles.Right, Margin = new Padding(0, 4, 0, 0), BackColor = SoftAppBack };
        var modeMonitor = new ChipButton("Monitor") { AccessibleDescription = "Current firewall mode" };
        var modeAsk = new ChipButton("Ask first · Soon") { Enabled = false, Margin = new Padding(6, 0, 0, 0) };
        modeMonitor.SetState("", true);
        modeAsk.SetState("", false);
        toolTip.SetToolTip(modeAsk, "Coming in a later version: ask before an app connects for the first time.");
        mode.Controls.AddRange([modeMonitor, modeAsk]);
        stats.Controls.Add(mode, 3, 0);

        // Banner for anything that stops blocking from working.
        var bannerText = new List<string>();
        var firewallState = FirewallRules.GetProfileState();
        if (!firewallState.AllActiveProfilesEnabled)
        {
            bannerText.Add(firewallState.Description);
        }

        if (!elevated)
        {
            bannerText.Add("HashGuard isn't running elevated, so it can't block or unblock apps. Turn on Settings → Behavior → Run elevated.");
        }

        if (!appSettings.NetworkMonitorEnabled)
        {
            bannerText.Add("Background monitoring is off: HashGuard only watches while this page is open. Turn it on in Settings → Firewall.");
        }

        var banner = new Label
        {
            Text = string.Join(Environment.NewLine, bannerText),
            Dock = DockStyle.Top,
            AutoSize = false,
            Height = bannerText.Count == 0 ? 0 : 18 + 20 * bannerText.Count,
            Padding = new Padding(12, 8, 12, 8),
            BackColor = Color.FromArgb(255, 241, 214),
            ForeColor = Color.FromArgb(122, 79, 0),
            Visible = bannerText.Count > 0,
            Tag = "warn-banner",
            UseMnemonic = false,
        };

        // App list card.
        var search = new TextBox { Width = 260, PlaceholderText = "Search apps, publishers or hosts", AccessibleName = "Search apps", Margin = new Padding(0, 6, 10, 0), Font = new Font("Segoe UI", 10, FontStyle.Regular) };
        var chipAll = new ChipButton("All");
        var chipOnline = new ChipButton("Online");
        var chipBlocked = new ChipButton("Blocked");
        var chipLook = new ChipButton("Needs a look");
        var chips = new[] { (chipAll, FirewallFilter.All), (chipOnline, FirewallFilter.Online), (chipBlocked, FirewallFilter.Blocked), (chipLook, FirewallFilter.NeedsLook) };
        var listBar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 52, WrapContents = false, Padding = new Padding(16, 6, 16, 0), BackColor = Color.White, Tag = "surface" };
        listBar.Controls.Add(search);
        foreach (var (chip, _) in chips)
        {
            chip.Margin = new Padding(0, 4, 6, 0);
            listBar.Controls.Add(chip);
        }

        var list = new CardList { Dock = DockStyle.Fill, AccessibleName = "Apps using the network", EmptyText = "Watching for connections…" };
        var listCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10), Margin = new Padding(0, 0, 9, 0) };
        listCard.Controls.Add(list);
        listCard.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, Tag = "hairline" });
        listCard.Controls.Add(listBar);

        // Detail card for the selected app.
        var detailName = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 30, Font = new Font("Segoe UI Semibold", 13, FontStyle.Regular), AutoEllipsis = true, UseMnemonic = false };
        var detailPill = new PillLabel { AutoSize = false, Height = 24, Width = 120, Radius = 12, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Regular) };
        var detailPillRow = new Panel { Dock = DockStyle.Top, Height = 30, BackColor = Color.Transparent };
        detailPillRow.Controls.Add(detailPill);
        var detailPath = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 40, Tag = "muted", UseMnemonic = false };
        // Facts as a two-column list (muted names, values on the right), as designed.
        var detailFacts = new TableLayoutPanel { Dock = DockStyle.Top, Height = 112, ColumnCount = 2, RowCount = 4, BackColor = Color.Transparent, Margin = new Padding(0), Padding = new Padding(0, 4, 0, 4) };
        detailFacts.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 98));
        detailFacts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var factValues = new Label[4];
        var factNames = new[] { "Signed by", "First seen", "Connections", "Status" };
        for (var row = 0; row < 4; row++)
        {
            detailFacts.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            detailFacts.Controls.Add(new Label { Text = factNames[row], AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Tag = "muted", UseMnemonic = false }, 0, row);
            factValues[row] = new Label { AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Regular), UseMnemonic = false };
            detailFacts.Controls.Add(factValues[row], 1, row);
        }
        var talksTitle = new Label { Text = "TALKS TO", AutoSize = false, Dock = DockStyle.Top, Height = 24, Tag = "muted", Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Regular), UseMnemonic = false };
        var talks = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 96, UseMnemonic = false };
        var primary = new Button { Text = "Block this app", Dock = DockStyle.Top, Height = 42, Tag = "danger-solid" };
        var secondary = new TableLayoutPanel { Dock = DockStyle.Top, Height = 46, ColumnCount = 2, RowCount = 1, Padding = new Padding(0, 6, 0, 0), BackColor = Color.Transparent };
        secondary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        secondary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var scan = new Button { Text = "Scan app", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var showFile = new Button { Text = "Show file", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        secondary.Controls.Add(scan, 0, 0);
        secondary.Controls.Add(showFile, 1, 0);
        var connections = new LinkLabel { Text = "All connections this session…", AutoSize = true, Dock = DockStyle.Top, Padding = new Padding(0, 8, 0, 0), Tag = "accent-link" };
        var detailCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(22, 18, 22, 16), Margin = new Padding(9, 0, 0, 0) };
        var detailEmpty = new Label { Text = "Select an app to see where it connects and to block or allow it.", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Tag = "muted", UseMnemonic = false };
        var detailBody = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
        foreach (var control in new Control[] { connections, secondary, primary, new Panel { Dock = DockStyle.Top, Height = 10, BackColor = Color.Transparent }, talks, talksTitle, detailFacts, detailPath, detailPillRow, detailName })
        {
            detailBody.Controls.Add(control);
        }

        detailCard.Controls.Add(detailBody);
        detailCard.Controls.Add(detailEmpty);

        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0), BackColor = SoftAppBack };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 340));
        grid.Controls.Add(listCard, 0, 0);
        grid.Controls.Add(detailCard, 1, 0);

        page.Controls.Add(grid);
        page.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 16, BackColor = SoftAppBack });
        page.Controls.Add(banner);
        page.Controls.Add(new Panel { Dock = DockStyle.Top, Height = bannerText.Count == 0 ? 0 : 12, BackColor = SoftAppBack });
        page.Controls.Add(stats);

        string? SelectedPath() => list.SelectedItem?.Tag as string;

        CardTone ToneFor(NetworkAppAssessment assessment, bool blocked) => assessment.Verdict.Kind switch
        {
            NetworkVerdictKind.Malicious => CardTone.Bad,
            NetworkVerdictKind.Suspicious => CardTone.Warn,
            _ when assessment.Untrusted => CardTone.Warn,
            _ when assessment.Verdict.Label == "Windows" => CardTone.Neutral,
            _ => blocked ? CardTone.Neutral : CardTone.Good,
        };

        bool Matches(NetworkRow row, FirewallFilter which) => which switch
        {
            FirewallFilter.Online => row.Online && !row.Blocked,
            FirewallFilter.Blocked => row.Blocked,
            FirewallFilter.NeedsLook => row.Assessment.Untrusted && !row.Blocked,
            _ => true,
        };

        void UpdateDetail()
        {
            var path = SelectedPath();
            detailBody.Visible = path is not null;
            detailEmpty.Visible = path is null;
            if (path is null)
            {
                return;
            }

            var assessment = AssessNetworkApp(path);
            var blocked = networkBlockedPaths.Contains(path);
            var exists = File.Exists(path);
            NetworkAppActivity? app = null;
            networkTracker?.TryGetApp(path, out app);
            detailName.Text = NetworkActivityTracker.DisplayName(path);
            detailPill.Text = assessment.Verdict.Label;
            detailPill.Width = TextRenderer.MeasureText(detailPill.Text, detailPill.Font).Width + 24;
            var (tint, ink) = ToneFor(assessment, blocked) switch
            {
                CardTone.Bad => (activePalette.DangerTint, activePalette.DangerText),
                CardTone.Warn => (activePalette.AttentionTint, activePalette.AttentionText),
                CardTone.Good => (activePalette.AccentTint, activePalette.AccentText),
                _ => (activePalette.NeutralTint, activePalette.MutedText),
            };
            detailPill.PillColor = tint;
            detailPill.ForeColor = ink;
            detailPill.Invalidate();
            detailPath.Text = path;
            factValues[0].Text = assessment.Signer;
            factValues[1].Text = app is null ? "—" : app.FirstSeenUtc.LocalDateTime.ToString("g", CultureInfo.CurrentCulture);
            factValues[2].Text = app is null ? "—" : $"{app.CurrentConnections} now · {app.TotalConnections} this session";
            factValues[3].Text = blocked ? "Blocked in Windows Firewall" : "Allowed";
            talks.Text = app is null || app.Endpoints.Count == 0
                ? "No connections seen this session."
                : string.Join(Environment.NewLine, app.Endpoints.Values.OrderByDescending(endpoint => endpoint.LastSeenUtc).Take(4)
                    .Select(endpoint => $"{DescribeEndpoint(endpoint)}   ·   {(endpoint.Scope == RemoteScope.Lan ? "LAN" : "Internet")}"));
            primary.Text = blocked ? "Allow this app" : "Block this app";
            primary.Tag = blocked ? null : "danger-solid";
            primary.Enabled = elevated && exists;
            scan.Enabled = exists;
            showFile.Enabled = exists;
            connections.Visible = app is not null;
            ApplyAppTheme(primary);
            toolTip.SetToolTip(primary, elevated ? "" : "Turn on Run elevated in Settings");
        }

        void RefreshRows()
        {
            if (page.IsDisposed)
            {
                return;
            }

            var rows = BuildNetworkRows("", hideTrusted: false, showIdle: true);
            foreach (var (chip, which) in chips)
            {
                chip.SetState(rows.Count(row => Matches(row, which)).ToString("N0", CultureInfo.CurrentCulture), which == filter);
            }

            var query = search.Text.Trim();
            var items = rows
                .Where(row => Matches(row, filter))
                .Where(row => query.Length == 0
                    || row.Path.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || row.Assessment.Signer.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || row.Columns[3].Contains(query, StringComparison.OrdinalIgnoreCase))
                .Select(row => new CardListItem
                {
                    LetterAvatar = true,
                    Tone = ToneFor(row.Assessment, row.Blocked),
                    Title = row.Columns[0],
                    Detail = $"{row.Assessment.Signer}  ·  {(row.Blocked ? "Blocked · " : "")}{row.Columns[3]}",
                    Pill = row.Assessment.Verdict.Label,
                    Trailing = row.Online ? "online" : row.Columns[5],
                    Toggle = File.Exists(row.Path) ? !row.Blocked : null,
                    ToggleLabel = row.Blocked ? "Blocked" : "Allowed",
                    Tag = row.Path,
                })
                .ToList();
            list.SetItems(items, keepScroll: true);
            statOnline.Text = (networkTracker?.Apps.Count(app => app.CurrentConnections > 0 && !networkBlockedPaths.Contains(app.Path)) ?? 0).ToString("N0", CultureInfo.CurrentCulture);
            statBlocked.Text = networkBlockedPaths.Count.ToString("N0", CultureInfo.CurrentCulture);
            var look = rows.Count(row => row.Online && row.Assessment.Untrusted && !row.Blocked);
            statLook.Text = look.ToString("N0", CultureInfo.CurrentCulture);
            statLook.ForeColor = look > 0 ? activePalette.AttentionText : activePalette.Text;
            list.EmptyText = rows.Count == 0 ? "Watching for connections… apps appear here as soon as they go online." : "No app matches this filter.";
            UpdateDetail();
            UpdateHomePage();
        }

        void SelectApp(string path)
        {
            filter = FirewallFilter.All;
            search.Text = "";
            RefreshRows();
            if (list.SelectTag(path))
            {
                list.Focus();
            }
        }

        void ToggleApp(string path)
        {
            var blocked = networkBlockedPaths.Contains(path);
            var changed = blocked ? UnblockNetworkApp(this, path) : BlockNetworkApp(this, path);
            if (changed)
            {
                RefreshRows();
            }
        }

        list.SelectionChanged += (_, _) => UpdateDetail();
        list.ToggleClicked += item =>
        {
            if (!elevated)
            {
                MessageBox.Show(this, "Blocking and unblocking change Windows Firewall, which needs HashGuard to run elevated.\n\nTurn on Settings → Behavior → Run elevated, then restart HashGuard.", "Run elevated", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (item.Tag is string path)
            {
                ToggleApp(path);
            }
        };
        list.ItemActivated += (_, _) =>
        {
            if (SelectedPath() is { } path && networkTracker is not null && networkTracker.TryGetApp(path, out var app))
            {
                ShowNetworkConnectionsDialog(this, app);
            }
        };
        primary.Click += (_, _) =>
        {
            if (SelectedPath() is { } path)
            {
                ToggleApp(path);
            }
        };
        scan.Click += async (_, _) =>
        {
            if (SelectedPath() is not { } path)
            {
                return;
            }

            networkAssessments.Remove(path);
            await ScanSelectedFilesAsync([path]);
            networkAssessments.Remove(path);
            RefreshRows();
        };
        showFile.Click += (_, _) =>
        {
            if (SelectedPath() is { } path && File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
            }
        };
        connections.LinkClicked += (_, _) =>
        {
            if (SelectedPath() is { } path && networkTracker is not null && networkTracker.TryGetApp(path, out var app))
            {
                ShowNetworkConnectionsDialog(this, app);
            }
        };
        foreach (var (chip, which) in chips)
        {
            chip.Click += (_, _) =>
            {
                filter = which;
                RefreshRows();
            };
        }

        search.TextChanged += (_, _) => RefreshRows();
        page.Disposed += (_, _) =>
        {
            refreshNetworkWindow = null;
            selectNetworkApp = null;
        };
        refreshNetworkWindow = RefreshRows;
        selectNetworkApp = SelectApp;
        RefreshRows();
        return page;
    }
}
