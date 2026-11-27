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

    /// <summary>The Monitor | Ask first switch, shown at the right of the Firewall page title.</summary>
    private Control? firewallModeSwitch;

    private Control BuildFirewallPage()
    {
        EnsureNetworkTracker();
        ReloadNetworkBlockedPaths();
        var elevated = IsRunningElevated();
        var filter = FirewallFilter.All;
        var page = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };

        // Stat cards + mode switch.
        var statOnline = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 38, Font = UiFonts.Create("Segoe UI Semibold", 18, FontStyle.Regular), UseMnemonic = false };
        var statBlocked = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 38, Font = UiFonts.Create("Segoe UI Semibold", 18, FontStyle.Regular), UseMnemonic = false };
        var statLook = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 38, Font = UiFonts.Create("Segoe UI Semibold", 18, FontStyle.Regular), UseMnemonic = false };
        CardPanel StatCard(string caption, Label value)
        {
            var card = new CardPanel { Dock = DockStyle.Fill, Radius = 16, Padding = new Padding(20, 12, 20, 10) };
            card.Controls.Add(value);
            card.Controls.Add(new Label { Text = caption, AutoSize = false, Dock = DockStyle.Top, Height = 20, Tag = "muted", UseMnemonic = false });
            return card;
        }

        var stats = new TableLayoutPanel { Dock = DockStyle.Top, Height = 84, ColumnCount = 3, RowCount = 1, Margin = new Padding(0), BackColor = SoftAppBack };
        for (var column = 0; column < 3; column++)
        {
            stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 3));
        }

        // Without this the row sizes to the cards' preferred height and cuts their bottoms off.
        stats.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var onlineCard = StatCard("Online now", statOnline);
        var blockedCard = StatCard("Blocked", statBlocked);
        var lookCard = StatCard("Needs a look", statLook);
        onlineCard.Margin = new Padding(0, 0, 8, 0);
        blockedCard.Margin = new Padding(4, 0, 4, 0);
        lookCard.Margin = new Padding(8, 0, 0, 0);
        stats.Controls.Add(onlineCard, 0, 0);
        stats.Controls.Add(blockedCard, 1, 0);
        stats.Controls.Add(lookCard, 2, 0);
        var mode = new ModeSwitch { Margin = new Padding(16, 2, 0, 0) };
        toolTip.SetToolTip(mode, "Monitor: HashGuard watches and alerts. Ask first (coming in a later version): ask before an app connects for the first time.");
        firewallModeSwitch = mode;

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
        // Short enough to show whole beside all four chips (publishers are searched too).
        var search = new TextBox { BorderStyle = BorderStyle.None, PlaceholderText = "Search apps or hosts", AccessibleName = "Search apps, publishers or hosts", Font = UiFonts.Create("Segoe UI", 10, FontStyle.Regular) };
        var searchBox = new SearchField(search) { Size = new Size(240, 38), Margin = new Padding(0, 0, 10, 0) };
        var chipAll = new ChipButton("All");
        var chipOnline = new ChipButton("Online");
        var chipBlocked = new ChipButton("Blocked");
        var chipLook = new ChipButton("Needs a look");
        var chips = new[] { (chipAll, FirewallFilter.All), (chipOnline, FirewallFilter.Online), (chipBlocked, FirewallFilter.Blocked), (chipLook, FirewallFilter.NeedsLook) };
        var listBar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 56, WrapContents = false, Padding = new Padding(12, 6, 12, 0), BackColor = Color.White, Tag = "surface" };
        listBar.Controls.Add(searchBox);
        foreach (var (chip, _) in chips)
        {
            chip.Margin = new Padding(0, 1, 6, 0);
            listBar.Controls.Add(chip);
        }

        // The search field takes whatever the chips leave, so every chip (Needs a look too) stays visible.
        void FitSearch()
        {
            var chipsWidth = chips.Sum(chip => chip.Item1.Width + chip.Item1.Margin.Horizontal);
            searchBox.Width = Math.Max(150, listBar.ClientSize.Width - listBar.Padding.Horizontal - chipsWidth - searchBox.Margin.Horizontal - 4);
        }

        listBar.Resize += (_, _) => FitSearch();

        // Rows as designed: avatar + name over publisher, the verdict label, the host, then the switch.
        var list = new CardList
        {
            Dock = DockStyle.Fill,
            AccessibleName = "Apps using the network",
            EmptyText = "Watching for connections…",
            Columns =
            [
                new CardColumn("App", CardColumnKind.Main, Width: 250),
                new CardColumn("Verdict", CardColumnKind.Pill, Width: 112),
                new CardColumn("Host", CardColumnKind.Text, Weight: 1),
            ],
        };
        var listCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10), Margin = new Padding(0, 0, 9, 0) };
        listCard.Controls.Add(list);
        listCard.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, Tag = "hairline" });
        listCard.Controls.Add(listBar);

        // Detail card for the selected app.
        // Header as designed: a 48px letter tile, then the name over the verdict pill.
        var detailAvatar = new LetterTile { Location = new Point(0, 2) };
        var detailName = new Label { AutoSize = false, Location = new Point(60, 0), Size = new Size(230, 28), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right, Font = UiFonts.Create("Segoe UI Semibold", 13, FontStyle.Regular), AutoEllipsis = true, UseMnemonic = false };
        var detailPill = new PillLabel { AutoSize = false, Location = new Point(60, 29), Height = 24, Width = 120, Radius = 12, TextAlign = ContentAlignment.MiddleCenter, Font = UiFonts.Create("Segoe UI Semibold", 8.5f, FontStyle.Regular) };
        var detailHead = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = Color.Transparent };
        detailHead.Controls.AddRange([detailAvatar, detailName, detailPill]);
        detailHead.Resize += (_, _) => detailName.Width = Math.Max(40, detailHead.Width - 60);
        // The whole path, wrapped at any character (paths have no spaces to break at).
        var detailPath = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 40, Tag = "muted", UseMnemonic = false, Padding = new Padding(0, 0, 0, 6) };
        var detailPathFull = "";
        void WrapDetailPath()
        {
            var wrapped = TextWrap.Anywhere(detailPathFull, detailPath.Font, detailPath.ClientSize.Width - 2);
            detailPath.Text = wrapped;
            detailPath.Height = TextRenderer.MeasureText(wrapped.Length == 0 ? " " : wrapped, detailPath.Font).Height + 8;
        }

        var lastPathWidth = 0;
        detailPath.SizeChanged += (_, _) =>
        {
            // Re-wrap only when the width changes (setting the height raises this event too).
            if (detailPath.ClientSize.Width != lastPathWidth)
            {
                lastPathWidth = detailPath.ClientSize.Width;
                WrapDetailPath();
            }
        };
        // Facts as a two-column list (muted names, values on the right), as designed.
        var detailFacts = new TableLayoutPanel { Dock = DockStyle.Top, Height = 112, ColumnCount = 2, RowCount = 4, BackColor = Color.Transparent, Margin = new Padding(0), Padding = new Padding(0, 4, 0, 4) };
        detailFacts.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 98));
        detailFacts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var factValues = new Label[4];
        var factNames = new[] { "Signed by", "First seen", "Connections", "Status" };
        for (var row = 0; row < 4; row++)
        {
            detailFacts.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            // Margin 0 so the names line up with "TALKS TO" and the path above.
            detailFacts.Controls.Add(new Label { Text = factNames[row], AutoSize = false, Dock = DockStyle.Fill, Margin = new Padding(0), TextAlign = ContentAlignment.MiddleLeft, Tag = "muted", UseMnemonic = false }, 0, row);
            factValues[row] = new Label { AutoSize = false, Dock = DockStyle.Fill, Margin = new Padding(0), TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, Font = UiFonts.Create("Segoe UI Semibold", 9.5f, FontStyle.Regular), UseMnemonic = false };
            detailFacts.Controls.Add(factValues[row], 1, row);
        }
        var talksTitle = new Label { Text = "TALKS TO", AutoSize = false, Dock = DockStyle.Top, Height = 30, Padding = new Padding(0, 8, 0, 0), Tag = "muted", Font = UiFonts.Create("Segoe UI Semibold", 8.5f, FontStyle.Regular), UseMnemonic = false };
        // One row per host: the host, and an "Internet" / "LAN" badge at the right, as designed.
        var talks = new TableLayoutPanel { Dock = DockStyle.Top, Height = 0, ColumnCount = 2, BackColor = Color.Transparent, Margin = new Padding(0), Padding = new Padding(0) };
        talks.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        talks.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var primary = new Button { Text = "Block this app", Dock = DockStyle.Top, Height = 42, Tag = "danger-solid" };
        var secondary = new TableLayoutPanel { Dock = DockStyle.Top, Height = 46, ColumnCount = 2, RowCount = 1, Padding = new Padding(0, 6, 0, 0), BackColor = Color.Transparent };
        secondary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        secondary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var scan = new Button { Text = "Scan app", Dock = DockStyle.Fill, Margin = new Padding(0, 0, 4, 0) };
        var showFile = new Button { Text = "Show file", Dock = DockStyle.Fill, Margin = new Padding(4, 0, 0, 0) };
        secondary.Controls.Add(scan, 0, 0);
        secondary.Controls.Add(showFile, 1, 0);
        // Every connection of an app is one double-click on its row away (not a link here, as designed).
        var detailCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(22, 18, 22, 16), Margin = new Padding(9, 0, 0, 0) };
        var detailEmpty = new Label { Text = "Select an app to see where it connects and to block or allow it.", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Tag = "muted", UseMnemonic = false };
        var detailBody = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
        foreach (var control in new Control[] { secondary, primary, new Panel { Dock = DockStyle.Top, Height = 12, BackColor = Color.Transparent }, talks, talksTitle, detailFacts, detailPath, detailHead })
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

        // Letter tiles follow the verdict, as designed: clean apps blue, not scanned amber, malicious red, Windows grey.
        static CardTone AvatarToneFor(NetworkAppAssessment assessment) => PillToneFor(assessment) switch
        {
            CardTone.Good => CardTone.Blue,
            var tone => tone,
        };

        // The verdict pill keeps its own colour: Clean is green even when the publisher isn't verified.
        static CardTone PillToneFor(NetworkAppAssessment assessment) => assessment.Verdict.Kind switch
        {
            NetworkVerdictKind.Malicious => CardTone.Bad,
            NetworkVerdictKind.Suspicious => CardTone.Warn,
            _ when assessment.Verdict.Label == "Windows" => CardTone.Neutral,
            _ when assessment.Verdict.Label.Contains("Clean", StringComparison.OrdinalIgnoreCase) => CardTone.Good,
            _ => CardTone.Warn,
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
            detailAvatar.Text = detailName.Text.Length > 0 ? detailName.Text[..1].ToUpperInvariant() : "?";
            (detailAvatar.TintColor, detailAvatar.InkColor) = AvatarToneFor(assessment) switch
            {
                CardTone.Bad => (activePalette.DangerTint, activePalette.DangerText),
                CardTone.Warn => (activePalette.AttentionTint, activePalette.AttentionText),
                CardTone.Blue => activePalette.AppBack == ThemePalette.Dark.AppBack ? (Color.FromArgb(30, 42, 66), Color.FromArgb(140, 172, 240)) : (Color.FromArgb(232, 239, 253), Color.FromArgb(36, 87, 197)),
                _ => (activePalette.NeutralTint, activePalette.MutedText),
            };
            detailAvatar.Invalidate();
            detailPill.Text = assessment.Verdict.Label;
            detailPill.Width = TextRenderer.MeasureText(detailPill.Text, detailPill.Font).Width + 24;
            var (tint, ink) = PillToneFor(assessment) switch
            {
                CardTone.Bad => (activePalette.DangerTint, activePalette.DangerText),
                CardTone.Warn => (activePalette.AttentionTint, activePalette.AttentionText),
                CardTone.Good => (activePalette.AccentTint, activePalette.AccentText),
                _ => (activePalette.NeutralTint, activePalette.MutedText),
            };
            detailPill.PillColor = tint;
            detailPill.ForeColor = ink;
            detailPill.Invalidate();
            detailPathFull = path;
            WrapDetailPath();
            factValues[0].Text = assessment.Signer;
            factValues[1].Text = app is null ? "—" : app.FirstSeenUtc.LocalDateTime.ToString("g", CultureInfo.CurrentCulture);
            factValues[2].Text = app is null ? "—" : $"{app.CurrentConnections} now · {app.TotalConnections} this session";
            factValues[3].Text = blocked ? "Blocked in Windows Firewall" : "Allowed";
            var endpoints = app?.Endpoints.Values.OrderByDescending(endpoint => endpoint.LastSeenUtc).Take(4).ToList() ?? [];
            var talksKey = string.Join("|", endpoints.Select(endpoint => DescribeEndpoint(endpoint) + endpoint.Scope));
            if (talks.Tag as string != talksKey)
            {
                talks.Tag = talksKey;
                talks.SuspendLayout();
                foreach (Control old in talks.Controls.Cast<Control>().ToList())
                {
                    old.Dispose();
                }

                talks.RowStyles.Clear();
                talks.RowCount = Math.Max(1, endpoints.Count);
                if (endpoints.Count == 0)
                {
                    talks.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
                    var none = new Label { Text = "No connections seen this session.", AutoSize = false, Dock = DockStyle.Fill, Margin = new Padding(0), TextAlign = ContentAlignment.MiddleLeft, ForeColor = activePalette.MutedText, Tag = "muted", UseMnemonic = false };
                    talks.Controls.Add(none, 0, 0);
                    talks.SetColumnSpan(none, 2);
                }

                for (var index = 0; index < endpoints.Count; index++)
                {
                    talks.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
                    talks.Controls.Add(new Label { Text = DescribeEndpoint(endpoints[index]), AutoSize = false, Dock = DockStyle.Fill, Margin = new Padding(0), TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, ForeColor = activePalette.Text, UseMnemonic = false }, 0, index);
                    var scope = endpoints[index].Scope == RemoteScope.Lan ? "LAN" : "Internet";
                    talks.Controls.Add(new PillLabel
                    {
                        Text = scope,
                        AutoSize = false,
                        Size = new Size(TextRenderer.MeasureText(scope, ChipFont).Width + 16, 22),
                        Margin = new Padding(8, 3, 0, 3),
                        Radius = 6,
                        TextAlign = ContentAlignment.MiddleCenter,
                        Font = ChipFont,
                        PillColor = activePalette.NeutralTint,
                        ForeColor = activePalette.MutedText,
                    }, 1, index);
                }

                talks.Height = endpoints.Count == 0 ? 26 : endpoints.Count * 28;
                talks.ResumeLayout();
            }
            primary.Text = blocked ? "Allow this app" : "Block this app";
            primary.Tag = blocked ? null : "danger-solid";
            primary.Enabled = elevated && exists;
            scan.Enabled = exists;
            showFile.Enabled = exists;
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
                chip.SetState("", which == filter);
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
                    Tone = AvatarToneFor(row.Assessment),
                    Title = row.Columns[0],
                    Detail = row.Assessment.Signer,
                    Pill = row.Assessment.Verdict.Label,
                    PillTone = PillToneFor(row.Assessment),
                    Cells = [(row.Blocked ? "Blocked · " : "") + row.Columns[3]],
                    Toggle = File.Exists(row.Path) ? !row.Blocked : null,
                    ToggleLabel = row.Blocked ? "Blocked" : "Allowed",
                    Tag = row.Path,
                })
                .ToList();
            list.SetItems(items, keepScroll: true);
            // As designed, the detail card always shows an app: the first one until you pick another.
            if (list.SelectedItem is null && items.Count > 0)
            {
                list.SelectTag(items[0].Tag!);
            }

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
            FitSearch();
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
        FitSearch();
        return page;
    }
}
