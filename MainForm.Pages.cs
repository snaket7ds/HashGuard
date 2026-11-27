using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace HashGuardScanner;

/// <summary>
/// v1.1.0 window: a sidebar and one page at a time (Home, Scan, Quarantine, Firewall, Activity,
/// Settings), with a slim status line at the bottom. The scanning, results and settings code is
/// unchanged; its controls (statusTitle, resultsView, scanButton, …) are placed on these pages.
/// </summary>
public sealed partial class MainForm : Form
{
    private readonly SidebarNav sidebar = new();
    private readonly Panel pageHost = new() { Dock = DockStyle.Fill, Padding = new Padding(32, 26, 32, 12), Tag = "page-host" };
    private readonly Dictionary<AppPage, Control> builtPages = [];
    private readonly Panel homeScanSlot = new() { Size = new Size(168, 46), Margin = new Padding(0, 0, 0, 10) };
    private readonly Panel scanPageScanSlot = new() { Size = new Size(168, 46), Margin = new Padding(0) };
    // The threat card inside the Home hero (as designed): top flagged file with Details · Ignore · Quarantine.
    private readonly CardPanel homeThreatCard = new() { Dock = DockStyle.Fill, Radius = 14, Padding = new Padding(18, 12, 16, 12), Visible = false, Tag = "threat-card" };
    private readonly Label homeThreatName = new() { AutoSize = false, Dock = DockStyle.Top, Height = 24, Font = new Font("Segoe UI Semibold", 10.5f, FontStyle.Regular), AutoEllipsis = true, UseMnemonic = false };
    private readonly Label homeThreatDetail = new() { AutoSize = false, Dock = DockStyle.Top, Height = 22, Tag = "muted", AutoEllipsis = true, UseMnemonic = false };
    private TableLayoutPanel? homePageLayout;
    private readonly PillLabel homeLastScanChip = new() { AutoSize = false, Height = 26, Width = 190, Padding = new Padding(10, 0, 10, 0), Radius = 13, Font = new Font("Segoe UI", 9, FontStyle.Regular), Tag = "chip-neutral" };
    private readonly PillLabel homeSourcesChip = new() { AutoSize = false, Height = 26, Width = 230, Padding = new Padding(10, 0, 10, 0), Radius = 13, Font = new Font("Segoe UI", 9, FontStyle.Regular), Tag = "chip-good" };
    private readonly Label homeAvLastScan = CreateValueLabel();
    private readonly Label homeAvOpenFiles = CreateValueLabel();
    private readonly Label homeAvSources = CreateValueLabel();
    private readonly Label homeFwOnline = CreateValueLabel();
    private readonly Label homeFwBlocked = CreateValueLabel();
    private readonly Label homeFwAlerts = CreateValueLabel();
    private readonly PillLabel homeAvPill = new() { AutoSize = false, Size = new Size(110, 24), Radius = 12, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Regular) };
    private readonly PillLabel homeFwPill = new() { AutoSize = false, Size = new Size(110, 24), Radius = 12, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Regular) };
    private readonly Label homeTileDecision = CreateTileValueLabel();
    private readonly Label homeTileQuarantine = CreateTileValueLabel();
    private readonly CardPanel homeHero = new() { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(28, 22, 28, 22), Margin = new Padding(0, 0, 0, 18) };
    private readonly ProgressRing scanRing = new() { Size = new Size(116, 116), IdleText = "Ready" };
    private readonly Label scanRingTitle = new() { AutoSize = false, Dock = DockStyle.Top, Height = 34, Font = new Font("Segoe UI Semibold", 15, FontStyle.Regular), Text = "Ready to scan", UseMnemonic = false };
    private readonly Label scanRingDetail = new() { AutoSize = false, Dock = DockStyle.Top, Height = 22, AutoEllipsis = true, Tag = "muted", UseMnemonic = false };
    private readonly FlowLayoutPanel scanSourceChips = new() { Dock = DockStyle.Top, Height = 34, WrapContents = false, Margin = new Padding(0), Padding = new Padding(0, 6, 0, 0) };
    private readonly Label scanCountChecked = CreateCountLabel();
    private readonly Label scanCountClean = CreateCountLabel();
    private readonly Label scanCountUnknown = CreateCountLabel();
    private readonly Label scanCountThreats = CreateCountLabel();
    private readonly Label reviewNoteLabel = new() { AutoSize = true, Tag = "muted", Margin = new Padding(12, 8, 0, 0), UseMnemonic = false };
    private AlertCard? overlayAlert;
    private DateTime? lastScanFinishedLocal;
    private bool lastDashboardScanning;
    private string lastDashboardSubtitle = "";

    private void BuildLayout()
    {
        BackColor = SoftAppBack;
        trayIcon.Text = "HashGuard";
        trayIcon.Icon = cleanTrayIcon;
        trayIcon.Visible = true;
        trayIcon.DoubleClick += (_, _) => RestoreFromTray();
        trayIcon.ContextMenuStrip = new ContextMenuStrip();
        trayIcon.ContextMenuStrip.Items.Add("Open HashGuard", null, (_, _) => OpenPageFromTray(AppPage.Home));
        trayIcon.ContextMenuStrip.Items.Add("Scan now", null, async (_, _) =>
        {
            OpenPageFromTray(AppPage.Scan);
            await StartScanAsync();
        });
        trayIcon.ContextMenuStrip.Items.Add("Quarantine", null, (_, _) => OpenPageFromTray(AppPage.Quarantine));
        trayIcon.ContextMenuStrip.Items.Add("Firewall", null, (_, _) => OpenPageFromTray(AppPage.Firewall));
        trayIcon.ContextMenuStrip.Items.Add(new ToolStripSeparator());
        trayIcon.ContextMenuStrip.Items.Add("Exit", null, (_, _) =>
        {
            exitRequested = true;
            trayIcon.Visible = false;
            Close();
        });

        lastScanFinishedLocal = ScanSnapshotStore.Load() is { } snapshot && snapshot.CapturedAtUtc != default
            ? snapshot.CapturedAtUtc.LocalDateTime
            : null;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0), Padding = new Padding(0), BackColor = SoftAppBack };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 224));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        sidebar.NavigateRequested += page => ShowPage(page);
        root.Controls.Add(sidebar, 0, 0);

        var content = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0), Padding = new Padding(0), BackColor = SoftAppBack };
        content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        // The old status bar is gone (not in the design); progress shows on the Scan page.
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        pageHost.BackColor = SoftAppBack;
        content.Controls.Add(pageHost, 0, 0);

        // Status line: a thin progress line along its top, status text and count below.
        var footer = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0), Padding = new Padding(0), Tag = "footer" };
        footer.Paint += (_, e) => DrawHairline(e.Graphics, 0, 0, footer.Width, activePalette.Hairline);
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0), Padding = new Padding(32, 0, 32, 0), BackColor = Color.Transparent };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        progressBar.Dock = DockStyle.Top;
        progressBar.Height = 3;
        progressBar.Margin = new Padding(0);
        progressBar.Style = ProgressBarStyle.Continuous;
        statusLabel.Dock = DockStyle.Fill;
        statusLabel.TextAlign = ContentAlignment.MiddleLeft;
        statusLabel.AutoSize = false;
        statusLabel.AutoEllipsis = true;
        statusLabel.UseMnemonic = false;
        statusLabel.Tag = "muted";
        countLabel.AutoSize = false;
        countLabel.Dock = DockStyle.Fill;
        countLabel.TextAlign = ContentAlignment.MiddleRight;
        countLabel.Width = 96;
        countLabel.Tag = "muted";
        bottom.Controls.Add(statusLabel, 0, 0);
        bottom.Controls.Add(countLabel, 1, 0);
        footer.Controls.Add(bottom);
        footer.Controls.Add(progressBar);
        footer.Visible = false;
        content.Controls.Add(footer, 0, 1);
        root.Controls.Add(content, 1, 0);
        Controls.Add(root);

        scanButton.Size = new Size(168, 46);
        scanButton.Dock = DockStyle.Fill;
        resultsView.Name = MainResultsViewName;
        progressBar.VisibleChanged += (_, _) => SyncScanRing();

        // The Scan page owns resultsView and configures its columns; scans fill it before anyone
        // opens the page, so build it now (hidden) rather than on first visit.
        GetOrBuildPage(AppPage.Scan);
        ShowPage(AppPage.Home);
        statusLabel.Text = "Ready";
        UpdateResultsEmptyState();
        ApplyAppTheme(this);
        UpdateHomePage();
    }

    private static bool IsInside(Control control, Control ancestor)
    {
        for (var current = control; current is not null; current = current.Parent)
        {
            if (current == ancestor)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Kept for the existing callers: the old tiles are now the Home page.</summary>
    private void UpdateReputationTile() => UpdateHomePage();

    private void UpdateQuarantineTile() => UpdateHomePage();

    private void OpenPageFromTray(AppPage page)
    {
        RestoreFromTray();
        ShowPage(page);
    }

    /// <summary>Shows a page. Settings, Quarantine and Activity are rebuilt each time so they show current data.</summary>
    private void ShowPage(AppPage page)
    {
        var rebuild = page is AppPage.Settings or AppPage.Quarantine or AppPage.Activity;
        if (rebuild && builtPages.Remove(page, out var stale))
        {
            // updateButton lives on the Settings page but is a long-lived field; keep it alive.
            if (updateButton.Parent is { } parent && IsInside(parent, stale))
            {
                parent.Controls.Remove(updateButton);
            }

            pageHost.Controls.Remove(stale);
            stale.Dispose();
        }

        GetOrBuildPage(page);
        foreach (var (key, control) in builtPages)
        {
            control.Visible = key == page;
        }

        ShowPageChrome(page);
    }

    private Control GetOrBuildPage(AppPage page)
    {
        if (!builtPages.TryGetValue(page, out var view))
        {
            view = page switch
            {
                AppPage.Home => BuildHomePage(),
                AppPage.Scan => BuildScanPage(),
                AppPage.Quarantine => WrapPage("Quarantine", "Files here can't run. Restore one only if you trust it, or delete it for good.", BuildQuarantinePage(), quarantineHeaderTools),
                AppPage.Firewall => WrapPage("Firewall", "Every app that talks to the network, with HashGuard's verdict. Turn an app off to block it.", BuildFirewallPage(), firewallModeSwitch),
                AppPage.Activity => WrapPage("Activity", "Everything HashGuard did: scans, files it checked, apps it blocked and files it quarantined.", BuildActivityPage(), activityHeaderTools),
                _ => WrapPage("Settings", "", BuildSettingsView()),
            };
            view.Dock = DockStyle.Fill;
            view.Visible = false;
            builtPages[page] = view;
            pageHost.Controls.Add(view);
            ApplyAppTheme(view);
        }

        return view;
    }

    private void ShowPageChrome(AppPage page)
    {
        // One scan button, moved to the page that is showing.
        var slot = page == AppPage.Scan ? scanPageScanSlot : homeScanSlot;
        if (scanButton.Parent != slot)
        {
            scanButton.Parent?.Controls.Remove(scanButton);
            slot.Controls.Add(scanButton);
        }

        firewallPageVisible = page == AppPage.Firewall;
        sidebar.SetActive(page);
        overlayAlert?.BringToFront();
        UpdateNetworkTimer();
        if (page == AppPage.Firewall)
        {
            refreshNetworkWindow?.Invoke();
        }
    }

    private Control WrapPage(string title, string subtitle, Control body, Control? headerRight = null)
    {
        var page = new TableLayoutPanel { ColumnCount = 1, RowCount = 2, Margin = new Padding(0), Padding = new Padding(0), BackColor = SoftAppBack };
        page.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        page.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var header = CreatePageHeader(title, subtitle);
        if (headerRight is null)
        {
            page.Controls.Add(header, 0, 0);
        }
        else
        {
            // Title on the left, a control (e.g. the Firewall mode switch) on the right, as designed.
            var bar = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, RowCount = 1, Margin = new Padding(0), BackColor = SoftAppBack };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.Margin = new Padding(0, 0, 0, 14);
            headerRight.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            bar.Controls.Add(header, 0, 0);
            bar.Controls.Add(headerRight, 1, 0);
            page.Controls.Add(bar, 0, 0);
        }
        body.Dock = DockStyle.Fill;
        body.Margin = new Padding(0);
        page.Controls.Add(body, 0, 1);
        return page;
    }

    private static Control CreatePageHeader(string title, string subtitle)
    {
        var header = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 14), BackColor = SoftAppBack };
        header.Controls.Add(new Label { Text = title, AutoSize = true, Font = new Font("Segoe UI Semibold", 18, FontStyle.Regular), Margin = new Padding(0), UseMnemonic = false, Tag = "page-title" });
        if (!string.IsNullOrWhiteSpace(subtitle))
        {
            header.Controls.Add(new Label { Text = subtitle, AutoSize = true, Margin = new Padding(1, 4, 0, 0), Tag = "muted", UseMnemonic = false });
        }

        return header;
    }

    private Control BuildHomePage()
    {
        var page = new TableLayoutPanel { ColumnCount = 1, RowCount = 5, Margin = new Padding(0), Padding = new Padding(0), BackColor = SoftAppBack, AutoScroll = true };
        page.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        page.RowStyles.Add(new RowStyle(SizeType.Absolute, 206));
        page.RowStyles.Add(new RowStyle(SizeType.Absolute, 236));
        page.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
        page.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        page.Controls.Add(CreatePageHeader("Home", ""), 0, 0);

        // Hero: the static badge, one headline and one sentence, two chips, the scan button.
        statusDot.Size = new Size(96, 96);
        statusDot.Margin = new Padding(0, 0, 24, 0);
        statusDot.BackColor = Color.Transparent;
        statusDot.Anchor = AnchorStyles.Left;
        statusDot.Paint -= PaintStatusDot;
        statusDot.Paint += PaintStatusDot;
        statusTitle.AutoSize = false;
        statusTitle.Dock = DockStyle.Top;
        statusTitle.Height = 40;
        statusTitle.Font = new Font("Segoe UI Semibold", 19, FontStyle.Regular);
        statusTitle.TextAlign = ContentAlignment.BottomLeft;
        statusTitle.UseMnemonic = false;
        statusSubtitle.AutoSize = false;
        statusSubtitle.Dock = DockStyle.Top;
        statusSubtitle.Height = 44;
        statusSubtitle.Font = new Font("Segoe UI", 10, FontStyle.Regular);
        statusSubtitle.TextAlign = ContentAlignment.TopLeft;
        statusSubtitle.Tag = "muted";
        statusSubtitle.UseMnemonic = false;
        var chips = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, WrapContents = false, Margin = new Padding(0), Padding = new Padding(0, 2, 0, 0), BackColor = Color.Transparent };
        homeLastScanChip.Margin = new Padding(0, 0, 8, 0);
        chips.Controls.Add(homeLastScanChip);
        chips.Controls.Add(homeSourcesChip);
        var text = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent, Padding = new Padding(0, 14, 0, 0) };
        text.Controls.Add(chips);
        text.Controls.Add(statusSubtitle);
        text.Controls.Add(statusTitle);
        var heroButtons = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Anchor = AnchorStyles.Right, Margin = new Padding(16, 0, 0, 0), BackColor = Color.Transparent };
        heroButtons.Controls.Add(homeScanSlot);
        var heroLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Color.Transparent, Margin = new Padding(0) };
        heroLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 124));
        heroLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        heroLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        heroLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        heroLayout.Controls.Add(statusDot, 0, 0);
        heroLayout.Controls.Add(text, 1, 0);
        heroLayout.Controls.Add(heroButtons, 2, 0);
        // Threat card under the status, shown only when something is flagged.
        var threatText = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent };
        threatText.Controls.Add(homeThreatDetail);
        threatText.Controls.Add(homeThreatName);
        var threatDetails = new Button { Text = "Details", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0) };
        var threatIgnore = new Button { Text = "Ignore", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0) };
        var threatQuarantine = new Button { Text = "Quarantine", AutoSize = true, Height = 40, Margin = new Padding(8, 0, 0, 0), Tag = "danger-solid" };
        threatDetails.Click += (_, _) => RunOnTopThreat("Details");
        threatIgnore.Click += (_, _) => RunOnTopThreat("Ignore");
        threatQuarantine.Click += (_, _) => RunOnTopThreat("Quarantine");
        var threatButtons = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Anchor = AnchorStyles.Right, BackColor = Color.Transparent, Margin = new Padding(0) };
        threatButtons.Controls.AddRange([threatDetails, threatIgnore, threatQuarantine]);
        var threatLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Color.Transparent, Margin = new Padding(0) };
        threatLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        threatLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        threatLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        threatLayout.Controls.Add(threatText, 0, 0);
        threatLayout.Controls.Add(threatButtons, 1, 0);
        homeThreatCard.Controls.Add(threatLayout);
        homeThreatCard.Margin = new Padding(0, 14, 0, 0);
        var heroStack = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Color.Transparent, Margin = new Padding(0) };
        heroStack.RowStyles.Add(new RowStyle(SizeType.Absolute, 150));
        heroStack.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        heroStack.Controls.Add(heroLayout, 0, 0);
        heroStack.Controls.Add(homeThreatCard, 0, 1);
        homeHero.Controls.Add(heroStack);
        homePageLayout = page;
        page.Controls.Add(homeHero, 0, 1);

        var pillars = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 18), BackColor = SoftAppBack };
        pillars.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        pillars.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        pillars.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var av = CreatePillarCard("icon:shield", "accent", "Antivirus", homeAvPill,
            [("Last scan", homeAvLastScan), ("Files you open", homeAvOpenFiles), ("Reputation sources", homeAvSources)],
            "Scan settings →", () => ShowPage(AppPage.Settings));
        av.Margin = new Padding(0, 0, 9, 0);
        var fw = CreatePillarCard("icon:firewall", "blue", "Firewall", homeFwPill,
            [("Apps online now", homeFwOnline), ("Blocked by HashGuard", homeFwBlocked), ("New-app alerts", homeFwAlerts)],
            "Open Firewall →", () => ShowPage(AppPage.Firewall));
        fw.Margin = new Padding(9, 0, 0, 0);
        pillars.Controls.Add(av, 0, 0);
        pillars.Controls.Add(fw, 1, 0);
        page.Controls.Add(pillars, 0, 2);

        var tiles = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = new Padding(0), BackColor = SoftAppBack };
        for (var column = 0; column < 3; column++)
        {
            tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 3));
        }

        tiles.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var decisionTile = CreateLinkTile("Needs your decision", homeTileDecision, () => ShowPage(AppPage.Scan));
        var quarantineTile = CreateLinkTile("Quarantine", homeTileQuarantine, () => ShowPage(AppPage.Quarantine));
        var activityTile = CreateLinkTile("Activity", new Label { Text = "Scans, blocks and alerts", Tag = "muted", AutoSize = false, Dock = DockStyle.Top, Height = 20 }, () => ShowPage(AppPage.Activity));
        decisionTile.Margin = new Padding(0, 0, 8, 0);
        quarantineTile.Margin = new Padding(4, 0, 4, 0);
        activityTile.Margin = new Padding(8, 0, 0, 0);
        tiles.Controls.Add(decisionTile, 0, 0);
        tiles.Controls.Add(quarantineTile, 1, 0);
        tiles.Controls.Add(activityTile, 2, 0);
        page.Controls.Add(tiles, 0, 3);
        return page;
    }

    private void PaintStatusDot(object? sender, PaintEventArgs e) =>
        PaintStatusBadge(e.Graphics, statusDot.ClientRectangle, statusDot.Tag as string ?? "idle", activePalette);

    private CardPanel CreatePillarCard(string glyph, string tone, string title, PillLabel pill, (string Label, Label Value)[] rows, string linkText, Action onLink)
    {
        var card = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(24, 20, 24, 18) };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = rows.Length + 2, BackColor = Color.Transparent, Margin = new Padding(0) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 168));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        foreach (var _ in rows)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        }

        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var head = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Color.Transparent, Margin = new Padding(0) };
        head.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 54));
        head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var icon = new IconBadge(glyph, tone) { Size = new Size(42, 42), Radius = 12, Anchor = AnchorStyles.Left };
        head.Controls.Add(icon, 0, 0);
        head.Controls.Add(new Label { Text = title, AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 12.5f, FontStyle.Regular), UseMnemonic = false }, 1, 0);
        pill.Anchor = AnchorStyles.Right;
        head.Controls.Add(pill, 2, 0);
        layout.Controls.Add(head, 0, 0);
        layout.SetColumnSpan(head, 2);
        for (var index = 0; index < rows.Length; index++)
        {
            layout.Controls.Add(new Label { Text = rows[index].Label, AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Tag = "muted", UseMnemonic = false }, 0, index + 1);
            layout.Controls.Add(rows[index].Value, 1, index + 1);
        }

        var link = new LinkLabel { Text = linkText, AutoSize = true, Anchor = AnchorStyles.Left | AnchorStyles.Bottom, Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Regular), LinkBehavior = LinkBehavior.HoverUnderline, Margin = new Padding(0, 0, 0, 2), Tag = "accent-link" };
        link.LinkClicked += (_, _) => onLink();
        layout.Controls.Add(link, 0, rows.Length + 1);
        layout.SetColumnSpan(link, 2);
        card.Controls.Add(layout);
        return card;
    }

    private static CardPanel CreateLinkTile(string title, Label detail, Action onClick)
    {
        var tile = new CardPanel { Dock = DockStyle.Fill, Radius = 16, Padding = new Padding(20, 16, 16, 14), AccessibleName = title, AccessibleRole = AccessibleRole.Link, TabStop = true };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, BackColor = Color.Transparent, Margin = new Padding(0) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 20));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = title, AutoSize = false, Dock = DockStyle.Fill, Font = new Font("Segoe UI Semibold", 10.5f, FontStyle.Regular), TextAlign = ContentAlignment.MiddleLeft, UseMnemonic = false }, 0, 0);
        detail.Dock = DockStyle.Fill;
        layout.Controls.Add(detail, 0, 1);
        var chevron = new Label { Text = "", Font = new Font("Segoe MDL2 Assets", 9, FontStyle.Regular), AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleRight, Tag = "chevron" };
        layout.Controls.Add(chevron, 1, 0);
        layout.SetRowSpan(chevron, 2);
        tile.Controls.Add(layout);
        WireClick(tile, onClick);
        tile.MakeInteractive();
        tile.KeyDown += (_, e) =>
        {
            if (e.KeyCode is Keys.Enter or Keys.Space)
            {
                onClick();
            }
        };
        return tile;
    }

    private static Label CreateValueLabel() =>
        new() { AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Regular), UseMnemonic = false };

    private static Label CreateTileValueLabel() =>
        new() { AutoSize = false, Dock = DockStyle.Top, Height = 20, Tag = "muted", UseMnemonic = false };

    private static Label CreateCountLabel() =>
        new() { AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI Semibold", 14, FontStyle.Regular), UseMnemonic = false };

    private Control BuildScanPage()
    {
        var page = new TableLayoutPanel { ColumnCount = 1, RowCount = 4, Margin = new Padding(0), Padding = new Padding(0), BackColor = SoftAppBack };
        page.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        page.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));
        page.RowStyles.Add(new RowStyle(SizeType.Absolute, 176));
        page.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        page.Controls.Add(CreatePageHeader("Scan", "Check the apps running now, or choose files to check."), 0, 0);

        // Scan types, as in the design: click one to start it.
        var types = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 16), BackColor = SoftAppBack };
        types.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        types.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        types.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var runningApps = CreateLinkTile("Running apps", new Label { Text = "Every app running now, with its startup entries", Tag = "muted", AutoSize = false, Dock = DockStyle.Top, Height = 20, UseMnemonic = false }, () =>
        {
            if (scanCancellation is null)
            {
                _ = StartScanAsync();
            }
        });
        var chooseFilesTile = CreateLinkTile("Choose files", new Label { Text = "Any file you pick", Tag = "muted", AutoSize = false, Dock = DockStyle.Top, Height = 20, UseMnemonic = false }, ChooseFilesToScan);
        runningApps.Margin = new Padding(0, 0, 8, 0);
        chooseFilesTile.Margin = new Padding(8, 0, 0, 0);
        types.Controls.Add(runningApps, 0, 0);
        types.Controls.Add(chooseFilesTile, 1, 0);
        page.Controls.Add(types, 0, 1);

        // Progress card: ring, what is being checked, provider chips, counts, scan / choose files.
        var progressCard = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(26, 20, 26, 20), Margin = new Padding(0, 0, 0, 18) };
        var progressLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = Color.Transparent, Margin = new Padding(0) };
        progressLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
        progressLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        progressLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 244));
        progressLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        scanRing.Anchor = AnchorStyles.Left;
        progressLayout.Controls.Add(scanRing, 0, 0);
        var info = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent, Padding = new Padding(0, 22, 12, 0) };
        info.Controls.Add(scanSourceChips);
        info.Controls.Add(scanRingDetail);
        info.Controls.Add(scanRingTitle);
        progressLayout.Controls.Add(info, 1, 0);
        // Counts as four small grey tiles (label above, number below), as designed.
        var counts = new TableLayoutPanel { Anchor = AnchorStyles.Left, Size = new Size(228, 108), ColumnCount = 2, RowCount = 2, BackColor = Color.Transparent, Margin = new Padding(0, 0, 12, 0) };
        counts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        counts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        counts.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        counts.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        var countTiles = new[] { ("Checked", scanCountChecked), ("Clean", scanCountClean), ("Unknown", scanCountUnknown), ("Threats", scanCountThreats) };
        for (var index = 0; index < countTiles.Length; index++)
        {
            var (caption, value) = countTiles[index];
            var tile = new StatTile { Dock = DockStyle.Fill, Margin = new Padding(index % 2 == 0 ? 0 : 5, index < 2 ? 0 : 5, index % 2 == 0 ? 5 : 0, index < 2 ? 5 : 0), Padding = new Padding(12, 5, 8, 2) };
            value.Dock = DockStyle.Fill;
            value.TextAlign = ContentAlignment.TopLeft;
            value.BackColor = Color.Transparent;
            tile.Controls.Add(value);
            tile.Controls.Add(new Label { Text = caption, Tag = "muted", AutoSize = false, Dock = DockStyle.Top, Height = 18, BackColor = Color.Transparent, UseMnemonic = false });
            counts.Controls.Add(tile, index % 2, index / 2);
        }
        progressLayout.Controls.Add(counts, 2, 0);
        var actions = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Anchor = AnchorStyles.Right, BackColor = Color.Transparent, Margin = new Padding(0) };
        actions.Controls.Add(scanPageScanSlot);
        var chooseFiles = new Button { Text = "Choose files…", Size = new Size(168, 40), Margin = new Padding(0, 10, 0, 0) };
        chooseFiles.Click += (_, _) => ChooseFilesToScan();
        actions.Controls.Add(chooseFiles);
        progressLayout.Controls.Add(actions, 3, 0);
        progressCard.Controls.Add(progressLayout);
        page.Controls.Add(progressCard, 0, 2);

        page.Controls.Add(BuildReviewPanel(), 0, 3);
        SyncScanRing();
        return page;
    }

    /// <summary>
    /// "Needs your decision" as designed: one card row per item with its own Details · Ignore ·
    /// Quarantine / Send to VirusTotal buttons. resultsView stays the data source (the scanning
    /// code fills it); it sits off-screen, and each button selects its row there and calls the
    /// existing action.
    /// </summary>
    private Control BuildReviewPanel()
    {
        ConfigureResultsView(resultsView);
        var panel = new CardPanel { Dock = DockStyle.Fill, Radius = 18, Padding = new Padding(6, 10, 6, 10), Margin = new Padding(0) };
        var title = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 52, WrapContents = false, Margin = new Padding(0), Padding = new Padding(20, 12, 20, 0), BackColor = Color.White, Tag = "surface" };
        title.Controls.Add(new Label { Text = "Needs your decision", AutoSize = true, Font = new Font("Segoe UI Semibold", 11.5f, FontStyle.Regular), Margin = new Padding(0, 2, 8, 0), UseMnemonic = false });
        reviewCountLabel.Margin = new Padding(0, 5, 0, 0);
        toolTip.SetToolTip(reviewCountLabel, "Items that need a decision");
        title.Controls.Add(reviewCountLabel);
        reviewNoteLabel.Margin = new Padding(12, 6, 0, 0);
        title.Controls.Add(reviewNoteLabel);
        var export = new LinkLabel { Text = "Export report", AutoSize = true, Margin = new Padding(24, 6, 0, 0), Tag = "accent-link" };
        export.LinkClicked += (_, _) => ExportScanReport();
        title.Controls.Add(export);

        reviewList.Dock = DockStyle.Fill;
        reviewList.AccessibleName = "Needs your decision";
        reviewList.EmptyText = "Nothing needs you. Unknown files and anything flagged show up here.";
        resultsView.Dock = DockStyle.None;
        resultsView.Size = new Size(1, 1);
        resultsView.Location = new Point(-10, -10);
        resultsView.TabStop = false;
        resultsEmptyLabel.Visible = false;
        panel.Controls.Add(reviewList);
        panel.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 1, Tag = "hairline" });
        panel.Controls.Add(title);
        panel.Controls.Add(resultsView);

        reviewList.ActionClicked += (item, action) => RunReviewAction(item, item.Actions[action]);
        reviewList.ItemActivated += (_, _) =>
        {
            if (reviewList.SelectedItem is { } item)
            {
                RunReviewAction(item, "Details");
            }
        };
        var menu = new ContextMenuStrip();
        menu.Opening += (_, args) =>
        {
            menu.Items.Clear();
            if (reviewList.SelectedItem is not { } item)
            {
                args.Cancel = true;
                return;
            }

            foreach (var action in item.Actions.Concat(["Open file location", "Ignore publisher"]).Distinct())
            {
                menu.Items.Add(action, null, (_, _) => RunReviewAction(item, action));
            }
        };
        reviewList.MenuRequested += point => menu.Show(reviewList, point);
        panel.Disposed += (_, _) => menu.Dispose();
        RefreshReviewList();
        return panel;
    }

    private readonly CardList reviewList = new();

    private async void ChooseFilesToScan()
    {
        using var picker = new OpenFileDialog { Title = "Choose files to scan", Multiselect = true, CheckFileExists = true };
        if (picker.ShowDialog(this) == DialogResult.OK && picker.FileNames.Length > 0)
        {
            await ScanSelectedFilesAsync(picker.FileNames);
        }
    }

    /// <summary>Selects the review row in resultsView and runs the existing action on it.</summary>
    private async void RunReviewAction(CardListItem item, string action)
    {
        if (item.Tag is not ListViewItem row || row.ListView != resultsView)
        {
            return;
        }

        resultsView.SelectedItems.Clear();
        row.Selected = true;
        switch (action)
        {
            case "Details":
                ShowReviewDetails(resultsView);
                break;
            case "Ignore":
            case "Unignore":
                ToggleSelectedIgnoreFlagWithConfirm(resultsView);
                break;
            case "Quarantine":
                QuarantineSelectedFiles(resultsView);
                break;
            case "Send to VirusTotal":
                await ApproveSelectedVirusTotalUploadsAsync(resultsView);
                break;
            case "Open file location":
                OpenSelectedFileLocation(resultsView);
                break;
            case "Ignore publisher":
                IgnoreSelectedPublisher(resultsView);
                break;
        }

        RefreshReviewList();
        UpdateHomePage();
    }

    /// <summary>Rebuilds the card rows from resultsView (cheap: the review list is short).</summary>
    private void RefreshReviewList()
    {
        var items = new List<CardListItem>();
        foreach (ListViewItem row in resultsView.Items)
        {
            if (FindResultForReviewQueueRow(row) is not { } result)
            {
                continue;
            }

            var name = Path.GetFileName(result.Path);
            var ignored = string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase);
            var description = ActivityText.Describe(result.Status, result.Malicious, result.Suspicious, ignored, string.IsNullOrWhiteSpace(name) ? result.ProcessNames : name);
            var canUpload = GetVirusTotalUploadTargets([row]).Count > 0;
            var (glyph, tone) = description.Kind switch
            {
                ActivityKind.Threat => ("!", CardTone.Bad),
                ActivityKind.Suspicious => ("!", CardTone.Warn),
                ActivityKind.Unknown => ("?", CardTone.Warn),
                ActivityKind.Error => ("\uE711", CardTone.Neutral),
                ActivityKind.Handled => ("–", CardTone.Neutral),
                _ => ("!", CardTone.Warn),
            };
            var titleText = description.Kind == ActivityKind.Clean ? $"{name} needs a look ({result.RiskLevel} risk)" : description.Title;
            var signer = result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase) ? "not signed" : string.IsNullOrWhiteSpace(result.SignaturePublisher) ? "" : $"signed by {result.SignaturePublisher}";
            var detail = string.Join(" · ", new[] { description.Kind == ActivityKind.Clean ? result.TrustSummary : "", signer, Path.GetDirectoryName(result.Path) ?? "" }.Where(part => !string.IsNullOrWhiteSpace(part)));
            string[] actions = ignored
                ? ["Details", "Unignore"]
                : (description.Kind is ActivityKind.Threat or ActivityKind.Suspicious or ActivityKind.Clean)
                    ? ["Details", "Ignore", "Quarantine"]
                    : canUpload ? ["Details", "Ignore", "Send to VirusTotal"] : ["Details", "Ignore", "Quarantine"];
            items.Add(new CardListItem
            {
                Glyph = glyph,
                Tone = tone,
                Title = titleText,
                Detail = detail,
                Actions = actions,
                DangerAction = Array.IndexOf(actions, "Quarantine"),
                PrimaryAction = Array.IndexOf(actions, "Send to VirusTotal"),
                Tag = row,
            });
        }

        // Most urgent first: threats, then suspicious, then the rest.
        items = items.OrderBy(item => item.Tone switch { CardTone.Bad => 0, CardTone.Warn => 1, _ => 2 }).ToList();
        reviewList.SetItems(items, keepScroll: true);
    }

    /// <summary>Keeps the Scan page's ring, title and counts in step with the scan (called with the summary).</summary>
    /// <summary>
    /// Keeps the Scan page in step with the scan. Per file only the ring and the current path move
    /// (<paramref name="countsToo"/> false); the counts are recomputed with the summary refresh.
    /// </summary>
    private void SyncScanRing(bool countsToo = true)
    {
        var running = scanCancellation is not null || scanGate.IsBusy;
        scanRing.Running = running;
        scanRing.Maximum = Math.Max(1, progressBar.Maximum);
        scanRing.Value = Math.Min(progressBar.Value, scanRing.Maximum);
        scanRingTitle.Text = running ? "Checking running apps…" : results.Count == 0 ? "Ready to scan" : "Scan finished";
        scanRingDetail.Text = running
            ? statusLabel.Text
            : results.Count == 0 ? "Scan the apps running now, or choose files." : HomeStatusText.FormatLastScan(lastScanFinishedLocal, DateTime.Now);
        if (!countsToo)
        {
            return;
        }

        scanCountChecked.Text = results.Count.ToString("N0");
        scanCountClean.Text = results.Count(result => !ResultNeedsAction(result) && result.Status != "error").ToString("N0");
        scanCountUnknown.Text = results.Count(result => result.Status is "unknown" or "uploaded").ToString("N0");
        scanCountThreats.Text = results.Count(result => ResultNeedsAction(result) && result.IsAlert).ToString("N0");
        scanCountClean.ForeColor = activePalette.AccentText;
        scanCountUnknown.ForeColor = activePalette.AttentionText;
        scanCountThreats.ForeColor = activePalette.DangerText;
        var providers = GetEnabledReputationProviders().ToList();
        var signature = string.Join("|", providers);
        if (scanSourceChips.Tag as string != signature)
        {
            scanSourceChips.Tag = signature;
            scanSourceChips.Controls.Clear();
            foreach (var provider in providers)
            {
                var name = provider switch { "VT" => "VirusTotal", "Malware Hash History" => "Team Cymru", _ => provider };
                scanSourceChips.Controls.Add(new PillLabel
                {
                    Text = name,
                    AutoSize = false,
                    Size = new Size(TextRenderer.MeasureText(name, Font).Width + 38, 26),
                    Radius = 12,
                    Padding = new Padding(24, 0, 10, 0),
                    Margin = new Padding(0, 0, 8, 0),
                    PillColor = activePalette.PillBack,
                    ForeColor = activePalette.Text,
                    DotColor = activePalette.AccentText,
                });
            }
        }
    }

    /// <summary>Home hero, pillar cards, tiles and sidebar badges. Cheap; called whenever state changes.</summary>
    private void UpdateHomePage()
    {
        var scanning = scanCancellation is not null || scanGate.IsBusy;
        var threats = results.Count(result => ResultNeedsAction(result) && result.IsAlert);
        var needs = results.Count(ResultNeedsAction);
        var providers = GetEnabledReputationProviders().Count();
        var status = HomeStatusText.Build(scanning, threats, needs, providers, 3, lastScanFinishedLocal, DateTime.Now, appSettings.NetworkMonitorEnabled);
        statusTitle.Text = status.Title;
        statusSubtitle.Text = scanning && !string.IsNullOrWhiteSpace(lastDashboardSubtitle) ? lastDashboardSubtitle : status.Subtitle;
        homeLastScanChip.Text = status.LastScanChip;
        homeSourcesChip.Text = status.SourcesChip;
        homeLastScanChip.Width = TextRenderer.MeasureText(homeLastScanChip.Text, homeLastScanChip.Font).Width + 26;
        homeSourcesChip.Width = TextRenderer.MeasureText(homeSourcesChip.Text, homeSourcesChip.Font).Width + 26;
        homeLastScanChip.PillColor = activePalette.NeutralTint;
        homeLastScanChip.ForeColor = activePalette.Text;
        homeSourcesChip.PillColor = providers > 0 ? activePalette.AccentTint : activePalette.AttentionTint;
        homeSourcesChip.ForeColor = providers > 0 ? activePalette.AccentText : activePalette.AttentionText;
        var topThreat = scanning ? null : FindTopThreat();
        homeThreatCard.Visible = topThreat is not null;
        if (homePageLayout is not null)
        {
            homePageLayout.RowStyles[1].Height = topThreat is null ? 206 : 306;
        }

        if (topThreat is { } threat)
        {
            homeThreatName.Text = Path.GetFileName(threat.Path);
            var engines = threat.Malicious > 0 ? $"Malicious · {threat.Malicious} security vendor{(threat.Malicious == 1 ? "" : "s")} flag it" : $"Suspicious · {threat.Suspicious} vendor{(threat.Suspicious == 1 ? "" : "s")}";
            var signer = threat.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase) ? "not signed" : threat.SignaturePublisher;
            homeThreatDetail.Text = string.Join(" · ", new[] { engines, signer, threat.Path }.Where(part => !string.IsNullOrWhiteSpace(part)));
            homeThreatCard.SurfaceColor = activePalette.DangerTint == ThemePalette.Light.DangerTint ? Color.FromArgb(254, 246, 245) : activePalette.DangerTint;
            homeThreatCard.EdgeColor = homeThreatCard.SurfaceColor;
            homeThreatCard.ShadowColor = Color.Transparent;
            homeThreatCard.Invalidate();
        }
        homeHero.EdgeColor = status.Tone == HomeTone.Danger ? activePalette.DangerTint : activePalette.Hairline;
        homeHero.Invalidate();

        homeAvLastScan.Text = HomeStatusText.FormatLastScan(lastScanFinishedLocal, DateTime.Now).Replace("Last scan ", "", StringComparison.Ordinal);
        homeAvOpenFiles.Text = scanAllFilesBox.Checked ? "Checked automatically" : "Off";
        homeAvSources.Text = providers == 0 ? "None enabled" : string.Join(", ", GetEnabledReputationProviders().Select(name => name switch { "VT" => "VirusTotal", "Malware Hash History" => "Team Cymru", _ => name }));
        SetPill(homeAvPill, threats > 0 ? "Action needed" : needs > 0 ? "Review" : "On", threats > 0 ? "bad" : needs > 0 ? "warn" : "good");
        var online = networkTracker?.Apps.Count(app => app.CurrentConnections > 0) ?? 0;
        homeFwOnline.Text = appSettings.NetworkMonitorEnabled || firewallPageVisible ? online.ToString("N0") : "Monitor off";
        homeFwBlocked.Text = networkBlockedPaths.Count == 1 ? "1 app" : $"{networkBlockedPaths.Count:N0} apps";
        homeFwAlerts.Text = NetworkNotifyModes.Normalize(appSettings.NetworkNotifyMode) switch
        {
            NetworkNotifyModes.NewApps => "Every new app",
            NetworkNotifyModes.Never => "Off",
            _ => "Untrusted apps only",
        };
        SetPill(homeFwPill, appSettings.NetworkMonitorEnabled ? "On" : "Monitor off", appSettings.NetworkMonitorEnabled ? "good" : "warn");

        homeTileDecision.Text = needs == 0 ? "Nothing to decide" : needs == 1 ? "1 item" : $"{needs:N0} items";
        var restorable = GetRestorableQuarantineCount();
        homeTileQuarantine.Text = restorable == 0 ? "Nothing isolated" : restorable == 1 ? "1 file isolated" : $"{restorable:N0} files isolated";
        sidebar.SetBadge(AppPage.Scan, HomeStatusText.BadgeText(needs), alert: true);
        sidebar.SetBadge(AppPage.Quarantine, HomeStatusText.BadgeText(restorable), alert: false);
        reviewNoteLabel.Text = needs == 0 ? "All done. Nothing needs you right now." : "Everything else is clean and needs nothing from you.";
        SyncScanRing();
    }

    private void SetPill(PillLabel pill, string text, string tone)
    {
        pill.Text = text;
        pill.Width = Math.Max(54, TextRenderer.MeasureText(text, pill.Font).Width + 24);
        (pill.PillColor, pill.ForeColor) = tone switch
        {
            "bad" => (activePalette.DangerTint, activePalette.DangerText),
            "warn" => (activePalette.AttentionTint, activePalette.AttentionText),
            _ => (activePalette.AccentTint, activePalette.AccentText),
        };
        pill.Invalidate();
    }

    /// <summary>The most serious flagged file in the review list (malicious before suspicious).</summary>
    private ScanResult? FindTopThreat() =>
        resultsView.Items.Cast<ListViewItem>()
            .Select(FindResultForReviewQueueRow)
            .Where(result => result is not null && ResultNeedsAction(result) && result.IsAlert)
            .OrderByDescending(result => result!.Malicious)
            .ThenByDescending(result => result!.Suspicious)
            .FirstOrDefault();

    /// <summary>The threat card's buttons: act on the top threat's row in the review list.</summary>
    private void RunOnTopThreat(string action)
    {
        var threat = FindTopThreat();
        var row = threat is null ? null : resultsView.Items.Cast<ListViewItem>().FirstOrDefault(item => FindResultForReviewQueueRow(item) == threat);
        if (row is null)
        {
            ShowPage(AppPage.Scan);
            return;
        }

        RunReviewAction(new CardListItem { Tag = row, Actions = [action] }, action);
    }

    /// <summary>Ignore, but ask first when a selected file is flagged malicious or suspicious.</summary>
    private void ToggleSelectedIgnoreFlagWithConfirm(ListView view)
    {
        var flagged = SafeSelectedItems(view)
            .Select(FindResultForReviewQueueRow)
            .Where(result => result is not null && result.IsDetection && !string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase))
            .Select(result => result!)
            .ToList();
        if (flagged.Count > 0)
        {
            var names = string.Join(Environment.NewLine, flagged.Take(6).Select(result => $"• {Path.GetFileName(result.Path)} ({(result.Malicious > 0 ? $"malicious, {result.Malicious}" : $"suspicious, {result.Suspicious}")})"));
            var answer = MessageBox.Show(
                this,
                $"Stop warning about {(flagged.Count == 1 ? "a file" : "files")} security vendors flag?{Environment.NewLine}{Environment.NewLine}{names}{Environment.NewLine}{Environment.NewLine}HashGuard won't warn about {(flagged.Count == 1 ? "it" : "them")} again. Press Ignore again on the same item to undo.",
                "Ignore anyway?",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes)
            {
                return;
            }
        }

        ToggleSelectedIgnoreFlag(view);
        UpdateHomePage();
    }

    /// <summary>Details for the selected review item: why, each source's verdict, signer, path, hash.</summary>
    private void ShowReviewDetails(ListView view)
    {
        var item = SafeSelectedItems(view).FirstOrDefault();
        var result = item is null ? null : FindResultForReviewQueueRow(item);
        if (item is null || result is null)
        {
            return;
        }

        using var dialog = new Form
        {
            Text = $"{Path.GetFileName(result.Path)}: details",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(640, 600),
            MinimumSize = new Size(520, 460),
            ShowInTaskbar = false,
            MinimizeBox = false,
        };
        var text = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            BorderStyle = BorderStyle.None,
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            Text = string.Join(Environment.NewLine, new[]
            {
                Path.GetFileName(result.Path),
                $"{result.Status} · risk {result.RiskLevel} ({result.RiskScore})",
                "",
                "Why it's here",
                BuildReasonSummary(item),
                "",
                "Reputation sources",
                string.IsNullOrWhiteSpace(result.ProviderSummary) ? "No source answered." : result.ProviderSummary.Replace(" | ", Environment.NewLine, StringComparison.Ordinal),
                "",
                $"Signed by: {(string.IsNullOrWhiteSpace(result.SignatureSummary) ? "unknown" : result.SignatureSummary)}",
                $"Location: {result.Path}",
                $"SHA-256: {result.Sha256}",
                $"Running: {(string.IsNullOrWhiteSpace(result.Pids) ? "no" : $"yes (PID {result.Pids})")}",
            }),
        };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 52, FlowDirection = FlowDirection.LeftToRight, Padding = new Padding(12, 10, 12, 8), WrapContents = false };
        var openReport = new Button { Text = "Open VirusTotal report", AutoSize = true };
        var openLocation = new Button { Text = "Open file location", AutoSize = true };
        var copyHash = new Button { Text = "Copy hash", AutoSize = true };
        var ignorePublisher = new Button { Text = "Ignore publisher", AutoSize = true, Enabled = !string.IsNullOrWhiteSpace(result.SignaturePublisher) };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.OK };
        openReport.Click += (_, _) => OpenSelectedReport(view);
        openLocation.Click += (_, _) => OpenSelectedFileLocation(view);
        copyHash.Click += (_, _) => CopySelectedHash(view);
        ignorePublisher.Click += (_, _) =>
        {
            IgnoreSelectedPublisher(view);
            dialog.Close();
        };
        buttons.Controls.AddRange([openReport, openLocation, copyHash, ignorePublisher, close]);
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

    /// <summary>
    /// Shows an alert: in the window (bottom-right overlay) when it is open, otherwise in a pop-up
    /// just above the tray.
    /// </summary>
    private void ShowAlert(AlertTone tone, string title, string body, IReadOnlyList<AlertButton> actions)
    {
        var card = new AlertCard();
        card.Surface = activePalette.Surface;
        card.Edge = activePalette.Hairline;
        card.TextColor = activePalette.Text;
        card.MutedColor = activePalette.MutedText;
        card.ButtonBack = activePalette.ButtonBack;
        card.ButtonBorder = activePalette.Border;
        card.Show(tone, title, body, actions);
        var windowOpen = Visible && WindowState != FormWindowState.Minimized;
        if (windowOpen)
        {
            overlayAlert?.Dispose();
            overlayAlert = card;
            var hostOrigin = PointToClient(pageHost.PointToScreen(Point.Empty));
            void Place() => card.Location = new Point(
                hostOrigin.X + pageHost.Width - card.Width - 20,
                hostOrigin.Y + pageHost.Height - card.Height - 16);
            Controls.Add(card);
            Place();
            card.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
            card.SizeChanged += (_, _) => Place();
            card.BringToFront();
            card.Dismissed += (_, _) =>
            {
                if (overlayAlert == card)
                {
                    overlayAlert = null;
                }

                card.Dispose();
            };
            var timer = new System.Windows.Forms.Timer { Interval = 30000 };
            timer.Tick += (_, _) =>
            {
                timer.Dispose();
                if (!card.IsDisposed && !card.ClientRectangle.Contains(card.PointToClient(Cursor.Position)))
                {
                    card.Dismiss();
                }
            };
            timer.Start();
            return;
        }

        TrayPopup.ShowCard(card);
    }
}
