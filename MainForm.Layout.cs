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
    private void BuildLayout()
    {
        BackColor = SoftAppBack;
        trayIcon.Text = "HashGuard";
        trayIcon.Icon = cleanTrayIcon;
        trayIcon.Visible = true;
        trayIcon.DoubleClick += (_, _) => RestoreFromTray();
        trayIcon.ContextMenuStrip = new ContextMenuStrip();
        trayIcon.ContextMenuStrip.Items.Add("Open", null, (_, _) => RestoreFromTray());
        trayIcon.ContextMenuStrip.Items.Add("Scan Now", null, async (_, _) => await StartScanAsync());
        trayIcon.ContextMenuStrip.Items.Add("View Quarantine", null, (_, _) =>
        {
            RestoreFromTray();
            ShowQuarantineDialog();
        });
        trayIcon.ContextMenuStrip.Items.Add("Exit", null, (_, _) =>
        {
            exitRequested = true;
            trayIcon.Visible = false;
            Close();
        });

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(0),
            BackColor = SoftAppBack,
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        Controls.Add(root);

        // Header: app mark + name on the left, Update / Settings / Scan Now on the right.
        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 2,
            Height = 64,
            BackColor = Color.White,
            Padding = new Padding(24, 14, 24, 14),
            Margin = new Padding(0),
        };
        header.Tag = "header";
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Paint += (_, e) => DrawHairline(e.Graphics, 0, header.Height - 1, header.Width, activePalette.Hairline);
        var titleBlock = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0) };
        var appMark = new IconBadge("", "brand") { Size = new Size(30, 30), Radius = 8, Margin = new Padding(0, 3, 10, 0) };
        appMark.Font = new Font("Segoe MDL2 Assets", 11, FontStyle.Regular);
        titleBlock.Controls.Add(appMark);
        titleBlock.Controls.Add(new Label
        {
            Text = "HashGuard",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 13, FontStyle.Regular),
            ForeColor = Color.FromArgb(27, 31, 36),
            Margin = new Padding(0, 5, 0, 0),
            Tag = "header-title",
        });
        header.Controls.Add(titleBlock, 0, 0);
        var headerButtons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0),
            Padding = new Padding(0),
        };
        ConfigureHeaderButton(updateButton);
        updateButton.Margin = new Padding(0, 0, 8, 0);
        updateButton.TextAlign = ContentAlignment.MiddleCenter;
        toolTip.SetToolTip(updateButton, "Check for HashGuard updates");
        ConfigureHeaderButton(settingsButton);
        settingsButton.Margin = new Padding(0, 0, 8, 0);
        settingsButton.TextAlign = ContentAlignment.MiddleCenter;
        settingsButton.AccessibleName = "Settings";
        toolTip.SetToolTip(settingsButton, "Settings");
        scanButton.Margin = new Padding(0);
        scanButton.TextAlign = ContentAlignment.MiddleCenter;
        SetScanButtonReadyStyle();
        headerButtons.Controls.Add(updateButton);
        headerButtons.Controls.Add(settingsButton);
        headerButtons.Controls.Add(scanButton);
        header.Controls.Add(headerButtons, 1, 0);
        root.Controls.Add(header, 0, 0);

        var main = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(24, 20, 24, 16),
            BackColor = SoftAppBack,
        };
        main.RowStyles.Add(new RowStyle(SizeType.Absolute, 216));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.Controls.Add(main, 0, 1);
        resultsView.Name = MainResultsViewName;

        var overview = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Margin = new Padding(0, 0, 0, 16),
            BackColor = SoftAppBack,
        };
        overview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
        overview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
        main.Controls.Add(overview, 0, 0);

        // Status card: the badge and one plain-language headline carry the state.
        var statusCard = CreateSoftCardPanel();
        statusCard.Radius = 14;
        statusCard.Margin = new Padding(0, 0, 16, 0);
        statusCard.Padding = new Padding(22, 20, 22, 20);
        statusDot.Paint += (_, e) => PaintStatusBadge(e.Graphics, statusDot.ClientRectangle, statusDot.Tag as string ?? "idle", activePalette);
        statusDot.Width = 80;
        statusDot.Height = 80;
        statusDot.Margin = new Padding(0, 0, 18, 0);
        statusDot.BackColor = Color.Transparent;
        statusTitle.AutoSize = false;
        statusTitle.Dock = DockStyle.Fill;
        statusTitle.TextAlign = ContentAlignment.BottomLeft;
        statusSubtitle.AutoSize = false;
        statusSubtitle.Dock = DockStyle.Fill;
        statusSubtitle.TextAlign = ContentAlignment.TopLeft;
        statusSubtitle.MaximumSize = new Size(0, 0);
        statusSubtitle.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);
        statusSubtitle.Margin = new Padding(1, 4, 0, 0);

        var statusLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, BackColor = Color.Transparent };
        statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        statusLayout.Controls.Add(statusDot, 0, 0);
        statusLayout.SetRowSpan(statusDot, 2);

        var statusText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0), BackColor = Color.Transparent };
        statusText.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        statusText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusText.Controls.Add(statusTitle, 0, 0);
        statusText.Controls.Add(statusSubtitle, 0, 1);
        statusLayout.Controls.Add(statusText, 1, 0);

        var stats = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 8, 0, 0), BackColor = Color.Transparent };
        stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        stats.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        summaryLabel.Dock = DockStyle.Fill;
        summaryLabel.MaximumSize = new Size(0, 0);
        summaryLabel.Padding = new Padding(14, 0, 10, 0);
        summaryLabel.Margin = new Padding(0, 0, 5, 0);
        actionLabel.Dock = DockStyle.Fill;
        actionLabel.Padding = new Padding(14, 0, 10, 0);
        actionLabel.Margin = new Padding(5, 0, 0, 0);
        stats.Controls.Add(summaryLabel, 0, 0);
        stats.Controls.Add(actionLabel, 1, 0);
        statusLayout.Controls.Add(stats, 0, 2);
        statusLayout.SetColumnSpan(stats, 2);
        statusCard.Controls.Add(statusLayout);
        overview.Controls.Add(statusCard, 0, 0);

        var tiles = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, Padding = new Padding(0), Margin = new Padding(0) };
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        tiles.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        tiles.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        var processTile = CreateFeatureTile("Process Security", "Running apps", "Protected", "");
        var reputationTile = CreateReputationTile();
        var quarantineTile = CreateQuarantineTile();
        var activityTile = CreateFeatureTile("Activity Log", "Scan history", "View history", "", ShowScanDetailsDialogSafe);
        // 12 px gaps between tiles, flush with the grid's outer edges.
        processTile.Margin = new Padding(0, 0, 6, 6);
        reputationTile.Margin = new Padding(6, 0, 0, 6);
        quarantineTile.Margin = new Padding(0, 6, 6, 0);
        activityTile.Margin = new Padding(6, 6, 0, 0);
        tiles.Controls.Add(processTile, 0, 0);
        tiles.Controls.Add(reputationTile, 1, 0);
        tiles.Controls.Add(quarantineTile, 0, 1);
        tiles.Controls.Add(activityTile, 1, 1);
        overview.Controls.Add(tiles, 1, 0);

        ConfigureResultsView(resultsView);
        var resultsPanel = CreateSoftCardPanel();
        resultsPanel.Radius = 14;
        resultsPanel.Padding = new Padding(20, 12, 20, 12);
        resultsPanel.Margin = new Padding(0);
        var resultsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Color.Transparent };
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        // Room for two wrapped button rows; buttons are bottom-aligned inside this strip.
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
        var queueTitle = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0),
            BackColor = Color.Transparent,
        };
        queueTitle.Controls.Add(new Label
        {
            Text = "Review Queue",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 11, FontStyle.Regular),
            Margin = new Padding(0, 4, 8, 0),
            BackColor = Color.Transparent,
        });
        reviewCountLabel.Margin = new Padding(0, 6, 0, 0);
        toolTip.SetToolTip(reviewCountLabel, "Items that need a decision");
        queueTitle.Controls.Add(reviewCountLabel);
        resultsLayout.Controls.Add(queueTitle, 0, 0);
        var resultsHost = new Panel { Dock = DockStyle.Fill };
        resultsHost.Controls.Add(resultsEmptyLabel);
        resultsHost.Controls.Add(resultsView);
        resultsEmptyLabel.BringToFront();
        resultsLayout.Controls.Add(resultsHost, 0, 1);
        resultsLayout.Paint += (_, e) =>
        {
            // Hairlines above the list and above the action bar instead of boxed borders.
            var listTop = resultsLayout.GetRowHeights()[0] - 1;
            var barTop = resultsLayout.Height - resultsLayout.GetRowHeights()[2];
            DrawHairline(e.Graphics, 0, listTop, resultsLayout.Width, activePalette.Hairline);
            DrawHairline(e.Graphics, 0, barTop, resultsLayout.Width, activePalette.Hairline);
        };
        // Triage actions on the left (grouped: open / ignore / act), utilities on the right.
        var queueActionsHost = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Margin = new Padding(0),
            Padding = new Padding(0),
            BackColor = Color.Transparent,
        };
        queueActionsHost.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        queueActionsHost.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        queueActionsHost.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var queueActions = new FlowLayoutPanel
        {
            Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            AutoScroll = false,
            Margin = new Padding(0),
            Padding = new Padding(0, 6, 0, 0),
            BackColor = Color.Transparent,
        };
        var utilityActions = new FlowLayoutPanel
        {
            Anchor = AnchorStyles.Right | AnchorStyles.Bottom,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(8, 0, 0, 0),
            Padding = new Padding(0, 6, 0, 0),
            BackColor = Color.Transparent,
        };
        var openReport = CreateQueueActionButton("Open Report");
        var openLocation = CreateQueueActionButton("Open Location");
        var ignoreSelected = CreateQueueActionButton("Ignore");
        var ignorePublisher = CreateQueueActionButton("Ignore Publisher");
        var quarantineSelected = CreateQueueActionButton("Quarantine");
        quarantineSelected.Tag = "danger-button";
        quarantineSelected.Font = new Font("Segoe UI Semibold", 9, FontStyle.Regular);
        var approveUpload = CreateQueueActionButton("Approve Upload");
        var exportReport = CreateQueueActionButton("Export");
        exportReport.Tag = "quiet-button";
        exportReport.MinimumSize = new Size(64, 32);
        var activityLog = CreateQueueActionButton("Activity Log");
        activityLog.Tag = "quiet-button";
        activityLog.MinimumSize = new Size(64, 32);
        activityLog.Margin = new Padding(0);
        openReport.Click += (_, _) => OpenSelectedReport(resultsView);
        openLocation.Click += (_, _) => OpenSelectedFileLocation(resultsView);
        ignoreSelected.Click += (_, _) => ToggleSelectedIgnoreFlag(resultsView);
        ignorePublisher.Click += (_, _) => IgnoreSelectedPublisher(resultsView);
        quarantineSelected.Click += (_, _) => QuarantineSelectedFiles(resultsView);
        approveUploadButton = approveUpload;
        approveUpload.Click += async (_, _) => await ApproveSelectedVirusTotalUploadsAsync(resultsView);
        exportReport.Click += (_, _) => ExportScanReport();
        activityLog.Click += (_, _) => ShowScanDetailsDialogSafe();
        resultsView.SelectedIndexChanged += (_, _) =>
        {
            if (reviewQueueBusy)
            {
                return;
            }

            ReconcileReviewQueue(updateSummary: false);
            UpdateReviewQueueActionButtons(
                openReport, openLocation, ignoreSelected, ignorePublisher, quarantineSelected);
        };
        resultsView.Enter += (_, _) => ReconcileReviewQueue();
        resultsView.MouseDown += (_, _) => ReconcileReviewQueue();
        openReport.Enabled = false;
        openLocation.Enabled = false;
        ignoreSelected.Enabled = false;
        ignorePublisher.Enabled = false;
        quarantineSelected.Enabled = false;
        approveUpload.Enabled = false;
        // Same order as before; separators only group them.
        queueActions.Controls.Add(openReport);
        queueActions.Controls.Add(openLocation);
        queueActions.Controls.Add(CreateActionSeparator());
        queueActions.Controls.Add(ignoreSelected);
        queueActions.Controls.Add(ignorePublisher);
        queueActions.Controls.Add(CreateActionSeparator());
        queueActions.Controls.Add(quarantineSelected);
        queueActions.Controls.Add(approveUpload);
        utilityActions.Controls.Add(exportReport);
        utilityActions.Controls.Add(activityLog);
        queueActionsHost.Controls.Add(queueActions, 0, 0);
        queueActionsHost.Controls.Add(utilityActions, 1, 0);
        resultsLayout.Controls.Add(queueActionsHost, 0, 2);
        resultsPanel.Controls.Add(resultsLayout);
        main.Controls.Add(resultsPanel, 0, 1);

        // Status bar: a thin progress line along its top edge, status text and count below.
        var footer = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0), Padding = new Padding(0), Tag = "footer" };
        footer.Paint += (_, e) => DrawHairline(e.Graphics, 0, 0, footer.Width, activePalette.Hairline);
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0), Padding = new Padding(24, 0, 24, 0), BackColor = Color.Transparent };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        progressBar.Dock = DockStyle.Top;
        progressBar.Height = 4;
        progressBar.Margin = new Padding(0);
        progressBar.Style = ProgressBarStyle.Continuous;
        statusLabel.Dock = DockStyle.Fill;
        statusLabel.TextAlign = ContentAlignment.MiddleLeft;
        statusLabel.Margin = new Padding(0);
        statusLabel.AutoSize = false;
        statusLabel.AutoEllipsis = true;
        statusLabel.UseMnemonic = false;
        statusLabel.Tag = "muted";
        countLabel.AutoSize = false;
        countLabel.Dock = DockStyle.Fill;
        countLabel.TextAlign = ContentAlignment.MiddleRight;
        countLabel.Margin = new Padding(0);
        countLabel.Width = 96;
        countLabel.Tag = "muted";
        bottom.Controls.Add(statusLabel, 0, 0);
        bottom.Controls.Add(countLabel, 1, 0);
        footer.Controls.Add(bottom);
        footer.Controls.Add(progressBar);
        root.Controls.Add(footer, 0, 2);
        statusLabel.Text = "Ready";
        UpdateResultsEmptyState();
        UpdateReputationTile();
        UpdateQuarantineTile();
        ApplyAppTheme(this);
    }

    private static void DrawHairline(Graphics graphics, int x, int y, int width, Color color)
    {
        using var pen = new Pen(color, 1);
        graphics.DrawLine(pen, x, y, x + width, y);
    }

    private static Panel CreateActionSeparator()
    {
        return new Panel { Width = 1, Height = 18, Margin = new Padding(6, 7, 12, 0), Tag = "separator" };
    }

    private void UpdateReviewCount()
    {
        UpdateReviewCount(results.Count(ResultNeedsAction));
    }

    private void UpdateReviewCount(int needsReview)
    {
        reviewCountLabel.Text = needsReview.ToString("N0");
        reviewCountLabel.PillColor = needsReview > 0 ? activePalette.DangerTint : activePalette.PillBack;
        reviewCountLabel.ForeColor = needsReview > 0 ? activePalette.DangerText : activePalette.MutedText;
        reviewCountLabel.Invalidate();
        actionLabel.PillColor = needsReview > 0 ? activePalette.DangerTint : activePalette.PillBack;
        actionLabel.ForeColor = needsReview > 0 ? activePalette.DangerText : activePalette.Text;
        actionLabel.Invalidate();
    }

    private static CardPanel CreateSoftCardPanel()
    {
        return new CardPanel
        {
            Dock = DockStyle.Fill,
            BackColor = SoftAppBack,
            BorderStyle = BorderStyle.None,
            Padding = new Padding(14),
        };
    }

    private static CardPanel CreateFeatureTile(string title, string subtitle, string state, string glyph, Action? onClick = null)
    {
        var tile = CreateSoftCardPanel();
        tile.Padding = new Padding(14, 12, 12, 12);
        var stateLabel = CreateTileState(state, SuccessGreen);
        stateLabel.Tag = "tile-ok";
        var layout = CreateTileLayout(
            new IconBadge(glyph, onClick is null ? "accent" : "neutral"),
            CreateTileTitle(title),
            CreateTileDetail(subtitle),
            stateLabel,
            showChevron: onClick is not null);
        tile.Controls.Add(layout);
        if (onClick is not null)
        {
            WireClick(tile, onClick);
            tile.MakeInteractive();
        }

        return tile;
    }

    private CardPanel CreateReputationTile()
    {
        var tile = CreateSoftCardPanel();
        tile.Padding = new Padding(14, 12, 12, 12);
        ConfigureTileDetailLabel(reputationStateLabel);
        ConfigureTileStateLabel(reputationProtectionLabel, SuccessGreen);
        var layout = CreateTileLayout(
            new IconBadge("", "accent"),
            CreateTileTitle("Cloud Reputation"),
            reputationStateLabel,
            reputationProtectionLabel,
            showChevron: false);
        tile.Controls.Add(layout);
        return tile;
    }

    private void UpdateReputationTile()
    {
        var enabled = GetEnabledReputationProviders().ToList();
        reputationStateLabel.Text = $"Connected services {enabled.Count}/3";
        reputationStateLabel.ForeColor = activePalette.MutedText;
        reputationProtectionLabel.Text = enabled.Count == 0 ? "Not protected" : "Protected";
        reputationProtectionLabel.ForeColor = enabled.Count == 0 ? activePalette.DangerText : activePalette.AccentText;
    }

    private CardPanel CreateQuarantineTile()
    {
        var tile = CreateSoftCardPanel();
        tile.Padding = new Padding(14, 12, 12, 12);
        ConfigureTileDetailLabel(quarantineCountLabel);
        ConfigureTileStateLabel(quarantineStateLabel, SuccessGreen);
        var layout = CreateTileLayout(
            new IconBadge("", "neutral"),
            CreateTileTitle("Quarantine"),
            quarantineCountLabel,
            quarantineStateLabel,
            showChevron: true);
        tile.Controls.Add(layout);
        WireClick(tile, ShowQuarantineDialog);
        tile.MakeInteractive();
        toolTip.SetToolTip(tile, "View quarantined files and restore or delete them");
        return tile;
    }

    private static void ConfigureHeaderButton(Button button)
    {
        // Outline buttons on light chrome; the theme pass sets their colors.
        button.BackColor = Color.White;
        button.ForeColor = Color.FromArgb(27, 31, 36);
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 1;
        button.FlatAppearance.BorderColor = SoftBorder;
        button.UseVisualStyleBackColor = false;
    }

    private static Button CreateQueueActionButton(string text)
    {
        return new Button
        {
            Text = text,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(84, 32),
            Height = 32,
            Margin = new Padding(0, 0, 6, 0),
            Padding = new Padding(8, 0, 8, 0),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Color.FromArgb(27, 31, 36),
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            UseVisualStyleBackColor = false,
        };
    }

    private static TableLayoutPanel CreateTileLayout(IconBadge icon, Label title, Label detail, Label state, bool showChevron)
    {
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 3,
            Margin = new Padding(0),
            Padding = new Padding(0),
            BackColor = Color.Transparent,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 46));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 18));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        icon.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        icon.Margin = new Padding(0, 2, 0, 0);
        layout.Controls.Add(icon, 0, 0);
        layout.SetRowSpan(icon, 3);
        layout.Controls.Add(title, 1, 0);
        layout.Controls.Add(detail, 1, 1);
        layout.Controls.Add(state, 1, 2);
        if (showChevron)
        {
            var chevron = new Label
            {
                Text = "",
                Font = new Font("Segoe MDL2 Assets", 8, FontStyle.Regular),
                AutoSize = false,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleRight,
                Margin = new Padding(0),
                Tag = "chevron",
            };
            layout.Controls.Add(chevron, 2, 0);
            layout.SetRowSpan(chevron, 3);
        }

        return layout;
    }

    private static Label CreateTileTitle(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = false,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular),
            ForeColor = Color.FromArgb(27, 31, 36),
            Margin = new Padding(0),
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
        };
    }

    private static Label CreateTileDetail(string text)
    {
        var label = new Label { Text = text, Tag = "muted" };
        ConfigureTileDetailLabel(label);
        return label;
    }

    private static Label CreateTileState(string text, Color color)
    {
        var label = new Label { Text = text };
        ConfigureTileStateLabel(label, color);
        return label;
    }

    private static void ConfigureTileDetailLabel(Label label)
    {
        label.AutoSize = false;
        label.Dock = DockStyle.Fill;
        label.Font = new Font("Segoe UI", 9, FontStyle.Regular);
        label.ForeColor = Color.FromArgb(86, 96, 106);
        label.Margin = new Padding(0);
        label.TextAlign = ContentAlignment.MiddleLeft;
        label.AutoEllipsis = true;
    }

    private static void ConfigureTileStateLabel(Label label, Color color)
    {
        label.AutoSize = false;
        label.Dock = DockStyle.Fill;
        label.Font = new Font("Segoe UI Semibold", 9, FontStyle.Regular);
        label.ForeColor = color;
        label.Margin = new Padding(0, 4, 0, 0);
        label.TextAlign = ContentAlignment.TopLeft;
        label.AutoEllipsis = true;
    }

    private void UpdateQuarantineTile()
    {
        var restorable = HashGuardLogic.CountRestorableQuarantineEntries(LoadQuarantineManifest());
        quarantineCountLabel.Text = restorable == 0
            ? "No files held"
            : restorable == 1 ? "1 file held" : $"{restorable} files held";
        quarantineCountLabel.ForeColor = activePalette.MutedText;
        quarantineStateLabel.Text = "View / Restore";
        quarantineStateLabel.ForeColor = restorable == 0 ? activePalette.AccentText : activePalette.AttentionText;
    }

    private IEnumerable<string> GetEnabledReputationProviders()
    {
        if (metaDefenderEnabledBox.Checked)
        {
            yield return "MetaDefender";
        }

        if (virusTotalEnabledBox.Checked)
        {
            yield return "VT";
        }

        if (mhrEnabledBox.Checked)
        {
            yield return "Malware Hash History";
        }
    }

    private static void WireClick(Control control, Action action)
    {
        control.Cursor = Cursors.Hand;
        control.Click += (_, _) => action();
        foreach (Control child in control.Controls)
        {
            WireClick(child, action);
        }
    }

    private static void ConfigureResultsView(ListView view)
    {
        if (view.Columns.Count > 0)
        {
            return;
        }

        if (view.Name == MainResultsViewName)
        {
            view.Columns.Add("Status", 112);
            view.Columns.Add("Risk", 92);
            view.Columns.Add("Trust / Publisher", 240);
            view.Columns.Add("Malicious", 0);
            view.Columns.Add("Suspicious", 0);
            view.Columns.Add("Process", 190);
            view.Columns.Add("PID(s)", 0);
            view.Columns.Add("SHA-256", 0);
            view.Columns.Add("Location", 440);
            view.Columns.Add("Recommended Review", 360);
        }
        else
        {
            view.Columns.Add("Status", 100);
            view.Columns.Add("Risk", 92);
            view.Columns.Add("Trust", 240);
            view.Columns.Add("Malicious", 84);
            view.Columns.Add("Suspicious", 84);
            view.Columns.Add("Process", 170);
            view.Columns.Add("PID(s)", 95);
            view.Columns.Add("SHA-256", 420);
            view.Columns.Add("Path", 520);
            view.Columns.Add("Notes", 360);
        }

        view.Dock = DockStyle.Fill;
        view.BackColor = Color.White;
        view.GridLines = false;
        view.HideSelection = false;
        view.BorderStyle = view.Name == MainResultsViewName ? BorderStyle.None : BorderStyle.FixedSingle;
        view.Font = new Font("Segoe UI", 9, FontStyle.Regular);
    }

    private static void PaintStatusBadge(Graphics graphics, Rectangle bounds, string state, ThemePalette palette)
    {
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        // Static badge (no animation): a solid state circle inside a soft halo of the same hue.
        var outer = Math.Max(20, Math.Min(bounds.Width, bounds.Height) - 4);
        var actionNeeded = state == "action";
        var scanning = state is "scanning" or "stopped";
        var idle = state == "idle";
        var fillColor = actionNeeded
            ? DangerRed
            : scanning
                ? AttentionYellow
                : idle
                    ? Color.FromArgb(169, 180, 187)
                    : BrandGreen;
        var haloColor = actionNeeded
            ? palette.DangerTint
            : scanning
                ? palette.AttentionTint
                : idle
                    ? palette.NeutralTint
                    : palette.AccentTint;
        var haloRect = new RectangleF((bounds.Width - outer) / 2f, (bounds.Height - outer) / 2f, outer, outer);
        using (var halo = new SolidBrush(haloColor))
        {
            graphics.FillEllipse(halo, haloRect);
        }

        var size = outer * 0.74f;
        var rect = new RectangleF((bounds.Width - size) / 2f, (bounds.Height - size) / 2f, size, size);
        using (var fill = new SolidBrush(fillColor))
        {
            graphics.FillEllipse(fill, rect);
        }

        var glyphColor = actionNeeded || idle ? Color.White : Color.FromArgb(18, 38, 10);
        using var pen = new Pen(glyphColor, Math.Max(3, size / 11))
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
            LineJoin = System.Drawing.Drawing2D.LineJoin.Round,
        };
        if (actionNeeded)
        {
            var centerX = rect.Left + rect.Width / 2f;
            graphics.DrawLine(pen, centerX, rect.Top + rect.Height * 0.25f, centerX, rect.Top + rect.Height * 0.58f);
            using var dot = new SolidBrush(Color.White);
            graphics.FillEllipse(dot, centerX - size * 0.065f, rect.Top + rect.Height * 0.70f, size * 0.13f, size * 0.13f);
        }
        else if (idle)
        {
            using var idlePen = new Pen(Color.White, Math.Max(3, size / 12));
            graphics.DrawEllipse(idlePen, rect.Left + size * 0.32f, rect.Top + size * 0.32f, size * 0.36f, size * 0.36f);
        }
        else if (scanning)
        {
            // Static activity bars (no animation).
            var cx = rect.Left + rect.Width / 2f;
            var cy = rect.Top + rect.Height / 2f;
            var barW = Math.Max(3f, size * 0.09f);
            var gap = size * 0.15f;
            using var barBrush = new SolidBrush(Color.FromArgb(42, 28, 0));
            for (var i = -1; i <= 1; i++)
            {
                var h = i == 0 ? size * 0.40f : size * 0.22f;
                var barRect = new RectangleF(cx + i * gap - barW / 2f, cy - h / 2f, barW, h);
                using var bar = RoundedPaint.RoundedRect(barRect, barW / 2f);
                graphics.FillPath(barBrush, bar);
            }
        }
        else
        {
            graphics.DrawLines(pen, new[]
            {
                new PointF(rect.Left + rect.Width * 0.28f, rect.Top + rect.Height * 0.51f),
                new PointF(rect.Left + rect.Width * 0.44f, rect.Top + rect.Height * 0.66f),
                new PointF(rect.Left + rect.Width * 0.73f, rect.Top + rect.Height * 0.35f),
            });
        }
    }

    private static Icon CreateTrayStatusIcon(TrayState state)
    {
        using var bitmap = new Bitmap(64, 64);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.Clear(Color.Transparent);

        PaintTrayStatusIcon(graphics, state);

        var handle = bitmap.GetHicon();
        try
        {
            return (Icon)Icon.FromHandle(handle).Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    private static void PaintTrayStatusIcon(Graphics graphics, TrayState state)
    {
        var badgeColor = state switch
        {
            TrayState.ActionNeeded => DangerRed,
            TrayState.Scanning => AttentionYellow,
            _ => BrandGreen,
        };

        using var badgeFill = new SolidBrush(badgeColor);
        using var badgeRing = new Pen(Color.FromArgb(24, 24, 24), 5.0f);
        using var badgeHighlight = new Pen(Color.White, 2.4f);
        using var badgePen = new Pen(Color.White, 8.0f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
        graphics.FillEllipse(badgeFill, 4, 4, 56, 56);
        graphics.DrawEllipse(badgeRing, 4, 4, 56, 56);
        graphics.DrawArc(badgeHighlight, 12, 10, 38, 34, 205, 105);

        if (state == TrayState.Clean)
        {
            graphics.DrawLines(badgePen, new[] { new Point(17, 34), new Point(27, 45), new Point(47, 22) });
        }
        else if (state == TrayState.ActionNeeded)
        {
            graphics.DrawLine(badgePen, 32, 16, 32, 39);
            graphics.FillEllipse(Brushes.White, 27, 46, 10, 10);
        }
        else if (state == TrayState.Scanning)
        {
            graphics.FillEllipse(Brushes.White, 22, 22, 20, 20);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);
}
