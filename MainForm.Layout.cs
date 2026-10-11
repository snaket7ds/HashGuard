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
            RowCount = 4,
            Padding = new Padding(0),
            BackColor = SoftAppBack,
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 4)); // brand accent strip
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));
        Controls.Add(root);

        var brandStrip = new Panel { Dock = DockStyle.Fill, BackColor = BrandGreen, Margin = new Padding(0), Tag = "brand-strip" };
        root.Controls.Add(brandStrip, 0, 0);

        // Light SecureAnywhere-style header (white/soft) instead of solid black admin bar.
        var header = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 2,
            Height = 76,
            BackColor = Color.White,
            Padding = new Padding(24, 12, 24, 12),
            Margin = new Padding(0),
        };
        header.Tag = "header";
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var titleBlock = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(0) };
        titleBlock.Controls.Add(new Label
        {
            Text = "HashGuard",
            AutoSize = true,
            Font = new Font("Segoe UI Semibold", 18, FontStyle.Bold),
            ForeColor = Color.FromArgb(32, 40, 48),
            Margin = new Padding(0),
            Tag = "header-title",
        });
        titleBlock.Controls.Add(new Label
        {
            Text = "Endpoint protection · Reputation · Quarantine",
            AutoSize = true,
            ForeColor = Color.FromArgb(100, 110, 120),
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
            Margin = new Padding(1, 2, 0, 0),
            Tag = "header-sub",
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
        ConfigureHeaderButton(settingsButton);
        settingsButton.Margin = new Padding(0, 0, 10, 0);
        settingsButton.TextAlign = ContentAlignment.MiddleCenter;
        settingsButton.AccessibleName = "Settings";
        toolTip.SetToolTip(settingsButton, "Settings");
        ConfigureHeaderButton(updateButton);
        updateButton.Margin = new Padding(0, 0, 10, 0);
        updateButton.TextAlign = ContentAlignment.MiddleCenter;
        toolTip.SetToolTip(updateButton, "Check for HashGuard updates");
        scanButton.Margin = new Padding(0);
        scanButton.TextAlign = ContentAlignment.MiddleCenter;
        SetScanButtonReadyStyle();
        headerButtons.Controls.Add(updateButton);
        headerButtons.Controls.Add(settingsButton);
        headerButtons.Controls.Add(scanButton);
        header.Controls.Add(headerButtons, 1, 0);
        root.Controls.Add(header, 0, 1);

        var main = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(20, 16, 20, 10),
            BackColor = SoftAppBack,
        };
        main.RowStyles.Add(new RowStyle(SizeType.Absolute, 218));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.Controls.Add(main, 0, 2);
        resultsView.Name = MainResultsViewName;

        var overview = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Margin = new Padding(0, 0, 0, 12),
            BackColor = SoftAppBack,
        };
        overview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
        overview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
        main.Controls.Add(overview, 0, 0);

        var statusCard = CreateSoftCardPanel();
        statusCard.Margin = new Padding(0, 0, 12, 0);
        statusCard.Padding = new Padding(18);
        statusDot.Paint += (_, e) => PaintStatusBadge(e.Graphics, statusDot.ClientRectangle, statusDot.Tag as string ?? "idle");
        statusDot.Width = 96;
        statusDot.Height = 96;
        statusDot.Margin = new Padding(0, 0, 18, 0);
        statusDot.BackColor = Color.Transparent;
        statusTitle.AutoSize = false;
        statusTitle.Dock = DockStyle.Fill;
        statusTitle.Font = new Font("Segoe UI Semibold", 17, FontStyle.Bold);
        statusTitle.TextAlign = ContentAlignment.BottomLeft;
        statusSubtitle.AutoSize = false;
        statusSubtitle.Dock = DockStyle.Fill;
        statusSubtitle.TextAlign = ContentAlignment.TopLeft;
        statusSubtitle.MaximumSize = new Size(0, 0);

        var statusLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, BackColor = Color.Transparent };
        statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 116));
        statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 96));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        statusLayout.Controls.Add(statusDot, 0, 0);
        statusLayout.SetRowSpan(statusDot, 2);

        var statusText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0), BackColor = Color.Transparent };
        statusText.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
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
        summaryLabel.TextAlign = ContentAlignment.MiddleLeft;
        summaryLabel.BackColor = Color.FromArgb(236, 245, 230);
        summaryLabel.Padding = new Padding(12, 0, 12, 0);
        summaryLabel.Margin = new Padding(0, 0, 8, 0);
        actionLabel.Dock = DockStyle.Fill;
        actionLabel.TextAlign = ContentAlignment.MiddleLeft;
        actionLabel.BackColor = Color.FromArgb(236, 245, 230);
        actionLabel.Padding = new Padding(12, 0, 12, 0);
        actionLabel.Margin = new Padding(0);
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

        tiles.Controls.Add(CreateFeatureTile("Process Security", "Running apps", "Protected"), 0, 0);
        tiles.Controls.Add(CreateReputationTile(), 1, 0);
        tiles.Controls.Add(CreateQuarantineTile(), 0, 1);
        tiles.Controls.Add(CreateFeatureTile("Activity Log", "Scan history", "View history", ShowScanDetailsDialogSafe), 1, 1);
        overview.Controls.Add(tiles, 1, 0);

        ConfigureResultsView(resultsView);
        var resultsPanel = CreateSoftCardPanel();
        resultsPanel.Padding = new Padding(16);
        resultsPanel.Margin = new Padding(0);
        var resultsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Color.Transparent };
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        // Room for two wrapped button rows; buttons are bottom-aligned inside this strip.
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
        resultsLayout.Controls.Add(new Label
        {
            Text = "PC Security · Review Queue",
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI Semibold", 10, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(40, 48, 56),
            BackColor = Color.Transparent,
        }, 0, 0);
        var resultsHost = new Panel { Dock = DockStyle.Fill };
        resultsHost.Controls.Add(resultsEmptyLabel);
        resultsHost.Controls.Add(resultsView);
        resultsEmptyLabel.BringToFront();
        resultsLayout.Controls.Add(resultsHost, 0, 1);
        // Host fills the footer strip; button flow docks to the bottom so a single row
        // sits on the card edge instead of floating in the middle of the tall strip.
        var queueActionsHost = new Panel
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(0),
            Padding = new Padding(0),
            BackColor = Color.Transparent,
        };
        var queueActions = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            AutoScroll = false,
            Margin = new Padding(0),
            Padding = new Padding(0, 6, 0, 0),
            BackColor = Color.Transparent,
        };
        var openReport = CreateQueueActionButton("Open Report");
        var openLocation = CreateQueueActionButton("Open Location");
        var ignoreSelected = CreateQueueActionButton("Ignore");
        var ignorePublisher = CreateQueueActionButton("Ignore Publisher");
        var quarantineSelected = CreateQueueActionButton("Quarantine");
        var approveUpload = CreateQueueActionButton("Approve Upload");
        var exportReport = CreateQueueActionButton("Export");
        var activityLog = CreateQueueActionButton("Activity Log");
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
        // Order: triage actions first, then always-available utilities (never clipped off the right edge).
        queueActions.Controls.Add(openReport);
        queueActions.Controls.Add(openLocation);
        queueActions.Controls.Add(ignoreSelected);
        queueActions.Controls.Add(ignorePublisher);
        queueActions.Controls.Add(quarantineSelected);
        queueActions.Controls.Add(approveUpload);
        queueActions.Controls.Add(exportReport);
        queueActions.Controls.Add(activityLog);
        queueActionsHost.Controls.Add(queueActions);
        resultsLayout.Controls.Add(queueActionsHost, 0, 2);
        resultsPanel.Controls.Add(resultsLayout);
        main.Controls.Add(resultsPanel, 0, 1);

        var bottomCard = CreateSoftCardPanel();
        bottomCard.Margin = new Padding(20, 0, 20, 16);
        bottomCard.Padding = new Padding(14, 10, 14, 10);
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, Margin = new Padding(0), Padding = new Padding(0), BackColor = Color.Transparent };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 12));
        bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        progressBar.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        progressBar.Height = 10;
        progressBar.Margin = new Padding(0, 0, 0, 0);
        progressBar.Style = ProgressBarStyle.Continuous;
        statusLabel.Dock = DockStyle.Fill;
        statusLabel.TextAlign = ContentAlignment.TopLeft;
        statusLabel.Margin = new Padding(0, 6, 0, 0);
        statusLabel.AutoSize = false;
        statusLabel.UseMnemonic = false;
        countLabel.AutoSize = false;
        countLabel.Dock = DockStyle.Fill;
        countLabel.TextAlign = ContentAlignment.MiddleRight;
        countLabel.Margin = new Padding(0, 0, 0, 0);
        countLabel.Width = 76;
        bottom.Controls.Add(progressBar, 0, 0);
        bottom.Controls.Add(countLabel, 1, 0);
        bottom.Controls.Add(statusLabel, 0, 1);
        bottom.SetColumnSpan(statusLabel, 2);
        bottomCard.Controls.Add(bottom);
        root.Controls.Add(bottomCard, 0, 3);

        statusLabel.Text = "Ready";
        UpdateResultsEmptyState();
        UpdateReputationTile();
        UpdateQuarantineTile();
        ApplyAppTheme(this);
    }

    private static Panel CreateSoftCardPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            BorderStyle = BorderStyle.None,
            Padding = new Padding(14),
            Tag = "soft-card",
        };
        panel.Paint += (_, e) => PaintSoftCardBorder(e.Graphics, panel.ClientRectangle, SoftBorder);
        return panel;
    }

    private static void PaintSoftCardBorder(Graphics graphics, Rectangle bounds, Color borderColor)
    {
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using var pen = new Pen(borderColor, 1);
        var rect = new Rectangle(bounds.X, bounds.Y, Math.Max(0, bounds.Width - 1), Math.Max(0, bounds.Height - 1));
        graphics.DrawRectangle(pen, rect);
    }

    private static Panel CreateFeatureTile(string title, string subtitle, string state, Action? onClick = null)
    {
        var tile = CreateSoftCardPanel();
        tile.Margin = new Padding(4);
        tile.Padding = new Padding(14);

        var cursor = onClick is null ? Cursors.Default : Cursors.Hand;
        var layout = CreateTileTextLayout(
            CreateTileTitle(title, cursor),
            CreateTileDetail(subtitle, cursor),
            CreateTileState(state, SuccessGreen, cursor));
        layout.Cursor = cursor;
        layout.BackColor = Color.Transparent;
        tile.Controls.Add(layout);
        if (onClick is not null)
        {
            WireClick(tile, onClick);
        }
        return tile;
    }

    private Panel CreateReputationTile()
    {
        var tile = CreateSoftCardPanel();
        tile.Margin = new Padding(4);
        tile.Padding = new Padding(14);

        ConfigureTileDetailLabel(reputationStateLabel);
        ConfigureTileStateLabel(reputationProtectionLabel, SuccessGreen);
        var layout = CreateTileTextLayout(
            CreateTileTitle("Cloud Reputation"),
            reputationStateLabel,
            reputationProtectionLabel);
        layout.BackColor = Color.Transparent;
        tile.Controls.Add(layout);
        return tile;
    }

    private void UpdateReputationTile()
    {
        var enabled = GetEnabledReputationProviders().ToList();
        reputationStateLabel.Text = $"Connected services {enabled.Count}/3";
        reputationStateLabel.ForeColor = Color.FromArgb(35, 35, 35);
        reputationProtectionLabel.Text = enabled.Count == 0 ? "Not protected" : "Protected";
        reputationProtectionLabel.ForeColor = enabled.Count == 0 ? DangerRed : SuccessGreen;
    }

    private Panel CreateQuarantineTile()
    {
        var tile = CreateSoftCardPanel();
        tile.Margin = new Padding(4);
        tile.Padding = new Padding(14);

        ConfigureTileDetailLabel(quarantineCountLabel);
        ConfigureTileStateLabel(quarantineStateLabel, SuccessGreen);
        var layout = CreateTileTextLayout(
            CreateTileTitle("Quarantine", Cursors.Hand),
            quarantineCountLabel,
            quarantineStateLabel);
        layout.Cursor = Cursors.Hand;
        layout.BackColor = Color.Transparent;
        tile.Controls.Add(layout);
        WireClick(tile, ShowQuarantineDialog);
        toolTip.SetToolTip(tile, "View quarantined files and restore or delete them");
        return tile;
    }

    private static void ConfigureHeaderButton(Button button)
    {
        // Ghost header buttons on light chrome (Webroot-style).
        button.BackColor = Color.FromArgb(245, 248, 250);
        button.ForeColor = Color.FromArgb(50, 60, 70);
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
            MinimumSize = new Size(88, 30),
            Height = 30,
            Margin = new Padding(0, 0, 6, 0),
            Padding = new Padding(10, 2, 10, 2),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(245, 248, 250),
            ForeColor = Color.FromArgb(40, 50, 60),
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
        };
    }

    private static TableLayoutPanel CreateTileTextLayout(Label title, Label detail, Label state)
    {
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Margin = new Padding(0),
            Padding = new Padding(0),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(title, 0, 0);
        layout.Controls.Add(detail, 0, 1);
        layout.Controls.Add(state, 0, 2);
        return layout;
    }

    private static Label CreateTileTitle(string text, Cursor? cursor = null)
    {
        return new Label
        {
            Text = text,
            AutoSize = false,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(35, 35, 35),
            Margin = new Padding(0),
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            Cursor = cursor ?? Cursors.Default,
        };
    }

    private static Label CreateTileDetail(string text, Cursor? cursor = null)
    {
        var label = new Label { Text = text, Cursor = cursor ?? Cursors.Default };
        ConfigureTileDetailLabel(label);
        return label;
    }

    private static Label CreateTileState(string text, Color color, Cursor? cursor = null)
    {
        var label = new Label { Text = text, Cursor = cursor ?? Cursors.Default };
        ConfigureTileStateLabel(label, color);
        return label;
    }

    private static void ConfigureTileDetailLabel(Label label)
    {
        label.AutoSize = false;
        label.Dock = DockStyle.Fill;
        label.Font = new Font("Segoe UI", 8.5f, FontStyle.Regular);
        label.ForeColor = Color.FromArgb(35, 35, 35);
        label.Margin = new Padding(0);
        label.TextAlign = ContentAlignment.MiddleLeft;
        label.AutoEllipsis = true;
    }

    private static void ConfigureTileStateLabel(Label label, Color color)
    {
        label.AutoSize = false;
        label.Dock = DockStyle.Fill;
        label.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
        label.ForeColor = color;
        label.Margin = new Padding(0);
        label.TextAlign = ContentAlignment.MiddleLeft;
        label.AutoEllipsis = true;
    }

    private void UpdateQuarantineTile()
    {
        var restorable = HashGuardLogic.CountRestorableQuarantineEntries(LoadQuarantineManifest());
        quarantineCountLabel.Text = restorable == 0
            ? "No files held"
            : restorable == 1 ? "1 file held" : $"{restorable} files held";
        quarantineCountLabel.ForeColor = Color.FromArgb(35, 35, 35);
        quarantineStateLabel.Text = "View / Restore";
        quarantineStateLabel.ForeColor = restorable == 0 ? SuccessGreen : AttentionYellow;
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
        view.BorderStyle = BorderStyle.FixedSingle;
        view.Font = new Font("Segoe UI", 9, FontStyle.Regular);
    }

    private static void PaintStatusBadge(Graphics graphics, Rectangle bounds, string state)
    {
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var size = Math.Max(20, Math.Min(bounds.Width, bounds.Height) - 8);
        // Webroot-style traffic light: green secure, yellow attention, red critical, gray idle.
        var actionNeeded = state == "action";
        var scanning = state is "scanning" or "stopped";
        var idle = state == "idle";
        var fillColor = actionNeeded
            ? DangerRed
            : scanning
                ? AttentionYellow
                : idle
                    ? Color.FromArgb(176, 190, 197)
                    : BrandGreen;

        var rect = new Rectangle((bounds.Width - size) / 2, (bounds.Height - size) / 2, size, size);

        using var fill = new SolidBrush(fillColor);
        using var ring = new Pen(Color.FromArgb(40, 0, 0, 0), Math.Max(2, size / 28));
        graphics.FillEllipse(fill, rect);
        graphics.DrawEllipse(ring, rect);

        var glyphColor = actionNeeded || idle ? Color.White : Color.FromArgb(30, 40, 30);
        using var pen = new Pen(glyphColor, Math.Max(3, size / 16))
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
            LineJoin = System.Drawing.Drawing2D.LineJoin.Round,
        };
        if (actionNeeded)
        {
            var centerX = rect.Left + rect.Width / 2f;
            graphics.DrawLine(pen, centerX, rect.Top + rect.Height * 0.25f, centerX, rect.Top + rect.Height * 0.62f);
            using var dot = new SolidBrush(Color.White);
            graphics.FillEllipse(dot, centerX - size * 0.055f, rect.Top + rect.Height * 0.74f, size * 0.11f, size * 0.11f);
        }
        else if (idle)
        {
            using var idlePen = new Pen(Color.White, Math.Max(3, size / 16));
            graphics.DrawEllipse(idlePen, rect.Left + size * 0.28f, rect.Top + size * 0.28f, size * 0.44f, size * 0.44f);
        }
        else if (scanning)
        {
            // Static activity bars (no animation).
            var cx = rect.Left + rect.Width / 2f;
            var cy = rect.Top + rect.Height / 2f;
            var barW = Math.Max(3f, size * 0.09f);
            var gap = size * 0.12f;
            using var barBrush = new SolidBrush(Color.FromArgb(30, 40, 30));
            for (var i = -1; i <= 1; i++)
            {
                var h = size * (0.22f + 0.12f * (i == 0 ? 1.15f : 0.75f));
                var x = cx + i * gap - barW / 2f;
                var y = cy - h / 2f;
                graphics.FillRectangle(barBrush, x, y, barW, h);
            }
        }
        else
        {
            graphics.DrawLines(pen, new[]
            {
                new PointF(rect.Left + rect.Width * 0.26f, rect.Top + rect.Height * 0.50f),
                new PointF(rect.Left + rect.Width * 0.43f, rect.Top + rect.Height * 0.67f),
                new PointF(rect.Left + rect.Width * 0.76f, rect.Top + rect.Height * 0.32f),
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
