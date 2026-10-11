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
    private void ShowScanDetailsDialog()
    {
        using var dialog = new Form
        {
            Text = "Activity Log",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(1360, 760),
            MinimumSize = new Size(1160, 620),
            BackColor = Color.FromArgb(246, 247, 249),
        };

        var detailView = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HideSelection = false,
            BorderStyle = BorderStyle.FixedSingle,
            // Virtual-ish feel: keep drawing off while bulk-inserting rows.
            VirtualMode = false,
        };
        ConfigureResultsView(detailView);
        detailView.Columns[ColProcess].Width = 150;
        detailView.Columns[ColSha256].Width = 300;
        detailView.Columns[ColPath].Width = 360;
        detailView.Columns[ColNotes].Width = 300;
        detailView.Dock = DockStyle.Fill;
        // Load rows after the window is visible so open feels instant.
        var allRows = new List<ActivityLogRow>();
        var loadGeneration = 0;

        var summaryLabel = new Label
        {
            Dock = DockStyle.Fill,
            Height = 28,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            Text = "Loading activity log…",
        };
        var searchBox = new TextBox
        {
            Width = 280,
            PlaceholderText = "Search process, hash, path, notes",
            Margin = new Padding(0, 0, 0, 0),
        };
        var reasonLabel = new Label
        {
            Text = "No row selected.",
            Dock = DockStyle.Fill,
            Height = 96,
            AutoEllipsis = true,
            Padding = new Padding(12, 10, 12, 10),
            BackColor = Color.White,
            ForeColor = Color.FromArgb(35, 35, 35),
            BorderStyle = BorderStyle.FixedSingle,
            Tag = "callout",
        };

        var openReport = CreateActivityActionButton("Open Report");
        var openFileLocation = CreateActivityActionButton("Open Location");
        var killProcess = CreateActivityActionButton("Kill Process");
        var quarantineFile = CreateActivityActionButton("Quarantine");
        var restoreQuarantine = CreateActivityActionButton("Quarantine Manager");
        var copyHash = CreateActivityActionButton("Copy Hash");
        var copySummary = CreateActivityActionButton("Copy Summary");
        var ignoreSelected = CreateActivityActionButton("Ignore Selected");
        var exportCsv = CreateActivityActionButton("Export CSV");
        var openLogs = CreateActivityActionButton("Open Logs");
        var close = CreateActivityActionButton("Close");
        close.DialogResult = DialogResult.OK;

        openReport.Click += (_, _) => OpenSelectedReport(detailView);
        openFileLocation.Click += (_, _) => OpenSelectedFileLocation(detailView);
        killProcess.Click += (_, _) => KillSelectedProcesses(detailView);
        quarantineFile.Click += (_, _) => QuarantineSelectedFiles(detailView);
        restoreQuarantine.Click += (_, _) => ShowQuarantineDialog();
        copyHash.Click += (_, _) => CopySelectedHash(detailView);
        copySummary.Click += (_, _) => CopySelectedReportSummary(detailView);
        ignoreSelected.Click += (_, _) =>
        {
            ToggleSelectedIgnoreFlag(detailView);
            UpdateIgnoreButtonText(detailView, ignoreSelected);
        };
        exportCsv.Click += (_, _) => ExportCsv(detailView);
        openLogs.Click += (_, _) => OpenLogFolder();

        var topPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 2,
            Margin = new Padding(0, 0, 0, 10),
            Padding = new Padding(0),
        };
        topPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        topPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        topPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        topPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        topPanel.Controls.Add(summaryLabel, 0, 0);
        topPanel.SetColumnSpan(summaryLabel, 2);

        var filters = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.FromArgb(246, 247, 249),
            Margin = new Padding(0),
        };
        var filterButtons = new List<Button>();
        var activeFilter = ActivityFilter.All;
        foreach (var filter in new[]
        {
            ActivityFilter.All,
            ActivityFilter.ActionNeeded,
            ActivityFilter.Unknown,
            ActivityFilter.Clean,
            ActivityFilter.Errors,
        })
        {
            var button = CreateActivityFilterButton(filter);
            filterButtons.Add(button);
            filters.Controls.Add(button);
        }
        topPanel.Controls.Add(filters, 0, 1);

        var searchPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(10, 0, 0, 0) };
        searchPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        searchPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        searchPanel.Controls.Add(new Label
        {
            Text = "Search",
            AutoSize = false,
            Width = 54,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.DimGray,
        }, 0, 0);
        searchPanel.Controls.Add(searchBox, 1, 0);
        topPanel.Controls.Add(searchPanel, 1, 1);

        void RefreshSelectionUi()
        {
            UpdateIgnoreButtonText(detailView, ignoreSelected);
            reasonLabel.Text = detailView.SelectedItems.Count > 0
                ? BuildSelectedReasonSummary(detailView)
                : detailView.Items.Count == 0
                    ? (allRows.Count == 0 ? "Loading activity log…" : "No scan rows match the current filter.")
                    : "Select a row to review the reason, trust signal, file path, and available actions.";
            var hasSelection = detailView.SelectedItems.Count > 0;
            openReport.Enabled = hasSelection;
            openFileLocation.Enabled = hasSelection;
            killProcess.Enabled = hasSelection;
            quarantineFile.Enabled = hasSelection;
            copyHash.Enabled = hasSelection;
            copySummary.Enabled = hasSelection;
            ignoreSelected.Enabled = hasSelection;
        }

        void ApplyFilter(ActivityFilter filter)
        {
            var palette = GetCurrentPalette();
            activeFilter = filter;
            var searchText = searchBox.Text.Trim();
            var visibleRows = allRows
                .Where(row => MatchesActivityFilter(filter, row))
                .Where(row => MatchesActivitySearch(row, searchText))
                .ToList();

            detailView.BeginUpdate();
            try
            {
                detailView.Items.Clear();
                // Pre-size capacity reduces realloc churn on large logs.
                detailView.Items.AddRange(visibleRows.Select(CreateActivityListViewItem).ToArray());
            }
            finally
            {
                detailView.EndUpdate();
            }

            foreach (var button in filterButtons)
            {
                var selected = button.Tag is ActivityFilter current && current == filter;
                button.BackColor = selected ? palette.Text : palette.ButtonBack;
                button.ForeColor = selected ? palette.Surface : palette.Text;
            }

            summaryLabel.Text = BuildActivityLogSummary(visibleRows, allRows, searchText);
            RefreshSelectionUi();
        }

        foreach (var button in filterButtons)
        {
            button.Click += (_, _) =>
            {
                if (button.Tag is ActivityFilter filter)
                {
                    ApplyFilter(filter);
                }
            };
        }

        // Debounce search so typing does not rebuild thousands of rows on every keystroke.
        var searchDebounce = new System.Windows.Forms.Timer { Interval = 200 };
        searchDebounce.Tick += (_, _) =>
        {
            searchDebounce.Stop();
            ApplyFilter(activeFilter);
        };
        searchBox.TextChanged += (_, _) =>
        {
            searchDebounce.Stop();
            searchDebounce.Start();
        };
        detailView.SelectedIndexChanged += (_, _) => RefreshSelectionUi();
        detailView.DoubleClick += (_, _) => OpenSelectedReport(detailView);
        UpdateIgnoreButtonText(detailView, ignoreSelected);

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4, Padding = new Padding(14) };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 104));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        layout.Controls.Add(topPanel, 0, 0);
        layout.Controls.Add(detailView, 0, 1);
        layout.Controls.Add(reasonLabel, 0, 2);

        var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, Padding = new Padding(0, 8, 0, 0) };
        actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        actions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        actions.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        actions.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        var rowActions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0) };
        rowActions.Controls.Add(openReport);
        rowActions.Controls.Add(openFileLocation);
        rowActions.Controls.Add(copyHash);
        rowActions.Controls.Add(copySummary);
        rowActions.Controls.Add(ignoreSelected);
        var remediationActions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0) };
        remediationActions.Controls.Add(killProcess);
        remediationActions.Controls.Add(quarantineFile);
        remediationActions.Controls.Add(restoreQuarantine);
        var logActions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Margin = new Padding(12, 0, 0, 0) };
        logActions.Controls.Add(close);
        logActions.Controls.Add(openLogs);
        logActions.Controls.Add(exportCsv);
        actions.Controls.Add(rowActions, 0, 0);
        actions.Controls.Add(remediationActions, 0, 1);
        actions.Controls.Add(logActions, 1, 0);
        actions.SetRowSpan(logActions, 2);
        layout.Controls.Add(actions, 0, 3);

        dialog.Controls.Add(layout);
        dialog.AcceptButton = close;
        ApplyAppTheme(dialog);
        dialog.Shown += async (_, _) =>
        {
            var generation = ++loadGeneration;
            summaryLabel.Text = "Loading activity log…";
            try
            {
                var rows = await Task.Run(LoadActivityLogRows).ConfigureAwait(true);
                if (dialog.IsDisposed || generation != loadGeneration)
                {
                    return;
                }

                allRows.Clear();
                allRows.AddRange(rows);
                ApplyFilter(activeFilter);
            }
            catch (Exception ex)
            {
                if (!dialog.IsDisposed)
                {
                    summaryLabel.Text = $"Could not load activity log: {ex.Message}";
                }
            }
        };
        dialog.FormClosed += (_, _) => searchDebounce.Dispose();
        dialog.ShowDialog(this);
    }
}
