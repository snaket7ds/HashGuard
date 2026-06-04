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
using Microsoft.Win32;

namespace HashGuardScanner;

public sealed class MainForm : Form
{
    internal const string ScanPipeName = "HashGuard.ScanRequest";
    private const string FileReportUrl = "https://www.virustotal.com/api/v3/files/{0}";
    private const string FileUploadUrl = "https://www.virustotal.com/api/v3/files";
    private const string LargeFileUploadUrl = "https://www.virustotal.com/api/v3/files/upload_url";
    private const string AnalysisUrl = "https://www.virustotal.com/api/v3/analyses/{0}";
    private const string ReportUrl = "https://www.virustotal.com/gui/file/{0}";
    private const string MetaDefenderReportUrl = "https://metadefender.com/results/hash/{0}";
    private const string MetaDefenderHashUrl = "https://api.metadefender.com/v4/hash/{0}";
    private const string CymruDnsQueryUrl = "https://dns.google/resolve?name={0}&type=TXT";
    private const long RegularUploadLimitBytes = 32L * 1024L * 1024L;
    private const string ConfigFolderName = "config";
    private const string AppSettingsFileName = "settings.json";
    private const string IgnoredHashesFileName = "ignored-hashes.json";
    private static readonly string CurrentVersion = GetCurrentVersion();
    private const string GitHubOwner = "snaket7ds";
    private const string GitHubRepo = "HashGuard";
    private static readonly TimeSpan CleanCacheMaxAge = TimeSpan.FromDays(7);
    private static readonly string[] ContextMenuRegistryPaths =
    [
        @"Software\Classes\*\shell\HashGuard",
        @"Software\Classes\AllFilesystemObjects\shell\HashGuard",
        @"Software\Classes\SystemFileAssociations\*\shell\HashGuard",
    ];
    private static readonly string[] LegacyContextMenuRegistryPaths =
    [
        @"Software\Classes\*\shell\VTPS",
        @"Software\Classes\AllFilesystemObjects\shell\VTPS",
        @"Software\Classes\SystemFileAssociations\*\shell\VTPS",
        @"Software\Classes\*\shell\VTProcessScanner",
        @"Software\Classes\AllFilesystemObjects\shell\VTProcessScanner",
        @"Software\Classes\SystemFileAssociations\*\shell\VTProcessScanner",
    ];
    private const string RunRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunRegistryValueName = "HashGuard";
    private const int ColStatus = 0;
    private const int ColRisk = 1;
    private const int ColTrust = 2;
    private const int ColMalicious = 3;
    private const int ColSuspicious = 4;
    private const int ColProcess = 5;
    private const int ColPids = 6;
    private const int ColSha256 = 7;
    private const int ColPath = 8;
    private const int ColNotes = 9;

    private readonly TextBox apiKeyBox = new() { UseSystemPasswordChar = true };
    private readonly TextBox metaDefenderApiKeyBox = new() { UseSystemPasswordChar = true };
    private readonly Button scanButton = new() { Text = "Run Process Scan", Width = 164, Height = 40, BackColor = Color.FromArgb(255, 205, 0), FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
    private readonly Button updateButton = new() { Text = "Update", Width = 86, Height = 40, Font = new Font("Segoe UI", 9, FontStyle.Bold) };
    private readonly Button settingsButton = new() { Text = "⚙", Width = 44, Height = 40, Font = new Font("Segoe UI Symbol", 14, FontStyle.Bold) };
    private readonly CheckBox freeApiLimitBox = new() { Text = "Free API limits (4/min, 500/day)", AutoSize = true, Checked = true };
    private readonly CheckBox rightClickScanBox = new() { Text = "Add Explorer right-click scan", AutoSize = true };
    private readonly CheckBox startWithWindowsBox = new() { Text = "Start with Windows", AutoSize = true };
    private readonly CheckBox startMinimizedBox = new() { Text = "Start minimized to tray", AutoSize = true };
    private readonly CheckBox autoProcessScanBox = new() { Text = "Scan automatically at startup", AutoSize = true, Checked = true };
    private readonly CheckBox runElevatedBox = new() { Text = "Run Elevated (Windows UAC permissions)", AutoSize = true };
    private readonly CheckBox scanAllFilesBox = new() { Text = "Scan files I open or select", AutoSize = true };
    private readonly CheckBox uploadUnknownBox = new() { Text = "Upload files missing from VirusTotal", AutoSize = true };
    private readonly CheckBox virusTotalEnabledBox = new() { Text = "Use VirusTotal", AutoSize = true, Checked = true };
    private readonly CheckBox metaDefenderEnabledBox = new() { Text = "Use MetaDefender Cloud", AutoSize = true, Checked = true };
    private readonly CheckBox mhrEnabledBox = new() { Text = "Use Team Cymru MHR", AutoSize = true, Checked = true };
    private readonly CheckBox hashCacheEnabledBox = new() { Text = "Enable Hash Cache", AutoSize = true, Checked = true };
    private readonly CheckBox autoUpdateChecksBox = new() { Text = "Check updates automatically", AutoSize = true };
    private readonly NumericUpDown delayBox = new() { Minimum = 0, Maximum = 120, Value = 16, Width = 64 };
    private readonly NumericUpDown timeoutBox = new() { Minimum = 10, Maximum = 300, Value = 60, Width = 64 };
    private readonly ListView resultsView = new() { View = View.Details, FullRowSelect = true, GridLines = true };
    private readonly ProgressBar progressBar = new();
    private readonly Label statusLabel = new() { AutoEllipsis = true };
    private readonly Label countLabel = new() { AutoSize = true };
    private readonly Panel statusDot = new() { Width = 92, Height = 92, Margin = new Padding(0, 0, 0, 10), Tag = "action" };
    private readonly Label statusTitle = new() { Text = "You are not protected", AutoSize = true, Font = new Font("Segoe UI", 24, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label statusSubtitle = new() { Text = "Run a process scan to verify protection.", AutoSize = true, ForeColor = Color.DimGray, TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label summaryLabel = new() { Text = "0 files scanned", AutoSize = true, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
    private readonly Label actionLabel = new() { Text = "0 action needed", AutoSize = true, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
    private readonly Label reputationStateLabel = new();
    private readonly Label reputationProtectionLabel = new();
    private readonly Label hashCacheStateLabel = new();
    private readonly NotifyIcon trayIcon = new();
    private readonly ToolTip toolTip = new();
    private readonly Icon cleanTrayIcon;
    private readonly Icon scanningTrayIcon;
    private readonly Icon actionTrayIcon;
    private readonly List<ScanResult> results = [];
    private readonly HashCache hashCache = new();
    private readonly QuotaTracker quotaTracker = new();
    private readonly HashSet<string> ignoredHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ProcessFileState> monitoredProcessFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> allFileScanQueue = new();
    private readonly HashSet<string> queuedAllFileScanPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> allFileWatchers = [];
    private readonly Dictionary<string, ProcessFileState> userTouchedFileScanStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly object allFileScanLock = new();
    private readonly System.Windows.Forms.Timer processMonitorTimer = new() { Interval = 5000 };
    private readonly System.Windows.Forms.Timer updateCheckTimer = new() { Interval = 60000 };
    private readonly System.Windows.Forms.Timer allFileScanTimer = new() { Interval = 15000 };
    private readonly string? startupScanFile;
    private readonly bool startupMinimized;
    private readonly int closedOlderInstances;
    private AppSettings appSettings = new();
    private CancellationTokenSource? scanCancellation;
    private readonly CancellationTokenSource scanPipeCancellation = new();
    private bool processMonitorScanRunning;
    private bool trayRunningNotificationShown;
    private bool uploadWarningShown;
    private bool scanAllFilesWarningShown;
    private bool exitRequested;
    private bool suppressSettingEvents;
    private bool updateCheckRunning;
    private bool allFileScanRunning;
    private bool processBaselineReady;
    private string lastAutoPromptedUpdateVersion = "";
    private string lastSkippedProcessLogSignature = "";
    private const int MaxAllFileScanQueueSize = 200;
    private static readonly HashSet<string> SensitiveFileScanExcludedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".3fr",
        ".3g2",
        ".3gp",
        ".aif",
        ".aiff",
        ".arw",
        ".avi",
        ".bmp",
        ".cr2",
        ".cr3",
        ".crw",
        ".dcr",
        ".dng",
        ".erf",
        ".flac",
        ".flv",
        ".gif",
        ".heic",
        ".heif",
        ".iiq",
        ".jpeg",
        ".jpg",
        ".k25",
        ".kdc",
        ".m2ts",
        ".m4a",
        ".m4v",
        ".mef",
        ".mkv",
        ".mos",
        ".mov",
        ".mp3",
        ".mp4",
        ".mpeg",
        ".mpg",
        ".mrw",
        ".mts",
        ".nef",
        ".nrw",
        ".ogg",
        ".orf",
        ".pef",
        ".png",
        ".raf",
        ".raw",
        ".rw2",
        ".rwl",
        ".sr2",
        ".srf",
        ".tif",
        ".tiff",
        ".wav",
        ".webm",
        ".webp",
        ".wma",
        ".wmv",
        ".x3f",
    };

    private static string GetCurrentVersion()
    {
        var version = typeof(MainForm).Assembly.GetName().Version;
        return version is null ? "1.0.0" : $"{version.Major}.{version.Minor}.{version.Build}";
    }

    public MainForm(string[] args)
    {
        cleanTrayIcon = CreateBugMagnifierIcon(TrayState.Clean);
        scanningTrayIcon = CreateBugMagnifierIcon(TrayState.Scanning);
        actionTrayIcon = CreateBugMagnifierIcon(TrayState.ActionNeeded);
        startupScanFile = ParseStartupScanFile(args);
        startupMinimized = args.Any(arg => string.Equals(arg, "--minimized", StringComparison.OrdinalIgnoreCase));
        closedOlderInstances = CloseOtherInstances();
        appSettings = LoadAppSettings();
        LoadIgnoredHashes();
        ApplyAppSettings();
        Text = "HashGuard";
        Icon = cleanTrayIcon;
        MinimumSize = new Size(760, 620);
        Size = new Size(900, 680);
        StartPosition = FormStartPosition.CenterScreen;

        BuildLayout();
        LoadApiKeyFromSettings();
        suppressSettingEvents = true;
        RepairRightClickScanIfNeeded();
        rightClickScanBox.Checked = IsRightClickScanInstalled();
        startWithWindowsBox.Checked = IsStartWithWindowsInstalled();
        suppressSettingEvents = false;

        scanButton.Click += async (_, _) => await StartScanAsync();
        processMonitorTimer.Tick += async (_, _) => await ScanNewProcessFilesAsync();
        allFileScanTimer.Tick += async (_, _) => await ScanQueuedAllFileAsync();
        updateCheckTimer.Tick += async (_, _) => await CheckForUpdatesAsync(automatic: true);
        updateButton.Click += async (_, _) => await CheckForUpdatesAsync();
        settingsButton.Click += (_, _) => ShowSettingsDialog();
        uploadUnknownBox.CheckedChanged += (_, _) => ConfirmUploads();
        rightClickScanBox.CheckedChanged += (_, _) => RightClickScanPreferenceChanged();
        startWithWindowsBox.CheckedChanged += (_, _) => StartWithWindowsPreferenceChanged();
        startMinimizedBox.CheckedChanged += (_, _) => SaveCurrentAppSettings();
        autoProcessScanBox.CheckedChanged += (_, _) => SaveCurrentAppSettings();
        scanAllFilesBox.CheckedChanged += (_, _) => ScanAllFilesPreferenceChanged();
        autoUpdateChecksBox.CheckedChanged += (_, _) =>
        {
            SaveCurrentAppSettings();
            UpdateAutomaticUpdateTimer();
        };
        Resize += (_, _) => MinimizeToTrayIfNeeded();
        FormClosing += (_, e) => CloseToTrayUnlessExiting(e);
        FormClosed += (_, _) =>
        {
            scanPipeCancellation.Cancel();
            StopAllFileWatchers();
        };
        Shown += async (_, _) =>
        {
            if (startupScanFile is not null)
            {
                await RunStartupFileScanAsync();
            }
            else if (autoProcessScanBox.Checked)
            {
                if (startupMinimized || startMinimizedBox.Checked)
                {
                    BeginInvoke(() =>
                    {
                        WindowState = FormWindowState.Minimized;
                        MinimizeToTrayIfNeeded();
                    });
                }

                await StartScanAsync(showCompletionMessages: false);
            }
            else if (startupMinimized || startMinimizedBox.Checked)
            {
                BeginInvoke(() =>
                {
                    WindowState = FormWindowState.Minimized;
                    MinimizeToTrayIfNeeded();
                });
            }
        };
        UpdateAutomaticUpdateTimer();
        UpdateAllFileScanner();
        _ = ListenForScanRequestsAsync(scanPipeCancellation.Token);
    }

    private void BuildLayout()
    {
        BackColor = Color.FromArgb(246, 247, 249);
        trayIcon.Text = "HashGuard";
        trayIcon.Icon = cleanTrayIcon;
        trayIcon.Visible = true;
        trayIcon.DoubleClick += (_, _) => RestoreFromTray();
        trayIcon.ContextMenuStrip = new ContextMenuStrip();
        trayIcon.ContextMenuStrip.Items.Add("Open", null, (_, _) => RestoreFromTray());
        trayIcon.ContextMenuStrip.Items.Add("Run Scan", null, async (_, _) => await StartScanAsync());
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
            RowCount = 2,
            Padding = new Padding(0),
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(root);

        var header = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, Height = 76, BackColor = Color.FromArgb(28, 28, 28), Padding = new Padding(22, 12, 22, 10) };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var titleBlock = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        titleBlock.Controls.Add(new Label { Text = "HashGuard", AutoSize = true, Font = new Font("Segoe UI", 18, FontStyle.Bold), ForeColor = Color.White });
        titleBlock.Controls.Add(new Label { Text = "Process reputation powered by cloud and hash intelligence", AutoSize = true, ForeColor = Color.FromArgb(205, 205, 205) });
        header.Controls.Add(titleBlock, 0, 0);
        var headerButtons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0),
            Padding = new Padding(0),
        };
        settingsButton.BackColor = Color.FromArgb(52, 52, 52);
        settingsButton.ForeColor = Color.White;
        settingsButton.FlatStyle = FlatStyle.Flat;
        settingsButton.Margin = new Padding(0, 0, 8, 0);
        settingsButton.TextAlign = ContentAlignment.MiddleCenter;
        settingsButton.AccessibleName = "Settings";
        toolTip.SetToolTip(settingsButton, "Settings");
        updateButton.BackColor = Color.FromArgb(52, 52, 52);
        updateButton.ForeColor = Color.White;
        updateButton.FlatStyle = FlatStyle.Flat;
        updateButton.Margin = new Padding(0, 0, 8, 0);
        updateButton.TextAlign = ContentAlignment.MiddleCenter;
        updateButton.FlatAppearance.BorderSize = 1;
        updateButton.FlatAppearance.BorderColor = Color.FromArgb(85, 85, 85);
        toolTip.SetToolTip(updateButton, "Check for HashGuard updates");
        scanButton.Margin = new Padding(0);
        scanButton.TextAlign = ContentAlignment.MiddleCenter;
        scanButton.FlatAppearance.BorderSize = 0;
        headerButtons.Controls.Add(updateButton);
        headerButtons.Controls.Add(settingsButton);
        headerButtons.Controls.Add(scanButton);
        header.Controls.Add(headerButtons, 1, 0);
        root.Controls.Add(header, 0, 0);

        var dashboard = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(22, 22, 22, 18),
        };
        dashboard.RowStyles.Add(new RowStyle(SizeType.Percent, 68));
        dashboard.RowStyles.Add(new RowStyle(SizeType.Percent, 21));
        dashboard.RowStyles.Add(new RowStyle(SizeType.Percent, 11));
        root.Controls.Add(dashboard, 0, 1);

        var statusCard = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Padding = new Padding(18),
            Margin = new Padding(0, 0, 0, 12),
        };
        statusDot.Paint += (_, e) => PaintStatusBadge(e.Graphics, statusDot.Tag as string ?? "clean");
        var statusLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        statusLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var statusText = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Anchor = AnchorStyles.None };
        statusDot.Anchor = AnchorStyles.None;
        statusTitle.Anchor = AnchorStyles.None;
        statusSubtitle.Anchor = AnchorStyles.None;
        statusText.Controls.Add(statusDot);
        statusText.Controls.Add(statusTitle);
        statusText.Controls.Add(statusSubtitle);
        statusLayout.Controls.Add(statusText, 0, 0);
        var stats = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.None, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(0, 14, 0, 0) };
        stats.Controls.Add(summaryLabel);
        stats.Controls.Add(new Label { Text = "  |  ", AutoSize = true, ForeColor = Color.Silver });
        stats.Controls.Add(actionLabel);
        statusLayout.Controls.Add(stats, 0, 1);
        statusCard.Controls.Add(statusLayout);
        dashboard.Controls.Add(statusCard, 0, 0);

        var tiles = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 7, Padding = new Padding(0), Margin = new Padding(0, 0, 0, 12) };
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 10));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 10));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 10));
        tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));

        tiles.Controls.Add(CreateFeatureTile("Process Security", "Running apps", "Protected"), 0, 0);
        tiles.Controls.Add(CreateReputationTile(), 2, 0);
        tiles.Controls.Add(CreateHashCacheTile(), 4, 0);
        tiles.Controls.Add(CreateFeatureTile("Activity Log", "Scan history", "Open", ShowScanDetailsDialogSafe), 6, 0);
        dashboard.Controls.Add(tiles, 0, 1);

        ConfigureResultsView(resultsView);
        var bottomCard = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(0),
            Padding = new Padding(14, 10, 14, 10),
        };
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = new Padding(0), Padding = new Padding(0) };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 22));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 78));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        progressBar.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        progressBar.Height = 14;
        progressBar.Margin = new Padding(0, 0, 12, 0);
        statusLabel.Dock = DockStyle.Fill;
        statusLabel.TextAlign = ContentAlignment.MiddleLeft;
        statusLabel.Margin = new Padding(0, 0, 12, 0);
        countLabel.AutoSize = false;
        countLabel.Dock = DockStyle.Fill;
        countLabel.TextAlign = ContentAlignment.MiddleRight;
        countLabel.Margin = new Padding(0, 0, 0, 0);
        countLabel.Width = 120;
        bottom.Controls.Add(progressBar, 0, 0);
        bottom.Controls.Add(statusLabel, 1, 0);
        bottom.Controls.Add(countLabel, 2, 0);
        bottomCard.Controls.Add(bottom);
        dashboard.Controls.Add(bottomCard, 0, 2);

        statusLabel.Text = "Ready";
        UpdateReputationTile();
        UpdateHashCacheTile();
    }

    private static Panel CreateFeatureTile(string title, string subtitle, string state, Action? onClick = null)
    {
        var tile = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(0),
            Padding = new Padding(10),
        };

        var cursor = onClick is null ? Cursors.Default : Cursors.Hand;
        var layout = CreateTileTextLayout(
            CreateTileTitle(title, cursor),
            CreateTileDetail(subtitle, cursor),
            CreateTileState(state, Color.SeaGreen, cursor));
        layout.Cursor = cursor;
        tile.Controls.Add(layout);
        if (onClick is not null)
        {
            WireClick(tile, onClick);
        }
        return tile;
    }

    private Panel CreateReputationTile()
    {
        var tile = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(0),
            Padding = new Padding(10),
        };

        ConfigureTileDetailLabel(reputationStateLabel);
        ConfigureTileStateLabel(reputationProtectionLabel, Color.SeaGreen);
        tile.Controls.Add(CreateTileTextLayout(
            CreateTileTitle("Cloud Reputation"),
            reputationStateLabel,
            reputationProtectionLabel));
        return tile;
    }

    private void UpdateReputationTile()
    {
        var enabled = GetEnabledReputationProviders().ToList();
        reputationStateLabel.Text = $"Connected services {enabled.Count}/3";
        reputationStateLabel.ForeColor = Color.FromArgb(35, 35, 35);
        reputationProtectionLabel.Text = enabled.Count == 0 ? "Not protected" : "Protected";
        reputationProtectionLabel.ForeColor = enabled.Count == 0 ? Color.Firebrick : Color.SeaGreen;
    }

    private Panel CreateHashCacheTile()
    {
        var tile = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(0),
            Padding = new Padding(10),
        };

        ConfigureTileStateLabel(hashCacheStateLabel, Color.SeaGreen);
        tile.Controls.Add(CreateTileTextLayout(
            CreateTileTitle("Hash Cache"),
            CreateTileDetail("Repeat lookups"),
            hashCacheStateLabel));
        WireClick(tile, OpenHashCacheFolder);
        return tile;
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
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
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
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
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
        label.Font = new Font("Segoe UI", 8, FontStyle.Regular);
        label.ForeColor = Color.FromArgb(35, 35, 35);
        label.Margin = new Padding(0);
        label.TextAlign = ContentAlignment.MiddleLeft;
        label.AutoEllipsis = true;
    }

    private static void ConfigureTileStateLabel(Label label, Color color)
    {
        label.AutoSize = false;
        label.Dock = DockStyle.Fill;
        label.Font = new Font("Segoe UI", 8, FontStyle.Bold);
        label.ForeColor = color;
        label.Margin = new Padding(0);
        label.TextAlign = ContentAlignment.MiddleLeft;
        label.AutoEllipsis = true;
    }

    private void UpdateHashCacheTile()
    {
        hashCacheStateLabel.Text = hashCacheEnabledBox.Checked ? "Enabled" : "Disabled";
        hashCacheStateLabel.ForeColor = hashCacheEnabledBox.Checked ? Color.SeaGreen : Color.Firebrick;
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

        view.Columns.Add("Status", 100);
        view.Columns.Add("Risk", 92);
        view.Columns.Add("Trust", 240);
        view.Columns.Add("Mal", 52);
        view.Columns.Add("Susp", 52);
        view.Columns.Add("Process", 170);
        view.Columns.Add("PID(s)", 95);
        view.Columns.Add("SHA-256", 420);
        view.Columns.Add("Path", 520);
        view.Columns.Add("Notes", 360);
        view.Dock = DockStyle.Fill;
        view.BackColor = Color.White;
    }

    private static void PaintStatusBadge(Graphics graphics, string state)
    {
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var rect = new Rectangle(4, 4, 82, 82);
        var actionNeeded = state == "action";
        var scanning = state is "scanning" or "stopped";
        var fillColor = actionNeeded
            ? Color.FromArgb(216, 55, 55)
            : scanning
                ? Color.FromArgb(255, 205, 0)
                : Color.FromArgb(35, 168, 92);
        using var fill = new SolidBrush(fillColor);
        using var pen = new Pen(actionNeeded ? Color.FromArgb(150, 0, 0) : Color.FromArgb(36, 36, 36), 5);
        graphics.FillEllipse(fill, rect);
        if (actionNeeded)
        {
            graphics.DrawLine(pen, 45, 24, 45, 54);
            graphics.FillEllipse(Brushes.White, 41, 62, 8, 8);
        }
        else
        {
            graphics.DrawLines(pen, new[] { new Point(25, 45), new Point(39, 59), new Point(66, 30) });
        }
    }

    private static Icon CreateBugMagnifierIcon(TrayState state)
    {
        using var bitmap = new Bitmap(32, 32);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.Clear(Color.Transparent);

        var bugFillColor = state == TrayState.ActionNeeded
            ? Color.FromArgb(218, 45, 45)
            : Color.FromArgb(255, 205, 0);
        using var bugFill = new SolidBrush(bugFillColor);
        using var darkPen = new Pen(Color.FromArgb(28, 28, 28), 2.0f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
        using var glassPen = new Pen(Color.FromArgb(28, 28, 28), 2.6f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
        using var highlightPen = new Pen(Color.White, 1.2f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };

        graphics.FillEllipse(bugFill, 7, 11, 12, 14);
        graphics.DrawEllipse(darkPen, 7, 11, 12, 14);
        graphics.FillEllipse(bugFill, 9, 7, 8, 7);
        graphics.DrawEllipse(darkPen, 9, 7, 8, 7);
        graphics.DrawLine(darkPen, 13, 12, 13, 24);
        graphics.DrawLine(darkPen, 8, 15, 3, 13);
        graphics.DrawLine(darkPen, 8, 20, 3, 23);
        graphics.DrawLine(darkPen, 18, 15, 22, 13);
        graphics.DrawLine(darkPen, 18, 20, 22, 22);
        graphics.DrawLine(darkPen, 10, 7, 7, 4);
        graphics.DrawLine(darkPen, 16, 7, 19, 4);

        graphics.DrawEllipse(glassPen, 13, 5, 13, 13);
        graphics.DrawLine(glassPen, 23, 16, 30, 24);
        graphics.DrawLine(highlightPen, 16, 8, 20, 6);

        PaintStatusOverlay(graphics, state);

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

    private static void PaintStatusOverlay(Graphics graphics, TrayState state)
    {
        var badgeColor = state switch
        {
            TrayState.ActionNeeded => Color.FromArgb(218, 45, 45),
            TrayState.Scanning => Color.FromArgb(255, 205, 0),
            _ => Color.FromArgb(0, 145, 82),
        };

        using var badgeFill = new SolidBrush(badgeColor);
        using var badgeRing = new Pen(Color.White, 2.2f);
        using var badgePen = new Pen(Color.White, 1.8f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
        graphics.FillEllipse(badgeFill, 18, 18, 13, 13);
        graphics.DrawEllipse(badgeRing, 18, 18, 13, 13);

        if (state == TrayState.Clean)
        {
            graphics.DrawLines(badgePen, new[] { new Point(21, 25), new Point(24, 28), new Point(29, 21) });
        }
        else if (state == TrayState.ActionNeeded)
        {
            graphics.DrawLine(badgePen, 24.5f, 21, 24.5f, 25.5f);
            graphics.FillEllipse(Brushes.White, 23.5f, 27, 2.4f, 2.4f);
        }
        else if (state == TrayState.Scanning)
        {
            graphics.FillEllipse(Brushes.White, 22, 22, 5, 5);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    private void ShowSettingsDialog()
    {
        using var dialog = new Form
        {
            Text = "Settings",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ClientSize = new Size(720, 620),
        };

        var vtEnabled = new CheckBox { Text = "Enable VirusTotal", Checked = virusTotalEnabledBox.Checked, AutoSize = true };
        var mdEnabled = new CheckBox { Text = "Enable MetaDefender Cloud", Checked = metaDefenderEnabledBox.Checked, AutoSize = true };
        var mhrEnabled = new CheckBox { Text = "Enable Team Cymru MHR", Checked = mhrEnabledBox.Checked, AutoSize = true };
        var apiKey = new TextBox { UseSystemPasswordChar = true, Text = apiKeyBox.Text, Dock = DockStyle.Fill };
        var metaDefenderApiKey = new TextBox { UseSystemPasswordChar = true, Text = metaDefenderApiKeyBox.Text, Dock = DockStyle.Fill };
        var freeLimit = new CheckBox { Text = "Free API limits (4/min, 500/day)", Checked = freeApiLimitBox.Checked, AutoSize = true };
        var rightClickScan = new CheckBox { Text = "Add Explorer right-click scan", Checked = rightClickScanBox.Checked, AutoSize = true };
        var startWithWindows = new CheckBox { Text = "Start with Windows", Checked = startWithWindowsBox.Checked, AutoSize = true };
        var startMinimized = new CheckBox { Text = "Start minimized to tray", Checked = startMinimizedBox.Checked, AutoSize = true };
        var autoProcessScan = new CheckBox { Text = "Scan automatically at startup", Checked = autoProcessScanBox.Checked, AutoSize = true };
        var runElevated = new CheckBox { Text = "Run elevated", Checked = runElevatedBox.Checked, AutoSize = true };
        var scanAllFiles = new CheckBox { Text = "Scan files I open or select", Checked = scanAllFilesBox.Checked, AutoSize = true };
        var autoUpdates = new CheckBox { Text = "Check updates automatically", Checked = autoUpdateChecksBox.Checked, AutoSize = true };
        var hashCache = new CheckBox { Text = "Enable Hash Cache", Checked = hashCacheEnabledBox.Checked, AutoSize = true };
        var uploadUnknown = new CheckBox { Text = "Upload files missing from VirusTotal", Checked = uploadUnknownBox.Checked, AutoSize = true };
        var delay = new NumericUpDown { Minimum = 0, Maximum = 120, Value = delayBox.Value, Width = 70 };
        var timeout = new NumericUpDown { Minimum = 10, Maximum = 300, Value = timeoutBox.Value, Width = 70 };
        var ok = new Button { Text = "Save", DialogResult = DialogResult.OK, AutoSize = true };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        dialog.Controls.Add(root);

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(18), AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.Controls.Add(layout, 0, 0);

        layout.Controls.Add(SectionLabel("Hash Scanners"), 1, 0);
        layout.Controls.Add(mdEnabled, 1, 1);
        layout.Controls.Add(new Label { Text = "MetaDefender API key", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        layout.Controls.Add(metaDefenderApiKey, 1, 2);
        layout.Controls.Add(vtEnabled, 1, 3);
        layout.Controls.Add(new Label { Text = "VirusTotal API key", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 4);
        layout.Controls.Add(apiKey, 1, 4);
        layout.Controls.Add(freeLimit, 1, 5);
        layout.Controls.Add(uploadUnknown, 1, 6);
        layout.Controls.Add(new Label { Text = "VirusTotal delay per request", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 7);
        layout.Controls.Add(delay, 1, 7);
        layout.Controls.Add(new Label { Text = "VirusTotal timeout", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 8);
        layout.Controls.Add(timeout, 1, 8);
        layout.Controls.Add(mhrEnabled, 1, 9);
        layout.Controls.Add(SectionLabel("App Settings"), 1, 10);
        layout.Controls.Add(hashCache, 1, 11);
        layout.Controls.Add(rightClickScan, 1, 12);
        layout.Controls.Add(startWithWindows, 1, 13);
        layout.Controls.Add(startMinimized, 1, 14);
        layout.Controls.Add(autoProcessScan, 1, 15);
        layout.Controls.Add(runElevated, 1, 16);
        layout.Controls.Add(scanAllFiles, 1, 17);
        layout.Controls.Add(autoUpdates, 1, 18);
        layout.Controls.Add(new Label { Text = $"HashGuard version {CurrentVersion}", AutoSize = true, ForeColor = Color.DimGray, Font = new Font("Segoe UI", 9, FontStyle.Bold) }, 1, 19);

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 8, 18, 14),
        };
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);
        root.Controls.Add(buttons, 0, 1);
        dialog.AcceptButton = ok;
        dialog.CancelButton = cancel;

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        apiKeyBox.Text = apiKey.Text.Trim();
        metaDefenderApiKeyBox.Text = metaDefenderApiKey.Text.Trim();
        delayBox.Value = delay.Value;
        timeoutBox.Value = timeout.Value;
        virusTotalEnabledBox.Checked = vtEnabled.Checked;
        metaDefenderEnabledBox.Checked = mdEnabled.Checked;
        mhrEnabledBox.Checked = mhrEnabled.Checked;
        freeApiLimitBox.Checked = freeLimit.Checked;
        uploadUnknownBox.Checked = uploadUnknown.Checked && !scanAllFiles.Checked && EnableVirusTotalUploadsWithWarning();
        hashCacheEnabledBox.Checked = hashCache.Checked;
        rightClickScanBox.Checked = rightClickScan.Checked;
        startWithWindowsBox.Checked = startWithWindows.Checked;
        startMinimizedBox.Checked = startMinimized.Checked;
        autoProcessScanBox.Checked = autoProcessScan.Checked;
        runElevatedBox.Checked = runElevated.Checked;
        scanAllFilesBox.Checked = scanAllFiles.Checked && EnableAllFileScanningWithWarning();
        if (scanAllFilesBox.Checked)
        {
            DisableVirusTotalUploadsForActiveFileScanning(showMessage: false);
        }
        autoUpdateChecksBox.Checked = autoUpdates.Checked;
        UpdateReputationTile();
        UpdateHashCacheTile();
        UpdateAutomaticUpdateTimer();
        UpdateAllFileScanner();
        SaveCurrentAppSettings();
    }

    private static Label SectionLabel(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            ForeColor = Color.FromArgb(35, 35, 35),
            Margin = new Padding(0, 10, 0, 4),
        };
    }

    private void SetDashboardState(string title, string subtitle, bool actionNeeded)
    {
        var scanning = title.Contains("Scanning", StringComparison.OrdinalIgnoreCase);
        var stopped = title.Contains("Stopped", StringComparison.OrdinalIgnoreCase);
        statusTitle.Text = actionNeeded ? "Action needed" : scanning ? "Scan in progress" : stopped ? "Scan stopped" : "You are protected";
        statusSubtitle.Text = subtitle;
        statusDot.Tag = actionNeeded ? "action" : scanning ? "scanning" : stopped ? "stopped" : "clean";
        statusDot.Invalidate();
        if (actionNeeded)
        {
            trayIcon.Icon = actionTrayIcon;
            trayIcon.Text = "HashGuard - Action needed";
        }
        else if (scanning)
        {
            trayIcon.Icon = scanningTrayIcon;
            trayIcon.Text = "HashGuard - Checking";
        }
        else if (stopped)
        {
            trayIcon.Icon = scanningTrayIcon;
            trayIcon.Text = "HashGuard - Stopped";
        }
        else
        {
            trayIcon.Icon = cleanTrayIcon;
            trayIcon.Text = "HashGuard - Clean";
        }
    }

    private async Task StartScanAsync(bool showCompletionMessages = true)
    {
        if (scanCancellation is not null)
        {
            scanCancellation.Cancel();
            scanButton.Enabled = false;
            statusLabel.Text = "Stopping scan...";
            return;
        }

        var apiKey = apiKeyBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(apiKey) || !string.IsNullOrWhiteSpace(metaDefenderApiKeyBox.Text))
        {
            SaveCurrentAppSettings();
        }

        using var cancellation = new CancellationTokenSource();
        scanCancellation = cancellation;
        var token = cancellation.Token;
        var scannedCount = 0;
        var totalCount = 0;
        var completedScan = false;
        scanButton.Text = "Stop Scan";
        scanButton.BackColor = Color.FromArgb(220, 64, 52);
        scanButton.ForeColor = Color.White;
        scanButton.Enabled = true;
        results.Clear();
        resultsView.Items.Clear();
        progressBar.Value = 0;
        countLabel.Text = "";
        statusLabel.Text = "Collecting running processes...";
        summaryLabel.Text = "Preparing scan";
        actionLabel.Text = "0 action needed";
        SetDashboardState("Scanning", "Checking running process files with enabled reputation services.", false);

        try
        {
            var processCollection = CollectProcessFiles();
            var grouped = processCollection.Files;
            AddPersistenceTargets(grouped);
            var paths = grouped.Keys.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToList();
            RefreshMonitoredProcessFiles(grouped.Keys);
            AddSkippedProcessLogIfNeeded(processCollection, force: true);

            totalCount = paths.Count;
            progressBar.Maximum = Math.Max(paths.Count, 1);

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds((int)timeoutBox.Value) };
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            await hashCache.LoadAsync();
            hashCache.ImportScanLogs(GetLogDirectories());
            await hashCache.MarkFileCleanAsync(Application.ExecutablePath, "HashGuard executable trusted locally.");
            await hashCache.SaveAsync();
            await quotaTracker.LoadAsync();

            for (var index = 0; index < paths.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                var path = paths[index];
                statusLabel.Text = $"Scanning {index + 1} of {paths.Count}: {path}";
                countLabel.Text = $"{index + 1} / {paths.Count}";
                var result = await ScanPathAsync(http, path, grouped[path], token);
                results.Add(result);
                AddResultRow(result);
                UpdateSummary();
                progressBar.Value = index + 1;
                scannedCount = index + 1;

                if (virusTotalEnabledBox.Checked && index + 1 < paths.Count && delayBox.Value > 0 && result.Status != "clean/seen")
                {
                    await Task.Delay(TimeSpan.FromSeconds((double)delayBox.Value), token);
                }
            }

            completedScan = true;
            processMonitorTimer.Start();

            var alerts = results.Where(result => result.IsAlert).ToList();
            var unknown = results.Count(result => result.Status is "unknown" or "uploaded");
            var errors = results.Count(result => result.Status == "error");
            statusLabel.Text = $"Done. {alerts.Count} suspicious, {unknown} unknown/uploaded, {errors} errors. Cache: {hashCache.Count} hashes.";
            SetDashboardState(
                alerts.Count > 0 || errors > 0 ? "Action needed" : "Clean",
                alerts.Count > 0
                    ? "A reputation service reported malicious or suspicious detections."
                    : errors > 0
                        ? "Some files could not be checked. Review Activity Log or Open Logs for details."
                        : "No malicious or suspicious detections were found.",
                alerts.Count > 0 || errors > 0);
            if (alerts.Count > 0)
            {
                var sample = string.Join(Environment.NewLine, alerts.Take(8).Select(r => $"{r.ProcessNames}: {r.Malicious} malicious, {r.Suspicious} suspicious"));
                if (showCompletionMessages)
                {
                    MessageBox.Show(this, sample, "Reputation detections found", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    trayIcon.ShowBalloonTip(4000, "HashGuard detections found", sample, ToolTipIcon.Warning);
                }
            }
            else if (errors > 0)
            {
                var message = $"{errors} file(s) could not be checked. Check Activity Log or Open Logs for error details.";
                if (showCompletionMessages)
                {
                    MessageBox.Show(this, message, "Scan completed with errors", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    trayIcon.ShowBalloonTip(4000, "HashGuard scan completed with errors", message, ToolTipIcon.Warning);
                }
            }
            else if (showCompletionMessages)
            {
                MessageBox.Show(this, "No malicious or suspicious detections were found.", "Scan complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        catch (OperationCanceledException)
        {
            statusLabel.Text = $"Stopped. {scannedCount} of {totalCount} files scanned.";
            SetDashboardState("Stopped", "The process scan was stopped before completion.", false);
        }
        catch (Exception ex)
        {
            statusLabel.Text = "Scan failed";
            SetDashboardState("Action needed", "The scan failed before completion.", true);
            MessageBox.Show(this, ex.Message, "Scan failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            scanCancellation = null;
            scanButton.Text = "Run Process Scan";
            scanButton.BackColor = Color.FromArgb(255, 205, 0);
            scanButton.ForeColor = SystemColors.ControlText;
            scanButton.Enabled = true;
            if (completedScan)
            {
                processBaselineReady = true;
                processMonitorTimer.Start();
            }
        }
    }

    private async Task ScanNewProcessFilesAsync()
    {
        if (scanCancellation is not null || processMonitorScanRunning)
        {
            return;
        }

        var processCollection = CollectProcessFiles();
        var grouped = processCollection.Files;
        var newPaths = grouped.Keys
            .Where(ShouldMonitorScanPath)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        RefreshMonitoredProcessFiles(grouped.Keys);
        AddSkippedProcessLogIfNeeded(processCollection, force: false);

        if (newPaths.Count == 0)
        {
            return;
        }

        processMonitorScanRunning = true;
        progressBar.Value = 0;
        progressBar.Maximum = Math.Max(newPaths.Count, 1);
        countLabel.Text = $"0 / {newPaths.Count}";
        statusLabel.Text = $"New process file found. Scanning {newPaths.Count} new file(s)...";
        SetDashboardState("Scanning", "New process file found. Checking it now.", false);

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds((int)timeoutBox.Value) };
            var apiKey = apiKeyBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            await hashCache.LoadAsync();
            hashCache.ImportScanLogs(GetLogDirectories());
            await hashCache.MarkFileCleanAsync(Application.ExecutablePath, "HashGuard executable trusted locally.");
            await hashCache.SaveAsync();
            await quotaTracker.LoadAsync();

            for (var index = 0; index < newPaths.Count; index++)
            {
                var path = newPaths[index];
                statusLabel.Text = $"Monitoring scan {index + 1} of {newPaths.Count}: {path}";
                countLabel.Text = $"{index + 1} / {newPaths.Count}";
                var result = await ScanPathAsync(http, path, grouped[path]);
                results.Add(result);
                AddResultRow(result);
                UpdateSummary();
                progressBar.Value = index + 1;

                if (virusTotalEnabledBox.Checked && index + 1 < newPaths.Count && delayBox.Value > 0 && result.Status != "clean/seen")
                {
                    await Task.Delay(TimeSpan.FromSeconds((double)delayBox.Value));
                }
            }

            var alerts = results.Where(result => result.IsAlert).ToList();
            var errors = results.Count(result => result.Status == "error");
            var lastScanTime = FormatCentralTime(DateTimeOffset.Now);
            SetDashboardState(
                alerts.Count > 0 || errors > 0 ? "Action needed" : "Clean",
                alerts.Count > 0
                    ? "A reputation service reported malicious or suspicious detections."
                    : errors > 0
                        ? "Some files could not be checked. Review Activity Log or Open Logs for details."
                        : $"Monitoring active. Scanned {newPaths.Count} new file(s). Last scan: {lastScanTime}.",
                alerts.Count > 0 || errors > 0);
            statusLabel.Text = $"Monitoring active. Scanned {newPaths.Count} new file(s). Last scan: {lastScanTime}.";
        }
        catch (Exception ex)
        {
            statusLabel.Text = "Monitoring scan failed";
            SetDashboardState("Action needed", "A monitoring scan failed. Check Activity Log or Open Logs.", true);
            MessageBox.Show(this, ex.Message, "Monitoring scan failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            processMonitorScanRunning = false;
        }
    }

    private bool ShouldMonitorScanPath(string path)
    {
        if (!monitoredProcessFiles.TryGetValue(path, out var previous))
        {
            return true;
        }

        return TryGetProcessFileState(path, out var current)
            && (current.Length != previous.Length || current.LastWriteTimeUtc != previous.LastWriteTimeUtc);
    }

    private void RefreshMonitoredProcessFiles(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            if (TryGetProcessFileState(path, out var state))
            {
                monitoredProcessFiles[path] = state;
            }
        }
    }

    private static bool TryGetProcessFileState(string path, out ProcessFileState state)
    {
        state = default;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return false;
            }

            state = new ProcessFileState(info.Length, info.LastWriteTimeUtc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void UpdateAllFileScanner()
    {
        if (scanAllFilesBox.Checked)
        {
            StartAllFileWatchers();
            QueueExplorerSelectedFiles();
            allFileScanTimer.Start();
            return;
        }

        allFileScanTimer.Stop();
        StopAllFileWatchers();
        lock (allFileScanLock)
        {
            allFileScanQueue.Clear();
            queuedAllFileScanPaths.Clear();
            userTouchedFileScanStates.Clear();
        }
    }

    private void StartAllFileWatchers()
    {
        if (allFileWatchers.Count > 0)
        {
            return;
        }

        var recentPath = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
        if (string.IsNullOrWhiteSpace(recentPath) || !Directory.Exists(recentPath))
        {
            return;
        }

        try
        {
            var watcher = new FileSystemWatcher(recentPath, "*.lnk")
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                InternalBufferSize = 16 * 1024,
            };
            watcher.Created += (_, e) => QueueRecentShortcutTarget(e.FullPath);
            watcher.Changed += (_, e) => QueueRecentShortcutTarget(e.FullPath);
            watcher.Renamed += (_, e) => QueueRecentShortcutTarget(e.FullPath);
            watcher.Error += (_, _) => BeginInvoke(() => statusLabel.Text = "Recent-file watcher missed activity. It will continue with new events.");
            watcher.EnableRaisingEvents = true;
            allFileWatchers.Add(watcher);
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Could not watch recent files: {ex.Message}";
        }
    }

    private void StopAllFileWatchers()
    {
        foreach (var watcher in allFileWatchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch
            {
                // Watcher cleanup is best-effort during shutdown/settings changes.
            }
        }

        allFileWatchers.Clear();
    }

    private void QueueAllFileScan(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        if (!ShouldQueueActiveFileScan(path))
        {
            return;
        }

        if (!TryGetProcessFileState(path, out var currentState))
        {
            return;
        }

        lock (allFileScanLock)
        {
            if (queuedAllFileScanPaths.Contains(path) || queuedAllFileScanPaths.Count >= MaxAllFileScanQueueSize)
            {
                return;
            }

            if (userTouchedFileScanStates.TryGetValue(path, out var previousState) &&
                currentState.Equals(previousState))
            {
                return;
            }

            userTouchedFileScanStates[path] = currentState;
            queuedAllFileScanPaths.Add(path);
            allFileScanQueue.Enqueue(path);
        }
    }

    private void QueueRecentShortcutTarget(string shortcutPath)
    {
        var targetPath = ResolveShortcutTarget(shortcutPath);
        if (!string.IsNullOrWhiteSpace(targetPath))
        {
            QueueAllFileScan(targetPath);
        }
    }

    private static string? ResolveShortcutTarget(string shortcutPath)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null)
            {
                return null;
            }

            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            string? targetPath = shortcut.TargetPath;
            return targetPath;
        }
        catch
        {
            return null;
        }
    }

    private void QueueExplorerSelectedFiles()
    {
        foreach (var path in GetExplorerSelectedFilePaths())
        {
            QueueAllFileScan(path);
        }
    }

    private static IEnumerable<string> GetExplorerSelectedFilePaths()
    {
        var shellType = Type.GetTypeFromProgID("Shell.Application");
        if (shellType is null)
        {
            yield break;
        }

        dynamic? shell = null;
        try
        {
            shell = Activator.CreateInstance(shellType);
        }
        catch
        {
            yield break;
        }

        if (shell is null)
        {
            yield break;
        }

        dynamic windows;
        try
        {
            windows = shell.Windows();
        }
        catch
        {
            yield break;
        }

        foreach (var window in windows)
        {
            if (!IsExplorerWindow(window))
            {
                continue;
            }

            foreach (var path in GetExplorerWindowFilePaths(window))
            {
                yield return path;
            }
        }
    }

    private static bool IsExplorerWindow(dynamic window)
    {
        try
        {
            var fullName = (string?)window.FullName;
            return !string.IsNullOrWhiteSpace(fullName) &&
                string.Equals(Path.GetFileName(fullName), "explorer.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> GetExplorerWindowFilePaths(dynamic window)
    {
        dynamic document;
        try
        {
            document = window.Document;
        }
        catch
        {
            yield break;
        }

        var yieldedSelected = false;
        dynamic selectedItems;
        try
        {
            selectedItems = document.SelectedItems();
        }
        catch
        {
            selectedItems = null!;
        }

        if (selectedItems is not null)
        {
            foreach (var item in selectedItems)
            {
                string? path = TryGetShellItemPath(item);
                if (!string.IsNullOrWhiteSpace(path))
                {
                    yieldedSelected = true;
                    yield return path;
                }
            }
        }

        if (yieldedSelected)
        {
            yield break;
        }

        string? focusedPath;
        try
        {
            focusedPath = TryGetShellItemPath(document.FocusedItem);
        }
        catch
        {
            yield break;
        }

        if (!string.IsNullOrWhiteSpace(focusedPath))
        {
            yield return focusedPath;
        }
    }

    private static string? TryGetShellItemPath(dynamic item)
    {
        try
        {
            string? path = item.Path;
            return path;
        }
        catch
        {
            return null;
        }
    }

    private async Task ScanQueuedAllFileAsync()
    {
        if (!scanAllFilesBox.Checked || !processBaselineReady || scanCancellation is not null || processMonitorScanRunning || allFileScanRunning)
        {
            return;
        }

        QueueExplorerSelectedFiles();

        string? path = null;
        lock (allFileScanLock)
        {
            while (allFileScanQueue.Count > 0)
            {
                var candidate = allFileScanQueue.Dequeue();
                queuedAllFileScanPaths.Remove(candidate);
                if (File.Exists(candidate))
                {
                    path = candidate;
                    break;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        allFileScanRunning = true;
        statusLabel.Text = $"Idle file scan: {path}";
        SetDashboardState("Scanning", "Process monitoring is idle. Checking file activity.", false);
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds((int)timeoutBox.Value) };
            var apiKey = apiKeyBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            await hashCache.LoadAsync();
            hashCache.ImportScanLogs(GetLogDirectories());
            await quotaTracker.LoadAsync();

            var result = await ScanPathAsync(
                http,
                path,
                [new ProcessFile(0, "File activity", path)],
                allowVirusTotalUploads: false);
            results.Add(result);
            AddResultRow(result);
            UpdateSummary();

            int queued;
            lock (allFileScanLock)
            {
                queued = allFileScanQueue.Count;
            }

            statusLabel.Text = $"Idle file scan complete. {queued} queued file(s).";
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Idle file scan failed: {ex.Message}";
            AddResultRow(new ScanResult(path, "File activity", "")
            {
                Status = "error",
                Notes = $"Idle file scan failed: {ex.Message}",
            });
            UpdateSummary();
        }
        finally
        {
            allFileScanRunning = false;
        }
    }

    private static bool ShouldQueueActiveFileScan(string path)
    {
        try
        {
            return File.Exists(path) && !SensitiveFileScanExcludedExtensions.Contains(Path.GetExtension(path));
        }
        catch
        {
            return false;
        }
    }

    private static string FormatCentralTime(DateTimeOffset timestamp)
    {
        try
        {
            var central = TimeZoneInfo.FindSystemTimeZoneById("Central Standard Time");
            return TimeZoneInfo.ConvertTime(timestamp, central).ToString("yyyy-MM-dd h:mm tt 'CST'");
        }
        catch
        {
            var central = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
            return TimeZoneInfo.ConvertTime(timestamp, central).ToString("yyyy-MM-dd h:mm tt 'CST'");
        }
    }

    private async Task RunStartupFileScanAsync()
    {
        if (string.IsNullOrWhiteSpace(startupScanFile))
        {
            return;
        }

        await ScanSingleFileAsync(startupScanFile);
    }

    private async Task ListenForScanRequestsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = CreateScanRequestPipe();
                await pipe.WaitForConnectionAsync(cancellationToken);
                using var reader = new StreamReader(pipe, Encoding.UTF8);
                var path = await reader.ReadLineAsync(cancellationToken);
                if (!string.IsNullOrWhiteSpace(path))
                {
                    BeginInvoke(async () =>
                    {
                        RestoreFromTray();
                        await ScanSingleFileAsync(path);
                    });
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                await Task.Delay(1000, cancellationToken);
            }
        }
    }

    private static NamedPipeServerStream CreateScanRequestPipe()
    {
        var pipeSecurity = new PipeSecurity();
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            WindowsIdentity.GetCurrent().User!,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.Write,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            ScanPipeName,
            PipeDirection.In,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            pipeSecurity);
    }

    private async Task ScanSingleFileAsync(string path)
    {
        var apiKey = apiKeyBox.Text.Trim();
        if (virusTotalEnabledBox.Checked && string.IsNullOrWhiteSpace(apiKey))
        {
            MessageBox.Show(this, "Open Settings and paste your VirusTotal API key before scanning.", "API key required", MessageBoxButtons.OK, MessageBoxIcon.Error);
            ShowSettingsDialog();
            apiKey = apiKeyBox.Text.Trim();
            if (virusTotalEnabledBox.Checked && string.IsNullOrWhiteSpace(apiKey))
            {
                return;
            }
        }

        if (!File.Exists(path))
        {
            MessageBox.Show(this, $"File not found:{Environment.NewLine}{path}", "Right-click scan", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        scanButton.Enabled = false;
        results.Clear();
        resultsView.Items.Clear();
        progressBar.Value = 0;
        progressBar.Maximum = 1;
        countLabel.Text = "1 / 1";
        statusLabel.Text = $"Scanning selected file: {path}";
        summaryLabel.Text = "Preparing scan";
        actionLabel.Text = "0 action needed";
        SetDashboardState("Scanning", "Checking the selected file with enabled reputation services.", false);

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds((int)timeoutBox.Value) };
            if (virusTotalEnabledBox.Checked && !string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }
            await hashCache.LoadAsync();
            hashCache.ImportScanLogs(GetLogDirectories());
            await hashCache.SaveAsync();
            await quotaTracker.LoadAsync();

            var processFile = new ProcessFile(0, Path.GetFileName(path), path);
            var result = await ScanPathAsync(http, path, [processFile]);
            results.Add(result);
            AddResultRow(result);
            UpdateSummary();
            progressBar.Value = 1;
            var alerts = results.Where(result => result.IsAlert).ToList();
            SetDashboardState(
                alerts.Count > 0 ? "Action needed" : "Clean",
                alerts.Count > 0 ? "A reputation service reported malicious or suspicious detections." : "No malicious or suspicious detections were found.",
                alerts.Count > 0);
            statusLabel.Text = alerts.Count > 0 ? "Selected file scan complete. Action needed." : "Selected file scan complete. No detections.";
        }
        catch (Exception ex)
        {
            statusLabel.Text = "Selected file scan failed";
            SetDashboardState("Action needed", "The selected file scan failed.", true);
            MessageBox.Show(this, ex.Message, "Right-click scan failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            scanButton.Enabled = true;
        }
    }

    private void AddSkippedProcessLogIfNeeded(ProcessCollectionResult processCollection, bool force)
    {
        if (processCollection.Skipped.Count == 0)
        {
            return;
        }

        var signature = string.Join("|", processCollection.Skipped
            .OrderBy(process => process.Pid)
            .ThenBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
            .Select(process => $"{process.Pid}:{process.Name}"));
        if (!force && string.Equals(signature, lastSkippedProcessLogSignature, StringComparison.Ordinal))
        {
            return;
        }

        lastSkippedProcessLogSignature = signature;
        var result = CreateSkippedProcessResult(processCollection.Skipped);
        results.Add(result);
        AddResultRow(result);
        UpdateSummary();
    }

    private static ScanResult CreateSkippedProcessResult(IReadOnlyList<SkippedProcess> skippedProcesses)
    {
        const int displayLimit = 20;
        var names = skippedProcesses
            .Select(process => process.Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Take(displayLimit)
            .ToList();
        var pids = skippedProcesses
            .Select(process => process.Pid)
            .Where(pid => pid > 0)
            .Distinct()
            .OrderBy(pid => pid)
            .Take(displayLimit)
            .Select(pid => pid.ToString())
            .ToList();
        var skippedList = skippedProcesses
            .OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(process => process.Pid)
            .Take(displayLimit)
            .Select(process => $"{process.Name} ({process.Pid})")
            .ToList();
        var remaining = skippedProcesses.Count - skippedList.Count;
        var skippedText = skippedList.Count == 0
            ? ""
            : $" Skipped: {string.Join("; ", skippedList)}{(remaining > 0 ? $"; +{remaining} more" : "")}.";

        return new ScanResult("", string.Join(", ", names), string.Join(", ", pids))
        {
            Status = "limited access",
            Notes = $"Windows protected {skippedProcesses.Count} running process(es) from inspection, or the process exited during collection. This is not a threat by itself. Run HashGuard elevated for more complete coverage, though some protected system/security processes may still be blocked.{skippedText}",
        };
    }

    private static ProcessCollectionResult CollectProcessFiles()
    {
        var grouped = new Dictionary<string, List<ProcessFile>>(StringComparer.OrdinalIgnoreCase);
        var skipped = new List<SkippedProcess>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var path = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(path))
                {
                    continue;
                }

                path = Path.GetFullPath(path);
                if (!grouped.TryGetValue(path, out var files))
                {
                    files = [];
                    grouped[path] = files;
                }

                files.Add(new ProcessFile(process.Id, process.ProcessName, path));
            }
            catch (Exception ex)
            {
                skipped.Add(GetSkippedProcess(process, ex));
            }
            finally
            {
                process.Dispose();
            }
        }

        return new ProcessCollectionResult(grouped, skipped);
    }

    private static void AddPersistenceTargets(Dictionary<string, List<ProcessFile>> grouped)
    {
        foreach (var target in CollectPersistenceTargets())
        {
            if (!File.Exists(target.Path))
            {
                continue;
            }

            if (!grouped.TryGetValue(target.Path, out var files))
            {
                files = [];
                grouped[target.Path] = files;
            }

            files.Add(new ProcessFile(0, target.Source, target.Path));
        }
    }

    private static IEnumerable<PersistenceTarget> CollectPersistenceTargets()
    {
        foreach (var target in CollectRunKeyPersistenceTargets(Registry.CurrentUser, "HKCU", RunRegistryPath))
        {
            yield return target;
        }

        foreach (var target in CollectRunKeyPersistenceTargets(Registry.LocalMachine, "HKLM", RunRegistryPath))
        {
            yield return target;
        }

        foreach (var folder in GetStartupFolders())
        {
            foreach (var target in CollectStartupFolderTargets(folder))
            {
                yield return target;
            }
        }

        foreach (var target in CollectServiceTargets())
        {
            yield return target;
        }
    }

    private static IEnumerable<PersistenceTarget> CollectRunKeyPersistenceTargets(RegistryKey root, string rootName, string subKeyPath)
    {
        using var key = root.OpenSubKey(subKeyPath);
        if (key is null)
        {
            yield break;
        }

        foreach (var valueName in key.GetValueNames())
        {
            var value = key.GetValue(valueName)?.ToString();
            var path = TryExtractExecutablePath(value);
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Startup: {rootName}\\Run\\{valueName}");
            }
        }
    }

    private static IEnumerable<string> GetStartupFolders()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
    }

    private static IEnumerable<PersistenceTarget> CollectStartupFolderTargets(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
        {
            yield break;
        }

        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var targetPath = Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase)
                ? TryResolveShortcutTarget(file)
                : file;
            if (!string.IsNullOrWhiteSpace(targetPath))
            {
                yield return new PersistenceTarget(targetPath, $"Startup folder: {Path.GetFileName(file)}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> CollectServiceTargets()
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null)
        {
            yield break;
        }

        foreach (var serviceName in services.GetSubKeyNames())
        {
            using var service = services.OpenSubKey(serviceName);
            var imagePath = service?.GetValue("ImagePath")?.ToString();
            var path = TryExtractExecutablePath(Environment.ExpandEnvironmentVariables(imagePath ?? ""));
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Service: {serviceName}");
            }
        }
    }

    private static string? TryResolveShortcutTarget(string shortcutPath)
    {
        try
        {
            var shell = Type.GetTypeFromProgID("WScript.Shell");
            if (shell is null)
            {
                return null;
            }

            dynamic shellObject = Activator.CreateInstance(shell)!;
            dynamic shortcut = shellObject.CreateShortcut(shortcutPath);
            return TryExtractExecutablePath((string?)shortcut.TargetPath);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryExtractExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = expanded.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return NormalizeExecutablePath(expanded[1..endQuote]);
            }
        }

        var exeIndex = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex >= 0)
        {
            return NormalizeExecutablePath(expanded[..(exeIndex + 4)].Trim());
        }

        return NormalizeExecutablePath(expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault());
    }

    private static string? NormalizeExecutablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path.Trim());
        }
        catch
        {
            return path.Trim();
        }
    }

    private static SkippedProcess GetSkippedProcess(Process process, Exception ex)
    {
        var pid = 0;
        var name = "Unknown process";
        try
        {
            pid = process.Id;
        }
        catch
        {
            // Process metadata is best-effort after collection failures.
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(process.ProcessName))
            {
                name = process.ProcessName;
            }
        }
        catch
        {
            // Process metadata is best-effort after collection failures.
        }

        return new SkippedProcess(pid, name, ex.GetType().Name);
    }

    private async Task CheckForUpdatesAsync(bool automatic = false)
    {
        if (updateCheckRunning)
        {
            return;
        }

        updateCheckRunning = true;
        if (!automatic)
        {
            updateButton.Enabled = false;
            statusLabel.Text = "Checking for updates...";
        }
        try
        {
            var releasesApiUrl = $"https://api.github.com/repos/{GitHubOwner}/{GitHubRepo}/releases";
            var latestReleaseApiUrl = $"{releasesApiUrl}/latest";
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"HashGuard/{CurrentVersion}");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

            var release = await GetLatestGitHubReleaseAsync(http, latestReleaseApiUrl, releasesApiUrl);
            if (release is null || string.IsNullOrWhiteSpace(release.TagName))
            {
                throw new InvalidOperationException("GitHub release data is missing a tag name.");
            }

            var releaseVersionText = release.TagName.Trim().TrimStart('v', 'V');
            if (!Version.TryParse(releaseVersionText, out var latestVersion) || !Version.TryParse(CurrentVersion, out var currentVersion))
            {
                throw new InvalidOperationException("GitHub release version is invalid.");
            }

            if (latestVersion <= currentVersion)
            {
                if (!automatic)
                {
                    statusLabel.Text = $"HashGuard is up to date ({CurrentVersion}).";
                    MessageBox.Show(this, $"HashGuard is up to date.{Environment.NewLine}Current version: {CurrentVersion}", "Update", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                return;
            }

            var exeAsset = release.Assets.FirstOrDefault(asset => string.Equals(asset.Name, "HashGuard.exe", StringComparison.OrdinalIgnoreCase));
            if (exeAsset is null || string.IsNullOrWhiteSpace(exeAsset.BrowserDownloadUrl))
            {
                throw new InvalidOperationException("GitHub release is missing the HashGuard.exe asset.");
            }

            var shaAsset = release.Assets.FirstOrDefault(asset =>
                string.Equals(asset.Name, "HashGuard.exe.sha256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(asset.Name, "HashGuard.sha256", StringComparison.OrdinalIgnoreCase));
            var expectedSha256 = GetReleaseAssetSha256(exeAsset);
            if (string.IsNullOrWhiteSpace(expectedSha256) && shaAsset is not null && !string.IsNullOrWhiteSpace(shaAsset.BrowserDownloadUrl))
            {
                var shaText = await DownloadGitHubUrlTextAsync(http, shaAsset.BrowserDownloadUrl, "download the checksum asset");
                expectedSha256 = ParseSha256Text(shaText);
            }

            if (string.IsNullOrWhiteSpace(expectedSha256))
            {
                throw new InvalidOperationException("GitHub release is missing SHA-256 verification. Add a HashGuard.exe.sha256 release asset.");
            }

            if (automatic)
            {
                if (!IsRunningElevated())
                {
                    if (!string.Equals(lastAutoPromptedUpdateVersion, latestVersion.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        lastAutoPromptedUpdateVersion = latestVersion.ToString();
                        statusLabel.Text = $"HashGuard {latestVersion} is available. Run elevated or click Update to install.";
                    }

                    return;
                }
            }
            else
            {
                var notes = string.IsNullOrWhiteSpace(release.Body) ? "" : $"{Environment.NewLine}{Environment.NewLine}{release.Body}";
                var accepted = MessageBox.Show(
                    this,
                    $"HashGuard {latestVersion} is available from GitHub. Install it now?{notes}",
                    "Update available",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (accepted != DialogResult.Yes)
                {
                    statusLabel.Text = "Update canceled.";
                    return;
                }
            }

            var updateDir = Path.Combine(AppContext.BaseDirectory, "updates");
            Directory.CreateDirectory(updateDir);
            var downloadPath = Path.Combine(updateDir, "HashGuard.exe.new");
            statusLabel.Text = "Downloading update...";
            await using (var download = await DownloadGitHubUrlStreamAsync(http, exeAsset.BrowserDownloadUrl, "download the HashGuard.exe asset"))
            await using (var output = File.Create(downloadPath))
            {
                await download.CopyToAsync(output);
            }

            statusLabel.Text = "Verifying update...";
            var actualSha256 = await Sha256FileAsync(downloadPath);
            if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(downloadPath);
                throw new InvalidOperationException("Downloaded update hash did not match the GitHub release checksum. Update was not installed.");
            }

            InstallDownloadedUpdate(downloadPath);
        }
        catch (Exception ex)
        {
            if (automatic)
            {
                statusLabel.Text = $"Automatic update check failed: {ex.Message}";
            }
            else
            {
                statusLabel.Text = "Update failed";
                MessageBox.Show(this, $"Update failed:{Environment.NewLine}{ex.Message}", "Update", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        finally
        {
            updateButton.Enabled = true;
            updateCheckRunning = false;
        }
    }

    private void UpdateAutomaticUpdateTimer()
    {
        updateCheckTimer.Enabled = autoUpdateChecksBox.Checked;
    }

    private static bool IsRunningElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void InstallDownloadedUpdate(string downloadPath)
    {
        var currentExe = Application.ExecutablePath;
        var backupPath = Path.Combine(Path.GetDirectoryName(currentExe)!, "HashGuard.exe.update-bak");
        var command = $"/c for /l %i in (1,1,60) do @(timeout /t 1 /nobreak >nul & copy /y \"{currentExe}\" \"{backupPath}\" >nul 2>nul & copy /y \"{downloadPath}\" \"{currentExe}\" >nul 2>nul && del /f /q \"{downloadPath}\" \"{backupPath}\" >nul 2>nul & start \"\" \"{currentExe}\" && exit /b 0)";
        Process.Start(new ProcessStartInfo("cmd.exe", command)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
        });

        exitRequested = true;
        trayIcon.Visible = false;
        Application.Exit();
    }

    private static string GetReleaseAssetSha256(GitHubAsset asset)
    {
        if (string.IsNullOrWhiteSpace(asset.Digest))
        {
            return "";
        }

        const string prefix = "sha256:";
        return asset.Digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? asset.Digest[prefix.Length..].Trim()
            : "";
    }

    private static string ParseSha256Text(string text)
    {
        foreach (var token in text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token.Length == 64 && token.All(Uri.IsHexDigit))
            {
                return token.ToLowerInvariant();
            }
        }

        return "";
    }

    private static async Task<Stream> GetGitHubStreamAsync(HttpClient http, string url, string action)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError(action, response.StatusCode, details));
        }

        var memory = new MemoryStream();
        await response.Content.CopyToAsync(memory);
        memory.Position = 0;
        return memory;
    }

    private static async Task<GitHubRelease?> GetLatestGitHubReleaseAsync(HttpClient http, string latestReleaseApiUrl, string releasesApiUrl)
    {
        try
        {
            await using var latestStream = await GetGitHubStreamAsync(http, latestReleaseApiUrl, "read the latest release");
            return await JsonSerializer.DeserializeAsync<GitHubRelease>(latestStream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("404 Not Found", StringComparison.OrdinalIgnoreCase))
        {
            await using var releasesStream = await GetGitHubStreamAsync(http, releasesApiUrl, "read the releases list");
            var releases = await JsonSerializer.DeserializeAsync<List<GitHubRelease>>(releasesStream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? [];
            return releases
                .Where(release => !release.Draft)
                .Select(release => new
                {
                    Release = release,
                    Parsed = Version.TryParse(release.TagName.Trim().TrimStart('v', 'V'), out var version),
                    Version = version
                })
                .Where(item => item.Parsed)
                .OrderByDescending(item => item.Version)
                .Select(item => item.Release)
                .FirstOrDefault();
        }
    }

    private static async Task<Stream> DownloadGitHubAssetStreamAsync(HttpClient http, string assetApiUrl)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, assetApiUrl);
        request.Headers.Accept.Clear();
        request.Headers.Accept.ParseAdd("application/octet-stream");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError("download the release asset", response.StatusCode, details));
        }

        var memory = new MemoryStream();
        await response.Content.CopyToAsync(memory);
        memory.Position = 0;
        return memory;
    }

    private static async Task<Stream> DownloadGitHubUrlStreamAsync(HttpClient http, string url, string action)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(BuildGitHubHttpError(action, response.StatusCode, details));
        }

        var memory = new MemoryStream();
        await response.Content.CopyToAsync(memory);
        memory.Position = 0;
        return memory;
    }

    private static async Task<string> DownloadGitHubUrlTextAsync(HttpClient http, string url, string action)
    {
        await using var stream = await DownloadGitHubUrlStreamAsync(http, url, action);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static async Task<string> DownloadGitHubAssetTextAsync(HttpClient http, string assetApiUrl)
    {
        await using var stream = await DownloadGitHubAssetStreamAsync(http, assetApiUrl);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static string BuildGitHubHttpError(string action, HttpStatusCode statusCode, string details)
    {
        var note = statusCode switch
        {
            HttpStatusCode.Unauthorized => "GitHub returned 401 Unauthorized.",
            HttpStatusCode.Forbidden => "GitHub returned 403 Forbidden. Verify the repository is public and release assets are available.",
            HttpStatusCode.NotFound => "GitHub returned 404 Not Found. Verify the repository, release, and asset names.",
            _ => $"GitHub returned {(int)statusCode} {statusCode}."
        };

        var detailText = string.IsNullOrWhiteSpace(details) ? "" : $"{Environment.NewLine}{details}";
        return $"Could not {action}. {note}{detailText}";
    }

    private async Task<ScanResult> ScanPathAsync(
        HttpClient http,
        string path,
        List<ProcessFile> processFiles,
        CancellationToken cancellationToken = default,
        bool allowVirusTotalUploads = true)
    {
        var names = string.Join(", ", processFiles.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n));
        var pids = string.Join(", ", processFiles.Select(p => p.Pid).OrderBy(pid => pid));
        var result = new ScanResult(path, names, pids);
        ApplyLocalFileIntelligence(result, processFiles);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (hashCacheEnabledBox.Checked && hashCache.TryGetUnchangedFile(path, out var cachedSha256, out var cachedEntry))
            {
                result.Sha256 = cachedSha256;
                result.Link = string.Format(ReportUrl, result.Sha256);
                result.ApplyCache(cachedEntry, "Skipped unchanged file");
                result.Status = "clean/seen";
                ApplyRiskAndTrust(result);
                return result;
            }

            result.Sha256 = await Sha256FileAsync(path, cancellationToken);
            result.Link = string.Format(ReportUrl, result.Sha256);
            if (hashCacheEnabledBox.Checked && hashCache.TryGet(result.Sha256, out var cached))
            {
                if (HashCache.IsReusableCleanEntry(cached))
                {
                    result.ApplyCache(cached);
                    result.Status = "clean/seen";
                    hashCache.SetFileState(result);
                    await hashCache.SaveAsync();
                    ApplyRiskAndTrust(result);
                    return result;
                }
            }

            var checkedAnyService = false;
            if (metaDefenderEnabledBox.Checked)
            {
                checkedAnyService = true;
                await ApplyMetaDefenderReportAsync(result, cancellationToken);
            }

            if (virusTotalEnabledBox.Checked)
            {
                checkedAnyService = true;
                await ApplyVirusTotalReportAsync(http, result, path, allowVirusTotalUploads, cancellationToken);
            }

            if (mhrEnabledBox.Checked)
            {
                checkedAnyService = true;
                await ApplyCymruReputationAsync(result, cancellationToken);
            }

            if (!checkedAnyService)
            {
                result.Status = "unknown";
                AppendResultNote(result, "No reputation services are enabled.");
            }
            else if (string.IsNullOrWhiteSpace(result.Status))
            {
                result.Status = result.IsAlert ? "detected" : "clean";
            }

            ApplyIgnoredHash(result);
            ApplyRiskAndTrust(result);
            await SaveResultToCacheAsync(result);
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.Status = "error";
            result.Notes = FormatScanError(ex);
            ApplyRiskAndTrust(result);
            return result;
        }
    }

    private static void ApplyLocalFileIntelligence(ScanResult result, List<ProcessFile> processFiles)
    {
        result.PersistenceSources = processFiles
            .Where(file => file.Pid == 0 && file.Name.Contains(':', StringComparison.Ordinal))
            .Select(file => file.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(source => source, StringComparer.OrdinalIgnoreCase)
            .ToList();

        try
        {
            var info = new FileInfo(result.Path);
            if (info.Exists)
            {
                result.FileSizeBytes = info.Length;
                result.LastWriteTimeUtc = info.LastWriteTimeUtc;
                result.FileAgeDays = Math.Max(0, (DateTime.UtcNow - info.LastWriteTimeUtc).TotalDays);
            }
        }
        catch
        {
            // Local metadata is best-effort and should not block reputation checks.
        }

        result.SignatureSummary = GetSignatureSummary(result.Path);
    }

    private static string GetSignatureSummary(string path)
    {
        try
        {
            var certificate = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(certificate);
            var publisher = cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            var expired = DateTime.Now < cert2.NotBefore || DateTime.Now > cert2.NotAfter;
            return expired
                ? $"Signed by {publisher}; certificate outside validity period"
                : $"Signed by {publisher}";
        }
        catch
        {
            return "Unsigned or signature unavailable";
        }
    }

    private static void ApplyRiskAndTrust(ScanResult result)
    {
        var score = 0;
        var reasons = new List<string>();
        var trust = new List<string>();

        if (result.Malicious > 0)
        {
            score += 80;
            reasons.Add($"{result.Malicious} malicious detection(s)");
        }

        if (result.Suspicious > 0)
        {
            score += Math.Min(50, result.Suspicious * 15);
            reasons.Add($"{result.Suspicious} suspicious detection(s)");
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(result.Status, "uploaded", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
            reasons.Add("hash not known clean");
        }

        if (string.Equals(result.Status, "error", StringComparison.OrdinalIgnoreCase))
        {
            score += 25;
            reasons.Add("scan error needs review");
        }

        if (IsRiskyUserWritablePath(result.Path))
        {
            score += 25;
            reasons.Add("user-writable/risky path");
        }

        if (result.PersistenceSources.Count > 0)
        {
            score += 25;
            reasons.Add("starts automatically");
            trust.Add(string.Join("; ", result.PersistenceSources));
        }

        if (result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
            reasons.Add("unsigned");
        }
        else if (!string.IsNullOrWhiteSpace(result.SignatureSummary))
        {
            trust.Add(result.SignatureSummary);
        }

        if (result.FileAgeDays is >= 0 and < 7)
        {
            score += 10;
            reasons.Add("recently modified");
        }

        if (IsWindowsOrProgramFilesPath(result.Path) && !result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            score = Math.Max(0, score - 15);
            trust.Add("trusted install location");
        }

        result.RiskScore = Math.Clamp(score, 0, 100);
        result.RiskLevel = result.RiskScore >= 70 ? "High"
            : result.RiskScore >= 40 ? "Medium"
            : result.RiskScore >= 15 ? "Low"
            : "Low";
        result.TrustSummary = trust.Count == 0 ? result.SignatureSummary : string.Join("; ", trust.Distinct(StringComparer.OrdinalIgnoreCase));

        if (reasons.Count > 0)
        {
            AppendResultNote(result, $"Risk: {string.Join(", ", reasons.Distinct(StringComparer.OrdinalIgnoreCase))}.");
        }
    }

    private static bool IsRiskyUserWritablePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var lower = path.ToLowerInvariant();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        return lower.Contains(@"\appdata\", StringComparison.Ordinal)
            || lower.Contains(@"\temp\", StringComparison.Ordinal)
            || lower.Contains(@"\downloads\", StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(userProfile) && lower.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase) && !IsWindowsOrProgramFilesPath(path));
    }

    private static bool IsWindowsOrProgramFilesPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var fullPath = path.ToLowerInvariant();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();
        return (!string.IsNullOrWhiteSpace(windows) && fullPath.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(programFiles) && fullPath.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(programFilesX86) && fullPath.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase));
    }

    private static string FormatScanError(Exception ex)
    {
        if (ex is HttpRequestException { StatusCode: HttpStatusCode.Unauthorized })
        {
            return "A reputation service returned 401 Unauthorized. Verify the saved API key in Settings.";
        }

        return ex.Message;
    }

    private async Task ApplyVirusTotalReportAsync(HttpClient http, ScanResult result, string path, bool allowUploads, CancellationToken cancellationToken)
    {
        try
        {
            EnsureVirusTotalApiKey(http);
            if (!await TryReserveVirusTotalQuotaAsync(result))
            {
                return;
            }

            using var reportResponse = await http.GetAsync(string.Format(FileReportUrl, result.Sha256), cancellationToken);
            if (reportResponse.StatusCode == HttpStatusCode.NotFound)
            {
                result.Status = "unknown";
                AppendResultNote(result, "VirusTotal: hash not found.");
                if (uploadUnknownBox.Checked && allowUploads)
                {
                    AppendResultNote(result, "VirusTotal: uploading unknown file for analysis.");
                    var analysisId = await UploadFileAsync(http, path, result, cancellationToken);
                    if (string.IsNullOrWhiteSpace(analysisId))
                    {
                        return;
                    }

                    result.Status = "uploaded";
                    AppendResultNote(result, $"VirusTotal analysis ID: {analysisId}");
                    await PollAnalysisAsync(http, analysisId, result, path, cancellationToken);
                }
                else if (uploadUnknownBox.Checked && !allowUploads)
                {
                    AppendResultNote(result, "VirusTotal: full-file upload skipped for background active-file scanning.");
                }

                return;
            }

            reportResponse.EnsureSuccessStatusCode();
            await using var reportStream = await reportResponse.Content.ReadAsStreamAsync(cancellationToken);
            using var reportJson = await JsonDocument.ParseAsync(reportStream, cancellationToken: cancellationToken);
            ApplyFileReportStats(result, reportJson.RootElement);
            AppendResultNote(result, result.IsDetection
                ? $"VirusTotal: {result.Malicious} malicious, {result.Suspicious} suspicious."
                : "VirusTotal: no malicious or suspicious detections.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppendResultNote(result, $"VirusTotal lookup failed: {FormatScanError(ex)}");
            if (uploadUnknownBox.Checked && allowUploads && string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                result.Status = "error";
            }
        }
    }

    private async Task ApplyMetaDefenderReportAsync(ScanResult result, CancellationToken cancellationToken)
    {
        var apiKey = metaDefenderApiKeyBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            MessageBox.Show(this, "Open Settings and paste your MetaDefender Cloud API key to use MetaDefender checks.", "MetaDefender API key required", MessageBoxButtons.OK, MessageBoxIcon.Information);
            ShowSettingsDialog();
            apiKey = metaDefenderApiKeyBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                metaDefenderEnabledBox.Checked = false;
                AppendResultNote(result, "MetaDefender Cloud: skipped, API key not configured.");
                return;
            }
        }

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.Add("apikey", apiKey);
            using var response = await http.GetAsync(string.Format(MetaDefenderHashUrl, result.Sha256), cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                AppendResultNote(result, "MetaDefender Cloud: hash not found.");
                return;
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                AppendResultNote(result, "MetaDefender Cloud: 401 Unauthorized. Verify the API key in Settings.");
                return;
            }

            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            ApplyMetaDefenderStats(result, json.RootElement);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppendResultNote(result, $"MetaDefender Cloud lookup failed: {ex.Message}");
        }
    }

    private async Task PollAnalysisAsync(HttpClient http, string analysisId, ScanResult result, string path, CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= 6; attempt++)
        {
            statusLabel.Text = $"Waiting for VirusTotal analysis {attempt} of 6: {path}";
            await Task.Delay(TimeSpan.FromSeconds(Math.Max((double)delayBox.Value, 15.0)), cancellationToken);

            if (!await TryReserveVirusTotalQuotaAsync(result))
            {
                return;
            }

            using var analysisResponse = await http.GetAsync(string.Format(AnalysisUrl, analysisId), cancellationToken);
            analysisResponse.EnsureSuccessStatusCode();
            await using var analysisStream = await analysisResponse.Content.ReadAsStreamAsync();
            using var analysisJson = await JsonDocument.ParseAsync(analysisStream);
            ApplyAnalysisStats(result, analysisJson.RootElement);

            var status = ReadString(analysisJson.RootElement, "data", "attributes", "status");
            if (status == "completed")
            {
                AppendResultNote(result, $"VirusTotal analysis ID: {analysisId}");
                return;
            }
        }

        AppendResultNote(result, $"VirusTotal analysis still running: {analysisId}");
    }

    private static async Task<string> Sha256FileAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void ApplyFileReportStats(ScanResult result, JsonElement root)
    {
        var stats = ReadElement(root, "data", "attributes", "last_analysis_stats");
        result.Malicious = ReadInt(stats, "malicious");
        result.Suspicious = ReadInt(stats, "suspicious");
        result.Harmless = ReadInt(stats, "harmless");
        result.Undetected = ReadInt(stats, "undetected");
        result.Status = result.IsAlert ? "detected" : "clean";
    }

    private static void ApplyAnalysisStats(ScanResult result, JsonElement root)
    {
        var stats = ReadElement(root, "data", "attributes", "stats");
        result.Malicious = ReadInt(stats, "malicious");
        result.Suspicious = ReadInt(stats, "suspicious");
        result.Harmless = ReadInt(stats, "harmless");
        result.Undetected = ReadInt(stats, "undetected");
        var status = ReadString(root, "data", "attributes", "status");
        if (result.IsAlert)
        {
            result.Status = "detected";
        }
        else if (status == "completed")
        {
            result.Status = "clean";
        }
    }

    private static void ApplyMetaDefenderStats(ScanResult result, JsonElement root)
    {
        var scanResults = ReadElement(root, "scan_results");
        var detected = ReadInt(scanResults, "total_detected_avs");
        var total = ReadInt(scanResults, "total_avs");
        var verdict = ReadString(scanResults, "scan_all_result_a") ?? ReadString(scanResults, "scan_all_result_i") ?? "";
        var threatName = ReadString(scanResults, "threat_name") ?? "";

        if (detected > 0 || verdict.Contains("infected", StringComparison.OrdinalIgnoreCase) || verdict.Contains("malicious", StringComparison.OrdinalIgnoreCase))
        {
            if (!result.IsDetection)
            {
                result.Suspicious = Math.Max(result.Suspicious, Math.Max(detected, 1));
            }

            result.Status = "detected";
            var detail = string.IsNullOrWhiteSpace(threatName) ? "" : $", {threatName}";
            AppendResultNote(result, $"MetaDefender Cloud: detected by {detected}/{total} engines{detail}.");
            return;
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(result.Status))
        {
            result.Status = "clean";
        }

        var totalText = total > 0 ? $" across {total} engines" : "";
        AppendResultNote(result, $"MetaDefender Cloud: no threat detected{totalText}.");
    }

    private static async Task ApplyCymruReputationAsync(ScanResult result, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(result.Sha256) || result.Sha256.Length != 64)
        {
            return;
        }

        try
        {
            var reputation = await QueryCymruAsync(result.Sha256, cancellationToken);
            if (reputation is null)
            {
                AppendResultNote(result, "Team Cymru MHR: no malware match.");
                return;
            }

            AppendResultNote(result, $"Team Cymru MHR: malware match, {reputation.DetectionPercent}% AV hit rate, last seen {reputation.LastSeenUtc:yyyy-MM-dd} UTC.");
            if (!result.IsDetection)
            {
                result.Malicious = 1;
                result.Status = "detected";
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppendResultNote(result, $"Team Cymru MHR lookup failed: {ex.Message}");
        }
    }

    private static async Task<CymruReputation?> QueryCymruAsync(string sha256, CancellationToken cancellationToken)
    {
        var queryName = BuildCymruQueryName(sha256);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        using var response = await http.GetAsync(string.Format(CymruDnsQueryUrl, Uri.EscapeDataString(queryName)), cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"DNS lookup returned {(int)response.StatusCode} {response.StatusCode}.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var status = ReadInt(document.RootElement, "Status");
        if (status == 3)
        {
            return null;
        }

        if (status != 0)
        {
            throw new InvalidOperationException($"DNS lookup status {status}.");
        }

        if (!document.RootElement.TryGetProperty("Answer", out var answers) || answers.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var answer in answers.EnumerateArray())
        {
            var data = ReadString(answer, "data");
            var reputation = ParseCymruTxt(data);
            if (reputation is not null)
            {
                return reputation;
            }
        }

        return null;
    }

    private static CymruReputation? ParseCymruTxt(string? data)
    {
        if (string.IsNullOrWhiteSpace(data))
        {
            return null;
        }

        var cleaned = data.Replace("\"", "", StringComparison.Ordinal).Trim();
        var parts = cleaned.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2 ||
            !long.TryParse(parts[0], out var unixSeconds) ||
            !int.TryParse(parts[1], out var detectionPercent))
        {
            return null;
        }

        return new CymruReputation(DateTimeOffset.FromUnixTimeSeconds(unixSeconds), detectionPercent);
    }

    private static void AppendResultNote(ScanResult result, string note)
    {
        result.Notes = string.IsNullOrWhiteSpace(result.Notes)
            ? note
            : $"{result.Notes}; {note}";
    }

    private void ApplyIgnoredHash(ScanResult result)
    {
        if (!string.IsNullOrWhiteSpace(result.Sha256) && ignoredHashes.Contains(result.Sha256) && result.IsDetection)
        {
            result.Status = "ignored";
            result.Notes = string.IsNullOrWhiteSpace(result.Notes)
                ? "Detection ignored by user."
                : $"{result.Notes}; Detection ignored by user.";
        }
    }

    private async Task<bool> TryReserveVirusTotalQuotaAsync(ScanResult? result = null)
    {
        if (!freeApiLimitBox.Checked)
        {
            return true;
        }

        var reservation = await quotaTracker.TryReserveAsync();
        if (reservation.Available)
        {
            return true;
        }

        if (result is not null)
        {
            result.VirusTotalDeferred = true;
            AppendResultNote(result, $"VirusTotal: queued for a future scan because the free API {reservation.LimitName} limit is reached.");
        }

        return false;
    }

    private void EnsureVirusTotalApiKey(HttpClient http)
    {
        if (http.DefaultRequestHeaders.Contains("x-apikey"))
        {
            return;
        }

        MessageBox.Show(this, "This file has not been seen as clean before. Open Settings and paste your VirusTotal API key to check it.", "API key required", MessageBoxButtons.OK, MessageBoxIcon.Information);
        ShowSettingsDialog();
        var apiKey = apiKeyBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            virusTotalEnabledBox.Checked = false;
            throw new InvalidOperationException("VirusTotal API key is required for VirusTotal checks.");
        }

        http.DefaultRequestHeaders.Add("x-apikey", apiKey);
    }

    private async Task SaveResultToCacheAsync(ScanResult result)
    {
        if (string.IsNullOrWhiteSpace(result.Sha256) || result.Status == "error" || result.VirusTotalDeferred)
        {
            return;
        }

        if (!hashCacheEnabledBox.Checked)
        {
            return;
        }

        hashCache.Set(result);
        await hashCache.SaveAsync();
    }

    private async Task<string?> UploadFileAsync(HttpClient http, string path, ScanResult result, CancellationToken cancellationToken)
    {
        var uploadUrl = FileUploadUrl;
        var info = new FileInfo(path);
        if (info.Length >= RegularUploadLimitBytes)
        {
            if (!await TryReserveVirusTotalQuotaAsync(result))
            {
                return null;
            }

            using var uploadUrlResponse = await http.GetAsync(LargeFileUploadUrl, cancellationToken);
            uploadUrlResponse.EnsureSuccessStatusCode();
            await using var uploadUrlStream = await uploadUrlResponse.Content.ReadAsStreamAsync();
            using var uploadUrlJson = await JsonDocument.ParseAsync(uploadUrlStream);
            uploadUrl = uploadUrlJson.RootElement.GetProperty("data").GetString() ?? FileUploadUrl;
        }

        await using var fileStream = File.OpenRead(path);
        using var form = new MultipartFormDataContent();
        var fileContent = new StreamContent(fileStream);
        fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        form.Add(fileContent, "file", Path.GetFileName(path));

        if (!await TryReserveVirusTotalQuotaAsync(result))
        {
            return null;
        }

        using var uploadResponse = await http.PostAsync(uploadUrl, form, cancellationToken);
        uploadResponse.EnsureSuccessStatusCode();
        await using var responseStream = await uploadResponse.Content.ReadAsStreamAsync();
        using var responseJson = await JsonDocument.ParseAsync(responseStream);
        return ReadString(responseJson.RootElement, "data", "id") ?? "submitted";
    }

    private void AddResultRow(ScanResult result)
    {
        var item = new ListViewItem(result.Status);
        item.SubItems.Add($"{result.RiskLevel} {result.RiskScore}");
        item.SubItems.Add(result.TrustSummary);
        item.SubItems.Add(result.Malicious.ToString());
        item.SubItems.Add(result.Suspicious.ToString());
        item.SubItems.Add(result.ProcessNames);
        item.SubItems.Add(result.Pids);
        item.SubItems.Add(result.Sha256);
        item.SubItems.Add(result.Path);
        item.SubItems.Add(result.Notes);
        item.Tag = result.Link;

        if (result.IsAlert)
        {
            item.BackColor = Color.MistyRose;
        }
        else if (result.Status == "ignored")
        {
            item.BackColor = Color.Honeydew;
        }
        else if (result.Status is "unknown" or "uploaded")
        {
            item.BackColor = Color.LemonChiffon;
        }
        else if (result.Status == "limited access")
        {
            item.BackColor = Color.LemonChiffon;
        }
        else if (result.Status == "error")
        {
            item.BackColor = Color.LightCoral;
        }

        resultsView.Items.Add(item);
        AppendScanLog(result);
    }

    private static void ApplyResultRowColor(ListViewItem item)
    {
        var status = item.Text;
        var malicious = item.SubItems.Count > ColMalicious && int.TryParse(item.SubItems[ColMalicious].Text, out var mal) ? mal : 0;
        var suspicious = item.SubItems.Count > ColSuspicious && int.TryParse(item.SubItems[ColSuspicious].Text, out var susp) ? susp : 0;
        var riskText = item.SubItems.Count > ColRisk ? item.SubItems[ColRisk].Text : "";

        if (status == "ignored")
        {
            item.BackColor = Color.Honeydew;
        }
        else if (malicious > 0 || suspicious > 0)
        {
            item.BackColor = Color.MistyRose;
        }
        else if (riskText.StartsWith("Medium", StringComparison.OrdinalIgnoreCase)
            || status is "unknown" or "uploaded" or "limited access")
        {
            item.BackColor = Color.LemonChiffon;
        }
        else if (status == "error")
        {
            item.BackColor = Color.LightCoral;
        }
    }

    private void UpdateSummary()
    {
        var alerts = results.Count(result => result.IsAlert);
        var unknown = results.Count(result => result.Status is "unknown" or "uploaded");
        var errors = results.Count(result => result.Status == "error");
        summaryLabel.Text = $"{results.Count} files scanned";
        actionLabel.Text = $"{alerts} action needed";
        if (scanCancellation is not null || processMonitorScanRunning)
        {
            return;
        }

        if (alerts > 0)
        {
            SetDashboardState("Action needed", $"{alerts} detection(s), {unknown} unknown/uploaded, {errors} errors.", true);
        }
        else if (errors > 0)
        {
            SetDashboardState("Action needed", $"{errors} error(s). Check Activity Log or Open Logs.", true);
        }
        else if (results.Count > 0)
        {
            SetDashboardState("Clean", "No action needed.", false);
        }
    }

    private void AppendScanLog(ScanResult result)
    {
        try
        {
            var logDir = GetLogDirectory();
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, $"scan-log-{DateTime.Now:yyyyMMdd}.csv");
            var writeHeader = !File.Exists(logPath);
            using var writer = new StreamWriter(logPath, append: true, Encoding.UTF8);
            if (writeHeader)
            {
                writer.WriteLine("timestamp,status,risk_score,risk_level,trust,malicious,suspicious,harmless,undetected,process_names,pids,sha256,path,link,notes");
            }

            writer.WriteLine(string.Join(",", new[]
            {
                Csv(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                Csv(result.Status),
                Csv(result.RiskScore.ToString()),
                Csv(result.RiskLevel),
                Csv(result.TrustSummary),
                Csv(result.Malicious.ToString()),
                Csv(result.Suspicious.ToString()),
                Csv(result.Harmless.ToString()),
                Csv(result.Undetected.ToString()),
                Csv(result.ProcessNames),
                Csv(result.Pids),
                Csv(result.Sha256),
                Csv(result.Path),
                Csv(result.Link),
                Csv(result.Notes),
            }));
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Could not write scan log: {ex.Message}";
        }
    }

    private void OpenLogFolder()
    {
        var logDir = GetLogDirectory();
        Directory.CreateDirectory(logDir);
        Process.Start(new ProcessStartInfo(logDir) { UseShellExecute = true });
    }

    private void OpenHashCacheFolder()
    {
        var configDir = GetConfigDirectory();
        Directory.CreateDirectory(configDir);
        Process.Start(new ProcessStartInfo(configDir) { UseShellExecute = true });
    }

    private void ShowScanDetailsDialog()
    {
        using var dialog = new Form
        {
            Text = "Scan Details",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(1320, 720),
            MinimumSize = new Size(1120, 560),
        };

        var detailView = new ListView { View = View.Details, FullRowSelect = true, GridLines = true };
        ConfigureResultsView(detailView);
        detailView.Columns[ColProcess].Width = 150;
        detailView.Columns[ColSha256].Width = 300;
        detailView.Columns[ColPath].Width = 360;
        detailView.Columns[ColNotes].Width = 300;
        detailView.Dock = DockStyle.Fill;
        foreach (var item in LoadActivityLogItems())
        {
            detailView.Items.Add(item);
        }

        var openReport = new Button { Text = "Open Report...", AutoSize = true };
        var openFileLocation = new Button { Text = "Open File Location", AutoSize = true };
        var killProcess = new Button { Text = "Kill Process", AutoSize = true };
        var quarantineFile = new Button { Text = "Quarantine File", AutoSize = true };
        var copyHash = new Button { Text = "Copy Hash", AutoSize = true };
        var ignoreSelected = new Button { Text = "Ignore Selected", AutoSize = true };
        var exportCsv = new Button { Text = "Export CSV", AutoSize = true };
        var openLogs = new Button { Text = "Open Logs", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.OK };

        openReport.Click += (_, _) => OpenSelectedReport(detailView);
        openFileLocation.Click += (_, _) => OpenSelectedFileLocation(detailView);
        killProcess.Click += (_, _) => KillSelectedProcesses(detailView);
        quarantineFile.Click += (_, _) => QuarantineSelectedFiles(detailView);
        copyHash.Click += (_, _) => CopySelectedHash(detailView);
        ignoreSelected.Click += (_, _) =>
        {
            ToggleSelectedIgnoreFlag(detailView);
            UpdateIgnoreButtonText(detailView, ignoreSelected);
        };
        exportCsv.Click += (_, _) => ExportCsv(detailView);
        openLogs.Click += (_, _) => OpenLogFolder();
        detailView.SelectedIndexChanged += (_, _) => UpdateIgnoreButtonText(detailView, ignoreSelected);
        UpdateIgnoreButtonText(detailView, ignoreSelected);

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, Padding = new Padding(12) };
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(detailView, 0, 0);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.Add(close);
        buttons.Controls.Add(openLogs);
        buttons.Controls.Add(exportCsv);
        buttons.Controls.Add(ignoreSelected);
        buttons.Controls.Add(quarantineFile);
        buttons.Controls.Add(killProcess);
        buttons.Controls.Add(copyHash);
        buttons.Controls.Add(openFileLocation);
        buttons.Controls.Add(openReport);
        layout.Controls.Add(buttons, 0, 1);

        dialog.Controls.Add(layout);
        dialog.AcceptButton = close;
        dialog.ShowDialog(this);
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

    private static List<ListViewItem> LoadActivityLogItems()
    {
        var items = new List<ListViewItem>();
        foreach (var logDirectory in GetLogDirectories().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(logDirectory))
            {
                continue;
            }

            foreach (var logPath in Directory.EnumerateFiles(logDirectory, "scan-log-*.csv").OrderByDescending(File.GetLastWriteTimeUtc))
            {
                items.AddRange(LoadActivityLogItems(logPath));
            }
        }

        return items;
    }

    private static IEnumerable<ListViewItem> LoadActivityLogItems(string logPath)
    {
        var lines = File.ReadLines(logPath).ToList();
        if (lines.Count < 2)
        {
            yield break;
        }

        var headers = ParseCsvLine(lines[0]);
        var columns = headers
            .Select((name, index) => new { Name = name.Trim(), Index = index })
            .ToDictionary(item => item.Name, item => item.Index, StringComparer.OrdinalIgnoreCase);

        foreach (var line in lines.Skip(1).Reverse())
        {
            var row = ParseCsvLine(line);
            var timestamp = GetCsvValue(row, columns, "timestamp");
            var notes = GetCsvValue(row, columns, "notes");
            if (!string.IsNullOrWhiteSpace(timestamp))
            {
                notes = string.IsNullOrWhiteSpace(notes) ? timestamp : $"{timestamp}; {notes}";
            }

            var item = new ListViewItem(GetCsvValue(row, columns, "status"));
            var riskLevel = GetCsvValue(row, columns, "risk_level");
            var riskScore = GetCsvValue(row, columns, "risk_score");
            item.SubItems.Add(string.IsNullOrWhiteSpace(riskLevel) && string.IsNullOrWhiteSpace(riskScore)
                ? ""
                : $"{riskLevel} {riskScore}".Trim());
            item.SubItems.Add(GetCsvValue(row, columns, "trust"));
            item.SubItems.Add(GetCsvValue(row, columns, "malicious"));
            item.SubItems.Add(GetCsvValue(row, columns, "suspicious"));
            item.SubItems.Add(GetCsvValue(row, columns, "process_names"));
            item.SubItems.Add(GetCsvValue(row, columns, "pids"));
            item.SubItems.Add(GetCsvValue(row, columns, "sha256"));
            item.SubItems.Add(GetCsvValue(row, columns, "path"));
            item.SubItems.Add(notes);
            item.Tag = GetCsvValue(row, columns, "link");
            ApplyResultRowColor(item);
            yield return item;
        }
    }

    private static string GetCsvValue(List<string> row, Dictionary<string, int> columns, string columnName)
    {
        return columns.TryGetValue(columnName, out var index) && index >= 0 && index < row.Count
            ? row[index]
            : "";
    }

    private static string GetLogDirectory()
    {
        return Path.Combine(AppContext.BaseDirectory, "logs");
    }

    private static IEnumerable<string> GetLogDirectories()
    {
        yield return GetLogDirectory();
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

    private static int CloseOtherInstances()
    {
        var current = Process.GetCurrentProcess();
        var currentExe = GetProcessPath(current);
        var closed = 0;

        foreach (var process in Process.GetProcessesByName("HashGuard"))
        {
            if (process.Id == current.Id)
            {
                continue;
            }

            try
            {
                var otherExe = GetProcessPath(process);
                if (!string.IsNullOrWhiteSpace(currentExe)
                    && !string.IsNullOrWhiteSpace(otherExe)
                    && !string.Equals(currentExe, otherExe, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (process.CloseMainWindow() && process.WaitForExit(3000))
                {
                    closed++;
                    continue;
                }

                process.Kill(entireProcessTree: true);
                if (process.WaitForExit(3000))
                {
                    closed++;
                }
            }
            catch
            {
                // If Windows denies access to a different user's process, leave it alone.
            }
            finally
            {
                process.Dispose();
            }
        }

        return closed;
    }

    private static string? GetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private void MinimizeToTrayIfNeeded()
    {
        if (WindowState != FormWindowState.Minimized)
        {
            return;
        }

        Hide();
        if (!trayRunningNotificationShown)
        {
            trayRunningNotificationShown = true;
            trayIcon.ShowBalloonTip(2500, "HashGuard", "Still running in the tray.", ToolTipIcon.Info);
        }
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private void CloseToTrayUnlessExiting(FormClosingEventArgs e)
    {
        if (exitRequested)
        {
            trayIcon.Visible = false;
            return;
        }

        e.Cancel = true;
        WindowState = FormWindowState.Minimized;
        MinimizeToTrayIfNeeded();
    }

    private void ConfirmUploads()
    {
        if (suppressSettingEvents)
        {
            return;
        }

        if (uploadUnknownBox.Checked && scanAllFilesBox.Checked)
        {
            DisableVirusTotalUploadsForActiveFileScanning(showMessage: true);
            SaveCurrentAppSettings();
            return;
        }

        if (uploadUnknownBox.Checked && !EnableVirusTotalUploadsWithWarning())
        {
            suppressSettingEvents = true;
            uploadUnknownBox.Checked = false;
            suppressSettingEvents = false;
        }

        SaveCurrentAppSettings();
    }

    private bool EnableVirusTotalUploadsWithWarning()
    {
        if (uploadWarningShown)
        {
            return true;
        }

        uploadWarningShown = ConfirmVirusTotalUploads();
        return uploadWarningShown;
    }

    private void ScanAllFilesPreferenceChanged()
    {
        if (suppressSettingEvents)
        {
            return;
        }

        if (scanAllFilesBox.Checked && !EnableAllFileScanningWithWarning())
        {
            suppressSettingEvents = true;
            scanAllFilesBox.Checked = false;
            suppressSettingEvents = false;
        }

        if (scanAllFilesBox.Checked)
        {
            DisableVirusTotalUploadsForActiveFileScanning(showMessage: false);
        }

        SaveCurrentAppSettings();
        UpdateAllFileScanner();
    }

    private bool EnableAllFileScanningWithWarning()
    {
        if (scanAllFilesWarningShown)
        {
            return true;
        }

        var accepted = MessageBox.Show(
            this,
            $"HashGuard will watch Windows Recent files and poll open File Explorer windows for selected or focused files, excluding common pictures, videos, audio files, and camera/raw media. It no longer performs a drive-wide discovery sweep or watches every folder. Scanning starts only when process scans are idle.{Environment.NewLine}{Environment.NewLine}To prevent background file uploads, enabling this will turn off \"Upload files missing from VirusTotal\". Open/selected file scanning uses hash lookups only and never uploads full files automatically.{Environment.NewLine}{Environment.NewLine}Enable open/selected file scanning?",
            "Confirm open/selected file scanning",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        scanAllFilesWarningShown = accepted == DialogResult.Yes;
        return scanAllFilesWarningShown;
    }

    private void DisableVirusTotalUploadsForActiveFileScanning(bool showMessage)
    {
        if (!uploadUnknownBox.Checked)
        {
            return;
        }

        suppressSettingEvents = true;
        uploadUnknownBox.Checked = false;
        suppressSettingEvents = false;
        uploadWarningShown = false;
        if (showMessage)
        {
            MessageBox.Show(
                this,
                "Upload files missing from VirusTotal was turned off because open/selected file scanning never uploads full files automatically.",
                "VirusTotal uploads disabled",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
    }

    private bool ConfirmVirusTotalUploads()
    {
        var accepted = MessageBox.Show(
            this,
            "When VirusTotal has not seen a file hash, HashGuard will upload the full file to VirusTotal for analysis. Do not enable this for private, proprietary, personal, or sensitive files unless you are comfortable sharing the file with VirusTotal. Enable uploads?",
            "Confirm VirusTotal uploads",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        return accepted == DialogResult.Yes;
    }

    private void LoadApiKeyFromSettings()
    {
        if (!string.IsNullOrWhiteSpace(appSettings.ApiKeyEncrypted))
        {
            try
            {
                apiKeyBox.Text = DecryptApiKey(appSettings.ApiKeyEncrypted).Trim();
            }
            catch (Exception ex)
            {
                statusLabel.Text = $"Could not load encrypted API key: {ex.Message}";
            }
        }

        if (string.IsNullOrWhiteSpace(apiKeyBox.Text))
        {
            apiKeyBox.Text = appSettings.ApiKey.Trim();
        }

        if (!string.IsNullOrWhiteSpace(appSettings.MetaDefenderApiKeyEncrypted))
        {
            try
            {
                metaDefenderApiKeyBox.Text = DecryptApiKey(appSettings.MetaDefenderApiKeyEncrypted).Trim();
            }
            catch (Exception ex)
            {
                statusLabel.Text = $"Could not load encrypted MetaDefender API key: {ex.Message}";
            }
        }

        if (string.IsNullOrWhiteSpace(metaDefenderApiKeyBox.Text))
        {
            metaDefenderApiKeyBox.Text = appSettings.MetaDefenderApiKey.Trim();
        }

    }

    private void ApplyAppSettings()
    {
        virusTotalEnabledBox.Checked = appSettings.VirusTotalEnabled;
        metaDefenderEnabledBox.Checked = appSettings.MetaDefenderEnabled;
        mhrEnabledBox.Checked = appSettings.MhrEnabled;
        hashCacheEnabledBox.Checked = appSettings.HashCacheEnabled;
        UpdateReputationTile();
        UpdateHashCacheTile();
        freeApiLimitBox.Checked = appSettings.FreeApiLimits;
        uploadUnknownBox.Checked = appSettings.UploadUnknown;
        startMinimizedBox.Checked = appSettings.StartMinimized;
        autoProcessScanBox.Checked = appSettings.AutoProcessScan;
        runElevatedBox.Checked = appSettings.RunElevated;
        scanAllFilesBox.Checked = appSettings.ScanAllFiles;
        if (scanAllFilesBox.Checked)
        {
            uploadUnknownBox.Checked = false;
        }

        autoUpdateChecksBox.Checked = appSettings.AutoUpdateChecks;
        delayBox.Value = Math.Clamp(appSettings.DelaySeconds, (int)delayBox.Minimum, (int)delayBox.Maximum);
        timeoutBox.Value = Math.Clamp(appSettings.TimeoutSeconds, (int)timeoutBox.Minimum, (int)timeoutBox.Maximum);
    }

    private void SaveCurrentAppSettings()
    {
        if (suppressSettingEvents)
        {
            return;
        }

        appSettings.FreeApiLimits = freeApiLimitBox.Checked;
        appSettings.VirusTotalEnabled = virusTotalEnabledBox.Checked;
        appSettings.MetaDefenderEnabled = metaDefenderEnabledBox.Checked;
        appSettings.MhrEnabled = mhrEnabledBox.Checked;
        appSettings.HashCacheEnabled = hashCacheEnabledBox.Checked;
        appSettings.UploadUnknown = uploadUnknownBox.Checked;
        appSettings.StartMinimized = startMinimizedBox.Checked;
        appSettings.AutoProcessScan = autoProcessScanBox.Checked;
        appSettings.RunElevated = runElevatedBox.Checked;
        appSettings.ScanAllFiles = scanAllFilesBox.Checked;
        appSettings.AutoUpdateChecks = autoUpdateChecksBox.Checked;
        appSettings.DelaySeconds = (int)delayBox.Value;
        appSettings.TimeoutSeconds = (int)timeoutBox.Value;

        appSettings.ApiKeyEncrypted = EncryptApiKey(apiKeyBox.Text.Trim());
        appSettings.MetaDefenderApiKeyEncrypted = EncryptApiKey(metaDefenderApiKeyBox.Text.Trim());
        appSettings.ApiKey = "";
        appSettings.MetaDefenderApiKey = "";
        try
        {
            Directory.CreateDirectory(GetConfigDirectory());
            File.WriteAllText(GetAppSettingsPath(), JsonSerializer.Serialize(appSettings, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Could not save settings: {ex.Message}";
        }
    }

    private static AppSettings LoadAppSettings()
    {
        try
        {
            var currentPath = GetAppSettingsPath();
            if (File.Exists(currentPath))
            {
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(currentPath, Encoding.UTF8)) ?? new AppSettings();
            }

            return new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    internal static bool ShouldRunElevatedFromSettings()
    {
        return LoadAppSettings().RunElevated;
    }

    private void RightClickScanPreferenceChanged()
    {
        if (suppressSettingEvents)
        {
            return;
        }

        try
        {
            if (rightClickScanBox.Checked)
            {
                var accepted = MessageBox.Show(
                    this,
                    "This adds a per-user Windows Explorer right-click menu item named \"Scan with HashGuard\" for files. Continue?",
                    "Add right-click scan",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (accepted != DialogResult.Yes)
                {
                    rightClickScanBox.Checked = false;
                    return;
                }

                InstallRightClickScan();
                statusLabel.Text = "Right-click scan installed.";
            }
            else
            {
                RemoveRightClickScan();
                statusLabel.Text = "Right-click scan removed.";
            }
        }
        catch (Exception ex)
        {
            rightClickScanBox.Checked = IsRightClickScanInstalled();
            MessageBox.Show(this, $"Could not update right-click scan:{Environment.NewLine}{ex.Message}", "Right-click scan failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static bool IsRightClickScanInstalled()
    {
        return ContextMenuRegistryPaths.All(path =>
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            using var command = Registry.CurrentUser.OpenSubKey(path + @"\command");
            return key is not null
                && command?.GetValue("") is string commandValue
                && commandValue.Contains(Application.ExecutablePath, StringComparison.OrdinalIgnoreCase);
        });
    }

    internal static void RepairRightClickScanIfNeeded()
    {
        if (IsRightClickScanInstalled() || !HasAnyRightClickScanRegistration())
        {
            return;
        }

        InstallRightClickScan();
    }

    private static bool HasAnyRightClickScanRegistration()
    {
        return ContextMenuRegistryPaths.Concat(LegacyContextMenuRegistryPaths).Any(path =>
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            using var command = Registry.CurrentUser.OpenSubKey(path + @"\command");
            return key is not null || command?.GetValue("") is string commandValue
                && (commandValue.Contains("HashGuard", StringComparison.OrdinalIgnoreCase)
                    || commandValue.Contains("VTPS", StringComparison.OrdinalIgnoreCase));
        });
    }

    private static void InstallRightClickScan()
    {
        foreach (var path in ContextMenuRegistryPaths)
        {
            using var key = Registry.CurrentUser.CreateSubKey(path);
            key.SetValue("", "Scan with HashGuard");
            key.SetValue("Icon", Application.ExecutablePath);
            key.SetValue("MultiSelectModel", "Single");

            using var command = key.CreateSubKey("command");
            command.SetValue("", $"\"{Application.ExecutablePath}\" --scan-file \"%1\"");
        }

        foreach (var path in LegacyContextMenuRegistryPaths)
        {
            Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
        }
    }

    private static void RemoveRightClickScan()
    {
        foreach (var path in ContextMenuRegistryPaths.Concat(LegacyContextMenuRegistryPaths))
        {
            Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
        }
    }

    private void StartWithWindowsPreferenceChanged()
    {
        if (suppressSettingEvents)
        {
            return;
        }

        try
        {
            if (startWithWindowsBox.Checked)
            {
                InstallStartWithWindows();
                statusLabel.Text = "Start with Windows enabled.";
            }
            else
            {
                RemoveStartWithWindows();
                statusLabel.Text = "Start with Windows disabled.";
            }
        }
        catch (Exception ex)
        {
            suppressSettingEvents = true;
            startWithWindowsBox.Checked = IsStartWithWindowsInstalled();
            suppressSettingEvents = false;
            MessageBox.Show(this, $"Could not update Windows startup:{Environment.NewLine}{ex.Message}", "Startup setting failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static bool IsStartWithWindowsInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath);
        return key?.GetValue(RunRegistryValueName) is string value
            && value.Contains(Application.ExecutablePath, StringComparison.OrdinalIgnoreCase);
    }

    private static void InstallStartWithWindows()
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunRegistryPath);
        key.SetValue(RunRegistryValueName, $"\"{Application.ExecutablePath}\" --minimized");
    }

    private static void RemoveStartWithWindows()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: true);
        key?.DeleteValue(RunRegistryValueName, throwOnMissingValue: false);
    }

    internal static string GetAppSettingsPath()
    {
        return Path.Combine(GetConfigDirectory(), AppSettingsFileName);
    }

    internal static string GetConfigDirectory()
    {
        return Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
    }

    private static string GetIgnoredHashesPath()
    {
        return Path.Combine(GetConfigDirectory(), IgnoredHashesFileName);
    }

    private void LoadIgnoredHashes()
    {
        ignoredHashes.Clear();
        var path = GetIgnoredHashesPath();
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var hashes = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path, Encoding.UTF8)) ?? [];
            foreach (var hash in hashes.Where(hash => !string.IsNullOrWhiteSpace(hash)))
            {
                ignoredHashes.Add(hash.Trim());
            }
        }
        catch
        {
            // Ignore malformed ignored-hash data; users can recreate it from Scan Details.
        }
    }

    private void SaveIgnoredHashes()
    {
        Directory.CreateDirectory(GetConfigDirectory());
        File.WriteAllText(
            GetIgnoredHashesPath(),
            JsonSerializer.Serialize(ignoredHashes.OrderBy(hash => hash, StringComparer.OrdinalIgnoreCase), new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);
    }

    internal static string EncryptApiKey(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return "";
        }

        var protectedBytes = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(apiKey),
            optionalEntropy: null,
            scope: DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }

    private static string DecryptApiKey(string encryptedApiKey)
    {
        if (string.IsNullOrWhiteSpace(encryptedApiKey))
        {
            return "";
        }

        var protectedBytes = Convert.FromBase64String(encryptedApiKey);
        var plainBytes = ProtectedData.Unprotect(
            protectedBytes,
            optionalEntropy: null,
            scope: DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(plainBytes);
    }

    private void OpenSelectedReport()
    {
        OpenSelectedReport(resultsView);
    }

    private void CopySelectedHash(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a row with a SHA-256 hash first.", "No hash selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var sha256 = GetSubItemText(sourceView.SelectedItems[0], ColSha256);
        if (string.IsNullOrWhiteSpace(sha256))
        {
            MessageBox.Show(this, "The selected row has no SHA-256 hash.", "No hash selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Clipboard.SetText(sha256);
        statusLabel.Text = "SHA-256 copied to clipboard.";
    }

    private void KillSelectedProcesses(ListView sourceView)
    {
        var selections = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .SelectMany(item => GetSubItemText(item, ColPids)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(pid => new
                {
                    Pid = int.TryParse(pid, out var value) ? value : 0,
                    Path = GetSubItemText(item, ColPath),
                }))
            .Where(selection => selection.Pid > 0 && selection.Pid != Environment.ProcessId)
            .GroupBy(selection => selection.Pid)
            .Select(group => group.First())
            .ToList();

        if (selections.Count == 0)
        {
            MessageBox.Show(this, "Select one or more rows with running process IDs.", "No running process selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Terminate {selections.Count} selected process(es)? HashGuard will only kill a PID if its current executable path still matches the selected row. Unsaved work in those processes may be lost.",
            "Kill selected processes",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var killed = 0;
        var failures = new List<string>();
        foreach (var selection in selections)
        {
            try
            {
                using var process = Process.GetProcessById(selection.Pid);
                var currentPath = GetProcessPath(process);
                if (string.IsNullOrWhiteSpace(currentPath)
                    || !string.Equals(currentPath, selection.Path, StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add($"{selection.Pid}: current process path no longer matches the selected row.");
                    continue;
                }

                process.Kill(entireProcessTree: true);
                if (process.WaitForExit(5000))
                {
                    killed++;
                }
            }
            catch (Exception ex)
            {
                failures.Add($"{selection.Pid}: {ex.Message}");
            }
        }

        statusLabel.Text = $"Killed {killed} process(es).";
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some processes could not be killed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void QuarantineSelectedFiles(ListView sourceView)
    {
        var paths = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Select(item => GetSubItemText(item, ColPath))
            .Where(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (paths.Count == 0)
        {
            MessageBox.Show(this, "Select one or more rows with existing files.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Move {paths.Count} selected file(s) to HashGuard quarantine? Running files may need their process killed first.",
            "Quarantine selected files",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var quarantineDir = Path.Combine(GetConfigDirectory(), "quarantine");
        Directory.CreateDirectory(quarantineDir);
        var moved = 0;
        var failures = new List<string>();

        foreach (var path in paths)
        {
            try
            {
                var target = Path.Combine(
                    quarantineDir,
                    $"{Path.GetFileName(path)}.{DateTime.Now:yyyyMMddHHmmss}.quarantine");
                File.Move(path, target);
                moved++;
                MarkRowsQuarantined(sourceView, path, target);
                MarkRowsQuarantined(resultsView, path, target);
            }
            catch (Exception ex)
            {
                failures.Add($"{path}: {ex.Message}");
            }
        }

        statusLabel.Text = $"Quarantined {moved} file(s).";
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some files could not be quarantined", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private static void MarkRowsQuarantined(ListView view, string originalPath, string quarantinePath)
    {
        foreach (ListViewItem item in view.Items)
        {
            if (!string.Equals(GetSubItemText(item, ColPath), originalPath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var notes = GetSubItemText(item, ColNotes);
            item.SubItems[ColNotes].Text = string.IsNullOrWhiteSpace(notes)
                ? $"Quarantined to {quarantinePath}"
                : $"{notes}; Quarantined to {quarantinePath}";
        }
    }

    private void OpenSelectedFileLocation(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a row with a file path first.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var path = GetSubItemText(sourceView.SelectedItems[0], ColPath);
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(this, "The selected row has no file path.", "No file path", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
                return;
            }

            var directory = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
            {
                Process.Start(new ProcessStartInfo(directory) { UseShellExecute = true });
                return;
            }

            MessageBox.Show(this, $"File location no longer exists:{Environment.NewLine}{path}", "File location unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not open file location:{Environment.NewLine}{ex.Message}", "Open file location failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ToggleSelectedIgnoreFlag(ListView sourceView)
    {
        var hashes = GetSelectedDetectionHashes(sourceView);
        if (hashes.Count > 0 && hashes.All(sha256 => IsIgnoredHashSelected(sourceView, sha256)))
        {
            ClearSelectedIgnoreFlags(sourceView, hashes);
            return;
        }

        IgnoreSelectedDetection(sourceView, hashes);
    }

    private void UpdateIgnoreButtonText(ListView sourceView, Button button)
    {
        var hashes = GetSelectedDetectionHashes(sourceView);
        button.Text = hashes.Count > 0 && hashes.All(sha256 => IsIgnoredHashSelected(sourceView, sha256))
            ? "Clear Ignore Flag"
            : "Ignore Selected";
    }

    private static List<string> GetSelectedDetectionHashes(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            return [];
        }

        return sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Where(item =>
            {
                var malicious = int.TryParse(GetSubItemText(item, ColMalicious), out var mal) ? mal : 0;
                var suspicious = int.TryParse(GetSubItemText(item, ColSuspicious), out var susp) ? susp : 0;
                return malicious + suspicious > 0 && !string.IsNullOrWhiteSpace(GetSubItemText(item, ColSha256));
            })
            .Select(item => GetSubItemText(item, ColSha256))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private bool IsIgnoredHashSelected(ListView sourceView, string sha256)
    {
        return ignoredHashes.Contains(sha256)
            || sourceView.SelectedItems
                .Cast<ListViewItem>()
                .Any(item => string.Equals(GetSubItemText(item, ColSha256), sha256, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(item.Text, "ignored", StringComparison.OrdinalIgnoreCase));
    }

    private void IgnoreSelectedDetection(ListView sourceView, List<string> hashes)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a detected row to ignore.", "No detection selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (hashes.Count == 0)
        {
            MessageBox.Show(this, "Select one or more detected items with SHA-256 hashes.", "No detection selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Ignore {hashes.Count} detection(s) in future scans?",
            "Ignore detections",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        foreach (var sha256 in hashes)
        {
            ignoredHashes.Add(sha256);
            MarkIgnoredRows(sourceView, sha256);
            MarkIgnoredRows(resultsView, sha256);
            foreach (var result in results.Where(result => string.Equals(result.Sha256, sha256, StringComparison.OrdinalIgnoreCase)))
            {
                result.Status = "ignored";
                if (!result.Notes.Contains("Detection ignored by user.", StringComparison.OrdinalIgnoreCase))
                {
                    result.Notes = string.IsNullOrWhiteSpace(result.Notes)
                        ? "Detection ignored by user."
                        : $"{result.Notes}; Detection ignored by user.";
                }
            }
        }

        SaveIgnoredHashes();
        UpdateSummary();
        statusLabel.Text = $"{hashes.Count} detection(s) ignored. Future scans will mark those hashes as ignored.";
    }

    private void ClearSelectedIgnoreFlags(ListView sourceView, List<string> hashes)
    {
        var accepted = MessageBox.Show(
            this,
            $"Clear the ignore flag for {hashes.Count} detection(s)?",
            "Clear ignore flag",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        foreach (var sha256 in hashes)
        {
            ignoredHashes.Remove(sha256);
            MarkUnignoredRows(sourceView, sha256);
            MarkUnignoredRows(resultsView, sha256);
            foreach (var result in results.Where(result => string.Equals(result.Sha256, sha256, StringComparison.OrdinalIgnoreCase)))
            {
                result.Status = result.IsDetection ? "detected" : "clean";
                result.Notes = RemoveIgnoreNote(result.Notes);
            }
        }

        SaveIgnoredHashes();
        UpdateSummary();
        statusLabel.Text = $"{hashes.Count} ignore flag(s) cleared.";
    }

    private static void MarkIgnoredRows(ListView view, string sha256)
    {
        foreach (ListViewItem row in view.Items)
        {
            if (!string.Equals(GetSubItemText(row, ColSha256), sha256, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            row.Text = "ignored";
            var notes = GetSubItemText(row, ColNotes);
            row.SubItems[ColNotes].Text = notes.Contains("Detection ignored by user.", StringComparison.OrdinalIgnoreCase)
                ? notes
                : string.IsNullOrWhiteSpace(notes)
                    ? "Detection ignored by user."
                    : $"{notes}; Detection ignored by user.";
            ApplyResultRowColor(row);
        }
    }

    private static void MarkUnignoredRows(ListView view, string sha256)
    {
        foreach (ListViewItem row in view.Items)
        {
            if (!string.Equals(GetSubItemText(row, ColSha256), sha256, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var malicious = int.TryParse(GetSubItemText(row, ColMalicious), out var mal) ? mal : 0;
            var suspicious = int.TryParse(GetSubItemText(row, ColSuspicious), out var susp) ? susp : 0;
            row.Text = malicious + suspicious > 0 ? "detected" : "clean";
            row.SubItems[ColNotes].Text = RemoveIgnoreNote(GetSubItemText(row, ColNotes));
            ApplyResultRowColor(row);
        }
    }

    private static string RemoveIgnoreNote(string notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return "";
        }

        return string.Join("; ",
            notes.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Where(note => !note.Equals("Detection ignored by user.", StringComparison.OrdinalIgnoreCase)));
    }

    private void OpenSelectedReport(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select a row with a SHA-256 hash first.", "No report selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var item = sourceView.SelectedItems[0];
        var sha256 = GetSubItemText(item, ColSha256);
        if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
        {
            MessageBox.Show(this, "The selected row has no valid SHA-256 hash.", "No report selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new Form
        {
            Text = "Open Report",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ClientSize = new Size(620, 186),
        };

        var prompt = new Label
        {
            Text = "Choose which report to open for the selected hash:",
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 10),
        };

        var hashLabel = new Label
        {
            Text = sha256,
            AutoEllipsis = true,
            Width = 574,
            Height = 22,
            ForeColor = Color.DimGray,
        };

        var virusTotal = new Button { Text = "VirusTotal", Width = 128, Height = 34 };
        var metaDefender = new Button { Text = "MalwareDefender", Width = 150, Height = 34 };
        var mhr = new Button { Text = "Cymru", Width = 108, Height = 34 };
        var cancel = new Button { Text = "Cancel", Width = 92, Height = 34, DialogResult = DialogResult.Cancel };

        virusTotal.Click += (_, _) => OpenReportAndClose(dialog, string.Format(ReportUrl, sha256));
        metaDefender.Click += (_, _) => OpenReportAndClose(dialog, string.Format(MetaDefenderReportUrl, sha256));
        mhr.Click += (_, _) => OpenReportAndClose(dialog, string.Format(CymruDnsQueryUrl, Uri.EscapeDataString(BuildCymruQueryName(sha256))));

        toolTip.SetToolTip(virusTotal, "Open VirusTotal report");
        toolTip.SetToolTip(metaDefender, "Open MalwareDefender report");
        toolTip.SetToolTip(mhr, "Open Cymru Malware Hash Registry DNS report");

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0, 14, 0, 0),
        };
        buttons.Controls.Add(virusTotal);
        buttons.Controls.Add(metaDefender);
        buttons.Controls.Add(mhr);
        buttons.Controls.Add(cancel);

        var layout = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(18),
        };
        layout.Controls.Add(prompt);
        layout.Controls.Add(hashLabel);
        layout.Controls.Add(buttons);
        dialog.Controls.Add(layout);
        dialog.CancelButton = cancel;
        dialog.ShowDialog(this);
    }

    private static void OpenReportAndClose(Form dialog, string link)
    {
        Process.Start(new ProcessStartInfo(link) { UseShellExecute = true });
        dialog.DialogResult = DialogResult.OK;
        dialog.Close();
    }

    private static string BuildCymruQueryName(string sha256)
    {
        if (sha256.Length != 64)
        {
            return sha256;
        }

        return $"{sha256[..32]}.{sha256[32..]}.hash.cymru.com";
    }

    private void ExportCsv()
    {
        ExportCsv(resultsView);
    }

    private void ExportCsv(ListView sourceView)
    {
        if (sourceView.Items.Count == 0)
        {
            MessageBox.Show(this, "There are no rows to export.", "No results", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = "Export scan results",
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = "csv",
            FileName = $"vt-process-scan-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var lines = new List<string>
        {
            "status,risk,trust,malicious,suspicious,harmless,undetected,process_names,pids,sha256,path,link,notes",
        };
        foreach (ListViewItem item in sourceView.Items)
        {
            lines.Add(string.Join(",", new[]
            {
                Csv(GetSubItemText(item, 0)),
                Csv(GetSubItemText(item, ColRisk)),
                Csv(GetSubItemText(item, ColTrust)),
                Csv(GetSubItemText(item, ColMalicious)),
                Csv(GetSubItemText(item, ColSuspicious)),
                Csv(""),
                Csv(""),
                Csv(GetSubItemText(item, ColProcess)),
                Csv(GetSubItemText(item, ColPids)),
                Csv(GetSubItemText(item, ColSha256)),
                Csv(GetSubItemText(item, ColPath)),
                Csv(item.Tag as string ?? ""),
                Csv(GetSubItemText(item, ColNotes)),
            }));
        }

        File.WriteAllLines(dialog.FileName, lines, Encoding.UTF8);
        MessageBox.Show(this, $"Saved {sourceView.Items.Count} rows to:{Environment.NewLine}{dialog.FileName}", "Export complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private static string GetSubItemText(ListViewItem item, int index)
    {
        return item.SubItems.Count > index ? item.SubItems[index].Text : "";
    }

    private static string Csv(string value)
    {
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static List<string> ParseCsvLine(string line)
    {
        var values = new List<string>();
        var current = new StringBuilder();
        var quoted = false;

        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character == '"')
            {
                if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                {
                    current.Append('"');
                    index++;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (character == ',' && !quoted)
            {
                values.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(character);
            }
        }

        values.Add(current.ToString());
        return values;
    }

    private static JsonElement ReadElement(JsonElement root, params string[] path)
    {
        var current = root;
        foreach (var segment in path)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out var next))
            {
                return default;
            }

            current = next;
        }

        return current;
    }

    private static int ReadInt(JsonElement root, string property)
    {
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty(property, out var value) && value.TryGetInt32(out var number))
        {
            return number;
        }

        return 0;
    }

    private static string? ReadString(JsonElement root, params string[] path)
    {
        var value = ReadElement(root, path);
        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private sealed record ProcessCollectionResult(Dictionary<string, List<ProcessFile>> Files, List<SkippedProcess> Skipped);
    private sealed record ProcessFile(int Pid, string Name, string Path);
    private sealed record SkippedProcess(int Pid, string Name, string Reason);
    private sealed record PersistenceTarget(string Path, string Source);
    private readonly record struct ProcessFileState(long Length, DateTime LastWriteTimeUtc);

    private sealed class HashCache
    {
        private static readonly string PrimaryCachePath = Path.Combine(
            GetConfigDirectory(),
            "hash-cache.json");
        private static readonly string FileStateCachePath = Path.Combine(
            GetConfigDirectory(),
            "file-state-cache.json");

        private readonly Dictionary<string, CacheEntry> entries = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, FileStateEntry> fileStates = new(StringComparer.OrdinalIgnoreCase);

        public int Count => entries.Count;

        public async Task LoadAsync()
        {
            entries.Clear();
            fileStates.Clear();
            foreach (var cachePath in GetCachePaths().Distinct(StringComparer.OrdinalIgnoreCase))
            {
                await LoadFromPathAsync(cachePath);
            }

            await LoadFileStatesAsync();
        }

        public bool TryGet(string sha256, out CacheEntry entry)
        {
            return entries.TryGetValue(sha256, out entry!);
        }

        public bool TryGetUnchangedFile(string path, out string sha256, out CacheEntry entry)
        {
            sha256 = "";
            entry = null!;

            if (!fileStates.TryGetValue(path, out var fileState) || !entries.TryGetValue(fileState.Sha256, out entry!) || !IsReusableCleanEntry(entry))
            {
                return false;
            }

            try
            {
                var info = new FileInfo(path);
                if (!info.Exists
                    || info.Length != fileState.Length
                    || info.LastWriteTimeUtc != fileState.LastWriteTimeUtc)
                {
                    return false;
                }

                sha256 = fileState.Sha256;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Set(ScanResult result)
        {
            entries[result.Sha256] = new CacheEntry
            {
                Status = result.Status,
                Malicious = result.Malicious,
                Suspicious = result.Suspicious,
                Harmless = result.Harmless,
                Undetected = result.Undetected,
                Link = result.Link,
                Notes = result.Notes,
                CheckedAtUtc = DateTimeOffset.UtcNow,
            };
            SetFileState(result);
        }

        public async Task MarkFileCleanAsync(string path, string notes)
        {
            if (!File.Exists(path))
            {
                return;
            }

            var sha256 = await Sha256FileAsync(path);
            entries[sha256] = new CacheEntry
            {
                Status = "clean",
                Link = string.Format(ReportUrl, sha256),
                Notes = notes,
                CheckedAtUtc = DateTimeOffset.UtcNow,
            };

            SetFileState(new ScanResult(path, Path.GetFileName(path), Process.GetCurrentProcess().Id.ToString())
            {
                Sha256 = sha256,
                Status = "clean",
                Link = string.Format(ReportUrl, sha256),
                Notes = notes,
            });
        }

        public void SetFileState(ScanResult result)
        {
            if (string.IsNullOrWhiteSpace(result.Sha256) || !entries.TryGetValue(result.Sha256, out var entry) || !IsReusableCleanEntry(entry))
            {
                return;
            }

            try
            {
                var info = new FileInfo(result.Path);
                if (!info.Exists)
                {
                    return;
                }

                fileStates[result.Path] = new FileStateEntry
                {
                    Sha256 = result.Sha256,
                    Length = info.Length,
                    LastWriteTimeUtc = info.LastWriteTimeUtc,
                };
            }
            catch
            {
                // File state caching is an optimization; scan results are still valid without it.
            }
        }

        public void ImportScanLogs(IEnumerable<string> logDirectories)
        {
            foreach (var logDirectory in logDirectories.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(logDirectory))
                {
                    continue;
                }

                foreach (var logPath in Directory.EnumerateFiles(logDirectory, "scan-log-*.csv"))
                {
                    ImportScanLog(logPath);
                }
            }
        }

        private void ImportScanLog(string logPath)
        {
            try
            {
                var lines = File.ReadLines(logPath).ToList();
                if (lines.Count < 2)
                {
                    return;
                }

                var headers = ParseCsvLine(lines[0]);
                var columns = headers
                    .Select((name, index) => new { Name = name.Trim(), Index = index })
                    .ToDictionary(item => item.Name, item => item.Index, StringComparer.OrdinalIgnoreCase);

                foreach (var line in lines.Skip(1))
                {
                    ImportScanLogRow(ParseCsvLine(line), columns, File.GetLastWriteTimeUtc(logPath));
                }
            }
            catch
            {
                // Old or manually edited logs should not block new scans.
            }
        }

        private void ImportScanLogRow(List<string> row, Dictionary<string, int> columns, DateTime checkedAtUtc)
        {
            var sha256 = GetCsvValue(row, columns, "sha256");
            if (sha256.Length != 64)
            {
                return;
            }

            var status = NormalizeCachedStatus(GetCsvValue(row, columns, "status"));
            if (string.IsNullOrWhiteSpace(status) || string.Equals(status, "error", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var entry = new CacheEntry
            {
                Status = status,
                Malicious = GetCsvInt(row, columns, "malicious"),
                Suspicious = GetCsvInt(row, columns, "suspicious"),
                Harmless = GetCsvInt(row, columns, "harmless"),
                Undetected = GetCsvInt(row, columns, "undetected"),
                Link = GetCsvValue(row, columns, "link"),
                Notes = GetCsvValue(row, columns, "notes"),
                CheckedAtUtc = new DateTimeOffset(DateTime.SpecifyKind(checkedAtUtc, DateTimeKind.Utc)),
            };

            MergeEntry(sha256, entry, entry.CheckedAtUtc);
            SetFileStateFromLog(GetCsvValue(row, columns, "path"), sha256, entry);
        }

        private static string GetCsvValue(List<string> row, Dictionary<string, int> columns, string columnName)
        {
            return columns.TryGetValue(columnName, out var index) && index >= 0 && index < row.Count
                ? row[index]
                : "";
        }

        private static int GetCsvInt(List<string> row, Dictionary<string, int> columns, string columnName)
        {
            return int.TryParse(GetCsvValue(row, columns, columnName), out var value) ? value : 0;
        }

        public static bool IsCleanEntry(CacheEntry entry)
        {
            return (string.Equals(entry.Status, "clean", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(entry.Status, "clean/seen", StringComparison.OrdinalIgnoreCase))
                && entry.Malicious == 0
                && entry.Suspicious == 0;
        }

        public static bool IsReusableCleanEntry(CacheEntry entry)
        {
            return IsCleanEntry(entry)
                && entry.CheckedAtUtc != default
                && DateTimeOffset.UtcNow - entry.CheckedAtUtc <= CleanCacheMaxAge;
        }

        private static string NormalizeCachedStatus(string status)
        {
            return string.Equals(status, "clean/seen", StringComparison.OrdinalIgnoreCase) ? "clean" : status;
        }

        private static List<string> ParseCsvLine(string line)
        {
            var values = new List<string>();
            var current = new StringBuilder();
            var quoted = false;

            for (var index = 0; index < line.Length; index++)
            {
                var character = line[index];
                if (character == '"')
                {
                    if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                    {
                        current.Append('"');
                        index++;
                    }
                    else
                    {
                        quoted = !quoted;
                    }
                }
                else if (character == ',' && !quoted)
                {
                    values.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(character);
                }
            }

            values.Add(current.ToString());
            return values;
        }

        public async Task SaveAsync()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PrimaryCachePath)!);
            await using var stream = File.Create(PrimaryCachePath);
            await JsonSerializer.SerializeAsync(stream, entries, new JsonSerializerOptions { WriteIndented = true });

            await using var fileStateStream = File.Create(FileStateCachePath);
            await JsonSerializer.SerializeAsync(fileStateStream, fileStates, new JsonSerializerOptions { WriteIndented = true });
        }

        private async Task LoadFileStatesAsync()
        {
            if (!File.Exists(FileStateCachePath))
            {
                return;
            }

            try
            {
                await using var stream = File.OpenRead(FileStateCachePath);
                var loaded = await JsonSerializer.DeserializeAsync<Dictionary<string, FileStateEntry>>(stream);
                if (loaded is null)
                {
                    return;
                }

                foreach (var item in loaded)
                {
                    if (!string.IsNullOrWhiteSpace(item.Value.Sha256))
                    {
                        fileStates[item.Key] = item.Value;
                    }
                }
            }
            catch
            {
                // Ignore stale or malformed file state cache data.
            }
        }

        private static IEnumerable<string> GetCachePaths()
        {
            yield return PrimaryCachePath;
            yield return Path.Combine(GetConfigDirectory(), "hash-cache.json");
            yield return Path.Combine(GetConfigDirectory(), "cache.json");
            yield return Path.Combine(AppContext.BaseDirectory, "hash-cache.json");

            if (!Directory.Exists(GetConfigDirectory()))
            {
                yield break;
            }

            foreach (var path in Directory.EnumerateFiles(GetConfigDirectory(), "*.json"))
            {
                yield return path;
            }
        }

        private async Task LoadFromPathAsync(string cachePath)
        {
            if (!File.Exists(cachePath))
            {
                return;
            }

            try
            {
                await using var stream = File.OpenRead(cachePath);
                var loaded = await JsonSerializer.DeserializeAsync<Dictionary<string, CacheEntry>>(stream);
                if (loaded is null)
                {
                    return;
                }

                var fileTime = new DateTimeOffset(File.GetLastWriteTimeUtc(cachePath), TimeSpan.Zero);
                foreach (var item in loaded)
                {
                    MergeEntry(item.Key, item.Value, fileTime);
                }
            }
            catch
            {
                // Non-cache JSON files may live in config; ignore anything that is not a cache.
            }
        }

        private void MergeEntry(string sha256, CacheEntry entry, DateTimeOffset fallbackCheckedAtUtc)
        {
            entry.Status = NormalizeCachedStatus(entry.Status);
            if (sha256.Length != 64 || string.IsNullOrWhiteSpace(entry.Status) || string.Equals(entry.Status, "error", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (entry.CheckedAtUtc == default)
            {
                entry.CheckedAtUtc = fallbackCheckedAtUtc;
            }

            if (!entries.TryGetValue(sha256, out var existing) || entry.CheckedAtUtc > existing.CheckedAtUtc)
            {
                entries[sha256] = entry;
            }
        }

        private void SetFileStateFromLog(string path, string sha256, CacheEntry entry)
        {
            if (string.IsNullOrWhiteSpace(path) || !IsCleanEntry(entry))
            {
                return;
            }

            try
            {
                var fullPath = Path.GetFullPath(path);
                var info = new FileInfo(fullPath);
                if (!info.Exists)
                {
                    return;
                }

                fileStates[fullPath] = new FileStateEntry
                {
                    Sha256 = sha256,
                    Length = info.Length,
                    LastWriteTimeUtc = info.LastWriteTimeUtc,
                };
            }
            catch
            {
                // Log path metadata is best-effort.
            }
        }
    }

    private sealed class QuotaTracker
    {
        private const int DailyLimit = 500;
        private const int MinuteLimit = 4;
        private static readonly string QuotaPath = Path.Combine(
            GetConfigDirectory(),
            "free-api-quota.json");

        private QuotaState state = new();

        public async Task LoadAsync()
        {
            if (File.Exists(QuotaPath))
            {
                await using var stream = File.OpenRead(QuotaPath);
                state = await JsonSerializer.DeserializeAsync<QuotaState>(stream) ?? new QuotaState();
            }

            ResetIfNewDay();
            TrimOldMinuteRequests(DateTimeOffset.UtcNow);
            await SaveAsync();
        }

        public async Task<QuotaReservation> TryReserveAsync()
        {
            ResetIfNewDay();
            var now = DateTimeOffset.UtcNow;
            TrimOldMinuteRequests(now);

            if (state.DailyCount >= DailyLimit)
            {
                return new QuotaReservation(false, "daily");
            }

            if (state.MinuteRequestsUtc.Count >= MinuteLimit)
            {
                return new QuotaReservation(false, "minute");
            }

            state.MinuteRequestsUtc.Add(now);
            state.DailyCount++;
            await SaveAsync();
            return new QuotaReservation(true, "");
        }

        private void ResetIfNewDay()
        {
            var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd");
            if (state.UtcDay == today)
            {
                return;
            }

            state.UtcDay = today;
            state.DailyCount = 0;
            state.MinuteRequestsUtc.Clear();
        }

        private void TrimOldMinuteRequests(DateTimeOffset now)
        {
            state.MinuteRequestsUtc = state.MinuteRequestsUtc
                .Where(requestTime => now - requestTime < TimeSpan.FromMinutes(1))
                .ToList();
        }

        private async Task SaveAsync()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(QuotaPath)!);
            await using var stream = File.Create(QuotaPath);
            await JsonSerializer.SerializeAsync(stream, state, new JsonSerializerOptions { WriteIndented = true });
        }
    }

    private readonly record struct QuotaReservation(bool Available, string LimitName);

    private sealed class CacheEntry
    {
        public string Status { get; set; } = "";
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public string Link { get; set; } = "";
        public string Notes { get; set; } = "";
        public DateTimeOffset CheckedAtUtc { get; set; }
    }

    private sealed class FileStateEntry
    {
        public string Sha256 { get; set; } = "";
        public long Length { get; set; }
        public DateTime LastWriteTimeUtc { get; set; }
    }

    private sealed class QuotaState
    {
        public string UtcDay { get; set; } = "";
        public int DailyCount { get; set; }
        public List<DateTimeOffset> MinuteRequestsUtc { get; set; } = [];
    }

    private sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")]
        public string TagName { get; set; } = "";

        [JsonPropertyName("body")]
        public string Body { get; set; } = "";

        [JsonPropertyName("draft")]
        public bool Draft { get; set; }

        [JsonPropertyName("assets")]
        public List<GitHubAsset> Assets { get; set; } = [];
    }

    private sealed class GitHubAsset
    {
        [JsonPropertyName("url")]
        public string Url { get; set; } = "";

        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("browser_download_url")]
        public string BrowserDownloadUrl { get; set; } = "";

        [JsonPropertyName("digest")]
        public string Digest { get; set; } = "";
    }

    private sealed record CymruReputation(DateTimeOffset LastSeenUtc, int DetectionPercent);

    private enum TrayState
    {
        Clean,
        Scanning,
        ActionNeeded,
    }

    internal sealed class AppSettings
    {
        public bool FreeApiLimits { get; set; } = true;
        public bool VirusTotalEnabled { get; set; } = true;
        public bool MetaDefenderEnabled { get; set; } = true;
        public bool MhrEnabled { get; set; } = true;
        public bool HashCacheEnabled { get; set; } = true;
        public bool UploadUnknown { get; set; }
        public bool StartMinimized { get; set; }
        public bool AutoProcessScan { get; set; } = true;
        public bool RunElevated { get; set; }
        public bool ScanAllFiles { get; set; }
        public bool AutoUpdateChecks { get; set; }
        public int DelaySeconds { get; set; } = 16;
        public int TimeoutSeconds { get; set; } = 60;
        public string ApiKeyEncrypted { get; set; } = "";
        public string MetaDefenderApiKeyEncrypted { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public string MetaDefenderApiKey { get; set; } = "";
    }

    private sealed class ScanResult(string path, string processNames, string pids)
    {
        public string Path { get; } = path;
        public string ProcessNames { get; } = processNames;
        public string Pids { get; } = pids;
        public string Sha256 { get; set; } = "";
        public string Status { get; set; } = "";
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public string Link { get; set; } = "";
        public string Notes { get; set; } = "";
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "Low";
        public string TrustSummary { get; set; } = "";
        public string SignatureSummary { get; set; } = "";
        public long FileSizeBytes { get; set; }
        public DateTime LastWriteTimeUtc { get; set; }
        public double FileAgeDays { get; set; } = -1;
        public List<string> PersistenceSources { get; set; } = [];
        public bool VirusTotalDeferred { get; set; }
        public bool IsDetection => Malicious > 0 || Suspicious > 0;
        public bool IsAlert => IsDetection && !string.Equals(Status, "ignored", StringComparison.OrdinalIgnoreCase);

        public void ApplyCache(CacheEntry entry, string prefix = "Cached")
        {
            Status = entry.Status;
            Malicious = entry.Malicious;
            Suspicious = entry.Suspicious;
            Harmless = entry.Harmless;
            Undetected = entry.Undetected;
            Link = entry.Link;
            Notes = $"{prefix} {entry.CheckedAtUtc.LocalDateTime:g}";
            if (!string.IsNullOrWhiteSpace(entry.Notes))
            {
                Notes += $"; {entry.Notes}";
            }
        }
    }
}
