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
    private const string QuarantineFolderName = "quarantine";
    private const string QuarantineManifestFileName = "quarantine-manifest.json";
    private static readonly string CurrentVersion = GetCurrentVersion();
    private const string GitHubOwner = "snaket7ds";
    private const string GitHubRepo = "HashGuard";
    private static readonly TimeSpan CleanCacheMaxAge = TimeSpan.FromDays(7);
    private static readonly TimeSpan UnknownCacheMaxAge = TimeSpan.FromHours(12);
    private static readonly TimeSpan ErrorCacheMaxAge = TimeSpan.FromHours(1);
    private static readonly TimeSpan DeferredCacheMaxAge = TimeSpan.FromMinutes(30);
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
    private const string MainResultsViewName = "mainResultsView";
    private const string ColorModeSystem = "system";
    private const string ColorModeLight = "light";
    private const string ColorModeDark = "dark";
    private static readonly Color AccentGold = Color.FromArgb(255, 199, 44);
    private static readonly Color SuccessGreen = Color.FromArgb(21, 128, 61);
    private static readonly Color DangerRed = Color.FromArgb(185, 28, 28);

    private readonly TextBox apiKeyBox = new() { UseSystemPasswordChar = true };
    private readonly TextBox metaDefenderApiKeyBox = new() { UseSystemPasswordChar = true };
    private readonly Button scanButton = new() { Text = "Run Scan", Width = 172, Height = 42, BackColor = AccentGold, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
    private readonly Button updateButton = new() { Text = "Update", Width = 86, Height = 40, Font = new Font("Segoe UI", 9, FontStyle.Bold) };
    private readonly Button settingsButton = new() { Text = "\uE713", Width = 44, Height = 40, Font = new Font("Segoe MDL2 Assets", 12, FontStyle.Regular) };
    private readonly CheckBox freeApiLimitBox = new() { Text = "Free API limits (4/min, 500/day)", AutoSize = true, Checked = true };
    private readonly CheckBox rightClickScanBox = new() { Text = "Add Explorer right-click scan", AutoSize = true };
    private readonly CheckBox startWithWindowsBox = new() { Text = "Start with Windows", AutoSize = true };
    private readonly CheckBox startMinimizedBox = new() { Text = "Start minimized to tray", AutoSize = true };
    private readonly CheckBox autoProcessScanBox = new() { Text = "Scan automatically at startup", AutoSize = true, Checked = true };
    private readonly CheckBox runElevatedBox = new() { Text = "Run Elevated (Windows UAC permissions)", AutoSize = true };
    private readonly CheckBox scanAllFilesBox = new() { Text = "Scan files I open or select", AutoSize = true };
    private readonly ComboBox colorModeBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 };
    private readonly CheckBox uploadUnknownBox = new() { Text = "Upload files missing from VirusTotal", AutoSize = true };
    private readonly CheckBox virusTotalEnabledBox = new() { Text = "Use VirusTotal", AutoSize = true, Checked = true };
    private readonly CheckBox metaDefenderEnabledBox = new() { Text = "Use MetaDefender Cloud", AutoSize = true, Checked = true };
    private readonly CheckBox mhrEnabledBox = new() { Text = "Use Team Cymru MHR", AutoSize = true, Checked = true };
    private readonly CheckBox hashCacheEnabledBox = new() { Text = "Enable Hash Cache", AutoSize = true, Checked = true };
    private readonly CheckBox autoUpdateChecksBox = new() { Text = "Check updates automatically", AutoSize = true };
    private readonly NumericUpDown delayBox = new() { Minimum = 0, Maximum = 120, Value = 16, Width = 64 };
    private readonly NumericUpDown timeoutBox = new() { Minimum = 10, Maximum = 300, Value = 60, Width = 64 };
    private readonly ListView resultsView = new() { View = View.Details, FullRowSelect = true, GridLines = false, HideSelection = false, BorderStyle = BorderStyle.FixedSingle };
    private readonly Label resultsEmptyLabel = new()
    {
        Text = "No items need review. Run a scan or open Activity Log for full scan history.",
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleCenter,
        ForeColor = Color.DimGray,
        Font = new Font("Segoe UI", 10, FontStyle.Regular),
    };
    private readonly ProgressBar progressBar = new();
    private readonly Label statusLabel = new() { AutoEllipsis = false };
    private readonly Label countLabel = new() { AutoSize = true };
    private readonly Panel statusDot = new() { Width = 92, Height = 92, Margin = new Padding(0, 0, 0, 10), Tag = "action" };
    private readonly Label statusTitle = new() { Text = "You are not protected", AutoSize = true, Font = new Font("Segoe UI", 24, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label statusSubtitle = new() { Text = "Run a process scan to verify protection.", AutoSize = true, ForeColor = Color.DimGray, TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label summaryLabel = new() { Text = "Items scanned: 0", AutoSize = false, Font = new Font("Segoe UI", 10, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label actionLabel = new() { Text = "Needs review: 0", AutoSize = false, Font = new Font("Segoe UI", 10, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
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
        cleanTrayIcon = CreateTrayStatusIcon(TrayState.Clean);
        scanningTrayIcon = CreateTrayStatusIcon(TrayState.Scanning);
        actionTrayIcon = CreateTrayStatusIcon(TrayState.ActionNeeded);
        startupScanFile = ParseStartupScanFile(args);
        startupMinimized = args.Any(arg => string.Equals(arg, "--minimized", StringComparison.OrdinalIgnoreCase));
        closedOlderInstances = CloseOtherInstances();
        appSettings = LoadAppSettings();
        LoadIgnoredHashes();
        colorModeBox.Items.AddRange(["Use Windows setting", "Light", "Dark"]);
        ApplyAppSettings();
        Text = "HashGuard";
        Icon = cleanTrayIcon;
        MinimumSize = new Size(900, 660);
        Size = new Size(1080, 760);
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
        colorModeBox.SelectedIndexChanged += (_, _) =>
        {
            SaveCurrentAppSettings();
            ApplyAppTheme(this);
        };
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
            ShowFirstRunSetupIfNeeded();
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
            RowCount = 3,
            Padding = new Padding(0),
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
        Controls.Add(root);

        var header = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, Height = 86, BackColor = Color.FromArgb(28, 28, 28), Padding = new Padding(24, 14, 24, 12) };
        header.Tag = "header";
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var titleBlock = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(0) };
        titleBlock.Controls.Add(new Label { Text = "HashGuard", AutoSize = true, Font = new Font("Segoe UI", 20, FontStyle.Bold), ForeColor = Color.White, Margin = new Padding(0) });
        titleBlock.Controls.Add(new Label { Text = "Process reputation, local trust scoring, and quarantine", AutoSize = true, ForeColor = Color.FromArgb(205, 205, 205), Margin = new Padding(1, 2, 0, 0) });
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
        root.Controls.Add(header, 0, 0);

        var main = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(20, 20, 20, 12),
        };
        main.RowStyles.Add(new RowStyle(SizeType.Absolute, 218));
        main.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.Controls.Add(main, 0, 1);
        resultsView.Name = MainResultsViewName;

        var overview = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Margin = new Padding(0, 0, 0, 12),
        };
        overview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
        overview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
        main.Controls.Add(overview, 0, 0);

        var statusCard = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Padding = new Padding(18),
            Margin = new Padding(0, 0, 12, 0),
            BorderStyle = BorderStyle.FixedSingle,
        };
        statusDot.Paint += (_, e) => PaintStatusBadge(e.Graphics, statusDot.ClientRectangle, statusDot.Tag as string ?? "clean");
        statusDot.Width = 96;
        statusDot.Height = 96;
        statusDot.Margin = new Padding(0, 0, 18, 0);
        statusTitle.AutoSize = false;
        statusTitle.Dock = DockStyle.Fill;
        statusTitle.Font = new Font("Segoe UI", 18, FontStyle.Bold);
        statusTitle.TextAlign = ContentAlignment.BottomLeft;
        statusSubtitle.AutoSize = false;
        statusSubtitle.Dock = DockStyle.Fill;
        statusSubtitle.TextAlign = ContentAlignment.TopLeft;
        statusSubtitle.MaximumSize = new Size(0, 0);

        var statusLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3 };
        statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 116));
        statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 96));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        statusLayout.Controls.Add(statusDot, 0, 0);
        statusLayout.SetRowSpan(statusDot, 2);

        var statusText = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0) };
        statusText.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        statusText.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        statusText.Controls.Add(statusTitle, 0, 0);
        statusText.Controls.Add(statusSubtitle, 0, 1);
        statusLayout.Controls.Add(statusText, 1, 0);

        var stats = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 8, 0, 0) };
        stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        stats.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        summaryLabel.Dock = DockStyle.Fill;
        summaryLabel.MaximumSize = new Size(0, 0);
        summaryLabel.TextAlign = ContentAlignment.MiddleLeft;
        summaryLabel.BackColor = Color.FromArgb(246, 247, 249);
        summaryLabel.Padding = new Padding(12, 0, 12, 0);
        summaryLabel.Margin = new Padding(0, 0, 8, 0);
        actionLabel.Dock = DockStyle.Fill;
        actionLabel.TextAlign = ContentAlignment.MiddleLeft;
        actionLabel.BackColor = Color.FromArgb(246, 247, 249);
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
        tiles.Controls.Add(CreateHashCacheTile(), 0, 1);
        tiles.Controls.Add(CreateFeatureTile("Activity Log", "Scan history", "Open", ShowScanDetailsDialogSafe), 1, 1);
        overview.Controls.Add(tiles, 1, 0);

        ConfigureResultsView(resultsView);
        var resultsPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Padding = new Padding(14),
            Margin = new Padding(0),
            BorderStyle = BorderStyle.FixedSingle,
        };
        var resultsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        resultsLayout.Controls.Add(new Label
        {
            Text = "Review Queue",
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(35, 35, 35),
        }, 0, 0);
        var resultsHost = new Panel { Dock = DockStyle.Fill };
        resultsHost.Controls.Add(resultsEmptyLabel);
        resultsHost.Controls.Add(resultsView);
        resultsEmptyLabel.BringToFront();
        resultsLayout.Controls.Add(resultsHost, 0, 1);
        var queueActions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 8, 0, 0) };
        queueActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        queueActions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var rowActions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0) };
        var openReport = CreateQueueActionButton("Open Report");
        var openLocation = CreateQueueActionButton("Open Location");
        var ignoreSelected = CreateQueueActionButton("Ignore");
        var quarantineSelected = CreateQueueActionButton("Quarantine");
        var utilityActions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Margin = new Padding(12, 0, 0, 0) };
        var activityLog = CreateQueueActionButton("Activity Log");
        openReport.Click += (_, _) => OpenSelectedReport(resultsView);
        openLocation.Click += (_, _) => OpenSelectedFileLocation(resultsView);
        ignoreSelected.Click += (_, _) => ToggleSelectedIgnoreFlag(resultsView);
        quarantineSelected.Click += (_, _) => QuarantineSelectedFiles(resultsView);
        activityLog.Click += (_, _) => ShowScanDetailsDialogSafe();
        resultsView.SelectedIndexChanged += (_, _) =>
        {
            ReconcileReviewQueue(updateSummary: false);
            var hasSelection = resultsView.SelectedItems.Count > 0;
            openReport.Enabled = hasSelection;
            openLocation.Enabled = hasSelection;
            ignoreSelected.Enabled = hasSelection;
            quarantineSelected.Enabled = hasSelection;
            UpdateIgnoreButtonText(resultsView, ignoreSelected);
        };
        resultsView.Enter += (_, _) => ReconcileReviewQueue();
        resultsView.MouseDown += (_, _) => ReconcileReviewQueue();
        openReport.Enabled = false;
        openLocation.Enabled = false;
        ignoreSelected.Enabled = false;
        quarantineSelected.Enabled = false;
        rowActions.Controls.Add(openReport);
        rowActions.Controls.Add(openLocation);
        rowActions.Controls.Add(ignoreSelected);
        rowActions.Controls.Add(quarantineSelected);
        utilityActions.Controls.Add(activityLog);
        queueActions.Controls.Add(rowActions, 0, 0);
        queueActions.Controls.Add(utilityActions, 1, 0);
        resultsLayout.Controls.Add(queueActions, 0, 2);
        resultsPanel.Controls.Add(resultsLayout);
        main.Controls.Add(resultsPanel, 0, 1);

        var bottomCard = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(20, 0, 20, 20),
            Padding = new Padding(14, 8, 14, 8),
            BorderStyle = BorderStyle.FixedSingle,
        };
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, Margin = new Padding(0), Padding = new Padding(0) };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 18));
        bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        progressBar.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        progressBar.Height = 14;
        progressBar.Margin = new Padding(0, 0, 0, 0);
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
        root.Controls.Add(bottomCard, 0, 2);

        statusLabel.Text = "Ready";
        UpdateResultsEmptyState();
        UpdateReputationTile();
        UpdateHashCacheTile();
        ApplyAppTheme(this);
    }

    private static Panel CreateFeatureTile(string title, string subtitle, string state, Action? onClick = null)
    {
        var tile = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(4),
            Padding = new Padding(12),
            BorderStyle = BorderStyle.FixedSingle,
        };

        var cursor = onClick is null ? Cursors.Default : Cursors.Hand;
        var layout = CreateTileTextLayout(
            CreateTileTitle(title, cursor),
            CreateTileDetail(subtitle, cursor),
            CreateTileState(state, SuccessGreen, cursor));
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
            Margin = new Padding(4),
            Padding = new Padding(12),
            BorderStyle = BorderStyle.FixedSingle,
        };

        ConfigureTileDetailLabel(reputationStateLabel);
        ConfigureTileStateLabel(reputationProtectionLabel, SuccessGreen);
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
        reputationProtectionLabel.ForeColor = enabled.Count == 0 ? DangerRed : SuccessGreen;
    }

    private Panel CreateHashCacheTile()
    {
        var tile = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.White,
            Margin = new Padding(4),
            Padding = new Padding(12),
            BorderStyle = BorderStyle.FixedSingle,
        };

        ConfigureTileStateLabel(hashCacheStateLabel, SuccessGreen);
        tile.Controls.Add(CreateTileTextLayout(
            CreateTileTitle("Hash Cache"),
            CreateTileDetail("Repeat lookups"),
            hashCacheStateLabel));
        WireClick(tile, OpenHashCacheFolder);
        return tile;
    }

    private static void ConfigureHeaderButton(Button button)
    {
        button.BackColor = Color.FromArgb(52, 52, 52);
        button.ForeColor = Color.White;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 1;
        button.FlatAppearance.BorderColor = Color.FromArgb(85, 85, 85);
        button.UseVisualStyleBackColor = false;
    }

    private static Button CreateQueueActionButton(string text)
    {
        return new Button
        {
            Text = text,
            Width = Math.Max(86, text.Length * 8 + 24),
            Height = 30,
            Margin = new Padding(0, 0, 8, 0),
            FlatStyle = FlatStyle.Flat,
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

    private void UpdateHashCacheTile()
    {
        hashCacheStateLabel.Text = hashCacheEnabledBox.Checked ? "Enabled" : "Disabled";
        hashCacheStateLabel.ForeColor = hashCacheEnabledBox.Checked ? SuccessGreen : DangerRed;
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
            view.Columns.Add("Mal", 0);
            view.Columns.Add("Susp", 0);
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
            view.Columns.Add("Mal", 52);
            view.Columns.Add("Susp", 52);
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
        var rect = new Rectangle((bounds.Width - size) / 2, (bounds.Height - size) / 2, size, size);
        var actionNeeded = state == "action";
        var scanning = state is "scanning" or "stopped";
        var fillColor = actionNeeded
            ? DangerRed
            : scanning
                ? Color.FromArgb(255, 205, 0)
                : SuccessGreen;
        using var fill = new SolidBrush(fillColor);
        using var pen = new Pen(actionNeeded ? Color.FromArgb(150, 0, 0) : Color.FromArgb(36, 36, 36), Math.Max(3, size / 16));
        graphics.FillEllipse(fill, rect);
        if (actionNeeded)
        {
            var centerX = rect.Left + rect.Width / 2;
            graphics.DrawLine(pen, centerX, rect.Top + rect.Height * 0.25f, centerX, rect.Top + rect.Height * 0.62f);
            graphics.FillEllipse(Brushes.White, centerX - size * 0.055f, rect.Top + rect.Height * 0.74f, size * 0.11f, size * 0.11f);
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
            TrayState.ActionNeeded => Color.FromArgb(218, 45, 45),
            TrayState.Scanning => Color.FromArgb(255, 205, 0),
            _ => Color.FromArgb(0, 145, 82),
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

    private void ShowSettingsDialog()
    {
        using var dialog = new Form
        {
            Text = "Settings",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.Sizable,
            MaximizeBox = true,
            MinimizeBox = false,
            ClientSize = new Size(1180, 860),
            MinimumSize = new Size(1080, 800),
            BackColor = Color.FromArgb(246, 247, 249),
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
        var colorMode = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 };
        colorMode.Items.AddRange(["Use Windows setting", "Light", "Dark"]);
        colorMode.SelectedIndex = Math.Clamp(colorModeBox.SelectedIndex, 0, colorMode.Items.Count - 1);
        var autoProcessScan = new CheckBox { Text = "Scan automatically at startup", Checked = autoProcessScanBox.Checked, AutoSize = true };
        var runElevated = new CheckBox { Text = "Run elevated", Checked = runElevatedBox.Checked, AutoSize = true };
        var scanAllFiles = new CheckBox { Text = "Scan files I open or select", Checked = scanAllFilesBox.Checked, AutoSize = true };
        var autoUpdates = new CheckBox { Text = "Check updates automatically", Checked = autoUpdateChecksBox.Checked, AutoSize = true };
        var hashCache = new CheckBox { Text = "Enable Hash Cache", Checked = hashCacheEnabledBox.Checked, AutoSize = true };
        var uploadUnknown = new CheckBox { Text = "Upload files missing from VirusTotal", Checked = uploadUnknownBox.Checked, AutoSize = true };
        var trustedPublishers = new TextBox
        {
            Text = string.Join(Environment.NewLine, appSettings.TrustedPublishers),
            Dock = DockStyle.Fill,
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Height = 82,
        };
        var delay = new NumericUpDown { Minimum = 0, Maximum = 120, Value = delayBox.Value, Width = 70 };
        var timeout = new NumericUpDown { Minimum = 10, Maximum = 300, Value = timeoutBox.Value, Width = 70 };
        var ok = new Button { Text = "Save", DialogResult = DialogResult.OK, Width = 96, Height = 34, FlatStyle = FlatStyle.Flat };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 96, Height = 34, FlatStyle = FlatStyle.Flat };
        var reputationValidation = new Label
        {
            Dock = DockStyle.Top,
            Height = 64,
            Padding = new Padding(10),
            BackColor = Color.FromArgb(255, 250, 220),
            ForeColor = Color.FromArgb(80, 60, 0),
            TextAlign = ContentAlignment.MiddleLeft,
            BorderStyle = BorderStyle.FixedSingle,
            Tag = "callout",
        };
        var updateInfo = new Label
        {
            Text = BuildVersionAndUpdateInfo(),
            Dock = DockStyle.Top,
            Height = 82,
            Padding = new Padding(10),
            BackColor = Color.White,
            ForeColor = Color.FromArgb(35, 35, 35),
            TextAlign = ContentAlignment.MiddleLeft,
            BorderStyle = BorderStyle.FixedSingle,
            Tag = "callout",
        };

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(0) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        dialog.Controls.Add(root);

        var settingsHeader = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 1,
            RowCount = 2,
            Height = 68,
            Padding = new Padding(22, 10, 22, 8),
            BackColor = Color.FromArgb(28, 28, 28),
            Tag = "header",
        };
        settingsHeader.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        settingsHeader.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        settingsHeader.Controls.Add(new Label
        {
            Text = $"HashGuard Settings  |  Version {CurrentVersion}",
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ForeColor = Color.White,
            TextAlign = ContentAlignment.MiddleLeft,
            Margin = new Padding(0),
        }, 0, 0);
        settingsHeader.Controls.Add(new Label
        {
            Text = "Provider keys, scan behavior, Windows integration, and trusted publishers",
            Dock = DockStyle.Fill,
            ForeColor = Color.FromArgb(205, 205, 205),
            TextAlign = ContentAlignment.TopLeft,
            Margin = new Padding(0),
        }, 0, 1);
        root.Controls.Add(settingsHeader, 0, 0);

        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(16, 12, 16, 10),
            Font = new Font("Segoe UI", 9, FontStyle.Regular),
        };
        root.Controls.Add(tabs, 0, 1);

        var reputationPage = CreateSettingsPage(
            ("Reputation Providers", [vtEnabled, mdEnabled, mhrEnabled, freeLimit, uploadUnknown]),
            ("API Keys", [CreateSettingRow("VirusTotal API key", apiKey), CreateSettingRow("MetaDefender API key", metaDefenderApiKey)]),
            ("Request Timing", [CreateSettingRow("VirusTotal delay per request", delay), CreateSettingRow("Request timeout", timeout)]),
            ("Provider Status", [reputationValidation]));
        AddSettingsTab(tabs, "Reputation", reputationPage);

        var behaviorPage = CreateSettingsPage(
            ("Scanning", [hashCache, autoProcessScan, scanAllFiles, runElevated]),
            ("Windows Integration", [rightClickScan, startWithWindows, startMinimized, CreateSettingRow("Colors", colorMode), autoUpdates]),
            ("Version and Updates", [updateInfo]));
        AddSettingsTab(tabs, "Behavior", behaviorPage);

        trustedPublishers.Height = 220;
        var trustPage = CreateSettingsPage(
            ("Trusted Publishers",
            [
                new Label
            {
                Text = "One publisher per line. Matching signed files receive a lower local risk score.",
                Dock = DockStyle.Top,
                Height = 34,
                ForeColor = Color.DimGray,
                TextAlign = ContentAlignment.MiddleLeft,
            },
                trustedPublishers,
            ]));
        AddSettingsTab(tabs, "Trust", trustPage);

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 4, 18, 12),
        };
        ok.BackColor = AccentGold;
        ok.ForeColor = Color.FromArgb(24, 24, 24);
        ok.FlatAppearance.BorderColor = Color.FromArgb(218, 161, 0);
        cancel.FlatAppearance.BorderSize = 1;
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);
        root.Controls.Add(buttons, 0, 2);
        dialog.AcceptButton = ok;
        dialog.CancelButton = cancel;
        ApplyAppTheme(dialog);

        void RefreshValidation()
        {
            reputationValidation.Text = BuildSettingsValidationText(
                vtEnabled.Checked,
                mdEnabled.Checked,
                mhrEnabled.Checked,
                apiKey.Text,
                metaDefenderApiKey.Text,
                uploadUnknown.Checked,
                scanAllFiles.Checked);
            reputationValidation.BackColor = reputationValidation.Text.StartsWith("Ready", StringComparison.OrdinalIgnoreCase)
                ? Color.FromArgb(230, 246, 236)
                : Color.FromArgb(255, 250, 220);
            reputationValidation.ForeColor = reputationValidation.Text.StartsWith("Ready", StringComparison.OrdinalIgnoreCase)
                ? Color.FromArgb(25, 100, 50)
                : Color.FromArgb(80, 60, 0);
        }

        foreach (var checkBox in new[] { vtEnabled, mdEnabled, mhrEnabled, uploadUnknown, scanAllFiles })
        {
            checkBox.CheckedChanged += (_, _) => RefreshValidation();
        }

        apiKey.TextChanged += (_, _) => RefreshValidation();
        metaDefenderApiKey.TextChanged += (_, _) => RefreshValidation();
        RefreshValidation();

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
        colorModeBox.SelectedIndex = colorMode.SelectedIndex;
        autoProcessScanBox.Checked = autoProcessScan.Checked;
        runElevatedBox.Checked = runElevated.Checked;
        scanAllFilesBox.Checked = scanAllFiles.Checked && EnableAllFileScanningWithWarning();
        if (scanAllFilesBox.Checked)
        {
            DisableVirusTotalUploadsForActiveFileScanning(showMessage: false);
        }
        autoUpdateChecksBox.Checked = autoUpdates.Checked;
        appSettings.TrustedPublishers = trustedPublishers.Lines
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(line => line, StringComparer.OrdinalIgnoreCase)
            .ToList();
        UpdateReputationTile();
        UpdateHashCacheTile();
        UpdateAutomaticUpdateTimer();
        UpdateAllFileScanner();
        SaveCurrentAppSettings();
        ApplyAppTheme(this);
    }

    private static string BuildSettingsValidationText(
        bool virusTotalEnabled,
        bool metaDefenderEnabled,
        bool mhrEnabled,
        string virusTotalApiKey,
        string metaDefenderApiKey,
        bool uploadUnknown,
        bool scanAllFiles)
    {
        var notes = new List<string>();
        if (!virusTotalEnabled && !metaDefenderEnabled && !mhrEnabled)
        {
            notes.Add("No cloud or hash reputation providers are enabled.");
        }

        if (virusTotalEnabled && string.IsNullOrWhiteSpace(virusTotalApiKey))
        {
            notes.Add("VirusTotal is enabled without an API key; HashGuard will rely on local signals, cache, and other providers.");
        }

        if (metaDefenderEnabled && string.IsNullOrWhiteSpace(metaDefenderApiKey))
        {
            notes.Add("MetaDefender Cloud is enabled without an API key; checks will be skipped until a key is saved.");
        }

        if (uploadUnknown && scanAllFiles)
        {
            notes.Add("Uploads cannot be enabled while open/selected file scanning is enabled.");
        }

        return notes.Count == 0
            ? "Ready: enabled providers and scan options are consistent."
            : string.Join(Environment.NewLine, notes);
    }

    private static string BuildVersionAndUpdateInfo()
    {
        var elevated = IsRunningElevated() ? "Yes" : "No";
        return string.Join(Environment.NewLine, new[]
        {
            $"Installed version: {CurrentVersion}",
            $"Executable: {Application.ExecutablePath}",
            $"Running elevated: {elevated}",
            "Use Update to check GitHub release notes and install a verified HashGuard.exe asset.",
        });
    }

    private void ShowFirstRunSetupIfNeeded()
    {
        if (appSettings.FirstRunSetupShown || startupMinimized || startupScanFile is not null)
        {
            return;
        }

        appSettings.FirstRunSetupShown = true;
        SaveCurrentAppSettings();
        var message = string.Join($"{Environment.NewLine}{Environment.NewLine}", new[]
        {
            "HashGuard can start with local-only protection. It will score unsigned files, risky paths, persistence entries, recent changes, and cached reputation without API keys.",
            "Cloud reputation is stronger when you add VirusTotal and MetaDefender API keys in Settings.",
            "Uploading unknown files is optional and privacy-sensitive. Leave uploads off for private, personal, proprietary, or sensitive files.",
            "Open Settings now?",
        });
        var openSettings = MessageBox.Show(this, message, "HashGuard first-run setup", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
        if (openSettings == DialogResult.Yes)
        {
            ShowSettingsDialog();
        }
    }

    private static void AddSettingsTab(TabControl tabs, string title, Control content)
    {
        var page = new TabPage(title) { BackColor = Color.White, Padding = new Padding(0) };
        content.Dock = DockStyle.Fill;
        page.Controls.Add(content);
        tabs.TabPages.Add(page);
    }

    private static FlowLayoutPanel CreateSettingsPage(params (string Title, Control[] Controls)[] sections)
    {
        var page = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = false,
            Padding = new Padding(14, 12, 14, 8),
            BackColor = Color.FromArgb(246, 247, 249),
        };
        page.ControlAdded += (_, e) =>
        {
            if (e.Control is not null)
            {
                ResizeSettingsSection(page, e.Control);
            }
        };
        page.SizeChanged += (_, _) =>
        {
            foreach (Control child in page.Controls)
            {
                ResizeSettingsSection(page, child);
            }
        };
        foreach (var section in sections)
        {
            page.Controls.Add(CreateSettingsSection(section.Title, section.Controls));
        }

        return page;
    }

    private static Panel CreateSettingsSection(string title, IEnumerable<Control> controls)
    {
        var section = new Panel
        {
            Width = 720,
            Height = 10,
            BackColor = Color.White,
            Padding = new Padding(12, 8, 12, 8),
            Margin = new Padding(0, 0, 0, 8),
            BorderStyle = BorderStyle.FixedSingle,
        };

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            ColumnCount = 1,
            RowCount = 1,
            Padding = new Padding(0),
            Margin = new Padding(0),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label
        {
            Text = title,
            Dock = DockStyle.Top,
            Height = 26,
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(35, 35, 35),
            TextAlign = ContentAlignment.MiddleLeft,
            Margin = new Padding(0, 0, 0, 4),
        });

        foreach (var control in controls)
        {
            control.Margin = new Padding(0, 1, 0, 4);
            control.Dock = DockStyle.Top;
            NormalizeSettingsControl(control);
            layout.Controls.Add(control);
        }

        section.Height = Math.Max(58, layout.PreferredSize.Height + section.Padding.Vertical);
        section.Controls.Add(layout);
        return section;
    }

    private static void NormalizeSettingsControl(Control control)
    {
        if (control is CheckBox checkBox)
        {
            checkBox.AutoSize = false;
            checkBox.Height = 24;
            checkBox.TextAlign = ContentAlignment.MiddleLeft;
            checkBox.UseMnemonic = false;
        }

        if (control is Label label)
        {
            label.AutoSize = false;
            label.UseMnemonic = false;
        }
    }

    private static void ResizeSettingsSection(FlowLayoutPanel page, Control section)
    {
        var availableWidth = page.ClientSize.Width - page.Padding.Horizontal;
        section.Width = Math.Max(560, availableWidth - section.Margin.Horizontal);
    }

    private static Control CreateSettingRow(string labelText, Control editor)
    {
        var row = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            ColumnCount = 2,
            Height = 30,
            Margin = new Padding(0, 1, 0, 4),
        };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.Controls.Add(new Label
        {
            Text = labelText,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(35, 35, 35),
            Margin = new Padding(0, 0, 12, 0),
        }, 0, 0);
        editor.Dock = DockStyle.Fill;
        row.Controls.Add(editor, 1, 0);
        return row;
    }

    private void ApplyAppTheme(Control root)
    {
        var palette = GetCurrentPalette();
        ApplyTheme(root, palette, inHeader: false);
        if (scanCancellation is null)
        {
            SetScanButtonReadyStyle();
        }
        else
        {
            SetScanButtonStopStyle();
        }
        resultsView.BackColor = palette.Surface;
        resultsView.ForeColor = palette.Text;
        resultsEmptyLabel.ForeColor = palette.MutedText;
        summaryLabel.BackColor = palette.PillBack;
        actionLabel.BackColor = palette.PillBack;
        statusSubtitle.ForeColor = palette.MutedText;
        reputationStateLabel.ForeColor = palette.Text;
        UpdateReputationTile();
        UpdateHashCacheTile();
        statusDot.Invalidate();
    }

    private ThemePalette GetCurrentPalette()
    {
        return appSettings.ColorMode switch
        {
            ColorModeDark => ThemePalette.Dark,
            ColorModeLight => ThemePalette.Light,
            _ => IsWindowsDarkAppTheme() ? ThemePalette.Dark : ThemePalette.Light,
        };
    }

    private static int ColorModeToIndex(string colorMode, bool legacyUseSystemDefaultColors)
    {
        return colorMode switch
        {
            ColorModeLight => 1,
            ColorModeDark => 2,
            ColorModeSystem => 0,
            _ => legacyUseSystemDefaultColors ? 0 : 1,
        };
    }

    private static string IndexToColorMode(int index)
    {
        return index switch
        {
            1 => ColorModeLight,
            2 => ColorModeDark,
            _ => ColorModeSystem,
        };
    }

    private static bool IsWindowsDarkAppTheme()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void ApplyTheme(Control control, ThemePalette palette, bool inHeader)
    {
        var header = inHeader || control.Tag as string == "header";
        switch (control)
        {
            case Form:
                control.BackColor = palette.AppBack;
                control.ForeColor = palette.Text;
                break;
            case ListView listView:
                listView.BackColor = palette.Surface;
                listView.ForeColor = palette.Text;
                break;
            case TextBox textBox:
                textBox.BackColor = palette.InputBack;
                textBox.ForeColor = palette.Text;
                break;
            case NumericUpDown numeric:
                numeric.BackColor = palette.InputBack;
                numeric.ForeColor = palette.Text;
                break;
            case ComboBox comboBox:
                comboBox.BackColor = palette.InputBack;
                comboBox.ForeColor = palette.Text;
                break;
            case Button button when button.Text is "Run Scan" or "Stop Scan":
                break;
            case Button button:
                button.FlatStyle = FlatStyle.Flat;
                button.FlatAppearance.BorderSize = 1;
                button.FlatAppearance.BorderColor = header ? palette.HeaderButtonBorder : palette.Border;
                button.BackColor = header ? palette.HeaderButtonBack : palette.ButtonBack;
                button.ForeColor = header ? Color.White : palette.Text;
                break;
            case CheckBox:
            case Label:
                if (control.Tag as string == "callout")
                {
                    control.BackColor = palette.CalloutBack;
                    control.ForeColor = palette.Text;
                    break;
                }

                if (!header && control.ForeColor != DangerRed && control.ForeColor != SuccessGreen)
                {
                    control.ForeColor = control.ForeColor == Color.DimGray ? palette.MutedText : palette.Text;
                }
                control.BackColor = Color.Transparent;
                break;
            case TabControl:
            case TabPage:
                control.BackColor = palette.Surface;
                control.ForeColor = palette.Text;
                break;
            case TableLayoutPanel:
            case FlowLayoutPanel:
            case Panel:
                control.BackColor = header ? palette.HeaderBack : (control.BackColor == ThemePalette.Light.AppBack ? palette.AppBack : palette.Surface);
                control.ForeColor = header ? Color.White : palette.Text;
                break;
        }

        foreach (Control child in control.Controls)
        {
            ApplyTheme(child, palette, header);
        }
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

    private void SetScanButtonReadyStyle()
    {
        scanButton.Text = "Run Scan";
        scanButton.BackColor = AccentGold;
        scanButton.ForeColor = Color.FromArgb(24, 24, 24);
        scanButton.FlatAppearance.BorderSize = 1;
        scanButton.FlatAppearance.BorderColor = Color.FromArgb(218, 161, 0);
    }

    private void SetScanButtonStopStyle()
    {
        scanButton.Text = "Stop Scan";
        scanButton.BackColor = DangerRed;
        scanButton.ForeColor = Color.White;
        scanButton.FlatAppearance.BorderSize = 1;
        scanButton.FlatAppearance.BorderColor = DangerRed;
    }

    private void SetDashboardState(string title, string subtitle, bool actionNeeded)
    {
        var scanning = title.Contains("Scanning", StringComparison.OrdinalIgnoreCase);
        var stopped = title.Contains("Stopped", StringComparison.OrdinalIgnoreCase);
        statusTitle.Text = actionNeeded ? "Threats need review" : scanning ? "Scanning" : stopped ? "Scan stopped" : "Protected";
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
        SetScanButtonStopStyle();
        scanButton.Enabled = true;
        results.Clear();
        resultsView.Items.Clear();
        UpdateResultsEmptyState();
        progressBar.Value = 0;
        countLabel.Text = "";
        statusLabel.Text = "Collecting running processes...";
        summaryLabel.Text = "Preparing scan";
        actionLabel.Text = "Needs review: 0";
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
                statusLabel.Text = $"Scanning {index + 1} of {paths.Count}: {FormatDisplayPath(path)}";
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

            var unresolved = results.Where(ResultNeedsAction).ToList();
            var alerts = unresolved.Where(result => result.IsAlert).ToList();
            var unknown = results.Count(result => result.Status is "unknown" or "uploaded");
            var errors = unresolved.Count(result => result.Status == "error");
            var highRisk = unresolved.Count(result => result.RiskScore >= 70);
            statusLabel.Text = $"Done. {unresolved.Count} action needed, {alerts.Count} detections, {unknown} unknown/uploaded, {errors} errors. Cache: {hashCache.Count} hashes.";
            SetDashboardState(
                unresolved.Count > 0 ? "Action needed" : "Clean",
                alerts.Count > 0
                    ? "A reputation service reported malicious or suspicious detections."
                    : errors > 0
                        ? "Some files could not be checked. Review Activity Log or Open Logs for details."
                        : highRisk > 0
                            ? "Local trust signals found high-risk files that need review."
                            : "No unresolved threats or high-risk items were found.",
                unresolved.Count > 0);
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
            SetScanButtonReadyStyle();
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
                statusLabel.Text = $"Monitoring scan {index + 1} of {newPaths.Count}: {FormatDisplayPath(path)}";
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

            var unresolved = results.Where(ResultNeedsAction).ToList();
            var alerts = unresolved.Where(result => result.IsAlert).ToList();
            var errors = unresolved.Count(result => result.Status == "error");
            var highRisk = unresolved.Count(result => result.RiskScore >= 70);
            var lastScanTime = FormatComputerTime(DateTimeOffset.Now);
            SetDashboardState(
                unresolved.Count > 0 ? "Action needed" : "Clean",
                alerts.Count > 0
                    ? "A reputation service reported malicious or suspicious detections."
                    : errors > 0
                        ? "Some files could not be checked. Review Activity Log or Open Logs for details."
                        : highRisk > 0
                            ? "Local trust signals found high-risk files that need review."
                            : $"Monitoring active. Scanned {newPaths.Count} new file(s). Last scan: {lastScanTime}.",
                unresolved.Count > 0);
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

    private static string FormatComputerTime(DateTimeOffset timestamp)
    {
        return timestamp.ToLocalTime().ToString("yyyy-MM-dd h:mm tt");
    }

    private static string FormatDisplayPath(string path, int maxLength = 86)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length <= maxLength)
        {
            return path;
        }

        var fileName = Path.GetFileName(path);
        var root = Path.GetPathRoot(path) ?? "";
        var directory = Path.GetDirectoryName(path) ?? "";
        var reserved = fileName.Length + root.Length + 8;
        var tailBudget = Math.Max(16, maxLength - reserved);
        var tail = directory.Length <= tailBudget ? directory : directory[^tailBudget..];
        return $"{root}...{tail}{Path.DirectorySeparatorChar}{fileName}";
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
        if (!File.Exists(path))
        {
            MessageBox.Show(this, $"File not found:{Environment.NewLine}{path}", "Right-click scan", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        scanButton.Enabled = false;
        results.Clear();
        resultsView.Items.Clear();
        UpdateResultsEmptyState();
        progressBar.Value = 0;
        progressBar.Maximum = 1;
        countLabel.Text = "1 / 1";
        statusLabel.Text = $"Scanning selected file: {FormatDisplayPath(path)}";
        summaryLabel.Text = "Preparing scan";
        actionLabel.Text = "Needs review: 0";
        SetDashboardState("Scanning", "Checking the selected file with enabled reputation services.", false);

        try
        {
            if (virusTotalEnabledBox.Checked && string.IsNullOrWhiteSpace(apiKey))
            {
                statusLabel.Text = "VirusTotal API key is not configured. Running local/provider checks that do not require it.";
            }

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
            var unresolved = results.Where(ResultNeedsAction).ToList();
            var alerts = unresolved.Where(result => result.IsAlert).ToList();
            SetDashboardState(
                unresolved.Count > 0 ? "Action needed" : "Clean",
                alerts.Count > 0
                    ? "A reputation service reported malicious or suspicious detections."
                    : unresolved.Count > 0
                        ? "Local trust signals found a file that needs review."
                        : "No unresolved threats or high-risk items were found.",
                unresolved.Count > 0);
            statusLabel.Text = unresolved.Count > 0 ? "Selected file scan complete. Review needed." : "Selected file scan complete. No unresolved threats.";
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

        foreach (var target in CollectScheduledTaskTargets())
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

    private static IEnumerable<PersistenceTarget> CollectScheduledTaskTargets()
    {
        if (!OperatingSystem.IsWindows())
        {
            yield break;
        }

        foreach (var target in CollectScheduledTaskXmlTargets())
        {
            yield return target;
        }

        string output;
        try
        {
            using var process = Process.Start(new ProcessStartInfo("schtasks.exe", "/query /fo csv /v")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            });
            if (process is null)
            {
                yield break;
            }

            output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10000);
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            {
                yield break;
            }
        }
        catch
        {
            yield break;
        }

        var lines = output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 2)
        {
            yield break;
        }

        var headers = ParseCsvLine(lines[0]);
        var columns = headers
            .Select((name, index) => new { Name = name.Trim(), Index = index })
            .ToDictionary(item => item.Name, item => item.Index, StringComparer.OrdinalIgnoreCase);

        foreach (var line in lines.Skip(1))
        {
            var row = ParseCsvLine(line);
            var taskName = GetCsvValue(row, columns, "TaskName");
            var action = GetCsvValue(row, columns, "Task To Run");
            var path = TryExtractExecutablePath(action);
            if (!string.IsNullOrWhiteSpace(path))
            {
                yield return new PersistenceTarget(path, $"Scheduled task: {taskName}");
            }
        }
    }

    private static IEnumerable<PersistenceTarget> CollectScheduledTaskXmlTargets()
    {
        var taskRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(taskRoot))
        {
            yield break;
        }

        foreach (var taskFile in Directory.EnumerateFiles(taskRoot, "*", SearchOption.AllDirectories))
        {
            XDocument document;
            try
            {
                document = XDocument.Load(taskFile);
            }
            catch
            {
                continue;
            }

            var execNodes = document.Descendants().Where(element => element.Name.LocalName == "Exec");
            foreach (var exec in execNodes)
            {
                var command = exec.Elements().FirstOrDefault(element => element.Name.LocalName == "Command")?.Value;
                var arguments = exec.Elements().FirstOrDefault(element => element.Name.LocalName == "Arguments")?.Value;
                var path = TryExtractExecutablePath($"{command} {arguments}".Trim());
                if (!string.IsNullOrWhiteSpace(path))
                {
                    yield return new PersistenceTarget(path, $"Scheduled task: {Path.GetRelativePath(taskRoot, taskFile)}");
                }
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
        return HashGuardLogic.TryExtractExecutablePath(command);
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
                    MessageBox.Show(
                        this,
                        $"HashGuard is up to date.{Environment.NewLine}Current version: {CurrentVersion}{Environment.NewLine}Latest GitHub version: {latestVersion}",
                        "Update",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
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

                if (HashCache.IsReusablePendingEntry(cached))
                {
                    result.ApplyCache(cached, "Recent cached provider state");
                    result.Status = cached.Status;
                    AppendResultNote(result, "Provider lookups skipped temporarily to reduce repeat API usage.");
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
                AddProviderResult(result, "Local", ProviderState.Unknown, "No reputation services are enabled.");
                AppendResultNote(result, "No reputation services are enabled.");
            }
            else if (string.IsNullOrWhiteSpace(result.Status))
            {
                result.Status = result.IsAlert ? "detected"
                    : result.ProviderResults.Count > 0 && result.ProviderResults.All(provider => provider.State is ProviderState.NotChecked or ProviderState.Deferred or ProviderState.Error)
                        ? "unknown"
                        : "clean";
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

        var signature = GetSignatureInfo(result.Path);
        result.SignatureSummary = signature.Summary;
        result.SignaturePublisher = signature.Publisher;
    }

    private static SignatureInfo GetSignatureInfo(string path)
    {
        try
        {
            var certificate = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(certificate);
            var publisher = cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            var expired = DateTime.Now < cert2.NotBefore || DateTime.Now > cert2.NotAfter;
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(3);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            var chainValid = chain.Build(cert2);
            var chainStatus = chainValid
                ? "chain valid"
                : string.Join(", ", chain.ChainStatus.Select(status => status.Status.ToString()).Distinct());
            var summary = expired
                ? $"Signed by {publisher}; certificate outside validity period; {chainStatus}"
                : $"Signed by {publisher}; {chainStatus}";
            return new SignatureInfo(summary, publisher);
        }
        catch
        {
            return new SignatureInfo("Unsigned or signature unavailable", "");
        }
    }

    private void ApplyRiskAndTrust(ScanResult result)
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

        var trustedPublisher = IsTrustedPublisher(result.SignaturePublisher);
        if (result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
            reasons.Add("unsigned");
        }
        else if (trustedPublisher)
        {
            score = Math.Max(0, score - 20);
            trust.Add($"trusted publisher: {result.SignaturePublisher}");
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

    private bool IsTrustedPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher))
        {
            return false;
        }

        return appSettings.TrustedPublishers.Any(trusted =>
            publisher.Contains(trusted, StringComparison.OrdinalIgnoreCase)
            || trusted.Contains(publisher, StringComparison.OrdinalIgnoreCase));
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
            if (!http.DefaultRequestHeaders.Contains("x-apikey"))
            {
                AddProviderResult(result, "VirusTotal", ProviderState.NotChecked, "API key not configured.");
                AppendResultNote(result, "VirusTotal: skipped, API key not configured.");
                return;
            }

            if (!await TryReserveVirusTotalQuotaAsync(result))
            {
                AddProviderResult(result, "VirusTotal", ProviderState.Deferred, "Free API quota reached.");
                return;
            }

            using var reportResponse = await http.GetAsync(string.Format(FileReportUrl, result.Sha256), cancellationToken);
            if (reportResponse.StatusCode == HttpStatusCode.NotFound)
            {
                result.Status = "unknown";
                AddProviderResult(result, "VirusTotal", ProviderState.Unknown, "Hash not found.");
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
                    AddProviderResult(result, "VirusTotal", ProviderState.Deferred, $"Uploaded for analysis: {analysisId}");
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
            AddProviderResult(result, "VirusTotal", result.IsDetection ? ProviderState.Detected : ProviderState.Clean,
                result.IsDetection ? $"{result.Malicious} malicious, {result.Suspicious} suspicious." : "No malicious or suspicious detections.");
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
            AddProviderResult(result, "VirusTotal", ProviderState.Error, FormatScanError(ex));
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
                AddProviderResult(result, "MetaDefender", ProviderState.NotChecked, "API key not configured.");
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
                AddProviderResult(result, "MetaDefender", ProviderState.Unknown, "Hash not found.");
                AppendResultNote(result, "MetaDefender Cloud: hash not found.");
                return;
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                AddProviderResult(result, "MetaDefender", ProviderState.Error, "401 Unauthorized.");
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
            AddProviderResult(result, "MetaDefender", ProviderState.Error, ex.Message);
        }
    }

    private async Task PollAnalysisAsync(HttpClient http, string analysisId, ScanResult result, string path, CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= 6; attempt++)
        {
            statusLabel.Text = $"Waiting for VirusTotal analysis {attempt} of 6: {FormatDisplayPath(path)}";
            await Task.Delay(TimeSpan.FromSeconds(Math.Max((double)delayBox.Value, 15.0)), cancellationToken);

            if (!await TryReserveVirusTotalQuotaAsync(result))
            {
                AddProviderResult(result, "VirusTotal", ProviderState.Deferred, "Free API quota reached while polling analysis.");
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
                AddProviderResult(result, "VirusTotal", result.IsDetection ? ProviderState.Detected : ProviderState.Clean,
                    result.IsDetection ? $"{result.Malicious} malicious, {result.Suspicious} suspicious." : "Analysis completed clean.");
                AppendResultNote(result, $"VirusTotal analysis ID: {analysisId}");
                return;
            }
        }

        AppendResultNote(result, $"VirusTotal analysis still running: {analysisId}");
        AddProviderResult(result, "VirusTotal", ProviderState.Deferred, $"Analysis still running: {analysisId}");
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
            AddProviderResult(result, "MetaDefender", ProviderState.Detected, $"Detected by {detected}/{total} engines{detail}.");
            AppendResultNote(result, $"MetaDefender Cloud: detected by {detected}/{total} engines{detail}.");
            return;
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(result.Status))
        {
            result.Status = "clean";
        }

        var totalText = total > 0 ? $" across {total} engines" : "";
        AddProviderResult(result, "MetaDefender", ProviderState.Clean, $"No threat detected{totalText}.");
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
                AddProviderResult(result, "Cymru MHR", ProviderState.Clean, "No malware match.");
                AppendResultNote(result, "Team Cymru MHR: no malware match.");
                return;
            }

            AppendResultNote(result, $"Team Cymru MHR: malware match, {reputation.DetectionPercent}% AV hit rate, last seen {reputation.LastSeenUtc:yyyy-MM-dd} UTC.");
            AddProviderResult(result, "Cymru MHR", ProviderState.Detected, $"{reputation.DetectionPercent}% AV hit rate, last seen {reputation.LastSeenUtc:yyyy-MM-dd} UTC.");
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
            AddProviderResult(result, "Cymru MHR", ProviderState.Error, ex.Message);
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

    private static void AddProviderResult(ScanResult result, string provider, ProviderState state, string detail)
    {
        result.ProviderResults.RemoveAll(item => string.Equals(item.Provider, provider, StringComparison.OrdinalIgnoreCase));
        result.ProviderResults.Add(new ProviderResult(provider, state, detail));
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
        if (string.IsNullOrWhiteSpace(result.Sha256))
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
        AppendScanLog(result);
        if (!ResultNeedsAction(result))
        {
            UpdateResultsEmptyState();
            return;
        }

        AddReviewQueueRow(result);
    }

    private void AddReviewQueueRow(ScanResult result)
    {
        if (resultsView.Items
            .Cast<ListViewItem>()
            .Any(item => string.Equals(GetSubItemText(item, ColSha256), result.Sha256, StringComparison.OrdinalIgnoreCase)
                && string.Equals(GetSubItemText(item, ColPath), result.Path, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var item = new ListViewItem(result.Status);
        item.SubItems.Add($"{result.RiskLevel} {result.RiskScore}");
        item.SubItems.Add(result.TrustSummary);
        item.SubItems.Add(result.Malicious.ToString());
        item.SubItems.Add(result.Suspicious.ToString());
        item.SubItems.Add(result.ProcessNames);
        item.SubItems.Add(result.Pids);
        item.SubItems.Add(result.Sha256);
        item.SubItems.Add(result.Path);
        item.SubItems.Add(resultsView.Name == MainResultsViewName ? BuildReviewRecommendation(result) : result.Notes);
        item.Tag = result.Link;

        if (result.IsAlert)
        {
            item.BackColor = Color.FromArgb(253, 232, 232);
        }
        else if (result.Status == "ignored")
        {
            item.BackColor = Color.FromArgb(232, 245, 233);
        }
        else if (result.Status is "unknown" or "uploaded")
        {
            item.BackColor = Color.FromArgb(255, 247, 214);
        }
        else if (result.Status == "limited access")
        {
            item.BackColor = Color.FromArgb(255, 247, 214);
        }
        else if (result.Status == "error")
        {
            item.BackColor = Color.FromArgb(248, 215, 218);
        }

        resultsView.Items.Add(item);
        UpdateResultsEmptyState();
        FitResultColumns(resultsView);
    }

    private void ReconcileReviewQueue(bool updateSummary = true)
    {
        if (results.Count == 0)
        {
            UpdateResultsEmptyState();
            return;
        }

        resultsView.BeginUpdate();
        try
        {
            foreach (var item in resultsView.Items.Cast<ListViewItem>().ToList())
            {
                var result = FindResultForReviewQueueRow(item);
                if (result is null || !ResultNeedsAction(result))
                {
                    resultsView.Items.Remove(item);
                    continue;
                }

                item.Text = result.Status;
                item.SubItems[ColRisk].Text = $"{result.RiskLevel} {result.RiskScore}";
                item.SubItems[ColTrust].Text = result.TrustSummary;
                item.SubItems[ColMalicious].Text = result.Malicious.ToString();
                item.SubItems[ColSuspicious].Text = result.Suspicious.ToString();
                item.SubItems[ColProcess].Text = result.ProcessNames;
                item.SubItems[ColPids].Text = result.Pids;
                item.SubItems[ColSha256].Text = result.Sha256;
                item.SubItems[ColPath].Text = result.Path;
                item.SubItems[ColNotes].Text = BuildReviewRecommendation(result);
                ApplyResultRowColor(item);
            }

            foreach (var result in results.Where(ResultNeedsAction))
            {
                AddReviewQueueRow(result);
            }
        }
        finally
        {
            resultsView.EndUpdate();
        }

        UpdateResultsEmptyState();
        FitResultColumns(resultsView);
        if (updateSummary)
        {
            UpdateSummary();
        }
    }

    private ScanResult? FindResultForReviewQueueRow(ListViewItem item)
    {
        var sha256 = GetSubItemText(item, ColSha256);
        var path = GetSubItemText(item, ColPath);
        return results.FirstOrDefault(result =>
            !string.IsNullOrWhiteSpace(sha256)
                ? string.Equals(result.Sha256, sha256, StringComparison.OrdinalIgnoreCase)
                : string.Equals(result.Path, path, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildReviewRecommendation(ScanResult result)
    {
        if (ResultIsHandled(result))
        {
            return string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase)
                ? "Handled: ignored by user"
                : "Handled: quarantined";
        }

        if (result.IsAlert)
        {
            return $"Review now: {result.Malicious} malicious / {result.Suspicious} suspicious detections";
        }

        if (string.Equals(result.Status, "error", StringComparison.OrdinalIgnoreCase))
        {
            return "Review scan error in Activity Log";
        }

        if (result.RiskScore >= 70)
        {
            return "Review high local risk signals";
        }

        if (result.Status is "unknown" or "uploaded" or "limited access")
        {
            return "Monitor: reputation incomplete";
        }

        return "No action needed";
    }

    private void UpdateResultsEmptyState()
    {
        resultsEmptyLabel.Visible = resultsView.Items.Count == 0;
        if (resultsEmptyLabel.Visible)
        {
            resultsEmptyLabel.BringToFront();
        }
    }

    private static void FitResultColumns(ListView view)
    {
        if (view.Columns.Count <= ColNotes)
        {
            return;
        }

        if (view.Name == MainResultsViewName)
        {
            var available = Math.Max(940, view.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 8);
            view.Columns[ColStatus].Width = 112;
            view.Columns[ColRisk].Width = 92;
            view.Columns[ColTrust].Width = Math.Max(190, available * 21 / 100);
            view.Columns[ColMalicious].Width = 0;
            view.Columns[ColSuspicious].Width = 0;
            view.Columns[ColProcess].Width = Math.Max(150, available * 18 / 100);
            view.Columns[ColPids].Width = 0;
            view.Columns[ColSha256].Width = 0;
            view.Columns[ColPath].Width = Math.Max(280, available * 28 / 100);
            view.Columns[ColNotes].Width = Math.Max(240, available - view.Columns[ColStatus].Width - view.Columns[ColRisk].Width - view.Columns[ColTrust].Width - view.Columns[ColProcess].Width - view.Columns[ColPath].Width);
            return;
        }

        view.Columns[ColStatus].Width = 104;
        view.Columns[ColRisk].Width = 96;
        view.Columns[ColMalicious].Width = 52;
        view.Columns[ColSuspicious].Width = 52;
        view.Columns[ColPids].Width = 95;
        view.Columns[ColProcess].Width = Math.Min(220, Math.Max(150, view.Columns[ColProcess].Width));
        view.Columns[ColTrust].Width = Math.Min(320, Math.Max(220, view.Columns[ColTrust].Width));
        view.Columns[ColSha256].Width = Math.Min(360, Math.Max(280, view.Columns[ColSha256].Width));
        view.Columns[ColPath].Width = Math.Min(520, Math.Max(360, view.Columns[ColPath].Width));
        view.Columns[ColNotes].Width = Math.Min(420, Math.Max(300, view.Columns[ColNotes].Width));
    }

    private static void ApplyResultRowColor(ListViewItem item)
    {
        item.BackColor = Color.Empty;
        var status = item.Text;
        var malicious = item.SubItems.Count > ColMalicious && int.TryParse(item.SubItems[ColMalicious].Text, out var mal) ? mal : 0;
        var suspicious = item.SubItems.Count > ColSuspicious && int.TryParse(item.SubItems[ColSuspicious].Text, out var susp) ? susp : 0;
        var riskText = item.SubItems.Count > ColRisk ? item.SubItems[ColRisk].Text : "";

        if (IsHandledActivityItem(item))
        {
            item.BackColor = Color.FromArgb(232, 245, 233);
        }
        else if (malicious > 0 || suspicious > 0)
        {
            item.BackColor = Color.FromArgb(253, 232, 232);
        }
        else if (riskText.StartsWith("Medium", StringComparison.OrdinalIgnoreCase)
            || status is "unknown" or "uploaded" or "limited access")
        {
            item.BackColor = Color.FromArgb(255, 247, 214);
        }
        else if (status == "error")
        {
            item.BackColor = Color.FromArgb(248, 215, 218);
        }
    }

    private void UpdateSummary()
    {
        var actionsNeeded = results.Count(ResultNeedsAction);
        var alerts = results.Count(result => ResultNeedsAction(result) && result.IsAlert);
        var unknown = results.Count(result => result.Status is "unknown" or "uploaded");
        var errors = results.Count(result => ResultNeedsAction(result) && result.Status == "error");
        var highRisk = results.Count(result => ResultNeedsAction(result) && result.RiskScore >= 70);
        var persistent = results.Count(result => result.PersistenceSources.Count > 0);
        var unsigned = results.Count(result => result.SignatureSummary.StartsWith("Unsigned", StringComparison.OrdinalIgnoreCase));
        summaryLabel.Text = $"Items scanned: {results.Count}";
        actionLabel.Text = $"Needs review: {actionsNeeded}";
        toolTip.SetToolTip(summaryLabel, $"{results.Count} scanned | {highRisk} high risk | {persistent} persistent | {unsigned} unsigned | {unknown} unknown");
        toolTip.SetToolTip(actionLabel, $"{actionsNeeded} file(s) need action | {alerts} detections | {highRisk} high risk | {errors} errors");
        if (scanCancellation is not null || processMonitorScanRunning)
        {
            return;
        }

        if (actionsNeeded > 0)
        {
            SetDashboardState("Action needed", $"{actionsNeeded} file(s) still need review. {alerts} detection(s), {highRisk} high risk, {errors} errors.", true);
        }
        else if (results.Count > 0)
        {
            SetDashboardState("Clean", "No action needed.", false);
        }
    }

    private static bool ResultNeedsAction(ScanResult result)
    {
        return !ResultIsHandled(result)
            && (result.IsAlert
                || result.RiskScore >= 70
                || string.Equals(result.Status, "error", StringComparison.OrdinalIgnoreCase));
    }

    private static bool ResultIsHandled(ScanResult result)
    {
        return string.Equals(result.Status, "ignored", StringComparison.OrdinalIgnoreCase)
            || result.Notes.Contains("Detection ignored by user.", StringComparison.OrdinalIgnoreCase)
            || result.Notes.Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase);
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
                writer.WriteLine("timestamp_computer_time,status,risk_score,risk_level,trust,provider_results,malicious,suspicious,harmless,undetected,process_names,pids,sha256,path,link,notes");
            }

            writer.WriteLine(string.Join(",", new[]
            {
                Csv(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                Csv(result.Status),
                Csv(result.RiskScore.ToString()),
                Csv(result.RiskLevel),
                Csv(result.TrustSummary),
                Csv(result.ProviderSummary),
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
            Text = "Activity Log",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(1360, 760),
            MinimumSize = new Size(1160, 620),
            BackColor = Color.FromArgb(246, 247, 249),
        };

        var detailView = new ListView { View = View.Details, FullRowSelect = true, GridLines = false, HideSelection = false, BorderStyle = BorderStyle.FixedSingle };
        ConfigureResultsView(detailView);
        detailView.Columns[ColProcess].Width = 150;
        detailView.Columns[ColSha256].Width = 300;
        detailView.Columns[ColPath].Width = 360;
        detailView.Columns[ColNotes].Width = 300;
        FitResultColumns(detailView);
        detailView.Dock = DockStyle.Fill;
        var allItems = LoadActivityLogItems();

        var summaryLabel = new Label
        {
            Dock = DockStyle.Fill,
            Height = 28,
            Font = new Font("Segoe UI", 9, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
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
                    ? "No scan rows match the current filter."
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
            var visibleItems = allItems
                .Where(item => MatchesActivityFilter(filter, item))
                .Where(item => MatchesActivitySearch(item, searchText))
                .ToList();

            detailView.BeginUpdate();
            detailView.Items.Clear();
            foreach (var item in visibleItems)
            {
                detailView.Items.Add(CloneActivityItem(item));
            }

            detailView.EndUpdate();
            FitResultColumns(detailView);
            foreach (var button in filterButtons)
            {
                var selected = button.Tag is ActivityFilter current && current == filter;
                button.BackColor = selected ? palette.Text : palette.ButtonBack;
                button.ForeColor = selected ? palette.Surface : palette.Text;
            }

            summaryLabel.Text = BuildActivityLogSummary(visibleItems, allItems, searchText);
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

        searchBox.TextChanged += (_, _) => ApplyFilter(activeFilter);
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
        ApplyFilter(ActivityFilter.All);
        dialog.ShowDialog(this);
    }

    private static Button CreateActivityFilterButton(ActivityFilter filter)
    {
        return new Button
        {
            Text = filter switch
            {
                ActivityFilter.ActionNeeded => "Action Needed",
                ActivityFilter.Unknown => "Unknown",
                ActivityFilter.Clean => "Clean",
                ActivityFilter.Errors => "Errors",
                _ => "All",
            },
            Tag = filter,
            AutoSize = true,
            Height = 32,
            Margin = new Padding(0, 0, 8, 0),
            FlatStyle = FlatStyle.Flat,
        };
    }

    private static Button CreateActivityActionButton(string text)
    {
        return new Button
        {
            Text = text,
            Width = Math.Max(96, text.Length * 8 + 24),
            Height = 32,
            Margin = new Padding(0, 0, 8, 6),
            FlatStyle = FlatStyle.Flat,
        };
    }

    private static bool MatchesActivityFilter(ActivityFilter filter, ListViewItem item)
    {
        if (filter == ActivityFilter.ActionNeeded && IsHandledActivityItem(item))
        {
            return false;
        }

        var malicious = int.TryParse(GetSubItemText(item, ColMalicious), out var mal) ? mal : 0;
        var suspicious = int.TryParse(GetSubItemText(item, ColSuspicious), out var susp) ? susp : 0;
        return HashGuardLogic.MatchesActivityFilter(filter, item.Text, GetSubItemText(item, ColRisk), malicious, suspicious);
    }

    private static bool IsHandledActivityItem(ListViewItem item)
    {
        return string.Equals(item.Text, "ignored", StringComparison.OrdinalIgnoreCase)
            || GetSubItemText(item, ColNotes).StartsWith("Handled:", StringComparison.OrdinalIgnoreCase)
            || GetSubItemText(item, ColNotes).Contains("Detection ignored by user.", StringComparison.OrdinalIgnoreCase)
            || GetSubItemText(item, ColNotes).Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesActivitySearch(ListViewItem item, string searchText)
    {
        if (string.IsNullOrWhiteSpace(searchText))
        {
            return true;
        }

        return item.SubItems
            .Cast<ListViewItem.ListViewSubItem>()
            .Any(subItem => subItem.Text.Contains(searchText, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildActivityLogSummary(IReadOnlyCollection<ListViewItem> visibleItems, IReadOnlyCollection<ListViewItem> allItems, string searchText)
    {
        var actionNeeded = allItems.Count(item => MatchesActivityFilter(ActivityFilter.ActionNeeded, item));
        var unknown = allItems.Count(item => MatchesActivityFilter(ActivityFilter.Unknown, item));
        var errors = allItems.Count(item => MatchesActivityFilter(ActivityFilter.Errors, item));
        var filtered = visibleItems.Count == allItems.Count && string.IsNullOrWhiteSpace(searchText)
            ? $"{visibleItems.Count} rows"
            : $"{visibleItems.Count} of {allItems.Count} rows";
        var searchSuffix = string.IsNullOrWhiteSpace(searchText) ? "" : $" | Search: {searchText}";
        return $"{filtered} | Action needed: {actionNeeded} | Unknown: {unknown} | Errors: {errors}{searchSuffix}";
    }

    private static ListViewItem CloneActivityItem(ListViewItem source)
    {
        var clone = new ListViewItem(source.Text)
        {
            BackColor = source.BackColor,
            ForeColor = source.ForeColor,
            Tag = source.Tag,
        };

        for (var index = 1; index < source.SubItems.Count; index++)
        {
            clone.SubItems.Add(source.SubItems[index].Text);
        }

        return clone;
    }

    private static string BuildSelectedReasonSummary(ListView sourceView)
    {
        if (sourceView.SelectedItems.Count == 0)
        {
            return "Select a row to see why HashGuard flagged it and which action is safest.";
        }

        var item = sourceView.SelectedItems[0];
        return BuildReasonSummary(item);
    }

    private static string BuildReasonSummary(ListViewItem item)
    {
        var status = item.Text;
        var risk = GetSubItemText(item, ColRisk);
        var trust = GetSubItemText(item, ColTrust);
        var malicious = GetSubItemText(item, ColMalicious);
        var suspicious = GetSubItemText(item, ColSuspicious);
        var process = GetSubItemText(item, ColProcess);
        var path = GetSubItemText(item, ColPath);
        var notes = GetSubItemText(item, ColNotes);
        var reasons = new List<string>();

        if (int.TryParse(malicious, out var mal) && mal > 0)
        {
            reasons.Add($"{mal} malicious detection(s)");
        }

        if (int.TryParse(suspicious, out var susp) && susp > 0)
        {
            reasons.Add($"{susp} suspicious detection(s)");
        }

        if (risk.StartsWith("High", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("high local risk score");
        }

        if (string.Equals(status, "unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, "uploaded", StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, "limited access", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("cloud reputation is incomplete");
        }

        if (string.Equals(status, "error", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("one or more checks failed");
        }

        foreach (var note in notes.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (note.StartsWith("Risk:", StringComparison.OrdinalIgnoreCase)
                || note.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase)
                || note.Contains("quota", StringComparison.OrdinalIgnoreCase)
                || note.Contains("Quarantined", StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add(note.TrimEnd('.'));
            }
        }

        var reasonText = reasons.Count == 0 ? "No immediate action reason." : string.Join("; ", reasons.Distinct(StringComparer.OrdinalIgnoreCase));
        return $"Status: {status} | Risk: {risk} | Process: {process}{Environment.NewLine}Reason: {reasonText}{Environment.NewLine}Trust: {trust}{Environment.NewLine}Path: {path}";
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
        colorModeBox.SelectedIndex = ColorModeToIndex(appSettings.ColorMode, appSettings.UseSystemDefaultColors);
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
        appSettings.ColorMode = IndexToColorMode(colorModeBox.SelectedIndex);
        appSettings.UseSystemDefaultColors = appSettings.ColorMode == ColorModeSystem;
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
                var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(currentPath, Encoding.UTF8)) ?? new AppSettings();
                settings.TrustedPublishers ??= new AppSettings().TrustedPublishers;
                return settings;
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

    private static string GetQuarantineDirectory()
    {
        return Path.Combine(GetConfigDirectory(), QuarantineFolderName);
    }

    private static string GetQuarantineManifestPath()
    {
        return Path.Combine(GetConfigDirectory(), QuarantineManifestFileName);
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

    private void CopySelectedReportSummary(ListView sourceView)
    {
        if (sourceView.SelectedIndices.Count == 0)
        {
            MessageBox.Show(this, "Select one or more rows first.", "No row selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var summaries = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Take(10)
            .Select(BuildReasonSummary);
        Clipboard.SetText(string.Join($"{Environment.NewLine}{Environment.NewLine}", summaries));
        statusLabel.Text = "Selection summary copied to clipboard.";
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
            $"Terminate {selections.Count} selected process(es)? HashGuard will only kill a PID if its current executable path still matches the selected row. Unsaved work in those processes may be lost.{Environment.NewLine}{Environment.NewLine}{BuildSelectedActionSummary(sourceView)}",
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
            $"Move {paths.Count} selected file(s) to HashGuard quarantine? Running files may need their process killed first.{Environment.NewLine}{Environment.NewLine}{BuildSelectedActionSummary(sourceView)}",
            "Quarantine selected files",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var quarantineDir = GetQuarantineDirectory();
        Directory.CreateDirectory(quarantineDir);
        var manifest = LoadQuarantineManifest();
        var moved = 0;
        var failures = new List<string>();

        foreach (var path in paths)
        {
            try
            {
                var sha256 = sourceView.Items
                    .Cast<ListViewItem>()
                    .Where(item => string.Equals(GetSubItemText(item, ColPath), path, StringComparison.OrdinalIgnoreCase))
                    .Select(item => GetSubItemText(item, ColSha256))
                    .FirstOrDefault(hash => !string.IsNullOrWhiteSpace(hash)) ?? "";
                var notes = sourceView.Items
                    .Cast<ListViewItem>()
                    .Where(item => string.Equals(GetSubItemText(item, ColPath), path, StringComparison.OrdinalIgnoreCase))
                    .Select(item => GetSubItemText(item, ColNotes))
                    .FirstOrDefault() ?? "";
                var target = Path.Combine(
                    quarantineDir,
                    $"{Path.GetFileName(path)}.{DateTime.Now:yyyyMMddHHmmss}.quarantine");
                File.Move(path, target);
                manifest.Add(new QuarantineEntry
                {
                    OriginalPath = path,
                    QuarantinePath = target,
                    Sha256 = sha256,
                    Notes = notes,
                    QuarantinedAtUtc = DateTimeOffset.UtcNow,
                });
                moved++;
                AppendQuarantineLog("quarantine", path, target, "moved to quarantine");
                MarkRowsQuarantined(sourceView, path, target);
                MarkRowsQuarantined(resultsView, path, target);
                MarkResultsQuarantined(path, target);
            }
            catch (Exception ex)
            {
                AppendQuarantineLog("quarantine-failed", path, "", ex.Message);
                failures.Add($"{path}: {ex.Message}");
            }
        }

        SaveQuarantineManifest(manifest);
        statusLabel.Text = $"Quarantined {moved} file(s).";
        ReconcileReviewQueue(updateSummary: false);
        UpdateSummary();
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some files could not be quarantined", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void MarkResultsQuarantined(string originalPath, string quarantinePath)
    {
        foreach (var result in results.Where(result => string.Equals(result.Path, originalPath, StringComparison.OrdinalIgnoreCase)))
        {
            result.Notes = result.Notes.Contains("Quarantined to ", StringComparison.OrdinalIgnoreCase)
                ? result.Notes
                : string.IsNullOrWhiteSpace(result.Notes)
                    ? $"Quarantined to {quarantinePath}"
                    : $"{result.Notes}; Quarantined to {quarantinePath}";
        }
    }

    private static string BuildSelectedActionSummary(ListView sourceView)
    {
        var lines = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Take(5)
            .Select(item =>
            {
                var risk = GetSubItemText(item, ColRisk);
                var pids = GetSubItemText(item, ColPids);
                var path = GetSubItemText(item, ColPath);
                var process = GetSubItemText(item, ColProcess);
                var reason = BuildReasonSummary(item)
                    .Split(Environment.NewLine)
                    .FirstOrDefault(line => line.StartsWith("Reason:", StringComparison.OrdinalIgnoreCase)) ?? "Reason: not available";
                return $"{process} | PID {pids} | {risk}{Environment.NewLine}{path}{Environment.NewLine}{reason}";
            })
            .ToList();
        var remaining = sourceView.SelectedItems.Count - lines.Count;
        if (remaining > 0)
        {
            lines.Add($"+{remaining} more");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private void ShowQuarantineDialog()
    {
        var allManifestEntries = LoadQuarantineManifest();
        var staleEntries = allManifestEntries
            .Where(entry => !File.Exists(entry.QuarantinePath))
            .ToList();
        var manifest = allManifestEntries
            .Where(entry => File.Exists(entry.QuarantinePath))
            .OrderByDescending(entry => entry.QuarantinedAtUtc)
            .ToList();

        using var dialog = new Form
        {
            Text = "HashGuard Quarantine",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(980, 520),
            MinimumSize = new Size(760, 420),
            BackColor = Color.FromArgb(246, 247, 249),
        };

        var view = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, HideSelection = false, BorderStyle = BorderStyle.FixedSingle };
        view.Columns.Add("Quarantined", 150);
        view.Columns.Add("SHA-256", 300);
        view.Columns.Add("Original Path", 420);
        view.Columns.Add("Notes", 360);
        foreach (var entry in manifest)
        {
            var item = new ListViewItem(entry.QuarantinedAtUtc.LocalDateTime.ToString("g"));
            item.SubItems.Add(entry.Sha256);
            item.SubItems.Add(entry.OriginalPath);
            item.SubItems.Add(entry.Notes);
            item.Tag = entry;
            view.Items.Add(item);
        }

        var heading = new Label
        {
            Text = BuildQuarantineHeading(manifest.Count, staleEntries.Count),
            Dock = DockStyle.Fill,
            Height = 32,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.FromArgb(35, 35, 35),
        };
        var restore = new Button { Text = "Restore Selected", AutoSize = true };
        var restoreDesktop = new Button { Text = "Restore to Desktop", AutoSize = true };
        var delete = new Button { Text = "Delete Selected", AutoSize = true };
        var repairMissing = new Button { Text = "Repair Missing", AutoSize = true };
        var openFolder = new Button { Text = "Open Quarantine", AutoSize = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.OK };

        void RefreshQuarantineUi()
        {
            var remainingManifest = LoadQuarantineManifest();
            var staleCount = remainingManifest.Count(entry => !File.Exists(entry.QuarantinePath));
            SetQuarantineButtonsEnabled(view.Items.Count > 0, staleCount > 0, restore, restoreDesktop, delete, repairMissing);
            heading.Text = BuildQuarantineHeading(view.Items.Count, staleCount);
        }

        RefreshQuarantineUi();

        restore.Click += async (_, _) =>
        {
            SetQuarantineButtonsEnabled(false, repairMissing.Enabled, restore, restoreDesktop, delete, repairMissing);
            try
            {
                await RestoreSelectedQuarantineEntriesAsync(view, restoreToDesktop: false);
            }
            finally
            {
                RefreshQuarantineUi();
            }
        };
        restoreDesktop.Click += async (_, _) =>
        {
            SetQuarantineButtonsEnabled(false, repairMissing.Enabled, restore, restoreDesktop, delete, repairMissing);
            try
            {
                await RestoreSelectedQuarantineEntriesAsync(view, restoreToDesktop: true);
            }
            finally
            {
                RefreshQuarantineUi();
            }
        };
        delete.Click += (_, _) =>
        {
            DeleteSelectedQuarantineEntries(view);
            RefreshQuarantineUi();
        };
        repairMissing.Click += (_, _) =>
        {
            RepairMissingQuarantineEntries();
            RefreshQuarantineUi();
        };
        openFolder.Click += (_, _) =>
        {
            Directory.CreateDirectory(GetQuarantineDirectory());
            Process.Start(new ProcessStartInfo(GetQuarantineDirectory()) { UseShellExecute = true });
        };

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.Add(close);
        buttons.Controls.Add(openFolder);
        buttons.Controls.Add(repairMissing);
        buttons.Controls.Add(delete);
        buttons.Controls.Add(restoreDesktop);
        buttons.Controls.Add(restore);

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, Padding = new Padding(12) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(view, 0, 1);
        layout.Controls.Add(buttons, 0, 2);
        dialog.Controls.Add(layout);
        dialog.AcceptButton = close;
        ApplyAppTheme(dialog);
        dialog.ShowDialog(this);
    }

    private static string BuildQuarantineHeading(int restorableCount, int staleCount)
    {
        if (restorableCount == 0)
        {
            return staleCount == 0
                ? "No quarantined files"
                : $"No restorable files. {staleCount} stale manifest {PluralizeEntry(staleCount)} can be repaired.";
        }

        var staleText = staleCount == 0
            ? ""
            : $" {staleCount} stale manifest {PluralizeEntry(staleCount)} found.";
        return $"{restorableCount} quarantined file(s). Select entries to restore or delete.{staleText}";
    }

    private static string PluralizeEntry(int count)
    {
        return count == 1 ? "entry" : "entries";
    }

    private static void SetQuarantineButtonsEnabled(
        bool hasRestorableRows,
        bool hasStaleRows,
        Button restore,
        Button restoreDesktop,
        Button delete,
        Button repairMissing)
    {
        restore.Enabled = hasRestorableRows;
        restoreDesktop.Enabled = hasRestorableRows;
        delete.Enabled = hasRestorableRows;
        repairMissing.Enabled = hasStaleRows;
    }

    private async Task RestoreSelectedQuarantineEntriesAsync(ListView view, bool restoreToDesktop)
    {
        var entries = GetSelectedQuarantineEntries(view);
        if (entries.Count == 0)
        {
            MessageBox.Show(this, "Select one or more quarantined files first.", "No quarantine selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var restoreTargetText = restoreToDesktop ? "to your Desktop" : "to their original paths";
        var accepted = MessageBox.Show(this, $"Restore {entries.Count} quarantined file(s) {restoreTargetText}?", "Restore quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var manifest = LoadQuarantineManifest();
        var restored = 0;
        var restoredEntries = new List<QuarantineEntry>();
        var failures = new List<string>();
        foreach (var entry in entries)
        {
            try
            {
                if (!File.Exists(entry.QuarantinePath))
                {
                    throw new FileNotFoundException("Quarantined file no longer exists.", entry.QuarantinePath);
                }

                var restorePath = restoreToDesktop
                    ? GetDesktopRestorePath(entry)
                    : entry.OriginalPath;
                if (!restoreToDesktop && File.Exists(restorePath))
                {
                    var replaceExisting = MessageBox.Show(
                        this,
                        $"A file already exists at the original path. Replace it with the quarantined copy?{Environment.NewLine}{restorePath}",
                        "Restore quarantine",
                        MessageBoxButtons.YesNoCancel,
                        MessageBoxIcon.Warning);
                    if (replaceExisting == DialogResult.Cancel)
                    {
                        continue;
                    }

                    if (replaceExisting == DialogResult.No)
                    {
                        using var saveDialog = new SaveFileDialog
                        {
                            Title = "Restore quarantined file as",
                            FileName = Path.GetFileName(restorePath),
                            InitialDirectory = Directory.Exists(Path.GetDirectoryName(restorePath)) ? Path.GetDirectoryName(restorePath) : Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                        };
                        if (saveDialog.ShowDialog(this) != DialogResult.OK)
                        {
                            continue;
                        }

                        restorePath = saveDialog.FileName;
                    }
                }

                if (!string.IsNullOrWhiteSpace(entry.Sha256))
                {
                    statusLabel.Text = $"Verifying quarantined file: {Path.GetFileName(entry.QuarantinePath)}";
                    var quarantinedHash = await Sha256FileAsync(entry.QuarantinePath);
                    if (!string.Equals(quarantinedHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Quarantined file hash no longer matches the manifest.");
                    }
                }

                if (IsWindowsOrProgramFilesPath(restorePath))
                {
                    var sensitiveAccepted = MessageBox.Show(
                        this,
                        $"Restore into a protected system or Program Files location?{Environment.NewLine}{restorePath}",
                        "Confirm protected restore",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning);
                    if (sensitiveAccepted != DialogResult.Yes)
                    {
                        continue;
                    }
                }

                var restoreDirectory = Path.GetDirectoryName(restorePath);
                if (!string.IsNullOrWhiteSpace(restoreDirectory))
                {
                    Directory.CreateDirectory(restoreDirectory);
                }

                if (File.Exists(restorePath))
                {
                    File.Delete(restorePath);
                }

                File.Move(entry.QuarantinePath, restorePath);
                manifest.RemoveAll(item => string.Equals(item.QuarantinePath, entry.QuarantinePath, StringComparison.OrdinalIgnoreCase));
                restored++;
                restoredEntries.Add(entry);
                AppendQuarantineLog(restoreToDesktop ? "restore-desktop" : "restore", entry.QuarantinePath, restorePath, "restored from quarantine");
            }
            catch (Exception ex)
            {
                AppendQuarantineLog("restore-failed", entry.QuarantinePath, entry.OriginalPath, ex.Message);
                failures.Add($"{entry.OriginalPath}: {ex.Message}");
            }
        }

        SaveQuarantineManifest(manifest);
        statusLabel.Text = $"Restored {restored} quarantined file(s).";
        if (failures.Count > 0)
        {
            MessageBox.Show(this, string.Join(Environment.NewLine, failures.Take(8)), "Some files could not be restored", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        RemoveQuarantineRows(view, restoredEntries);
    }

    private static string GetDesktopRestorePath(QuarantineEntry entry)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktop))
        {
            desktop = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        var originalName = Path.GetFileName(entry.OriginalPath);
        if (string.IsNullOrWhiteSpace(originalName))
        {
            originalName = Path.GetFileNameWithoutExtension(entry.QuarantinePath);
        }

        foreach (var invalidChar in Path.GetInvalidFileNameChars())
        {
            originalName = originalName.Replace(invalidChar, '_');
        }

        if (string.IsNullOrWhiteSpace(originalName))
        {
            originalName = "HashGuard-Restored-File";
        }

        var candidate = Path.Combine(desktop, originalName);
        if (!File.Exists(candidate))
        {
            return candidate;
        }

        var name = Path.GetFileNameWithoutExtension(originalName);
        var extension = Path.GetExtension(originalName);
        for (var index = 1; index < 1000; index++)
        {
            candidate = Path.Combine(desktop, $"{name} ({index}){extension}");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }

        return Path.Combine(desktop, $"{name}-{DateTime.Now:yyyyMMddHHmmss}{extension}");
    }

    private void RepairMissingQuarantineEntries()
    {
        var manifest = LoadQuarantineManifest();
        var staleEntries = manifest
            .Where(entry => !File.Exists(entry.QuarantinePath))
            .ToList();
        if (staleEntries.Count == 0)
        {
            MessageBox.Show(this, "No missing quarantine entries were found.", "Repair quarantine", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(
            this,
            $"Remove {staleEntries.Count} stale manifest entr{(staleEntries.Count == 1 ? "y" : "ies")} for quarantined files that no longer exist?",
            "Repair quarantine",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        manifest.RemoveAll(entry => !File.Exists(entry.QuarantinePath));
        SaveQuarantineManifest(manifest);
        foreach (var entry in staleEntries)
        {
            AppendQuarantineLog("repair-missing", entry.QuarantinePath, entry.OriginalPath, "removed stale manifest entry");
        }

        statusLabel.Text = $"Removed {staleEntries.Count} stale quarantine entr{(staleEntries.Count == 1 ? "y" : "ies")}.";
    }

    private void DeleteSelectedQuarantineEntries(ListView view)
    {
        var entries = GetSelectedQuarantineEntries(view);
        if (entries.Count == 0)
        {
            MessageBox.Show(this, "Select one or more quarantined files first.", "No quarantine selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var accepted = MessageBox.Show(this, $"Permanently delete {entries.Count} quarantined file(s)?", "Delete quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var manifest = LoadQuarantineManifest();
        var deletedEntries = new List<QuarantineEntry>();
        foreach (var entry in entries)
        {
            try
            {
                if (File.Exists(entry.QuarantinePath))
                {
                    File.Delete(entry.QuarantinePath);
                }

                manifest.RemoveAll(item => string.Equals(item.QuarantinePath, entry.QuarantinePath, StringComparison.OrdinalIgnoreCase));
                deletedEntries.Add(entry);
                AppendQuarantineLog("delete", entry.QuarantinePath, entry.OriginalPath, "deleted from quarantine");
            }
            catch (Exception ex)
            {
                AppendQuarantineLog("delete-failed", entry.QuarantinePath, entry.OriginalPath, ex.Message);
                MessageBox.Show(this, ex.Message, "Delete quarantine failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        SaveQuarantineManifest(manifest);
        statusLabel.Text = "Selected quarantine entries deleted.";
        RemoveQuarantineRows(view, deletedEntries);
    }

    private static void RemoveQuarantineRows(ListView view, List<QuarantineEntry> entries)
    {
        var quarantinedPaths = entries
            .Select(entry => entry.QuarantinePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var item in view.Items.Cast<ListViewItem>().ToList())
        {
            if (item.Tag is QuarantineEntry entry && quarantinedPaths.Contains(entry.QuarantinePath))
            {
                view.Items.Remove(item);
            }
        }
    }

    private static List<QuarantineEntry> GetSelectedQuarantineEntries(ListView view)
    {
        return view.SelectedItems
            .Cast<ListViewItem>()
            .Select(item => item.Tag as QuarantineEntry)
            .Where(entry => entry is not null)
            .Cast<QuarantineEntry>()
            .ToList();
    }

    private static List<QuarantineEntry> LoadQuarantineManifest()
    {
        try
        {
            var path = GetQuarantineManifestPath();
            return File.Exists(path)
                ? JsonSerializer.Deserialize<List<QuarantineEntry>>(File.ReadAllText(path, Encoding.UTF8)) ?? []
                : [];
        }
        catch
        {
            return [];
        }
    }

    private static void SaveQuarantineManifest(List<QuarantineEntry> manifest)
    {
        Directory.CreateDirectory(GetConfigDirectory());
        File.WriteAllText(
            GetQuarantineManifestPath(),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);
    }

    private static void AppendQuarantineLog(string action, string sourcePath, string targetPath, string details)
    {
        try
        {
            var logDir = GetLogDirectory();
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, $"quarantine-log-{DateTime.Now:yyyyMMdd}.csv");
            var writeHeader = !File.Exists(logPath);
            using var writer = new StreamWriter(logPath, append: true, Encoding.UTF8);
            if (writeHeader)
            {
                writer.WriteLine("timestamp_computer_time,action,source_path,target_path,details");
            }

            writer.WriteLine(string.Join(",", new[]
            {
                Csv(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")),
                Csv(action),
                Csv(sourcePath),
                Csv(targetPath),
                Csv(details),
            }));
        }
        catch
        {
            // Quarantine logging must never block the quarantine action itself.
        }
    }

    private static void MarkRowsQuarantined(ListView view, string originalPath, string quarantinePath)
    {
        foreach (var item in view.Items.Cast<ListViewItem>().ToList())
        {
            if (!string.Equals(GetSubItemText(item, ColPath), originalPath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (view.Name == MainResultsViewName)
            {
                view.Items.Remove(item);
                continue;
            }

            var notes = GetSubItemText(item, ColNotes);
            item.SubItems[ColNotes].Text = string.IsNullOrWhiteSpace(notes)
                ? $"Quarantined to {quarantinePath}"
                : $"{notes}; Quarantined to {quarantinePath}";
            ApplyResultRowColor(item);
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
        ReconcileReviewQueue(updateSummary: false);
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
                if (ResultNeedsAction(result))
                {
                    AddReviewQueueRow(result);
                }
            }
        }

        SaveIgnoredHashes();
        ReconcileReviewQueue(updateSummary: false);
        UpdateSummary();
        statusLabel.Text = $"{hashes.Count} ignore flag(s) cleared.";
    }

    private static void MarkIgnoredRows(ListView view, string sha256)
    {
        foreach (var row in view.Items.Cast<ListViewItem>().ToList())
        {
            if (!string.Equals(GetSubItemText(row, ColSha256), sha256, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (view.Name == MainResultsViewName)
            {
                view.Items.Remove(row);
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
            row.SubItems[ColNotes].Text = view.Name == MainResultsViewName
                ? malicious + suspicious > 0
                    ? $"Review now: {malicious} malicious / {suspicious} suspicious detections"
                    : "No action needed"
                : RemoveIgnoreNote(GetSubItemText(row, ColNotes));
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
        var metaDefender = new Button { Text = "MetaDefender", Width = 150, Height = 34 };
        var mhr = new Button { Text = "Cymru", Width = 108, Height = 34 };
        var cancel = new Button { Text = "Cancel", Width = 92, Height = 34, DialogResult = DialogResult.Cancel };

        virusTotal.Click += (_, _) => OpenReportAndClose(dialog, string.Format(ReportUrl, sha256));
        metaDefender.Click += (_, _) => OpenReportAndClose(dialog, string.Format(MetaDefenderReportUrl, sha256));
        mhr.Click += (_, _) => OpenReportAndClose(dialog, string.Format(CymruDnsQueryUrl, Uri.EscapeDataString(BuildCymruQueryName(sha256))));

        toolTip.SetToolTip(virusTotal, "Open VirusTotal report");
        toolTip.SetToolTip(metaDefender, "Open MetaDefender report");
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
            "status,risk,trust,provider_results,malicious,suspicious,harmless,undetected,process_names,pids,sha256,path,link,notes",
        };
        foreach (ListViewItem item in sourceView.Items)
        {
            lines.Add(string.Join(",", new[]
            {
                Csv(GetSubItemText(item, 0)),
                Csv(GetSubItemText(item, ColRisk)),
                Csv(GetSubItemText(item, ColTrust)),
                Csv(""),
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
        return HashGuardLogic.ParseCsvLine(line);
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
    private sealed record SignatureInfo(string Summary, string Publisher);
    private sealed record ProviderResult(string Provider, ProviderState State, string Detail);
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
                VirusTotalDeferred = result.VirusTotalDeferred,
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

        public static bool IsReusablePendingEntry(CacheEntry entry)
        {
            return HashGuardLogic.CanReuseProviderCache(entry.Status, entry.VirusTotalDeferred, entry.CheckedAtUtc, DateTimeOffset.UtcNow);
        }

        private static string NormalizeCachedStatus(string status)
        {
            return string.Equals(status, "clean/seen", StringComparison.OrdinalIgnoreCase) ? "clean" : status;
        }

        private static List<string> ParseCsvLine(string line)
        {
            return HashGuardLogic.ParseCsvLine(line);
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
            if (sha256.Length != 64 || string.IsNullOrWhiteSpace(entry.Status))
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
        public bool VirusTotalDeferred { get; set; }
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
        public bool UseSystemDefaultColors { get; set; }
        public string ColorMode { get; set; } = ColorModeLight;
        public bool FirstRunSetupShown { get; set; }
        public int DelaySeconds { get; set; } = 16;
        public int TimeoutSeconds { get; set; } = 60;
        public string ApiKeyEncrypted { get; set; } = "";
        public string MetaDefenderApiKeyEncrypted { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public string MetaDefenderApiKey { get; set; } = "";
        public List<string> TrustedPublishers { get; set; } =
        [
            "Microsoft Corporation",
            "Microsoft Windows",
            "NVIDIA Corporation",
            "Advanced Micro Devices",
            "Intel Corporation",
            "Dell Inc.",
            "HP Inc.",
            "Lenovo",
        ];
    }

    private readonly record struct ThemePalette(
        Color AppBack,
        Color Surface,
        Color PillBack,
        Color InputBack,
        Color Text,
        Color MutedText,
        Color ButtonBack,
        Color Border,
        Color CalloutBack,
        Color HeaderBack,
        Color HeaderButtonBack,
        Color HeaderButtonBorder)
    {
        public static ThemePalette Light { get; } = new(
            Color.FromArgb(246, 247, 249),
            Color.White,
            Color.FromArgb(246, 247, 249),
            Color.White,
            Color.FromArgb(35, 35, 35),
            Color.DimGray,
            SystemColors.Control,
            Color.FromArgb(218, 222, 228),
            Color.FromArgb(250, 251, 253),
            Color.FromArgb(28, 28, 28),
            Color.FromArgb(52, 52, 52),
            Color.FromArgb(85, 85, 85));

        public static ThemePalette Dark { get; } = new(
            Color.FromArgb(24, 26, 30),
            Color.FromArgb(34, 37, 43),
            Color.FromArgb(44, 48, 55),
            Color.FromArgb(25, 28, 33),
            Color.FromArgb(235, 238, 242),
            Color.FromArgb(170, 176, 186),
            Color.FromArgb(50, 55, 64),
            Color.FromArgb(72, 78, 88),
            Color.FromArgb(40, 44, 52),
            Color.FromArgb(18, 20, 24),
            Color.FromArgb(44, 48, 56),
            Color.FromArgb(76, 82, 92));
    }

    private sealed class QuarantineEntry
    {
        public string OriginalPath { get; set; } = "";
        public string QuarantinePath { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Notes { get; set; } = "";
        public DateTimeOffset QuarantinedAtUtc { get; set; }
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
        public List<ProviderResult> ProviderResults { get; } = [];
        public string ProviderSummary => ProviderResults.Count == 0
            ? ""
            : string.Join(" | ", ProviderResults.Select(result => $"{result.Provider}: {result.State}{(string.IsNullOrWhiteSpace(result.Detail) ? "" : $" ({result.Detail})")}"));
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "Low";
        public string TrustSummary { get; set; } = "";
        public string SignatureSummary { get; set; } = "";
        public string SignaturePublisher { get; set; } = "";
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
            VirusTotalDeferred = entry.VirusTotalDeferred;
            Notes = $"{prefix} {entry.CheckedAtUtc.LocalDateTime:g}";
            if (!string.IsNullOrWhiteSpace(entry.Notes))
            {
                Notes += $"; {entry.Notes}";
            }
        }
    }
}
