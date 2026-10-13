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
    internal const string ScanPipeName = AppPaths.ScanPipeName;

    private static readonly string CurrentVersion = AppConstants.GetCurrentVersion();

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

    // Webroot-inspired SecureAnywhere palette (brand green primary, calm neutrals).
    private static readonly Color BrandGreen = Color.FromArgb(125, 204, 38);      // #7DCC26 Webroot green
    private static readonly Color BrandGreenDark = Color.FromArgb(90, 160, 20);
    private static readonly Color AccentGold = BrandGreen; // primary CTA uses brand green
    private static readonly Color SuccessGreen = Color.FromArgb(76, 175, 40);
    private static readonly Color AttentionYellow = Color.FromArgb(255, 193, 7);
    private static readonly Color DangerRed = Color.FromArgb(211, 47, 47);
    private static readonly Color SoftBorder = Color.FromArgb(214, 219, 225);
    private static readonly Color SoftAppBack = Color.FromArgb(242, 243, 245);

    private readonly TextBox apiKeyBox = new() { UseSystemPasswordChar = true };
    private readonly TextBox metaDefenderApiKeyBox = new() { UseSystemPasswordChar = true };
    private readonly Button scanButton = new() { Text = "Scan Now", Width = 128, Height = 36, BackColor = BrandGreen, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Regular) };
    private readonly Button updateButton = new() { Text = "Check for Updates", Width = 140, Height = 36, Font = new Font("Segoe UI", 9, FontStyle.Regular) };
    private readonly Button settingsButton = new() { Text = "\uE713", Width = 36, Height = 36, Font = new Font("Segoe MDL2 Assets", 11, FontStyle.Regular) };
    private readonly CheckBox freeApiLimitBox = new() { Text = "Free API limits (4/min, 500/day)", AutoSize = true, Checked = true };
    private readonly CheckBox rightClickScanBox = new() { Text = "Add Explorer right-click scan", AutoSize = true };
    private readonly CheckBox startWithWindowsBox = new() { Text = "Start with Windows", AutoSize = true };
    private readonly CheckBox startMinimizedBox = new() { Text = "Start minimized to tray", AutoSize = true };
    private readonly CheckBox autoProcessScanBox = new() { Text = "Scan automatically at startup", AutoSize = true, Checked = true };
    private readonly CheckBox runElevatedBox = new() { Text = "Run Elevated (Windows UAC permissions)", AutoSize = true };
    private readonly CheckBox scanAllFilesBox = new() { Text = "Scan files I open or select", AutoSize = true };
    private readonly ComboBox colorModeBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 };
    private readonly CheckBox uploadUnknownBox = new() { Text = "Allow VirusTotal uploads (approve each file in Review Queue)", AutoSize = true };
    private readonly CheckBox virusTotalEnabledBox = new() { Text = "Use VirusTotal", AutoSize = true, Checked = true };
    private readonly CheckBox metaDefenderEnabledBox = new() { Text = "Use MetaDefender Cloud", AutoSize = true, Checked = true };
    private readonly CheckBox mhrEnabledBox = new() { Text = "Use Team Cymru MHR", AutoSize = true, Checked = true };
    private readonly CheckBox hashCacheEnabledBox = new() { Text = "Enable Hash Cache", AutoSize = true, Checked = true };
    private readonly CheckBox deltaScanBox = new() { Text = "Delta scan: reuse cached hash for unchanged files", AutoSize = true };
    private readonly CheckBox autoUpdateChecksBox = new() { Text = "Check updates automatically", AutoSize = true };
    private readonly CheckBox telemetryEnabledBox = new() { Text = "Send anonymous usage data", AutoSize = true, Checked = false };
    private readonly NumericUpDown delayBox = new() { Minimum = 0, Maximum = 120, Value = 16, Width = 64 };
    private readonly NumericUpDown timeoutBox = new() { Minimum = 10, Maximum = 300, Value = 60, Width = 64 };
    private readonly ListView resultsView = new() { View = View.Details, FullRowSelect = true, GridLines = false, HideSelection = false, BorderStyle = BorderStyle.FixedSingle };
    private readonly Label resultsEmptyLabel = new()
    {
        Text = "No items need review. Unknown VirusTotal hashes appear here so you can approve an upload.",
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleCenter,
        ForeColor = Color.DimGray,
        Font = new Font("Segoe UI", 10, FontStyle.Regular),
    };
    private readonly ProgressBar progressBar = new();
    private readonly Label statusLabel = new() { AutoEllipsis = false };
    private readonly Label countLabel = new() { AutoSize = true };
    private readonly Panel statusDot = new() { Width = 92, Height = 92, Margin = new Padding(0, 0, 0, 10), Tag = "idle" };
    private readonly Label statusTitle = new() { Text = "Not scanned yet", AutoSize = true, Font = new Font("Segoe UI Semibold", 19, FontStyle.Regular), TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label statusSubtitle = new() { Text = "Run a scan to check running apps and local trust signals.", AutoSize = true, ForeColor = Color.DimGray, TextAlign = ContentAlignment.MiddleCenter };
    private readonly PillLabel summaryLabel = new() { Text = "Items scanned: 0", AutoSize = false, Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular), TextAlign = ContentAlignment.MiddleLeft };
    private readonly PillLabel actionLabel = new() { Text = "Needs review: 0", AutoSize = false, Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular), TextAlign = ContentAlignment.MiddleLeft };
    private readonly PillLabel reviewCountLabel = new() { Text = "0", AutoSize = true, Font = new Font("Segoe UI Semibold", 8.5f, FontStyle.Regular), TextAlign = ContentAlignment.MiddleCenter, Padding = new Padding(8, 2, 8, 2), Radius = 10 };
    private readonly Label reputationStateLabel = new();
    private readonly Label reputationProtectionLabel = new();
    private readonly Label quarantineCountLabel = new();
    private readonly Label quarantineStateLabel = new();
    private readonly NotifyIcon trayIcon = new();
    private readonly ToolTip toolTip = new();
    private readonly Icon cleanTrayIcon;
    private readonly Icon scanningTrayIcon;
    private readonly Icon actionTrayIcon;
    private readonly List<ScanResult> results = [];
    private readonly HashCache hashCache = new();
    private readonly QuotaTracker quotaTracker = new();
    private readonly HashSet<string> ignoredHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> ignoredPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ProcessFileState> monitoredProcessFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> allFileScanQueue = new();
    private readonly HashSet<string> queuedAllFileScanPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> allFileWatchers = [];
    private readonly Dictionary<string, ProcessFileState> userTouchedFileScanStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly object allFileScanLock = new();
    private readonly ScanGate scanGate = new();
    private readonly System.Windows.Forms.Timer processMonitorTimer = new() { Interval = 5000 };
    private readonly System.Windows.Forms.Timer updateCheckTimer = new() { Interval = 60000 };
    private readonly System.Windows.Forms.Timer allFileScanTimer = new() { Interval = 15000 };
    private readonly System.Windows.Forms.Timer telemetryHeartbeatTimer = new() { Interval = 300000 };
    private readonly string? startupScanFile;
    private readonly bool startupMinimized;
    private readonly int closedOlderInstances;
    private AppSettings appSettings = new();
    private CancellationTokenSource? scanCancellation;
    private readonly CancellationTokenSource scanPipeCancellation = new();
    private bool trayRunningNotificationShown;
    private bool uploadWarningShown;
    private bool scanAllFilesWarningShown;
    private bool exitRequested;
    private bool suppressSettingEvents;
    private bool updateCheckRunning;
    private bool processBaselineReady;
    private string lastAutoPromptedUpdateVersion = "";
    private string lastSkippedProcessLogSignature = "";
    private bool batchScanUi;
    private bool reviewQueueBusy;
    private Button? approveUploadButton;
    private int scanUiDirty;
    private DateTime scanUiLastFlushUtc;
    private const int ScanUiFlushEvery = 12;
    private static readonly TimeSpan ScanUiFlushInterval = TimeSpan.FromMilliseconds(150);
    private const int MaxAllFileScanQueueSize = 200;
    private readonly SemaphoreSlim virusTotalLaneGate = new(1, 1);
    private DateTimeOffset nextVirusTotalRequestUtc = DateTimeOffset.MinValue;
    private readonly ScanRequestQueue explorerScanRequests = new();
    private bool explorerScanDrainRunning;
    private static readonly TimeSpan ExplorerBurstCollectDelay = TimeSpan.FromMilliseconds(300);
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
        LoadIgnoredPaths();
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
        telemetryHeartbeatTimer.Tick += (_, _) => _ = SendTelemetryEventAsync("app_ping");
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
        telemetryEnabledBox.CheckedChanged += (_, _) => SaveCurrentAppSettings();
        Resize += (_, _) => MinimizeToTrayIfNeeded();
        FormClosing += (_, e) => CloseToTrayUnlessExiting(e);
        FormClosed += (_, _) =>
        {
            scanPipeCancellation.Cancel();
            telemetryHeartbeatTimer.Stop();
            StopAllFileWatchers();
        };
        Shown += async (_, _) =>
        {
            _ = InitializeTelemetryAsync();
            ShowFirstRunSetupIfNeeded();
            if (AppPaths.UsingFallbackStorage)
            {
                statusLabel.Text = $"The app folder is read-only, so settings and logs are saved in {AppPaths.GetConfigRoot()}.";
            }

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

    private void SetScanButtonReadyStyle()
    {
        scanButton.Text = "Scan Now";
        scanButton.BackColor = BrandGreen;
        scanButton.ForeColor = Color.FromArgb(20, 40, 10);
        scanButton.FlatAppearance.BorderSize = 0;
        scanButton.FlatAppearance.BorderColor = BrandGreenDark;
        scanButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(116, 192, 34);
        scanButton.FlatAppearance.MouseDownBackColor = Color.FromArgb(104, 176, 30);
        scanButton.FlatStyle = FlatStyle.Flat;
    }

    private void SetScanButtonStopStyle()
    {
        // Stopping is not destructive, so it is a quiet outline button rather than red.
        scanButton.Text = "Stop Scan";
        scanButton.BackColor = activePalette.HeaderButtonBack;
        scanButton.ForeColor = activePalette.Text;
        scanButton.FlatAppearance.BorderSize = 1;
        scanButton.FlatAppearance.BorderColor = activePalette.HeaderButtonBorder;
        scanButton.FlatAppearance.MouseOverBackColor = activePalette.SurfaceHover;
        scanButton.FlatAppearance.MouseDownBackColor = activePalette.SurfacePressed;
    }

    private void SetDashboardState(string title, string subtitle, bool actionNeeded)
    {
        var scanning = title.Contains("Scanning", StringComparison.OrdinalIgnoreCase);
        var stopped = title.Contains("Stopped", StringComparison.OrdinalIgnoreCase);
        // Webroot-style status copy: green = secure, yellow = attention, red = critical.
        statusTitle.Text = actionNeeded
            ? "Attention needed"
            : scanning
                ? "Scanning"
                : stopped
                    ? "Scan stopped"
                    : "Your device is secure";
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
            trayIcon.Text = "HashGuard - Secure";
        }
    }

    private void IgnoreSelectedPublisher(ListView sourceView)
    {
        if (sourceView.SelectedItems.Count == 0)
        {
            MessageBox.Show(this, "Select a signed file row first.", "No file selected", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var publishers = sourceView.SelectedItems
            .Cast<ListViewItem>()
            .Select(FindResultForReviewQueueRow)
            .Where(result => result is not null)
            .Select(result => result!.SignaturePublisher)
            .Where(publisher => !string.IsNullOrWhiteSpace(publisher))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (publishers.Count == 0)
        {
            MessageBox.Show(this, "The selected row has no Authenticode publisher to ignore.", "No publisher", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var publisher = publishers[0];
        var accepted = MessageBox.Show(
            this,
            $"Ignore all currently listed review-queue files signed by:{Environment.NewLine}{publisher}{Environment.NewLine}{Environment.NewLine}This adds matching hashes/paths to the ignore list.",
            "Ignore publisher",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);
        if (accepted != DialogResult.Yes)
        {
            return;
        }

        var matched = results
            .Where(result => HashGuardLogic.PublisherMatchesForIgnore(result.SignaturePublisher, publisher))
            .ToList();
        if (matched.Count == 0)
        {
            MessageBox.Show(this, "No matching signed files were found in the current scan.", "Ignore publisher", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        foreach (var result in matched)
        {
            if (!string.IsNullOrWhiteSpace(result.Sha256))
            {
                ignoredHashes.Add(result.Sha256);
            }
            else if (!string.IsNullOrWhiteSpace(result.Path))
            {
                ignoredPaths.Add(result.Path);
            }

            result.StatusBeforeIgnore = string.IsNullOrWhiteSpace(result.StatusBeforeIgnore) ? result.Status : result.StatusBeforeIgnore;
            result.Status = "ignored";
            if (!HashGuardLogic.HasIgnoreNote(result.Notes))
            {
                AppendResultNote(result, "File hash ignored by user.");
            }
        }

        SaveIgnoredHashes();
        SaveIgnoredPaths();
        ReconcileReviewQueue();
        UpdateSummary();
        statusLabel.Text = $"Ignored {matched.Count} file(s) from publisher {publisher}.";
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
}
