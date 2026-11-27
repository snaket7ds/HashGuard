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
    private void ShowSettingsDialog()
    {
        RestoreFromTray();
        ShowPage(AppPage.Settings);
    }

    /// <summary>The Settings page (was the Settings window before v1.1.0). Save applies; Discard rebuilds it.</summary>
    private Control BuildSettingsView()
    {
        var dialog = new Panel { Dock = DockStyle.Fill, BackColor = SoftAppBack };
        var pendingTrusted = appSettings.TrustedPublishers.ToList();

        var vtEnabled = new ToggleSwitch { Text = "Enable VirusTotal", Checked = virusTotalEnabledBox.Checked, AutoSize = true };
        var mdEnabled = new ToggleSwitch { Text = "Enable MetaDefender Cloud", Checked = metaDefenderEnabledBox.Checked, AutoSize = true };
        var mhrEnabled = new ToggleSwitch { Text = "Enable Team Cymru MHR", Checked = mhrEnabledBox.Checked, AutoSize = true };
        var apiKey = new TextBox { UseSystemPasswordChar = true, Text = apiKeyBox.Text, Dock = DockStyle.Fill };
        var metaDefenderApiKey = new TextBox { UseSystemPasswordChar = true, Text = metaDefenderApiKeyBox.Text, Dock = DockStyle.Fill };
        var freeLimit = new ToggleSwitch { Text = "Free API limits (4/min, 500/day)", Checked = freeApiLimitBox.Checked, AutoSize = true };
        var rightClickScan = new ToggleSwitch { Text = "Add Explorer right-click scan", Checked = rightClickScanBox.Checked, AutoSize = true };
        var startWithWindows = new ToggleSwitch { Text = "Start with Windows", Checked = startWithWindowsBox.Checked, AutoSize = true };
        var startMinimized = new ToggleSwitch { Text = "Start minimized to tray", Checked = startMinimizedBox.Checked, AutoSize = true };
        var colorMode = new DropdownField { Width = 200 };
        colorMode.Items.AddRange(["Use Windows setting", "Light", "Dark"]);
        colorMode.SelectedIndex = Math.Clamp(colorModeBox.SelectedIndex, 0, colorMode.Items.Count - 1);
        var autoProcessScan = new ToggleSwitch { Text = "Scan automatically at startup", Checked = autoProcessScanBox.Checked, AutoSize = true };
        var runElevated = new ToggleSwitch { Text = "Run elevated", Checked = runElevatedBox.Checked, AutoSize = true };
        var scanAllFiles = new ToggleSwitch { Text = "Scan files I open or select", Checked = scanAllFilesBox.Checked, AutoSize = true };
        var scheduledDaily = new ToggleSwitch { Text = "Daily scan of running apps (catches up if the PC was off)", Checked = appSettings.ScheduledDailyScan, AutoSize = true };
        var scheduledHour = new NumericUpDown { Minimum = 0, Maximum = 23, Value = Math.Clamp(appSettings.ScheduledScanHour, 0, 23), Width = 70 };
        var preferDelta = new ToggleSwitch { Text = "Highlight new files since last scan", Checked = appSettings.PreferDeltaScan, AutoSize = true };
        var deltaScan = new ToggleSwitch { Text = "Reuse cached hash for unchanged files (delta scan)", Checked = appSettings.DeltaScanEnabled, AutoSize = true };
        var suppressTray = new ToggleSwitch { Text = "Suppress repeat tray alerts for same detections", Checked = appSettings.SuppressRepeatTrayAlerts, AutoSize = true };
        var autoUpdates = new ToggleSwitch { Text = "Check updates automatically", Checked = autoUpdateChecksBox.Checked, AutoSize = true };
        var telemetryEnabled = new ToggleSwitch { Text = "Send anonymous usage data", Checked = telemetryEnabledBox.Checked, AutoSize = true };
        var hashCache = new ToggleSwitch { Text = "Enable Hash Cache", Checked = hashCacheEnabledBox.Checked, AutoSize = true };
        var uploadUnknown = new ToggleSwitch { Text = "Allow VirusTotal uploads (approve each file in Review Queue)", Checked = uploadUnknownBox.Checked, AutoSize = true };
        var networkMonitor = new ToggleSwitch { Text = "Watch network connections in the background (needed for alerts and auto-block)", Checked = appSettings.NetworkMonitorEnabled, AutoSize = true };
        var networkNotify = new DropdownField { Width = 360 };
        networkNotify.Items.AddRange(["When an untrusted app connects for the first time", "When any app connects for the first time", "Never"]);
        networkNotify.SelectedIndex = NetworkNotifyModes.Normalize(appSettings.NetworkNotifyMode) switch
        {
            NetworkNotifyModes.NewApps => 1,
            NetworkNotifyModes.Never => 2,
            _ => 0,
        };
        var autoBlockMalicious = new ToggleSwitch { Text = "Automatically block apps HashGuard flags as malicious (needs Run elevated)", Checked = appSettings.AutoBlockMalicious, AutoSize = true };
        var networkInfo = new Label
        {
            Text = "Open the Firewall page from the sidebar to see which apps connect where. Blocking adds Windows Firewall rules in the \"HashGuard\" group; HashGuard never changes your other firewall rules.",
            Dock = DockStyle.Top,
            Height = 52,
            ForeColor = Color.DimGray,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        var delay = new NumericUpDown { Minimum = 0, Maximum = 120, Value = delayBox.Value, Width = 70 };
        var timeout = new NumericUpDown { Minimum = 10, Maximum = 300, Value = timeoutBox.Value, Width = 70 };
        var ok = new Button { Text = "Save", Width = 104, Height = 38, FlatStyle = FlatStyle.Flat, Tag = "primary-button" };
        var cancel = new Button { Text = "Discard", Width = 104, Height = 38, FlatStyle = FlatStyle.Flat };
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
        // One row as designed ("HashGuard 1.1.3 · …  [Check for updates]"); the details are its tooltip.
        var versionRowLabel = $"HashGuard {CurrentVersion}";
        SettingRowHelp[versionRowLabel] = AppPaths.UsingFallbackStorage
            ? $"Settings and logs in {AppPaths.GetConfigRoot()}"
            : "Signed releases from GitHub";
        toolTip.SetToolTip(updateButton, BuildVersionAndUpdateInfo());

        // Tabs + footer only (no large header strip — frees vertical space for Behavior/Version content).
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(0), BackColor = SoftAppBack };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        dialog.Controls.Add(root);

        var tabs = new SegmentTabs { Dock = DockStyle.Fill, Margin = new Padding(0) };
        root.Controls.Add(tabs, 0, 0);

        var reputationPage = CreateSettingsPage(
            ("Reputation Providers", [vtEnabled, mdEnabled, mhrEnabled, freeLimit, uploadUnknown]),
            ("API Keys", [CreateSettingRow("VirusTotal API key", apiKey), CreateSettingRow("MetaDefender API key", metaDefenderApiKey)]),
            ("Request Timing", [CreateSettingRow("VirusTotal delay per request", delay), CreateSettingRow("Request timeout", timeout)]),
            ("Provider Status", [reputationValidation]));

        var behaviorPage = CreateSettingsPage(
            ("Windows", [runElevated, startWithWindows, startMinimized, rightClickScan, suppressTray, CreateSettingRow("Appearance", colorMode)]),
            ("Updates and privacy", [autoUpdates, CreateSettingRow(versionRowLabel, updateButton), telemetryEnabled]));
        // Stored & ignored hashes (the original app's lists, back as buttons).
        var viewStored = new Button { Text = "View…", Size = new Size(110, 36) };
        var viewIgnored = new Button { Text = "View…", Size = new Size(110, 36) };
        viewStored.Click += (_, _) => ShowHashLists(ignoredTab: false);
        viewIgnored.Click += (_, _) => ShowHashLists(ignoredTab: true);
        var antivirusPage = CreateSettingsPage(
            ("Scans", [autoProcessScan, scheduledDaily, CreateSettingRow("Daily scan hour (0-23)", scheduledHour), scanAllFiles]),
            ("Speed", [hashCache, deltaScan, preferDelta]),
            ("Hashes", [CreateSettingRow("Stored hashes", viewStored), CreateSettingRow("Ignored files", viewIgnored)]));
        AddSettingsTab(tabs, "Behavior", behaviorPage);
        AddSettingsTab(tabs, "Reputation", reputationPage);
        AddSettingsTab(tabs, "Antivirus", antivirusPage);

        var removeRules = new Button { Text = "Remove all…", AutoSize = true, Height = 34, Tag = "danger-button" };
        removeRules.Click += (_, _) => RemoveAllNetworkRules(this);
        var networkPage = CreateSettingsPage(
            ("Firewall", [networkMonitor, CreateSettingRow("New-app alerts", networkNotify), autoBlockMalicious, CreateSettingRow("HashGuard firewall rules", removeRules), networkInfo]));
        AddSettingsTab(tabs, "Firewall", networkPage);

        var trustPage = BuildTrustEditor(pendingTrusted);
        AddSettingsTab(tabs, "Trust", trustPage);

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Padding = new Padding(0, 8, 0, 4),
            BackColor = SoftAppBack,
        };
        ok.BackColor = BrandGreen;
        ok.ForeColor = Color.FromArgb(20, 40, 10);
        ok.FlatAppearance.BorderColor = BrandGreenDark;
        ok.FlatAppearance.BorderSize = 0;
        cancel.FlatAppearance.BorderSize = 1;
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);
        root.Controls.Add(buttons, 0, 1);

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

        var confirmingUpload = false;
        void OnUploadUnknownChanged(object? sender, EventArgs args)
        {
            RefreshValidation();
            if (!uploadUnknown.Checked || confirmingUpload)
            {
                return;
            }

            confirmingUpload = true;
            try
            {
                if (!EnableVirusTotalUploadsWithWarning())
                {
                    uploadUnknown.Checked = false;
                }
            }
            finally
            {
                confirmingUpload = false;
            }
        }

        foreach (var checkBox in new[] { vtEnabled, mdEnabled, mhrEnabled, scanAllFiles })
        {
            checkBox.CheckedChanged += (_, _) => RefreshValidation();
        }

        uploadUnknown.CheckedChanged += OnUploadUnknownChanged;
        apiKey.TextChanged += (_, _) => RefreshValidation();
        metaDefenderApiKey.TextChanged += (_, _) => RefreshValidation();
        RefreshValidation();

        ok.Click += (_, _) => Apply();
        cancel.Click += (_, _) =>
        {
            ShowPage(AppPage.Settings);
            statusLabel.Text = "Settings changes discarded.";
        };
        return dialog;

        void Apply()
        {

        apiKeyBox.Text = apiKey.Text.Trim();
        metaDefenderApiKeyBox.Text = metaDefenderApiKey.Text.Trim();
        delayBox.Value = delay.Value;
        timeoutBox.Value = timeout.Value;
        virusTotalEnabledBox.Checked = vtEnabled.Checked;
        metaDefenderEnabledBox.Checked = mdEnabled.Checked;
        mhrEnabledBox.Checked = mhrEnabled.Checked;
        freeApiLimitBox.Checked = freeLimit.Checked;

        var enableScanAllFiles = scanAllFiles.Checked;
        if (enableScanAllFiles && !scanAllFilesBox.Checked && !EnableAllFileScanningWithWarning())
        {
            enableScanAllFiles = false;
        }

        var startupWasInstalled = startWithWindowsBox.Checked;
        var runElevatedWasOn = runElevatedBox.Checked;
        suppressSettingEvents = true;
        try
        {
            uploadUnknownBox.Checked = uploadUnknown.Checked;
            hashCacheEnabledBox.Checked = hashCache.Checked;
            deltaScanBox.Checked = deltaScan.Checked;
            rightClickScanBox.Checked = rightClickScan.Checked;
            startWithWindowsBox.Checked = startWithWindows.Checked;
            startMinimizedBox.Checked = startMinimized.Checked;
            colorModeBox.SelectedIndex = colorMode.SelectedIndex;
            autoProcessScanBox.Checked = autoProcessScan.Checked;
            runElevatedBox.Checked = runElevated.Checked;
            scanAllFilesBox.Checked = enableScanAllFiles;
        }
        finally
        {
            suppressSettingEvents = false;
        }

        // The boxes above were set with change events suppressed, so apply startup here. Before
        // v1.0.73 the dialog never wrote it: ticking "Start with Windows" in Settings did nothing.
        if (startWithWindows.Checked != startupWasInstalled || runElevated.Checked != runElevatedWasOn)
        {
            try
            {
                ApplyStartWithWindows();
            }
            catch (Exception ex)
            {
                suppressSettingEvents = true;
                startWithWindowsBox.Checked = IsStartWithWindowsInstalled();
                suppressSettingEvents = false;
                MessageBox.Show(this, $"Could not update Windows startup:{Environment.NewLine}{ex.Message}", "Startup setting failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        autoUpdateChecksBox.Checked = autoUpdates.Checked;
        telemetryEnabledBox.Checked = telemetryEnabled.Checked;
        appSettings.NetworkMonitorEnabled = networkMonitor.Checked;
        appSettings.NetworkNotifyMode = networkNotify.SelectedIndex switch
        {
            1 => NetworkNotifyModes.NewApps,
            2 => NetworkNotifyModes.Never,
            _ => NetworkNotifyModes.Untrusted,
        };
        appSettings.AutoBlockMalicious = autoBlockMalicious.Checked;
        appSettings.ScheduledDailyScan = scheduledDaily.Checked;
        appSettings.ScheduledScanHour = (int)scheduledHour.Value;
        appSettings.PreferDeltaScan = preferDelta.Checked;
        appSettings.DeltaScanEnabled = deltaScan.Checked;
        appSettings.SuppressRepeatTrayAlerts = suppressTray.Checked;
        appSettings.TrustedPublishers = pendingTrusted
            .Select(HashGuardLogic.NormalizePublisher)
            .Where(line => line.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(line => line, StringComparer.OrdinalIgnoreCase)
            .ToList();
        UpdateReputationTile();
        UpdateQuarantineTile();
        UpdateAutomaticUpdateTimer();
        UpdateAllFileScanner();
        SaveCurrentAppSettings();
        UpdateNetworkTimer();
        try
        {
            ScheduledScan.Apply(appSettings.ScheduledDailyScan, appSettings.ScheduledScanHour, Application.ExecutablePath, appSettings.RunElevated && IsRunningElevated());
        }
        catch
        {
            // Scheduled task registration is best-effort.
        }
        ApplyAppTheme(this);
        UpdateHomePage();
        statusLabel.Text = "Settings saved.";
        }
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
            notes.Add("Open/selected file scanning never uploads full files. Scan Now and right-click still upload unknown hashes.");
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
            AppPaths.UsingFallbackStorage
                ? $"Settings and logs: {AppPaths.GetConfigRoot()} (the app folder is read-only)"
                : "Settings and logs: next to HashGuard.exe",
            "Use Update to check GitHub release notes and install a verified HashGuard.exe asset.",
        });
    }

    private async Task InitializeTelemetryAsync()
    {
        if (!appSettings.TelemetryEnabled || string.IsNullOrWhiteSpace(AppConstants.TelemetryEndpointUrl))
        {
            telemetryHeartbeatTimer.Stop();
            return;
        }

        if (string.IsNullOrWhiteSpace(appSettings.AnonymousInstallId))
        {
            appSettings.AnonymousInstallId = Guid.NewGuid().ToString("N");
            SaveCurrentAppSettings();
        }

        if (!appSettings.AppInstallReported)
        {
            if (await SendTelemetryEventAsync("app_install"))
            {
                appSettings.AppInstallReported = true;
                SaveCurrentAppSettings();
            }
        }

        // Always announce presence when init runs (startup, or Settings toggle on).
        _ = SendTelemetryEventAsync("app_start");
        if (!telemetryHeartbeatTimer.Enabled)
        {
            telemetryHeartbeatTimer.Start();
        }
    }

    /// <summary>Counts for the heartbeat: the same numbers as the Firewall page's stat cards.</summary>
    private Dictionary<string, object> BuildFirewallSnapshotTelemetry()
    {
        var monitoring = appSettings.NetworkMonitorEnabled && networkTracker is not null;
        var online = networkTracker?.Apps.Count(app => app.CurrentConnections > 0 && !networkBlockedPaths.Contains(app.Path)) ?? 0;
        return HashGuardLogic.BuildFirewallSnapshotTelemetry(monitoring, online, networkBlockedPaths.Count);
    }

    private void SendFirewallActionTelemetry(string kind, int count = 1)
    {
        if (HashGuardLogic.BuildFirewallActionTelemetry(kind, count) is { } data)
        {
            _ = SendTelemetryEventAsync("firewall_block", data);
        }
    }

    private async Task<bool> SendTelemetryEventAsync(string eventType, Dictionary<string, object>? data = null)
    {
        if (!appSettings.TelemetryEnabled || string.IsNullOrWhiteSpace(AppConstants.TelemetryEndpointUrl))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(appSettings.AnonymousInstallId))
        {
            appSettings.AnonymousInstallId = Guid.NewGuid().ToString("N");
            SaveCurrentAppSettings();
        }

        return await TelemetryClient.SendAsync(
            AppConstants.TelemetryEndpointUrl,
            eventType,
            appSettings.AnonymousInstallId,
            CurrentVersion,
            data);
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
            "Choose your protection mode:",
            "• Local-only (default): scores unsigned files, risky paths, persistence, recent changes, and the local hash cache — no cloud API keys required.",
            "• Cloud reputation: add free VirusTotal and/or MetaDefender API keys in Settings for multi-engine hash checks.",
            "Uploading unknown files to VirusTotal is optional and privacy-sensitive. Keep uploads off for private, personal, proprietary, or sensitive files.",
            "Anonymous usage reporting is on: a random install ID, the app and Windows version, and scan and firewall counts. Never file or app names, paths, hashes, addresses or user names. Turn it off in Settings. You can also enable scheduled daily scans and export reports there.",
            "Open Settings now?",
        });
        var openSettings = MessageBox.Show(this, message, "HashGuard first-run setup", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
        if (openSettings == DialogResult.Yes)
        {
            ShowSettingsDialog();
        }
    }

    private static void AddSettingsTab(SegmentTabs tabs, string title, Control content) => tabs.AddTab(title, content);

    /// <summary>Friendly name and one-line explanation for each setting, as in the design.</summary>
    private static readonly Dictionary<string, (string Label, string Help)> SettingWords = new(StringComparer.Ordinal)
    {
        ["Enable VirusTotal"] = ("VirusTotal", "Checks each file hash against 70+ antivirus engines"),
        ["Enable MetaDefender Cloud"] = ("MetaDefender Cloud", "A second multi-engine opinion"),
        ["Enable Team Cymru MHR"] = ("Team Cymru Malware Hash Registry", "Free hash lookups, no key needed"),
        ["Free API limits (4/min, 500/day)"] = ("Stay within free API limits", "4 lookups a minute, 500 a day"),
        ["Allow VirusTotal uploads (approve each file in Review Queue)"] = ("Allow VirusTotal uploads", "Only files VirusTotal has never seen, and only after you approve each one"),
        ["Add Explorer right-click scan"] = ("Add \u201cScan with HashGuard\u201d to the right-click menu", "For files in File Explorer"),
        ["Start with Windows"] = ("Start with Windows", "Starts elevated at sign-in without a UAC prompt when Run elevated is on"),
        ["Start minimized to tray"] = ("Start minimized to the tray", "HashGuard waits quietly next to the clock"),
        ["Scan automatically at startup"] = ("Scan running apps when HashGuard starts", "A quick check every time you sign in"),
        ["Run elevated"] = ("Run elevated", "Needed to block apps and to inspect protected processes"),
        ["Scan files I open or select"] = ("Check files you open or select", "Never uploads anything; skips photos, video and music"),
        ["Daily scan of running apps (catches up if the PC was off)"] = ("Daily scan", "Scans running apps once a day; catches up if the PC was off"),
        ["Highlight new files since last scan"] = ("Highlight new files", "Marks files that weren't there at the last scan"),
        ["Reuse cached hash for unchanged files (delta scan)"] = ("Skip unchanged files", "Reuses the saved hash when a file hasn\u2019t changed on disk"),
        ["Suppress repeat tray alerts for same detections"] = ("Don\u2019t repeat the same alert", "One alert per threat until something changes"),
        ["Check updates automatically"] = ("Check for updates automatically", "Updates are verified with HashGuard\u2019s signature before installing"),
        ["Send anonymous usage data"] = ("Send anonymous usage data", "A random install ID, versions and scan counts. Never file names, paths or hashes"),
        ["Enable Hash Cache"] = ("Remember results", "Files already known to be clean aren\u2019t looked up again"),
        ["Watch network connections in the background (needed for alerts and auto-block)"] = ("Watch network connections in the background", "Needed for new-app alerts and auto-block"),
        ["Automatically block apps HashGuard flags as malicious (needs Run elevated)"] = ("Automatically block apps flagged as malicious", "Adds a Windows Firewall rule as soon as one connects (needs Run elevated)"),
    };

    private static readonly Dictionary<string, string> SettingRowHelp = new(StringComparer.Ordinal)
    {
        ["Stored hashes"] = "Files HashGuard already checked and remembers. Forget one to check it again",
        ["Ignored files"] = "Files you told HashGuard to ignore. Un-ignore one to check it again",
        ["VirusTotal API key"] = "Kept encrypted on this PC",
        ["MetaDefender API key"] = "Kept encrypted on this PC",
        ["VirusTotal delay per request"] = "Seconds between lookups; raise it if you hit the free limit",
        ["Request timeout"] = "Seconds to wait for a source to answer",
        ["Appearance"] = "Light, dark or follow Windows",
        ["Daily scan hour (0-23)"] = "When the daily scan runs",
        ["New-app alerts"] = "When an app goes online for the first time",
        ["HashGuard firewall rules"] = "Removes every rule HashGuard added; your own rules stay",
        ["Updates"] = "Download and install the latest signed release",
    };

    /// <summary>
    /// Settings tab body as designed: one rounded card per section, spread over two columns, each
    /// setting a row with its name, a one-line explanation and its switch or field on the right.
    /// </summary>
    private static Control CreateSettingsPage(params (string Title, Control[] Controls)[] sections)
    {
        var scroller = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = SoftAppBack, Padding = new Padding(0, 4, 0, 4) };
        var columns = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, RowCount = 1, BackColor = SoftAppBack, Margin = new Padding(0) };
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var stacks = new[] { CreateSettingsColumn(new Padding(0, 0, 8, 0)), CreateSettingsColumn(new Padding(8, 0, 0, 0)) };
        var heights = new[] { 0, 0 };
        foreach (var section in sections)
        {
            var card = CreateSettingsCard(section.Title, section.Controls);
            var column = heights[0] <= heights[1] ? 0 : 1;
            stacks[column].Controls.Add(card);
            heights[column] += card.Height + 16;
        }

        columns.Controls.Add(stacks[0], 0, 0);
        columns.Controls.Add(stacks[1], 1, 0);
        void Fit()
        {
            foreach (var stack in stacks)
            {
                var width = Math.Max(240, stack.ClientSize.Width);
                foreach (Control card in stack.Controls)
                {
                    card.Width = width;
                }
            }
        }

        foreach (var stack in stacks)
        {
            stack.SizeChanged += (_, _) => Fit();
        }

        scroller.Controls.Add(columns);
        return scroller;
    }

    private static FlowLayoutPanel CreateSettingsColumn(Padding margin) =>
        new() { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right, Margin = margin, BackColor = SoftAppBack };

    private static CardPanel CreateSettingsCard(string title, Control[] controls)
    {
        var card = new CardPanel { Radius = 16, Padding = new Padding(20, 12, 20, 10), Margin = new Padding(0, 0, 0, 16), Width = 420 };
        var rows = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = controls.Length + 1, BackColor = Color.Transparent, Margin = new Padding(0) };
        rows.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        rows.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        rows.Controls.Add(new Label { Text = title, AutoSize = false, Dock = DockStyle.Fill, Font = UiFonts.Create("Segoe UI Semibold", 11, FontStyle.Regular), TextAlign = ContentAlignment.MiddleLeft, UseMnemonic = false }, 0, 0);
        var height = 34;
        for (var index = 0; index < controls.Length; index++)
        {
            var row = CreateSettingsCardRow(controls[index]);
            rows.RowStyles.Add(new RowStyle(SizeType.Absolute, row.Height));
            rows.Controls.Add(row, 0, index + 1);
            height += row.Height;
        }

        card.Controls.Add(rows);
        card.Height = height + card.Padding.Vertical + 6;
        return card;
    }

    private static Control CreateSettingsCardRow(Control control)
    {
        string label;
        string help;
        Control editor;
        if (control is ToggleSwitch toggle)
        {
            (label, help) = SettingWords.TryGetValue(toggle.Text, out var words) ? words : (toggle.Text, "");
            toggle.AccessibleName = label;
            toggle.AccessibleDescription = help;
            editor = toggle;
        }
        else if (control.Tag is SettingRowTag tag)
        {
            label = tag.Label;
            help = SettingRowHelp.TryGetValue(tag.Label, out var helpText) ? helpText : "";
            editor = tag.Editor;
        }
        else
        {
            control.Dock = DockStyle.Fill;
            control.Margin = new Padding(0, 6, 0, 6);
            var holder = new Panel { Dock = DockStyle.Fill, Height = Math.Max(40, control.Height + 12), BackColor = Color.Transparent, Margin = new Padding(0) };
            holder.Controls.Add(control);
            return holder;
        }

        // Long help wraps to a second line instead of being cut off.
        var twoLines = TextRenderer.MeasureText(help, SettingsHelpFont).Width > 330;
        var row = new TableLayoutPanel { Dock = DockStyle.Fill, Height = string.IsNullOrEmpty(help) ? 46 : twoLines ? 74 : 58, ColumnCount = 2, RowCount = 1, BackColor = Color.Transparent, Margin = new Padding(0), Tag = "settings-row" };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        row.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var text = new Panel { Dock = DockStyle.Fill, BackColor = Color.Transparent, Margin = new Padding(0, 4, 12, 4) };
        if (!string.IsNullOrEmpty(help))
        {
            text.Controls.Add(new Label { Text = help, AutoSize = false, Dock = DockStyle.Top, Height = twoLines ? 36 : 20, Tag = "muted", AutoEllipsis = true, UseMnemonic = false });
        }

        text.Controls.Add(new Label { Text = label, AutoSize = false, Dock = DockStyle.Top, Height = 24, Font = UiFonts.Create("Segoe UI Semibold", 9.75f, FontStyle.Regular), AutoEllipsis = true, UseMnemonic = false, TextAlign = ContentAlignment.BottomLeft });
        editor.Dock = DockStyle.None;
        editor.Anchor = AnchorStyles.Right;
        editor.Margin = new Padding(0);
        if (editor is TextBox or ComboBox or DropdownField)
        {
            editor.Width = 230;
        }
        else if (editor is NumericUpDown)
        {
            editor.Width = 80;
        }

        row.Controls.Add(text, 0, 0);
        row.Controls.Add(editor, 1, 0);
        return row;
    }

    private sealed record SettingRowTag(string Label, Control Editor);

    private static readonly Font SettingsHelpFont = UiFonts.Create("Segoe UI", 9);

    /// <summary>A labelled field; laid out as a settings row by <see cref="CreateSettingsCardRow"/>.</summary>
    private static Control CreateSettingRow(string labelText, Control editor) =>
        new Panel { Tag = new SettingRowTag(labelText, editor), Height = 1 };
}
