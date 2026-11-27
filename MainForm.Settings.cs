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
        var scheduledDaily = new CheckBox { Text = "Daily scan of running apps (catches up if the PC was off)", Checked = appSettings.ScheduledDailyScan, AutoSize = true };
        var scheduledHour = new NumericUpDown { Minimum = 0, Maximum = 23, Value = Math.Clamp(appSettings.ScheduledScanHour, 0, 23), Width = 70 };
        var preferDelta = new CheckBox { Text = "Highlight new files since last scan", Checked = appSettings.PreferDeltaScan, AutoSize = true };
        var deltaScan = new CheckBox { Text = "Reuse cached hash for unchanged files (delta scan)", Checked = appSettings.DeltaScanEnabled, AutoSize = true };
        var suppressTray = new CheckBox { Text = "Suppress repeat tray alerts for same detections", Checked = appSettings.SuppressRepeatTrayAlerts, AutoSize = true };
        var autoUpdates = new CheckBox { Text = "Check updates automatically", Checked = autoUpdateChecksBox.Checked, AutoSize = true };
        var telemetryEnabled = new CheckBox { Text = "Send anonymous usage data", Checked = telemetryEnabledBox.Checked, AutoSize = true };
        var hashCache = new CheckBox { Text = "Enable Hash Cache", Checked = hashCacheEnabledBox.Checked, AutoSize = true };
        var uploadUnknown = new CheckBox { Text = "Allow VirusTotal uploads (approve each file in Review Queue)", Checked = uploadUnknownBox.Checked, AutoSize = true };
        var networkMonitor = new CheckBox { Text = "Watch network connections in the background (needed for alerts and auto-block)", Checked = appSettings.NetworkMonitorEnabled, AutoSize = true };
        var networkNotify = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 360 };
        networkNotify.Items.AddRange(["When an untrusted app connects for the first time", "When any app connects for the first time", "Never"]);
        networkNotify.SelectedIndex = NetworkNotifyModes.Normalize(appSettings.NetworkNotifyMode) switch
        {
            NetworkNotifyModes.NewApps => 1,
            NetworkNotifyModes.Never => 2,
            _ => 0,
        };
        var autoBlockMalicious = new CheckBox { Text = "Automatically block apps HashGuard flags as malicious (needs Run elevated)", Checked = appSettings.AutoBlockMalicious, AutoSize = true };
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
        var updateInfo = new Label
        {
            Text = BuildVersionAndUpdateInfo(),
            Dock = DockStyle.Top,
            AutoSize = false,
            Height = 96,
            Padding = new Padding(10),
            BackColor = Color.FromArgb(248, 250, 252),
            ForeColor = Color.FromArgb(35, 35, 35),
            TextAlign = ContentAlignment.TopLeft,
            BorderStyle = BorderStyle.FixedSingle,
            Tag = "callout",
        };

        // Tabs + footer only (no large header strip — frees vertical space for Behavior/Version content).
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(0) };
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        dialog.Controls.Add(root);

        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 0, 0, 6),
            Font = new Font("Segoe UI", 10, FontStyle.Regular),
            Padding = new Point(18, 6),
        };
        root.Controls.Add(tabs, 0, 0);

        var reputationPage = CreateSettingsPage(
            ("Reputation Providers", [vtEnabled, mdEnabled, mhrEnabled, freeLimit, uploadUnknown]),
            ("API Keys", [CreateSettingRow("VirusTotal API key", apiKey), CreateSettingRow("MetaDefender API key", metaDefenderApiKey)]),
            ("Request Timing", [CreateSettingRow("VirusTotal delay per request", delay), CreateSettingRow("Request timeout", timeout)]),
            ("Provider Status", [reputationValidation]));

        var behaviorPage = CreateSettingsPage(
            ("Windows Integration", [runElevated, startWithWindows, startMinimized, rightClickScan, CreateSettingRow("Colors", colorMode), autoUpdates, suppressTray]),
            ("Privacy", [telemetryEnabled]),
            ("Version and Updates", [updateInfo, updateButton]));
        var antivirusPage = CreateSettingsPage(
            ("Scans", [autoProcessScan, scheduledDaily, CreateSettingRow("Daily scan hour (0-23)", scheduledHour), scanAllFiles]),
            ("Speed", [hashCache, deltaScan, preferDelta]));
        AddSettingsTab(tabs, "Behavior", behaviorPage);
        AddSettingsTab(tabs, "Reputation", reputationPage);
        AddSettingsTab(tabs, "Antivirus", antivirusPage);

        var networkPage = CreateSettingsPage(
            ("Firewall", [networkMonitor, CreateSettingRow("Alerts", networkNotify), autoBlockMalicious, networkInfo]));
        AddSettingsTab(tabs, "Firewall", networkPage);

        var trustPage = BuildTrustEditor(pendingTrusted);
        AddSettingsTab(tabs, "Trust", trustPage);

        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 4, 18, 12),
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
            "Anonymous usage reporting is on: a random install ID, the app and Windows version, and scan counts. Never file names, paths, hashes or user names. Turn it off in Settings. You can also enable scheduled daily scans and export reports there.",
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
        var page = new TabPage(title) { BackColor = Color.White, Padding = new Padding(8) };
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
            // Allow scroll when a tab has many sections (Behavior / Version and Updates).
            AutoScroll = true,
            Padding = new Padding(12, 10, 12, 10),
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
            Padding = new Padding(12, 8, 12, 10),
            Margin = new Padding(0, 0, 0, 8),
            BorderStyle = BorderStyle.FixedSingle,
        };

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
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

        section.Controls.Add(layout);
        MeasureSettingsSectionHeight(section, layout);
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
        var availableWidth = page.ClientSize.Width - page.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth;
        section.Width = Math.Max(560, availableWidth - section.Margin.Horizontal);
        if (section is Panel panel
            && panel.Controls.Count > 0
            && panel.Controls[0] is TableLayoutPanel layout)
        {
            MeasureSettingsSectionHeight(panel, layout);
        }
    }

    private static void MeasureSettingsSectionHeight(Panel section, TableLayoutPanel layout)
    {
        layout.PerformLayout();
        var contentHeight = layout.PreferredSize.Height;
        if (contentHeight <= 0)
        {
            contentHeight = layout.Height;
        }

        section.Height = Math.Max(58, contentHeight + section.Padding.Vertical + 6);
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
}
