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
        deltaScanBox.Checked = appSettings.DeltaScanEnabled;
        UpdateReputationTile();
        UpdateQuarantineTile();
        freeApiLimitBox.Checked = appSettings.FreeApiLimits;
        uploadUnknownBox.Checked = appSettings.UploadUnknown;
        uploadWarningShown = appSettings.UploadUnknownAcknowledged;
        startMinimizedBox.Checked = appSettings.StartMinimized;
        autoProcessScanBox.Checked = appSettings.AutoProcessScan;
        runElevatedBox.Checked = appSettings.RunElevated;
        scanAllFilesBox.Checked = appSettings.ScanAllFiles;
        scanAllFilesWarningShown = appSettings.ScanAllFilesAcknowledged;

        autoUpdateChecksBox.Checked = appSettings.AutoUpdateChecks;
        telemetryEnabledBox.Checked = appSettings.TelemetryEnabled;
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
        appSettings.DeltaScanEnabled = deltaScanBox.Checked;
        appSettings.UploadUnknown = uploadUnknownBox.Checked;
        appSettings.UploadUnknownAcknowledged = uploadWarningShown || appSettings.UploadUnknownAcknowledged;
        appSettings.ScanAllFilesAcknowledged = scanAllFilesWarningShown || appSettings.ScanAllFilesAcknowledged;
        appSettings.StartMinimized = startMinimizedBox.Checked;
        appSettings.AutoProcessScan = autoProcessScanBox.Checked;
        appSettings.RunElevated = runElevatedBox.Checked;
        appSettings.ScanAllFiles = scanAllFilesBox.Checked;
        appSettings.AutoUpdateChecks = autoUpdateChecksBox.Checked;
        var telemetryWasEnabled = appSettings.TelemetryEnabled;
        appSettings.TelemetryEnabled = telemetryEnabledBox.Checked;
        if (appSettings.TelemetryEnabled && string.IsNullOrWhiteSpace(appSettings.AnonymousInstallId))
        {
            appSettings.AnonymousInstallId = Guid.NewGuid().ToString("N");
        }
        appSettings.ColorMode = IndexToColorMode(colorModeBox.SelectedIndex);
        appSettings.UseSystemDefaultColors = appSettings.ColorMode == AppConstants.ColorModeSystem;
        appSettings.DelaySeconds = (int)delayBox.Value;
        appSettings.TimeoutSeconds = (int)timeoutBox.Value;

        appSettings.ApiKeyEncrypted = EncryptApiKey(apiKeyBox.Text.Trim());
        appSettings.MetaDefenderApiKeyEncrypted = EncryptApiKey(metaDefenderApiKeyBox.Text.Trim());
        appSettings.ApiKey = "";
        appSettings.MetaDefenderApiKey = "";
        try
        {
            Directory.CreateDirectory(AppPaths.GetConfigDirectory());
            File.WriteAllText(AppPaths.GetAppSettingsPath(), JsonSerializer.Serialize(appSettings, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            statusLabel.Text = $"Could not save settings: {ex.Message}";
        }

        // Start/stop reporting immediately when the setting changes (do not require app restart).
        if (appSettings.TelemetryEnabled && !telemetryWasEnabled)
        {
            _ = InitializeTelemetryAsync();
        }
        else if (!appSettings.TelemetryEnabled && telemetryWasEnabled)
        {
            telemetryHeartbeatTimer.Stop();
        }
    }

    private static AppSettings LoadAppSettings()
    {
        try
        {
            var currentPath = AppPaths.GetAppSettingsPath();
            if (File.Exists(currentPath))
            {
                var settingsJson = File.ReadAllText(currentPath, Encoding.UTF8);
                var settings = JsonSerializer.Deserialize<AppSettings>(settingsJson) ?? new AppSettings();
                settings.TrustedPublishers ??= new AppSettings().TrustedPublishers;
                PopulateLegacyPlaintextKeys(settings, settingsJson);
                return settings;
            }

            return new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    /// <summary>
    /// Reads the pre-DPAPI plaintext API keys that older builds wrote. Those properties are
    /// [JsonIgnore] now, so HashGuard can no longer persist a plaintext key, but existing
    /// settings files still need their keys migrated into the encrypted fields on load.
    /// </summary>
    private static void PopulateLegacyPlaintextKeys(AppSettings settings, string settingsJson)
    {
        try
        {
            using var document = JsonDocument.Parse(settingsJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            if (document.RootElement.TryGetProperty("ApiKey", out var apiKey) && apiKey.ValueKind == JsonValueKind.String)
            {
                settings.ApiKey = apiKey.GetString() ?? "";
            }

            if (document.RootElement.TryGetProperty("MetaDefenderApiKey", out var metaDefenderKey) && metaDefenderKey.ValueKind == JsonValueKind.String)
            {
                settings.MetaDefenderApiKey = metaDefenderKey.GetString() ?? "";
            }
        }
        catch
        {
            // Legacy plaintext migration is best-effort.
        }
    }

    internal static bool ShouldRunElevatedFromSettings()
    {
        return LoadAppSettings().RunElevated;
    }

    private static string GetIgnoredHashesPath() => AppPaths.GetIgnoredHashesPath();


    private static string GetIgnoredPathsPath() => AppPaths.GetIgnoredPathsPath();


    private static string GetQuarantineDirectory() => AppPaths.GetQuarantineDirectory();


    private static string GetQuarantineManifestPath() => AppPaths.GetQuarantineManifestPath();



    // Compatibility wrappers for Program.cs / first-run setup.
    internal static string GetAppSettingsPath() => AppPaths.GetAppSettingsPath();
    internal static string GetConfigDirectory() => AppPaths.GetConfigDirectory();

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
        Directory.CreateDirectory(AppPaths.GetConfigDirectory());
        File.WriteAllText(
            GetIgnoredHashesPath(),
            JsonSerializer.Serialize(ignoredHashes.OrderBy(hash => hash, StringComparer.OrdinalIgnoreCase), new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);
    }

    private void LoadIgnoredPaths()
    {
        ignoredPaths.Clear();
        var path = GetIgnoredPathsPath();
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var paths = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path, Encoding.UTF8)) ?? [];
            foreach (var ignoredPath in paths.Where(ignoredPath => !string.IsNullOrWhiteSpace(ignoredPath)))
            {
                ignoredPaths.Add(ignoredPath.Trim());
            }
        }
        catch
        {
            // Ignore malformed ignored-path data; users can recreate it from the Review Queue.
        }
    }

    private void SaveIgnoredPaths()
    {
        Directory.CreateDirectory(AppPaths.GetConfigDirectory());
        File.WriteAllText(
            GetIgnoredPathsPath(),
            JsonSerializer.Serialize(ignoredPaths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase), new JsonSerializerOptions { WriteIndented = true }),
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
}
