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
        if (uploadWarningShown || appSettings.UploadUnknownAcknowledged)
        {
            uploadWarningShown = true;
            appSettings.UploadUnknownAcknowledged = true;
            return true;
        }

        var accepted = ConfirmVirusTotalUploads();
        uploadWarningShown = accepted;
        appSettings.UploadUnknownAcknowledged = accepted;
        return accepted;
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

        SaveCurrentAppSettings();
        UpdateAllFileScanner();
    }

    private bool EnableAllFileScanningWithWarning()
    {
        if (scanAllFilesWarningShown || appSettings.ScanAllFilesAcknowledged)
        {
            scanAllFilesWarningShown = true;
            appSettings.ScanAllFilesAcknowledged = true;
            return true;
        }

        var accepted = MessageBox.Show(
            this,
            $"HashGuard will watch Windows Recent files and poll open File Explorer windows for selected or focused files, excluding common pictures, videos, audio files, and camera/raw media. Scanning starts only when process scans are idle.{Environment.NewLine}{Environment.NewLine}Open/selected file scanning uses hash lookups only and never uploads full files. Scan Now and Explorer right-click still upload if that option is enabled.{Environment.NewLine}{Environment.NewLine}Enable open/selected file scanning?",
            "Confirm open/selected file scanning",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);
        var yes = accepted == DialogResult.Yes;
        scanAllFilesWarningShown = yes;
        appSettings.ScanAllFilesAcknowledged = yes;
        return yes;
    }

    private bool ConfirmVirusTotalUploads()
    {
        var accepted = MessageBox.Show(
            this,
            "When VirusTotal has not seen a file hash, HashGuard lists it in the Review Queue. You approve each upload with Approve Upload. Do not enable this for private, proprietary, personal, or sensitive files unless you are comfortable sharing the file with VirusTotal. Allow uploads?",
            "Confirm VirusTotal uploads",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        return accepted == DialogResult.Yes;
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

    /// <summary>
    /// Registers how HashGuard starts at sign-in, from "Start with Windows" and "Run elevated":
    /// elevated → a Task Scheduler logon task with highest privileges (no UAC prompt);
    /// not elevated → the per-user Run key. The other mechanism is removed so only one starts it.
    /// </summary>
    private void ApplyStartWithWindows()
    {
        var exePath = Application.ExecutablePath;
        if (!startWithWindowsBox.Checked)
        {
            RemoveRunKeyStartup();
            RemoveElevatedStartupTaskIfPossible();
            statusLabel.Text = "Start with Windows disabled.";
            return;
        }

        if (runElevatedBox.Checked)
        {
            if (!IsRunningElevated())
            {
                // Only an elevated process can register a highest-privileges task. Keep the Run key
                // so HashGuard still starts; the next (elevated) launch finishes the switch.
                InstallRunKeyStartup();
                statusLabel.Text = "Start with Windows enabled. Restart HashGuard once (it will ask for admin) to start elevated without a prompt.";
                return;
            }

            ElevatedStartupTask.Install(exePath, CurrentUserSid());
            RemoveRunKeyStartup();
            statusLabel.Text = "Start with Windows enabled: HashGuard starts elevated at sign-in without a UAC prompt.";
            return;
        }

        InstallRunKeyStartup();
        RemoveElevatedStartupTaskIfPossible();
        statusLabel.Text = "Start with Windows enabled.";
    }

    /// <summary>
    /// Called once at launch: when HashGuard runs elevated with both settings on, move an existing
    /// Run-key startup to the elevated task, or repoint the task after HashGuard.exe moved.
    /// </summary>
    private void MigrateStartupToElevatedTaskIfNeeded()
    {
        if (!runElevatedBox.Checked || !IsRunningElevated() || !IsStartWithWindowsInstalled())
        {
            return;
        }

        var exePath = Application.ExecutablePath;
        if (!IsRunKeyStartupInstalled() && ElevatedStartupTask.IsInstalledFor(exePath))
        {
            return;
        }

        try
        {
            ElevatedStartupTask.Install(exePath, CurrentUserSid());
            RemoveRunKeyStartup();
            statusLabel.Text = "HashGuard now starts elevated at sign-in without a UAC prompt.";
        }
        catch (Exception ex)
        {
            // Keep the Run key; startup still works, just with a prompt.
            statusLabel.Text = $"Could not set up prompt-free elevated startup: {ex.Message}";
        }
    }

    private void RemoveElevatedStartupTaskIfPossible()
    {
        try
        {
            ElevatedStartupTask.Remove();
        }
        catch (Exception ex) when (!IsRunningElevated())
        {
            throw new InvalidOperationException(
                $"The elevated startup task can only be removed while HashGuard runs elevated. {ex.Message}", ex);
        }
    }

    private static string CurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new InvalidOperationException("Could not read the current user's SID.");
    }

    private static bool IsStartWithWindowsInstalled() =>
        IsRunKeyStartupInstalled() || ElevatedStartupTask.IsInstalledFor(Application.ExecutablePath);

    private static bool IsRunKeyStartupInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath);
        return key?.GetValue(RunRegistryValueName) is string value
            && value.Contains(Application.ExecutablePath, StringComparison.OrdinalIgnoreCase);
    }

    private static void InstallRunKeyStartup()
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunRegistryPath);
        key.SetValue(RunRegistryValueName, $"\"{Application.ExecutablePath}\" {ElevatedStartupTask.StartupArguments}");
    }

    private static void RemoveRunKeyStartup()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunRegistryPath, writable: true);
        key?.DeleteValue(RunRegistryValueName, throwOnMissingValue: false);
    }
}
