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
    private async Task ScanQueuedAllFileAsync()
    {
        if (!scanAllFilesBox.Checked || !processBaselineReady || scanCancellation is not null || scanGate.IsBusy)
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

        if (!scanGate.TryEnter())
        {
            return;
        }

        statusLabel.Text = $"Idle file scan: {path}";
        SetDashboardState("Scanning", "Process monitoring is idle. Checking file activity.", false);
        try
        {
            using var http = AppHttp.Create((int)timeoutBox.Value);
            var apiKey = apiKeyBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            await EnsureScanStorageReadyAsync(markSelfTrusted: false).ConfigureAwait(true);

            var result = await ScanPathAsync(
                http,
                path,
                [new ProcessFile(0, "File activity", path)],
                allowVirusTotalUploads: false);
            results.Add(result);
            AddResultRow(result);
            UpdateSummary();
            await hashCache.SaveIfDirtyAsync().ConfigureAwait(true);

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
            scanGate.Exit();
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
                var safePath = ScanPathSecurity.TryNormalizeScanPath(path, out _);
                if (!string.IsNullOrWhiteSpace(safePath))
                {
                    BeginInvoke(async () =>
                    {
                        RestoreFromTray();
                        await ScanSingleFileAsync(safePath);
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

        if (!scanGate.TryEnter())
        {
            MessageBox.Show(this, "A scan is already running. Try again when it finishes.", "Right-click scan", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        EnsureProviderKeysConfigured();

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
        UpdateReviewCount(0);
        SetDashboardState("Scanning", "Checking the selected file with enabled reputation services.", false);

        try
        {
            if (virusTotalEnabledBox.Checked && string.IsNullOrWhiteSpace(apiKey))
            {
                statusLabel.Text = "VirusTotal API key is not configured. Running local/provider checks that do not require it.";
            }

            using var http = AppHttp.Create((int)timeoutBox.Value);
            if (virusTotalEnabledBox.Checked && !string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }
            await EnsureScanStorageReadyAsync().ConfigureAwait(true);

            var processFile = new ProcessFile(0, Path.GetFileName(path), path);
            var result = await ScanPathAsync(http, path, [processFile]);
            results.Add(result);
            AddResultRow(result);
            UpdateSummary();
            progressBar.Value = 1;
            await hashCache.SaveIfDirtyAsync().ConfigureAwait(true);
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
            scanGate.Exit();
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

    /// <summary>
    /// Warm hash cache + quota in memory. Reload/import only when needed; skip re-hashing
    /// HashGuard.exe when it is already known clean.
    /// </summary>
    private async Task EnsureScanStorageReadyAsync(
        CancellationToken cancellationToken = default,
        bool markSelfTrusted = true)
    {
        // Capture WinForms state before any await / thread hop.
        var exePath = Application.ExecutablePath;
        var logDirectories = GetLogDirectories().ToList();

        cancellationToken.ThrowIfCancellationRequested();
        await hashCache.EnsureLoadedAsync().ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        hashCache.ImportScanLogsIfChanged(logDirectories);

        if (markSelfTrusted && !hashCache.IsTrustedCleanPath(exePath))
        {
            await hashCache.MarkFileCleanAsync(exePath, "HashGuard executable trusted locally.").ConfigureAwait(false);
            await hashCache.SaveIfDirtyAsync().ConfigureAwait(false);
        }

        await quotaTracker.EnsureLoadedAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Validates provider API keys once before a scan starts. Prompts for a missing MetaDefender
    /// key and disables the provider if the user leaves it blank, so the scan loop never has to
    /// pop modal dialogs per file.
    /// </summary>
    private void EnsureProviderKeysConfigured()
    {
        var metaDefenderMissing = metaDefenderEnabledBox.Checked
            && string.IsNullOrWhiteSpace(metaDefenderApiKeyBox.Text.Trim());
        if (!metaDefenderMissing)
        {
            return;
        }

        MessageBox.Show(
            this,
            "MetaDefender Cloud is enabled but no API key is saved. Open Settings and paste your MetaDefender Cloud API key, or disable MetaDefender.",
            "MetaDefender API key required",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
        ShowSettingsDialog();
        if (string.IsNullOrWhiteSpace(metaDefenderApiKeyBox.Text.Trim()))
        {
            metaDefenderEnabledBox.Checked = false;
            UpdateReputationTile();
        }
    }
}
