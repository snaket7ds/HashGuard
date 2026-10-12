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
    private async Task StartScanAsync(bool showCompletionMessages = true)
    {
        if (scanCancellation is not null)
        {
            scanCancellation.Cancel();
            scanButton.Enabled = false;
            statusLabel.Text = "Stopping scan...";
            return;
        }

        if (!scanGate.TryEnter())
        {
            statusLabel.Text = "A scan is already running.";
            return;
        }

        var apiKey = apiKeyBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(apiKey) || !string.IsNullOrWhiteSpace(metaDefenderApiKeyBox.Text))
        {
            SaveCurrentAppSettings();
        }

        EnsureProviderKeysConfigured();

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
        UpdateReviewCount(0);
        SetDashboardState("Scanning", "Checking running process files with enabled reputation services.", false);

        try
        {
            // Process enumeration + persistence registry reads are expensive — keep UI responsive.
            var processCollection = await CollectProcessFilesWithPersistenceAsync(token).ConfigureAwait(true);
            var grouped = processCollection.Files;
            var paths = grouped.Keys.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToList();
            RefreshMonitoredProcessFiles(grouped.Keys);
            AddSkippedProcessLogIfNeeded(processCollection, force: true);

            totalCount = paths.Count;
            progressBar.Maximum = Math.Max(paths.Count, 1);

            using var http = AppHttp.Create((int)timeoutBox.Value);
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            statusLabel.Text = "Preparing reputation cache...";
            await EnsureScanStorageReadyAsync(token).ConfigureAwait(true);

            BeginScanUiBatch();
            for (var index = 0; index < paths.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                var path = paths[index];
                var result = await ScanPathAsync(http, path, grouped[path], token);
                results.Add(result);
                AddResultRow(result);
                scannedCount = index + 1;
                PulseScanUi(scannedCount, paths.Count, path);
                await hashCache.FlushIfDueAsync().ConfigureAwait(true);

                if (virusTotalEnabledBox.Checked
                    && index + 1 < paths.Count
                    && delayBox.Value > 0
                    && IssuedVirusTotalRequest(result))
                {
                    await Task.Delay(TimeSpan.FromSeconds((double)delayBox.Value), token);
                }
            }

            completedScan = true;
            processMonitorTimer.Start();

            var unresolved = results.Where(ResultNeedsAction).ToList();
            var previousSnapshot = ScanSnapshotStore.Load();
            ScanSnapshotStore.MarkNewSinceLastScan(results, previousSnapshot);
            var newSinceLast = results.Count(result => result.IsNewSinceLastScan);
            ScanSnapshotStore.Save(results);
            resultsView.BeginUpdate();
            try
            {
                resultsView.Items.Clear();
                foreach (var result in results)
                {
                    AddResultRow(result);
                }
            }
            finally
            {
                resultsView.EndUpdate();
            }
            ReconcileReviewQueue();

            var alerts = unresolved.Where(result => result.IsAlert).ToList();
            var unknown = results.Count(result => result.Status is "unknown" or "uploaded");
            var errors = unresolved.Count(result => result.Status == "error");
            var highRisk = unresolved.Count(result => result.RiskScore >= 70);
            var newText = newSinceLast > 0 ? $", {newSinceLast} new since last scan" : "";
            var summaryParts = new[]
            {
                Plural(unresolved.Count, "item") + " need action",
                Plural(alerts.Count, "detection"),
                Plural(unknown, "unknown file"),
                Plural(errors, "error"),
            };
            statusLabel.Text = $"Done: {string.Join(" · ", summaryParts)}{newText} · cache {hashCache.Count:N0} hashes";
            _ = SendTelemetryEventAsync(
                "scan_complete",
                HashGuardLogic.BuildScanCompleteTelemetry(results.Count, unresolved.Count, alerts.Count, unknown, errors));
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
                    var signature = HashGuardLogic.BuildTrayAlertSignature(alerts.Select(r => (r.Sha256, r.Path)));
                    if (HashGuardLogic.ShouldShowTrayAlert(appSettings.SuppressRepeatTrayAlerts, appSettings.LastTrayAlertSignature, signature))
                    {
                        appSettings.LastTrayAlertSignature = signature;
                        SaveCurrentAppSettings();
                        trayIcon.ShowBalloonTip(4000, "HashGuard detections found", sample, ToolTipIcon.Warning);
                    }
                }
            }
            else if (unresolved.Count == 0)
            {
                appSettings.LastTrayAlertSignature = "";
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
            try
            {
                await hashCache.SaveIfDirtyAsync().ConfigureAwait(true);
            }
            catch
            {
                // Cache flush is best-effort; scan results are already in memory.
            }

            EndScanUiBatch();
            scanCancellation = null;
            SetScanButtonReadyStyle();
            scanButton.Enabled = true;
            if (completedScan)
            {
                processBaselineReady = true;
                processMonitorTimer.Start();
            }

            scanGate.Exit();
        }
    }

    private async Task ScanNewProcessFilesAsync()
    {
        if (scanCancellation is not null || scanGate.IsBusy)
        {
            return;
        }

        var processCollection = await CollectProcessFilesAsync().ConfigureAwait(true);
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

        if (!scanGate.TryEnter())
        {
            return;
        }

        EnsureProviderKeysConfigured();

        progressBar.Value = 0;
        progressBar.Maximum = Math.Max(newPaths.Count, 1);
        countLabel.Text = $"0 / {newPaths.Count}";
        statusLabel.Text = $"New process file found. Scanning {newPaths.Count} new file(s)...";
        SetDashboardState("Scanning", "New process file found. Checking it now.", false);

        try
        {
            using var http = AppHttp.Create((int)timeoutBox.Value);
            var apiKey = apiKeyBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                http.DefaultRequestHeaders.Add("x-apikey", apiKey);
            }

            await EnsureScanStorageReadyAsync().ConfigureAwait(true);

            BeginScanUiBatch();
            for (var index = 0; index < newPaths.Count; index++)
            {
                var path = newPaths[index];
                var result = await ScanPathAsync(http, path, grouped[path]);
                results.Add(result);
                AddResultRow(result);
                PulseScanUi(index + 1, newPaths.Count, path, "Monitoring scan");
                await hashCache.FlushIfDueAsync().ConfigureAwait(true);

                if (virusTotalEnabledBox.Checked
                    && index + 1 < newPaths.Count
                    && delayBox.Value > 0
                    && IssuedVirusTotalRequest(result))
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
            try
            {
                await hashCache.SaveIfDirtyAsync().ConfigureAwait(true);
            }
            catch
            {
                // Cache flush is best-effort; monitoring results stay in memory.
            }

            EndScanUiBatch();
            scanGate.Exit();
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
}
