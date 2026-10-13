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
    private async Task ApplyVirusTotalReportAsync(
        HttpClient http,
        ScanResult result,
        string path,
        bool allowUploads,
        bool uploadUnknown,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!http.DefaultRequestHeaders.Contains("x-apikey"))
            {
                AddProviderResult(result, "VirusTotal", ProviderState.NotChecked, "API key not configured.");
                AppendResultNote(result, "VirusTotal: skipped, API key not configured.");
                return;
            }

            using var lane = await EnterVirusTotalLaneAsync(cancellationToken);
            if (!await TryReserveVirusTotalQuotaAsync(result, cancellationToken, waitForMinuteSlot: false))
            {
                AddProviderResult(result, "VirusTotal", ProviderState.Deferred, "Free API quota reached.");
                return;
            }

            await lane.WaitForSpacingAsync(cancellationToken);
            using var reportResponse = await http.GetAsync(string.Format(AppConstants.VirusTotalFileReportUrl, result.Sha256), cancellationToken);
            if (reportResponse.StatusCode != HttpStatusCode.OK)
            {
                var errorBody = await reportResponse.Content.ReadAsStringAsync(cancellationToken);
                if (HashGuardLogic.IsVirusTotalNotFound((int)reportResponse.StatusCode, errorBody))
                {
                    HandleVirusTotalHashNotFound(result, path);
                    return;
                }

                throw new HttpRequestException(
                    $"VirusTotal returned {(int)reportResponse.StatusCode} {reportResponse.StatusCode}. {TrimVirusTotalError(errorBody)}");
            }

            await using var reportStream = await reportResponse.Content.ReadAsStreamAsync(cancellationToken);
            using var reportJson = await JsonDocument.ParseAsync(reportStream, cancellationToken: cancellationToken);
            ProviderStats.ApplyVirusTotalFileReport(result, reportJson.RootElement);
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
            if (uploadUnknown && allowUploads && string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                result.Status = "error";
            }
        }
    }

    private static void HandleVirusTotalHashNotFound(ScanResult result, string path)
    {
        result.Status = "unknown";
        AddProviderResult(result, "VirusTotal", ProviderState.Unknown, "Hash not found.");
        result.NeedsVirusTotalUpload = File.Exists(path);
        AppendResultNote(
            result,
            result.NeedsVirusTotalUpload
                ? "VirusTotal: hash not found. Approve upload from the Review Queue to send this file."
                : "VirusTotal: hash not found.");
    }

    private async Task TryApplyExistingVirusTotalReportAsync(
        HttpClient http,
        ScanResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!await TryReserveVirusTotalQuotaAsync(result, cancellationToken, waitForMinuteSlot: true))
            {
                return;
            }

            using var reportResponse = await http.GetAsync(
                string.Format(AppConstants.VirusTotalFileReportUrl, result.Sha256),
                cancellationToken);
            if (!reportResponse.IsSuccessStatusCode)
            {
                return;
            }

            await using var reportStream = await reportResponse.Content.ReadAsStreamAsync(cancellationToken);
            using var reportJson = await JsonDocument.ParseAsync(reportStream, cancellationToken: cancellationToken);
            ProviderStats.ApplyVirusTotalFileReport(result, reportJson.RootElement);
            AddProviderResult(result, "VirusTotal", result.IsDetection ? ProviderState.Detected : ProviderState.Clean,
                result.IsDetection ? $"{result.Malicious} malicious, {result.Suspicious} suspicious." : "No malicious or suspicious detections.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Upload already succeeded; a follow-up report fetch is best-effort.
        }
    }

    private static string TrimVirusTotalError(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return "";
        }

        var trimmed = body.ReplaceLineEndings(" ").Trim();
        return trimmed.Length <= 240 ? trimmed : trimmed[..240] + "…";
    }

    private async Task ApplyMetaDefenderReportAsync(ScanResult result, CancellationToken cancellationToken)
    {
        var apiKey = metaDefenderApiKeyBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            // Keys are validated once before the scan starts (EnsureProviderKeysConfigured).
            // Never block the per-file scan loop with a modal dialog.
            AddProviderResult(result, "MetaDefender", ProviderState.NotChecked, "API key not configured.");
            AppendResultNote(result, "MetaDefender Cloud: skipped, API key not configured.");
            return;
        }

        try
        {
            using var http = AppHttp.Create(TimeSpan.FromSeconds(30));
            http.DefaultRequestHeaders.Add("apikey", apiKey);
            using var response = await http.GetAsync(string.Format(AppConstants.MetaDefenderHashUrl, result.Sha256), cancellationToken);
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

            if (!await TryReserveVirusTotalQuotaAsync(result, cancellationToken, waitForMinuteSlot: true))
            {
                AddProviderResult(result, "VirusTotal", ProviderState.Deferred, "Free API quota reached while polling analysis.");
                return;
            }

            using var analysisResponse = await http.GetAsync(string.Format(AppConstants.VirusTotalAnalysisUrl, analysisId), cancellationToken);
            analysisResponse.EnsureSuccessStatusCode();
            await using var analysisStream = await analysisResponse.Content.ReadAsStreamAsync();
            using var analysisJson = await JsonDocument.ParseAsync(analysisStream);
            ProviderStats.ApplyVirusTotalAnalysis(result, analysisJson.RootElement);

            var status = JsonPath.ReadString(analysisJson.RootElement, "data", "attributes", "status");
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

    private static void ApplyMetaDefenderStats(ScanResult result, JsonElement root)
    {
        var scanResults = JsonPath.ReadElement(root, "scan_results");
        var detected = JsonPath.ReadInt(scanResults, "total_detected_avs");
        var total = JsonPath.ReadInt(scanResults, "total_avs");
        var verdict = JsonPath.ReadString(scanResults, "scan_all_result_a") ?? JsonPath.ReadString(scanResults, "scan_all_result_i") ?? "";
        var threatName = JsonPath.ReadString(scanResults, "threat_name") ?? "";

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
            var reputation = await CymruClient.QueryAsync(result.Sha256, cancellationToken);
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
        var ignoredByHash = !string.IsNullOrWhiteSpace(result.Sha256) && ignoredHashes.Contains(result.Sha256);
        var ignoredByPath = !string.IsNullOrWhiteSpace(result.Path) && ignoredPaths.Contains(result.Path);
        if (ignoredByHash || ignoredByPath)
        {
            result.StatusBeforeIgnore = result.Status;
            result.Status = "ignored";
            var ignoreNote = ignoredByHash ? "File hash ignored by user." : "File path ignored by user.";
            result.Notes = string.IsNullOrWhiteSpace(result.Notes)
                ? ignoreNote
                : HashGuardLogic.HasIgnoreNote(result.Notes)
                    ? result.Notes
                    : $"{result.Notes}; {ignoreNote}";
        }
    }

    /// <summary>
    /// Scans look up several files at once, but VirusTotal's free tier allows 4 requests a
    /// minute. While the free-API limit or a per-request delay is set, scan lookups take turns
    /// here and start at least "VirusTotal delay per request" apart (this replaces the old
    /// pause between files). With neither set, lookups are not held back.
    /// </summary>
    private async Task<VirusTotalLane> EnterVirusTotalLaneAsync(CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromSeconds((double)delayBox.Value);
        if (!freeApiLimitBox.Checked && delay <= TimeSpan.Zero)
        {
            return new VirusTotalLane(this, held: false, TimeSpan.Zero);
        }

        await virusTotalLaneGate.WaitAsync(cancellationToken);
        return new VirusTotalLane(this, held: true, delay);
    }

    private sealed class VirusTotalLane : IDisposable
    {
        private readonly MainForm owner;
        private readonly bool held;
        private readonly TimeSpan delay;

        public VirusTotalLane(MainForm owner, bool held, TimeSpan delay)
        {
            this.owner = owner;
            this.held = held;
            this.delay = delay;
        }

        /// <summary>Waits out the spacing since the last request, then books the next slot.</summary>
        public async Task WaitForSpacingAsync(CancellationToken cancellationToken)
        {
            if (!held)
            {
                return;
            }

            var wait = owner.nextVirusTotalRequestUtc - DateTimeOffset.UtcNow;
            if (wait > TimeSpan.Zero)
            {
                await Task.Delay(wait, cancellationToken);
            }

            owner.nextVirusTotalRequestUtc = DateTimeOffset.UtcNow + delay;
        }

        public void Dispose()
        {
            if (held)
            {
                owner.virusTotalLaneGate.Release();
            }
        }
    }

    private async Task<bool> TryReserveVirusTotalQuotaAsync(
        ScanResult? result,
        CancellationToken cancellationToken,
        bool waitForMinuteSlot)
    {
        if (!freeApiLimitBox.Checked)
        {
            return true;
        }

        var reservation = await quotaTracker.TryReserveAsync();
        if (!reservation.Available
            && waitForMinuteSlot
            && string.Equals(reservation.LimitName, "minute", StringComparison.OrdinalIgnoreCase))
        {
            await Task.Delay(TimeSpan.FromSeconds(16), cancellationToken);
            reservation = await quotaTracker.TryReserveAsync();
        }

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
        await hashCache.FlushIfDueAsync();
    }

    private async Task<string?> UploadFileAsync(HttpClient http, string path, ScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(path))
            {
                AppendResultNote(result, "VirusTotal upload skipped: file no longer exists.");
                return null;
            }

            var uploadUrl = AppConstants.VirusTotalFileUploadUrl;
            var info = new FileInfo(path);
            if (info.Length == 0)
            {
                AppendResultNote(result, "VirusTotal upload skipped: file is empty.");
                return null;
            }

            if (info.Length >= AppConstants.RegularUploadLimitBytes)
            {
                if (!await TryReserveVirusTotalQuotaAsync(result, cancellationToken, waitForMinuteSlot: true))
                {
                    return null;
                }

                using var uploadUrlResponse = await http.GetAsync(AppConstants.VirusTotalLargeFileUploadUrl, cancellationToken);
                var uploadUrlBody = await uploadUrlResponse.Content.ReadAsStringAsync(cancellationToken);
                if (!uploadUrlResponse.IsSuccessStatusCode)
                {
                    AppendResultNote(result, $"VirusTotal large-file upload URL failed: {(int)uploadUrlResponse.StatusCode}. {TrimVirusTotalError(uploadUrlBody)}");
                    return null;
                }

                using var uploadUrlJson = JsonDocument.Parse(uploadUrlBody);
                uploadUrl = uploadUrlJson.RootElement.TryGetProperty("data", out var dataEl) && dataEl.ValueKind == JsonValueKind.String
                    ? dataEl.GetString() ?? AppConstants.VirusTotalFileUploadUrl
                    : AppConstants.VirusTotalFileUploadUrl;
            }

            await using var fileStream = File.OpenRead(path);
            using var form = new MultipartFormDataContent();
            var fileContent = new StreamContent(fileStream);
            fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
            form.Add(fileContent, "file", Path.GetFileName(path));

            if (!await TryReserveVirusTotalQuotaAsync(result, cancellationToken, waitForMinuteSlot: true))
            {
                return null;
            }

            using var uploadResponse = await http.PostAsync(uploadUrl, form, cancellationToken);
            var responseText = await uploadResponse.Content.ReadAsStringAsync(cancellationToken);
            if (HashGuardLogic.IsVirusTotalAlreadyExists((int)uploadResponse.StatusCode, responseText))
            {
                AppendResultNote(result, "VirusTotal: file already present; using submitted analysis id if available.");
                return HashGuardLogic.TryReadVirusTotalAnalysisId(responseText) ?? "already-exists";
            }

            if (!uploadResponse.IsSuccessStatusCode)
            {
                AppendResultNote(
                    result,
                    $"VirusTotal upload failed: {(int)uploadResponse.StatusCode} {uploadResponse.StatusCode}. {TrimVirusTotalError(responseText)}");
                return null;
            }

            return HashGuardLogic.TryReadVirusTotalAnalysisId(responseText) ?? "submitted";
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppendResultNote(result, $"VirusTotal upload failed: {FormatScanError(ex)}");
            return null;
        }
    }
}
