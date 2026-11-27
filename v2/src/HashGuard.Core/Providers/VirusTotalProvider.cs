using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace HashGuard.Core;

/// <summary>
/// VirusTotal: hash lookups during scans, and (only after the user approves it) uploading a file
/// no source knows, then polling the analysis.
/// </summary>
public sealed class VirusTotalProvider : IReputationProvider, IDisposable
{
    public const string ProviderName = "VirusTotal";

    private readonly HttpClient http;
    private readonly VirusTotalPacer pacer;
    private readonly bool ownsHttp;

    /// <summary>Creates a provider with its own HTTP client carrying <paramref name="apiKey"/>.</summary>
    public VirusTotalProvider(string apiKey, VirusTotalPacer pacer, TimeSpan timeout)
        : this(CreateClient(apiKey, timeout), pacer, ownsHttp: true)
    {
    }

    /// <summary>Uses <paramref name="http"/> as given; it must already carry the x-apikey header.</summary>
    public VirusTotalProvider(HttpClient http, VirusTotalPacer pacer, bool ownsHttp = false)
    {
        this.http = http;
        this.pacer = pacer;
        this.ownsHttp = ownsHttp;
    }

    public string Name => ProviderName;

    /// <summary>Seconds between analysis polls; at least 15.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(15);

    private bool HasKey => http.DefaultRequestHeaders.Contains("x-apikey");

    public async Task LookupAsync(ScanResult result, LookupRequest request, CancellationToken cancellationToken)
    {
        try
        {
            if (!HasKey)
            {
                result.SetProviderResult(Name, ProviderState.NotChecked, "API key not configured.");
                result.AppendNote("VirusTotal: skipped, API key not configured.");
                return;
            }

            using var turn = await pacer.EnterAsync(cancellationToken);
            if (!await pacer.TryReserveAsync(result, waitForMinuteSlot: false, cancellationToken))
            {
                result.SetProviderResult(Name, ProviderState.Deferred, "Free API quota reached.");
                return;
            }

            await pacer.WaitForSpacingAsync(cancellationToken);
            using var response = await http.GetAsync(string.Format(AppConstants.VirusTotalFileReportUrl, result.Sha256), cancellationToken);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
                if (HashGuardLogic.IsVirusTotalNotFound((int)response.StatusCode, errorBody))
                {
                    RecordHashNotFound(result, request.Path);
                    return;
                }

                throw new HttpRequestException(
                    $"VirusTotal returned {(int)response.StatusCode} {response.StatusCode}. {ScanResultNotes.TrimServiceError(errorBody)}",
                    null,
                    response.StatusCode);
            }

            await ApplyReportAsync(response, result, cancellationToken);
            result.AppendNote(result.IsDetection
                ? $"VirusTotal: {result.Malicious} malicious, {result.Suspicious} suspicious."
                : "VirusTotal: no malicious or suspicious detections.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var message = ScanResultNotes.FormatError(ex);
            result.AppendNote($"VirusTotal lookup failed: {message}");
            result.SetProviderResult(Name, ProviderState.Error, message);
            if (request.UploadUnknown && request.AllowUploads && string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                result.Status = "error";
            }
        }
    }

    /// <summary>
    /// Sends the file to VirusTotal (the user approved it), then waits for the analysis.
    /// <paramref name="status"/> receives progress text such as "Waiting for VirusTotal analysis 2 of 6".
    /// </summary>
    /// <returns>False when the upload failed; the reason is in the result's notes.</returns>
    public async Task<bool> UploadAndAnalyzeAsync(ScanResult result, IProgress<string>? status, CancellationToken cancellationToken)
    {
        result.AppendNote("VirusTotal: upload approved.");
        var analysisId = await UploadAsync(result, cancellationToken);
        if (string.IsNullOrWhiteSpace(analysisId))
        {
            return false;
        }

        result.NeedsVirusTotalUpload = false;
        result.Status = "uploaded";
        result.SetProviderResult(Name, ProviderState.Deferred, $"Uploaded for analysis: {analysisId}");
        result.AppendNote($"VirusTotal analysis ID: {analysisId}");
        if (analysisId is "already-exists" or "submitted")
        {
            await TryApplyExistingReportAsync(result, cancellationToken);
        }
        else
        {
            await PollAnalysisAsync(analysisId, result, status, cancellationToken);
        }

        return true;
    }

    /// <summary>Uploads the file; returns the analysis id, "already-exists", "submitted", or null on failure (with a note).</summary>
    public async Task<string?> UploadAsync(ScanResult result, CancellationToken cancellationToken)
    {
        var path = result.Path;
        try
        {
            if (!File.Exists(path))
            {
                result.AppendNote("VirusTotal upload skipped: file no longer exists.");
                return null;
            }

            var info = new FileInfo(path);
            if (info.Length == 0)
            {
                result.AppendNote("VirusTotal upload skipped: file is empty.");
                return null;
            }

            var uploadUrl = AppConstants.VirusTotalFileUploadUrl;
            if (info.Length >= AppConstants.RegularUploadLimitBytes)
            {
                if (!await pacer.TryReserveAsync(result, waitForMinuteSlot: true, cancellationToken))
                {
                    return null;
                }

                using var urlResponse = await http.GetAsync(AppConstants.VirusTotalLargeFileUploadUrl, cancellationToken);
                var urlBody = await urlResponse.Content.ReadAsStringAsync(cancellationToken);
                if (!urlResponse.IsSuccessStatusCode)
                {
                    result.AppendNote($"VirusTotal large-file upload URL failed: {(int)urlResponse.StatusCode}. {ScanResultNotes.TrimServiceError(urlBody)}");
                    return null;
                }

                using var urlJson = JsonDocument.Parse(urlBody);
                uploadUrl = urlJson.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.String
                    ? data.GetString() ?? AppConstants.VirusTotalFileUploadUrl
                    : AppConstants.VirusTotalFileUploadUrl;
            }

            await using var fileStream = File.OpenRead(path);
            using var form = new MultipartFormDataContent();
            var fileContent = new StreamContent(fileStream);
            fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
            form.Add(fileContent, "file", Path.GetFileName(path));

            if (!await pacer.TryReserveAsync(result, waitForMinuteSlot: true, cancellationToken))
            {
                return null;
            }

            using var uploadResponse = await http.PostAsync(uploadUrl, form, cancellationToken);
            var responseText = await uploadResponse.Content.ReadAsStringAsync(cancellationToken);
            if (HashGuardLogic.IsVirusTotalAlreadyExists((int)uploadResponse.StatusCode, responseText))
            {
                result.AppendNote("VirusTotal: file already present; using submitted analysis id if available.");
                return HashGuardLogic.TryReadVirusTotalAnalysisId(responseText) ?? "already-exists";
            }

            if (!uploadResponse.IsSuccessStatusCode)
            {
                result.AppendNote($"VirusTotal upload failed: {(int)uploadResponse.StatusCode} {uploadResponse.StatusCode}. {ScanResultNotes.TrimServiceError(responseText)}");
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
            result.AppendNote($"VirusTotal upload failed: {ScanResultNotes.FormatError(ex)}");
            return null;
        }
    }

    /// <summary>Polls an uploaded file's analysis up to 6 times.</summary>
    public async Task PollAnalysisAsync(string analysisId, ScanResult result, IProgress<string>? status, CancellationToken cancellationToken)
    {
        var interval = PollInterval < TimeSpan.FromSeconds(15) ? TimeSpan.FromSeconds(15) : PollInterval;
        interval = interval < pacer.Delay ? pacer.Delay : interval;
        for (var attempt = 1; attempt <= 6; attempt++)
        {
            status?.Report($"Waiting for VirusTotal analysis {attempt} of 6");
            await Task.Delay(interval, cancellationToken);

            if (!await pacer.TryReserveAsync(result, waitForMinuteSlot: true, cancellationToken))
            {
                result.SetProviderResult(Name, ProviderState.Deferred, "Free API quota reached while polling analysis.");
                return;
            }

            using var response = await http.GetAsync(string.Format(AppConstants.VirusTotalAnalysisUrl, analysisId), cancellationToken);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            ProviderStats.ApplyVirusTotalAnalysis(result, json.RootElement);

            if (JsonPath.ReadString(json.RootElement, "data", "attributes", "status") == "completed")
            {
                result.SetProviderResult(Name, result.IsDetection ? ProviderState.Detected : ProviderState.Clean,
                    result.IsDetection ? $"{result.Malicious} malicious, {result.Suspicious} suspicious." : "Analysis completed clean.");
                result.AppendNote($"VirusTotal analysis ID: {analysisId}");
                return;
            }
        }

        result.AppendNote($"VirusTotal analysis still running: {analysisId}");
        result.SetProviderResult(Name, ProviderState.Deferred, $"Analysis still running: {analysisId}");
    }

    /// <summary>After an upload VirusTotal already knew: fetch its report. Best effort.</summary>
    public async Task TryApplyExistingReportAsync(ScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            if (!await pacer.TryReserveAsync(result, waitForMinuteSlot: true, cancellationToken))
            {
                return;
            }

            using var response = await http.GetAsync(string.Format(AppConstants.VirusTotalFileReportUrl, result.Sha256), cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                await ApplyReportAsync(response, result, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // The upload already succeeded; the follow-up report is best effort.
        }
    }

    public void Dispose()
    {
        if (ownsHttp)
        {
            http.Dispose();
        }
    }

    private async Task ApplyReportAsync(HttpResponseMessage response, ScanResult result, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        ProviderStats.ApplyVirusTotalFileReport(result, json.RootElement);
        result.SetProviderResult(Name, result.IsDetection ? ProviderState.Detected : ProviderState.Clean,
            result.IsDetection ? $"{result.Malicious} malicious, {result.Suspicious} suspicious." : "No malicious or suspicious detections.");
    }

    private void RecordHashNotFound(ScanResult result, string path)
    {
        result.Status = "unknown";
        result.SetProviderResult(Name, ProviderState.Unknown, "Hash not found.");
        result.NeedsVirusTotalUpload = File.Exists(path);
        result.AppendNote(result.NeedsVirusTotalUpload
            ? "VirusTotal: hash not found. You can send this file from Needs your decision."
            : "VirusTotal: hash not found.");
    }

    private static HttpClient CreateClient(string apiKey, TimeSpan timeout)
    {
        var client = AppHttp.Create(timeout);
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            client.DefaultRequestHeaders.Add("x-apikey", apiKey.Trim());
        }

        return client;
    }
}
