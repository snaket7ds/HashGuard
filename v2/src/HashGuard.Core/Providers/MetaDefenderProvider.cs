using System.Net;
using System.Text.Json;

namespace HashGuard.Core;

/// <summary>MetaDefender Cloud hash lookups.</summary>
public sealed class MetaDefenderProvider : IReputationProvider, IDisposable
{
    public const string ProviderName = "MetaDefender";

    private readonly HttpClient http;
    private readonly bool ownsHttp;
    private readonly bool hasKey;

    public MetaDefenderProvider(string apiKey)
        : this(AppHttp.Create(TimeSpan.FromSeconds(30)), apiKey, ownsHttp: true)
    {
    }

    public MetaDefenderProvider(HttpClient http, string apiKey, bool ownsHttp = false)
    {
        this.http = http;
        this.ownsHttp = ownsHttp;
        hasKey = !string.IsNullOrWhiteSpace(apiKey);
        if (hasKey && !http.DefaultRequestHeaders.Contains("apikey"))
        {
            http.DefaultRequestHeaders.Add("apikey", apiKey.Trim());
        }
    }

    public string Name => ProviderName;

    public async Task LookupAsync(ScanResult result, LookupRequest request, CancellationToken cancellationToken)
    {
        if (!hasKey)
        {
            result.SetProviderResult(Name, ProviderState.NotChecked, "API key not configured.");
            result.AppendNote("MetaDefender Cloud: skipped, API key not configured.");
            return;
        }

        try
        {
            using var response = await http.GetAsync(string.Format(AppConstants.MetaDefenderHashUrl, result.Sha256), cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                result.SetProviderResult(Name, ProviderState.Unknown, "Hash not found.");
                result.AppendNote("MetaDefender Cloud: hash not found.");
                return;
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                result.SetProviderResult(Name, ProviderState.Error, "401 Unauthorized.");
                result.AppendNote("MetaDefender Cloud: 401 Unauthorized. Verify the API key in Settings.");
                return;
            }

            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            ApplyStats(result, json.RootElement);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.AppendNote($"MetaDefender Cloud lookup failed: {ex.Message}");
            result.SetProviderResult(Name, ProviderState.Error, ex.Message);
        }
    }

    public void Dispose()
    {
        if (ownsHttp)
        {
            http.Dispose();
        }
    }

    internal static void ApplyStats(ScanResult result, JsonElement root)
    {
        var scanResults = JsonPath.ReadElement(root, "scan_results");
        var detected = JsonPath.ReadInt(scanResults, "total_detected_avs");
        var total = JsonPath.ReadInt(scanResults, "total_avs");
        var verdict = JsonPath.ReadString(scanResults, "scan_all_result_a") ?? JsonPath.ReadString(scanResults, "scan_all_result_i") ?? "";
        var threatName = JsonPath.ReadString(scanResults, "threat_name") ?? "";

        if (detected > 0
            || verdict.Contains("infected", StringComparison.OrdinalIgnoreCase)
            || verdict.Contains("malicious", StringComparison.OrdinalIgnoreCase))
        {
            if (!result.IsDetection)
            {
                result.Suspicious = Math.Max(result.Suspicious, Math.Max(detected, 1));
            }

            result.Status = "detected";
            var detail = string.IsNullOrWhiteSpace(threatName) ? "" : $", {threatName}";
            result.SetProviderResult(ProviderName, ProviderState.Detected, $"Detected by {detected}/{total} engines{detail}.");
            result.AppendNote($"MetaDefender Cloud: detected by {detected}/{total} engines{detail}.");
            return;
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(result.Status))
        {
            result.Status = "clean";
        }

        var totalText = total > 0 ? $" across {total} engines" : "";
        result.SetProviderResult(ProviderName, ProviderState.Clean, $"No threat detected{totalText}.");
        result.AppendNote($"MetaDefender Cloud: no threat detected{totalText}.");
    }
}
