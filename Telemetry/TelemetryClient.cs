using System.Text;
using System.Text.Json;

namespace HashGuardScanner;

/// <summary>Anonymous usage events (install ID + version only; no paths/hashes).</summary>
internal static class TelemetryClient
{
    public static object BuildPayload(
        string eventType,
        string installId,
        string appVersion,
        string osVersion,
        Dictionary<string, object>? data)
    {
        return new
        {
            eventType,
            installId,
            appVersion,
            osVersion,
            sentAtUtc = DateTimeOffset.UtcNow,
            data = data ?? [],
        };
    }

    public static bool IsSafeEventType(string eventType) =>
        eventType is "app_install" or "app_start" or "app_ping" or "scan_complete";

    public static async Task<bool> SendAsync(
        string endpointUrl,
        string eventType,
        string installId,
        string appVersion,
        Dictionary<string, object>? data = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(endpointUrl)
            || !IsSafeEventType(eventType)
            || string.IsNullOrWhiteSpace(installId)
            || installId.Length < 8
            || string.Equals(installId, "probe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var http = AppHttp.Create(TimeSpan.FromSeconds(5));
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"HashGuard/{appVersion}");
            var payload = BuildPayload(eventType, installId, appVersion, Environment.OSVersion.VersionString, data);
            using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            using var response = await http.PostAsync(endpointUrl, content, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}
