using System.Text.Json;

namespace HashGuardScanner;

internal static class CymruClient
{
    public static async Task<CymruReputation?> QueryAsync(string sha256, CancellationToken cancellationToken)
    {
        var queryName = ProviderStats.BuildCymruQueryName(sha256);
        using var http = AppHttp.Create(TimeSpan.FromSeconds(10));
        using var response = await http.GetAsync(
            string.Format(AppConstants.CymruDnsQueryUrl, Uri.EscapeDataString(queryName)),
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"DNS lookup returned {(int)response.StatusCode} {response.StatusCode}.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        return ProviderStats.ParseCymruDnsResponse(document.RootElement);
    }
}
