using System.Text.Json;

namespace HashGuardScanner;

/// <summary>Pure provider response → <see cref="ScanResult"/> mapping (unit-testable).</summary>
internal static class ProviderStats
{
    public static void ApplyVirusTotalFileReport(ScanResult result, JsonElement root)
    {
        var stats = JsonPath.ReadElement(root, "data", "attributes", "last_analysis_stats");
        result.Malicious = JsonPath.ReadInt(stats, "malicious");
        result.Suspicious = JsonPath.ReadInt(stats, "suspicious");
        result.Harmless = JsonPath.ReadInt(stats, "harmless");
        result.Undetected = JsonPath.ReadInt(stats, "undetected");
        result.Status = result.IsAlert ? "detected" : "clean";
    }

    public static void ApplyVirusTotalAnalysis(ScanResult result, JsonElement root)
    {
        var stats = JsonPath.ReadElement(root, "data", "attributes", "stats");
        result.Malicious = JsonPath.ReadInt(stats, "malicious");
        result.Suspicious = JsonPath.ReadInt(stats, "suspicious");
        result.Harmless = JsonPath.ReadInt(stats, "harmless");
        result.Undetected = JsonPath.ReadInt(stats, "undetected");
        var status = JsonPath.ReadString(root, "data", "attributes", "status");
        if (result.IsAlert)
        {
            result.Status = "detected";
        }
        else if (status == "completed")
        {
            result.Status = "clean";
        }
    }

    public static (ProviderState State, string Detail, string Note, bool MarkDetected, int SuspiciousBoost) ApplyMetaDefender(
        ScanResult result,
        JsonElement root)
    {
        var scanResults = JsonPath.ReadElement(root, "scan_results");
        var detected = JsonPath.ReadInt(scanResults, "total_detected_avs");
        var total = JsonPath.ReadInt(scanResults, "total_avs");
        var verdict = JsonPath.ReadString(scanResults, "scan_all_result_a")
            ?? JsonPath.ReadString(scanResults, "scan_all_result_i")
            ?? "";
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
            var detailSuffix = string.IsNullOrWhiteSpace(threatName) ? "" : $", {threatName}";
            var detail = $"Detected by {detected}/{total} engines{detailSuffix}.";
            return (ProviderState.Detected, detail, $"MetaDefender Cloud: detected by {detected}/{total} engines{detailSuffix}.", true, 0);
        }

        if (string.Equals(result.Status, "unknown", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(result.Status))
        {
            result.Status = "clean";
        }

        var totalText = total > 0 ? $" across {total} engines" : "";
        return (ProviderState.Clean, $"No threat detected{totalText}.", $"MetaDefender Cloud: no threat detected{totalText}.", false, 0);
    }

    public static CymruReputation? ParseCymruTxt(string? data)
    {
        if (string.IsNullOrWhiteSpace(data))
        {
            return null;
        }

        var cleaned = data.Replace("\"", "", StringComparison.Ordinal).Trim();
        var parts = cleaned.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2 ||
            !long.TryParse(parts[0], out var unixSeconds) ||
            !int.TryParse(parts[1], out var detectionPercent))
        {
            return null;
        }

        return new CymruReputation(DateTimeOffset.FromUnixTimeSeconds(unixSeconds), detectionPercent);
    }

    public static string BuildCymruQueryName(string sha256)
    {
        if (sha256.Length != 64)
        {
            return sha256;
        }

        return $"{sha256[..32]}.{sha256[32..]}.hash.cymru.com";
    }

    public static CymruReputation? ParseCymruDnsResponse(JsonElement root)
    {
        var status = JsonPath.ReadInt(root, "Status");
        if (status == 3)
        {
            return null;
        }

        if (status != 0)
        {
            throw new InvalidOperationException($"DNS lookup status {status}.");
        }

        if (!root.TryGetProperty("Answer", out var answers) || answers.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var answer in answers.EnumerateArray())
        {
            var data = JsonPath.ReadString(answer, "data");
            var reputation = ParseCymruTxt(data);
            if (reputation is not null)
            {
                return reputation;
            }
        }

        return null;
    }
}
